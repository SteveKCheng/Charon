using System.Buffers;
using System.Net.Security;
using System.Text;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Charon;

/// <summary>The target of a CONNECT request, which all requests inside the tunnel must go to.</summary>
internal sealed class Tunnel(Authority target)
{
    public Authority Target { get; } = target;

    public int RequestCount;
}

/// <summary>
/// Makes a Kestrel endpoint accept the two ways that HTTP proxies are used.
/// </summary>
/// <remarks>
/// <para>
/// Neither Kestrel nor YARP have support for CONNECT.  But, Kestrel can be made to serve
/// the inside of a tunnel with this arrangement of connection middleware:
/// </para>
/// <code>
///                 ┌─ "CONNECT ..." ──► Kestrel's TLS ─┐
///   connection ───┤                                   ├──► Kestrel's HTTP/1.1, HTTP/2
///                 └─ anything else ───────────────────┘
/// </code>
/// <para>
/// The CONNECT request is consumed here, before any HTTP parser sees it. So a client's
/// decrypted traffic reaches the same HTTP stack and <see cref="ForwardProxy"/> as
/// plain-text requests, with no extra hop.  Data in a tunnel that is not TLS, or not HTTP
/// inside of TLS, is not understood and the connection gets dropped.  That is deliberate.
/// </para>
/// </remarks>
internal static class ProxyListener
{
    private const int MaxConnectHeadLength = 8192;

    private static readonly TimeSpan FirstRequestTimeout = TimeSpan.FromSeconds(30);

    private static readonly ReadOnlyMemory<byte> ConnectPrefix = "CONNECT "u8.ToArray();
    private static readonly byte[] EndOfHead = "\r\n\r\n"u8.ToArray();

    private static readonly ReadOnlyMemory<byte> Established =
        "HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray();

    private static readonly ReadOnlyMemory<byte> BadRequest =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();

    public static void Configure(ListenOptions listenOptions, CertificateAuthority ca, TrafficLog log)
    {
        ConnectionDelegate? httpPipeline = null;

        listenOptions.Use(tlsPipeline => connection =>
            HandleConnectionAsync(connection, tlsPipeline, httpPipeline!, log));

        listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context =>
            {
                var tunnel = GetTunnel(context.Connection.Features)!;

                // The certificate is for the CONNECT target and not for whatever the client
                // says in SNI, so that the name verified is the one being connected to.
                return ValueTask.FromResult(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = ca.GetCertificate(tunnel.Target.Host),
                    ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                });
            },
        });

        // Middleware is composed last to first, so this
        // runs before the connection delegate above can be called.
        listenOptions.Use(next => httpPipeline = next);
    }

    /// <summary>Gets the tunnel that a connection is for, if any.</summary>
    public static Tunnel? GetTunnel(IFeatureCollection features)
    {
        object? tunnel = null;
        features.Get<IConnectionItemsFeature>()?.Items.TryGetValue(typeof(Tunnel), out tunnel);
        return (Tunnel?)tunnel;
    }

    private static async Task HandleConnectionAsync(ConnectionContext connection,
                                                    ConnectionDelegate tlsPipeline,
                                                    ConnectionDelegate httpPipeline,
                                                    TrafficLog log)
    {
        // Set on all connections, as this is how requests get told apart from the Web UI's.
        connection.Items[typeof(ProxyListener)] = true;

        string? head;
        try
        {
            using var timeout = new CancellationTokenSource(FirstRequestTimeout);
            head = await ReadConnectHeadAsync(connection, timeout.Token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (InvalidDataException)
        {
            await connection.Transport.Output.WriteAsync(BadRequest);
            return;
        }

        if (head is null)
        {
            await httpPipeline(connection);
            return;
        }

        var requestLine = head.AsSpan(0, head.IndexOf('\r')).ToString().Split(' ');
        if (requestLine is not ["CONNECT", var target, "HTTP/1.1" or "HTTP/1.0"] ||
            !Authority.TryParse(target, defaultPort: 0, out var authority))
        {
            await connection.Transport.Output.WriteAsync(BadRequest);
            return;
        }

        var tunnel = new Tunnel(authority);
        connection.Items[typeof(Tunnel)] = tunnel;
        await connection.Transport.Output.WriteAsync(Established);

        await tlsPipeline(connection);

        // Otherwise a client failing to get through, say because it pins
        // certificates or is not speaking HTTP, would not show up anywhere.
        if (tunnel.RequestCount == 0)
        {
            log.Add(connection.RemoteEndPoint?.ToString() ?? "?", "CONNECT",
                    $"{authority.UrlHost}:{authority.Port}", allowed: false,
                    note: "No HTTP request was received in the tunnel");
        }
    }

    /// <summary>
    /// Reads the head of a CONNECT request from the start of a connection, leaving behind
    /// what comes after it.  If the connection begins with something else, returns null with
    /// nothing consumed.
    /// </summary>
    private static async Task<string?> ReadConnectHeadAsync(ConnectionContext connection,
                                                            CancellationToken cancellationToken)
    {
        var input = connection.Transport.Input;

        while (true)
        {
            var result = await input.ReadAsync(cancellationToken);
            var buffer = result.Buffer;
            var reader = new SequenceReader<byte>(buffer);

            int prefixLength = (int)Math.Min(buffer.Length, ConnectPrefix.Length);
            if (!buffer.Slice(0, prefixLength).ToArray().AsSpan().SequenceEqual(ConnectPrefix.Span[..prefixLength]))
            {
                // Not "AdvanceTo(start, end)": the next reader must get this data straight away.
                input.AdvanceTo(buffer.Start);
                return null;
            }

            if (reader.TryReadTo(out ReadOnlySequence<byte> head, EndOfHead, advancePastDelimiter: true))
            {
                if (head.Length > MaxConnectHeadLength)
                    throw new InvalidDataException();

                var text = Encoding.Latin1.GetString(head) + "\r\n";
                input.AdvanceTo(reader.Position);
                return text;
            }

            if (buffer.Length > MaxConnectHeadLength || result.IsCompleted)
                throw new InvalidDataException();

            input.AdvanceTo(buffer.Start, buffer.End);
        }
    }
}
