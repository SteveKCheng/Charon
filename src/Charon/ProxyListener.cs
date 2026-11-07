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
/// <param name="target">Where the tunnel goes.</param>
/// <param name="userName">Who it is for, or null for an anonymous client.</param>
internal sealed class Tunnel(Authority target, string? userName)
{
    public Authority Target { get; } = target;

    /// <summary>
    /// The user, as identified by the CONNECT request.  Nothing inside the tunnel can change
    /// this.  It is a name so that changes to the user apply to tunnels that are open.
    /// </summary>
    public string? UserName { get; } = userName;

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

    /// <summary>The value of the Proxy-Authenticate header, for asking for credentials.</summary>
    public const string ProxyAuthenticateChallenge = "Basic realm=\"Charon\"";

    private static readonly ReadOnlyMemory<byte> ProxyAuthenticationRequired = Encoding.ASCII.GetBytes(
        "HTTP/1.1 407 Proxy Authentication Required\r\n" +
        $"Proxy-Authenticate: {ProxyAuthenticateChallenge}\r\n" +
        "Content-Length: 0\r\nConnection: close\r\n\r\n");

    public static void Configure(ListenOptions listenOptions, CertificateAuthority ca, TrafficLog log,
                                 IClientAuthenticator authenticator)
    {
        ConnectionDelegate? httpPipeline = null;

        listenOptions.Use(tlsPipeline => connection =>
            HandleConnectionAsync(connection, tlsPipeline, httpPipeline!, log, authenticator));

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

    /// <summary>Gets how the listener of a connection identifies clients.</summary>
    public static IClientAuthenticator GetAuthenticator(IFeatureCollection features) =>
        (IClientAuthenticator)features.Get<IConnectionItemsFeature>()!.Items[typeof(IClientAuthenticator)]!;

    /// <summary>Gets a header from the head of a request, as text.</summary>
    private static string? FindHeader(string head, string name)
    {
        foreach (var line in head.Split("\r\n"))
        {
            if (line.StartsWith(name, StringComparison.OrdinalIgnoreCase) &&
                line.Length > name.Length && line[name.Length] == ':')
            {
                return line[(name.Length + 1)..].Trim();
            }
        }

        return null;
    }

    private static async Task HandleConnectionAsync(ConnectionContext connection,
                                                    ConnectionDelegate tlsPipeline,
                                                    ConnectionDelegate httpPipeline,
                                                    TrafficLog log,
                                                    IClientAuthenticator authenticator)
    {
        // Set on all connections, as this is how requests get told apart from the Web UI's.
        connection.Items[typeof(ProxyListener)] = true;

        // A connection can bring its own, if the transport already knows who it is from.
        if (connection.Items.TryGetValue(typeof(IClientAuthenticator), out var own))
            authenticator = (IClientAuthenticator)own!;
        else
            connection.Items[typeof(IClientAuthenticator)] = authenticator;

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

        var proxyAuthorization = FindHeader(head, "Proxy-Authorization");
        if (!authenticator.TryAuthenticate(proxyAuthorization, out var userName))
        {
            // Being asked for a password is a normal step for many clients, unlike getting it wrong.
            if (proxyAuthorization is not null)
            {
                log.Add(connection.RemoteEndPoint?.ToString() ?? "unix", "CONNECT",
                        $"{authority.UrlHost}:{authority.Port}", allowed: false,
                        status: StatusCodes.Status407ProxyAuthenticationRequired, reason: "wrong proxy credentials");
            }

            await connection.Transport.Output.WriteAsync(ProxyAuthenticationRequired);
            return;
        }

        var tunnel = new Tunnel(authority, userName);
        connection.Items[typeof(Tunnel)] = tunnel;
        await connection.Transport.Output.WriteAsync(Established);

        await tlsPipeline(connection);

        // Otherwise a client failing to get through, say because it pins
        // certificates or is not speaking HTTP, would not show up anywhere.
        if (tunnel.RequestCount == 0)
        {
            log.Add(connection.RemoteEndPoint?.ToString() ?? "unix", "CONNECT",
                    $"{authority.UrlHost}:{authority.Port}", allowed: false,
                    note: "No HTTP request was received in the tunnel", reason: "no HTTP in tunnel", user: userName);
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
