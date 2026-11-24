using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Text;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Charon;

/// <summary>
/// Records the destination of a CONNECT tunnel, required as context to forward
/// HTTP requests inside the tunnel.
/// </summary>
/// <remarks>
/// <para>
/// An instance of this class is added as a connection feature (<see cref="ConnectionContext.Features" />)
/// when a CONNECT tunnel is established.  Then, <see cref="ForwardProxy.ProxyRequestAsync" />
/// can recover the needed context to forward individual HTTP requests within that tunnel.
/// </para>
/// </remarks> 
/// <param name="target">Where the tunnel connects to.</param>
/// <param name="userName">The proxy's user, or null for the anonymous user. </param>
internal sealed class Tunnel(Authority target, string? userName)
{
    /// <summary>
    /// Which HTTPS server to connect to for all requests in the CONNECT tunnel.
    /// </summary>
    public Authority Target { get; } = target;

    /// <summary>
    /// The proxy's user, as identified by the CONNECT request, or null for an anonymous user.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The proxy's user cannot be overridden from HTTP request headers within the tunnel.
    /// </para>
    /// <para>
    /// The user is represented by the string name instead of an object, so that changes
    /// to the user's settings apply to tunnels that are currently open.
    /// </para>
    /// </remarks>
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

    private static ReadOnlySpan<byte> ConnectPrefix => "CONNECT "u8;
    private static ReadOnlySpan<byte> EndOfHead => "\r\n\r\n"u8;

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

    /// <summary>
    /// Sets up this proxy as connection middleware for Kestrel.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kestrel's connection middleware is distinct from ASP.NET Core's HTTP middleware.
    /// The former handles the raw byte stream from accepting a connection; 
    /// the latter handles parsing of HTTP requests.
    /// </para>
    /// <para>
    /// None of Kestrel, ASP.NET Core or YARP supports the <c>CONNECT</c> requests required
    /// for proxying HTTPS URLs, so this middleware must set up Kestrel to let our own
    /// middleware to switch the stream to HTTPS upon receiving <c>CONNECT</c>.
    /// </para>
    /// </remarks>
    public static void Configure(ListenOptions listenOptions, CertificateAuthority ca, TrafficLog log,
                                 IClientAuthenticator authenticator)
    {
        ConnectionDelegate? httpPipeline = null;

        // Middleware ①: contains our proxying logic.  
        // If a CONNECT request is seen, our proxy defers to (invokes) httpsPipeline;
        // all other requests go to httpPipeline.
        listenOptions.Use(httpsPipeline => connection =>
            HandleConnectionAsync(connection, httpsPipeline, httpPipeline!, log, authenticator));

        // Middleware ②: sets up the HTTPS handler from Kestrel, which appears as 
        // httpsPipeline in middleware ①.
        listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context =>
            {
                var tunnel = context.Connection.Features.Get<Tunnel>();
                Debug.Assert(tunnel is not null, 
                    "A Tunnel should have been set up as a ConnectionContext feature after a CONNECT request");

                // The certificate is for the CONNECT target and not for whatever the client
                // says in SNI, so that the name verified is the one being connected to.
                return ValueTask.FromResult(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = ca.GetCertificate(tunnel.Target.Host),
                    ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                });
            },
        });

        // This middleware ③ is only to capture the middleware ④ above us, which is
        // expected to be the regular HTTP handler from Kestrel, to pass into 
        // middleware ①, as httpPipeline.
        listenOptions.Use(next => httpPipeline = next);
    }

    /// <summary>
    /// Has clients use TLS to connect to the proxy itself.  This must come before
    /// <see cref="Configure" />.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This protects what the client sends to the proxy outside of tunnels, above all its
    /// password.  The TLS of a tunnel is then nested inside this one.
    /// </para>
    /// <para>
    /// There is one certificate for all the names the proxy has been given, plus the IP address
    /// the client connected to.  So what the client says in SNI does not matter, which it
    /// leaves out anyway when connecting to an IP address.
    /// </para>
    /// </remarks>
    public static void UseTlsToProxy(ListenOptions listenOptions, CertificateAuthority ca, string[] names)
    {
        listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context => ValueTask.FromResult(new SslServerAuthenticationOptions
            {
                ServerCertificateContext = ca.GetCertificate(AddLocalAddress(names, context.Connection.LocalEndPoint)),

                // Not HTTP/2, as CONNECT is only understood in HTTP/1.x here.
                // Inside of a tunnel, HTTP/2 is negotiated separately.
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }),
        });

        // Make the decrypted connection look like any other to what comes next.  In particular,
        // Kestrel's TLS for tunnels does nothing on a connection that has ITlsConnectionFeature.
        // And what is outside of a tunnel are requests for http:// URLs, so they should not
        // appear to have come by HTTPS.
        listenOptions.Use(next => connection =>
        {
            connection.Features.Set<ITlsConnectionFeature>(null);
            connection.Features.Set<ITlsHandshakeFeature>(null);
            connection.Features.Set<ITlsApplicationProtocolFeature>(null);
            connection.Features.Set<ISslStreamFeature>(null);
            return next(connection);
        });
    }

    private static string[] AddLocalAddress(string[] names, EndPoint? localEndPoint)
    {
        if (localEndPoint is not IPEndPoint { Address: var address })
            return names;

        // IPv4 clients of a listener on [::] appear like this, but verify the plain address.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Certificates have no scopes, which link-local addresses have.
        else if (address.IsIPv6LinkLocal)
            address = new IPAddress(address.GetAddressBytes());

        var text = address.ToString();
        return names.Contains(text) ? names : [.. names, text];
    }

    /// <summary>
    /// Gets the field value corresponding to a field name in a HTTP request header. 
    /// </summary>
    /// <param name="request">
    /// Buffer containing the HTTP request line and headers, converted to UTF-16.
    /// </param>
    /// <param name="fieldName">
    /// The name of the field to look for. 
    /// </param>
    /// <returns>
    /// The value of the first field found whose name matches <paramref name="fieldName" />,
    /// or null if there is no such field.  Whitespace is trimmed.
    /// </returns>
    private static string? FindHeader(ReadOnlySpan<char> request, ReadOnlySpan<char> fieldName)
    {
        while (!request.IsEmpty)
        {
            // Field line ends on CRLF or end of buffer
            const string lineTerminator = "\r\n";
            int lineEndIndex = request.IndexOf(lineTerminator);
            var line = lineEndIndex < 0 ? request : request[..lineEndIndex];
            request = lineEndIndex < 0 ? default : request[(lineEndIndex + lineTerminator.Length)..];

            // Separator between field name and value.
            // If there is no field value, ignore this line.
            var nameEndIndex = line.IndexOf(':');
            if (nameEndIndex < 0)
                continue;

            // From RFC 9112 §5 and RFC 9110 §5.6.3:
            //   field-line = field-name ":" OWS field-value OWS 
            //   OWS        = *( SP / HTAB )
            var currentName = line[0..nameEndIndex];
            if (currentName.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                return line[(nameEndIndex + 1)..].Trim(" \t").ToString();
        }

        return null;
    }

    /// <summary>
    /// Delegates handling of a connection to HTTP or HTTPS,
    /// depending on the presence of a <c>CONNECT</c> request.
    /// </summary>
    /// <param name="connection">The current connection to handle. </param>
    /// <param name="httpsPipeline">HTTPS handler (from Kestrel). </param>
    /// <param name="httpPipeline">HTTP handler (from Kestrel). </param>
    /// <param name="log">For logging unauthorized <c>CONNECT</c> requests. </param>
    /// <param name="authenticator">Used to check for unauthorized requests
    /// for the current connection. </param>
    private static async Task HandleConnectionAsync(ConnectionContext connection,
                                                    ConnectionDelegate httpsPipeline,
                                                    ConnectionDelegate httpPipeline,
                                                    TrafficLog log,
                                                    IClientAuthenticator authenticator)
    {
        // Set on all connections, as this is how requests get told apart from the Web UI's.
        connection.Items[typeof(ProxyListener)] = true;

        // A connection may already have a connection-specific IClientAuthenticator like
        // FixedUserAuthenticator.  If it does not, then set it to use the "default" one
        // passed into this method.
        if (connection.Features.Get<IClientAuthenticator>() is {} connectionAuthenticator)
            authenticator = connectionAuthenticator;
        else
            connection.Features.Set<IClientAuthenticator>(authenticator);

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

        // Parse for "CONNECT authority-form http-version"
        static bool TryParseConnectRequest(ReadOnlySpan<char> line, out Authority authority)
        {
            authority = default;
            Span<Range> ranges = stackalloc Range[4];
            if (line.Split(ranges, ' ', StringSplitOptions.None) != 3)
                return false;

            var request = line[ranges[0]];
            var target = line[ranges[1]];
            var httpVersion = line[ranges[2]];

            if (!(request is "CONNECT")) 
                return false;
            if (!(httpVersion is "HTTP/1.1" || httpVersion is "HTTP/1.0")) 
                return false;

            return Authority.TryParse(target, defaultPort: 0, out authority);
        }

        if (!TryParseConnectRequest(head.AsSpan(0, head.IndexOf('\r')), out var authority))
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
                log.Add(ListenAddresses.NameOfClient(connection.RemoteEndPoint), "CONNECT",
                        $"{authority.UrlHost}:{authority.Port}", allowed: false,
                        status: StatusCodes.Status407ProxyAuthenticationRequired, reason: "wrong proxy credentials");
            }

            await connection.Transport.Output.WriteAsync(ProxyAuthenticationRequired);
            return;
        }

        var tunnel = new Tunnel(authority, userName);
        connection.Features.Set<Tunnel>(tunnel);

        await connection.Transport.Output.WriteAsync(Established);

        await httpsPipeline(connection);

        // Log a message if the client requested nothing (valid) over the tunnel, 
        // e.g. because it failed TLS certificate validation, or is not speaking HTTP.
        if (tunnel.RequestCount == 0)
        {
            log.Add(ListenAddresses.NameOfClient(connection.RemoteEndPoint), "CONNECT",
                    $"{authority.UrlHost}:{authority.Port}", allowed: false,
                    note: "No HTTP request was received in the tunnel", reason: "no HTTP in tunnel", user: userName);
        }
    }

    /// <summary>
    /// Reads the <c>CONNECT</c> request (including HTTP headers) from the start of a connection, 
    /// if there is one.
    /// </summary>
    /// <param name="connection">
    /// The HTTP connection to read from to look for a <c>CONNECT</c> request.  If found, the entirety
    /// of the request, including the <see cref="EndOfHead" /> terminator, will be consumed from
    /// the connection.  Otherwise, nothing is consumed from the connection. 
    /// </param>
    /// <param name="cancellationToken">
    /// Can be used to cancel the asynchronous reading from the HTTP connection. 
    /// </param>
    /// <returns>
    /// <para>
    /// If a HTTP <c>CONNECT</c> request is present at the current position in <paramref name="connection" />,
    /// the returned string will include the request line, plus all of the HTTP headers, including the
    /// <see cref="EndOfHead" /> terminator at the end.
    /// </para> 
    /// <para>
    /// If there is no <c>CONNECT</c> request, the returned value is null.
    /// </para>
    /// </returns>
    private static async Task<string?> ReadConnectHeadAsync(ConnectionContext connection,
                                                            CancellationToken cancellationToken)
    {
        var input = connection.Transport.Input;

        while (true)
        {
            var result = await input.ReadAsync(cancellationToken);
            var buffer = result.Buffer;

            static bool MatchesConnectPrefix(ReadOnlySequence<byte> buffer)
            {
                int prefixLength = (int)Math.Min(buffer.Length, ConnectPrefix.Length);

                // We need to copy "buffer" to "shortBuffer" for this byte-wise comparison
                // because the former is a ReadOnlySequence<byte> that does not support
                // SequenceEqual against ReadOnlySpan<byte>.  And then, this code must
                // be put in a separate (inner) function because stackalloc is not allowed
                // across suspension points in an asynchronous method.
                Span<byte> shortBuffer = stackalloc byte[prefixLength];
                buffer.Slice(0, prefixLength).CopyTo(shortBuffer);

                // Note: HTTP request methods are case-sensitive (RFC 9112 §3.1).
                return shortBuffer.SequenceEqual(ConnectPrefix[..prefixLength]);
            }

            bool isAdvanced = false;
            try
            {
                // Quit as soon as we see anything that cannot begin a CONNECT request.
                if (!MatchesConnectPrefix(buffer))
                    return null;

                // Examine the currently read bytes to the end of HTTP headers.
                // Note that TryReadTo returning success here implies that the entire ConnectPrefix
                // string matched, and not just ConnectPrefix[..prefixLength] above.
                var reader = new SequenceReader<byte>(buffer);
                if (reader.TryReadTo(out ReadOnlySequence<byte> head, EndOfHead, advancePastDelimiter: true))
                {
                    if (head.Length > MaxConnectHeadLength)
                        throw new InvalidDataException();

                    // TryReadTo above advances past the delimiter string, but does not include it
                    // in the output.  We do want to include it though.
                    head = buffer.Slice(buffer.Start, reader.Position);
                    var text = Encoding.Latin1.GetString(head);

                    // Consider all of the bytes of the CONNECT request consumed, in the underlying "input". 
                    input.AdvanceTo(reader.Position);
                    isAdvanced = true;
                
                    return text;
                }

                if (buffer.Length > MaxConnectHeadLength || result.IsCompleted)
                    throw new InvalidDataException();

                // Do not consume anything (yet), but wake up the next call to ReadAsync
                // only when there are more bytes beyond the prefix we have examined so far.
                input.AdvanceTo(buffer.Start, buffer.End);
                isAdvanced = true;
            }
            finally
            {
                // PipeReader requires that we mark the read operation as complete,
                // even if we consume or process nothing. 
                if (!isAdvanced)
                    input.AdvanceTo(buffer.Start);
            }
        }
    }
}
