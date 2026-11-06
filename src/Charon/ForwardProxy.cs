using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http.Features;
using Yarp.ReverseProxy.Forwarder;

namespace Charon;

/// <summary>Applies the whitelist to requests from clients, and forwards the ones allowed.</summary>
internal sealed class ForwardProxy
{
    private readonly IHttpForwarder _forwarder;
    private readonly Whitelist _whitelist;
    private readonly TrafficLog _log;
    private readonly CredentialStore _credentials;
    private readonly ProxyUserStore _users;
    private readonly HttpMessageInvoker _upstream;
    private readonly ILogger<ForwardProxy> _logger;
    private readonly ForwarderRequestConfig _requestConfig;
    private readonly TrafficStore? _headerStore;
    private readonly int _headersMaxBytes;

    public ForwardProxy(IHttpForwarder forwarder, Whitelist whitelist, TrafficLog log, CredentialStore credentials,
                        ProxyUserStore users,
                        HttpMessageInvoker upstream, ILogger<ForwardProxy> logger, CharonOptions options,
                        TrafficStore? store = null)
    {
        _forwarder = forwarder;
        _whitelist = whitelist;
        _log = log;
        _credentials = credentials;
        _users = users;
        _upstream = upstream;
        _logger = logger;
        _requestConfig = new ForwarderRequestConfig { ActivityTimeout = options.ActivityTimeout };
        _headerStore = options.TrafficHeaders ? store : null;
        _headersMaxBytes = options.TrafficHeadersMaxBytes;
    }

    /// <summary>Makes the client for connecting to upstream servers.</summary>
    public static HttpMessageInvoker CreateUpstreamClient(CharonOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            // The environment's proxy settings are for clients, not for the proxy itself.
            UseProxy = options.UpstreamProxy is not null,
            Proxy = options.UpstreamProxy is { } proxy ? new WebProxy(proxy) : null,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            EnableMultipleHttp2Connections = true,
            ConnectTimeout = TimeSpan.FromSeconds(15),

            // Otherwise, trace context from inside the proxy gets added to requests.
            ActivityHeadersPropagator = null,
        };

        if (options.UpstreamRootsFile is { } rootsFile)
        {
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,

                // As SocketsHttpHandler would do if no policy were given.
                RevocationMode = X509RevocationMode.NoCheck,
            };
            policy.CustomTrustStore.ImportFromPemFile(rootsFile);
            handler.SslOptions.CertificateChainPolicy = policy;
        }

        return new HttpMessageInvoker(handler);
    }

    public async Task HandleAsync(HttpContext context)
    {
        var tunnel = ProxyListener.GetTunnel(context.Features);
        if (tunnel is not null)
            Interlocked.Increment(ref tunnel.RequestCount);

        var request = context.Request;
        var client = context.Connection.RemoteIpAddress + ":" + context.Connection.RemotePort;

        // In a tunnel, this was settled by the CONNECT request.  Otherwise, unlike
        // for a tunnel, every request on a connection stands on its own.
        var userName = tunnel?.UserName;
        var isAuthenticated = tunnel is not null ||
            ProxyListener.GetAuthenticator(context.Features).TryAuthenticate(request.Headers.ProxyAuthorization, out userName);

        ProxyUser? user = null;
        if (!isAuthenticated || (userName is not null && (user = _users.Find(userName)) is null))
        {
            // The second case is the user being removed.  It then has no credentials.
            context.Response.Headers.ProxyAuthenticate = ProxyListener.ProxyAuthenticateChallenge;
            context.Response.Headers.Connection = "close";
            await RefuseAsync(context, client, userName, StatusCodes.Status407ProxyAuthenticationRequired,
                              request.Method, context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "",
                              "This proxy needs a valid user name and password.",
                              reason: "wrong proxy credentials");
            return;
        }

        var capability = RequestPolicy.GetRequiredCapability(context);

        if (HttpMethods.IsConnect(request.Method) && capability is null)
        {
            // Only the first request of a connection can be CONNECT: see ProxyListener.
            context.Response.Headers.Connection = "close";
            await RefuseAsync(context, client, userName, StatusCodes.Status405MethodNotAllowed,
                              request.Method, tunnel is null ? "(proxy)" : "(tunnel)",
                              "CONNECT must be the first request on a connection to this proxy.",
                              reason: "CONNECT not first");
            return;
        }

        if (GetDestination(context, tunnel, out string? problem) is not { } destination)
        {
            await RefuseAsync(context, client, userName,
                              tunnel is null ? StatusCodes.Status400BadRequest
                                             : StatusCodes.Status421MisdirectedRequest,
                              request.Method, context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "", problem!,
                              reason: tunnel is null ? "bad request" : "host mismatch", note: problem);
            return;
        }

        var url = destination.AbsoluteUri;

        if (RequestPolicy.FindViolation(request, destination) is { } violation)
        {
            await RefuseAsync(context, client, userName, StatusCodes.Status403Forbidden, request.Method, url,
                              $"Access Denied: {violation}", reason: "forbidden request", note: violation);
            return;
        }

        var decision = capability is { } required
            ? _whitelist.Evaluate(required, url, destination.IdnHost.ToLowerInvariant())
            : new WhitelistDecision(null, _whitelist.Version.Hash);

        if (decision.Rule is not { } rule)
        {
            await RefuseAsync(context, client, userName, StatusCodes.Status403Forbidden, request.Method, url,
                              $"Access Denied: '{url}' (method {request.Method}{Describe(capability)}) " +
                              "is disallowed by the sandbox's whitelist.",
                              reason: capability is { } needed ? $"no {RequestPolicy.RuleType(needed)} rule"
                                                               : "no rule can allow this",
                              whitelist: decision.Version);
            return;
        }

        // This comes after the checks above: no rule here widens what clients may do.
        var credential = _credentials.Find(destination);
        CredentialValue? credentialValue = null;
        if (credential is not null)
        {
            try
            {
                // Users opt in to something narrower: other credentials stay as they are.
                credentialValue = await credential.GetValueAsync(context.RequestAborted,
                                                                 user?.Credentials.GetValueOrDefault(credential.Name));
            }
            catch (CredentialUnavailableException e)
            {
                // Going ahead without it would have the agent see confusing failures at best.
                _logger.LogError("Credential {Name} is unavailable: {Message}", credential.Name, e.Message);
                await RefuseAsync(context, client, userName, StatusCodes.Status502BadGateway, request.Method, url,
                                  $"The proxy could not obtain the credential '{credential.Name}' for this request.",
                                  reason: "credential unavailable", note: credential.Name,
                                  whitelist: decision.Version);
                return;
            }
        }

        var entry = _log.Add(client, request.Method, url, allowed: true,
                             note: credential is null ? null : $"Credential {credential.Name}",
                             ruleLine: rule.Line, rule: rule.Text, whitelist: decision.Version, user: userName);
        long startTime = Stopwatch.GetTimestamp();

        // What the client sent: this is before any credential gets added.
        RecordHeaders(entry, request.Headers, isResponse: false, credential: null);

        var error = await _forwarder.SendAsync(
            context, destination.GetLeftPart(UriPartial.Authority), _upstream, _requestConfig,
            new FixedDestination(destination, credential?.Header, credentialValue?.HeaderValue));

        RecordHeaders(entry, context.Response.Headers, isResponse: true, credentialValue);

        _log.Update(entry with
        {
            Status = context.Response.StatusCode,
            DurationMs = Stopwatch.GetElapsedTime(startTime).TotalMilliseconds,
            Note = error == ForwarderError.None ? entry.Note : error.ToString(),
        });
    }

    /// <summary>Tells why a request can be refused though its method and URL look allowed.</summary>
    private static string Describe(Capability? capability) => capability switch
    {
        Capability.GetWithBody => ", with a body",
        Capability.WebSocket => ", as a WebSocket",
        null => ", or its protocol upgrade",
        _ => "",
    };

    private Task RefuseAsync(HttpContext context, string client, string? user, int status,
                             string method, string url, string message, string reason,
                             string? note = null, string? whitelist = null)
    {
        var entry = _log.Add(client, method, url, allowed: false, status: status, note: note,
                             reason: reason, whitelist: whitelist, user: user);
        RecordHeaders(entry, context.Request.Headers, isResponse: false, credential: null);
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/plain";
        return context.Response.WriteAsync(message + "\n");
    }

    private void RecordHeaders(TrafficEntry entry, IHeaderDictionary headers, bool isResponse,
                               CredentialValue? credential)
    {
        if (_headerStore is null)
            return;

        try
        {
            var json = HeaderCapture.ToJson(headers, _headersMaxBytes, credential);
            _headerStore.AddHeaders(entry, isResponse ? null : json, isResponse ? json : null);
        }
        catch (ArgumentException e)
        {
            // Text that cannot be encoded.  Recording is not to get in the way of the request.
            _logger.LogWarning("Could not record headers for {Url}: {Message}", entry.Url, e.Message);
        }
    }

    /// <summary>
    /// Determines the one and only URL that a request is going to.
    /// </summary>
    /// <remarks>
    /// The whitelist gets to see this URL, and it is what is forwarded, so that there can
    /// be no difference in interpretation between the two.  The host comes from the CONNECT
    /// request or the request line, but not from the Host header which is not trusted:
    /// if it disagrees the request is refused, or else a client could reach
    /// other sites hosted at a whitelisted server (domain fronting).
    /// </remarks>
    private static Uri? GetDestination(HttpContext context, Tunnel? tunnel, out string? problem)
    {
        var request = context.Request;
        string scheme;
        Authority target;

        if (tunnel is not null)
        {
            scheme = "https";
            target = tunnel.Target;
        }
        else
        {
            var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
            if (!rawTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                problem = "This is a proxy: requests must be sent with an absolute http:// URL, or CONNECT.";
                return null;
            }

            int start = "http://".Length;
            int end = rawTarget.AsSpan(start).IndexOfAny('/', '?', '#');
            var authorityText = end < 0 ? rawTarget[start..] : rawTarget.Substring(start, end);
            if (!Authority.TryParse(authorityText, defaultPort: 80, out target))
            {
                problem = "The URL has an invalid host.";
                return null;
            }

            scheme = "http";
        }

        int defaultPort = tunnel is not null ? 443 : 80;
        if (request.Host.HasValue &&
            !(Authority.TryParse(request.Host.Value, defaultPort, out var hostHeader) && hostHeader == target))
        {
            problem = "The Host header does not match the host being connected to.";
            return null;
        }

        problem = null;
        return RequestUtilities.MakeDestinationAddress(
            $"{scheme}://{target.UrlHost}:{target.Port}", request.Path, request.QueryString);
    }

    private sealed class FixedDestination(Uri destination, string? credentialHeader, string? credentialValue)
        : HttpTransformer
    {
        public override async ValueTask TransformRequestAsync(HttpContext httpContext,
                                                              HttpRequestMessage proxyRequest,
                                                              string destinationPrefix,
                                                              CancellationToken cancellationToken)
        {
            await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);
            proxyRequest.RequestUri = destination;

            // Derive it from the URI.  HttpClient also takes the TLS server name from here.
            proxyRequest.Headers.Host = null;

            if (credentialHeader is not null)
            {
                proxyRequest.Headers.Remove(credentialHeader);
                proxyRequest.Headers.TryAddWithoutValidation(credentialHeader, credentialValue);
            }
        }
    }
}
