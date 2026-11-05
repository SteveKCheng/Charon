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
    private readonly HttpMessageInvoker _upstream;
    private readonly ForwarderRequestConfig _requestConfig;

    public ForwardProxy(IHttpForwarder forwarder, Whitelist whitelist, TrafficLog log, CharonOptions options)
    {
        _forwarder = forwarder;
        _whitelist = whitelist;
        _log = log;
        _requestConfig = new ForwarderRequestConfig { ActivityTimeout = options.ActivityTimeout };

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

        _upstream = new HttpMessageInvoker(handler);
    }

    public async Task HandleAsync(HttpContext context)
    {
        var tunnel = ProxyListener.GetTunnel(context.Features);
        if (tunnel is not null)
            Interlocked.Increment(ref tunnel.RequestCount);

        var request = context.Request;
        var client = context.Connection.RemoteIpAddress + ":" + context.Connection.RemotePort;

        // WebSockets over HTTP/2 use CONNECT, where over HTTP/1.1 they use GET.
        var isExtendedConnect = context.Features.Get<IHttpExtendedConnectFeature>()?.IsExtendedConnect == true;
        var method = isExtendedConnect ? HttpMethods.Get : request.Method;

        if (HttpMethods.IsConnect(method))
        {
            // Only the first request of a connection can be CONNECT: see ProxyListener.
            context.Response.Headers.Connection = "close";
            await RefuseAsync(context, client, StatusCodes.Status405MethodNotAllowed,
                              request.Method, tunnel is null ? "(proxy)" : "(tunnel)",
                              "CONNECT must be the first request on a connection to this proxy.");
            return;
        }

        if (GetDestination(context, tunnel, out string? problem) is not { } destination)
        {
            await RefuseAsync(context, client,
                              tunnel is null ? StatusCodes.Status400BadRequest
                                             : StatusCodes.Status421MisdirectedRequest,
                              request.Method, context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "", problem!);
            return;
        }

        var url = destination.AbsoluteUri;

        if (!_whitelist.IsAllowed(method, url, destination.IdnHost.ToLowerInvariant()))
        {
            await RefuseAsync(context, client, StatusCodes.Status403Forbidden, request.Method, url,
                              $"Access Denied: '{url}' (method {request.Method}) is disallowed by the sandbox's whitelist.");
            return;
        }

        var entry = _log.Add(client, request.Method, url, allowed: true);
        long startTime = Stopwatch.GetTimestamp();

        var error = await _forwarder.SendAsync(context, destination.GetLeftPart(UriPartial.Authority), _upstream,
                                               _requestConfig, new FixedDestination(destination));

        _log.Update(entry with
        {
            Status = context.Response.StatusCode,
            DurationMs = Stopwatch.GetElapsedTime(startTime).TotalMilliseconds,
            Note = error == ForwarderError.None ? null : error.ToString(),
        });
    }

    private Task RefuseAsync(HttpContext context, string client, int status,
                             string method, string url, string message)
    {
        _log.Add(client, method, url, allowed: false, status: status);
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/plain";
        return context.Response.WriteAsync(message + "\n");
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

    private sealed class FixedDestination(Uri destination) : HttpTransformer
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
        }
    }
}
