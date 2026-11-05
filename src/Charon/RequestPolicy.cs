using Microsoft.AspNetCore.Http.Features;

namespace Charon;

/// <summary>What a rule of the whitelist can grant.</summary>
internal enum Capability { Get, Post, Put, GetWithBody, WebSocket, Count }

/// <summary>
/// Rejects requests that say one thing in the parts that the whitelist looks at, while
/// asking for something else in a way some servers or frameworks would act upon.
/// </summary>
/// <remarks>
/// Whitelisting a URL means trusting its server to be well-behaved, but not to be free of
/// loopholes.  This is defense in depth against them.  It is not content inspection:
/// everything here is a yes-or-no test of the form of a request, and bodies are not read.
/// </remarks>
internal static class RequestPolicy
{
    /// <summary>
    /// Headers that make the method or URL differ from those in the request line, or that
    /// claim to be from a trusted proxy in front of the server.  Nothing legitimate in a
    /// sandbox needs them, so there is no way to allow them.
    /// </summary>
    private static readonly string[] ForbiddenHeaders =
    [
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Original-URL", "X-Rewrite-URL", "X-Original-Method",
        "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Forwarded-Server", "X-Host", "X-Real-IP",
    ];

    /// <summary>The equivalents of the override headers in query strings.</summary>
    private static readonly string[] ForbiddenQueryParameters =
    [
        "_method", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    ];

    /// <summary>Times to decode a path, to see through it being encoded multiple times.</summary>
    private const int MaxPathDecodings = 3;

    public static Capability? ForMethod(string method) => method.ToUpperInvariant() switch
    {
        "GET" or "HEAD" or "OPTIONS" => Capability.Get,
        "POST" => Capability.Post,
        "PUT" or "PATCH" or "DELETE" => Capability.Put,
        _ => null,
    };

    /// <summary>The type of rule, as written in the whitelist, that grants a capability.</summary>
    public static string RuleType(Capability capability) => capability switch
    {
        Capability.Get => "GET",
        Capability.Post => "POST",
        Capability.Put => "PUT",
        Capability.GetWithBody => "GET-BODY",
        Capability.WebSocket => "WEBSOCKET",
        _ => throw new ArgumentOutOfRangeException(nameof(capability)),
    };

    /// <summary>Gets what a request needs a rule to grant, or null if nothing can grant it.</summary>
    public static Capability? GetRequiredCapability(HttpContext context)
    {
        var request = context.Request;

        // WebSockets over HTTP/2 use CONNECT, where over HTTP/1.1 they use GET.
        if (context.Features.Get<IHttpExtendedConnectFeature>() is { IsExtendedConnect: true } connect)
            return IsWebSocket(connect.Protocol) ? Capability.WebSocket : null;

        if (context.Features.Get<IHttpUpgradeFeature>()?.IsUpgradableRequest == true)
        {
            return HttpMethods.IsGet(request.Method) && IsWebSocket(request.Headers.Upgrade)
                ? Capability.WebSocket : null;
        }

        var capability = ForMethod(request.Method);
        return capability == Capability.Get && HasBody(context) ? Capability.GetWithBody : capability;
    }

    private static bool IsWebSocket(string? protocol) =>
        string.Equals(protocol, "websocket", StringComparison.OrdinalIgnoreCase);

    private static bool HasBody(HttpContext context) =>
        context.Request.ContentLength is { } length
            ? length > 0
            : context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody != false;

    /// <summary>Checks for what is not allowed whatever the rules say.</summary>
    /// <param name="request">The request.</param>
    /// <param name="destination">Where the request is to be forwarded.</param>
    /// <returns>Explanation for the client, or null if there is no problem.</returns>
    public static string? FindViolation(HttpRequest request, Uri destination)
    {
        foreach (var header in ForbiddenHeaders)
        {
            if (request.Headers.ContainsKey(header))
                return $"The header {header} is not allowed through this proxy.";
        }

        if (request.QueryString.HasValue)
        {
            foreach (var parameter in ForbiddenQueryParameters)
            {
                if (request.Query.ContainsKey(parameter))
                    return $"The query parameter {parameter} is not allowed through this proxy.";
            }
        }

        if (HasEncodedTraversal(destination.AbsolutePath))
            return "Encoded \"..\" path segments are not allowed through this proxy.";

        return null;
    }

    /// <summary>
    /// Detects a path that would go up a level once a server has decoded it.  The ordinary
    /// kind has been resolved by now, so that the whitelist sees the result.  But, encoded
    /// slashes must be preserved: they are not separators in the path as far as the HTTP
    /// standards go, and legitimately occur in npm's and GitLab's URLs.
    /// </summary>
    private static bool HasEncodedTraversal(string path)
    {
        if (!path.Contains(".."))
        {
            // Dots might yet be encoded, but only within something encoded twice.
            if (!path.Contains("%25"))
                return false;
        }

        for (int i = 0; i < MaxPathDecodings; i++)
        {
            path = Uri.UnescapeDataString(path);
            foreach (var segment in path.Split('/', '\\'))
            {
                // Some Java servers take ";..." as parameters of the segment.
                if (segment.AsSpan().StartsWith("..") && (segment.Length == 2 || segment[2] == ';'))
                    return true;
            }
        }

        return false;
    }
}
