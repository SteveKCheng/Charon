using System.Net;
using System.Net.Sockets;

namespace Charon;

/// <summary>A validated host and port, with the host in canonical (lower) case.</summary>
internal readonly record struct Authority(string Host, int Port)
{
    /// <summary>The host as written in a URL: IPv6 addresses need brackets.</summary>
    public string UrlHost => Host.Contains(':') ? $"[{Host}]" : Host;

    /// <summary>
    /// Parses "host:port", "[ipv6]:port", or if <paramref name="defaultPort"/> is
    /// non-zero, the same without the port.  Anything not plainly one of those is
    /// rejected, because the result decides where the proxy connects to.
    /// </summary>
    public static bool TryParse(string text, int defaultPort, out Authority authority)
    {
        authority = default;

        string host;
        string? port = null;

        if (text.StartsWith('['))
        {
            int end = text.IndexOf(']');
            if (end < 0)
                return false;

            host = text[1..end];
            if (!IPAddress.TryParse(host, out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            host = address.ToString();
            var rest = text.AsSpan(end + 1);
            if (rest.Length > 0)
            {
                if (rest[0] != ':')
                    return false;
                port = rest[1..].ToString();
            }
        }
        else
        {
            int colon = text.IndexOf(':');
            host = colon < 0 ? text : text[..colon];
            port = colon < 0 ? null : text[(colon + 1)..];

            if (host.Length is 0 or > 253 ||
                !host.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_'))
                return false;

            host = host.ToLowerInvariant();
        }

        int portNumber = defaultPort;
        if (port is not null &&
            (!port.All(char.IsAsciiDigit) || !int.TryParse(port, out portNumber)))
            return false;

        if (portNumber is < 1 or > 65535)
            return false;

        authority = new Authority(host, portNumber);
        return true;
    }
}
