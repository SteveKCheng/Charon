using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Charon;

/// <summary>A validated host and port, with the host in canonical (lower) case.</summary>
internal readonly record struct Authority(string Host, int Port)
{
    /// <summary>The host as written in a URL: IPv6 addresses need brackets.</summary>
    public string UrlHost => Host.Contains(':') ? $"[{Host}]" : Host;

    /// <summary>
    /// Parses the "authority" part of an URI without the part with the user name/info.  
    /// </summary>
    /// <remarks>
    /// The accepted formats are "host:port", "[ipv6]:port", or if <paramref name="defaultPort"/> is
    /// non-zero, the same without the port.
    /// </remarks>
    public static bool TryParse(ReadOnlySpan<char> text, int defaultPort, out Authority authority)
    {
        authority = default;

        ReadOnlySpan<char> hostText;
        ReadOnlySpan<char> portText;
        string hostName;                // Canonicalized host name

        // Parse numerical IPv6 addresses in brackets
        if (text.StartsWith('['))
        {
            int end = text.IndexOf(']');
            if (end < 0)
                return false;

            var host = text[1..end];
            if (!IPAddress.TryParse(host, out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            hostName = address.ToString();

            // The rest of text must be empty or a port specification
            var rest = text[(end + 1)..];
            if (rest.Length == 0)
                portText = default;
            else if (rest[0] == ':')
                portText = rest[1..];
            else
                return false;
        }

        // IPv4 address, or host name
        else
        {
            int colon = text.IndexOf(':');
            hostText = colon < 0 ? text : text[..colon];
            portText = colon < 0 ? default : text[(colon + 1)..]; 

            // Manual loop (avoiding LINQ's memory allocations) to check for valid syntax
            // for a host name
            static bool HasOnlyValidChars(ReadOnlySpan<char> hostText)
            {
                foreach (var c in hostText)
                {
                    bool valid = char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_';
                    if (!valid) return false;
                }
                return true;
            }

            if (hostText.Length is 0 or > 253 || !HasOnlyValidChars(hostText))
                return false;

            Span<char> hostNameBuffer = stackalloc char[hostText.Length]; 
            hostText.ToLowerInvariant(hostNameBuffer);
            hostName = hostNameBuffer.ToString();
        }

        // Parse a port number expressed in ASCII digits.  This function
        // follows RFC 3986 [URI] §3.2.3, except the sequence of ASCII digits may not be empty.
        // (The exceptional case is handled outside this function.)
        static bool TryParsePort(ReadOnlySpan<char> portText, out int portNumber)
            => int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out portNumber) &&
               portNumber is > 0 and <= ushort.MaxValue;

        // Parse a port specification.  If portText is an empty string, the port will be
        // defaulted only when defaultPort > 0.  Note that an input of "host:" and "host"
        // is treated the same, since that's what RFC 3986 says.
        //
        // In the case of RFC 9110 [HTTP Semantics], §9.3.6 says a CONNECT request that targets
        // an empty or invalid port number MUST be rejected, which is effected here when
        // the caller sets defaultPort to zero.
        int portNumber = defaultPort;
        if (!(portText.Length > 0 ? TryParsePort(portText, out portNumber) : (defaultPort > 0)))
            return false;

        authority = new Authority(hostName, portNumber);
        return true;
    }
}
