using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace Charon;

/// <summary>Where the proxy and the Web UI listen, as given in the settings.</summary>
internal static partial class ListenAddresses
{
    public const string Forms = "an IPv4 address and port such as 127.0.0.1:8080, " +
                                "an IPv6 address in brackets and port such as [::1]:8080, " +
                                "or the absolute path of a Unix domain socket";

    /// <summary>
    /// IPv4 addresses must have all four parts, as <see cref="IPAddress.Parse(string)"/> would
    /// otherwise take "1:80" for 0.0.0.1, port 80.
    /// </summary>
    [GeneratedRegex(@"^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+$")]
    private static partial Regex IPv4WithPort();

    [GeneratedRegex(@"^\[[^\]]+\]:[0-9]+$")]
    private static partial Regex IPv6WithPort();

    /// <summary>Reads one address, which is either an <see cref="IPEndPoint"/> or a Unix domain socket.</summary>
    /// <exception cref="FormatException">It is neither, with a message saying why.</exception>
    public static EndPoint Parse(string text)
    {
        if (text.StartsWith('/'))
        {
            if (!UnixSockets.IsValidPath(text))
                throw new FormatException($"The path of the socket \"{text}\" is longer than {UnixSockets.MaxPathLength} bytes.");
            return new UnixDomainSocketEndPoint(text);
        }

        if ((IPv4WithPort().IsMatch(text) || IPv6WithPort().IsMatch(text)) &&
            IPEndPoint.TryParse(text, out var endPoint))
        {
            if (endPoint.Port == 0)
                throw new FormatException($"\"{text}\" needs a port that is not 0.");
            return endPoint;
        }

        throw new FormatException($"\"{text}\" is not {Forms}.");
    }

    /// <summary>Reads the addresses of both settings, which together must not repeat any.</summary>
    /// <exception cref="InvalidOperationException">An address cannot be listened on.</exception>
    public static (EndPoint[] Proxy, EndPoint[] Ui) ParseSettings(CharonOptions options)
    {
        var seen = new HashSet<string>();
        EndPoint[] ParseSetting(string setting, string[] addresses) => addresses.Select(text =>
        {
            EndPoint endPoint;
            try
            {
                endPoint = Parse(text);
            }
            catch (FormatException e)
            {
                throw new InvalidOperationException($"In the setting {setting}: {e.Message}");
            }

            if (!seen.Add(Key(endPoint)))
                throw new InvalidOperationException($"In the setting {setting}: \"{text}\" is listened on already.");
            return endPoint;
        }).ToArray();

        return (ParseSetting(nameof(options.ProxyListen), options.ProxyListen ?? CharonOptions.DefaultProxyListen),
                ParseSetting(nameof(options.UiListen), options.UiListen ?? CharonOptions.DefaultUiListen));
    }

    /// <summary>Has Kestrel listen on an address from <see cref="Parse"/>.</summary>
    /// <remarks>
    /// Kestrel cannot bind where a socket was left behind by a process that died, so that is
    /// removed first.  Anything else in the way is an error: these addresses are not
    /// reloaded, so unlike the sockets of users, there is no point in trying again later.
    /// </remarks>
    public static void Listen(KestrelServerOptions kestrel, EndPoint endPoint, Action<ListenOptions> configure)
    {
        if (endPoint is UnixDomainSocketEndPoint && !UnixSockets.TryPrepare(endPoint.ToString()!, out var problem))
            throw new IOException($"Cannot listen on {endPoint}: {problem}");

        kestrel.Listen(endPoint, configure);
    }

    /// <summary>
    /// The same for all ways of writing an address, such as "[::1]" and "[0::1]", so that
    /// addresses can be compared: for paths, that is only as they are written.
    /// </summary>
    public static string Key(EndPoint endPoint) => endPoint.ToString()!;

    /// <summary>How a client is shown in the traffic log.</summary>
    public static string NameOfClient(EndPoint? endPoint) => endPoint is IPEndPoint ip ? ip.ToString() : "unix";
}
