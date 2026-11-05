using System.Net;

namespace Charon;

/// <summary>Settings, bound from the "Charon" configuration section.</summary>
public sealed class CharonOptions
{
    private static readonly string ConfigDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "charon");

    /// <summary>Address that the proxy and the Web UI listen on.</summary>
    public string ListenAddress { get; set; } = IPAddress.Loopback.ToString();

    public int ProxyPort { get; set; } = 8080;

    public int UiPort { get; set; } = 8081;

    /// <summary>Same format as the whitelist of the mitmproxy-whitelist add-in.</summary>
    public string WhitelistFile { get; set; } = Path.Combine(ConfigDirectory, "whitelist.txt");

    /// <summary>PEM certificate of the interception CA; generated if it does not exist.</summary>
    public string CaCertificateFile { get; set; } = Path.Combine(ConfigDirectory, "ca.crt");

    /// <summary>PEM private key of the CA. May be the same file as the certificate.</summary>
    public string CaKeyFile { get; set; } = Path.Combine(ConfigDirectory, "ca.key");

    /// <summary>If set, these roots replace the system's for validating upstream servers.</summary>
    public string? UpstreamRootsFile { get; set; }

    /// <summary>If set, connect to upstream servers through this HTTP proxy.</summary>
    public string? UpstreamProxy { get; set; }

    /// <summary>
    /// Longest pause allowed in the data of a forwarded exchange.  YARP's default of
    /// 100 seconds is too short for LLM APIs, which can think for a while between tokens.
    /// </summary>
    public TimeSpan ActivityTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Number of requests retained for display in the Web UI.</summary>
    public int TrafficLogCapacity { get; set; } = 10_000;
}
