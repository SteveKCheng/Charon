namespace Charon;

/// <summary>Settings, bound from the "Charon" configuration section.</summary>
public sealed class CharonOptions
{
    private static readonly string ConfigDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "charon");

    public static readonly string[] DefaultProxyListen = ["127.0.0.1:8080"];

    public static readonly string[] DefaultUiListen = ["127.0.0.1:8081"];

    /// <summary>
    /// Addresses that the proxy listens on: <see cref="ListenAddresses.Forms"/>.
    /// Null means <see cref="DefaultProxyListen"/>, and empty means none.  The default is not
    /// assigned here, as binding configuration would add to it instead of replacing it.
    /// </summary>
    public string[]? ProxyListen { get; set; }

    /// <summary>Addresses that the Web UI listens on, in the same way as <see cref="ProxyListen"/>.</summary>
    public string[]? UiListen { get; set; }

    /// <summary>Same format as the whitelist of the mitmproxy-whitelist add-in.</summary>
    public string WhitelistFile { get; set; } = Path.Combine(ConfigDirectory, "whitelist.txt");

    /// <summary>
    /// JSON file of credentials to add to requests.  It and the files it refers
    /// to must be kept out of sandboxes, and be accessible by their owner only.
    /// </summary>
    public string CredentialsFile { get; set; } = Path.Combine(ConfigDirectory, "credentials.json");

    /// <summary>
    /// JSON file of the users of the proxy, for giving them narrower credentials.
    /// It should not be accessible from sandboxes, and must be private to its owner.
    /// </summary>
    public string ProxyUsersFile { get; set; } = Path.Combine(ConfigDirectory, "users.json");

    /// <summary>
    /// Whether clients must identify themselves as a user.  If not, those that do not get
    /// the credentials as they are in the credentials file.  Clients that
    /// wait to be asked for their password then never send it, like git by default.
    /// </summary>
    public bool RequireProxyAuthentication { get; set; }

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

    /// <summary>
    /// SQLite database to record requests in, so that they can be analyzed at any time.
    /// Set to an empty string to not have one.  Like the files of the
    /// CA, it should be kept away from sandboxes.
    /// </summary>
    public string TrafficDatabaseFile { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".local", "state", "charon", "traffic.db");

    /// <summary>How long requests stay in the database.</summary>
    public TimeSpan TrafficRetention { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Size that the database is kept under, by removing its oldest requests.  There has to be a
    /// limit, or else a client could fill the disk just by making requests.
    /// </summary>
    public long TrafficDatabaseMaxBytes { get; set; } = 256L * 1024 * 1024;

    /// <summary>
    /// Whether to record the headers of requests and responses in the database.  They are as
    /// received from the client, so without injected credentials, and with the values
    /// of the usual headers for secrets replaced.  Each request takes up much more space.
    /// </summary>
    public bool TrafficHeaders { get; set; }

    /// <summary>Limit on what is recorded of the headers of a single request or response.</summary>
    public int TrafficHeadersMaxBytes { get; set; } = 16 * 1024;

    /// <summary>Number of requests retained for display in the Web UI.</summary>
    public int TrafficLogCapacity { get; set; } = 10_000;

    /// <summary>Reads the settings, refusing any that are not known so that misspellings do not go unnoticed.</summary>
    public static CharonOptions Load(IConfiguration configuration) =>
        configuration.GetSection("Charon").Get<CharonOptions>(binder => binder.ErrorOnUnknownConfiguration = true)
        ?? new CharonOptions();
}
