using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Charon;

/// <summary>A credential could not be obtained.  The message contains no secrets.</summary>
internal sealed class CredentialUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>Where the secret of a credential comes from.</summary>
internal interface ITokenSource
{
    /// <exception cref="CredentialUnavailableException">The token cannot be had.</exception>
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);

    /// <summary>Gets the source for the tokens of a user, which can have a different scope.</summary>
    /// <exception cref="CredentialUnavailableException">Tokens of this source have no scope to set.</exception>
    ITokenSource ForGrant(CredentialGrant grant);
}

/// <summary>What goes in the header of a request for a credential.</summary>
/// <param name="HeaderValue">The value to set the header to.</param>
/// <param name="Secrets">The forms in which the secret appears in the value.</param>
internal sealed record CredentialValue(string HeaderValue, string[] Secrets)
{
    /// <summary>Whether some text gives away the secret.</summary>
    public bool AppearsIn(string text) => Secrets.Any(s => text.Contains(s, StringComparison.Ordinal));
}

/// <summary>How a credential is described in the credentials file.</summary>
internal sealed record CredentialConfig
{
    /// <summary>Identifies the credential in logs and in the Web UI.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// The server that gets the credential, as "https://host" or "https://host:port".
    /// This is separate from <see cref="Url"/> so that an overly lax regular expression
    /// cannot result in a secret going to another site.
    /// </summary>
    public required string Origin { get; init; }

    /// <summary>Regular expression for the URLs at the origin that get the credential.</summary>
    public required string Url { get; init; }

    /// The default value for <see cref="Header" /> if not specified.
    public const string DefaultHeader = "Authorization";

    /// <summary>Header to set.  Any value for it from the client is replaced.</summary>
    public string Header { get; init => field = value ?? DefaultHeader; } = DefaultHeader;

    /// The default value for <see cref="Scheme" /> if not specified.
    public const string DefaultScheme = "Bearer";

    /// <summary>Text before the token in the header value, if any.</summary>
    public string Scheme { get; init => field = value ?? DefaultScheme; } = DefaultScheme;

    /// <summary>If set, send HTTP Basic authentication for this user, with the token as password.</summary>
    public string? BasicUser { get; init; }

    /// <summary>File containing the token.  Changes to it take effect immediately.</summary>
    public string? TokenFile { get; init; }

    /// <summary>Get short-lived tokens from a GitHub App, instead of having a fixed token.</summary>
    public GitHubAppConfig? GitHubApp { get; init; }
}

/// <summary>A secret to add to requests, for the agent to use without being able to read it.</summary>
internal sealed class Credential(CredentialConfig config, Regex url, ITokenSource source)
{
    public string Name => config.Name;

    public string Header => config.Header;

    public bool Matches(string destinationUrl) => url.IsMatch(destinationUrl);

    /// <summary>Gets the value to set the header to.</summary>
    /// <param name="cancellationToken">For giving up.</param>
    /// <param name="grant">What a user gets of this credential, or null for the credential as it is.</param>
    /// <exception cref="CredentialUnavailableException">The token cannot be had.</exception>
    public async ValueTask<CredentialValue> GetValueAsync(CancellationToken cancellationToken,
                                                          CredentialGrant? grant = null)
    {
        var token = await (grant is null ? source : source.ForGrant(grant)).GetTokenAsync(cancellationToken);

        if (token.Length == 0 || token.Any(char.IsControl))
            throw new CredentialUnavailableException("The token is empty or has control characters.");

        if (config.BasicUser is { } user)
        {
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{token}"));
            return new CredentialValue("Basic " + encoded, [token, encoded]);
        }

        return new CredentialValue(config.Scheme.Length > 0 ? $"{config.Scheme} {token}" : token, [token]);
    }
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, 
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, 
    AllowTrailingCommas = true,
    ReadCommentHandling =  JsonCommentHandling.Skip)]
[JsonSerializable(typeof(CredentialConfig[]))]
internal partial class CredentialStoreJsonContext : JsonSerializerContext
{
}

/// <summary>The credentials to inject, which are never to be visible to the sandbox.</summary>
internal sealed class CredentialStore : IDisposable
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private readonly HttpMessageInvoker _client;
    private readonly ILogger? _logger;
    private readonly PolledFile _file;

    private volatile Dictionary<string, List<Credential>> _byOrigin = new();

    /// <summary>Loads a file if it exists, and follows changes to it.</summary>
    /// <param name="path">Path to the file.</param>
    /// <param name="client">For requesting tokens from servers.</param>
    /// <param name="logger">Receives reports of problems with the file.</param>
    public CredentialStore(string path, HttpMessageInvoker client, ILogger? logger = null)
    {
        _client = client;
        _logger = logger;
        _file = new PolledFile(path, Load, () => _byOrigin = new(), logger);
    }

    public void Dispose() => _file.Dispose();

    private void Load(string path)
    {
        PrivateFile.Check(path);
        _byOrigin = Parse(File.ReadAllText(path), _client, out int count);
        _logger?.LogInformation("Loaded {Count} credentials from {Path}", count, path);
    }

    /// <summary>Whether there is a credential of some name.</summary>
    public bool Contains(string name) => _byOrigin.Values.Any(list => list.Any(c => c.Name == name));

    /// <summary>Finds the first credential, in the order of the file, for a URL.</summary>
    /// <param name="destination">Where the request is actually going.</param>
    public Credential? Find(Uri destination)
    {
        if (!_byOrigin.TryGetValue(destination.GetLeftPart(UriPartial.Authority), out var candidates))
            return null;

        var url = destination.AbsoluteUri;

        try
        {
            return candidates.Find(c => c.Matches(url));
        }
        catch (RegexMatchTimeoutException)
        {
            _logger?.LogWarning("Timed out matching credentials for {Url}", url);
            return null;
        }
    }

    internal static Dictionary<string, List<Credential>> Parse(string json, HttpMessageInvoker client, out int count)
    {
        CredentialConfig[]? configs;
        try
        {
            configs = JsonSerializer.Deserialize<CredentialConfig[]>(json,
                CredentialStoreJsonContext.Default.CredentialConfigArray);
        }
        catch (JsonException e)
        {
            // JsonException can quote the text around the error, which might be a secret.
            throw new FormatException($"Invalid JSON at line {e.LineNumber + 1}.");
        }

        var byOrigin = new Dictionary<string, List<Credential>>();
        count = 0;

        foreach (var config in configs ?? [])
        {
            var origin = ParseOrigin(config);

            if (config.Name.Length == 0 || config.Name.Any(char.IsControl))
                throw new FormatException("A credential has an invalid name.");

            if (config.Header.Length == 0 || !config.Header.All(IsHeaderNameChar))
                throw new FormatException($"Credential {config.Name} has an invalid header name.");

            if ((config.TokenFile is null) == (config.GitHubApp is null))
                throw new FormatException($"Credential {config.Name} must have one of tokenFile or gitHubApp.");

            Regex url;
            try
            {
                url = new Regex(config.Url, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MatchTimeout);
            }
            catch (ArgumentException e)
            {
                throw new FormatException($"Credential {config.Name} has an invalid regular expression: {e.Message}");
            }

            ITokenSource source = config.TokenFile is { } tokenFile
                ? new FileTokenSource(tokenFile)
                : new GitHubAppTokenSource(config.GitHubApp!, client);

            if (!byOrigin.TryGetValue(origin, out var list))
                byOrigin[origin] = list = new List<Credential>(1);
            list.Add(new Credential(config, url, source));
            count++;
        }

        return byOrigin;
    }

    private static string ParseOrigin(CredentialConfig config)
    {
        if (!Uri.TryCreate(config.Origin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.UserInfo.Length > 0 ||
            uri.PathAndQuery != "/" ||
            uri.Fragment.Length > 0)
        {
            throw new FormatException(
                $"Credential {config.Name} needs an origin like https://example.com: " +
                "secrets are not to be sent in the clear.");
        }

        return uri.GetLeftPart(UriPartial.Authority);
    }

    private static bool IsHeaderNameChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c);
}

/// <summary>Files containing secrets, which are required to be inaccessible to other users.</summary>
internal static class PrivateFile
{
    private const UnixFileMode OtherUsers =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <exception cref="FormatException">Others have access to the file.</exception>
    public static void Check(string path)
    {
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & OtherUsers) != 0)
            throw new FormatException($"{path} must not be accessible to other users: try chmod 600.");
    }
}

/// <summary>A long-lived token kept in a file, such as a personal access token or API key.</summary>
internal sealed class FileTokenSource(string path) : ITokenSource
{
    private sealed record Cached(DateTime LastWriteTime, string Token);

    private volatile Cached? _cached;

    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var lastWriteTime = File.GetLastWriteTimeUtc(path);
            var cached = _cached;
            if (cached?.LastWriteTime != lastWriteTime)
            {
                PrivateFile.Check(path);
                _cached = cached = new Cached(lastWriteTime, File.ReadAllText(path).Trim());
            }

            return ValueTask.FromResult(cached.Token);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
        {
            throw new CredentialUnavailableException(e.Message, e);
        }
    }

    public ITokenSource ForGrant(CredentialGrant grant)
    {
        // Silently handing out the token would give more than what was written.
        if (grant.HasPermissions || grant.HasRepositories)
            throw new CredentialUnavailableException("A token from a file cannot be limited by a user's settings.");

        return this;
    }
}
