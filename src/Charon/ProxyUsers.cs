using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Charon;

/// <summary>Decides who a client of the proxy is.</summary>
/// <remarks>
/// A listener has one of these, so that listeners can go about this differently.  For a Unix
/// domain socket dedicated to one user, the socket itself says who the client is.
/// </remarks>
internal interface IClientAuthenticator
{
    /// <summary>Identifies a client from what it sent.</summary>
    /// <param name="proxyAuthorization">The value of its Proxy-Authorization header, if any.</param>
    /// <param name="userName">The name of the user, or null for an anonymous client.</param>
    /// <returns>False if the client is to be refused, and asked for credentials.</returns>
    bool TryAuthenticate(string? proxyAuthorization, out string? userName);
}

/// <summary>What a user gets of a credential, in the file of users.</summary>
/// <remarks>
/// <para>
/// These properties have three states.  If absent, what is in the file of credentials applies.
/// Otherwise, they replace it, with null meaning no restriction, and an empty
/// value meaning nothing, for which no token is issued.
/// </para>
/// <para>
/// The setters must stay as they are, not "init".  Source-generated deserialization
/// assigns init-only properties even when they are absent from the JSON, which
/// would turn "absent" into "no restriction" without anybody noticing.
/// </para>
/// </remarks>
internal sealed class CredentialGrant
{
    /// <summary>Same as <see cref="GitHubAppConfig.Permissions"/>.</summary>
    public Dictionary<string, string>? Permissions
    {
        get;
        set { field = value; HasPermissions = true; }
    }

    /// <summary>Same as <see cref="GitHubAppConfig.Repositories"/>.</summary>
    public string[]? Repositories
    {
        get;
        set { field = value; HasRepositories = true; }
    }

    /// <summary>Whether <see cref="Permissions"/> overrides what is in the file of credentials.</summary>
    [JsonIgnore]
    public bool HasPermissions { get; private set; }

    /// <summary>Whether <see cref="Repositories"/> overrides what is in the file of credentials.</summary>
    [JsonIgnore]
    public bool HasRepositories { get; private set; }
}

/// <summary>How a user is described in the file of users.</summary>
internal sealed class ProxyUserConfig
{
    /// <summary>The user name, to give to the proxy.</summary>
    public required string Name { get; init; }

    /// <summary>The password in the clear.</summary>
    public string? Password { get; init; }

    /// <summary>The SHA-256 hash of the password in hexadecimal, as an alternative.</summary>
    public string? PasswordSha256 { get; init; }

    /// <summary>
    /// Absolute path of a Unix domain socket to listen on for this user alone, who then
    /// needs no password.
    /// </summary>
    public string? Socket { get; init; }

    /// <summary>
    /// How credentials differ for this user, by name.  For those
    /// not listed, it gets the same as an anonymous client.
    /// </summary>
    public Dictionary<string, CredentialGrant>? Credentials { get; init; }
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    AllowTrailingCommas = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(ProxyUserConfig[]))]
internal partial class ProxyUserJsonContext : JsonSerializerContext
{
}

/// <summary>An identified client of the proxy.</summary>
/// <param name="Name">The user name.</param>
/// <param name="PasswordHash">The hash of its password, or null if it only uses its socket.</param>
/// <param name="Socket">Path of its Unix domain socket, if it has one.</param>
/// <param name="Credentials">How credentials differ for it.</param>
internal sealed record ProxyUser(string Name, byte[]? PasswordHash, string? Socket,
                                 Dictionary<string, CredentialGrant> Credentials);

/// <summary>
/// The users of the proxy.  These are to limit the damage from an agent making
/// a mistake, by opting in to narrower credentials for it.  It knows its password, so
/// this is no security boundary between agents.
/// </summary>
internal sealed class ProxyUserStore : IClientAuthenticator, IDisposable
{
    private const string BasicPrefix = "Basic ";

    private readonly bool _requireAuthentication;
    private readonly CredentialStore _credentials;
    private readonly ILogger? _logger;
    private readonly PolledFile _file;

    private volatile Dictionary<string, ProxyUser> _users = new();

    /// <summary>Loads a file if it exists, and follows changes to it.</summary>
    /// <param name="path">Path to the file.</param>
    /// <param name="requireAuthentication">Whether anonymous clients are refused.</param>
    /// <param name="credentials">For checking the names of credentials.</param>
    /// <param name="logger">Receives reports of problems with the file.</param>
    public ProxyUserStore(string path, bool requireAuthentication, CredentialStore credentials, ILogger? logger = null)
    {
        _requireAuthentication = requireAuthentication;
        _credentials = credentials;
        _logger = logger;
        _file = new PolledFile(path, Load, () => _users = new(), logger);
    }

    public void Dispose() => _file.Dispose();

    private void Load(string path)
    {
        PrivateFile.Check(path);
        _users = Parse(File.ReadAllText(path));
        _logger?.LogInformation("Loaded {Count} users from {Path}", _users.Count, path);

        foreach (var user in _users.Values)
        {
            foreach (var name in user.Credentials.Keys)
            {
                if (!_credentials.Contains(name))
                    _logger?.LogWarning("User {User} refers to unknown credential {Name}", user.Name, name);
            }
        }
    }

    internal static Dictionary<string, ProxyUser> Parse(string json)
    {
        ProxyUserConfig[]? configs;
        try
        {
            configs = JsonSerializer.Deserialize(json, ProxyUserJsonContext.Default.ProxyUserConfigArray);
        }
        catch (JsonException e)
        {
            // JsonException can quote the text around the error, which might be a password.
            throw new FormatException($"Invalid JSON at line {e.LineNumber + 1}.");
        }

        var users = new Dictionary<string, ProxyUser>();

        foreach (var config in configs ?? [])
        {
            if (config.Name.Length == 0 || config.Name.Contains(':') || config.Name.Any(char.IsControl))
                throw new FormatException("A user has an invalid name: it cannot contain a colon.");

            if (config.Password is not null && config.PasswordSha256 is not null)
                throw new FormatException($"User {config.Name} cannot have both password and passwordSha256.");

            if (config.Password is null && config.PasswordSha256 is null && config.Socket is null)
                throw new FormatException($"User {config.Name} must have a password or a socket.");

            if (config.Socket is { } socket && !UnixSockets.IsValidPath(socket))
            {
                throw new FormatException(
                    $"User {config.Name} has an invalid socket: it must be an absolute path of " +
                    $"at most {UnixSockets.MaxPathLength} bytes.");
            }

            byte[]? hash = null;
            try
            {
                if (config.Password is { } password)
                    hash = Hash(password);
                else if (config.PasswordSha256 is { } passwordHash)
                    hash = Convert.FromHexString(passwordHash);
            }
            catch (FormatException)
            {
                throw new FormatException($"User {config.Name} has an invalid passwordSha256.");
            }

            if (hash is not null && hash.Length != SHA256.HashSizeInBytes)
                throw new FormatException($"User {config.Name} has an invalid passwordSha256.");

            if (config.Socket is not null && users.Values.Any(user => user.Socket == config.Socket))
                throw new FormatException($"The socket of user {config.Name} is that of another user.");

            if (!users.TryAdd(config.Name, new ProxyUser(config.Name, hash, config.Socket, config.Credentials ?? new())))
                throw new FormatException($"There is more than one user named {config.Name}.");
        }

        return users;
    }

    private static byte[] Hash(string password) => SHA256.HashData(Encoding.UTF8.GetBytes(password));

    /// <summary>The users that have sockets of their own.</summary>
    public IEnumerable<ProxyUser> UsersWithSockets => _users.Values.Where(user => user.Socket is not null);

    /// <summary>Gets a user by name, which fails if it has since been removed.</summary>
    public ProxyUser? Find(string name) => _users.GetValueOrDefault(name);

    /// <remarks>
    /// Credentials that are given are always checked.  Wrong ones must not get
    /// treated as anonymous, which may well be allowed more than the user would be.
    /// </remarks>
    public bool TryAuthenticate(string? proxyAuthorization, out string? userName)
    {
        userName = null;

        if (string.IsNullOrEmpty(proxyAuthorization))
            return !_requireAuthentication;

        if (!proxyAuthorization.StartsWith(BasicPrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(proxyAuthorization[BasicPrefix.Length..].Trim()));
        }
        catch (FormatException)
        {
            return false;
        }

        int colon = decoded.IndexOf(':');
        if (colon < 0 || Find(decoded[..colon]) is not { PasswordHash: { } passwordHash } user)
            return false;

        if (!CryptographicOperations.FixedTimeEquals(Hash(decoded[(colon + 1)..]), passwordHash))
            return false;

        userName = user.Name;
        return true;
    }
}
