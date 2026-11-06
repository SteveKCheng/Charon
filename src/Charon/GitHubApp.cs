using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Charon;

/// <summary>Identifies an installation of a GitHub App, in the credentials file.</summary>
internal sealed record GitHubAppConfig
{
    /// <summary>The App's ID or client ID.</summary>
    public required string AppId { get; init; }

    public required long InstallationId { get; init; }

    /// <summary>PEM file of the App's private key.</summary>
    public required string PrivateKeyFile { get; init; }

    /// <summary>Different from the default for GitHub Enterprise Server.</summary>
    public string ApiBase { get; init => field = value ?? ApiBaseDefault; } = ApiBaseDefault;

    /// <summary>The default value for <see cref="ApiBase" />. </summary>
    public const string ApiBaseDefault = "https://api.github.com";

    /// <summary>
    /// The App's permissions that tokens get: for example <c>{"actions": "write"}</c>.
    /// If null, they get all of them.  This only ever contracts, so if it is
    /// empty, tokens could do nothing, and none are issued.
    /// </summary>
    public Dictionary<string, string>? Permissions { get; init; }

    /// <summary>
    /// The repositories of the installation that tokens work on.  If null they work on all of
    /// them.  As for <see cref="Permissions"/>, none are issued if this is empty.
    /// </summary>
    public string[]? Repositories { get; init; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(GitHubAppTokenSource.TokenRequest))]
[JsonSerializable(typeof(GitHubAppTokenSource.TokenResponse))]
internal partial class GitHubAppJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Gets installation access tokens, which expire after an hour, from a GitHub App.
/// The App's private key is only used here.  Unlike the requests that the
/// tokens go in, the requests here do not originate from a client.
/// </summary>
internal sealed class GitHubAppTokenSource(GitHubAppConfig config, HttpMessageInvoker client) : ITokenSource
{
    /// <summary>Tokens with less time than this left are not used, as requests can take a while.</summary>
    private static readonly TimeSpan RenewalMargin = TimeSpan.FromMinutes(5);

    /// <summary>Time between attempts after a failure, so clients cannot make us hammer GitHub.</summary>
    private static readonly TimeSpan FailureCooldown = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions RequestOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    internal sealed record TokenRequest(
        [property: JsonPropertyName("permissions")] Dictionary<string, string>? Permissions,
        [property: JsonPropertyName("repositories")] string[]? Repositories);

    internal sealed record TokenResponse(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);
    
    private readonly SemaphoreSlim _lock = new(1);

    /// <summary>
    /// Sources for the scopes of users.  Users with the same scope share tokens, and
    /// each scope has its own failures, so that one user's mistake leaves the others working.
    /// </summary>
    private readonly ConcurrentDictionary<string, GitHubAppTokenSource> _scoped = new();

    private volatile TokenResponse? _current;
    private DateTimeOffset _retryTime;
    private string? _failure;

    private static bool IsFresh(TokenResponse? token) =>
        token is not null && token.ExpiresAt - DateTimeOffset.UtcNow > RenewalMargin;

    public ITokenSource ForGrant(CredentialGrant grant)
    {
        var scoped = config with
        {
            Permissions = grant.HasPermissions ? grant.Permissions : config.Permissions,
            Repositories = grant.HasRepositories ? grant.Repositories : config.Repositories,
        };

        return _scoped.GetOrAdd(ScopeKey(scoped), static (_, state) => new GitHubAppTokenSource(state.scoped, state.client),
                                (scoped, client));
    }

    /// <summary>Makes a string that is the same for equal scopes.  Null and empty must differ.</summary>
    private static string ScopeKey(GitHubAppConfig scope)
    {
        var permissions = scope.Permissions?.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value}");
        var repositories = scope.Repositories?.Order(StringComparer.Ordinal);
        return (permissions is null ? "*" : "[" + string.Join(',', permissions) + "]") + "\n" +
               (repositories is null ? "*" : "[" + string.Join(',', repositories) + "]");
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        // GitHub might well take these to mean no restriction, which is the opposite.
        if (config.Permissions is { Count: 0 } || config.Repositories is { Length: 0 })
            throw new CredentialUnavailableException("The scope of the token is empty, which allows nothing.");

        if (_current is { } current && IsFresh(current))
            return current.Token;

        await _lock.WaitAsync(cancellationToken);
        try
        {
            if (_current is { } renewed && IsFresh(renewed))
                return renewed.Token;

            if (DateTimeOffset.UtcNow < _retryTime)
                throw new CredentialUnavailableException(_failure!);

            try
            {
                var token = await RequestTokenAsync();
                _current = token;
                return token.Token;
            }
            catch (Exception e) when (e is not CredentialUnavailableException)
            {
                _failure = e is HttpRequestException or OperationCanceledException or TimeoutException
                    ? "Could not reach the GitHub API." : "Could not get a token from GitHub.";
                _retryTime = DateTimeOffset.UtcNow + FailureCooldown;
                throw new CredentialUnavailableException(_failure, e);
            }
            catch (CredentialUnavailableException e)
            {
                _failure = e.Message;
                _retryTime = DateTimeOffset.UtcNow + FailureCooldown;
                throw;
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<TokenResponse> RequestTokenAsync()
    {
        // Not the client's cancellation token: other clients may be waiting on this.
        using var timeout = new CancellationTokenSource(RequestTimeout);

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"{config.ApiBase.TrimEnd('/')}/app/installations/{config.InstallationId}/access_tokens");
        request.Headers.TryAddWithoutValidation("Authorization", MakeJsonWebToken());
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        request.Headers.TryAddWithoutValidation("User-Agent", "Charon");
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        request.Content = JsonContent.Create(new TokenRequest(config.Permissions, config.Repositories),
                                             jsonTypeInfo: GitHubAppJsonContext.Default.TokenRequest);            

        using var response = await client.SendAsync(request, timeout.Token);
        if (!response.IsSuccessStatusCode)
            throw new CredentialUnavailableException($"GitHub refused to issue a token: status {(int)response.StatusCode}.");

        return await response.Content.ReadFromJsonAsync(GitHubAppJsonContext.Default.TokenResponse, timeout.Token)
            ?? throw new CredentialUnavailableException("GitHub's response had no token.");
    }

    /// <summary>Makes the proof of the App's identity, as GitHub's documentation specifies it.</summary>
    private string MakeJsonWebToken()
    {
        string pem;
        try
        {
            PrivateFile.Check(config.PrivateKeyFile);
            pem = File.ReadAllText(config.PrivateKeyFile);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
        {
            throw new CredentialUnavailableException(e.Message, e);
        }

        using var key = RSA.Create();
        key.ImportFromPem(pem);

        // Backdated in case of clock drift.  GitHub allows at most 10 minutes of validity.
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Span<byte> outBuffer = stackalloc byte[512];  // Buffer for composing the final output
        byte[] tempBuffer = new byte[256];            // Buffer for intermediate outputs
        int outPos;                                   // Current writing position on outBuffer

        // Write prefix first, into outBuffer
        var prefix = "Bearer "u8;
        prefix.CopyTo(outBuffer);
        outPos = prefix.Length;
        
        static int ToBase64Url(ReadOnlySpan<byte> source, Span<byte> destination)
            => Base64Url.TryEncodeToUtf8(source, destination, out int bytesWritten)
                ? bytesWritten
                : throw new System.ArgumentException("Internal buffer for UTF-8 encoding is too short. This is a bug in Charon. "); 
        
        using (var jsonStream = new MemoryStream(tempBuffer))
        using (var jsonWriter = new Utf8JsonWriter(jsonStream))
        {
            // Write Base64Url(Header)
            jsonStream.SetLength(0);
            jsonWriter.WriteStartObject();
            jsonWriter.WriteString("alg"u8, "RS256"u8);
            jsonWriter.WriteString("typ"u8, "JWT"u8);
            jsonWriter.WriteEndObject();
            jsonWriter.Flush();
            outPos += ToBase64Url(tempBuffer[..(int)jsonStream.Length], outBuffer[outPos..]);
    
            // Write separator between Base64Url(Header) and Base64Url(Payload)
            outBuffer[outPos++] = (byte)'.';
    
            jsonWriter.Reset();

            // Write Base64Url(Payload)
            jsonStream.SetLength(0);
            jsonWriter.WriteStartObject();
            jsonWriter.WriteNumber("iat"u8, now - 60);
            jsonWriter.WriteNumber("exp"u8, now + 540);
            jsonWriter.WriteString("iss"u8, config.AppId);
            jsonWriter.WriteEndObject();
            jsonWriter.Flush();
            outPos += ToBase64Url(tempBuffer[..(int)jsonStream.Length], outBuffer[outPos..]);
        }

        // Form Signature(Base64Url(Header) + '.' + Base64Url(Payload))
        var signedPart = outBuffer[prefix.Length..outPos];
        int signatureLength = key.SignData(signedPart, tempBuffer,
                                           HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Append '.', then Base64Url(Signature(…)), to the output buffer
        outBuffer[outPos++] = (byte)'.';
        outPos += ToBase64Url(tempBuffer[..signatureLength], outBuffer[outPos..]);

        var outString = Encoding.ASCII.GetString(outBuffer[..outPos]);
        return outString;
    }
}
