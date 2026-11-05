using System.Buffers.Text;
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
    public string ApiBase { get; init; } = "https://api.github.com";

    /// <summary>
    /// If set, tokens get only these of the App's permissions: for example
    /// <c>{"actions": "write"}</c>.  Otherwise, tokens get all of them.
    /// </summary>
    public Dictionary<string, string>? Permissions { get; init; }

    /// <summary>If set, tokens only work on these repositories of the installation.</summary>
    public string[]? Repositories { get; init; }
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

    private sealed record TokenRequest(
        [property: JsonPropertyName("permissions")] Dictionary<string, string>? Permissions,
        [property: JsonPropertyName("repositories")] string[]? Repositories);

    private sealed record TokenResponse(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

    private readonly SemaphoreSlim _lock = new(1);

    private volatile TokenResponse? _current;
    private DateTimeOffset _retryTime;
    private string? _failure;

    private static bool IsFresh(TokenResponse? token) =>
        token is not null && token.ExpiresAt - DateTimeOffset.UtcNow > RenewalMargin;

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
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
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + MakeJsonWebToken());
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        request.Headers.TryAddWithoutValidation("User-Agent", "Charon");
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        request.Content = JsonContent.Create(new TokenRequest(config.Permissions, config.Repositories),
                                             options: RequestOptions);

        using var response = await client.SendAsync(request, timeout.Token);
        if (!response.IsSuccessStatusCode)
            throw new CredentialUnavailableException($"GitHub refused to issue a token: status {(int)response.StatusCode}.");

        return await response.Content.ReadFromJsonAsync<TokenResponse>(timeout.Token)
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
        var header = """{"alg":"RS256","typ":"JWT"}""";
        var payload = JsonSerializer.Serialize(new { iat = now - 60, exp = now + 540, iss = config.AppId });

        var signedPart = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header)) + "." +
                         Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload));
        var signature = key.SignData(Encoding.ASCII.GetBytes(signedPart),
                                     HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return signedPart + "." + Base64Url.EncodeToString(signature);
    }
}
