using System.Net;
using System.Text;
using System.Text.Json;

namespace Charon.Tests;

/// <summary>Credentials must reach only their servers, and never the client.</summary>
[Collection("charon")]
public sealed class CredentialTests(Harness h)
{
    private string Url(string path) => $"https://localhost:{h.HttpsPort}{path}";

    private async Task<JsonElement> GetUpstreamHeadersAsync(string url, string? clientAuthorization = null)
    {
        using var client = h.MakeClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (clientAuthorization is not null)
            request.Headers.TryAddWithoutValidation("Authorization", clientAuthorization);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Harness.ParseEcho(await response.Content.ReadAsStringAsync()).GetProperty("headers");
    }

    private static string? Header(JsonElement headers, string name) =>
        headers.TryGetProperty(name, out var value) ? value.GetString() : null;

    [Fact]
    public async Task BearerTokenIsAdded() =>
        Assert.Equal($"Bearer {Harness.StaticToken}",
                     Header(await GetUpstreamHeadersAsync(Url("/api/bearer")), "Authorization"));

    [Fact]
    public async Task WhatTheClientSendsIsReplaced() =>
        Assert.Equal($"Bearer {Harness.StaticToken}",
                     Header(await GetUpstreamHeadersAsync(Url("/api/bearer"), "Bearer dummy"), "Authorization"));

    [Fact]
    public async Task BasicAuthentication() =>
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"x-access-token:{Harness.StaticToken}")),
                     Header(await GetUpstreamHeadersAsync(Url("/api/basic")), "Authorization"));

    [Fact]
    public async Task HeaderOtherThanAuthorization()
    {
        var headers = await GetUpstreamHeadersAsync(Url("/api/key"), "Bearer dummy");
        Assert.Equal(Harness.StaticToken, Header(headers, "x-api-key"));
        Assert.Equal("Bearer dummy", Header(headers, "Authorization"));
    }

    [Fact]
    public async Task OtherUrlsOfTheServerGetNothing() =>
        Assert.Null(Header(await GetUpstreamHeadersAsync(Url("/api/other")), "Authorization"));

    [Fact]
    public async Task OtherHostOfTheSameServerGetsNothing() =>
        Assert.Null(Header(await GetUpstreamHeadersAsync($"https://127.0.0.1:{h.HttpsPort}/api/bearer"), "Authorization"));

    [Fact]
    public async Task PlainHttpGetsNothing() =>
        Assert.Null(Header(await GetUpstreamHeadersAsync($"http://localhost:{h.HttpPort}/api/bearer"), "Authorization"));

    [Fact]
    public async Task HostHeaderCannotAttractACredential()
    {
        var marker = $"/api/bearer/{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"127.0.0.1:{h.HttpsPort}", "127.0.0.1");
        var response = await Harness.ExchangeAsync(tls,
            $"GET {marker} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 421", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task RedirectsAreLeftToTheClient()
    {
        // If the proxy were to follow them, the header it added might go along.
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        var response = await Harness.ExchangeAsync(tls,
            $"GET /api/bearer/redirect HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 302", response);
        Assert.False(h.UpstreamSaw("/api/bearer/redirected"));
    }

    [Fact]
    public async Task WhitelistStillApplies()
    {
        // The credential's URL pattern, unanchored, matches here; the whitelist does not.
        using var client = h.MakeClient();
        var marker = $"/denied/api/bearer/{Guid.NewGuid()}";
        var response = await client.GetAsync(Url(marker));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task ChangedTokenFileTakesEffect()
    {
        var path = h.TokenFile;
        try
        {
            File.WriteAllText(path, "rotated\n");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(5));
            Assert.Equal("Bearer rotated", Header(await GetUpstreamHeadersAsync(Url("/api/bearer/rotation")), "Authorization"));
        }
        finally
        {
            File.WriteAllText(path, Harness.StaticToken);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(10));
        }
    }

    [Fact]
    public async Task GitHubAppTokenIsObtainedOnceAndScoped()
    {
        var first = Header(await GetUpstreamHeadersAsync(Url("/api/app/1")), "Authorization");
        var second = Header(await GetUpstreamHeadersAsync(Url("/api/app/2")), "Authorization");

        Assert.StartsWith("Bearer ghs_installation_42_", first);
        Assert.Equal(first, second);
        Assert.Equal(1, h.TokenRequestCount(Harness.GoodInstallation));

        var scope = JsonDocument.Parse(h.TokenRequests.First(r => r.Installation == Harness.GoodInstallation).Scope).RootElement;
        Assert.Equal("write", scope.GetProperty("permissions").GetProperty("actions").GetString());
        Assert.Equal("proj", scope.GetProperty("repositories")[0].GetString());
    }

    [Fact]
    public async Task GitHubAppTokenNearExpiryIsRenewed()
    {
        var first = Header(await GetUpstreamHeadersAsync(Url("/api/short/1")), "Authorization");
        var second = Header(await GetUpstreamHeadersAsync(Url("/api/short/2")), "Authorization");
        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData("/api/refused")]
    [InlineData("/api/no-file")]
    public async Task FailureToGetTokenStopsTheRequest(string path)
    {
        var marker = $"{path}/{Guid.NewGuid()}";
        using var client = h.MakeClient();
        var response = await client.GetAsync(Url(marker));
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.False(h.UpstreamSaw(marker));
        Assert.DoesNotContain("do not repeat", text);
        Assert.DoesNotContain(h.Directory, text);
    }

    [Fact]
    public async Task FailuresDoNotHammerTheServer()
    {
        using var client = h.MakeClient();
        for (int i = 0; i < 5; i++)
            await client.GetAsync(Url("/api/refused/again"));
        Assert.Equal(1, h.TokenRequestCount(Harness.BadInstallation));
    }

    [Fact]
    public async Task WebUiNamesTheCredentialButDoesNotShowIt()
    {
        await GetUpstreamHeadersAsync(Url("/api/bearer/in-ui"));

        using var ui = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var response = await ui.GetAsync($"http://127.0.0.1:{h.UiPort}/api/traffic",
                                               HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(timeout.Token));

        while (await reader.ReadLineAsync(timeout.Token) is { } line)
        {
            Assert.DoesNotContain(Harness.StaticToken, line);
            if (line.Contains("/api/bearer/in-ui") && line.Contains("Credential bearer"))
                return;
        }
    }
}

public sealed class CredentialConfigTests
{
    private static readonly HttpMessageInvoker Client = new(new SocketsHttpHandler());

    private static int Parse(string json)
    {
        CredentialStore.Parse(json, Client, out int count);
        return count;
    }

    [Fact]
    public void AcceptsCommentsAndGitHubApps() => Assert.Equal(2, Parse("""
        [
          // Comments are useful in here.
          { "name": "a", "origin": "https://example.com", "url": "^https://example\\.com/x", "tokenFile": "/t" },
          { "name": "b", "origin": "https://example.com:8443", "url": ".",
            "gitHubApp": { "appId": "1", "installationId": 2, "privateKeyFile": "/k" } },
        ]
        """));

    [Fact]
    public async Task OmittedSettingsGetTheirDefaults()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "secret");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var json = $$"""[{ "name": "a", "origin": "https://x.test", "url": ".", "tokenFile": "{{path}}" }]""";
            var credential = CredentialStore.Parse(json, Client, out _)["https://x.test"].Single();

            Assert.Equal("Authorization", credential.Header);
            Assert.Equal("Bearer secret", (await credential.GetValueAsync(default)).HeaderValue);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void OmittedApiBaseGetsItsDefault()
    {
        var config = JsonSerializer.Deserialize(
            """[{ "name": "a", "origin": "https://x.test", "url": ".", "gitHubApp": { "appId": "1", "installationId": 2, "privateKeyFile": "/k" } }]""",
            CredentialStoreJsonContext.Default.CredentialConfigArray)!;

        Assert.Equal("https://api.github.com", config[0].GitHubApp!.ApiBase);
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("example.com")]
    [InlineData("https://example.com/path")]
    [InlineData("https://user@example.com")]
    [InlineData("https://example.com?x=1")]
    public void OriginMustBeJustHttps(string origin) => Assert.Throws<FormatException>(() => Parse($$"""
        [{ "name": "a", "origin": "{{origin}}", "url": ".", "tokenFile": "/t" }]
        """));

    [Theory]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "url": "." }""")]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "tokenFile": "/t" }""")]
    [InlineData("""{ "origin": "https://x.test", "url": ".", "tokenFile": "/t" }""")]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "url": "(", "tokenFile": "/t" }""")]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "url": ".", "tokenFile": "/t", "header": "a b" }""")]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "url": ".", "tokenFile": "/t", "orgin": "x" }""")]
    [InlineData("""{ "name": "a", "origin": "https://x.test", "url": ".", "tokenFile": "/t", "gitHubApp": { "appId": "1", "installationId": 2, "privateKeyFile": "/k" } }""")]
    public void InvalidEntriesAreRejected(string entry) =>
        Assert.Throws<FormatException>(() => Parse($"[{entry}]"));

    [Fact]
    public void ParseErrorsDoNotQuoteTheFile()
    {
        var e = Assert.Throws<FormatException>(() => Parse("""[{ "name": "a", "origin": ghp_secret }]"""));
        Assert.DoesNotContain("ghp_secret", e.Message);
    }

    [Fact]
    public async Task FilesOthersCanReadAreRefused()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "secret");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            await Assert.ThrowsAsync<CredentialUnavailableException>(
                async () => await new FileTokenSource(path).GetTokenAsync(default));

            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Assert.Equal("secret", await new FileTokenSource(path).GetTokenAsync(default));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CredentialsFileOthersCanReadIsNotLoaded()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """[{ "name": "a", "origin": "https://x.test", "url": ".", "tokenFile": "/t" }]""");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
            using var store = new CredentialStore(path, Client);
            Assert.Null(store.Find(new Uri("https://x.test/")));

            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            using var secure = new CredentialStore(path, Client);
            Assert.NotNull(secure.Find(new Uri("https://x.test/")));
            Assert.Null(secure.Find(new Uri("https://x.test:8443/")));
            Assert.Null(secure.Find(new Uri("http://x.test/")));
            Assert.Null(secure.Find(new Uri("https://evil.test/https://x.test/")));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task TokenWithLineBreakIsRefused()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "secret\r\nEvil: header\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var config = new CredentialConfig { Name = "a", Origin = "https://x.test", Url = "." };
            var credential = new Credential(config, new(""), new FileTokenSource(path));
            await Assert.ThrowsAsync<CredentialUnavailableException>(
                async () => await credential.GetValueAsync(default));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
