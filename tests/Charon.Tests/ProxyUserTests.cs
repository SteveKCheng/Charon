using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Charon.Tests;

/// <summary>What the users of the proxy get, and in particular, that they get no more.</summary>
[Collection("charon")]
public sealed class ProxyUserTests(Harness h)
{
    private string Head(string path, string extra = "") =>
        $"GET {path} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\n{extra}Connection: close\r\n\r\n";

    private async Task<string> GetAsUserAsync(string user, string path)
    {
        await using var tls = await h.OpenTunnelAsUserAsync(user, user + "-pw", $"localhost:{h.HttpsPort}", "localhost");
        return await Harness.ExchangeAsync(tls, Head(path));
    }

    private async Task<string> GetAnonymouslyAsync(string path, string extra = "")
    {
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        return await Harness.ExchangeAsync(tls, Head(path, extra));
    }

    private static string? Token(string response) => Regex.Match(response, "ghs_installation_[0-9]+_[0-9]+") is { Success: true } m ? m.Value : null;

    /// <summary>Finds out what scope a token was issued for, from the stand-in for GitHub.</summary>
    private JsonElement ScopeOf(string token)
    {
        int index = int.Parse(token[(token.LastIndexOf('_') + 1)..]);
        lock (h.TokenRequests)
            return JsonDocument.Parse(h.TokenRequests[index - 1].Scope).RootElement;
    }

    private static string[] Repositories(JsonElement scope) =>
        scope.GetProperty("repositories").EnumerateArray().Select(e => e.GetString()!).ToArray();

    [Fact]
    public async Task UserGetsTokenOfItsOwnScope()
    {
        var scope = ScopeOf(Token(await GetAsUserAsync("alice", "/api/scoped/1"))!);
        Assert.Equal(["alice-repo"], Repositories(scope));
        Assert.Equal("read", scope.GetProperty("permissions").GetProperty("contents").GetString());
        Assert.False(scope.GetProperty("permissions").TryGetProperty("actions", out _));
    }

    [Fact]
    public async Task AnonymousClientGetsTheDefaultScope()
    {
        var scope = ScopeOf(Token(await GetAnonymouslyAsync("/api/scoped/2"))!);
        Assert.Equal(["proj"], Repositories(scope));
        Assert.Equal("write", scope.GetProperty("permissions").GetProperty("actions").GetString());
    }

    [Fact]
    public async Task UsersOfTheSameScopeShareATokenAndOthersDoNot()
    {
        var alice = Token(await GetAsUserAsync("alice", "/api/scoped/3"));
        var bob = Token(await GetAsUserAsync("bob", "/api/scoped/4"));
        var anonymous = Token(await GetAnonymouslyAsync("/api/scoped/5"));
        Assert.Equal(alice, bob);
        Assert.NotEqual(alice, anonymous);
    }

    [Fact]
    public async Task NullAndEmptyAreDifferentScopes()
    {
        // Were they mistaken for the same, an empty scope could get a token with no restriction.
        Assert.NotNull(Token(await GetAsUserAsync("judy", "/api/scoped/14")));
        Assert.StartsWith("HTTP/1.1 502", await GetAsUserAsync("frank", "/api/scoped/15"));

        Assert.NotNull(Token(await GetAsUserAsync("carol", "/api/scoped/16")));
        Assert.StartsWith("HTTP/1.1 502", await GetAsUserAsync("erin", "/api/scoped/17"));
    }

    [Fact]
    public async Task OrderDoesNotMakeAScopeDifferent() => Assert.Equal(
        Token(await GetAsUserAsync("heidi", "/api/scoped/12")),
        Token(await GetAsUserAsync("ivan", "/api/scoped/13")));

    [Fact]
    public async Task AbsentSettingsInheritAndNullLiftsTheRestriction()
    {
        // carol sets repositories to null, leaving permissions out.
        var carol = ScopeOf(Token(await GetAsUserAsync("carol", "/api/scoped/6"))!);
        Assert.False(carol.TryGetProperty("repositories", out _));
        Assert.Equal("write", carol.GetProperty("permissions").GetProperty("actions").GetString());

        // dave leaves out both, which is not the same.
        var dave = ScopeOf(Token(await GetAsUserAsync("dave", "/api/scoped/7"))!);
        Assert.Equal(["proj"], Repositories(dave));
        Assert.Equal("write", dave.GetProperty("permissions").GetProperty("actions").GetString());
    }

    [Theory]
    [InlineData("erin")]
    [InlineData("frank")]
    public async Task EmptyScopeGetsNoTokenAndLeavesOthersWorking(string user)
    {
        var marker = $"/api/scoped/{Guid.NewGuid()}";
        int before;
        lock (h.TokenRequests)
            before = h.TokenRequests.Count;

        var response = await GetAsUserAsync(user, marker);

        Assert.StartsWith("HTTP/1.1 502", response);
        Assert.False(h.UpstreamSaw(marker));
        lock (h.TokenRequests)
            Assert.Equal(before, h.TokenRequests.Count);

        Assert.NotNull(Token(await GetAsUserAsync("alice", "/api/scoped/8")));
    }

    [Fact]
    public async Task EmptyScopeInTheCredentialsFileGetsNoToken()
    {
        var response = await GetAnonymouslyAsync("/api/empty-main");
        Assert.StartsWith("HTTP/1.1 502", response);
        Assert.Equal(0, h.TokenRequestCount(Harness.EmptyInstallation));
    }

    [Fact]
    public async Task UnlistedCredentialFallsBackToTheDefault()
    {
        Assert.Contains(Harness.StaticToken, await GetAsUserAsync("grace", "/api/bearer/grace"));

        var scope = ScopeOf(Token(await GetAsUserAsync("grace", "/api/scoped/grace"))!);
        Assert.Equal(["proj"], Repositories(scope));
        Assert.Equal("write", scope.GetProperty("permissions").GetProperty("actions").GetString());
    }

    [Fact]
    public async Task EmptyScopeIsHowToDenyACredentialToAUser()
    {
        // It works for a token from a file too, since those refuse any settings.
        var marker = $"/api/key/{Guid.NewGuid()}";
        Assert.StartsWith("HTTP/1.1 502", await GetAsUserAsync("alice", marker));
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task ListedCredentialWithNoSettingsIsGiven() =>
        Assert.Contains(Harness.StaticToken, await GetAsUserAsync("alice", "/api/bearer/alice"));

    [Fact]
    public async Task PasswordCanBeGivenAsAHash() =>
        Assert.NotNull(Token(await GetAsUserAsync("bob", "/api/scoped/9")));

    [Theory]
    [InlineData("alice", "wrong")]
    [InlineData("nobody", "alice-pw")]
    [InlineData("alice", "")]
    public async Task WrongCredentialsAreNotTreatedAsAnonymous(string user, string password)
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"CONNECT localhost:{h.HttpsPort} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\n" +
            $"Proxy-Authorization: {Harness.BasicAuthorization(user, password)}\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 407", response);
        Assert.Contains("Proxy-Authenticate: Basic", response);
    }

    [Theory]
    [InlineData("Basic !!!not-base64")]
    [InlineData("Basic YWxpY2U=")]             // "alice" with no colon
    [InlineData("Bearer alice-pw")]
    public async Task MalformedCredentialsAreRefused(string value)
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"CONNECT localhost:{h.HttpsPort} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nProxy-Authorization: {value}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", response);
    }

    [Fact]
    public async Task WrongCredentialsOnPlainRequestAreRefused()
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}{marker} HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\n" +
            $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "wrong")}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 407", response);
        Assert.Contains("Proxy-Authenticate: Basic", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task HeadersInsideATunnelCannotChangeWhoItIsFor()
    {
        var authorization = $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "alice-pw")}\r\n";

        // A correct password for alice, from inside an anonymous tunnel.
        var anonymous = ScopeOf(Token(await GetAnonymouslyAsync("/api/scoped/10", authorization))!);
        Assert.Equal(["proj"], Repositories(anonymous));

        // And a wrong one, inside a tunnel of a user.
        await using var tls = await h.OpenTunnelAsUserAsync("bob", "bob-pw", $"localhost:{h.HttpsPort}", "localhost");
        var response = await Harness.ExchangeAsync(tls, Head("/api/scoped/11",
            $"Proxy-Authorization: {Harness.BasicAuthorization("erin", "wrong")}\r\n"));
        Assert.Equal(["alice-repo"], Repositories(ScopeOf(Token(response)!)));
        Assert.DoesNotContain("Proxy-Authorization", response, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EachPlainRequestIdentifiesItself()
    {
        var first = Guid.NewGuid().ToString();
        var second = Guid.NewGuid().ToString();
        await using var stream = await h.ConnectRawAsync();
        await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}/allowed/{first} HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\n" +
            $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "alice-pw")}\r\n\r\n" +
            $"GET http://localhost:{h.HttpPort}/allowed/{second} HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\n" +
            "Connection: close\r\n\r\n");

        Assert.Equal("alice", await h.WaitForTrafficAsync(
            $"SELECT user FROM requests WHERE url LIKE '%{first}'", r => r.GetString(0)));
        Assert.True(await h.WaitForTrafficAsync(
            $"SELECT user IS NULL FROM requests WHERE url LIKE '%{second}'", r => r.GetBoolean(0)));
    }

    [Fact]
    public async Task UserAndWrongPasswordsAreRecorded()
    {
        var marker = Guid.NewGuid().ToString();
        await GetAsUserAsync("alice", $"/denied/{marker}");
        Assert.Equal("alice", await h.WaitForTrafficAsync(
            $"SELECT user FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));

        await using var stream = await h.ConnectRawAsync();
        await Harness.ExchangeAsync(stream,
            $"CONNECT wrong-password.test:443 HTTP/1.1\r\nProxy-Authorization: {Harness.BasicAuthorization("alice", "nope")}\r\n\r\n");
        Assert.Equal("wrong proxy credentials", await h.WaitForTrafficAsync(
            "SELECT reason FROM requests WHERE url = 'wrong-password.test:443'", r => r.GetString(0)));
    }

    [Fact]
    public async Task ChangesApplyToTunnelsThatAreOpen()
    {
        var original = File.ReadAllText(h.UsersFile);
        var tunnel = await h.OpenTunnelAsUserAsync("dave", "dave-pw", $"localhost:{h.HttpsPort}", "localhost");
        try
        {
            File.WriteAllText(h.UsersFile, original.Replace("""{ "name": "dave", "password": "dave-pw", "credentials": { "scoped": {} } },""", ""));

            // A new tunnel being refused shows that the file was reloaded.
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (true)
            {
                await using var probe = await h.ConnectRawAsync();
                await probe.WriteAsync(Encoding.ASCII.GetBytes(
                    $"CONNECT localhost:{h.HttpsPort} HTTP/1.1\r\n" +
                    $"Proxy-Authorization: {Harness.BasicAuthorization("dave", "dave-pw")}\r\n\r\n"));
                if ((await Harness.ReadHeadAsync(probe)).StartsWith("HTTP/1.1 407"))
                    break;

                Assert.True(DateTime.UtcNow < deadline, "The change did not take effect");
                await Task.Delay(100);
            }

            var response = await Harness.ExchangeAsync(tunnel, Head("/api/scoped/removed"));
            Assert.StartsWith("HTTP/1.1 407", response);
        }
        finally
        {
            await tunnel.DisposeAsync();
            File.WriteAllText(h.UsersFile, original);
            await Task.Delay(1500);
        }
    }
}

/// <summary>Everyone having to identify themselves, which is an option.</summary>
/// <remarks>In the collection to not run at the same time as the others, as ports could clash.</remarks>
[Collection("charon")]
public sealed class RequiredAuthenticationTests : IAsyncLifetime
{
    private readonly Harness _h = new() { RequireProxyAuthentication = true };

    public Task InitializeAsync() => _h.InitializeAsync();

    public Task DisposeAsync() => _h.DisposeAsync();

    [Fact]
    public async Task AnonymousClientsAreAskedForCredentials()
    {
        await using var stream = await _h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"CONNECT localhost:{_h.HttpsPort} HTTP/1.1\r\nHost: localhost:{_h.HttpsPort}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", response);
        Assert.Contains("Proxy-Authenticate: Basic", response);

        await using var plain = await _h.ConnectRawAsync();
        Assert.StartsWith("HTTP/1.1 407", await Harness.ExchangeAsync(plain,
            $"GET http://localhost:{_h.HttpPort}/allowed/x HTTP/1.1\r\nHost: localhost:{_h.HttpPort}\r\nConnection: close\r\n\r\n"));
    }

    [Fact]
    public async Task ClientThatWaitsToBeAskedGetsThrough()
    {
        // .NET's HttpClient works this way, as git does by default.
        using var client = _h.MakeClient(proxyCredentials: new NetworkCredential("grace", "grace-pw"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"https://localhost:{_h.HttpsPort}/allowed/x")).StatusCode);
    }
}

public sealed class ProxyUserConfigTests
{
    private static Dictionary<string, ProxyUser> Parse(string json) => ProxyUserStore.Parse(json);

    [Fact]
    public void AbsentNullAndEmptyAreDistinct()
    {
        var grants = Parse("""
            [{ "name": "a", "password": "p", "credentials": {
                 "absent": {},
                 "null": { "repositories": null, "permissions": null },
                 "empty": { "repositories": [], "permissions": {} } } }]
            """)["a"].Credentials;

        Assert.False(grants["absent"].HasRepositories);
        Assert.False(grants["absent"].HasPermissions);

        Assert.True(grants["null"].HasRepositories);
        Assert.True(grants["null"].HasPermissions);
        Assert.Null(grants["null"].Repositories);
        Assert.Null(grants["null"].Permissions);

        Assert.True(grants["empty"].HasRepositories);
        Assert.True(grants["empty"].HasPermissions);
        Assert.Empty(grants["empty"].Repositories!);
        Assert.Empty(grants["empty"].Permissions!);
    }

    [Theory]
    [InlineData("""{ "name": "a" }""")]
    [InlineData("""{ "name": "a", "password": "p", "passwordSha256": "00" }""")]
    [InlineData("""{ "name": "a", "passwordSha256": "not hex" }""")]
    [InlineData("""{ "name": "a", "passwordSha256": "00" }""")]
    [InlineData("""{ "name": "a:b", "password": "p" }""")]
    [InlineData("""{ "name": "", "password": "p" }""")]
    [InlineData("""{ "password": "p" }""")]
    [InlineData("""{ "name": "a", "password": "p", "credential": {} }""")]
    [InlineData("""{ "name": "a", "password": "p", "credentials": { "c": { "repository": [] } } }""")]
    public void InvalidEntriesAreRejected(string entry) =>
        Assert.Throws<FormatException>(() => Parse($"[{entry}]"));

    [Fact]
    public void DuplicateNamesAreRejected() => Assert.Throws<FormatException>(() => Parse("""
        [{ "name": "a", "password": "p" }, { "name": "a", "password": "q" }]
        """));

    [Fact]
    public void ParseErrorsDoNotQuoteTheFile()
    {
        var e = Assert.Throws<FormatException>(() => Parse("""[{ "name": "a", "password": hunter2 }]"""));
        Assert.DoesNotContain("hunter2", e.Message);
    }

    [Fact]
    public void FileOthersCanReadIsNotLoaded()
    {
        var path = Path.GetTempFileName();
        var credentials = new CredentialStore(path + ".none", new HttpMessageInvoker(new SocketsHttpHandler()));
        try
        {
            File.WriteAllText(path, """[{ "name": "a", "password": "p" }]""");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
            using var store = new ProxyUserStore(path, false, credentials);
            Assert.Null(store.Find("a"));

            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            using var secure = new ProxyUserStore(path, false, credentials);
            Assert.NotNull(secure.Find("a"));
        }
        finally
        {
            File.Delete(path);
            credentials.Dispose();
        }
    }

    [Fact]
    public void MissingFileMeansCredentialsGivenAreRefusedAndAnonymousIsAllowed()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        using var credentials = new CredentialStore(path, new HttpMessageInvoker(new SocketsHttpHandler()));
        using var store = new ProxyUserStore(path, false, credentials);

        Assert.True(store.TryAuthenticate(null, out var user));
        Assert.Null(user);
        Assert.False(store.TryAuthenticate(Harness.BasicAuthorization("a", "p"), out _));
    }
}
