using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Charon.Tests;

/// <summary>What the proxy records about real requests.</summary>
[Collection("charon")]
public sealed class TrafficRecordingTests(Harness h)
{
    private async Task<int> GetStatusAsync(string url)
    {
        using var client = h.MakeClient();
        return (int)(await client.GetAsync(url)).StatusCode;
    }

    private sealed record Row(string? Reason, string? Note, string? Rule, long? Line, string? Whitelist, long? Status);

    private Task<Row> FindAsync(string marker) => h.WaitForTrafficAsync(
        $"SELECT reason, note, rule, rule_line, whitelist, status FROM requests WHERE url LIKE '%{marker}%' AND status IS NOT NULL",
        r => new Row(r.IsDBNull(0) ? null : r.GetString(0), r.IsDBNull(1) ? null : r.GetString(1),
                     r.IsDBNull(2) ? null : r.GetString(2), r.IsDBNull(3) ? null : r.GetInt64(3),
                     r.IsDBNull(4) ? null : r.GetString(4), r.IsDBNull(5) ? null : r.GetInt64(5)));

    [Fact]
    public async Task AllowedRequestRecordsTheRuleAndTheStatus()
    {
        var marker = Guid.NewGuid().ToString();
        Assert.Equal(200, await GetStatusAsync($"https://localhost:{h.HttpsPort}/allowed/{marker}"));

        var found = await FindAsync(marker);
        Assert.Null(found.Reason);
        Assert.Equal(200, found.Status);
        Assert.Equal(@"GET: ^https?://localhost:[0-9]+/allowed", found.Rule);

        var lines = File.ReadAllLines(h.WhitelistFile);
        Assert.Equal(found.Rule, lines[found.Line!.Value - 1].Trim());
    }

    [Theory]
    [InlineData("GET", "/denied", "no GET rule")]
    [InlineData("POST", "/denied", "no POST rule")]
    [InlineData("DELETE", "/denied", "no PUT rule")]
    [InlineData("PROPFIND", "/allowed/x", "no rule can allow this")]
    public async Task DenialsRecordTheReason(string method, string path, string reason)
    {
        var marker = Guid.NewGuid().ToString();
        using var client = h.MakeClient();
        await client.SendAsync(new HttpRequestMessage(
            new HttpMethod(method), $"https://localhost:{h.HttpsPort}{path}?{marker}"));

        var found = await FindAsync(marker);
        Assert.Equal(reason, found.Reason);
        Assert.Equal(403, found.Status);
        Assert.Null(found.Rule);
        Assert.NotNull(found.Whitelist);
    }

    [Fact]
    public async Task BodyAndWebSocketDenialsNameTheRuleTypeNeeded()
    {
        var marker = Guid.NewGuid().ToString();
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        await Harness.ExchangeAsync(tls,
            $"GET /allowed/{marker} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\n" +
            "Connection: close\r\nContent-Length: 1\r\n\r\nx");
        Assert.Equal("no GET-BODY rule", (await FindAsync(marker)).Reason);

        var socketMarker = Guid.NewGuid().ToString();
        using var socket = h.MakeWebSocket();
        await Assert.ThrowsAnyAsync<Exception>(() => socket.ConnectAsync(
            new Uri($"wss://localhost:{h.HttpsPort}/allowed/ws-{socketMarker}"), default));
        Assert.Equal("no WEBSOCKET rule", (await FindAsync(socketMarker)).Reason);
    }

    [Fact]
    public async Task ForbiddenRequestRecordsWhatWasWrong()
    {
        var marker = Guid.NewGuid().ToString();
        using var client = h.MakeClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{h.HttpsPort}/allowed/{marker}");
        request.Headers.Add("X-Original-URL", "/secret");
        await client.SendAsync(request);

        var found = await FindAsync(marker);
        Assert.Equal("forbidden request", found.Reason);
        Assert.Contains("X-Original-URL", found.Note);
    }

    [Fact]
    public async Task TunnelWithoutHttpRecordsTheReason()
    {
        var port = h.RawPort;
        await using var stream = await h.ConnectRawAsync();
        await Harness.ExchangeAsync(stream, $"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\nnot TLS\r\n");

        Assert.Equal("no HTTP in tunnel", await h.WaitForTrafficAsync(
            $"SELECT reason FROM requests WHERE url = '127.0.0.1:{port}' AND method = 'CONNECT'", r => r.GetString(0)));
    }

    [Fact]
    public async Task WhitelistContentsCanBeRecovered()
    {
        var marker = Guid.NewGuid().ToString();
        await GetStatusAsync($"https://localhost:{h.HttpsPort}/denied/{marker}");
        var hash = (await FindAsync(marker)).Whitelist;

        var contents = await h.WaitForTrafficAsync(
            $"SELECT contents FROM whitelists WHERE hash = '{hash}'", r => r.GetString(0));
        Assert.Contains("GET-BODY:", contents);
    }

    [Fact]
    public async Task InjectedCredentialIsNotWrittenToTheDatabase()
    {
        var marker = Guid.NewGuid().ToString();
        await GetStatusAsync($"https://localhost:{h.HttpsPort}/api/bearer/{marker}");
        Assert.Equal("Credential bearer", (await FindAsync(marker)).Note);

        foreach (var file in Directory.GetFiles(Path.GetDirectoryName(h.TrafficDatabaseFile)!))
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            Assert.DoesNotContain(Harness.StaticToken, Encoding.Latin1.GetString(buffer.ToArray()));
        }
    }

    [Fact]
    public async Task WebUiReportsTheStateOfTheDatabase()
    {
        using var ui = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        var root = JsonDocument.Parse(await ui.GetStringAsync($"http://127.0.0.1:{h.UiPort}/api/status")).RootElement;
        Assert.Equal(CharonApp.Version, root.GetProperty("version").GetString());
        Assert.Matches(@"^\d+\.\d+\.\d+.*\+[0-9a-f]{7,}(\.modified)?$", CharonApp.Version);

        var status = root.GetProperty("trafficDatabase");
        Assert.True(status.GetProperty("healthy").GetBoolean());
        Assert.Equal(0, status.GetProperty("droppedEvents").GetInt64());
    }
}

/// <summary>What gets recorded of headers: most importantly, what does not.</summary>
[Collection("charon")]
public sealed class HeaderRecordingTests(Harness h)
{
    private static Dictionary<string, string> Parse(string json) =>
        JsonDocument.Parse(json).RootElement.EnumerateArray()
            .ToDictionary(p => p[0].GetString()!, p => p[1].GetString()!, StringComparer.OrdinalIgnoreCase);

    private Task<string> FindAsync(string marker, string column) => h.WaitForTrafficAsync(
        $"""
        SELECT h.{column} FROM headers h JOIN requests r ON h.session = r.session AND h.id = r.id
        WHERE r.url LIKE '%{marker}%' AND h.{column} IS NOT NULL
        """, r => r.GetString(0));

    private async Task SendAsync(string path, params (string Name, string Value)[] headers)
    {
        using var client = h.MakeClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{h.HttpsPort}{path}");
        foreach (var (name, value) in headers)
            request.Headers.TryAddWithoutValidation(name, value);
        await client.SendAsync(request);
    }

    private void AssertNotInDatabaseFiles(string secret)
    {
        foreach (var file in Directory.GetFiles(Path.GetDirectoryName(h.TrafficDatabaseFile)!))
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            Assert.DoesNotContain(secret, Encoding.Latin1.GetString(buffer.ToArray()));
        }
    }

    [Fact]
    public async Task RequestAndResponseHeadersAreRecorded()
    {
        var marker = Guid.NewGuid().ToString();
        await SendAsync($"/allowed/{marker}", ("X-Custom", "client-value"));

        Assert.Equal("client-value", Parse(await FindAsync(marker, "request"))["X-Custom"]);
        Assert.Contains("application/json", Parse(await FindAsync(marker, "response"))["Content-Type"]);
    }

    [Fact]
    public async Task HeadersOfDeniedRequestsAreRecorded()
    {
        var marker = Guid.NewGuid().ToString();
        await SendAsync($"/denied/{marker}", ("X-HTTP-Method-Override", "DELETE"));
        Assert.Equal("DELETE", Parse(await FindAsync(marker, "request"))["X-HTTP-Method-Override"]);
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("Cookie")]
    [InlineData("X-Api-Key")]
    public async Task UsualHeadersForSecretsAreRedacted(string name)
    {
        var marker = Guid.NewGuid().ToString();
        var secret = Guid.NewGuid().ToString();
        await SendAsync($"/allowed/{marker}", (name, secret));

        Assert.Equal("[redacted]", Parse(await FindAsync(marker, "request"))[name]);
        AssertNotInDatabaseFiles(secret);
    }

    [Fact]
    public async Task InjectedCredentialIsNotRecorded()
    {
        var marker = Guid.NewGuid().ToString();
        await SendAsync($"/api/bearer/{marker}", ("Authorization", "Bearer dummy"));
        await FindAsync(marker, "response");
        AssertNotInDatabaseFiles(Harness.StaticToken);
    }

    [Fact]
    public async Task CredentialRepeatedInResponseHeadersIsScrubbed()
    {
        await SendAsync("/api/bearer/echo?scrub-bearer");
        var headers = Parse(await FindAsync("scrub-bearer", "response"));

        Assert.Equal("[redacted]", headers["X-Echo"]);
        Assert.Equal("[redacted]", headers["X-Echo-Token"]);
        Assert.Equal("[redacted]", headers["Set-Cookie"]);
        Assert.Equal("kept", headers["X-Innocent"]);
        AssertNotInDatabaseFiles(Harness.StaticToken);
    }

    [Fact]
    public async Task EncodedCredentialInResponseHeadersIsScrubbed()
    {
        await SendAsync("/api/basic/echo?scrub-basic");
        Assert.Equal("[redacted]", Parse(await FindAsync("scrub-basic", "response"))["X-Echo-Token"]);
    }

    [Fact]
    public async Task OversizedHeadersAreTruncated()
    {
        var marker = Guid.NewGuid().ToString();
        await SendAsync($"/allowed/{marker}", ("X-Small", "1"), ("X-Huge", new string('h', 100_000)));

        var json = await FindAsync(marker, "request");
        Assert.True(json.Length < 20_000, $"Length is {json.Length}");
        Assert.Contains("(truncated)", json);
    }

    [Fact]
    public async Task HeadersAreOffUnlessAskedFor()
    {
        var other = new Harness { RecordHeaders = false };
        await other.InitializeAsync();
        try
        {
            var marker = Guid.NewGuid().ToString();
            using var client = other.MakeClient();
            await client.GetAsync($"https://localhost:{other.HttpsPort}/allowed/{marker}");

            await other.WaitForTrafficAsync($"SELECT 1 FROM requests WHERE url LIKE '%{marker}%' AND status IS NOT NULL", r => r.GetInt64(0));
            Assert.Equal(0, await other.WaitForTrafficAsync("SELECT count(*) FROM headers", r => r.GetInt64(0)));
        }
        finally
        {
            await other.DisposeAsync();
        }
    }
}

/// <summary>The behaviour of the store itself, including when things go wrong.</summary>
public sealed class TrafficStoreTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("charon-store").FullName;
    private readonly Whitelist _whitelist;

    public TrafficStoreTests()
    {
        File.WriteAllText(WhitelistPath, "GET: ^https://x\\.test/\n");
        _whitelist = new Whitelist(WhitelistPath);
    }

    private string WhitelistPath => Path.Combine(_directory, "whitelist.txt");
    private string DatabasePath => Path.Combine(_directory, "new", "traffic.db");

    public void Dispose()
    {
        _whitelist.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private CharonOptions Options(long maxBytes = 1L << 30, TimeSpan? retention = null) => new()
    {
        TrafficDatabaseFile = DatabasePath,
        TrafficDatabaseMaxBytes = maxBytes,
        TrafficRetention = retention ?? TimeSpan.FromDays(14),
    };

    private long Scalar(string sql)
    {
        using var database = new SqliteConnection($"Data Source={DatabasePath};Pooling=False;Mode=ReadOnly");
        database.Open();
        using var command = database.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "Timed out");
            await Task.Delay(20);
        }
    }

    [Fact]
    public async Task RequestsSurviveARestartWithoutIdsColliding()
    {
        for (int run = 1; run <= 2; run++)
        {
            var log = new TrafficLog(10);
            var store = new TrafficStore(Options(), log, _whitelist);
            await store.StartAsync(default);
            log.Add("client", "GET", $"https://x.test/{run}", allowed: true);
            await store.StopAsync(default);
            await Task.Delay(5);   // Sessions are told apart by the time.
        }

        Assert.Equal(2, Scalar("SELECT count(*) FROM requests"));
        Assert.Equal(2, Scalar("SELECT count(*) FROM sessions"));
        Assert.Equal(2, Scalar("SELECT count(DISTINCT session) FROM requests"));
    }

    [Fact]
    public async Task EntriesInTheQueueAreWrittenOnStopping()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);
        for (int i = 0; i < 10_000; i++)
            log.Add("client", "GET", $"https://x.test/{i}", allowed: true);
        await store.StopAsync(default);

        Assert.Equal(10_000, Scalar("SELECT count(*) FROM requests"));
    }

    [Fact]
    public async Task FinishingARequestUpdatesItsRow()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);

        var entry = log.Add("client", "GET", "https://x.test/", allowed: true);
        await WaitUntilAsync(() => File.Exists(DatabasePath) && TryScalar("SELECT count(*) FROM requests WHERE status IS NULL") == 1);

        log.Update(entry with { Status = 200, DurationMs = 5 });
        await store.StopAsync(default);

        Assert.Equal(1, Scalar("SELECT count(*) FROM requests"));
        Assert.Equal(200, Scalar("SELECT status FROM requests"));
    }

    private long? TryScalar(string sql)
    {
        try { return Scalar(sql); }
        catch (SqliteException) { return null; }
    }

    [Fact]
    public async Task UnfinishedRequestStaysVisible()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);
        log.Add("client", "GET", "https://x.test/long-running", allowed: true);
        await store.StopAsync(default);

        Assert.Equal(1, Scalar("SELECT count(*) FROM requests WHERE status IS NULL"));
    }

    [Fact]
    public async Task FilesArePrivate()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);
        log.Add("client", "GET", "https://x.test/", allowed: true);
        await WaitUntilAsync(() => File.Exists(DatabasePath + "-wal"));

        const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                                    UnixFileMode.OtherRead | UnixFileMode.OtherWrite;
        Assert.Equal(0, (int)(File.GetUnixFileMode(DatabasePath) & others));
        Assert.Equal(0, (int)(File.GetUnixFileMode(DatabasePath + "-wal") & others));
        await store.StopAsync(default);
    }

    [Fact]
    public async Task OverflowIsRecordedAsAGap()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist, queueCapacity: 100);

        // The writer is not running yet, so that this exceeds the capacity of the queue.
        for (int i = 0; i < 150; i++)
            log.Add("client", "GET", $"https://x.test/{i}", allowed: true);
        Assert.Equal(50, store.Status.DroppedEvents);

        await store.StartAsync(default);
        await store.StopAsync(default);

        Assert.Equal(50, Scalar("SELECT sum(dropped_events) FROM gaps"));
        Assert.Equal(100, Scalar("SELECT count(*) FROM requests"));
        Assert.Equal(50, Scalar("SELECT min(id) - 1 FROM requests"));
    }

    [Fact]
    public async Task OldRequestsAreRemoved()
    {
        // Long enough that a slow machine does not remove the request before the first check.
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(retention: TimeSpan.FromSeconds(2)), log, _whitelist);
        await store.StartAsync(default);
        log.Add("client", "GET", "https://x.test/old", allowed: true);
        await store.StopAsync(default);
        Assert.Equal(1, Scalar("SELECT count(*) FROM requests"));

        await Task.Delay(TimeSpan.FromSeconds(2.5));

        var later = new TrafficStore(Options(retention: TimeSpan.FromSeconds(2)), new TrafficLog(10), _whitelist);
        await later.StartAsync(default);
        await later.StopAsync(default);
        Assert.Equal(0, Scalar("SELECT count(*) FROM requests"));
    }

    [Fact]
    public async Task SizeLimitHoldsAndKeepsTheNewest()
    {
        const long limit = 1024 * 1024;
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(maxBytes: limit), log, _whitelist);
        await store.StartAsync(default);

        const int count = 100_000;
        for (int i = 0; i < count; i++)
        {
            log.Add("client", "GET", $"https://x.test/{i}/{new string('p', 100)}", allowed: true);
            if (i % 4096 == 0)
                await Task.Delay(1);
        }
        await store.StopAsync(default);

        Assert.True(new FileInfo(DatabasePath).Length < limit * 2, $"File is {new FileInfo(DatabasePath).Length} bytes");
        Assert.True(Scalar("SELECT count(*) FROM requests") is > 0 and < count);
        Assert.Equal(count, Scalar("SELECT max(id) FROM requests"));
    }

    [Fact]
    public async Task HeadersAreRemovedWithTheirRequests()
    {
        const long limit = 4 * 1024 * 1024;
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(maxBytes: limit), log, _whitelist);
        await store.StartAsync(default);

        for (int i = 0; i < 20_000; i++)
        {
            var entry = log.Add("client", "GET", $"https://x.test/{i}", allowed: true);
            store.AddHeaders(entry, $"[[\"X-Padding\",\"{new string('p', 500)}\"]]", null);
            if (i % 1024 == 0)
                await Task.Delay(20);
        }
        await store.StopAsync(default);

        Assert.Equal(0, Scalar("""
            SELECT count(*) FROM headers h WHERE NOT EXISTS
                (SELECT 1 FROM requests r WHERE r.session = h.session AND r.id = h.id)
            """));
        Assert.True(Scalar("SELECT count(*) FROM headers") > 0);
        Assert.True(new FileInfo(DatabasePath).Length < limit * 2, $"File is {new FileInfo(DatabasePath).Length} bytes");
    }

    [Fact]
    public async Task OldHeadersWithoutARequestAreRemoved()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(retention: TimeSpan.FromMilliseconds(200)), log, _whitelist);
        await store.StartAsync(default);
        store.AddHeaders(new TrafficEntry(1, DateTimeOffset.UtcNow, "c", "GET", "u", true), "[]", null);
        await store.StopAsync(default);
        Assert.Equal(1, Scalar("SELECT count(*) FROM headers"));

        await Task.Delay(300);

        var later = new TrafficStore(Options(retention: TimeSpan.FromMilliseconds(200)), new TrafficLog(10), _whitelist);
        await later.StartAsync(default);
        await later.StopAsync(default);
        Assert.Equal(0, Scalar("SELECT count(*) FROM headers"));
    }

    [Fact]
    public async Task OverflowOfHeadersKeepsTheRequestsAndIsRecorded()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist, headerQueueCapacity: 10);

        for (int i = 0; i < 25; i++)
            store.AddHeaders(log.Add("client", "GET", $"https://x.test/{i}", allowed: true), "[]", null);
        Assert.Equal(15, store.Status.DroppedHeaders);

        await store.StartAsync(default);
        await store.StopAsync(default);

        Assert.Equal(25, Scalar("SELECT count(*) FROM requests"));
        Assert.Equal(10, Scalar("SELECT count(*) FROM headers"));
        Assert.Equal(15, Scalar("SELECT sum(dropped_headers) FROM gaps"));
    }

    [Fact]
    public async Task EveryVersionOfTheWhitelistIsKept()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);

        File.WriteAllText(WhitelistPath, "GET: ^https://y\\.test/\n");
        await WaitUntilAsync(() => _whitelist.Version.Contents.Contains("y\\.test"));
        await store.StopAsync(default);

        Assert.Equal(2, Scalar("SELECT count(*) FROM whitelists"));
    }

    [Fact]
    public async Task UnusableDatabaseIsReportedAndRecoveredFrom()
    {
        var log = new TrafficLog(10);

        // Others can read the file, which is refused like for a file with secrets.
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        File.WriteAllBytes(DatabasePath, []);
        File.SetUnixFileMode(DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);

        var store = new TrafficStore(Options(), log, _whitelist) { RetryDelay = TimeSpan.FromMilliseconds(50) };
        await store.StartAsync(default);
        log.Add("client", "GET", "https://x.test/during-failure", allowed: true);
        await WaitUntilAsync(() => !store.Status.Healthy);
        Assert.Contains("chmod", store.Status.Error);

        File.SetUnixFileMode(DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await WaitUntilAsync(() => store.Status.Healthy);
        await store.StopAsync(default);

        Assert.Equal(1, Scalar("SELECT count(*) FROM requests"));
    }

    [Fact]
    public async Task EntriesAreKeptWhenAWriteFails()
    {
        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist) { RetryDelay = TimeSpan.FromMilliseconds(500) };
        await store.StartAsync(default);

        log.Add("client", "GET", "https://x.test/first", allowed: true);
        await WaitUntilAsync(() => File.Exists(DatabasePath) && TryScalar("SELECT count(*) FROM requests") == 1);

        // A failure of the writing itself, as opposed to opening the database.
        using (var database = new SqliteConnection($"Data Source={DatabasePath};Pooling=False"))
        {
            database.Open();
            using var command = database.CreateCommand();
            command.CommandText = "DROP TABLE requests";
            command.ExecuteNonQuery();
        }

        log.Add("client", "GET", "https://x.test/second", allowed: true);
        await WaitUntilAsync(() => !store.Status.Healthy);
        await WaitUntilAsync(() => store.Status.Healthy);
        await store.StopAsync(default);

        Assert.Equal(1, Scalar("SELECT count(*) FROM requests WHERE url LIKE '%second'"));
    }

    [Fact]
    public async Task DatabaseOfThePreviousVersionIsMigrated()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using (var database = new SqliteConnection($"Data Source={DatabasePath};Pooling=False"))
        {
            database.Open();
            using var command = database.CreateCommand();
            command.CommandText = """
                CREATE TABLE requests(
                    session INTEGER NOT NULL, id INTEGER NOT NULL, time_ms INTEGER NOT NULL, client TEXT NOT NULL,
                    method TEXT NOT NULL, url TEXT NOT NULL, allowed INTEGER NOT NULL, status INTEGER,
                    duration_ms REAL, reason TEXT, note TEXT, rule_line INTEGER, rule TEXT, whitelist TEXT,
                    PRIMARY KEY(session, id)) WITHOUT ROWID;
                CREATE VIEW traffic AS SELECT method, url FROM requests;
                PRAGMA user_version = 1;
                """;
            command.ExecuteNonQuery();
            command.CommandText = $"INSERT INTO requests VALUES(1, 1, {DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}, " +
                                  "'c', 'GET', 'https://old.test/', 1, 200, 1, NULL, NULL, NULL, NULL, NULL)";
            command.ExecuteNonQuery();
        }
        File.SetUnixFileMode(DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var log = new TrafficLog(10);
        var store = new TrafficStore(Options(), log, _whitelist);
        await store.StartAsync(default);
        log.Add("client", "GET", "https://new.test/", allowed: true, user: "alice");
        await store.StopAsync(default);

        Assert.True(store.Status.Healthy, store.Status.Error);
        Assert.Equal(2, Scalar("PRAGMA user_version"));
        Assert.Equal(2, Scalar("SELECT count(*) FROM requests"));
        Assert.Equal(1, Scalar("SELECT count(*) FROM requests WHERE user = 'alice' AND url = 'https://new.test/'"));
        Assert.Equal(1, Scalar("SELECT count(*) FROM traffic WHERE user = 'alice'"));
        Assert.Equal(1, Scalar("SELECT count(*) FROM requests WHERE user IS NULL AND url = 'https://old.test/'"));
    }

    [Fact]
    public async Task DatabaseFromTheFutureIsLeftAlone()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using (var database = new SqliteConnection($"Data Source={DatabasePath};Pooling=False"))
        {
            database.Open();
            using var command = database.CreateCommand();
            command.CommandText = "PRAGMA user_version = 999";
            command.ExecuteNonQuery();
        }
        File.SetUnixFileMode(DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var store = new TrafficStore(Options(), new TrafficLog(10), _whitelist) { RetryDelay = TimeSpan.FromMilliseconds(50) };
        await store.StartAsync(default);
        await WaitUntilAsync(() => !store.Status.Healthy);
        await store.StopAsync(default);

        Assert.Equal(999, Scalar("PRAGMA user_version"));
    }
}
