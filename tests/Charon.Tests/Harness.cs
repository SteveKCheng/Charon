using System.Buffers.Text;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Data.Sqlite;

namespace Charon.Tests;

/// <summary>Runs Charon, and an upstream server it is to reach, on loopback ports.</summary>
public sealed class Harness : IAsyncLifetime
{
    private WebApplication _charon = null!;
    private WebApplication _upstream = null!;
    private TcpListener _rawUpstream = null!;

    public string Directory { get; } = System.IO.Directory.CreateTempSubdirectory("charon-test").FullName;
    public int ProxyPort { get; } = FreePort();
    public int UiPort { get; } = FreePort();
    public int HttpPort { get; } = FreePort();
    public int HttpsPort { get; } = FreePort();
    public int UntrustedHttpsPort { get; } = FreePort();

    /// <summary>A TCP listener that counts connections and records what it is sent.</summary>
    public int RawPort { get; private set; }
    public int RawConnections;

    /// <summary>Paths of all requests that arrived at the upstream server.</summary>
    public List<string> UpstreamRequests { get; } = new();

    public string WhitelistFile => Path.Combine(Directory, "whitelist.txt");
    public string CredentialsFile => Path.Combine(Directory, "credentials.json");
    public string TokenFile => Path.Combine(Directory, "token");
    public string TrafficDatabaseFile => Path.Combine(Directory, "state", "traffic.db");
    public string AppKeyFile => Path.Combine(Directory, "app-key.pem");

    private RSA AppKey { get; } = RSA.Create(2048);

    /// <summary>Requests that the stand-in for GitHub got for tokens, with what they asked for.</summary>
    public List<(long Installation, string Scope)> TokenRequests { get; } = new();

    public int TokenRequestCount(long installation)
    {
        lock (TokenRequests)
            return TokenRequests.Count(r => r.Installation == installation);
    }

    public string CaFile => Path.Combine(Directory, "ca.crt");

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static (X509Certificate2 Root, X509Certificate2 Leaf) MakeServerCertificate(string name)
    {
        using var rootKey = ECDsa.Create();
        var rootRequest = new CertificateRequest($"CN={name}", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var now = DateTimeOffset.UtcNow;
        var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(7));

        var leafKey = ECDsa.Create();
        var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        leafRequest.CertificateExtensions.Add(names.Build());
        var leaf = leafRequest.Create(root, now.AddDays(-1), now.AddDays(7), [1, 2, 3, 4])
                              .CopyWithPrivateKey(leafKey);
        return (root, leaf);
    }

    public async Task InitializeAsync()
    {
        var (root, leaf) = MakeServerCertificate("Test upstream root");
        var (_, untrustedLeaf) = MakeServerCertificate("Untrusted root");
        var rootsFile = Path.Combine(Directory, "upstream-roots.pem");
        File.WriteAllText(rootsFile, root.ExportCertificatePem());

        File.WriteAllText(WhitelistFile, $"""
            # Rules for the tests: note that 127.0.0.1 is not on the list, but localhost is.
            GET: ^https?://localhost:[0-9]+/allowed
            POST: ^https?://localhost:[0-9]+/allowed/post
            PUT: ^https?://localhost:[0-9]+/allowed/put
            GET: ^https://localhost:{UntrustedHttpsPort}/
            GET: ^https://127\.0\.0\.1:{RawPort}/
            GET-BODY: ^https://localhost:[0-9]+/allowed/body-ok
            WEBSOCKET: ^https://localhost:[0-9]+/allowed/ws$
            ANY: ^https?://localhost:[0-9]+/api/
            ANY: ^https://127\.0\.0\.1:[0-9]+/api/
            GET: ^http://localhost:{UiPort}/
            """);

        WriteCredentials();

        _rawUpstream = new TcpListener(IPAddress.Loopback, 0);
        _rawUpstream.Start();
        RawPort = ((IPEndPoint)_rawUpstream.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                using var client = await _rawUpstream.AcceptTcpClientAsync();
                Interlocked.Increment(ref RawConnections);
            }
        });

        await StartUpstreamAsync(leaf, untrustedLeaf);

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        _charon = CharonApp.Build(builder, new CharonOptions
        {
            ProxyPort = ProxyPort,
            UiPort = UiPort,
            WhitelistFile = WhitelistFile,
            CaCertificateFile = CaFile,
            CaKeyFile = Path.Combine(Directory, "ca.key"),
            UpstreamRootsFile = rootsFile,
            CredentialsFile = CredentialsFile,
            TrafficDatabaseFile = TrafficDatabaseFile,
        });
        await _charon.StartAsync();
    }

    public const string StaticToken = "static-secret-token";

    private static void WritePrivate(string path, string contents)
    {
        File.WriteAllText(path, contents);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private void WriteCredentials()
    {
        WritePrivate(TokenFile, StaticToken + "\n");
        WritePrivate(AppKeyFile, AppKey.ExportPkcs8PrivateKeyPem());

        object App(long installationId) => new
        {
            appId = "1234",
            installationId,
            privateKeyFile = AppKeyFile,
            apiBase = $"https://localhost:{HttpsPort}",
            permissions = new Dictionary<string, string> { ["actions"] = "write" },
            repositories = new[] { "proj" },
        };

        var origin = $"https://localhost:{HttpsPort}";
        WritePrivate(CredentialsFile, JsonSerializer.Serialize(new object[]
        {
            new { name = "bearer", origin, url = "/api/bearer", tokenFile = TokenFile },
            new { name = "basic", origin, url = "/api/basic", tokenFile = TokenFile, basicUser = "x-access-token" },
            new { name = "key", origin, url = "/api/key", tokenFile = TokenFile, header = "x-api-key", scheme = "" },
            new { name = "app", origin, url = "/api/app", gitHubApp = App(GoodInstallation) },
            new { name = "short", origin, url = "/api/short", gitHubApp = App(ShortLivedInstallation) },
            new { name = "refused", origin, url = "/api/refused", gitHubApp = App(BadInstallation) },
            new { name = "no-file", origin, url = "/api/no-file", tokenFile = TokenFile + ".missing" },
        }));
    }

    public const long GoodInstallation = 42;
    public const long ShortLivedInstallation = 43;
    public const long BadInstallation = 44;

    /// <summary>Stands in for GitHub: verifies the App's token and issues a new one.</summary>
    private async Task IssueTokenAsync(HttpContext context)
    {
        var installation = long.Parse((string)context.Request.RouteValues["id"]!);
        using var body = await JsonDocument.ParseAsync(context.Request.Body);
        var scope = body.RootElement.GetRawText();
        var parts = (context.Request.Headers.Authorization.ToString().Split(' ') is ["Bearer", var jwt]
            ? jwt : "").Split('.');
        var claims = parts.Length == 3
            ? JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1])).RootElement : default;

        bool valid = parts.Length == 3 &&
            AppKey.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Base64Url.DecodeFromChars(parts[2]),
                              HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) &&
            claims.GetProperty("iss").GetString() == "1234" &&
            claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64() <= 600;

        lock (TokenRequests)
            TokenRequests.Add((installation, scope));

        if (!valid || installation == BadInstallation)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("not for you: do not repeat this");
            return;
        }

        int count;
        lock (TokenRequests)
            count = TokenRequests.Count;

        var lifetime = installation == ShortLivedInstallation ? TimeSpan.FromMinutes(1) : TimeSpan.FromHours(1);
        await context.Response.WriteAsJsonAsync(new Dictionary<string, object>
        {
            ["token"] = $"ghs_installation_{installation}_{count}",
            ["expires_at"] = DateTimeOffset.UtcNow + lifetime,
        });
    }

    private async Task StartUpstreamAsync(X509Certificate2 leaf, X509Certificate2 untrustedLeaf)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = null;
            kestrel.ListenLocalhost(HttpPort);
            kestrel.ListenLocalhost(HttpsPort, listen =>
            {
                listen.Protocols = HttpProtocols.Http1AndHttp2;
                listen.UseHttps(leaf);
            });
            kestrel.ListenLocalhost(UntrustedHttpsPort, listen => listen.UseHttps(untrustedLeaf));
        });

        var app = builder.Build();
        app.UseWebSockets();
        app.Use(async (context, next) =>
        {
            lock (UpstreamRequests)
                UpstreamRequests.Add(context.Request.Path + context.Request.QueryString);
            await next(context);
        });

        app.Map("/allowed/stream", async context =>
        {
            context.Response.ContentType = "text/event-stream";
            for (int i = 0; i < 5; i++)
            {
                await context.Response.WriteAsync($"data: {i}\n\n");
                await context.Response.Body.FlushAsync();
                await Task.Delay(200);
            }
        });

        app.Map("/allowed/ws", async context =>
        {
            using var socket = await context.WebSockets.AcceptWebSocketAsync();
            var buffer = new byte[1024];
            var received = await socket.ReceiveAsync(buffer, default);
            await socket.SendAsync(buffer.AsMemory(0, received.Count), WebSocketMessageType.Text, true, default);
            await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, default);
        });

        app.MapPost("/app/installations/{id}/access_tokens", IssueTokenAsync);

        app.Map("/api/bearer/redirect", context =>
        {
            context.Response.Redirect($"https://127.0.0.1:{HttpsPort}/api/bearer/redirected");
            return Task.CompletedTask;
        });

        app.Map("/allowed/post/size", async context =>
        {
            long total = 0;
            var buffer = new byte[65536];
            int count;
            while ((count = await context.Request.Body.ReadAsync(buffer)) > 0)
                total += count;
            await context.Response.WriteAsync(total.ToString());
        });

        app.MapFallback(context => context.Response.WriteAsJsonAsync(new
        {
            context.Request.Method,
            Path = context.Request.Path + context.Request.QueryString,
            Protocol = context.Request.Protocol,
            Headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
        }));

        await app.StartAsync();
        _upstream = app;
    }

    public async Task DisposeAsync()
    {
        await _charon.DisposeAsync();
        await _upstream.DisposeAsync();
        _rawUpstream.Stop();
        System.IO.Directory.Delete(Directory, recursive: true);
    }

    public bool UpstreamSaw(string path)
    {
        lock (UpstreamRequests)
            return UpstreamRequests.Contains(path);
    }

    private SocketsHttpHandler MakeHandler() => new()
    {
        Proxy = new WebProxy($"http://127.0.0.1:{ProxyPort}"),
        UseProxy = true,
        SslOptions = { CertificateChainPolicy = TrustCharon() },
    };

    private X509ChainPolicy TrustCharon()
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        policy.CustomTrustStore.ImportFromPemFile(CaFile);
        return policy;
    }

    /// <summary>Client that verifies certificates against Charon's CA alone.</summary>
    public HttpClient MakeClient(Version? version = null) => new(MakeHandler())
    {
        DefaultRequestVersion = version ?? HttpVersion.Version11,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(30),
    };

    /// <summary>For WebSockets over HTTP/2, which needs the handler passed in.</summary>
    public HttpMessageInvoker MakeInvoker() => new(MakeHandler());

    public ClientWebSocket MakeWebSocket()
    {
        var socket = new ClientWebSocket();
        socket.Options.Proxy = new WebProxy($"http://127.0.0.1:{ProxyPort}");
        socket.Options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
        {
            using var chain = new X509Chain { ChainPolicy = TrustCharon() };
            return chain.Build(new X509Certificate2(certificate!));
        };
        return socket;
    }

    /// <summary>Waits for a query of the traffic database to have a result, as writes are delayed.</summary>
    public async Task<T> WaitForTrafficAsync<T>(string sql, Func<SqliteDataReader, T> read)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (true)
        {
            await using var database = new SqliteConnection($"Data Source={TrafficDatabaseFile};Pooling=False;Mode=ReadOnly");
            database.Open();
            await using var command = database.CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
                return read(reader);

            Assert.True(DateTime.UtcNow < deadline, $"No result from: {sql}");
            await Task.Delay(50);
        }
    }

    /// <summary>Opens a connection to the proxy that is under the test's complete control.</summary>
    public async Task<Stream> ConnectRawAsync()
    {
        var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ProxyPort);
        var stream = client.GetStream();
        stream.ReadTimeout = 10_000;
        return stream;
    }

    /// <summary>Issues CONNECT and does TLS, returning the stream inside the tunnel.</summary>
    public async Task<SslStream> OpenTunnelAsync(string target, string sni, params string[] alpn)
    {
        var stream = await ConnectRawAsync();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"));
        var head = await ReadHeadAsync(stream);
        Assert.StartsWith("HTTP/1.1 200", head);

        var tls = new SslStream(stream);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            CertificateChainPolicy = TrustCharon(),
            ApplicationProtocols = alpn.Select(a => new SslApplicationProtocol(a)).ToList(),
        });
        return tls;
    }

    /// <summary>Sends text as-is, and returns the head of the response plus any body.</summary>
    public static async Task<string> ExchangeAsync(Stream stream, string request)
    {
        await stream.WriteAsync(Encoding.Latin1.GetBytes(request));
        var result = new StringBuilder();
        var buffer = new byte[8192];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            int count;
            while ((count = await stream.ReadAsync(buffer, timeout.Token)) > 0)
                result.Append(Encoding.Latin1.GetString(buffer, 0, count));
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
        }

        return result.ToString();
    }

    public static async Task<string> ReadHeadAsync(Stream stream)
    {
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n") && await stream.ReadAsync(one) > 0)
            head.Append((char)one[0]);
        return head.ToString();
    }

    public static JsonElement ParseEcho(string json) => JsonDocument.Parse(json).RootElement;
}

[CollectionDefinition("charon")]
public sealed class CharonCollection : ICollectionFixture<Harness>;
