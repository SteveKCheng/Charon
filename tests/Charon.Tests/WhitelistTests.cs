using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Charon.Tests;

public sealed class WhitelistTests : IDisposable
{
    private readonly string _path = Path.GetTempFileName();

    public void Dispose() => File.Delete(_path);

    private Whitelist Load(params string[] lines)
    {
        File.WriteAllLines(_path, lines);
        return new Whitelist(_path);
    }

    private static bool Allowed(Whitelist list, string method, string url) =>
        RequestPolicy.ForMethod(method) is { } capability && list.IsAllowed(capability, url, new Uri(url).IdnHost);

    [Theory]
    [InlineData(@"^https://example\.com/", "example.com")]
    [InlineData(@"^https?://example\.com/", "example.com")]
    [InlineData(@"^https://([-a-z0-9.]+\.)?github\.com/", "github.com")]
    [InlineData(@"^https://(?:[-a-z0-9.]+\.)?GitHub\.com/", "github.com")]
    [InlineData(@"^https?://localhost:[0-9]+/", "localhost")]
    [InlineData(@"^https://a\.b/x(y|z)$", "a.b")]
    [InlineData(@"^https://a\.b$", "a.b")]
    [InlineData(@"^tcp://a\.b:22/$", "a.b")]
    [InlineData(@"^https://example.com/", null)]             // "." here is any character
    [InlineData(@"^https://a\.b/|^https://c\.d/", null)]     // Not all matches have a.b
    [InlineData(@"^https://a\.b/x|y", null)]
    [InlineData(@"^https://a\.b*/", null)]
    [InlineData(@"^https://a\.b?c/", null)]
    [InlineData(@"^https://a[.]b/", null)]
    [InlineData(@"https://a\.b/", null)]                     // Unanchored
    [InlineData(@"^http.*://a\.b/", null)]
    [InlineData(@"/reloaded$", null)]
    public void LiteralHostOfRule(string pattern, string? host) =>
        Assert.Equal(host, Whitelist.GetLiteralHost(pattern));

    [Fact]
    public void ExamplesFromTheAddInsDocumentation()
    {
        using var list = Load(
            "# comment",
            "",
            @"GET: ^https?://example.com/",
            @"GET: ^https://mitm\.it/",
            @"GET: ^https?://localhost/",
            @"GET: ^https://([-a-z0-9.]+\.)?github\.com/",
            @"POST: ^https://github.com/[^/]+/[^/]+\.git/git-upload-pack");

        Assert.True(Allowed(list, "GET", "https://EXAMPLE.com/x"));
        Assert.True(Allowed(list, "HEAD", "https://api.github.com/repos"));
        Assert.True(Allowed(list, "GET", "https://github.com/a"));
        Assert.True(Allowed(list, "POST", "https://github.com/a/b.git/git-upload-pack"));
        Assert.False(Allowed(list, "POST", "https://github.com/a/b.git/git-receive-pack"));
        Assert.False(Allowed(list, "GET", "https://notgithub.com/"));
        Assert.False(Allowed(list, "GET", "https://github.com.evil.example/"));
        Assert.False(Allowed(list, "PUT", "https://example.com/x"));
    }

    [Fact]
    public void OptInRuleTypesAreSeparateFromGetAndAny()
    {
        using var list = Load(
            @"ANY: ^https://a\.test/",
            @"GET-BODY: ^https://b\.test/",
            @"WEBSOCKET: ^https://c\.test/");

        Assert.True(list.IsAllowed(Capability.Get, "https://a.test/", "a.test"));
        Assert.False(list.IsAllowed(Capability.GetWithBody, "https://a.test/", "a.test"));
        Assert.False(list.IsAllowed(Capability.WebSocket, "https://a.test/", "a.test"));

        Assert.True(list.IsAllowed(Capability.GetWithBody, "https://b.test/", "b.test"));
        Assert.False(list.IsAllowed(Capability.Get, "https://b.test/", "b.test"));

        Assert.True(list.IsAllowed(Capability.WebSocket, "https://c.test/", "c.test"));
        Assert.False(list.IsAllowed(Capability.Get, "https://c.test/", "c.test"));
    }

    [Fact]
    public void TcpRulesAreSeparateFromAllOthers()
    {
        using var list = Load(@"ANY: .*", @"TCP: ^tcp://a\.test:22/$", @"TCP: ^tcp://.*\.b\.test:(22|23)/");

        Assert.True(list.IsAllowed(Capability.Tcp, "tcp://a.test:22/", "a.test"));
        Assert.True(list.IsAllowed(Capability.Tcp, "tcp://x.b.test:23/", "x.b.test"));
        Assert.False(list.IsAllowed(Capability.Tcp, "tcp://a.test:2222/", "a.test"));
        Assert.False(list.IsAllowed(Capability.Tcp, "tcp://x.a.test:22/", "x.a.test"));
        Assert.False(list.IsAllowed(Capability.Tcp, "tcp://c.test:22/", "c.test"));

        using var tcpOnly = Load(@"TCP: ^tcp://.*/$");
        Assert.False(tcpOnly.IsAllowed(Capability.Get, "https://a.test/", "a.test"));
    }

    [Theory]
    [InlineData(@"tcp://a\.test:22/")]
    [InlineData(@".*")]
    [InlineData(@"^https://a\.test/")]
    [InlineData(@"^tcp://a\.test:22")]
    [InlineData(@"^tcp://a\.test:22$")]
    [InlineData(@"^tcp://a\.test:22/|.*/")]
    public void LooseTcpRulesMakeTheWhitelistInvalid(string pattern)
    {
        using var list = Load(@"GET: ^https://x\.test/", "TCP: " + pattern);
        Assert.False(Allowed(list, "GET", "https://x.test/"));
        Assert.False(list.IsAllowed(Capability.Tcp, "tcp://a.test:22/", "a.test"));
    }

    [Theory]
    [InlineData(@"^tcp://a\.test:443/$", true)]
    [InlineData(@"^tcp://.*/$", true)]
    [InlineData(@"^tcp://a\.test:22/$", false)]
    [InlineData(@"^tcp://b\.test:443/$", false)]
    [InlineData(@"^tcp://plain\.test:443/$", false)]
    public void TcpRulesThatBypassOthersAreWarnedAbout(string pattern, bool expected)
    {
        File.WriteAllLines(_path, [@"GET: ^https://a\.test/", @"GET: ^http://plain\.test/", "TCP: " + pattern]);
        var logger = new ListLogger();
        using var list = new Whitelist(_path, logger);

        if (!expected)
            Assert.Empty(logger.Warnings);
        else
            Assert.Contains("a.test:443", Assert.Single(logger.Warnings));
    }

    [Fact]
    public void IndexAgreesWithLinearScan()
    {
        // The index must not change what the regular expressions alone would decide.
        string[] rules =
        [
            @"^https://a\.example\.com/x", @"^https://([-a-z0-9.]+\.)?b\.example\.com/",
            @"^https?://c\.example\.org:8[0-9]+/", @"^https://d\.example\.org$",
            @"^https://e\.example\.net/(p|q)/", @"example\.io/open", @"^https://[a-f]\.example\.net/",
        ];
        using var list = Load(rules.Select(r => "ANY: " + r).ToArray());
        var regexes = rules.Select(r => new Regex(r, RegexOptions.IgnoreCase)).ToArray();

        var random = new Random(42);
        string[] hosts = ["a", "b", "c", "d", "e", "f", "x.b", "y.x.b", "z", "xb", "a.b"];
        string[] domains = ["example.com", "example.org", "example.net", "example.io", "b.example.com"];
        string[] paths = ["", "/", "/x", "/p/1", "/q/", "/r/", "/open", "/x/example.io/open"];
        string[] ports = ["", ":8080", ":81", ":443"];
        string[] schemes = ["http", "https"];

        for (int i = 0; i < 20_000; i++)
        {
            string Pick(string[] from) => from[random.Next(from.Length)];
            var url = new Uri($"{Pick(schemes)}://{Pick(hosts)}.{Pick(domains)}{Pick(ports)}{Pick(paths)}").AbsoluteUri;
            Assert.True(regexes.Any(r => r.IsMatch(url)) == Allowed(list, "GET", url), url);
        }
    }

    [Fact]
    public void CatastrophicRuleFailsClosed()
    {
        using var list = Load(@"GET: ^https://x\.test/(a+)+$");
        var url = "https://x.test/" + new string('a', 64) + "!";
        Assert.False(Allowed(list, "GET", url));
    }

    [Fact]
    public async Task InvalidEditKeepsTheRulesAndDeletionDropsThem()
    {
        using var list = Load(@"GET: ^https://x\.test/");
        Assert.True(Allowed(list, "GET", "https://x.test/"));

        File.WriteAllText(_path, "GET: ^https://x\\.test/(\n");
        await Task.Delay(1500);
        Assert.True(Allowed(list, "GET", "https://x.test/"));

        File.Delete(_path);
        await Task.Delay(1500);
        Assert.False(Allowed(list, "GET", "https://x.test/"));
    }

    [Fact]
    public void MissingFileAllowsNothing()
    {
        using var list = new Whitelist(_path + ".does-not-exist");
        Assert.False(Allowed(list, "GET", "https://x.test/"));
    }
}

public sealed class CertificateAuthorityTests
{
    [Fact]
    public void LoadsCombinedPemFileLikeMitmproxysCa()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=mitmproxy", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var now = DateTimeOffset.UtcNow;
        using var root = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem() + "\n" + root.ExportCertificatePem());
            var ca = CertificateAuthority.LoadOrCreate(path, path);
            Assert.Equal(root.Thumbprint, ca.Certificate.Thumbprint);
            Assert.Equal(root.Subject, ca.GetCertificate("example.com").TargetCertificate.Issuer);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("under_score.example.com")]
    [InlineData("a-long-label-that-goes-on-and-on-and-on-and-on.and-another-that-goes-on-and-on-and-on-and-on.example.com")]
    public void IssuesFromRsaCaSuchAsMitmproxys(string host)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=mitmproxy", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        using var root = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        var leaf = new CertificateAuthority(root).GetCertificate(host).TargetCertificate;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf), string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));
        Assert.True(leaf.MatchesHostname(host));
    }

    private static X509Certificate2 MakeRoot(DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Charon Proxy CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        return request.CreateSelfSigned(notAfter.AddYears(-1), notAfter);
    }

    /// <summary>Certificates cannot outlast the CA, so renewing them does not help when it is about to expire.</summary>
    [Theory]
    [InlineData(12)]
    [InlineData(-12)]
    [InlineData(-240)]
    public void CertificatesEndWithTheCA(int hoursLeft)
    {
        using var root = MakeRoot(DateTimeOffset.UtcNow.AddHours(hoursLeft));
        var ca = new CertificateAuthority(root);

        var context = ca.GetCertificate("example.com");
        Assert.Equal(root.NotAfter, context.TargetCertificate.NotAfter);
        Assert.Same(context, ca.GetCertificate("example.com"));
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void CertificatesAreRenewedBeforeTheyExpire()
    {
        var time = new ManualTime();
        var start = time.Now;
        using var root = MakeRoot(start.AddDays(50));
        var ca = new CertificateAuthority(root, time);

        var first = ca.GetCertificate("example.com");
        time.Now = start.AddDays(28);
        Assert.Same(first, ca.GetCertificate("example.com"));

        time.Now = start.AddDays(29.5);
        var second = ca.GetCertificate("example.com");
        Assert.True(second.TargetCertificate.NotAfter > first.TargetCertificate.NotAfter);

        // The second already lasts for as long as the CA does.
        Assert.Equal(root.NotAfter, second.TargetCertificate.NotAfter);
        time.Now = start.AddDays(49.5);
        Assert.Same(second, ca.GetCertificate("example.com"));
        time.Now = start.AddDays(60);
        Assert.Same(second, ca.GetCertificate("example.com"));
    }

    [Theory]
    [InlineData(31, null)]
    [InlineData(29, "expires at")]
    [InlineData(-1, "expired at")]
    public void ExpiryOfTheCAIsWarnedAbout(int daysLeft, string? expected)
    {
        var time = new ManualTime();
        using var root = MakeRoot(time.Now.AddDays(daysLeft));
        var logger = new ListLogger();

        new CertificateAuthority(root, time).WarnOfExpiry(logger, "/path/to/ca.crt");

        if (expected is null)
        {
            Assert.Empty(logger.Entries);
            return;
        }

        var warning = Assert.Single(logger.Warnings);
        Assert.Contains(expected, warning);
        Assert.Contains("/path/to/ca.crt", warning);
    }
}
