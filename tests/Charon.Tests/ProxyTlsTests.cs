using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;

namespace Charon.Tests;

/// <summary>Clients using TLS to connect to the proxy itself.</summary>
[Collection("charon")]
public sealed class ProxyTlsTests(Harness h)
{
    private HttpClient MakeClient(Version? version = null, ICredentials? credentials = null) =>
        h.MakeClient(version, credentials, $"https://localhost:{h.ProxyTlsPort}");

    private async Task<string> ConnectAsync(Stream stream, string headers = "")
    {
        var target = $"localhost:{h.HttpsPort}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{headers}\r\n"));
        return await Harness.ReadHeadAsync(stream);
    }

    [Theory]
    [InlineData("1.1")]
    [InlineData("2.0")]
    public async Task TunnelIsNested(string version)
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        using var client = MakeClient(Version.Parse(version));
        var response = await client.GetAsync($"https://localhost:{h.HttpsPort}{marker}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Version.Parse(version), response.Version);
        Assert.True(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task PlainHttpUrlIsForwarded()
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        using var client = MakeClient();
        var response = await client.GetAsync($"http://localhost:{h.HttpPort}{marker}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task WhitelistAppliesInAndOutOfTunnels()
    {
        using var client = MakeClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"https://localhost:{h.HttpsPort}/denied")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"http://localhost:{h.HttpPort}/denied")).StatusCode);
    }

    [Fact]
    public async Task LargeUploadGetsThrough()
    {
        const int size = 8 * 1024 * 1024;
        using var client = MakeClient();
        using var content = new ByteArrayContent(new byte[size]);
        var response = await client.PostAsync($"https://localhost:{h.HttpsPort}/allowed/post/size", content);
        Assert.Equal(size.ToString(), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UserIsIdentified()
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        await using var outer = await h.ConnectTlsAsync("localhost");
        var head = await ConnectAsync(outer, $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "alice-pw")}\r\n");
        Assert.StartsWith("HTTP/1.1 200", head);

        await using var tunnel = await h.StartTunnelTlsAsync(outer, "localhost");
        Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(tunnel,
            $"GET {marker} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n"));
        Assert.Equal("alice", await h.WaitForTrafficAsync(
            $"SELECT user FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));
    }

    [Fact]
    public async Task WrongPasswordIsRefused()
    {
        await using var outer = await h.ConnectTlsAsync("localhost");
        Assert.StartsWith("HTTP/1.1 407", await ConnectAsync(
            outer, $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "wrong")}\r\n"));
    }

    [Theory]
    [InlineData("localhost", "127.0.0.1")]
    [InlineData("proxy.test", "127.0.0.1")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::1", "::1")]
    public async Task CertificateIsForTheNamesOfTheProxy(string name, string address)
    {
        await using var outer = await h.ConnectTlsAsync(name, IPAddress.Parse(address));
        Assert.StartsWith("HTTP/1.1 200", await ConnectAsync(outer));
    }

    [Fact]
    public async Task CertificateIsNotForWhateverIsInSni()
    {
        await Assert.ThrowsAsync<AuthenticationException>(() => h.ConnectTlsAsync("github.com"));
    }

    [Fact]
    public async Task Http2IsNotNegotiatedWithTheProxyItself()
    {
        await using var outer = await h.ConnectTlsAsync("localhost", null, "h2", "http/1.1");
        Assert.Equal(SslApplicationProtocol.Http11, outer.NegotiatedApplicationProtocol);
        Assert.StartsWith("HTTP/1.1 200", await ConnectAsync(outer));
    }

    [Fact]
    public async Task RequestForTheProxyItselfIsNotTakenForTheWebUI()
    {
        await using var outer = await h.ConnectTlsAsync("localhost");
        var response = await Harness.ExchangeAsync(outer,
            $"GET /api/status HTTP/1.1\r\nHost: localhost:{h.ProxyTlsPort}\r\nConnection: close\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 400", response);
    }

    [Fact]
    public async Task HttpsUrlOutsideATunnelIsStillRefused()
    {
        await using var outer = await h.ConnectTlsAsync("localhost");
        var response = await Harness.ExchangeAsync(outer,
            $"GET https://localhost:{h.HttpsPort}/allowed HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 400", response);
    }

    [Fact]
    public async Task PlainTextOnTheTlsPortIsNotServed()
    {
        using var client = h.MakeClient(proxyUrl: $"http://127.0.0.1:{h.ProxyTlsPort}");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://localhost:{h.HttpPort}/allowed/x"));
    }

    [Fact]
    public async Task TlsOnThePlainPortIsNotServed()
    {
        using var client = h.MakeClient(proxyUrl: $"https://127.0.0.1:{h.ProxyPort}");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://localhost:{h.HttpPort}/allowed/x"));
    }
}
