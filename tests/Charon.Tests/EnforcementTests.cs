using System.Net;
using System.Text;

namespace Charon.Tests;

/// <summary>
/// Attempts by a hostile client to get past the whitelist.  In the requests here,
/// "localhost" is whitelisted and "127.0.0.1" is not, though they reach the same server.
/// </summary>
[Collection("charon")]
public sealed class EnforcementTests(Harness h)
{
    [Theory]
    [InlineData("GET", "/denied")]
    [InlineData("POST", "/allowed/get-only")]
    [InlineData("DELETE", "/allowed/post")]
    [InlineData("TRACE", "/allowed/x")]
    [InlineData("PROPFIND", "/allowed/x")]
    public async Task UnlistedMethodsAndPathsAreDenied(string method, string path)
    {
        using var client = h.MakeClient();
        var marker = $"{path}?{Guid.NewGuid()}";
        var response = await client.SendAsync(new HttpRequestMessage(
            new HttpMethod(method), $"https://localhost:{h.HttpsPort}{marker}"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("Access Denied", await response.Content.ReadAsStringAsync());
        Assert.False(h.UpstreamSaw(marker));
    }

    [Theory]
    [InlineData("HEAD", "/allowed/x")]
    [InlineData("OPTIONS", "/allowed/x")]
    [InlineData("POST", "/allowed/post/x")]
    [InlineData("PATCH", "/allowed/put/x")]
    [InlineData("DELETE", "/allowed/put/x")]
    public async Task MethodClassesOfTheAddInAreHonoured(string method, string path)
    {
        using var client = h.MakeClient();
        var response = await client.SendAsync(new HttpRequestMessage(
            new HttpMethod(method), $"https://localhost:{h.HttpsPort}{path}"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task HostHeaderCannotClaimAWhitelistedHostInATunnel()
    {
        // mitmproxy-whitelist falls to this: it would test the URL built from the Host header.
        var marker = $"/allowed/spoofed-{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"127.0.0.1:{h.HttpsPort}", "127.0.0.1");
        var response = await Harness.ExchangeAsync(tls,
            $"GET {marker} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 421", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task HostHeaderCannotFrontForAnotherSite()
    {
        var marker = $"/allowed/fronted-{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        var response = await Harness.ExchangeAsync(tls,
            $"GET {marker} HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 421", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task AbsoluteUrlInsideTunnelCannotRedirectIt()
    {
        var marker = $"/allowed/absolute-{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"127.0.0.1:{h.HttpsPort}", "127.0.0.1");
        var response = await Harness.ExchangeAsync(tls,
            $"GET https://localhost:{h.HttpsPort}{marker} HTTP/1.1\r\n" +
            $"Host: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.Matches(@"^HTTP/1\.1 4\d\d", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task Http2AuthorityCannotClaimAWhitelistedHost()
    {
        var marker = $"/allowed/h2-{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"127.0.0.1:{h.HttpsPort}", "127.0.0.1", "h2");
        Assert.Equal("h2", tls.NegotiatedApplicationProtocol.ToString());

        // A minimal HTTP/2 client: HPACK with literals only, and no Huffman coding.
        static byte[] Literal(int index, string value) =>
            [(byte)index, (byte)value.Length, .. Encoding.ASCII.GetBytes(value)];
        byte[] block =
        [
            0x82,   // :method GET
            0x87,   // :scheme https
            .. Literal(0x04, marker),
            .. Literal(0x01, $"localhost:{h.HttpsPort}"),
        ];
        byte[] frames =
        [
            .. "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8,
            0, 0, 0, 4, 0, 0, 0, 0, 0,   // SETTINGS
            0, (byte)(block.Length >> 8), (byte)block.Length, 1, 5, 0, 0, 0, 1,   // HEADERS, end of stream
            .. block,
        ];
        await tls.WriteAsync(frames);

        // The status arrives as a HEADERS frame on stream 1.
        var header = new byte[9];
        byte[] payload;
        do
        {
            await tls.ReadExactlyAsync(header);
            payload = new byte[(header[0] << 16) | (header[1] << 8) | header[2]];
            await tls.ReadExactlyAsync(payload);
        } while (header[3] != 1);

        // 421 is not in the HPACK static table, so it appears as a literal.
        Assert.Contains("421", Encoding.ASCII.GetString(payload));
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task PlainRequestCannotDisagreeWithItsHostHeader()
    {
        var marker = $"/allowed/plain-spoof-{Guid.NewGuid()}";
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://127.0.0.1:{h.HttpPort}{marker} HTTP/1.1\r\n" +
            $"Host: localhost:{h.HttpPort}\r\nConnection: close\r\n\r\n");

        Assert.Matches(@"^HTTP/1\.1 4\d\d", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task UserInfoCannotDisguiseTheHost()
    {
        var marker = $"/allowed/userinfo-{Guid.NewGuid()}";
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}@127.0.0.1:{h.HttpPort}{marker} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{h.HttpPort}\r\nConnection: close\r\n\r\n");

        Assert.Matches(@"^HTTP/1\.1 4\d\d", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Theory]
    [InlineData("/allowed/../secret")]
    [InlineData("/allowed/%2e%2e/secret")]
    [InlineData("/allowed/%2E%2E/secret")]
    [InlineData("/allowed/.%2e/secret")]
    [InlineData("/allowed/./../secret")]
    public async Task PathTraversalIsJudgedAsItWillBeForwarded(string path)
    {
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        var response = await Harness.ExchangeAsync(tls,
            $"GET {path} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 403", response);
        Assert.False(h.UpstreamSaw("/secret"));
    }

    [Fact]
    public async Task EncodedSlashesAreForwardedVerbatim()
    {
        // A known limit: this is one segment to the proxy, so it passes a rule for /allowed.
        // A server that decodes %2F before routing would see something else.  Rules cannot
        // currently guard against that, so this documents the behaviour rather than endorses it.
        var path = $"/allowed/x%2F..%2F..%2Fsecret-{Guid.NewGuid()}";
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        await Harness.ExchangeAsync(tls,
            $"GET {path} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");

        Assert.True(h.UpstreamSaw(path));
    }

    [Fact]
    public async Task RawTcpInTunnelGoesNowhere()
    {
        // The target is whitelisted for HTTPS, so that only protocol enforcement can stop this.
        int before = h.RawConnections;
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"CONNECT 127.0.0.1:{h.RawPort} HTTP/1.1\r\n\r\nSSH-2.0-OpenSSH_9.9\r\n");

        Assert.StartsWith("HTTP/1.1 200", response);
        Assert.DoesNotContain("SSH", response);
        Assert.Equal(before, h.RawConnections);
    }

    [Fact]
    public async Task NonHttpInsideTlsGoesNowhere()
    {
        int before = h.RawConnections;
        await using var tls = await h.OpenTunnelAsync($"127.0.0.1:{h.RawPort}", "127.0.0.1");
        await Harness.ExchangeAsync(tls, "\u0001\u0002 not HTTP at all\r\n\r\n");
        Assert.Equal(before, h.RawConnections);
    }

    [Theory]
    [InlineData("CONNECT localhost HTTP/1.1")]
    [InlineData("CONNECT localhost:0 HTTP/1.1")]
    [InlineData("CONNECT localhost:99999 HTTP/1.1")]
    [InlineData("CONNECT user@localhost:443 HTTP/1.1")]
    [InlineData("CONNECT local\u0001host:443 HTTP/1.1")]
    [InlineData("CONNECT [::1:443 HTTP/1.1")]
    [InlineData("CONNECT localhost:443 extra HTTP/1.1")]
    public async Task MalformedConnectIsRejected(string line)
    {
        await using var stream = await h.ConnectRawAsync();
        Assert.StartsWith("HTTP/1.1 400", await Harness.ExchangeAsync(stream, line + "\r\n\r\n"));
    }

    [Fact]
    public async Task ConnectAfterPlainRequestIsRefused()
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}/allowed/first HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\n\r\n" +
            $"CONNECT localhost:{h.HttpsPort} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\n\r\n");

        Assert.Contains("HTTP/1.1 200", response);
        Assert.DoesNotContain("established", response);
        Assert.Matches(@"HTTP/1\.1 4\d\d", response);
    }

    [Fact]
    public async Task OriginFormRequestsDoNotReachTheWebUi()
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET /api/traffic HTTP/1.1\r\nHost: localhost:{h.UiPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 400", response);
        Assert.DoesNotContain("text/event-stream", response);
    }

    [Fact]
    public async Task HostHeaderOfTheWebUiDoesNotRouteToIt()
    {
        // In a tunnel to a whitelisted host: this has the proxy's listener serve as the UI's.
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.UiPort}", "localhost");
        var response = await Harness.ExchangeAsync(tls,
            $"GET /ca.crt HTTP/1.1\r\nHost: localhost:{h.UiPort}\r\nConnection: close\r\n\r\n");

        Assert.DoesNotContain("BEGIN CERTIFICATE", response);
    }
}
