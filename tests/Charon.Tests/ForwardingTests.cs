using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;

namespace Charon.Tests;

/// <summary>Traffic that is allowed must arrive intact, by every means that clients use.</summary>
[Collection("charon")]
public sealed class ForwardingTests(Harness h)
{
    [Fact]
    public async Task PlainHttp()
    {
        using var client = h.MakeClient();
        var response = await client.GetAsync($"http://localhost:{h.HttpPort}/allowed/plain?a=1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/allowed/plain?a=1",
                     Harness.ParseEcho(await response.Content.ReadAsStringAsync()).GetProperty("path").GetString());
    }

    [Theory]
    [InlineData("1.1", "HTTP/2")]    // The two legs negotiate their versions independently.
    [InlineData("2.0", "HTTP/2")]
    public async Task HttpsWithEitherHttpVersion(string version, string upstreamProtocol)
    {
        using var client = h.MakeClient(Version.Parse(version));
        var response = await client.GetAsync($"https://localhost:{h.HttpsPort}/allowed/tls");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Version.Parse(version), response.Version);
        Assert.Equal(upstreamProtocol,
                     Harness.ParseEcho(await response.Content.ReadAsStringAsync()).GetProperty("protocol").GetString());
    }

    [Fact]
    public async Task ProxyHeadersDoNotLeakUpstream()
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}/allowed/headers HTTP/1.1\r\n" +
            $"Host: localhost:{h.HttpPort}\r\nProxy-Connection: keep-alive\r\n" +
            "Proxy-Authorization: Basic c2VjcmV0\r\nConnection: close\r\n\r\n");

        var headers = response[response.IndexOf('{')..];
        Assert.DoesNotContain("Proxy-", headers);
        Assert.DoesNotContain("traceparent", headers);
        Assert.DoesNotContain("X-Forwarded", headers);
    }

    [Fact]
    public async Task EventStreamIsNotBuffered()
    {
        using var client = h.MakeClient();
        using var response = await client.GetAsync($"https://localhost:{h.HttpsPort}/allowed/stream",
                                                   HttpCompletionOption.ResponseHeadersRead);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync());

        var times = new List<long>();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (await reader.ReadLineAsync() is { } line)
        {
            if (line.Length > 0)
                times.Add(clock.ElapsedMilliseconds);
        }

        Assert.Equal(5, times.Count);
        Assert.True(times[^1] - times[0] > 600, $"Events arrived together: {string.Join(' ', times)}");
    }

    [Fact]
    public async Task WebSocket()
    {
        using var socket = h.MakeWebSocket();
        await socket.ConnectAsync(new Uri($"wss://localhost:{h.HttpsPort}/allowed/ws"), default);
        await socket.SendAsync("hello"u8.ToArray(), WebSocketMessageType.Text, true, default);
        var buffer = new byte[64];
        var received = await socket.ReceiveAsync(buffer, default);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer, 0, received.Count));
    }

    [Fact]
    public async Task WebSocketOverHttp2()
    {
        using var socket = new ClientWebSocket();
        socket.Options.HttpVersion = HttpVersion.Version20;
        socket.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
        using var invoker = h.MakeInvoker();
        await socket.ConnectAsync(new Uri($"wss://localhost:{h.HttpsPort}/allowed/ws"), invoker, default);
        await socket.SendAsync("hello"u8.ToArray(), WebSocketMessageType.Text, true, default);
        var buffer = new byte[64];
        var received = await socket.ReceiveAsync(buffer, default);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer, 0, received.Count));
    }

    [Fact]
    public async Task UploadOverKestrelsDefaultLimit()
    {
        const long size = 40L * 1024 * 1024;
        using var client = h.MakeClient();
        using var content = new ByteArrayContent(new byte[size]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var response = await client.PostAsync($"https://localhost:{h.HttpsPort}/allowed/post/size", content);
        Assert.Equal(size.ToString(), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EarlyDataAfterConnectIsKept()
    {
        // Clients may send the TLS handshake without awaiting the response to CONNECT, and
        // the request can be split anywhere, including in the prefix that identifies it.
        await using var stream = await h.ConnectRawAsync();
        await stream.WriteAsync("CONN"u8.ToArray());
        await stream.FlushAsync();
        await Task.Delay(50);
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"ECT localhost:{h.HttpsPort} HTTP/1.1\r\n\r"));
        await stream.FlushAsync();
        await Task.Delay(50);
        await stream.WriteAsync("\nEARLY"u8.ToArray());
        Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));
    }

    [Fact]
    public async Task UpstreamCertificatesAreVerified()
    {
        using var client = h.MakeClient();
        var response = await client.GetAsync($"https://localhost:{h.UntrustedHttpsPort}/allowed/x");
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task RulesReloadWithoutRestart()
    {
        var url = $"https://localhost:{h.HttpsPort}/reloaded";
        using var client = h.MakeClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(url)).StatusCode);

        var original = File.ReadAllText(h.WhitelistFile);
        File.WriteAllText(h.WhitelistFile, original + "\nGET: /reloaded$\n");
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while ((await client.GetAsync(url)).StatusCode != HttpStatusCode.OK)
            {
                Assert.True(DateTime.UtcNow < deadline, "New rule did not take effect");
                await Task.Delay(100);
            }
        }
        finally
        {
            File.WriteAllText(h.WhitelistFile, original);
        }
    }

    [Fact]
    public async Task WebUiShowsAllowedAndDeniedTraffic()
    {
        using var client = h.MakeClient();
        await client.GetAsync($"https://localhost:{h.HttpsPort}/allowed/seen-in-ui");
        await client.GetAsync($"https://localhost:{h.HttpsPort}/denied-seen-in-ui");

        using var ui = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var response = await ui.GetAsync($"http://127.0.0.1:{h.UiPort}/api/traffic",
                                               HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);

        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(timeout.Token));
        bool sawAllowed = false, sawDenied = false;
        while (!(sawAllowed && sawDenied) && await reader.ReadLineAsync(timeout.Token) is { } line)
        {
            sawAllowed |= line.Contains("/allowed/seen-in-ui");
            sawDenied |= line.Contains("/denied-seen-in-ui") && line.Contains("\"allowed\":false");
        }

        Assert.True(sawAllowed && sawDenied);
    }
}
