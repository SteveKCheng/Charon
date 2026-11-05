using System.Net;
using System.Net.WebSockets;
using System.Text;

namespace Charon.Tests;

/// <summary>Requests to whitelisted URLs that try to do more than the rules would suggest.</summary>
[Collection("charon")]
public sealed class RequestPolicyTests(Harness h)
{
    private async Task<string> SendInTunnelAsync(string head)
    {
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        return await Harness.ExchangeAsync(tls, head);
    }

    private string Headers => $"Host: localhost:{h.HttpsPort}\r\nConnection: close\r\n";

    [Theory]
    [InlineData("GET", "Content-Length: 7\r\n\r\npayload")]
    [InlineData("GET", "Transfer-Encoding: chunked\r\n\r\n7\r\npayload\r\n0\r\n\r\n")]
    [InlineData("HEAD", "Content-Length: 7\r\n\r\npayload")]
    [InlineData("OPTIONS", "Content-Length: 7\r\n\r\npayload")]
    public async Task ReadRulesDoNotAllowBodies(string method, string rest)
    {
        var marker = $"/allowed/body-{Guid.NewGuid()}";
        var response = await SendInTunnelAsync($"{method} {marker} HTTP/1.1\r\n{Headers}{rest}");
        Assert.StartsWith("HTTP/1.1 403", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task EmptyBodyDoesNotCount()
    {
        var response = await SendInTunnelAsync($"GET /allowed/empty HTTP/1.1\r\n{Headers}Content-Length: 0\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 200", response);
    }

    [Fact]
    public async Task BodyCanBeAllowedByItsOwnRule()
    {
        var response = await SendInTunnelAsync(
            $"GET /allowed/body-ok HTTP/1.1\r\n{Headers}Content-Length: 7\r\n\r\npayload");
        Assert.StartsWith("HTTP/1.1 200", response);
    }

    [Theory]
    [InlineData("X-HTTP-Method-Override: DELETE")]
    [InlineData("x-http-method-override: DELETE")]
    [InlineData("X-HTTP-Method: DELETE")]
    [InlineData("X-Method-Override: PUT")]
    [InlineData("X-Original-URL: /secret")]
    [InlineData("X-Rewrite-URL: /secret")]
    [InlineData("X-Forwarded-For: 127.0.0.1")]
    [InlineData("X-Forwarded-Host: evil.example")]
    [InlineData("X-Forwarded-Proto: http")]
    [InlineData("Forwarded: for=127.0.0.1")]
    [InlineData("X-Real-IP: 127.0.0.1")]
    [InlineData("X-Host: evil.example")]
    public async Task OverridesAreDenied(string header)
    {
        var marker = $"/allowed/override-{Guid.NewGuid()}";
        var response = await SendInTunnelAsync($"GET {marker} HTTP/1.1\r\n{Headers}{header}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 403", response);
        Assert.Contains("Access Denied", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Theory]
    [InlineData("_method=DELETE")]
    [InlineData("a=1&_METHOD=DELETE")]
    [InlineData("%5Fmethod=DELETE")]
    [InlineData("X-HTTP-Method-Override=DELETE")]
    public async Task OverridesInQueryAreDenied(string query)
    {
        var marker = $"/allowed/override-{Guid.NewGuid()}?{query}";
        var response = await SendInTunnelAsync($"POST {marker} HTTP/1.1\r\n{Headers}Content-Length: 0\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 403", response);
        Assert.False(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task OrdinaryParameterNamedSimilarlyIsFine()
    {
        var response = await SendInTunnelAsync($"GET /allowed/x?method=fast HTTP/1.1\r\n{Headers}\r\n");
        Assert.StartsWith("HTTP/1.1 200", response);
    }

    [Fact]
    public async Task WebSocketNeedsItsOwnRule()
    {
        // A GET rule covers this URL, which would have been enough.
        using var socket = h.MakeWebSocket();
        var e = await Assert.ThrowsAsync<WebSocketException>(() =>
            socket.ConnectAsync(new Uri($"wss://localhost:{h.HttpsPort}/allowed/ws-no-rule"), default));
        Assert.Contains("403", e.Message);
    }

    [Fact]
    public async Task WebSocketOverHttp2NeedsItsOwnRule()
    {
        using var socket = new ClientWebSocket();
        socket.Options.HttpVersion = HttpVersion.Version20;
        socket.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
        using var invoker = h.MakeInvoker();
        var e = await Assert.ThrowsAsync<WebSocketException>(() =>
            socket.ConnectAsync(new Uri($"wss://localhost:{h.HttpsPort}/allowed/ws-no-rule"), invoker, default));
        Assert.Contains("403", e.Message);
    }

    [Theory]
    [InlineData("h2c")]
    [InlineData("TLS/1.0")]
    [InlineData("some-other-protocol")]
    public async Task OtherUpgradesAreDenied(string protocol)
    {
        // Exactly the URL of a WEBSOCKET rule, so that it can only be the protocol that is refused.
        await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
        await tls.WriteAsync(Encoding.ASCII.GetBytes(
            $"GET /allowed/ws HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\n" +
            $"Connection: Upgrade\r\nUpgrade: {protocol}\r\n\r\n"));
        Assert.StartsWith("HTTP/1.1 403", await Harness.ReadHeadAsync(tls));
    }

    [Theory]
    [InlineData("/allowed/x%2F..%2F..%2Fsecret")]
    [InlineData("/allowed/x%2f..%2f..%2fsecret")]
    [InlineData("/allowed/x%5C..%5C..%5Csecret")]
    [InlineData("/allowed/x/..%2F..%2Fsecret")]
    [InlineData("/allowed/x/..%5Csecret")]
    [InlineData("/allowed/x%252F..%252F..%252Fsecret")]
    [InlineData("/allowed/%252e%252e/secret")]
    [InlineData("/allowed/%25252e%25252e/secret")]
    [InlineData("/allowed/..;/secret")]
    [InlineData("/allowed/..;x=1/secret")]
    [InlineData("/allowed/x%2F..")]
    public async Task EncodedTraversalIsDenied(string path)
    {
        var response = await SendInTunnelAsync($"GET {path} HTTP/1.1\r\n{Headers}\r\n");
        Assert.StartsWith("HTTP/1.1 403", response);
        Assert.False(h.UpstreamSaw(path));
    }

    [Theory]
    [InlineData("/allowed/@scope%2Fpackage")]
    [InlineData("/allowed/projects/group%2Fsubgroup%2Fname")]
    [InlineData("/allowed/file..name")]
    [InlineData("/allowed/...")]
    [InlineData("/allowed/a..%2Fb")]
    public async Task LegitimateEncodingsAndDotsPass(string path)
    {
        await SendInTunnelAsync($"GET {path} HTTP/1.1\r\n{Headers}\r\n");
        Assert.True(h.UpstreamSaw(path));
    }

    [Fact]
    public async Task DenialsExplainThemselvesToTheAgent()
    {
        var response = await SendInTunnelAsync(
            $"GET /allowed/x HTTP/1.1\r\n{Headers}Content-Length: 7\r\n\r\npayload");
        Assert.Contains("with a body", response);
    }
}
