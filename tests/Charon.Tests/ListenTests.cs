using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Charon.Tests;

/// <summary>Reading the addresses to listen on, which come from the settings.</summary>
public sealed class ListenAddressTests
{
    [Theory]
    [InlineData("127.0.0.1:8080", "127.0.0.1", 8080)]
    [InlineData("0.0.0.0:80", "0.0.0.0", 80)]
    [InlineData("192.168.122.1:65535", "192.168.122.1", 65535)]
    [InlineData("[::1]:8080", "::1", 8080)]
    [InlineData("[::]:8080", "::", 8080)]
    [InlineData("[fe80::1%1]:8080", "fe80::1%1", 8080)]
    public void IPAddressesWithPortsAreRead(string text, string address, int port)
    {
        var endPoint = Assert.IsType<IPEndPoint>(ListenAddresses.Parse(text));
        Assert.Equal(IPAddress.Parse(address), endPoint.Address);
        Assert.Equal(port, endPoint.Port);
    }

    [Fact]
    public void AbsolutePathIsAUnixDomainSocket()
    {
        var endPoint = Assert.IsType<UnixDomainSocketEndPoint>(ListenAddresses.Parse("/run/user/1000/http-proxy.socket"));
        Assert.Equal("/run/user/1000/http-proxy.socket", endPoint.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost:8080")]
    [InlineData("127.0.0.1")]
    [InlineData("8080")]
    [InlineData(":8080")]
    [InlineData("1:80")]
    [InlineData("127.1:80")]
    [InlineData("::1:8080")]
    [InlineData("[::1]")]
    [InlineData("[::1]8080")]
    [InlineData("[127.0.0.1]:8080")]
    [InlineData("127.0.0.1:0")]
    [InlineData("127.0.0.1:65536")]
    [InlineData("127.0.0.1:8080 ")]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("relative/proxy.sock")]
    [InlineData("~/proxy.sock")]
    public void OtherFormsAreRefused(string text)
    {
        Assert.Throws<FormatException>(() => ListenAddresses.Parse(text));
    }

    [Fact]
    public void PathOfSocketMustFitTheLimit()
    {
        var longest = "/" + new string('a', UnixSockets.MaxPathLength - 1);
        ListenAddresses.Parse(longest);
        Assert.Throws<FormatException>(() => ListenAddresses.Parse(longest + "a"));
    }

    [Fact]
    public void PathOfSocketIsMeasuredInBytes()
    {
        var path = "/" + new string('é', UnixSockets.MaxPathLength / 2 + 1);
        Assert.True(path.Length <= UnixSockets.MaxPathLength);
        Assert.Throws<FormatException>(() => ListenAddresses.Parse(path));
    }

    private static CharonOptions Load(params (string Key, string Value)[] settings) =>
        CharonOptions.Load(new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s => KeyValuePair.Create(s.Key, (string?)s.Value)))
            .Build());

    [Fact]
    public void DefaultsAreTheUsualPortsOnIPv4Loopback()
    {
        var (proxy, ui) = ListenAddresses.ParseSettings(Load());
        Assert.Equal([new IPEndPoint(IPAddress.Loopback, 8080)], proxy);
        Assert.Equal([new IPEndPoint(IPAddress.Loopback, 8081)], ui);
    }

    [Fact]
    public void ConfiguredAddressesReplaceTheDefaultsInsteadOfAddingToThem()
    {
        var (proxy, ui) = ListenAddresses.ParseSettings(Load(
            ("Charon:ProxyListen:0", "[::1]:9000"),
            ("Charon:ProxyListen:1", "/run/proxy.sock"),
            ("Charon:UiListen:0", "127.0.0.1:9001")));

        Assert.Equal(["[::1]:9000", "/run/proxy.sock"], proxy.Select(e => e.ToString()));
        Assert.Equal(["127.0.0.1:9001"], ui.Select(e => e.ToString()));
    }

    [Fact]
    public void EmptyListMeansNotListening()
    {
        var (proxy, ui) = ListenAddresses.ParseSettings(new CharonOptions { ProxyListen = [], UiListen = [] });
        Assert.Empty(proxy);
        Assert.Empty(ui);
    }

    [Theory]
    [InlineData("127.0.0.1:9000", "127.0.0.1:9000")]
    [InlineData("[::1]:9000", "[0:0::1]:9000")]
    [InlineData("/run/proxy.sock", "/run/proxy.sock")]
    public void SameAddressTwiceIsRefused(string first, string second)
    {
        Assert.Throws<InvalidOperationException>(() =>
            ListenAddresses.ParseSettings(new CharonOptions { ProxyListen = [first, second], UiListen = [] }));
        var e = Assert.Throws<InvalidOperationException>(() =>
            ListenAddresses.ParseSettings(new CharonOptions { ProxyListen = [first], UiListen = [second] }));
        Assert.Contains("UiListen", e.Message);
    }

    [Fact]
    public void BadAddressIsReportedWithItsSetting()
    {
        var e = Assert.Throws<InvalidOperationException>(() =>
            ListenAddresses.ParseSettings(new CharonOptions { UiListen = ["localhost:8081"] }));
        Assert.Contains("UiListen", e.Message);
        Assert.Contains("localhost:8081", e.Message);
    }

    [Theory]
    [InlineData("Charon:ProxyPort", "8080")]
    [InlineData("Charon:ListenAddress", "127.0.0.1")]
    [InlineData("Charon:WhitelistFlie", "/x")]
    public void UnknownSettingsAreRefused(string key, string value)
    {
        var e = Assert.Throws<InvalidOperationException>(() => Load((key, value)));
        Assert.Contains(key.Split(':')[1], e.Message);
    }

    [Fact]
    public void KnownSettingsAreRead()
    {
        var options = Load(("Charon:TrafficHeaders", "true"), ("Charon:ActivityTimeout", "00:01:00"));
        Assert.True(options.TrafficHeaders);
        Assert.Equal(TimeSpan.FromMinutes(1), options.ActivityTimeout);
    }

    [Fact]
    public void OtherSectionsAreNotChecked()
    {
        Load(("Logging:LogLevel:Default", "Warning"));
    }
}

/// <summary>Charon listening on all of the addresses it is given.</summary>
[Collection("charon")]
public sealed class ListeningTests(Harness h)
{
    private string PlainGet(int port, string path) =>
        $"GET http://localhost:{port}{path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n";

    [Fact]
    public async Task ProxyWorksOnIPv6()
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        using var client = new TcpClient(AddressFamily.InterNetworkV6);
        await client.ConnectAsync(IPAddress.IPv6Loopback, h.ProxyPort);

        Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(client.GetStream(), PlainGet(h.HttpPort, marker)));
        Assert.True(h.UpstreamSaw(marker));
    }

    [Fact]
    public async Task ProxyOnUnixSocketTreatsClientsAsAnonymous()
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        await using (var stream = await h.ConnectUnixAsync(h.ProxySocketPath))
            Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(stream, PlainGet(h.HttpPort, marker)));

        Assert.Equal(("unix", true), await h.WaitForTrafficAsync(
            $"SELECT client, user IS NULL FROM requests WHERE url LIKE '%{marker}'",
            r => (r.GetString(0), r.GetBoolean(1))));
    }

    [Fact]
    public async Task EmptyTunnelOnUnixSocketIsRecordedAsFromThere()
    {
        var target = $"{Guid.NewGuid()}.test:443";
        await using (var stream = await h.ConnectUnixAsync(h.ProxySocketPath))
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"));
            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));
        }

        Assert.Equal("unix", await h.WaitForTrafficAsync(
            $"SELECT client FROM requests WHERE url LIKE '%{target}%'", r => r.GetString(0)));
    }

    [Fact]
    public async Task TunnelOnUnixSocketGetsTheDefaultCredentials()
    {
        await using var tls = await h.OpenTunnelOverSocketAsync(path: h.ProxySocketPath);
        var response = await Harness.ExchangeAsync(tls,
            $"GET /api/bearer/echo HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");
        Assert.Contains($"X-Echo: Bearer {Harness.StaticToken}", response, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WebUIWorksOnUnixSocket()
    {
        await using var stream = await h.ConnectUnixAsync(h.UiSocketPath);
        var response = await Harness.ExchangeAsync(stream,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 200", response);
        Assert.Contains("\"version\"", response);
    }

    [Fact]
    public async Task WebUIIsNotOnTheProxySocket()
    {
        await using var stream = await h.ConnectUnixAsync(h.ProxySocketPath);
        var response = await Harness.ExchangeAsync(stream,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        Assert.DoesNotContain("\"version\"", response);
    }
}

/// <summary>What is in the way of a Unix domain socket when Charon starts.</summary>
[Collection("charon")]
public sealed class ListeningStartupTests
{
    private static Socket NewSocket() => new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);

    [Fact]
    public async Task StaleSocketIsReplaced()
    {
        var h = new Harness();
        try
        {
            // .NET removes the file when closing, unless it is somewhere else at the time.
            var aside = h.ProxySocketPath + ".aside";
            using (var socket = NewSocket())
            {
                socket.Bind(new UnixDomainSocketEndPoint(h.ProxySocketPath));
                socket.Listen();
                File.Move(h.ProxySocketPath, aside);
            }
            File.Move(aside, h.ProxySocketPath);

            await h.InitializeAsync();

            await using var stream = await h.ConnectUnixAsync(h.ProxySocketPath);
            Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(stream,
                $"GET http://localhost:{h.HttpPort}/allowed/x HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\nConnection: close\r\n\r\n"));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task FileInTheWayStopsStartingAndIsKept()
    {
        var h = new Harness();
        try
        {
            File.WriteAllText(h.UiSocketPath, "not a socket");

            var e = await Assert.ThrowsAsync<IOException>(h.InitializeAsync);
            Assert.Contains(h.UiSocketPath, e.Message);
            Assert.Equal("not a socket", File.ReadAllText(h.UiSocketPath));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task SocketOfAnotherInstanceStopsStarting()
    {
        var h = new Harness();
        try
        {
            using var other = NewSocket();
            other.Bind(new UnixDomainSocketEndPoint(h.ProxySocketPath));
            other.Listen();

            await Assert.ThrowsAsync<IOException>(h.InitializeAsync);

            using var client = NewSocket();
            client.Connect(new UnixDomainSocketEndPoint(h.ProxySocketPath));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task SocketsAreRemovedOnStopping()
    {
        var h = new Harness();
        await h.InitializeAsync();
        Assert.True(File.Exists(h.ProxySocketPath));
        Assert.True(File.Exists(h.UiSocketPath));

        await h.StopCharonAsync();
        Assert.False(File.Exists(h.ProxySocketPath));
        Assert.False(File.Exists(h.UiSocketPath));
        await h.DisposeAsync();
    }
}
