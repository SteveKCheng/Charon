using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Charon.Tests;

/// <summary>Charon stopping when it has had no connections for a while.</summary>
[Collection("charon")]
public sealed class IdleExitTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(400);

    /// <summary>Longer than the timeout, with time to spare for a slow machine.</summary>
    private static readonly TimeSpan WellPastTimeout = TimeSpan.FromSeconds(2);

    private static Socket Listening(EndPoint endPoint)
    {
        if (endPoint is UnixDomainSocketEndPoint)
            Directory.CreateDirectory(Path.GetDirectoryName(endPoint.ToString())!);
        var socket = new Socket(endPoint.AddressFamily, SocketType.Stream,
                                endPoint is UnixDomainSocketEndPoint ? ProtocolType.Unspecified : ProtocolType.Tcp);
        socket.Bind(endPoint);
        socket.Listen();
        return socket;
    }

    /// <summary>Starts Charon as if by systemd, passing the socket for the proxy's IPv4 address.</summary>
    private static async Task<Harness> StartAsync(TimeSpan? timeout = null, bool countsWebUI = true, bool activated = true)
    {
        var h = new Harness { IdleTimeout = timeout ?? Timeout, IdleTimeoutCountsWebUI = countsWebUI };
        if (activated)
            h.SystemdSockets.Add((Listening(new IPEndPoint(IPAddress.Loopback, h.ProxyPort)), "proxy"));
        try
        {
            await h.InitializeAsync();
            return h;
        }
        catch
        {
            await h.DisposeAsync();
            throw;
        }
    }

    private static async Task AssertStopsAsync(Harness h)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(10), h.Stopping);
            Assert.Fail("Charon did not stop when idle.");
        }
        catch (TaskCanceledException)
        {
        }
    }

    private static async Task AssertKeepsRunningAsync(Harness h, TimeSpan duration)
    {
        await Task.Delay(duration);
        Assert.False(h.Stopping.IsCancellationRequested, "Charon stopped, but should not have.");
    }

    [Fact]
    public async Task StopsWhenNothingConnects()
    {
        var h = await StartAsync();
        try
        {
            await AssertStopsAsync(h);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenConnectionKeepsItRunningUntilClosed()
    {
        var h = await StartAsync();
        try
        {
            var stream = await h.ConnectRawAsync();
            await AssertKeepsRunningAsync(h, WellPastTimeout);

            await stream.DisposeAsync();
            await AssertStopsAsync(h);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenTunnelKeepsItRunning()
    {
        var h = await StartAsync();
        try
        {
            await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
            await AssertKeepsRunningAsync(h, WellPastTimeout);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task EachConnectionStartsTheTimeAgain()
    {
        var h = await StartAsync(TimeSpan.FromSeconds(3));
        try
        {
            // Connections far more often than the timeout, so that a slow machine is not a
            // problem, and for longer than it.
            for (int i = 0; i < 15; i++)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(300));
                await using (var stream = await h.ConnectRawAsync())
                {
                }
                Assert.False(h.Stopping.IsCancellationRequested, $"Charon stopped after connection {i}.");
            }

            await AssertStopsAsync(h);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ConnectionOfUserKeepsItRunning()
    {
        var h = await StartAsync();
        try
        {
            await using var stream = await h.ConnectUnixAsync(h.SocketPath);
            await AssertKeepsRunningAsync(h, WellPastTimeout);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task WebUIKeepsItRunningByDefault()
    {
        var h = await StartAsync();
        try
        {
            await using var stream = await h.ConnectUnixAsync(h.UiSocketPath);
            await AssertKeepsRunningAsync(h, WellPastTimeout);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task WebUIDoesNotKeepItRunningIfSoSet()
    {
        var h = await StartAsync(countsWebUI: false);
        try
        {
            // As the page does, for the stream of requests.
            await using var stream = await h.ConnectUnixAsync(h.UiSocketPath);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET /api/traffic HTTP/1.1\r\nHost: localhost\r\n\r\n"));

            await AssertStopsAsync(h);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task StoppingEndsTheStreamOfTheWebUI()
    {
        var h = new Harness();
        try
        {
            await h.InitializeAsync();

            // The head of the response is sent only with the first entry, so there has to be one.
            await using (var proxy = await h.ConnectRawAsync())
            {
                await Harness.ExchangeAsync(proxy,
                    $"GET http://localhost:{h.HttpPort}/allowed/x HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\nConnection: close\r\n\r\n");
            }

            await using var stream = await h.ConnectUnixAsync(h.UiSocketPath);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET /api/traffic HTTP/1.1\r\nHost: localhost\r\n\r\n"));
            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));

            // Kestrel would wait half a minute for the stream to end, by default.
            var stopping = h.StopCharonAsync();
            Assert.Same(stopping, await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(10))));
            await stopping;

            var buffer = new byte[64 * 1024];
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (await stream.ReadAsync(buffer, timeout.Token) > 0)
            {
            }
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task CompletingEndsStreamsOfTheLogNowAndLater()
    {
        var log = new TrafficLog(10);
        log.Add("client", "GET", "https://x.test/1", allowed: true);
        var early = log.SubscribeAsync(default).GetAsyncEnumerator();
        Assert.True(await early.MoveNextAsync());
        var waiting = early.MoveNextAsync().AsTask();
        Assert.False(waiting.IsCompleted);

        log.Complete();
        Assert.False(await waiting.WaitAsync(TimeSpan.FromSeconds(5)));

        // Such as a request on a connection kept alive, which comes in while stopping.
        var late = new List<TrafficEntry>();
        await foreach (var entry in log.SubscribeAsync(default).WithCancellation(new CancellationTokenSource(5000).Token))
            late.Add(entry);
        Assert.Equal("https://x.test/1", Assert.Single(late).Url);
    }

    [Fact]
    public async Task DoesNotStopIfNotStartedBySystemd()
    {
        var h = await StartAsync(activated: false);
        try
        {
            await AssertKeepsRunningAsync(h, WellPastTimeout);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task DoesNotStopWithoutTheSetting()
    {
        var h = new Harness();
        h.SystemdSockets.Add((Listening(new IPEndPoint(IPAddress.Loopback, h.ProxyPort)), "proxy"));
        try
        {
            await h.InitializeAsync();
            await AssertKeepsRunningAsync(h, WellPastTimeout);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task TimeoutMustBeMoreThanZero(int seconds)
    {
        var e = await Assert.ThrowsAsync<InvalidOperationException>(() => StartAsync(TimeSpan.FromSeconds(seconds)));
        Assert.Contains("IdleTimeout", e.Message);
    }
}
