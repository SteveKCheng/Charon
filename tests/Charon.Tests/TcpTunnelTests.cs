using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Charon.Tests;

/// <summary>Tunnels with any data in them, as TCP rules allow.</summary>
[Collection("charon")]
public sealed class TcpTunnelTests(Harness h) : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    private readonly TcpListener _server = Start(Harness.TcpAddress, 0);

    private static TcpListener Start(IPAddress address, int port)
    {
        var listener = new TcpListener(address, port);
        listener.Start();
        return listener;
    }

    public void Dispose() => _server.Dispose();

    private int Port => ((IPEndPoint)_server.LocalEndpoint).Port;
    private string Target => $"{Harness.TcpAddress}:{Port}";

    private static async Task<Socket> AcceptAsync(TcpListener server)
    {
        using var timeout = new CancellationTokenSource(Limit);
        return await server.AcceptSocketAsync(timeout.Token);
    }

    private static async Task<Socket> ConnectProxyAsync(Harness h)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        await socket.ConnectAsync(IPAddress.Loopback, h.ProxyPort);
        return socket;
    }

    private static Task SendAsync(Socket socket, string text) => socket.SendAsync(Encoding.Latin1.GetBytes(text));

    /// <summary>Not through a NetworkStream, which does not work once the socket has been shut down one way.</summary>
    private static async Task<string> ReceiveAsync(Socket socket, int length)
    {
        using var timeout = new CancellationTokenSource(Limit);
        var buffer = new byte[length];
        for (int total = 0; total < length;)
        {
            int count = await socket.ReceiveAsync(buffer.AsMemory(total), timeout.Token);
            if (count == 0)
                throw new EndOfStreamException();
            total += count;
        }
        return Encoding.Latin1.GetString(buffer);
    }

    private static async Task<string> ReceiveAsync(Stream stream, int length)
    {
        using var timeout = new CancellationTokenSource(Limit);
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, timeout.Token);
        return Encoding.Latin1.GetString(buffer);
    }

    private static async Task AssertEndAsync(Socket socket)
    {
        using var timeout = new CancellationTokenSource(Limit);
        Assert.Equal(0, await socket.ReceiveAsync(new byte[1], timeout.Token));
    }

    private static async Task<string> RequestAsync(Socket socket, string target, string version = "1.1", string after = "")
    {
        await SendAsync(socket, $"CONNECT {target} HTTP/{version}\r\n\r\n{after}");
        return await Harness.ReadHeadAsync(new NetworkStream(socket));
    }

    private async Task<(Socket Client, Socket Server)> OpenAsync()
    {
        var client = await ConnectProxyAsync(h);
        var accepting = AcceptAsync(_server);
        Assert.StartsWith("HTTP/1.1 200", await RequestAsync(client, Target));
        return (client, await accepting);
    }

    private Task<(int? Status, string? Note, string? Rule, bool Allowed, string? User)> LoggedAsync(string target) =>
        h.WaitForTrafficAsync(
            $"SELECT status, note, rule, allowed, user FROM requests WHERE method = 'CONNECT' AND url = 'tcp://{target}/' AND status IS NOT NULL",
            r => ((int?)r.GetInt32(0), r.IsDBNull(1) ? null : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2),
                  r.GetBoolean(3), r.IsDBNull(4) ? null : r.GetString(4)));

    [Fact]
    public async Task ServerMaySpeakFirst()
    {
        var (client, server) = await OpenAsync();
        using (client)
        using (server)
        {
            await SendAsync(server, "SSH-2.0-test\r\n");
            Assert.Equal("SSH-2.0-test\r\n", await ReceiveAsync(client, 14));
            await SendAsync(client, "hello");
            Assert.Equal("hello", await ReceiveAsync(server, 5));
        }
    }

    [Fact]
    public async Task TlsIsNotIntercepted()
    {
        var (client, server) = await OpenAsync();
        using (client)
        using (server)
        {
            await SendAsync(client, "\x16\x03\x01\x00\x05hello");
            Assert.Equal("\x16\x03\x01\x00\x05hello", await ReceiveAsync(server, 10));
        }
    }

    [Fact]
    public async Task EarlyDataIsKeptAndHttp10IsAccepted()
    {
        using var client = await ConnectProxyAsync(h);
        var accepting = AcceptAsync(_server);
        Assert.StartsWith("HTTP/1.1 200", await RequestAsync(client, Target, "1.0", "early"));
        using var server = await accepting;
        Assert.Equal("early", await ReceiveAsync(server, 5));
    }

    [Fact]
    public async Task ResponseArrivesAfterClientFinishesSending()
    {
        var (client, server) = await OpenAsync();
        using (client)
        using (server)
        {
            await SendAsync(client, "request");
            client.Shutdown(SocketShutdown.Send);
            Assert.Equal("request", await ReceiveAsync(server, 7));
            await AssertEndAsync(server);

            await Task.Delay(300);
            await SendAsync(server, "response");
            Assert.Equal("response", await ReceiveAsync(client, 8));
            server.Shutdown(SocketShutdown.Send);
            await AssertEndAsync(client);
        }

        var logged = await LoggedAsync(Target);
        Assert.Equal((200, "7 bytes sent, 8 bytes received", true), (logged.Status, logged.Note, logged.Allowed));
        Assert.StartsWith("TCP: ", logged.Rule);
    }

    [Fact]
    public async Task ServerFinishingClosesTheTunnelAfterItsData()
    {
        var (client, server) = await OpenAsync();
        using (client)
        {
            await SendAsync(server, "bye");
            server.Dispose();
            Assert.Equal("bye", await ReceiveAsync(client, 3));
            await AssertEndAsync(client);
        }
    }

    [Fact]
    public async Task ResetByTheServerIsNotTakenForTheEnd()
    {
        var (client, server) = await OpenAsync();
        using (client)
        {
            await SendAsync(server, "partial");
            Assert.Equal("partial", await ReceiveAsync(client, 7));
            server.LingerState = new LingerOption(true, 0);
            server.Dispose();

            using var timeout = new CancellationTokenSource(Limit);
            await Assert.ThrowsAsync<SocketException>(async () => await client.ReceiveAsync(new byte[1], timeout.Token));
        }

        Assert.Contains("Server disconnected", (await LoggedAsync(Target)).Note);
    }

    [Fact]
    public async Task ClientGoingAwayClosesTheConnectionToTheServer()
    {
        var (client, server) = await OpenAsync();
        using (server)
        {
            client.LingerState = new LingerOption(true, 0);
            client.Dispose();

            using var timeout = new CancellationTokenSource(Limit);
            try
            {
                Assert.Equal(0, await server.ReceiveAsync(new byte[1], timeout.Token));
            }
            catch (SocketException)
            {
            }
        }

        Assert.Contains("Client disconnected", (await LoggedAsync(Target)).Note);
    }

    [Fact]
    public async Task LargeTransfersInBothDirectionsAtOnce()
    {
        const int size = 16 * 1024 * 1024;
        var toServer = new byte[size];
        var toClient = new byte[size];
        new Random(1).NextBytes(toServer);
        new Random(2).NextBytes(toClient);

        var (client, server) = await OpenAsync();
        using (client)
        using (server)
        {
            async Task<byte[]> ReadAllAsync(Socket socket)
            {
                var buffer = new byte[size];
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                await new NetworkStream(socket).ReadExactlyAsync(buffer, timeout.Token);
                return buffer;
            }

            var atServer = ReadAllAsync(server);
            var atClient = ReadAllAsync(client);
            await Task.WhenAll(new NetworkStream(client).WriteAsync(toServer).AsTask(),
                               new NetworkStream(server).WriteAsync(toClient).AsTask());
            var (receivedByServer, receivedByClient) = (await atServer, await atClient);
            Assert.True(toServer.AsSpan().SequenceEqual(receivedByServer));
            Assert.True(toClient.AsSpan().SequenceEqual(receivedByClient));
        }
    }

    [Theory]
    [InlineData("localhost", "127.0.0.1")]
    [InlineData("localhost", "::1")]
    [InlineData("[::1]", "::1")]
    public async Task HostsAreResolvedByTheProxy(string host, string address)
    {
        using var listener = Start(IPAddress.Parse(address), h.TcpPort);
        using var client = await ConnectProxyAsync(h);
        var accepting = AcceptAsync(listener);
        Assert.StartsWith("HTTP/1.1 200", await RequestAsync(client, $"{host}:{h.TcpPort}"));
        using var server = await accepting;
        await SendAsync(server, "x");
        Assert.Equal("x", await ReceiveAsync(client, 1));
    }

    [Fact]
    public async Task FailureToConnectIsReported()
    {
        var target = Target;
        _server.Stop();
        using var client = await ConnectProxyAsync(h);
        Assert.StartsWith("HTTP/1.1 502", await RequestAsync(client, target));
        await AssertEndAsync(client);

        var logged = await LoggedAsync(target);
        Assert.Equal(502, logged.Status);
        Assert.Contains("ConnectionRefused", logged.Note);
    }

    [Fact]
    public async Task OtherPortsOfAnAllowedHostAreNotConnectedTo()
    {
        using var listener = Start(IPAddress.Loopback, 0);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var stream = await h.ConnectRawAsync();
        await Harness.ExchangeAsync(stream, $"CONNECT localhost:{port} HTTP/1.1\r\n\r\nSSH-2.0-test\r\n");
        Assert.False(listener.Pending());
    }

    [Fact]
    public async Task WrongPasswordIsRefusedBeforeConnecting()
    {
        using var client = await ConnectProxyAsync(h);
        await SendAsync(client, $"CONNECT {Target} HTTP/1.1\r\nProxy-Authorization: {Harness.BasicAuthorization("alice", "wrong")}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", await Harness.ReadHeadAsync(new NetworkStream(client)));
        Assert.False(_server.Pending());
    }

    [Fact]
    public async Task WorksOverTlsToTheProxyAndIdentifiesTheUser()
    {
        var accepting = AcceptAsync(_server);
        await using (var outer = await h.ConnectTlsAsync("localhost"))
        {
            await outer.WriteAsync(Encoding.ASCII.GetBytes(
                $"CONNECT {Target} HTTP/1.1\r\nProxy-Authorization: {Harness.BasicAuthorization("alice", "alice-pw")}\r\n\r\n"));
            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(outer));
            using var server = await accepting;
            await SendAsync(server, "banner");
            Assert.Equal("banner", await ReceiveAsync(outer, 6));
            await outer.WriteAsync("hello"u8.ToArray());
            Assert.Equal("hello", await ReceiveAsync(server, 5));

            // Half-closing works here as well: TLS has its own way of saying so.
            await outer.ShutdownAsync();
            await AssertEndAsync(server);
            await SendAsync(server, "late");
            Assert.Equal("late", await ReceiveAsync(outer, 4));
        }

        Assert.Equal("alice", (await LoggedAsync(Target)).User);
    }

    [Fact]
    public async Task WorksOnTheSocketOfAUser()
    {
        var accepting = AcceptAsync(_server);
        await using (var stream = await h.ConnectUnixAsync())
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {Target} HTTP/1.1\r\n\r\n"));
            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));
            using var server = await accepting;
            await SendAsync(server, "banner");
            Assert.Equal("banner", await ReceiveAsync(stream, 6));
        }

        Assert.Equal("socket-user", (await LoggedAsync(Target)).User);
    }

    private static async Task WithOwnCharonAsync(Harness own, Func<Harness, Task> test)
    {
        try
        {
            await own.InitializeAsync();
            await test(own);
        }
        finally
        {
            await own.DisposeAsync();
        }
    }

    [Fact]
    public Task SilentServerIsDroppedOnlyOnceTheClientHasFinished() =>
        WithOwnCharonAsync(new Harness { ActivityTimeout = TimeSpan.FromSeconds(1) }, async own =>
        {
            using var client = await ConnectProxyAsync(own);
            var accepting = AcceptAsync(_server);
            Assert.StartsWith("HTTP/1.1 200", await RequestAsync(client, Target));
            using var server = await accepting;

            // Idle for longer than the timeout.
            await Task.Delay(2500);
            await SendAsync(server, "still here");
            Assert.Equal("still here", await ReceiveAsync(client, 10));

            client.Shutdown(SocketShutdown.Send);
            await AssertEndAsync(server);

            // The data starts the time again.
            for (int i = 0; i < 4; i++)
            {
                await Task.Delay(500);
                await SendAsync(server, "x");
                Assert.Equal("x", await ReceiveAsync(client, 1));
            }

            using var timeout = new CancellationTokenSource(Limit);
            await Assert.ThrowsAsync<SocketException>(async () => await client.ReceiveAsync(new byte[1], timeout.Token));
        });

    [Fact]
    public Task StoppingClosesTunnels() =>
        WithOwnCharonAsync(new Harness(), async own =>
        {
            using var client = await ConnectProxyAsync(own);
            var accepting = AcceptAsync(_server);
            Assert.StartsWith("HTTP/1.1 200", await RequestAsync(client, Target));
            using var server = await accepting;

            await own.StopCharonAsync().WaitAsync(Limit);
        });

    [Fact]
    public Task UpstreamProxyIsNotBypassed() =>
        WithOwnCharonAsync(new Harness { UpstreamProxy = "http://127.0.0.1:9" }, async own =>
        {
            using var client = await ConnectProxyAsync(own);
            Assert.StartsWith("HTTP/1.1 501", await RequestAsync(client, Target));
            Assert.False(_server.Pending());
        });
}
