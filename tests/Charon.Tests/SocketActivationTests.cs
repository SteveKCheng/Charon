using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Charon.Tests;

/// <summary>Charon using the sockets that systemd passes, in place of binding their addresses.</summary>
[Collection("charon")]
public sealed class SocketActivationTests
{
    private static Socket Listening(EndPoint endPoint)
    {
        var socket = new Socket(endPoint.AddressFamily, SocketType.Stream,
                                endPoint is UnixDomainSocketEndPoint ? ProtocolType.Unspecified : ProtocolType.Tcp);
        socket.Bind(endPoint);
        socket.Listen();
        return socket;
    }

    private static string PlainGet(int port, string path) =>
        $"GET http://localhost:{port}{path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n";

    private const string StatusRequest = "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    /// <summary>
    /// Charon would fail to start if it bound these addresses itself, as the sockets
    /// from "systemd" are on them.  So that it starts at all shows that it used them.
    /// </summary>
    [Fact]
    public async Task SocketsFromSystemdAreUsedForTheirAddresses()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new IPEndPoint(IPAddress.Loopback, h.ProxyPort)), "proxy"));
            // The name is only for messages: what the socket is for is decided by its address.
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(h.UiSocketPath)), "proxy"));

            await h.InitializeAsync();

            var marker = $"/allowed/{Guid.NewGuid()}";
            await using (var stream = await h.ConnectRawAsync())
                Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(stream, PlainGet(h.HttpPort, marker)));
            Assert.True(h.UpstreamSaw(marker));

            await using (var stream = await h.ConnectUnixAsync(h.UiSocketPath))
                Assert.Contains("\"version\"", await Harness.ExchangeAsync(stream, StatusRequest));

            // The addresses that systemd did not pass are listened on by Charon itself.
            await using (var stream = await h.ConnectUnixAsync(h.ProxySocketPath))
                Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(stream, PlainGet(h.HttpPort, marker)));
            using (var ipv6 = new TcpClient(AddressFamily.InterNetworkV6))
            {
                await ipv6.ConnectAsync(IPAddress.IPv6Loopback, h.ProxyPort);
                Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(ipv6.GetStream(), PlainGet(h.HttpPort, marker)));
            }
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ConnectionMadeBeforeStartingIsServed()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new IPEndPoint(IPAddress.Loopback, h.ProxyPort)), "proxy"));

            // As systemd starts Charon on the first connection, which is waiting to be accepted.
            using var early = new TcpClient();
            await early.ConnectAsync(IPAddress.Loopback, h.ProxyPort);
            var marker = $"/allowed/{Guid.NewGuid()}";
            var stream = early.GetStream();
            stream.ReadTimeout = 10_000;
            await stream.WriteAsync(Encoding.ASCII.GetBytes(PlainGet(h.HttpPort, marker)));

            await h.InitializeAsync();

            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));
            Assert.True(h.UpstreamSaw(marker));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task TunnelWorksOnSocketFromSystemd()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new IPEndPoint(IPAddress.Loopback, h.ProxyPort)), "proxy"));
            await h.InitializeAsync();

            await using var tls = await h.OpenTunnelAsync($"localhost:{h.HttpsPort}", "localhost");
            var response = await Harness.ExchangeAsync(tls,
                $"GET /api/bearer/echo HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n");
            Assert.Contains($"X-Echo: Bearer {Harness.StaticToken}", response, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task StoppingClosesTheSocketsButLeavesTheirFiles()
    {
        var h = new Harness();
        var socket = Listening(new UnixDomainSocketEndPoint(h.ProxySocketPath));
        var target = Descriptors.Target((int)socket.SafeHandle.DangerousGetHandle())!;
        h.SystemdSockets.Add((socket, "proxy"));
        await h.InitializeAsync();
        Assert.True(Descriptors.IsOpen(target));

        await h.StopCharonAsync();
        Assert.False(Descriptors.IsOpen(target));
        Assert.True(File.Exists(h.ProxySocketPath), "The socket's file belongs to systemd.");
        Assert.False(File.Exists(h.UiSocketPath), "Charon removes the files of sockets it bound itself.");
        await h.DisposeAsync();
    }
}
