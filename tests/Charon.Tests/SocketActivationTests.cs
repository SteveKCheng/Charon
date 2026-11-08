using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Charon.Tests;

/// <summary>Charon using the sockets that systemd passes, in place of binding their addresses.</summary>
[Collection("charon")]
public sealed class SocketActivationTests
{
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

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (!await condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting for: {what}");
            await Task.Delay(50);
        }
    }

    /// <summary>The user that a request through a Unix domain socket was recorded as, or null if it was refused.</summary>
    private static async Task<string?> UserOverSocketAsync(Harness h, string path)
    {
        var marker = $"/allowed/{Guid.NewGuid()}";
        try
        {
            await using var stream = await h.ConnectUnixAsync(path);
            var response = await Harness.ExchangeAsync(stream, PlainGet(h.HttpPort, marker));
            if (!response.StartsWith("HTTP/1.1 200"))
                return null;
        }
        catch (Exception e) when (e is IOException or SocketException)
        {
            return null;
        }

        return await h.WaitForTrafficAsync($"SELECT user FROM requests WHERE url LIKE '%{marker}'",
                                           r => r.IsDBNull(0) ? "(none)" : r.GetString(0));
    }

    /// <summary>Whether a connection gets closed without an answer, instead of being left to hang.</summary>
    private static async Task AssertClosedAsync(Stream stream)
    {
        var buffer = new byte[1];
        try
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(StatusRequest));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            Assert.Equal(0, await stream.ReadAsync(buffer, timeout.Token));
        }
        catch (IOException)
        {
            // Reset, which is closed as well.
        }
    }

    private static void RemoveSocketUser(Harness h)
    {
        var text = File.ReadAllText(h.UsersFile);
        var remaining = Regex.Replace(text, """\{ "name": "socket-user".*?\} \} \},""", "", RegexOptions.Singleline);
        Assert.NotEqual(text, remaining);
        File.WriteAllText(h.UsersFile, remaining);
    }

    [Fact]
    public async Task SocketOfUserFromSystemdIsUsedForTheUser()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(h.SocketPath)), "agent"));
            await h.InitializeAsync();

            Assert.Equal("socket-user", await UserOverSocketAsync(h, h.SocketPath));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ConnectionToSocketOfUserMadeBeforeStartingIsServed()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(h.SocketPath)), "agent"));

            // As systemd starts Charon on the first connection, which is waiting to be accepted.
            var marker = $"/allowed/{Guid.NewGuid()}";
            await using var stream = await h.ConnectUnixAsync(h.SocketPath);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(PlainGet(h.HttpPort, marker)));

            await h.InitializeAsync();

            Assert.StartsWith("HTTP/1.1 200", await Harness.ReadHeadAsync(stream));
            Assert.Equal("socket-user", await h.WaitForTrafficAsync(
                $"SELECT user FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ConnectionsToSocketsForNothingAreClosed()
    {
        var h = new Harness();
        try
        {
            var stray = Path.Combine(h.Directory, "stray.sock");
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(stray)), "stray"));
            var tcp = Listening(new IPEndPoint(IPAddress.Loopback, 0));
            var tcpEndPoint = (IPEndPoint)tcp.LocalEndPoint!;
            h.SystemdSockets.Add((tcp, "stray-tcp"));
            await h.InitializeAsync();

            await using (var stream = await h.ConnectUnixAsync(stray))
                await AssertClosedAsync(stream);

            using var client = new TcpClient();
            await client.ConnectAsync(tcpEndPoint);
            await AssertClosedAsync(client.GetStream());

            Assert.True(File.Exists(stray));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task SocketOfRemovedUserClosesConnectionsUntilTheUserIsBack()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(h.SocketPath)), "agent"));
            await h.InitializeAsync();
            Assert.Equal("socket-user", await UserOverSocketAsync(h, h.SocketPath));

            var users = File.ReadAllText(h.UsersFile);
            RemoveSocketUser(h);
            await WaitUntilAsync(async () => await UserOverSocketAsync(h, h.SocketPath) is null, "connections closed");
            await using (var stream = await h.ConnectUnixAsync(h.SocketPath))
                await AssertClosedAsync(stream);
            Assert.True(File.Exists(h.SocketPath), "The socket's file belongs to systemd.");

            // Charon could not bind the path again, as the socket from systemd is still listening there.
            File.WriteAllText(h.UsersFile, users);
            await WaitUntilAsync(async () => await UserOverSocketAsync(h, h.SocketPath) == "socket-user", "user back");
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task SocketOfUserIsBoundAgainIfTheFileFromSystemdIsDeleted()
    {
        var h = new Harness();
        try
        {
            h.SystemdSockets.Add((Listening(new UnixDomainSocketEndPoint(h.SocketPath)), "agent"));
            await h.InitializeAsync();

            File.Delete(h.SocketPath);
            await WaitUntilAsync(async () => await UserOverSocketAsync(h, h.SocketPath) == "socket-user", "new socket");
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task StoppingLeavesTheFileOfTheSocketOfAUser()
    {
        var h = new Harness();
        var socket = Listening(new UnixDomainSocketEndPoint(h.SocketPath));
        var target = Descriptors.Target((int)socket.SafeHandle.DangerousGetHandle())!;
        h.SystemdSockets.Add((socket, "agent"));
        await h.InitializeAsync();

        await h.StopCharonAsync();
        Assert.False(Descriptors.IsOpen(target));
        Assert.True(File.Exists(h.SocketPath), "The socket's file belongs to systemd.");
        await h.DisposeAsync();
    }
}
