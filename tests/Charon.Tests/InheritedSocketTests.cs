using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Charon.Tests;

/// <summary>Taking the sockets that systemd passes, made here by the tests instead.</summary>
public sealed class InheritedSocketTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("charon-inherit").FullName;
    private readonly ListLogger _logger = new();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                                Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));

        public IEnumerable<string> Warnings => Entries.Where(e => e.Level == LogLevel.Warning).Select(e => e.Message);
    }

    /// <summary>
    /// Gives up a descriptor without closing it, as it would be on being passed to a new
    /// process.  What it was is returned, to find whether it is still open later.
    /// </summary>
    private static (int Descriptor, string Target) Release(SafeHandle handle)
    {
        int descriptor = (int)handle.DangerousGetHandle();
        var target = Target(descriptor)!;
        handle.SetHandleAsInvalid();
        return (descriptor, target);
    }

    private static (int Descriptor, string Target) Release(Socket socket)
    {
        // It must not be disposed or finalized after this, as that would never finish.
        GC.SuppressFinalize(socket);
        return Release(socket.SafeHandle);
    }

    private static string? Target(int descriptor) => new FileInfo($"/proc/self/fd/{descriptor}").LinkTarget;

    /// <summary>
    /// Whether anything in this process still refers to what a descriptor was.  Its number
    /// may have been reused, by any test running at the same time, but a socket's inode is not.
    /// </summary>
    private static bool IsOpen(string target) =>
        Directory.EnumerateFileSystemEntries("/proc/self/fd").Any(path =>
        {
            try
            {
                return new FileInfo(path).LinkTarget == target;
            }
            catch (IOException)
            {
                return false;
            }
        });

    private static Socket Listening(EndPoint endPoint)
    {
        var socket = new Socket(endPoint.AddressFamily, SocketType.Stream,
                                endPoint is UnixDomainSocketEndPoint ? ProtocolType.Unspecified : ProtocolType.Tcp);
        socket.Bind(endPoint);
        socket.Listen();
        return socket;
    }

    private InheritedSockets Inherit(IEnumerable<(int Descriptor, string Target)> passed, params string[] names) =>
        new(passed.Select(p => p.Descriptor).ToArray(), names, _logger);

    [Theory]
    [InlineData(null, null, 0)]
    [InlineData("123", "2", 2)]
    [InlineData("123", "0", 0)]
    [InlineData("124", "2", 0)]
    [InlineData(null, "2", 0)]
    [InlineData("123", null, 0)]
    [InlineData("x", "2", 0)]
    public void CountIsBelievedOnlyIfMeantForThisProcess(string? pid, string? fds, int expected)
    {
        Assert.Equal(expected, InheritedSockets.CountPassed(pid, fds, 123, out var problem));
        Assert.Null(problem);
    }

    [Theory]
    [InlineData("")]
    [InlineData("x")]
    [InlineData("-1")]
    [InlineData("+2")]
    [InlineData(" 2")]
    [InlineData("2147483647")]
    public void CountThatIsNotANumberIsAProblem(string fds)
    {
        Assert.Equal(0, InheritedSockets.CountPassed("123", fds, 123, out var problem));
        Assert.Contains("LISTEN_FDS", problem);
    }

    [Fact]
    public void VariablesAreUnsetEvenIfMeantForAnotherProcess()
    {
        Environment.SetEnvironmentVariable("LISTEN_PID", (Environment.ProcessId + 1).ToString());
        Environment.SetEnvironmentVariable("LISTEN_FDS", "1");
        Environment.SetEnvironmentVariable("LISTEN_FDNAMES", "proxy");

        using var sockets = InheritedSockets.FromEnvironment(_logger);

        Assert.Empty(sockets.Remaining);
        Assert.Null(Environment.GetEnvironmentVariable("LISTEN_PID"));
        Assert.Null(Environment.GetEnvironmentVariable("LISTEN_FDS"));
        Assert.Null(Environment.GetEnvironmentVariable("LISTEN_FDNAMES"));
    }

    [Fact]
    public void SocketsAreFoundByTheAddressesTheyAreOn()
    {
        var path = Path.Combine(_directory, "proxy.sock");
        var ipv4 = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var ipv6 = Listening(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        var unix = Listening(new UnixDomainSocketEndPoint(path));
        var ipv4Port = ((IPEndPoint)ipv4.LocalEndPoint!).Port;
        var ipv6Port = ((IPEndPoint)ipv6.LocalEndPoint!).Port;

        using var sockets = Inherit([Release(ipv4), Release(ipv6), Release(unix)], "proxy", "", "user");
        Assert.Equal(3, sockets.Remaining.Length);
        Assert.Empty(_logger.Warnings);

        // As written in the settings, which need not be the same as what the system says.
        Assert.True(sockets.TryTake(ListenAddresses.Parse($"[0::1]:{ipv6Port}"), out var taken));
        Assert.Equal(new IPEndPoint(IPAddress.IPv6Loopback, ipv6Port), taken.EndPoint);
        Assert.Null(taken.Name);
        taken.Socket.Dispose();

        Assert.True(sockets.TryTake(ListenAddresses.Parse(path), out taken));
        Assert.Equal("user", taken.Name);
        taken.Socket.Dispose();

        var left = Assert.Single(sockets.Remaining);
        Assert.Equal(new IPEndPoint(IPAddress.Loopback, ipv4Port), left.EndPoint);
        Assert.Equal("proxy", left.Name);
    }

    [Fact]
    public void SocketCanBeTakenOnlyOnce()
    {
        var socket = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var endPoint = socket.LocalEndPoint!;
        using var sockets = Inherit([Release(socket)]);

        Assert.True(sockets.TryTake(endPoint, out var taken));
        Assert.False(sockets.TryTake(endPoint, out _));
        Assert.Empty(sockets.Remaining);
        taken.Socket.Dispose();
    }

    [Fact]
    public void OtherAddressIsNotFound()
    {
        var socket = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
        using var sockets = Inherit([Release(socket)]);

        Assert.False(sockets.TryTake(new IPEndPoint(IPAddress.Any, port), out _));
        Assert.False(sockets.TryTake(new IPEndPoint(IPAddress.IPv6Loopback, port), out _));
        Assert.False(sockets.TryTake(new IPEndPoint(IPAddress.Loopback, port + 1), out _));
        Assert.Single(sockets.Remaining);
    }

    [Fact]
    public async Task TakenSocketAcceptsConnections()
    {
        var socket = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var endPoint = (IPEndPoint)socket.LocalEndPoint!;
        using var sockets = Inherit([Release(socket)]);
        Assert.True(sockets.TryTake(endPoint, out var taken));

        using var client = new TcpClient();
        await client.ConnectAsync(endPoint);
        using var accepted = await taken.Socket.AcceptAsync();
        Assert.Equal(((IPEndPoint)client.Client.LocalEndPoint!).Port, ((IPEndPoint)accepted.RemoteEndPoint!).Port);
        taken.Socket.Dispose();
    }

    [Fact]
    public void ConnectionIsClosedAndNotKept()
    {
        using var listener = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Connect(listener.LocalEndPoint!);
        using var accepted = listener.Accept();

        // What Accept=yes would pass.
        var passed = Release(client);
        using var sockets = Inherit([passed]);

        Assert.Empty(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("not listening") && w.Contains($"descriptor {passed.Descriptor}"));
        Assert.False(IsOpen(passed.Target));
    }

    [Fact]
    public void SocketThatIsNotListeningIsClosed()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var passed = Release(socket);
        using var sockets = Inherit([passed]);

        Assert.Empty(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("not listening"));
        Assert.False(IsOpen(passed.Target));
    }

    [Fact]
    public void DatagramSocketIsClosed()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var passed = Release(socket);
        using var sockets = Inherit([passed]);

        Assert.Empty(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("Dgram"));
        Assert.False(IsOpen(passed.Target));
    }

    [Fact]
    public void FileIsClosed()
    {
        var path = Path.Combine(_directory, "not-a-socket");
        File.WriteAllText(path, "");
        var passed = Release(File.OpenHandle(path));
        using var sockets = Inherit([passed]);

        Assert.Empty(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("not a socket"));
        Assert.False(IsOpen(passed.Target));
    }

    [Fact]
    public void AbstractUnixDomainSocketIsClosed()
    {
        var socket = Listening(new UnixDomainSocketEndPoint($"\0charon-test-{Guid.NewGuid()}"));
        var passed = Release(socket);
        using var sockets = Inherit([passed]);

        Assert.Empty(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("not an address"));
        Assert.False(IsOpen(passed.Target));
    }

    [Fact]
    public void SecondSocketOnTheSameAddressIsClosed()
    {
        // Possible with ReusePort=yes in the unit.
        Socket ReusingPort()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.SetRawSocketOption(1, 15, BitConverter.GetBytes(1)); // SOL_SOCKET, SO_REUSEPORT
            return socket;
        }

        var first = ReusingPort();
        first.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        first.Listen();
        var second = ReusingPort();
        second.Bind(first.LocalEndPoint!);
        second.Listen();

        var kept = Release(first);
        var dropped = Release(second);
        using var sockets = Inherit([kept, dropped]);

        Assert.Single(sockets.Remaining);
        Assert.Contains(_logger.Warnings, w => w.Contains("already"));
        Assert.False(IsOpen(dropped.Target));
        Assert.True(IsOpen(kept.Target));
    }

    [Fact]
    public void DisposingClosesWhatWasNotTakenButLeavesTheFiles()
    {
        var path = Path.Combine(_directory, "proxy.sock");
        var unix = Listening(new UnixDomainSocketEndPoint(path));
        var tcp = Listening(new IPEndPoint(IPAddress.Loopback, 0));
        var endPoint = tcp.LocalEndPoint!;
        var left = Release(unix);
        var taken = Release(tcp);

        var sockets = Inherit([left, taken]);
        Assert.True(sockets.TryTake(endPoint, out var inherited));
        sockets.Dispose();

        Assert.False(IsOpen(left.Target));
        Assert.True(File.Exists(path), "The socket's file belongs to systemd.");
        Assert.True(IsOpen(taken.Target));

        inherited.Socket.Dispose();
        Assert.False(IsOpen(taken.Target));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void NothingIsInheritedByDefault()
    {
        using var sockets = InheritedSockets.None(_logger);
        Assert.Empty(sockets.Remaining);
        Assert.False(sockets.TryTake(new IPEndPoint(IPAddress.Loopback, 8080), out _));
    }
}
