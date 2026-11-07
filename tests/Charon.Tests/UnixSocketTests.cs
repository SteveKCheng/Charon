using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Charon.Tests;

/// <summary>A user's own socket, where the connection itself says who the client is.</summary>
[Collection("charon")]
public sealed class UnixSocketTests(Harness h)
{
    private string Head(string path) =>
        $"GET {path} HTTP/1.1\r\nHost: localhost:{h.HttpsPort}\r\nConnection: close\r\n\r\n";

    private string RepositoriesOf(string response)
    {
        var token = Regex.Match(response, "ghs_installation_[0-9]+_[0-9]+").Value;
        int index = int.Parse(token[(token.LastIndexOf('_') + 1)..]);
        lock (h.TokenRequests)
            return h.TokenRequests[index - 1].Scope;
    }

    [Fact]
    public async Task TunnelGetsTheCredentialsOfTheUserWithoutAPassword()
    {
        await using var tls = await h.OpenTunnelOverSocketAsync();
        Assert.Contains("socket-repo", RepositoriesOf(await Harness.ExchangeAsync(tls, Head("/api/scoped/socket"))));
    }

    [Fact]
    public async Task PlainRequestWorks()
    {
        var marker = Guid.NewGuid().ToString();
        await using var stream = await h.ConnectUnixAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}/allowed/{marker} HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\nConnection: close\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 200", response);
        Assert.Equal("socket-user", await h.WaitForTrafficAsync(
            $"SELECT user FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));
    }

    [Fact]
    public async Task RequestsAreRecordedWithUserAndNoAddress()
    {
        var marker = Guid.NewGuid().ToString();
        await using var tls = await h.OpenTunnelOverSocketAsync();
        await Harness.ExchangeAsync(tls, Head($"/denied/{marker}"));

        Assert.Equal("socket-user|unix", await h.WaitForTrafficAsync(
            $"SELECT user || '|' || client FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));
    }

    [Fact]
    public async Task PasswordsSentToTheSocketChangeNothing()
    {
        // Those of someone else, and wrong ones, do not make it anyone else or get it refused.
        foreach (var (user, password) in new[] { ("alice", "alice-pw"), ("alice", "wrong") })
        {
            var header = $"Proxy-Authorization: {Harness.BasicAuthorization(user, password)}\r\n";
            await using var tls = await h.OpenTunnelOverSocketAsync(header);
            Assert.Contains("socket-repo", RepositoriesOf(await Harness.ExchangeAsync(tls, Head("/api/scoped/socket"))));
        }

        await using var stream = await h.ConnectUnixAsync();
        var marker = Guid.NewGuid().ToString();
        await Harness.ExchangeAsync(stream,
            $"GET http://localhost:{h.HttpPort}/allowed/{marker} HTTP/1.1\r\nHost: localhost:{h.HttpPort}\r\n" +
            $"Proxy-Authorization: {Harness.BasicAuthorization("alice", "alice-pw")}\r\nConnection: close\r\n\r\n");
        Assert.Equal("socket-user", await h.WaitForTrafficAsync(
            $"SELECT user FROM requests WHERE url LIKE '%{marker}'", r => r.GetString(0)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("anything")]
    public async Task UserWithoutAPasswordCannotLogInOverTcp(string password)
    {
        await using var stream = await h.ConnectRawAsync();
        var response = await Harness.ExchangeAsync(stream,
            $"CONNECT localhost:{h.HttpsPort} HTTP/1.1\r\n" +
            $"Proxy-Authorization: {Harness.BasicAuthorization("socket-user", password)}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", response);
    }

    [Fact]
    public async Task WhitelistAndPolicyStillApply()
    {
        await using var tls = await h.OpenTunnelOverSocketAsync();
        Assert.StartsWith("HTTP/1.1 403", await Harness.ExchangeAsync(tls, Head("/denied/socket")));
    }

    [Fact]
    public void DirectoryOfTheSocketIsPrivate()
    {
        const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                    UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        Assert.Equal(0, (int)(File.GetUnixFileMode(Path.GetDirectoryName(h.SocketPath)!) & others));
    }

    [Fact]
    public async Task ProblemWithOneSocketLeavesTheProxyRunning()
    {
        // The harness has another user whose path is taken up by a regular file.
        Assert.Equal("not a socket", File.ReadAllText(h.BlockedSocketPath));

        await using var tls = await h.OpenTunnelOverSocketAsync();
        Assert.StartsWith("HTTP/1.1 200", await Harness.ExchangeAsync(tls, Head("/allowed/still-up")));
    }
}

public sealed class UnixSocketPreparationTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("charon-sock").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string SocketPath => Path.Combine(_directory, "s.sock");

    private static Socket NewSocket() => new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);

    /// <summary>Leaves what a process leaves behind when it gets killed.</summary>
    private void MakeStaleSocket()
    {
        // .NET removes the file when closing, unless it is somewhere else at the time.
        var aside = SocketPath + ".aside";
        using (var socket = NewSocket())
        {
            socket.Bind(new UnixDomainSocketEndPoint(SocketPath));
            socket.Listen();
            File.Move(SocketPath, aside);
        }
        File.Move(aside, SocketPath);
    }

    [Fact]
    public void NothingThereIsFine()
    {
        var path = Path.Combine(_directory, "new", "s.sock");
        Assert.True(UnixSockets.Prepare(path, null));
        Assert.True(Directory.Exists(Path.GetDirectoryName(path)));
    }

    [Fact]
    public void StaleSocketIsRemovedSoItCanBeBound()
    {
        MakeStaleSocket();
        Assert.True(File.Exists(SocketPath));

        Assert.True(UnixSockets.Prepare(SocketPath, null));

        using var socket = NewSocket();
        socket.Bind(new UnixDomainSocketEndPoint(SocketPath));
    }

    [Fact]
    public void RegularFileIsLeftAlone()
    {
        File.WriteAllText(SocketPath, "precious");
        Assert.False(UnixSockets.Prepare(SocketPath, null));
        Assert.Equal("precious", File.ReadAllText(SocketPath));
    }

    [Fact]
    public void SocketInUseIsLeftAlone()
    {
        using var listener = NewSocket();
        listener.Bind(new UnixDomainSocketEndPoint(SocketPath));
        listener.Listen();

        Assert.False(UnixSockets.Prepare(SocketPath, null));

        using var client = NewSocket();
        client.Connect(new UnixDomainSocketEndPoint(SocketPath));
    }

    [Theory]
    [InlineData("""{ "name": "a", "socket": "relative/path.sock" }""")]
    [InlineData("""{ "name": "a", "socket": "~/path.sock" }""")]
    public void InvalidPathsAreRejected(string entry) =>
        Assert.Throws<FormatException>(() => ProxyUserStore.Parse($"[{entry}]"));

    [Fact]
    public void OverlongPathIsRejected()
    {
        var path = "/" + new string('x', UnixSockets.MaxPathLength);
        Assert.Throws<FormatException>(() => ProxyUserStore.Parse($$"""[{ "name": "a", "socket": "{{path}}" }]"""));

        var longest = "/" + new string('x', UnixSockets.MaxPathLength - 1);
        Assert.Equal(longest, ProxyUserStore.Parse($$"""[{ "name": "a", "socket": "{{longest}}" }]""")["a"].Socket);
    }

    [Fact]
    public void SharedSocketIsRejected() => Assert.Throws<FormatException>(() => ProxyUserStore.Parse("""
        [{ "name": "a", "socket": "/s" }, { "name": "b", "socket": "/s" }]
        """));

    [Fact]
    public void SocketOrPasswordIsNeededAndBothAreAllowed()
    {
        Assert.Throws<FormatException>(() => ProxyUserStore.Parse("""[{ "name": "a" }]"""));
        Assert.Null(ProxyUserStore.Parse("""[{ "name": "a", "socket": "/s" }]""")["a"].PasswordHash);
        Assert.NotNull(ProxyUserStore.Parse("""[{ "name": "a", "socket": "/s", "password": "p" }]""")["a"].PasswordHash);
    }
}
