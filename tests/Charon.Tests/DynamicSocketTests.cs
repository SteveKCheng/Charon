using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Charon.Tests;

/// <summary>Sockets following changes to the users, with no need for a restart.</summary>
[Collection("charon")]
public sealed class DynamicSocketTests : IAsyncLifetime
{
    private readonly Harness _h = new();

    public Task InitializeAsync() => _h.InitializeAsync();

    public Task DisposeAsync() => _h.DisposeAsync();

    private string NewPath => Path.Combine(_h.Directory, "new", "proxy.sock");

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting for: {what}");
            await Task.Delay(50);
        }
    }

    private static bool IsListening(string path)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Connect(new UnixDomainSocketEndPoint(path));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private void AddUser(string entry)
    {
        var text = File.ReadAllText(_h.UsersFile).TrimEnd();
        File.WriteAllText(_h.UsersFile, text[..^1] + entry + "\n]");
    }

    private void ReplaceInUsers(string from, string to)
    {
        var text = File.ReadAllText(_h.UsersFile);
        Assert.Contains(from, text);
        File.WriteAllText(_h.UsersFile, text.Replace(from, to));
    }

    private void RemoveSocketUser()
    {
        var text = File.ReadAllText(_h.UsersFile);
        var remaining = Regex.Replace(text, """\{ "name": "socket-user".*?\} \} \},""", "", RegexOptions.Singleline);
        Assert.NotEqual(text, remaining);
        File.WriteAllText(_h.UsersFile, remaining);
    }

    private async Task<string> RepositoriesOverSocketAsync(string path)
    {
        await using var tls = await _h.OpenTunnelOverSocketAsync(path: path);
        var response = await Harness.ExchangeAsync(tls,
            $"GET /api/scoped/dynamic HTTP/1.1\r\nHost: localhost:{_h.HttpsPort}\r\nConnection: close\r\n\r\n");
        var token = Regex.Match(response, "ghs_installation_[0-9]+_[0-9]+").Value;

        // A socket of a user that was just removed refuses requests, until the socket changes.
        if (token.Length == 0)
            return "";

        lock (_h.TokenRequests)
            return _h.TokenRequests[int.Parse(token[(token.LastIndexOf('_') + 1)..]) - 1].Scope;
    }

    [Fact]
    public async Task AddedUserGetsASocket()
    {
        AddUser($$"""{ "name": "late", "socket": "{{NewPath}}", "credentials": { "scoped": { "repositories": ["late-repo"] } } }""");
        await WaitUntilAsync(() => IsListening(NewPath), "the new socket");

        Assert.Contains("late-repo", await RepositoriesOverSocketAsync(NewPath));
    }

    [Fact]
    public async Task RemovedUserLosesItsSocket()
    {
        RemoveSocketUser();
        await WaitUntilAsync(() => !File.Exists(_h.SocketPath), "the socket to be gone");
    }

    [Fact]
    public async Task OpenConnectionOfARemovedUserIsRefused()
    {
        await using var tls = await _h.OpenTunnelOverSocketAsync();
        RemoveSocketUser();
        await WaitUntilAsync(() => !File.Exists(_h.SocketPath), "the socket to be gone");

        var response = await Harness.ExchangeAsync(tls,
            $"GET /api/scoped/gone HTTP/1.1\r\nHost: localhost:{_h.HttpsPort}\r\nConnection: close\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", response);
    }

    [Fact]
    public async Task MovedSocketFollows()
    {
        ReplaceInUsers(_h.SocketPath, NewPath);
        await WaitUntilAsync(() => IsListening(NewPath) && !File.Exists(_h.SocketPath), "the socket to move");

        Assert.Contains("socket-repo", await RepositoriesOverSocketAsync(NewPath));
    }

    [Fact]
    public async Task SocketGivenToAnotherUserIdentifiesThatUser()
    {
        Assert.Contains("socket-repo", await RepositoriesOverSocketAsync(_h.SocketPath));

        RemoveSocketUser();
        AddUser($$"""{ "name": "heir", "socket": "{{_h.SocketPath}}", "credentials": { "scoped": { "repositories": ["heir-repo"] } } }""");

        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (true)
        {
            // It is briefly gone, and connections might still get the old user before that.
            try
            {
                if ((await RepositoriesOverSocketAsync(_h.SocketPath)).Contains("heir-repo"))
                    return;
            }
            catch (SocketException)
            {
            }

            Assert.True(DateTime.UtcNow < deadline, "The socket did not change hands");
            await Task.Delay(100);
        }
    }

    [Fact]
    public async Task DeletedSocketComesBack()
    {
        File.Delete(_h.SocketPath);
        await WaitUntilAsync(() => IsListening(_h.SocketPath), "the socket to come back");
        Assert.Contains("socket-repo", await RepositoriesOverSocketAsync(_h.SocketPath));
    }

    [Fact]
    public async Task ClearedPathStartsToWork()
    {
        Assert.False(IsListening(_h.BlockedSocketPath));
        File.Delete(_h.BlockedSocketPath);
        await WaitUntilAsync(() => IsListening(_h.BlockedSocketPath), "the socket to appear");
    }

    [Fact]
    public async Task InvalidEditKeepsTheSocketsAndCanBeRecoveredFrom()
    {
        var good = File.ReadAllText(_h.UsersFile);
        File.WriteAllText(_h.UsersFile, "[ this is not JSON");
        await Task.Delay(2500);

        Assert.True(IsListening(_h.SocketPath));
        Assert.Contains("socket-repo", await RepositoriesOverSocketAsync(_h.SocketPath));

        File.WriteAllText(_h.UsersFile, good);
        AddUser($$"""{ "name": "late", "socket": "{{NewPath}}" }""");
        await WaitUntilAsync(() => IsListening(NewPath), "the new socket");
    }

    [Fact]
    public async Task DeletingTheFileOfUsersRemovesSockets()
    {
        File.Delete(_h.UsersFile);
        await WaitUntilAsync(() => !File.Exists(_h.SocketPath), "the socket to be gone");
    }

    [Fact]
    public async Task OtherUsersAreNotDisturbed()
    {
        await using var tls = await _h.OpenTunnelOverSocketAsync();
        AddUser($$"""{ "name": "late", "socket": "{{NewPath}}" }""");
        await WaitUntilAsync(() => IsListening(NewPath), "the new socket");

        var response = await Harness.ExchangeAsync(tls,
            $"GET /allowed/undisturbed HTTP/1.1\r\nHost: localhost:{_h.HttpsPort}\r\nConnection: close\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 200", response);
    }

    [Fact]
    public async Task ManyConnectionsAtOnceWork()
    {
        await WaitUntilAsync(() => IsListening(_h.SocketPath), "the socket");

        var results = await Task.WhenAll(Enumerable.Range(0, 200).Select(async i =>
        {
            await using var stream = await _h.ConnectUnixAsync();
            return await Harness.ExchangeAsync(stream,
                $"GET http://localhost:{_h.HttpPort}/allowed/many-{i} HTTP/1.1\r\n" +
                $"Host: localhost:{_h.HttpPort}\r\nConnection: close\r\n\r\n");
        }));

        Assert.All(results, response => Assert.StartsWith("HTTP/1.1 200", response));
    }

    [Fact]
    public async Task StoppingRemovesTheSockets()
    {
        await WaitUntilAsync(() => IsListening(_h.SocketPath), "the socket");
        await _h.StopCharonAsync();
        Assert.False(File.Exists(_h.SocketPath));
    }
}
