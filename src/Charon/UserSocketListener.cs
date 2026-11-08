using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;

namespace Charon;

/// <summary>Stands for all the Unix domain sockets of users, as one endpoint of Kestrel.</summary>
internal sealed class UserSocketsEndPoint : EndPoint
{
    public override string ToString() => "user-sockets";
}

/// <summary>Has Kestrel use <see cref="UserSocketListener"/> for <see cref="UserSocketsEndPoint"/>.</summary>
internal sealed class UserSocketListenerFactory(ProxyUserStore users, InheritedSockets inherited, ILoggerFactory loggerFactory)
    : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is UserSocketsEndPoint;

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<IConnectionListener>(new UserSocketListener(endpoint, users, inherited, loggerFactory));
}

/// <summary>
/// Listens on the Unix domain socket of each user, following changes to the list of users.
/// </summary>
/// <remarks>
/// <para>
/// Kestrel's endpoints are fixed once it has started, which is why this exists.  To Kestrel
/// this is one listener, and it hands over connections from whichever socket they
/// came in on.  Each carries the authenticator for its user: see <see cref="ProxyListener"/>.
/// Only the listening is done here, as connections are made by Kestrel's socket transport.
/// </para>
/// <para>
/// What is wanted is regularly compared with what exists, as opposed to reacting to changes
/// in the file.  That way this also recovers from what happens outside the proxy, such as a
/// socket getting deleted, or something in the way of one being removed.  Connections that
/// have been made are not cut off.  If a user goes away, their requests are refused instead.
/// </para>
/// <para>
/// Sockets from systemd that were not for the proxy or the Web UI are kept here, for the
/// whole time, as Charon cannot make systemd stop listening on them.  One is used for
/// the user with its path, if any.  Otherwise its connections are closed at once, as
/// leaving them waiting would have clients hang.
/// </para>
/// </remarks>
internal sealed class UserSocketListener : IConnectionListener
{
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromSeconds(1);

    /// <summary>Time to wait after accepting fails, as it is likely to fail again at once.</summary>
    private static readonly TimeSpan AcceptRetryDelay = TimeSpan.FromSeconds(1);

    /// <param name="Held">Set if the socket is from systemd.</param>
    private sealed record ActiveSocket(string UserName, Socket Socket, HeldSocket? Held = null);

    /// <summary>A socket from systemd, which is accepted on until stopping.</summary>
    private sealed class HeldSocket(Socket socket)
    {
        public Socket Socket => socket;

        /// <summary>Whose connections it gets, or null for them to be closed.</summary>
        public volatile string? UserName;
    }

    private readonly ProxyUserStore _users;
    private readonly ILogger _logger;
    private readonly SocketConnectionContextFactory _connectionFactory;
    private readonly CancellationTokenSource _stopping = new();
    private readonly Task _reconciling;

    private readonly Channel<ConnectionContext> _connections =
        Channel.CreateBounded<ConnectionContext>(new BoundedChannelOptions(64) { SingleReader = true });

    /// <summary>The sockets being listened on, by path.  Used only by the task that reconciles.</summary>
    private readonly Dictionary<string, ActiveSocket> _active = new();

    /// <summary>What is wrong with sockets that cannot be set up, so it is not logged every time.</summary>
    private readonly Dictionary<string, string> _problems = new();

    /// <summary>
    /// The sockets from systemd, by <see cref="ListenAddresses.Key"/>, which for a Unix domain
    /// socket is its path.  Used only by the task that reconciles, after being filled.
    /// </summary>
    private readonly Dictionary<string, HeldSocket> _held = new();

    public EndPoint EndPoint { get; }

    /// <param name="inherited">
    /// Takes all of the sockets left, so it should be after the proxy and the Web UI have theirs.
    /// </param>
    public UserSocketListener(EndPoint endPoint, ProxyUserStore users, InheritedSockets inherited, ILoggerFactory loggerFactory)
    {
        EndPoint = endPoint;
        _users = users;
        _logger = loggerFactory.CreateLogger<UserSocketListener>();
        _connectionFactory = new SocketConnectionContextFactory(new SocketConnectionFactoryOptions(), _logger);

        foreach (var remaining in inherited.Remaining)
        {
            if (!inherited.TryTake(remaining.EndPoint, out var taken))
                continue;

            _held[ListenAddresses.Key(taken.EndPoint)] = new HeldSocket(taken.Socket);
        }

        // The first time is not in the background, so the sockets are there once Kestrel has started.
        Reconcile();
        _reconciling = Task.Run(ReconcileRegularlyAsync);

        // Only now that they have their users, as there can be connections waiting already:
        // the one that had systemd start Charon, for a start.
        foreach (var (address, held) in _held)
        {
            _ = AcceptAsync(held.Socket, () => held.UserName, address);
            if (held.UserName is null)
            {
                _logger.LogWarning("systemd passed a socket on {Address}, which is not for the proxy, the Web UI " +
                                   "or any user, so connections to it are closed", address);
            }
        }
    }

    private async Task ReconcileRegularlyAsync()
    {
        using var timer = new PeriodicTimer(ReconcileInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(_stopping.Token))
                Reconcile();
        }
        catch (OperationCanceledException)
        {
        }

        foreach (var (path, active) in _active.ToArray())
        {
            if (active.Held is null)
                Stop(path);
        }

        // Their files are left alone, as they are systemd's.
        foreach (var held in _held.Values)
            held.Socket.Dispose();

        _connections.Writer.TryComplete();
    }

    /// <summary>Makes the sockets being listened on match what the users say.</summary>
    private void Reconcile()
    {
        var wanted = _users.UsersWithSockets.ToDictionary(user => user.Socket!, user => user.Name);
        var heldBefore = _held.Where(h => h.Value.UserName is not null).Select(h => h.Key).ToArray();

        foreach (var (path, active) in _active.ToArray())
        {
            if (!wanted.TryGetValue(path, out var userName) || userName != active.UserName || !File.Exists(path))
                Stop(path);
        }

        foreach (var (path, userName) in wanted)
        {
            if (!_active.ContainsKey(path))
                Start(path, userName);
        }

        foreach (var path in _problems.Keys.Where(path => !wanted.ContainsKey(path)).ToArray())
            _problems.Remove(path);

        // Not if the user has a new socket at the path, as the file of this one was deleted.
        foreach (var path in heldBefore.Where(path => _held[path].UserName is null && !_active.ContainsKey(path)))
            _logger.LogWarning("Closing connections to {Path}, the socket from systemd, as no user has it now", path);
    }

    private void Start(string path, string userName)
    {
        // Unless its file has been deleted: then it cannot be reached, and a new socket has to be bound.
        if (_held.TryGetValue(path, out var held) && File.Exists(path))
        {
            held.UserName = userName;
            _problems.Remove(path);
            _active[path] = new ActiveSocket(userName, held.Socket, held);
            _logger.LogInformation("Listening on {Path} for user {User}, with the socket from systemd", path, userName);
            return;
        }

        Socket? socket = null;
        try
        {
            if (!UnixSockets.TryPrepare(path, out var problem))
            {
                ReportProblem(path, problem);
                return;
            }

            socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.Bind(new UnixDomainSocketEndPoint(path));
            socket.Listen();
        }
        catch (Exception e) when (e is SocketException or IOException or UnauthorizedAccessException)
        {
            socket?.Dispose();
            ReportProblem(path, e.Message);
            return;
        }

        _problems.Remove(path);
        _active[path] = new ActiveSocket(userName, socket);
        _ = AcceptAsync(socket, () => userName, path);
        _logger.LogInformation("Listening on {Path} for user {User}", path, userName);
    }

    private void ReportProblem(string path, string problem)
    {
        if (_problems.GetValueOrDefault(path) == problem)
            return;

        _problems[path] = problem;
        _logger.LogError("Not listening on {Path}: {Problem}", path, problem);
    }

    /// <remarks>Disposing also removes the file of the socket, unless it is systemd's.</remarks>
    private void Stop(string path)
    {
        _active.Remove(path, out var active);
        if (active!.Held is { } held)
        {
            held.UserName = null;
            return;
        }

        active.Socket.Dispose();
        _logger.LogInformation("Stopped listening on {Path}", path);
    }

    /// <param name="userName">Whose connections are accepted now, or null for them to be closed.</param>
    private async Task AcceptAsync(Socket socket, Func<string?> userName, string address)
    {
        while (true)
        {
            try
            {
                var client = await socket.AcceptAsync(_stopping.Token);
                if (userName() is not { } name)
                {
                    client.Dispose();
                    continue;
                }

                var connection = _connectionFactory.Create(client);
                connection.Items[typeof(IClientAuthenticator)] = new FixedUserAuthenticator(name);

                try
                {
                    await _connections.Writer.WriteAsync(connection, _stopping.Token);
                }
                catch (Exception e) when (e is OperationCanceledException or ChannelClosedException)
                {
                    await connection.DisposeAsync();
                    return;
                }
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.OperationAborted)
            {
                return;
            }
            catch (SocketException e)
            {
                // Such as having run out of file descriptors.  The socket is still good.
                _logger.LogError("Could not accept a connection on {Address}: {Message}", address, e.Message);
                await Task.Delay(AcceptRetryDelay);
            }
        }
    }

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await _connections.Reader.ReadAsync(cancellationToken);
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        await _stopping.CancelAsync();
        await _reconciling.WaitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync();
        _connectionFactory.Dispose();
        _stopping.Dispose();
    }
}
