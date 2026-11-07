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
internal sealed class UserSocketListenerFactory(ProxyUserStore users, ILoggerFactory loggerFactory)
    : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is UserSocketsEndPoint;

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<IConnectionListener>(new UserSocketListener(endpoint, users, loggerFactory));
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
/// </remarks>
internal sealed class UserSocketListener : IConnectionListener
{
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromSeconds(1);

    /// <summary>Time to wait after accepting fails, as it is likely to fail again at once.</summary>
    private static readonly TimeSpan AcceptRetryDelay = TimeSpan.FromSeconds(1);

    private sealed record ActiveSocket(string UserName, Socket Socket);

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

    public EndPoint EndPoint { get; }

    public UserSocketListener(EndPoint endPoint, ProxyUserStore users, ILoggerFactory loggerFactory)
    {
        EndPoint = endPoint;
        _users = users;
        _logger = loggerFactory.CreateLogger<UserSocketListener>();
        _connectionFactory = new SocketConnectionContextFactory(new SocketConnectionFactoryOptions(), _logger);

        // The first time is not in the background, so the sockets are there once Kestrel has started.
        Reconcile();
        _reconciling = Task.Run(ReconcileRegularlyAsync);
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

        foreach (var path in _active.Keys.ToArray())
            Stop(path);

        _connections.Writer.TryComplete();
    }

    /// <summary>Makes the sockets being listened on match what the users say.</summary>
    private void Reconcile()
    {
        var wanted = _users.UsersWithSockets.ToDictionary(user => user.Socket!, user => user.Name);

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
    }

    private void Start(string path, string userName)
    {
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
        _ = AcceptAsync(socket, userName);
        _logger.LogInformation("Listening on {Path} for user {User}", path, userName);
    }

    private void ReportProblem(string path, string problem)
    {
        if (_problems.GetValueOrDefault(path) == problem)
            return;

        _problems[path] = problem;
        _logger.LogError("Not listening on {Path}: {Problem}", path, problem);
    }

    /// <remarks>Disposing also removes the file of the socket.</remarks>
    private void Stop(string path)
    {
        _active.Remove(path, out var active);
        active!.Socket.Dispose();
        _logger.LogInformation("Stopped listening on {Path}", path);
    }

    private async Task AcceptAsync(Socket socket, string userName)
    {
        var authenticator = new FixedUserAuthenticator(userName);

        while (true)
        {
            try
            {
                var client = await socket.AcceptAsync(_stopping.Token);
                var connection = _connectionFactory.Create(client);
                connection.Items[typeof(IClientAuthenticator)] = authenticator;

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
                _logger.LogError("Could not accept a connection for user {User}: {Message}", userName, e.Message);
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
