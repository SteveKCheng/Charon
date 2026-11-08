using System.Diagnostics;
using Microsoft.AspNetCore.Connections;

namespace Charon;

/// <summary>
/// Stops Charon when it has had no connections for a while, so that it takes no memory until
/// systemd starts it again, on the next connection to one of its sockets.
/// </summary>
/// <remarks>
/// Connections are counted on the listeners given <see cref="Track"/>.  A connection that arrives
/// while stopping is not lost if it is to a socket from systemd, as systemd keeps the socket open:
/// it waits there, and starts Charon again.
/// </remarks>
internal sealed class IdleExit(CharonOptions options, InheritedSockets inherited,
                               IHostApplicationLifetime lifetime, ILogger<IdleExit> logger)
    : IHostedService, IDisposable
{
    private readonly Lock _lock = new();
    private int _connections;
    private long _idleSince = Stopwatch.GetTimestamp();
    private ITimer? _timer;
    private TimeSpan _timeout;
    private bool _stopping;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.IdleTimeout is not { } timeout)
            return Task.CompletedTask;

        if (!inherited.IsActivated)
        {
            logger.LogWarning("IdleTimeout is set, but systemd did not start Charon, which then " +
                              "would not be started again: so it is not stopping when idle");
            return Task.CompletedTask;
        }

        lock (_lock)
        {
            _timeout = timeout;
            _idleSince = Stopwatch.GetTimestamp();
            _timer = TimeProvider.System.CreateTimer(_ => OnTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            if (_connections == 0)
                _timer.Change(timeout, Timeout.InfiniteTimeSpan);
        }

        logger.LogInformation("Stopping after {Timeout} with no connections", timeout);
        return Task.CompletedTask;
    }

    /// <summary>Connection middleware, for counting the connections to a listener.</summary>
    public ConnectionDelegate Track(ConnectionDelegate next) => async connection =>
    {
        lock (_lock)
        {
            if (_connections++ == 0)
                _timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        try
        {
            await next(connection);
        }
        finally
        {
            lock (_lock)
            {
                if (--_connections == 0)
                {
                    _idleSince = Stopwatch.GetTimestamp();
                    _timer?.Change(_timeout, Timeout.InfiniteTimeSpan);
                }
            }
        }
    };

    private void OnTimer()
    {
        lock (_lock)
        {
            if (_stopping || _connections > 0)
                return;

            // The timer may have gone off from before the latest connection, and run late.
            var left = _timeout - Stopwatch.GetElapsedTime(_idleSince);
            if (left > TimeSpan.Zero)
            {
                _timer!.Change(left, Timeout.InfiniteTimeSpan);
                return;
            }

            _stopping = true;
        }

        logger.LogInformation("No connections for {Timeout}, so stopping until the next one", _timeout);
        lifetime.StopApplication();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Dispose();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }
}
