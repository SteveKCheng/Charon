namespace Charon;

/// <summary>
/// Keeps something up to date with a configuration file, which need not exist.  If a new
/// version of the file is not usable, the last one remains in force.
/// </summary>
internal sealed class PolledFile : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    private readonly string _path;
    private readonly Action<string> _load;
    private readonly Action _clear;
    private readonly ILogger? _logger;
    private readonly CancellationTokenSource _disposed = new();

    private DateTime _lastWriteTime;

    /// <param name="path">Path to the file.</param>
    /// <param name="load">
    /// Reads the file at the path it is given.  May throw <see cref="FormatException"/>.
    /// </param>
    /// <param name="clear">Called when the file is gone.</param>
    /// <param name="logger">Receives reports of problems with the file.</param>
    public PolledFile(string path, Action<string> load, Action clear, ILogger? logger)
    {
        _path = path;
        _load = load;
        _clear = clear;
        _logger = logger;

        Reload();
        _ = PollAsync();
    }

    public void Dispose() => _disposed.Cancel();

    private async Task PollAsync()
    {
        using var timer = new PeriodicTimer(PollInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(_disposed.Token))
                Reload();
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void Reload()
    {
        try
        {
            var lastWriteTime = File.GetLastWriteTimeUtc(_path);
            if (lastWriteTime == _lastWriteTime)
                return;

            _load(_path);
            _lastWriteTime = lastWriteTime;
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            _lastWriteTime = default;
            _clear();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
        {
            // Not to be retried until the file changes, or else the log is flooded.
            _lastWriteTime = File.GetLastWriteTimeUtc(_path);
            _logger?.LogError("Could not load {Path}: {Message}", _path, e.Message);
        }
    }
}
