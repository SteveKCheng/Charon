using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Data.Sqlite;

namespace Charon;

/// <summary>The state of the traffic database, for the Web UI.</summary>
/// <param name="Path">The database file.</param>
/// <param name="Healthy">Whether writing to the database is working.</param>
/// <param name="Error">What is wrong, if it is not.</param>
/// <param name="DroppedEvents">Events lost since starting, because the queue overflowed.</param>
/// <param name="DroppedHeaders">The same, for sets of headers.</param>
public sealed record TrafficStoreStatus(string Path, bool Healthy, string? Error, long DroppedEvents, long DroppedHeaders);

/// <summary>
/// Records requests in an SQLite database, which outlives the process, for the user to query.
/// </summary>
/// <remarks>
/// <para>
/// This is off the path of requests: entries wait in a queue, for a background task to
/// write them in batches.  It follows that nothing going wrong here can be allowed to affect
/// the proxy.  If the queue fills up the oldest entries get dropped, and if the database
/// cannot be written to then proxying carries on, with the problem being reported.
/// Losses are recorded in the database, so that it does not misrepresent what happened.
/// </para>
/// <para>
/// A request is written when it starts, and updated when it finishes.  So those still
/// unfinished when the process dies are there, without a status.
/// </para>
/// <para>
/// Headers, if they are recorded, have a table and a queue of their own.  They can be much larger
/// than the rest, and they make writing several times slower.  So, under load, they
/// are the first to go, and the bound on their memory use is the length of their
/// queue multiplied by the limit on the size of each item.
/// </para>
/// </remarks>
internal sealed class TrafficStore : IHostedService
{
    private const int SchemaVersion = 2;

    private const int DefaultQueueCapacity = 64 * 1024;

    private const int DefaultHeaderQueueCapacity = 4096;

    private const int MaxBatchSize = 4096;

    /// <summary>
    /// Limit on the text of headers in a batch.  The size limit of the database is
    /// checked between batches, so this is by how much the database can overshoot it.
    /// </summary>
    private const int MaxHeaderBatchLength = 1024 * 1024;

    private static readonly TimeSpan FlushInterval = TimeSpan.FromMilliseconds(250);

    private static readonly TimeSpan AgePruneInterval = TimeSpan.FromMinutes(10);

    /// <summary>Fraction of the size limit to go down to when the database reaches it.</summary>
    private const double SizePruneTarget = 0.9;

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY,   -- Time that the process started, in Unix milliseconds
            pid INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS requests(
            session INTEGER NOT NULL,
            id INTEGER NOT NULL,
            time_ms INTEGER NOT NULL,   -- Unix milliseconds
            client TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            status INTEGER,             -- Null if the request never finished
            duration_ms REAL,
            reason TEXT,                -- Why it was denied
            note TEXT,
            rule_line INTEGER,          -- The rule of the whitelist that allowed it
            rule TEXT,
            whitelist TEXT,             -- See the table whitelists
            user TEXT,                  -- The user of the proxy, if not anonymous
            PRIMARY KEY(session, id)) WITHOUT ROWID;

        CREATE INDEX IF NOT EXISTS requests_by_time ON requests(time_ms);

        CREATE INDEX IF NOT EXISTS denied_requests_by_time ON requests(time_ms) WHERE NOT allowed;

        -- Optional.  Values are JSON arrays of pairs of names and values.
        CREATE TABLE IF NOT EXISTS headers(
            session INTEGER NOT NULL,
            id INTEGER NOT NULL,
            time_ms INTEGER NOT NULL,
            request TEXT,
            response TEXT,
            PRIMARY KEY(session, id));

        CREATE INDEX IF NOT EXISTS headers_by_time ON headers(time_ms);

        -- Every version of the whitelist, to find out what the rules were at some point.
        CREATE TABLE IF NOT EXISTS whitelists(
            hash TEXT PRIMARY KEY,
            first_seen_ms INTEGER NOT NULL,
            contents TEXT NOT NULL);

        -- Requests that are missing from the table of them, because they could not be written.
        CREATE TABLE IF NOT EXISTS gaps(
            session INTEGER NOT NULL,
            time_ms INTEGER NOT NULL,
            dropped_events INTEGER NOT NULL,
            dropped_headers INTEGER NOT NULL);

        CREATE VIEW IF NOT EXISTS traffic AS
            SELECT datetime(time_ms / 1000, 'unixepoch', 'localtime') AS time,
                   method, status, allowed, url, reason, note, rule, user, client, duration_ms
            FROM requests;
        """;

    private const string UpsertRequest = """
        INSERT INTO requests VALUES($session, $id, $time, $client, $method, $url, $allowed, $status,
                                    $duration, $reason, $note, $ruleLine, $rule, $whitelist, $user)
        ON CONFLICT(session, id) DO UPDATE SET
            status = excluded.status, duration_ms = excluded.duration_ms, note = excluded.note
        """;

    private const string UpsertHeaders = """
        INSERT INTO headers VALUES($session, $id, $time, $request, $response)
        ON CONFLICT(session, id) DO UPDATE SET
            request = coalesce(excluded.request, request), response = coalesce(excluded.response, response)
        """;

    private sealed record HeaderRecord(long Id, DateTimeOffset Time, string? Request, string? Response);

    private readonly string _path;
    private readonly long _maxBytes;
    private readonly TimeSpan _retention;
    private readonly Whitelist _whitelist;
    private readonly ILogger? _logger;
    private readonly long _session = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private readonly Channel<TrafficEntry> _queue;
    private readonly Channel<HeaderRecord> _headerQueue;
    private readonly ConcurrentQueue<WhitelistVersion> _newWhitelists = new();

    /// <summary>
    /// Entries taken off the queue, by ID.  They stay here until written.  Most requests start and
    /// finish within a batch, and it takes writing just the last entry, which has everything.
    /// </summary>
    private readonly Dictionary<long, TrafficEntry> _batch = new(MaxBatchSize);
    private readonly List<HeaderRecord> _headerBatch = new(MaxBatchSize);

    private readonly CancellationTokenSource _stopping = new();
    private Task _worker = Task.CompletedTask;

    private SqliteConnection? _database;
    private SqliteCommand? _upsert;
    private SqliteParameter[] _upsertParameters = [];
    private SqliteCommand? _upsertHeaders;
    private DateTime _nextAgePrune;

    private long _droppedEvents;
    private long _unrecordedDrops;
    private long _droppedHeaders;
    private long _unrecordedHeaderDrops;
    private volatile string? _error;

    /// <summary>Time to wait before trying again after failing to write to the database.</summary>
    internal TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(5);

    public TrafficStore(CharonOptions options, TrafficLog log, Whitelist whitelist, ILogger? logger = null,
                        int queueCapacity = DefaultQueueCapacity,
                        int headerQueueCapacity = DefaultHeaderQueueCapacity)
    {
        _path = options.TrafficDatabaseFile;
        _maxBytes = options.TrafficDatabaseMaxBytes;
        _retention = options.TrafficRetention;
        _whitelist = whitelist;
        _logger = logger;

        _queue = Channel.CreateBounded<TrafficEntry>(
            new BoundedChannelOptions(queueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            },
            _ =>
            {
                Interlocked.Increment(ref _droppedEvents);
                Interlocked.Increment(ref _unrecordedDrops);
            });

        _headerQueue = Channel.CreateBounded<HeaderRecord>(
            new BoundedChannelOptions(headerQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            },
            _ =>
            {
                Interlocked.Increment(ref _droppedHeaders);
                Interlocked.Increment(ref _unrecordedHeaderDrops);
            });

        log.Sink = entry => _queue.Writer.TryWrite(entry);
        whitelist.Changed += _newWhitelists.Enqueue;
    }

    public TrafficStoreStatus Status =>
        new(_path, _error is null, _error, Interlocked.Read(ref _droppedEvents), Interlocked.Read(ref _droppedHeaders));

    /// <summary>Queues headers to be recorded, for the request of a log entry.</summary>
    /// <param name="entry">The entry for the request.</param>
    /// <param name="request">The headers of the request, if they are being added now.</param>
    /// <param name="response">The headers of the response, if they are being added now.</param>
    public void AddHeaders(TrafficEntry entry, string? request, string? response) =>
        _headerQueue.Writer.TryWrite(new HeaderRecord(entry.Id, entry.Time, request, response));

    /// <remarks>
    /// This is not a BackgroundService, which does not run its task at all if it gets stopped
    /// straight away.  Then what is in the queue would never be written.
    /// </remarks>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _worker = Task.Run(() => RunAsync(_stopping.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _stopping.CancelAsync();
        await _worker.WaitAsync(cancellationToken);
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (true)
            {
                Flush();

                if (_error is not null)
                {
                    await Task.Delay(RetryDelay, stoppingToken);
                    continue;
                }

                // Wake up without traffic too, as the time comes for old requests to go.
                await Task.WhenAny(_queue.Reader.WaitToReadAsync(stoppingToken).AsTask(),
                                   Task.Delay(AgePruneInterval, stoppingToken));
                await Task.Delay(FlushInterval, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
        }

        // The requests have stopped by now: the server is shut down before this.
        Flush();
        CloseDatabase();
    }

    /// <summary>Writes out what is in the queue.  Never throws: see the remarks of the class.</summary>
    private void Flush()
    {
        try
        {
            var database = _database ?? OpenDatabase();

            do
            {
                while (_batch.Count < MaxBatchSize && _queue.Reader.TryRead(out var entry))
                    _batch[entry.Id] = entry;

                long headerLength = 0;
                while (_headerBatch.Count < MaxBatchSize && headerLength < MaxHeaderBatchLength &&
                       _headerQueue.Reader.TryRead(out var headers))
                {
                    _headerBatch.Add(headers);
                    headerLength += (headers.Request?.Length ?? 0) + (headers.Response?.Length ?? 0);
                }

                WriteBatch(database);
                _batch.Clear();
                _headerBatch.Clear();

                PruneBySize(database);
            }
            while (_queue.Reader.Count > 0 || _headerQueue.Reader.Count > 0);

            if (DateTime.UtcNow >= _nextAgePrune)
                PruneByAge(database);

            if (_error is not null)
            {
                _logger?.LogInformation("Writing to {Path} is working again", _path);
                _error = null;
            }
        }
        catch (Exception e)
        {
            // Includes SqliteException and those from file access, and even
            // if it is none of those, the proxy is not to be taken down with it.
            if (_error != e.Message)
                _logger?.LogError("Cannot write to the traffic database {Path}: {Message}", _path, e.Message);
            _error = e.Message;
            CloseDatabase();
        }
    }

    private SqliteConnection OpenDatabase()
    {
        PrepareFile();

        var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _path,
            Pooling = false,
        }.ToString());

        try
        {
            database.Open();

            // The write-ahead log lets people query the database while it is being written to.
            Execute(database, """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA journal_size_limit = 16777216;
                """);

            long version = Query(database, "PRAGMA user_version");
            if (version > SchemaVersion)
                throw new InvalidOperationException($"The database is of a newer version, {version}.");

            // This is added last, as VALUES in the upsert goes by the order of the columns.
            if (version == 1)
                Execute(database, "ALTER TABLE requests ADD COLUMN user TEXT; DROP VIEW IF EXISTS traffic;");

            Execute(database, Schema + $"PRAGMA user_version = {SchemaVersion};");

            using (var command = database.CreateCommand())
            {
                command.CommandText = "INSERT OR IGNORE INTO sessions VALUES($id, $pid)";
                command.Parameters.AddWithValue("$id", _session);
                command.Parameters.AddWithValue("$pid", Environment.ProcessId);
                command.ExecuteNonQuery();
            }

            _upsert = database.CreateCommand();
            _upsert.CommandText = UpsertRequest;
            _upsertParameters = new[] { "session", "id", "time", "client", "method", "url", "allowed", "status",
                                        "duration", "reason", "note", "ruleLine", "rule", "whitelist", "user" }
                .Select(name => new SqliteParameter { ParameterName = "$" + name }).ToArray();
            _upsert.Parameters.AddRange(_upsertParameters);
            _upsert.Prepare();

            _upsertHeaders = database.CreateCommand();
            _upsertHeaders.CommandText = UpsertHeaders;
            foreach (var name in new[] { "session", "id", "time", "request", "response" })
                _upsertHeaders.Parameters.Add(new SqliteParameter { ParameterName = "$" + name });
            _upsertHeaders.Prepare();
        }
        catch
        {
            database.Dispose();
            throw;
        }

        // It may be a different file from the one that was last written to.
        _newWhitelists.Enqueue(_whitelist.Version);

        _database = database;
        return database;
    }

    /// <summary>
    /// Makes sure that the file is private before anything goes in it.
    /// SQLite gives the files that accompany the database the same permissions.
    /// </summary>
    private void PrepareFile()
    {
        if (!File.Exists(_path))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(_path))!;
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };

            if (!OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            else
            {
                Directory.CreateDirectory(directory);
            }

            new FileStream(_path, options).Dispose();
        }

        PrivateFile.Check(_path);
    }

    private void CloseDatabase()
    {
        _upsert?.Dispose();
        _upsert = null;
        _upsertHeaders?.Dispose();
        _upsertHeaders = null;
        _database?.Dispose();
        _database = null;
    }

    private void WriteBatch(SqliteConnection database)
    {
        long drops = Interlocked.Read(ref _unrecordedDrops);
        long headerDrops = Interlocked.Read(ref _unrecordedHeaderDrops);
        var whitelists = _newWhitelists.ToArray();

        if (_batch.Count == 0 && _headerBatch.Count == 0 && drops == 0 && headerDrops == 0 && whitelists.Length == 0)
            return;

        using var transaction = database.BeginTransaction();

        var upsert = _upsert!;
        upsert.Transaction = transaction;
        foreach (var entry in _batch.Values)
        {
            SetParameters(entry);
            upsert.ExecuteNonQuery();
        }

        var upsertHeaders = _upsertHeaders!;
        upsertHeaders.Transaction = transaction;
        foreach (var headers in _headerBatch)
        {
            var parameters = upsertHeaders.Parameters;
            parameters["$session"].Value = _session;
            parameters["$id"].Value = headers.Id;
            parameters["$time"].Value = headers.Time.ToUnixTimeMilliseconds();
            parameters["$request"].Value = (object?)headers.Request ?? DBNull.Value;
            parameters["$response"].Value = (object?)headers.Response ?? DBNull.Value;
            upsertHeaders.ExecuteNonQuery();
        }

        foreach (var whitelist in whitelists)
        {
            using var command = database.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT OR IGNORE INTO whitelists VALUES($hash, $time, $contents)";
            command.Parameters.AddWithValue("$hash", whitelist.Hash);
            command.Parameters.AddWithValue("$time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            command.Parameters.AddWithValue("$contents", whitelist.Contents);
            command.ExecuteNonQuery();
        }

        if (drops > 0 || headerDrops > 0)
        {
            using var command = database.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO gaps VALUES($session, $time, $dropped, $droppedHeaders)";
            command.Parameters.AddWithValue("$session", _session);
            command.Parameters.AddWithValue("$time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            command.Parameters.AddWithValue("$dropped", drops);
            command.Parameters.AddWithValue("$droppedHeaders", headerDrops);
            command.ExecuteNonQuery();
        }

        transaction.Commit();

        Interlocked.Add(ref _unrecordedDrops, -drops);
        Interlocked.Add(ref _unrecordedHeaderDrops, -headerDrops);
        for (int i = 0; i < whitelists.Length; i++)
            _newWhitelists.TryDequeue(out _);
    }

    /// <summary>Sets the parameters of the upsert, in the order of their creation.</summary>
    private void SetParameters(TrafficEntry entry)
    {
        var parameters = _upsertParameters;
        parameters[0].Value = _session;
        parameters[1].Value = entry.Id;
        parameters[2].Value = entry.Time.ToUnixTimeMilliseconds();
        parameters[3].Value = entry.Client;
        parameters[4].Value = entry.Method;
        parameters[5].Value = entry.Url;
        parameters[6].Value = entry.Allowed;
        parameters[7].Value = (object?)entry.Status ?? DBNull.Value;
        parameters[8].Value = (object?)entry.DurationMs ?? DBNull.Value;
        parameters[9].Value = (object?)entry.Reason ?? DBNull.Value;
        parameters[10].Value = (object?)entry.Note ?? DBNull.Value;
        parameters[11].Value = (object?)entry.RuleLine ?? DBNull.Value;
        parameters[12].Value = (object?)entry.Rule ?? DBNull.Value;
        parameters[13].Value = (object?)entry.Whitelist ?? DBNull.Value;
        parameters[14].Value = (object?)entry.User ?? DBNull.Value;
    }

    /// <summary>
    /// Keeps to the size limit.  This is checked often, as a client making
    /// many requests can get there quickly.  What matters is the space in use: the file
    /// itself does not shrink, but it stops growing as the freed space gets reused.
    /// </summary>
    private void PruneBySize(SqliteConnection database)
    {
        long used = (Query(database, "PRAGMA page_count") - Query(database, "PRAGMA freelist_count")) *
                    Query(database, "PRAGMA page_size");
        if (used <= _maxBytes)
            return;

        long rows = Query(database, "SELECT count(*) FROM requests");
        long excess = (long)(rows * (1.0 - SizePruneTarget * _maxBytes / used));

        using var command = database.CreateCommand();
        command.CommandText = "SELECT time_ms FROM requests ORDER BY time_ms LIMIT 1 OFFSET $excess";
        command.Parameters.AddWithValue("$excess", Math.Clamp(excess, 0, Math.Max(rows - 1, 0)));
        if (command.ExecuteScalar() is not long cutoff)
            return;

        // Going by the time also covers headers whose request was lost to an overflowing queue.
        command.CommandText = """
            DELETE FROM requests WHERE time_ms <= $cutoff;
            DELETE FROM headers WHERE time_ms <= $cutoff;
            """;
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$cutoff", cutoff);
        command.ExecuteNonQuery();
    }

    private void PruneByAge(SqliteConnection database)
    {
        using var command = database.CreateCommand();
        command.CommandText = """
            DELETE FROM requests WHERE time_ms < $cutoff;
            DELETE FROM headers WHERE time_ms < $cutoff;
            DELETE FROM gaps WHERE time_ms < $cutoff;
            DELETE FROM sessions WHERE id < $cutoff AND id <> $session AND
                id NOT IN (SELECT DISTINCT session FROM requests);
            DELETE FROM whitelists WHERE first_seen_ms < $cutoff AND hash <> $whitelist AND
                hash NOT IN (SELECT whitelist FROM requests WHERE whitelist IS NOT NULL);
            """;
        command.Parameters.AddWithValue("$cutoff", (DateTimeOffset.UtcNow - _retention).ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$session", _session);
        command.Parameters.AddWithValue("$whitelist", _whitelist.Version.Hash);
        command.ExecuteNonQuery();

        _nextAgePrune = DateTime.UtcNow + AgePruneInterval;
    }

    private static void Execute(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Query(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }
}
