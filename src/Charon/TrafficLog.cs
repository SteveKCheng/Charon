using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace Charon;

/// <summary>What is shown about a request in the Web UI.</summary>
/// <param name="Id">Identifies the request: an entry is re-published when the request finishes.</param>
/// <param name="Status">HTTP status returned to the client, or null if not finished.</param>
/// <param name="Note">Explains an unusual outcome.</param>
/// <param name="Reason">Why the request was refused: one of a limited set of phrases.</param>
/// <param name="RuleLine">Line in the whitelist of the rule that allowed the request.</param>
/// <param name="Rule">Text of the rule that allowed the request.</param>
/// <param name="Whitelist">Hash of the whitelist in force, if it got consulted.</param>
public sealed record TrafficEntry(
    long Id,
    DateTimeOffset Time,
    string Client,
    string Method,
    string Url,
    bool Allowed,
    int? Status = null,
    double? DurationMs = null,
    string? Note = null,
    string? Reason = null,
    int? RuleLine = null,
    string? Rule = null,
    string? Whitelist = null);

/// <summary>
/// Remembers the most recent requests, and notifies Web UI sessions of them.  Only
/// metadata is kept and it is bounded, so that memory use does not grow with
/// traffic as in mitmweb, which retains bodies.
/// </summary>
public sealed class TrafficLog(int capacity)
{
    private const int SubscriberBacklog = 4096;

    private readonly Lock _lock = new();
    private readonly TrafficEntry[] _entries = new TrafficEntry[capacity];
    private readonly List<Channel<TrafficEntry>> _subscribers = new();
    private long _lastId;

    /// <summary>
    /// Receives all new and updated entries.  This must not block,
    /// since it is called in the course of handling requests.
    /// </summary>
    public Action<TrafficEntry>? Sink { get; set; }

    /// <summary>Records a new request.</summary>
    public TrafficEntry Add(string client, string method, string url, bool allowed,
                            int? status = null, string? note = null, string? reason = null,
                            int? ruleLine = null, string? rule = null, string? whitelist = null)
    {
        lock (_lock)
        {
            var entry = new TrafficEntry(++_lastId, DateTimeOffset.UtcNow, client, method, url, allowed,
                                         status, null, note, reason, ruleLine, rule, whitelist);
            Publish(entry);
            return entry;
        }
    }

    /// <summary>Replaces an entry with an updated one having the same ID.</summary>
    public void Update(TrafficEntry entry)
    {
        lock (_lock)
            Publish(entry);
    }

    private void Publish(TrafficEntry entry)
    {
        // A request that outlasts the capacity of the log may have had its slot reused.
        ref var slot = ref _entries[entry.Id % _entries.Length];
        if (slot is null || slot.Id <= entry.Id)
            slot = entry;

        foreach (var subscriber in _subscribers)
            subscriber.Writer.TryWrite(entry);

        Sink?.Invoke(entry);
    }

    /// <summary>Streams the entries in the log, and then any new or updated ones as they come.</summary>
    public async IAsyncEnumerable<TrafficEntry> SubscribeAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // A session that cannot keep up misses entries, instead of holding up the proxy.
        var channel = Channel.CreateBounded<TrafficEntry>(new BoundedChannelOptions(SubscriberBacklog)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

        TrafficEntry[] snapshot;
        lock (_lock)
        {
            snapshot = _entries.Where(e => e is not null).OrderBy(e => e.Id).ToArray();
            _subscribers.Add(channel);
        }

        try
        {
            foreach (var entry in snapshot)
                yield return entry;

            await foreach (var entry in channel.Reader.ReadAllAsync(cancellationToken))
                yield return entry;
        }
        finally
        {
            lock (_lock)
                _subscribers.Remove(channel);
        }
    }
}
