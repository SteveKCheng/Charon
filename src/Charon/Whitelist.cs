using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Charon;

/// <summary>A line of the whitelist that allows something.</summary>
internal sealed record WhitelistRule(int Line, string Text);

/// <summary>One state of the whitelist.</summary>
/// <param name="Hash">Identifies the contents.</param>
/// <param name="Contents">The text of the file.</param>
internal sealed record WhitelistVersion(string Hash, string Contents)
{
    public static WhitelistVersion Of(string contents) => new(
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(contents)).AsSpan(0, 8)), contents);
}

/// <summary>The outcome of checking a request against the whitelist.</summary>
/// <param name="Rule">The rule that allows the request, or null if it is denied.</param>
/// <param name="Version">The hash of the whitelist that this was decided by.</param>
internal readonly record struct WhitelistDecision(WhitelistRule? Rule, string Version);

/// <summary>
/// The URLs that clients may access: anything that does not match is denied.
/// </summary>
/// <remarks>
/// <para>
/// The file format and matching semantics are those of mitmproxy-whitelist: lines of
/// <c>METHOD: regex</c>, with the regex matched case-insensitively and unanchored.
/// </para>
/// <para>
/// Hyperscan's trick of matching all patterns at once is not available from
/// System.Text.RegularExpressions: a big alternation costs time linear in the number
/// of rules, and under RegexOptions.NonBacktracking, around a megabyte for each.
/// Instead, rules are bucketed under the host name they spell out literally, so
/// only a handful of them need to run for any URL.  Rules for which that cannot be
/// determined go in a list that is always scanned.  Mistakes in the bucketing can
/// only ever deny a URL, never allow one, since a rule's regex must still match.
/// </para>
/// <para>
/// Beyond the add-in's format, there are the rule types <c>GET-BODY</c> and
/// <c>WEBSOCKET</c>, for what a <c>GET</c> rule no longer grants: see <see cref="Capability"/>.
/// </para>
/// </remarks>
internal sealed class Whitelist : IDisposable
{
    /// <summary>Guards against a badly-written rule being exploited for denial of service.</summary>
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private const RegexOptions PatternOptions = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>Matches the prefix of a rule that gives its host name literally.</summary>
    private static readonly Regex LiteralHostRule = new(
        @"^\^https\??://(?:\((?:\?:)?\[-a-z0-9\.\]\+\\\.\)\?)?(?<host>(?:[-a-z0-9_]|\\\.)+)(?:[/:$]|\\/|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private sealed record CompiledRule(Regex Regex, WhitelistRule Source);

    private sealed class RuleSet
    {
        public readonly Dictionary<string, List<CompiledRule>> ByHost = new();
        public readonly List<CompiledRule> Unindexed = new();
    }

    /// <summary>Rules along with their origin, swapped in as one so that the two always agree.</summary>
    private sealed record Snapshot(RuleSet[] Rules, WhitelistVersion Version);

    private static readonly Snapshot Nothing = new(NewRuleSets(), WhitelistVersion.Of(""));

    private readonly ILogger? _logger;
    private readonly PolledFile _file;

    private volatile Snapshot _current = Nothing;

    /// <summary>The whitelist now in force.</summary>
    public WhitelistVersion Version => _current.Version;

    /// <summary>Raised when the whitelist in force changes.</summary>
    public event Action<WhitelistVersion>? Changed;

    /// <summary>Loads a file, and follows changes to it.  If it is gone then nothing is allowed.</summary>
    public Whitelist(string path, ILogger? logger = null)
    {
        _logger = logger;
        _file = new PolledFile(path, Load, () => Replace(Nothing), logger);
    }

    public void Dispose() => _file.Dispose();

    private void Load(string path)
    {
        var contents = File.ReadAllText(path);
        var rules = Parse(contents.Split('\n'), out int count, out int unindexed);
        Replace(new Snapshot(rules, WhitelistVersion.Of(contents)));
        _logger?.LogInformation("Loaded {Count} rules from {Path}, of which {Unindexed} are not indexed by host",
                                count, path, unindexed);
    }

    private void Replace(Snapshot snapshot)
    {
        bool changed = snapshot.Version != _current.Version;
        _current = snapshot;
        if (changed)
            Changed?.Invoke(snapshot.Version);
    }

    private static RuleSet[] NewRuleSets()
    {
        var sets = new RuleSet[(int)Capability.Count];
        for (int i = 0; i < sets.Length; i++)
            sets[i] = new RuleSet();
        return sets;
    }

    /// <summary>Decides on a request.</summary>
    /// <param name="capability">What the request needs.</param>
    /// <param name="url">The URL exactly as it will be requested upstream.</param>
    /// <param name="host">Host of the URL, in lower case.</param>
    public WhitelistDecision Evaluate(Capability capability, string url, string host)
    {
        var snapshot = _current;
        var rules = snapshot.Rules[(int)capability];

        try
        {
            for (int start = 0; start >= 0;)
            {
                if (rules.ByHost.TryGetValue(host[start..], out var bucket) &&
                    FindMatch(bucket, url) is { } rule)
                {
                    return new WhitelistDecision(rule, snapshot.Version.Hash);
                }

                int dot = host.IndexOf('.', start);
                start = dot < 0 ? -1 : dot + 1;
            }

            return new WhitelistDecision(FindMatch(rules.Unindexed, url), snapshot.Version.Hash);
        }
        catch (RegexMatchTimeoutException)
        {
            _logger?.LogWarning("Denying {Url}: timed out while matching rules", url);
            return new WhitelistDecision(null, snapshot.Version.Hash);
        }
    }

    /// <summary>Whether a request is allowed: see <see cref="Evaluate"/>.</summary>
    public bool IsAllowed(Capability capability, string url, string host) =>
        Evaluate(capability, url, host).Rule is not null;

    private static WhitelistRule? FindMatch(List<CompiledRule> rules, string url)
    {
        foreach (var rule in rules)
        {
            if (rule.Regex.IsMatch(url))
                return rule.Source;
        }

        return null;
    }

    private static RuleSet[] Parse(string[] lines, out int count, out int unindexed)
    {
        var sets = NewRuleSets();
        count = unindexed = 0;

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            int colon = line.IndexOf(':');
            var methods = colon < 0 ? null : line[..colon] switch
            {
                "GET" => new[] { Capability.Get },
                "POST" => [Capability.Post],
                "PUT" => [Capability.Put],
                "ANY" => [Capability.Get, Capability.Post, Capability.Put],
                "GET-BODY" => [Capability.GetWithBody],
                "WEBSOCKET" => [Capability.WebSocket],
                _ => null,
            };
            var pattern = line[(colon + 1)..].Trim();
            if (methods is null || pattern.Length == 0)
                throw new FormatException($"Invalid rule at line {i + 1}");

            CompiledRule rule;
            try
            {
                rule = new CompiledRule(new Regex(pattern, PatternOptions, MatchTimeout),
                                        new WhitelistRule(i + 1, line));
            }
            catch (ArgumentException e)
            {
                throw new FormatException($"Invalid regular expression at line {i + 1}: {e.Message}");
            }

            var host = GetLiteralHost(pattern);
            foreach (var method in methods)
            {
                var set = sets[(int)method];
                if (host is null)
                {
                    set.Unindexed.Add(rule);
                }
                else
                {
                    if (!set.ByHost.TryGetValue(host, out var bucket))
                        set.ByHost[host] = bucket = new List<CompiledRule>(1);
                    bucket.Add(rule);
                }
            }

            count++;
            if (host is null)
                unindexed++;
        }

        return sets;
    }

    /// <summary>
    /// Gets the host name, or domain if subdomains are allowed, that all
    /// URLs matching a rule must have, or null if it cannot be determined.
    /// </summary>
    internal static string? GetLiteralHost(string pattern)
    {
        var match = LiteralHostRule.Match(pattern);
        if (!match.Success || HasTopLevelAlternation(pattern))
            return null;

        return match.Groups["host"].Value.Replace(@"\.", ".").ToLowerInvariant();
    }

    /// <summary>Whether a pattern is like <c>^a|^b</c>, where a prefix says nothing of the whole.</summary>
    private static bool HasTopLevelAlternation(string pattern)
    {
        int depth = 0;
        bool inClass = false;

        for (int i = 0; i < pattern.Length; i++)
        {
            switch (pattern[i])
            {
                case '\\': i++; break;
                case '[': inClass = true; break;
                case ']': inClass = false; break;
                case '(' when !inClass: depth++; break;
                case ')' when !inClass: depth--; break;
                case '|' when !inClass && depth == 0: return true;
            }
        }

        return false;
    }
}
