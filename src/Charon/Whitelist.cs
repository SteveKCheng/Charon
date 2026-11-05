using System.Text.RegularExpressions;

namespace Charon;

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

    private sealed class RuleSet
    {
        public readonly Dictionary<string, List<Regex>> ByHost = new();
        public readonly List<Regex> Unindexed = new();
    }

    private readonly ILogger? _logger;
    private readonly PolledFile _file;

    private volatile RuleSet[] _rules = NewRuleSets();

    /// <summary>Loads a file, and follows changes to it.  If it is gone then nothing is allowed.</summary>
    public Whitelist(string path, ILogger? logger = null)
    {
        _logger = logger;
        _file = new PolledFile(path, Load, () => _rules = NewRuleSets(), logger);
    }

    public void Dispose() => _file.Dispose();

    private void Load(string path)
    {
        _rules = Parse(File.ReadAllLines(path), out int count, out int unindexed);
        _logger?.LogInformation("Loaded {Count} rules from {Path}, of which {Unindexed} are not indexed by host",
                                count, path, unindexed);
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
    public bool IsAllowed(Capability capability, string url, string host)
    {
        var rules = _rules[(int)capability];

        try
        {
            for (int start = 0; start >= 0;)
            {
                if (rules.ByHost.TryGetValue(host[start..], out var bucket) && AnyMatch(bucket, url))
                    return true;

                int dot = host.IndexOf('.', start);
                start = dot < 0 ? -1 : dot + 1;
            }

            return AnyMatch(rules.Unindexed, url);
        }
        catch (RegexMatchTimeoutException)
        {
            _logger?.LogWarning("Denying {Url}: timed out while matching rules", url);
            return false;
        }
    }

    private static bool AnyMatch(List<Regex> rules, string url)
    {
        foreach (var rule in rules)
        {
            if (rule.IsMatch(url))
                return true;
        }

        return false;
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

            Regex regex;
            try
            {
                regex = new Regex(pattern, PatternOptions, MatchTimeout);
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
                    set.Unindexed.Add(regex);
                }
                else
                {
                    if (!set.ByHost.TryGetValue(host, out var bucket))
                        set.ByHost[host] = bucket = new List<Regex>(1);
                    bucket.Add(regex);
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
