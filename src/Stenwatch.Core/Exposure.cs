using System.Text.RegularExpressions;

namespace Stenwatch.Core;

/// <summary>One finding that is not a CVE matched to an asset: a misconfiguration, an exposed service, an end-of-life product, a web app alert.
/// Every connector produces this shape. Tier and Rule come only from <see cref="Rank"/>, a fixed ladder; an LLM never sets them.
/// ItemId is what Remediation and History use in place of the CVE id in their (cve, asset) key, so tasks and history need no new schema.
/// Rows are kept per component in exposures/&lt;component&gt;.csv in the data folder.</summary>
public record Exposure(string Component, string Asset, string ItemId, string Title, string Severity, string Evidence, string Source, string Date,
                       string Tier = "", string Rule = "")
{
    static readonly string[] Head = { "component", "asset", "item_id", "title", "severity", "evidence", "source", "date", "tier", "rule" };
    static readonly Regex Exploited = new(@"actively exploited|exploited in the wild|known exploited|\bkev\b|confirmed compromised", RegexOptions.IgnoreCase);
    static readonly Regex Exposed = new(@"internet|public|external|exposed", RegexOptions.IgnoreCase);

    /// <summary>Severity as 0 (none or info) to 4 (critical): words as written, or a 0-10 score.</summary>
    public static int Level(string severity)
    {
        var s = severity.Trim().ToLowerInvariant();
        if (double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n))
            return n >= 9 ? 4 : n >= 7 ? 3 : n >= 4 ? 2 : n > 0 ? 1 : 0;
        return s.Contains("critical") ? 4 : s.Contains("high") ? 3 : s.Contains("medium") || s.Contains("moderate") ? 2 : s.Contains("low") ? 1 : 0;
    }

    /// <summary>The ladder: the first rule that holds sets the tier and is named. Rule-based, not validated against outcomes.
    /// ponytail: evidence is matched by fixed words; a connector that knows more (a KEV flag, an exposure flag) should say so in Evidence.</summary>
    public static Exposure Rank(Exposure e)
    {
        var lvl = Level(e.Severity);
        var (tier, rule) =
            Exploited.IsMatch(e.Evidence) ? ("Act", "the evidence says it is exploited or compromised") :
            lvl >= 3 && Exposed.IsMatch(e.Evidence) ? ("Attend", "high or critical, and the evidence says it is reachable from the internet") :
            lvl == 4 ? ("Attend", "critical severity") :
            lvl == 3 ? ("Track", "high severity, no sign of exploitation") :
            ("Ignore", "medium or low severity, no sign of exploitation");
        return e with { Tier = tier, Rule = rule };
    }

    static string Dir(string data) => Path.Combine(data, "exposures");
    /// <summary>File name for a component: "End-of-life software" -> end-of-life-software.csv.</summary>
    static string Slug(string s) => Regex.Replace(s.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
    /// <summary>A component fed by several formats keeps one file per format: misconfiguration--intune-devices.csv.</summary>
    public static string FileFor(string data, string component, string? source = null) => Path.Combine(Dir(data), Slug(component) + (source is null ? "" : "--" + Slug(source)) + ".csv");
    /// <summary>The newest import for a component (any of its files), or null when nothing was imported. A file with no rows counts: it was checked and nothing was found.</summary>
    public static DateTime? Imported(string data, string component) => !Directory.Exists(Dir(data)) ? null
        : Directory.GetFiles(Dir(data), Slug(component) + "*.csv").Select(File.GetLastWriteTime).Cast<DateTime?>().DefaultIfEmpty(null).Max();

    /// <summary>Replace one component's rows from one source (an import replaces the previous import of the same format), ranked on the way in.</summary>
    public static void Save(string data, string component, IEnumerable<Exposure> rows, string? source = null)
    {
        Directory.CreateDirectory(Dir(data));
        Csv.Write(FileFor(data, component, source), new[] { Head }.Concat(rows.Select(r => Rank(r with { Component = component }))
            .Select(r => new[] { r.Component, r.Asset, r.ItemId, r.Title, r.Severity, r.Evidence, r.Source, r.Date, r.Tier, r.Rule })));
    }

    /// <summary>Every component's rows, re-ranked so a hand-edited tier never survives. Empty when nothing was imported.</summary>
    public static List<Exposure> Load(string data, string? component = null)
    {
        if (!Directory.Exists(Dir(data))) return new();
        return Directory.GetFiles(Dir(data), "*.csv").SelectMany(Csv.ReadDict).Where(r => component is null || r.GetValueOrDefault("component", "") == component).Select(r => Rank(new Exposure(r.GetValueOrDefault("component", ""), r.GetValueOrDefault("asset", ""), r.GetValueOrDefault("item_id", ""),
            r.GetValueOrDefault("title", ""), r.GetValueOrDefault("severity", ""), r.GetValueOrDefault("evidence", ""), r.GetValueOrDefault("source", ""), r.GetValueOrDefault("date", "")))).ToList();
    }
}
