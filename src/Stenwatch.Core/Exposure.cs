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
    static readonly Regex Exploited = new(@"actively exploited|exploited in the wild|known exploited|\bkev\b", RegexOptions.IgnoreCase);
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
            Exploited.IsMatch(e.Evidence) ? ("Act", "the evidence says it is exploited") :
            lvl >= 3 && Exposed.IsMatch(e.Evidence) ? ("Attend", "high or critical, and the evidence says it is reachable from the internet") :
            lvl == 4 ? ("Attend", "critical severity") :
            lvl == 3 ? ("Track", "high severity, no sign of exploitation") :
            ("Ignore", "medium or low severity, no sign of exploitation");
        return e with { Tier = tier, Rule = rule };
    }

    static string Dir(string data) => Path.Combine(data, "exposures");
    /// <summary>File name for a component: "End-of-life software" -> end-of-life-software.csv.</summary>
    public static string FileFor(string data, string component) => Path.Combine(Dir(data), Regex.Replace(component.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-') + ".csv");

    /// <summary>Replace one component's rows (an import replaces the previous import), ranked on the way in.</summary>
    public static void Save(string data, string component, IEnumerable<Exposure> rows)
    {
        Directory.CreateDirectory(Dir(data));
        Csv.Write(FileFor(data, component), new[] { Head }.Concat(rows.Select(r => Rank(r with { Component = component }))
            .Select(r => new[] { r.Component, r.Asset, r.ItemId, r.Title, r.Severity, r.Evidence, r.Source, r.Date, r.Tier, r.Rule })));
    }

    /// <summary>Every component's rows, re-ranked so a hand-edited tier never survives. Empty when nothing was imported.</summary>
    public static List<Exposure> Load(string data, string? component = null)
    {
        if (!Directory.Exists(Dir(data))) return new();
        var files = component is null ? Directory.GetFiles(Dir(data), "*.csv") : File.Exists(FileFor(data, component)) ? new[] { FileFor(data, component) } : Array.Empty<string>();
        return files.SelectMany(Csv.ReadDict).Select(r => Rank(new Exposure(r.GetValueOrDefault("component", ""), r.GetValueOrDefault("asset", ""), r.GetValueOrDefault("item_id", ""),
            r.GetValueOrDefault("title", ""), r.GetValueOrDefault("severity", ""), r.GetValueOrDefault("evidence", ""), r.GetValueOrDefault("source", ""), r.GetValueOrDefault("date", "")))).ToList();
    }
}
