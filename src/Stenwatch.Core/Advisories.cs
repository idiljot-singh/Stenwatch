using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Stenwatch.Core;

/// <summary>One national or vendor advisory. Cves may be empty: many advisories name only a product.</summary>
public record Advisory(string Source, string Title, string Link, string Published, string Text, List<string> Cves, string ExploitMaturity)
{
    /// <summary>Wording that says attackers are using it now (English and Finnish). Decided by fixed words, not by the LLM.</summary>
    public bool ActivelyExploited => LlmActive || Active.IsMatch(Title + " " + Text);
    /// <summary>Filled by TriageLlm and checked against the text there: products named, a two-sentence English summary, and whether the wording says it is exploited now.</summary>
    public List<string> Products { get; init; } = new();
    public string Summary { get; init; } = "";
    /// <summary>Threat groups the advisory text names (LLM-extracted, kept only if the name is in the text).</summary>
    public List<string> Actors { get; init; } = new();
    public bool LlmActive { get; init; }
    public bool Analysed { get; init; }
    /// <summary>From the source: how much its word counts (A-F) and who may see its text (TLP). Pasted mail counts as B.</summary>
    public string Grade { get; init; } = "A";
    public string Tlp { get; init; } = "CLEAR";
    public bool ExploitExists => ExploitMaturity is "Functional" or "High";

    static readonly Regex Active = new(
        @"actively exploited|exploited in the wild|exists in the wild|Exploited:\s*Yes|being exploited|under active exploitation|active exploitation|zero-day|0-day|" +
        @"aktiivisesti hyödynn|hyödynnetään aktiivisesti|hyödynnetty hyökkäyks|hyökkäyksissä on hyödynn|hyödynnetään hyökkäyksissä|nollapäivä",
        RegexOptions.IgnoreCase);
}

/// <summary>Reads advisory feeds (NCSC-FI today), keeps what it has seen in advisories.json, and matches advisories to fix actions by CVE id first and by product name second.
/// ponytail: product matching is a word list, not fuzzy; add an alias in Aliases (or data/product_aliases.txt, "product=alias") when a feed names a product differently.</summary>
public static class Advisories
{
    public const string NcscFi = "https://www.kyberturvallisuuskeskus.fi/files/rss/vulns.xml";
    static readonly Regex CveId = new(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase);

    static readonly Dictionary<string, string[]> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Microsoft Edge"] = new[] { "microsoft edge" }, ["Google Chrome"] = new[] { "google chrome", "chromium" },
        ["Mozilla Firefox"] = new[] { "firefox" }, ["Mozilla Thunderbird"] = new[] { "thunderbird" }, ["Docker Desktop"] = new[] { "docker desktop" },
        ["PHP"] = new[] { "php" }, ["Python"] = new[] { "python" },
    };

    // ---- reading -----------------------------------------------------------------------------------------------------------

    /// <summary>NCSC-FI's vulnerability stream: each description reads "Classification: Critical, Solution: ..., Exploit Maturity: Functional, CVSSv3.1: 9.5, CVEs: CVE-..., Summary: ...".</summary>
    public static List<Advisory> ParseRss(string xml, string source)
    {
        var items = XDocument.Parse(xml).Descendants("item");
        return items.Select(i =>
        {
            var text = ((string?)i.Element("description") ?? "").Trim();
            var maturity = Regex.Match(text, @"Exploit Maturity:\s*([A-Za-z ]+?),") is { Success: true } m ? m.Groups[1].Value.Trim() : "";
            var pub = DateTimeOffset.TryParse((string?)i.Element("pubDate"), out var d) ? d.ToString("yyyy-MM-dd") : "";
            return new Advisory(source, ((string?)i.Element("title") ?? "").Trim(), ((string?)i.Element("link") ?? "").Trim(), pub, text,
                CveId.Matches(text + " " + (string?)i.Element("title")).Select(c => c.Value.ToUpperInvariant()).Distinct().ToList(), maturity);
        }).ToList();
    }

    /// <summary>An advisory pasted or saved by the analyst (.txt, .eml, .msg saved as text): the whole file is the text, its first line is the title.</summary>
    public static Advisory FromText(string path)
    {
        var text = File.ReadAllText(path);
        var title = text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l != "" && !l.StartsWith("From:", StringComparison.OrdinalIgnoreCase)) ?? Path.GetFileName(path);
        if (Regex.Match(text, @"^Subject:\s*(.+)$", RegexOptions.Multiline | RegexOptions.IgnoreCase) is { Success: true } s) title = s.Groups[1].Value.Trim();
        return new("Pasted", title, path, File.GetLastWriteTime(path).ToString("yyyy-MM-dd"), text,
            CveId.Matches(text).Select(c => c.Value.ToUpperInvariant()).Distinct().ToList(), "") { Grade = "B" };
    }

    /// <summary>Fetches every enabled source (sources.json) and merges into advisories.json, de-duplicated by link. A source that fails keeps what was stored and says so.</summary>
    public static async Task<(List<Advisory> All, string Note)> Refresh(string dir, HttpClient http, IEnumerable<Source>? sources = null, DateOnly? today = null)
    {
        var all = Load(dir); var notes = new List<string>();
        if (http.DefaultRequestHeaders.UserAgent.Count == 0) http.DefaultRequestHeaders.UserAgent.ParseAdd("Stenwatch");
        foreach (var src in (sources ?? Sources.Load(dir)).Where(x => x.Enabled))
        {
            try
            {
                var fresh = await Sources.Fetch(src, http, dir, today ?? DateOnly.FromDateTime(DateTime.Now));
                all = Merge(all, fresh.Select(f => all.FirstOrDefault(o => o.Link == f.Link && o.Analysed) is { } old ? old with { Grade = f.Grade, Tlp = f.Tlp } : f)); // keep what the LLM already read
                notes.Add($"{src.Name}: {fresh.Count}");
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Xml.XmlException or JsonException or KeyNotFoundException or InvalidOperationException)
            { notes.Add($"{src.Name}: not reachable ({e.GetType().Name})"); }
        }
        Save(dir, all);
        return (all, "Sources: " + string.Join(", ", notes) + (notes.Any(n => n.Contains("not reachable")) ? $"; stored advisories kept ({all.Count})" : ""));
    }

    public static void Save(string dir, List<Advisory> all) =>
        File.WriteAllText(Path.Combine(dir, "advisories.json"), JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));

    /// <summary>Adds advisories to the stored list unless the same link is already there (advisory memory: next export matches them again).</summary>
    public static List<Advisory> Merge(List<Advisory> all, IEnumerable<Advisory> add) =>
        add.Concat(all).GroupBy(a => a.Link).Select(g => g.First()).Take(1500).ToList();

    public static List<Advisory> Load(string dir) =>
        File.Exists(Path.Combine(dir, "advisories.json")) ? JsonSerializer.Deserialize<List<Advisory>>(File.ReadAllText(Path.Combine(dir, "advisories.json"))) ?? new() : new();

    // ---- matching -----------------------------------------------------------------------------------------------------------

    public record Match(Advisory Advisory, bool ByCve);

    static string[] AliasesOf(string product, string? dir)
    {
        var extra = dir is not null && File.Exists(Path.Combine(dir, "product_aliases.txt"))
            ? File.ReadAllLines(Path.Combine(dir, "product_aliases.txt")).Select(l => l.Split('=', 2)).Where(p => p.Length == 2 && p[0].Trim().Equals(product, StringComparison.OrdinalIgnoreCase)).Select(p => p[1].Trim().ToLowerInvariant())
            : Enumerable.Empty<string>();
        return (Aliases.TryGetValue(product, out var a) ? a : new[] { product.ToLowerInvariant() }).Concat(extra).ToArray();
    }

    /// <summary>Advisories published in the last <paramref name="days"/> days that name one of the CVEs, else (no CVE id in the advisory) the product.
    /// An advisory with CVE ids that match none of ours is NOT matched by product: its CVEs are other CVEs.</summary>
    public static List<Match> For(string product, IEnumerable<string> cves, IEnumerable<Advisory> all, DateOnly today, int days = 30, string? dir = null)
    {
        var set = cves.ToHashSet(StringComparer.OrdinalIgnoreCase); var aliases = AliasesOf(product, dir);
        return all.Where(a => !DateOnly.TryParse(a.Published, out var p) || p >= today.AddDays(-days))
            .Select(a => a.Cves.Count > 0 ? (a, ok: a.Cves.Any(set.Contains), cve: true)
                : (a, ok: aliases.Any(al => Regex.IsMatch(a.Title + " " + a.Text, @"\b" + Regex.Escape(al) + @"\b", RegexOptions.IgnoreCase) || a.Products.Any(p => p.Contains(al, StringComparison.OrdinalIgnoreCase))), cve: false))
            .Where(x => x.ok).Select(x => new Match(x.a, x.cve)).ToList();
    }
}
