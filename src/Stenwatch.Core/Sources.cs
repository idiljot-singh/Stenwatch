using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Stenwatch.Core;

/// <summary>An intelligence source the analyst can add: RSS or Atom (most national CERTs), or Microsoft's MSRC API.
/// Grade A-F is how much its word counts (A-B: an "actively exploited" claim means Act). Tlp decides which LLM may see its text.
/// RequireCve drops items naming no CVE (vendor blogs: beta and Android posts).</summary>
public record Source(string Name, string Type, string Url, string Grade = "A", string Tlp = "CLEAR", bool Enabled = true, bool RequireCve = false);

public static class Sources
{
    /// <summary>Free sources, each checked to answer on 2026-10-29.</summary>
    public static readonly Source[] Defaults =
    {
        new("NCSC-FI", "rss", Advisories.NcscFi),
        new("CERT-EU", "rss", "https://cert.europa.eu/publications/security-advisories-rss"),
        new("CISA", "rss", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        new("Microsoft MSRC", "msrc", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", RequireCve: true),
        new("Chrome Releases", "atom", "https://feeds.feedburner.com/GoogleChromeReleases", RequireCve: true),
    };
    public static readonly string[] Grades = { "A", "B", "C", "D", "E", "F" }, Tlps = { "CLEAR", "GREEN", "AMBER", "RED" }, Types = { "rss", "atom", "msrc" };

    static string File_(string dir) => Path.Combine(dir, "sources.json");
    public static List<Source> Load(string dir) =>
        File.Exists(File_(dir)) ? JsonSerializer.Deserialize<List<Source>>(File.ReadAllText(File_(dir))) ?? Defaults.ToList() : Defaults.ToList();
    public static void Save(string dir, List<Source> all) => File.WriteAllText(File_(dir), JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));

    /// <summary>One source's items, stamped with its name, grade and TLP, from the last <paramref name="days"/> days.</summary>
    public static async Task<List<Advisory>> Fetch(Source s, HttpClient http, string dir, DateOnly today, int days = 30)
    {
        var items = s.Type switch
        {
            "atom" => ParseAtom(await http.GetStringAsync(s.Url), s.Name),
            "msrc" => await Msrc(s, http, dir),
            _ => Advisories.ParseRss(await http.GetStringAsync(s.Url), s.Name),
        };
        return items.Where(a => (!s.RequireCve || a.Cves.Count > 0) && (!DateOnly.TryParse(a.Published, out var d) || d >= today.AddDays(-days)))
            .Select(a => a with { Grade = s.Grade, Tlp = s.Tlp }).ToList();
    }

    public static List<Advisory> ParseAtom(string xml, string source)
    {
        XNamespace a = "http://www.w3.org/2005/Atom";
        return XDocument.Parse(xml).Descendants(a + "entry").Select(e =>
        {
            var html = (string?)e.Element(a + "content") ?? (string?)e.Element(a + "summary") ?? "";
            var text = Regex.Replace(System.Net.WebUtility.HtmlDecode(Regex.Replace(html, "<[^>]+>", " ")), @"\s+", " ").Trim();
            var link = e.Elements(a + "link").FirstOrDefault(l => (string?)l.Attribute("rel") is null or "alternate")?.Attribute("href")?.Value ?? "";
            var pub = DateTimeOffset.TryParse((string?)e.Element(a + "published") ?? (string?)e.Element(a + "updated"), out var d) ? d.ToString("yyyy-MM-dd") : "";
            return new Advisory(source, ((string?)e.Element(a + "title") ?? "").Trim(), link, pub, text,
                Regex.Matches(text, @"CVE-\d{4}-\d{4,}").Select(m => m.Value).Distinct().ToList(), "");
        }).ToList();
    }

    /// <summary>Microsoft's newest monthly CVRF document: one advisory per CVE Microsoft marks "Exploited:Yes".
    /// ponytail: only exploited CVEs are kept; a vendor fix alone is already implied by Defender's own list. The 30 MB document is fetched again only when Microsoft revises it.</summary>
    static async Task<List<Advisory>> Msrc(Source s, HttpClient http, string dir)
    {
        using var updates = JsonDocument.Parse(await http.GetStringAsync(s.Url));
        var month = updates.RootElement.GetProperty("value").EnumerateArray().MaxBy(u => u.GetProperty("InitialReleaseDate").GetString());
        var url = month.GetProperty("CvrfUrl").GetString()!; var stamp = url + "|" + month.GetProperty("CurrentReleaseDate").GetString();
        var seen = Path.Combine(dir, "msrc-seen.txt");
        if (File.Exists(seen) && File.ReadAllText(seen) == stamp) return Advisories.Load(dir).Where(a => a.Source == s.Name).ToList();
        using var req = new HttpRequestMessage(HttpMethod.Get, url); req.Headers.Accept.ParseAdd("application/json");
        using var r = await http.SendAsync(req); r.EnsureSuccessStatusCode();
        var list = ParseCvrf(await r.Content.ReadAsStringAsync(), s.Name);
        File.WriteAllText(seen, stamp);
        return list;
    }

    public static List<Advisory> ParseCvrf(string json, string source)
    {
        using var doc = JsonDocument.Parse(json);
        var released = doc.RootElement.GetProperty("DocumentTracking").GetProperty("InitialReleaseDate").GetString()![..10];
        var list = new List<Advisory>();
        foreach (var v in doc.RootElement.GetProperty("Vulnerability").EnumerateArray())
        {
            var status = v.TryGetProperty("Threats", out var th) ? th.EnumerateArray()
                .Select(t => t.TryGetProperty("Description", out var d) && d.TryGetProperty("Value", out var val) ? val.GetString() ?? "" : "")
                .FirstOrDefault(x => x.Contains("Exploited:Yes")) : null;
            if (status is null) continue;
            var cve = v.GetProperty("CVE").GetString()!;
            var title = v.TryGetProperty("Title", out var t2) && t2.TryGetProperty("Value", out var tv) ? tv.GetString() ?? cve : cve;
            list.Add(new(source, $"{cve} {title}", $"https://msrc.microsoft.com/update-guide/vulnerability/{cve}", released,
                $"Microsoft security update {released}: {title}. Exploit status: {status}", new() { cve }, "Functional"));
        }
        return list;
    }
}
