using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

public record DefenderRow(string Cve, string Severity, double Cvss, double Epss, int Age, bool Defender, string[] Products, int Exposed, string Description);

/// <summary>One thing to do (update one product), with every CVE it clears. Tier and Rule come from the ladder; Flag is the analyst's own mark.</summary>
public record FixAction(string Product, string Fix, List<DefenderRow> Rows, int Exposed, int Age, double MaxCvss, double MaxEpss, int Kev, int NotInNvd,
    string Tier, string Rule, string Feeds, string Flag = "", bool Snoozed = false, List<Advisories.Match>? Matched = null, string Label = "")
{
    public string Key => Product;
    /// <summary>MITRE ATT&amp;CK groups documented exploiting one of its CVEs (cve.db actor_cve). Sources only, never model memory.</summary>
    public List<string> Actors { get; init; } = new();
    /// <summary>The intel card: cited lines built from the evidence (Intel.Card), or the LLM's cited version of them.</summary>
    public string Card { get; init; } = "";
    public string Reason => $"{Rule}. {Rows.Count} CVEs, {Exposed} machines, oldest {Age} days.";
}

/// <summary>Defender TVM vulnerability export -> fix actions ranked by a fixed, readable ladder. The LLM and the feeds (phase 2) add evidence; they never set the tier.
/// ponytail: one fix action per product (not per branch such as Firefox ESR), upgrade the grouping if two branches need separate answers.</summary>
public static class DefenderTriage
{
    public static readonly string[] Tiers = { "Act", "Attend", "Track", "Ignore" };
    const double AttendEpss = 0.05;     // same cut as the main ladder's default
    const int WideExposure = 100;       // machines; "widely exposed" in the Attend rule

    // Defender lists the distro/vendor repackaging of a product next to the product itself: those are noise.
    static readonly HashSet<string> Distro = new() { "debian", "suse", "wolfi", "chainguard", "minimus", "red_hat", "centos", "alma_linux", "rocky_linux",
        "amazon", "fedora", "oracle", "ubuntu", "alpine", "bitnami", "vmware", "dhi", "opensuse" };
    static readonly Dictionary<string, string> Names = new()
    {
        ["microsoft:edge_chromium-based"] = "Microsoft Edge", ["microsoft:edge_chromium"] = "Microsoft Edge", ["mozilla:firefox"] = "Mozilla Firefox", ["mozilla:thunderbird"] = "Mozilla Thunderbird",
        ["google:chrome"] = "Google Chrome", ["php:php"] = "PHP", ["docker:desktop"] = "Docker Desktop", ["python:python"] = "Python",
    };
    /// <summary>Product classes that face the internet by nature. No asset list exists, so this is the proxy; data/product_classes.txt (one word per line) extends it.</summary>
    static readonly string[] InternetFacing = { "edge", "chrome", "firefox", "thunderbird", "php", "outlook", "teams", "exchange", "sharepoint" };

    // ---- 1. read the export -------------------------------------------------------------------------------------------------

    static readonly Regex Record = new(
        @"^(CVE-\d{4}-\d+),(\w+),([\d.]*),([\d.]*),(\d*),(""[^""]*""|[^,]*),(""[^""]*""|[^,]*),(""[^""]*""|[^,]*),(\w+),(\w+),(\w+),(.*?),(\d+),(.*)$", RegexOptions.Singleline);
    static readonly Regex Fixed = new(@"(?:prior to|before|earlier than|fixed in(?: version)?|fixed versions?:?)\s+(?:[A-Za-z][\w-]*\s+)?v?(\d+(?:\.\d+){1,3}|\d{2,})", RegexOptions.IgnoreCase);
    static readonly Regex Upgrade = new(@"(?:upgrade|update) to\s+(?:[A-Za-z][\w-]*\s+){1,3}v?(\d+\.\d+(?:\.\d+){0,2})", RegexOptions.IgnoreCase);
    // product words a fixed version can belong to in a description
    static readonly string[] Owners = Names.Values.Select(n => n.Split(' ')[^1]).Append("ESR").Distinct().ToArray();

    /// <summary>Reads the export as Defender writes it (CSV, or .xlsx with proper columns) and also as it looks when the CSV was opened in Excel and split on commas
    /// (one record spread over many cells, descriptions broken across rows). Records are found by their CVE id, not by line.</summary>
    public static List<DefenderRow> Load(string path)
    {
        string text;
        if (Path.GetExtension(path).Equals(".xlsx", StringComparison.OrdinalIgnoreCase))
        {
            var cells = Inventory.XlsxCells(path);
            var columnar = cells.Any(r => Regex.IsMatch(r.Values.First(), @"^CVE-\d{4}-\d+$")); // a proper table; otherwise the cells are pieces of a comma-split CSV
            text = string.Join("\n", cells.Select(r => string.Join(",", columnar ? r.Values.Select(Quote) : r.Values)));
        }
        else text = File.ReadAllText(path).TrimStart('﻿');
        var rows = new List<DefenderRow>();
        foreach (var rec in Regex.Split(text, @"\r?\n(?=CVE-\d{4}-\d+,)").Where(r => r.StartsWith("CVE-")))
        {
            var m = Record.Match(rec);
            if (!m.Success) continue;
            var g = m.Groups;
            var software = Unquote(g[12].Value).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            var desc = Regex.Replace(g[14].Value, @"""?,\w*\s*$", "").Trim().Trim('"').Replace("\"\"", "\"");
            rows.Add(new(g[1].Value, g[2].Value, Num(g[3].Value), Num(g[4].Value), int.TryParse(g[5].Value, out var age) ? age : 0,
                g[9].Value == "True" || g[10].Value == "True" || g[11].Value == "True", Product(software), int.Parse(g[13].Value), desc));
        }
        return rows;
    }

    static string Quote(string c) => c.IndexOfAny(new[] { ',', '"', '\n' }) >= 0 ? "\"" + c.Replace("\"", "\"\"") + "\"" : c;
    static string Unquote(string s) => s.Length > 1 && s[0] == '"' && s[^1] == '"' ? s[1..^1] : s;
    static double Num(string s) => double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : 0;

    /// <summary>The products a CVE needs a fix for: every known product it lists (a Mozilla CVE hits Firefox and Thunderbird), else the first listing that is not a distro repackage.</summary>
    static string[] Product(string[] software)
    {
        var known = software.Where(Names.ContainsKey).Select(s => Names[s]).Distinct().ToArray();
        if (known.Length > 0) return known;
        var p = software.FirstOrDefault(s => !Distro.Contains(s.Split(':')[0])) ?? software.FirstOrDefault() ?? "unknown";
        var t = System.Globalization.CultureInfo.InvariantCulture.TextInfo;
        var (vendor, prod) = p.Contains(':') ? (p.Split(':')[0], p.Split(':', 2)[1]) : ("", p);
        if (prod.StartsWith(vendor, StringComparison.OrdinalIgnoreCase)) vendor = ""; // "openssl:openssl" -> "Openssl", "telegram:telegram_desktop" -> "Telegram Desktop"
        return new[] { t.ToTitleCase((vendor + " " + prod).Trim().Replace('_', ' ')) };
    }

    static string Trim(string s) => s.Length > 70 ? s[..67] + "..." : s;

    public static int CveCount(IEnumerable<FixAction> actions) => actions.SelectMany(a => a.Rows).Select(r => r.Cve).Distinct().Count();

    /// <summary>The version that fixes every CVE, from the descriptions ("prior to 148.0.7778.216", "fixed in Firefox 151", "upgrade to Docker Desktop version 4.76.0"), or "".
    /// A version belongs to the product named in its own clause ("Google Chrome prior to X"), else to the first product the description names,
    /// so Edge does not take Chrome's build number as its own: it gets "the build with the Chrome X fix".</summary>
    public static string FixVersion(string product, IEnumerable<string> descriptions)
    {
        var own = product.Split(' ')[^1];
        var found = descriptions.SelectMany(d => Fixed.Matches(d).Concat(Upgrade.Matches(d)).Select(m => (Ver: m.Groups[1].Value,
            By: Owner(d[Math.Max(0, m.Groups[1].Index - 40)..m.Groups[1].Index], own, last: true) ?? Owner(d, own, last: false)))).ToList();
        var mine = found.Where(f => f.By is null || f.By.Equals(own, StringComparison.OrdinalIgnoreCase)).Select(f => f.Ver).ToList();
        if (mine.Count > 0) return mine.Max(ByVersion) + " or later";
        if (found.Count == 0) return "";
        var other = found.MaxBy(f => f.Ver, ByVersion);
        return $"the build with the {other.By} {other.Ver} fix";
    }

    // ponytail: word heuristic over AI-written text; "Edge prior to <Chrome build>" in one clause would still go to Edge. NVD, tried first in Rank, is exact.
    static string? Owner(string text, string own, bool last) => Owners.Append(own)
        .Select(w => (w, m: Regex.Match(text, $@"\b{Regex.Escape(w)}\b", RegexOptions.IgnoreCase | (last ? RegexOptions.RightToLeft : RegexOptions.None)))).Where(x => x.m.Success)
        .OrderBy(x => last ? -x.m.Index : x.m.Index).Select(x => x.w).FirstOrDefault();

    /// <summary>NVD's fixed versions (cpe versionEndExcluding) for one product, one per branch that clears every CVE: "8.2.34 / 8.3.35 or later". "" if NVD has none.</summary>
    public static string NvdFix(string product, IEnumerable<List<(string Product, string Fixed)>> perCve)
    {
        var cves = perCve.Select(l => l.Where(x => x.Product == product).Select(x => x.Fixed).ToList()).Where(l => l.Count > 0).ToList();
        // a branch counts only if every CVE has a fix in it or was fixed before the branch (Chrome 148 drops out once one CVE needs 154)
        var branches = cves.SelectMany(l => l).GroupBy(Branch).Select(g => g.Max(ByVersion)!)
            .Where(b => cves.All(l => l.Any(v => Branch(v) == Branch(b)) || l.All(v => ByVersion.Compare(v, b) < 0))).Order(ByVersion).ToList();
        return branches.Count == 0 ? "" : string.Join(" / ", branches) + " or later";
    }

    static string Branch(string v) { var n = Nums(v); return n.Length < 2 || n[0] >= 20 ? n.FirstOrDefault().ToString() : $"{n[0]}.{n[1]}"; } // PHP 8.3, OpenSSL 3.0; Chrome 154
    static int[] Nums(string v) => Regex.Matches(v, @"\d+").Select(m => int.TryParse(m.Value, out var n) ? n : 0).ToArray();
    static readonly Comparer<string> ByVersion = Comparer<string>.Create((a, b) =>
    {
        var (x, y) = (Nums(a), Nums(b));
        for (var i = 0; i < Math.Min(x.Length, y.Length); i++) if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        return x.Length != y.Length ? x.Length.CompareTo(y.Length) : string.CompareOrdinal(a, b); // 1.1.1zh < 1.1.1zq
    });

    /// <summary>A cve.cpes JSON list -> (product, fixed version) for every entry with versionEndExcluding.</summary>
    static List<(string, string)> Cpes(string json) => (JsonSerializer.Deserialize<List<Dictionary<string, JsonElement>>>(json) ?? new())
        .Where(m => m.TryGetValue("versionEndExcluding", out var v) && v.ValueKind == JsonValueKind.String && m.TryGetValue("criteria", out var c) && c.GetString()!.Split(':').Length > 4)
        .Select(m => (Product(new[] { string.Join(':', m["criteria"].GetString()!.Split(':')[3..5]) })[0], m["versionEndExcluding"].GetString()!)).ToList();

    // ---- 2. rank ----------------------------------------------------------------------------------------------------------

    /// <summary>Joins the rows to cve.db (KEV, EPSS) when it exists, groups by product and applies the ladder. cve.db may be null: Defender's own data is used alone.</summary>
    public static List<FixAction> Rank(List<DefenderRow> rows, string? cveDb, string? dataDir = null, List<Advisory>? advisories = null, DateOnly? today = null)
    {
        var kev = new HashSet<string>(); var inNvd = new HashSet<string>(); var epss = new Dictionary<string, double>(); var actors = new Dictionary<string, List<string>>();
        var fixes = new Dictionary<string, List<(string, string)>>();
        if (cveDb is not null && File.Exists(cveDb))
        {
            using var db = new SqliteConnection($"Data Source={cveDb};Mode=ReadOnly"); db.Open();
            using var c = db.CreateCommand();
            c.CommandText = "SELECT count(*) FROM pragma_table_info('cve') WHERE name = 'cpes'";
            var hasCpes = (long)c.ExecuteScalar()! == 1;
            // independent lookups: a CVE can be in KEV or EPSS before NVD has it (the export's only KEV CVE is exactly that)
            c.CommandText = "SELECT (SELECT 1 FROM cve WHERE id = @id), (SELECT epss FROM epss WHERE id = @id), (SELECT 1 FROM kev WHERE id = @id), " +
                (hasCpes ? "(SELECT cpes FROM cve WHERE id = @id)" : "NULL");
            var p = c.Parameters.Add("@id", SqliteType.Text);
            foreach (var cve in rows.Select(r => r.Cve).Distinct())
            {
                p.Value = cve; using var r = c.ExecuteReader(); r.Read();
                if (!r.IsDBNull(0)) inNvd.Add(cve);
                if (!r.IsDBNull(1)) epss[cve] = r.GetDouble(1);
                if (!r.IsDBNull(2)) kev.Add(cve);
                if (!r.IsDBNull(3)) fixes[cve] = Cpes(r.GetString(3));
            }
            using var t = db.CreateCommand();
            t.CommandText = "SELECT count(*) FROM sqlite_master WHERE name IN ('actor', 'actor_cve')";
            if ((long)t.ExecuteScalar()! == 2) // ATT&CK synced
            {
                t.CommandText = "SELECT a.name FROM actor_cve x JOIN actor a ON a.id = x.actor WHERE x.cve = @id";
                var q = t.Parameters.Add("@id", SqliteType.Text);
                foreach (var cve in rows.Select(r => r.Cve).Distinct())
                {
                    q.Value = cve; using var r = t.ExecuteReader();
                    while (r.Read()) (actors.TryGetValue(cve, out var l) ? l : actors[cve] = new()).Add(r.GetString(0));
                }
            }
        }
        var internet = InternetFacing.Concat(dataDir is not null && File.Exists(Path.Combine(dataDir, "product_classes.txt"))
            ? File.ReadAllLines(Path.Combine(dataDir, "product_classes.txt")).Select(l => l.Trim().ToLowerInvariant()).Where(l => l != "") : Array.Empty<string>()).ToArray();
        var useDb = inNvd.Count > 0;
        return rows.SelectMany(r => r.Products.Select(p => (p, r))).GroupBy(x => x.p, x => x.r).Select(g =>
        {
            var list = g.ToList();
            var nKev = list.Count(r => kev.Contains(r.Cve));
            var maxEpss = list.Max(r => Math.Max(r.Epss, epss.GetValueOrDefault(r.Cve)));
            var maxCvss = list.Max(r => r.Cvss); var exposed = list.Max(r => r.Exposed);
            var defender = list.Count(r => r.Defender);
            var web = internet.Any(w => g.Key.Contains(w, StringComparison.OrdinalIgnoreCase));
            var adv = Advisories.For(g.Key, list.Select(r => r.Cve), advisories ?? new(), today ?? DateOnly.FromDateTime(DateTime.Now), dir: dataDir);
            var groups = list.SelectMany(r => actors.GetValueOrDefault(r.Cve) ?? new()).Distinct().ToList();
            static bool Strong(Advisories.Match m) => m.Advisory.Grade is "A" or "B";
            var hot = adv.FirstOrDefault(m => m.Advisory.ActivelyExploited && Strong(m)); var weakHot = adv.FirstOrDefault(m => m.Advisory.ActivelyExploited && !Strong(m));
            var exists = adv.FirstOrDefault(m => m.Advisory.ExploitExists);
            string How(Advisories.Match m) => $"{m.Advisory.Source} \"{Trim(m.Advisory.Title)}\" ({(m.ByCve ? "names its CVE" : "matched by product name only")})";
            string Src(Advisories.Match m) => m.Advisory.Source;
            string Only(Advisories.Match m) => m.ByCve ? "" : " (name only)";
            // Rule is the full sentence (detail pane, briefing, xlsx); Label is the few words the grid shows
            var (tier, rule, label) =
                nKev > 0 ? ("Act", $"CISA KEV lists {nKev} of its CVEs as exploited", "KEV: exploited") :
                hot is not null ? ("Act", $"{How(hot)} says it is actively exploited", $"{Src(hot)}: actively exploited") :
                weakHot is not null ? ("Attend", $"{How(weakHot)} says it is actively exploited (grade {weakHot.Advisory.Grade} source)", $"{Src(weakHot)}: exploited (grade {weakHot.Advisory.Grade})") :
                groups.Count > 0 ? ("Attend", $"MITRE ATT&CK documents {string.Join(", ", groups)} exploiting one of its CVEs", $"Used by {groups[0]}{(groups.Count > 1 ? $" +{groups.Count - 1}" : "")}") :
                exists is not null ? ("Attend", $"{How(exists)} reports a working exploit", $"{Src(exists)}: exploit exists") :
                adv.Count > 0 ? ("Attend", $"{How(adv[0])}", $"{Src(adv[0])} advisory{Only(adv[0])}") :
                defender > 0 ? ("Attend", $"Defender marks {defender} CVEs as exploited or threat-linked", "Defender: exploited") :
                maxEpss >= AttendEpss ? ("Attend", $"EPSS is {maxEpss:P1}, at or above {AttendEpss:P0}", $"EPSS {maxEpss:P0}") :
                maxCvss >= 7 && web && exposed >= WideExposure ? ("Attend", $"high severity on an internet-facing product on {exposed} machines", "High, internet-facing, wide") :
                maxCvss >= 7 ? ("Track", "high or critical severity, no sign of exploitation", "High, not exploited") :
                ("Ignore", "medium or low severity, no sign of exploitation", "Low, not exploited");
            var feeds = new List<string>();
            if (nKev > 0) feeds.Add("KEV"); foreach (var s in adv.Select(m => m.Advisory.Source).Distinct()) feeds.Add(s); if (maxEpss >= AttendEpss) feeds.Add("EPSS"); if (defender > 0) feeds.Add("Defender"); if (groups.Count > 0) feeds.Add("ATT&CK");
            var fix = NvdFix(g.Key, list.Select(r => fixes.GetValueOrDefault(r.Cve) ?? new())) is { Length: > 0 } nvd ? nvd : FixVersion(g.Key, list.Select(r => r.Description));
            var fa = new FixAction(g.Key, fix, list.OrderByDescending(r => kev.Contains(r.Cve)).ThenByDescending(r => r.Cvss).ToList(),
                exposed, list.Max(r => r.Age), maxCvss, maxEpss, nKev, useDb ? list.Count(r => !inNvd.Contains(r.Cve)) : 0, tier, rule, string.Join(" · ", feeds), Matched: adv, Label: label) { Actors = groups };
            return fa with { Card = Intel.Card(Intel.Rows(fa)) };
        }).OrderBy(a => Array.IndexOf(Tiers, a.Tier)).ThenByDescending(a => a.Exposed).ThenByDescending(a => a.Age).ToList();
    }

    // ---- 3. analyst flags and the daily difference ---------------------------------------------------------------------------

    public record Flag(string Action, string Reason, string Until);

    public static Dictionary<string, Flag> LoadFlags(string dir) =>
        File.Exists(Path.Combine(dir, "triage-flags.json")) ? JsonSerializer.Deserialize<Dictionary<string, Flag>>(File.ReadAllText(Path.Combine(dir, "triage-flags.json"))) ?? new() : new();

    /// <summary>Marks a fix action Agree / Raise / Lower / Snooze with a reason (and a date for Snooze). Stored in triage-flags.json.</summary>
    public static void SetFlag(string dir, string key, string action, string reason, string until = "")
    {
        if (!new[] { "Agree", "Raise", "Lower", "Snooze" }.Contains(action)) throw new ArgumentException("action must be Agree, Raise, Lower or Snooze");
        var flags = LoadFlags(dir); flags[key] = new(action, reason, until);
        File.WriteAllText(Path.Combine(dir, "triage-flags.json"), JsonSerializer.Serialize(flags, new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>The analyst's mark wins, and says so: Raise/Lower move one tier, Snooze (until a date) keeps the tier but takes it off the decision list.</summary>
    public static List<FixAction> ApplyFlags(List<FixAction> actions, Dictionary<string, Flag> flags, DateOnly today) => actions.Select(a =>
    {
        if (!flags.TryGetValue(a.Key, out var f)) return a;
        var expired = DateOnly.TryParse(f.Until, out var u) && u < today;
        if (expired) return a with { Flag = $"flag expired {f.Until} ({f.Action}: {f.Reason})" };
        var i = Array.IndexOf(Tiers, a.Tier);
        var tier = f.Action == "Raise" ? Tiers[Math.Max(0, i - 1)] : f.Action == "Lower" ? Tiers[Math.Min(Tiers.Length - 1, i + 1)] : a.Tier;
        return a with { Tier = tier, Flag = $"{f.Action}: {f.Reason}" + (f.Until != "" ? $" (until {f.Until})" : ""), Snoozed = f.Action == "Snooze" };
    }).OrderBy(a => Array.IndexOf(Tiers, a.Tier)).ThenByDescending(a => a.Exposed).ThenByDescending(a => a.Age).ToList();

    public record Diff(bool HasPrevious, string PreviousDay, List<string> New, List<string> Gone, List<(string Key, string From, string To)> Changed);

    /// <summary>Compares today's tiers with the latest earlier day kept in triage-history/, then saves today's.</summary>
    public static Diff SaveAndCompare(string dir, List<FixAction> actions, DateOnly today)
    {
        var hist = Path.Combine(dir, "triage-history"); Directory.CreateDirectory(hist);
        var prev = Directory.GetFiles(hist, "*.json").Select(Path.GetFileNameWithoutExtension).Where(n => string.CompareOrdinal(n, today.ToString("yyyy-MM-dd")) < 0).OrderBy(n => n).LastOrDefault();
        var now = actions.ToDictionary(a => a.Key, a => a.Tier);
        File.WriteAllText(Path.Combine(hist, today.ToString("yyyy-MM-dd") + ".json"), JsonSerializer.Serialize(now));
        if (prev is null) return new(false, "", new(), new(), new());
        var old = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Path.Combine(hist, prev + ".json"))) ?? new();
        return new(true, prev, now.Keys.Except(old.Keys).ToList(), old.Keys.Except(now.Keys).ToList(),
            now.Where(kv => old.TryGetValue(kv.Key, out var t) && t != kv.Value).Select(kv => (kv.Key, old[kv.Key], kv.Value)).ToList());
    }

    // ---- 4. the morning briefing --------------------------------------------------------------------------------------------

    /// <summary>Recent advisories that matched no fix action: either not our estate, or something Defender does not see. The analyst decides which.</summary>
    public static List<Advisory> Unmatched(List<FixAction> actions, List<Advisory> advisories, DateOnly today, int days = 30) =>
        advisories.Where(a => (!DateOnly.TryParse(a.Published, out var d) || d >= today.AddDays(-days)) && !actions.Any(f => f.Matched?.Any(m => m.Advisory.Link == a.Link) == true)).ToList();

    public static string Html(List<FixAction> actions, Diff diff, string source, DateOnly today, List<Advisory>? unmatched = null)
    {
        string E(string s) => WebUtility.HtmlEncode(s);
        var decide = actions.Where(a => a.Tier is "Act" or "Attend" && !a.Snoozed
            && (!diff.HasPrevious || diff.New.Contains(a.Key) || diff.Changed.Any(c => c.Key == a.Key))).ToList();
        var sb = new StringBuilder($"<!doctype html><meta charset=utf-8><title>Stenwatch morning briefing</title><style>body{{font:15px system-ui;max-width:1000px;margin:24px auto;padding:0 16px}}" +
            "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}.Act{color:#b00020;font-weight:700}.Attend{color:#b25e00;font-weight:700}" +
            $".n{{color:#666;font-size:13px}}</style><h1>Morning briefing {today:yyyy-MM-dd}</h1><p class=n>Source: {E(source)}. {CveCount(actions)} CVEs in {actions.Count} fix actions.</p>");
        sb.Append("<h2>Needs a decision today</h2>");
        if (decide.Count == 0) sb.Append("<p>Nothing new or changed in Act or Attend.</p>");
        foreach (var a in decide) sb.Append($"<p><b class={a.Tier}>{a.Tier}</b> {E(a.Product)}{(a.Fix != "" ? " to " + E(a.Fix) : "")}: {E(a.Reason)}<br><span class=n>{E(a.Card.Split('\n')[0])}</span></p>");
        if (diff.HasPrevious)
            sb.Append($"<p class=n>Since {diff.PreviousDay}: {diff.New.Count} new, {diff.Gone.Count} gone, {diff.Changed.Count} changed tier" +
                (diff.Changed.Count > 0 ? " (" + E(string.Join(", ", diff.Changed.Select(c => $"{c.Key} {c.From}→{c.To}"))) + ")" : "") + ".</p>");
        else sb.Append("<p class=n>First export kept: tomorrow's briefing will show what changed.</p>");
        sb.Append("<h2>Fix actions, in order</h2><table><tr><th>Tier<th>Fix action<th>CVEs<th>Machines<th>Feeds<th>Why<th>Analyst</tr>");
        foreach (var a in actions)
        {
            sb.Append($"<tr><td class={a.Tier}>{a.Tier}<td>{E(a.Product)}{(a.Fix != "" ? "<br>update to " + E(a.Fix) : "<br><span class=n>no fixed version published: latest vendor update</span>")}<td>{a.Rows.Count}<td>{a.Exposed}<td>{E(a.Feeds)}" +
                $"<td title=\"{E(a.Rule)}\">{E(a.Label != "" ? a.Label : a.Rule)}{(a.NotInNvd > 0 ? $"<br><span class=n>{a.NotInNvd} CVEs not in local NVD</span>" : "")}<td>{E(a.Flag)}</tr>");
        }
        sb.Append("</table>");
        if (unmatched is { Count: > 0 })
        {
            sb.Append($"<h2>Advisories with no match in this export ({unmatched.Count})</h2><details class=n><summary>What is this list?</summary>Advisories from the last 30 days that matched nothing in this export: other products, or something Defender does not see. Your call.</details><ul>");
            foreach (var u in unmatched) sb.Append($"<li>{E(u.Source)} {E(u.Published)}: <a href=\"{E(u.Link)}\">{E(u.Title)}</a>{(u.ActivelyExploited ? " <b class=Act>actively exploited</b>" : u.ExploitExists ? " <b class=Attend>exploit exists</b>" : "")}" +
                (u.Cves.Count > 0 ? $" <span class=n>{E(string.Join(", ", u.Cves.Take(4)))}</span>" : "") + "</li>");
            sb.Append("</ul>");
        }
        sb.Append("<details class=n><summary>Rule-based ranking, not validated against outcomes</summary>The ladder is a fixed rule set: each row names the rule that fired. " +
            "No asset list was available: exposure is Defender's machine count only. Mark a row in the app (Agree, Raise, Lower, Snooze); your mark is kept and shown.</details>");
        return sb.ToString();
    }

    // ---- 4b. one morning's run: used by the CLI and the app --------------------------------------------------------------------

    public record Options(string Export, string Data, string CveDb, bool FetchFeeds, bool UseLlm, IEnumerable<string>? AdvisoryFiles = null, DateOnly? Today = null);
    public record Result(List<FixAction> Actions, Diff Diff, List<Advisory> Advisories, List<Advisory> Unmatched, string ItNote, string NoteSource, List<string> Notes, string OutDir);

    /// <summary>Read the export, refresh feeds, let the LLM read what the rules cannot, rank, apply the analyst's flags, compare with yesterday, write briefing.html, fix-actions.xlsx and it-note.txt.
    /// Every optional step fails soft: a note says what was skipped and why.</summary>
    public static async Task<Result> Run(Options o, HttpClient? http = null, Action<string>? log = null)
    {
        var today = o.Today ?? DateOnly.FromDateTime(DateTime.Now); var notes = new List<string>(); http ??= new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        void Note(string s) { notes.Add(s); log?.Invoke(s); }
        log?.Invoke("Reading the Defender export...");
        var rows = Load(o.Export);
        if (rows.Count == 0) throw new InvalidDataException("no vulnerability rows found: is this a Defender 'Vulnerabilities export' file?");
        var advisories = Advisories.Load(o.Data);
        if (o.FetchFeeds) { log?.Invoke("Fetching sources (NCSC-FI, CERT-EU, CISA, Microsoft, Chrome)..."); var (all, note) = await Advisories.Refresh(o.Data, http); advisories = all; Note(note); }
        var pasted = (o.AdvisoryFiles ?? Array.Empty<string>()).Where(File.Exists).Select(Advisories.FromText).ToList();
        if (pasted.Count > 0) { advisories = Advisories.Merge(advisories, pasted); Advisories.Save(o.Data, advisories); Note($"{pasted.Count} pasted advisories kept"); }
        if (o.UseLlm)
        {
            if (!TriageLlm.Ready) Note("LLM skipped: no OpenRouter key (Settings) and no local model configured");
            else { log?.Invoke("LLM is reading advisories that name no CVE..."); var (all, note) = await TriageLlm.Enrich(advisories, http, log: Note); advisories = all; Advisories.Save(o.Data, advisories); Note(note); }
        }
        var actions = ApplyFlags(Rank(rows, o.CveDb, o.Data, advisories, today), LoadFlags(o.Data), today);
        if (o.UseLlm && TriageLlm.Ready) // cards for what needs a decision; ponytail: top 6 only, free models are slow
        {
            var prof = Path.Combine(o.Data, "profile.yaml");
            var org = TriageLlm.Local && File.Exists(prof) && Profile.Load(prof).Organisation is { Sector.Length: > 0 } og ? $"a {og.Sector} organisation in {og.Country}" : "the organisation";
            var top = actions.Where(x => x.Tier is "Act" or "Attend" && !x.Snoozed).Take(6).ToList();
            for (var k = 0; k < top.Count; k++)
            {
                log?.Invoke($"LLM intel card {k + 1}/{top.Count}: {top[k].Product}...");
                actions[actions.IndexOf(top[k])] = top[k] with { Card = await TriageLlm.IntelCard(top[k], org, o.Data, http, Note) };
            }
        }
        var diff = SaveAndCompare(o.Data, actions, today);
        var unmatched = Unmatched(actions, advisories, today);
        string itNote, source = "template";
        log?.Invoke("Writing the note to IT...");
        if (o.UseLlm && TriageLlm.Ready) (itNote, source) = await TriageLlm.ItNoteWithLlm(actions, today, http, Note); else itNote = TriageLlm.ItNote(actions, today);
        var dir = Path.Combine(o.Data, "out", "triage"); Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "briefing.html"), Html(actions, diff, Path.GetFileName(o.Export), today, unmatched));
        File.WriteAllText(Path.Combine(dir, "it-note.txt"), itNote);
        WriteXlsx(Path.Combine(dir, "fix-actions.xlsx"), actions);
        return new(actions, diff, advisories, unmatched, itNote, source, notes, dir);
    }

    // ---- 5. xlsx with the added columns ---------------------------------------------------------------------------------------

    public static void WriteXlsx(string path, List<FixAction> actions)
    {
        var sheets = new (string Name, List<string[]> Rows)[]
        {
            ("Fix actions", new[] { new[] { "Tier", "Fix action", "Update to", "CVEs", "Machines", "Max CVSS", "Max EPSS", "KEV", "Feeds", "Rule", "Analyst flag" } }
                .Concat(actions.Select(a => new[] { a.Tier, a.Product, a.Fix, a.Rows.Count.ToString(), a.Exposed.ToString(), a.MaxCvss.ToString("0.0"), a.MaxEpss.ToString("0.00000"), a.Kev.ToString(), a.Feeds, a.Rule, a.Flag })).ToList()),
            ("CVEs", new[] { new[] { "CVE", "Tier of fix action", "Fix action", "Severity", "CVSS", "EPSS", "Age (days)", "Machines", "Defender exploit/threat flag" } }
                .Concat(actions.SelectMany(a => a.Rows.Select(r => new[] { r.Cve, a.Tier, a.Product, r.Severity, r.Cvss.ToString("0.0"), r.Epss.ToString("0.00000"), r.Age.ToString(), r.Exposed.ToString(), r.Defender ? "yes" : "no" }))).ToList()),
        };
        WriteWorkbook(path, sheets);
    }

    /// <summary>Smallest valid .xlsx: text cells only, no styles. Excel, Inventory.XlsxCells and Defender.Load read it back.</summary>
    public static void WriteWorkbook(string path, (string Name, List<string[]> Rows)[] sheets)
    {
        if (File.Exists(path)) File.Delete(path);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        void Add(string name, string body) { using var w = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false)); w.Write(body); }
        const string ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main", rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        Add("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
            + string.Concat(sheets.Select((_, i) => $"<Override PartName=\"/xl/worksheets/sheet{i + 1}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>")) + "</Types>");
        Add("_rels/.rels", $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{rel}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");
        Add("xl/workbook.xml", $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"{ns}\" xmlns:r=\"{rel}\"><sheets>"
            + string.Concat(sheets.Select((s, i) => $"<sheet name=\"{WebUtility.HtmlEncode(s.Name)}\" sheetId=\"{i + 1}\" r:id=\"rId{i + 1}\"/>")) + "</sheets></workbook>");
        Add("xl/_rels/workbook.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            + string.Concat(sheets.Select((_, i) => $"<Relationship Id=\"rId{i + 1}\" Type=\"{rel}/worksheet\" Target=\"worksheets/sheet{i + 1}.xml\"/>")) + "</Relationships>");
        for (int i = 0; i < sheets.Length; i++)
            Add($"xl/worksheets/sheet{i + 1}.xml", $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><worksheet xmlns=\"{ns}\"><sheetData>"
                + string.Concat(sheets[i].Rows.Select((r, ri) => $"<row r=\"{ri + 1}\">" + string.Concat(r.Select((c, ci) =>
                    $"<c r=\"{(char)('A' + ci)}{ri + 1}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{WebUtility.HtmlEncode(c)}</t></is></c>")) + "</row>")) + "</sheetData></worksheet>");
    }
}
