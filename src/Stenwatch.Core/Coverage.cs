using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>A component of exposure management: its short name, its Coverage group, and the export it needs before it can be connected.</summary>
public record Component(string Name, string Group, string Needs);

/// <summary>One component's state: connected / partly / not connected / needs attention, one number with its caption, the last import (yyyy-MM-dd or ""),
/// and a note: where the data comes from, or the export it still needs.</summary>
public record CoverageStatus(Component Component, string Status, int Count, string Caption, string LastImport, string Note);

/// <summary>Which components have data, worked out from what is in the data folder. Nothing is fetched and nothing is guessed:
/// a component nothing can feed yet is "not connected" and names the export it will need (docs/components.md, "First step").</summary>
public static class Coverage
{
    public const string Connected = "connected", Partly = "partly", NotConnected = "not connected", Attention = "needs attention";
    public static readonly string[] Groups = { "Know your estate", "Find weaknesses", "Know the threat", "Act and prove" };

    public static readonly Component[] Components =
    {
        new("Assets", Groups[0], "an inventory export (Intune, SCCM, CMDB) or assets.csv"),
        new("Attack surface", Groups[0], "Defender EASM export"),
        new("Cloud workloads", Groups[0], "Defender for Cloud recommendations export (CSV)"),
        new("OT and IoT", Groups[0], "Defender for IoT inventory export"),
        new("AI discovery", Groups[0], "Defender for Cloud Apps discovered apps, \"Generative AI\" category"),
        new("Identity", Groups[0], "Entra risky users export"),
        new("Vulnerabilities", Groups[1], "Defender vulnerabilities export, or cve.db with assets.csv"),
        new("Web apps", Groups[1], "OWASP ZAP JSON and SARIF files"),
        new("Misconfiguration", Groups[1], "Defender security recommendations export"),
        new("End-of-life software", Groups[1], "the asset list checked against endoflife.date"),
        new("Intelligence", Groups[2], "CSAF/VEX file reader"),
        new("Ticketing", Groups[3], "one webhook (Teams, Jira, ServiceNow, Azure DevOps)"),
        new("Reports", Groups[3], "a rank, which writes the reports"),
        new("Connectors", Groups[3], "Tenable/Qualys CSV import"),
    };

    /// <summary>Every component's status from <paramref name="dir"/> (cve.db, assets.csv, advisories.json, sources.json, triage-history/, tasks, exposures/).
    /// assetsCsv overrides the asset list (the Example Organisation's assets.example.csv).</summary>
    public static List<CoverageStatus> Of(string dir, string? assetsCsv = null, DateTimeOffset? now = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        var exposures = Exposure.Load(dir).ToLookup(e => e.Component);
        var db = Path.Combine(dir, "cve.db"); var assets = assetsCsv ?? Path.Combine(dir, "assets.csv");
        static string Day(DateTime t) => t.ToString("yyyy-MM-dd");
        static string Newest(IEnumerable<string> days) => days.Where(d => d != "").DefaultIfEmpty("").Max()!;

        // what the database holds; every table may be missing (feeds not synced, never ranked)
        var meta = new Dictionary<string, string>(); long cves = 0, kev = 0, lastRun = 0, tasks = 0, ticketed = 0; var runAt = "";
        if (File.Exists(db))
        {
            using var c = new SqliteConnection($"Data Source={db};Mode=ReadOnly;Pooling=False"); c.Open();
            long N(string sql) { try { using var q = c.CreateCommand(); q.CommandText = sql; return Convert.ToInt64(q.ExecuteScalar() ?? 0L); } catch (SqliteException) { return 0; } }
            try { using var q = c.CreateCommand(); q.CommandText = "SELECT key, value FROM meta"; using var r = q.ExecuteReader(); while (r.Read()) meta[r.GetString(0)] = r.GetString(1); } catch (SqliteException) { }
            cves = N("SELECT COUNT(*) FROM cve"); kev = N("SELECT COUNT(*) FROM kev");
            lastRun = N("SELECT COUNT(DISTINCT cve) FROM finding_history WHERE state = 'open' AND run = (SELECT MAX(id) FROM run)");
            try { using var q = c.CreateCommand(); q.CommandText = "SELECT at FROM run ORDER BY id DESC LIMIT 1"; runAt = q.ExecuteScalar() as string ?? ""; } catch (SqliteException) { }
            tasks = N("SELECT COUNT(*) FROM task WHERE state IN ('Open','InProgress','Fixed','Reopened')"); ticketed = N("SELECT COUNT(*) FROM task WHERE ticket <> ''");
        }
        string Meta(string k) => meta.TryGetValue(k, out var v) ? v[..Math.Min(10, v.Length)] : "";
        bool Stale(string k) => meta.TryGetValue(k, out var v) && EvidenceOf.IsStale(v, at);

        var assetRows = 0; var internet = 0; var inventory = false;
        try
        {
            if (File.Exists(assets) && !(inventory = Inventory.IsInventory(assets)))
            {
                var rows = Csv.ReadDict(assets); assetRows = rows.Count;
                internet = rows.Count(r => r.GetValueOrDefault("internet_facing", "").Trim().ToLowerInvariant() is "y" or "yes" or "true" or "1");
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException) { inventory = true; } // unreadable: needs a look
        var assetsDay = File.Exists(assets) ? Day(File.GetLastWriteTime(assets)) : "";

        var hist = Path.Combine(dir, "triage-history");
        var triage = Directory.Exists(hist) ? Directory.GetFiles(hist, "*.json").OrderBy(f => f, StringComparer.Ordinal).LastOrDefault() : null;
        var triageDay = triage is null ? "" : Path.GetFileNameWithoutExtension(triage);
        var fixActions = 0;
        try { if (triage is not null) fixActions = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(triage))?.Count ?? 0; }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException) { }

        var advisories = File.Exists(Path.Combine(dir, "advisories.json")) ? Advisories.Load(dir).Count : 0;
        var advDay = advisories > 0 ? Day(File.GetLastWriteTime(Path.Combine(dir, "advisories.json"))) : "";
        var sources = Sources.Load(dir).Count(s => s.Enabled);

        var reports = Directory.Exists(Path.Combine(dir, "out")) ? Directory.GetFiles(Path.Combine(dir, "out"), "full-report.html", SearchOption.AllDirectories) : Array.Empty<string>();

        CoverageStatus S(Component k)
        {
            CoverageStatus R(string status, int n, string caption, string day, string note) => new(k, status, n, caption, day, note);
            var mine = exposures[k.Name].ToList();
            if (mine.Count > 0) // an import for this component: its own rows count first
                return R(Connected, mine.Count, "findings", Newest(mine.Select(e => e.Date).Append(Day(File.GetLastWriteTime(Exposure.FileFor(dir, k.Name))))), $"{mine.Count} rows imported");
            var not = R(NotConnected, 0, "", "", "Needs " + k.Needs);
            switch (k.Name)
            {
                case "Assets":
                    if (inventory) return R(Attention, 0, "", assetsDay, "assets.csv is an inventory export: convert it on Threat profile");
                    return assetRows > 0 ? R(Connected, assetRows, "assets", assetsDay, "assets.csv") : not;
                case "Attack surface":
                    return internet > 0 ? R(Partly, internet, "internet-facing", assetsDay, "internet-facing flag in the asset list only; " + "needs " + k.Needs) : not;
                case "Vulnerabilities":
                    if (lastRun == 0 && fixActions == 0) return cves > 0 || assetRows > 0 ? R(Partly, 0, "", Meta("nvd_sync"), cves > 0 ? "feeds synced, not ranked yet" : "asset list only, no feeds yet") : not;
                    var day = Newest(new[] { runAt.Length >= 10 ? runAt[..10] : runAt, triageDay });
                    var note = lastRun > 0 ? "rank of cve.db against the asset list" : "Defender export (Morning triage)";
                    if (Stale("kev_sync")) return R(Attention, (int)(lastRun > 0 ? lastRun : fixActions), lastRun > 0 ? "CVEs" : "fix actions", day, "the KEV feed is out of date: sync on Feeds");
                    return R(Connected, (int)(lastRun > 0 ? lastRun : fixActions), lastRun > 0 ? "CVEs" : "fix actions", day, note);
                case "Intelligence":
                    if (kev == 0 && advisories == 0) return not;
                    if (Stale("kev_sync")) return R(Attention, sources, "sources", Newest(new[] { Meta("kev_sync"), advDay }), "the KEV feed is out of date: sync on Feeds");
                    return R(kev > 0 && advisories > 0 ? Connected : Partly, sources, "sources", Newest(new[] { Meta("kev_sync"), advDay }),
                        kev > 0 && advisories > 0 ? "public feeds and advisories" : kev > 0 ? "public feeds; no advisories read yet" : "advisories; public feeds not synced");
                case "Ticketing":
                    return tasks > 0 || ticketed > 0 ? R(Partly, (int)tasks, "active tasks", "", "tasks with owner and ticket field; nothing is pushed yet. Needs " + k.Needs) : not;
                case "Reports":
                    return reports.Length > 0 ? R(Connected, reports.Length, "reports", Newest(reports.Select(f => Day(File.GetLastWriteTime(f)))), "written by every rank") : not;
                case "Connectors":
                    var active = new[] { cves > 0, assetRows > 0, triage is not null, advisories > 0 }.Count(x => x);
                    return active > 0 ? R(Partly, active, "active", "", "file imports and public feeds; needs " + k.Needs) : not;
                default: return not;
            }
        }
        return Components.Select(S).ToList();
    }
}
