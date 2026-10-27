using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Everything one run knows, in one document: the six CTI steps in order, then method and limits.
/// Built from the parts already written (report.md, threat-profile.md, paths.md) plus what the run used, so it cannot disagree with them.</summary>
public static class FullReport
{
    /// <summary>A part written earlier, without its own title and TLP line, headings one level down.</summary>
    static string Part(string outDir, string file)
    {
        var path = Path.Combine(outDir, file);
        if (!File.Exists(path)) return "";
        var lines = File.ReadAllLines(path).Skip(1).Where(l => !l.StartsWith("**TLP:AMBER**")).Select(l => l.StartsWith("#") ? "#" + l : l);
        return string.Join("\n", lines).Trim();
    }

    static string Cell(string s) => s.Replace("|", "/").Replace("\n", " ");

    public static string Write(PipelineFiles files, string outDir, Profile p, SqliteConnection db, OrgContext ctx, List<Ranked> ranked,
                               List<RemediationTask> tasks, bool example, bool pdf)
    {
        var today = DateOnly.FromDateTime(DateTime.Today);
        var md = new List<string>
        {
            $"# Full intelligence report: {p.Organisation.Name}, {today:yyyy-MM-dd}", "",
            "**TLP:AMBER**: limited disclosure, organisation and clients on a need-to-know basis only.", "",
            "One run of the intelligence cycle, step by step: who we are and who targets us (1), where the intelligence comes from (2), " +
            "what we run and how it fits together (3), what needs doing and why (4), how an attacker could get in (5), and the work that follows (6). " +
            "Method and limits are at the end.", "",
        };

        // 1 Direction
        md.AddRange(new[] { "## 1 Direction: who we are and who targets us", "",
            $"**{p.Organisation.Name}**, {p.Organisation.Sector}, {p.Organisation.Country}.", "", "### Priority intelligence requirements", "" });
        md.AddRange(p.Pirs.Select(x => "- " + x)); md.Add("");
        md.Add(Part(outDir, "threat-profile.md")); md.Add("");
        md.AddRange(new[] { "### How priority is decided", "",
            $"- Likelihood = {p.Weights.Epss} x EPSS + {p.Weights.Kev} x known exploited (KEV) + {p.Weights.Ransomware} x used in ransomware + {p.Weights.ThreatProfile} x used by a tracked group",
            $"- Impact = CVSS / 10 x asset criticality x exposure (internet {p.Exposure.Internet}, internal {p.Exposure.Internal})",
            "- Act: exploited and (internet-facing or high weight), patch within 48 hours. Attend: exploited, or EPSS of at least " + p.Tiers.AttendEpss.ToString(CultureInfo.InvariantCulture) + ". Track: watch. Ignore: no action.",
            $"- Deadlines: {string.Join(", ", p.Sla.Select(s => $"{s.Key} {s.Value} days"))}", "" });

        // 2 Collection
        var meta = new Dictionary<string, string>();
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT key, value FROM meta"; using var r = c.ExecuteReader(); while (r.Read()) meta[r.GetString(0)] = r.GetString(1); }
        long N(string t) { try { using var c = db.CreateCommand(); c.CommandText = $"SELECT COUNT(*) FROM {t}"; return (long)c.ExecuteScalar()!; } catch { return 0; } }
        string When(string k) => meta.TryGetValue(k, out var v) ? v[..Math.Min(10, v.Length)] : "not recorded";
        md.AddRange(new[] { "## 2 Collection: where the intelligence comes from", "",
            "Public sources only. Nothing about our estate leaves the organisation.", "",
            "| Source | What it tells us | Last pulled | Records |", "|---|---|---|---|",
            $"| NVD (NIST) | every published CVE, severity, affected products | {When("nvd_sync")} | {N("cve"):N0} |",
            $"| CISA KEV | CVEs confirmed exploited in the wild, ransomware use | {When("kev_sync")} | {N("kev"):N0} |",
            $"| FIRST EPSS | daily probability of exploitation in the next 30 days | {When("epss_sync")} | {N("epss"):N0} |",
            $"| MITRE ATT&CK | threat groups, their techniques and targets | {When("attack_sync")} | {N("actor"):N0} groups, {N("technique"):N0} techniques |",
            $"| CTID Mappings Explorer | which techniques an exploited CVE enables | {When("ctid_sync")} | {N("cve_technique"):N0} |",
            $"| MITRE D3FEND | defensive countermeasures per technique | {When("d3fend_sync")} | {N("defend"):N0} |", "" });

        // 3 Processing
        var owned = File.Exists(files.Assets) ? Process.LoadAssets(files.Assets) : new();
        md.AddRange(new[] { "## 3 Processing: our estate and how it fits together", "",
            $"- {owned.Count} assets in the asset list, {owned.Count(a => a.InternetFacing)} of them internet-facing; {owned.Count(a => a.Version == "")} without a version (every CVE for the product is counted unless a patch baseline is set)." });
        if (p.PatchBaseline != "") md.Add($"- Assumption: assets without a version or OS build are treated as patched for CVEs published before {p.PatchBaseline}.");
        var unmatched = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(files.Assets))!, "assets.unmatched.csv");
        if (!example && File.Exists(unmatched) && Csv.ReadDict(unmatched) is { Count: > 0 } um)
            md.Add($"- Not analysed: {string.Join(", ", um.Select(u => $"{u.GetValueOrDefault("what")} ({u.GetValueOrDefault("hosts")} hosts)"))}. NVD has no product entry for them, so no published CVE can be tied to them.");
        md.Add("");
        md.AddRange(new[] { "### Business services", "" });
        md.AddRange(ctx.Services.Count == 0 ? new[] { "None recorded: every asset keeps its own criticality.", "" }
            : new[] { "| Service | Owner | Criticality | Data | Assets |", "|---|---|---|---|---|" }
                .Concat(ctx.Services.Select(s => $"| {Cell(s.Name)} | {Cell(s.Owner)} | {s.Criticality} | {s.DataClass} | {Cell(string.Join(", ", ctx.ServiceAssets.GetValueOrDefault(s.Name) ?? new()))} |")).Append(""));
        var jewels = ctx.Assets.Values.Where(a => a.CrownJewel).Select(a => a.Asset).ToList();
        md.AddRange(new[] { "### Crown jewels", "", jewels.Count == 0 ? "None marked." : string.Join(", ", jewels), "", "### Links (what can reach what)", "" });
        md.AddRange(ctx.Links.Count == 0 ? new[] { "None recorded: attack paths can only show internet-facing entry points.", "" }
            : new[] { "| From | To | Kind | Port |", "|---|---|---|---|" }.Concat(ctx.Links.Select(l => $"| {Cell(l.Src)} | {Cell(l.Dst)} | {l.Kind} | {l.Port} |")).Append(""));
        md.AddRange(new[] { "### Security controls", "" });
        md.AddRange(ctx.Controls.Count == 0 ? new[] { "None recorded.", "" }
            : new[] { "| Control | Scope | Counters | Strength | Evidence | Counts? |", "|---|---|---|---|---|---|" }
                .Concat(ctx.Controls.Select(c => $"| {Cell(c.Name)} | {Cell(c.Scope)} | {c.Counters} | {c.Effectiveness} | {Cell(c.Evidence)} {c.EvidenceDate} | {(OrgContext.EvidenceValid(c, today) ? "yes" : "no: evidence missing, undated or expired")} |")).Append(""));

        // 4 Analysis, 5 Attack paths
        md.AddRange(new[] { "## 4 Analysis: what needs doing and why", "", Part(outDir, "report.md"), "", "## 5 Attack paths: how an attacker could get in", "" });
        var paths = Part(outDir, "paths.md");
        md.Add(paths != "" ? paths : "No routes to crown jewels: they need crown jewels and links between assets (step 3).");
        md.Add("");

        // 6 Feedback
        md.AddRange(new[] { "## 6 Feedback: the work that follows", "" });
        if (example) md.AddRange(new[] { "*Example Organisation: the tasks below come from a simulated eight-week history (earlier runs replayed on the estate before its upgrades).*", "" });
        {
            var by = tasks.GroupBy(t => t.State).Select(g => $"{g.Key} {g.Count()}");
            md.Add($"Tasks by state: {string.Join(", ", by)}. A fix counts as verified only when a later run no longer finds the CVE.");
            md.AddRange(new[] { "", "| CVE | Asset | Tier | State | Owner | Due |", "|---|---|---|---|---|---|" });
            md.AddRange(tasks.Where(t => TaskState.Active.Contains(t.State)).OrderBy(t => t.Due).Take(40)
                .Select(t => $"| [{t.Cve}](https://nvd.nist.gov/vuln/detail/{t.Cve}) | {Cell(t.Asset)} | {t.Tier} | {t.State} | {Cell(t.Owner)} | {t.Due} |"));
        }
        md.Add("");

        md.AddRange(new[] { "## Method and limits", "",
            "- Every priority lists its evidence, the source and how confident Stenwatch is. High: rests on confirmed exploitation. Medium: on predictions. Low: an assumption was needed.",
            "- No exploitation evidence is not evidence of safety.",
            "- Attack paths are possible, not proven: they follow declared links and assume each vulnerability works the way its CVSS vector or ATT&CK tactic says.",
            "- Automatic threat-group selection and the attack-path weighting are Proposed: reasoned, not yet validated against outcomes.",
            "- Stenwatch does not scan. What we run comes from the asset list; its accuracy limits everything above.", "" });

        var text = string.Join("\n", md);
        File.WriteAllText(Path.Combine(outDir, "full-report.md"), text);
        var html = Path.Combine(outDir, "full-report.html");
        Render.WritePage(text, html, "Full intelligence report", p.Organisation.Name, today.ToString("yyyy-MM-dd"),
            new[] { "Act", "Attend", "Track", "Ignore" }.Select(t => (t, ranked.Where(r => r.Tier == t).Select(r => r.Cve).Distinct().Count(), "CVEs")));
        if (pdf) Render.ToPdf(html);
        return html;
    }
}
