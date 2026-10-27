using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Test 1 of docs/evaluation.md: does ATT&amp;CK overlap improve prioritisation over EPSS alone?
/// Temporal backtest: only information published on or before T0 is used to rank; the outcome is KEV listing in the following 180 days.</summary>
public class AttackValue
{
    public record Result(string Label, string Reason, string Markdown, Dictionary<string, object> Inputs);

    readonly HttpClient http;
    readonly string cache;
    readonly Action<string> log;

    public AttackValue(string cacheDir, HttpClient? http = null, Action<string>? log = null)
    {
        cache = cacheDir; Directory.CreateDirectory(cache);
        this.http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        if (this.http.DefaultRequestHeaders.UserAgent.Count == 0) this.http.DefaultRequestHeaders.UserAgent.ParseAdd("Stenwatch");
        this.log = log ?? (_ => { });
    }

    async Task<byte[]> Fetch(string url, string name)
    {
        var path = Path.Combine(cache, name);
        if (File.Exists(path)) return await File.ReadAllBytesAsync(path);
        log($"  downloading {url}");
        var b = await http.GetByteArrayAsync(url);
        await File.WriteAllBytesAsync(path, b);
        return b;
    }

    static string S(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    /// <summary>FIRST publishes a file per day; use the one for T0 (or the next day if that one is missing).</summary>
    async Task<(Dictionary<string, double> Scores, string File)> EpssAt(DateOnly t0)
    {
        for (int i = 0; i < 4; i++)
        {
            var d = t0.AddDays(i).ToString("yyyy-MM-dd");
            try
            {
                var gz = await Fetch($"https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz", $"epss-{d}.csv.gz");
                using var sr = new StreamReader(new GZipStream(new MemoryStream(gz), CompressionMode.Decompress));
                var scores = new Dictionary<string, double>();
                foreach (var l in sr.ReadToEnd().Split('\n').Where(l => l != "" && !l.StartsWith('#')).Skip(1)) { var p = l.Split(','); scores[p[0]] = double.Parse(p[1], CultureInfo.InvariantCulture); }
                return (scores, $"epss_scores-{d}.csv.gz");
            }
            catch (HttpRequestException) { }
        }
        throw new InvalidOperationException($"no EPSS archive file found for {t0:yyyy-MM-dd}");
    }

    /// <summary>The last ATT&amp;CK Enterprise release published on or before T0.</summary>
    async Task<(string Version, string Modified, List<JsonElement> Objects)> AttackAt(DateOnly t0)
    {
        using var idx = JsonDocument.Parse(await Fetch("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json", "attack-index.json"));
        var versions = idx.RootElement.GetProperty("collections").EnumerateArray().First(c => S(c, "name").Contains("Enterprise")).GetProperty("versions").EnumerateArray()
            .Select(v => (Version: S(v, "version"), Modified: S(v, "modified"))).Where(v => string.CompareOrdinal(v.Modified[..10], t0.ToString("yyyy-MM-dd")) <= 0)
            .OrderByDescending(v => v.Modified).ToList();
        var best = versions.First();
        var bytes = await Fetch($"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{best.Version}.json", $"attack-{best.Version}.json");
        var doc = JsonDocument.Parse(bytes);
        return (best.Version, best.Modified, doc.RootElement.GetProperty("objects").EnumerateArray().ToList());
    }

    /// <summary>CTID KEV mapping releases are dated folders; use the newest dated on or before T0 (none: empty mapping).</summary>
    async Task<(string? Release, Dictionary<string, HashSet<string>> Map)> CtidAt(DateOnly t0)
    {
        const string api = "https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev";
        async Task<JsonElement> Ls(string url, string name) { using var d = JsonDocument.Parse(await Fetch(url, name)); return d.RootElement.Clone(); }
        var releases = new List<(DateOnly Date, string Attack, string Kev)>();
        foreach (var a in (await Ls(api, "ctid-root.json")).EnumerateArray().Where(x => S(x, "type") == "dir"))
            foreach (var k in (await Ls($"{api}/{S(a, "name")}", $"ctid-{S(a, "name")}.json")).EnumerateArray())
                if (DateOnly.TryParseExact(S(k, "name")[4..], "MM.dd.yyyy", out var d)) releases.Add((d, S(a, "name"), S(k, "name")));
        var pick = releases.Where(r => r.Date <= t0).OrderByDescending(r => r.Date).Cast<(DateOnly, string, string)?>().FirstOrDefault();
        var map = new Dictionary<string, HashSet<string>>();
        if (pick is null) return (null, map);
        var (_, attack, kev) = pick.Value;
        var files = await Ls($"{api}/{attack}/{kev}/enterprise", $"ctid-{attack}-{kev}.json");
        var url = files.EnumerateArray().First(f => S(f, "name").EndsWith(".json")).GetProperty("download_url").GetString()!;
        using var doc = JsonDocument.Parse(await Fetch(url, $"ctid-{attack}-{kev}-map.json"));
        foreach (var m in doc.RootElement.GetProperty("mapping_objects").EnumerateArray().Where(m => S(m, "attack_object_id") != ""))
        {
            if (!map.TryGetValue(S(m, "capability_id"), out var s)) map[S(m, "capability_id")] = s = new();
            s.Add(S(m, "attack_object_id"));
        }
        return ($"{attack}/{kev}", map);
    }

    public async Task<Result> Run(string dbPath, Profile profile, bool allGroups = false, int windowDays = 180, int[]? topN = null)
    {
        topN ??= new[] { 100, 500, 1000 };
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture; // reports must read the same on every machine
        using var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly"); db.Open();
        string Scalar(string sql) { using var c = db.CreateCommand(); c.CommandText = sql; return Convert.ToString(c.ExecuteScalar(), CultureInfo.InvariantCulture)!; }
        var tEnd = DateOnly.ParseExact(Scalar("SELECT MAX(date_added) FROM kev"), "yyyy-MM-dd");
        var t0 = tEnd.AddDays(-windowDays);
        var d0 = t0.ToString("yyyy-MM-dd");
        log($"T0 = {d0}, outcome window to {tEnd:yyyy-MM-dd}");

        var kevDate = new Dictionary<string, string>();
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT id, date_added FROM kev"; using var r = c.ExecuteReader(); while (r.Read()) kevDate[r.GetString(0)] = r.GetString(1); }
        var cands = new List<(string Id, double Cvss, bool Pos)>();
        using (var c = db.CreateCommand())
        {
            c.CommandText = "SELECT id, cvss FROM cve WHERE substr(published,1,10) <= @d";
            c.Parameters.AddWithValue("@d", d0);
            using var r = c.ExecuteReader();
            while (r.Read())
            {
                var id = r.GetString(0);
                if (kevDate.TryGetValue(id, out var added) && string.CompareOrdinal(added, d0) <= 0) continue; // already known exploited at T0
                cands.Add((id, r.IsDBNull(1) ? 0 : r.GetDouble(1), kevDate.ContainsKey(id)));
            }
        }
        int pos = cands.Count(c => c.Pos);
        log($"{cands.Count} candidates, {pos} later entered KEV");
        if (pos < 20) return new Result("Not applicable", $"only {pos} positives in the window; the database does not cover enough of it (check the NVD sync date)", "", new());

        var (epss, epssFile) = await EpssAt(t0);
        var (version, modified, objects) = await AttackAt(t0);
        var (techniques, actors, aTech, aCve) = Collect.ParseAttack(objects);
        var (ctidRelease, ctid) = await CtidAt(t0);

        var groups = allGroups ? actors.Select(a => a.Item1).ToHashSet() : profile.ThreatGroups.Keys.ToHashSet();
        var cited = aCve.Where(x => groups.Contains(x.Item1)).Select(x => x.Item2).ToHashSet();
        var used = aTech.Where(x => groups.Contains(x.Item1)).Select(x => x.Item2).ToHashSet();
        double Overlap(string id) => cited.Contains(id) ? 1.0 : ctid.TryGetValue(id, out var t) && t.Any(used.Contains) ? 0.5 : 0.0;

        var n = cands.Count;
        var y = cands.Select(c => c.Pos).ToArray();
        var cvss = cands.Select(c => c.Cvss).ToArray();
        var e = cands.Select(c => epss.GetValueOrDefault(c.Id)).ToArray();
        var ov = cands.Select(c => Overlap(c.Id)).ToArray();
        var w = profile.Weights;
        var combined = Enumerable.Range(0, n).Select(i => w.Epss * e[i] + w.ThreatProfile * ov[i]).ToArray();
        int ovAll = ov.Count(x => x > 0), ovPos = Enumerable.Range(0, n).Count(i => y[i] && ov[i] > 0);
        int ctidMapped = cands.Count(c => ctid.ContainsKey(c.Id)), ctidMappedPos = cands.Count(c => c.Pos && ctid.ContainsKey(c.Id));
        int citedAll = cands.Count(c => cited.Contains(c.Id)), citedPos = cands.Count(c => c.Pos && cited.Contains(c.Id));

        var rows = new[] { ("a  CVSS only", cvss), ("b  EPSS(T0) only", e), ("c  EPSS + ATT&CK overlap", combined) };
        var md = new StringBuilder();
        md.AppendLine($"# Test 1: does ATT&CK overlap improve prioritisation? ({(allGroups ? "all ATT&CK groups" : "bundled threat profile")})");
        md.AppendLine();
        md.AppendLine($"Prediction date T0 = {d0}; outcome = added to CISA KEV between T0 and {tEnd:yyyy-MM-dd} ({windowDays} days). Candidates: {n} CVEs published by T0 and not in KEV at T0; {pos} positives ({100.0 * pos / n:0.000}%).");
        md.AppendLine();
        md.AppendLine("## Inputs (all dated on or before T0)");
        md.AppendLine();
        md.AppendLine($"* EPSS: `{epssFile}` ({epss.Count} scores)");
        md.AppendLine($"* ATT&CK Enterprise v{version} (published {modified[..10]}): {actors.Count} groups, {aCve.Count} group-to-CVE links in description text");
        md.AppendLine($"* CTID KEV mapping release: {ctidRelease ?? "none on or before T0"} ({ctid.Count} CVEs mapped)");
        md.AppendLine($"* Groups used: {groups.Count} ({(allGroups ? "all" : "bundled profile")}); CVSS from the database");
        md.AppendLine();
        md.AppendLine("## Coverage of the ATT&CK-derived feature among candidates");
        md.AppendLine();
        md.AppendLine("| Feature | Candidates | Positives |");
        md.AppendLine("|---|---|---|");
        md.AppendLine($"| Any overlap (>0) | {ovAll} ({100.0 * ovAll / n:0.000}%) | {ovPos} of {pos} ({100.0 * ovPos / pos:0.0}%) |");
        md.AppendLine($"| CVE named in a profiled group's ATT&CK text | {citedAll} | {citedPos} |");
        md.AppendLine($"| CVE has a CTID technique mapping | {ctidMapped} | {ctidMappedPos} |");
        md.AppendLine();
        md.AppendLine("## Ranking quality");
        md.AppendLine();
        md.AppendLine("| Ranking | Average precision | " + string.Join(" | ", topN.Select(t => $"Top {t}: found / efficiency")) + " |");
        md.AppendLine("|---|---|" + string.Join("|", topN.Select(_ => "---")) + "|");
        foreach (var (name, s) in rows)
            md.AppendLine($"| {name} | {Metrics.AveragePrecision(y, s):0.0000} | " + string.Join(" | ", topN.Select(t => { var (cov, eff, _) = Metrics.AtTop(y, s, t); return $"{cov * pos:0.0} of {pos} ({cov:P1}) / {eff:P1}"; })) + " |");
        var (delta, lo, hi, pNot) = Metrics.PairedBootstrap(y, combined, e);
        var (d2, lo2, hi2, pNot2) = Metrics.PairedBootstrap(y, e, cvss);
        md.AppendLine();
        md.AppendLine($"Primary: lift of c over b (average precision) **{delta:+0.0000;-0.0000;0.0000}**, 95% interval [{lo:+0.0000;-0.0000;0.0000}, {hi:+0.0000;-0.0000;0.0000}]; share of 1000 resamples where c did not beat b: {pNot:P1}.");
        md.AppendLine();
        md.AppendLine($"Secondary (pillar 2): lift of EPSS over CVSS alone **{d2:+0.0000;-0.0000;0.0000}**, 95% interval [{lo2:+0.0000;-0.0000;0.0000}, {hi2:+0.0000;-0.0000;0.0000}]; share of resamples where EPSS did not beat CVSS: {pNot2:P1}. With {pos} positives the interval is wide; treat it as supporting evidence, not a precise estimate.");

        string label, reason;
        if (ovAll < 0.01 * n || ovPos == 0) (label, reason) = ("Not applicable", $"the overlap feature exists for {ovAll} of {n} candidates and {ovPos} of {pos} positives, so this data cannot show an effect either way. This is expected: CTID maps techniques only for CVEs already in KEV, and a group's ATT&CK text names a CVE after it was exploited");
        else if (lo > 0 && ovPos >= 0.05 * pos) (label, reason) = ("Validated", "the interval for the lift is above zero and the feature covers at least 5% of the positives");
        else if (hi < 0) (label, reason) = ("Harmful", "the interval for the lift is below zero");
        else (label, reason) = ("Not shown", "the interval for the lift includes zero, or the feature covers fewer than 5% of the positives");
        md.AppendLine();
        md.AppendLine($"## Result by the pre-registered rule: **{label}**");
        md.AppendLine();
        md.AppendLine(reason + ".");
        if (label is "Not shown" or "Harmful")
            md.AppendLine().AppendLine("Consequence (pre-registered): the `threat_profile` weight is set to 0 in the shipped profile and the overlap is shown as context, not a scoring input.");
        else if (label == "Not applicable")
            md.AppendLine().AppendLine("Consequence: the overlap is labelled **Not validated**. It stays visible as context. Whether it keeps a scoring weight is a decision for the profile owner; this test gives no evidence for or against it. (The pre-registration did not define this case.)");
        md.AppendLine();
        md.AppendLine("## Limitations");
        md.AppendLine();
        md.AppendLine("* CVSS comes from the current database, so a score revised after T0 leaks a small amount of future information into ranking a.");
        md.AppendLine("* Only one window and one outcome (KEV listing) are tested. KEV is not all exploitation; absence from it is not safety.");
        md.AppendLine("* Ties are broken pseudo-randomly (5 seeds for the point estimate, one fixed order inside the bootstrap).");

        var inputs = new Dictionary<string, object> { ["t0"] = d0, ["t_end"] = tEnd.ToString("yyyy-MM-dd"), ["epss_file"] = epssFile, ["attack_version"] = version,
            ["attack_modified"] = modified, ["ctid_release"] = ctidRelease ?? "", ["candidates"] = n, ["positives"] = pos, ["overlap_candidates"] = ovAll, ["overlap_positives"] = ovPos, ["label"] = label };
        return new Result(label, reason, md.ToString(), inputs);
    }
}
