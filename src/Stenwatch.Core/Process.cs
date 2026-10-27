using System.Numerics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>CTI stage 3 - Processing: match every CVE to the assets we own and the suppliers we use.</summary>
public static class Process
{
    static readonly string[] Yes = { "y", "yes", "true", "1" };
    static bool IsYes(string s) => Yes.Contains(s.Trim().ToLowerInvariant());

    public static List<Asset> LoadAssets(string path, bool thirdParty = false)
    {
        var assets = new List<Asset>();
        var rows = Csv.ReadDict(path);
        var need = thirdParty ? new[] { "name", "cpe", "version", "type", "data_access", "privileged", "internet_facing" } : new[] { "name", "cpe", "version", "criticality", "internet_facing" };
        if (rows.Count > 0 && need.Where(n => !rows[0].ContainsKey(n)).ToList() is { Count: > 0 } missing)
            throw new InvalidDataException($"{Path.GetFileName(path)} is missing the column(s) {string.Join(", ", missing)}. Found: {string.Join(", ", rows[0].Keys)}."
                + (thirdParty ? "" : " An inventory export (hostname, vendor, product, os ...) can be converted on 1 Direction: Convert inventory."));
        foreach (var r in rows)
        {
            var cpe = r["cpe"].Trim().TrimEnd(':');
            if (cpe.Count(c => c == ':') != 4)
                throw new InvalidDataException($"{r["name"]}: cpe must look like cpe:2.3:a:vendor:product, got '{cpe}'");
            assets.Add(thirdParty
                ? new Asset(r["name"], cpe, r["version"].Trim(), 0, IsYes(r["internet_facing"]), true,
                    r["type"], r["data_access"].Trim().ToLowerInvariant(), IsYes(r["privileged"]))
                : new Asset(r["name"], cpe, r["version"].Trim(), int.Parse(r["criticality"]), IsYes(r["internet_facing"]), false));
        }
        return assets;
    }

    public static readonly string[] DecisionStatus = { "patched", "mitigated", "accepted", "false_positive", "not_affected" };

    public static List<Decision> LoadDecisions(string path)
    {
        if (!File.Exists(path)) return new();
        return Csv.ReadDict(path).Select(r =>
        {
            var status = r["status"].Trim().ToLowerInvariant();
            if (!DecisionStatus.Contains(status))
                throw new InvalidDataException($"exceptions.csv: {r["cve"]}: status must be one of {string.Join(", ", DecisionStatus)}");
            var asset = r["asset"].Trim();
            return new Decision(r["cve"], asset == "" ? "*" : asset, status, r.GetValueOrDefault("until", "").Trim(), r.GetValueOrDefault("note", ""));
        }).ToList();
    }

    static void WriteDecisions(string path, IEnumerable<Decision> rows) =>
        Csv.Write(path, new[] { new[] { "cve", "asset", "status", "until", "note" } }.Concat(rows.Select(r => new[] { r.Cve, r.Asset, r.Status, r.Until, r.Note })));

    /// <summary>Console form -> exceptions.csv. One decision per CVE + asset: recording again replaces it.</summary>
    public static Decision RecordDecision(string path, string cve, string asset, string status, string until = "", string note = "")
    {
        if (!Regex.IsMatch(cve, @"^CVE-\d{4}-\d{4,}$")) throw new ArgumentException("CVE ids look like CVE-2024-12345");
        if (!DecisionStatus.Contains(status)) throw new ArgumentException($"status must be one of {string.Join(", ", DecisionStatus)}");
        if (until != "" && !DateOnly.TryParseExact(until, "yyyy-MM-dd", out _)) throw new ArgumentException("until must be YYYY-MM-DD");
        var row = new Decision(cve, asset.Trim() == "" ? "*" : asset.Trim(), status, until, string.Join(" ", note.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) is { Length: > 300 } n ? n[..300] : string.Join(" ", note.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)));
        WriteDecisions(path, LoadDecisions(path).Where(e => (e.Cve, e.Asset) != (row.Cve, row.Asset)).Append(row));
        return row;
    }

    public static void RemoveDecision(string path, string cve, string asset) =>
        WriteDecisions(path, LoadDecisions(path).Where(e => (e.Cve, e.Asset) != (cve, asset)));

    /// <summary>-> (kept, suppressed). A decision past its `until` date stops applying: risk comes back for review.</summary>
    public static (List<Ranked> Kept, List<Ranked> Suppressed) ApplyDecisions(IEnumerable<Ranked> ranked, List<Decision> decisions, DateOnly? today = null)
    {
        var d = (today ?? DateOnly.FromDateTime(DateTime.Today)).ToString("yyyy-MM-dd");
        var live = decisions.Where(e => e.Until == "" || string.CompareOrdinal(e.Until, d) >= 0).ToList();
        List<Ranked> kept = new(), suppressed = new();
        foreach (var r in ranked)
        {
            var hit = live.FirstOrDefault(e => e.Cve == r.Cve && (e.Asset == "*" || e.Asset == r.Asset.Name));
            if (hit is null) kept.Add(r); else suppressed.Add(r with { Decision = hit });
        }
        return (kept, suppressed);
    }

    /// <summary>'10.0.17763.5000' -> comparable parts. Numbers compare as numbers, text as text.</summary>
    // ponytail: generic version compare, vendor-specific schemes (e.g. '2.8_mr10') compare as text
    public static List<(int Kind, BigInteger Num, string Text)> VKey(string v) =>
        Regex.Split(v.ToLowerInvariant(), @"[.\-_]").Where(p => p != "")
            .Select(p => p.All(char.IsAsciiDigit) ? (0, BigInteger.Parse(p), "") : (1, BigInteger.Zero, p)).ToList();

    public static int Cmp(string a, string b)
    {
        List<(int Kind, BigInteger Num, string Text)> x = VKey(a), y = VKey(b);
        for (int i = 0; i < Math.Min(x.Count, y.Count); i++)
        {
            int c = x[i].Kind != y[i].Kind ? x[i].Kind.CompareTo(y[i].Kind)
                  : x[i].Kind == 0 ? x[i].Num.CompareTo(y[i].Num) : string.CompareOrdinal(x[i].Text, y[i].Text);
            if (c != 0) return c;
        }
        return x.Count.CompareTo(y.Count);
    }

    /// <summary>Does one NVD cpeMatch entry cover this asset version?</summary>
    public static bool Affects(JsonElement m, string version)
    {
        if (version == "") return true; // unknown version: assume affected, report says so
        var v = m.GetProperty("criteria").GetString()!.Split(':')[5];
        // ponytail: CPE 'update' field (e.g. Exchange cumulative_update_14) ignored -> may over-match within a release
        if (v != "*" && v != "-") return Cmp(v, version) == 0;
        bool Has(string k, out string s) { s = m.TryGetProperty(k, out var p) ? p.GetString()! : ""; return s != ""; }
        return !((Has("versionStartIncluding", out var si) && Cmp(version, si) < 0)
              || (Has("versionStartExcluding", out var se) && Cmp(version, se) <= 0)
              || (Has("versionEndIncluding", out var ei) && Cmp(version, ei) > 0)
              || (Has("versionEndExcluding", out var ee) && Cmp(version, ee) >= 0));
    }

    /// <summary>-> one finding per (asset, CVE), joined with KEV and EPSS.
    /// Third party with unknown version: only CVEs published or KEV-added in the last `recentDays` count.
    /// Owned asset with unknown version and a patchBaseline (YYYY-MM-DD): CVEs published before it are assumed patched.</summary>
    // ponytail: one LIKE full-scan per asset (~0.5 s each); add a cpe index table past ~100 assets
    // ponytail: publication date stands in for patch date (true for monthly vendors like Microsoft, Apple); an OS build is exact, use it when you have it
    public static List<Finding> Match(SqliteConnection db, IEnumerable<Asset> assets, int recentDays = 90, DateOnly? today = null, string patchBaseline = "")
    {
        var cutoff = (today ?? DateOnly.FromDateTime(DateTime.Today)).AddDays(-recentDays).ToString("yyyy-MM-dd");
        var findings = new List<Finding>();
        bool hasVector;
        using (var pc = db.CreateCommand()) { pc.CommandText = "SELECT COUNT(*) FROM pragma_table_info('cve') WHERE name='vector'"; hasVector = (long)pc.ExecuteScalar()! > 0; }
        foreach (var a in assets)
        {
            var sql = @"SELECT c.id, c.cvss, c.cwe, c.cpes, c.description, e.epss, k.id IS NOT NULL, k.ransomware, c.published, e.percentile, k.date_added, " + (hasVector ? "c.vector" : "''") + @"
                        FROM cve c LEFT JOIN epss e USING(id) LEFT JOIN kev k USING(id) WHERE ";
            using var cmd = db.CreateCommand();
            if (a.OnlyCves is { } only) // Defender already decided which CVEs apply at this patch level
            {
                if (only.Count == 0) continue;
                var names = only.Order(StringComparer.Ordinal).Select((c, i) => { cmd.Parameters.AddWithValue("@d" + i, c); return "@d" + i; });
                sql += $"c.id IN ({string.Join(",", names)})";
            }
            else { sql += "c.cpes LIKE @cpe"; cmd.Parameters.AddWithValue("@cpe", $"%\"{a.Cpe}:%"); }
            if (a.ThirdParty && a.Version == "") { sql += " AND (c.published >= @cut OR k.date_added >= @cut)"; cmd.Parameters.AddWithValue("@cut", cutoff); }
            else if (!a.ThirdParty && a.Version == "" && a.OnlyCves is null && patchBaseline != "") { sql += " AND c.published >= @base"; cmd.Parameters.AddWithValue("@base", patchBaseline); }
            cmd.CommandText = sql;
            using var rd = cmd.ExecuteReader();
            while (rd.Read())
            {
                var cpes = rd.GetString(3);
                if (a.OnlyCves is null)
                {
                    using var doc = JsonDocument.Parse(cpes);
                    if (!doc.RootElement.EnumerateArray().Any(m => m.GetProperty("criteria").GetString()!.StartsWith(a.Cpe + ":") && Affects(m, a.Version)))
                        continue;
                }
                findings.Add(new Finding(a, rd.GetString(0), rd.IsDBNull(1) ? null : rd.GetDouble(1), Str(rd, 2), Str(rd, 4),
                    rd.IsDBNull(5) ? 0.0 : rd.GetDouble(5), rd.GetInt64(6) != 0, !rd.IsDBNull(7) && rd.GetInt64(7) != 0,
                    Str(rd, 8), rd.IsDBNull(9) ? null : rd.GetDouble(9), Str(rd, 10), Str(rd, 11)));
            }
        }
        return findings;
    }

    static string Str(SqliteDataReader r, int i) => r.IsDBNull(i) ? "" : r.GetString(i);
}
