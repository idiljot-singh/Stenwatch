using System.Globalization;
using System.IO.Compression;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>CTI stage 2 - Collection: pull global CVE, KEV, EPSS and ATT&amp;CK feeds into the database.
/// Same schema as the Python version, so an existing cve.db keeps working.</summary>
public class Collect
{
    const string NvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const string KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const string EpssUrl = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    const string AttackUrl = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
    const string CtidApi = "https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev";
    const string D3fendUrl = "https://d3fend.mitre.org/api/offensive-technique/attack/{0}.json";
    public const int MinKev = 1000, MinEpss = 100_000, MinTechniques = 500, MinMappings = 500, MinMitigations = 500, MinDefend = 100;
    static readonly Regex CveRe = new(@"CVE-\d{4}-\d{4,}");

    const string Schema = @"
CREATE TABLE IF NOT EXISTS cve  (id TEXT PRIMARY KEY, published TEXT, modified TEXT, cvss REAL, cwe TEXT, cpes TEXT, description TEXT, vector TEXT);
CREATE TABLE IF NOT EXISTS kev  (id TEXT PRIMARY KEY, date_added TEXT, ransomware INTEGER, vendor TEXT, product TEXT);
CREATE TABLE IF NOT EXISTS epss (id TEXT PRIMARY KEY, epss REAL, percentile REAL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS technique       (id TEXT PRIMARY KEY, name TEXT, tactics TEXT);
CREATE TABLE IF NOT EXISTS actor           (id TEXT PRIMARY KEY, name TEXT, aliases TEXT);
CREATE TABLE IF NOT EXISTS actor_technique (actor TEXT, technique TEXT, PRIMARY KEY (actor, technique));
CREATE TABLE IF NOT EXISTS actor_cve       (actor TEXT, cve TEXT, PRIMARY KEY (actor, cve));
CREATE TABLE IF NOT EXISTS actor_profile   (id TEXT PRIMARY KEY, description TEXT, modified TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS profile_group   (id TEXT PRIMARY KEY, name TEXT, score REAL, reasons TEXT, computed_at TEXT);
CREATE TABLE IF NOT EXISTS cve_technique   (cve TEXT, technique TEXT, mapping_type TEXT, PRIMARY KEY (cve, technique, mapping_type));
CREATE TABLE IF NOT EXISTS mitigation      (technique TEXT, id TEXT, name TEXT, PRIMARY KEY (technique, id));
CREATE TABLE IF NOT EXISTS defend          (technique TEXT, id TEXT, name TEXT, tactic TEXT, PRIMARY KEY (technique, id));";

    readonly HttpClient http;
    readonly Action<string> log;
    readonly CancellationToken ct; // checked between feeds and between NVD pages: every committed page stays, nothing half-written

    public Collect(HttpClient? http = null, Action<string>? log = null, CancellationToken ct = default)
    {
        this.ct = ct;
        this.http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        if (this.http.DefaultRequestHeaders.UserAgent.Count == 0) this.http.DefaultRequestHeaders.UserAgent.ParseAdd("Stenwatch");
        this.log = log ?? (_ => { });
    }

    public static SqliteConnection Connect(string path)
    {
        var db = new SqliteConnection($"Data Source={path}");
        db.Open();
        Exec(db, Schema);
        using (var c = db.CreateCommand()) // databases from before the vector column: add it (filled as CVEs are re-synced)
        {
            c.CommandText = "SELECT COUNT(*) FROM pragma_table_info('cve') WHERE name='vector'";
            if ((long)c.ExecuteScalar()! == 0) Exec(db, "ALTER TABLE cve ADD COLUMN vector TEXT");
        }
        return db;
    }

    static void Exec(SqliteConnection db, string sql, params (string, object?)[] ps)
    {
        using var c = db.CreateCommand(); c.CommandText = sql;
        foreach (var (k, v) in ps) c.Parameters.AddWithValue(k, v ?? DBNull.Value);
        c.ExecuteNonQuery();
    }

    static void Replace(SqliteConnection db, string[] tables, string insertSql, IEnumerable<object?[]>[] rowSets)
    {
        using var tx = db.BeginTransaction();
        foreach (var t in tables) Exec(db, $"DELETE FROM {t}");
        for (int i = 0; i < rowSets.Length; i++) Insert(db, insertSql.Split('|')[i], rowSets[i]);
        tx.Commit();
    }

    static void Insert(SqliteConnection db, string sql, IEnumerable<object?[]> rows)
    {
        using var c = db.CreateCommand(); c.CommandText = sql;
        var n = sql.Count(ch => ch == '@');
        for (int i = 0; i < n; i++) c.Parameters.Add(new SqliteParameter("@p" + i, null));
        foreach (var r in rows)
        {
            for (int i = 0; i < n; i++) c.Parameters[i].Value = r[i] ?? DBNull.Value;
            c.ExecuteNonQuery();
        }
    }

    /// <summary>Record when a feed was last pulled (provenance, freshness: pillars 5 and 12).</summary>
    public static void SetMeta(SqliteConnection db, string key, string value) =>
        Exec(db, "INSERT OR REPLACE INTO meta VALUES (@k, @v)", ("@k", key), ("@v", value));

    static string Stamp() => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static void CheckSize(string name, int rows, int minimum)
    {
        if (rows < minimum) throw new InvalidDataException($"{name} feed has {rows} rows, expected >= {minimum}; keeping old data");
    }

    // ---------- NVD ----------

    static string S(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
    static IEnumerable<JsonElement> A(JsonElement e, string k) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray() : Enumerable.Empty<JsonElement>();

    /// <summary>One NVD 'vulnerabilities[]' item -> cve row (id, published, modified, cvss, cwe, cpes json, description). Missing fields are left empty: NVD records vary.</summary>
    public static object?[] ParseNvd(JsonElement item)
    {
        var c = item.TryGetProperty("cve", out var cv) ? cv : item;
        double? cvss = null; string vector = "";
        foreach (var key in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
            if (c.TryGetProperty("metrics", out var m) && A(m, key).FirstOrDefault() is { ValueKind: JsonValueKind.Object } first && first.TryGetProperty("cvssData", out var data)
                && data.TryGetProperty("baseScore", out var bs) && bs.TryGetDouble(out var score))
            {
                cvss = score; vector = S(data, "vectorString");
                break;
            }
        var cwe = A(c, "weaknesses").SelectMany(w => A(w, "description").Select(d => S(d, "value"))).Distinct().Order(StringComparer.Ordinal);
        var cpes = new List<Dictionary<string, JsonElement>>();
        foreach (var conf in A(c, "configurations"))
            foreach (var node in A(conf, "nodes"))
                foreach (var match in A(node, "cpeMatch"))
                    if (match.TryGetProperty("vulnerable", out var vu) && vu.ValueKind == JsonValueKind.True)
                        cpes.Add(match.EnumerateObject().Where(p => p.Name != "matchCriteriaId").ToDictionary(p => p.Name, p => p.Value));
        var desc = A(c, "descriptions").Where(d => S(d, "lang") == "en").Select(d => S(d, "value")).FirstOrDefault() ?? "";
        return new object?[] { S(c, "id"), S(c, "published"), S(c, "lastModified"), cvss, string.Join(",", cwe), JsonSerializer.Serialize(cpes), desc, vector };
    }

    /// <summary>Full load on first run, then incremental by lastModified. `since` overrides.</summary>
    public async Task SyncNvd(SqliteConnection db, string? apiKey = null, DateTimeOffset? since = null)
    {
        var delay = TimeSpan.FromSeconds(apiKey != null ? 0.7 : 6.5); // NVD: 50 req/30s with key, 5 req/30s without
        string? last;
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT value FROM meta WHERE key='nvd_sync'"; last = c.ExecuteScalar() as string; }
        var start = since ?? (last != null ? DateTimeOffset.Parse(last, CultureInfo.InvariantCulture) : (DateTimeOffset?)null);
        var now = DateTimeOffset.UtcNow;

        // NVD allows max 120 days per lastMod window; no window at all = full dump
        var windows = new List<(DateTimeOffset, DateTimeOffset)?>();
        if (start is null) windows.Add(null);
        for (var s = start; s is not null && s < now;) { var e = s.Value.AddDays(120) < now ? s.Value.AddDays(120) : now; windows.Add((s.Value, e)); s = e; }

        foreach (var win in windows)
        {
            // the full dump resumes where a failed or cancelled run stopped (nvd_index), instead of starting 15 minutes over
            int index = 0, bad = 0;
            if (win is null) using (var c = db.CreateCommand()) { c.CommandText = "SELECT value FROM meta WHERE key='nvd_index'"; index = int.TryParse(c.ExecuteScalar() as string, out var i) ? i : 0; }
            if (index > 0) log($"  NVD: resuming the full download at {index}");
            while (true)
            {
                var url = $"{NvdUrl}?resultsPerPage=2000&startIndex={index}";
                if (win is { } w) url += $"&lastModStartDate={Uri.EscapeDataString(Iso(w.Item1))}&lastModEndDate={Uri.EscapeDataString(Iso(w.Item2))}";
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                if (apiKey != null) req.Headers.Add("apiKey", apiKey);
                using var resp = await http.SendAsync(req, ct);
                if ((int)resp.StatusCode is 403 or 429 or 503) { await Task.Delay(TimeSpan.FromSeconds(30), ct); continue; } // rate limited: back off, retry
                resp.EnsureSuccessStatusCode();
                var body = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                // NVD sometimes answers 200 with no CVE list (busy, maintenance): treat it like a rate limit, three tries
                if (!root.TryGetProperty("vulnerabilities", out var vulns) || !root.TryGetProperty("totalResults", out var tot) || !root.TryGetProperty("resultsPerPage", out var per))
                {
                    if (++bad > 3) throw new InvalidDataException($"NVD page {index}: reply has no CVE list: {body[..Math.Min(200, body.Length)]}");
                    log($"  NVD page {index}: reply has no CVE list, retrying in 30 s"); await Task.Delay(TimeSpan.FromSeconds(30), ct); continue;
                }
                bad = 0;
                var rows = new List<object?[]>();
                foreach (var item in A(root, "vulnerabilities"))
                    try { if (ParseNvd(item) is var r && (string)r[0]! != "") rows.Add(r); }
                    catch (Exception e) when (e is InvalidOperationException or FormatException or KeyNotFoundException) { log($"  NVD: skipped one record ({e.Message})"); }
                index += per.GetInt32();
                using (var tx = db.BeginTransaction())
                {
                    Insert(db, "INSERT OR REPLACE INTO cve VALUES (@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7)", rows);
                    if (win is null) Exec(db, "INSERT OR REPLACE INTO meta VALUES ('nvd_index', @v)", ("@v", index.ToString()));
                    tx.Commit();
                }
                var total = tot.GetInt32();
                log($"  NVD {index}/{total}");
                if (index >= total) break;
                await Task.Delay(delay, ct);
            }
        }
        if (since is null) // a --since test run must not mark the full backfill as done
        {
            Exec(db, "INSERT OR REPLACE INTO meta VALUES ('nvd_sync', @v)", ("@v", Iso(now)));
            Exec(db, "DELETE FROM meta WHERE key='nvd_index'");
        }
    }

    static string Iso(DateTimeOffset d) => d.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz", CultureInfo.InvariantCulture);

    // ---------- KEV, EPSS ----------

    public async Task<int> SyncKev(SqliteConnection db)
    {
        using var doc = JsonDocument.Parse(await http.GetStringAsync(KevUrl));
        var v = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().ToList();
        CheckSize("KEV", v.Count, MinKev);
        var rows = v.Select(x => new object?[] { S(x, "cveID"), S(x, "dateAdded"), S(x, "knownRansomwareCampaignUse") == "Known" ? 1 : 0, S(x, "vendorProject"), S(x, "product") }).ToList();
        Replace(db, new[] { "kev" }, "INSERT INTO kev VALUES (@p0,@p1,@p2,@p3,@p4)", new IEnumerable<object?[]>[] { rows });
        SetMeta(db, "kev_sync", Stamp());
        return rows.Count;
    }

    public async Task<int> SyncEpss(SqliteConnection db)
    {
        var gz = await http.GetByteArrayAsync(EpssUrl);
        using var sr = new StreamReader(new GZipStream(new MemoryStream(gz), CompressionMode.Decompress));
        var rows = new List<object?[]>();
        var all = (await sr.ReadToEndAsync()).Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l != "").ToList();
        var model = all.FirstOrDefault(l => l.StartsWith('#')) ?? ""; // "#model_version:v2025.03.14,score_date:2026-10-26T00:00:00Z"
        var lines = all.Where(l => !l.StartsWith('#')).Skip(1); // then the header
        foreach (var l in lines) { var p = l.Split(','); rows.Add(new object?[] { p[0], double.Parse(p[1], CultureInfo.InvariantCulture), double.Parse(p[2], CultureInfo.InvariantCulture) }); }
        CheckSize("EPSS", rows.Count, MinEpss);
        Replace(db, new[] { "epss" }, "INSERT INTO epss VALUES (@p0,@p1,@p2)", new IEnumerable<object?[]>[] { rows });
        SetMeta(db, "epss_sync", Stamp()); SetMeta(db, "epss_model", model.TrimStart('#'));
        return rows.Count;
    }

    // ---------- ATT&CK ----------

    static string? Ext(JsonElement o) => o.TryGetProperty("external_references", out var refs)
        ? refs.EnumerateArray().Where(r => S(r, "source_name") == "mitre-attack").Select(r => S(r, "external_id")).FirstOrDefault() : null;

    static Dictionary<string, JsonElement> Live(IEnumerable<JsonElement> objects)
    {
        var d = new Dictionary<string, JsonElement>();
        foreach (var o in objects)
        {
            if (o.TryGetProperty("revoked", out var r) && r.ValueKind == JsonValueKind.True) continue;
            if (o.TryGetProperty("x_mitre_deprecated", out var x) && x.ValueKind == JsonValueKind.True) continue;
            d[S(o, "id")] = o;
        }
        return d;
    }

    /// <summary>ATT&amp;CK STIX objects -> (techniques, actors, actor_technique, actor_cve) rows.</summary>
    public static (List<(string, string, string)> Techniques, List<(string, string, string)> Actors,
                   List<(string, string)> ActorTechnique, List<(string, string)> ActorCve) ParseAttack(IEnumerable<JsonElement> objects)
    {
        var live = Live(objects);
        var techniques = live.Values.Where(o => S(o, "type") == "attack-pattern").Select(o => (Ext(o)!, S(o, "name"),
            o.TryGetProperty("kill_chain_phases", out var k) ? string.Join(",", k.EnumerateArray().Select(p => S(p, "phase_name"))) : "")).ToList();
        var actors = live.Where(kv => S(kv.Value, "type") == "intrusion-set").ToDictionary(kv => kv.Key, kv => kv.Value);

        // campaign -> groups it is attributed to, so campaign activity counts for the group
        var attributed = new Dictionary<string, HashSet<string>>();
        foreach (var o in live.Values)
            if (S(o, "type") == "relationship" && S(o, "relationship_type") == "attributed-to" && actors.ContainsKey(S(o, "target_ref")))
            {
                if (!attributed.TryGetValue(S(o, "source_ref"), out var set)) attributed[S(o, "source_ref")] = set = new();
                set.Add(S(o, "target_ref"));
            }
        IEnumerable<string> Who(string r) => actors.ContainsKey(r) ? new[] { r } : attributed.GetValueOrDefault(r) ?? new HashSet<string>();

        var aTech = new SortedSet<(string, string)>(); var aCve = new SortedSet<(string, string)>();
        foreach (var o in live.Values)
        {
            var type = S(o, "type");
            if (type == "relationship" && S(o, "relationship_type") == "uses")
                foreach (var actor in Who(S(o, "source_ref")))
                {
                    if (live.TryGetValue(S(o, "target_ref"), out var target) && S(target, "type") == "attack-pattern") aTech.Add((Ext(actors[actor])!, Ext(target)!));
                    foreach (Match m in CveRe.Matches(S(o, "description"))) aCve.Add((Ext(actors[actor])!, m.Value)); // "APT28 exploited CVE-2023-23397 ..."
                }
            else if (type is "intrusion-set" or "campaign")
                foreach (var actor in Who(S(o, "id")))
                    foreach (Match m in CveRe.Matches(S(o, "description"))) aCve.Add((Ext(actors[actor])!, m.Value));
        }
        var actorRows = actors.Values.Select(o => (Ext(o)!, S(o, "name"),
            o.TryGetProperty("aliases", out var al) ? string.Join(",", al.EnumerateArray().Select(a => a.GetString())) : "")).ToList();
        return (techniques, actorRows, aTech.ToList(), aCve.ToList());
    }

    /// <summary>For automatic threat-group selection: each group's description (links stripped), when MITRE last edited it, and the latest
    /// campaign end date attributed to it. -> (id, description, modified, last_seen).</summary>
    public static List<(string, string, string, string)> ParseActorProfiles(IEnumerable<JsonElement> objects)
    {
        var live = Live(objects);
        var actors = live.Where(kv => S(kv.Value, "type") == "intrusion-set").ToDictionary(kv => kv.Key, kv => kv.Value);
        var lastSeen = new Dictionary<string, string>();
        foreach (var o in live.Values.Where(o => S(o, "type") == "relationship" && S(o, "relationship_type") == "attributed-to" && actors.ContainsKey(S(o, "target_ref"))))
            if (live.TryGetValue(S(o, "source_ref"), out var camp) && S(camp, "type") == "campaign" && S(camp, "last_seen") is { Length: > 0 } seen
                && string.CompareOrdinal(seen, lastSeen.GetValueOrDefault(S(o, "target_ref"), "")) > 0)
                lastSeen[S(o, "target_ref")] = seen;
        return actors.Select(kv => (Ext(kv.Value)!, Regex.Replace(S(kv.Value, "description"), @"\[([^\]]+)\]\([^)]*\)", "$1"), S(kv.Value, "modified"),
            lastSeen.GetValueOrDefault(kv.Key, ""))).ToList();
    }

    /// <summary>ATT&amp;CK "course-of-action mitigates technique" -> (technique, M-id, name) rows.</summary>
    public static List<(string, string, string)> ParseMitigations(IEnumerable<JsonElement> objects)
    {
        var live = Live(objects);
        var rows = new SortedSet<(string, string, string)>();
        foreach (var o in live.Values)
            if (S(o, "type") == "relationship" && S(o, "relationship_type") == "mitigates"
                && live.TryGetValue(S(o, "source_ref"), out var src) && live.TryGetValue(S(o, "target_ref"), out var dst)
                && S(src, "type") == "course-of-action" && (Ext(src) ?? "").StartsWith('M'))
                rows.Add((Ext(dst)!, Ext(src)!, S(src, "name")));
        return rows.ToList();
    }

    public async Task<(int, int, int)> SyncAttack(SqliteConnection db)
    {
        using var doc = JsonDocument.Parse(await http.GetStringAsync(AttackUrl));
        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();
        var (techniques, actors, aTech, aCve) = ParseAttack(objects);
        var mitigations = ParseMitigations(objects);
        var profiles = ParseActorProfiles(objects);
        CheckSize("ATT&CK techniques", techniques.Count, MinTechniques);
        CheckSize("ATT&CK mitigations", mitigations.Count, MinMitigations);
        object?[] R(params object?[] x) => x;
        Replace(db, new[] { "technique", "actor", "actor_technique", "actor_cve", "mitigation", "actor_profile" },
            "INSERT INTO mitigation VALUES (@p0,@p1,@p2)|INSERT INTO technique VALUES (@p0,@p1,@p2)|INSERT INTO actor VALUES (@p0,@p1,@p2)|INSERT INTO actor_technique VALUES (@p0,@p1)|INSERT INTO actor_cve VALUES (@p0,@p1)|INSERT INTO actor_profile VALUES (@p0,@p1,@p2,@p3)",
            new IEnumerable<object?[]>[] { mitigations.Select(m => R(m.Item1, m.Item2, m.Item3)), techniques.Select(t => R(t.Item1, t.Item2, t.Item3)),
                actors.Select(a => R(a.Item1, a.Item2, a.Item3)), aTech.Select(a => R(a.Item1, a.Item2)), aCve.Select(a => R(a.Item1, a.Item2)), profiles.Select(a => R(a.Item1, a.Item2, a.Item3, a.Item4)) });
        SetMeta(db, "attack_sync", Stamp());
        return (techniques.Count, actors.Count, aCve.Count);
    }

    // ---------- CTID, D3FEND ----------

    async Task<JsonElement> Ls(string url) { using var d = JsonDocument.Parse(await http.GetStringAsync(url)); return d.RootElement.Clone(); }

    /// <summary>CTID publishes KEV->ATT&amp;CK mappings in dated folders; pick the newest ATT&amp;CK and KEV release.</summary>
    async Task<string> LatestCtidUrl()
    {
        static int[] Nums(string s) => Regex.Matches(s, @"\d+").Select(m => int.Parse(m.Value)).ToArray();
        static int CmpNums(int[] a, int[] b) { for (int i = 0; i < Math.Min(a.Length, b.Length); i++) if (a[i] != b[i]) return a[i].CompareTo(b[i]); return a.Length.CompareTo(b.Length); }
        var attack = (await Ls(CtidApi)).EnumerateArray().Where(d => S(d, "type") == "dir").MaxBy(d => Nums(S(d, "name")), Comparer<int[]>.Create(CmpNums))!;
        var kev = (await Ls($"{CtidApi}/{S(attack, "name")}")).EnumerateArray()
            .MaxBy(d => DateTime.ParseExact(S(d, "name")[4..], "MM.dd.yyyy", CultureInfo.InvariantCulture));
        var files = await Ls($"{CtidApi}/{S(attack, "name")}/{S(kev, "name")}/enterprise");
        return files.EnumerateArray().First(f => S(f, "name").EndsWith(".json")).GetProperty("download_url").GetString()!;
    }

    public async Task<int> SyncCtid(SqliteConnection db)
    {
        using var doc = JsonDocument.Parse(await http.GetStringAsync(await LatestCtidUrl()));
        var rows = new SortedSet<(string, string, string)>();
        foreach (var m in doc.RootElement.GetProperty("mapping_objects").EnumerateArray())
            if (S(m, "attack_object_id") != "") rows.Add((S(m, "capability_id"), S(m, "attack_object_id"), S(m, "mapping_type")));
        CheckSize("CTID KEV mappings", rows.Count, MinMappings);
        Replace(db, new[] { "cve_technique" }, "INSERT INTO cve_technique VALUES (@p0,@p1,@p2)",
            new IEnumerable<object?[]>[] { rows.Select(r => new object?[] { r.Item1, r.Item2, r.Item3 }) });
        SetMeta(db, "ctid_sync", Stamp());
        return rows.Count;
    }

    /// <summary>D3FEND API answer for one ATT&amp;CK technique -> (technique, D3-id, name, defensive tactic) rows.</summary>
    public static HashSet<(string, string, string, string)> ParseD3fend(string technique, JsonElement data)
    {
        var rows = new HashSet<(string, string, string, string)>();
        if (data.TryGetProperty("off_to_def", out var o) && o.TryGetProperty("results", out var r) && r.TryGetProperty("bindings", out var b))
            foreach (var x in b.EnumerateArray())
                if (x.TryGetProperty("def_tech_id", out var id))
                    rows.Add((technique, id.GetProperty("value").GetString()!, x.GetProperty("def_tech_label").GetProperty("value").GetString()!, x.GetProperty("def_tactic_label").GetProperty("value").GetString()!));
        return rows;
    }

    /// <summary>D3FEND countermeasures for every technique a CVE maps to. There is no bulk file, so one request each.</summary>
    // ponytail: ~155 sequential requests (~1 min); cache by technique if D3FEND starts rate-limiting
    public async Task<int> SyncD3fend(SqliteConnection db)
    {
        var techs = new List<string>();
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT DISTINCT technique FROM cve_technique"; using var r = c.ExecuteReader(); while (r.Read()) techs.Add(r.GetString(0)); }
        var rows = new HashSet<(string, string, string, string)>();
        foreach (var t in techs)
        {
            ct.ThrowIfCancellationRequested();
            using var resp = await http.GetAsync(string.Format(D3fendUrl, t), ct);
            if (!resp.IsSuccessStatusCode) continue;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            rows.UnionWith(ParseD3fend(t, doc.RootElement));
        }
        CheckSize("D3FEND countermeasures", rows.Count, MinDefend);
        Replace(db, new[] { "defend" }, "INSERT INTO defend VALUES (@p0,@p1,@p2,@p3)",
            new IEnumerable<object?[]>[] { rows.Order().Select(r => new object?[] { r.Item1, r.Item2, r.Item3, r.Item4 }) });
        SetMeta(db, "d3fend_sync", Stamp());
        return rows.Count;
    }

    public async Task Run(string dbPath, DateTimeOffset? since = null)
    {
        using var db = Connect(dbPath);
        var failed = new List<string>();
        // each feed on its own: one failing is logged and the rest still update
        async Task Step(string name, string start, Func<Task<string>> run)
        {
            ct.ThrowIfCancellationRequested(); log(start);
            try { log(await run()); }
            catch (Exception e) when (!ct.IsCancellationRequested) { failed.Add(name); log($"{name}: FAILED: {Errors.Explain(e)}"); }
        }
        await Step("KEV", "KEV: downloading...", async () => $"KEV:  {await SyncKev(db)} known-exploited CVEs");
        await Step("EPSS", "EPSS: downloading...", async () => $"EPSS: {await SyncEpss(db)} scored CVEs");
        await Step("ATT&CK", "ATT&CK: downloading (about 40 MB)...", async () => { var (t, a, c) = await SyncAttack(db); return $"ATT&CK: {t} techniques, {a} groups, {c} group->CVE links"; });
        await Step("CTID", "CTID: downloading...", async () => $"CTID: {await SyncCtid(db)} CVE->technique mappings");
        await Step("D3FEND", "D3FEND: fetching countermeasures, one request per technique (about 30 seconds)...", async () => $"D3FEND: {await SyncD3fend(db)} technique->countermeasure links");
        await Step("NVD", "NVD:  syncing (first full run takes ~15 min without an API key)", async () =>
        {
            await SyncNvd(db, Secrets.Get("NVD_API_KEY"), since);
            using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT COUNT(*) FROM cve";
            return $"NVD:  {cmd.ExecuteScalar()} CVEs in db";
        });
        if (failed.Count > 0) throw new InvalidOperationException($"{string.Join(", ", failed)} failed (reason above); the other feeds were updated");
    }
}
