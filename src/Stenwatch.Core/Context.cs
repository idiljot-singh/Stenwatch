using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>A business service the organisation runs (pillar 9). Its criticality (1-3) is defined by the organisation, not guessed.</summary>
public record Service(string Name, string Owner, int Criticality, string DataClass = "internal", string Regulatory = "", int RtoHours = 0, string Note = "");

/// <summary>Where an asset sits and who owns it. CrownJewel marks assets an attacker must not reach (targets for attack paths).</summary>
public record AssetContext(string Asset, string Zone = "", string Owner = "", bool CrownJewel = false);

/// <summary>A can-reach relationship: Src can open a connection to Dst (network), or holds credentials/trust into it. Direction matters.</summary>
public record Link(string Src, string Dst, string Kind = "network", string Port = "", string Note = "");

/// <summary>A security control (pillar 10). It only counts while its evidence is present, dated, and unexpired.
/// Counters lists ATT&amp;CK technique ids (T1190) and/or D3FEND ids (D3-NTF) it defends against; Scope is asset names, zone:NAME or *.</summary>
public record Control(string Id, string Name, string Type, string Scope, string Counters, string Effectiveness = "partial",
                      string Evidence = "", string EvidenceDate = "", string Expires = "");

/// <summary>Everything the organisation tells Stenwatch beyond the asset list. Empty by default, in which case scoring is unchanged.</summary>
public class OrgContext
{
    public List<Service> Services = new();
    public Dictionary<string, List<string>> ServiceAssets = new(); // service -> asset names
    public Dictionary<string, AssetContext> Assets = new();
    public List<Link> Links = new();
    public List<Control> Controls = new();

    public bool IsEmpty => Services.Count == 0 && Links.Count == 0 && Controls.Count == 0 && Assets.Count == 0;

    /// <summary>The services that depend on this asset.</summary>
    public IEnumerable<Service> ServicesOf(string asset) =>
        Services.Where(s => ServiceAssets.TryGetValue(s.Name, out var l) && l.Contains(asset));

    /// <summary>Business-impact weight for an asset: the highest criticality among services that depend on it, or null when none is defined.</summary>
    public int? ServiceWeight(string asset) { var s = ServicesOf(asset).ToList(); return s.Count == 0 ? null : s.Max(x => x.Criticality); }

    public string Zone(string asset) => Assets.TryGetValue(asset, out var a) ? a.Zone : "";

    public bool InScope(Control c, string asset) =>
        c.Scope.Split(',').Select(x => x.Trim()).Any(x => x == "*" || x == asset || (x.StartsWith("zone:") && x[5..] == Zone(asset)));

    /// <summary>Evidence present, dated, within maxAgeDays, and not past its expiry.</summary>
    public static bool EvidenceValid(Control c, DateOnly today, int maxAgeDays = 365)
    {
        if (c.Evidence.Trim() == "" || !DateOnly.TryParseExact(c.EvidenceDate, "yyyy-MM-dd", out var d)) return false;
        if (today.DayNumber - d.DayNumber > maxAgeDays) return false;
        return c.Expires == "" || string.CompareOrdinal(c.Expires, today.ToString("yyyy-MM-dd")) >= 0;
    }

    /// <summary>Controls that are in scope, evidenced, and counter at least one technique or D3FEND countermeasure of the finding.</summary>
    public List<Control> Compensating(string asset, IEnumerable<string> techniqueIds, IEnumerable<string> defendIds, DateOnly today, int maxAgeDays = 365)
    {
        var mine = techniqueIds.Concat(defendIds).ToHashSet();
        return Controls.Where(c => InScope(c, asset) && EvidenceValid(c, today, maxAgeDays)
            && c.Counters.Split(',').Select(x => x.Trim()).Any(x => x != "" && mine.Contains(x))).ToList();
    }
}

/// <summary>SQLite storage and CSV import for the organisation context (same file as the feeds).</summary>
public static class ContextStore
{
    const string Schema = @"
CREATE TABLE IF NOT EXISTS service       (name TEXT PRIMARY KEY, owner TEXT, criticality INTEGER, data_class TEXT, regulatory TEXT, rto_hours INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS service_asset (service TEXT, asset TEXT, PRIMARY KEY (service, asset));
CREATE TABLE IF NOT EXISTS asset_context (asset TEXT PRIMARY KEY, zone TEXT, owner TEXT, crown_jewel INTEGER);
CREATE TABLE IF NOT EXISTS link          (src TEXT, dst TEXT, kind TEXT, port TEXT, note TEXT, PRIMARY KEY (src, dst, kind, port));
CREATE TABLE IF NOT EXISTS control       (id TEXT PRIMARY KEY, name TEXT, type TEXT, scope TEXT, counters TEXT, effectiveness TEXT, evidence TEXT, evidence_date TEXT, expires TEXT);";

    static SqliteCommand Cmd(SqliteConnection db, string sql, params (string, object?)[] ps)
    {
        var c = db.CreateCommand(); c.CommandText = sql;
        foreach (var (k, v) in ps) c.Parameters.AddWithValue(k, v ?? DBNull.Value);
        return c;
    }

    public static void EnsureSchema(SqliteConnection db) { using var c = Cmd(db, Schema); c.ExecuteNonQuery(); }

    public static OrgContext Load(SqliteConnection db)
    {
        EnsureSchema(db);
        var ctx = new OrgContext();
        using (var r = Cmd(db, "SELECT name, owner, criticality, data_class, regulatory, rto_hours, note FROM service ORDER BY name").ExecuteReader())
            while (r.Read()) ctx.Services.Add(new(r.GetString(0), S(r, 1), (int)r.GetInt64(2), S(r, 3), S(r, 4), (int)(r.IsDBNull(5) ? 0 : r.GetInt64(5)), S(r, 6)));
        using (var r = Cmd(db, "SELECT service, asset FROM service_asset ORDER BY service, asset").ExecuteReader())
            while (r.Read()) { if (!ctx.ServiceAssets.TryGetValue(r.GetString(0), out var l)) ctx.ServiceAssets[r.GetString(0)] = l = new(); l.Add(r.GetString(1)); }
        using (var r = Cmd(db, "SELECT asset, zone, owner, crown_jewel FROM asset_context ORDER BY asset").ExecuteReader())
            while (r.Read()) ctx.Assets[r.GetString(0)] = new(r.GetString(0), S(r, 1), S(r, 2), !r.IsDBNull(3) && r.GetInt64(3) != 0);
        using (var r = Cmd(db, "SELECT src, dst, kind, port, note FROM link ORDER BY src, dst, kind, port").ExecuteReader())
            while (r.Read()) ctx.Links.Add(new(r.GetString(0), r.GetString(1), S(r, 2), S(r, 3), S(r, 4)));
        using (var r = Cmd(db, "SELECT id, name, type, scope, counters, effectiveness, evidence, evidence_date, expires FROM control ORDER BY id").ExecuteReader())
            while (r.Read()) ctx.Controls.Add(new(r.GetString(0), S(r, 1), S(r, 2), S(r, 3), S(r, 4), S(r, 5), S(r, 6), S(r, 7), S(r, 8)));
        return ctx;
    }

    static string S(SqliteDataReader r, int i) => r.IsDBNull(i) ? "" : r.GetString(i);

    public static void Save(SqliteConnection db, Service s, IEnumerable<string> assets)
    {
        if (s.Criticality is < 1 or > 3) throw new ArgumentException("service criticality must be 1, 2 or 3");
        EnsureSchema(db); // no transaction here: callers (the app's Save, ImportServices) wrap one around all rows, and SQLite cannot nest them
        Cmd(db, "INSERT OR REPLACE INTO service VALUES (@n,@o,@c,@d,@r,@t,@note)", ("@n", s.Name), ("@o", s.Owner), ("@c", s.Criticality), ("@d", s.DataClass),
            ("@r", s.Regulatory), ("@t", s.RtoHours), ("@note", s.Note)).ExecuteNonQuery();
        Cmd(db, "DELETE FROM service_asset WHERE service = @n", ("@n", s.Name)).ExecuteNonQuery();
        foreach (var a in assets.Distinct()) Cmd(db, "INSERT INTO service_asset VALUES (@n,@a)", ("@n", s.Name), ("@a", a)).ExecuteNonQuery();
    }

    public static void Save(SqliteConnection db, AssetContext a)
    {
        EnsureSchema(db);
        Cmd(db, "INSERT OR REPLACE INTO asset_context VALUES (@a,@z,@o,@c)", ("@a", a.Asset), ("@z", a.Zone), ("@o", a.Owner), ("@c", a.CrownJewel ? 1 : 0)).ExecuteNonQuery();
    }

    public static void Save(SqliteConnection db, Link l)
    {
        if (l.Src == l.Dst) throw new ArgumentException("a link needs two different assets");
        EnsureSchema(db);
        Cmd(db, "INSERT OR REPLACE INTO link VALUES (@s,@d,@k,@p,@n)", ("@s", l.Src), ("@d", l.Dst), ("@k", l.Kind), ("@p", l.Port), ("@n", l.Note)).ExecuteNonQuery();
    }

    public static void Save(SqliteConnection db, Control c)
    {
        if (c.Effectiveness is not ("partial" or "strong")) throw new ArgumentException("effectiveness must be partial or strong");
        if (c.EvidenceDate != "" && !DateOnly.TryParseExact(c.EvidenceDate, "yyyy-MM-dd", out _)) throw new ArgumentException("evidence_date must be YYYY-MM-DD");
        EnsureSchema(db);
        Cmd(db, "INSERT OR REPLACE INTO control VALUES (@i,@n,@t,@s,@c,@e,@ev,@d,@x)", ("@i", c.Id), ("@n", c.Name), ("@t", c.Type), ("@s", c.Scope),
            ("@c", c.Counters), ("@e", c.Effectiveness), ("@ev", c.Evidence), ("@d", c.EvidenceDate), ("@x", c.Expires)).ExecuteNonQuery();
    }

    public static void Delete(SqliteConnection db, string table, string key)
    {
        var (sql, cols) = table switch
        {
            "service" => ("DELETE FROM service WHERE name=@k; DELETE FROM service_asset WHERE service=@k", true),
            "control" => ("DELETE FROM control WHERE id=@k", true),
            "asset_context" => ("DELETE FROM asset_context WHERE asset=@k", true),
            _ => throw new ArgumentException("unknown table " + table),
        };
        Cmd(db, sql, ("@k", key)).ExecuteNonQuery();
    }

    public static void DeleteLink(SqliteConnection db, Link l) =>
        Cmd(db, "DELETE FROM link WHERE src=@s AND dst=@d AND kind=@k AND port=@p", ("@s", l.Src), ("@d", l.Dst), ("@k", l.Kind), ("@p", l.Port)).ExecuteNonQuery();

    // ---------- CSV import (services.csv, links.csv, controls.csv, asset_context.csv) ----------

    /// <summary>The bundled Example Organisation's context (services, assets, links, controls), read from *.example.csv next to the profile
    /// into memory only: the example never writes to the real organisation's database.</summary>
    public static OrgContext LoadExample(string dir)
    {
        using var db = Collect.Connect(":memory:");
        foreach (var (file, import) in new (string, Func<SqliteConnection, string, int>)[] {
            ("services.example.csv", ImportServices), ("asset_context.example.csv", ImportAssetContext), ("links.example.csv", ImportLinks), ("controls.example.csv", ImportControls) })
            if (File.Exists(Path.Combine(dir, file))) import(db, Path.Combine(dir, file));
        return Load(db);
    }

    /// <summary>services.csv: name,owner,criticality,data_class,regulatory,rto_hours,assets (assets separated by ';').</summary>
    public static int ImportServices(SqliteConnection db, string path)
    {
        var rows = Csv.ReadDict(path);
        EnsureSchema(db);
        using var tx = db.BeginTransaction();
        foreach (var r in rows)
            Save(db, new Service(r["name"].Trim(), r.GetValueOrDefault("owner", ""), int.Parse(r["criticality"], CultureInfo.InvariantCulture), r.GetValueOrDefault("data_class", "internal"),
                r.GetValueOrDefault("regulatory", ""), int.TryParse(r.GetValueOrDefault("rto_hours", ""), out var h) ? h : 0, r.GetValueOrDefault("note", "")),
                r.GetValueOrDefault("assets", "").Split(';').Select(x => x.Trim()).Where(x => x != ""));
        tx.Commit();
        return rows.Count;
    }

    /// <summary>links.csv: src,dst,kind,port,note.</summary>
    public static int ImportLinks(SqliteConnection db, string path)
    {
        var rows = Csv.ReadDict(path);
        foreach (var r in rows) Save(db, new Link(r["src"].Trim(), r["dst"].Trim(), r.GetValueOrDefault("kind", "network"), r.GetValueOrDefault("port", ""), r.GetValueOrDefault("note", "")));
        return rows.Count;
    }

    /// <summary>controls.csv: id,name,type,scope,counters,effectiveness,evidence,evidence_date,expires.</summary>
    public static int ImportControls(SqliteConnection db, string path)
    {
        var rows = Csv.ReadDict(path);
        foreach (var r in rows)
            Save(db, new Control(r["id"].Trim(), r["name"], r.GetValueOrDefault("type", ""), r.GetValueOrDefault("scope", "*"), r.GetValueOrDefault("counters", ""),
                r.GetValueOrDefault("effectiveness", "partial"), r.GetValueOrDefault("evidence", ""), r.GetValueOrDefault("evidence_date", ""), r.GetValueOrDefault("expires", "")));
        return rows.Count;
    }

    /// <summary>asset_context.csv: asset,zone,owner,crown_jewel.</summary>
    public static int ImportAssetContext(SqliteConnection db, string path)
    {
        var rows = Csv.ReadDict(path);
        foreach (var r in rows) Save(db, new AssetContext(r["asset"].Trim(), r.GetValueOrDefault("zone", ""), r.GetValueOrDefault("owner", ""),
            new[] { "y", "yes", "true", "1" }.Contains(r.GetValueOrDefault("crown_jewel", "").Trim().ToLowerInvariant())));
        return rows.Count;
    }
}
