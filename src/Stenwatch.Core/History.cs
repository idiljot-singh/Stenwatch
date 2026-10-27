using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Something that changed between two runs, with the reason (pillar 5: "why did this priority change?").</summary>
public record ChangeEvent(string Kind, string Cve, string Asset, string Detail);

/// <summary>Pillar 5: every run is kept, so priorities can be explained over time and remediation can be verified (pillar 14).
/// Lives in the same SQLite file as the feeds; the Python version ignores these tables.</summary>
public static class History
{
    const string Schema = @"
CREATE TABLE IF NOT EXISTS run             (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS finding_history (run INTEGER, cve TEXT, asset TEXT, state TEXT, tier TEXT, risk REAL, likelihood REAL, impact REAL,
                                            kev INTEGER, ransomware INTEGER, epss REAL, cvss REAL, confidence TEXT, why TEXT,
                                            PRIMARY KEY (run, cve, asset));
CREATE TABLE IF NOT EXISTS change_event    (run INTEGER, kind TEXT, cve TEXT, asset TEXT, detail TEXT);";

    /// <summary>An EPSS move at least this large (absolute) is worth an event.</summary>
    public const double EpssJump = 0.10;
    static readonly string[] TierOrder = { "Ignore", "Track", "Attend", "Act" };

    record Row(string Tier, string State, double Risk, bool Kev, bool Ransomware, double Epss, double? Cvss, string Why);

    public static void EnsureSchema(SqliteConnection db)
    {
        using var c = db.CreateCommand(); c.CommandText = Schema; c.ExecuteNonQuery();
    }

    static object V(object? o) => o ?? DBNull.Value;

    /// <summary>Store this run (open and suppressed findings) and diff it against the previous one. -> (run id, events).</summary>
    public static (long Run, List<ChangeEvent> Events) Record(SqliteConnection db, IEnumerable<Ranked> open, IEnumerable<Ranked> suppressed,
                                                              string note = "", DateTimeOffset? at = null)
    {
        EnsureSchema(db);
        using var tx = db.BeginTransaction();
        var prev = Previous(db, note);

        long run;
        using (var c = db.CreateCommand())
        {
            c.CommandText = "INSERT INTO run (at, note) VALUES (@a, @n); SELECT last_insert_rowid();";
            c.Parameters.AddWithValue("@a", (at ?? DateTimeOffset.UtcNow).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            c.Parameters.AddWithValue("@n", note);
            run = (long)c.ExecuteScalar()!;
        }

        var current = new Dictionary<(string, string), Row>();
        foreach (var (state, rows) in new[] { ("open", open), ("suppressed", suppressed) })
            foreach (var r in rows)
            {
                var key = (r.Cve, r.Asset.Name);
                current[key] = new Row(r.Tier, state, r.Risk, r.F.Kev, r.F.Ransomware, r.F.Epss, r.F.Cvss, r.Why);
                using var c = db.CreateCommand();
                c.CommandText = "INSERT OR REPLACE INTO finding_history VALUES (@run,@cve,@asset,@state,@tier,@risk,@lik,@imp,@kev,@ran,@epss,@cvss,@conf,@why)";
                foreach (var (k, v) in new (string, object?)[] { ("@run", run), ("@cve", r.Cve), ("@asset", r.Asset.Name), ("@state", state), ("@tier", r.Tier),
                    ("@risk", r.Risk), ("@lik", r.Likelihood), ("@imp", r.Impact), ("@kev", r.F.Kev ? 1 : 0), ("@ran", r.F.Ransomware ? 1 : 0),
                    ("@epss", r.F.Epss), ("@cvss", r.F.Cvss), ("@conf", r.Confidence), ("@why", r.Why) })
                    c.Parameters.AddWithValue(k, V(v));
                c.ExecuteNonQuery();
            }

        var events = prev is null ? new List<ChangeEvent>() : Diff(prev, current);
        foreach (var e in events)
        {
            using var c = db.CreateCommand();
            c.CommandText = "INSERT INTO change_event VALUES (@run,@k,@cve,@asset,@d)";
            c.Parameters.AddWithValue("@run", run); c.Parameters.AddWithValue("@k", e.Kind); c.Parameters.AddWithValue("@cve", e.Cve);
            c.Parameters.AddWithValue("@asset", e.Asset); c.Parameters.AddWithValue("@d", e.Detail);
            c.ExecuteNonQuery();
        }
        tx.Commit();
        return (run, events);
    }

    /// <summary>The latest earlier run with the same note (scope), so the Example Organisation never mixes with real runs.</summary>
    static Dictionary<(string, string), Row>? Previous(SqliteConnection db, string note)
    {
        long? last;
        using (var c = db.CreateCommand()) { c.CommandText = "SELECT MAX(id) FROM run WHERE note = @n"; c.Parameters.AddWithValue("@n", note); last = c.ExecuteScalar() as long?; }
        if (last is null) return null;
        var d = new Dictionary<(string, string), Row>();
        using var q = db.CreateCommand();
        q.CommandText = "SELECT cve, asset, state, tier, risk, kev, ransomware, epss, cvss, why FROM finding_history WHERE run = @r";
        q.Parameters.AddWithValue("@r", last);
        using var r = q.ExecuteReader();
        while (r.Read())
            d[(r.GetString(0), r.GetString(1))] = new Row(r.GetString(3), r.GetString(2), r.GetDouble(4), r.GetInt64(5) != 0, r.GetInt64(6) != 0,
                r.GetDouble(7), r.IsDBNull(8) ? null : r.GetDouble(8), r.GetString(9));
        return d;
    }

    static List<ChangeEvent> Diff(Dictionary<(string, string), Row> prev, Dictionary<(string, string), Row> cur)
    {
        var ev = new List<ChangeEvent>();
        foreach (var ((cve, asset), now) in cur.OrderBy(x => x.Key.Item1, StringComparer.Ordinal).ThenBy(x => x.Key.Item2, StringComparer.Ordinal))
        {
            if (!prev.TryGetValue((cve, asset), out var was))
            {
                ev.Add(new("new", cve, asset, $"new finding, tier {now.Tier}"));
                continue;
            }
            var why = new List<string>();
            if (!was.Kev && now.Kev) { ev.Add(new("entered_kev", cve, asset, "added to CISA KEV: exploitation is now confirmed")); why.Add("entered KEV"); }
            if (!was.Ransomware && now.Ransomware) { ev.Add(new("ransomware", cve, asset, "now flagged for ransomware use")); why.Add("ransomware use flagged"); }
            if (Math.Abs(now.Epss - was.Epss) >= EpssJump)
            { ev.Add(new("epss_jump", cve, asset, $"EPSS {Py.F(was.Epss, 2)} to {Py.F(now.Epss, 2)}")); why.Add($"EPSS {Py.F(was.Epss, 2)} to {Py.F(now.Epss, 2)}"); }
            if (was.State != now.State)
                ev.Add(new(now.State == "suppressed" ? "decision_applied" : "decision_expired", cve, asset,
                    now.State == "suppressed" ? "an analyst decision now suppresses it" : "the analyst decision expired or was removed: back for review"));
            int a = Array.IndexOf(TierOrder, was.Tier), b = Array.IndexOf(TierOrder, now.Tier);
            if (a != b)
                ev.Add(new(b > a ? "tier_up" : "tier_down", cve, asset,
                    $"{was.Tier} to {now.Tier}" + (why.Count > 0 ? ": " + string.Join(", ", why) : was.Why != now.Why ? ": inputs changed (" + WhatChanged(was.Why, now.Why) + ")" : "")));
        }
        foreach (var ((cve, asset), was) in prev.Where(p => p.Value.State == "open" && !cur.ContainsKey(p.Key))
                     .OrderBy(x => x.Key.Item1, StringComparer.Ordinal).ThenBy(x => x.Key.Item2, StringComparer.Ordinal))
            ev.Add(new("resolved", cve, asset, "no longer matches this asset (patched, upgraded or removed)"));
        return ev;
    }

    static string WhatChanged(string was, string now)
    {
        var a = was.Split("; ").ToHashSet(); var b = now.Split("; ").ToHashSet();
        var parts = b.Except(a).Select(x => "+" + x).Concat(a.Except(b).Select(x => "-" + x)).ToList();
        return parts.Count > 0 ? string.Join(", ", parts) : "ordering only";
    }

    public static List<ChangeEvent> Events(SqliteConnection db, long? run = null, string note = "")
    {
        EnsureSchema(db);
        using var c = db.CreateCommand();
        c.CommandText = "SELECT kind, cve, asset, detail FROM change_event WHERE run = COALESCE(@r, (SELECT MAX(id) FROM run WHERE note = @n)) ORDER BY rowid"; c.Parameters.AddWithValue("@n", note);
        c.Parameters.AddWithValue("@r", run is null ? DBNull.Value : run);
        using var r = c.ExecuteReader();
        var l = new List<ChangeEvent>();
        while (r.Read()) l.Add(new(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));
        return l;
    }
}
