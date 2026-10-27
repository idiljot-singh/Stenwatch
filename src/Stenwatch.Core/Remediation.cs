using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Open (found, not started) > InProgress > Fixed (someone says it is done) > Verified (a later scan confirms it is gone).
/// Reopened = it came back after being Verified or Fixed. Excepted = an analyst decision suppresses it, with an optional expiry.</summary>
public static class TaskState
{
    public const string Open = "Open", InProgress = "InProgress", Fixed = "Fixed", Verified = "Verified", Reopened = "Reopened", Excepted = "Excepted";
    public static readonly string[] Active = { Open, InProgress, Fixed, Reopened };
}

public record RemediationTask(long Id, string Cve, string Asset, string State, string Tier, string Owner, string Ticket, string Opened,
                              string Due, string Closed, string Note)
{
    public bool Overdue(DateOnly today) => TaskState.Active.Contains(State) && string.CompareOrdinal(Due, today.ToString("yyyy-MM-dd")) < 0;
}

/// <summary>Pillar 14: turn priorities into work with owners and deadlines, and confirm the fix from evidence instead of taking it on trust.
/// Verification is automatic: a task becomes Verified when a later run no longer finds the CVE on the asset
/// (patched, upgraded or removed; with Defender that is the device's own patch level).</summary>
public static class Remediation
{
    const string Schema = @"
CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT, asset TEXT, state TEXT, tier TEXT, owner TEXT, ticket TEXT,
                                 opened TEXT, due TEXT, closed TEXT, note TEXT, verified_run INTEGER);
CREATE INDEX IF NOT EXISTS task_key ON task (cve, asset);";

    static string D(DateOnly d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    static SqliteCommand Cmd(SqliteConnection db, string sql, params (string, object?)[] ps)
    {
        var c = db.CreateCommand(); c.CommandText = sql;
        foreach (var (k, v) in ps) c.Parameters.AddWithValue(k, v ?? DBNull.Value);
        return c;
    }

    public static void EnsureSchema(SqliteConnection db) { using var c = Cmd(db, Schema); c.ExecuteNonQuery(); }

    /// <summary>Days allowed to fix a finding of this tier. Act matches the "within 48 h" decision.</summary>
    public static int SlaDays(string tier, Profile p) => p.Sla.TryGetValue(tier, out var d) ? d : 0;

    public static List<RemediationTask> Load(SqliteConnection db, params string[] states)
    {
        EnsureSchema(db);
        var sql = "SELECT id, cve, asset, state, tier, owner, ticket, opened, due, closed, note FROM task"
            + (states.Length > 0 ? " WHERE state IN (" + string.Join(",", states.Select((_, i) => "@s" + i)) + ")" : "") + " ORDER BY due, id";
        using var c = Cmd(db, sql, states.Select((s, i) => ("@s" + i, (object?)s)).ToArray());
        using var r = c.ExecuteReader();
        var l = new List<RemediationTask>();
        string S(int i) => r.IsDBNull(i) ? "" : r.GetString(i);
        while (r.Read()) l.Add(new(r.GetInt64(0), S(1), S(2), S(3), S(4), S(5), S(6), S(7), S(8), S(9), S(10)));
        return l;
    }

    /// <summary>Reconcile tasks with the latest run. Creates tasks for Act and Attend findings, marks tasks Verified when the finding is gone,
    /// reopens tasks whose finding returned, and mirrors analyst decisions. -> the tasks that changed.</summary>
    public static List<RemediationTask> Sync(SqliteConnection db, IEnumerable<Ranked> open, IEnumerable<Ranked> suppressed, Profile p,
                                             long run = 0, DateOnly? today = null)
    {
        EnsureSchema(db);
        using var tx = db.BeginTransaction(); // one commit for the whole run, not one per task
        var day = today ?? DateOnly.FromDateTime(DateTime.Today);
        var changed = new HashSet<long>();
        var all = Load(db);
        var latest = all.GroupBy(t => (t.Cve, t.Asset)).ToDictionary(g => g.Key, g => g.OrderBy(t => t.Id).Last());
        var openKeys = open.ToDictionary(r => (r.Cve, r.Asset.Name));
        var suppressedKeys = suppressed.ToDictionary(r => (r.Cve, r.Asset.Name));

        void Set(RemediationTask t, string state, string note = "", bool close = false)
        {
            using var c = Cmd(db, "UPDATE task SET state=@s, closed=@c, note=@n, verified_run=@v WHERE id=@i",
                ("@s", state), ("@c", close ? D(day) : ""), ("@n", note != "" ? note : t.Note), ("@v", state == TaskState.Verified ? run : null), ("@i", t.Id));
            c.ExecuteNonQuery(); changed.Add(t.Id);
        }

        foreach (var (key, r) in openKeys.Where(x => x.Value.Tier is "Act" or "Attend"))
        {
            if (!latest.TryGetValue(key, out var t) || t.State is TaskState.Verified)
            {
                if (t != null) // it came back after being verified: a new task, linked by the note
                {
                    Insert(db, r, p, day, "reopened: the finding returned after verification");
                    changed.Add(LastId(db));
                }
                else { Insert(db, r, p, day, ""); changed.Add(LastId(db)); }
            }
            else if (t.State is TaskState.Fixed) Set(t, TaskState.Reopened, "claimed fixed, but the next scan still finds it");
            else if (t.State is TaskState.Excepted) Set(t, TaskState.Open, "the analyst decision expired or was removed");
        }
        foreach (var (key, t) in latest)
        {
            if (!TaskState.Active.Contains(t.State) && t.State != TaskState.Excepted) continue;
            if (suppressedKeys.ContainsKey(key)) { if (t.State != TaskState.Excepted) Set(t, TaskState.Excepted, "suppressed by an analyst decision"); }
            else if (!openKeys.ContainsKey(key) && t.State != TaskState.Excepted) Set(t, TaskState.Verified, "verified: the CVE no longer matches this asset", close: true);
        }
        tx.Commit();
        return Load(db).Where(t => changed.Contains(t.Id)).ToList();
    }

    static long LastId(SqliteConnection db) { using var c = Cmd(db, "SELECT last_insert_rowid()"); return (long)c.ExecuteScalar()!; }

    static void Insert(SqliteConnection db, Ranked r, Profile p, DateOnly day, string note)
    {
        using var c = Cmd(db, "INSERT INTO task (cve, asset, state, tier, owner, ticket, opened, due, closed, note) VALUES (@c,@a,@s,@t,@o,'',@op,@du,'',@n)",
            ("@c", r.Cve), ("@a", r.Asset.Name), ("@s", note.StartsWith("reopened") ? TaskState.Reopened : TaskState.Open), ("@t", r.Tier), ("@o", ""),
            ("@op", D(day)), ("@du", D(day.AddDays(SlaDays(r.Tier, p)))), ("@n", note));
        c.ExecuteNonQuery();
    }

    // ---- analyst actions (the WPF app calls these) ----
    public static void Assign(SqliteConnection db, long id, string owner, string ticket = "")
    {
        using var c = Cmd(db, "UPDATE task SET owner=@o, ticket=@t, state=CASE WHEN state IN ('Open','Reopened') THEN 'InProgress' ELSE state END WHERE id=@i", ("@o", owner), ("@t", ticket), ("@i", id));
        c.ExecuteNonQuery();
    }

    /// <summary>"We fixed it." Not enough to close: the task stays Fixed until a scan confirms.</summary>
    public static void ClaimFixed(SqliteConnection db, long id, string note = "")
    {
        using var c = Cmd(db, "UPDATE task SET state='Fixed', note=@n WHERE id=@i AND state IN ('Open','InProgress','Reopened')", ("@n", note), ("@i", id));
        c.ExecuteNonQuery();
    }
}
