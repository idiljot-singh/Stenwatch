using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>The Example Organisation's past, so Feedback, "what changed" and Effectiveness have something real to show.
/// Earlier runs are replayed through the same History and Remediation code a real organisation uses, into a throwaway database:
/// the estate as it was before its upgrades (history.example.csv: asset, until_days_ago, version), CVEs hidden until they were published,
/// KEV entries until they were added, and analysts assigning tasks and claiming fixes in between. Simulated, and labelled so where shown.</summary>
public static class ExampleHistory
{
    public const string File = "example-state.db";
    static readonly int[] DaysAgo = { 56, 42, 28, 14, 7 };

    public static (long Run, List<ChangeEvent> Events, List<RemediationTask> Changes) Replay(string stateDb, SqliteConnection feeds, PipelineFiles files,
        Profile profile, OrgContext ctx, List<Ranked> ranked, List<Ranked> suppressed, DateOnly today)
    {
        SqliteConnection.ClearAllPools();
        if (System.IO.File.Exists(stateDb)) System.IO.File.Delete(stateDb);
        using var db = new SqliteConnection($"Data Source={stateDb}"); db.Open();
        var hist = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(files.Assets))!, "history.example.csv");
        var past = System.IO.File.Exists(hist) ? Csv.ReadDict(hist).Select(h => (Asset: h["asset"], Until: int.Parse(h["until_days_ago"]), Version: h["version"])).ToList() : new();
        var assets = Process.LoadAssets(files.Assets);
        var decisions = files.Decisions is { } d ? Process.LoadDecisions(d) : new();
        var threat = Analyse.LoadThreat(feeds, profile);
        var now = ranked.Concat(suppressed).Select(r => r.F).ToList();
        var stillThere = now.Select(f => (f.Cve, f.Asset.Name)).ToHashSet();

        for (int i = 0; i < DaysAgo.Length; i++)
        {
            int ago = DaysAgo[i], next = i + 1 < DaysAgo.Length ? DaysAgo[i + 1] : 0;
            var day = today.AddDays(-ago); var ds = day.ToString("yyyy-MM-dd");
            // the version each upgraded asset ran on that day (the earliest upgrade still ahead of it)
            var then = past.Where(p => p.Until < ago).GroupBy(p => p.Asset).ToDictionary(g => g.Key, g => g.MinBy(p => p.Until).Version);
            var old = assets.Where(a => then.ContainsKey(a.Name)).Select(a => a with { Version = then[a.Name] }).ToList();
            var findings = now.Where(f => !then.ContainsKey(f.Asset.Name)).Concat(Process.Match(feeds, old, profile.ThirdParty.RecentDays, day, profile.PatchBaseline))
                .Where(f => string.CompareOrdinal(f.Published, ds) <= 0)
                .Select(f => string.CompareOrdinal(f.KevAdded, ds) > 0 ? f with { Kev = false, Ransomware = false } : f);
            var (open, supp) = Process.ApplyDecisions(Analyse.Rank(findings, profile, threat, ctx, null, day), decisions, day);
            var (run, _) = History.Record(db, open, supp, "example", new DateTimeOffset(day.ToDateTime(new TimeOnly(6, 0)), TimeSpan.Zero));
            Remediation.Sync(db, open, supp, profile, run, day);
            Analysts(db, ctx, past.Where(p => p.Until < ago && p.Until >= next).Select(p => p.Asset).ToHashSet(), stillThere, first: i == 1);
        }
        var (last, events) = History.Record(db, ranked, suppressed, "example");
        return (last, events, Remediation.Sync(db, ranked, suppressed, profile, last, today));
    }

    /// <summary>Between runs: owners pick up most new tasks, what the coming upgrades fix is claimed fixed (the next run verifies it),
    /// and once, three fixes are claimed that do not hold (the next run reopens them).</summary>
    static void Analysts(SqliteConnection db, OrgContext ctx, HashSet<string> upgrading, HashSet<(string, string)> stillThere, bool first)
    {
        string Owner(string asset) => ctx.Assets.TryGetValue(asset, out var a) && a.Owner != "" ? a.Owner : ctx.ServicesOf(asset).Select(s => s.Owner).FirstOrDefault() ?? "";
        foreach (var t in Remediation.Load(db, TaskState.Open, TaskState.Reopened).Where(t => t.Id % 5 != 0 && Owner(t.Asset) != ""))
            Remediation.Assign(db, t.Id, Owner(t.Asset), $"CHG-{4100 + t.Id}");
        var active = Remediation.Load(db, TaskState.Open, TaskState.InProgress);
        foreach (var t in active.Where(t => upgrading.Contains(t.Asset) && !stillThere.Contains((t.Cve, t.Asset)))) Remediation.ClaimFixed(db, t.Id, "claimed fixed: upgraded");
        if (first) foreach (var t in active.Where(t => t.Asset.StartsWith("Domain controllers")).Take(3)) Remediation.ClaimFixed(db, t.Id, "claimed fixed");
    }
}
