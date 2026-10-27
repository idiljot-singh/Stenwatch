namespace Stenwatch.Core;

public record RunOptions(bool Example = false, bool Pdf = true, string Out = "", bool Collect = false, DateTimeOffset? Since = null);

public record RunResult(List<Ranked> Ranked, List<Ranked> Suppressed, PathResult? Paths, long Run, List<ChangeEvent> Events,
                        List<RemediationTask> TaskChanges, OrgContext Context, Profile Profile, string OutDir, string BriefSource);

/// <summary>One call that does what the whole CTI cycle does: collect (optional), process, analyse, disseminate, feedback.
/// The command line and the desktop app both use it, so they cannot drift apart.</summary>
public static class Engine
{
    public static async Task<RunResult> Run(PipelineFiles files, RunOptions o, Action<string>? log = null)
    {
        log ??= _ => { };
        var profile = Profile.Load(files.Profile);
        if (o.Collect && !o.Example) await new Collect(log: log).Run(files.Db, o.Since);

        List<Asset>? live = null;
        if (profile.Defender.Enabled)
        {
            live = await Defender.FetchAssets(profile.Defender);
            log($"Defender: {live.Count} software/version groups from the device fleet");
        }

        // The Example Organisation never touches the real organisation's context, history or tasks.
        using var db = Collect.Connect(files.Db);
        // threat groups: pinned ones, plus (targeting.mode: auto) the best matches for this organisation from ATT&CK
        var (effective, groups, groupNote) = ThreatProfileAuto.Effective(profile, db);
        profile = effective; log("Threat groups: " + groupNote);
        var ctx = o.Example ? ContextStore.LoadExample(Path.GetDirectoryName(Path.GetFullPath(files.Profile))!) : ContextStore.Load(db);
        if (!ctx.IsEmpty) log($"Context: {ctx.Services.Count} services, {ctx.Links.Count} links, {ctx.Controls.Count} controls");

        log("Processing and analysis");
        if (profile.PatchBaseline != "") log($"Assumption (patch_baseline {profile.PatchBaseline}): on assets without a version or OS build, CVEs published before that date are treated as patched");
        var ((ranked, suppressed), paths) = Pipeline.RunWithPaths(files, null, live, ctx, null, profile);
        log($"Analysis: {ranked.Count} ranked findings ({suppressed.Count} suppressed)");

        var outDir = o.Out != "" ? o.Out : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(files.Db))!, "out", o.Example ? "example-cs" : "cs");
        Directory.CreateDirectory(outDir);
        var today = DateOnly.FromDateTime(DateTime.Today).ToString("yyyy-MM-dd");
        var decisions = files.Decisions != null ? Process.LoadDecisions(files.Decisions) : new();
        Disseminate.WriteReports(ranked, outDir, profile, suppressed: suppressed, expired: decisions.Where(e => e.Until != "" && string.CompareOrdinal(e.Until, today) < 0).ToList());
        Disseminate.WriteStix(ranked, outDir, profile);
        Disseminate.WriteDashboard(ranked, outDir, profile);
        Disseminate.WriteNavigator(ranked, outDir, profile);
        File.WriteAllText(Path.Combine(outDir, "threat-profile.md"), ThreatProfileAuto.Markdown(profile, groups, groupNote));
        if (paths != null) Disseminate.WritePaths(paths, outDir, profile);
        var names = ranked.Select(r => r.Asset.Name).Distinct().Append(profile.Organisation.Name);
        var (brief, source) = await Llm.Brief(ranked, profile.Llm, names, $"a {profile.Organisation.Sector} organisation in {profile.Organisation.Country}", log: log);
        Disseminate.WriteBrief(brief, source, outDir, profile);
        if (o.Pdf)
        {
            var pdfs = new[] { "report", "brief" }.Select(n => Render.ToPdf(Path.Combine(outDir, n + ".html"))).Where(p => p != null).ToList();
            log("PDF: " + (pdfs.Count > 0 ? string.Join(", ", pdfs.Select(Path.GetFileName)) : "skipped (needs Microsoft Edge or Chrome)"));
        }

        long run = 0; var events = new List<ChangeEvent>(); var tasks = new List<RemediationTask>(); List<RemediationTask> allTasks;
        if (!o.Example)
        {
            ThreatProfileAuto.Store(db, groups);
            (run, events) = History.Record(db, ranked, suppressed);
            tasks = Remediation.Sync(db, ranked, suppressed, profile, run);
            log($"Feedback: run {run}, {events.Count} change(s), {tasks.Count} task update(s)");
            allTasks = Remediation.Load(db);
        }
        else
        {
            var state = Path.Combine(outDir, ExampleHistory.File);
            (run, events, tasks) = ExampleHistory.Replay(state, db, files, profile, ctx, ranked, suppressed, DateOnly.FromDateTime(DateTime.Today));
            using (var sdb = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={state}")) { sdb.Open(); allTasks = Remediation.Load(sdb); }
            log($"Feedback (simulated history of the Example Organisation): run {run}, {events.Count} change(s), {allTasks.Count} task(s)");
        }
        FullReport.Write(files, outDir, profile, db, ctx, ranked, allTasks, o.Example, o.Pdf);
        log("Full report: full-report.html" + (o.Pdf ? " and .pdf" : ""));
        return new RunResult(ranked, suppressed, paths, run, events, tasks, ctx, profile, outDir, source);
    }
}
