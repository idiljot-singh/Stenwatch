using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

public record PipelineFiles(string Db, string Profile, string Assets, string? ThirdParties, string? Decisions);

public static class Pipeline
{
    /// <summary>Match -> score -> apply analyst decisions. -> (ranked, suppressed).</summary>
    public static (List<Ranked> Ranked, List<Ranked> Suppressed) Run(PipelineFiles f, DateOnly? today = null, IEnumerable<Asset>? extraAssets = null)
        => RunWithPaths(f, today, extraAssets, null).Item1;

    /// <summary>As Run, with the organisation context (services, links, controls) and the attack paths it implies.</summary>
    public static ((List<Ranked> Ranked, List<Ranked> Suppressed), PathResult? Paths) RunWithPaths(PipelineFiles f, DateOnly? today, IEnumerable<Asset>? extraAssets, OrgContext? ctx, PathOptions? opt = null, Profile? effective = null)
    {
        var profile = effective ?? Profile.Load(f.Profile);
        using var db = new SqliteConnection($"Data Source={f.Db};Mode=ReadOnly");
        db.Open();
        var assets = Process.LoadAssets(f.Assets);
        if (extraAssets != null) assets.AddRange(extraAssets); // e.g. the live Defender inventory
        if (f.ThirdParties is { } t && File.Exists(t)) assets.AddRange(Process.LoadAssets(t, thirdParty: true));
        var findings = Process.Match(db, assets, profile.ThirdParty.RecentDays, today, profile.PatchBaseline);
        var (ranked, paths) = Analyse.RankWithPaths(findings, profile, Analyse.LoadThreat(db, profile), ctx, opt, today);
        var decisions = f.Decisions is { } d ? Process.LoadDecisions(d) : new();
        return (Process.ApplyDecisions(ranked, decisions, today), paths);
    }

    /// <summary>Columns shared with the Python original (parity-tested); CsvExtra follows them.</summary>
    public static readonly string[] CsvExtra = { "confidence", "exploitation", "evidence" };

    public static readonly string[] CsvHeader =
    {
        "rank", "tier", "risk", "cve", "asset", "source", "kev", "ransomware", "epss", "cvss", "likelihood", "impact",
        "exploited_by", "techniques", "why", "summary", "d3fend", "mitigations",
        "diamond_adversary", "diamond_capability", "diamond_infrastructure", "diamond_victim", "diamond_phase",
    };

    /// <summary>report.csv, column for column the same as the Python pipeline's.</summary>
    public static void WriteCsv(string path, IEnumerable<Ranked> ranked) =>
        Csv.Write(path, new[] { CsvHeader.Concat(CsvExtra) }.Concat(ranked.Select((r, i) => new[]
        {
            (i + 1).ToString(), r.Tier, Py.Repr(r.Risk), r.Cve, r.Asset.Name, r.Asset.ThirdParty ? "third-party" : "owned",
            Py.Bool(r.F.Kev), Py.Bool(r.F.Ransomware), Py.Repr(r.F.Epss), Py.Repr(r.F.Cvss) is "None" ? "" : Py.Repr(r.F.Cvss),
            Py.Repr(r.Likelihood), Py.Repr(r.Impact), string.Join(";", r.CitedBy), string.Join(";", r.Techniques.Select(t => t.Id)),
            r.Why, r.Summary, string.Join(";", r.Defend.Select(d => $"{d.Tactic}: {d.Name} ({d.Id})")),
            string.Join(";", r.Mitigations.Select(m => $"{m.Name} ({m.Id})")),
            r.Diamond.Adversary, r.Diamond.Capability, r.Diamond.Infrastructure, r.Diamond.Victim, r.Diamond.Phase,
            r.Confidence, r.Exploitation, string.Join(";", r.Evidence.Select(e => $"{e.Signal} [{e.Kind}, {e.Confidence}, {e.Source}]")),
        })));
}
