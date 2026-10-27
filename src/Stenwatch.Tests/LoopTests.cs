using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Pillars 13-15: knowledge graph, remediation lifecycle, effectiveness metrics.</summary>
public class LoopTests
{
    static readonly Profile P = Profile.Load(Path.Combine(Root(), "profile.example.yaml"));
    static string Root() { for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent) if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return Path.Combine(d.FullName, "examples"); throw new FileNotFoundException(); }
    static Asset A(string n, bool web = false) => new(n, "cpe:2.3:a:x:" + n, "1", 2, web, false);
    static Ranked R(string cve, Asset a, bool kev = true, string cwe = "CWE-79", double epss = 0.5)
    {
        var f = new Finding(a, cve, 9.0, cwe, "d", epss, kev, false, "2026-01-01", 0.9, "2026-02-01");
        return Analyse.Score(f, P, new Threat());
    }

    // ---------- remediation ----------

    [Fact]
    public void Task_IsCreatedWithSla_VerifiedByRescan_AndReopenedWhenItReturns()
    {
        using var db = Collect.Connect(":memory:");
        var web = A("web", true); var r = R("CVE-1", web);
        Assert.Equal("Act", r.Tier);
        var d1 = new DateOnly(2026, 10, 1);
        var created = Assert.Single(Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 1, d1));
        Assert.Equal("Open", created.State); Assert.Equal("2026-10-03", created.Due); // Act: 48 h
        Assert.Empty(Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 2, d1)); // nothing new on a repeat run: no duplicate task

        Remediation.Assign(db, created.Id, "ops", "TICKET-7");
        Remediation.ClaimFixed(db, created.Id, "patched KB123");
        Assert.Equal("Fixed", Remediation.Load(db)[0].State);              // a claim is not a verification
        var d2 = new DateOnly(2026, 10, 2);
        var back = Assert.Single(Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 3, d2)); // still found by the scan
        Assert.Equal("Reopened", back.State); Assert.Contains("claimed fixed", back.Note);

        var d3 = new DateOnly(2026, 10, 3);
        var done = Assert.Single(Remediation.Sync(db, Array.Empty<Ranked>(), Array.Empty<Ranked>(), P, 4, d3)); // gone from the scan
        Assert.Equal("Verified", done.State); Assert.Equal("2026-10-03", done.Closed);

        var again = Assert.Single(Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 5, new DateOnly(2026, 10, 9)));
        Assert.Equal("Reopened", again.State); Assert.Contains("returned after verification", again.Note);
        Assert.Equal(2, Remediation.Load(db).Count); // the verified task is kept as history
    }

    [Fact]
    public void Decisions_SuppressTasks_AndExpiryBringsThemBack()
    {
        using var db = Collect.Connect(":memory:");
        var r = R("CVE-1", A("web", true)); var day = new DateOnly(2026, 10, 1);
        Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 1, day);
        Assert.Equal("Excepted", Assert.Single(Remediation.Sync(db, Array.Empty<Ranked>(), new[] { r }, P, 2, day)).State);
        Assert.Equal("Open", Assert.Single(Remediation.Sync(db, new[] { r }, Array.Empty<Ranked>(), P, 3, day)).State);
    }

    [Fact]
    public void TierSlaAndOverdue()
    {
        using var db = Collect.Connect(":memory:");
        var attend = R("CVE-2", A("lab"), kev: false, epss: 0.2);
        Assert.Equal("Attend", attend.Tier);
        var t = Assert.Single(Remediation.Sync(db, new[] { attend }, Array.Empty<Ranked>(), P, 1, new DateOnly(2026, 10, 1)));
        Assert.Equal("2026-10-31", t.Due); Assert.True(t.Overdue(new DateOnly(2026, 11, 1))); Assert.False(t.Overdue(new DateOnly(2026, 10, 31)));
    }

    [Fact]
    public void OpsMetrics_CountOnlyVerifiedWork()
    {
        var day = new DateOnly(2026, 10, 20);
        RemediationTask T(long id, string state, string opened, string due, string closed, string tier = "Act", string note = "") =>
            new(id, "CVE-" + id, "a", state, tier, "", "", opened, due, closed, note);
        var tasks = new[] { T(1, "Verified", "2026-10-01", "2026-10-03", "2026-10-02"), T(2, "Verified", "2026-10-01", "2026-10-03", "2026-10-09"),
            T(3, "Open", "2026-10-01", "2026-10-03", ""), T(4, "Reopened", "2026-10-01", "2026-10-03", "", note: "claimed fixed, but the next scan still finds it") };
        var m = Effectiveness.Ops(tasks, day);
        Assert.Equal(2, m.Verified); Assert.Equal(4.5, m.MedianDaysToVerify); Assert.Equal(0.5, m.SlaCompliance);
        Assert.Equal(2.0 / 3, m.VerifiedClosureRate!.Value, 3); Assert.Equal(2, m.Overdue); // open + reopened are past due; unverified work is not averaged in
    }

    // ---------- ranking metrics ----------

    static List<Candidate> Population(int n = 400)
    {
        var rnd = new Random(1); var l = new List<Candidate>();
        for (int i = 0; i < n; i++)
        {
            double signal = rnd.NextDouble(); bool pos = rnd.NextDouble() < 0.05 + 0.5 * signal * signal * signal;
            l.Add(new($"C{i}", pos, new() { ["signal"] = signal, ["noise"] = rnd.NextDouble() }));
        }
        return l;
    }

    [Fact]
    public void Metrics_RewardARealSignal_AndNotNoise()
    {
        var c = Population();
        var good = Metrics.Evaluate(c, "signal", x => x.X["signal"], new[] { 40 });
        var bad = Metrics.Evaluate(c, "noise", x => x.X["noise"], new[] { 40 });
        Assert.True(good.AveragePrecision > bad.AveragePrecision + 0.05);
        Assert.True(good.AtN[40].Coverage > bad.AtN[40].Coverage); Assert.Equal(0.1, good.AtN[40].Effort, 6);
        Assert.Equal(good.AveragePrecision, Metrics.AveragePrecision(c, x => x.X["signal"]), 12); // deterministic across reruns
    }

    [Fact]
    public void Bootstrap_SeparatesRealLiftFromNoLift()
    {
        var c = Population();
        var real = Metrics.PairedBootstrap(c, x => x.X["signal"], x => x.X["noise"]);
        Assert.True(real.Low > 0 && real.PNotBetter < 0.05);
        // adding pure noise to a good scorer is not a lift: the interval spans zero
        var none = Metrics.PairedBootstrap(c, x => x.X["signal"] + 1e-9 * x.X["noise"], x => x.X["signal"]);
        Assert.True(none.Low <= 0 && none.High >= 0);
    }

    [Fact]
    public void Brier_PenalisesOverconfidence()
    {
        var c = Population();
        double Calibrated(Candidate x) => 0.05 + 0.5 * Math.Pow(x.X["signal"], 3);
        Assert.True(Metrics.Brier(c, Calibrated) < Metrics.Brier(c, x => x.X["signal"] > 0.5 ? 1.0 : 0.0));
    }

    // ---------- knowledge graph ----------

    [Fact]
    public void Graph_AnswersQuestionsThatCrossSeveralTables()
    {
        using var db = Collect.Connect(":memory:");
        void Run(string sql) { using var c = db.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }
        Run("INSERT INTO technique VALUES ('T1190','Exploit Public-Facing Application','initial-access')");
        Run("INSERT INTO actor VALUES ('G0007','APT28','')"); Run("INSERT INTO actor VALUES ('G0016','APT29','')");
        Run("INSERT INTO actor_technique VALUES ('G0016','T1190')");   // APT29 uses the technique
        Run("INSERT INTO actor_cve VALUES ('G0007','CVE-1')");          // APT28's ATT&CK text names CVE-1
        Run("INSERT INTO cve_technique VALUES ('CVE-2','T1190','exploitation_technique')");
        Run("INSERT INTO mitigation VALUES ('T1190','M1051','Update Software')");
        var web = A("web", true); var app = A("app");
        var ranked = new[] { R("CVE-1", web, cwe: "CWE-79"), R("CVE-2", app, cwe: "CWE-79"), R("CVE-3", app, cwe: "CWE-89") };
        var ctx = new OrgContext { Links = { new Link("web", "app") }, Services = { new Service("Shop", "ops", 3) }, ServiceAssets = { ["Shop"] = new() { "web" } } };
        var g = Knowledge.Build(db, ranked, ctx);

        var apt28 = g.AssetsHitBy("G0007");  // reported directly
        Assert.Equal(new[] { ("web", "CVE-1", "reported") }, apt28);
        var apt29 = g.AssetsHitBy("G0016");  // only through a shared technique: weaker, and labelled that way
        Assert.Equal(new[] { ("app", "CVE-2", "technique") }, apt29);
        Assert.Equal(new[] { ("app", "CVE-2"), ("web", "CVE-1") }, g.SharedWeakness("CWE-79"));
        Assert.Equal(new[] { ("web", "CVE-1") }, g.SharedWeakness("CWE-79", a => a == "web"));
        var chain = g.Connect("service:Shop", "mitigation:M1051")!;
        Assert.Equal(new[] { "service:Shop", "asset:web", "asset:app", "cve:CVE-2", "technique:T1190", "mitigation:M1051" }, chain.Select(x => x.Item1.Key));
        Assert.Null(g.Connect("service:Shop", "actor:G0099"));
        Assert.Contains(g.Neighbours("technique:T1190").Select(n => n.Node.Key), k => k == "actor:G0016");
    }
}
