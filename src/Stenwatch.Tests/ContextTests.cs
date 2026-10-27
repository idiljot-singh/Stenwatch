using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Pillars 8-10: services (business impact), attack paths, compensating controls.</summary>
public class ContextTests
{
    static readonly Profile P = Profile.Load(Path.Combine(Root(), "profile.example.yaml"));
    static readonly DateOnly Today = new(2026, 10, 26);
    static string Root() { for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent) if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return Path.Combine(d.FullName, "examples"); throw new FileNotFoundException(); }

    static Asset A(string name, bool web = false, int crit = 1) => new(name, "cpe:2.3:a:x:" + name, "1", crit, web, false);
    static readonly Technique Entry = new("T1190", "Exploit Public-Facing Application", "initial-access");
    static readonly Technique Lateral = new("T1210", "Exploitation of Remote Services", "lateral-movement");
    static readonly Technique Post = new("T1068", "Exploitation for Privilege Escalation", "privilege-escalation");

    static Threat Threat(params (string cve, Technique t)[] maps)
    {
        var t = new Threat();
        foreach (var (cve, tech) in maps) t.Techniques[cve] = new() { tech };
        return t;
    }

    static Finding F(Asset a, string cve, bool kev = true, double epss = 0.5) =>
        new(a, cve, 9.0, "CWE-1", "d", epss, kev, false, "2026-01-01", 0.9, "2026-02-01");

    // internet -> web (entry) -> app (pivot) -> db (pivot, crown jewel); "lab" is linked from nobody
    static (OrgContext, List<Finding>, Threat) Estate()
    {
        var web = A("web", web: true); var app = A("app"); var db = A("db", crit: 1); var lab = A("lab");
        var ctx = new OrgContext();
        ctx.Links.AddRange(new[] { new Link("web", "app"), new Link("app", "db") });
        ctx.Assets["db"] = new AssetContext("db", "data", "dba", CrownJewel: true);
        var f = new List<Finding> { F(web, "CVE-A"), F(app, "CVE-B"), F(db, "CVE-C"), F(lab, "CVE-D") };
        return (ctx, f, Threat(("CVE-A", Entry), ("CVE-B", Lateral), ("CVE-C", Lateral), ("CVE-D", Entry)));
    }

    [Fact]
    public void NoContext_LeavesScoringUnchanged()
    {
        var (_, f, t) = Estate();
        var plain = Analyse.Rank(f, P, t); var empty = Analyse.Rank(f, P, t, new OrgContext());
        Assert.Equal(plain.Select(r => (r.Cve, r.Risk, r.Tier, r.Why)), empty.Select(r => (r.Cve, r.Risk, r.Tier, r.Why)));
    }

    [Fact]
    public void AttackPath_ReachesCrownJewelThroughLinks_AndNotUnlinkedHosts()
    {
        var (ctx, f, t) = Estate();
        var (ranked, paths) = Analyse.RankWithPaths(f, P, t, ctx, today: Today);
        var path = Assert.Single(paths!.Paths);
        Assert.Equal("db", path.Target); Assert.Equal(new[] { "web", "app", "db" }, path.Hops.Select(h => h.Asset));
        Assert.Equal(path.Hops.Aggregate(1.0, (p, h) => p * h.Likelihood), path.Likelihood, 9);
        Assert.False(paths.Reachable("lab"));        // no link leads to it, and "initial-access" only matters if it is internet-facing
        Assert.Equal(3, paths.Hops["db"]);
        Assert.StartsWith("Internet > web (CVE-A) > app (CVE-B) > db (CVE-C)", path.Describe());
        // db is internal but now reachable: higher exposure than lab, and the reason says so
        var db = ranked.Single(r => r.Cve == "CVE-C"); var lab = ranked.Single(r => r.Cve == "CVE-D");
        Assert.Contains("reachable from the internet in 3 steps", db.Why); Assert.DoesNotContain("reachable", lab.Why);
        Assert.Equal(P.Exposure.Reachable, db.Impact / (9.0 / 10 * 1), 3);
    }

    [Fact]
    public void LocalOnlyVulnerabilities_CannotBeTraversed_AndAttackMappingsDecideThat()
    {
        var (ctx, f, _) = Estate();
        var local = Threat(("CVE-A", Entry), ("CVE-B", Post), ("CVE-C", Lateral), ("CVE-D", Entry)); // app's CVE is post-exploitation only
        Assert.Empty(Analyse.RankWithPaths(f, P, local, ctx, today: Today).Paths!.Paths);
        // ablation: without ATT&CK nothing is known about any CVE, so no path is drawn at all (conservative default)
        var (_, noAttack) = Analyse.RankWithPaths(f, P, Estate().Item3, ctx, new PathOptions(UseAttack: false), Today);
        Assert.Empty(noAttack!.Paths);
        // ... unless unknown vulnerabilities are assumed network-exploitable: paths appear, but only by assumption
        var (_, assumed) = Analyse.RankWithPaths(f, P, Estate().Item3, ctx, new PathOptions(UseAttack: false, UnknownAs: Cap.Network), Today);
        Assert.Single(assumed!.Paths);
        Assert.All(assumed.Paths[0].Hops, h => Assert.StartsWith("no capability evidence", h.Basis));
    }

    [Fact]
    public void CvssVector_DecidesCapabilityWhenPresent()
    {
        var web = A("web", web: true);
        var r = Analyse.Score(F(web, "CVE-V") with { Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }, P, new Threat());
        Assert.Equal(Cap.Network, AttackPaths.Capability(r, new PathOptions()).Cap);
        var l = Analyse.Score(F(web, "CVE-L") with { Vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" }, P, new Threat());
        Assert.Equal(Cap.Local, AttackPaths.Capability(l, new PathOptions()).Cap);
        var auth = Analyse.Score(F(web, "CVE-P") with { Vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" }, P, new Threat());
        Assert.Equal(Cap.Pivot, AttackPaths.Capability(auth, new PathOptions()).Cap); // network but needs a login: not usable from the internet
    }

    [Fact]
    public void ServiceCriticality_ReplacesAssetCriticality_WhenDefined()
    {
        var (ctx, f, t) = Estate();
        var plain = Analyse.Rank(f.Where(x => x.Cve == "CVE-B"), P, t, new OrgContext { Links = ctx.Links })[0];
        var sctx = new OrgContext { Links = ctx.Links, Services = { new Service("Payroll", "HR", 3, "regulated", "GDPR", 4) }, ServiceAssets = { ["Payroll"] = new() { "app" } } };
        var withService = Analyse.Rank(f.Where(x => x.Cve == "CVE-B"), P, t, sctx)[0];
        Assert.True(withService.Impact > plain.Impact); Assert.Contains("supports Payroll (service criticality 3)", withService.Why);
        Assert.Contains(withService.Evidence, e => e.Signal == "service impact" && e.Value.Contains("GDPR"));
    }

    [Fact]
    public void Control_ReducesLikelihoodOnlyWhileEvidenceIsValid_AndNeverHidesConfirmedExploitation()
    {
        var web = A("web", web: true); var f = F(web, "CVE-A"); var t = Threat(("CVE-A", Entry));
        var baseline = Analyse.Score(f, P, t, new OrgContext(), today: Today);
        Control Waf(string date = "2026-09-01", string expires = "", string counters = "T1190") =>
            new("C1", "WAF", "waf", "*", counters, "strong", "pen-test report 2026-09", date, expires);
        double Likelihood(Control c) => Analyse.Score(f, P, t, new OrgContext { Controls = { c } }, today: Today).Likelihood;

        Assert.Equal(baseline.Likelihood * P.Controls.Strong, Likelihood(Waf()), 3);
        Assert.Equal(baseline.Likelihood, Likelihood(Waf(date: "2024-01-01")));            // evidence too old
        Assert.Equal(baseline.Likelihood, Likelihood(Waf(expires: "2026-10-01")));         // expired
        Assert.Equal(baseline.Likelihood, Likelihood(Waf() with { Evidence = "" }));       // installed is not evidence of effectiveness
        Assert.Equal(baseline.Likelihood, Likelihood(Waf(counters: "T9999")));             // does not counter this finding's techniques
        Assert.Equal(baseline.Likelihood, Likelihood(Waf() with { Scope = "zone:dmz" }));  // out of scope

        var controlled = Analyse.Score(f, P, t, new OrgContext { Controls = { Waf() } }, today: Today);
        Assert.Equal("Act", controlled.Tier);                                              // KEV + internet-facing stays Act
        Assert.Contains("verify the control actually blocks it or patch", controlled.Summary);
        Assert.Contains(controlled.Evidence, e => e.Signal == "control");
    }

    [Fact]
    public void ContextStore_RoundTripsAndValidates()
    {
        using var db = Collect.Connect(":memory:");
        ContextStore.EnsureSchema(db);
        using (var tx = db.BeginTransaction()) // as the app's Save context does: one transaction around every row (a nested one used to fail)
        {
            ContextStore.Save(db, new Service("Payroll", "HR", 3, "regulated", "GDPR", 4), new[] { "app", "db" });
            ContextStore.Save(db, new AssetContext("db", "data", "dba", true));
            ContextStore.Save(db, new Link("app", "db", "network", "1433"));
            ContextStore.Save(db, new Control("C1", "WAF", "waf", "zone:dmz", "T1190", "strong", "report", "2026-09-01"));
            tx.Commit();
        }
        var c = ContextStore.Load(db);
        Assert.Equal(new[] { "app", "db" }, c.ServiceAssets["Payroll"]); Assert.True(c.Assets["db"].CrownJewel);
        Assert.Equal("1433", Assert.Single(c.Links).Port); Assert.Equal(3, c.ServiceWeight("db"));
        Assert.Throws<ArgumentException>(() => ContextStore.Save(db, new Service("x", "", 4), Array.Empty<string>()));
        Assert.Throws<ArgumentException>(() => ContextStore.Save(db, new Control("C2", "x", "x", "*", "", "magic")));
        Assert.Throws<ArgumentException>(() => ContextStore.Save(db, new Link("a", "a")));
        ContextStore.Delete(db, "service", "Payroll");
        Assert.Empty(ContextStore.Load(db).Services);
    }
}
