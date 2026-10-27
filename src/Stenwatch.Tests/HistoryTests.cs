using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

public class HistoryTests
{
    static readonly Profile P = Profile.Load(Path.Combine(Root(), "profile.example.yaml"));
    static string Root() { for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent) if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return Path.Combine(d.FullName, "examples"); throw new FileNotFoundException(); }

    static Finding F(bool kev = false, double epss = 0.02) =>
        new(new Asset("mail", "cpe:2.3:a:microsoft:exchange_server", "2019", 3, true, false), "CVE-2021-26855", 9.1, "CWE-918", "x", epss, kev, false, "2021-03-03", 0.5, kev ? "2026-10-20" : "");

    static Ranked R(Finding f) => Analyse.Rank(new[] { f }, P, new Threat())[0];

    [Fact]
    public void SameInputs_NoEvents_AndNoDuplicateRows()
    {
        using var db = Collect.Connect(":memory:");
        History.Record(db, new[] { R(F()) }, Array.Empty<Ranked>());
        var (run, events) = History.Record(db, new[] { R(F()) }, Array.Empty<Ranked>());
        Assert.Equal(2, run); Assert.Empty(events);
        using var c = db.CreateCommand(); c.CommandText = "SELECT COUNT(*) FROM finding_history GROUP BY run"; using var r = c.ExecuteReader();
        while (r.Read()) Assert.Equal(1, r.GetInt64(0));
    }

    [Fact]
    public void EnteringKev_RaisesTierWithReason_AndFixingItResolves()
    {
        using var db = Collect.Connect(":memory:");
        History.Record(db, new[] { R(F()) }, Array.Empty<Ranked>());
        var (_, up) = History.Record(db, new[] { R(F(kev: true, epss: 0.60)) }, Array.Empty<Ranked>());
        Assert.Contains(up, e => e.Kind == "entered_kev");
        Assert.Contains(up, e => e.Kind == "epss_jump" && e.Detail == "EPSS 0.02 to 0.60");
        var tier = Assert.Single(up, e => e.Kind == "tier_up");
        Assert.StartsWith("Track to Act: ", tier.Detail); Assert.Contains("entered KEV", tier.Detail);
        var (_, gone) = History.Record(db, Array.Empty<Ranked>(), Array.Empty<Ranked>());
        Assert.Equal("resolved", Assert.Single(gone).Kind); // the verification signal for remediation (pillar 14)
        Assert.Equal("resolved", Assert.Single(History.Events(db)).Kind);
    }

    [Fact]
    public void Decisions_AreTrackedBothWays()
    {
        using var db = Collect.Connect(":memory:");
        var r = R(F(kev: true));
        History.Record(db, new[] { r }, Array.Empty<Ranked>());
        Assert.Equal("decision_applied", Assert.Single(History.Record(db, Array.Empty<Ranked>(), new[] { r }).Events, e => e.Kind != "resolved").Kind);
        Assert.Equal("decision_expired", Assert.Single(History.Record(db, new[] { r }, Array.Empty<Ranked>()).Events).Kind);
    }

    [Fact]
    public void Evidence_SeparatesObservedFromPredicted_AndAbsenceIsUnknownNotSafe()
    {
        var kev = R(F(kev: true)); var quiet = R(F(epss: 0.001));
        Assert.Contains(kev.Evidence, e => e.Signal == "KEV" && e.Kind == "observed");
        Assert.Contains(quiet.Evidence, e => e.Signal == "EPSS" && e.Kind == "predicted");
        Assert.DoesNotContain(quiet.Evidence, e => e.Kind == "observed");
        Assert.StartsWith("unknown:", quiet.Exploitation); Assert.Contains("not evidence of safety", quiet.Exploitation);
        Assert.Equal("High", kev.Confidence); Assert.Equal("Medium", quiet.Confidence);
        var noVersion = R(F(kev: true) with { Asset = F().Asset with { Version = "" } });
        Assert.Equal("Medium", noVersion.Confidence); // a filled-in assumption lowers confidence
        Assert.True(EvidenceOf.IsStale("2026-01-01T00:00:00Z", DateTimeOffset.Parse("2026-10-26T00:00:00Z")));
    }
}
