using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

public class ThreatProfileAutoTests
{
    static string Root() { for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent) if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return Path.Combine(d.FullName, "examples"); throw new FileNotFoundException(); }
    static Profile Base(string sector = "Finance", string country = "Finland", string mode = "auto")
    {
        var p = Profile.Load(Path.Combine(Root(), "profile.example.yaml"));
        p.Organisation.Sector = sector; p.Organisation.Country = country; p.Targeting.Mode = mode; p.ThreatGroups = new() { ["G0007"] = "APT28" };
        return p;
    }

    static Microsoft.Data.Sqlite.SqliteConnection Db()
    {
        var db = Collect.Connect(":memory:");
        void Add(string id, string name, string desc, string modified, string lastSeen)
        {
            foreach (var sql in new[] { $"INSERT INTO actor VALUES ('{id}','{name}','')", $"INSERT INTO actor_profile VALUES ('{id}','{desc}','{modified}','{lastSeen}')" })
            { using var c = db.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }
        }
        Add("G0007", "APT28", "Russia-based espionage against government", "2025-01-01T00:00:00Z", "");
        Add("G1", "BankHunters", "targets banks and financial institutions in Finland and the Nordic region", "2025-06-01T00:00:00Z", "2026-03-01T00:00:00Z");
        Add("G2", "ReefCrew", "a ransomware group that attacks hospitals and manufacturers worldwide", "2026-05-01T00:00:00Z", "2026-01-01T00:00:00Z");
        Add("G3", "OldTimers", "targeted financial institutions in Finland", "2019-01-01T00:00:00Z", "2019-06-01T00:00:00Z");
        Add("G4", "FarEast", "espionage against universities in Japan", "2026-02-01T00:00:00Z", "2026-02-01T00:00:00Z");
        return db;
    }

    [Fact]
    public void ManualMode_ChangesNothing()
    {
        using var db = Db(); var p = Base(mode: "manual");
        var (eff, picks, note) = ThreatProfileAuto.Effective(p, db);
        Assert.Same(p, eff); Assert.Equal("G0007", Assert.Single(picks).Id); Assert.StartsWith("manual", note);
    }

    [Fact]
    public void AutoMode_PicksBySectorCountryRansomwareAndRecency_AndExplainsWhy()
    {
        using var db = Db(); var today = new DateOnly(2026, 10, 26);
        var (eff, picks, _) = ThreatProfileAuto.Effective(Base(), db, today);
        var ids = picks.Select(x => x.Id).ToList();
        Assert.Equal(new[] { "G0007", "G1" }, ids);                               // pinned first, then by score; ReefCrew (ransomware + recent only = 4) is below the default minimum of 6
        Assert.DoesNotContain("G3", ids);                                         // matches sector and country but silent since 2019: no sign of recent activity, so never auto-picked
        Assert.DoesNotContain("G4", ids);                                         // espionage against another sector and country
        var bank = picks.Single(x => x.Id == "G1");
        Assert.Equal(3 + 3 + 2, bank.Score); Assert.Contains(bank.Reasons, r => r.Contains("finance")); Assert.Contains(bank.Reasons, r => r.StartsWith("names finland"));
        Assert.Equal(new[] { "G0007", "G1" }.Order(), eff.ThreatGroups.Keys.Order());            // the profile that scoring actually uses
        var loose = Base(); loose.Targeting.MinScore = 4;
        var looseIds = ThreatProfileAuto.Effective(loose, db, today).Picks;
        Assert.Contains(looseIds.Single(x => x.Id == "G2").Reasons, r => r.Contains("ransomware"));  // ransomware applies to any sector
    }

    [Fact]
    public void Include_Exclude_MaxGroups_AndPinnedAreRespected()
    {
        using var db = Db(); var today = new DateOnly(2026, 10, 26);
        var p = Base(); p.Targeting.Exclude.Add("G1"); p.Targeting.Include.Add("G4");
        var ids = ThreatProfileAuto.Effective(p, db, today).Picks.Select(x => x.Id).ToList();
        Assert.DoesNotContain("G1", ids); Assert.Contains("G4", ids); Assert.Contains("G0007", ids);
        var one = Base(); one.Targeting.MaxGroups = 1;
        Assert.Equal(2, ThreatProfileAuto.Effective(one, db, today).Picks.Count); // the pinned group plus the single best
    }

    [Fact]
    public void WithoutAttackGroupText_FallsBackToPinnedAndSaysWhy()
    {
        using var empty = Collect.Connect(":memory:");
        var (eff, picks, note) = ThreatProfileAuto.Effective(Base(), empty);
        Assert.Single(picks); Assert.Contains("sync feeds", note); Assert.Equal(1, eff.ThreatGroups.Count);
    }

    [Fact]
    public void FreeTextSectors_MapToCanonicalOnes_AndCountriesToRegions()
    {
        Assert.Contains("manufacturing", ThreatProfileAuto.SectorsOf(new[] { "Engineering and design" }));
        Assert.Contains("healthcare", ThreatProfileAuto.SectorsOf(new[] { "Hospital services" }));
        Assert.Empty(ThreatProfileAuto.SectorsOf(new[] { "Example sector" }));
        using var db = Db();
        var regionOnly = ThreatProfileAuto.Score(Base(country: "Sweden"), new[] { ("G9", "Nordic", "attacks banks across the nordic region", "", "2026-06-01T00:00:00Z") }, new DateOnly(2026, 10, 26));
        Assert.Contains(regionOnly[0].Reasons, r => r.Contains("region of sweden"));
    }

    [Fact]
    public void Store_AndMarkdown_RecordTheReasons()
    {
        using var db = Db(); var p = Base();
        var (eff, picks, note) = ThreatProfileAuto.Effective(p, db, new DateOnly(2026, 10, 26));
        ThreatProfileAuto.Store(db, picks);
        using var c = db.CreateCommand(); c.CommandText = "SELECT COUNT(*) FROM profile_group"; Assert.Equal((long)picks.Count, c.ExecuteScalar());
        var md = ThreatProfileAuto.Markdown(eff, picks, note);
        Assert.Contains("**Proposed**", md); Assert.Contains("BankHunters", md); Assert.Contains("described as targeting finance", md);
    }

    [Fact]
    public void ParseActorProfiles_StripsLinksAndFindsLatestCampaign()
    {
        string R(string id) => $@"[{{""source_name"": ""mitre-attack"", ""external_id"": ""{id}""}}]";
        var objs = System.Text.Json.JsonDocument.Parse($@"[
          {{""type"":""intrusion-set"",""id"":""is--1"",""name"":""X"",""description"":""[X](https://attack.mitre.org/groups/G1) targets banks."",""modified"":""2026-01-01T00:00:00Z"",""external_references"":{R("G1")}}},
          {{""type"":""campaign"",""id"":""c--1"",""name"":""C1"",""last_seen"":""2025-05-01T00:00:00Z"",""external_references"":{R("C1")}}},
          {{""type"":""campaign"",""id"":""c--2"",""name"":""C2"",""last_seen"":""2026-02-01T00:00:00Z"",""external_references"":{R("C2")}}},
          {{""type"":""relationship"",""id"":""r--1"",""relationship_type"":""attributed-to"",""source_ref"":""c--1"",""target_ref"":""is--1""}},
          {{""type"":""relationship"",""id"":""r--2"",""relationship_type"":""attributed-to"",""source_ref"":""c--2"",""target_ref"":""is--1""}}]").RootElement.EnumerateArray().ToList();
        var row = Assert.Single(Collect.ParseActorProfiles(objs));
        Assert.Equal(("G1", "X targets banks.", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"), row);
    }
}
