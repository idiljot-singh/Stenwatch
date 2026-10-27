using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Checks the evaluation tooling itself. The chains below are SYNTHETIC fixtures that exercise the code; they are not evidence about ATT&amp;CK.</summary>
public class EvaluationTests
{
    static readonly Profile P = Profile.Load(Path.Combine(Root(), "profile.example.yaml"));
    static string Root() { for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent) if (File.Exists(Path.Combine(d.FullName, "examples", "profile.example.yaml"))) return Path.Combine(d.FullName, "examples"); throw new FileNotFoundException(); }

    static string Chains(string source = "https://example.org/synthetic")
    {
        var path = Path.Combine(Path.GetTempPath(), $"chains-{Guid.NewGuid():N}.csv");
        string H = "chain_id,source_url,kind,order,asset,cve,internet_facing,tactics,vector,linked_from\n";
        var rows = new System.Text.StringBuilder(H);
        for (int c = 1; c <= 5; c++)   // web (initial access) > app (lateral) > db (lateral); plus a distractor host reachable from web with a local-only bug
        {
            rows.AppendLine($"c{c},{source},step,1,web{c},CVE-{c}-1,y,initial-access,,");
            rows.AppendLine($"c{c},{source},step,2,app{c},CVE-{c}-2,n,lateral-movement,,");
            rows.AppendLine($"c{c},{source},step,3,db{c},CVE-{c}-3,n,lateral-movement,,");
            rows.AppendLine($"c{c},{source},distractor,0,decoy{c},CVE-{c}-9,n,privilege-escalation,,web{c}");
        }
        File.WriteAllText(path, rows.ToString());
        return path;
    }

    [Fact]
    public void ChainEval_AttackMappingsFindTheDocumentedPath_WhereNothingKnownFindsNone()
    {
        var r = ChainEval.Run(Chains(), P);
        double Recall(string v) => r.Where(x => x.Variant == v).Average(x => x.Recall);
        Assert.Equal(1.0, Recall("ATT&CK only"), 6);          // tactics say web is an entry and app/db can be pivoted through
        Assert.Equal(0.0, Recall("vector only"), 6);          // no vectors in the fixture: nothing is known
        Assert.Contains("**Validated**", ChainEval.Report(r)); // synthetic fixture: proves the arithmetic, not the claim
        var assumed = r.Where(x => x.Variant == "assume network-exploitable").ToList();
        Assert.All(assumed, x => Assert.True(x.Found));
    }

    [Fact]
    public void ChainEval_RefusesUnsourcedChains_AndWontReportOnFewerThanFive()
    {
        Assert.Throws<InvalidDataException>(() => ChainEval.Run(Chains(source: ""), P));
        var one = Path.Combine(Path.GetTempPath(), $"chains-{Guid.NewGuid():N}.csv");
        File.WriteAllText(one, "chain_id,source_url,kind,order,asset,cve,internet_facing,tactics,vector,linked_from\nc1,https://x,step,1,web,CVE-1,y,initial-access,,\nc1,https://x,step,2,db,CVE-2,n,lateral-movement,,\n");
        Assert.Contains("**Not run.**", ChainEval.Report(ChainEval.Run(one, P)));
    }

    [Fact]
    public void RatingSheet_IsBlind_Reproducible_AndNeedsThirtyRatings()
    {
        var web = new Asset("web", "cpe:2.3:a:x:web", "1", 2, true, false);
        var threat = new Threat();
        for (int i = 0; i < 40; i++)
        {
            threat.Techniques[$"CVE-{i}"] = new() { new Technique("T1190", "Exploit", "initial-access") };
        }
        threat.Defend["T1190"] = new() { new Defend("D3-NTF", "Network Traffic Filtering", "Isolate") };
        threat.Mitigations["T1190"] = new() { new Mitigation("M1051", "Update Software") };
        var ranked = Enumerable.Range(0, 40).Select(i => Analyse.Score(new Finding(web, $"CVE-{i}", 9.0, "", "d", 0.9, true, false, "", null, ""), P, threat)).ToList();
        var dir = Path.Combine(Path.GetTempPath(), $"rate-{Guid.NewGuid():N}"); Directory.CreateDirectory(dir);
        Assert.Equal(30, RatingSheet.Export(ranked, Path.Combine(dir, "s.csv"), Path.Combine(dir, "k.csv")));
        RatingSheet.Export(ranked, Path.Combine(dir, "s2.csv"), Path.Combine(dir, "k2.csv"));
        Assert.Equal(File.ReadAllText(Path.Combine(dir, "s.csv")), File.ReadAllText(Path.Combine(dir, "s2.csv")));
        Assert.DoesNotContain("specific", File.ReadAllText(Path.Combine(dir, "s.csv"))); // the sheet never says which list is which
        Assert.Equal("Not run", RatingSheet.Import(Path.Combine(dir, "s.csv"), Path.Combine(dir, "k.csv")).Label); // blank ratings

        var key = Csv.ReadDict(Path.Combine(dir, "k.csv")).ToDictionary(r => r["id"], r => r["list_1_is"]);
        var rated = new List<IEnumerable<string>> { new[] { "id", "cve", "asset_type", "list_1", "list_2", "rating_1", "rating_2" } };
        foreach (var r in Csv.ReadDict(Path.Combine(dir, "s.csv")))
            rated.Add(new[] { r["id"], r["cve"], r["asset_type"], r["list_1"], r["list_2"], key[r["id"]] == "specific" ? "5" : "2", key[r["id"]] == "specific" ? "2" : "5" });
        Csv.Write(Path.Combine(dir, "done.csv"), rated);
        var res = RatingSheet.Import(Path.Combine(dir, "done.csv"), Path.Combine(dir, "k.csv"));
        Assert.Equal(("Validated", 30), (res.Label, res.Rated)); Assert.Equal(5.0, res.Specific); Assert.Equal(2.0, res.Generic);
    }
}
