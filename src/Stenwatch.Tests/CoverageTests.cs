using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Exposure rows (ladder, per-component files) and Coverage (status worked out from a data folder). Offline, in a temp folder.</summary>
public class CoverageTests : IDisposable
{
    readonly string dir = Directory.CreateTempSubdirectory("stenwatch-cov").FullName;
    public void Dispose() => Directory.Delete(dir, true);

    static Exposure E(string sev, string evidence = "", string id = "X-1") => new("Web apps", "portal", id, "SQL injection", sev, evidence, "ZAP", "2026-11-01");

    [Theory]
    [InlineData("Medium", "listed in CISA KEV", "Act")]
    [InlineData("High", "reachable from the internet", "Attend")]
    [InlineData("Critical", "", "Attend")]
    [InlineData("8.1", "", "Track")]
    [InlineData("Low", "internet-facing", "Ignore")]
    [InlineData("", "", "Ignore")]
    public void Ladder_SetsTierAndNamesTheRule(string sev, string evidence, string tier)
    {
        var r = Exposure.Rank(E(sev, evidence));
        Assert.Equal(tier, r.Tier); Assert.NotEqual("", r.Rule);
    }

    [Fact]
    public void SaveAndLoad_PerComponent_RanksOnTheWayIn_AndIgnoresAHandEditedTier()
    {
        Exposure.Save(dir, "Web apps", new[] { E("High", "public login page") with { Tier = "Ignore" }, E("Low", id: "X-2") });
        Exposure.Save(dir, "End-of-life software", new[] { new Exposure("", "srv1", "eol:windows-server-2012", "Windows Server 2012", "High", "out of support", "endoflife.date", "2026-10-31") });
        Assert.True(File.Exists(Path.Combine(dir, "exposures", "end-of-life-software.csv")));
        var all = Exposure.Load(dir);
        Assert.Equal(3, all.Count);
        Assert.Equal("Attend", all.Single(e => e.ItemId == "X-1").Tier);
        Assert.Equal("End-of-life software", all.Single(e => e.Asset == "srv1").Component);
        Assert.Equal(2, Exposure.Load(dir, "Web apps").Count);
        Exposure.Save(dir, "Web apps", new[] { E("Low") }); // an import replaces the previous one
        Assert.Single(Exposure.Load(dir, "Web apps"));
    }

    [Fact]
    public void EmptyFolder_EveryComponentNotConnected_AndNamesTheExportItNeeds()
    {
        var all = Coverage.Of(dir);
        Assert.Equal(14, all.Count);
        Assert.All(all, c => Assert.Contains(c.Component.Group, Coverage.Groups));
        Assert.All(all, c => Assert.Equal(Coverage.NotConnected, c.Status));
        Assert.Contains("Defender for Cloud", all.Single(c => c.Component.Name == "Cloud workloads").Note);
    }

    [Fact]
    public void FilesInTheFolder_ConnectTheirComponents()
    {
        File.WriteAllText(Path.Combine(dir, "assets.csv"), "name,cpe,version,criticality,internet_facing\nmail,cpe:2.3:a:microsoft:exchange_server,2019,3,y\nfiles,cpe:2.3:o:microsoft:windows_server_2019,,2,n\n");
        Directory.CreateDirectory(Path.Combine(dir, "triage-history"));
        File.WriteAllText(Path.Combine(dir, "triage-history", "2026-11-02.json"), "{\"Microsoft Edge\":\"Act\",\"7-Zip\":\"Attend\"}");
        Exposure.Save(dir, "Cloud workloads", new[] { new Exposure("", "vm1", "rec-1", "Disk not encrypted", "Medium", "", "Defender for Cloud", "2026-11-01") });
        var s = Coverage.Of(dir).ToDictionary(c => c.Component.Name);
        Assert.Equal((Coverage.Connected, 2), (s["Assets"].Status, s["Assets"].Count));
        Assert.Equal((Coverage.Partly, 1), (s["Attack surface"].Status, s["Attack surface"].Count));
        Assert.Equal((Coverage.Connected, 2, "2026-11-02"), (s["Vulnerabilities"].Status, s["Vulnerabilities"].Count, s["Vulnerabilities"].LastImport));
        Assert.Equal((Coverage.Connected, 1), (s["Cloud workloads"].Status, s["Cloud workloads"].Count));
        Assert.Equal(Coverage.NotConnected, s["Web apps"].Status);
    }

    [Fact]
    public void UnconvertedInventory_NeedsAttention()
    {
        File.WriteAllText(Path.Combine(dir, "assets.csv"), "hostname,vendor,product,version\npc1,Mozilla,Firefox,128\n");
        Assert.Equal(Coverage.Attention, Coverage.Of(dir).Single(c => c.Component.Name == "Assets").Status);
    }
}
