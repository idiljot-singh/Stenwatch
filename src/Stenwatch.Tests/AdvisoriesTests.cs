using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Advisories: reading NCSC-FI's feed, matching by CVE id then by product name, Finnish urgency words, and the ladder's use of them. Offline.</summary>
public class AdvisoriesTests
{
    const string Feed = @"<?xml version=""1.0""?><rss version=""2.0""><channel>
<item><title>Pre-boot RCE in EDK II PXE driver</title><link>https://x/edk2</link><pubDate>Wed, 28 Oct 2026 05:00:00 +0200</pubDate>
 <description><![CDATA[ Classification: Critical, Solution: Official Fix, Exploit Maturity: Functional, CVSSv3.1: 9.5, CVEs: CVE-2026-1001, Summary: A flaw. ]]></description></item>
<item><title>Mozilla Foundation Security Advisories</title><link>https://x/mfsa</link><pubDate>Tue, 27 Oct 2026 05:00:00 +0200</pubDate>
 <description><![CDATA[ Classification: Severe, Solution: Official Fix, Exploit Maturity: Not Defined, CVSSv3.1: None, CVEs: , Summary: Security Vulnerabilities fixed in Thunderbird 153.6 ]]></description></item>
<item><title>Some other product</title><link>https://x/other</link><pubDate>Tue, 27 Oct 2026 05:00:00 +0200</pubDate>
 <description><![CDATA[ Classification: Critical, Exploit Maturity: Not Defined, CVEs: CVE-2026-5555, Summary: Not ours. ]]></description></item>
</channel></rss>";

    static readonly DateOnly Today = new(2026, 10, 29);

    static List<DefenderRow> Rows() => new()
    {
        new("CVE-2026-1001", "High", 8.8, 0.003, 30, false, new[] { "Microsoft Edge" }, 150, "fixed prior to 148.0.1"),
        new("CVE-2026-1002", "Medium", 6.5, 0.003, 10, false, new[] { "Mozilla Thunderbird" }, 40, "fixed in 151"),
    };

    [Fact]
    public void ParseRss_ReadsCvesAndExploitMaturity()
    {
        var a = Advisories.ParseRss(Feed, "NCSC-FI");
        Assert.Equal(3, a.Count);
        Assert.Equal(new[] { "CVE-2026-1001" }, a[0].Cves);
        Assert.True(a[0].ExploitExists);
        Assert.Empty(a[1].Cves);
        Assert.Equal("2026-10-28", a[0].Published);
    }

    [Fact]
    public void Match_ByCveId_ThenByProductName_AndNeverByProductWhenTheAdvisoryNamesOtherCves()
    {
        var ad = Advisories.ParseRss(Feed, "NCSC-FI");
        var edge = Advisories.For("Microsoft Edge", new[] { "CVE-2026-1001" }, ad, Today);
        Assert.Single(edge); Assert.True(edge[0].ByCve);
        var tb = Advisories.For("Mozilla Thunderbird", new[] { "CVE-2026-1002" }, ad, Today);
        Assert.Single(tb); Assert.False(tb[0].ByCve);                       // no CVE id in the advisory: product name matched
        Assert.Empty(Advisories.For("Microsoft Edge", new[] { "CVE-2026-9999" }, ad, Today)); // other-product advisory with its own CVEs is not ours
    }

    [Fact]
    public void FinnishAndEnglishUrgencyWords_MeanActivelyExploited()
    {
        Assert.True(new Advisory("x", "t", "l", "", "Haavoittuvuutta hyödynnetään aktiivisesti hyökkäyksissä", new(), "").ActivelyExploited);
        Assert.True(new Advisory("x", "t", "l", "", "Google confirms it is exploited in the wild", new(), "").ActivelyExploited);
        Assert.False(new Advisory("x", "t", "l", "", "Päivitä Firefox kun ehdit", new(), "").ActivelyExploited);
    }

    [Fact]
    public void Ladder_AdvisoryWithExploit_RaisesToAttend_ActiveExploitationToAct_AndStaleAdvisoriesAreIgnored()
    {
        var ad = Advisories.ParseRss(Feed, "NCSC-FI");
        var a = DefenderTriage.Rank(Rows(), null, null, ad, Today);
        var edge = a.Single(x => x.Product == "Microsoft Edge");
        Assert.Equal("Attend", edge.Tier); Assert.Contains("NCSC-FI", edge.Feeds); Assert.Contains("working exploit", edge.Rule);
        var tb = a.Single(x => x.Product == "Mozilla Thunderbird");
        Assert.Equal("Attend", tb.Tier); Assert.Contains("matched by product name only", tb.Rule);

        var hot = ad.Append(new Advisory("Pasted", "Kriittinen Edge-haavoittuvuus", "mail", "2026-10-28", "Microsoft Edge: haavoittuvuutta hyödynnetään aktiivisesti", new(), "")).ToList();
        Assert.Equal("Act", DefenderTriage.Rank(Rows(), null, null, hot, Today).Single(x => x.Product == "Microsoft Edge").Tier);

        var stale = DefenderTriage.Rank(Rows(), null, null, ad, new DateOnly(2026, 12, 31)).Single(x => x.Product == "Microsoft Edge");
        Assert.DoesNotContain("NCSC-FI", stale.Feeds); Assert.DoesNotContain("NCSC-FI", stale.Rule); // old advisories no longer count (Attend here is the exposure rule)
    }

    [Fact]
    public void Briefing_ListsAdvisoriesThatMatchedNothing()
    {
        var ad = Advisories.ParseRss(Feed, "NCSC-FI");
        var actions = DefenderTriage.Rank(Rows(), null, null, ad, Today);
        var un = DefenderTriage.Unmatched(actions, ad, Today);
        Assert.Equal("Some other product", Assert.Single(un).Title);
        Assert.Contains("Some other product", DefenderTriage.Html(actions, new(false, "", new(), new(), new()), "x", Today, un));
    }

    [Fact]
    public void FromText_UsesSubjectAsTitle_AndFindsCveIds()
    {
        var f = Path.GetTempFileName();
        File.WriteAllText(f, "From: cert@example.fi\nSubject: Kriittinen haavoittuvuus Edgessä\n\nCVE-2026-1001 ja cve-2026-1002 hyödynnetään aktiivisesti.");
        var a = Advisories.FromText(f);
        Assert.Equal("Kriittinen haavoittuvuus Edgessä", a.Title);
        Assert.Equal(new[] { "CVE-2026-1001", "CVE-2026-1002" }, a.Cves);
        Assert.True(a.ActivelyExploited);
    }

    [Fact]
    public async Task Refresh_KeepsStoredAdvisories_WhenTheFeedIsDown()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        File.WriteAllText(Path.Combine(dir, "advisories.json"), System.Text.Json.JsonSerializer.Serialize(Advisories.ParseRss(Feed, "NCSC-FI")));
        var (all, note) = await Advisories.Refresh(dir, new HttpClient(new Down()), new[] { new Source("Test", "rss", "https://example.invalid/feed") });
        Assert.Equal(3, all.Count); Assert.Contains("not reachable", note);
    }

    class Down : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken c) => throw new HttpRequestException("offline");
    }
}
