using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;
using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Sources, graded evidence, threat groups from ATT&amp;CK, the cited intel card and the TLP gate. Offline.</summary>
public class IntelTests
{
    static readonly DateOnly Today = new(2026, 10, 29);
    static DefenderRow Row(string cve, string product) => new(cve, "High", 8.8, 0.003, 30, false, new[] { product }, 50, "fixed prior to 148.0.1");

    [Fact]
    public void ParseAtom_ReadsChromeStylePosts()
    {
        var xml = "<feed xmlns=\"http://www.w3.org/2005/Atom\"><entry><title>Stable Channel Update for Desktop</title><published>2026-10-28T10:00:00Z</published>" +
            "<link rel=\"alternate\" href=\"https://x/post\"/><content type=\"html\">&lt;p&gt;[$N/A][CVE-2026-1001] High. Google is aware that an exploit for CVE-2026-1001 exists in the wild.&lt;/p&gt;</content></entry>" +
            "<entry><title>Chrome Beta for Android</title><published>2026-10-28T10:00:00Z</published><content>no ids</content></entry></feed>";
        var a = Sources.ParseAtom(xml, "Chrome Releases");
        Assert.Equal(2, a.Count); Assert.Equal(new[] { "CVE-2026-1001" }, a[0].Cves); Assert.True(a[0].ActivelyExploited);
        Assert.Equal("https://x/post", a[0].Link); Assert.Equal("2026-10-28", a[0].Published);
    }

    [Fact]
    public void ParseCvrf_KeepsOnlyCvesMicrosoftMarksExploited()
    {
        var json = "{\"DocumentTracking\":{\"InitialReleaseDate\":\"2026-10-13T07:00:00\"},\"Vulnerability\":[" +
            "{\"CVE\":\"CVE-2026-1001\",\"Title\":{\"Value\":\"Windows Shell Security Feature Bypass\"},\"Threats\":[{\"Description\":{\"Value\":\"Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected\"},\"Type\":1}]}," +
            "{\"CVE\":\"CVE-2026-1002\",\"Title\":{\"Value\":\"Other\"},\"Threats\":[{\"Description\":{\"Value\":\"Publicly Disclosed:No;Exploited:No\"},\"Type\":1}]}]}";
        var a = Assert.Single(Sources.ParseCvrf(json, "Microsoft MSRC"));
        Assert.Equal("CVE-2026-1001", a.Cves[0]); Assert.True(a.ActivelyExploited); Assert.Equal("2026-10-13", a.Published);
    }

    [Fact]
    public void Ladder_ActiveFromGradeAorB_IsAct_FromGradeC_IsAttend()
    {
        var hot = new Advisory("Blog", "Edge exploited", "l", "2026-10-28", "CVE-2026-1001 is actively exploited", new() { "CVE-2026-1001" }, "");
        var rows = new List<DefenderRow> { Row("CVE-2026-1001", "Microsoft Edge") };
        Assert.Equal("Act", DefenderTriage.Rank(rows, null, null, new() { hot }, Today)[0].Tier);
        var weak = DefenderTriage.Rank(rows, null, null, new() { hot with { Grade = "C" } }, Today)[0];
        Assert.Equal("Attend", weak.Tier); Assert.Contains("grade C", weak.Rule);
    }

    [Fact]
    public void Ladder_ThreatGroupFromAttack_RaisesToAttend_AndIsCited()
    {
        var dir = Directory.CreateTempSubdirectory().FullName; var db = Path.Combine(dir, "cve.db");
        using (var c = new SqliteConnection($"Data Source={db}"))
        {
            c.Open(); using var cmd = c.CreateCommand();
            cmd.CommandText = "CREATE TABLE cve (id TEXT); CREATE TABLE epss (id TEXT, epss REAL); CREATE TABLE kev (id TEXT); CREATE TABLE actor (id TEXT, name TEXT, aliases TEXT);" +
                "CREATE TABLE actor_cve (actor TEXT, cve TEXT); INSERT INTO actor VALUES ('G0007', 'APT28', ''); INSERT INTO actor_cve VALUES ('G0007', 'CVE-2026-1001')";
            cmd.ExecuteNonQuery();
        }
        var a = DefenderTriage.Rank(new() { new("CVE-2026-1001", "Medium", 5.0, 0.001, 3, false, new[] { "Docker Desktop" }, 1, "") }, db, dir)[0];
        Assert.Equal("Attend", a.Tier); Assert.Equal(new[] { "APT28" }, a.Actors); Assert.Contains("ATT&CK", a.Feeds);
        Assert.Contains("APT28", a.Card); Assert.Contains("[1]", a.Card);
    }

    [Fact]
    public void LlmActorNotInTheText_IsDropped()
    {
        var a = new Advisory("Pasted", "t", "m", "", "Sandworm is exploiting CVE-2026-1001 now.", new(), "");
        var got = TriageLlm.Apply(a, "{\"cves\":[],\"products\":[],\"actors\":[\"Sandworm\",\"APT29\"],\"actively_exploited\":false,\"exploited_quote\":\"\",\"summary_en\":\"x\"}")!;
        Assert.Equal(new[] { "Sandworm" }, got.Actors);
    }

    [Fact]
    public void Cited_DropsSentencesWithoutValidCitations()
    {
        var c = Intel.Cited("Let me think about evidence [1].\nExploited: yes, CISA lists it [1].\nWho: APT28 [2].\nWho: again [2].\nReal-world severity: very high.\n" +
            "Why it matters here: you run it [7].\nExploited: [1]\nReal-world severity: " + new string('x', 200) + " [1]", new[] { 1, 2 });
        Assert.Equal("Exploited: yes, CISA lists it [1].\nWho: APT28 [2].", c); // thinking aloud, repeats, uncited, bad [n], empty: all dropped
    }

    [Fact]
    public void TlpGate_RedNever_AmberOnlyLocal()
    {
        var rows = new List<IntelRow> { new(1, "x", "a", "A", "CLEAR", "c", "", ""), new(2, "x", "b", "A", "AMBER", "c", "", ""), new(3, "x", "c", "A", "RED", "c", "", "") };
        Assert.Equal((1, 2), (Intel.ForLlm(rows, false).Send.Count, Intel.ForLlm(rows, false).Held));
        Assert.Equal(new[] { 1, 2 }, Intel.ForLlm(rows, true).Send.Select(r => r.N));
    }

    class Fake : HttpMessageHandler
    {
        public int Calls; public string? LastBody; readonly string reply;
        public Fake(string reply) => this.reply = reply;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken c)
        {
            Calls++; LastBody = await r.Content!.ReadAsStringAsync(c);
            var body = System.Text.Json.JsonSerializer.Serialize(new { choices = new[] { new { message = new { content = reply } } } });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    [Fact]
    public async Task IntelCard_KeepsCitedLines_HoldsAmberFromCloud_AndCaches()
    {
        Environment.SetEnvironmentVariable(TriageLlm.KeyName, "test-key");
        var dir = Directory.CreateTempSubdirectory().FullName;
        var clear = new Advisory("CERT-EU", "Edge flaw", "l1", "2026-10-28", "CVE-2026-1001 actively exploited", new() { "CVE-2026-1001" }, "");
        var amber = new Advisory("ISAC", "Sector note", "l2", "2026-10-28", "CVE-2026-1001 seen against our sector", new() { "CVE-2026-1001" }, "") { Tlp = "AMBER" };
        var a = DefenderTriage.Rank(new() { Row("CVE-2026-1001", "Microsoft Edge") }, null, null, new() { clear, amber }, Today)[0];
        var fake = new Fake("Exploited: CERT-EU says yes [1].\nWho: APT99 did it.");
        var card = await TriageLlm.IntelCard(a, "a finance organisation in Finland", dir, new HttpClient(fake));
        Assert.StartsWith("Exploited: CERT-EU says yes [1].", card); Assert.DoesNotContain("APT99", card);
        Assert.Contains("1 TLP:AMBER or RED", card); Assert.DoesNotContain("sector", fake.LastBody!);
        Assert.DoesNotContain("50 machines", fake.LastBody!); // organisation details never go to a cloud model
        await TriageLlm.IntelCard(a, "a finance organisation in Finland", dir, new HttpClient(fake));
        Assert.Equal(1, fake.Calls); // second time from intel-cache.json
    }
}
