using System.Net;
using System.Text;
using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>The LLM may only add what the advisory's own text supports; every failure leaves the rule-based result. Offline: OpenRouter is faked.</summary>
public class TriageLlmTests
{
    static Advisory Mail(string text) => new("Pasted", "Kriittinen haavoittuvuus", "mail-1", "2026-10-28", text, new(), "");

    [Fact]
    public void Apply_KeepsOnlyCvesAndQuotesThatAreInTheText()
    {
        var a = Mail("Microsoft Edge: CVE-2026-1001 on kriittinen. Haavoittuvuutta hyödynnetään aktiivisesti hyökkäyksissä.");
        var got = TriageLlm.Apply(a, "```json\n{\"cves\":[\"CVE-2026-1001\",\"CVE-2026-7777\"],\"products\":[\"Microsoft Edge\"],\"actively_exploited\":true," +
            "\"exploited_quote\":\"hyödynnetään aktiivisesti hyökkäyksissä\",\"summary_en\":\"Edge flaw under attack.\"}\n```")!;
        Assert.Equal(new[] { "CVE-2026-1001" }, got.Cves);            // 7777 is not in the text: dropped
        Assert.True(got.LlmActive); Assert.True(got.ActivelyExploited); Assert.True(got.Analysed);
        Assert.Equal("Edge flaw under attack.", got.Summary);
    }

    [Fact]
    public void Apply_RejectsUrgencyWithoutAQuoteFromTheText_AndNonJson()
    {
        var a = Mail("Päivitä Edge kun ehdit. CVE-2026-1001.");
        var got = TriageLlm.Apply(a, "{\"actively_exploited\":true,\"exploited_quote\":\"it is being exploited everywhere\",\"cves\":[],\"products\":[]}")!;
        Assert.False(got.LlmActive);
        Assert.False(TriageLlm.Apply(a, "{\"actively_exploited\":true,\"exploited_quote\":\"\"}")!.LlmActive);
        Assert.Null(TriageLlm.Apply(a, "sorry, I cannot help with that"));
    }

    [Fact]
    public void Ladder_UsesWhatTheLlmFound_ProductOnlyAdvisoryBecomesACveMatch()
    {
        var a = TriageLlm.Apply(Mail("Edge-selaimen haavoittuvuus CVE-2026-1001, hyödynnetään aktiivisesti."),
            "{\"cves\":[\"CVE-2026-1001\"],\"products\":[\"Microsoft Edge\"],\"actively_exploited\":true,\"exploited_quote\":\"hyödynnetään aktiivisesti\",\"summary_en\":\"x\"}")!;
        var rows = new List<DefenderRow> { new("CVE-2026-1001", "High", 8.8, 0.003, 30, false, new[] { "Microsoft Edge" }, 150, "prior to 148.0.1") };
        var f = DefenderTriage.Rank(rows, null, null, new() { a }, new DateOnly(2026, 10, 29)).Single();
        Assert.Equal("Act", f.Tier); Assert.Contains("names its CVE", f.Rule);
    }

    class Fake : HttpMessageHandler
    {
        public int Calls; public string Sent = ""; readonly Func<string> content;
        public Fake(Func<string> content) => this.content = content;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken c)
        {
            Calls++; Sent = r.Content!.ReadAsStringAsync(c).Result;
            var body = System.Text.Json.JsonSerializer.Serialize(new { choices = new[] { new { message = new { content = content() } } } });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    [Fact]
    public async Task Enrich_ReadsOnlyUnreadAdvisories_AndSurvivesGarbage()
    {
        Environment.SetEnvironmentVariable(TriageLlm.KeyName, "test-key");
        var good = new Fake(() => "{\"cves\":[],\"products\":[\"Mozilla Firefox\"],\"actively_exploited\":false,\"exploited_quote\":\"\",\"summary_en\":\"Firefox fixes.\"}");
        var (all, note) = await TriageLlm.Enrich(new() { Mail("Firefox 151 korjaa haavoittuvuuksia") }, new HttpClient(good));
        Assert.Equal(1, good.Calls); Assert.True(all[0].Analysed); Assert.Equal("Mozilla Firefox", all[0].Products[0]); Assert.Contains("read 1", note);

        var again = await TriageLlm.Enrich(all, new HttpClient(good));
        Assert.Equal(1, good.Calls); Assert.Contains("nothing new", again.Note);          // already read: no second call

        var (kept, note2) = await TriageLlm.Enrich(new() { Mail("jotain") }, new HttpClient(new Fake(() => "I am sorry")));
        Assert.False(kept[0].Analysed); Assert.Contains("not parsed", note2);
    }

    [Fact]
    public async Task ItNote_LlmVersionNeedsEveryProduct_ElseThePlainNoteStands()
    {
        Environment.SetEnvironmentVariable(TriageLlm.KeyName, "test-key");
        var rows = new List<DefenderRow> { new("CVE-2026-1001", "High", 8.8, 0.003, 30, false, new[] { "Microsoft Edge" }, 150, "fixed prior to 148.0.1") };
        var actions = DefenderTriage.Rank(rows, null);
        var plain = TriageLlm.ItNote(actions, new DateOnly(2026, 10, 29));
        Assert.Contains("Microsoft Edge: update to 148.0.1", plain); Assert.Contains("about 150 machines", plain);

        var noteFake = new Fake(() => "Subject: Patching\nPlease update Microsoft Edge to 148.0.1.");
        var (ok, src) = await TriageLlm.ItNoteWithLlm(actions, new DateOnly(2026, 10, 29), new HttpClient(noteFake));
        Assert.DoesNotContain("150", noteFake.Sent); // the machine count stays off a cloud model
        Assert.StartsWith("LLM", src);
        var (fallback, src2) = await TriageLlm.ItNoteWithLlm(actions, new DateOnly(2026, 10, 29), new HttpClient(new Fake(() => "Subject: Patching\nPlease update the browser.")));
        Assert.Equal(plain, fallback); Assert.Contains("failed", src2);
    }

    [Fact]
    public async Task Run_EndToEnd_WritesBriefingXlsxAndNote_WithoutNetwork()
    {
        var dir = Directory.CreateTempSubdirectory().FullName; var export = Path.Combine(dir, "e.csv");
        File.WriteAllText(export, "Name,Severity,CVSS v3,Epss score,Age (days),Published,First detected,Updated,Has Exploit,Has Known Threats,Has Associated Alerts,Related Software,Exposed Machines,Description,Status\n" +
            "CVE-2026-1001,High,8.8,0.003,30,\"27 May, 2026\",\"29 May, 2026\",\"06 Oct, 2026\",False,False,False,microsoft:edge_chromium-based,150,\"Fixed prior to 148.0.1.\",RemediationRequired\n");
        var run = await DefenderTriage.Run(new(export, dir, "", false, false, null, new DateOnly(2026, 10, 29)));
        Assert.Single(run.Actions); Assert.True(File.Exists(Path.Combine(run.OutDir, "briefing.html")));
        Assert.True(File.Exists(Path.Combine(run.OutDir, "fix-actions.xlsx"))); Assert.Contains("Microsoft Edge", File.ReadAllText(Path.Combine(run.OutDir, "it-note.txt")));
        await Assert.ThrowsAsync<InvalidDataException>(() => DefenderTriage.Run(new(Path.Combine(dir, "empty.csv").Also(p => File.WriteAllText(p, "hello")), dir, "", false, false)));
    }
}

static class Ext { public static string Also(this string s, Action<string> a) { a(s); return s; } }
