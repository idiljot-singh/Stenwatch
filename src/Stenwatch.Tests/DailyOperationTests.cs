using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Phase 2, daily operation: morning run, schedule command text, ticket push, briefing delivery, end of life, hunting queries. Offline: every HTTP call is a stub.</summary>
public class DailyOperationTests : IDisposable
{
    readonly string dir = Directory.CreateTempSubdirectory("stenwatch-daily").FullName;
    public void Dispose() { SqliteConnection.ClearAllPools(); Directory.Delete(dir, true); }

    class Stub : HttpMessageHandler
    {
        public readonly List<(string Url, string Body)> Seen = new(); public string Token = ""; readonly Func<HttpRequestMessage, HttpResponseMessage> answer;
        public Stub(Func<HttpRequestMessage, HttpResponseMessage> answer) => this.answer = answer;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken c)
        {
            Seen.Add((r.RequestUri!.ToString(), r.Content is null ? "" : await r.Content.ReadAsStringAsync(c)));
            if (r.Headers.TryGetValues("X-Automation-Webhook-Token", out var v)) Token = v.Single();
            return answer(r);
        }
    }
    static HttpResponseMessage Ok(string body = "") => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    const string Export = "Vulnerabilities Export,29 Oct 2026\nName,Severity,CVSS v3,Epss score,Age (days),Published,First detected,Updated,Has Exploit,Has Known Threats,Has Associated Alerts,Related Software,Exposed Machines,Description,Status\n" +
        "CVE-2026-1001,High,8.8,0.30000,30,\"27 May, 2026\",\"29 May, 2026\",\"06 Oct, 2026\",False,False,False,google:chrome,150,\"Summary: fixed prior to 148.0.1\",RemediationRequired\n";

    [Fact]
    public void Tickets_UrlProblem_NamesTheReason()
    {
        Assert.Equal("no webhook set", Tickets.UrlProblem(" "));
        Assert.Equal("the webhook address must start with https://", Tickets.UrlProblem("http://example.test/hook"));
        Assert.Null(Tickets.UrlProblem("https://example.test/hook"));
    }

    [Fact]
    public async Task Morning_PicksNewestExport_WritesEml_PostsDecisions_ThenSaysNothingNew()
    {
        var watch = Directory.CreateDirectory(Path.Combine(dir, "watch")).FullName; var data = Directory.CreateDirectory(Path.Combine(dir, "data")).FullName;
        File.WriteAllText(Path.Combine(watch, "old.csv"), "not an export"); File.SetLastWriteTimeUtc(Path.Combine(watch, "old.csv"), DateTime.UtcNow.AddDays(-2));
        File.WriteAllText(Path.Combine(watch, "export.csv"), Export); File.WriteAllText(Path.Combine(watch, "~$export.xlsx"), "lock");
        Assert.Equal(Path.Combine(watch, "export.csv"), Morning.Newest(watch));

        var stub = new Stub(r => r.Method == HttpMethod.Post ? new HttpResponseMessage(HttpStatusCode.Accepted) : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var m = await Morning.Run(data, watch, http: new HttpClient(stub), today: new DateOnly(2026, 10, 29), briefingUrl: "https://example.test/hook");
        Assert.True(m.NewExport);
        var eml = File.ReadAllText(m.Eml);
        Assert.Contains("Subject: Stenwatch morning briefing 2026-10-29", eml); Assert.Contains("X-Unsent: 1", eml); Assert.DoesNotContain("To:", eml);
        var html = Encoding.UTF8.GetString(Convert.FromBase64String(string.Concat(eml[(eml.IndexOf("\r\n\r\n") + 4)..].Split("\r\n"))));
        Assert.Contains("Needs a decision today", html);
        var post = stub.Seen.Single(s => s.Url == "https://example.test/hook").Body;
        Assert.Contains("application/vnd.microsoft.card.adaptive", post); Assert.Contains("Google Chrome", post);
        Assert.Contains(m.Notes, n => n.StartsWith("Teams: webhook accepted"));
        Assert.Equal(watch, Morning.Load(data).Folder);

        var again = await Morning.Run(data, http: new HttpClient(stub));
        Assert.False(again.NewExport); Assert.Contains(again.Notes, n => n.StartsWith("No new export since the last run"));
        Assert.Contains(again.Notes, n => n.StartsWith("Sources:")); // feeds were still refreshed (and failed soft)
    }

    [Fact]
    public void Schedule_GivesTheExactCommand_AndNoneInTheStoreEdition()
    {
        var r = Morning.ScheduleCommand(new TimeOnly(7, 5), @"C:\Program Files\Stenwatch\stenwatch-cli.exe", @"D:\org data\", packaged: false);
        Assert.Equal("schtasks /create /f /tn \"Stenwatch morning run\" /sc daily /st 07:05 /tr \"\\\"C:\\Program Files\\Stenwatch\\stenwatch-cli.exe\\\" --morning --data \\\"D:\\org data\\\"\"", r.Command);
        var store = Morning.ScheduleCommand(new TimeOnly(7, 0), packaged: true);
        Assert.Null(store.Command); Assert.Contains("Store edition", store.Note);
        Assert.Equal("schtasks /delete /f /tn \"Stenwatch morning run\"", Morning.UnscheduleCommand());
        Assert.Null(Morning.ScheduleCommand(new TimeOnly(7, 0), @"C:\" + new string('x', 250) + @"\stenwatch-cli.exe", packaged: false).Command); // over 262 characters
    }

    static long OneTask(SqliteConnection db)
    {
        Remediation.EnsureSchema(db);
        using var c = db.CreateCommand();
        c.CommandText = "INSERT INTO task (cve, asset, state, tier, owner, ticket, opened, due, closed, note) VALUES ('CVE-2026-1001','Mail server','Open','Act','Ann','', '2026-11-01','2026-11-03','','')";
        c.ExecuteNonQuery(); c.CommandText = "SELECT last_insert_rowid()"; return (long)c.ExecuteScalar()!;
    }

    [Fact]
    public async Task Ticket_PlainJsonHasExactlyTheEightFields_StateAndReferenceKept_HttpRefused()
    {
        using var db = new SqliteConnection($"Data Source={Path.Combine(dir, "t.db")}"); db.Open();
        var id = OneTask(db);
        Tickets.SetFormat(dir, teams: false);
        var stub = new Stub(_ => Ok("{\"id\":7,\"url\":\"https://dev.azure.com/org/_apis/wit/workItems/7\"}"));
        var r = await Tickets.Push(db, id, "CISA KEV lists it as exploited", dir, new HttpClient(stub), "https://example.test/ticket", ("X-Automation-Webhook-Token", "tok"));
        Assert.Equal((Tickets.Sent, "https://dev.azure.com/org/_apis/wit/workItems/7"), (r.State, r.Reference));
        using var sent = JsonDocument.Parse(stub.Seen.Single().Body);
        Assert.Equal(new[] { "task_id", "item", "asset", "tier", "deadline", "owner", "reason", "link" }, sent.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2026-1001", sent.RootElement.GetProperty("link").GetString());
        Assert.Equal("tok", stub.Token);
        Tickets.SetFormat(dir, teams: true); // Teams: 2xx is Sent, the reply is not read for a reference, no secret header
        var stub2 = new Stub(_ => Ok("INC0099999"));
        var tr = await Tickets.Push(db, id, "", dir, new HttpClient(stub2), "https://example.test/teams", ("X-Automation-Webhook-Token", "tok"));
        Assert.Equal((Tickets.Sent, ""), (tr.State, tr.Reference)); Assert.Equal("", stub2.Token);
        Tickets.SetFormat(dir, teams: false);
        var t = Remediation.Load(db).Single();
        Assert.Equal((Tickets.Sent, "https://dev.azure.com/org/_apis/wit/workItems/7"), (t.TicketState, t.Ticket));

        var bad = await Tickets.Push(db, id, "", dir, new HttpClient(stub), "http://example.test/secret-token");
        Assert.Equal(Tickets.Failed, bad.State); Assert.DoesNotContain("secret-token", bad.Note); Assert.Single(stub.Seen);
        Assert.Equal("https://dev.azure.com/org/_apis/wit/workItems/7", Remediation.Load(db).Single().Ticket); // a failure keeps the old reference
        Assert.Equal("INC0012345", Tickets.Reference("{\"result\":{\"number\":\"INC0012345\"}}"));
    }

    [Fact]
    public void Ticket_TeamsCard_HasTheWorkflowsShape()
    {
        var t = new RemediationTask(3, "CVE-2026-1001", "Mail server", "Open", "Act", "", "", "2026-11-01", "2026-11-03", "", "");
        using var doc = JsonDocument.Parse(Tickets.Payload(t, "KEV", teams: true));
        var a = doc.RootElement.GetProperty("attachments")[0];
        Assert.Equal("message", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("application/vnd.microsoft.card.adaptive", a.GetProperty("contentType").GetString());
        Assert.Equal(JsonValueKind.Null, a.GetProperty("contentUrl").ValueKind);
        Assert.Equal("AdaptiveCard", a.GetProperty("content").GetProperty("type").GetString());
    }

    [Fact]
    public void Schema_OldTaskTableGetsTicketState_RowsReadAsNotSent()
    {
        using var db = new SqliteConnection($"Data Source={Path.Combine(dir, "old.db")}"); db.Open();
        using (var c = db.CreateCommand())
        {
            c.CommandText = "CREATE TABLE task (id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT, asset TEXT, state TEXT, tier TEXT, owner TEXT, ticket TEXT, opened TEXT, due TEXT, closed TEXT, note TEXT, verified_run INTEGER);" +
                "INSERT INTO task (cve, asset, state, tier, owner, ticket, opened, due, closed, note) VALUES ('CVE-2026-1','a','Open','Act','','INC1','2026-11-01','2026-11-03','','')";
            c.ExecuteNonQuery();
        }
        var t = Remediation.Load(db).Single();
        Assert.Equal((Tickets.NotSent, "INC1"), (t.TicketState, t.Ticket));
    }

    static string Product(params (string Name, bool Eol, string? From)[] rel) => JsonSerializer.Serialize(new { schema_version = "1.2.0", result = new
    {
        name = "x", releases = rel.Select(r => new { name = r.Name, isEol = r.Eol, eolFrom = r.From, isMaintained = !r.Eol }).ToArray()
    } });

    [Fact]
    public async Task Eol_PastSoonAndUnchecked_CachedForTheDay_OfflineUsesTheCache()
    {
        var assets = new List<Asset>
        {
            new("Portal runtime", "cpe:2.3:a:php:php", "8.1.12", 2, true, false),
            new("Proxy", "cpe:2.3:a:f5:nginx", "1.24.0", 2, false, false),
            new("Files", "cpe:2.3:o:microsoft:windows_server_2019", "10.0.17763.5329", 3, false, false),
            new("No version", "cpe:2.3:a:php:php", "", 2, false, false),
            new("Unmapped", "cpe:2.3:a:7-zip:7-zip", "23.01", 1, false, false),
            new("Laptops", "cpe:2.3:o:microsoft:windows_11_23h2", "10.0.22631.3880", 2, false, false),
            new("CMS", "cpe:2.3:a:wordpress:wordpress", "6.2.2", 2, false, false),
        };
        var day = new DateOnly(2026, 11, 16);
        var stub = new Stub(r => r.RequestUri!.AbsolutePath switch
        {
            "/api/v1/products/php/" => Ok(Product(("8.1", true, "2025-12-31"), ("8.4", false, "2028-12-31"))),
            "/api/v1/products/nginx/" => Ok(Product(("1.24", false, "2027-06-01"))),
            "/api/v1/products/windows-server/" => Ok(Product(("2019", false, "2027-01-10"))),
            "/api/v1/products/windows/" => Ok(Product(("11-23h2-w", true, "2025-11-11"), ("11-23h2-e", false, "2026-12-01"))),
            "/api/v1/products/wordpress/" => Ok(Product(("6.2", false, null))),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound),
        });
        var r = await Eol.Check(dir, assets, new HttpClient(stub), today: day);
        Assert.Equal((4, 1, 2, 3), (r.Checked, r.Past, r.Soon, r.NotChecked.Count)); // WordPress 6.2 has no date: not checked
        var win = Exposure.Load(dir, Eol.Component).Single(e => e.Asset == "Laptops"); // edition not known: the later (Enterprise) date, not the earlier
        Assert.Equal("Medium", win.Severity); Assert.Contains("2026-12-01", win.Evidence); Assert.Contains("edition not known", win.Evidence);
        var rows = Exposure.Load(dir, Eol.Component);
        var php = rows.Single(e => e.Asset == "Portal runtime");
        Assert.Equal(("High", "Attend"), (php.Severity, php.Tier)); // past end of life and internet-facing: the ladder raises it
        Assert.Contains("2025-12-31", php.Evidence); Assert.Contains("endoflife.date", php.Evidence);
        Assert.Equal("Medium", rows.Single(e => e.Asset == "Files").Severity); // 2019 cycle pinned, ends within 90 days
        Assert.Equal(Coverage.Connected, Coverage.Of(dir).Single(c => c.Component.Name == Eol.Component).Status);

        var calls = stub.Seen.Count;
        await Eol.Check(dir, assets, new HttpClient(stub), today: day); Assert.Equal(calls, stub.Seen.Count); // once a day
        var offline = await Eol.Check(dir, assets, new HttpClient(new Stub(_ => throw new HttpRequestException("down"))), today: day.AddDays(1));
        Assert.Contains("not reachable", offline.Note); Assert.Equal(4, offline.Checked);
    }

    [Fact]
    public void Kql_TemplateForAValidCve_TechniquesAsComments_NothingElseGetsIn()
    {
        var q = Kql.Query("CVE-2026-1001", new[] { "Mail server\n| take 1" }, new[] { new Technique("T1190", "Exploit Public-Facing Application", "initial-access") })!;
        Assert.Contains("| where CveId == \"CVE-2026-1001\"", q);
        Assert.Contains("// ATT&CK hunting leads (CTID KEV mappings): T1190 Exploit Public-Facing Application", q);
        Assert.Contains("not run against a tenant", q);
        Assert.All(q.Split('\n').Where(l => l.Contains("take 1")), l => Assert.StartsWith("//", l)); // the asset name stays inside a comment
        Assert.Null(Kql.Query("CVE-2026-1001\" or 1==1", new[] { "x" }, Array.Empty<Technique>()));
    }
}
