using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>Ticket push: one remediation task posted to one webhook, as a Microsoft Teams Workflows card (Adaptive Card message, docs/formats.md)
/// or as a plain JSON object that Jira, ServiceNow and Azure DevOps automations accept. One call per task; nothing is read back except the reply's reference.
/// What leaves the machine, and only to the customer's own webhook: task_id, item (CVE id or exposure item id), asset (the asset NAME), tier, deadline, owner,
/// reason (the rule text the caller passes) and link (the NVD page for a CVE, else empty). No machine counts, no profile, no other task.
/// Asset names are organisation details; they go here because the ticket system is the customer's own. They never go to an LLM.
/// The webhook URL is a secret (Credential Manager via <see cref="Secrets"/>): it is never written to a plain file, a log line or a note.
/// A plain-JSON webhook may need one secret header (Jira's incoming webhook: X-Automation-Webhook-Token): its name and value are secrets too, sent only with the plain JSON shape.
/// State on the task (column ticket_state): "" = Not sent, Sent, Failed. A reference or link found in the reply goes in the task's ticket field.</summary>
public static class Tickets
{
    public const string Secret = "STENWATCH_TICKET_WEBHOOK", HeaderName = "STENWATCH_TICKET_HEADER_NAME", HeaderValue = "STENWATCH_TICKET_HEADER_VALUE", NotSent = "", Sent = "Sent", Failed = "Failed";
    public record Outcome(string State, string Reference, string Note);

    /// <summary>"teams" (default) or "json", kept in ticket-format.txt in the data folder. Not a secret.</summary>
    public static bool IsTeams(string data) => !(File.Exists(Path.Combine(data, "ticket-format.txt")) && File.ReadAllText(Path.Combine(data, "ticket-format.txt")).Trim().Equals("json", StringComparison.OrdinalIgnoreCase));
    public static void SetFormat(string data, bool teams) => File.WriteAllText(Path.Combine(data, "ticket-format.txt"), teams ? "teams" : "json");

    /// <summary>Public reference page for the item: NVD for a CVE id, nothing for an exposure item.</summary>
    public static string Link(string item) => Regex.IsMatch(item, @"^CVE-\d{4}-\d+$") ? "https://nvd.nist.gov/vuln/detail/" + item : "";

    /// <summary>The body posted for one task. Exactly the eight fields named in the class summary.</summary>
    public static string Payload(RemediationTask t, string reason, bool teams)
    {
        var f = new (string Key, string Value)[] { ("task_id", t.Id.ToString()), ("item", t.Cve), ("asset", t.Asset), ("tier", t.Tier), ("deadline", t.Due),
            ("owner", t.Owner), ("reason", reason), ("link", Link(t.Cve)) };
        if (!teams)
        {
            var o = new JsonObject(); foreach (var (k, v) in f) o[k] = k == "task_id" ? JsonValue.Create(t.Id) : JsonValue.Create(v);
            return o.ToJsonString();
        }
        return Card($"Stenwatch task T-{t.Id}: {t.Tier} {t.Cve}", f.Where(x => x.Value != "").Select(x => (x.Key.Replace('_', ' '), x.Value)), "");
    }

    /// <summary>A Teams Workflows message: type "message" with one Adaptive Card attachment (shape from docs/formats.md, Teams incoming webhook).</summary>
    public static string Card(string title, IEnumerable<(string Title, string Value)> facts, string text)
    {
        var body = new JsonArray { new JsonObject { ["type"] = "TextBlock", ["text"] = title, ["weight"] = "Bolder", ["size"] = "Medium", ["wrap"] = true } };
        if (text != "") body.Add(new JsonObject { ["type"] = "TextBlock", ["text"] = text, ["wrap"] = true });
        var fs = facts.Select(x => (JsonNode)new JsonObject { ["title"] = x.Title, ["value"] = x.Value }).ToArray();
        if (fs.Length > 0) body.Add(new JsonObject { ["type"] = "FactSet", ["facts"] = new JsonArray(fs) });
        return new JsonObject
        {
            ["type"] = "message",
            ["attachments"] = new JsonArray { new JsonObject { ["contentType"] = "application/vnd.microsoft.card.adaptive", ["contentUrl"] = null,
                ["content"] = new JsonObject { ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json", ["type"] = "AdaptiveCard", ["version"] = "1.4", ["body"] = body } } },
        }.ToJsonString();
    }

    /// <summary>Why a webhook address cannot be used (the same words Post gives), or null when it is a well-formed https address. Sends nothing.</summary>
    public static string? UrlProblem(string? url) => string.IsNullOrWhiteSpace(url) ? "no webhook set"
        : Uri.TryCreate(url.Trim(), UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps ? null : "the webhook address must start with https://";

    /// <summary>POST json to a webhook. https only (same rule as Sources.Fetch and TriageLlm.Ask). Fails soft: (false, "", note).
    /// The note never contains the URL or an exception message (a host name can be in one).</summary>
    public static async Task<(bool Ok, string Reply, string Note)> Post(HttpClient http, string? url, string json, (string Name, string Value)? header = null)
    {
        if (UrlProblem(url) is { } bad) return (false, "", bad);
        var u = new Uri(url!.Trim());
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, u) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
            if (header is { } h && !req.Headers.TryAddWithoutValidation(h.Name, h.Value)) return (false, "", "the secret header name is not valid");
            using var r = await http.SendAsync(req);
            var reply = await r.Content.ReadAsStringAsync();
            return r.IsSuccessStatusCode ? (true, reply, $"webhook accepted it (HTTP {(int)r.StatusCode})") : (false, reply, $"webhook answered HTTP {(int)r.StatusCode}");
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException) { return (false, "", $"webhook not reachable ({e.GetType().Name})"); }
    }

    /// <summary>A ticket reference in the reply, or "": a URL first (Azure DevOps "url", Jira "self"), else an id such as ABC-123 or INC0012345.
    /// ponytail: pattern match on the reply text, not per-product parsing; a product that answers differently just gets no reference.</summary>
    public static string Reference(string reply)
    {
        if (Regex.Match(reply, @"https://[^\s""'<>]+") is { Success: true } m) return m.Value[..Math.Min(200, m.Value.Length)];
        return Regex.Match(reply, @"\b(?:[A-Z][A-Z0-9]{1,9}-\d+|(?:INC|RITM|REQ|CHG|PRB)\d{4,})\b") is { Success: true } id ? id.Value : "";
    }

    /// <summary>Push one task to the ticket webhook (url, else the stored secret) and keep the state on the task. Never throws for a network failure.
    /// Teams: any 2xx is Sent and the reply is not read (it is not documented). Plain JSON: the stored secret header (or <paramref name="header"/>) is added when set.</summary>
    public static async Task<Outcome> Push(SqliteConnection db, long id, string reason, string data, HttpClient? http = null, string? url = null, (string Name, string Value)? header = null)
    {
        var t = Remediation.Load(db).FirstOrDefault(x => x.Id == id) ?? throw new ArgumentException($"no task T-{id}");
        http ??= new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        if (reason == "") reason = t.Note;
        url ??= Secrets.Get(Secret);
        if (string.IsNullOrWhiteSpace(url)) return new(t.TicketState, "", "no ticket webhook set: add one on Integrations");
        var teams = IsTeams(data);
        header ??= !teams && Secrets.Get(HeaderName) is { Length: > 0 } hn && Secrets.Get(HeaderValue) is { Length: > 0 } hv ? (hn, hv) : null;
        var (ok, reply, note) = await Post(http, url, Payload(t, reason, teams), teams ? null : header);
        var reference = ok && !teams ? Reference(reply) : "";
        Remediation.SetTicket(db, id, ok ? Sent : Failed, reference);
        return new(ok ? Sent : Failed, reference, $"T-{id}: {note}" + (reference != "" ? $", reference {reference}" : ""));
    }
}
