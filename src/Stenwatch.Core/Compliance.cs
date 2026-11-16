using System.Text;

namespace Stenwatch.Core;

/// <summary>Compliance evidence: one HTML page that sets what Stenwatch already stores (ranked findings, tasks, deadlines, verification) beside the NIS2 and
/// ISO/IEC 27001 requirements it is evidence for. It is an extract for an auditor to read, not a statement of compliance, and the page says so.
/// ponytail: three requirements with fixed wording; add more rows when an auditor asks for one Stenwatch has data for.</summary>
public static class Compliance
{
    public const string FileName = "compliance-evidence.html";

    public static string Html(string org, List<Ranked> ranked, List<RemediationTask> tasks, List<Exposure> exposures, DateOnly today)
    {
        var day = today.ToString("yyyy-MM-dd"); string E(string s) => Render.Esc(s);
        int N(string state) => tasks.Count(t => t.State == state);
        var active = tasks.Where(t => t.State is TaskState.Open or TaskState.InProgress or TaskState.Reopened).ToList();
        var overdue = active.Count(t => t.Due != "" && string.CompareOrdinal(t.Due, day) < 0);
        var tiers = string.Join(", ", DefenderTriage.Tiers.Select(t => $"{t} {ranked.Count(r => r.Tier == t) + exposures.Count(x => x.Tier == t):N0}"));
        var rows = new (string Nis2, string Iso, string Evidence)[]
        {
            ("Article 21(2)(a): policies on risk analysis and information system security", "Clause 6.1.2 Information security risk assessment; Annex A 5.7 Threat intelligence",
                $"{ranked.Count:N0} vulnerability findings and {exposures.Count:N0} other exposure findings were ranked on {day} by fixed, written rules; every finding carries the rule that set its tier. By tier: {tiers}."),
            ("Article 21(2)(e): security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure", "Annex A 8.8 Management of technical vulnerabilities",
                $"{tasks.Count:N0} remediation tasks are recorded, each with a tier, an owner field and a deadline: {active.Count:N0} active ({overdue:N0} past their deadline), {N(TaskState.Fixed):N0} claimed fixed, {N(TaskState.Verified):N0} verified, {N(TaskState.Excepted):N0} under an accepted exception."),
            ("Article 21(2)(f): policies and procedures to assess the effectiveness of cybersecurity risk-management measures", "Clause 9.1 Monitoring, measurement, analysis and evaluation",
                $"A task counts as verified only when a later run no longer finds the item: {N(TaskState.Verified):N0} verified, {N(TaskState.Reopened):N0} reopened because the item was found again after a claimed fix."),
        };
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Compliance evidence</title><style>body{font:14px/1.5 Segoe UI,Arial,sans-serif;max-width:1000px;margin:32px auto;padding:0 16px;color:#111}table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #bbb;padding:6px 8px;text-align:left;vertical-align:top}th{background:#eee}.tlp{background:#ffc233;font-weight:bold;padding:2px 8px}.note{color:#444}</style></head><body>");
        sb.Append($"<p><span class=\"tlp\">TLP:AMBER</span></p><h1>Compliance evidence: {E(org)}</h1><p>Written by Stenwatch on {day}.</p>");
        sb.Append("<p class=\"note\">This page is evidence, not a statement of compliance. It shows what Stenwatch has recorded about vulnerability handling, beside the NIS2 Directive (EU) 2022/2555 and ISO/IEC 27001:2022 requirements that the records relate to. Whether a requirement is met is for your auditor to decide; Stenwatch covers only the parts named here. The wording of each requirement is shortened: read the source text.</p>");
        sb.Append("<h2>Requirements and the records behind them</h2><table><tr><th>NIS2</th><th>ISO/IEC 27001:2022</th><th>What Stenwatch has recorded</th></tr>");
        foreach (var r in rows) sb.Append($"<tr><td>{E(r.Nis2)}</td><td>{E(r.Iso)}</td><td>{E(r.Evidence)}</td></tr>");
        sb.Append($"</table><h2>Remediation tasks</h2><p class=\"note\">{(tasks.Count > 300 ? $"The first 300 of {tasks.Count:N0}, urgent tiers first." : "All tasks, urgent tiers first.")}</p><table><tr><th>Task</th><th>Item</th><th>Asset</th><th>Tier</th><th>State</th><th>Owner</th><th>Opened</th><th>Due</th><th>Closed</th></tr>");
        foreach (var t in tasks.OrderBy(t => Array.IndexOf(DefenderTriage.Tiers, t.Tier)).ThenBy(t => t.Due, StringComparer.Ordinal).Take(300))
            sb.Append($"<tr><td>T-{t.Id}</td><td>{E(t.Cve)}</td><td>{E(t.Asset)}</td><td>{E(t.Tier)}</td><td>{E(t.State)}</td><td>{E(t.Owner)}</td><td>{E(t.Opened)}</td><td>{E(t.Due)}</td><td>{E(t.Closed)}</td></tr>");
        return sb.Append("</table></body></html>").ToString();
    }

    public static void Write(string outDir, string org, List<Ranked> ranked, List<RemediationTask> tasks, List<Exposure> exposures, DateOnly today)
        => File.WriteAllText(Path.Combine(outDir, FileName), Html(org, ranked, tasks, exposures, today), new UTF8Encoding(false));
}
