using System.Text.RegularExpressions;

namespace Stenwatch.Core;

/// <summary>One sourced claim about a fix action. N is its citation number [N].</summary>
public record IntelRow(int N, string Kind, string Source, string Grade, string Tlp, string Claim, string Link, string Date);

/// <summary>Evidence for a fix action, the deterministic intel card built from it, and the gates on what an LLM may see and say.
/// Every claim comes from a source row; nothing comes from a model's memory.</summary>
public static class Intel
{
    public static List<IntelRow> Rows(FixAction a)
    {
        var rows = new List<IntelRow>(); int n = 0;
        if (a.Kev > 0) rows.Add(new(++n, "exploited", "CISA KEV", "A", "CLEAR", $"{a.Kev} of its CVEs are on CISA's Known Exploited Vulnerabilities list", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", ""));
        foreach (var g in a.Actors) rows.Add(new(++n, "actor", "MITRE ATT&CK", "A", "CLEAR", $"Threat group {g} is documented exploiting one of its CVEs", "https://attack.mitre.org/groups/", ""));
        foreach (var m in a.Matched ?? new())
        {
            var ad = m.Advisory;
            foreach (var g in ad.Actors) rows.Add(new(++n, "actor", ad.Source, ad.Grade, ad.Tlp, $"Names threat group {g}: {ad.Title}", ad.Link, ad.Published));
            rows.Add(new(++n, ad.ActivelyExploited ? "exploited" : ad.ExploitExists ? "exploit" : "advisory", ad.Source, ad.Grade, ad.Tlp,
                (ad.Summary != "" ? ad.Summary : ad.Title) + (ad.ActivelyExploited ? " Says it is actively exploited." : ad.ExploitExists ? " Reports a working exploit." : "") + (m.ByCve ? "" : " (matched by product name)"),
                ad.Link, ad.Published));
        }
        if (a.MaxEpss >= 0.05) rows.Add(new(++n, "epss", "FIRST EPSS", "B", "CLEAR", $"EPSS gives {a.MaxEpss:P0} chance of exploitation in the next 30 days", "https://www.first.org/epss/", ""));
        return rows;
    }

    /// <summary>The card without an LLM: one cited line per row.</summary>
    public static string Card(List<IntelRow> rows) => rows.Count == 0 ? "No intelligence beyond Defender's own data."
        : string.Join("\n", rows.Select(r => $"{r.Claim} ({r.Source}, grade {r.Grade}{(r.Date != "" ? ", " + r.Date : "")}) [{r.N}]"));

    /// <summary>TLP gate: RED never leaves; AMBER only to a model on this machine.</summary>
    public static (List<IntelRow> Send, int Held) ForLlm(List<IntelRow> rows, bool localModel)
    {
        var send = rows.Where(r => r.Tlp != "RED" && (r.Tlp != "AMBER" || localModel)).ToList();
        return (send, rows.Count - send.Count);
    }

    /// <summary>Keeps only the card's four labelled lines, each once, each with real text and citations to rows that exist.
    /// Anything else (uncited claims, a model thinking aloud) is dropped, not trusted.</summary>
    public static string Cited(string reply, IEnumerable<int> valid)
    {
        var ok = valid.ToHashSet(); var seen = new HashSet<string>(); var keep = new List<string>();
        foreach (var raw in reply.Split('\n'))
        {
            var l = raw.Trim().TrimStart('*', '-', ' ').Replace("**", "");
            var m = Regex.Match(l, @"^(Exploited|Who|Real-world severity|Why it matters here):\s*(.+)$", RegexOptions.IgnoreCase);
            if (!m.Success || seen.Contains(m.Groups[1].Value.ToLowerInvariant())) continue;
            var refs = Regex.Matches(l, @"\[(\d+)\]").Select(x => int.Parse(x.Groups[1].Value)).ToList();
            var text = Regex.Replace(m.Groups[2].Value, @"\[\d+\]", "").Trim(' ', '.', ':', '"');
            if (refs.Count == 0 || !refs.All(ok.Contains) || text.Length < 3 || l.Length > 200) continue; // a card line is short; long ones are the model reasoning aloud
            seen.Add(m.Groups[1].Value.ToLowerInvariant()); keep.Add(l);
        }
        return string.Join("\n", keep);
    }
}
