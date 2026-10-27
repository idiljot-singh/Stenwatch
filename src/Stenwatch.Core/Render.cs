using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Stenwatch.Core;

/// <summary>Turn the Markdown reports into designed HTML pages (and PDFs via Edge/Chrome).</summary>
public static class Render
{
    static readonly Dictionary<string, string> TierClass = new() { ["Act"] = "act", ["Attend"] = "attend", ["Track"] = "track", ["Ignore"] = "ignore" };

    public static string Resource(string name)
    {
        var asm = typeof(Render).Assembly;
        using var s = asm.GetManifestResourceStream(asm.GetManifestResourceNames().First(n => n.EndsWith(name)))!;
        return new StreamReader(s, Encoding.UTF8).ReadToEnd();
    }

    /// <summary>Same escaping as Python's html.escape(quote=True).</summary>
    public static string Esc(string s) => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#x27;");

    /// <summary>Escape first, then allow only bold, code and https links: feed text can never inject markup.</summary>
    public static string Inline(string text)
    {
        var t = Esc(text);
        t = Regex.Replace(t, "`([^`]+)`", "<code>$1</code>");
        t = Regex.Replace(t, @"\*\*(.+?)\*\*", "<strong>$1</strong>");
        return Regex.Replace(t, @"\[([^\]]+)\]\((https://[^)\s]+)\)", "<a href=\"$2\" rel=\"noopener\">$1</a>");
    }

    static string Cell(string text)
    {
        var h = Inline(text.Trim());
        var m = Regex.Match(h, "^(?:<strong>)?(Act|Attend|Track|Ignore)(?:</strong>)?$");
        return m.Success ? $"<span class=\"pill {TierClass[m.Groups[1].Value]}\">{m.Groups[1].Value}</span>" : h;
    }

    /// <summary>The small Markdown subset the reports use: headings, tables, bullet lists, paragraphs.</summary>
    public static string MdToHtml(string md)
    {
        var o = new List<string>(); var lines = md.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        if (lines.Count > 0 && lines[^1] == "") lines.RemoveAt(lines.Count - 1); // splitlines() drops the trailing empty piece
        int i = 0;
        while (i < lines.Count)
        {
            var line = lines[i].TrimEnd();
            if (line.StartsWith('|'))
            {
                var rows = new List<string[]>();
                while (i < lines.Count && lines[i].StartsWith('|')) { rows.Add(lines[i].Trim().Trim('|').Split('|')); i++; }
                o.Add("<div class=\"wrap\"><table><thead><tr>" + string.Concat(rows[0].Select(c => $"<th>{Inline(c.Trim())}</th>")) +
                      "</tr></thead><tbody>" + string.Concat(rows.Skip(2).Select(r => "<tr>" + string.Concat(r.Select(c => $"<td>{Cell(c)}</td>")) + "</tr>")) +
                      "</tbody></table></div>");
                continue;
            }
            if (Regex.IsMatch(line, @"^[-*] "))
            {
                var items = new List<string>();
                while (i < lines.Count && Regex.IsMatch(lines[i], @"^[-*] ")) { items.Add($"<li>{Inline(lines[i][2..])}</li>"); i++; }
                o.Add("<ul>" + string.Concat(items) + "</ul>");
                continue;
            }
            var m = Regex.Match(line, @"^(#{1,3}) (.*)");
            if (m.Success && m.Groups[1].Length > 1) o.Add($"<h{m.Groups[1].Length}>{Inline(m.Groups[2].Value)}</h{m.Groups[1].Length}>"); // the page header already carries the H1
            else if (line != "" && !m.Success) o.Add($"<p>{Inline(line)}</p>");
            i++;
        }
        return string.Join("\n", o);
    }

    /// <summary>cards: (tier, count, caption). md is trusted structure plus untrusted text; Inline() escapes it all.</summary>
    public static void WritePage(string md, string path, string kind, string org, string today, IEnumerable<(string, int, string)>? cards = null, string note = "")
    {
        var cardsHtml = cards is null || !cards.Any() ? "" : "<div class=\"cards\">" + string.Concat(cards.Select(c =>
            $"<div class=\"card {TierClass[c.Item1]}\"><span>{c.Item1}</span><b>{c.Item2}</b><small>{Esc(c.Item3)}</small></div>")) + "</div>";
        var page = Resource("page.html").Replace("__BODY__", MdToHtml(md)).Replace("__CARDS__", cardsHtml)
            .Replace("__NOTE__", note != "" ? $"<div class=\"note\">{Inline(note)}</div>" : "")
            .Replace("__KIND__", Esc(kind)).Replace("__ORG__", Esc(org)).Replace("__DATE__", today);
        File.WriteAllText(path, page, new UTF8Encoding(false));
    }

    public static string? FindBrowser() => new[]
    {
        @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        @"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    }.FirstOrDefault(File.Exists);

    /// <summary>HTML -> PDF with the machine's own Edge or Chrome. Returns the PDF path, or null when there is no browser.</summary>
    public static string? ToPdf(string htmlPath)
    {
        if (FindBrowser() is not { } browser) return null;
        var pdf = Path.ChangeExtension(htmlPath, ".pdf");
        var tmp = Path.Combine(Path.GetTempPath(), "stenwatch-pdf-" + Guid.NewGuid().ToString("N"));
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(browser) { CreateNoWindow = true, UseShellExecute = false };
            foreach (var a in new[] { "--headless", "--disable-gpu", "--log-level=3", "--no-pdf-header-footer", $"--user-data-dir={tmp}",
                                      $"--print-to-pdf={Path.GetFullPath(pdf)}", new Uri(Path.GetFullPath(htmlPath)).AbsoluteUri }) psi.ArgumentList.Add(a);
            using var p = System.Diagnostics.Process.Start(psi)!;
            if (!p.WaitForExit(120_000)) p.Kill(true);
        }
        finally { try { Directory.Delete(tmp, true); } catch { } }
        return File.Exists(pdf) ? pdf : null;
    }
}
