using System.Text;
using System.Text.RegularExpressions;

namespace Stenwatch.Core;

/// <summary>Detection content: a Microsoft Defender advanced hunting query per Act finding, from one fixed template (no LLM).
/// It lists the devices Defender Vulnerability Management still reports with the CVE (table DeviceTvmSoftwareVulnerabilities); ATT&amp;CK techniques, when the finding has them,
/// are named in a comment as hunting leads. The CVE id goes in only after a strict CVE-\d{4}-\d+ check, and every other text is a single comment line,
/// so nothing else can reach the query. These are templates: they have not been run against a tenant.</summary>
public static class Kql
{
    public const string FileName = "hunting-queries.kql";
    static readonly Regex Cve = new(@"^CVE-\d{4}-\d+$");

    /// <summary>Text for a // comment: one line, no control characters.</summary>
    static string Comment(string s) => Regex.Replace(s, @"[\p{C}]+", " ").Trim();

    /// <summary>The query for one CVE on the named assets, or null when the id is not a CVE id.</summary>
    public static string? Query(string cve, IEnumerable<string> assets, IEnumerable<Technique> techniques)
    {
        if (!Cve.IsMatch(cve)) return null;
        var sb = new StringBuilder();
        sb.Append($"// {cve}: Act on {Comment(string.Join(", ", assets))}\n");
        sb.Append("// Template from Stenwatch, not run against a tenant: check the result in Defender advanced hunting before relying on it.\n");
        var t = techniques.Select(x => Comment($"{x.Id} {x.Name}")).Distinct().ToList();
        if (t.Count > 0) sb.Append($"// ATT&CK hunting leads (CTID KEV mappings): {string.Join("; ", t)}\n");
        sb.Append("DeviceTvmSoftwareVulnerabilities\n");
        sb.Append($"| where CveId == \"{cve}\"\n");
        sb.Append("| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate\n");
        return sb.ToString();
    }

    /// <summary>The query for one finding (the button on a finding's detail).</summary>
    public static string? For(Ranked r) => Query(r.Cve, new[] { r.Asset.Name }, r.Techniques);

    /// <summary>hunting-queries.kql in outDir: one query per CVE among the Act findings (its assets listed together). Returns the number of queries.</summary>
    public static int Write(IEnumerable<Ranked> ranked, string outDir)
    {
        var qs = ranked.Where(r => r.Tier == "Act").GroupBy(r => r.Cve)
            .Select(g => Query(g.Key, g.Select(r => r.Asset.Name).Distinct(), g.SelectMany(r => r.Techniques).DistinctBy(x => x.Id))).OfType<string>().ToList();
        File.WriteAllText(Path.Combine(outDir, FileName), $"// Stenwatch hunting queries {DateTime.Today:yyyy-MM-dd}: {qs.Count} Act findings. Templates, not run against a tenant. TLP:AMBER.\n\n"
            + string.Join("\n", qs));
        return qs.Count;
    }
}
