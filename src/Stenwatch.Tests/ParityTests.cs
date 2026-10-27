using Stenwatch.Core;
using Xunit;

namespace Stenwatch.Tests;

/// <summary>Golden tests: the C# pipeline must reproduce the Python pipeline's out/example/ files.
/// Needs data/cve.db and a fresh Python baseline (python python/run.py --example --skip-collect); skipped otherwise.</summary>
public class ParityTests
{
    static string? Root()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "data", "cve.db")) && File.Exists(Path.Combine(d.FullName, "data", "out", "example", "report.csv"))) return d.FullName;
        return null;
    }

    static PipelineFiles Example(string root) => new(Path.Combine(root, "data", "cve.db"), Path.Combine(root, "examples", "profile.example.yaml"),
        Path.Combine(root, "examples", "assets.example.csv"), Path.Combine(root, "examples", "third_parties.example.csv"), Path.Combine(root, "examples", "exceptions.example.csv"));

    [Fact]
    public void ExampleOrganisation_MatchesPythonReportCsv()
    {
        var root = Root();
        if (root is null) return; // no data on this machine
        var (ranked, _) = Pipeline.Run(Example(root));
        var tmp = Path.Combine(Path.GetTempPath(), "stenwatch-parity.csv");
        Pipeline.WriteCsv(tmp, ranked);

        var want = Csv.ReadDict(Path.Combine(root, "data", "out", "example", "report.csv"));
        var got = Csv.ReadDict(tmp);
        Assert.Equal(want.Count, got.Count);
        var bad = new Dictionary<string, int>(); string? first = null;
        for (int i = 0; i < want.Count; i++)
            foreach (var col in Pipeline.CsvHeader.Where(c => want[i][c] != got[i][c]))
            {
                bad[col] = bad.GetValueOrDefault(col) + 1;
                first ??= $"row {i + 1} {col}:\n  py: {want[i][col]}\n  cs: {got[i][col]}";
            }
        Assert.True(bad.Count == 0, $"mismatches per column: {string.Join(", ", bad.Select(kv => kv.Key + "=" + kv.Value))}\n{first}");
    }

    [Fact]
    public void ExampleOrganisation_ReportMarkdownBriefAndStixIdsMatchPython()
    {
        var root = Root();
        if (root is null) return;
        var files = Example(root);
        var profile = Profile.Load(files.Profile);
        var (ranked, suppressed) = Pipeline.Run(files);
        var tmp = Path.Combine(Path.GetTempPath(), "stenwatch-parity-out"); Directory.CreateDirectory(tmp);
        var today = DateOnly.FromDateTime(DateTime.Today).ToString("yyyy-MM-dd");
        var expired = Process.LoadDecisions(files.Decisions!).Where(e => e.Until != "" && string.CompareOrdinal(e.Until, today) < 0).ToList();
        Disseminate.WriteReports(ranked, tmp, profile, suppressed: suppressed, expired: expired);
        var (brief, src) = Llm.Brief(ranked, profile.Llm).GetAwaiter().GetResult();
        Disseminate.WriteBrief(brief, src, tmp, profile);
        Disseminate.WriteStix(ranked, tmp, profile);

        var py = Path.Combine(root, "data", "out", "example");
        foreach (var f in new[] { "report.md", "brief.md" })
            Assert.Equal(File.ReadAllText(Path.Combine(py, f)).ReplaceLineEndings("\n"), File.ReadAllText(Path.Combine(tmp, f)).ReplaceLineEndings("\n"));

        static HashSet<string> Ids(string p) => System.Text.Json.JsonDocument.Parse(File.ReadAllText(p)).RootElement.GetProperty("objects")
            .EnumerateArray().Select(o => o.GetProperty("id").GetString()!).ToHashSet();
        // deterministic ids = re-importing into MISP/OpenCTI updates objects instead of duplicating them
        Assert.Equal(Ids(Path.Combine(py, "bundle.json")), Ids(Path.Combine(tmp, "bundle.json")));
    }

    [Fact]
    public void Render_EscapesFeedTextAndKeepsOnlyHttpsLinks()
    {
        var h = Render.MdToHtml("## <script>alert(1)</script>\n[x](javascript:alert(1)) [ok](https://nvd.nist.gov/)\n| A |\n|---|\n| Act |");
        Assert.DoesNotContain("<script", h); Assert.DoesNotContain("<a href=\"javascript", h);
        Assert.Contains("<a href=\"https://nvd.nist.gov/\"", h); Assert.Contains("class=\"pill act\"", h);
    }
}
