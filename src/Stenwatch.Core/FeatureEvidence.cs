using System.Text.Json;

namespace Stenwatch.Core;

/// <summary>How much each framework-derived feature has been shown to help (docs/evaluation.md). Shown next to the feature in the app and reports.</summary>
public record FeatureLabel(string Feature, string Label, string Detail);

public static class FeatureEvidence
{
    /// <summary>Reads the results the evaluation commands wrote to out/evaluation; anything not yet run says so.</summary>
    public static List<FeatureLabel> Load(string dataDir)
    {
        var dir = Path.Combine(dataDir, "out", "evaluation");
        string? Label(string name)
        {
            var path = Path.Combine(dir, name + ".json");
            if (!File.Exists(path)) return null;
            using var d = JsonDocument.Parse(File.ReadAllText(path));
            return d.RootElement.TryGetProperty("label", out var l) ? l.GetString() : null;
        }
        string Md(string name, string dflt) { var p = Path.Combine(dir, name + ".md"); return File.Exists(p) ? $"see out/evaluation/{name}.md" : dflt; }

        var overlap = Label("attack-value");
        var paths = File.Exists(Path.Combine(dir, "attack-paths.md")) && File.ReadAllText(Path.Combine(dir, "attack-paths.md")).Contains("**Validated**") ? "Validated"
            : File.Exists(Path.Combine(dir, "attack-paths.md")) && File.ReadAllText(Path.Combine(dir, "attack-paths.md")).Contains("**Not shown**") ? "Not shown" : "Not run";
        return new()
        {
            new("EPSS exploitation likelihood (pillar 2)", File.Exists(Path.Combine(dir, "attack-value.md")) ? "Supported" : "Not run",
                "beat CVSS alone on a temporal backtest, small sample; " + Md("attack-value", "run --evaluate-attack")),
            new("ATT&CK threat-profile overlap in scoring", overlap == "Not applicable" ? "Not validated" : overlap ?? "Not run",
                overlap == "Not applicable" ? "the data cannot test it: technique mappings only exist for CVEs already exploited. Context, not evidence of accuracy" : Md("attack-value", "run --evaluate-attack")),
            new("Automatic threat-group selection", "Proposed", "keyword match of sector and country against ATT&CK group text, plus recent campaigns; reasons are shown, nothing shows it predicts what attacks you"),
            new("ATT&CK tactics in attack-path capability", paths, "needs sourced reference chains in docs/evaluation/chains.csv"),
            new("D3FEND / ATT&CK mitigation recommendations", "Proposed", "needs analyst ratings (--rating-sheet, --rating-import); no outcome data exists"),
            new("SSVC decision tiers", "Rule-based", "transparent rules from the profile; outcome comparison not run"),
            new("Diamond Model", "Display-only", "no outcome measure exists; explanation, not a prediction"),
            new("Attack paths", "Proposed", "possible paths from links and capability rules; not verified against real intrusions"),
            new("Compensating controls", "Proposed", "multipliers are configurable assumptions; only evidenced, unexpired controls count"),
        };
    }
}
