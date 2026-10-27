namespace Stenwatch.Core;

public record Asset(
    string Name, string Cpe, string Version, int Criticality, bool InternetFacing, bool ThirdParty,
    string Type = "", string DataAccess = "", bool Privileged = false, HashSet<string>? OnlyCves = null);

public record Finding(
    Asset Asset, string Cve, double? Cvss, string Cwe, string Description, double Epss, bool Kev,
    bool Ransomware, string Published, double? Percentile, string KevAdded, string Vector = "");

public record Technique(string Id, string Name, string Tactics);
public record Defend(string Id, string Name, string Tactic);
public record Mitigation(string Id, string Name);

public record Diamond(string Adversary, string Capability, string Infrastructure, string Victim, string Phase);

public record Ranked(
    Finding F, double Likelihood, double Impact, double Risk, string Tier, List<string> CitedBy,
    List<Technique> Techniques, string Why, List<Defend> Defend, List<Mitigation> Mitigations,
    Diamond Diamond, string Summary)
{
    /// <summary>Pillar 12: what the priority rests on, how sure we are, and what is known about exploitation.</summary>
    public List<Evidence> Evidence { get; init; } = new();
    public string Confidence { get; init; } = "";
    public string Exploitation { get; init; } = "";
    public Asset Asset => F.Asset;
    public string Cve => F.Cve;
    public Decision? Decision { get; init; }
    /// <summary>Pillars 8-10: organisation context that shaped this score (all empty when none was provided).</summary>
    public List<Control> Controls { get; init; } = new();
    public List<Service> Services { get; init; } = new();
    public string PathNote { get; init; } = "";
}

/// <summary>An analyst decision (exceptions.csv).</summary>
public record Decision(string Cve, string Asset, string Status, string Until, string Note);

/// <summary>Everything the threat profile needs, read once from the database.</summary>
public class Threat
{
    public Dictionary<string, List<string>> Cited = new();       // cve -> profiled group names that exploited it
    public Dictionary<string, List<string>> Used = new();        // technique -> profiled group names using it
    public Dictionary<string, List<Technique>> Techniques = new(); // cve -> techniques
    public Dictionary<string, List<Defend>> Defend = new();      // technique -> D3FEND countermeasures
    public Dictionary<string, List<Mitigation>> Mitigations = new();
    public Dictionary<string, string> Meta = new();                // feed sync times, EPSS model version
}
