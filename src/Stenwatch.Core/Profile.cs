using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Stenwatch.Core;

public class Profile
{
    public OrgCfg Organisation { get; set; } = new();
    public List<string> Pirs { get; set; } = new();
    public Dictionary<string, string> ThreatGroups { get; set; } = new();
    public WeightsCfg Weights { get; set; } = new();
    public ExposureCfg Exposure { get; set; } = new();
    public ThirdPartyCfg ThirdParty { get; set; } = new();
    public TiersCfg Tiers { get; set; } = new();
    public ControlsCfg Controls { get; set; } = new();
    /// <summary>Days allowed to fix a finding, by tier. Act matches the "within 48 h" decision.</summary>
    public Dictionary<string, int> Sla { get; set; } = new() { ["Act"] = 2, ["Attend"] = 30, ["Track"] = 90 };
    /// <summary>YYYY-MM-DD, empty = off. Assets without a version or OS build are assumed patched for every CVE published before this date.
    /// An assumption: it hides a missed patch. An OS build in the asset list is exact and needs no assumption.</summary>
    public string PatchBaseline { get; set; } = "";
    public TargetingCfg Targeting { get; set; } = new();
    public LlmCfg Llm { get; set; } = new();
    public DefenderCfg Defender { get; set; } = new();

    /// <summary>A copy that tracks a different set of groups (the effective set after automatic selection).</summary>
    public Profile WithThreatGroups(Dictionary<string, string> groups) { var c = (Profile)MemberwiseClone(); c.ThreatGroups = groups; return c; }

    public static Profile Load(string path) =>
        new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties().Build().Deserialize<Profile>(File.ReadAllText(path));
}

/// <summary>Which threat groups are tracked. manual = only threat_groups. auto = also pick groups from MITRE ATT&amp;CK that match the
/// organisation's sector and country, refreshed whenever ATT&amp;CK is synced. threat_groups are always kept (pinned); exclude removes an auto pick.</summary>
public class TargetingCfg
{
    public string Mode { get; set; } = "manual";
    public List<string> Sectors { get; set; } = new();     // extra sectors beyond organisation.sector
    public List<string> Countries { get; set; } = new();   // extra countries or regions beyond organisation.country
    public int MaxGroups { get; set; } = 10;
    /// <summary>A group needs at least this score. 6 means, for example, sector + ransomware + recent activity, or sector + country. Lower it to track more groups.</summary>
    public double MinScore { get; set; } = 6;
    public List<string> Include { get; set; } = new();     // ATT&CK group ids to always add
    public List<string> Exclude { get; set; } = new();     // ATT&CK group ids never to add automatically
}

public class LlmCfg
{
    public string Provider { get; set; } = "none"; public string Model { get; set; } = ""; public string Url { get; set; } = "http://localhost:11434";
    public string Endpoint { get; set; } = ""; public string Deployment { get; set; } = ""; public string ApiVersion { get; set; } = "";
}
public class DefenderCfg
{
    public bool Enabled { get; set; } public string TenantId { get; set; } = ""; public string ClientId { get; set; } = "";
    public string Certificate { get; set; } = ""; public string Thumbprint { get; set; } = "";
}
public class OrgCfg{ public string Name { get; set; } = ""; public string Sector { get; set; } = ""; public string Country { get; set; } = ""; }
// defaults = profile.example.yaml, so a profile that leaves a section out still scores sensibly
public class WeightsCfg { public double Epss { get; set; } = 0.4; public double Kev { get; set; } = 0.3; public double Ransomware { get; set; } = 0.1; public double ThreatProfile { get; set; } = 0.2; }
public class ExposureCfg
{
    public double Internet { get; set; } = 1.5; public double Internal { get; set; } = 1.0;
    /// <summary>Internal asset an attacker can reach from the internet through a chain of exploitable hosts. Proposed, not validated: tune or set equal to internal.</summary>
    public double Reachable { get; set; } = 1.25;
}
/// <summary>How much an evidenced compensating control multiplies exploitation likelihood. Proposed, not validated.</summary>
public class ControlsCfg { public double Partial { get; set; } = 0.8; public double Strong { get; set; } = 0.5; public int EvidenceDays { get; set; } = 365; }
public class ThirdPartyCfg { public int RecentDays { get; set; } = 90; public Dictionary<string, double> DataAccess { get; set; } = new() { ["none"] = 1.0, ["internal"] = 1.5, ["confidential"] = 2.0 }; public double Privileged { get; set; } = 1.5; }
public class TiersCfg { public double AttendEpss { get; set; } = 0.1; public double TrackEpss { get; set; } = 0.01; public double TrackCvss { get; set; } = 7.0; }
