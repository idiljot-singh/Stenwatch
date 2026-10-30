using Stenwatch.Core;

namespace Stenwatch.App;

/// <summary>Editable rows for the Context grids. Plain properties, so a DataGrid can edit them directly.</summary>
public class ServiceRow : System.ComponentModel.INotifyPropertyChanged
{
    public string Name { get; set; } = ""; public string Owner { get; set; } = ""; public int Criticality { get; set; } = 2;
    public string DataClass { get; set; } = "internal"; public string Regulatory { get; set; } = ""; public int RtoHours { get; set; }
    string assets = "";
    /// <summary>Names separated by ';'. Notifies, because the tick list beside the grid changes it.</summary>
    public string Assets { get => assets; set { assets = value; PropertyChanged?.Invoke(this, new(nameof(Assets))); } }
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
}
public class LinkRow { public string From { get; set; } = ""; public string To { get; set; } = ""; public string Kind { get; set; } = "network"; public string Port { get; set; } = ""; public string Note { get; set; } = ""; }
public class ControlRow
{
    public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string Type { get; set; } = ""; public string Scope { get; set; } = "*";
    public string Counters { get; set; } = ""; public string Effectiveness { get; set; } = "partial"; public string Evidence { get; set; } = "";
    public string EvidenceDate { get; set; } = ""; public string Expires { get; set; } = "";
}
public class AssetRow { public string Asset { get; set; } = ""; public string Zone { get; set; } = ""; public string Owner { get; set; } = ""; public bool CrownJewel { get; set; } }

/// <summary>A finding as the grid shows it.</summary>
public class FindingRow
{
    public Ranked R { get; init; } = null!;
    public string Tier => R.Tier; public double Risk => R.Risk; public string Cve => R.Cve; public string Asset => R.Asset.Name;
    public string Confidence => R.Confidence;
    public string Exploitation => R.Exploitation.Split(':')[0]; public string Why => R.Why;
    public string Source => R.Asset.ThirdParty ? "supplier" : "owned";
}

/// <summary>A fix action as the Morning triage grid shows it.</summary>
public class TriageRow
{
    public FixAction A { get; init; } = null!;
    public string Tier => A.Tier; public string Product => A.Product; public string Fix => A.Fix == "" ? "latest vendor update" : A.Fix; public int Cves => A.Rows.Count; public int Machines => A.Exposed;
    public string Feeds => A.Feeds; public string Why => A.Label != "" ? A.Label : A.Rule; public string Flag => A.Flag.Split(':')[0]; // full sentence and reason: Detail tab
}

public class PathRow { public AttackPath P { get; init; } = null!; public string Target => P.Target; public int Steps => P.Length; public string Likelihood => P.Likelihood.ToString("0.000"); public string Route => P.Describe(); }

public class GroupRow
{
    readonly GroupPick g;
    public GroupRow(GroupPick g) { this.g = g; }
    public string Id => g.Id; public string Name => g.Name; public string Source => g.Source;
    public string ScoreText => g.Source == "auto" ? g.Score.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture) : "";
    public string ReasonText => string.Join("; ", g.Reasons);
}
