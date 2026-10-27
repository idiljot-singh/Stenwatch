using System.Globalization;

namespace Stenwatch.Core;

/// <summary>One piece of intelligence behind a finding, with where it came from and how far to trust it (pillar 12).
/// Kind: observed (confirmed exploitation) | predicted (model estimate) | vendor (NVD/CVSS) | community (CTID mapping, ATT&amp;CK text)
///       | heuristic (our own rule) | assumption (a gap we filled in).</summary>
public record Evidence(string Signal, string Source, string Kind, string Value, string Confidence,
                       string CollectedAt = "", string PublishedAt = "", string Note = "");

public static class EvidenceOf
{
    /// <summary>Feeds older than this are flagged stale and lower the finding's confidence.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(7);

    static string At(Dictionary<string, string> meta, string key) => meta.GetValueOrDefault(key, "");

    public static bool IsStale(string stamp, DateTimeOffset now) =>
        DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) && now - t > StaleAfter;

    /// <summary>The evidence behind one finding. Absence of exploitation evidence is "unknown", never "safe".</summary>
    public static List<Evidence> Build(Finding f, Asset a, List<string> cited, List<string> shared, List<Technique> techs,
                                       Dictionary<string, string> meta)
    {
        var e = new List<Evidence>();
        if (f.Kev)
            e.Add(new("KEV", "CISA Known Exploited Vulnerabilities", "observed", "exploited in the wild", "high", At(meta, "kev_sync"), f.KevAdded));
        if (f.Ransomware)
            e.Add(new("ransomware", "CISA Known Exploited Vulnerabilities", "observed", "known ransomware campaign use", "high", At(meta, "kev_sync"), f.KevAdded));
        e.Add(new("EPSS", "FIRST EPSS", "predicted", $"{Py.Pct(f.Epss, 1)} in the next 30 days", "medium", At(meta, "epss_sync"), "",
            "probability estimate for 30 days (model " + (At(meta, "epss_model") is { Length: > 0 } m ? m : "version unknown") + "), not certainty; population-level, not specific to this organisation"));
        e.Add(f.Cvss is null
            ? new("CVSS", "assumed", "assumption", $"NVD has not scored it; {Py.Repr(5.0)} assumed", "low", "", f.Published)
            : new("CVSS", "NIST NVD", "vendor", Py.Repr(f.Cvss), "high", "", f.Published, "technical severity only"));
        if (cited.Count > 0)
            e.Add(new("threat group", "MITRE ATT&CK", "community", $"{string.Join(", ", cited.Distinct().Order(StringComparer.Ordinal))} named with this CVE", "medium",
                At(meta, "attack_sync"), "", "CVE found in the group's or campaign's ATT&CK description text; documents a report, not a current campaign"));
        else if (shared.Count > 0)
            e.Add(new("technique overlap", "MITRE ATT&CK + CTID", "heuristic", $"{shared.Count} profiled groups use techniques this CVE enables", "low",
                At(meta, "ctid_sync"), "", "a shared technique does not prove those groups exploit this CVE"));
        if (techs.Count > 0)
            e.Add(new("techniques", "CTID KEV to ATT&CK mapping", "community", string.Join(", ", techs.Take(4).Select(t => t.Id)), "medium", At(meta, "ctid_sync")));
        if (a.Version == "")
            e.Add(new("version", "asset list", "assumption", a.ThirdParty ? "supplier version unknown: recent CVEs only" : "version unknown: assumed affected", "low"));
        return e;
    }

    /// <summary>Exploitation status shown next to the tier: what is known, and what is not.</summary>
    public static string Exploitation(Finding f, bool cited, TiersCfg t) =>
        f.Kev ? "observed: confirmed exploited in the wild (CISA KEV)"
        : cited ? "reported: a profiled threat group is documented exploiting it"
        : f.Epss >= t.AttendEpss ? "predicted: high exploitation likelihood, not yet confirmed"
        : f.Epss >= t.TrackEpss ? "predicted: moderate likelihood, no confirmed exploitation"
        : "unknown: no exploitation evidence found, which is not evidence of safety";

    /// <summary>High / Medium / Low confidence in the priority. Starts High when it rests on observed exploitation, Medium when it rests on
    /// predictions, and drops one level for each class of assumption or stale feed (never below Low).</summary>
    public static string Confidence(List<Evidence> evidence, Dictionary<string, string> meta, DateTimeOffset now)
    {
        int level = evidence.Any(x => x.Kind == "observed") ? 2 : 1;
        if (evidence.Any(x => x.Kind == "assumption")) level--;
        var needed = evidence.Where(x => x.Kind is "observed" or "predicted").Select(x => x.CollectedAt);
        if (needed.Any(s => s != "" && IsStale(s, now))) level--;
        return new[] { "Low", "Medium", "High" }[Math.Clamp(level, 0, 2)];
    }
}
