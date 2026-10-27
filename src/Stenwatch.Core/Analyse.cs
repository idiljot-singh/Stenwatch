using Microsoft.Data.Sqlite;

namespace Stenwatch.Core;

/// <summary>CTI stage 4 - Analysis: explainable risk score, threat profile and SSVC tier per finding.
/// likelihood = w.epss*EPSS + w.kev*inKEV + w.ransomware*ransomware + w.threat_profile*overlap
/// impact     = CVSS/10 * weight * exposure;  risk = likelihood * impact. All weights come from the profile.</summary>
public static class Analyse
{
    const double CvssUnknown = 5.0; // NVD not yet scored: assume medium, say so in the reasons
    static readonly string[] D3Tactics = { "Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore" };
    static readonly Defend Patch = new("D3-SU", "Software Update", "Harden"); // the countermeasure for any known vulnerability
    public static readonly Dictionary<string, string> Action = new()
    {
        ["Act"] = "patch or mitigate within 48 h", ["Attend"] = "next patch cycle",
        ["Track"] = "watch for exploitation", ["Ignore"] = "no action",
    };

    public static Threat LoadThreat(SqliteConnection db, Profile p)
    {
        var groups = p.ThreatGroups;
        var t = new Threat();
        var q = string.Join(",", groups.Keys.Select((_, i) => "@g" + i));
        SqliteCommand Cmd(string sql) { var c = db.CreateCommand(); c.CommandText = sql; int i = 0; foreach (var g in groups.Keys) c.Parameters.AddWithValue("@g" + i++, g); return c; }

        using (var c = Cmd($"SELECT actor, cve FROM actor_cve WHERE actor IN ({q})"))
        using (var r = c.ExecuteReader())
            while (r.Read()) Add(t.Cited, r.GetString(1), groups[r.GetString(0)]);
        using (var c = Cmd($"SELECT actor, technique FROM actor_technique WHERE actor IN ({q})"))
        using (var r = c.ExecuteReader())
            while (r.Read()) Add(t.Used, r.GetString(1), groups[r.GetString(0)]);
        using (var c = Cmd(@"SELECT DISTINCT m.cve, t.id, t.name, t.tactics FROM cve_technique m JOIN technique t ON t.id = m.technique ORDER BY m.cve, t.id"))
        using (var r = c.ExecuteReader())
            while (r.Read()) Add(t.Techniques, r.GetString(0), new Technique(r.GetString(1), r.GetString(2), r.IsDBNull(3) ? "" : r.GetString(3)));
        try
        {
            using (var c = Cmd("SELECT technique, id, name, tactic FROM defend"))
            using (var r = c.ExecuteReader())
                while (r.Read()) Add(t.Defend, r.GetString(0), new Defend(r.GetString(1), r.GetString(2), r.GetString(3)));
            using (var c = Cmd("SELECT technique, id, name FROM mitigation"))
            using (var r = c.ExecuteReader())
                while (r.Read()) Add(t.Mitigations, r.GetString(0), new Mitigation(r.GetString(1), r.GetString(2)));
        }
        catch (SqliteException) { } // database from before these tables existed: sync to fill them
        using (var c = Cmd("SELECT key, value FROM meta"))
        using (var r = c.ExecuteReader())
            while (r.Read()) t.Meta[r.GetString(0)] = r.GetString(1);
        return t;
    }

    static void Add<K, V>(Dictionary<K, List<V>> d, K k, V v) where K : notnull
    {
        if (!d.TryGetValue(k, out var l)) d[k] = l = new();
        l.Add(v);
    }

    public static double BlastRadius(Asset a, Profile p) =>
        p.ThirdParty.DataAccess[a.DataAccess] * (a.Privileged ? p.ThirdParty.Privileged : 1.0);

    /// <summary>-> (tier, the rule that put it there)</summary>
    public static (string Tier, string Reason) Tier(Finding f, double weight, bool exploited, Profile p)
    {
        var t = p.Tiers;
        if (exploited && (f.Asset.InternetFacing || weight >= 3))
            return ("Act", "it is exploited and the asset is " + (f.Asset.InternetFacing ? "internet-facing" : "among the most critical"));
        if (exploited) return ("Attend", "it is exploited, but the asset is internal and not top-critical");
        if (f.Epss >= t.AttendEpss) return ("Attend", $"EPSS is at or above {Py.Repr(t.AttendEpss)}");
        if (f.Epss >= t.TrackEpss) return ("Track", $"EPSS is at or above {Py.Repr(t.TrackEpss)}, with no confirmed exploitation");
        if ((f.Cvss ?? 0) >= t.TrackCvss) return ("Track", $"CVSS is {Py.Repr(f.Cvss)} (at or above {Py.Repr(t.TrackCvss)}), with no exploitation signal");
        return ("Ignore", "there is no exploitation signal and severity is low");
    }

    /// <summary>Real CWE ids only; NVD also uses placeholders like NVD-CWE-noinfo.</summary>
    public static string Cwes(Finding f) =>
        string.Join(", ", f.Cwe.Split(',').Select(c => c.Trim()).Where(c => c.StartsWith("CWE-")));

    /// <summary>D3FEND countermeasures for the finding's techniques, most-shared first, capped per tactic.
    /// Software Update always leads: patching is the countermeasure to any known vulnerability.</summary>
    public static (List<Defend>, List<Mitigation>) Countermeasures(List<Technique> techs, Threat threat, int perTactic = 3)
    {
        var byTactic = D3Tactics.Concat(new[] { "" }).ToDictionary(x => x, _ => new List<Defend>());
        foreach (var d in MostCommon(techs.SelectMany(x => threat.Defend.GetValueOrDefault(x.Id) ?? new())))
        {
            if (d.Id == Patch.Id) continue;
            if (!byTactic.TryGetValue(d.Tactic, out var l)) byTactic[d.Tactic] = l = new();
            if (l.Count < perTactic) l.Add(d);
        }
        var ranked = new List<Defend> { Patch };
        ranked.AddRange(D3Tactics.SelectMany(x => byTactic[x]));
        var mits = MostCommon(techs.SelectMany(x => threat.Mitigations.GetValueOrDefault(x.Id) ?? new())).Take(5).ToList();
        return (ranked, mits);
    }

    /// <summary>Counter.most_common(): by count, ties in first-seen order.</summary>
    static List<T> MostCommon<T>(IEnumerable<T> items) where T : notnull
    {
        var order = new List<T>(); var n = new Dictionary<T, int>();
        foreach (var i in items) { if (n.TryGetValue(i, out var c)) n[i] = c + 1; else { n[i] = 1; order.Add(i); } }
        return order.OrderByDescending(i => n[i]).ToList();
    }

    /// <summary>Projected Diamond Model of an intrusion through this finding: not an observed event, a potential one.</summary>
    public static Diamond DiamondOf(Finding f, Asset a, Profile p, List<string> cited, List<string> shared, List<Technique> techs)
    {
        var org = p.Organisation;
        var uniq = cited.Distinct().Order(StringComparer.Ordinal).ToList();
        var adversary = cited.Count > 0 ? $"{string.Join(", ", uniq)}: known to exploit this CVE"
            : shared.Count > 0 ? $"{shared.Count} profiled groups able to use its techniques ({string.Join(", ", shared.Take(3))}{(shared.Count > 3 ? ", ..." : "")})"
            : f.Ransomware ? "ransomware operators (CISA)"
            : f.Kev ? "unattributed actors exploiting it in the wild (CISA KEV)"
            : "no known adversary; opportunistic scanning is the likely threat";
        var exploit = f.Kev ? "weaponised: exploited in the wild" : $"EPSS {Py.Pct(f.Epss, 1)} in 30 days";
        var cw = Cwes(f);
        var capability = $"{f.Cve}{(cw != "" ? " (" + cw + ")" : "")}, {exploit}"
            + (techs.Count > 0 ? "; techniques " + string.Join(", ", techs.Take(4).Select(t => t.Id)) : "");
        var infrastructure = a.InternetFacing ? "reachable from the internet: attacker infrastructure can hit it directly"
            : a.ThirdParty ? $"through the supplier's access ({a.Type})"
            : "needs an internal foothold first (phishing, a compromised device or VPN)";
        var victim = $"{org.Name} ({org.Sector}, {org.Country}): {a.Name}, "
            + (a.ThirdParty ? $"{a.DataAccess} data{(a.Privileged ? ", privileged" : "")}" : $"criticality {a.Criticality}");
        var phase = techs.SelectMany(t => t.Tactics.Split(',')).Where(x => x != "").Select(x => x.Replace("-", " ")).Distinct().ToList();
        return new Diamond(adversary, capability, infrastructure, victim, phase.Count > 0 ? string.Join(", ", phase) : "not mapped");
    }

    /// <summary>Plain-English context for one finding: what, where, how likely, who, what an attacker gets, what to do.</summary>
    public static string Summary(Finding f, Asset a, List<string> cited, List<string> shared, List<Technique> techs,
                                 string tier, string reason, List<Defend> defend)
    {
        var where = a.ThirdParty ? $"a supplier-operated {a.Type} with {a.DataAccess} data access{(a.Privileged ? " and privileged access" : "")}"
                                 : $"an owned asset of criticality {a.Criticality} (of 3)";
        var s = new List<string> { $"{f.Cve} affects {a.Name}, {where}, {(a.InternetFacing ? "exposed to the internet" : "on the internal network")}." };
        var desc = string.Join(" ", f.Description.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        if (desc != "")
        {
            var first = desc.Split(". ")[0].TrimEnd('.');
            s.Add((first.Length > 300 ? first[..297] + "..." : first) + ".");
        }
        var facts = new List<string>();
        if (f.Published != "") facts.Add($"published {f.Published[..Math.Min(10, f.Published.Length)]}");
        if (Cwes(f) != "") facts.Add($"weakness {Cwes(f)}");
        if (facts.Count > 0) { var j = string.Join(", ", facts); s.Add(char.ToUpperInvariant(j[0]) + j[1..] + "."); }
        s.Add(f.Kev ? "CISA lists it as exploited in the wild" + (f.KevAdded != "" ? $" since {f.KevAdded}" : "")
                      + (f.Ransomware ? ", including in ransomware campaigns" : "") + "."
                    : "It is not in CISA's catalogue of exploited vulnerabilities.");
        s.Add($"EPSS puts the chance of exploitation in the next 30 days at {Py.Pct(f.Epss, 1)}"
              + (f.Percentile is > 0 ? $", higher than {Py.Pct(f.Percentile.Value, 0)} of all CVEs" : "") + ".");
        if (cited.Count > 0) s.Add($"Threat groups in your profile known to exploit it: {string.Join(", ", cited.Distinct().Order(StringComparer.Ordinal))}.");
        else if (shared.Count > 0) s.Add($"It enables ATT&CK techniques used by {shared.Count} of your profiled groups ({string.Join(", ", shared)}).");
        if (techs.Count > 0)
            s.Add("If exploited, an attacker could achieve: " + string.Join("; ", techs.Take(4).Select(t =>
                $"{(t.Tactics.Split(',')[0] is { Length: > 0 } x ? x : "unmapped tactic").Replace("-", " ")} ({t.Id} {t.Name})")) + ".");
        var lead = new Dictionary<string, string>();
        foreach (var d in defend) lead.TryAdd(d.Tactic, $"{d.Name} ({d.Id})");
        if (tier != "Ignore")
            s.Add("Defend (MITRE D3FEND): " + string.Join("; ", D3Tactics.Where(lead.ContainsKey).Select(t => $"{t.ToLowerInvariant()} with {lead[t]}")) + ".");
        var step = Action[tier] + (a.ThirdParty && tier is "Act" or "Attend"
            ? ". Ask the supplier to confirm the patch status and limit their access until they do" : "");
        s.Add($"Decision: {tier}, because {reason}. Next step: {step}.");
        return string.Join(" ", s);
    }

    /// <summary>Score one finding. With no organisation context the result is identical to the original pipeline (parity-tested).
    /// With context: service criticality replaces the asset's own (9), internal assets reachable from the internet get the Reachable
    /// exposure (8, 10), and evidenced controls that counter the finding's techniques scale likelihood (10).</summary>
    public static Ranked Score(Finding f, Profile p, Threat threat, OrgContext? ctx = null, PathResult? paths = null, DateOnly? today = null)
    {
        Asset a = f.Asset; var w = p.Weights;
        var cited = threat.Cited.GetValueOrDefault(f.Cve) ?? new();
        var techs = threat.Techniques.GetValueOrDefault(f.Cve) ?? new();
        var shared = techs.SelectMany(t => threat.Used.GetValueOrDefault(t.Id) ?? new()).Distinct().Order(StringComparer.Ordinal).ToList();
        double overlap = cited.Count > 0 ? 1.0 : shared.Count > 0 ? 0.5 : 0.0;
        var (defend, mitigations) = Countermeasures(techs, threat);

        // organisation context (empty by default)
        var services = !a.ThirdParty && ctx != null ? ctx.ServicesOf(a.Name).ToList() : new List<Service>();
        var controls = ctx?.Compensating(a.Name, techs.Select(t => t.Id), defend.Select(d => d.Id), today ?? DateOnly.FromDateTime(DateTime.Today), p.Controls.EvidenceDays) ?? new();
        bool reachable = !a.InternetFacing && paths != null && paths.Reachable(a.Name);
        double control = controls.Count == 0 ? 1.0 : controls.Min(c => c.Effectiveness == "strong" ? p.Controls.Strong : p.Controls.Partial);

        double likelihood = w.Epss * f.Epss + w.Kev * (f.Kev ? 1 : 0) + w.Ransomware * (f.Ransomware ? 1 : 0) + w.ThreatProfile * overlap;
        likelihood *= control;
        double cvss = f.Cvss ?? CvssUnknown;
        double weight = a.ThirdParty ? BlastRadius(a, p) : services.Count > 0 ? services.Max(x => x.Criticality) : a.Criticality;
        double exposure = a.InternetFacing ? p.Exposure.Internet : reachable ? p.Exposure.Reachable : p.Exposure.Internal;
        double impact = cvss / 10 * weight * exposure;

        var why = new List<string> { $"EPSS {Py.F(f.Epss, 2)}" };
        if (f.Kev) why.Add("KEV: exploited in the wild");
        if (f.Ransomware) why.Add("used by ransomware");
        if (cited.Count > 0) why.Add($"exploited by {string.Join(", ", cited.Distinct().Order(StringComparer.Ordinal))} (threat profile)");
        else if (shared.Count > 0) why.Add($"enables techniques used by {shared.Count} profiled groups");
        why.Add(f.Cvss is not null ? $"CVSS {Py.Repr(f.Cvss)}" : "CVSS n/a (assumed 5.0)");
        if (a.ThirdParty)
            why.Add($"third party ({a.Type}, {a.DataAccess} data{(a.Privileged ? ", privileged access" : "")}): blast radius {Py.G(weight)}");
        else if (services.Count > 0)
            why.Add($"supports {string.Join(", ", services.Select(x => x.Name))} (service criticality {services.Max(x => x.Criticality)})");
        else why.Add($"criticality {a.Criticality}");
        if (a.InternetFacing) why.Add("internet-facing");
        else if (reachable) why.Add($"reachable from the internet in {paths!.Hops[a.Name]} steps (possible path)");
        if (controls.Count > 0)
            why.Add($"compensating control {string.Join(", ", controls.Select(c => $"{c.Name} (evidence {c.EvidenceDate})"))} scales likelihood by {Py.Repr(control)}");
        if (a.Version == "")
            why.Add(a.ThirdParty ? $"version unknown: recent CVEs only ({p.ThirdParty.RecentDays} days)" : "version unknown: assumed affected");

        var (tier, reason) = Tier(f, weight, f.Kev || cited.Count > 0, p);
        if (controls.Count > 0 && tier == "Act")
            reason += ". A compensating control is recorded, but exploitation is confirmed, so verify the control actually blocks it or patch";
        var evidence = EvidenceOf.Build(f, a, cited, shared, techs, threat.Meta);
        foreach (var x in services) evidence.Add(new("service impact", "organisation", "analyst", $"{x.Name}: criticality {x.Criticality}, {x.DataClass} data{(x.Regulatory != "" ? ", " + x.Regulatory : "")}", "high"));
        foreach (var c in controls) evidence.Add(new("control", "organisation", "analyst", $"{c.Name} ({c.Effectiveness})", "medium", "", c.EvidenceDate, c.Evidence));
        if (reachable) evidence.Add(new("attack path", "link table + capability rules", "heuristic", $"reachable in {paths!.Hops[a.Name]} steps", "low", "", "", "possible, not proven: link reachability and exploit feasibility are assumed"));
        return new Ranked(f, Py.Round3(likelihood), Py.Round3(impact), Py.Round3(likelihood * impact), tier,
            cited.Distinct().Order(StringComparer.Ordinal).ToList(), techs, string.Join("; ", why), defend, mitigations,
            DiamondOf(f, a, p, cited, shared, techs), Summary(f, a, cited, shared, techs, tier, reason, defend))
        {
            Evidence = evidence, Confidence = EvidenceOf.Confidence(evidence, threat.Meta, DateTimeOffset.UtcNow),
            Exploitation = EvidenceOf.Exploitation(f, cited.Count > 0, p.Tiers),
            Controls = controls, Services = services,
            PathNote = reachable ? paths!.BestTo[a.Name].Describe() : "",
        };
    }

    /// <summary>Highest risk first; ties by CVE id, then input order (stable), as the Python original.
    /// With organisation context, scores once, derives attack paths from those scores, then scores again so exposure reflects reachability.</summary>
    public static (List<Ranked> Ranked, PathResult? Paths) RankWithPaths(IEnumerable<Finding> findings, Profile p, Threat threat,
                                                                          OrgContext? ctx = null, PathOptions? opt = null, DateOnly? today = null)
    {
        var fs = findings.ToList();
        PathResult? paths = null;
        if (ctx is { IsEmpty: false })
            paths = AttackPaths.Build(ctx, fs.Select(f => Score(f, p, threat, ctx, null, today)).ToList(), opt);
        return (fs.Select(f => Score(f, p, threat, ctx, paths, today)).OrderByDescending(r => r.Risk).ThenBy(r => r.Cve, StringComparer.Ordinal).ToList(), paths);
    }

    public static List<Ranked> Rank(IEnumerable<Finding> findings, Profile p, Threat threat, OrgContext? ctx = null, PathOptions? opt = null, DateOnly? today = null) =>
        RankWithPaths(findings, p, threat, ctx, opt, today).Ranked;
}
