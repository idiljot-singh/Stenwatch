"""CTI stage 4 - Analysis: explainable risk score, threat profile and SSVC tier per finding.

likelihood = w.epss*EPSS + w.kev*inKEV + w.ransomware*ransomware + w.threat_profile*overlap
             overlap = 1.0 if a profiled group is known to exploit the CVE
                     = 0.5 if the CVE enables ATT&CK techniques a profiled group uses
impact     = CVSS/10 * weight * exposure
             weight = criticality (1-3) for owned assets
                    = blast radius (1-3) for third parties: data access x privileged
risk       = likelihood * impact
All weights and thresholds come from profile.yaml.
Each finding also gets MITRE D3FEND countermeasures and ATT&CK mitigations for its techniques, and a
projected Diamond Model (adversary, capability, infrastructure, victim) of an intrusion through it.
"""
import collections, sqlite3

CVSS_UNKNOWN = 5.0  # NVD not yet scored: assume medium, say so in the reasons
D3_TACTICS = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]
PATCH = ("D3-SU", "Software Update", "Harden")  # the D3FEND countermeasure for any known vulnerability
ACTION = {"Act": "patch or mitigate within 48 h", "Attend": "next patch cycle",
          "Track": "watch for exploitation", "Ignore": "no action"}


def load_threat(db, profile):
    """Everything the threat profile needs, read once from cve.db."""
    groups = profile["threat_groups"]
    q = ",".join("?" * len(groups))
    known = {g for (g,) in db.execute(f"SELECT id FROM actor WHERE id IN ({q})", list(groups))}
    unknown = set(groups) - known
    if unknown and db.execute("SELECT COUNT(*) FROM actor").fetchone()[0]:
        print(f"  warning: not in ATT&CK, ignored: {', '.join(sorted(unknown))}")

    cited = {}  # cve -> [group names that exploited it]
    for g, cve in db.execute(f"SELECT actor, cve FROM actor_cve WHERE actor IN ({q})", list(groups)):
        cited.setdefault(cve, []).append(groups[g])
    used = {}   # technique -> [profiled group names using it]
    for g, t in db.execute(f"SELECT actor, technique FROM actor_technique WHERE actor IN ({q})", list(groups)):
        used.setdefault(t, []).append(groups[g])
    techniques = {}  # cve -> [(technique id, name, tactics)]
    for cve, tid, name, tactics in db.execute("""
            SELECT DISTINCT m.cve, t.id, t.name, t.tactics
            FROM cve_technique m JOIN technique t ON t.id = m.technique"""):
        techniques.setdefault(cve, []).append((tid, name, tactics))
    defend, mitigations = {}, {}  # technique -> D3FEND countermeasures / ATT&CK mitigations
    try:
        for t, did, name, tactic in db.execute("SELECT technique, id, name, tactic FROM defend"):
            defend.setdefault(t, []).append((did, name, tactic))
        for t, mid, name in db.execute("SELECT technique, id, name FROM mitigation"):
            mitigations.setdefault(t, []).append((mid, name))
    except sqlite3.OperationalError:  # database from before these tables existed: sync to fill them
        pass
    return {"cited": cited, "used": used, "techniques": techniques, "defend": defend, "mitigations": mitigations}


def blast_radius(a, p):
    tp = p["third_party"]
    return tp["data_access"][a["data_access"]] * (tp["privileged"] if a["privileged"] else 1.0)


def tier(f, weight, exploited, p):
    """-> (tier, the rule that put it there)"""
    t = p["tiers"]
    if exploited and (f["asset"]["internet_facing"] or weight >= 3):
        return "Act", "it is exploited and the asset is " + ("internet-facing" if f["asset"]["internet_facing"] else "among the most critical")
    if exploited:
        return "Attend", "it is exploited, but the asset is internal and not top-critical"
    if f["epss"] >= t["attend_epss"]:
        return "Attend", f"EPSS is at or above {t['attend_epss']}"
    if f["epss"] >= t["track_epss"]:
        return "Track", f"EPSS is at or above {t['track_epss']}, with no confirmed exploitation"
    if (f["cvss"] or 0) >= t["track_cvss"]:
        return "Track", f"CVSS is {f['cvss']} (at or above {t['track_cvss']}), with no exploitation signal"
    return "Ignore", "there is no exploitation signal and severity is low"


def cwes(f):
    """Real CWE ids only; NVD also uses placeholders like NVD-CWE-noinfo."""
    return ", ".join(c.strip() for c in (f.get("cwe") or "").split(",") if c.strip().startswith("CWE-"))


def countermeasures(techs, threat, per_tactic=3):
    """D3FEND countermeasures for the finding's techniques, most-shared first, capped per tactic.
    Software Update always leads: patching is the countermeasure to any known vulnerability."""
    count = collections.Counter(d for tid, _, _ in techs for d in threat.get("defend", {}).get(tid, []))
    by_tactic = collections.defaultdict(list)
    for d, _ in count.most_common():
        if d[0] != PATCH[0] and len(by_tactic[d[2]]) < per_tactic:
            by_tactic[d[2]].append(d)
    ranked = [PATCH] + [d for t in D3_TACTICS for d in by_tactic[t]]
    mits = collections.Counter(m for tid, _, _ in techs for m in threat.get("mitigations", {}).get(tid, []))
    return ranked, [m for m, _ in mits.most_common(5)]


def diamond(f, a, p, cited, shared, techs):
    """Projected Diamond Model of an intrusion through this finding: not an observed event, a potential one."""
    org = p["organisation"]
    adversary = (f"{', '.join(sorted(set(cited)))}: known to exploit this CVE" if cited
                 else f"{len(shared)} profiled groups able to use its techniques ({', '.join(shared[:3])}{', ...' if len(shared) > 3 else ''})" if shared
                 else "ransomware operators (CISA)" if f["ransomware"]
                 else "unattributed actors exploiting it in the wild (CISA KEV)" if f["kev"]
                 else "no known adversary; opportunistic scanning is the likely threat")
    exploit = "weaponised: exploited in the wild" if f["kev"] else f"EPSS {f['epss']:.1%} in 30 days"
    capability = f"{f['cve']}{' (' + cwes(f) + ')' if cwes(f) else ''}, {exploit}" + (
        "; techniques " + ", ".join(t[0] for t in techs[:4]) if techs else "")
    infrastructure = ("reachable from the internet: attacker infrastructure can hit it directly" if a["internet_facing"]
                      else f"through the supplier's access ({a['type']})" if a["third_party"]
                      else "needs an internal foothold first (phishing, a compromised device or VPN)")
    victim = (f"{org['name']} ({org['sector']}, {org['country']}): {a['name']}, "
              + (f"{a['data_access']} data{', privileged' if a['privileged'] else ''}" if a["third_party"] else f"criticality {a['criticality']}"))
    phase = list(dict.fromkeys(tac.replace("-", " ") for _, _, tacs in techs for tac in tacs.split(",") if tac)) or ["not mapped"]
    return {"adversary": adversary, "capability": capability, "infrastructure": infrastructure,
            "victim": victim, "phase": ", ".join(phase)}


def summary(f, a, cited, shared, techs, tier_, reason, defend=()):
    """Plain-English context for one finding: what, where, how likely, who, what an attacker gets, what to do."""
    where = (f"a supplier-operated {a['type']} with {a['data_access']} data access{' and privileged access' if a['privileged'] else ''}"
             if a["third_party"] else f"an owned asset of criticality {a['criticality']} (of 3)")
    s = [f"{f['cve']} affects {a['name']}, {where}, {'exposed to the internet' if a['internet_facing'] else 'on the internal network'}."]
    desc = " ".join((f.get("description") or "").split())
    if desc:
        first = desc.split(". ")[0].rstrip(".")
        s.append((first[:297] + "..." if len(first) > 300 else first) + ".")
    facts = [x for x in (f"published {f['published'][:10]}" if f.get("published") else "",
                         f"weakness {cwes(f)}" if cwes(f) else "") if x]
    if facts:
        s.append(facts[0][0].upper() + ", ".join(facts)[1:] + ".")
    if f["kev"]:
        s.append("CISA lists it as exploited in the wild" + (f" since {f['kev_added']}" if f.get("kev_added") else "")
                 + (", including in ransomware campaigns" if f["ransomware"] else "") + ".")
    else:
        s.append("It is not in CISA's catalogue of exploited vulnerabilities.")
    pct = f.get("percentile")
    s.append(f"EPSS puts the chance of exploitation in the next 30 days at {f['epss']:.1%}"
             + (f", higher than {pct:.0%} of all CVEs" if pct else "") + ".")
    if cited:
        s.append(f"Threat groups in your profile known to exploit it: {', '.join(sorted(set(cited)))}.")
    elif shared:
        s.append(f"It enables ATT&CK techniques used by {len(shared)} of your profiled groups ({', '.join(shared)}).")
    if techs:
        s.append("If exploited, an attacker could achieve: " + "; ".join(
            f"{(tacs.split(',')[0] or 'unmapped tactic').replace('-', ' ')} ({tid} {name})" for tid, name, tacs in techs[:4]) + ".")
    lead = {}
    for did, name, tactic in defend:
        lead.setdefault(tactic, f"{name} ({did})")
    if tier_ != "Ignore":
        s.append("Defend (MITRE D3FEND): " + "; ".join(f"{t.lower()} with {lead[t]}" for t in D3_TACTICS if t in lead) + ".")
    step = ACTION[tier_] + (". Ask the supplier to confirm the patch status and limit their access until they do" if a["third_party"] and tier_ in ("Act", "Attend") else "")
    s.append(f"Decision: {tier_}, because {reason}. Next step: {step}.")
    return " ".join(s)


def score(f, p, threat):
    a, w = f["asset"], p["weights"]
    cited = threat["cited"].get(f["cve"], [])
    techs = threat["techniques"].get(f["cve"], [])
    shared = sorted({g for tid, _, _ in techs for g in threat["used"].get(tid, [])})
    overlap = 1.0 if cited else 0.5 if shared else 0.0

    likelihood = w["epss"] * f["epss"] + w["kev"] * f["kev"] + w["ransomware"] * f["ransomware"] + w["threat_profile"] * overlap
    cvss = f["cvss"] if f["cvss"] is not None else CVSS_UNKNOWN
    weight = blast_radius(a, p) if a["third_party"] else a["criticality"]
    impact = cvss / 10 * weight * p["exposure"]["internet" if a["internet_facing"] else "internal"]

    why = [f"EPSS {f['epss']:.2f}"]
    if f["kev"]: why.append("KEV: exploited in the wild")
    if f["ransomware"]: why.append("used by ransomware")
    if cited: why.append(f"exploited by {', '.join(sorted(set(cited)))} (threat profile)")
    elif shared: why.append(f"enables techniques used by {len(shared)} profiled groups")
    why.append(f"CVSS {f['cvss']}" if f["cvss"] is not None else "CVSS n/a (assumed 5.0)")
    if a["third_party"]:
        why.append(f"third party ({a['type']}, {a['data_access']} data"
                   f"{', privileged access' if a['privileged'] else ''}): blast radius {weight:g}")
    else:
        why.append(f"criticality {a['criticality']}")
    if a["internet_facing"]: why.append("internet-facing")
    if not a["version"]:
        why.append(f"version unknown: recent CVEs only ({p['third_party']['recent_days']} days)" if a["third_party"]
                   else "version unknown: assumed affected")

    tier_, reason = tier(f, weight, f["kev"] or bool(cited), p)
    defend, mitigations = countermeasures(techs, threat)
    return {**f, "likelihood": round(likelihood, 3), "impact": round(impact, 3),
            "risk": round(likelihood * impact, 3), "tier": tier_, "cited_by": sorted(set(cited)), "techniques": techs,
            "why": "; ".join(why), "defend": defend, "mitigations": mitigations,
            "diamond": diamond(f, a, p, cited, shared, techs),
            "summary": summary(f, a, cited, shared, techs, tier_, reason, defend)}


def rank(findings, p, threat):
    return sorted((score(f, p, threat) for f in findings), key=lambda r: (-r["risk"], r["cve"]))
