"""Point-in-time backtest of Stenwatch's scoring signals.   .build\\Scripts\\python tools/backtest.py        (needs numpy, requests)

Question: if we had ranked every not-yet-exploited CVE on a given day, how well would the ranking have found the ones CISA
added to its Known Exploited Vulnerabilities (KEV) catalogue in the following 180 days?

Design (full write-up: python tools/backtest_report.py -> docs/backtest/report.html):
  * six NON-overlapping 180-day windows; at each origin T0 only data that existed on T0 is used (that day's EPSS file, CVSS, publication date)
  * population  = CVEs published by T0, with an EPSS score on T0, not yet in KEV on T0
  * positives   = members of the population added to KEV in (T0, T0 + 180 days]
  * ties are handled exactly (expected value under random order), so there is no seed and no luck in the numbers
Writes docs/backtest/results.json, which the report reads: no number in the report is typed by hand.
"""
import csv, gzip, hashlib, json, math, platform, sqlite3, subprocess, sys
from datetime import date, datetime, timedelta
from pathlib import Path

import numpy as np
import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "tools" / ".cache" / "epss"
RESULTS = ROOT / "docs" / "backtest" / "results.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"
ORIGINS = [date(2023, 10, 1), date(2024, 4, 1), date(2024, 10, 1), date(2025, 4, 1), date(2025, 10, 1), date(2026, 4, 1)]
HORIZON = 180
BUDGETS = [0.0025, 0.01, 0.05, 0.10]                       # share of the population a team could review
CURVE = [round(10 ** (-3 + 3 * i / 40), 6) for i in range(41)]  # 0.1 % .. 100 % of the population, log-spaced
TIERS = yaml.safe_load((ROOT / "profile.example.yaml").read_text(encoding="utf-8"))["tiers"]   # the product's own thresholds

RANKINGS = {  # name -> (label, score(cvss, epss))
    "stenwatch": ("Stenwatch score (EPSS x CVSS)", lambda c, e: e * c),
    "epss": ("EPSS alone", lambda c, e: e),
    "cvss": ("CVSS alone", lambda c, e: c),
}
QUEUES = {  # name -> (label, rule(cvss, epss))
    "attend": (f"Stenwatch Attend (EPSS >= {TIERS['attend_epss']})", lambda c, e: e >= TIERS["attend_epss"]),
    "attend_track": (f"Stenwatch Attend + Track (EPSS >= {TIERS['track_epss']} or CVSS >= {TIERS['track_cvss']})",
                     lambda c, e: (e >= TIERS["track_epss"]) | (c >= TIERS["track_cvss"])),
    "cvss9": ("CVSS >= 9 (critical)", lambda c, e: c >= 9),
    "cvss7": ("CVSS >= 7 (high and critical)", lambda c, e: c >= 7),
}
SWEEP_EPSS = [0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5]
SWEEP_CVSS = [5, 6, 7, 8, 9, 9.5]


# ----------------------------------------------------------------------------- statistics (small, exact, tested in tools/test_backtest.py)
def wilson(hits, n, z=1.96):
    """95 % Wilson score interval for a proportion."""
    if n == 0:
        return (0.0, 1.0)
    p = hits / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def sign_test(b, c):
    """Exact two-sided binomial test on the discordant pairs of a paired comparison (McNemar, exact)."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def tie_groups(score, y):
    """Sort descending and collapse equal scores. Returns cumulative counts (n, positives) at the END of every tie group plus the group sizes."""
    order = np.argsort(-score, kind="stable")
    s, yy = score[order], y[order]
    edges = np.flatnonzero(np.r_[True, s[1:] != s[:-1]])
    ends = np.r_[edges[1:], len(s)]
    cum_n = ends.astype(float)
    cum_p = np.cumsum(yy)[ends - 1].astype(float)
    n_g = np.diff(np.r_[0, cum_n])
    p_g = np.diff(np.r_[0, cum_p])
    return cum_n, cum_p, n_g, p_g


def hits_at(groups, k):
    """Expected positives among the first k reviewed, when ties are broken at random."""
    cum_n, cum_p, n_g, p_g = groups
    if k <= 0:
        return 0.0
    if k >= cum_n[-1]:
        return float(cum_p[-1])
    g = int(np.searchsorted(cum_n, k, side="left"))
    prev_n = cum_n[g - 1] if g else 0.0
    prev_p = cum_p[g - 1] if g else 0.0
    return float(prev_p + p_g[g] * (k - prev_n) / n_g[g])


def reviews_for(groups, target):
    """Expected number of reviews needed to have found `target` positives."""
    cum_n, cum_p, n_g, p_g = groups
    if target <= 0:
        return 0.0
    if target > cum_p[-1]:
        return float(cum_n[-1])
    g = int(np.searchsorted(cum_p, target, side="left"))
    prev_n = cum_n[g - 1] if g else 0.0
    prev_p = cum_p[g - 1] if g else 0.0
    return float(prev_n + n_g[g] * (target - prev_p) / p_g[g])


def auc(groups):
    """ROC AUC with half credit for ties (the Mann-Whitney statistic)."""
    cum_n, cum_p, n_g, p_g = groups
    neg_g = n_g - p_g
    neg_below = neg_g.sum() - np.cumsum(neg_g)         # negatives in strictly lower-scored groups
    num = float((p_g * (neg_below + 0.5 * neg_g)).sum())
    return num / (p_g.sum() * neg_g.sum())


# ----------------------------------------------------------------------------- data
def load_epss(day):
    """Dated EPSS snapshot, cached on disk. Returns (dict cve -> score, sha256 of the file, row count)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / f"epss_scores-{day}.csv.gz"
    if not f.exists():
        r = requests.get(EPSS_URL.format(day), timeout=180)
        r.raise_for_status()
        f.write_bytes(r.content)
    raw = gzip.decompress(f.read_bytes()).decode()
    rows = {r["cve"]: float(r["epss"]) for r in csv.DictReader(l for l in raw.splitlines() if not l.startswith("#"))}
    return rows, hashlib.sha256(f.read_bytes()).hexdigest(), len(rows)


def window(db, t0):
    end = t0 + timedelta(days=HORIZON)
    epss, sha, n_epss = load_epss(t0)
    known = {r[0] for r in db.execute("SELECT id FROM kev WHERE date_added <= ?", (str(t0),))}
    adds = {r[0] for r in db.execute("SELECT id FROM kev WHERE date_added > ? AND date_added <= ?", (str(t0), str(end)))}
    ids, cvss, score = [], [], []
    missing_cvss = 0
    for i, c in db.execute("SELECT id, cvss FROM cve WHERE published <= ?", (f"{t0}T23:59:59",)):
        if i in epss and i not in known:
            ids.append(i)
            missing_cvss += c is None
            cvss.append(0.0 if c is None else c)
            score.append(epss[i])
    cvss, e = np.array(cvss), np.array(score)
    y = np.array([i in adds for i in ids], dtype=float)
    in_pop = set(ids)
    out = {"origin": str(t0), "end": str(end), "epss_sha256": sha, "epss_rows": n_epss, "population": len(ids), "positives": int(y.sum()),
           "kev_adds_in_window": len(adds), "adds_outside_population": len(adds - in_pop),
           "adds_published_after_origin": sum(1 for a in adds if a not in in_pop and (lambda r: r is not None and r[0] > f"{t0}T23:59:59")(db.execute("SELECT published FROM cve WHERE id=?", (a,)).fetchone())),
           "adds_not_in_database": sum(1 for a in adds if db.execute("SELECT 1 FROM cve WHERE id=?", (a,)).fetchone() is None),
           "missing_cvss": missing_cvss, "base_rate": float(y.mean())}
    out["rankings"], gs = {}, {}
    for name, (label, fn) in RANKINGS.items():
        g = gs[name] = tie_groups(fn(cvss, e), y)
        P, N = y.sum(), len(y)
        out["rankings"][name] = {"auc": auc(g), "reviews50": reviews_for(g, .5 * P), "reviews80": reviews_for(g, .8 * P),
                                 "hits_at_budget": {str(b): hits_at(g, b * N) for b in BUDGETS},
                                 "curve_hits": [hits_at(g, f * N) for f in CURVE]}
    out["queues"], member = {}, {}
    for name, (label, rule) in QUEUES.items():
        m = rule(cvss, e)
        out["queues"][name] = {"size": int(m.sum()), "hits": int((m & (y == 1)).sum())}
        member[name] = [int(v) for v in m[y == 1]]       # per positive: inside this queue or not (for the paired test)
    out["member"] = member
    # equal-size comparison: every ranking reviewed down to exactly the size of each queue
    out["equal_size"] = {q: {r: hits_at(gs[r], out["queues"][q]["size"]) for r in RANKINGS} for q in QUEUES}
    out["sweep_epss"] = [{"t": t, "size": int((e >= t).sum()), "hits": int(((e >= t) & (y == 1)).sum())} for t in SWEEP_EPSS]
    out["sweep_cvss"] = [{"t": t, "size": int((cvss >= t).sum()), "hits": int(((cvss >= t) & (y == 1)).sum())} for t in SWEEP_CVSS]
    # independent re-computation used by the self-checks: queue recall through the ranking machinery
    g_e = tie_groups(e, y)
    out["check_attend_via_ranking"] = hits_at(g_e, out["queues"]["attend"]["size"])
    out["check_ids_unique"] = len(ids) == len(set(ids))
    return out


def aggregate(wins):
    """Pool the windows: recall = pooled positives found / pooled positives, with Wilson intervals and a paired exact test."""
    P = sum(w["positives"] for w in wins)
    N = sum(w["population"] for w in wins)
    agg = {"windows": len(wins), "positives": P, "population": N, "base_rate": P / N, "queues": {}, "rankings": {}, "paired": {}}
    for q in QUEUES:
        hits = sum(w["queues"][q]["hits"] for w in wins)
        size = sum(w["queues"][q]["size"] for w in wins)
        lo, hi = wilson(hits, P)
        agg["queues"][q] = {"hits": hits, "size": size, "share": size / N, "recall": hits / P, "ci": [lo, hi],
                            "precision": hits / size if size else 0, "lift": (hits / size) / (P / N) if size else 0,
                            "per_window": [w["queues"][q]["hits"] / w["positives"] for w in wins]}
    for a, b in (("attend", "cvss9"), ("attend", "cvss7"), ("attend_track", "cvss7")):
        ma = sum((w["member"][a] for w in wins), [])
        mb = sum((w["member"][b] for w in wins), [])
        n10 = sum(1 for x, y in zip(ma, mb) if x and not y)
        n01 = sum(1 for x, y in zip(ma, mb) if y and not x)
        agg["paired"][f"{a}_vs_{b}"] = {"both": sum(1 for x, y in zip(ma, mb) if x and y), "only_a": n10, "only_b": n01,
                                        "neither": sum(1 for x, y in zip(ma, mb) if not x and not y), "p": sign_test(n10, n01)}
    for r in RANKINGS:
        rec = {}
        for b in BUDGETS:
            h = sum(w["rankings"][r]["hits_at_budget"][str(b)] for w in wins)
            rec[str(b)] = {"recall": h / P, "ci": list(wilson(h, P))}
        curve = [sum(w["rankings"][r]["curve_hits"][i] for w in wins) / P for i in range(len(CURVE))]
        aucs = [w["rankings"][r]["auc"] for w in wins]
        agg["rankings"][r] = {"recall_at_budget": rec, "curve": curve, "auc_mean": float(np.mean(aucs)), "auc_sd": float(np.std(aucs, ddof=1)),
                              "auc_per_window": aucs,
                              "reviews50_median": float(np.median([w["rankings"][r]["reviews50"] for w in wins])),
                              "reviews80_median": float(np.median([w["rankings"][r]["reviews80"] for w in wins])),
                              "reviews50_share": float(np.median([w["rankings"][r]["reviews50"] / w["population"] for w in wins])),
                              "reviews80_share": float(np.median([w["rankings"][r]["reviews80"] / w["population"] for w in wins]))}
    agg["equal_size"] = {q: {r: {"recall": sum(w["equal_size"][q][r] for w in wins) / P,
                                 "ci": list(wilson(sum(w["equal_size"][q][r] for w in wins), P))} for r in RANKINGS} for q in QUEUES}
    agg["sweep_epss"] = [{"t": t, "size_share": sum(w["sweep_epss"][i]["size"] for w in wins) / N, "recall": sum(w["sweep_epss"][i]["hits"] for w in wins) / P}
                         for i, t in enumerate(SWEEP_EPSS)]
    agg["sweep_cvss"] = [{"t": t, "size_share": sum(w["sweep_cvss"][i]["size"] for w in wins) / N, "recall": sum(w["sweep_cvss"][i]["hits"] for w in wins) / P}
                         for i, t in enumerate(SWEEP_CVSS)]
    return agg


def checks(wins, agg, db):
    """Self-checks recorded in the report. Each is (what, passed)."""
    c = []
    c.append(("every EPSS snapshot has more than 150,000 scored CVEs", all(w["epss_rows"] > 150_000 for w in wins)))
    c.append(("every window has at least 20 positives", all(w["positives"] >= 20 for w in wins)))
    c.append(("no CVE appears twice in a population", all(w["check_ids_unique"] for w in wins)))
    c.append(("positives are a subset of the KEV additions of the window", all(w["positives"] <= w["kev_adds_in_window"] for w in wins)))
    c.append(("the six windows do not overlap", all(date.fromisoformat(a["end"]) <= date.fromisoformat(b["origin"]) for a, b in zip(wins, wins[1:]))))
    c.append(("Attend queue recall computed by rule equals recall computed through the ranking code (difference < 0.5 positive per window)",
              all(abs(w["queues"]["attend"]["hits"] - w["check_attend_via_ranking"]) < 0.5 for w in wins)))
    c.append(("a perfect ranking would reach AUC 1 and a tie-only ranking AUC 0.5 (unit tests in tools/test_backtest.py)", _run_tests()))
    c.append(("queue sizes shrink as thresholds rise (monotone sweeps)", all(a["size_share"] >= b["size_share"] for s in (agg["sweep_epss"], agg["sweep_cvss"]) for a, b in zip(s, s[1:]))))
    c.append(("pooled recall never exceeds 1 and the 100 % budget finds every positive", all(abs(agg["rankings"][r]["curve"][-1] - 1) < 1e-9 for r in RANKINGS)))
    c.append(("database has complete NVD coverage for 2024 and 2025 (more than 30,000 CVEs per year)",
              all(db.execute("SELECT COUNT(*) FROM cve WHERE published LIKE ?", (f"{y}%",)).fetchone()[0] > 30_000 for y in (2024, 2025))))
    return [{"check": a, "passed": bool(b)} for a, b in c]


def _run_tests():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "test_backtest.py")], capture_output=True, text=True)
    return r.returncode == 0


def main():
    db = sqlite3.connect(f"{(ROOT / 'cve.db').as_uri()}?mode=ro", uri=True)
    wins = []
    for t0 in ORIGINS:
        w = window(db, t0)
        print(f"{w['origin']}: population {w['population']:,}, positives {w['positives']} of {w['kev_adds_in_window']} KEV additions", flush=True)
        wins.append(w)
    agg = aggregate(wins)
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    if subprocess.run(["git", "status", "--porcelain", "tools", "cti"], capture_output=True, text=True, cwd=ROOT).stdout.strip():
        commit += " + uncommitted changes"
    kev = db.execute("SELECT COUNT(*), MIN(date_added), MAX(date_added) FROM kev").fetchone()
    res = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "code_commit": commit, "python": platform.python_version(), "numpy": np.__version__,
           "horizon_days": HORIZON, "tiers": TIERS, "budgets": BUDGETS, "curve_x": CURVE,
           "labels": {"rankings": {k: v[0] for k, v in RANKINGS.items()}, "queues": {k: v[0] for k, v in QUEUES.items()}},
           "database": {"cves": db.execute("SELECT COUNT(*) FROM cve").fetchone()[0], "latest_published": db.execute("SELECT MAX(published) FROM cve").fetchone()[0][:10],
                        "kev_rows": kev[0], "kev_first": kev[1], "kev_last": kev[2],
                        "per_year": {y: db.execute("SELECT COUNT(*) FROM cve WHERE published LIKE ?", (f"{y}%",)).fetchone()[0] for y in range(2019, 2027)}},
           "windows": [{k: v for k, v in w.items() if k not in ("member", "check_attend_via_ranking", "check_ids_unique", "equal_size")} | {"member_n": len(w["member"]["attend"])} for w in wins],
           "pooled": agg, "checks": checks(wins, agg, db)}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(res, indent=1), encoding="utf-8")
    p = agg
    print(f"\npooled: {p['positives']} positives in {p['population']:,} CVE-windows (base rate {p['base_rate']:.3%})")
    for q, v in p["queues"].items():
        print(f"  {QUEUES[q][0]:62} queue {v['share']:6.1%}  recall {v['recall']:5.1%}  95% CI {v['ci'][0]:.0%}-{v['ci'][1]:.0%}")
    for k, v in p["paired"].items():
        print(f"  paired {k}: only A {v['only_a']}, only B {v['only_b']}, p = {v['p']:.3g}")
    for r, v in p["rankings"].items():
        print(f"  {RANKINGS[r][0]:34} AUC {v['auc_mean']:.3f} +/- {v['auc_sd']:.3f}   median reviews to find 50 %: {v['reviews50_median']:,.0f} ({v['reviews50_share']:.1%})")
    failed = [c for c in res["checks"] if not c["passed"]]
    print(f"\nself-checks: {len(res['checks']) - len(failed)}/{len(res['checks'])} passed" + ("" if not failed else "  FAILED: " + "; ".join(c["check"] for c in failed)))
    print("wrote", RESULTS)


if __name__ == "__main__":
    main()
