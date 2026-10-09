"""Backtest: would Stenwatch's signals have put the CVEs that later became known-exploited near the top?

python tools/backtest.py                 three origins, 180-day horizon, reads cve.db, downloads dated EPSS files
python tools/backtest.py 2026-01-01 90   one origin and a horizon in days

At each origin date T0 we only use what was knowable then: the EPSS file of that day and CVSS. Positives are CVEs that were
NOT yet in CISA KEV at T0 and were added within the horizon. We compare how much work each ranking needs to find them.
Not testable (no point-in-time data): the KEV flag itself, ransomware use, threat-group overlap, asset context.
"""
import csv, gzip, io, random, sqlite3, sys
from datetime import date, timedelta
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
URL = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"
T = yaml.safe_load((ROOT / "profile.example.yaml").read_text(encoding="utf-8"))["tiers"]


def epss_on(day):
    raw = gzip.decompress(requests.get(URL.format(day), timeout=120).content).decode()
    return {r["cve"]: float(r["epss"]) for r in csv.DictReader(l for l in raw.splitlines() if not l.startswith("#"))}


def test(db, t0, days):
    end = t0 + timedelta(days=days)
    epss = epss_on(t0)
    known = {r[0] for r in db.execute("SELECT id FROM kev WHERE date_added <= ?", (str(t0),))}
    later = {r[0] for r in db.execute("SELECT id FROM kev WHERE date_added > ? AND date_added <= ?", (str(t0), str(end)))}
    pop = [(i, cvss or 0.0, epss[i]) for i, cvss in db.execute("SELECT id, cvss FROM cve WHERE published <= ?", (f"{t0}T23:59",))
           if i in epss and i not in known]
    random.Random(1).shuffle(pop)  # ties (CVSS has many) are broken at random, not by id order
    pos = sum(i in later for i, *_ in pop)
    rankings = {"CVSS only": lambda r: -r[1], "EPSS only": lambda r: -r[2], "Stenwatch (EPSS x CVSS)": lambda r: -(0.4 * r[2]) * r[1] / 10}
    rows = []
    for name, key in rankings.items():
        hits, need50, need80 = 0, None, None
        for n, r in enumerate(sorted(pop, key=key), 1):
            hits += r[0] in later
            if need50 is None and hits >= pos * 0.5:
                need50 = n
            if need80 is None and hits >= pos * 0.8:
                need80 = n
                break
        top = sorted(pop, key=key)[:1000]
        rows.append((name, sum(r[0] in later for r in top), need50, need80))
    tiers = {"CVSS >= 9 queue": lambda r: r[1] >= 9, "CVSS >= 7 queue": lambda r: r[1] >= T["track_cvss"],
             "Stenwatch Attend (EPSS>=%s)" % T["attend_epss"]: lambda r: r[2] >= T["attend_epss"],
             "Stenwatch Attend+Track": lambda r: r[2] >= T["track_epss"] or r[1] >= T["track_cvss"]}
    tier_rows = [(n, sum(f(r) for r in pop), sum(f(r) and r[0] in later for r in pop)) for n, f in tiers.items()]
    return len(pop), pos, rows, tier_rows


def show(t0, days, res):
    n, pos, rows, tier_rows = res
    print(f"\nOrigin {t0}, next {days} days: {n:,} CVEs not yet in KEV, {pos} of them became known-exploited")
    print(f"  {'ranking':26} {'hits in top 1000':>17} {'reviews for 50%':>16} {'reviews for 80%':>16}")
    for name, top, a, b in rows:
        print(f"  {name:26} {top:>17} {a:>16,} {b:>16,}")
    print(f"  {'queue':30} {'size':>8} {'caught':>7} {'recall':>7}")
    for name, size, caught in tier_rows:
        print(f"  {name:30} {size:>8,} {caught:>7} {caught / pos:>7.0%}")


if __name__ == "__main__":
    db = sqlite3.connect(f"{(ROOT / 'cve.db').as_uri()}?mode=ro", uri=True)
    origins = [date.fromisoformat(sys.argv[1])] if len(sys.argv) > 1 else [date(2025, 10, 1), date(2026, 1, 1), date(2026, 4, 1)]
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 180
    for t0 in origins:
        show(t0, days, test(db, t0, days))
