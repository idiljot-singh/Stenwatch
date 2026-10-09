"""Fill a gap in cve.db by PUBLICATION date (the normal sync is by last-modified date and starts from the oldest CVE):
    .build\\Scripts\\python tools/nvd_fill.py 2024-01-01 2026-10-09
Uses the same parser and the same public NVD API as the product (cti/collect.py); without an API key NVD allows 5 requests per 30 seconds.
The backtest (tools/backtest.py) checks that 2024 and 2025 are complete before it trusts its own numbers."""
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cti import collect  # noqa: E402


def fill(db, start, end, delay=6.5):
    t = start
    while t < end:
        t2 = min(t + timedelta(days=119), end)         # NVD allows at most 120 days per publication window
        params = {"resultsPerPage": 2000, "startIndex": 0, "pubStartDate": t.strftime("%Y-%m-%dT00:00:00.000"), "pubEndDate": t2.strftime("%Y-%m-%dT23:59:59.999")}
        while True:
            r = requests.get(collect.NVD_URL, params=params, timeout=90)
            if r.status_code in (403, 429, 503):
                time.sleep(30)
                continue
            r.raise_for_status()
            data = r.json()
            db.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?)", [collect.parse_nvd(v) for v in data["vulnerabilities"]])
            db.commit()
            params["startIndex"] += data["resultsPerPage"]
            print(f"  {t:%Y-%m-%d}..{t2:%Y-%m-%d}: {params['startIndex']}/{data['totalResults']}", flush=True)
            if params["startIndex"] >= data["totalResults"]:
                break
            time.sleep(delay)
        t = t2 + timedelta(days=1)


if __name__ == "__main__":
    a, b = (datetime.fromisoformat(x).replace(tzinfo=timezone.utc) for x in sys.argv[1:3])
    db = collect.connect(str(ROOT / "cve.db"))
    fill(db, a, b)
    print("cves now:", db.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
