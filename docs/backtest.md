# Backtest: do Stenwatch's signals find the CVEs that later get exploited?

Run: `python tools/backtest.py` (reads `cve.db`, downloads the dated EPSS file for each origin date).

**Method.** At an origin date T0 we use only what was knowable then: that day's EPSS file and CVSS. The population is every CVE published by T0 that was **not yet** in CISA KEV (about 218,000). The positives are the ones added to KEV in the next 180 days (22 to 30 per window). We compare how much work each approach needs to find them.

## Results (three windows)

| Origin | New KEV adds | CVSS-only: reviews for 50% | EPSS x CVSS: reviews for 50% | Hits in top 1,000 (CVSS / Stenwatch) |
|---|---|---|---|---|
| 2025-10-01 | 30 | 38,136 | 4,512 | 0 / 7 |
| 2026-01-01 | 27 | 37,758 | 5,942 | 1 / 8 |
| 2026-04-01 | 22 | 49,264 | 6,321 | 0 / 5 |

Queues (share of later-exploited CVEs each would have caught):

| Queue | Size | Recall across the three windows |
|---|---|---|
| CVSS >= 9 ("critical") | about 30,600 | 33%, 22%, 14% |
| Stenwatch **Attend** (EPSS >= 0.1) | about 19,000 | 70%, 67%, 73% |
| CVSS >= 7 | about 108,700 | 90%, 93%, 100% |
| Stenwatch Attend + Track | about 130,000 | 97%, 100%, 100% |

## What it shows
- Ranking by exploitation probability finds half of the later-exploited CVEs after roughly **5,000 reviews, against 38,000 to 49,000** for severity alone.
- The **Attend** tier is the clear win: a smaller queue than "CVSS >= 9" with about **70% recall against 14% to 33%**.

## What it does not show
- **Track is not selective.** Attend + Track is no better than "CVSS >= 7" and is larger. Treat Track as a watch list, not a work queue.
- **The tail is hard.** To reach 80% recall, EPSS ranking needs 41,000 to 102,000 reviews; it is no better than severity there.
- **Small samples.** 22 to 30 positives per window, three overlapping windows. Directional, not a precise rate.
- **Population-wide.** Stenwatch first filters to your own assets (cutting this queue by orders of magnitude); this test measures only the scoring signals.
- **Not testable here:** the KEV flag itself, ransomware use, threat-group overlap and asset context have no point-in-time data. CVSS values are today's NVD values.
