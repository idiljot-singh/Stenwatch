# Backtest summary

Does Stenwatch's ranking find the CVEs that attackers go on to use? Six non-overlapping six-month windows, using only data available on each start day, scored against CISA's Known Exploited Vulnerabilities (KEV) additions. Full method, statistics and limits: [report.html](backtest/report.html) ([PDF](backtest/report.pdf)). Raw numbers: [results.json](backtest/results.json).

**257 later-exploited CVEs** among 1,588,223 CVE-windows (base rate 0.016%).

| Queue | Share of CVEs | Later-exploited CVEs found (95% interval) |
|---|---|---|
| Stenwatch Attend (EPSS >= 0.1) | 6.1% | 40% (34% to 46%) |
| Stenwatch Attend + Track (EPSS >= 0.01 or CVSS >= 7.0) | 54.9% | 90% (86% to 93%) |
| CVSS >= 9 (critical) | 13.0% | 36% (30% to 42%) |
| CVSS >= 7 (high and critical) | 48.2% | 86% (81% to 89%) |

- Attend found 40% from a queue 2.1 times smaller than the CVSS 9+ list, which found 36%. The difference in what they found is not significant (p = 0.329); the size difference is the gain.
- At the same queue size the Stenwatch ranking is clearly better than severity (reading as many CVEs as the CVSS 9+ list holds: 50% against 36%). It is better at small review budgets and worse in the long tail: a CVSS ranking reaches 80% after 42.5% of the list, the Stenwatch score after 58.2%.
- 62% of CISA additions concerned CVEs not yet published at the start of the window, so no ranking could have found them.

> **Correction.** An earlier version of this page said the Attend queue caught about 70% of later-exploited CVEs against about a third for the critical list. That was wrong: it came from a local database missing most 2024 and 2025 CVEs. The figures above replace it.

Reproduce: `python tools/backtest.py` then `python tools/backtest_report.py` (see section 9 of the report).
