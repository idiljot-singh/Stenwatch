# Test 1: does ATT&CK overlap improve prioritisation? (bundled threat profile)

Prediction date T0 = 2026-04-29; outcome = added to CISA KEV between T0 and 2026-10-26 (180 days). Candidates: 343109 CVEs published by T0 and not in KEV at T0; 36 positives (0.010%).

## Inputs (all dated on or before T0)

* EPSS: `epss_scores-2026-04-29.csv.gz` (329633 scores)
* ATT&CK Enterprise v19.0 (published 2026-04-28): 174 groups, 189 group-to-CVE links in description text
* CTID KEV mapping release: attack-16.1/kev-07.28.2025 (419 CVEs mapped)
* Groups used: 9 (bundled profile); CVSS from the database

## Coverage of the ATT&CK-derived feature among candidates

| Feature | Candidates | Positives |
|---|---|---|
| Any overlap (>0) | 1 (0.000%) | 0 of 36 (0.0%) |
| CVE named in a profiled group's ATT&CK text | 1 | 0 |
| CVE has a CTID technique mapping | 0 | 0 |

## Ranking quality

| Ranking | Average precision | Top 100: found / efficiency | Top 500: found / efficiency | Top 1000: found / efficiency |
|---|---|---|---|---|
| a  CVSS only | 0.0003 | 0.0 of 36 (0.0 %) / 0.0 % | 0.0 of 36 (0.0 %) / 0.0 % | 0.0 of 36 (0.0 %) / 0.0 % |
| b  EPSS(T0) only | 0.0033 | 1.0 of 36 (2.8 %) / 1.0 % | 4.0 of 36 (11.1 %) / 0.8 % | 7.0 of 36 (19.4 %) / 0.7 % |
| c  EPSS + ATT&CK overlap | 0.0033 | 1.0 of 36 (2.8 %) / 1.0 % | 4.0 of 36 (11.1 %) / 0.8 % | 7.0 of 36 (19.4 %) / 0.7 % |

Primary: lift of c over b (average precision) **0.0000**, 95% interval [-0.0001, 0.0000]; share of 1000 resamples where c did not beat b: 100.0 %.

Secondary (pillar 2): lift of EPSS over CVSS alone **+0.0030**, 95% interval [+0.0007, +0.0085]; share of resamples where EPSS did not beat CVSS: 0.1 %. With 36 positives the interval is wide; treat it as supporting evidence, not a precise estimate.

## Result by the pre-registered rule: **Not applicable**

the overlap feature exists for 1 of 343109 candidates and 0 of 36 positives, so this data cannot show an effect either way. This is expected: CTID maps techniques only for CVEs already in KEV, and a group's ATT&CK text names a CVE after it was exploited.

Consequence: the overlap is labelled **Not validated**. It stays visible as context. Whether it keeps a scoring weight is a decision for the profile owner; this test gives no evidence for or against it. (The pre-registration did not define this case.)

## Limitations

* CVSS comes from the current database, so a score revised after T0 leaks a small amount of future information into ranking a.
* Only one window and one outcome (KEV listing) are tested. KEV is not all exploitation; absence from it is not safety.
* Ties are broken pseudo-randomly (5 seeds for the point estimate, one fixed order inside the bootstrap).
