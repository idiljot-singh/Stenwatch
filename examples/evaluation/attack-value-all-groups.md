# Test 1: does ATT&CK overlap improve prioritisation? (all ATT&CK groups)

Prediction date T0 = 2026-04-11; outcome = added to CISA KEV between T0 and 2026-10-08 (180 days). Candidates: 339837 CVEs published by T0 and not in KEV at T0; 54 positives (0.016%).

## Inputs (all dated on or before T0)

* EPSS: `epss_scores-2026-04-11.csv.gz` (326508 scores)
* ATT&CK Enterprise v18.1 (published 2025-11-13): 172 groups, 189 group-to-CVE links in description text
* CTID KEV mapping release: attack-16.1/kev-07.28.2025 (419 CVEs mapped)
* Groups used: 172 (all); CVSS from the database

## Coverage of the ATT&CK-derived feature among candidates

| Feature | Candidates | Positives |
|---|---|---|
| Any overlap (>0) | 6 (0.002%) | 0 of 54 (0.0%) |
| CVE named in a profiled group's ATT&CK text | 6 | 0 |
| CVE has a CTID technique mapping | 0 | 0 |

## Ranking quality

| Ranking | Average precision | Top 100: found / efficiency | Top 500: found / efficiency | Top 1000: found / efficiency |
|---|---|---|---|---|
| a  CVSS only | 0.0004 | 0.0 of 54 (0.0 %) / 0.0 % | 0.2 of 54 (0.4 %) / 0.0 % | 0.6 of 54 (1.1 %) / 0.1 % |
| b  EPSS(T0) only | 0.0028 | 1.0 of 54 (1.9 %) / 1.0 % | 4.0 of 54 (7.4 %) / 0.8 % | 7.0 of 54 (13.0 %) / 0.7 % |
| c  EPSS + ATT&CK overlap | 0.0027 | 1.0 of 54 (1.9 %) / 1.0 % | 4.0 of 54 (7.4 %) / 0.8 % | 7.0 of 54 (13.0 %) / 0.7 % |

Primary: lift of c over b (average precision) **0.0000**, 95% interval [-0.0001, 0.0000]; share of 1000 resamples where c did not beat b: 100.0 %.

Secondary (pillar 2): lift of EPSS over CVSS alone **+0.0024**, 95% interval [+0.0007, +0.0060]; share of resamples where EPSS did not beat CVSS: 0.0 %. With 54 positives the interval is wide; treat it as supporting evidence, not a precise estimate.

## Result by the pre-registered rule: **Not applicable**

the overlap feature exists for 6 of 339837 candidates and 0 of 54 positives, so this data cannot show an effect either way. This is expected: CTID maps techniques only for CVEs already in KEV, and a group's ATT&CK text names a CVE after it was exploited.

Consequence: the overlap is labelled **Not validated**. It stays visible as context. Whether it keeps a scoring weight is a decision for the profile owner; this test gives no evidence for or against it. (The pre-registration did not define this case.)

## Limitations

* CVSS comes from the current database, so a score revised after T0 leaks a small amount of future information into ranking a.
* Only one window and one outcome (KEV listing) are tested. KEV is not all exploitation; absence from it is not safety.
* Ties are broken pseudo-randomly (5 seeds for the point estimate, one fixed order inside the bootstrap).
