# Does ATT&CK help? Pre-registered evaluation

Written 2026-10-26, before any evaluation was run. Showing ATT&CK technique IDs is not evidence that they make the tool better. Each ATT&CK-derived feature below must beat a baseline on a metric fixed here, or it is labelled accordingly in the app, the reports and the documentation.

The same harness covers the other frameworks Stenwatch displays (SSVC tiers, Diamond Model, D3FEND) where a test is possible. Frameworks that cannot be tested with outcome data are labelled *Display-only*.

## Evidence labels (shown in the product)

| Label | Meaning |
|---|---|
| **Validated** | Beat its baseline on the pre-registered metric, with the stated confidence. |
| **Not shown** | Tested properly; no demonstrable benefit. The feature stays visible as context but is removed from scoring. |
| **Not applicable** | The data needed by the test does not exist at prediction time (for example a mapping that only exists after the event). |
| **Display-only** | Cannot be tested with outcome data. Stays as explanation, makes no claim about accuracy. |
| **Not run** | Required input (reference chains, analyst ratings) has not been supplied yet. |

## Test 1: does ATT&CK overlap improve prioritisation?

**Question.** Among CVEs not yet known to be exploited, does adding the threat-profile overlap (`threat_profile` weight in the likelihood) rank the CVEs that later enter CISA KEV higher than EPSS alone?

**Design.** Temporal backtest. Prediction date `T0` is 180 days before the latest KEV `dateAdded` in the database. Everything the ranking uses must be knowable at `T0`:

* Population: CVEs published on or before `T0` that were **not** in KEV at `T0`.
* Outcome (positive): the CVE is added to KEV in `(T0, T0 + 180 days]`.
* EPSS: the FIRST archive file for `T0` (not today's scores).
* ATT&CK groups and techniques: the last ATT&CK release published on or before `T0`.
* CTID KEV-to-ATT&CK mapping: the last release dated on or before `T0`.
* CVSS: from the database; a score revised after `T0` is a small leak, reported as a limitation.

**Rankings compared.**

| | Ranking |
|---|---|
| a | CVSS only |
| b | EPSS(`T0`) only (the baseline for the lift question) |
| c | b + overlap: `0.4*EPSS + 0.2*overlap`, overlap 1.0 if a profiled group's ATT&CK text names the CVE, 0.5 if a CTID mapping gives a technique a profiled group uses, else 0 (the product's weights, ATT&CK as of `T0`) |

The profile is the bundled threat-group set (`profile.example.yaml`). A second run uses all ATT&CK groups, to check the result is not an artefact of the group choice.

**Metrics.** Average precision; coverage, efficiency and effort at top 100, 500 and 1000 (the EPSS evaluation measures); positives per 1000 CVEs ranked. Ties are broken pseudo-randomly over 20 seeds. The lift of c over b is the paired-bootstrap 95% interval of the average-precision difference (1000 resamples, fixed seed).

**Decision rule.**

* **Validated**: lower bound of the interval > 0 *and* overlap present for at least 5% of the positives.
* **Not applicable**: overlap present for fewer than 1% of the candidates, or for none of the positives. The test cannot detect an effect, and the result says so rather than "no effect".
* **Harmful**: upper bound < 0.
* **Not shown**: anything else.

**Threats to validity, tested not assumed.**

* *Circularity.* CTID maps techniques only for CVEs already in KEV when the mapping was made, so for candidates (not in KEV at `T0`) the technique mapping is empty by construction. The harness reports the share of candidates and of positives with any mapping at `T0`.
* *Leakage.* Group-to-CVE links come from ATT&CK description text written after exploitation. Using the release as of `T0` removes later text. A CVE named in an ATT&CK release before `T0` but not in KEV is the only case where the feature could carry new information.
* *Thin coverage.* Reported as above.
* *Multiple comparisons.* One primary comparison (c vs b, bundled profile). The all-groups run and every other cut are secondary and labelled so.

**What a negative result means.** `threat_profile` weight is set to 0 in the shipped profile and the overlap is relabelled "context, not a scoring input". The ATT&CK view, mitigations and Diamond Model stay as explanation.

## Test 2: does ATT&CK improve attack-path interpretation?

**Question.** When the path engine decides which vulnerabilities let an attacker move, does using ATT&CK tactics (initial access, lateral movement) produce paths closer to documented intrusions than using CVSS vectors alone, or than assuming nothing?

**Design.** Ablation on one graph: vector only, ATT&CK only, both, and "unknown assumed network-exploitable". Reference set: published intrusion reports that name the vulnerabilities and the order of movement, encoded in `docs/evaluation/chains.csv` with a **source URL for every row**. Each chain is run on a graph rebuilt from the report.

**Metrics.** Hop precision and recall against the documented chain; false paths per target (paths found that the report does not support); path-count reduction compared with the "assume network" variant.

**Inputs not supplied.** No reference chains are bundled, because they must come from sources that can be cited and checked; inventing them would defeat the test. **Status: Not run** until `chains.csv` has at least five sourced chains. Decision rule once run: **Validated** if ATT&CK (alone or with vectors) has higher hop recall than vector-only at no worse precision on at least 4 of the chains; otherwise **Not shown**.

## Test 3: are D3FEND / ATT&CK mitigation recommendations better than generic advice?

**Question.** For findings with a technique mapping, are the technique-specific recommendations rated more useful by analysts than a generic baseline (patch plus the five most common mitigations across all findings)?

**Design.** `Stenwatch --rating-sheet` exports a blind sheet (random order, labels hidden) for 30 findings. Raters score each list 1 to 5 (useful and specific, to wrong or generic). `--rating-import` summarises it.

**Metrics.** Mean rating difference with a paired-bootstrap 95% interval; share of findings with any technique mapping (coverage); share of recommendations already satisfied by a recorded control.

**Decision rule.** **Validated** if the interval's lower bound is above 0.5 points and coverage is reported. Otherwise the recommendations stay labelled **Proposed**. No outcome data exists for "did the recommendation reduce risk", so the label can go no higher than rated usefulness. **Status: Not run** until ratings exist.

## Other frameworks

| Item | Test | Expected label |
|---|---|---|
| SSVC tiers (Act/Attend/Track/Ignore) | Compare the tier ordering with the continuous risk ordering on the Test 1 population using the same outcome | Reported with the same rule |
| Diamond Model | No outcome measure exists | Display-only |
| D3FEND countermeasure lists | Test 3 | As Test 3 |
| ATT&CK tactics in path capability | Test 2 | As Test 2 |

## Reproducibility

Every number comes from `Stenwatch --evaluate-attack`, which downloads the archives, writes the inputs it used (file names, dates, row counts) next to the results, and fixes all random seeds. Nothing is published as a claim until the script's output has been checked and the database coverage of the evaluation window has been confirmed. Negative results are reported as they are.

## Results

### 2026-10-26: first run of Test 1

Run with `Stenwatch --evaluate-attack` on the local database (NVD complete to 2026-10-09; KEV to 2026-10-08). T0 = 2026-04-11. 339,837 candidates, 54 later entered KEV. Inputs: EPSS archive for T0, ATT&CK Enterprise v18.1, CTID release attack-16.1/kev-07.28.2025.

| | Result |
|---|---|
| ATT&CK overlap (bundled profile) | present for 1 of 339,837 candidates and 0 of 54 positives. **Not applicable.** |
| ATT&CK overlap (all 172 groups) | present for 6 candidates and 0 positives. **Not applicable.** |
| CTID technique mapping | present for 0 candidates. This is the circularity named above: the mapping only exists for CVEs already in KEV. |
| EPSS over CVSS (secondary, pillar 2) | average precision 0.0028 vs 0.0004; lift +0.0024, 95% interval [+0.0007, +0.0060]. With 54 positives the interval is wide. |

**Reading.** The test cannot say whether ATT&CK overlap helps, because the feature barely exists for the CVEs one is trying to predict. It does not show that overlap is useless, and it does not show that it works. The pre-registration did not define the product consequence of *Not applicable*. Decided afterwards and recorded here: the overlap is labelled **Not validated** in the app and reports, and stays visible as context; whether it keeps a scoring weight is a decision for the profile owner. Re-running on later windows will change the numbers, not the structure of the problem.

Test 2 (attack-path interpretation) and Test 3 (recommendation ratings): **Not run**; they need sourced reference chains and analyst ratings that have not been supplied.
