# The 15 pillars

Stenwatch is built on the characteristics of a cyber threat intelligence driven vulnerability management tool set out in the research framework (*Research Framework: CTI-Driven Vulnerability Management*, 26 October 2026). The CTI lifecycle (Direction, Collection, Processing, Analysis, Dissemination, Feedback) is the navigation; the pillars are the capabilities inside it.

**Evidence labels.** The research framework labels each characteristic Strong, Moderate or Proposed by how well it is supported in the literature. The *Status* column below is different: it says what Stenwatch does today and how far that has been tested. See [evaluation.md](evaluation.md) for how the tests are defined and what they found.

| # | Pillar | Where | Status |
|---|---|---|---|
| 1 | Exploitation-aware prioritisation | `Collect`, `EvidenceOf` | Done. KEV and ransomware flags are stored as *observed* evidence with source and date; a proof-of-concept is never counted as exploitation. |
| 2 | Predictive exploitation | `Collect`, `Analyse` | Done. EPSS with percentile, model version and pull time; the 30-day horizon is stated next to the number. Supported by the backtest (secondary result, 54 positives, wide interval). |
| 3 | Adversary and campaign context | `Collect.ParseAttack`, `Knowledge` | Done. Groups, techniques, campaigns. A group-to-CVE link taken from ATT&CK description text is labelled *reported*; a shared technique is labelled *technique only* (weaker). The threat-profile overlap in scoring is **Not validated** (see evaluation). Which groups are tracked can be chosen **automatically** from the organisation's sector and country (`targeting.mode: auto`): a keyword match against ATT&CK group text plus recent campaign activity, refreshed whenever ATT&CK is synced, with the reason for every pick shown. **Proposed**, not tested against what actually attacks organisations like yours. |
| 4 | Multi-source fusion | `Process`, `Analyse` | Partly. NVD, KEV, EPSS, ATT&CK, CTID, D3FEND, Defender and local data are joined with their sources kept. **Not done:** detecting and reporting disagreement between sources; the join is a fixed weighted sum. |
| 5 | Continuous reassessment | `History`, `Collect` | Done. Every run is stored; changes (new, entered KEV, EPSS jump, tier up or down, resolved, decision applied or expired) are recorded with the reason. Feed pull times are stored and stale feeds lower confidence. **Not built in:** a scheduler; run the CLI from Task Scheduler. |
| 6 | Asset-aware risk | `Process`, `Defender` | Done. CPE and version matching, supplier blast radius, optional Defender inventory with its own patch-level CVE list. |
| 7 | Multi-factor risk | `Analyse.Score` | Done. EPSS, KEV, ransomware, threat overlap, CVSS, service criticality, exposure, controls. Weights are configurable and **not calibrated**. The output is a tier with a reason, not a claimed probability. |
| 8 | Attack paths | `AttackPaths` | Done, **Proposed**. Paths follow links you declare; whether a vulnerability can be used remotely comes from the CVSS vector or ATT&CK tactic. "Possible, not proven." Whether ATT&CK improves this is Test 2 (**Not run**). |
| 9 | Business impact | `Context` | Done. Services with an organisation-defined criticality (1 to 3) replace the asset's own. Data class, regulation and recovery time are recorded and shown, not scored. |
| 10 | Exposure and controls | `Context`, `Analyse` | Done, **Proposed**. A control counts only with dated, unexpired evidence and only for techniques it declares it counters. Multipliers (0.8, 0.5) and the reachable-exposure factor (1.25) are assumptions, configurable. A confirmed exploited finding stays Act whatever controls exist. |
| 11 | Explainable recommendations | `Analyse`, `Evidence` | Done. Score terms, tier rule, plain-English summary, evidence table, what is known and unknown about exploitation, Diamond Model, D3FEND and ATT&CK mitigations. |
| 12 | Confidence and provenance | `Evidence`, `EvidenceOf` | Done at finding level: every signal has a kind (observed, predicted, vendor, community, heuristic, assumption), source, time and confidence; the finding gets High, Medium or Low. Missing exploitation evidence is shown as *unknown*, not safe. **Not done:** per-datum calibrated confidence. |
| 13 | Relationship graph | `Knowledge` | Done. Built in memory from the tables and findings; questions across adversaries, techniques, weaknesses, assets, services and controls. A relational model holds the same facts; the graph is for queries that cross several of them. |
| 14 | Remediation and verification | `Remediation` | Done. Tasks with SLA, owner and ticket, a state machine, exceptions with expiry, and **automatic verification**: a task is Verified only when a later scan no longer finds the CVE. A claimed fix that is still found reopens the task. **Not done:** pushing tasks to a ticketing system. |
| 15 | Feedback and effectiveness | `Effectiveness`, `AttackValue` | Partly. Time to verify, SLA compliance, share of fixes that held, a temporal backtest harness (coverage, efficiency, effort, average precision, paired bootstrap). Only Test 1 has been run. Weights are not tuned from outcomes. |

## What is and is not claimed

* Nothing here claims Stenwatch reduces risk. It can show whether the work it creates gets verified, and which of its features have been tested.
* Features without a passing test are labelled in the app (Effectiveness page) and are listed in [evaluation.md](evaluation.md).
