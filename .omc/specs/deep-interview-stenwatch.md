# Deep Interview Spec: Stenwatch as a professional CTI proof of concept

## Metadata
- Rounds: 6 (plus Round 0 topology)
- Final Ambiguity Score: ~15% (estimated, not formally model-scored)
- Type: brownfield
- Threshold: 0.2
- Threshold Source: default
- Initial Context Summarized: no
- Status: PASSED, pending approval (no execution started)
- Source idea: `docs/IDEA.md`

## Clarity Breakdown (estimated)
| Dimension | Score | Note |
|-----------|-------|------|
| Goal | 0.90 | Make the existing trial a professional, finished product |
| Constraints | 0.80 | Laptop first, data sensitivity known, hosting deferred |
| Success Criteria | 0.75 | Less manual work, clear patch/skip list; metrics not yet numeric |
| Context | 0.85 | Existing code; org inventory source still unconfirmed |

## Topology
| Component | Status | Description | Coverage / Deferral Note |
|-----------|--------|-------------|--------------------------|
| Inventory | active | Systems, installed software and versions | Workstations (entry point) and data-holding systems (impact) in v1 |
| CVE matching | active | Compare inventory against CVEs | Existing CPE and version matching |
| Prioritisation | active | Rank into Act / Attend / Track / Ignore with reasons | Data-holding systems weighted highest for impact |
| Outputs | active | Reports, dashboard, brief, CSV, STIX | Existing outputs; "rest of pipeline" |
| Azure / shared hosting | deferred | Org-wide hosting behind work sign-in | User-confirmed: start on analyst laptop, hosting later |
| Sentinel / Foundry / Defender integrations | deferred | Words from the user's seniors; not understood yet | Future work; user wants to learn by building |

## Goal
Take the current Stenwatch trial and make it a professional, finished proof of concept for an organisation with about 1,800 workstations, data servers and cloud. It compares the list of systems and their software versions against CVEs and ranks them for the Cyber Threat Intelligence process, so analysts get a clear "patch this, skip that" list instead of manual work over too many CVEs. It is a recommendation in the user's thesis on the organisation's CTI process.

## Constraints
- The user is a beginner and wants to learn by building, so explanations and small steps matter.
- First version runs on an analyst laptop. Shared-server or Azure hosting is later work.
- Workstations are the most likely entry point and data is the most important asset: the data-holding systems must carry the highest impact weight.
- Demonstration data: fake inventory in a format typical of such organisations. Not published anywhere; shared only within the organisation and the school at most.
- The organisation is mostly Microsoft plus VMware for servers and is ISO 27001 certified.

## Non-Goals
- Azure, Sentinel, Foundry and Defender integrations in version 1.
- Public release of any real organisational data.

## Acceptance Criteria (derived from answers, to confirm with the user)
- [ ] A realistic fake inventory (workstations plus data-holding servers, with OS and software versions) exists in a format common in organisations.
- [ ] Running the pipeline on that inventory matches CVEs and produces a ranked list with a written reason for each finding.
- [ ] Systems holding data rank higher than equivalent systems that do not.
- [ ] The output clearly separates what to act on from what to skip.
- [ ] Runs on a single analyst laptop with no hosting.
- [ ] The user can explain each stage in their own words (learning goal).

## Open Questions (user to confirm with seniors or supervisor)
- Where the organisation's real inventory lives, and whether it is complete.
- Which export formats that inventory offers, so the fake data matches.
- What numeric evidence the thesis needs to show the tool reduces manual work.

## Assumptions Exposed and Resolved
| Assumption | Challenge | Resolution |
|------------|-----------|------------|
| Azure hosting is part of the idea | Asked where it runs | Came from seniors' words; deferred, start on a laptop |
| The product is for live use | Asked who uses it and with what data | It is a thesis recommendation and proof of concept |
| All system types at once | Asked for v1 scope | Workstations as entry point plus data-holding systems for impact |

## Technical Context
Existing Stenwatch code is taken from the README only (not code-explored in this interview): `run.py`, `app.py`, `cti/` with one module per CTI stage, SQLite `cve.db`, bundled Example Organisation.
