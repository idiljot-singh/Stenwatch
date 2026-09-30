# Plan: Stenwatch as a professional CTI proof of concept (v4)

Status: pending approval (v4: fixes from two review passes applied; not re-reviewed after v4). Source spec: `.omc/specs/deep-interview-stenwatch.md`

## Requirements Summary
Make the existing trial credible as a thesis recommendation for an organisation of ~1,800 workstations plus data servers. Runs on an analyst laptop with realistic fake data. Data-holding systems must outrank equivalent non-data systems. The user is a beginner and must be able to explain every stage.

## Findings from the code
- `cti/process.py:8` `load_assets` reads one row per product (`name,cpe,version,criticality,internet_facing`); real CPE/version matching runs on these rows. `vkey` (`process.py:70`) turns a literal `x` in a version into text that sorts above every number, so fake versions must be concrete builds.
- `cti/defender.py:49-77` `to_assets` groups across the fleet, takes max criticality per group and sets `only_cves` (`process.py:103-108`), which skips CPE matching. Unsuitable for the data-first demo.
- `cti/analyse.py:62-65` gives Act only when the CVE is exploited (KEV or threat-profile citation) and the row is internet-facing or weight >= 3. `analyse.py:161-162` makes impact grow with `criticality`.
- `run.py:19,34,41` read only `ROOT/assets.csv`. `run.py:47-48` merges the real `third_parties.csv`, `run.py:55` applies the real `exceptions.csv`, `run.py:42-46` adds Defender if `profile.yaml` enables it. `--example` (`run.py:83-85`) swaps all four to their `*.example.*` files and writes to `out/example`.
- `test_pipeline.py:55-59,121-123` hold the ranking/tier checks, `:158-167` the Defender test; it uses an in-memory DB (`:27`). CVE-2021-26855 is in it and in KEV (`:31,48`).
- `disseminate.py:57,109,177` print `date.today()`; STIX objects carry creation time.

## Gaps against the spec
1. No fleet-scale fake inventory the tool can run on.
2. The data-first rule has no test.
3. No thesis evidence (raw versus prioritised counts).

## RALPLAN-DR summary
**Principles:** (1) reuse existing fields and code; (2) a beginner can explain every change; (3) no real organisational data ever enters a demo run; (4) scoring stays explainable and the real matching stage is exercised; (5) hosting and integrations stay out of scope.
**Decision drivers:** (a) the data-first rule is provable by a test; (b) the demo exercises real CVE matching; (c) smallest diff.
**Options:**
- A. New `data_sensitivity` column, Defender-shaped fake fleet. Rejected: duplicates `criticality`, Defender path merges roles and skips CPE matching.
- B. Per-machine inventory rewrite. Rejected: large change, conflicts with the no-hostnames design.
- C. Documentation only. Rejected: no data-first rule, no evidence.
- D (chosen). Generator writes a fleet-level `assets.csv` (workstation rows with counts in the name, data servers as separate rows at `criticality` 3). A 3-line `--assets PATH` option in `run.py`, used together with `--example`, runs it without touching real files.
**Why D:** real matching, existing criticality/tier path, real data kept out by the existing `--example` swap.

## Implementation steps
1. **`run.py` (3 lines).** Add `p.add_argument("--assets")`. After the `--example` block: `if args.assets: ASSETS = Path(args.assets); OUT = ASSETS.parent`. Use it as `--example --assets out/fake_fleet/assets.csv`, so profile, suppliers and exceptions come from the example files (no real data, Defender off) and reports land in `out/fake_fleet/`. Confirm `profile.example.yaml` has Defender disabled and `llm: provider: none` (`:66-67`).
2. **`tools/make_fake_fleet.py` (seeded).** Writes `assets.csv`-format rows to `out/fake_fleet/assets.csv` and **exits non-zero if the file already exists**. Rows: `Windows 11 23H2 (1760 workstations)` at criticality 1 and `(data)`-tagged servers at criticality 3, using NVD-real CPEs such as `cpe:2.3:o:microsoft:windows_11_23h2` with concrete builds such as `10.0.22631.2428` (no `x`). Name the exact CPE/version strings in the script header.
3. **Test in `test_pipeline.py`** next to `:55-59`: two rows with the **same CPE**, both `internet_facing=False`, workstation row first (criticality 1) and data row second (criticality 3), against KEV CVE-2021-26855. Assert the data row is ranked first and is Act, and the workstation row is Attend.
4. **Mutation check (manual, once):** set both rows to criticality 1, run `python test_pipeline.py`, confirm the new assert fails, revert.
5. **`docs/POC.md`:** how to run it, counts, and a "explain each stage in your own words" section. Raw count = all matched findings before tiering; prioritised = Act + Attend. All numbers labelled synthetic. Fake data follows `assets.csv` format, not a vendor export. Limit: for CVEs that are not exploited, data rows rank higher but do not change tier.

## Acceptance criteria (each with its command)
- [ ] `python test_pipeline.py` prints `ok`, including the new data-first check.
- [ ] Mutation check (step 4) makes the new assert fail.
- [ ] `python tools/make_fake_fleet.py` succeeds once and exits non-zero on the second run.
- [ ] With a populated `cve.db` (on a fresh laptop first run `python run.py --since 2026-01-01`): `python run.py --example --assets out/fake_fleet/assets.csv --skip-collect` produces `out/fake_fleet/report.csv` with a written reason per finding for ~1,800 workstations and several data servers.
- [ ] Running that command twice the same day gives identical `report.csv` (`diff` empty).
- [ ] The repo-root `assets.csv`, `third_parties.csv`, `exceptions.csv` and `profile.yaml` are unchanged after the run (`git status` / file timestamps).
- [ ] `docs/POC.md` gives raw versus prioritised counts, the not-exploited limit, and the stage-by-stage explanation.

## Risks and mitigations
- Fake data unlike the real inventory. Mitigation: open question for seniors; `assets.csv` is the fallback; other export formats are future work.
- Example exceptions could suppress fake findings. Mitigation: they match by asset name or `*`; check `exceptions.example.csv` when building step 2 names.
- Synthetic numbers overstate benefit. Mitigation: labelled synthetic.
- Fleet-level rows hide per-machine detail. Accepted for a proof of concept.

## ADR
- **Decision:** Option D.
- **Drivers:** provable data-first rule, real matching exercised, real data kept out, smallest diff.
- **Alternatives considered:** A, B, C above.
- **Why chosen:** reuses `criticality`, `tier` and `--example`; one 3-line CLI change.
- **Consequences:** data-holding is a convention on criticality 3; reports for the fake run sit in `out/fake_fleet/`; no per-host drill-down.
- **Follow-ups:** confirm real inventory source and export format; hosting, Defender and Sentinel integrations as future work.

## Changelog
v1 to v2: dropped `data_sensitivity` column and Defender-shaped fleet. v2 to v3: no overwrite of real `assets.csv`, KEV-based test, manual determinism, real CPEs. v3 to v4: added the `--assets` override (both reviewers found `run.py` could not read the fake file), real data excluded via `--example`, concrete build numbers, runnable commands for every criterion including the mutation check, workstation-first row order so the rank assert cannot pass by a tie, corrected ADR.
