# 0002: Rewrite in C# (WPF) on the 15 research pillars

**Status:** accepted 2026-10-26. The Python version stays in the repository until the installer and the public pages are moved over.

## Context

Stenwatch 0.1 is a Python pipeline with a browser console. It covered the research framework's characteristics 1 to 4, 6, 7 and 11. It stored no history (every sync overwrote the feed tables), had no evidence or confidence model, no way to say what an asset is for, no attack paths, no remediation tracking and no measurement of its own usefulness. ATT&CK data was displayed and used in one scoring term, with no test that it helped.

## Decision

* One .NET 8 solution: `Stenwatch.Core` (everything that is not UI), `Stenwatch.App` (WPF), `Stenwatch.Cli` (scheduled runs), `Stenwatch.Tests`.
* The **CTI lifecycle stays the navigation**; the 15 characteristics from the research framework are the capability layer ([pillars.md](../pillars.md)).
* **Parity first.** The ported pipeline must reproduce the Python output for the Example Organisation: `report.csv` (every column, 6,302 findings), `report.md`, `brief.md` and the STIX object ids. This is a test, and it passes. New behaviour is added only where organisation data is supplied, so with no context scoring is unchanged.
* The feed tables keep the Python schema (one added column, `vector`) so an existing `cve.db` keeps working. History, tasks and organisation context live in the same SQLite file.
* **Frameworks are tested, not displayed.** Each ATT&CK-derived feature must beat a baseline on a metric fixed in advance ([evaluation.md](../evaluation.md)), or it is labelled Not validated, Not shown or Display-only in the product.

## Consequences

* The first result is uncomfortable and kept: the ATT&CK threat-profile overlap cannot be tested on the prediction task because the data it relies on (CTID mappings, ATT&CK group descriptions) is written after exploitation. The overlap is labelled *Not validated*. Whether it keeps a scoring weight is left to the profile owner.
* Proposed multipliers (reachable exposure, control effectiveness) are configurable and labelled as unvalidated.
* The attack-path and recommendation tests are built but **not run**: they need sourced intrusion reports and analyst ratings that nobody has supplied. Inventing them would defeat the tests.
* The Example Organisation never touches the real organisation's context, history or tasks.
