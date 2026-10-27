# data/

**Your own files. Everything here except this note is git-ignored: it is a map of where your organisation is vulnerable, so never commit it.**

| File | What it is |
|---|---|
| `profile.yaml` | Who you are, who targets you, scoring weights, targeting mode. Copy from `examples/profile.example.yaml`. |
| `assets.csv` | Software you run. |
| `third_parties.csv` | Suppliers who run software for you (optional). |
| `exceptions.csv` | Analyst decisions: patched, accepted, and so on (optional). |
| `cve.db` | The vulnerability database: public feeds, plus run history, tasks and your services, links and controls (C# edition). Large (about 500 MB). |
| `out/` | Everything Stenwatch writes: reports, dashboard, brief, STIX, ATT&CK layer, evaluation results. |
| `run.log`, `*.bak` | Run log and automatic backups. |

Where this folder is used:

* Running from a checkout, both editions use `data/`.
* Installed, the C# edition uses `%APPDATA%\Stenwatch` instead. Set `STENWATCH_DATA` to point either edition somewhere else.

To start from blank, delete the contents of this folder (keep this file).
