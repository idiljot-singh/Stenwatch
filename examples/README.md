# examples/

The **Example Organisation**: a fictional engineering and construction company of about 1,600 staff, bundled so every part of Stenwatch can be tried without real data. Nothing here describes a real estate.

Its business runs on servers and network drives: project and CAD data on Windows file servers and Synology storage, an SAP ERP, a SQL Server project database, Exchange, a PHP/WordPress customer portal, Jira, Confluence, GitLab and Jenkins, VMware, Veeam backups, FortiGate remote access, Cisco and Aruba networks, and 2,800 endpoints and phones.

| File | Used by | What it is |
|---|---|---|
| `profile.example.yaml` | both editions | Organisation, threat groups, weights, tiers. Copy it to `data/profile.yaml` and edit the copy. |
| `assets.example.csv` | both editions | 41 owned assets, one row per product and version (servers, network, endpoints, applications). |
| `third_parties.example.csv` | both editions | Six suppliers with their data access (MSP, backup, file exchange, partner access, payroll). |
| `exceptions.example.csv` | both editions | Four analyst decisions, one of them expired. |
| `services.example.csv` | C# edition | 14 business services, their criticality, data and the assets they run on. |
| `asset_context.example.csv` | C# edition | Zone, owner and crown-jewel flag per asset. |
| `links.example.csv` | C# edition | 30 can-reach links (network drives, database connections, admin and trust relationships), for attack paths. |
| `controls.example.csv` | C# edition | Eight controls with dated evidence; one is too old to count. |
| `history.example.csv` | C# edition | Versions some assets ran before their upgrades. The example replays eight weeks of runs from them, so Feedback, "what changed" and Effectiveness have data. Simulated, and labelled so. |
| `inventory.example.csv` | C# edition | The raw inventory export the asset list comes from: 2,844 hosts, one row each. Try Convert inventory on it. |
| `apps.example.csv` | C# edition | An Intune-style "discovered apps" report: semicolon-separated, one row per program and version with a device count. |
| `sbom.example.json` | C# edition | A CycloneDX SBOM of the customer portal: PHP, WordPress, OpenSSL and libraries a host inventory cannot see. |
| `advisory.example.txt` | Morning triage | A fictional Finnish advisory email to try "Add advisory email" with (it names CVE-2026-9998 and says it is actively exploited). |
| `evaluation/` | C# edition | The published evaluation results (docs/evaluation.md), shown on Effectiveness until you run the evaluation yourself. |

Run it:

```
dotnet run --project src/Stenwatch.Cli -- --example          # C# edition
dotnet run --project src/Stenwatch.Cli -- --convert-inventory examples/inventory.example.csv   # see what an export converts to
```

The example is read-only: it never writes to your own data folder. Its simulated task history lives next to its reports (`out/example-cs/example-state.db`) and is rebuilt on every rank.
