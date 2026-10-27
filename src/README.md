# src/: the C# edition (0.2, beta)

.NET 8 solution (`Stenwatch.sln`).

| Project | What |
|---|---|
| `Stenwatch.Core` | Everything that is not UI. Collection, matching, scoring, evidence and confidence, run history, services and controls, attack paths, knowledge graph, remediation tasks, effectiveness metrics, the ATT&CK backtest, reports and STIX. |
| `Stenwatch.App` | The WPF desktop app: one page per CTI lifecycle stage plus attack paths, knowledge graph and effectiveness. |
| `Stenwatch.Cli` | `stenwatch-cli`: scheduled runs, imports and the evaluation commands. |
| `Stenwatch.Tests` | xunit tests, including a parity test against the Python edition's output. |

Where things are in `Stenwatch.Core` (pillar numbers refer to [`docs/pillars.md`](../docs/pillars.md)):

| File | Pillar | |
|---|---|---|
| `Collect.cs`, `Secrets.cs` | 1 to 5 | Public feeds into SQLite |
| `Process.cs`, `Defender.cs` | 4, 6 | Matching assets and suppliers to CVEs |
| `Analyse.cs`, `Profile.cs` | 7, 11 | Scoring, tiers, explanations |
| `Evidence.cs` | 12 | Evidence kinds, confidence, what is known about exploitation |
| `History.cs` | 5 | Every run, and why priorities changed |
| `Context.cs` | 9, 10 | Services, asset context, links, controls |
| `AttackPath.cs` | 8 | Possible routes to crown jewels |
| `Knowledge.cs` | 13 | Graph queries across the data |
| `Remediation.cs` | 14 | Tasks, SLA, automatic verification |
| `Effectiveness.cs`, `AttackValue.cs`, `ChainEval.cs` | 15 | Metrics and the pre-registered tests ([`docs/evaluation.md`](../docs/evaluation.md)) |
| `ThreatProfileAuto.cs` | 3 | Choosing threat groups from sector and country |
| `Disseminate.cs`, `Render.cs`, `Llm.cs` | 11 | Reports, dashboard, brief, STIX, ATT&CK layer |
| `Engine.cs`, `Pipeline.cs` | | The whole cycle in one call, used by the app and the CLI |
| `AppPaths.cs` | | Where bundled and user files live |

```
dotnet test src/Stenwatch.Tests
dotnet run --project src/Stenwatch.App
dotnet run --project src/Stenwatch.Cli -- --example
```

The parity test needs `data/cve.db` and a fresh Python baseline (`python python/run.py --example --skip-collect`); without them it skips.
