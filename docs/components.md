# Components and interface design

This is a design for future versions of Stenwatch. None of it is built yet, except where a row says "Have" or "(exists)" for something the app does today. The visual reference is the static mock-up in [`design/mockup.html`](../design/mockup.html) (open it in a browser; it has a dark and a light theme and a Tokens page with every colour). The mock-up is outside `docs/` on purpose, so it is not published on the public site.

The document has five parts: principles, the component map, navigation and pages, interface design, and build order.

## 1. Principles

- Stenwatch is the CTI prioritisation layer on top of Microsoft's sensors. It imports what Defender, Intune, Entra and Defender for Cloud already see. It never becomes a scanner.
- Every component starts as **a file import**, the way Morning triage reads the Defender export: no app registration, and it works inside the Store package. An API pull comes second, through one shared read-only connector built from `Defender.Token` and `Defender.GetAll` (`src/Stenwatch.Core/Defender.cs`).
- Every connector produces rows in one shape (component, asset, item, evidence, source, date). A **fixed, readable ladder** sets Act / Attend / Track / Ignore and names the rule, as `DefenderTriage.Rank` does today. The LLM never sets a tier. Analyst marks (`DefenderTriage.SetFlag`) and tasks (`Remediation`) are reused, not rebuilt.
- A component with no data says so. There are no empty pages that look like they work.

## 2. Component map

Eleven components were named. For each: what Stenwatch has today, the gap, the first step (a file import) and the later step (an API pull).

| Component | Today | Gap | First step (file import) | Later (API) |
|---|---|---|---|---|
| Vulnerability management | Have: NVD, KEV, EPSS, tiers, exceptions, tasks, verification | No scheduler; weights not calibrated | Scheduled morning run | |
| Asset inventory | Have: assets.csv, inventory / Intune apps / CycloneDX convert, Defender API | No live Intune or Entra pull | (exists) | Graph: Intune devices and apps |
| Integrated intelligence | Have: KEV, EPSS, ATT&CK, CTID, D3FEND, five advisory sources, STIX out | No VEX/CSAF, no MISP/TAXII, no source disagreement | CSAF/VEX file reader | TAXII |
| Dashboards and reporting | Have: dashboard, reports, brief, PDF, briefing | No trends, no coverage section | Coverage section in the full report; trend from `History` | Power BI over `report.csv` |
| Ticketing | Partly: tasks with owner, SLA, ticket field; IT note | Nothing is pushed | One webhook (Teams, Jira, ServiceNow, Azure DevOps) | Two-way status |
| Third-party connectors | Partly: Defender API and export, RSS/Atom, MSRC, STIX, Navigator layer | Sentinel, Intune, Defender for Cloud, Tenable/Qualys | Tenable/Qualys CSV import | Sentinel TI upload of the STIX bundle |
| Attack surface management | Partly: internet-facing flag, links, attack paths, suppliers | No outside-in view | Defender EASM export | Shodan/Censys by domain |
| Web application security | Little: SBOM components, WAF as a control | No DAST/SAST findings | OWASP ZAP JSON and SARIF files | GitHub Advanced Security alerts |
| OT and IoT | Little: CPE matching works for hardware if listed; CISA feed carries ICS advisories | No OT inventory, no ATT&CK for ICS | Defender for IoT inventory export | ATT&CK for ICS matrix in `Collect` |
| Cloud workload protection | None | All | Defender for Cloud recommendations export (CSV) | Azure Resource Graph, container images |
| AI discovery | None | All | Defender for Cloud Apps discovered apps, "Generative AI" category | MITRE ATLAS context |

Identity exposure (Entra risky users, stale privileged accounts) is the one further tile that is not in the table above (the Identity tile, in "Know your estate", phase 3). The other additions are in the second table below. Only End-of-life software gets a new tile; the rest are finding types, connectors, outputs or release work that use a place that already exists.

### Extras

| Item | What it is | Where it lives in the app | Phase |
|---|---|---|---|
| End-of-life software | A new finding type: software past vendor support, from the asset list checked against endoflife.date | A 14th Coverage tile (group "Find weaknesses"); rows in Findings | 2 |
| Misconfiguration | A finding type from Defender security recommendations and Secure Score | The existing Misconfiguration tile; rows in Findings | 3 |
| Exposure Management import | A connector: Microsoft's own attack paths and critical assets | An Integrations row; shown on Attack paths next to Stenwatch's own | 3 |
| Detection content | An output: a KQL hunting query for each Act finding, from a fixed template | A button on the finding detail; a file in Reports | 2 |
| Briefing delivery | An output: post the morning briefing to Teams, or save it as a ready-to-send email file | An Integrations row next to the schedule | 2 |
| Compliance evidence | A report: NIS2 / ISO 27001 evidence from stored tasks and decisions | One more output on Reports | 4 |
| MSP mode | Several organisations in one install | An organisation switcher in the toolbar | 6, with its own plan |
| Own SBOM and signed releases | Release engineering, not an app feature | Nothing in the app; a CI step and the release page | SBOM now; signing when a certificate exists |

Every format these components read, and how it was learned, is listed in [`formats.md`](formats.md).

## 3. Navigation and pages

The workspaces are renamed and regrouped **by job**, pages get plain professional names, and the six CTI stages live on a separate **Guided run** page.

Today there are three workspaces over one rail (`Ws0` to `Ws2`, `Nav` and `Pages` in `src/Stenwatch.App/MainWindow.xaml`; `WsClick` and `Go` in `MainWindow.xaml.cs`), with Settings behind an icon. Every existing page keeps its content. What changes is which area it sits in and what it is called.

```
STENWATCH  [Home] [Exposure] [Intelligence] [Response]      (plug) (?) (theme) (gear)  TLP

Home             Exposure         Intelligence       Response
Dashboard        Findings         Threat profile     Remediation
Morning triage   Estate           Feeds              Tickets
Guided run       Attack paths     Advisories         Reports
                 Coverage         Knowledge graph    Effectiveness
```

| Area | Page | Was | Change |
|---|---|---|---|
| **Home** | Dashboard | Overview | Renamed. Adds the line "Coverage: n of 14 connected". |
| | Morning triage | Morning triage | None. |
| | Guided run | (new) | The six CTI stages in order (Direction, Collection, Processing, Analysis, Dissemination, Feedback), each with one sentence, its state, and a button to its page. For first-time users, teaching and the thesis. |
| **Exposure** | Findings | 4 Analysis | Renamed. New *Component* column and filter: findings from every component in one ranked list, including end-of-life software (phase 2) and misconfigurations (phase 3). A finding of type Act gets a *Hunting query (KQL)* button on its detail (phase 2). |
| | Estate | 3 Processing | Renamed. Same four tabs (services, asset context, links, controls). |
| | Attack paths | Attack paths | Phase 3: Microsoft's own attack paths from Exposure Management are listed next to Stenwatch's own, labelled by source. Otherwise none. |
| | Coverage | (new) | One tile per component, in four groups. |
| **Intelligence** | Threat profile | 1 Direction | Renamed. |
| | Feeds | 2 Collection | Renamed. |
| | Advisories | (new) | Every stored advisory with source, grade, TLP and whether it matched; the grid that sits in a Morning triage tab today, given its own page. |
| | Knowledge graph | Knowledge graph | None. |
| **Response** | Remediation | 6 Feedback | Renamed. *Push to ticket* button and a ticket-state column. |
| | Tickets | (new) | Tasks that were pushed, their state and link. |
| | Reports | 5 Dissemination | Renamed. The full report gains a Coverage section. The hunting queries are saved here as files (phase 2); a compliance evidence report (NIS2 / ISO 27001) is one more output (phase 4). |
| | Effectiveness | Effectiveness | None. |
| **Toolbar icons** | Integrations (plug) | part of Settings | Connectors table (everything that goes in or out: files, APIs, the ticket webhook) and the schedule. Briefing delivery (Teams post, or an email file) is a row next to the schedule (phase 2); the Exposure Management import is a row in the table (phase 3). Intelligence sources and API keys move here (`BuildSources` in `MainWindow.Triage.cs`, the key rows in `MainWindow.xaml.cs`). |
| | Guide (?) | Guide (rail) | Moves from the rail to an icon. Text updated to the new names. |
| | Theme | (new) | Follow Windows, dark, light. |
| | Settings (gear) | Settings | Keeps your files and updates. |
| | Organisation switcher | (new) | Phase 6 only (MSP mode, with its own plan): a drop-down in the toolbar to switch between organisations, each with its own data folder. |

### The Coverage page

```
EXPOSURE > COVERAGE        5 of 14 connected  [=====------]      (?)

KNOW YOUR ESTATE
[Assets       ] [Attack surface] [Cloud workloads]
[connected    ] [partly        ] [not connected  ]
[2,844 hosts  ] [12 exposed    ] [Import export  ]
[OT and IoT   ] [AI discovery  ] [Identity       ]

FIND WEAKNESSES
[Vulnerabilities] [Web apps] [Misconfiguration]
[End-of-life  ]

KNOW THE THREAT           ACT AND PROVE
[Intelligence]            [Ticketing] [Reports] [Connectors]
```

A tile shows status (connected / partly / not connected), where the data comes from, when it was last imported, one number, and one button: *Open* (goes to the page that shows it) or *Import* / *Connect*. Not connected tiles are grey and name the exact export they need.

### What the renaming touches outside the app

To be done in phase 1 with the code: `README.md`, `docs/guides/MORNING-TRIAGE.md` and `WALKTHROUGH.md`, the `docs/index.html` wording, `docs/pillars.md` (the "Where" wording), and the screenshots. The four films still show the old names; re-cutting them costs narration credits and is a separate decision.

## 4. Interface design

The decisions: **keep and extend today's look**; components are told apart by **icon and name, not colour**; **dark and light** themes; reviewed first as an **HTML mock-up in real colours** (`design/mockup.html`).

### Colour rule

Colour carries meaning and nothing else: green is the brand and "go", the four tier colours mean Act / Attend / Track / Ignore, amber means "needs your attention". A component never has its own colour.

### Colour tokens

The dark column is what `src/Stenwatch.App/App.xaml` uses today (the loose hex values in it get these names). The light column starts from the print palette already in `src/Stenwatch.Core/Assets/page.html`, with the green and the grey darkened because the originals fell short of the 4.5:1 reading contrast (4.1 and 4.3). All text colours below pass 4.5:1 on both Bg and Card (calculated).

| Token | Dark | Light | Used for |
|---|---|---|---|
| Bg | `#050505` | `#ffffff` | Window, grids |
| Card | `#0b0b0b` | `#f5f6f8` | Tiles, inputs, grid headers |
| Raised | `#151b23` | `#eef1f5` | Buttons |
| RaisedHover | `#1b2430` | `#e4e9f0` | Button and icon hover |
| Line | `#2a3340` | `#d5dae2` | Borders, grid lines |
| LineStrong | `#344050` | `#b8c0cc` | Button and input edges |
| Fg | `#e8edf3` | `#10141c` | Text |
| Mute | `#9aa6b6` | `#4a5568` | Secondary text |
| Dim | `#808c9c` | `#5f6a7a` | Captions, grid headers, "not connected" |
| Accent | `#3ee6a8` | `#087a57` | Brand, selected, primary button, "connected" |
| AccentHover | `#6ff0c0` | `#07704f` | Primary button hover |
| OnAccent | `#03140d` | `#ffffff` | Text on Accent |
| Selected | `#10261f` | `#dcf3ea` | Selected row, selected rail item |
| Act | `#ff4d5e` | `#b00020` | Tier Act, overdue |
| Attend | `#ff9f43` | `#a85400` | Tier Attend |
| Track | `#4ea3ff` | `#1f63c4` | Tier Track |
| Ignore | `#7a8699` | `#5b6676` | Tier Ignore |
| Warn | `#ffc233` | `#8a6100` | Import failed or stale |

TLP chips keep the standard TLP colours in both themes.

### Type and spacing

Unchanged from today, written down so new parts match. Body Segoe UI 13; page title 26 SemiBold; section heading Cascadia Code 11, Accent, capitals; rail and grid headers Cascadia Code 11 to 12; tile number 22 SemiBold; caption 11 Mute. Spacing in steps of 4. Page margin 24. Corners 4 on buttons, 6 on tiles. Borders 1 px Line.

### New interface parts

| Part | What it is | States |
|---|---|---|
| Component tile | Card 220 x 112: icon and name on top, status line, one number, one button | connected, partly, not connected (text Dim, button "Import"), needs attention (Warn); hover and keyboard focus = Accent edge |
| Status mark | Dot plus a word, never colour alone | connected = filled Accent dot; partly = Accent ring; not connected = Dim ring; needs attention = filled Warn dot |
| Component tag | Icon and short name in a grid cell (the new Component column) | plain text colour |
| Connector row | Name, feeds, kind (file / API / webhook), status mark, last run, one action | same four statuses |
| Coverage counter | "5 of 14 connected" with a thin Accent bar | |
| Ticket state | Pill: Not sent, Sent, In progress, Done, Failed | Dim, Track, Attend, Accent, Warn |
| Theme switch | One icon button in the toolbar: follow Windows, dark, light | |

Reused as they are: buttons, Primary button, segments, rail, sub-tabs, grids, the "?" `HelpButton`, tier colours.

### Component icons

Built-in Segoe Fluent Icons, the font the toolbar already uses. Vulnerabilities = bug; Assets = devices; Attack surface = globe; Cloud workloads = cloud; Web apps = web page; OT and IoT = chip; AI discovery = robot; Identity = person; Misconfiguration = wrench; Intelligence = radar; Ticketing = tag; Reports = document; Connectors = plug. The exact glyphs are fixed in the mock-up.

### Accessibility

Status and tier are always a word as well as a colour. Tiles are real buttons with a spoken name ("Cloud workloads: not connected. Import"). Everything is reachable by keyboard with a visible Accent focus edge. At the minimum window (980 x 600) tiles wrap to three per row.

### How light mode is built

This is phase 1, not done yet. The brushes move into two dictionaries (dark, light) and the app's brush references change from fixed to switchable. The theme follows the Windows app setting, with the toolbar switch to override. Reports already have a light print palette; its green changes to the new light Accent so app and paper match.

## 5. Build order

The work runs in phases. Each phase ends with the tests passing, a commit and a short report; the next phase starts only after that. An import is built only against a format someone has seen (see [`formats.md`](formats.md)); until a real export has been read, it stays "from documentation only" and the app says so on that connector.

| Phase | What it contains | Ships as |
|---|---|---|
| 0 | Housekeeping: the security fixes merged to `main`; `samples/` (git-ignored) and `docs/formats.md`; this document and the mock-up with the extras added; Stenwatch's own SBOM (CycloneDX) published by CI | 0.2.2.0 (fixes only, no package until the redesign ships) |
| 1 | Interface: colour tokens as dark and light themes; the four areas (Home, Exposure, Intelligence, Response) and the new page names; toolbar icons for Integrations, Guide, Theme and Settings; the shared `Exposure` row shape and `Coverage`; the Component column in Findings; new pages Guided run, Coverage (tiles from data that exists today, the rest "not connected"), Advisories, Integrations and Tickets (empty until phase 2); the Dashboard coverage line; README, guides and Guide text with the new names | 0.3.0 |
| 2 | Daily operation: scheduled morning run (CLI mode on the newest export in a watched folder, registered with Windows Task Scheduler); ticket push by one webhook; Briefing delivery (Teams post, or an email file); End-of-life software against endoflife.date, with the 14th tile; Detection content (a KQL hunting query per Act finding) | 0.3.x |
| 3 | Microsoft estate: the shared Graph connector, file imports first, for Intune (devices, apps, update compliance), Entra identity exposure (risky users, stale privileged accounts), Defender for Cloud (cloud workloads, container images), Misconfiguration (Defender security recommendations, Secure Score) and the Exposure Management import (Microsoft's attack paths and critical assets) | 0.4.0 |
| 4 | Outside-in and applications: Defender EASM export (feeds the internet-facing flag and Findings); OWASP ZAP JSON and SARIF files as findings; Compliance evidence report (NIS2 / ISO 27001) on Reports | 0.5.0 |
| 5 | AI and OT: Defender for Cloud Apps discovered apps in the generative-AI category, with MITRE ATLAS for context; Defender for IoT inventory import; ATT&CK for ICS added to `Collect` | 0.6.0 |
| 6 | MSP mode: several organisations in one install, a data folder per organisation and a switcher in the toolbar. It touches `AppPaths.Data` and every page that reads the data folder, so it is planned in detail when phase 5 is done | Own plan |
| Release | After the last phase that is approved: Store package and Setup installer; README and Store screenshots retaken. The Setup installer is signed by the build script when a certificate is present; until then the Store build is the signed one. The four films still show the old interface and are re-cut only if decided then | |

Phase numbers are in the order of the plan, not a promise of dates.

### Open points

Not solved now, listed for later:

- How a scheduled run starts from a Store-packaged app. Checked against Microsoft's pages on 2026-11-16 ([`formats.md`](formats.md), Task Scheduler section): the package folder name carries the version and changes with each update, so a task pointing at that path breaks on update; an execution alias in the manifest (`uap5:AppExecutionAlias` or `uap3` with `desktop:ExecutionAlias`, Windows 10 1709 or later) is the documented way to start a packaged program by a fixed name, and the manifest in `installer/msix` has none yet. No Microsoft page says whether Task Scheduler can start such an alias; one community report says it could not be selected as a task action. This stays open until it is tried on a real Store install, and the Setup-edition fallback stands.
- Whether Graph sign-in should be interactive (simpler for a security manager) or the certificate app registration `Defender.cs` uses today.
