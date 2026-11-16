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

Suggested additions (each gets a row and a tile): **Identity exposure** (Entra risky users, stale privileged accounts), **Misconfiguration** (Defender security recommendations, Secure Score), **End-of-life software** (endoflife.date), **Detection content** (a KQL hunting query per Act finding), **Compliance evidence** (NIS2 / ISO 27001 report from stored tasks and decisions), **Briefing delivery** (email or Teams), **Exposure Management import** (Microsoft's own attack paths next to Stenwatch's), **MSP mode**, **Stenwatch's own SBOM and signed releases**.

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
| **Home** | Dashboard | Overview | Renamed. Adds the line "Coverage: n of 13 connected". |
| | Morning triage | Morning triage | None. |
| | Guided run | (new) | The six CTI stages in order (Direction, Collection, Processing, Analysis, Dissemination, Feedback), each with one sentence, its state, and a button to its page. For first-time users, teaching and the thesis. |
| **Exposure** | Findings | 4 Analysis | Renamed. New *Component* column and filter: findings from every component in one ranked list. |
| | Estate | 3 Processing | Renamed. Same four tabs (services, asset context, links, controls). |
| | Attack paths | Attack paths | None. |
| | Coverage | (new) | One tile per component, in four groups. |
| **Intelligence** | Threat profile | 1 Direction | Renamed. |
| | Feeds | 2 Collection | Renamed. |
| | Advisories | (new) | Every stored advisory with source, grade, TLP and whether it matched; the grid that sits in a Morning triage tab today, given its own page. |
| | Knowledge graph | Knowledge graph | None. |
| **Response** | Remediation | 6 Feedback | Renamed. *Push to ticket* button and a ticket-state column. |
| | Tickets | (new) | Tasks that were pushed, their state and link. |
| | Reports | 5 Dissemination | Renamed. The full report gains a Coverage section. |
| | Effectiveness | Effectiveness | None. |
| **Toolbar icons** | Integrations (plug) | part of Settings | Connectors table (everything that goes in or out: files, APIs, the ticket webhook) and the schedule. Intelligence sources and API keys move here (`BuildSources` in `MainWindow.Triage.cs`, the key rows in `MainWindow.xaml.cs`). |
| | Guide (?) | Guide (rail) | Moves from the rail to an icon. Text updated to the new names. |
| | Theme | (new) | Follow Windows, dark, light. |
| | Settings (gear) | Settings | Keeps your files and updates. |

### The Coverage page

```
EXPOSURE > COVERAGE        5 of 13 connected  [=====------]      (?)

KNOW YOUR ESTATE
[Assets       ] [Attack surface] [Cloud workloads]
[connected    ] [partly        ] [not connected  ]
[2,844 hosts  ] [12 exposed    ] [Import export  ]
[OT and IoT   ] [AI discovery  ] [Identity       ]

FIND WEAKNESSES
[Vulnerabilities] [Web apps] [Misconfiguration]

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
| Coverage counter | "5 of 13 connected" with a thin Accent bar | |
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

| Phase | What | Ships as |
|---|---|---|
| 0 | Security fixes; this document; the HTML mock-up | 0.2.2.0 (fixes only) |
| 1 | Interface: colour tokens and light theme; new navigation and page names; Guided run, Coverage (tiles from data that already exists), Advisories and Integrations pages; Component column; guides, README and Store screenshots updated | 0.3.0 |
| 2 | Scheduler and ticket webhook | 0.3.x |
| 3 | Graph connector: Intune, Entra identity, Defender for Cloud | 0.4.0 |
| 4 | Attack surface (EASM) and web apps (ZAP, SARIF) | 0.5.0 |
| 5 | AI discovery and OT/IoT | 0.6.0 |

Phase 0 is the current round. No app interface code and no new component is built in it.

### Open points

Not solved now, listed for later:

- How a scheduled run starts from a Store-packaged app. Task Scheduler against a packaged path is fragile; a startup task or an alias for the CLI are the candidates.
- Whether Graph sign-in should be interactive (simpler for a security manager) or the certificate app registration `Defender.cs` uses today.
