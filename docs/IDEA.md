# Stenwatch: the idea

Stenwatch is a threat-informed CVE prioritisation tool. It watches the whole global vulnerability feed and narrows it to the few CVEs that need action in one organisation, with a reason for every decision.

## The problem

About 40,000 CVEs are published every year, and most teams rank them by CVSS. CVSS measures how bad a flaw could be, not whether anyone is using it against that organisation.

## The idea

Every CVE is judged by three questions:

1. Do we run it? Owned assets are matched by product (CPE) and version.
2. Do our suppliers run it? Third parties are weighted by blast radius: the data they hold and the access they have.
3. Are the attackers who target us using it? Known exploitation (CISA KEV), predicted exploitation (FIRST EPSS) and the adversary groups in the organisation's threat profile (MITRE ATT&CK with CTID mappings).

The result is a ranked, explainable list in four SSVC decision tiers: Act (within 48 h), Attend, Track and Ignore.

## How it works

- It follows the full CTI lifecycle: Direction, Collection, Processing, Analysis, Dissemination and Feedback, one module per stage.
- `risk = likelihood × impact`. Every term is written out next to each finding, with a plain-English summary of what it is, how likely it is to be used, by whom, what an attacker gains and what to do.
- It is deterministic. The same inputs give a byte-identical ranking, and all weights live in one YAML file.
- An optional LLM only writes the management brief and never scores.
- Each finding lists MITRE D3FEND countermeasures and ATT&CK mitigations, plus a projected Diamond Model (adversary, capability, infrastructure, victim).

## Inputs and outputs

- Inputs: an organisation and threat profile, the software it runs, its suppliers and analyst exceptions.
- Outputs: an analyst dashboard, a Markdown report, a management brief, a CSV and a STIX 2.1 bundle for MISP, OpenCTI or Sentinel.
- Interfaces: a command-line runner and a local web console that walks through each stage and streams its output.

## Design principles

- Small: plain Python, 4 dependencies, SQLite, no servers.
- Secure by design: localhost-only console with CSRF and DNS-rebinding protection, secrets in the OS credential store, hash-pinned dependencies, TLP:AMBER marking and feed-poisoning guards.

## Optional: running it for a whole organisation on Azure

- A scheduled Container Apps Job (or Functions timer) runs collection and ranking every few hours.
- The console runs on Container Apps or App Service behind Entra ID sign-in, with Analyst and Viewer roles.
- Azure Database for PostgreSQL gives everyone one shared CVE store.
- Blob Storage holds the versioned inputs and the generated reports.
- Key Vault and a Managed Identity hold the secrets.
- The STIX bundle goes to Microsoft Sentinel as threat intelligence, so Act-tier CVEs can drive incidents.
- An Azure AI Foundry model deployment writes the management brief inside the organisation's own tenant.
- Defender for Endpoint or Azure Resource Graph keeps the asset list current automatically.
- Azure Monitor and Log Analytics provide logging and alerts.
