# Stenwatch

Narrows the world's published vulnerabilities to the few that need action in one organisation's estate, and says why.

## Language

**Finding**:
One CVE matched to one asset or supplier, with a risk score and a written reason.
_Avoid_: Alert, hit, vulnerability (for the matched result)

**Tier**:
The decision attached to a Finding: Act (within 48 h), Attend, Track or Ignore.
_Avoid_: Priority, severity, level

**Feed**:
A public source Stenwatch downloads: NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK/D3FEND, CTID mappings.
_Avoid_: Source, API

**Organisation data**:
The files that describe the organisation: profile, assets, suppliers and exceptions. Private, never published.
_Avoid_: Config, inputs

**Example Organisation**:
The bundled fictional organisation used to try Stenwatch without any real data.
_Avoid_: Demo, sample data

**Console**:
The local browser interface that runs each stage and shows its output.
_Avoid_: Dashboard (that is a separate output), UI, app

**Dashboard**:
The generated analyst page of ranked Findings, one of the five outputs.
_Avoid_: Console

**Tour**:
The skippable first-run walkthrough inside the Console.
_Avoid_: Onboarding, wizard (that is the installer)

**Beta installer**:
The Windows Setup wizard that installs Stenwatch for the current user.
_Avoid_: Setup, package
