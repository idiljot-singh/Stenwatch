# Security policy

Stenwatch holds a map of which vulnerable software an organisation runs, so its own security matters.

## Reporting a vulnerability
Please **don't open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository. You'll get an answer within 7 days.

## Scope
In scope: the pipeline code, the local web interface (`python/app.py`, `python/cti/app.html`), the generated
dashboard, and how feed data is parsed.
Out of scope: the upstream feeds themselves (NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK, CTID).

## Built-in controls
The threat model and every control are described in
[docs/guides/WALKTHROUGH.md, sections 10 and 11](docs/guides/WALKTHROUGH.md#11-security-of-the-pipeline-itself).
