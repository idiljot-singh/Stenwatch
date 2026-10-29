# Stenwatch privacy policy

Last updated: 29 October 2026

Stenwatch is a desktop app that runs on your own computer. It has no user accounts, no telemetry and no analytics, and the author receives no data from it.

## What stays on your computer
Everything you give Stenwatch stays in its data folder on your machine: your organisation profile, asset and supplier lists, Microsoft Defender exports, decisions and marks, the vulnerability database and every report. Nothing of this is uploaded by Stenwatch.

## What Stenwatch downloads
Public information only: NIST NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK and D3FEND, the CTID mappings, and the advisory feeds you enable (by default NCSC-FI, CERT-EU, CISA, Microsoft MSRC and Chrome Releases). These requests carry no information about you or your organisation. "Check for updates" asks GitHub for the latest release (not used when installed from the Microsoft Store).

## Optional AI features (off by default)
If you switch on the LLM option and give it a key, Stenwatch sends public advisory text and product names to the model you chose (OpenRouter, or a model on your own machine). It never sends machine counts, your sector or country, or TLP:AMBER or TLP:RED text to a cloud model; pasted emails have IP addresses and host names removed first. What the provider does with that text is governed by its own privacy policy.

## Keys
API keys you enter are stored in Windows Credential Manager on your computer.

## Contact
Questions: open an issue at https://github.com/idiljot-singh/Stenwatch/issues
