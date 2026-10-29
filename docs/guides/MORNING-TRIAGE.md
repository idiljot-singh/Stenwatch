# Morning triage

Take the Microsoft Defender vulnerability export, add what the feeds and national advisories say, and get **fix actions** in order, each with its reason. One row is one thing to do ("update Edge to 154.x"), with every CVE it clears.

## Each morning
1. In Defender: Vulnerability management, Vulnerabilities, Export. Save the file (`export-tvm-vulnerabilities*.xlsx`) in one folder.
2. Stenwatch, **Morning triage**. First time: **Folder...** and pick that folder. After that, just **Run triage**.
3. Read the grid top to bottom. Click a row: the **Detail** tab shows its CVEs and the advisories that matched. Every **?** icon explains the thing next to it.
4. Disagree? Type a reason, press **Raise**, **Lower**, **Snooze** (with a date) or **Agree**. The mark is kept and shown tomorrow.
5. **Note to IT** tab: **Copy** gives the message for the IT team. **Briefing** and **Excel** open the page and the spreadsheet.

## What it does
- Reads the export even when Excel has split the CSV across columns.
- Joins each CVE to the local `cve.db` (CISA KEV, EPSS). Without `cve.db` it uses Defender's own fields only.
- Groups by product and the highest fixed version the descriptions name.
- **Tier**, by fixed rules, each row says which rule fired:
  - **Act**: KEV lists one of its CVEs, or an advisory says it is actively exploited (English or Finnish wording).
  - **Attend**: an advisory names its CVE or product, or reports a working exploit, or Defender marks it exploited, or EPSS is 5% or more, or high severity on an internet-facing product on 100+ machines.
  - **Track**: other high or critical. **Ignore**: the rest.
- **Feeds** fetches every enabled source (Settings, Intelligence sources, or the toolbar's sources icon): NCSC-FI, CERT-EU, CISA advisories, Microsoft MSRC (only CVEs Microsoft marks exploited) and Chrome Releases. Add any RSS or Atom feed. Each source has a **grade** (A-F: "actively exploited" from A or B means Act, from C-F means Attend) and a **TLP** (CLEAR may go to a cloud LLM, AMBER only to a local model, RED to no LLM). Advisories that match nothing in the export are listed, in case Defender does not see that product.
- **Threat groups** come from MITRE ATT&CK (cve.db) and from advisory text that names a group. A group linked to a CVE raises the fix action to at least Attend. Never from a model's memory.
- **Intel card** (Detail tab): what the evidence says, one cited line per source ([n] = the numbered source listed under it). With LLM on, the top six Act/Attend actions get a written card (Exploited / Who / Real-world severity / Why it matters here); a line without a valid citation, or that is not one of those four, is dropped. Cards are cached in `intel-cache.json`.
- **LLM** (OpenRouter, `nvidia/nemotron-3-ultra-550b-a55b:free`, no credits needed; the paid id without `:free` returns HTTP 402 until credits are bought; free requests are slow, up to a few minutes for a run): reads advisories that name no CVE, extracts CVEs and products, writes a two-sentence English summary, and drafts the note to IT. It cannot set a tier. A CVE id or an "actively exploited" claim is accepted only if the advisory text contains it (the claim needs a quote). Any failure leaves the rule-based result. Add the key on the Settings page. To change model or endpoint, put lines in `llm.txt` in the data folder, for example `model=...` and `url=http://localhost:11434/v1` for a local Ollama (no key, nothing leaves the machine; try `qwen2.5:7b-instruct`, Finnish is weaker in small models). Only public advisory text is sent, with IP addresses and host names removed.
- **Advisory...** takes a saved `.txt` or `.eml`. Try `examples/advisory.example.txt` (fictional, Finnish).

## Limits, stated plainly
- The ladder is a fixed rule set and has **not been validated against outcomes**. It says why, it does not claim to be right.
- No asset list: exposure is Defender's machine count only. A device-level export would let it weigh criticality.
- An advisory that names only a product (no CVE ids) raises that product to Attend. The reason says "product name only"; Lower it if it is noise.
- Only NCSC-FI is a live feed so far. Vendor feeds are not added yet.
- The export is a snapshot. Advisories newer than it show as unmatched until the next export.

Command line: `stenwatch-cli --defender-export FILE [--fetch-feeds] [--llm] [--advisory-file mail.txt]`, and `--triage-flag "Microsoft Edge" Lower "reason" [until]`. Output goes to `out/triage/` in the data folder.
