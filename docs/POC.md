# Proof of concept: fleet-scale run on synthetic data

All numbers below are **synthetic**: a fake inventory in `assets.csv` format (not a vendor export), matched against the real CVE feeds in `cve.db`. No real organisational data is used.

## Run it

```bash
python test_pipeline.py                                   # includes the data-first check
python tools/make_fake_fleet.py                           # writes out/fake_fleet/assets.csv (refuses to overwrite)
python run.py --since 2026-01-01                          # first time only: fills cve.db
python run.py --example --assets out/fake_fleet/assets.csv --skip-collect
```

`--example` takes profile, suppliers and exceptions from the `*.example.*` files, so real files are never read. Reports land in `out/fake_fleet/`.

## Result (cve.db with 8,726 CVEs)

| | Count |
|---|---|
| Raw findings (all matched CVE x asset rows, before tiering) | 1,291 |
| Prioritised (Act + Attend) | 18 |
| Act | 6, all on the data-holding file servers |
| Attend | 12, workstations (6) and app servers (6) |

Same exploited CVEs hit all three Windows rows. Only the data servers become Act, because they are criticality 3 and the rule is exploited AND (internet-facing OR criticality >= 3).

## Explain each stage in your own words

- **Direction:** `profile.example.yaml` says who we are, which attackers matter and the weights.
- **Collection:** NVD, KEV, EPSS and ATT&CK are downloaded into `cve.db`.
- **Processing:** each inventory row is matched to CVEs by product (CPE) and version.
- **Analysis:** risk = likelihood x impact. Impact grows with criticality, so data servers outrank workstations; KEV or a threat-group citation makes a CVE "exploited".
- **Dissemination:** `report.csv` has one written reason per finding.
- **Feedback:** `exceptions.csv` suppresses patched or accepted items until they expire.

## Limits

- Data-holding is a convention: criticality 3 plus `(data)` in the name.
- For CVEs that are **not** exploited, data servers rank higher but the tier does not change.
- Rows are fleet-level (counts in the name); there is no per-machine drill-down.
- The SQL Server row and the example suppliers matched nothing in this CVE set.
