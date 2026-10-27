# examples/

The **Example Organisation**: fictional data bundled so Stenwatch can be tried without any real data. Nothing here describes a real estate.

| File | Used by | What it is |
|---|---|---|
| `profile.example.yaml` | both editions | Organisation, threat groups, weights, tiers. Copy it to `data/profile.yaml` and edit the copy. |
| `assets.example.csv` | both editions | Six owned assets (mail, file, database, firewall, ...). |
| `third_parties.example.csv` | both editions | Five suppliers with their data access. |
| `exceptions.example.csv` | both editions | Four analyst decisions, one of them expired. |
| `services.example.csv` | C# edition | Business services and the assets they depend on. |
| `asset_context.example.csv` | C# edition | Zone, owner and crown-jewel flag per asset. |
| `links.example.csv` | C# edition | Which asset can reach which (for attack paths). |
| `controls.example.csv` | C# edition | One control with dated evidence. |

Run it:

```
dotnet run --project src/Stenwatch.Cli -- --example          # C# edition
python python/run.py --example --skip-collect                  # Python edition
```

The example is read-only: it never writes to your own data folder.
