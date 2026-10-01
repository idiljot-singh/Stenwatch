"""Write a synthetic fleet-level assets.csv (~1,800 workstations + data servers) to out/fake_fleet/.

Fake data in assets.csv format, not a vendor export. Refuses to overwrite.
Rows (CPE, concrete build; a literal 'x' in a version would sort above every number):
  cpe:2.3:o:microsoft:windows_11_23h2   10.0.22631.2428   workstations, criticality 1
  cpe:2.3:o:microsoft:windows_server_2022 10.0.20348.2113 servers, criticality 3 (data) or 2
  cpe:2.3:a:microsoft:sql_server        2019              data servers, criticality 3
Run: python tools/make_fake_fleet.py, then
     python run.py --example --assets out/fake_fleet/assets.csv --skip-collect
"""
import sys
from pathlib import Path

OUT = Path(__file__).parent.parent / "out" / "fake_fleet" / "assets.csv"
ROWS = """name,cpe,version,criticality,internet_facing
Windows 11 23H2 (1760 workstations),cpe:2.3:o:microsoft:windows_11_23h2,10.0.22631.2428,1,n
Windows Server 2022 (20 app servers),cpe:2.3:o:microsoft:windows_server_2022,10.0.20348.2113,2,n
Windows Server 2022 (data) (file servers),cpe:2.3:o:microsoft:windows_server_2022,10.0.20348.2113,3,n
SQL Server 2019 (data) (customer DB),cpe:2.3:a:microsoft:sql_server,2019,3,n
"""

if OUT.exists():
    sys.exit(f"{OUT} exists; delete it to regenerate")
OUT.parent.mkdir(parents=True)
OUT.write_text(ROWS, encoding="utf-8")
print(f"wrote {OUT}")
