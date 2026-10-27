import os
import sys
import tempfile
from pathlib import Path

os.environ["STENWATCH_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
sys.path.insert(0, str(Path(__file__).parent.parent))  # repo root has its own app.py, so saas/ must come first
sys.path.insert(0, str(Path(__file__).parent))
import app as A  # noqa: E402
import upload  # noqa: E402
import io, contextlib  # noqa: E402,E401

with contextlib.redirect_stdout(io.StringIO()) as o:
    A.seed("Alpha", "a@example.com")
    A.seed("Beta", "b@example.com")
ka, kb = [l.split(": ")[1].strip() for l in o.getvalue().splitlines()]
ROW = dict(rank=1, tier="Act", risk=1.0, cve="CVE-2025-26633", source="owned", kev=True, ransomware=False,
           epss=0.3, cvss=7.0, why="KEV", asset="asset-abc123abc123")
c = A.app.test_client()
H = lambda k: {"X-Tenant-Key": k}  # noqa: E731

assert c.post("/api/findings", json=[ROW]).status_code == 401, "no key"
assert c.post("/api/findings", json=[ROW], headers=H("wrong")).status_code == 401, "bad key"
assert c.post("/api/findings", json=[{**ROW, "extra": 1}], headers=H(ka)).status_code == 400, "unknown field"
assert c.post("/api/findings", json=[{**ROW, "asset": "File server"}], headers=H(ka)).status_code == 400, "real asset name"
assert c.post("/api/findings", json=[{**ROW, "cve": "x"}], headers=H(ka)).status_code == 400, "bad cve"
assert c.post("/api/findings", json=[ROW] * (A.MAX_ROWS + 1), headers=H(ka)).status_code == 400, "too many"
assert c.post("/api/findings", json=[{**ROW, "why": "reach 10.0.0.5 now"}], headers=H(ka)).status_code == 400, "IP in why"
assert c.post("/api/findings", json=[{**ROW, "why": "<b>x</b>"}], headers=H(ka)).status_code == 400, "markup in why"
assert c.post("/api/findings", data="[" * 100000, content_type="application/json", headers=H(ka)).status_code == 400, "deep JSON"
assert c.post("/api/findings", json=[ROW], headers=H(ka)).status_code == 200

os.environ["STENWATCH_DEV_USER"] = "a@example.com"
page = c.get("/")
assert page.status_code == 200 and b"CVE-2025-26633" in page.data
assert page.headers["X-Content-Type-Options"] == "nosniff" and "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
os.environ["STENWATCH_DEV_USER"] = "b@example.com"
assert b"CVE-2025-26633" not in c.get("/").data, "tenant B must not see tenant A"
os.environ.pop("STENWATCH_DEV_USER")
assert c.get("/").status_code == 401, "no sign-in"
os.environ["STENWATCH_TRUST_EASYAUTH"] = "1"
assert c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "a@example.com"}).status_code == 500, "refuse trust when Easy Auth is not enabled"
os.environ["WEBSITE_AUTH_ENABLED"] = "True"
assert c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "A@Example.com"}).status_code == 200, "case-insensitive"
assert c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "a@example.com"}).status_code == 200
os.environ.pop("STENWATCH_TRUST_EASYAUTH")
os.environ.pop("WEBSITE_AUTH_ENABLED")
assert c.get("/", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "a@example.com"}).status_code == 401, "header untrusted unless enabled"
os.environ["STENWATCH_DEV_USER"] = "a@example.com"
os.environ["WEBSITE_SITE_NAME"] = "x"
assert c.get("/").status_code == 401, "dev user must never work on App Service"
os.environ.pop("WEBSITE_SITE_NAME")
os.environ.pop("STENWATCH_DEV_USER")

# XSS: a hostile 'why' must come out escaped
assert c.post("/api/findings", json=[{**ROW, "why": "<script>alert(1)</script>"}], headers=H(kb)).status_code == 400
os.environ["STENWATCH_DEV_USER"] = "b@example.com"

# rate limit
codes = {c.post("/api/findings", json=[ROW], headers=H(ka)).status_code for _ in range(40)}
assert 429 in codes, "rate limit"

assert c.delete("/api/tenant", headers=H(kb)).status_code == 200
assert c.post("/api/findings", json=[ROW], headers=H(kb)).status_code == 401, "erased tenant"

# agent: asset names never leave
rep = Path(tempfile.mkdtemp()) / "r.csv"
rep.write_text("rank,tier,risk,cve,asset,source,kev,ransomware,epss,cvss,why\n"
               "1,Act,1.0,CVE-2025-26633,File server (Windows Server 2019),owned,True,False,0.3,7.0,patch File server (Windows Server 2019) now\n"
               "2,Ignore,0.1,CVE-2025-1111,X,owned,False,False,0,0,w\n", "utf-8")
p = upload.payload(rep, "k")
assert len(p) == 1 and "File server" not in str(p) and A.FIELDS["asset"](p[0]["asset"])
assert all(A.FIELDS[k](v) for k, v in p[0].items()), "agent output must pass the server schema"
print("ok")
