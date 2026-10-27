"""Local agent: sends ranked Findings to the hosted dashboard. Asset names are replaced by keyed pseudonyms first.

    python saas/upload.py https://<your-app>.azurewebsites.net [path/to/report.csv]
Key: STENWATCH_TENANT_KEY in Windows Credential Manager (service 'stenwatch') or the environment.
"""
import csv
import hashlib
import hmac
import secrets
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cti.vault import secret  # noqa: E402


def alias_key():
    """Local-only secret for the aliases. Never sent: the server knows the tenant key, so that key can't be the one."""
    k = secret("STENWATCH_ALIAS_KEY")
    if not k:
        import keyring
        k = secrets.token_hex(32)
        keyring.set_password("stenwatch", "STENWATCH_ALIAS_KEY", k)
    return k


def payload(report, key):
    """report.csv rows -> upload rows. Aliases are an HMAC under a local secret, so the server can't reverse them from a name list."""
    def alias(name):
        return "asset-" + hmac.new(key.encode(), name.encode(), hashlib.sha256).hexdigest()[:12]
    out = []
    for r in csv.DictReader(open(report, encoding="utf-8")):
        if r["tier"] not in ("Act", "Attend", "Track"):
            continue
        out.append({"rank": int(r["rank"]), "tier": r["tier"], "risk": float(r["risk"]), "cve": r["cve"],
                    "source": "owned" if r["source"] == "owned" else "supplier",
                    "kev": r["kev"] == "True", "ransomware": r["ransomware"] == "True",
                    "epss": float(r["epss"]), "cvss": float(r["cvss"] or 0),
                    "why": (r["why"].replace(r["asset"], alias(r["asset"])) if r["asset"] else r["why"])[:300], "asset": alias(r["asset"])})
    return out


if __name__ == "__main__":
    base = sys.argv[1].rstrip("/")
    key = secret("STENWATCH_TENANT_KEY")
    if not key:
        sys.exit("no STENWATCH_TENANT_KEY")
    if not base.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        sys.exit("https only: the tenant key must not travel in clear")
    rows = payload(sys.argv[2] if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent / "out" / "report.csv", alias_key())
    r = requests.post(f"{base}/api/findings", json=rows, headers={"X-Tenant-Key": key}, timeout=60)
    print(r.status_code, r.text.strip())
