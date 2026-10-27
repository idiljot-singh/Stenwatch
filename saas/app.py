"""Stenwatch hosted dashboard (demo). Receives ranked Findings from the local agent, shows them per tenant.

Hybrid design: assets, suppliers and exceptions never reach this service; see docs/adr/0001-hybrid-saas-on-azure.md.
Run locally:  python app.py seed <tenant> <viewer-email>   then   STENWATCH_DEV_USER=<viewer-email> flask --app app run
"""
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import defaultdict, deque

from flask import Flask, abort, g, jsonify, request

DB = os.environ.get("STENWATCH_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db"))
TIERS = ("Act", "Attend", "Track")
MAX_ROWS = 2000
# field -> validator. Anything not listed is rejected, so the service can't be sent what it shouldn't hold.
FIELDS = {
    "rank": lambda v: isinstance(v, int) and not isinstance(v, bool) and 0 < v < 10**6,
    "tier": lambda v: v in TIERS,
    "risk": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v < 100,
    "cve": lambda v: isinstance(v, str) and re.fullmatch(r"CVE-\d{4}-\d{4,9}", v) is not None,
    "source": lambda v: v in ("owned", "supplier"),
    "kev": lambda v: isinstance(v, bool),
    "ransomware": lambda v: isinstance(v, bool),
    "epss": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1,
    "cvss": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 10,
    "why": lambda v: isinstance(v, str) and len(v) <= 300 and re.fullmatch(r"[A-Za-z0-9 .,;:()'/+-]*", v) is not None
    and not re.search(r"\d+\.\d+\.\d+\.\d+", v),  # known vocabulary only: no hostnames, no IPs
    "asset": lambda v: isinstance(v, str) and re.fullmatch(r"asset-[0-9a-f]{12}", v) is not None,
}
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cache-Control": "no-store",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000
log = logging.getLogger("stenwatch")
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(message)s")
_hits = defaultdict(deque)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA secure_delete = ON")  # erased rows are overwritten, not left in free pages
        g.db.executescript(
            "CREATE TABLE IF NOT EXISTS tenants(id INTEGER PRIMARY KEY, name TEXT UNIQUE, key_hash TEXT UNIQUE, viewer TEXT);"
            "CREATE TABLE IF NOT EXISTS findings(tenant_id INTEGER, uploaded_at TEXT, " + ", ".join(FIELDS) + ");")
    return g.db


@app.teardown_appcontext
def close_db(_):
    if "db" in g:
        g.db.close()


@app.after_request
def secure(resp):
    resp.headers.update(HEADERS)
    return resp


def key_hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def tenant_for_key():
    """Tenant of the X-Tenant-Key header, or 401. Keys are 256-bit random, so a plain SHA-256 lookup is enough."""
    key = request.headers.get("X-Tenant-Key", "")
    row = db().execute("SELECT * FROM tenants WHERE key_hash = ?", (key_hash(key),)).fetchone() if key else None
    if row is None or not hmac.compare_digest(row["key_hash"], key_hash(key)):
        log.info("auth-fail path=%s", request.path)
        abort(401)
    now = time.monotonic()
    q = _hits[row["id"]]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 30:  # ponytail: per-process counter; use the gateway's limiter if this ever scales out
        abort(429)
    q.append(now)
    return row


def viewer_tenant():
    """Tenant of the signed-in user. App Service 'Easy Auth' sets the header; trusted only when told to be."""
    if os.environ.get("STENWATCH_TRUST_EASYAUTH") == "1":
        if os.environ.get("WEBSITE_AUTH_ENABLED", "").lower() != "true":
            abort(500)  # header would be client-controlled: refuse rather than fail open
        user = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    elif os.environ.get("WEBSITE_SITE_NAME"):
        abort(401)  # on App Service the dev user is never honoured
    else:
        user = os.environ.get("STENWATCH_DEV_USER")
    # ponytail: matches the name claim; the Entra app registration must be single-tenant. Match X-MS-CLIENT-PRINCIPAL-ID (oid) for real use
    row = db().execute("SELECT * FROM tenants WHERE viewer = ?", (user.lower(),)).fetchone() if user else None
    if row is None:
        abort(401)
    return row


def clean(rows):
    """Strict schema: exact field set, validated values, bounded size. -> list of tuples or None."""
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        return None
    out = []
    for r in rows:
        if not isinstance(r, dict) or set(r) != set(FIELDS) or not all(FIELDS[k](v) for k, v in r.items()):
            return None
        out.append(tuple(r[k] for k in FIELDS))
    return out


@app.post("/api/findings")
def upload():
    t = tenant_for_key()
    try:
        rows = clean(request.get_json(silent=True))
    except RecursionError:  # absurdly nested JSON
        rows = None
    if rows is None:
        abort(400)
    d = db()
    d.execute("DELETE FROM findings WHERE tenant_id = ?", (t["id"],))  # each upload is a full snapshot
    d.executemany(f"INSERT INTO findings VALUES (?, datetime('now'), {','.join('?' * len(FIELDS))})",  # nosec B608 (placeholders only)
                  [(t["id"], *r) for r in rows])
    d.commit()
    log.info("upload tenant=%s rows=%d", t["id"], len(rows))
    return jsonify(stored=len(rows))


@app.delete("/api/tenant")
def erase():
    """GDPR erasure: removes the tenant and everything stored for it."""
    t = tenant_for_key()
    d = db()
    d.execute("DELETE FROM findings WHERE tenant_id = ?", (t["id"],))
    d.execute("DELETE FROM tenants WHERE id = ?", (t["id"],))
    d.commit()
    log.info("erase tenant=%s", t["id"])
    return jsonify(erased=True)


STYLE = ("body{font:15px system-ui;background:#0a101b;color:#dbe6f3;max-width:1000px;margin:2rem auto;padding:0 1rem}"
         "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #223;padding:.4rem;text-align:left}"
         ".Act{color:#ff4d5e}.Attend{color:#ffb454}.Track{color:#5aa9ff}small{color:#8a9bb0}")


def shell(title, body):
    return f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>{title}</title><style>{STYLE}</style>{body}"


@app.get("/")
def dashboard():
    t = viewer_tenant()
    rows = db().execute("SELECT * FROM findings WHERE tenant_id = ? ORDER BY rank", (t["id"],)).fetchall()
    log.info("view tenant=%s", t["id"])
    e = html.escape
    body = "".join(
        f"<tr><td>{r['rank']}</td><td class={r['tier']}>{e(r['tier'])}</td><td>{r['risk']:.3f}</td><td>{e(r['cve'])}</td>"
        f"<td>{e(r['asset'])} ({e(r['source'])})</td><td>{'KEV' if r['kev'] else ''}</td><td>{e(r['why'])}</td></tr>" for r in rows)
    when = rows[0]["uploaded_at"] if rows else "never"
    return shell("Stenwatch hosted demo",
                 f"<h1>Stenwatch · {e(t['name'])}</h1><p><small>Last upload {e(when)} UTC. Asset names are pseudonyms; "
                 f"the real asset list never leaves the organisation. <a href=/privacy style=color:inherit>Privacy</a></small></p>"
                 f"<table><tr><th>#<th>Tier<th>Risk<th>CVE<th>Asset<th><th>Why</tr>{body}</table>")


@app.get("/privacy")
def privacy():
    return shell("Privacy", "<h1>Privacy</h1><p>Demo service, EU region. It stores ranked vulnerability Findings with pseudonymised "
                 "asset labels, and the sign-in identity of the viewer. No asset names, IP addresses or supplier names are accepted. "
                 "Data is deleted on request (DELETE /api/tenant). Do not upload real organisation data.</p>")


def seed(name, viewer):
    key = secrets.token_urlsafe(32)
    with app.app_context():
        db().execute("INSERT INTO tenants(name, key_hash, viewer) VALUES (?, ?, ?)", (name, key_hash(key), viewer.lower()))
        db().commit()
    print("Tenant key (shown once, store it in Credential Manager as STENWATCH_TENANT_KEY):", key)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "seed":
        seed(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
