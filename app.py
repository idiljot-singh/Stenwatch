"""Stenwatch console: run the pipeline from a browser and watch each CTI stage work.

python app.py        opens http://127.0.0.1:8765 (local only; stop with Ctrl+C)
python app.py --pdf  WALKTHROUGH.md -> WALKTHROUGH.pdf (needs pandoc + Edge or Chrome)

The page never runs arbitrary commands: only the fixed actions in ACTIONS, one at a time.
"""
import csv, json, os, re, secrets, shutil, sqlite3, subprocess, sys, tempfile, threading, time, webbrowser
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

import yaml

from cti import process
from cti.paths import APP, DATA, FROZEN, VERSION, find_browser

ROOT = DATA  # organisation files; APP holds Stenwatch's own files
PORT = 8765  # first free port from here is used
TOKEN = secrets.token_urlsafe(24)  # new per start; a hostile web page can't read or send it
EDITABLE = {"profile.yaml", "assets.csv", "third_parties.csv", "exceptions.csv"}
OUTPUTS = {"dashboard.html": "text/html", "report.html": "text/html", "brief.html": "text/html", "report.pdf": "application/pdf",
           "brief.pdf": "application/pdf", "report.md": "text/plain", "brief.md": "text/plain",
           "report.csv": "text/csv", "bundle.json": "application/json"}
CLI = [str(Path(sys.executable).with_name("stenwatch-cli.exe"))] if FROZEN else [sys.executable, "-u"]  # console-less exe can't pipe output


def py(script, *args):
    return CLI + [str(APP / script), *args]

job = {"lines": [], "running": False, "code": None, "name": ""}
lock = threading.Lock()


def stream(argv, log):
    log("> " + " ".join(Path(argv[0]).stem if i == 0 else Path(x).name if x.endswith(".py") else x for i, x in enumerate(argv) if x != "-u"))
    p = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    for line in p.stdout:
        log(line.rstrip())
    return p.wait()


PRINT_CSS = """
@page{size:A4;margin:16mm 14mm}
body{font:10.5pt/1.5 "Segoe UI",system-ui,sans-serif;color:#1d1d1b;max-width:none;margin:0;padding:0}
h1.title{font-size:22pt;border-bottom:3px solid #c62828;padding-bottom:6px;margin-top:30%;break-before:auto}
.date{color:#6b6b66}hr{display:none}
h1{font-size:16pt;margin-top:0;break-before:page;border-bottom:1px solid #ccc;padding-bottom:3px}
h2{font-size:12.5pt;margin-top:1.2em}h1,h2,h3{break-after:avoid}
#TOC{break-after:page}#TOC ul{list-style:none;padding-left:1em}#TOC>ul>li{margin-top:.3em}
table{border-collapse:collapse;width:100%;margin:.6em 0;font-size:9pt;break-inside:auto}
th,td{border:1px solid #ccc;padding:3px 6px;vertical-align:top;text-align:left}th{background:#f1f1ee}
tr{break-inside:avoid}code{font:9pt Consolas,monospace;background:#f3f3f0;padding:0 3px;border-radius:3px}
pre{background:#f3f3f0;padding:8px;white-space:pre-wrap;word-break:break-word;break-inside:avoid}pre code{padding:0}
a{color:#2e6fb7;text-decoration:none}
"""


def open_window(url):
    """Show the console as an app window (Edge/Chrome, no tabs or address bar), or in the default browser if neither exists."""
    browser = find_browser()
    if browser:
        subprocess.Popen([browser, f"--app={url}", "--window-size=1360,900"])
    else:
        webbrowser.open(url)


IDLE = 150  # seconds without a heartbeat from the page: the window is gone, so quit
last_seen = time.time()


def watch(server, idle=IDLE, every=5):
    """Quit when no page is open any more. Browser-agnostic: it never depends on which process shows the window."""
    while time.time() - last_seen < idle:
        time.sleep(every)
    server.shutdown()


def build_pdf(log):
    browser = find_browser()
    if not shutil.which("pandoc") or not browser:
        log("Needs pandoc (pandoc.org) and Microsoft Edge or Chrome on this machine.")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        page, css = Path(tmp) / "walkthrough.html", Path(tmp) / "print.html"
        css.write_text(f"<style>{PRINT_CSS}</style>", encoding="utf-8")
        # shift -1: the document's own H1 becomes the title page, phases become chapters
        code = stream(["pandoc", str(APP / "WALKTHROUGH.md"), "-f", "gfm", "-s", "--toc", "--toc-depth=1",
                       "--shift-heading-level-by=-1", "--metadata", f"date={date.today()}",
                       "-H", str(css), "-o", str(page)], log)
        if code:
            return code
        # links to local files would resolve to this temp folder and leak its path into the PDF
        html = page.read_text(encoding="utf-8")
        page.write_text(re.sub(r'<a\s+href="(?!https?:|mailto:|#)[^"]*"', "<a", html), encoding="utf-8")
        stream([browser, "--headless", "--disable-gpu", "--log-level=3", "--no-pdf-header-footer",
                f"--user-data-dir={tmp}", f"--print-to-pdf={APP / 'WALKTHROUGH.pdf'}", page.as_uri()],
               lambda line: ":ERROR:" in line or log(line))  # drop Chromium's internal log noise
    ok = (APP / "WALKTHROUGH.pdf").exists()
    log(f"WALKTHROUGH.pdf {'written' if ok else 'NOT written'}")
    return 0 if ok else 1


ACTIONS = {  # name -> (label, function(log, arg))
    "test":  lambda log, _: stream(py("test_pipeline.py"), log),
    "rank":  lambda log, _: stream(py("run.py", "--skip-collect"), log),
    "since": lambda log, d: stream(py("run.py", "--since", date.fromisoformat(d).isoformat()), log),
    "full":  lambda log, _: stream(py("run.py"), log),
    "pdf":   lambda log, _: build_pdf(log),
}


def starter():
    """First run: begin with the Example Organisation's files so no step needs a hand-made CSV."""
    for n in EDITABLE:
        if not (ROOT / n).exists():
            shutil.copy2(APP / n.replace(".", ".example.", 1), ROOT / n)


def start(name, arg):
    if name in ("rank", "since", "full"):
        starter()
    with lock:
        if job["running"]:
            return False
        job.update(lines=[], running=True, code=None, name=name)

    def work():
        try:
            code = ACTIONS[name](job["lines"].append, arg)
        except Exception as e:
            job["lines"].append(f"ERROR {type(e).__name__}: {e}")
            code = 1
        job.update(running=False, code=code)
    threading.Thread(target=work, daemon=True).start()
    return True


def state():
    """Everything the page shows about the current data, read fresh each time."""
    s = {"db": {}, "log": [], "outputs": {}, "top": [], "tiers": {}, "files": {n: (ROOT / n).exists() for n in EDITABLE}}
    if (ROOT / "cve.db").exists():
        db = sqlite3.connect(f"{(ROOT / 'cve.db').as_uri()}?mode=ro", uri=True)
        for t in ("cve", "kev", "epss", "technique", "actor", "cve_technique"):
            try:
                s["db"][t] = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except sqlite3.Error:
                s["db"][t] = 0
        row = db.execute("SELECT value FROM meta WHERE key='nvd_sync'").fetchone()
        s["db"]["nvd_sync"] = row[0] if row else None
        db.close()
    if (ROOT / "run.log").exists():
        s["log"] = (ROOT / "run.log").read_text(encoding="utf-8").splitlines()[-8:]
    for n in OUTPUTS:
        f = ROOT / "out" / n
        s["outputs"][n] = f.stat().st_mtime if f.exists() else None
    if (ROOT / "out" / "report.csv").exists():
        with open(ROOT / "out" / "report.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        s["top"] = rows[:10]
        for r in rows:
            s["tiers"][r["tier"]] = s["tiers"].get(r["tier"], 0) + 1
    s["pdf"] = (APP / "WALKTHROUGH.pdf").exists()
    s["version"], s["frozen"], s["tour"] = VERSION, FROZEN, (ROOT / "tour.done").exists()
    prof = ROOT / "profile.yaml" if (ROOT / "profile.yaml").exists() else APP / "profile.example.yaml"
    s["profile"] = yaml.safe_load(prof.read_text(encoding="utf-8"))
    return s


def validate(name, text):
    """Reject a broken file before it overwrites a working one."""
    if name == "profile.yaml":
        p = yaml.safe_load(text)
        for key in ("organisation", "threat_groups", "weights", "exposure", "third_party", "tiers"):
            if key not in (p or {}):
                raise ValueError(f"missing section: {key}")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8", newline="") as f:
        f.write(text)
    try:
        path = Path(f.name)
        if name == "exceptions.csv":
            process.load_exceptions(path)
        else:
            process.load_assets(path, third_party=name == "third_parties.csv")
    except KeyError as e:
        raise ValueError(f"missing column {e}")
    finally:
        path.unlink()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        body = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def allowed(self, need_token=True):
        # Host check stops DNS rebinding; token check stops other sites driving the API
        if self.headers.get("Host") not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
            self.send(403, {"error": "bad host"})
            return False
        if need_token and not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN):
            self.send(403, {"error": "bad token"})
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/":
            if self.allowed(need_token=False):
                self.send(200, (APP / "cti" / "app.html").read_text(encoding="utf-8").replace("__TOKEN__", TOKEN), "text/html")
        elif url.path.startswith("/out/") or url.path == "/WALKTHROUGH.pdf":
            # outputs open in new tabs, so they carry the token in the URL instead of a header
            if not self.allowed(need_token=False):
                return
            if not secrets.compare_digest(q.get("t", [""])[0], TOKEN):
                return self.send(403, {"error": "bad token"})
            name = url.path.rsplit("/", 1)[1]
            f = APP / "WALKTHROUGH.pdf" if name == "WALKTHROUGH.pdf" else ROOT / "out" / name
            if (name in OUTPUTS or name == "WALKTHROUGH.pdf") and f.exists():
                self.send(200, f.read_bytes(), OUTPUTS.get(name, "application/pdf"))
            else:
                self.send(404, {"error": "not found"})
        elif url.path == "/ping":  # lets a second launch find this one
            if self.allowed(need_token=False):
                self.send(200, "stenwatch", "text/plain")
        elif not self.allowed():
            return
        elif url.path == "/api/state":
            self.send(200, state())
        elif url.path == "/api/job":
            since = int(q.get("from", ["0"])[0])
            self.send(200, {**job, "lines": job["lines"][since:], "total": len(job["lines"])})
        elif url.path == "/api/file":
            name = q.get("name", [""])[0]
            if name not in EDITABLE:
                return self.send(404, {"error": "not editable"})
            f = ROOT / name
            src = f if f.exists() else APP / name.replace(".", ".example.", 1)
            self.send(200, {"text": src.read_text(encoding="utf-8") if src.exists() else "", "exists": f.exists()})
        elif url.path == "/api/decisions":
            self.send(200, {"rows": process.load_exceptions(ROOT / "exceptions.csv")})
        elif url.path == "/api/findings":  # find a finding to record a decision about: newest ranking, best risk first
            term = q.get("q", [""])[0].strip().lower()
            f = ROOT / "out" / "report.csv"
            rows = []
            if f.exists():
                with open(f, newline="", encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
            hits = [r for r in rows if term in r["cve"].lower() or term in r["asset"].lower()][:15]
            self.send(200, {"rows": [{k: r[k] for k in ("tier", "risk", "cve", "asset")} for r in hits]})
        elif url.path == "/api/cpe":
            term = q.get("term", [""])[0].strip()
            if len(term) < 3:
                return self.send(400, {"error": "type at least 3 letters"})
            db = sqlite3.connect(f"{(ROOT / 'cve.db').as_uri()}?mode=ro", uri=True)
            self.send(200, {"hits": process.suggest_cpe(db, term)})
            db.close()
        else:
            self.send(404, {"error": "not found"})

    def do_POST(self):
        global last_seen
        url = urlparse(self.path)
        if url.path == "/api/closing":  # sent by the page as it closes (sendBeacon can't set a header, so the token is in the URL)
            if self.allowed(need_token=False):
                if not secrets.compare_digest(parse_qs(url.query).get("t", [""])[0], TOKEN):
                    return self.send(403, {"error": "bad token"})
                last_seen = time.time() - IDLE + 30  # quit in 30 s unless a reload sends a heartbeat first
                self.send(200, {"ok": True})
            return
        if not self.allowed():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/api/run":
            name, arg = body.get("action"), body.get("arg", "")
            if name not in ACTIONS:
                return self.send(400, {"error": "unknown action"})
            if name == "since":
                try:
                    date.fromisoformat(arg)
                except ValueError:
                    return self.send(400, {"error": "date must be YYYY-MM-DD"})
            ok = start(name, arg)
            self.send(200 if ok else 409, {"started": ok} if ok else {"error": f"'{job['name']}' is still running"})
        elif self.path in ("/api/decision", "/api/decision/delete"):
            f = ROOT / "exceptions.csv"
            try:
                if self.path.endswith("delete"):
                    process.remove_exception(f, body.get("cve", ""), body.get("asset", ""))
                else:
                    process.record_exception(f, body.get("cve", "").strip().upper(), body.get("asset", ""), body.get("status", ""),
                                             body.get("until", ""), body.get("note", ""))
            except ValueError as e:
                return self.send(400, {"error": str(e)})
            self.send(200, {"ok": True})
        elif self.path == "/api/starter":  # first run: start from the Example Organisation's files
            starter()
            self.send(200, {"ok": True})
        elif self.path == "/api/tour":
            (ROOT / "tour.done").write_text("1")
            self.send(200, {"ok": True})
        elif self.path == "/api/alive":
            last_seen = time.time()
            self.send(200, {"ok": True})
        elif self.path == "/api/quit":
            self.send(200, {"quit": True})
            threading.Thread(target=server.shutdown).start()
        elif self.path == "/api/file":
            name, text = body.get("name"), body.get("text", "")
            if name not in EDITABLE:
                return self.send(404, {"error": "not editable"})
            try:
                validate(name, text)
            except Exception as e:
                return self.send(400, {"error": f"{name} not saved: {e}"})
            f = ROOT / name
            if f.exists():
                shutil.copy2(f, f.with_suffix(f.suffix + ".bak"))  # one step of undo
            f.write_text(text, encoding="utf-8", newline="")
            self.send(200, {"saved": name})
        else:
            self.send(404, {"error": "not found"})


if __name__ == "__main__":
    if "--pdf" in sys.argv:
        raise SystemExit(build_pdf(print))
    PORTFILE = DATA / "console.port"
    try:
        old = int(PORTFILE.read_text())
        running = urlopen(f"http://127.0.0.1:{old}/ping", timeout=1).read() == b"stenwatch"
    except (OSError, ValueError):
        running = False
    if running:  # already started: just show it again
        open_window(f"http://127.0.0.1:{old}")
        raise SystemExit
    for PORT in range(8765, 8785):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)  # never 0.0.0.0: this tool maps our weak spots
            break
        except OSError:
            pass
    else:
        raise SystemExit("No free port between 8765 and 8784")
    PORTFILE.write_text(str(PORT))
    print(f"Stenwatch console: http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    open_window(f"http://127.0.0.1:{PORT}")
    threading.Thread(target=watch, args=(server,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    PORTFILE.unlink(missing_ok=True)
