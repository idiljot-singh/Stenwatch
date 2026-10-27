"""Cloud demo: the unmodified Stenwatch Console, behind a filtering proxy. Example Organisation only.

The Console binds loopback and trusts anyone who reaches it, so it is never exposed directly. This file runs it on
127.0.0.1:8765 and publishes a proxy that (1) rewrites Host so the Console's own check passes, (2) lets through only
the routes the demo needs, and (3) refuses anything that could stop it or reach the internet. Put Easy Auth (sign-in)
in front of it on Azure; the proxy itself has no login.

    HOST=127.0.0.1 PORT=8000 python cloud/serve.py
"""
import http.client
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402  (the Console; its __main__ block does not run on import)

INNER = 8765
GET_OK = {"/", "/api/state", "/api/job", "/api/file", "/api/decisions", "/api/findings", "/api/cpe"}
POST_OK = {"/api/decision", "/api/decision/delete", "/api/starter", "/api/tour", "/api/alive", "/api/file", "/api/run"}
RUN_OK = {"rank", "test"}  # no 'full'/'since' (downloads feeds from the internet), no 'pdf' (needs pandoc and a browser)
MAX_BODY = 1_000_000


class Proxy(BaseHTTPRequestHandler):
    def reply(self, code, body=b"", ctype="application/json", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY"),
                     ("Strict-Transport-Security", "max-age=31536000"), ("Cache-Control", "no-store"), *extra):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def forward(self, body=None):
        c = http.client.HTTPConnection("127.0.0.1", INNER, timeout=600)
        headers = {"Host": f"127.0.0.1:{INNER}", "X-Token": self.headers.get("X-Token", "")}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        c.request(self.command, self.path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        self.reply(r.status, data, r.getheader("Content-Type", "application/json"))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in GET_OK or (path.startswith("/out/") and path.count("/") == 2):
            return self.forward()
        self.reply(404, b'{"error":"not available in the demo"}')

    def do_POST(self):
        path = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self.reply(413, b'{"error":"too large"}')
        body = self.rfile.read(n)
        if path == "/api/closing":  # the page sends this as it closes; the demo never quits
            return self.reply(200, b'{"ok":true}')
        if path not in POST_OK:
            return self.reply(403, b'{"error":"not available in the demo"}')
        if path == "/api/run":
            try:
                ok = json.loads(body or b"{}").get("action") in RUN_OK
            except ValueError:
                ok = False
            if not ok:
                return self.reply(403, b'{"error":"this step is disabled in the cloud demo (it downloads feeds or needs a local browser)"}')
        self.forward(body)

    def log_message(self, *a):  # quiet: no request lines, they can carry the console token in the URL
        pass


if __name__ == "__main__":
    app.PORT = INNER
    app.server = ThreadingHTTPServer(("127.0.0.1", INNER), app.Handler)  # Handler's /api/quit uses this global
    threading.Thread(target=app.server.serve_forever, daemon=True).start()
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8000"))
    print(f"Stenwatch cloud demo on http://{host}:{port}  (Example Organisation only)")
    ThreadingHTTPServer((host, port), Proxy).serve_forever()
