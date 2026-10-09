"""Builds the four architecture diagrams in docs/diagrams/ from the real code: python tools/diagrams.py
Numbers come from tools/metrics.py, so the pictures cannot drift from the code. Style: diagram-design skill, Stenwatch dark skin."""
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metrics

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "diagrams"
M = {m["file"]: m for m in map(metrics.measure, metrics.FILES)}
TOTAL_LOC = sum(m["loc"] for m in M.values())
TOTAL_FN = sum(m["functions"] for m in M.values())
TOTAL_DEC = sum(m["decisions"] for m in M.values())

PAPER, INK, MUTED, SOFT, ACCENT, LINK, CARD = "#060a11", "#e6edf6", "#8d9bb0", "#7886a0", "#3ee6a8", "#5aa9ff", "#0e1624"
MONO, SANS = "'Geist Mono', monospace", "'Geist', sans-serif"
KINDS = {  # fill, stroke, dash, stroke-width
    "backend": (CARD, INK, None, 1), "focal": ("rgba(62,230,168,0.10)", ACCENT, None, 1.2),
    "store": ("rgba(230,237,246,0.05)", MUTED, None, 1), "external": ("rgba(230,237,246,0.03)", "rgba(230,237,246,0.30)", None, 1),
    "input": ("rgba(141,155,176,0.10)", "#5d6c83", None, 1), "optional": ("rgba(230,237,246,0.02)", "rgba(230,237,246,0.25)", "4,3", 1)}
STROKES = {"muted": (MUTED, "arrow"), "link": (LINK, "arrow-link"), "accent": (ACCENT, "arrow-accent")}

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>__TITLE__</title>
<meta name="author" content="Diljot Singh Johal">
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--paper:#060a11;--ink:#e6edf6;--muted:#8d9bb0;--accent:#3ee6a8}
body{font-family:'Geist',system-ui,sans-serif;background:var(--paper);color:var(--ink);min-height:100vh;display:flex;justify-content:center;padding:3rem 2rem}
.frame{max-width:1200px;width:100%}.diagram-container{width:100%;overflow-x:auto}
.eyebrow{font-family:'Geist Mono',monospace;font-size:.66rem;font-weight:500;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-bottom:.5rem}
h1{font-family:'Instrument Serif',serif;font-size:clamp(1.5rem,2.4vw + .75rem,2rem);font-weight:400;letter-spacing:-.02em;line-height:1.15;margin-bottom:.6rem}
.lede{color:var(--muted);max-width:78ch;font-size:.95rem;margin-bottom:1.4rem}.lede b{color:var(--ink);font-weight:600}
svg{width:100%;min-width:__W__px;display:block}
.nav{margin-top:1.4rem;font:.7rem 'Geist Mono',monospace;letter-spacing:.08em;color:var(--muted)}.nav a{color:var(--accent);text-decoration:none;margin-right:1.2rem}
@media print{.diagram-container{overflow-x:visible}svg{min-width:0}}
</style></head><body><div class="frame">
<p class="eyebrow">__EYEBROW__</p><h1>__HEADING__</h1><p class="lede">__LEDE__</p>
<div class="diagram-container">__SVG__</div>
<p class="nav"><a href="code-map.html">Code map</a><a href="one-click.html">One click, step by step</a><a href="installed-app.html">Installed app</a><a href="complexity.html">Complexity</a><span>Stenwatch by Diljot Singh Johal</span></p>
</div></body></html>
"""


def rounded(pts, r=8):
    """Orthogonal polyline -> path with rounded corners (rule 1)."""
    d = f"M{pts[0][0]},{pts[0][1]}"
    for i in range(1, len(pts) - 1):
        (x0, y0), (x1, y1), (x2, y2) = pts[i - 1], pts[i], pts[i + 1]
        r1, r2 = min(r, (abs(x1 - x0) + abs(y1 - y0)) / 2), min(r, (abs(x2 - x1) + abs(y2 - y1)) / 2)
        a = (x1 - (x1 - x0) / max(1, abs(x1 - x0) + abs(y1 - y0)) * r1, y1 - (y1 - y0) / max(1, abs(x1 - x0) + abs(y1 - y0)) * r1)
        b = (x1 + (x2 - x1) / max(1, abs(x2 - x1) + abs(y2 - y1)) * r2, y1 + (y2 - y1) / max(1, abs(x2 - x1) + abs(y2 - y1)) * r2)
        d += f" L{a[0]:g},{a[1]:g} Q{x1},{y1} {b[0]:g},{b[1]:g}"
    return d + f" L{pts[-1][0]},{pts[-1][1]}"


class Diagram:
    def __init__(self, slug, title, desc, w, h):
        self.slug, self.title, self.desc, self.w, self.h = slug, title, desc, w, h
        self.zones, self.edges, self.nodes, self.labels = [], [], [], []

    def zone(self, x, y, w, h, label, lx=12):
        lw = len(label) * 5.4 + 16
        self.zones.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="rgba(230,237,246,0.02)" stroke="rgba(230,237,246,0.18)" stroke-width="0.8" stroke-dasharray="4,4"/>'
                          f'<rect x="{x + lx}" y="{y - 7}" width="{lw:g}" height="14" rx="2" fill="{PAPER}"/>'
                          f'<text x="{x + lx + 8}" y="{y + 3}" fill="{SOFT}" font-size="8" font-family="{MONO}" letter-spacing="0.14em">{html.escape(label)}</text>')

    def node(self, x, y, w, h, name, sub, tag, kind="backend", badge=None, chips=()):
        fill, stroke, dash, sw = KINDS[kind]
        tagc = ACCENT if kind == "focal" else SOFT
        da = f' stroke-dasharray="{dash}"' if dash else ""
        s = (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{PAPER}"/>'
             f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{da}/>'
             f'<text x="{x + 12}" y="{y + 18}" fill="{tagc}" font-size="7" font-family="{MONO}" letter-spacing="0.18em">{html.escape(tag)}</text>'
             f'<text x="{x + 12}" y="{y + 38}" fill="{INK}" font-size="12" font-weight="600" font-family="{SANS}">{html.escape(name)}</text>')
        if sub:
            s += f'<text x="{x + 12}" y="{y + 54}" fill="{MUTED}" font-size="9" font-family="{MONO}">{html.escape(sub)}</text>'
        for i, (cn, cv) in enumerate(chips):  # artifact chips (deployment)
            cy = y + 62 + i * 30
            s += (f'<rect x="{x + 10}" y="{cy}" width="{w - 20}" height="24" rx="4" fill="rgba(230,237,246,0.05)" stroke="{MUTED}" stroke-width="0.8"/>'
                  f'<text x="{x + 18}" y="{cy + 16}" fill="{INK}" font-size="11" font-family="{SANS}">{html.escape(cn)}</text>'
                  f'<text x="{x + w - 18}" y="{cy + 16}" fill="{MUTED}" font-size="9" font-family="{MONO}" text-anchor="end">{html.escape(cv)}</text>')
        if badge:
            bw = len(badge) * 5 + 10
            s += (f'<rect x="{x + w - bw - 8}" y="{y + 7}" width="{bw:g}" height="14" rx="2" fill="{PAPER}" stroke="{stroke}" stroke-width="0.8"/>'
                  f'<text x="{x + w - 8 - bw / 2:g}" y="{y + 17}" fill="{MUTED}" font-size="8" font-family="{MONO}" text-anchor="middle">{html.escape(badge)}</text>')
        self.nodes.append(s)

    def edge(self, pts, kind="muted", dashed=False, label=None, at=None, color=None):
        col, marker = STROKES[kind]
        da = ' stroke-dasharray="5,4"' if dashed else ""
        self.edges.append(f'<path d="{rounded(pts)}" fill="none" stroke="{col}" stroke-width="1.2"{da} marker-end="url(#{marker})"/>')
        if label:
            self.label(*at, label, color or col)

    def label(self, cx, cy, text, color=MUTED, anchor="middle"):
        """cx, cy = centre of the mask; the text sits on an opaque paper rect (rule 2)."""
        w = len(text) * 5.1 + 12
        x = cx - w / 2 if anchor == "middle" else cx
        self.labels.append(f'<rect x="{x:g}" y="{cy - 7}" width="{w:g}" height="14" fill="{PAPER}"/>'
                           f'<text x="{x + w / 2:g}" y="{cy + 3}" fill="{color}" font-size="8" font-family="{MONO}" text-anchor="middle" letter-spacing="0.06em">{html.escape(text)}</text>')

    def legend(self, items, y):
        x, out = 24, [f'<line x1="24" y1="{y - 14}" x2="{self.w - 24}" y2="{y - 14}" stroke="rgba(230,237,246,0.14)" stroke-width="0.8"/>']
        for kind, text in items:
            if kind == "line":
                out.append(f'<line x1="{x}" y1="{y + 5}" x2="{x + 22}" y2="{y + 5}" stroke="{LINK}" stroke-width="1.2"/>')
                w = 28
            elif kind == "dash":
                out.append(f'<line x1="{x}" y1="{y + 5}" x2="{x + 22}" y2="{y + 5}" stroke="{MUTED}" stroke-width="1.2" stroke-dasharray="5,4"/>')
                w = 28
            else:
                f, s, d, sw = KINDS[kind]
                out.append(f'<rect x="{x}" y="{y}" width="14" height="10" rx="2" fill="{f}" stroke="{s}" stroke-width="{sw}"' + (f' stroke-dasharray="{d}"' if d else "") + "/>")
                w = 20
            out.append(f'<text x="{x + w}" y="{y + 9}" fill="{MUTED}" font-size="8" font-family="{MONO}" letter-spacing="0.06em">{html.escape(text)}</text>')
            x += w + len(text) * 5.2 + 22
        self.nodes.append("".join(out))

    def svg(self, extra=""):
        defs = "".join(f'<marker id="{m}" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="{c}"/></marker>'
                       for m, c in (("arrow", MUTED), ("arrow-link", LINK), ("arrow-accent", ACCENT)))
        defs += f'<marker id="arrow-open" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polyline points="0 0, 8 3, 0 6" fill="none" stroke="{MUTED}" stroke-width="1.2"/></marker>'
        return (f'<svg viewBox="0 0 {self.w} {self.h}" xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="{self.slug}-title {self.slug}-desc">'
                f'<title id="{self.slug}-title">{html.escape(self.title)}</title><desc id="{self.slug}-desc">{html.escape(self.desc)}</desc><defs>{defs}</defs>'
                f'<rect width="100%" height="100%" fill="{PAPER}"/>{"".join(self.zones)}{extra}{"".join(self.edges)}{"".join(self.labels)}{"".join(self.nodes)}</svg>')

    def write(self, name, eyebrow, heading, lede, extra=""):
        OUT.mkdir(parents=True, exist_ok=True)
        page = (PAGE.replace("__TITLE__", html.escape(self.title)).replace("__W__", str(self.w)).replace("__EYEBROW__", eyebrow)
                .replace("__HEADING__", heading).replace("__LEDE__", lede).replace("__SVG__", self.svg(extra)))
        (OUT / name).write_text(page, encoding="utf-8")


def sub(f, extra=""):
    m = M[f]
    return f"{m['loc']} lines · {m['functions']} fn · cc {m['max_cc']}" + extra


# ---------------------------------------------------------------- 1. code map
def code_map():
    d = Diagram("code-map", "Stenwatch code map", "Two entry points call a four-stage pipeline in the cti package; stages read and write a SQLite store and write the reports.", 1000, 640)
    d.zone(24, 24, 952, 112, "ENTRY POINTS")
    d.zone(24, 176, 952, 236, "cti/ PACKAGE · ONE MODULE PER CTI STAGE")
    d.zone(24, 452, 952, 108, "DATA FOLDER · %APPDATA%" + chr(92) + "Stenwatch", lx=330)
    d.node(40, 60, 200, 64, "app.py", sub("app.py"), "CONSOLE SERVER")
    d.node(300, 60, 200, 64, "run.py", sub("run.py"), "COMMAND LINE")
    d.node(40, 212, 170, 64, "collect.py", sub("cti/collect.py"), "1 · COLLECTION")
    d.node(290, 212, 170, 64, "process.py", sub("cti/process.py"), "2 · PROCESSING")
    d.node(540, 212, 170, 64, "analyse.py", sub("cti/analyse.py"), "3 · ANALYSIS", "focal")
    d.node(790, 212, 170, 64, "disseminate.py", sub("cti/disseminate.py"), "4 · DISSEMINATION")
    sup = sum(M[f]["loc"] for f in M if f.startswith("cti/") and Path(f).stem in ("render", "llm", "vault", "paths", "defender"))
    d.node(290, 336, 410, 64, "render · llm · vault · paths · defender", f"{sup} lines · HTML + PDF, brief, keyring, folders", "SHARED HELPERS", "backend")
    d.node(40, 488, 230, 64, "cve.db", "SQLite · every CVE and feed row", "STORE", "store")
    d.node(700, 488, 260, 64, "out/ · reports", "html · pdf · csv · stix", "OUTPUT", "store")
    d.edge([(240, 92), (300, 92)], dashed=True, label="SPAWNS", at=(270, 78))
    d.edge([(400, 124), (400, 176)], label="CALLS IN ORDER", at=(462, 150))
    for (x1, x2, t) in ((210, 290, "CVE ROWS"), (460, 540, "FINDINGS"), (710, 790, "RANKED")):
        d.edge([(x1, 244), (x2, 244)], label=t, at=((x1 + x2) / 2, 230))
    d.edge([(100, 276), (100, 488)], label="WRITES", at=(138, 380))
    d.edge([(300, 276), (300, 312), (220, 312), (220, 488)], label="READS", at=(262, 298))
    d.edge([(810, 276), (810, 306), (640, 306), (640, 336)], dashed=True, label="USES", at=(725, 292))
    d.edge([(900, 276), (900, 488)], label="WRITES", at=(938, 380))
    d.legend([("backend", "MODULE"), ("focal", "SCORING CORE"), ("store", "DATA"), ("dash", "SPAWN / OPTIONAL USE")], 592)
    d.write("code-map.html", "Architecture · code level", "How the code is organised",
            f"<b>{TOTAL_LOC:,} lines</b>, <b>{TOTAL_FN} functions</b> and <b>{TOTAL_DEC} decision points</b> across {len(M)} Python files, four dependencies, no server beyond a localhost web page. "
            "Each box shows its size and <b>cc</b>, the decision paths in its busiest function. "
            "<b>analyse.py</b> is the scoring core; <b>process.py</b> and <b>analyse.py</b> also read the extra tables in cve.db, and your own CSV/YAML files are read by process.py. "
            "cli.py (4 lines) lets the installed app stream run.py output and is left out.")


# ---------------------------------------------------------------- 2. one click, step by step
def one_click():
    d = Diagram("one-click", "What happens when you click Quick sync", "A time-ordered sequence between the console page, the local server, the pipeline runner, the feeds and the data folder.", 1000, 720)
    X = {"page": 110, "app": 300, "run": 490, "db": 700, "feeds": 880}
    names = {"page": ("CONSOLE PAGE", "browser window"), "app": ("app.py", "local server :8765"), "run": ("run.py", "pipeline runner"),
             "db": ("cve.db · out/", "your data folder"), "feeds": ("Public feeds", "NVD · KEV · EPSS · ATT&CK")}
    life, act = [], []
    for k, x in X.items():
        life.append(f'<line x1="{x}" y1="92" x2="{x}" y2="660" stroke="rgba(230,237,246,0.20)" stroke-width="1" stroke-dasharray="3,3"/>')
        kind = "focal" if k == "run" else "external" if k == "feeds" else "store" if k == "db" else "backend"
        d.node(x - 80, 28, 160, 64, names[k][0], names[k][1], "ACTOR", kind)
    for k, y1, y2 in (("app", 124, 664), ("run", 170, 620), ("feeds", 212, 270), ("db", 300, 420)):
        act.append(f'<rect x="{X[k] - 4}" y="{y1}" width="8" height="{y2 - y1}" fill="rgba(230,237,246,0.06)" stroke="{MUTED}" stroke-width="0.8"/>')

    def msg(y, a, b, text, kind="muted", dashed=False, open_=False, side="above"):
        x1, x2 = X[a] + (4 if X[b] > X[a] else -4), X[b] - (4 if X[b] > X[a] else -4)
        col = STROKES[kind][0]
        marker = "arrow-open" if open_ else STROKES[kind][1]
        da = ' stroke-dasharray="5,4"' if dashed else ""
        d.edges.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{col}" stroke-width="1.2"{da} marker-end="url(#{marker})"/>')
        mid = (X[a] + X[b]) / 2
        if a == "run" and b in ("feeds",):
            mid = 590  # keep the label clear of the cve.db lifeline
        d.label(mid, y - 12, text, col)

    msg(132, "page", "app", "POST /api/run")
    msg(176, "app", "run", "SPAWN PROCESS")
    msg(220, "run", "feeds", "HTTPS GET", "link")
    msg(264, "feeds", "run", "JSON · CSV", "link", dashed=True)
    msg(308, "run", "db", "UPSERT ROWS")
    # self-message: match, score, tier
    d.edges.append(f'<path d="{rounded([(494, 340), (560, 340), (560, 364), (494, 364)], 6)}" fill="none" stroke="{MUTED}" stroke-width="1.2" marker-end="url(#arrow)"/>')
    d.label(634, 352, "MATCH · SCORE · TIER", MUTED)
    msg(396, "run", "db", "WRITE REPORTS")
    msg(440, "run", "app", "STDOUT LINES", dashed=True, open_=True)
    # loop fragment
    frame = (f'<rect x="70" y="468" width="270" height="112" rx="4" fill="rgba(230,237,246,0.03)" stroke="rgba(230,237,246,0.22)" stroke-width="1"/>'
             f'<rect x="70" y="468" width="44" height="16" rx="2" fill="{PAPER}" stroke="rgba(230,237,246,0.22)" stroke-width="1"/>'
             f'<text x="92" y="480" fill="{MUTED}" font-size="8" font-family="{MONO}" text-anchor="middle" letter-spacing="0.12em">LOOP</text>'
             f'<text x="124" y="480" fill="{MUTED}" font-size="8" font-family="{MONO}">[every 700 ms while running]</text>')
    msg(512, "page", "app", "GET /api/job")
    msg(556, "app", "page", "NEW LINES", dashed=True)
    msg(610, "run", "app", "EXIT CODE 0", dashed=True)
    msg(654, "app", "page", "NEW RANKING", "accent")
    d.nodes.append("")
    d.legend([("backend", "ACTOR"), ("dash", "RETURN / STREAM"), ("line", "INTERNET")], 696)
    d.write("one-click.html", "Sequence · working", "One click, step by step",
            "You press <b>Quick sync</b>. The page asks the local server to run the pipeline; the server starts <b>run.py</b> as a separate process, which downloads the feeds, "
            "writes <b>cve.db</b>, matches and scores every finding, and writes the reports. While it runs, the page polls every 700 ms and shows each output line. "
            "The only traffic that leaves the PC is the feed download.", extra="".join(life) + "".join(act) + frame)


# ---------------------------------------------------------------- 3. the installed app
def installed_app():
    d = Diagram("installed-app", "Stenwatch installed on a Windows PC", "An Edge app window talks over loopback to a windowless server process, which spawns a console runner that downloads public feeds and writes the data folder.", 1000, 600)
    d.zone(24, 40, 720, 520, "THIS PC · CURRENT USER · NO ADMIN")
    d.zone(776, 40, 200, 520, "INTERNET")
    d.node(48, 80, 232, 70, "Edge app window", "no tabs, no address bar", "WINDOW", "backend")
    d.node(48, 250, 232, 100, "Stenwatch.exe", "windowless · quits when window closes", "PROCESS", "focal", chips=[("Python 3.14 + app.py", "v0.1.0-beta")])
    d.node(340, 250, 220, 100, "stenwatch-cli.exe", "console runner, no flashing window", "PROCESS", "backend", chips=[("run.py · test suite", "v0.1.0-beta")])
    d.node(48, 440, 300, 90, "%APPDATA%\\Stenwatch", "survives updates and uninstall", "DATA FOLDER", "store", chips=[("cve.db · CSVs · profile · out/", "yours")])
    d.node(400, 440, 200, 90, "Credential Manager", "optional API keys", "WINDOWS", "optional")
    d.node(792, 250, 168, 100, "Public feeds", "read-only downloads", "EXTERNAL", "external", chips=[("NVD · KEV · EPSS", "6 feeds")])
    d.edge([(100, 150), (100, 250)], label="HTTP :8765", at=(150, 200))
    d.edge([(220, 250), (220, 150)], dashed=True, label="LAUNCHES", at=(272, 200))
    d.edge([(280, 300), (340, 300)], label="SPAWNS", at=(310, 286))
    d.edge([(560, 300), (792, 300)], kind="link", label="HTTPS :443", at=(676, 288))
    d.edge([(380, 350), (380, 394), (260, 394), (260, 440)], label="READ · WRITE", at=(320, 380))
    d.edge([(120, 350), (120, 440)], label="READS", at=(160, 396))
    d.edge([(500, 350), (500, 440)], dashed=True, label="KEYRING", at=(540, 396))
    d.legend([("focal", "THE INSTALLED APP"), ("backend", "PROCESS / WINDOW"), ("store", "DATA"), ("line", "INTERNET")], 580)
    d.write("installed-app.html", "Deployment · where it runs", "What runs on a PC after you install it",
            "Two small programs share one folder. <b>Stenwatch.exe</b> serves the console on 127.0.0.1 only and opens it in an Edge app window; it starts <b>stenwatch-cli.exe</b> for the heavy work so output can stream back. "
            "Your files live in <b>%APPDATA%\\Stenwatch</b>, apart from the program, so updating or uninstalling never touches them unless you say so. "
            "The feed download is the only traffic leaving the machine.")


# ---------------------------------------------------------------- 4. complexity
def complexity():
    rows = sorted(((c, f"{n}()", f) for f, m in M.items() for n, c, _ in m["funcs"]), reverse=True)[:8]
    d = Diagram("complexity", "Most complex functions in Stenwatch", "Horizontal bars of McCabe complexity for the eight most complex functions; write_reports is the highest at 41.", 1000, 520)
    x0, x1, top, pitch, hi = 300, 940, 78, 44, 45
    sc = (x1 - x0) / hi
    grid = []
    for v in (0, 10, 20, 30, 40):
        x = x0 + v * sc
        grid.append(f'<line x1="{x:g}" y1="56" x2="{x:g}" y2="{top + pitch * 8 - 8}" stroke="rgba(230,237,246,{0.25 if v == 0 else 0.08})" stroke-width="{1 if v == 0 else 0.8}"/>'
                    f'<text x="{x:g}" y="{top + pitch * 8 + 8}" fill="{MUTED}" font-size="8" font-family="{MONO}" text-anchor="middle">{v}</text>')
    for v, t in ((10, "SIMPLE"), (20, "MODERATE")):
        x = x0 + v * sc
        grid.append(f'<line x1="{x:g}" y1="56" x2="{x:g}" y2="{top + pitch * 8 - 8}" stroke="{SOFT}" stroke-width="1" stroke-dasharray="4,3"/>')
    grid.append(f'<text x="{x0 + 5 * sc:g}" y="50" fill="{SOFT}" font-size="8" font-family="{MONO}" text-anchor="middle" letter-spacing="0.12em">1–10 SIMPLE</text>'
                f'<text x="{x0 + 15 * sc:g}" y="50" fill="{SOFT}" font-size="8" font-family="{MONO}" text-anchor="middle" letter-spacing="0.12em">11–20 MODERATE</text>'
                f'<text x="{x0 + 32 * sc:g}" y="50" fill="{SOFT}" font-size="8" font-family="{MONO}" text-anchor="middle" letter-spacing="0.12em">21+ HIGH RISK: HARD TO TEST</text>')
    bars = []
    for i, (c, name, f) in enumerate(rows):
        y = top + i * pitch
        focal = i == 0
        fill, stroke = ("rgba(62,230,168,0.14)", ACCENT) if focal else ("rgba(141,155,176,0.15)", MUTED)
        bars.append(f'<text x="{x0 - 14}" y="{y + 14}" fill="{INK}" font-size="12" font-weight="600" font-family="{SANS}" text-anchor="end">{html.escape(name)}</text>'
                    f'<text x="{x0 - 14}" y="{y + 28}" fill="{MUTED}" font-size="8" font-family="{MONO}" text-anchor="end">{html.escape(f)}</text>'
                    f'<rect x="{x0}" y="{y}" width="{c * sc:g}" height="30" fill="{PAPER}"/>'
                    f'<rect x="{x0}" y="{y}" width="{c * sc:g}" height="30" rx="3" fill="{fill}" stroke="{stroke}" stroke-width="1"/>'
                    + (f'<text x="{x0 + c * sc - 10:g}" y="{y + 19}" fill="{INK}" font-size="10" font-weight="600" font-family="{MONO}" text-anchor="end">{c}</text>'
                       if any(abs(x0 + c * sc + 18 - (x0 + t * sc)) < 18 for t in (10, 20)) else
                       f'<text x="{x0 + c * sc + 10:g}" y="{y + 19}" fill="{ACCENT if focal else MUTED}" font-size="10" font-weight="600" font-family="{MONO}">{c}</text>'))
    d.nodes.append("".join(grid) + "".join(bars))
    d.legend([("focal", "HIGHEST"), ("store", "OTHER TOP FUNCTIONS")], 504)
    worst = rows[0]
    over = sum(1 for m in M.values() for _, c, _ in m["funcs"] if c > 20)
    d.write("complexity.html", "Complexity · where the risk is", "Where the complexity lives",
            f"Complexity here is McCabe's count: one plus every decision path (if, loop, exception, and/or) in a function. Across <b>{TOTAL_FN} functions</b> only <b>{over}</b> pass 20, "
            f"and the busiest is <b>{worst[1]}</b> in {worst[2]} at <b>{worst[0]}</b>: it builds the whole intelligence report in one function. "
            "That is the first place to split if the report grows. The web handlers in app.py come next because one function routes every request.")


if __name__ == "__main__":
    code_map(); one_click(); installed_app(); complexity()
    print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.html"))))
