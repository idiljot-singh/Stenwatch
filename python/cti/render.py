"""Turn the Markdown reports into designed HTML pages (and PDFs via Edge/Chrome). Same look as the console and dashboard."""
import html, re, subprocess, tempfile
from pathlib import Path

from cti.paths import find_browser

TIER_CLASS = {"Act": "act", "Attend": "attend", "Track": "track", "Ignore": "ignore"}


def inline(text):
    """Escape first, then allow only bold, code and https links: feed text can never inject markup."""
    t = html.escape(text)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    return re.sub(r"\[([^\]]+)\]\((https://[^)\s]+)\)", r'<a href="\2" rel="noopener">\1</a>', t)


def cell(text):
    h = inline(text.strip())
    m = re.fullmatch(r"(?:<strong>)?(Act|Attend|Track|Ignore)(?:</strong>)?", h)
    return f'<span class="pill {TIER_CLASS[m[1]]}">{m[1]}</span>' if m else h


def md_to_html(md):
    """The small Markdown subset the reports use: headings, tables, bullet lists, paragraphs."""
    out, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        line = lines[i].rstrip()
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head, body = rows[0], [r for r in rows[2:]]
            out.append('<div class="wrap"><table><thead><tr>' + "".join(f"<th>{inline(c.strip())}</th>" for c in head) +
                       "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in body) +
                       "</tbody></table></div>")
            continue
        if re.match(r"[-*] ", line):
            items = []
            while i < len(lines) and re.match(r"[-*] ", lines[i]):
                items.append(f"<li>{inline(lines[i][2:])}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        m = re.match(r"(#{1,3}) (.*)", line)
        if m and len(m[1]) > 1:  # the page header already carries the H1
            out.append(f"<h{len(m[1])}>{inline(m[2])}</h{len(m[1])}>")
        elif line and not m:
            out.append(f"<p>{inline(line)}</p>")
        i += 1
    return "\n".join(out)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__KIND__ · __ORG__</title>
<meta name="author" content="Diljot Singh Johal">
<style>
:root{color-scheme:dark;--bg:#050505;--card:#0b0b0b;--fg:#e8edf3;--mute:#9aa6b6;--dim:#6a7686;--line:#222a35;--accent:#3ee6a8;
  --act:#ff4d5e;--attend:#ff9f43;--track:#4ea3ff;--ignore:#7a8699;
  --display:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,monospace;--sans:"Space Grotesk","Segoe UI",system-ui,sans-serif}
@media print{:root{color-scheme:light;--bg:#fff;--card:#f5f6f8;--fg:#10141c;--mute:#4a5568;--dim:#6b7686;--line:#d5dae2;--accent:#0b8f67}
  @page{size:A4;margin:14mm 13mm}body{font-size:10pt}.wrap{overflow:visible}h2,h3{break-after:avoid}tr,.card,.note{break-inside:avoid}}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;color:var(--fg);font:15px/1.6 var(--sans);background:var(--bg)}
.tlp{display:flex;justify-content:center;gap:10px;padding:6px 16px;background:#000;color:#9aa6b6;font:600 11px var(--display);letter-spacing:.08em;text-transform:uppercase}
.tlp b{background:#ffc233;color:#000;padding:1px 8px;border-radius:3px}
@media print{.tlp{background:#fff;color:#333;border-bottom:1px solid var(--line)}}
main{max-width:960px;margin:0 auto;padding:28px 24px 48px}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:22px;font:700 13px var(--display);letter-spacing:.2em;text-transform:uppercase}
.brand svg{width:30px;height:30px}
.eyebrow{font:700 11px var(--display);letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
h1{font-size:34px;line-height:1.15;font-weight:600;letter-spacing:-.03em;margin:8px 0 6px}
.meta{color:var(--mute);margin:0 0 20px;font:13px var(--display)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--c);border-radius:4px;padding:12px 16px}
.card b{display:block;font:700 30px var(--display);letter-spacing:-.03em}
.card span{font:700 11px var(--display);letter-spacing:.14em;text-transform:uppercase;color:var(--c)}
.card small{display:block;color:var(--mute);font-size:12px}
.note{border:1px solid var(--line);border-left:3px solid #ffc233;background:var(--card);padding:10px 14px;border-radius:4px;color:var(--mute);margin:14px 0}
h2{font:700 13px var(--display);letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:24px 0 6px}
p,li{max-width:84ch}ul{padding-left:20px}li{margin:3px 0}
a{color:var(--track);text-decoration:none}a:hover{text-decoration:underline}
code{font:12.5px var(--display);background:var(--card);padding:1px 5px;border-radius:3px}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:4px;margin:10px 0 14px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:8px 11px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--card);font:600 10.5px var(--display);letter-spacing:.1em;text-transform:uppercase;color:var(--dim);white-space:nowrap}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;border:1px solid var(--c);color:var(--c);font:700 11px var(--display);letter-spacing:.06em;text-transform:uppercase}
.act{--c:var(--act)}.attend{--c:var(--attend)}.track{--c:var(--track)}.ignore{--c:var(--ignore)}
footer{margin-top:40px;color:var(--dim);font:12px var(--display)}
@media (max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:26px}}
</style></head><body>
<div class="tlp"><b>TLP:AMBER</b> limited disclosure · organisation and clients, need-to-know only</div>
<main>
<div class="brand"><svg viewBox="0 0 40 40" aria-hidden="true"><path d="M20 2.5l15 8.7v17.6L20 37.5 5 28.8V11.2z" fill="none" stroke="#3ee6a8" stroke-width="1.6"/><circle cx="20" cy="20" r="9" fill="none" stroke="#5aa9ff" stroke-width="1.2" opacity=".8"/><circle cx="20" cy="20" r="3.2" fill="#3ee6a8"/><path d="M20 7v6M20 27v6M7 20h6M27 20h6" stroke="#3ee6a8" stroke-width="1.4" stroke-linecap="round"/></svg>Stenwatch</div>
<div class="eyebrow">__KIND__</div>
<h1>__ORG__</h1>
<p class="meta">__DATE__ · threat-informed CVE prioritisation</p>
__NOTE____CARDS__
__BODY__
<footer>Generated by Stenwatch · TLP:AMBER</footer>
</main></body></html>
"""


def write_page(md, path, kind, org, today, cards=(), note=""):
    """cards: (label, count, caption) per tier. md is trusted structure plus untrusted text; inline() escapes it all."""
    cards_html = ('<div class="cards">' + "".join(
        f'<div class="card {TIER_CLASS[t]}"><span>{t}</span><b>{n}</b><small>{html.escape(cap)}</small></div>'
        for t, n, cap in cards) + "</div>") if cards else ""
    page = (PAGE.replace("__BODY__", md_to_html(md)).replace("__CARDS__", cards_html)
            .replace("__NOTE__", f'<div class="note">{inline(note)}</div>' if note else "")
            .replace("__KIND__", html.escape(kind)).replace("__ORG__", html.escape(org)).replace("__DATE__", str(today)))
    Path(path).write_text(page, encoding="utf-8")


def to_pdf(page):
    """HTML -> PDF with the machine's own Edge or Chrome. Returns the PDF path, or None when there is no browser."""
    browser, page = find_browser(), Path(page)
    if not browser:
        return None
    pdf = page.with_suffix(".pdf")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([browser, "--headless", "--disable-gpu", "--log-level=3", "--no-pdf-header-footer",
                        f"--user-data-dir={tmp}", f"--print-to-pdf={pdf}", page.as_uri()],
                       capture_output=True, timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return pdf if pdf.exists() else None
