"""Builds the backtest report from docs/backtest/results.json:  .build\\Scripts\\python tools/backtest_report.py
Writes docs/backtest/report.html and report.pdf. Every number, sentence about the results and chart is generated from results.json."""
import html
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cti.render import to_pdf

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "backtest"
R = json.loads((OUT / "results.json").read_text(encoding="utf-8"))
P, W, L = R["pooled"], R["windows"], R["labels"]
INK, MUTED, GRID, GREEN, BLUE, ORANGE, RED = "#1a2233", "#5b6678", "#e3e7ee", "#0f9d73", "#2f6fd0", "#d9822b", "#c8344a"
FONT, MONO = "'Segoe UI',system-ui,sans-serif", "'Cascadia Mono',Consolas,monospace"
e = lambda s: html.escape(s).replace("&gt;=", "&ge;")


def pct(x, d=0):
    return f"{100 * x:.{d}f}%"


def num(x):
    return f"{x:,.0f}"


def ci(q):
    return f"{pct(q['ci'][0])} to {pct(q['ci'][1])}"


def pv(p):
    return "below 0.001" if p < 0.001 else f"{p:.3f}"


Q, RK = P["queues"], P["rankings"]
A, C9, C7, AT = Q["attend"], Q["cvss9"], Q["cvss7"], Q["attend_track"]
ST, EP, CV = RK["stenwatch"], RK["epss"], RK["cvss"]
pair9, pair7 = P["paired"]["attend_vs_cvss9"], P["paired"]["attend_vs_cvss7"]
wins_better = sum(1 for a, b in zip(A["per_window"], C9["per_window"]) if a > b)
adds = sum(w["kev_adds_in_window"] for w in W)
in_scope = sum(w["positives"] for w in W)
late = sum(w["adds_published_after_origin"] for w in W)
nodb = sum(w["adds_not_in_database"] for w in W)
other = adds - in_scope - late - nodb
shrink = lambda a, b: f"{b / a:.1f}"      # how many times larger b is than a


# ---------------------------------------------------------------------------------------------------------------- charts
def axes(w, h, x0, y0, x1, y1, xlabel, ylabel, xticks, yticks, xfmt, yfmt):
    s = []
    for v, px in yticks:
        s.append(f'<line x1="{x0}" y1="{px}" x2="{x1}" y2="{px}" stroke="{GRID}" stroke-width="1"/><text x="{x0 - 8}" y="{px + 4}" text-anchor="end" font-size="11" fill="{MUTED}" font-family="{MONO}">{yfmt(v)}</text>')
    for v, px in xticks:
        s.append(f'<line x1="{px}" y1="{y0}" x2="{px}" y2="{y1}" stroke="{GRID}" stroke-width="1"/><text x="{px}" y="{y1 + 16}" text-anchor="middle" font-size="11" fill="{MUTED}" font-family="{MONO}">{xfmt(v)}</text>')
    s.append(f'<text x="{(x0 + x1) / 2}" y="{y1 + 38}" text-anchor="middle" font-size="12" fill="{INK}" font-family="{FONT}">{e(xlabel)}</text>')
    s.append(f'<text transform="translate(16 {(y0 + y1) / 2}) rotate(-90)" text-anchor="middle" font-size="12" fill="{INK}" font-family="{FONT}">{e(ylabel)}</text>')
    return "".join(s)


def svg(w, h, body, title, desc, fid):
    return (f'<svg viewBox="0 0 {w} {h}" role="img" aria-labelledby="{fid}-t {fid}-d" xmlns="http://www.w3.org/2000/svg"><title id="{fid}-t">{e(title)}</title>'
            f'<desc id="{fid}-d">{e(desc)}</desc><rect width="{w}" height="{h}" fill="#fff"/>{body}</svg>')


def fig_design():
    w, h, x0, x1 = 880, 250, 110, 850
    d0, d1 = date.fromisoformat(W[0]["origin"]), date.fromisoformat(W[-1]["end"])
    span = (d1 - d0).days
    X = lambda d: x0 + (date.fromisoformat(d) - d0).days / span * (x1 - x0)
    b = []
    for i, win in enumerate(W):
        y = 40 + i * 28
        xo, xe = X(win["origin"]), X(win["end"])
        b.append(f'<text x="{x0 - 12}" y="{y + 12}" text-anchor="end" font-size="11" fill="{INK}" font-family="{MONO}">window {i + 1}</text>')
        b.append(f'<rect x="{x0}" y="{y}" width="{xo - x0:.1f}" height="18" fill="{GRID}"/>' if i else "")
        b.append(f'<rect x="{xo:.1f}" y="{y}" width="{xe - xo:.1f}" height="18" fill="{GREEN}" opacity=".85"/>')
        b.append(f'<line x1="{xo:.1f}" y1="{y - 4}" x2="{xo:.1f}" y2="{y + 22}" stroke="{INK}" stroke-width="2"/>')
        b.append(f'<text x="{xo + 5:.1f}" y="{y + 13}" font-size="10" fill="#fff" font-family="{MONO}">T0 {win["origin"][:7]}</text>')
    b.append(f'<rect x="{x0}" y="{40 + 6 * 28 + 14}" width="14" height="10" fill="{GRID}"/><text x="{x0 + 20}" y="{40 + 6 * 28 + 23}" font-size="11" fill="{MUTED}" font-family="{FONT}">history up to T0: the only data a score may use (that day\'s EPSS file, CVSS, publication date)</text>')
    b.append(f'<rect x="{x0}" y="{40 + 6 * 28 + 32}" width="14" height="10" fill="{GREEN}" opacity=".85"/><text x="{x0 + 20}" y="{40 + 6 * 28 + 41}" font-size="11" fill="{MUTED}" font-family="{FONT}">the next {R["horizon_days"]} days: a CVE added to CISA KEV here counts as a positive. Windows do not overlap.</text>')
    return svg(w, h, "".join(b), "Backtest design", "Six consecutive 180 day windows, each scored with data available at its start.", "f1")


def fig_gain():
    w, h, x0, y0, x1, y1 = 880, 470, 70, 20, 840, 400
    xs = R["curve_x"]
    lx = lambda v: x0 + (__import__("math").log10(v) + 3) / 3 * (x1 - x0)
    ly = lambda v: y1 - v * (y1 - y0)
    b = [axes(w, h, x0, y0, x1, y1, "Share of all not-yet-exploited CVEs reviewed (log scale)", "Share of later-exploited CVEs found",
              [(v, lx(v)) for v in (0.001, 0.01, 0.1, 1)], [(v, ly(v)) for v in (0, .2, .4, .6, .8, 1)], lambda v: pct(v, 1 if v < .01 else 0) if v < 1 else "100%", lambda v: pct(v))]
    b.append(f'<line x1="{lx(0.001)}" y1="{ly(0.001)}" x2="{lx(1)}" y2="{ly(1)}" stroke="{MUTED}" stroke-width="1.2" stroke-dasharray="5,4"/>')
    for name, col in (("cvss", ORANGE), ("epss", BLUE), ("stenwatch", GREEN)):
        pts = " ".join(f"{lx(x):.1f},{ly(v):.1f}" for x, v in zip(xs, RK[name]["curve"]))
        b.append(f'<polyline points="{pts}" fill="none" stroke="{col}" stroke-width="{2.6 if name == "stenwatch" else 2}" stroke-linejoin="round"/>')
    marks = (("attend", GREEN, "circle", "Attend", 11, 4, "start"), ("attend_track", GREEN, "square", "Attend + Track", -11, -9, "end"),
             ("cvss9", ORANGE, "diamond", "CVSS 9+", 11, 4, "start"), ("cvss7", ORANGE, "square", "CVSS 7+", -11, 19, "end"))
    for q, col, shape, label, dx, dy, anc in marks:
        x, y = lx(Q[q]["share"]), ly(Q[q]["recall"])
        if shape == "circle":
            b.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="#fff" stroke="{col}" stroke-width="2.4"/>')
        elif shape == "square":
            b.append(f'<rect x="{x - 5.5:.1f}" y="{y - 5.5:.1f}" width="11" height="11" fill="#fff" stroke="{col}" stroke-width="2.4"/>')
        else:
            b.append(f'<path d="M{x:.1f},{y - 7:.1f} L{x + 7:.1f},{y:.1f} L{x:.1f},{y + 7:.1f} L{x - 7:.1f},{y:.1f} Z" fill="#fff" stroke="{col}" stroke-width="2.4"/>')
        b.append(f'<text x="{x + dx:.1f}" y="{y + dy:.1f}" text-anchor="{anc}" font-size="11" fill="{INK}" font-family="{FONT}" font-weight="600">{label}</text>')
    ly0 = y1 + 56
    for i, (txt, col, dash) in enumerate((("Stenwatch score (EPSS x CVSS)", GREEN, ""), ("EPSS alone", BLUE, ""), ("CVSS alone", ORANGE, ""), ("No skill (random order)", MUTED, "5,4"))):
        xx = x0 + i * 200
        b.append(f'<line x1="{xx}" y1="{ly0}" x2="{xx + 24}" y2="{ly0}" stroke="{col}" stroke-width="2.4" stroke-dasharray="{dash}"/><text x="{xx + 30}" y="{ly0 + 4}" font-size="11" fill="{INK}" font-family="{FONT}">{txt}</text>')
    return svg(w, h, "".join(b), "Gain chart", "Share of later-exploited CVEs found against share of CVEs reviewed, for three rankings and four queues.", "f2")


def fig_queues():
    w, h, x0, x1 = 880, 210, 250, 760
    rows = [("attend", GREEN), ("attend_track", GREEN), ("cvss9", ORANGE), ("cvss7", ORANGE)]
    b = [f'<line x1="{x0}" y1="20" x2="{x0}" y2="{20 + 44 * 4}" stroke="{MUTED}"/>']
    for v in (0, .25, .5, .75, 1):
        x = x0 + v * (x1 - x0)
        b.append(f'<line x1="{x}" y1="20" x2="{x}" y2="{20 + 44 * 4}" stroke="{GRID}"/><text x="{x}" y="{20 + 44 * 4 + 16}" text-anchor="middle" font-size="11" fill="{MUTED}" font-family="{MONO}">{pct(v)}</text>')
    for i, (q, col) in enumerate(rows):
        y = 28 + i * 44
        v = Q[q]
        b.append(f'<text x="{x0 - 10}" y="{y + 12}" text-anchor="end" font-size="12" fill="{INK}" font-family="{FONT}" font-weight="600">{e(short(q))}</text>')
        b.append(f'<text x="{x0 - 10}" y="{y + 26}" text-anchor="end" font-size="10" fill="{MUTED}" font-family="{MONO}">queue = {pct(v["share"], 1)} of CVEs</text>')
        b.append(f'<rect x="{x0}" y="{y}" width="{v["recall"] * (x1 - x0):.1f}" height="24" fill="{col}" opacity=".85"/>')
        lo, hi = v["ci"]
        xl, xh, ym = x0 + lo * (x1 - x0), x0 + hi * (x1 - x0), y + 12
        b.append(f'<line x1="{xl:.1f}" y1="{ym}" x2="{xh:.1f}" y2="{ym}" stroke="{INK}" stroke-width="1.6"/><line x1="{xl:.1f}" y1="{ym - 6}" x2="{xl:.1f}" y2="{ym + 6}" stroke="{INK}" stroke-width="1.6"/><line x1="{xh:.1f}" y1="{ym - 6}" x2="{xh:.1f}" y2="{ym + 6}" stroke="{INK}" stroke-width="1.6"/>')
        b.append(f'<text x="{xh + 8:.1f}" y="{ym + 4}" font-size="12" fill="{INK}" font-family="{MONO}" font-weight="700">{pct(v["recall"])}</text>')
    return svg(w, h, "".join(b), "Recall by queue", "Share of later-exploited CVEs caught by each queue with 95 percent intervals.", "f3")


def fig_windows():
    w, h, x0, x1 = 880, 250, 140, 800
    xmax = 0.6 if max(A["per_window"] + C9["per_window"]) < 0.6 else 1.0
    b = []
    for v in [t for t in (0, .2, .4, .6, .8, 1) if t <= xmax + 1e-9]:
        x = x0 + v / xmax * (x1 - x0)
        b.append(f'<line x1="{x}" y1="20" x2="{x}" y2="{20 + 6 * 30}" stroke="{GRID}"/><text x="{x}" y="{20 + 6 * 30 + 16}" text-anchor="middle" font-size="11" fill="{MUTED}" font-family="{MONO}">{pct(v)}</text>')
    for i, win in enumerate(W):
        y = 34 + i * 30
        a, c = A["per_window"][i], C9["per_window"][i]
        b.append(f'<text x="{x0 - 12}" y="{y + 4}" text-anchor="end" font-size="11" fill="{INK}" font-family="{MONO}">{win["origin"][:7]} (n={win["positives"]})</text>')
        b.append(f'<line x1="{x0 + c / xmax * (x1 - x0):.1f}" y1="{y}" x2="{x0 + a / xmax * (x1 - x0):.1f}" y2="{y}" stroke="{MUTED}" stroke-width="1.4"/>')
        b.append(f'<circle cx="{x0 + c / xmax * (x1 - x0):.1f}" cy="{y}" r="6" fill="#fff" stroke="{ORANGE}" stroke-width="2.4"/><circle cx="{x0 + a / xmax * (x1 - x0):.1f}" cy="{y}" r="6" fill="{GREEN}" stroke="{INK}" stroke-width="1"/>')
    b.append(f'<circle cx="{x0}" cy="{20 + 6 * 30 + 42}" r="6" fill="#fff" stroke="{ORANGE}" stroke-width="2.4"/><text x="{x0 + 12}" y="{20 + 6 * 30 + 46}" font-size="11" fill="{INK}" font-family="{FONT}">CVSS 9+ queue</text>'
             f'<circle cx="{x0 + 160}" cy="{20 + 6 * 30 + 42}" r="6" fill="{GREEN}" stroke="{INK}"/><text x="{x0 + 172}" y="{20 + 6 * 30 + 46}" font-size="11" fill="{INK}" font-family="{FONT}">Stenwatch Attend queue</text>')
    return svg(w, h, "".join(b), "Recall in each window", "Recall of the Attend queue and the CVSS 9 and above queue in each of six windows.", "f4")


def fig_sweep():
    w, h, x0, y0, x1, y1 = 880, 440, 70, 20, 840, 370
    import math
    lx = lambda v: x0 + (math.log10(v) + 2) / 2 * (x1 - x0)
    ly = lambda v: y1 - v * (y1 - y0)
    b = [axes(w, h, x0, y0, x1, y1, "Share of all CVEs in the queue (log scale)", "Share of later-exploited CVEs found",
              [(v, lx(v)) for v in (0.01, 0.1, 1)], [(v, ly(v)) for v in (0, .2, .4, .6, .8, 1)], lambda v: pct(v), lambda v: pct(v))]
    for name, col, key, fmt in (("EPSS threshold", GREEN, "sweep_epss", lambda t: f"{t:g}"), ("CVSS threshold", ORANGE, "sweep_cvss", lambda t: f"{t:g}")):
        pts = [(lx(max(s["size_share"], 0.0101)), ly(s["recall"]), s["t"]) for s in P[key]]
        b.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)}" fill="none" stroke="{col}" stroke-width="2"/>')
        for x, y, t in pts:
            sel = (key == "sweep_epss" and t == R["tiers"]["attend_epss"]) or (key == "sweep_cvss" and t in (7, 9))
            b.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{6 if sel else 3.6}" fill="{col if not sel else "#fff"}" stroke="{col}" stroke-width="2.2"/>')
            b.append(f'<text x="{x + 8:.1f}" y="{y + (-7 if key == "sweep_epss" else 17):.1f}" font-size="10" fill="{INK}" font-family="{MONO}">{fmt(t)}</text>')
    b.append(f'<line x1="{x0}" y1="{y1 + 56}" x2="{x0 + 24}" y2="{y1 + 56}" stroke="{GREEN}" stroke-width="2.4"/><text x="{x0 + 30}" y="{y1 + 60}" font-size="11" fill="{INK}" font-family="{FONT}">EPSS at or above the value shown</text>'
             f'<line x1="{x0 + 290}" y1="{y1 + 56}" x2="{x0 + 314}" y2="{y1 + 56}" stroke="{ORANGE}" stroke-width="2.4"/><text x="{x0 + 320}" y="{y1 + 60}" font-size="11" fill="{INK}" font-family="{FONT}">CVSS at or above the value shown</text>'
             f'<circle cx="{x0 + 600}" cy="{y1 + 56}" r="6" fill="#fff" stroke="{INK}" stroke-width="2.2"/><text x="{x0 + 612}" y="{y1 + 60}" font-size="11" fill="{INK}" font-family="{FONT}">thresholds used in this report</text>')
    return svg(w, h, "".join(b), "Threshold sensitivity", "Recall against queue size as the EPSS and CVSS thresholds change.", "f5")


def short(q):
    return {"attend": "Stenwatch Attend", "attend_track": "Attend + Track", "cvss9": "CVSS 9 and above", "cvss7": "CVSS 7 and above"}[q]


# ---------------------------------------------------------------------------------------------------------------- text
def table(head, rows, cls=""):
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="wrap"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>'


EQ = P["equal_size"]
assert EQ["cvss9"]["stenwatch"]["recall"] > EQ["cvss9"]["cvss"]["recall"] and EQ["attend"]["stenwatch"]["recall"] > EQ["attend"]["cvss"]["recall"], "text says the Stenwatch ranking wins at small queue sizes"
assert EQ["cvss7"]["cvss"]["recall"] > EQ["cvss7"]["stenwatch"]["recall"], "text says the CVSS ranking wins at large queue sizes"
assert EQ["attend_track"]["cvss"]["recall"] >= Q["attend_track"]["recall"] - 0.02, "text says Attend + Track is no better than the CVSS ranking of the same size"
assert CV["reviews80_share"] < ST["reviews80_share"] and CV["auc_mean"] > ST["auc_mean"], "text says CVSS wins in the tail and on AUC"
assert A["share"] < C9["share"] and 0.0 < pair9["p"], "text compares a smaller Attend queue with the critical list"
xs = R["curve_x"]
cross = next((x for x, a, b in zip(xs, ST["curve"], CV["curve"]) if b > a + 1e-9), None)   # first review budget at which the CVSS ranking is ahead
rb = lambda r, b: RK[r]["recall_at_budget"][str(b)]["recall"]
sw = {s["t"]: s for s in P["sweep_epss"]}
low_epss = 1 - sw[0.01]["recall"]                                                          # share of later-exploited CVEs whose EPSS was under 0.01 on the origin day
late_share = late / adds
small_ok = all(rb("stenwatch", b) > rb("cvss", b) for b in (0.01, 0.05, 0.1))
tail_ok = ST["reviews80_share"] < CV["reviews80_share"] and ST["auc_mean"] > CV["auc_mean"]
h1 = "Supported" if small_ok and tail_ok else "Partly supported" if small_ok else "Not supported"
more = A["recall"] > C9["recall"] and pair9["p"] < 0.05
h2 = "Supported" if more and A["share"] <= C9["share"] else "Partly supported" if A["recall"] >= C9["recall"] and A["share"] < C9["share"] else "Not supported"
hit_ratio = A["precision"] / C9["precision"]
ptxt = lambda p: ("= " + pv(p)) if p >= 0.001 else pv(p)
cmp = lambda a, b, hi="higher", lo="lower": hi if a > b else lo
cross_txt = (f"The two gain curves cross at about {pct(cross)} of the list: reading further than that, the CVSS ranking is ahead." if cross else "The CVSS ranking is never ahead of the Stenwatch ranking.")
A_size, C9_size = pct(A["share"], 1), pct(C9["share"], 1)

BODY = f"""
<h1>Does Stenwatch's scoring find the vulnerabilities attackers actually use?</h1>
<p class="sub">A point-in-time backtest against CISA's Known Exploited Vulnerabilities catalogue &middot; Stenwatch {e(R['code_commit'])} &middot; run {e(R['generated'])} &middot; Diljot Singh Johal</p>

<h2>1. Summary</h2>
<p><b>What was tested.</b> On six start dates, six months apart, we ranked every CVE that was not yet known to be exploited, using only what was knowable that day. Then we counted how many were added to CISA's known-exploited list over the next six months ({P['positives']} in all) and how much reading each method needed to find them.</p>
<ul>
<li><b>The Attend queue is small and efficient, but it is not more complete than the critical list.</b> Attend (EPSS at or above {R['tiers']['attend_epss']}) holds {A_size} of all CVEs and found <b>{pct(A['recall'])}</b> of the later-exploited ones (95% interval {ci(A)}). The usual CVSS 9 and above list holds {C9_size} and found <b>{pct(C9['recall'])}</b> ({ci(C9)}). The difference in what they found is not statistically significant (p {ptxt(pair9['p'])}), but Attend does it from a queue {shrink(A['share'], C9['share'])} times smaller, so each CVE read is {hit_ratio:.1f} times as likely to be a hit.</li>
<li><b>At the same queue size the Stenwatch ranking is clearly better.</b> Reading down the Stenwatch score for as many CVEs as the critical list holds finds {pct(EQ['cvss9']['stenwatch']['recall'])} of the exploited CVEs, against {pct(EQ['cvss9']['cvss']['recall'])} for the critical list itself. For a queue the size of Attend, a severity ranking finds only {pct(EQ['attend']['cvss']['recall'])} against Attend's {pct(A['recall'])}.</li>
<li><b>The advantage is at small review budgets, and it reverses in the long tail.</b> After reading the first 1% of the list the Stenwatch score has found {pct(rb('stenwatch', 0.01))} against {pct(rb('cvss', 0.01))} for CVSS; after 10%, {pct(rb('stenwatch', 0.1))} against {pct(rb('cvss', 0.1))}. To reach 80% of the exploited CVEs, CVSS needs {pct(CV['reviews80_share'], 1)} of the list and the Stenwatch score {pct(ST['reviews80_share'], 1)}. {cross_txt} Overall AUC is {CV['auc_mean']:.3f} for CVSS and {ST['auc_mean']:.3f} for the Stenwatch score. {pct(low_epss)} of the later-exploited CVEs had an EPSS below 0.01 on the origin day, and no probability-led ranking can place them early.</li>
<li><b>Most CISA additions cannot be predicted six months ahead.</b> {pct(late_share)} of the {num(adds)} CVEs CISA added during the windows had not even been published on the origin day. They are out of reach of any ranking; they are caught once CISA lists them, which is what Stenwatch's KEV feed is for.</li>
</ul>
<p class="note"><b>A correction.</b> An earlier exploratory run reported that the Attend queue caught about 70% against about a third for the critical list. That result is withdrawn. It came from a local database that was missing most CVEs published in 2024 and 2025, which silently removed the hardest-to-find exploited CVEs from the test. This report uses a complete database and replaces it. Please do not quote the 70% figure.</p>
<p class="note"><b>Read this before quoting the numbers.</b> {P['positives']} positives are enough to separate large differences but not to give tight percentages; the intervals show the uncertainty. The test measures the global scoring signals only. It does not test the KEV flag, ransomware use, threat-group matching or your asset list, which have no point-in-time history. See section 7.</p>

<h2>2. Terms used</h2>
{table(["Term", "Meaning"], [
    ["CVE", "A public identifier for one software vulnerability, such as CVE-2024-12345."],
    ["CVSS", "A 0 to 10 severity score for how bad a flaw could be. It says nothing about whether anyone is using it."],
    ["EPSS", "A 0 to 1 probability, published daily by FIRST, that a CVE will be exploited in the next 30 days."],
    ["KEV", "CISA's catalogue of vulnerabilities known to be exploited in the wild. Used here as the answer key."],
    ["Queue", "The CVEs a rule selects for attention, for example every CVE with EPSS at or above 0.1."],
    ["Recall", "Of the CVEs that were later exploited, the share a queue contained."],
    ["Hit rate", "Of the CVEs in a queue, the share that were later exploited. Lift is the hit rate divided by the base rate."],
    ["Review budget", "How far down a ranked list a team can read, as a share of all CVEs."],
], "small")}

<h2>3. Questions and hypotheses</h2>
<p>Stenwatch ranks vulnerabilities by risk = likelihood &times; impact, where likelihood leans on EPSS and impact on CVSS. The question is whether that ranking would have pointed a team at vulnerabilities attackers went on to use, better than the common practice of working down the CVSS list. Two hypotheses were written before the complete-data run:</p>
<ul><li><b>H1.</b> A ranking by EPSS &times; CVSS finds later-exploited CVEs with less review effort than a ranking by CVSS alone. <b>Verdict: {h1}.</b> {'It holds at small review budgets (the first 1%, 5% and 10% of the list) but not over the whole list: CVSS reaches 80% sooner and has the higher AUC.' if small_ok and not tail_ok else ''}</li>
<li><b>H2.</b> The Attend queue catches more later-exploited CVEs than a critical-severity queue (CVSS 9 and above) of similar or smaller size. <b>Verdict: {h2}.</b> {'Attend caught ' + pct(A['recall']) + ' against ' + pct(C9['recall']) + ' (not a significant difference) from a queue ' + shrink(A['share'], C9['share']) + ' times smaller. "Catches more" is not shown; "catches as many from far less" is.' if h2 == 'Partly supported' else ''}</li></ul>
<p>The first exploratory run suggested stronger results than these (section 1, correction). The windows, thresholds and measures below were fixed before the complete-data run and were not changed afterwards. The thresholds are the product's own defaults (profile.example.yaml), not values tuned on this data. The equal-size comparison (6.5) was added after seeing the first results, because comparing queues of different sizes is unfair to both; treat it as exploratory.</p>

<h2>4. Data and provenance</h2>
{table(["Data", "What it is", "Used for", "Point in time?"], [
    ["EPSS daily files", f"FIRST's exploit-probability score for every CVE, one file per day from epss.empiricalsecurity.com. Six snapshots, one per window start (SHA-256 of each in section 9).", "Ranking score", "Yes: the file of the origin day"],
    ["CISA KEV catalogue", f"{num(R['database']['kev_rows'])} entries, first added {R['database']['kev_first']}, latest {R['database']['kev_last']}, with the date each CVE was added.", "Labels (what counts as exploited, and when)", "Yes: the date added decides the window"],
    ["NVD CVE records", f"{num(R['database']['cves'])} CVEs, latest published {R['database']['latest_published']}. CVSS is the first available of v4.0, v3.1, v3.0, v2 as stored by Stenwatch.", "Severity, publication date", "Publication date yes; CVSS is today's value"],
])}
<p>All feeds are public and were downloaded with Stenwatch's own collector (cti/collect.py; the gap fill used tools/nvd_fill.py, which uses the same parser). CVEs with no CVSS score ({num(sum(w['missing_cvss'] for w in W))} across all windows, {pct(sum(w['missing_cvss'] for w in W) / P['population'], 1)}) are treated as severity 0, which only hurts the CVSS baselines.</p>
<p><b>Data audit.</b> Before the final run the database was checked against NVD's yearly volumes and found to be missing most of 2024 and 2025 (26 and 869 records). It was completed, and the self-check in section 9 now refuses to run if either year has fewer than 30,000 CVEs. Records per year in the database used: {", ".join(f"{y}: {num(n)}" for y, n in R['database']['per_year'].items() if int(y) >= 2022)}.</p>

<h2>5. Method</h2>
<h3>5.1 Design</h3>
<p>Six consecutive, non-overlapping windows of {R['horizon_days']} days (figure 1). At each origin date T0 we rebuild the situation of a team on that day: which CVEs existed, how severe they looked, what EPSS said, and which were already known to be exploited. We then look forward {R['horizon_days']} days and see which CVEs were added to KEV. Non-overlapping windows keep one exploited CVE from being counted twice.</p>
<figure>{fig_design()}<figcaption><b>Figure 1.</b> Backtest design. Grey: history available at T0. Green: the {R['horizon_days']} days used to label outcomes.</figcaption></figure>
<h3>5.2 Population and labels</h3>
<ul><li><b>Population at T0:</b> every CVE published on or before T0, with an EPSS score on T0, and <i>not yet in KEV on T0</i>. Already-exploited CVEs are excluded because ranking them is not a prediction.</li>
<li><b>Positive:</b> a member of that population added to KEV during the next {R['horizon_days']} days. Everything else in the population is a negative.</li></ul>
<p>Of the {num(adds)} CVEs added to KEV during the six windows, <b>{num(in_scope)}</b> ({pct(in_scope / adds)}) are in scope. The rest cannot be scored on the origin day: {num(late)} were published after T0, {num(nodb)} are not in the NVD copy, and {num(other)} had no EPSS score on T0.</p>
<h3>5.3 What is compared</h3>
{table(["Name", "How it works"], [
    ["Stenwatch score", "EPSS &times; CVSS: the part of the product's risk formula (likelihood &times; impact) that can be reproduced without KEV, threat-group or asset information. The weights are constants and do not change the order."],
    ["EPSS alone", "Rank by exploit probability."],
    ["CVSS alone", "Rank by severity: what most vulnerability lists do."],
    ["Attend queue", f"EPSS at or above {R['tiers']['attend_epss']} (the product's Attend threshold for CVEs not yet known to be exploited)."],
    ["Attend + Track queue", f"EPSS at or above {R['tiers']['track_epss']}, or CVSS at or above {R['tiers']['track_cvss']}."],
    ["CVSS 9 and above, CVSS 7 and above", "The two severity lists teams commonly work from."],
], "small")}
<h3>5.4 Measures and statistics</h3>
<ul><li><b>Recall</b> of a queue and its <b>size</b> (the review cost); <b>hit rate</b> and <b>lift</b>.</li>
<li><b>Gain curve</b> (figure 3): recall against share reviewed while reading down a ranking. <b>Reviews to find 50% and 80%</b> of the positives (median of the six windows). <b>ROC AUC</b>: the chance that a random positive is ranked above a random negative (0.5 is no skill, 1 is perfect).</li>
<li><b>Ties.</b> CVSS has few distinct values, so many CVEs tie. Ties are resolved by their expected value under random order (exact, no random seed); AUC gives half credit to ties.</li>
<li><b>Intervals.</b> Pooled recall uses 95% Wilson score intervals.</li>
<li><b>Paired comparison.</b> Two queues are judged on the same positives, so the difference is tested on the positives only one of them caught, with an exact two-sided binomial (sign) test.</li>
<li><b>Across windows.</b> AUC is the mean &plusmn; standard deviation of six windows. No test is applied across windows; six is too few.</li></ul>
<h3>5.5 Safeguards against looking ahead</h3>
{table(["Risk", "What we did"], [
    ["Using today's EPSS", "Each window uses that origin day's own EPSS file."],
    ["Using later KEV knowledge", "CVEs already in KEV on T0 are removed; only the date added decides outcomes. The KEV flag is never used as a feature."],
    ["Using CVEs that did not exist", "Only CVEs published on or before T0."],
    ["Tuning on the answer", "Thresholds are the product's defaults, fixed before the run; section 8 shows how results move if they change."],
    ["CVSS revisions", "CVSS is today's NVD value, because scores at T0 are not stored. Possible effect: section 7."],
], "small")}

<h2>6. Results</h2>
<h3>6.1 The windows</h3>
{table(["Origin", "Population", "Positives", "KEV additions", "Base rate"],
       [[w['origin'], num(w['population']), str(w['positives']), str(w['kev_adds_in_window']), pct(w['base_rate'], 3)] for w in W] +
       [[f"<b>Pooled</b>", f"<b>{num(P['population'])}</b>", f"<b>{P['positives']}</b>", f"<b>{adds}</b>", f"<b>{pct(P['base_rate'], 3)}</b>"]])}
<p>The base rate is the chance that a random not-yet-exploited CVE is added to KEV within six months: about {pct(P['base_rate'], 3)}. Reading CVEs in random order would find 1% of the positives per 1% of effort.</p>
<h3>6.2 Queues</h3>
{table(["Queue", "Size (share of CVEs)", "Positives caught", "Recall (95% interval)", "Hit rate", "Lift over random"],
       [[e(L['queues'][q]), pct(Q[q]['share'], 1), f"{Q[q]['hits']} of {P['positives']}", f"<b>{pct(Q[q]['recall'])}</b> ({ci(Q[q])})", pct(Q[q]['precision'], 3), f"{Q[q]['lift']:.1f}x"] for q in ("attend", "attend_track", "cvss9", "cvss7")])}
<figure>{fig_queues()}<figcaption><b>Figure 2.</b> Recall of each queue, pooled over six windows, with 95% intervals.</figcaption></figure>
<p><b>Paired comparison.</b> Attend against CVSS 9 and above, on the same {P['positives']} positives:</p>
{table(["", "Caught by CVSS 9+", "Missed by CVSS 9+"], [["Caught by Attend", str(pair9['both']), f"<b>{pair9['only_a']}</b>"], ["Missed by Attend", f"<b>{pair9['only_b']}</b>", str(pair9['neither'])]], "small")}
<p>Attend found {pair9['only_a']} exploited CVEs the critical list missed; the critical list found {pair9['only_b']} that Attend missed (exact test p {ptxt(pair9['p'])}). So the two queues largely catch different CVEs, and neither contains the other. Against the much larger CVSS 7 and above list, Attend found {pair7['only_a']} that list missed and missed {pair7['only_b']} it found (p {ptxt(pair7['p'])}); that list is {shrink(A['share'], C7['share'])} times the size of the Attend queue.</p>
<h3>6.3 Rankings</h3>
{table(["Ranking", "AUC (mean ± SD, 6 windows)", "Reviews to find 50%", "Reviews to find 80%", "Found in the first 1%", "Found in the first 5%", "Found in the first 10%"],
       [[e(L['rankings'][r]), f"{RK[r]['auc_mean']:.3f} &plusmn; {RK[r]['auc_sd']:.3f}", pct(RK[r]['reviews50_share'], 1), pct(RK[r]['reviews80_share'], 1), pct(rb(r, 0.01)), pct(rb(r, 0.05)), pct(rb(r, 0.1))] for r in ("stenwatch", "epss", "cvss")])}
<figure>{fig_gain()}<figcaption><b>Figure 3.</b> Gain chart. A curve that rises sooner means less work to find the same share of exploited CVEs. The four marked points are the queues of section 6.2.</figcaption></figure>
<h3>6.4 Consistency across windows</h3>
<figure>{fig_windows()}<figcaption><b>Figure 4.</b> Recall of the Attend queue against the CVSS 9+ queue in each window (n is the number of positives). Attend was higher in {wins_better} of 6 windows.</figcaption></figure>
<h3>6.5 At equal queue size (exploratory)</h3>
<p>Queues of different sizes are hard to compare, so here every ranking is read down to exactly the size of each queue and its recall is shown beside the queue's own.</p>
{table(["Queue size set by", "Share of CVEs", "Stenwatch score ranking", "EPSS ranking", "CVSS ranking", "The queue itself"],
       [[e(short(q)), pct(Q[q]['share'], 1), pct(EQ[q]['stenwatch']['recall']), pct(EQ[q]['epss']['recall']), pct(EQ[q]['cvss']['recall']), f"<b>{pct(Q[q]['recall'])}</b>"] for q in ("attend", "cvss9", "cvss7", "attend_track")])}
<p>Up to a queue the size of the critical list, a probability-led ranking finds many more exploited CVEs than a severity ranking. At the size of the large lists, the CVSS ranking is ahead: {pct(EQ['cvss7']['cvss']['recall'])} against {pct(EQ['cvss7']['stenwatch']['recall'])} at the size of the CVSS 7+ list. The Attend + Track queue ({pct(AT['recall'])}) is no better than simply reading the CVSS ranking to the same size ({pct(EQ['attend_track']['cvss']['recall'])}).</p>
<h3>6.6 Why severity wins in the tail</h3>
<p>{pct(low_epss)} of the later-exploited CVEs had an EPSS score under 0.01 on the origin day, so they sit in the bottom of any probability ranking and are reached only by reading very far down it. Severity does not depend on prior exploitation signals, which is why it recovers them late. This is the argument for keeping a severity-based second pass behind the Attend queue.</p>

<h2>7. Threats to validity and limits</h2>
<ol>
<li><b>KEV is a proxy for "exploited".</b> CISA lists vulnerabilities with evidence of exploitation that are relevant to its mission and have remediation guidance. Exploited CVEs it never lists count here as negatives. The test measures agreement with CISA's list.</li>
<li><b>Only CVEs that existed on T0 can be scored.</b> {pct(late_share)} of KEV additions in these windows were published after T0; no ranking could have found them in advance.</li>
<li><b>Few positives.</b> {P['positives']} in total, between {min(w['positives'] for w in W)} and {max(w['positives'] for w in W)} per window. Single-window figures are noisy. Pooled intervals assume positives are independent, but exploited CVEs often cluster in one product, so the true uncertainty is somewhat larger than shown.</li>
<li><b>EPSS changed model version</b> during the period, so scores are not perfectly comparable across windows; section 8 shows sensitivity to the threshold.</li>
<li><b>CVSS is today's value.</b> NVD revises scores after publication. If revisions are more likely for CVEs that later prove important, severity is slightly flattered; the bias would favour the CVSS baselines, not Stenwatch.</li>
<li><b>Not tested here:</b> the KEV flag, ransomware use, threat-group overlap, asset criticality, internet exposure and supplier context. They have no point-in-time history. In use they act on top of the ranking, so this report tests the part that can be tested and nothing more.</li>
<li><b>Global, not local.</b> The queues cover all CVEs. In use, Stenwatch first filters to your own assets, which shrinks the queue by orders of magnitude; the ranking quality measured here carries over, the percentages do not.</li>
<li><b>An earlier result was wrong.</b> See the correction in section 1. The self-check on database coverage was added because of it.</li>
</ol>

<h2>8. Sensitivity to the thresholds</h2>
<p>Moving the EPSS threshold trades queue size against recall along one curve (figure 5). Lowering the default of {R['tiers']['attend_epss']} to 0.05 would add {pct(sw[0.05]['size_share'] - A['share'], 1)} of all CVEs to the queue and {100 * (sw[0.05]['recall'] - A['recall']):.0f} points of recall; raising it to 0.2 would remove {pct(A['share'] - sw[0.2]['size_share'], 1)} of CVEs and {100 * (A['recall'] - sw[0.2]['recall']):.0f} points of recall.</p>
{table(["EPSS at or above", "Queue (share of CVEs)", "Recall"], [[f"{s['t']:g}" + (" (default)" if s['t'] == R['tiers']['attend_epss'] else ""), pct(s['size_share'], 2), pct(s['recall'])] for s in P['sweep_epss']], "small")}
{table(["CVSS at or above", "Queue (share of CVEs)", "Recall"], [[f"{s['t']:g}", pct(s['size_share'], 1), pct(s['recall'])] for s in P['sweep_cvss']], "small")}
<figure>{fig_sweep()}<figcaption><b>Figure 5.</b> Recall against queue size as each threshold moves. Ringed points are the thresholds used in this report.</figcaption></figure>

<h2>9. Reproducibility and checks</h2>
<p>Everything is regenerated by commands run from the repository root: <code>python tools/backtest.py</code> (downloads six EPSS files, writes docs/backtest/results.json; about a minute once the database is complete), then <code>python tools/backtest_report.py</code> (writes this report). The statistics have unit tests with hand-worked answers (<code>python tools/test_backtest.py</code>). To complete a database that is missing years, <code>python tools/nvd_fill.py 2024-01-01 2026-10-09</code>.</p>
{table(["Check", "Result"], [[e(c['check']), '<b style="color:#0f9d73">passed</b>' if c['passed'] else '<b style="color:#c8344a">FAILED</b>'] for c in R['checks']], "small")}
{table(["Window origin", "EPSS file SHA-256", "Rows"], [[w['origin'], f"<code>{w['epss_sha256'][:24]}&hellip;</code>", num(w['epss_rows'])] for w in W], "small")}
<p>Software: Python {e(R['python'])}, NumPy {e(R['numpy'])}; code revision {e(R['code_commit'])}.</p>

<h2>10. Conclusions and next steps</h2>
<ol><li><b>Use Attend as the first-pass queue.</b> It is {shrink(A['share'], C9['share'])} times smaller than the critical list, finds about as many later-exploited CVEs, and each CVE read is {hit_ratio:.1f} times as likely to matter.</li>
<li><b>Do not stop at Attend.</b> About {pct(1 - A['recall'])} of later-exploited CVEs sit outside it. Keep a severity-ordered second pass behind it for as long as capacity allows; the Track tier is that pass, and it is large.</li>
<li><b>Keep the KEV feed fresh.</b> {pct(late_share)} of CISA additions concern CVEs that did not exist six months earlier; the Act tier, which reacts to KEV, is what covers them.</li>
<li><b>Re-run every quarter.</b> New windows add positives and show whether EPSS model changes move the thresholds; the commands above take minutes.</li>
<li><b>Add labels that do not depend on CISA</b> (public exploit code, vendor advisories noting exploitation) to reduce the proxy problem.</li>
<li><b>Test the local part separately.</b> Asset context cannot be backtested globally; measure it on your own incidents and patch decisions.</li></ol>

<h2>Appendix: per-window detail</h2>
{table(["Origin", "Queue", "Size", "Positives caught", "Recall"],
       [[w['origin'], e(short(q)), num(w['queues'][q]['size']), f"{w['queues'][q]['hits']} of {w['positives']}", pct(w['queues'][q]['hits'] / w['positives'])] for w in W for q in ("attend", "cvss9")], "small")}
<p class="foot">Stenwatch by Diljot Singh Johal &middot; MIT licence &middot; feed data belongs to FIRST, CISA and NIST.</p>
"""

CSS = """
*{box-sizing:border-box}body{margin:0;background:#f4f6f9;color:#1a2233;font:15px/1.6 'Segoe UI',system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:40px 36px 60px;background:#fff}
h1{font-size:28px;line-height:1.2;margin:0 0 6px;letter-spacing:-.02em}.sub{color:#5b6678;font-size:13px;margin:0 0 24px}
h2{font-size:19px;margin:34px 0 8px;padding-bottom:5px;border-bottom:2px solid #0f9d73}h3{font-size:15.5px;margin:22px 0 6px}
p,li{max-width:78ch}li{margin:4px 0}code{font:12.5px 'Cascadia Mono',Consolas,monospace;background:#eef1f5;padding:1px 5px;border-radius:3px}
.note{background:#fff7e8;border-left:4px solid #d9822b;padding:10px 14px;border-radius:3px}
.wrap{overflow-x:auto;margin:10px 0 14px}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border:1px solid #d9dee6;padding:6px 9px;text-align:left;vertical-align:top}th{background:#eef1f5;font-size:12px}
table.small{width:auto;min-width:60%}figure{margin:14px 0}figure svg{width:100%;height:auto;border:1px solid #e3e7ee}
figcaption{font-size:12.5px;color:#5b6678;margin-top:4px}.foot{margin-top:36px;color:#5b6678;font-size:12px}
@media print{body{background:#fff}main{padding:0;max-width:none}@page{size:A4;margin:14mm 13mm}h2,h3{break-after:avoid}figure,table,tr{break-inside:avoid}body{font-size:10.5pt}}
"""


def summary_md():
    """docs/backtest.md: a short summary generated from the same results, so it can never disagree with the report."""
    lines = [
        "# Backtest summary", "",
        "Does Stenwatch's ranking find the CVEs that attackers go on to use? Six non-overlapping six-month windows, using only data available on each start day, scored against CISA's Known Exploited Vulnerabilities (KEV) additions. "
        "Full method, statistics and limits: [report.html](backtest/report.html) ([PDF](backtest/report.pdf)). Raw numbers: [results.json](backtest/results.json).", "",
        f"**{P['positives']} later-exploited CVEs** among {num(P['population'])} CVE-windows (base rate {pct(P['base_rate'], 3)}).", "",
        "| Queue | Share of CVEs | Later-exploited CVEs found (95% interval) |", "|---|---|---|",
    ]
    for q in ("attend", "attend_track", "cvss9", "cvss7"):
        lines.append(f"| {L['queues'][q]} | {pct(Q[q]['share'], 1)} | {pct(Q[q]['recall'])} ({ci(Q[q])}) |")
    lines += ["",
        f"- Attend found {pct(A['recall'])} from a queue {shrink(A['share'], C9['share'])} times smaller than the CVSS 9+ list, which found {pct(C9['recall'])}. The difference in what they found is not significant (p {ptxt(pair9['p'])}); the size difference is the gain.",
        f"- At the same queue size the Stenwatch ranking is clearly better than severity (reading as many CVEs as the CVSS 9+ list holds: {pct(EQ['cvss9']['stenwatch']['recall'])} against {pct(EQ['cvss9']['cvss']['recall'])}). It is better at small review budgets and worse in the long tail: a CVSS ranking reaches 80% after {pct(CV['reviews80_share'], 1)} of the list, the Stenwatch score after {pct(ST['reviews80_share'], 1)}.",
        f"- {pct(late_share)} of CISA additions concerned CVEs not yet published at the start of the window, so no ranking could have found them.", "",
        "> **Correction.** An earlier version of this page said the Attend queue caught about 70% of later-exploited CVEs against about a third for the critical list. That was wrong: it came from a local database missing most 2024 and 2025 CVEs. The figures above replace it.", "",
        "Reproduce: `python tools/backtest.py` then `python tools/backtest_report.py` (see section 9 of the report).", ""]
    (ROOT / "docs" / "backtest.md").write_text(chr(10).join(lines), encoding="utf-8")


def main():
    summary_md()
    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="author" content="Diljot Singh Johal"><title>Stenwatch backtest report</title><style>{CSS}</style></head><body><main>{BODY}</main></body></html>')
    (OUT / "report.html").write_text(page, encoding="utf-8")
    pdf = to_pdf(OUT / "report.html")
    print("wrote", OUT / "report.html", "and", pdf if pdf else "(no PDF: needs Edge or Chrome)")


if __name__ == "__main__":
    main()
