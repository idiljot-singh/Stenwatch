"""Capture the CC0 'Pilot Duck Adventurer' (Meshy, by SPLYGON) from its public viewer at 16 angles as transparent PNGs: python video/capture_duck.py"""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

URL = "https://www.meshy.ai/3d-models/Pilot-Duck-Adventurer-019d5dfb-791a-722b-87db-cd6b5a296b38?page=landing"
OUT = Path(__file__).resolve().parent / "duck"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 16
HIDE = "html,body,#__next,div,section,main{background:transparent!important}body *{visibility:hidden!important}canvas{visibility:visible!important;background:transparent!important;background-image:none!important}*::before,*::after{background:transparent!important;background-image:none!important}"

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge")
    pg = b.new_page(viewport={"width": 1500, "height": 950}, device_scale_factor=1.5)
    pg.goto(URL, wait_until="networkidle", timeout=90000)
    pg.wait_for_timeout(7000)
    box = pg.evaluate("(() => { const r = document.querySelector('canvas').getBoundingClientRect(); return {x: r.x, y: r.y, w: r.width, h: r.height}; })()")
    pg.add_style_tag(content=HIDE)
    cx, cy, step = box["x"] + box["w"] / 2, box["y"] + box["h"] / 2, box["h"] / N   # a drag of one canvas height turns the model 360 degrees
    for i in range(N):
        pg.wait_for_timeout(900)
        pg.screenshot(path=str(OUT / f"duck_{i:02d}.png"), omit_background=True,
                      clip={"x": box["x"] + box["w"] * .1, "y": box["y"] + 20, "width": box["w"] * .8, "height": box["h"] - 30})
        pg.mouse.move(cx, cy); pg.mouse.down(); pg.mouse.move(cx + step, cy, steps=8); pg.mouse.up()
    b.close()
print("captured", N)
