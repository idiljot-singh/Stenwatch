"""Cut the duck out of its viewer background: python video/cutout_duck.py
The viewer background is a smooth dark gradient with a soft floor shadow, so "smooth region touching the border" = background.
Writes video/duck/cut_00..15.png (transparent, cropped to one common box so the feet stay put) and a contact sheet in video/out/."""
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter
from scipy import ndimage as ndi

HERE = Path(__file__).resolve().parent
SRC, OUT = HERE / "duck", HERE / "out"
EDGE = 7     # a colour jump bigger than this between neighbours is an edge, not gradient
H = 640      # output height in pixels


def matte(path):
    rgb = np.asarray(Image.open(path).convert("RGB")).astype(np.int16)
    gx = np.abs(np.diff(rgb, axis=1)).max(axis=2); gy = np.abs(np.diff(rgb, axis=0)).max(axis=2)
    edge = np.zeros(rgb.shape[:2], bool)
    edge[:, :-1] |= gx > EDGE; edge[:, 1:] |= gx > EDGE; edge[:-1, :] |= gy > EDGE; edge[1:, :] |= gy > EDGE
    edge = ndi.binary_dilation(edge, iterations=1)                       # close hairline gaps in the outline
    lab, _ = ndi.label(~edge)
    border = np.unique(np.concatenate([lab[0], lab[-1], lab[:, 0], lab[:, -1]]))
    bg = np.isin(lab, border[border > 0])
    fg = ndi.binary_fill_holes(~bg)                                       # the duck, including smooth patches inside it
    fg = ndi.binary_opening(fg, iterations=2)
    keep, n = ndi.label(fg)                                               # drop specks: keep the biggest blob
    if n > 1:
        fg = keep == (1 + int(np.argmax(ndi.sum(fg, keep, range(1, n + 1)))))
    fg = ndi.binary_erosion(fg, iterations=1)                             # trim the dark fringe of the old background
    a = Image.fromarray((fg * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(1.1))
    img = Image.open(path).convert("RGBA"); img.putalpha(a)
    return img


def main():
    imgs = [matte(p) for p in sorted(SRC.glob("duck_*.png"))]
    boxes = [i.getchannel("A").point(lambda v: 255 if v > 20 else 0).getbbox() for i in imgs]
    l, t = min(b[0] for b in boxes), min(b[1] for b in boxes)
    r, bm = max(b[2] for b in boxes), max(b[3] for b in boxes)
    pad = 12
    crop = (max(0, l - pad), max(0, t - pad), min(imgs[0].width, r + pad), min(imgs[0].height, bm + pad))
    w = round((crop[2] - crop[0]) * H / (crop[3] - crop[1]))
    for i, im in enumerate(imgs):
        im.crop(crop).resize((w, H), Image.LANCZOS).save(SRC / f"cut_{i:02d}.png")
    sheet = Image.new("RGBA", (w * 8 // 2, H * 2 // 2), (255, 0, 255, 255))
    for i, im in enumerate(imgs):
        small = im.crop(crop).resize((w // 2, H // 2), Image.LANCZOS)
        sheet.alpha_composite(small, ((i % 8) * (w // 2), (i // 8) * (H // 2)))
    sheet.convert("RGB").save(OUT / "duck_sheet.png")
    print("size", w, H, "crop", crop)


if __name__ == "__main__":
    main()
