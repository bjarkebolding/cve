#!/usr/bin/env python3
"""Generate logo.svg from the real Turrican sprite art.

Default source: art/turrican_ref.png -- the box-art scene: Turrican (white
armor, blue visor) firing his blaster, yellow/red muzzle flash, on a black
field with a light-gray product border. The black background becomes
transparent, so the logo sits naturally on the site's black theme.

Alternate source: art/turrican_box.png -- single hero on a WHITE background
(8-bit colormap, C64 palette); the white background is removed by a
corner-connected flood fill (interior white armor is preserved).

The tool auto-detects the background from the corner pixels, crops to the
content bbox, downscales to a crisp pixel grid (box average) and snaps every
pixel to the dominant palette. Output: one SVG rect per pixel -> logo.svg.

Run:  python3 tools/make_logo.py [source.png]
"""
import os
import struct
import sys
import zlib
from collections import Counter, deque

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "logo.svg")
TARGET_W = 64          # final grid width (capped at source width: no upscale)
FLOOD_WHITE = 240      # channels >= this (all 3) count as white background
DARK_FIELD = 70        # max channel < this = part of the black field
CONTENT_TH = 45        # max channel > this = content (sprite)
CELL_DROP = 30         # cell avg max below this -> transparent
MIN_ALPHA = 0.50       # a cell keeps color if >= this fraction of its
                       # source pixels are content


# ------------------------------------------------------------------ PNG read
def decode_png(path):
    """Decode 8-bit RGB (2) or palette (3) PNG. Returns (w, h, rgb, palette).
    Stdlib only."""
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w, h, ct, plte = 8, b"", 0, 0, 0, None
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            w, h, _, ct = struct.unpack(">IIBB", chunk[:10])
        elif typ == b"PLTE":
            plte = chunk
        elif typ == b"IDAT":
            idat += chunk
        pos += 12 + ln
    raw = zlib.decompress(idat)
    ch = {2: 3, 3: 1}[ct]
    stride = w * ch
    out, prev, p = bytearray(), bytearray(stride), 0
    for _ in range(h):
        f = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        if f == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 255
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b, c = prev[i], (prev[i - ch] if i >= ch else 0)
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        out += line
        prev = line
    if ct == 3:
        pal = [(plte[i * 3], plte[i * 3 + 1], plte[i * 3 + 2])
               for i in range(len(plte) // 3)]
        rgb = bytearray()
        for i in out:
            rgb += bytes(pal[i])
        return w, h, bytes(rgb), pal
    return w, h, bytes(out), None


# ------------------------------------------------------------------ masks
def corners_bright(w, h, px):
    n = 0
    for (x, y) in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
        n += 1 if max(px[(y * w + x) * 3:(y * w + x) * 3 + 3]) > 128 else 0
    return n >= 3


def flood_white(w, h, px):
    """Corner-connected flood fill over near-white -> keep mask list."""
    bg = bytearray(w * h)
    q = deque([(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)])
    while q:
        x, y = q.popleft()
        i = y * w + x
        if bg[i]:
            continue
        r, g, b = px[i * 3], px[i * 3 + 1], px[i * 3 + 2]
        if r < FLOOD_WHITE or g < FLOOD_WHITE or b < FLOOD_WHITE:
            continue
        bg[i] = 1
        if x > 0: q.append((x - 1, y))
        if x < w - 1: q.append((x + 1, y))
        if y > 0: q.append((x, y - 1))
        if y < h - 1: q.append((x, y + 1))
    return [1 if not v else 0 for v in bg]


def black_field(w, h, px):
    """Bbox of the dark field (the black square inside the product border)."""
    minx, miny, maxx, maxy = w, h, -1, -1
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 3
            if max(px[i], px[i + 1], px[i + 2]) < DARK_FIELD:
                if x < minx: minx = x
                if x > maxx: maxx = x
                if y < miny: miny = y
                if y > maxy: maxy = y
    if maxx < 0:
        raise SystemExit("no black field found (is this the right image?)")
    return minx, miny, maxx, maxy


def content_mask(w, h, px, x0, y0, x1, y1):
    """Content pixels (bright) inside the black field -> keep mask list."""
    keep = [0] * (w * h)
    for y in range(y0, y1 + 1):
        row = y * w
        for x in range(x0, x1 + 1):
            i = row + x
            if max(px[i * 3], px[i * 3 + 1], px[i * 3 + 2]) > CONTENT_TH:
                keep[i] = 1
    return keep


# ------------------------------------------------------------------- utils
def bbox_of(keep, w, h):
    minx, miny, maxx, maxy = w, h, -1, -1
    for y in range(h):
        for x in range(w):
            if keep[y * w + x]:
                if x < minx: minx = x
                if x > maxx: maxx = x
                if y < miny: miny = y
                if y > maxy: maxy = y
    if maxx < 0:
        raise SystemExit("no content pixels found")
    return minx, miny, maxx, maxy


def build_palette(w, px, keep, x0, y0, x1, y1, max_colors=10):
    c = Counter()
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            i = (y * w + x) * 3
            if keep[y * w + x]:
                c[(px[i] >> 4 << 4, px[i + 1] >> 4 << 4, px[i + 2] >> 4 << 4)] += 1
    pal = []
    for col, _ in c.most_common(max_colors * 3):
        if max(col) < CELL_DROP * 1.2:
            continue
        if all(sum(abs(a - b) for a, b in zip(col, o)) > 48 for o in pal):
            pal.append(col)
        if len(pal) == max_colors:
            break
    return pal


def downsample(w, h, px, keep, x0, y0, x1, y1, tw, pal):
    bw, bh = x1 - x0 + 1, y1 - y0 + 1
    tw = min(tw, bw)  # never upscale -- keep source detail 1:1
    f = bw / tw
    th = max(1, round(bh / f))
    d2 = lambda c, p: (c[0] - p[0]) ** 2 + (c[1] - p[1]) ** 2 + (c[2] - p[2]) ** 2
    cells = []
    for gy in range(th):
        for gx in range(tw):
            xa, ya = x0 + int(gx * f), y0 + int(gy * f)
            xb, yb = (min(x0 + int((gx + 1) * f), x1 + 1),
                      min(y0 + int((gy + 1) * f), y1 + 1))
            n, kc, rs, gs, bs = 0, 0, 0, 0, 0
            for y in range(ya, yb):
                row = y * w
                for x in range(xa, xb):
                    i = row + x
                    n += 1
                    if keep[i]:
                        kc += 1
                        rs += px[i * 3]; gs += px[i * 3 + 1]; bs += px[i * 3 + 2]
            if n == 0 or kc / n < MIN_ALPHA:
                cells.append(None)
                continue
            avg = (rs / kc, gs / kc, bs / kc)
            if max(avg) < CELL_DROP:
                cells.append(None)
                continue
            cells.append(min(pal, key=lambda p: d2(avg, p)))
    rows = [cells[r * tw:(r + 1) * tw] for r in range(th)]
    while rows and all(c is None for c in rows[0]):
        rows.pop(0)
    while rows and all(c is None for c in rows[-1]):
        rows.pop()
    return len(rows[0]), len(rows), rows


def largest_component(w, h, keep, min_frac=0.02):
    """Drop small disconnected specks (compression artifacts, stray pixels):
    keep only components >= min_frac of the largest one."""
    seen = [0] * (w * h)
    comps = []
    for start in range(w * h):
        if not keep[start] or seen[start]:
            continue
        q = deque([start]); seen[start] = 1; comp = []
        while q:
            i = q.popleft(); comp.append(i)
            x, y = i % w, i // w
            for j in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
                if 0 <= j[0] < w and 0 <= j[1] < h:
                    n = j[1] * w + j[0]
                    if keep[n] and not seen[n]:
                        seen[n] = 1; q.append(n)
        comps.append(comp)
    if not comps:
        return keep
    big = max(len(c) for c in comps)
    out = keep[:]
    for c in comps:
        if len(c) < max(16, min_frac * big):
            for i in c:
                out[i] = 0
    return out


def main():
    args = sys.argv[1:]
    crop = None
    for a in args:
        if a.startswith("--crop="):
            crop = tuple(int(v) for v in a.split("=", 1)[1].split(","))
            args.remove(a)
    src = args[0] if args else os.path.join(BASE, "art", "turrican_box.png")
    w, h, px, plte = decode_png(src)
    print(f"source: {src} ({w}x{h}, palette={len(plte) if plte else 0})")

    # A genuine black field is a big contiguous dark square (>= half the
    # image in both dimensions); a sprite's dark outline is not.
    try:
        fx0, fy0, fx1, fy1 = black_field(w, h, px)
    except SystemExit:
        fx0 = fx1 = fy0 = fy1 = -1
    use_field = fx1 - fx0 > 0.5 * w and fy1 - fy0 > 0.5 * h

    if use_field:
        print(f"background: black field ({fx0},{fy0})-({fx1},{fy1})")
        cx0, cy0, cx1, cy1 = crop if crop else (fx0, fy0, fx1, fy1)
        if crop:
            print(f"crop: ({cx0},{cy0})-({cx1},{cy1})")
        keep = content_mask(w, h, px, cx0, cy0, cx1, cy1)
        keep = largest_component(w, h, keep)
        x0, y0, x1, y1 = bbox_of(keep, w, h)
        pal = build_palette(w, px, keep, x0, y0, x1, y1)
    else:
        print("background: white (corner flood fill)")
        keep = flood_white(w, h, px)
        keep = largest_component(w, h, keep)
        x0, y0, x1, y1 = bbox_of(keep, w, h)
        pal = plte if plte else build_palette(w, px, keep, x0, y0, x1, y1)
    print(f"content bbox: ({x0},{y0})-({x1},{y1}) = {x1 - x0 + 1}x{y1 - y0 + 1}")
    print("palette:", " ".join("#%02x%02x%02x" % c for c in pal))

    gw, gh, rows = downsample(w, h, px, keep, x0, y0, x1, y1, TARGET_W, pal)

    def sem(c):
        if c is None:
            return "."
        r, g, b = c
        if r > 190 and g > 190 and b > 190: return "W"
        if r > 190 and g > 140 and b < 130: return "Y"
        if r > 170 and g < 130 and b < 130: return "R"
        if r > 110 and g < 80: return "r"
        if b > 150 and r < 140: return "B"
        if b > 90 and r < 110: return "b"
        if max(r, g, b) > 110: return "#"
        if max(r, g, b) > 55: return ","
        return "."
    print("  (W=white B=blue R/Y=red/yellow #=gray .=bg)")
    for row in rows:
        print("  " + "".join(sem(c) for c in row))

    rects = []
    for y, row in enumerate(rows):
        for x, c in enumerate(row):
            if c is None:
                continue
            rects.append(
                f'<rect x="{x}" y="{y}" width="1" height="1" '
                f'fill="#{c[0]:02x}{c[1]:02x}{c[2]:02x}"/>')
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{gw}" height="{gh}" '
        f'viewBox="0 0 {gw} {gh}" '
        f'shape-rendering="crispEdges" role="img" '
        f'aria-label="Turrican space hero firing his blaster (pixel art)">'
        + "".join(rects) + "</svg>\n"
    )
    with open(OUT, "w") as f:
        f.write(svg)
    print(f"wrote {OUT} ({gw}x{gh}, {len(rects)} px)")


if __name__ == "__main__":
    main()
