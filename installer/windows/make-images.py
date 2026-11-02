#!/usr/bin/env python3
"""Draws the setup wizard images from the Wantastic logo.

Inno Setup wants 24-bit BMPs: the side panel (164x314, plus 2x) and the
header mark (55x55, plus 2x). Standard library only; run it after the logo
changes and commit the output:

    python3 installer/windows/make-images.py
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# Brand colours: the console's navy and the logo's blue.
NAVY_TOP = (11, 18, 38)
NAVY_BOTTOM = (13, 42, 92)
WHITE = (255, 255, 255)


def read_png(path):
    """Decodes an 8-bit RGBA, non-interlaced PNG into rows of RGBA tuples."""
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path
    pos, idat, width, height = 8, b"", 0, 0
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert depth == 8 and ctype == 6 and interlace == 0, "need 8-bit RGBA"
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride, bpp = width * 4, 4
    rows, prev, i = [], bytearray(stride), 0
    for _ in range(height):
        f = raw[i]
        line = bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[x] = (line[x] + pred) & 255
        rows.append([tuple(line[x:x + 4]) for x in range(0, stride, 4)])
        prev = line
    return rows


def canvas(w, h, top, bottom):
    out = []
    for y in range(h):
        t = y / max(h - 1, 1)
        out.append([tuple(round(top[k] + (bottom[k] - top[k]) * t) for k in range(3))] * w)
    return [list(r) for r in out]


def paste(img, logo, cx, cy):
    lh, lw = len(logo), len(logo[0])
    x0, y0 = cx - lw // 2, cy - lh // 2
    for y in range(lh):
        for x in range(lw):
            r, g, b, a = logo[y][x]
            if a == 0:
                continue
            bg = img[y0 + y][x0 + x]
            img[y0 + y][x0 + x] = tuple(round((v * a + bv * (255 - a)) / 255) for v, bv in zip((r, g, b), bg))


def write_bmp(path, img):
    h, w = len(img), len(img[0])
    pad = (4 - (w * 3) % 4) % 4
    body = bytearray()
    for row in reversed(img):
        for r, g, b in row:
            body += bytes((b, g, r))
        body += b"\x00" * pad
    header = struct.pack("<2sIHHI", b"BM", 54 + len(body), 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body), 2835, 2835, 0, 0)
    open(path, "wb").write(header + info + body)


def write_ico(path, sizes):
    """An .ico holding the PNG logo at each size (Vista+ PNG entries)."""
    images = [open(os.path.join(HERE, f"logo-{n}.png"), "rb").read() for n in sizes]
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for n, png in zip(sizes, images):
        out += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
    open(path, "wb").write(out + b"".join(images))


def main():
    logos = {n: read_png(os.path.join(HERE, f"logo-{n}.png")) for n in (64, 128, 256)}
    for scale, logo in ((1, logos[128]), (2, logos[256])):
        w, h = 164 * scale, 314 * scale
        img = canvas(w, h, NAVY_TOP, NAVY_BOTTOM)
        paste(img, logo, w // 2, int(h * 0.36))
        suffix = "" if scale == 1 else "-2x"
        write_bmp(os.path.join(HERE, f"wizard{suffix}.bmp"), img)
    for scale, logo in ((1, logos[64]), (2, logos[128])):
        n = 64 * scale
        img = canvas(n, n, WHITE, WHITE)
        paste(img, logo, n // 2, n // 2)
        suffix = "" if scale == 1 else "-2x"
        write_bmp(os.path.join(HERE, f"wizard-small{suffix}.bmp"), img)
    write_ico(os.path.join(HERE, "wantastic.ico"), (16, 32, 64, 128, 256))


if __name__ == "__main__":
    main()
