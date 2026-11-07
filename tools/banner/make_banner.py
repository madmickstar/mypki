"""Generate a mypki banner in the same visual language as madmickstar/mcp_eveng's assets/banner.png.

Style facts were MEASURED from the reference PNG (analyze_ref.py), not eyeballed:
  canvas 2890x578; six light-blue mosaic shades (~11-13% each); navy rgb(16,48,120) for borders/frame/outlines;
  dashed bands rows 10-24 and 554-568 (15px tall); a 3px solid frame line at rows 34-36 / 542-544, inset 34;
  letters assembled from square tiles with a navy outline, mid-blue fill and a nested inner square.

Deterministic: the mosaic is seeded, so re-running reproduces the same bytes.

In-tree since the README restructure. MEASURED on this box (system python3 with Pillow 12.3.0 -- note that Pillow is NOT
in .venv, so regenerate with an interpreter that has it installed):
    python3 tools/banner/make_banner.py assets/banner.png 316 320 0.32
    -> font=316 tracking=320 thr=0.32: glyphs 2380x306, frame interior 2816 wide
    -> wrote assets/banner.png 2890x578 9860 bytes
    -> sha256 f9df99a436d781db41d39a450535a31fad2019839e8124fbd796a19d944836cc, identical to the committed banner
Re-running with the same three arguments therefore reproduces the shipped file byte for byte. `tools/` is linted by
`make lint`, so this file is held to the same ruff rules as the package even though it ships nothing.
"""

from __future__ import annotations

import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 2890, 578
TILE = 34
FRAME_INSET = 34
BAND_H = 15

BG_SHADES = [
    (160, 216, 248),
    (152, 208, 248),
    (144, 200, 248),
    (136, 192, 240),
    (120, 184, 232),
    (112, 176, 224),
]
NAVY = (16, 48, 120)
NAVY_MID = (24, 72, 144)
NAVY_LIGHT = (32, 88, 168)
LETTER_FILL = (64, 192, 248)
LETTER_INNER = (128, 208, 248)
SPECKLE = (224, 240, 248)

TEXT = "myPKI"


def background(draw: ImageDraw.ImageDraw, rng: random.Random) -> None:
    for gy in range((H + TILE - 1) // TILE):
        for gx in range((W + TILE - 1) // TILE):
            x0, y0 = gx * TILE, gy * TILE
            # Inclusive bottom-right corner, clamped to the canvas. W and H are exact multiples of TILE here,
            # so the clamp only ever bites on a resized canvas -- but it must not produce an inverted rectangle.
            x1 = min(x0 + TILE, W) - 1
            y1 = min(y0 + TILE, H) - 1
            if x1 < x0 or y1 < y0:
                continue
            low = BG_SHADES[(gx // 3 + gy // 2) % len(BG_SHADES)]
            pick = low if rng.random() < 0.55 else BG_SHADES[rng.randrange(len(BG_SHADES))]
            draw.rectangle([x0, y0, x1, y1], fill=pick)
            if rng.random() < 0.12:
                sx = x0 + rng.randrange(1, max(2, TILE - 4))
                sy = y0 + rng.randrange(1, max(2, TILE - 4))
                draw.rectangle([sx, sy, sx + 2, sy + 2], fill=SPECKLE)


def dashed_band(draw: ImageDraw.ImageDraw, top: int) -> None:
    x = 8
    while x + BAND_H - 1 <= W - 9:
        draw.rectangle([x, top, x + BAND_H - 1, top + BAND_H - 1], fill=NAVY)
        x += BAND_H + 7


def frame(draw: ImageDraw.ImageDraw) -> None:
    for t in range(3):
        draw.rectangle(
            [FRAME_INSET + t, FRAME_INSET + t, W - 1 - FRAME_INSET - t, H - 1 - FRAME_INSET - t],
            outline=NAVY,
        )


def letter_grid(font_size: int, tracking: int, threshold: float):
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
    widths = [font.getbbox(ch)[2] - font.getbbox(ch)[0] for ch in TEXT]
    total_w = sum(widths) + tracking * (len(TEXT) - 1)
    pad = 90
    mask_img = Image.new("L", (total_w + 2 * pad, font_size + 2 * pad), 0)
    mask_draw = ImageDraw.Draw(mask_img)
    x = pad
    for ch in TEXT:
        mask_draw.text((x, pad), ch, font=font, fill=255)
        x += (font.getbbox(ch)[2] - font.getbbox(ch)[0]) + tracking

    cols, rows = mask_img.width // TILE, mask_img.height // TILE
    grid = []
    for gy in range(rows):
        row = []
        for gx in range(cols):
            block = mask_img.crop((gx * TILE, gy * TILE, (gx + 1) * TILE, (gy + 1) * TILE))
            hist = block.histogram()
            ink = sum(i * c for i, c in enumerate(hist) if i > 128)
            row.append((ink / (TILE * TILE * 255)) >= threshold)
        grid.append(row)

    on_rows = [i for i, r in enumerate(grid) if any(r)]
    on_cols = [j for j in range(cols) if any(grid[i][j] for i in range(rows))]
    return grid, min(on_rows), max(on_rows), min(on_cols), max(on_cols)


def draw_tile(draw: ImageDraw.ImageDraw, x0: int, y0: int) -> None:
    x1, y1 = x0 + TILE - 3, y0 + TILE - 3
    draw.rectangle([x0, y0, x1, y1], fill=LETTER_FILL, outline=NAVY)
    draw.rectangle([x0 + 4, y0 + 4, x1 - 4, y1 - 4], outline=NAVY_MID)
    draw.rectangle([x0 + 8, y0 + 8, x1 - 8, y1 - 8], fill=LETTER_INNER, outline=NAVY_LIGHT)
    draw.rectangle([x0 + 12, y0 + 12, x1 - 12, y1 - 12], outline=NAVY_MID)
    for dx, dy in ((0, 0), (TILE - 3, 0), (0, TILE - 3), (TILE - 3, TILE - 3)):
        draw.rectangle([x0 + dx, y0 + dy, x0 + dx + 1, y0 + dy + 1], fill=SPECKLE)


def build(font_size: int = 316, tracking: int = 320, threshold: float = 0.32) -> Image.Image:
    img = Image.new("RGB", (W, H), BG_SHADES[3])
    draw = ImageDraw.Draw(img)
    rng = random.Random(20261107)

    background(draw, rng)
    dashed_band(draw, 10)
    dashed_band(draw, H - 10 - BAND_H)
    frame(draw)

    grid, top, bottom, left, right = letter_grid(font_size, tracking, threshold)
    glyph_w = (right - left + 1) * TILE
    glyph_h = (bottom - top + 1) * TILE
    inner_w = W - 2 * (FRAME_INSET + 3)
    inner_h = H - 2 * (FRAME_INSET + 3)
    off_x = FRAME_INSET + 3 + (inner_w - glyph_w) // 2 - left * TILE
    off_y = FRAME_INSET + 3 + (inner_h - glyph_h) // 2 - top * TILE

    for gy in range(top, bottom + 1):
        for gx in range(left, right + 1):
            if grid[gy][gx]:
                draw_tile(draw, off_x + gx * TILE, off_y + gy * TILE)
    return img


def letter_extent(font_size: int, tracking: int, threshold: float) -> tuple[int, int]:
    # `_grid`: the cells themselves are not needed here, only the extent of the rows/columns they occupy. The underscore
    # is what keeps `make lint`'s RUF059 from firing on an unpacked value that is deliberately unused.
    _grid, top, bottom, left, right = letter_grid(font_size, tracking, threshold)
    return (right - left + 1) * TILE, (bottom - top + 1) * TILE


if __name__ == "__main__":
    import sys

    out = Path(sys.argv[1] if len(sys.argv) > 1 else "banner_draft.png")
    font_size = int(sys.argv[2]) if len(sys.argv) > 2 else 316
    tracking = int(sys.argv[3]) if len(sys.argv) > 3 else 320
    threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.32
    out.parent.mkdir(parents=True, exist_ok=True)
    gw, gh = letter_extent(font_size, tracking, threshold)
    inner = W - 2 * (FRAME_INSET + 3)
    print(f"font={font_size} tracking={tracking} thr={threshold}: glyphs {gw}x{gh}, frame interior {inner} wide")
    image = build(font_size, tracking, threshold)
    quantised = image.convert("P", palette=Image.ADAPTIVE, colors=32)
    quantised.save(out, optimize=True)
    print(f"wrote {out} {image.size[0]}x{image.size[1]} {out.stat().st_size} bytes")
