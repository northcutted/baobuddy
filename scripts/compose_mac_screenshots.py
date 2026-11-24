#!/usr/bin/env python3
"""Compose macOS marketing screenshots for the README and site.

Raw window captures (``screencapture -l <window>``, transparent background with
the system shadow) live in ``docs/media/mac/raw/<NN_Name>.png``. Each is placed
on the same teal gradient and headline style as the App Store screenshots
(``scripts/process_screenshots.py``) at 2880x1800.

Usage:
    uv run --no-project --with pillow python3 scripts/compose_mac_screenshots.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import process_screenshots as ps  # noqa: E402

CANVAS = (2880, 1800)
HEADLINE_BOX_FRAC = (0.08, 0.05, 0.92, 0.22)
CONTENT_TOP_FRAC = 0.25
CONTENT_BOTTOM_PAD_FRAC = 0.03

HEADLINES = {
    "01_MenuBar": "Approve grants from the menu bar\nTouch ID, scoped and short-lived",
    "02_Servers": "OpenBao and Vault servers\nSwitch environments anytime",
    "03_HardwareKeys": "Keys live in the Secure Enclave\nOnly the public half leaves your Mac",
}

# Small windows are scaled up a little so they read at README size.
MAX_SCALE = {"01_MenuBar": 1.5}


def compose(src: Path, dest: Path, headline: str) -> None:
    with Image.open(src) as opened:
        window = opened.convert("RGBA")

    canvas = Image.new("RGBA", CANVAS, (0, 0, 0, 255))
    ps._draw_gradient_on(canvas, ps.BRAND_TOP, ps.BRAND_BOTTOM)
    ps._paint_top_highlight(canvas)

    w, h = CANVAS
    fx0, fy0, fx1, fy1 = HEADLINE_BOX_FRAC
    ps._draw_headline(canvas, headline, (int(fx0 * w), int(fy0 * h), int(fx1 * w), int(fy1 * h)))

    top = int(h * CONTENT_TOP_FRAC)
    avail_w = int(w * 0.9)
    avail_h = h - top - int(h * CONTENT_BOTTOM_PAD_FRAC)
    scale = min(avail_w / window.width, avail_h / window.height, MAX_SCALE.get(src.stem, 1.0))
    if scale != 1.0:
        window = window.resize((round(window.width * scale), round(window.height * scale)), Image.LANCZOS)
    x = (w - window.width) // 2
    y = top + (avail_h - window.height) // 2
    canvas.alpha_composite(window, (x, y))

    dest.parent.mkdir(parents=True, exist_ok=True)
    canvas.convert("RGB").save(dest, format="PNG", optimize=True)
    print(f"composed {dest}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    raw = root / "docs/media/mac/raw"
    out = root / "docs/media/mac"
    for src in sorted(raw.glob("*.png")):
        compose(src, out / src.name, HEADLINES.get(src.stem, ps.DEFAULT_HEADLINE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
