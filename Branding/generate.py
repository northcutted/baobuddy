#!/usr/bin/env python3
"""Generate every BaoBuddy brand asset from one set of vector geometry.

Run `make brand` (or `python3 Branding/generate.py`) after changing anything
below. The script rewrites:

  Branding/svg/*.svg                      master vector files
  Branding/png/*.png                      raster exports (needs rsvg-convert)
  BaoBuddy/AppIcon.icon/                  Icon Composer (Liquid Glass) app icon
  BaoBuddy/Assets.xcassets/BaoBuddy*.imageset
  BaoBuddyLiveActivity/Assets.xcassets/BaoBuddyGlyph*.imageset
  MacHelper/MenuBarGlyph*.png             macOS menu bar template images (@1x/@2x)

All drawing happens on a 1024 x 1024 grid (the Icon Composer canvas). Shapes
that must read as cut-outs (face, pleats, the gap around the padlock) are SVG
masks, so every single-colour variant stays transparent where it should.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "Branding"

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------
TEAL = "#0F766E"         # Bao Teal: primary brand / AccentColor (light)
TEAL_BRIGHT = "#14B8A6"  # Bao Teal Bright: AccentColor (dark), Live Activity
TEAL_TOP = "#1AA99A"     # app icon gradient, top
TEAL_DEEP = "#0A5650"    # app icon gradient, bottom
CREAM = "#FFF6E5"        # Steam Cream: the bun
TAN = "#E8CB9C"          # Pleat Tan: folds and outline on light surfaces
INK = "#1E293B"          # Soy Ink: face and text
BLUSH = "#F6AE9F"        # cheeks (full-colour mark only)
NIGHT = "#0B1B1A"        # dark-appearance icon background

# --------------------------------------------------------------------------
# Geometry (1024 grid, before centring)
# --------------------------------------------------------------------------
# The top is a pinched point with a fan of pleats. Avoid a round nub up there:
# without pleats a smooth dome plus a nub stops reading as food.
BUN = (
    "M262 770 C196 770 158 736 160 680 C166 500 300 362 436 332 "
    "C458 326 472 314 480 300 C488 314 502 326 524 332 "
    "C660 362 794 500 800 680 C802 736 764 770 698 770 Z"
)
PLEATS = [
    "M456 344 Q392 356 360 404",
    "M468 352 Q434 382 424 428",
    "M480 356 L480 432",
    "M492 352 Q526 382 536 428",
    "M504 344 Q568 356 600 404",
]
LOCK_BODY = dict(x=670, y=670, w=160, h=150, r=30)
SHACKLE_CLOSED = "M702 670 V636 A48 48 0 0 1 798 636 V670"
SHACKLE_OPEN = "M702 614 V596 A48 48 0 0 1 798 596 V670"
SHACKLE_W = 30

# Centring offset that places the artwork on the 1024 icon canvas.
CENTRE = (17, -31)


class Style:
    """Detail level: `mark` for 32pt and up, `glyph` (bolder cut-outs) for 14-28pt."""

    def __init__(self, *, pleat_w: int, eye_r: int, eye_y: int, eye_dx: int,
                 smile: str, smile_w: int, gap: int, keyhole_r: int):
        self.pleat_w = pleat_w
        self.eye_r = eye_r
        self.eye_y = eye_y
        self.eye_dx = eye_dx
        self.smile = smile
        self.smile_w = smile_w
        self.gap = gap
        self.keyhole_r = keyhole_r


MARK = Style(pleat_w=20, eye_r=30, eye_y=580, eye_dx=74,
             smile="M444 630 Q480 664 516 630", smile_w=22, gap=26, keyhole_r=18)
GLYPH = Style(pleat_w=26, eye_r=42, eye_y=590, eye_dx=82,
              smile="M436 646 Q480 694 524 646", smile_w=36, gap=40, keyhole_r=24)

# Padded crop for marks; a tight crop for small glyphs (menu bar, Dynamic Island).
MARK_VIEWBOX = (132, 258, 726, 590)
GLYPH_VIEWBOX = (150, 270, 690, 560)


def lock_body_svg(fill: str = "#000", extra: str = "") -> str:
    b = LOCK_BODY
    return (f'<rect x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" height="{b["h"]}" '
            f'rx="{b["r"]}" fill="{fill}" {extra}/>')


def keyhole_svg(s: Style, fill: str = "#000") -> str:
    cx = LOCK_BODY["x"] + LOCK_BODY["w"] / 2
    cy = LOCK_BODY["y"] + 65
    r = s.keyhole_r
    w = r
    return (f'<circle cx="{cx:g}" cy="{cy}" r="{r}" fill="{fill}"/>'
            f'<rect x="{cx - w / 2:g}" y="{cy}" width="{w}" height="{r * 2.4:g}" '
            f'rx="{w / 2:g}" fill="{fill}"/>')


def eyes_svg(s: Style, fill: str) -> str:
    return "".join(f'<circle cx="{480 + d * s.eye_dx}" cy="{s.eye_y}" r="{s.eye_r}" fill="{fill}"/>'
                   for d in (-1, 1))


def strokes_svg(paths: list[str], colour: str, width: int) -> str:
    inner = "".join(f'<path d="{p}"/>' for p in paths)
    return (f'<g fill="none" stroke="{colour}" stroke-width="{width}" '
            f'stroke-linecap="round" stroke-linejoin="round">{inner}</g>')


def lock_gap_svg(s: Style, shackle: str) -> str:
    """Black lock silhouette, grown by the gap, for use inside a mask."""
    return (lock_body_svg("#000", f'stroke="#000" stroke-width="{s.gap * 2}" stroke-linejoin="round"')
            + f'<path d="{shackle}" fill="none" stroke="#000" '
              f'stroke-width="{SHACKLE_W + s.gap * 2}" stroke-linecap="round"/>')


def svg_doc(viewbox: tuple[int, int, int, int], body: str, defs: str = "",
            size: tuple[int, int] | None = None) -> str:
    x, y, w, h = viewbox
    pw, ph = size or (w, h)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x} {y} {w} {h}" '
            f'width="{pw}" height="{ph}">'
            + (f"<defs>{defs}</defs>" if defs else "") + body + "</svg>\n")


def doc(viewbox: tuple[int, int, int, int], art: tuple[str, str]) -> str:
    defs, body = art
    return svg_doc(viewbox, body, defs)


def mask(id_: str, viewbox: tuple[int, int, int, int], cutouts: str) -> str:
    x, y, w, h = viewbox
    return (f'<mask id="{id_}" maskUnits="userSpaceOnUse" x="{x - 200}" y="{y - 200}" '
            f'width="{w + 400}" height="{h + 400}">'
            f'<rect x="{x - 200}" y="{y - 200}" width="{w + 400}" height="{h + 400}" fill="#fff"/>'
            f"{cutouts}</mask>")


def offset(viewbox: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Translate a viewBox defined on the raw grid onto the centred grid."""
    x, y, w, h = viewbox
    return (x + CENTRE[0], y + CENTRE[1], w, h)


# --------------------------------------------------------------------------
# Compositions. Each returns (defs, body) on the centred 1024 grid.
# --------------------------------------------------------------------------
def mono(colour: str, s: Style = MARK, unlocked: bool = False,
         parts: str = "all") -> tuple[str, str]:
    """Single-colour mark: face, pleats and lock gap are see-through."""
    shackle = SHACKLE_OPEN if unlocked else SHACKLE_CLOSED
    vb = (0, 0, 1024, 1024)
    cut_bun = (eyes_svg(s, "#000")
               + strokes_svg([s.smile], "#000", s.smile_w)
               + strokes_svg(PLEATS, "#000", s.pleat_w)
               + lock_gap_svg(s, shackle))
    defs = mask("bun", vb, cut_bun) + mask("key", vb, keyhole_svg(s))
    bun = f'<path d="{BUN}" fill="{colour}" mask="url(#bun)"/>'
    lock = (f'<g mask="url(#key)">{lock_body_svg(colour)}</g>'
            f'<path d="{shackle}" fill="none" stroke="{colour}" stroke-width="{SHACKLE_W}" '
            f'stroke-linecap="round"/>')
    content = {"all": bun + lock, "bun": bun, "lock": lock}[parts]
    return defs, f'<g transform="translate({CENTRE[0]} {CENTRE[1]})">{content}</g>'


def full_colour(lock_colour: str = TEAL, outline: bool = False) -> tuple[str, str]:
    """Cream bun, ink face, blush cheeks, teal padlock."""
    s = MARK
    vb = (0, 0, 1024, 1024)
    defs = mask("gap", vb, lock_gap_svg(s, SHACKLE_CLOSED)) + mask("key", vb, keyhole_svg(s))
    stroke = f' stroke="{TAN}" stroke-width="14" stroke-linejoin="round"' if outline else ""
    bun = (f'<g mask="url(#gap)">'
           f'<path d="{BUN}" fill="{CREAM}"{stroke}/>'
           + strokes_svg(PLEATS, TAN, s.pleat_w)
           + "".join(f'<ellipse cx="{480 + d * 130}" cy="634" rx="34" ry="20" fill="{BLUSH}"/>'
                     for d in (-1, 1))
           + eyes_svg(s, INK)
           + strokes_svg([s.smile], INK, s.smile_w)
           + "</g>")
    lock = (f'<g mask="url(#key)">{lock_body_svg(lock_colour)}</g>'
            f'<path d="{SHACKLE_CLOSED}" fill="none" stroke="{lock_colour}" '
            f'stroke-width="{SHACKLE_W}" stroke-linecap="round"/>')
    return defs, f'<g transform="translate({CENTRE[0]} {CENTRE[1]})">{bun}{lock}</g>'


def flat_icon(corner: bool = False) -> str:
    """Flat (non-glass) icon tile for README, web and social use."""
    defs, body = mono(CREAM)
    grad = (f'<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="{TEAL_TOP}"/><stop offset="1" stop-color="{TEAL_DEEP}"/>'
            f"</linearGradient>")
    rx = ' rx="230"' if corner else ""
    tile = f'<rect width="1024" height="1024"{rx} fill="url(#bg)"/>'
    return svg_doc((0, 0, 1024, 1024), tile + body, grad + defs)


def social_card() -> str:
    """1280 x 640 GitHub social preview: icon tile on teal."""
    defs, body = mono(CREAM)
    grad = (f'<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="{TEAL_TOP}"/><stop offset="1" stop-color="{TEAL_DEEP}"/>'
            f"</linearGradient>")
    inner = f'<g transform="translate(320 0) scale(0.625) translate(0 0)">{body}</g>'
    return svg_doc((0, 0, 1280, 640), f'<rect width="1280" height="640" fill="url(#bg)"/>{inner}',
                   grad + defs)


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------
def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_json(path: Path, data: dict) -> None:
    write(path, json.dumps(data, indent=2) + "\n")


def p3(hex_: str, alpha: float = 1.0) -> str:
    """Icon Composer colour string. Hex values are treated as sRGB."""
    r, g, b = (int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return f"srgb:{r:.5f},{g:.5f},{b:.5f},{alpha:.5f}"


def imageset(path: Path, svg: str, template: bool) -> None:
    if path.exists():
        shutil.rmtree(path)
    name = path.stem + ".svg"
    write(path / name, svg)
    props: dict[str, object] = {"preserves-vector-representation": True}
    if template:
        props["template-rendering-intent"] = "template"
    write_json(path / "Contents.json", {
        "images": [{"filename": name, "idiom": "universal"}],
        "info": {"author": "xcode", "version": 1},
        "properties": props,
    })


def app_icon(path: Path) -> None:
    """Icon Composer document: teal glass tile, cream bun and padlock layers."""
    if path.exists():
        shutil.rmtree(path)
    canvas = (0, 0, 1024, 1024)
    for part in ("bun", "lock"):
        defs, body = mono("#FFFFFF", parts=part)
        write(path / "Assets" / f"{part}.svg", svg_doc(canvas, body, defs))

    gradient = lambda top, bottom: {  # noqa: E731
        "linear-gradient": [p3(top), p3(bottom)],
        "orientation": {"start": {"x": 0.5, "y": 0}, "stop": {"x": 0.5, "y": 1}},
    }

    def layer(name: str, light: str, dark: str) -> dict:
        return {
            "image-name": f"{name}.svg",
            "name": name,
            "fill-specializations": [
                {"value": {"solid": p3(light)}},
                {"appearance": "dark", "value": {"solid": p3(dark)}},
            ],
        }

    def group(name: str, light: str, dark: str) -> dict:
        return {
            "layers": [layer(name, light, dark)],
            "shadow": {"kind": "neutral", "opacity": 0.5},
            "translucency": {"enabled": True, "value": 0.3},
            "specular": True,
        }

    write_json(path / "icon.json", {
        "fill-specializations": [
            {"value": gradient(TEAL_TOP, TEAL_DEEP)},
            {"appearance": "dark", "value": gradient("#123A37", NIGHT)},
        ],
        # First group is front-most.
        "groups": [
            group("lock", "#FFFFFF", TEAL_BRIGHT),
            group("bun", CREAM, CREAM),
        ],
        "supported-platforms": {"squares": ["iOS", "macOS"]},
    })


def rsvg(src: Path, dst: Path, width: int, fmt: str = "png") -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rsvg-convert", "-f", fmt, "-w", str(width), "-o", str(dst), str(src)],
                   check=True)


def main() -> None:
    svg_dir = BRAND / "svg"
    if svg_dir.exists():
        shutil.rmtree(svg_dir)

    mark_vb, glyph_vb = offset(MARK_VIEWBOX), offset(GLYPH_VIEWBOX)
    masters = {
        "baobuddy-mark.svg": doc(mark_vb, full_colour(outline=True)),
        "baobuddy-mark-on-dark.svg": doc(mark_vb, full_colour(TEAL_BRIGHT)),
        "baobuddy-mark-teal.svg": doc(mark_vb, mono(TEAL)),
        "baobuddy-mark-white.svg": doc(mark_vb, mono("#FFFFFF")),
        "baobuddy-mark-ink.svg": doc(mark_vb, mono(INK)),
        "baobuddy-glyph.svg": doc(glyph_vb, mono("#000000", GLYPH)),
        "baobuddy-glyph-unlocked.svg": doc(glyph_vb, mono("#000000", GLYPH, True)),
        "baobuddy-app-icon.svg": flat_icon(corner=True),
        "baobuddy-app-icon-square.svg": flat_icon(),
        "baobuddy-social.svg": social_card(),
    }
    for name, text in masters.items():
        write(svg_dir / name, text)

    # Xcode asset catalogs (vector, template where the system should tint).
    app_assets = ROOT / "BaoBuddy" / "Assets.xcassets"
    imageset(app_assets / "BaoBuddyMark.imageset",
             doc(mark_vb, (mono("#000000"))), template=True)
    widget_assets = ROOT / "BaoBuddyLiveActivity" / "Assets.xcassets"
    write_json(widget_assets / "Contents.json", {"info": {"author": "xcode", "version": 1}})
    # Glyphs carry a tab-bar-sized intrinsic size (24pt tall), since UIKit bars don't resize images.
    glyph_size = (round(24 * GLYPH_VIEWBOX[2] / GLYPH_VIEWBOX[3]), 24)
    for assets in (app_assets, widget_assets):
        for asset, unlocked in (("BaoBuddyGlyph", False), ("BaoBuddyGlyphUnlocked", True)):
            defs, body = mono("#000000", GLYPH, unlocked)
            imageset(assets / f"{asset}.imageset", svg_doc(glyph_vb, body, defs, glyph_size),
                     template=True)

    app_icon(ROOT / "BaoBuddy" / "AppIcon.icon")

    if shutil.which("rsvg-convert") is None:
        print("rsvg-convert not found (brew install librsvg); skipped PNG and PDF exports")
        return

    png = BRAND / "png"
    if png.exists():
        shutil.rmtree(png)
    rsvg(svg_dir / "baobuddy-app-icon.svg", png / "baobuddy-app-icon-1024.png", 1024)
    rsvg(svg_dir / "baobuddy-app-icon.svg", png / "baobuddy-app-icon-256.png", 256)
    rsvg(svg_dir / "baobuddy-mark.svg", png / "baobuddy-mark-512.png", 512)
    rsvg(svg_dir / "baobuddy-mark-on-dark.svg", png / "baobuddy-mark-on-dark-512.png", 512)
    rsvg(svg_dir / "baobuddy-mark-teal.svg", png / "baobuddy-mark-teal-512.png", 512)
    rsvg(svg_dir / "baobuddy-mark-white.svg", png / "baobuddy-mark-white-512.png", 512)
    rsvg(svg_dir / "baobuddy-social.svg", png / "baobuddy-social-1280x640.png", 1280)

    # macOS menu bar: @1x/@2x PNG template images, 18pt tall.
    # (Cairo's PDF export emits luminance SMasks that macOS CGPDF drops when drawing
    # template images, so PNG alpha masks are used instead.)
    for old_pdf in (ROOT / "MacHelper").glob("MenuBarGlyph*.pdf"):
        old_pdf.unlink()
    bar_w_1x = round(18 * GLYPH_VIEWBOX[2] / GLYPH_VIEWBOX[3])
    for name in ("baobuddy-glyph", "baobuddy-glyph-unlocked"):
        out = "MenuBarGlyph" + ("Unlocked" if name.endswith("unlocked") else "")
        rsvg(svg_dir / f"{name}.svg", ROOT / "MacHelper" / f"{out}.png", bar_w_1x, "png")
        rsvg(svg_dir / f"{name}.svg", ROOT / "MacHelper" / f"{out}@2x.png", bar_w_1x * 2, "png")
    print("Brand assets regenerated.")


if __name__ == "__main__":
    main()
