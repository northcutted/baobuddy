# BaoBuddy brand

<img src="png/baobuddy-app-icon-256.png" width="128" alt="BaoBuddy app icon">

One happy bao with a padlock. The mark is flat and built from a few solid
shapes, so it holds up as a single colour, at 16 pt, and under Liquid Glass.

## Source of truth

Don't edit generated files by hand. Change the geometry or palette in
[`generate.py`](generate.py), then run:

```sh
make brand        # needs python3 and rsvg-convert (brew install librsvg)
```

The script rewrites every asset below. Commit the outputs with the script.

| Output | Used for |
| --- | --- |
| `BaoBuddy/AppIcon.icon` | iOS and macOS app icon (Icon Composer, Liquid Glass). Xcode renders the iOS 18 fallback; `make build-mac` compiles it for the helper. |
| `BaoBuddy/Assets.xcassets/BaoBuddyMark` | In-app mark, template image. `BaoBuddyEmblem` puts it on a tinted tile. |
| `…/BaoBuddyGlyph`, `BaoBuddyGlyphUnlocked` | Small sizes: tab bar, Dynamic Island, Live Activity. Template images. |
| `MacHelper/MenuBarGlyph*.png` | macOS menu bar (template PNGs `@1x`/`@2x`, idle and active). |
| `Branding/svg/` | Master vectors for README, web, slides. |
| `Branding/png/` | Raster exports, including a 1280 × 640 GitHub social preview. |

## The mark

| File | Use on |
| --- | --- |
| `baobuddy-mark.svg` | Light surfaces, full colour (tan outline keeps the cream bun visible). |
| `baobuddy-mark-on-dark.svg` | Dark surfaces, full colour. |
| `baobuddy-mark-teal.svg` | Light surfaces, one colour. |
| `baobuddy-mark-white.svg` | Teal, photos, or dark surfaces, one colour. |
| `baobuddy-mark-ink.svg` | Print or monochrome documents. |
| `baobuddy-glyph.svg` | 14–28 pt. Bolder pleats, a larger face and a wider gap around the padlock. |
| `baobuddy-glyph-unlocked.svg` | Same glyph with the shackle open. Means "a grant is active". |
| `baobuddy-app-icon.svg` | Flat icon tile for places that can't show the real icon. |

Rules:

- Use the glyph below 32 pt and the mark above it.
- Keep clear space of at least the padlock's width on every side.
- The face, pleats and padlock gap are cut-outs. Don't fill them with
  another colour; let the background show through.
- Keep the pleats, even on the glyph: they are what makes the shape read as a bao.
- Don't rotate, outline, add shadows, or redraw the face. Expressions other
  than the smile are not part of the brand.
- Locked means idle or protected. Unlocked means a grant is live. Don't use the
  unlocked glyph for anything else.

## Colour

| Token | Hex | Role |
| --- | --- | --- |
| Bao Teal | `#0F766E` | Primary. `AccentColor` in light mode, buttons, one-colour mark. |
| Bao Teal Bright | `#14B8A6` | `AccentColor` in dark mode, Live Activity tint. |
| Icon gradient | `#1AA99A` → `#0A5650` | App icon background, flat icon tile. |
| Steam Cream | `#FFF6E5` | The bun. `BaoTheme.cream`. |
| Pleat Tan | `#E8CB9C` | Folds and outline on the full-colour mark. |
| Soy Ink | `#1E293B` | Face, text on cream. `BaoTheme.ink`. |
| Blush | `#F6AE9F` | Cheeks, full-colour mark only. |
| Elevated | system orange | Elevated scopes only. Never part of the logo itself. |

In SwiftUI use `BaoTheme` tokens and system colours. Don't hard-code hex
values in views.

## In the app

- `BaoBuddyEmblem(tint:size:)` is the app icon in miniature: a continuous-corner
  tile filled with `tint` and the cream mark. Pass `BaoTheme.elevated` for
  elevated grants so the whole tile turns orange.
- Tab bar and toolbar items use `Image("BaoBuddyGlyph")`. It is a template
  image, so the system tints it like an SF Symbol.
- Typography is the system font. For a wordmark next to the mark, use
  `Text("BaoBuddy").font(.title.weight(.semibold))`. There is no custom
  typeface, so the brand follows Dynamic Type and the platform's type scale.

## App icon

`AppIcon.icon` has two layers on a teal gradient: the bun (face and pleats
cut out) and the padlock in front. Icon Composer supplies the glass, shadow
and specular highlight, and the system derives the dark, tinted and clear
appearances. Dark mode uses a near-black teal background, cream bun and
bright-teal padlock.

To preview every appearance:

```sh
ICTOOL="/Applications/Xcode.app/Contents/Applications/Icon Composer.app/Contents/Executables/ictool"
for r in Default Dark TintedLight TintedDark ClearLight ClearDark; do
  "$ICTOOL" BaoBuddy/AppIcon.icon --export-image --output-file "/tmp/icon-$r.png" \
    --platform iOS --rendition $r --width 1024 --height 1024 --scale 1
done
```

You can also open `AppIcon.icon` in Icon Composer to tune glass settings. If
you do, copy any changes back into `app_icon()` in `generate.py`, or the next
`make brand` overwrites them.
