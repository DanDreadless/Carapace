# Rendering Pipeline

## Overview
After layout is computed by `taffy`, `src/renderer/mod.rs` rasterises the
node tree to PNG via `tiny-skia`, or generates a PDF via `lopdf`.

## Font Handling
1. `fontdb::Database` is populated from system fonts + any bundled fallback fonts.
2. For each text node, `rustybuzz` performs Unicode-aware text shaping (GSUB/GPOS).
3. Glyph outlines are loaded via `ab_glyph` and rasterised into the skia pixmap.
4. Fallback chain: requested font → system sans-serif → bundled Noto Sans.

## Layout (`layout/mod.rs`)
- Builds a `taffy::TaffyTree` from the `DomSnapshot`.
- CSS `display`, `flex-*`, `grid-*`, `width`, `height`, `margin`, `padding` are mapped.
- Taffy computes absolute positions for every node.
- Output: `LayoutTree` — same node IDs as VDom, each annotated with `Rect { x, y, w, h }`.

## PNG Output (`renderer/mod.rs`)
1. Allocate `tiny_skia::Pixmap` at viewport size (default 1280×800).
2. Fill background (`white` default).
3. Walk `LayoutTree` in document order (back-to-front):
   - Paint background color / background image.
   - Paint borders (solid only for now).
   - Paint text via rustybuzz + ab_glyph glyph rendering.
   - Paint `<img>` via decoded `image::DynamicImage` scaled to layout rect.
4. Encode pixmap as PNG via `tiny_skia::Pixmap::encode_png()`.

## PDF Output
1. Build a `lopdf::Document`.
2. For each page (1280pt wide, variable height for full-page capture):
   - Walk layout tree, emit PDF drawing operators.
   - Embed fonts as Type3 or use standard PDF fonts for Latin.
3. Compress with `lopdf`'s built-in Flate filter.

## JSON DOM Output
When `--output-format json`, the annotated `DomSnapshot` + `LayoutTree` +
`ThreatReport` are merged and serialised as a single JSON document.
This is the primary output format for programmatic analysis.

## Viewport / Capture Modes
| Mode | Behaviour |
|------|-----------|
| Default | 1280×800 viewport, crops at fold |
| `--full-page` | Expands height to fit entire layout tree |
| `--width N` | Custom viewport width |

## Known Limitations (TODO)
- CSS `position: fixed/sticky` not yet handled by taffy integration.
- `border-radius`, `box-shadow`, gradients not yet rendered.
- `<video>` elements render as grey placeholder.
- Right-to-left / BiDi text shaping needs additional rustybuzz configuration.
- `@font-face` remote font fetching not yet wired to SafeFetcher.
