# CSS Processing

## Overview
`src/css/mod.rs` collects, fetches, and normalises all stylesheets referenced
by the page. No CSS is capable of executing code after this stage.

## Pipeline
1. Collect `<link rel="stylesheet">` URLs from sanitized DOM.
2. Collect `<style>` block contents.
3. Fetch linked sheets via `SafeFetcher` (same SSRF protection as HTML fetch).
4. Detect and compile SCSS (files ending `.scss` or containing SCSS syntax) via `grass`.
5. Strip dangerous CSS: `expression()`, `url(javascript:)`, `-moz-binding`, `@import` of non-HTTP.
6. Resolve `@import` chains (max depth 5 to prevent loops).
7. Build a flat map of `selector → { property: value }`.

## Dangerous Patterns Stripped
| Pattern | Reason |
|---------|--------|
| `expression(...)` | IE CSS expression execution |
| `url(javascript:...)` | JS URL in CSS |
| `url(data:text/html...)` | HTML injection via CSS |
| `-moz-binding` | XBL binding (Firefox legacy) |
| `behavior: url(...)` | IE HTC behavior files |
| `@import url(file://...)` | Local file read |

## SCSS Support
- `grass` crate compiles SCSS to plain CSS entirely in Rust.
- No subprocess, no Node.js.
- Compilation errors are logged and the sheet is skipped.

## Less Support
- Less requires JS execution. It is run inside the rquickjs sandbox
  with the same restrictions as framework JS (no network, no filesystem).
- The compiled CSS is extracted from the sandbox and treated as plain CSS.

## Tailwind Extraction
When Tailwind is detected (presence of `tailwind.config` reference or
utility class patterns), class names are extracted from the HTML and matched
against the Tailwind preset to produce a minimal stylesheet without fetching
the CDN script.

## Output
`ResolvedStyles`: a map from CSS selector string to a `HashMap<String, String>`
of property/value pairs. This feeds the layout engine.
