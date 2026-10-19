# Architecture

## Pipeline Overview

```
URL Input
   │
   ▼
┌─────────────────────────────────────────────────────────────┐
│  SafeFetcher (fetcher/)                                      │
│  - Scheme validation (http/https only)                      │
│  - SSRF / private-IP blocking                               │
│  - DNS resolution + rebinding check (per redirect hop)      │
│  - Decompression bomb limit                                 │
│  - Drive-by download detection (Content-Disposition +       │
│    executable MIME types) → SHA256 recorded, body discarded │
└───────────────────────────┬─────────────────────────────────┘
                            │ FetchResult { body, headers, url, content_type }
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  HtmlProcessor (html/)                                       │
│  - html5ever parse → RcDom                                  │
│  - Sanitizer DOM walk:                                      │
│      strip <script>, <iframe>, <object>, <embed>            │
│      strip on* attributes                                   │
│      strip javascript: / data: URLs                         │
│  - Collect <link rel=stylesheet>, <style>, <img src> refs   │
│  - Framework fingerprinting (React, Vue, Angular, …)        │
└───────────────────────────┬─────────────────────────────────┘
                            │ ProcessedHtml { dom, styles, framework }
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  JsProcessor (js/)                                           │
│  - Static analysis (oxc_parser AST walk):                   │
│      DOM mutations, fetch/XHR calls,                        │
│      eval/Function, base64/hex decode                       │
│  - Optional sandbox (rquickjs):                             │
│      Virtual DOM injection                                  │
│      Intercept window/document/fetch                        │
│      Run framework init code                                │
│      Extract post-render DOM snapshot                       │
└───────────────────────────┬─────────────────────────────────┘
                            │ ThreatFlags
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Sub-resource fetch (lib.rs)                                 │
│  - Fetch external stylesheets → raw CSS strings             │
│  - Fetch <img> URLs → raw bytes (keyed by src attr)         │
│  - Drive-by download check on each sub-resource             │
│  - Skipped if --no-assets                                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ css_sheets: Vec<String>
                            │ image_bytes: HashMap<src, Vec<u8>>
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  HtmlInliner (html/inliner.rs)                               │
│  - Strips <link rel=stylesheet> elements from DOM           │
│  - Sanitizes CSS via sanitize_css_for_browser():            │
│      removes @import, external url(), @font-face            │
│  - Injects sanitized CSS as <style> blocks in <head>        │
│  - Replaces <img src> with base64 data URIs                 │
│  - Serialises DOM to a fully self-contained HTML string     │
└───────────────────────────┬─────────────────────────────────┘
                            │ self-contained HTML (no external deps)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Browser Backend (renderer/backend.rs)              PRIMARY  │
│  - Writes HTML to /tmp/carapace_<pid>_<ts>.html             │
│  - Launches Chromium headless with:                         │
│      --disable-javascript                                   │
│      --proxy-server=socks5://127.0.0.1:1  (network kill)   │
│      --disable-remote-fonts                                 │
│      --no-sandbox (required in containers)                  │
│  - Falls back to wkhtmltoimage/wkhtmltopdf if absent        │
│  - Temp file always deleted after render                    │
└───────────────────────────┬─────────────────────────────────┘
                            │ PNG / PDF file
                            ▼        (or --no-browser flag)
┌─────────────────────────────────────────────────────────────┐
│  Rust Renderer (renderer/mod.rs)                  FALLBACK   │
│  - CssProcessor: parse rules, resolve vars, match selectors │
│  - LayoutEngine: taffy flexbox/grid → LayoutTree            │
│  - tiny-skia rasterisation → PNG                            │
│  - lopdf document assembly → PDF                            │
│  - SVG rasterisation via resvg/usvg                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ThreatReport (threat/)                                      │
│  - Aggregates flags from all pipeline stages                │
│  - Deduplicates flags by code; applies volume bonus scoring │
│  - Outputs JSON report alongside rendered file              │
└─────────────────────────────────────────────────────────────┘
```

## Deployment

Carapace ships as a Docker image (see [Docker Deployment](docker.md)).
The container adds OS-level isolation on top of the in-process sandboxing:

```
┌─────────────────────────────────────────┐
│  Docker container (non-root, cap_drop)  │
│  ┌───────────────────────────────────┐  │
│  │  Carapace process                 │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Chromium (--no-sandbox)    │  │  │
│  │  │  JS disabled, proxy=dead    │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

A future HTTP API mode will wrap the same pipeline behind an `axum` server —
same container, same security model.

## Key Design Decisions

### Browser backend (primary render path)
Chromium headless is the primary renderer because it produces pixel-perfect
output matching what a real user would see. The self-contained HTML passed to
it has zero external dependencies, so Chromium makes no network requests.
The CSS network kill-switch (`--proxy-server=socks5://127.0.0.1:1`) and
`--disable-javascript` are belt-and-suspenders guarantees on top of that.

### Rust renderer (fallback)
The built-in Rust renderer (`--no-browser`) is a best-effort approximation
useful when Chromium and wkhtmltoimage are unavailable. It handles the CSS box
model, flexbox, images, and text, but will not match a real browser exactly.

### No real JS execution
All JavaScript is either:
1. Statically analysed (oxc_parser AST walk) — extracts mutations without running code
2. Run in the rquickjs sandbox with a virtual DOM — frameworks render into a fake tree

The real DOM / real network / real filesystem is never accessible from JS.

### SSRF-first fetch
DNS is resolved before the TCP connection is made. Each redirect hop is
independently validated. Raw IP literals are checked at parse time.

### HTML sanitizer allowlist
The HTML sanitizer uses an **element allowlist** (not a blocklist). Any tag not
explicitly permitted is stripped. This is safer than enumerating dangerous tags.

### Drive-by download detection
After every fetch (main URL and each sub-resource), Carapace inspects
`Content-Disposition` and the MIME type. If an auto-download is indicated, the
body is SHA256-hashed and the hash is recorded in the threat report. The body
is never written to disk.

### CSS network isolation
Raw CSS fetched from the target could contain `@import` or `url(https://...)`
that would cause Chromium to make outbound requests. `sanitize_css_for_browser`
strips all three vectors (`@import`, external `url()`, `@font-face`) before the
CSS is injected, and the Chromium proxy kill-switch provides a second layer.

## Crate Dependency Map

```
main.rs
  └── lib.rs
        ├── fetcher      → reqwest, rustls, url, tokio, hickory-resolver, sha2
        ├── html         → html5ever, markup5ever_rcdom, base64
        ├── js           → oxc_parser, oxc_ast, oxc_allocator, rquickjs
        ├── css          → cssparser, grass, regex
        ├── layout       → taffy
        ├── renderer     → tiny-skia, ab_glyph, fontdb, image, lopdf, resvg, usvg
        └── threat       → serde, serde_json, chrono
```

## Module Status

| Module | Status |
|--------|--------|
| fetcher | Complete (SSRF, redirect validation, drive-by detection) |
| html/sanitizer | Complete |
| html/inliner | Complete (CSS sanitization, image inlining, DOM serialization) |
| js/analysis | Complete scaffold |
| js/runtime | Complete scaffold |
| js/vdom | Complete scaffold |
| css | Complete (parse, vars, selectors, browser sanitization) |
| layout | Complete (flexbox, grid, full box model) |
| renderer | Complete (PNG, PDF, SVG, text, images) |
| renderer/backend | Complete (Chromium + wkhtmltoimage fallback) |
| threat | Complete (dedup, volume scoring, drive-by flags) |
