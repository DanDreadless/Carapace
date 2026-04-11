# Carapace — CLAUDE.md

## Project Overview
Carapace is a safe HTML/CSS/JS renderer built in Rust for security researchers.
It fetches a URL and renders it to PNG/PDF without executing malicious code.
The primary render path uses Chromium headless with JS disabled and a network
kill-switch; a built-in Rust renderer is available as a fallback (`--no-browser`).

**Native (development)**
```bash
cargo build --release

# Render subcommand
./target/release/carapace render https://example.com -o output.png
./target/release/carapace render https://example.com --output-format pdf -o output.pdf
./target/release/carapace render https://example.com --output-format json -o report.json
./target/release/carapace render https://example.com --no-browser -o output.png

# Serve subcommand (HTTP API)
./target/release/carapace serve --port 8080
CARAPACE_API_KEY=s3cr3t ./target/release/carapace serve --port 8080
```

**Docker (recommended for production / malicious-site analysis)**
```bash
docker build -t carapace:latest .

# Render (one-shot)
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    render https://example.com -o /output/render.png

# API server (long-running)
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -e CARAPACE_API_KEY=s3cr3t \
    -p 8080:8080 \
    carapace:latest \
    serve --port 8080
```

## Rust Coding Standards
- Use `thiserror` for library errors; `anyhow` only in `main.rs`
- All public APIs return `Result<T, CarapaceError>` from `crate::error`
- Prefer `async fn` with `tokio`; never block in async context (`spawn_blocking` when needed)
- Use `#[must_use]` on functions whose results should not be discarded
- No `unwrap()`/`expect()` outside unit tests — always propagate with `?`
- Use `tracing::{info, warn, error, debug, span}` for all diagnostics
- Security-critical paths (SSRF, sanitizer, JS interception) require unit tests
- `cargo clippy -- -D warnings` must be clean before merging
- Keep modules single-concern; prefer many small files over large ones
- Document public structs/fns with `///`; skip obvious internals

## Module Structure
```
src/
  main.rs          — Binary entry point, wires CLI → pipeline
  lib.rs           — Library root; pipeline orchestration + drive-by download detection
  error.rs         — CarapaceError enum + Result alias
  cli.rs           — Clap derive structs (Args, OutputFormat, --no-browser flag)
  fetcher/
    mod.rs         — SafeFetcher; fetch + SSRF validation + size limiting
    ssrf.rs        — IP-range checks, blocked-scheme list
  html/
    mod.rs         — HtmlProcessor; parse → sanitize → output; rcdom_to_snapshot
    sanitizer.rs   — DOM walker; strips scripts, on*, javascript:, data:
    inliner.rs     — HtmlInliner; removes <link>, inlines CSS + images, serializes DOM
  js/
    mod.rs         — JsProcessor; static-analysis + runtime dispatch
    analysis.rs    — oxc_parser AST walker; extracts DOM mutations, fetches, obfuscation
    runtime.rs     — rquickjs sandbox setup + execution loop
    vdom.rs        — Virtual DOM state + JS-facing API stubs
  css/
    mod.rs         — CssProcessor; parse, var resolution, sanitize_css_for_browser
  layout/
    mod.rs         — LayoutEngine; taffy flexbox/grid + full CSS box model
  renderer/
    mod.rs         — Renderer; tiny-skia → PNG, lopdf → PDF, SVG via resvg
    backend.rs     — Headless browser dispatch (Chromium → wkhtmltoimage fallback)
  api/
    mod.rs         — axum router, AppState, serve() entry point
    handlers.rs    — RenderRequest/RenderResponse types, render + health handlers
  threat/
    mod.rs         — ThreatReport; flag dedup, volume scoring, drive-by detection
```

## Documentation Index
| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, data flow, module interactions |
| [HTTP API](docs/api.md) | API endpoints, request/response schema, Insight integration |
| [Docker Deployment](docs/docker.md) | Container build, security flags, production usage |
| [HTTP Fetcher](docs/http-fetcher.md) | SSRF protection, DNS validation, decompression limits |
| [HTML Sanitizer](docs/html-sanitizer.md) | Blocked tags, attributes, URL schemes, bypass research |
| [JS Runtime](docs/js-runtime.md) | rquickjs sandbox, execution model, intercepted globals |
| [Virtual DOM](docs/virtual-dom.md) | JS-visible API surface, intercepted calls, state extraction |
| [CSS Processing](docs/css-processing.md) | SCSS, Less sandboxing, Tailwind class extraction |
| [Threat Report](docs/threat-report.md) | Output schema, flag taxonomy, JSON structure |
| [Rendering](docs/rendering.md) | Layout pipeline, font loading, PNG/PDF output |

## Workflow Notes
- Update the relevant doc whenever a module's behaviour changes
- When adding a new module, create its doc and add a row to this index
- Threat report schema changes must be reflected in `docs/threat-report.md`
- New blocked patterns (sanitizer, SSRF) must include a regression test
