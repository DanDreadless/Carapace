# Carapace — CLAUDE.md

## Project Overview
Carapace is a safe HTML/CSS/JS renderer built in Rust for security researchers.
It renders a URL in headless Chromium **with JavaScript enabled** — attacker code
runs, so the container is the trust boundary — behind an SSRF-enforcing policy
proxy (same-origin + vetted CDNs live; cross-origin refused and recorded). Live
render is over CDP when `CARAPACE_CDP=1` (Insight's setting); an offline render of
the sanitised page, `wkhtmltoimage`, and a built-in Rust renderer (`--no-browser`)
are the fallbacks. `/solve` gets past Cloudflare challenges and JS cloaking gates
and returns the served document + navigation chain. See README.md.

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
- `cargo +1.96 clippy --release --all-targets -- -D warnings` must be clean before merging (it is, as of 2026-10-08; the old debt was cleared behaviour-identically and verified by tests + `js_differential`).
- `Cargo.lock` is tracked (binary crate; the Dockerfile copies it). Dependency changes show up in review.
- **Toolchain:** Rust **1.96** (Dockerfile `rust:1.96-slim-bookworm`), the MSRV of oxc 0.152. Build locally with `cargo +1.96 …` until the host's stable reaches 1.96.
- **Parser / runtime upgrades (oxc, rquickjs, Rust) must prove no detection change.** Build `examples/js_differential.rs` at the old and new commit, run both over the same corpus (Insight's clean-snapshot scripts + inline scripts + `threat_fixtures` JS), and require byte-identical JSONL. Flags are sorted. The baseline is deterministic (verified identical across two runs), so any diff is real. The oxc 0.39 → 0.152 upgrade was verified this way on 1,994 scripts.
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
    analysis.rs    — oxc_parser AST walker (oxc 0.152; `Visit` lives in `oxc_ast_visit`); extracts DOM mutations, fetches, obfuscation
    runtime.rs     — rquickjs sandbox setup + execution loop
    sinks.rs       — sink index (/triage): dangerous ops, resolved args (oxc_semantic), enclosing-function spans
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
    triage.rs      — POST /triage (content-only, own semaphore) → js::sinks::index
  threat/
    mod.rs         — ThreatReport; flag dedup, volume scoring, drive-by detection
```

## Documentation
There is no `docs/` directory in this repo (the index that used to live here pointed
at files that were never committed). The references are:

| Document | Covers |
|----------|--------|
| [README.md](README.md) | How it works, security model, CLI, HTTP API (`/render`, `/analyse`, `/solve`), threat-report schema + flag codes, env vars, render ladder |
| Insight `docs/research-carapace-rendering-2026.md` | Live-navigation policy proxy, blank detection, CDP design |
| Insight `docs/research-carapace16-nav-capture-2026.md` | CDP `Fetch` nav capture (`nav_targets`) |
| Insight `docs/research-large-js-deobfuscation-2026.md` | Deobfuscation ladder (oxc folding, QuickJS sink capture) |
| Insight `docs/detection-engine.md` | How Insight consumes Carapace flags; JS-gate following via `/solve` |

## Workflow Notes
- Update README.md whenever an endpoint, flag, env var or threat-report field changes
- Threat report schema changes must be reflected in README.md's Threat report section
- New blocked patterns (sanitizer, SSRF) must include a regression test
