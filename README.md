# Carapace

<img src="images/Carapace.png" width="400" alt="Carapace">

Safe HTML/CSS/JS renderer for security researchers. Carapace fetches a URL, sanitises the page, and renders it to a PNG — without executing JavaScript, loading external resources, or making any network requests from the browser. A threat report is produced alongside every render.

---

## How it works

1. **Fetch** — A hardened Rust HTTP client fetches the URL with SSRF protection and decompression-bomb limits.
2. **Parse & sanitise** — The HTML is parsed and scrubbed: `<script>` tags, event handlers, `javascript:` URIs, and `data:` URLs are stripped.
3. **Static JS analysis** — Script content is analysed with an AST walker before removal. Detects eval, obfuscation, exfiltration calls, DOM sinks, and sandbox evasion probes.
4. **Inline resources** — External stylesheets and images are fetched and inlined as data URIs. External `url()` references in CSS are blocked.
5. **Render** — A self-contained HTML file (no external dependencies) is handed to Chromium headless with JavaScript disabled and a network kill-switch (`--proxy-server=socks5://127.0.0.1:1`). The browser makes zero network requests.
6. **Threat report** — All findings are collected into a JSON report written alongside the output.

---

## Security model

- JavaScript is fully disabled in Chromium (`--disable-javascript`)
- All outbound HTTP/HTTPS requests from the browser are killed via a dead SOCKS5 proxy
- Remote fonts are blocked (`--disable-remote-fonts`)
- CSS `@import`, external `url()`, and `@font-face` are stripped before injection
- The HTML sanitiser removes every `on*` attribute, `<script>`, `<iframe>`, `<object>`, `<embed>`, and `<form>`
- SSRF protection blocks private, loopback, and link-local IP ranges at both URL-validation and DNS-resolution time
- Docker: runs as a non-root user (uid 1000), all Linux capabilities dropped

---

## Quick start

### Docker (recommended)

Build once:
```bash
docker build -t carapace:latest .
```

Render a URL to PNG:
```bash
docker run --rm --cap-drop=ALL --security-opt no-new-privileges:true -v "/tmp:/output" carapace:latest render https://example.com -o /output/render.png
```

Threat report only (no image):
```bash
docker run --rm --cap-drop=ALL --security-opt no-new-privileges:true -v "/tmp:/output" carapace:latest render https://example.com --output-format json -o /output/report.json
```

Start the HTTP API server:
```bash
docker run --rm --cap-drop=ALL --security-opt no-new-privileges:true -e CARAPACE_API_KEY=s3cr3t -p 8080:8080 carapace:latest serve --port 8080
```

### Native (development)

```bash
cargo build --release
./target/release/carapace render https://example.com -o output.png
./target/release/carapace render https://example.com --output-format json -o report.json
./target/release/carapace serve --port 8080
```

---

## CLI reference

### `render`

```
carapace render <URL> -o <FILE> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output <FILE>` | required | Output file path |
| `--output-format <FORMAT>` | `png` | `png` or `json` |
| `--width <PX>` | `1280` | Viewport width in pixels |
| `--height <PX>` | `800` | Viewport height in pixels |
| `--timeout <SECS>` | `30` | Request timeout |
| `--max-size <SIZE>` | `10MB` | Max response size (`5MB`, `500KB`, etc.) |
| `--max-redirects <N>` | `5` | Max redirect hops |
| `--https-only` | off | Reject plain HTTP URLs |
| `--no-assets` | off | Skip fetching images and stylesheets |
| `--no-browser` | off | Use the built-in Rust renderer instead of Chromium |
| `--no-js-sandbox` | off | Skip the rquickjs runtime (static analysis only) |
| `--threat-report` | on | Write `<output>.threat.json` alongside the render |
| `-v, --verbose` | off | Enable debug logging |

### `serve`

```
carapace serve [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port <PORT>` | `8080` | Port to listen on |
| `--host <HOST>` | `0.0.0.0` | Bind address |
| `--api-key <KEY>` | none | Require `X-API-Key` header (also `CARAPACE_API_KEY` env var) |
| `--max-concurrent <N>` | `4` | Max parallel render jobs |
| `--https-only` | off | Reject plain HTTP URLs submitted to the API |
| `--timeout <SECS>` | `30` | Per-request fetch timeout |

---

## HTTP API

### `GET /health`

```bash
curl http://localhost:8080/health
```
```json
{ "status": "ok", "version": "0.1.0" }
```

### `POST /render`

```bash
curl -s -X POST http://localhost:8080/render -H "Content-Type: application/json" -H "X-API-Key: s3cr3t" -d '{"url":"https://example.com","format":"png"}' | jq -r .output | base64 -d > render.png
```

**Request body:**

```json
{
  "url": "https://example.com",
  "format": "png",
  "width": 1280,
  "height": 800,
  "no_assets": false,
  "no_browser": false,
  "no_js_sandbox": false,
  "max_size": null
}
```

**Response:**

```json
{
  "url": "https://example.com",
  "format": "png",
  "output": "<base64-encoded PNG>",
  "content_type": "image/png",
  "threat_report": { ... }
}
```

`output` is `null` when `format` is `"json"` — the threat report is the entire response in that case.

---

## Threat report

Every render produces a threat report. When using the CLI it is written to `<output>.threat.json`. Via the API it is returned inline as `threat_report`.

```json
{
  "url": "https://example.com",
  "scanned_at": "2026-04-11T14:34:11Z",
  "risk_score": 0,
  "framework_detected": "Unknown",
  "tech_stack": [],
  "flags": [],
  "js_flags": [],
  "html_flags": [],
  "drive_by_downloads": []
}
```

**Risk score** is 0–100. Flags from the HTML sanitiser, JS static analysis, and drive-by download detection all contribute to the score.

**JS flags detected:** `eval` calls, `Function()` constructor, `document.write`, dangerous DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`), base64/hex obfuscation, exfiltration (`fetch`, `XMLHttpRequest`, `WebSocket`), cookie writes, `postMessage`, redirect attempts, and sandbox evasion probes (`navigator.webdriver`, screen dimension checks, plugin enumeration, headless string markers).

---

## Tech stack detection

Carapace detects the technology stack from the pre-sanitisation DOM — before the sanitiser strips custom elements and framework-specific attributes. Detected technologies are included in the threat report under `tech_stack`.

Detection covers: React, Vue, Angular, Svelte, Next.js, Nuxt, HTMX, Alpine.js, Livewire, Tailwind CSS, Bootstrap, Bulma, shadcn/ui, WordPress, Drupal, Joomla, Shopify, Magento, Wix, Squarespace, jQuery, Lodash, Moment.js, Axios, Socket.io, and more.

---

## Renderer fallback

The primary render path is Chromium headless. If Chromium is not available, Carapace falls back to `wkhtmltoimage`. Both are invoked with JavaScript disabled.

Pass `--no-browser` to force the built-in Rust renderer (tiny-skia + taffy layout engine). The Rust renderer is approximate — it handles basic CSS box model, flexbox, and inline text but does not support all CSS features. Use it only when no headless browser is available.
