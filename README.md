# Carapace

<p align="center">
<img src="images/Carapace_logo.png" width="400" alt="Carapace" border-radius=50%>
</p>

Safe HTML/CSS/JS renderer for security researchers. Carapace fetches a URL, sanitises the page, analyses the JavaScript, and renders it to a PNG — with all outbound network requests intercepted and blocked. A threat report is produced alongside every render.

---

## How it works

1. **Fetch** — A hardened Rust HTTP client (reqwest with HTTP/2 support) fetches the URL with SSRF protection and decompression-bomb limits.
2. **Parse & sanitise** — The HTML is parsed and scrubbed: `<script>` tags, event handlers, `javascript:` URIs, and `data:` URLs are stripped before the page reaches the browser.
3. **Static JS analysis** — All collected script content is walked with an AST analyser before removal. Detects eval, obfuscation, exfiltration calls, DOM sinks, and sandbox evasion probes.
4. **JS sandbox** — For framework-driven pages (React, Vue, Angular, etc.), scripts are executed in an isolated rquickjs runtime. Network APIs are shimmed to log and block all outbound calls.
5. **Inline resources** — External stylesheets and images are fetched and inlined as data URIs. External `url()` references in CSS are blocked.
6. **Render** — A self-contained HTML file is handed to Chromium headless with **JavaScript enabled** and all network requests routed through a local logging proxy. The proxy records every URL the page attempts to reach and immediately rejects the connection — no data leaves the machine. This allows dynamic overlays (ClickFix, SocGholish, ClearFake, drainers) to render and be visible in the screenshot.
7. **Threat report** — All findings from static analysis, the JS sandbox, the CSS overlay detector, and the network intercept log are collected into a JSON report alongside the screenshot.

---

## Security model

- All outbound connections from Chromium are routed through a local logging proxy that immediately rejects every connection — no data ever leaves the machine
- The proxy records every URL Chromium attempted to reach at runtime; these appear as `INTERCEPTED_REQUEST` findings in the threat report
- `--disable-blink-features=AutomationControlled` suppresses the `navigator.webdriver` flag so evasive scripts execute their actual attack path rather than a clean scanner path
- `--virtual-time-budget=3000` allows JS timers up to 3 seconds to fire before the screenshot is taken, catching attacks that delay their overlay to evade scanners
- Remote fonts are blocked (`--disable-remote-fonts`)
- CSS `@import`, external `url()`, and `@font-face` are stripped before injection into the browser
- The HTML sanitiser removes every `on*` attribute, `<script>`, `<iframe>`, `<object>`, `<embed>`, and `<form>` before the page is handed to Chromium
- SSRF protection blocks private, loopback, and link-local IP ranges at both URL-validation and DNS-resolution time
- The rquickjs JS sandbox shims `fetch`, `XMLHttpRequest`, and `WebSocket` — all network calls are logged and blocked
- Docker: runs as a non-root user (uid 1000), all Linux capabilities dropped
- `wkhtmltoimage` fallback uses `--disable-javascript`

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
curl -s -X POST http://localhost:8080/render -H "Content-Type: application/json" -H "X-API-Key: s3cr3t" \
  -d '{"url":"https://example.com","format":"png"}' | jq -r .output | base64 -d > render.png
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
  "scanned_at": "2026-04-18T09:00:00Z",
  "risk_score": 0,
  "framework_detected": "Unknown",
  "tech_stack": [],
  "flags": [],
  "blocked_network": [],
  "js_flags": [],
  "html_flags": [],
  "drive_by_downloads": []
}
```

**Risk score** is 0–100. Flags from static JS analysis, HTML sanitisation, CSS overlay detection, runtime network interception, and drive-by download detection all contribute to the score.

**`blocked_network`** is a list of URLs that JavaScript attempted to reach at runtime. All were rejected by the logging proxy — nothing was fetched.

### Flag codes

| Code | Source | Description |
|------|--------|-------------|
| `JS_EVAL_DETECTED` | Static / runtime | `eval()` call detected |
| `JS_FUNCTION_CONSTRUCTOR` | Static / runtime | `new Function(args)` — dynamic code generation (zero-arg form suppressed) |
| `BASE64_OBFUSCATION` | Static | `atob()` decoding a string literal; decoded value in evidence |
| `HEX_OBFUSCATION` | Static | High-density `\xNN` hex escape sequences |
| `INNER_HTML_MUTATION` | Static | Assignment to `innerHTML` / `outerHTML` / `insertAdjacentHTML` |
| `WEBSOCKET_ATTEMPT` | Static | `new WebSocket()` constructor |
| `TIMER_STRING_EXEC` | Static | `setTimeout`/`setInterval` called with a string argument |
| `REDIRECT_ATTEMPT` | Static | Assignment to `window.location` or similar |
| `DOCUMENT_WRITE` | Static | `document.write()` call |
| `COOKIE_ACCESS` | Static | Write to `document.cookie` |
| `CSS_OVERLAY_INJECTED` | CSS analyser | Fullscreen `position:fixed` overlay — ClickFix / SocGholish structural signature |
| `INTERCEPTED_REQUEST` | Runtime | URLs JavaScript attempted to fetch at runtime (all blocked); list in evidence |
| `DRIVE_BY_DOWNLOAD` | Fetcher | Automatic file download intercepted (executables/archives only; CSS/fonts/images suppressed) |
| `SANDBOX_EVASION_WEBDRIVER` | Static | `navigator.webdriver` read — anti-analysis probe |
| `SANDBOX_EVASION_HEADLESS_STRING` | Static | Headless browser identifier string (`HeadlessChrome`, `PhantomJS`, `$cdc_`) |
| `SANDBOX_EVASION_SCREEN_PROBE` | Static | `window.outerHeight`/`outerWidth` read — headless detection |
| `SANDBOX_EVASION_PLUGINS_PROBE` | Static | `navigator.plugins` read — headless detection |
| `SANDBOX_EVASION_CHROME_RUNTIME` | Static | `window.chrome` / `chrome.runtime` read — automation detection |
| `SANDBOX_EVASION_FOCUS_PROBE` | Static | `document.hasFocus()` call — headless detection |
| `EVENT_HANDLER_STRIPPED` | HTML sanitiser | Inline `on*` event handler removed |
| `META_REDIRECT_STRIPPED` | HTML sanitiser | `<meta http-equiv="refresh">` redirect removed |

---

## Tech stack detection

Carapace detects the technology stack from the pre-sanitisation DOM — before the sanitiser strips custom elements and framework-specific attributes. Detected technologies are included in the threat report under `tech_stack`.

Detection covers: React, Vue, Angular, Svelte, Next.js, Nuxt, HTMX, Alpine.js, Livewire, Tailwind CSS, Bootstrap, Bulma, shadcn/ui, WordPress, Drupal, Joomla, Shopify, Magento, Wix, Squarespace, jQuery, Lodash, Moment.js, Axios, Socket.io, and more.

---

## Renderer fallback

The primary render path is Chromium headless with JavaScript enabled and a logging network proxy. If Chromium is not available, Carapace falls back to `wkhtmltoimage` with JavaScript disabled.

Pass `--no-browser` to force the built-in Rust renderer (tiny-skia + taffy layout engine). The Rust renderer is approximate — it handles basic CSS box model, flexbox, and inline text but does not support all CSS features. Use it only when no headless browser is available.
