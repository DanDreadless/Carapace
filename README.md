# Carapace

<p align="center">
<img src="images/Carapace_logo.png" width="400" alt="Carapace" border-radius=50%>
</p>

Confined HTML/CSS/JS renderer for security researchers. Carapace loads a URL in headless Chromium **with JavaScript enabled** — so runtime-injected attacks (ClickFix, SocGholish, ClearFake, drainers) actually render — behind an SSRF-enforcing policy proxy: the page's own same-origin content loads live, and every cross-origin request (the C2 / exfiltration signal) is refused and recorded. A threat report is produced alongside every render. A `/solve` endpoint gets past Cloudflare challenges and JavaScript cloaking gates and returns the page the server actually served.

Carapace is the renderer behind [Insight](https://insight.vault1337.com/).

---

## How it works

1. **Fetch** — A hardened Rust HTTP client (reqwest with HTTP/2 support) fetches the URL with SSRF protection and decompression-bomb limits.
2. **Parse & sanitise** — The HTML is parsed and scrubbed: `<script>` tags, event handlers, `javascript:` URIs, and `data:` URLs are stripped before the page reaches the browser.
3. **Static JS analysis** — All collected script content is walked with an AST analyser (OXC) before removal. Detects eval, obfuscation, exfiltration calls, DOM sinks, clipboard hijacks, and sandbox evasion probes.
4. **JS sandbox** — For framework-driven pages (React, Vue, Angular, etc.), scripts are executed in an isolated rquickjs runtime. Network APIs are shimmed to log and block all outbound calls.
5. **Inline resources** — External stylesheets and images are fetched and inlined as data URIs. External `url()` references in CSS are blocked.
6. **Render (live)** — Chromium headless navigates the **real URL** with **JavaScript enabled** — driven over the Chrome DevTools Protocol through a pipe (`--remote-debugging-pipe`, no debug port a page could reach) when `CARAPACE_CDP` is on, otherwise via Chromium's CLI. All traffic goes through the **policy proxy**: the page's own host and a vetted CDN/font list are fetched live, with every resolved IP SSRF-checked; cross-origin requests are refused and recorded. A Windows identity is presented so OS-gated payloads execute, navigation is suppressed so the attack UI stays on screen, and the page settles on network-idle (floored so delayed overlays still inject) before the screenshot and post-JS DOM are captured.
7. **Navigation capture** (`CARAPACE_CDP_NAV_CAPTURE`) — Main-frame navigations are intercepted with CDP `Fetch` (Document only): the first is the validated page load and continues; every later one is a client-side redirect whose JS-computed destination is recorded and blocked, never dispatched. Destinations are returned as `nav_targets` for the caller to SSRF-validate and scan.
8. **Offline fallback** — If the live render fails or comes back blank, the self-contained sanitised HTML (steps 2–5) is rendered with a proxy that refuses every connection and a `fetch`/`XMLHttpRequest` mock, so data-driven pages still show something.
9. **Threat report** — All findings from static analysis, the JS sandbox, the CSS overlay detector, the post-render DOM diff, and the network intercept log are collected into a JSON report alongside the screenshot.
10. **Annotation** — A verdict badge is composited onto the bottom of every screenshot showing the domain, risk score, verdict label, and scan timestamp.

---

## Security model

Carapace **executes attacker JavaScript**, so the browser is treated as hostile and the container is the trust boundary:

- **Policy proxy** — every Chromium connection goes through it. Same-origin (the page's own host and subdomains) and a vetted read-only CDN/font list are forwarded; everything else is refused with a 503 and recorded (`INTERCEPTED_REQUEST`). The proxy resolves each host itself and rejects the connection if **any** resolved IP is private, loopback, link-local, metadata or CGNAT — which also defeats DNS rebinding. Forwarded connections are bounded in count, time and bytes.
- **Control channel** — CDP runs over `--remote-debugging-pipe`, never a TCP port, so the page cannot reach it. Event domains that an adversarial page could flood are kept off or drained with bounded queues.
- **Hard deadlines** — each browser runs in its own process group with a watchdog that `killpg`s it at the deadline; a hung or hostile page cannot outlive its budget.
- **Memory bounds** — one renderer process per page, a capped V8 heap, and `oom_score_adj=1000` so a runaway page loses its own browser rather than the server.
- **Isolation between renders** — a fresh browser process and private profile per render.
- `--disable-blink-features=AutomationControlled` suppresses the `navigator.webdriver` flag so evasive scripts execute their actual attack path rather than a clean scanner path
- On the offline path, `--virtual-time-budget=5000` lets JS timers up to 5 seconds fire before the screenshot, catching attacks that delay their overlay to evade scanners
- `--run-all-compositor-stages-before-draw` ensures layout, paint, and compositing complete before the PNG is captured, preventing partial blank renders
- Offline path only (the live render loads the real page through the policy proxy instead): remote fonts are blocked (`--disable-remote-fonts`); CSS `@import`, external `url()`, and `@font-face` are stripped; and the HTML sanitiser removes every `on*` attribute, `<script>`, `<iframe>`, `<object>`, `<embed>`, and `<form>` before the self-contained page is handed to Chromium
- SSRF protection blocks private, loopback, and link-local IP ranges at both URL-validation and DNS-resolution time
- The rquickjs JS sandbox shims `fetch`, `XMLHttpRequest`, and `WebSocket` — all network calls are logged and blocked
- Docker: runs as a non-root user (uid 1000), all Linux capabilities dropped. In production also run it with `--read-only` (tmpfs for `/tmp`, `/home/carapace`, `/output`), `--init` (reaps Chromium's child processes), bounded memory/CPU/PIDs, and on a network that cannot reach anything but the internet — Insight runs it inside a VPN namespace attached to a render-only network, with a host egress firewall dropping private ranges
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
| `--height <PX>` | `800` | Viewport height in pixels (0 = full-page capture) |
| `--mobile-screenshot` | off | Capture a second screenshot at 375×844 (iPhone viewport) alongside the desktop render |
| `--mobile-ua` | off | Use an iPhone/Safari User-Agent for the fetch and render — reveals pages that cloak content by User-Agent (blank to desktop, real phish to mobile) |
| `--android-ua` | off | Use an Android/Chrome User-Agent instead of iPhone; takes precedence over `--mobile-ua` |
| `--timeout <SECS>` | `30` | Request timeout |
| `--max-size <SIZE>` | `10MB` | Max response size (`5MB`, `500KB`, etc.) |
| `--max-redirects <N>` | `5` | Max redirect hops |
| `--block-private-ips` | on | Block requests to private/loopback/link-local IP ranges (SSRF protection) |
| `--https-only` | off | Reject plain HTTP URLs |
| `--no-assets` | off | Skip fetching sub-resources (images, stylesheets, fonts) |
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
| `--block-private-ips` | on | Block requests to private/loopback IP ranges in submitted URLs (SSRF protection) |
| `--https-only` | off | Reject plain HTTP URLs submitted to the API |
| `--timeout <SECS>` | `30` | Per-request fetch timeout |
| `-v, --verbose` | off | Enable debug logging |

---

## HTTP API

### `GET /health`

```bash
curl http://localhost:8080/health
```
```json
{ "status": "ok", "version": "0.2.3" }
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
  "mobile_screenshot": false,
  "mobile_ua": false,
  "android_ua": false,
  "max_size": null
}
```

**Response:**

```json
{
  "url": "https://example.com",
  "format": "png",
  "output": "<base64-encoded PNG>",
  "mobile_output": "<base64-encoded PNG, or null if mobile_screenshot was false>",
  "content_type": "image/png",
  "threat_report": { ... }
}
```

`output` is `null` when `format` is `"json"` — the threat report is the entire response in that case.

`mobile_output` is a second PNG captured at 375×844 (iPhone viewport). `null` unless `mobile_screenshot: true` was sent.

### `POST /analyse`

Runs OXC-based static JS analysis on a URL or raw content without Chromium. Use this for direct `.js` script URLs — feeding raw JS to `/render` causes Chromium to hang because async JS never resolves in a blank-page context.

```bash
curl -s -X POST http://localhost:8080/analyse -H "Content-Type: application/json" -H "X-API-Key: s3cr3t" \
  -d '{"url":"https://example.com/app.js"}' | jq .threat_report
```

**Request body:**

```json
{
  "url": "https://example.com/app.js",
  "content": null,
  "max_size": null,
  "source_name": null
}
```

Either `url` or `content` must be provided. `content` takes precedence if both are given. For files larger than 512 KB, analysis runs on overlapping 256 KB chunks (32 KB overlap) to catch patterns split at a boundary.

**Response:** same shape as `/render` with `output: null` and `mobile_output: null`; only `threat_report` is populated.

### `POST /solve`

Loads a URL in the confined browser, lets whatever gate stands in front of the content play out, and returns **the document the server actually served** plus the path the browser was sent down. Two uses:

- **Cloudflare bot challenges** that a plain or TLS-impersonating client cannot pass. The policy proxy additionally allows `challenges.cloudflare.com` (Turnstile); the User-Agent is Chromium's own with the `HeadlessChrome` token removed, set by flag so the Sec-CH-UA client hints stay native and consistent.
- **JavaScript cloaking gates** — a content-less page that re-requests itself with a proof-of-JS token, after which the server picks what to serve. No render bootstrap is injected, so the gate's own navigation fires. If the gate forwards off-site (a TDS doorway), the cross-origin hop is **recorded in `nav_chain` but not fetched** — the policy proxy still refuses it.

```bash
curl -s -X POST http://localhost:8080/solve -H "Content-Type: application/json" -H "X-API-Key: s3cr3t" \
  -d '{"url":"https://example.com/"}'
```

Request: `{"url": "https://..."}` — http(s) only (https-only when the server enforces it), a hostname rather than an IP literal, no credentials in the URL.

**Response:**

```json
{
  "solved": true,
  "challenge_absent": false,
  "clearance_source": "fresh",
  "final_url": "https://example.com/",
  "title": "Example",
  "cookie_names": ["cf_clearance"],
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) ... Chrome/151.0.0.0 Safari/537.36",
  "document": {
    "url": "https://example.com/",
    "status": 200,
    "headers": { "content-type": "text/html; charset=utf-8", "server": "cloudflare" },
    "body_b64": "<base64 raw response body>",
    "truncated": false
  },
  "nav_chain": ["https://example.com/", "https://example.com/?__cf_chl_tk=..."],
  "elapsed_ms": 3162,
  "intercepted": []
}
```

- `solved` — `cf_clearance` was issued **and** the "Just a moment…" interstitial is gone. `challenge_absent` — the page loaded without any challenge (or a JS gate was followed). An interactive Turnstile that cannot be passed returns both `false`, never an error.
- `document` — the last **main-frame** response the browser received (sub-frames such as the Turnstile iframe are ignored), captured over CDP `Network`: raw body (base64, capped at 5 MB) and headers. `null` if it could not be captured, and never returned for an uncleared interstitial.
- `nav_chain` — ordered main-frame navigations (≤10, http/https), server redirects included.
- `clearance_source` — `fresh`, `cached`, or `none`. Clearance cookies are cached **per host inside Carapace** (≤25 min) and fed back into the next solve's browser before it navigates, so a repeat request skips the challenge. **Clearance values never leave Carapace** — only `cookie_names` are returned. Returning the page rather than cookies also matters when the caller's egress IP differs from Carapace's: clearance is bound to the IP that solved it.
- The response is produced by a browser that has just run the target's JavaScript — callers must treat every field as untrusted input.

A solve holds a render slot and is capped at 25 seconds.

---

## Threat report

Every render produces a threat report. When using the CLI it is written to `<output>.threat.json`. Via the API it is returned inline as `threat_report`.

```json
{
  "url": "https://example.com",
  "timestamp": "2026-04-18T09:00:00Z",
  "framework_detected": "Unknown",
  "tech_stack": [],
  "risk_score": 0,
  "render_skipped": false,
  "render_blank": false,
  "blank_ratio": 0.0,
  "render_mode": "live",
  "rendered_html": "",
  "normalized_scripts": [],
  "decoded_payloads": [],
  "runtime_scripts": [],
  "nav_targets": [],
  "html_flags": [],
  "js_flags": [],
  "blocked_network": [],
  "flags": []
}
```

**Risk score** is 0–100. Flags from static JS analysis, HTML sanitisation, CSS overlay detection, post-render DOM diff, runtime network interception, drive-by download detection, QR-code (quishing) decoding, and Browser-in-the-Browser detection all contribute to the score.

**`blocked_network`** is a list of URLs that JavaScript attempted to reach at runtime. All were rejected by the logging proxy — nothing was fetched.

**`html_flags`** and **`js_flags`** are raw sanitiser/static-analysis flag lists (one entry per occurrence, not deduplicated). The deduplicated `flags` array is the primary findings list; `html_flags` and `js_flags` provide accurate per-code counts for volume scoring.

**`render_skipped`** is `true` when the content-type was not `text/html` — the HTML/render pipeline was bypassed and OXC JS analysis was run directly on the raw body (e.g. a `.js` URL submitted to `/analyse`).

**`render_mode`** records which strategy produced the delivered screenshot: `"live"` (navigated the real URL through the same-origin proxy), `"offline_fallback"` (live render failed or came back blank → offline self-contained render), or `"offline"` (live disabled). **`render_blank`** is `true` when the delivered screenshot is effectively all near-white pixels after the retry ladder was exhausted, and **`blank_ratio`** (0.0–1.0) is the near-white pixel fraction behind that decision.

**`rendered_html`** is the post-JS DOM of a successful live render (capped for transport), letting a caller re-run the analysers on what the browser actually rendered — essential for service-worker-gated content (IPFS `dweb.link`) and fully JS-rendered SPAs. **`normalized_scripts`** (Tier-0 deobfuscation: constants folded) and **`decoded_payloads`** (Tier-2: cleartext captured from `eval`/`Function`/`document.write` sinks while the script's own decoder ran) expose the resolved payload behind obfuscation.

**`nav_targets`** are main-frame redirect destinations captured (and blocked, never dispatched) on a live render — including JS-computed interstitial/TDS destinations no static analysis can resolve (≤10; enabled by `CARAPACE_CDP_NAV_CAPTURE`). The caller SSRF-validates them before following. **`runtime_scripts`** are bodies of scripts loaded at runtime via `fetch()+eval` or dynamic `import()` that never appear as `<script>` tags (enabled by `CARAPACE_CDP_CAPTURE`).

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `CARAPACE_API_KEY` | none | Same as `--api-key` |
| `CARAPACE_CDP` | off (Insight sets `1`) | Live render driven over CDP in one browser session. Off: the live render uses Chromium's CLI (`--screenshot` / `--dump-dom`) through the same policy proxy |
| `CARAPACE_CDP_NAV_CAPTURE` | off (Insight sets `1`) | Capture main-frame redirect destinations (`nav_targets`) via CDP `Fetch` interception. Requires `CARAPACE_CDP` |
| `CARAPACE_CDP_CAPTURE` | off | Capture runtime-loaded script bodies (`runtime_scripts`) via CDP `Network`. Requires `CARAPACE_CDP` |

Flags accept `1`, `true` or `on`. `/solve` always uses CDP, whatever these are set to.

### Flag codes

| Code | Source | Description |
|------|--------|-------------|
| `JS_EVAL_DETECTED` | Static / runtime | `eval()` call detected |
| `JS_FUNCTION_CONSTRUCTOR` | Static / runtime | `new Function("...")` — dynamic code generation with a string-literal body |
| `JS_FUNCTION_CONSTRUCTOR_DYNAMIC` | Static | `new Function(expr)` — body assembled at runtime from a variable; not statically readable |
| `BASE64_OBFUSCATION` | Static | `atob()` decoding a string literal; decoded value in evidence |
| `HEX_OBFUSCATION` | Static | High-density `\xNN` hex escape sequences |
| `INNER_HTML_MUTATION` | Static | Assignment to `innerHTML` / `outerHTML` / `insertAdjacentHTML` |
| `WEBSOCKET_ATTEMPT` | Static | `new WebSocket()` constructor |
| `TIMER_STRING_EXEC` | Static | `setTimeout`/`setInterval` called with a string argument |
| `REDIRECT_ATTEMPT` | Static | Assignment to `window.location` or similar |
| `DOCUMENT_WRITE` | Static | `document.write()` call |
| `COOKIE_ACCESS` | Static | Write to `document.cookie` |
| `CLIPBOARD_HIJACK` | Runtime | `navigator.clipboard.writeText()` or `copy` event handler wrote to the system clipboard |
| `CLIPBOARD_HIJACK_CLICKFIX` | Runtime | Clipboard write contained a shell command — confirmed ClickFix paste-and-run attack |
| `CSS_OVERLAY_INJECTED` | CSS analyser | Fullscreen `position:fixed` overlay in static CSS — ClickFix / SocGholish structural signature |
| `DYNAMIC_OVERLAY_INJECTED` | DOM diff | Viewport-spanning element present in the post-JS DOM but absent from static HTML — JS-injected overlay |
| `DYNAMIC_OVERLAY_INJECTED_CLICKFIX` | DOM diff | JS-injected overlay confirmed alongside clipboard hijack — complete ClickFix attack chain |
| `INTERCEPTED_REQUEST` | Runtime | URLs JavaScript attempted to fetch at runtime (all blocked); list in evidence |
| `NETWORK_ATTEMPT_BLOCKED` | Runtime (sandbox) | `fetch` / `XMLHttpRequest` / `WebSocket` call attempted inside the rquickjs sandbox and blocked; kind → URL in evidence |
| `DRIVE_BY_DOWNLOAD` | Fetcher | Automatic file download intercepted (executables/archives only; images/fonts suppressed) |
| `CRYPTO_WALLET_API` | Static / runtime | Wallet RPC method invoked (e.g. `eth_sendTransaction`) — wallet-drainer behaviour |
| `ETHERHIDING_ONCHAIN_READ` | Runtime | `eth_call` on-chain read with no connected wallet — ClearFake EtherHiding C2 |
| `CLIENTSIDE_DECRYPTED_PAGE` | Runtime | AES-GCM client-side page decryption injected into the DOM (EvilTokens ghost code) |
| `OBFUSCATION_UNRESOLVED` | Static | Obfuscated code that could not be statically resolved; detail in evidence |
| `QR_CODE_URL` | Renderer | URL payload decoded from a QR code in page images or the rendered screenshot (quishing) |
| `BITB_FAKE_WINDOW` | HTML analyser | Browser-in-the-Browser: a fake window frame rendering another brand's login URL as address-bar text above a password field (Sneaky2FA / M365 / Facebook BitB) — **Critical** |
| `BLOCKED_ELEMENT_SCRIPT` | HTML sanitiser | `<script>` tag removed before render |
| `BLOCKED_ELEMENT_IFRAME` | HTML sanitiser | `<iframe>` tag removed before render |
| `BLOCKED_ELEMENT_OTHER` | HTML sanitiser | Other disallowed element (`<object>`, `<embed>`, `<form>`, …) removed |
| `JAVASCRIPT_URL_STRIPPED` | HTML sanitiser | `javascript:` URI or other blocked (non-`on*`) attribute removed |
| `SANDBOX_EVASION_WEBDRIVER` | Static | `navigator.webdriver` read — anti-analysis probe |
| `SANDBOX_EVASION_HEADLESS_STRING` | Static | Headless browser identifier string (`HeadlessChrome`, `PhantomJS`, `$cdc_`) |
| `SANDBOX_EVASION_SCREEN_PROBE` | Static | `window.outerHeight`/`outerWidth` read — headless detection |
| `SANDBOX_EVASION_PLUGINS_PROBE` | Static | `navigator.plugins` read — headless detection |
| `SANDBOX_EVASION_CHROME_RUNTIME` | Static | `window.chrome` / `chrome.runtime` read — automation detection |
| `SANDBOX_EVASION_FOCUS_PROBE` | Static | `document.hasFocus()` call — headless detection |
| `SANDBOX_EVASION_CANVAS_FINGERPRINT` | Static | `WEBGL_debug_renderer_info` / `UNMASKED_RENDERER_WEBGL` access — GPU fingerprinting to detect headless Chromium |
| `SANDBOX_EVASION_LANGUAGES` | Static | `navigator.languages` read — returns empty array in headless; used to distinguish real browsers |
| `SANDBOX_EVASION_NOTIFICATION` | Static | `Notification.permission` read — notification API probe; behaves differently in headless |
| `SANDBOX_EVASION_HARDWARE_FINGERPRINT` | Static | `navigator.deviceMemory` / `navigator.hardwareConcurrency` read — undefined in headless |
| `EVENT_HANDLER_STRIPPED` | HTML sanitiser | Inline `on*` event handler removed |
| `META_REDIRECT_STRIPPED` | HTML sanitiser | `<meta http-equiv="refresh">` redirect removed |

---

## Tech stack detection

Carapace detects the technology stack from the pre-sanitisation DOM — before the sanitiser strips custom elements and framework-specific attributes. Detected technologies are included in the threat report under `tech_stack`.

Detection covers: React, Vue, Angular, Svelte, Next.js, Nuxt, HTMX, Alpine.js, Livewire, Tailwind CSS, Bootstrap, Bulma, shadcn/ui, WordPress, Drupal, Joomla, Shopify, Magento, Wix, Squarespace, jQuery, Lodash, Moment.js, Axios, Socket.io, and more.

---

## Renderer fallback

The render ladder is: **live render** (the real URL, JavaScript enabled, through the policy proxy — over CDP when `CARAPACE_CDP` is on, with the CLI live render as its fallback) → **offline render** of the sanitised self-contained page (JavaScript enabled, every connection refused, network mocked) when the live render fails or comes back blank (`render_mode` records which one produced the screenshot). If Chromium is not available, Carapace falls back to `wkhtmltoimage` with JavaScript disabled.

Pass `--no-browser` to force the built-in Rust renderer (tiny-skia + taffy layout engine). The Rust renderer is approximate — it handles basic CSS box model, flexbox, and inline text but does not support all CSS features. Use it only when no headless browser is available.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
