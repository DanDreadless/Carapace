# Threat Report

## Overview
Every Carapace run produces a `<output>.threat.json` file alongside the rendered
output. It aggregates security flags emitted by every pipeline stage and
produces a normalised risk score.

## JSON Schema

```json
{
  "url": "https://example.com",
  "timestamp": "2026-04-11T12:00:00Z",
  "framework_detected": "React",
  "risk_score": 72,

  "flags": [
    {
      "severity": "critical",
      "code": "JS_EVAL_DETECTED",
      "detail": "eval() call"
    },
    {
      "severity": "critical",
      "code": "DRIVE_BY_DOWNLOAD",
      "detail": "auto-download blocked: \"malware.exe\" (application/x-msdownload) 204800 bytes — SHA256: a3f5c1..."
    },
    {
      "severity": "high",
      "code": "BASE64_OBFUSCATION",
      "detail": "atob('YWxlcnQo…') → 'alert(…)'"
    },
    {
      "severity": "medium",
      "code": "NETWORK_ATTEMPT_BLOCKED",
      "detail": "fetch → https://c2.example.com/beacon"
    }
  ]
}
```

`flags` is the primary output — one entry per distinct threat code detected.
Duplicate detections of the same code contribute to the risk score's volume
bonus but do not produce additional flag entries.

## Flag Taxonomy

### Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Direct code execution or malware delivery attempt |
| `high` | Obfuscation, C2 calls, credential theft |
| `medium` | Network calls, DOM manipulation sinks, redirects |
| `low` | Informational: blocked passive elements |

### Flag Codes

#### Fetcher

| Code | Severity | Description |
|------|----------|-------------|
| `DRIVE_BY_DOWNLOAD` | critical | Response triggers auto-download (`Content-Disposition: attachment` or executable MIME type). Filename and SHA256 hash recorded; body never written to disk. |
| `SSRF_BLOCKED` | high | Request to private/loopback/link-local IP blocked |
| `DECOMPRESSION_BOMB` | high | Response exceeded configured size limit |

#### HTML Sanitizer

| Code | Severity | Description |
|------|----------|-------------|
| `BLOCKED_ELEMENT_SCRIPT` | high | `<script>` tag removed |
| `BLOCKED_ELEMENT_IFRAME` | medium | `<iframe>` tag removed |
| `BLOCKED_ELEMENT_OTHER` | low | Other dangerous tag removed |
| `EVENT_HANDLER_STRIPPED` | high | `on*` attribute removed |
| `JAVASCRIPT_URL_STRIPPED` | medium | `javascript:` URL removed |
| `META_REDIRECT_STRIPPED` | medium | `<meta http-equiv=refresh>` removed |

#### JS Static Analysis / Sandbox

| Code | Severity | Description |
|------|----------|-------------|
| `JS_EVAL_DETECTED` | critical | `eval()` call found |
| `JS_FUNCTION_CONSTRUCTOR` | critical | `new Function(…)` call found |
| `BASE64_OBFUSCATION` | high | `atob()` decodes to executable payload |
| `HEX_OBFUSCATION` | high | Hex-escaped string likely executable |
| `INNER_HTML_MUTATION` | high | Assignment to `innerHTML`/`outerHTML` |
| `WEBSOCKET_ATTEMPT` | high | `WebSocket` constructor called |
| `TIMER_STRING_EXEC` | high | `setTimeout`/`setInterval` with string arg |
| `NETWORK_ATTEMPT_BLOCKED` | medium | `fetch`/XHR attempted in sandbox |
| `REDIRECT_ATTEMPT` | medium | `window.location` assignment |
| `DOCUMENT_WRITE` | medium | `document.write()` used |
| `COOKIE_ACCESS` | medium | `document.cookie` write |
| `SANDBOX_EVASION_WEBDRIVER` | high | `navigator.webdriver` accessed — script probing for headless Chrome/Selenium |
| `SANDBOX_EVASION_HEADLESS_STRING` | high | String literal contains known headless browser identifier (`HeadlessChrome`, `PhantomJS`, `$cdc_`, etc.) |
| `SANDBOX_EVASION_SCREEN_PROBE` | medium | `window.outerHeight`/`outerWidth` accessed — headless zero-dimension fingerprint check |
| `SANDBOX_EVASION_PLUGINS_PROBE` | low | `navigator.plugins` accessed — headless plugin-list fingerprint check |

## Risk Score Calculation

```
base score = sum of severity weights for each unique flag code:
    critical → 40 pts
    high     → 20 pts
    medium   → 10 pts
    low      →  5 pts

volume bonus = for each code detected more than once across the raw flags:
    (occurrences − 1) × 2, capped at 10 pts per code

risk_score = min(base + volume_bonus, 100)
```

Example: a page with one `JS_EVAL_DETECTED` (40), two
`NETWORK_ATTEMPT_BLOCKED` (10 + 2 volume bonus), and five
`EVENT_HANDLER_STRIPPED` (20 + 8 volume bonus) = 80.

## Drive-By Download Detail

When a URL (or any sub-resource it references) responds with
`Content-Disposition: attachment` or an executable MIME type, Carapace:

1. Computes the SHA256 digest of the response body in memory
2. Extracts the filename from `Content-Disposition: filename=` or the URL path
3. Records the flag — filename, MIME type, size, and SHA256 hash
4. **Discards the body** — it is never written to disk

Detected MIME types include: `application/octet-stream`, `application/zip`,
`application/x-rar-compressed`, `application/x-7z-compressed`,
`application/x-tar`, `application/x-msdownload`,
`application/vnd.microsoft.portable-executable`, `application/x-elf`,
`application/java-archive`, `application/vnd.android.package-archive`,
`application/x-apple-diskimage`, and others.
