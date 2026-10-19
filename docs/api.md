# HTTP API

Carapace ships with a built-in HTTP API server for integration with other tools
(e.g. Insight). Start it with the `serve` subcommand instead of `render`.

## Starting the server

```bash
# Native
carapace serve --port 8080

# With API key auth enabled
carapace serve --port 8080 --api-key s3cr3t
# or via env var
CARAPACE_API_KEY=s3cr3t carapace serve --port 8080

# Docker (recommended)
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -e CARAPACE_API_KEY=s3cr3t \
    -p 8080:8080 \
    carapace:latest \
    serve --port 8080

# docker compose
docker compose run --rm -p 8080:8080 carapace serve --port 8080
```

### serve flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | TCP port to listen on |
| `--host` | `0.0.0.0` | Bind address |
| `--api-key` | *(none)* | If set, require `X-API-Key: <key>` header. Also read from `CARAPACE_API_KEY` env var. |
| `--max-concurrent` | `4` | Max parallel render jobs; excess requests get `429` |
| `--block-private-ips` | `true` | Block SSRF to private/loopback ranges (cannot be overridden per-request) |
| `--https-only` | `false` | Reject plain HTTP URLs (cannot be overridden per-request) |
| `--timeout` | `30` | Per-fetch timeout in seconds |

---

## Endpoints

### `POST /render`

Fetch a URL, render it, and return the image and threat report.

**Request body** (JSON):

```json
{
  "url": "https://example.com",
  "format": "png",
  "width": 1280,
  "height": 800,
  "no_assets": false,
  "max_size": null,
  "no_browser": false,
  "no_js_sandbox": false
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | **required** | URL to fetch and render |
| `format` | string | `"png"` | `"png"`, `"pdf"`, or `"json"` |
| `width` | integer | `1280` | Viewport width in pixels |
| `height` | integer | `800` | Viewport height in pixels |
| `no_assets` | boolean | `false` | Skip fetching sub-resources |
| `max_size` | integer\|null | `null` | Max response body bytes |
| `no_browser` | boolean | `false` | Use the Rust renderer instead of Chromium |
| `no_js_sandbox` | boolean | `false` | Disable the JS sandbox |

> `block_private_ips` and `https_only` are **server-side settings only** — they
> cannot be overridden per-request to prevent SSRF bypass.

**Response `200`** (JSON):

```json
{
  "url": "https://example.com",
  "format": "png",
  "output": "<base64-encoded PNG bytes>",
  "content_type": "image/png",
  "threat_report": {
    "url": "https://example.com",
    "timestamp": "2026-04-11T12:00:00Z",
    "framework_detected": null,
    "risk_score": 0,
    "flags": []
  }
}
```

When `format` is `"json"`, `output` is `null` and the full analysis is in
`threat_report`. For `"png"` and `"pdf"`, `output` is a Base64-encoded blob.

| Field | Description |
|-------|-------------|
| `url` | The final URL after any redirects |
| `format` | Actual format rendered |
| `output` | Base64-encoded PNG or PDF, or `null` for json format |
| `content_type` | `image/png`, `application/pdf`, or `application/json` |
| `threat_report` | Full threat report (see [threat-report.md](threat-report.md)) |

**Error responses:**

| Status | Condition |
|--------|-----------|
| `400` | Malformed JSON body |
| `401` | Missing or incorrect `X-API-Key` |
| `429` | Server at `--max-concurrent` limit |
| `504` | Render exceeded timeout |
| `500` | Pipeline error (bad URL, SSRF block, render failure) |

```json
{ "error": "description of what went wrong" }
```

---

### `GET /health`

Liveness probe. Returns `200` when the server is ready.

```json
{ "status": "ok", "version": "0.1.0" }
```

---

## Examples

**Render to PNG:**

```bash
curl -s -X POST http://localhost:8080/render \
  -H "Content-Type: application/json" \
  -H "X-API-Key: s3cr3t" \
  -d '{"url": "https://example.com"}' \
  | jq -r '.output' \
  | base64 -d > render.png
```

**Threat report only (no image):**

```bash
curl -s -X POST http://localhost:8080/render \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "format": "json"}' \
  | jq '.threat_report'
```

**Python (as used by Insight):**

```python
import requests, base64

resp = requests.post(
    "http://carapace:8080/render",
    headers={"X-API-Key": "s3cr3t"},
    json={"url": target_url, "format": "png", "width": 1280},
    timeout=120,
)
resp.raise_for_status()
data = resp.json()

screenshot_bytes = base64.b64decode(data["output"])
risk_score       = data["threat_report"]["risk_score"]
flags            = data["threat_report"]["flags"]
```

---

## Integrating with Insight

Add Carapace as a sidecar service in Insight's `docker-compose.yml`:

```yaml
services:
  # ... existing Insight services ...

  carapace:
    image: carapace:latest
    environment:
      CARAPACE_API_KEY: "${CARAPACE_API_KEY}"
    ports: []                    # internal only — not exposed to host
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 1g
    command: ["serve", "--port", "8080"]

networks:
  default:
    # Both Django and Carapace are on the same internal network.
    # Insight calls http://carapace:8080/render — no external exposure.
```

In Insight's Celery scan task:

```python
import os, requests, base64
from django.conf import settings

CARAPACE_URL = os.getenv("CARAPACE_URL", "http://carapace:8080")
CARAPACE_KEY = os.getenv("CARAPACE_API_KEY", "")

def render_url(target_url: str) -> dict:
    resp = requests.post(
        f"{CARAPACE_URL}/render",
        headers={"X-API-Key": CARAPACE_KEY},
        json={"url": target_url, "format": "png", "width": 1280},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()
```
