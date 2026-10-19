# Docker Deployment

## Why Docker

Carapace already isolates malicious content through several layers:

| Layer | What it blocks |
|-------|---------------|
| SafeFetcher | SSRF, private IPs, decompression bombs |
| HTML sanitizer | `<script>`, `<iframe>`, `on*` attrs, `javascript:` URLs |
| JS processor | Static analysis + sandboxed execution only |
| CSS sanitizer | `@import`, external `url()`, `@font-face` |
| Chromium flags | `--disable-javascript`, `--proxy-server=socks5://127.0.0.1:1` |

The Docker container adds a final **OS-level isolation layer**: cgroups, namespaces, and a non-root user. This makes the `--no-sandbox` Chromium flag (required in container environments) safe in practice — even if Chromium were somehow exploited, it is confined to the container.

## Quick Start

```bash
# Build the image
docker build -t carapace:latest .

# Render a URL to PNG — output lands in ./output/
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    render https://example.com -o /output/render.png

# Render to PDF
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    render https://example.com --output-format pdf -o /output/render.pdf

# JSON threat report only (no image)
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    render https://example.com --output-format json -o /output/report.json

# HTTP API server
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -e CARAPACE_API_KEY=s3cr3t \
    -p 8080:8080 \
    carapace:latest \
    serve --port 8080
```

The `./output/` directory on the host receives both the rendered file and the
`*.threat.json` report.

## Using docker compose

```bash
# One-off render
docker compose run --rm carapace render https://example.com -o /output/render.png

# API server
docker compose run --rm -p 8080:8080 carapace serve --port 8080

# Force rebuild after source changes
docker compose build
```

## Security Flags Explained

| Flag | Why |
|------|-----|
| `--cap-drop=ALL` | Strips all Linux capabilities (no raw sockets, no ptrace, no mount, etc.) |
| `--security-opt no-new-privileges:true` | Prevents SUID binaries inside the container from escalating |
| `-v ./output:/output` | Only writable path is the output mount; container filesystem is effectively read-only for the app |
| Non-root user `carapace` (uid 1000) | Even if Chromium is compromised it cannot write to system paths |

Optional hardening for maximum isolation:

```bash
# Read-only root filesystem; only /output and /tmp remain writable
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=256m \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    https://example.com -o /output/render.png
```

## Image Contents

The multi-stage build keeps the runtime image lean:

| Stage | Base | Purpose |
|-------|------|---------|
| `builder` | `rust:1.88-slim-bookworm` | Compile the binary |
| `runtime` | `debian:bookworm-slim` | Run the binary |

The final image contains:
- The `carapace` binary
- Chromium and its shared library dependencies
- `fonts-liberation` + `fonts-noto-color-emoji`
- TLS root store (`ca-certificates`)

It does **not** contain: the Rust toolchain, source code, build tools, or any
development headers.

## Analysing Malicious Sites

When pointing Carapace at a known-bad URL, the container boundary gives you an
extra guarantee: even if a site exploits a hypothetical renderer bug, the
damage is contained to the ephemeral container. Remove it when done:

```bash
docker run --rm \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=256m \
    -v "$(pwd)/output:/output" \
    carapace:latest \
    https://known-malicious-site.example.com -o /output/analysis.png

# Container is automatically removed after the run (--rm).
# Check the threat report:
cat output/analysis.threat.json
```

## HTTP API Mode

Carapace includes a built-in HTTP API server. Start it with the `serve`
subcommand. See [API documentation](api.md) for the full endpoint reference
and Insight integration guide.

The security model is identical to the render mode — the same container image,
same isolation flags, same pipeline. The API server is a thin axum wrapper
around the existing render pipeline.

## Building for Different Architectures

```bash
# Build for linux/amd64 explicitly (useful on Apple Silicon hosts)
docker build --platform linux/amd64 -t carapace:latest .

# Multi-arch manifest (requires docker buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t carapace:latest --push .
```
