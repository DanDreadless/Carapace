# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Compile
#
# Uses the official Rust image so we get rustup + cargo out of the box.
# BuildKit cache mounts keep the registry and build artefacts warm across
# rebuilds so re-compiling after a source change is fast.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Only the C compiler toolchain and OpenSSL headers are needed at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cp target/release/carapace /usr/local/bin/carapace


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime
#
# Minimal Debian image with only Chromium, TLS roots, and fonts.
# Everything else is stripped.  The final image contains no build tools,
# no Rust toolchain, and no source code.
#
# Security posture inside the container:
#   - Non-root user (uid 1000)
#   - Chromium runs with --disable-javascript + network kill-switch
#     (--proxy-server=socks5://127.0.0.1:1), so even --no-sandbox is safe
#   - All capabilities dropped at runtime via docker run / compose
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# chromium pulls in all its own hard dependencies automatically.
# fonts-liberation  — metrically compatible with Arial/Times/Courier
# fonts-noto-color-emoji — prevents missing-glyph boxes for emoji content
# ca-certificates   — TLS root store for outbound HTTPS fetches
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        curl \
        fonts-liberation \
        fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user — never run as root.
RUN useradd -m -u 1000 -s /bin/sh carapace

COPY --from=builder /usr/local/bin/carapace /usr/local/bin/carapace

# /output is the expected mount point for rendered files and threat reports.
# The temp directory used during rendering is /tmp (already world-writable).
RUN mkdir -p /output && chown carapace:carapace /output

USER carapace
WORKDIR /home/carapace

ENTRYPOINT ["/usr/local/bin/carapace"]
