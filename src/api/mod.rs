/// HTTP API server for Carapace.
///
/// Exposes two endpoints:
///   POST /render  — fetch a URL, render it, return image + threat report
///   GET  /health  — liveness probe
///
/// Authentication is optional: set `--api-key` (or `CARAPACE_API_KEY` env var)
/// to require an `X-API-Key` header on every request.
///
/// Concurrency is bounded by `--max-concurrent` (default 4). Excess requests
/// receive 429 Too Many Requests immediately rather than queuing.
pub mod handlers;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Semaphore;
use tracing::info;

use crate::cli::ServeArgs;
use crate::error::Result;
use crate::error::CarapaceError;

// ── Shared server state ───────────────────────────────────────────────────────

pub struct AppState {
    /// Limits the number of render jobs running in parallel.
    pub semaphore: Semaphore,
    /// If `Some`, every request must supply a matching `X-API-Key` header.
    pub api_key: Option<String>,
    /// Forwarded to each `RenderArgs` — callers cannot override this.
    pub block_private_ips: bool,
    /// Forwarded to each `RenderArgs` — callers cannot override this.
    pub https_only: bool,
    /// Per-fetch network timeout passed to the pipeline.
    pub timeout_secs: u64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Start the HTTP API server and block until it exits.
pub async fn serve(args: ServeArgs) -> Result<()> {
    let state = Arc::new(AppState {
        semaphore: Semaphore::new(args.max_concurrent),
        api_key: args.api_key.clone(),
        block_private_ips: args.block_private_ips,
        https_only: args.https_only,
        timeout_secs: args.timeout,
    });

    let app = Router::new()
        .route("/render", post(handlers::render))
        .route("/health", get(handlers::health))
        .with_state(state)
        // Reject request bodies over 1 MB to prevent memory exhaustion.
        // The actual URL payload is tiny; this guards against malformed clients.
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| CarapaceError::Render(format!("failed to bind {}: {}", addr, e)))?;

    info!(
        "Carapace API listening on http://{} (max_concurrent={}, auth={})",
        addr,
        args.max_concurrent,
        if args.api_key.is_some() { "enabled" } else { "disabled" },
    );

    axum::serve(listener, app)
        .await
        .map_err(|e| CarapaceError::Render(format!("server error: {}", e)))?;

    Ok(())
}
