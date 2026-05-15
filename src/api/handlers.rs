use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::cli::{OutputFormat, RenderArgs};
use crate::threat::ThreatReport;

use super::AppState;

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RenderRequest {
    /// URL to fetch and render
    pub url: String,

    /// Output format: "png" (default) or "json"
    #[serde(default = "default_format")]
    pub format: String,

    /// Viewport width in pixels (default: 1280)
    #[serde(default = "default_width")]
    pub width: u32,

    /// Viewport height in pixels (default: 800)
    #[serde(default = "default_height")]
    pub height: u32,

    /// Skip fetching sub-resources (images, stylesheets)
    #[serde(default)]
    pub no_assets: bool,

    /// Maximum response body size in bytes
    pub max_size: Option<u64>,

    /// Use the built-in Rust renderer instead of Chromium
    #[serde(default)]
    pub no_browser: bool,

    /// Disable the JS sandbox (static analysis only)
    #[serde(default)]
    pub no_js_sandbox: bool,

    /// Capture a second screenshot at mobile viewport (375×812 — iPhone SE) alongside the desktop.
    /// Many phishing/ClickFix pages are mobile-first; the desktop render can hide attack UI
    /// that only appears at narrow widths.
    #[serde(default)]
    pub mobile_screenshot: bool,
}

fn default_format() -> String { "png".into() }
fn default_width()  -> u32    { 1280 }
fn default_height() -> u32    { 800 }

#[derive(Debug, Serialize)]
pub struct RenderResponse {
    pub url: String,
    pub format: String,
    /// Base64-encoded PNG bytes. `null` when format is "json".
    pub output: Option<String>,
    /// Base64-encoded mobile viewport PNG (375×812). `null` when `mobile_screenshot` was not requested.
    pub mobile_output: Option<String>,
    /// MIME type of `output` ("image/png" or "application/json").
    pub content_type: String,
    pub threat_report: serde_json::Value,
}

fn err_resp(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ── Analyse request type (LJS-06) ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AnalyseRequest {
    /// URL to fetch and analyse; ignored when `content` is provided.
    pub url: Option<String>,
    /// Raw script content to analyse; takes precedence over `url`.
    pub content: Option<String>,
    /// Maximum response body size in bytes when fetching a URL (default: 2 MB).
    pub max_size: Option<u64>,
    /// Label used in evidence blocks (defaults to `url`, or `"inline"`).
    pub source_name: Option<String>,
}

// ── Health handler ────────────────────────────────────────────────────────────

pub async fn health() -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

// ── Render handler ────────────────────────────────────────────────────────────

pub async fn render(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RenderRequest>,
) -> Response {
    // ── Auth ──────────────────────────────────────────────────────────────────
    if let Some(expected) = &state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            warn!("render rejected: invalid API key");
            return err_resp(StatusCode::UNAUTHORIZED, "invalid or missing X-API-Key");
        }
    }

    // ── Concurrency limit ─────────────────────────────────────────────────────
    let _permit = match state.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!("render rejected: at concurrency limit");
            return err_resp(StatusCode::TOO_MANY_REQUESTS, "server busy — try again shortly");
        }
    };

    info!("API render: {} (format={})", req.url, req.format);

    // ── Parse output format ───────────────────────────────────────────────────
    let output_format = match req.format.to_ascii_lowercase().as_str() {
        "json" => OutputFormat::Json,
        _      => OutputFormat::Png,
    };
    let ext = match output_format {
        OutputFormat::Png  => "png",
        OutputFormat::Json => "json",
    };

    // ── Temp output path ──────────────────────────────────────────────────────
    let output_path: PathBuf = std::env::temp_dir().join(format!(
        "carapace_api_{}_{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
        ext,
    ));

    // ── Build RenderArgs ──────────────────────────────────────────────────────
    // Security-critical flags (block_private_ips, https_only) come from the
    // server config — the caller cannot override them per-request.
    let args = RenderArgs {
        url: req.url.clone(),
        output: output_path.clone(),
        output_format,
        block_private_ips: state.block_private_ips,
        https_only: state.https_only,
        no_assets: req.no_assets,
        max_size: req.max_size,
        max_redirects: 5,
        timeout: state.timeout_secs,
        width: req.width,
        height: req.height,
        mobile_screenshot: req.mobile_screenshot,
        // Threat report is returned inline — no sidecar file needed.
        threat_report: false,
        no_js_sandbox: req.no_js_sandbox,
        no_browser: req.no_browser,
        verbose: false,
    };

    // ── Run pipeline + read output in a blocking thread ───────────────────────
    //
    // The render pipeline holds `markup5ever_rcdom::RcDom` (built on `Rc`, not
    // `Arc`) across `.await` points, making the future !Send.  Axum requires
    // Send futures on its multi-thread runtime.
    //
    // Solution: move the whole pipeline into `spawn_blocking` and drive it with
    // `Handle::block_on`.  This pins the !Send work to a single OS thread.
    // The output file is read and the temp path cleaned up inside the same
    // closure so we never touch the file from the async context.
    let wall_clock = Duration::from_secs(state.timeout_secs + 30);
    let handle = tokio::runtime::Handle::current();
    let path_for_closure = output_path.clone();
    let fmt_for_closure  = output_format;

    let mobile_for_closure = req.mobile_screenshot && output_format == OutputFormat::Png;

    type BlockingResult = Result<
        (ThreatReport, Option<Vec<u8>>, Option<Vec<u8>>),  // (report, desktop, mobile)
        Box<dyn std::error::Error + Send + Sync>,
    >;

    let task: BlockingResult = tokio::task::spawn_blocking(move || {
        // Drive the async pipeline synchronously on this thread.
        let pipeline = handle.block_on(async {
            tokio::time::timeout(wall_clock, crate::run(&args)).await
        });

        let report = match pipeline {
            Err(_elapsed) => return Err("render timed out".into()),
            Ok(Err(e))    => return Err(e.to_string().into()),
            Ok(Ok(r))     => r,
        };

        // Read the desktop screenshot.  For json format the output is in `report` itself.
        let file_bytes = match fmt_for_closure {
            OutputFormat::Json => None,
            OutputFormat::Png => Some(
                std::fs::read(&path_for_closure)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?,
            ),
        };
        let _ = std::fs::remove_file(&path_for_closure);

        // Read the mobile screenshot if it was requested and produced.
        let mobile_bytes = if mobile_for_closure {
            let mp = path_for_closure.with_extension("mobile.png");
            if mp.exists() {
                let bytes = std::fs::read(&mp).ok();
                let _ = std::fs::remove_file(&mp);
                bytes
            } else {
                None
            }
        } else {
            None
        };

        Ok((report, file_bytes, mobile_bytes))
    })
    .await
    .unwrap_or_else(|e| Err(format!("task panicked: {e}").into()));

    let (report, file_bytes, mobile_bytes) = match task {
        Ok(pair) => pair,
        Err(e)   => {
            warn!("render failed for {}: {}", req.url, e);
            let status = if e.to_string().contains("timed out") {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return err_resp(status, &e.to_string());
        }
    };

    // ── Encode output ─────────────────────────────────────────────────────────
    let (output_b64, content_type) = match file_bytes {
        None => (None, "application/json".to_string()),
        Some(bytes) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            (Some(b64), "image/png".to_string())
        }
    };
    let mobile_b64 = mobile_bytes.map(|b| base64::engine::general_purpose::STANDARD.encode(&b));

    // ── Serialise threat report ───────────────────────────────────────────────
    let threat_json = match serde_json::to_value(&report) {
        Ok(v)  => v,
        Err(e) => return err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("serialisation error: {e}"),
        ),
    };

    info!("API render complete: {} risk_score={}", req.url, report.risk_score);

    Json(RenderResponse {
        url: req.url,
        format: ext.to_string(),
        output: output_b64,
        mobile_output: mobile_b64,
        content_type,
        threat_report: threat_json,
    })
    .into_response()
}

// ── Analyse handler (LJS-06) ──────────────────────────────────────────────────
//
// Runs OXC-based static JS analysis on a URL or raw content without any
// Chromium involvement.  Avoids the hang caused by feeding raw JS to the
// browser render pipeline (Chromium executes it in a blank-page context where
// async code never resolves).
//
// LJS-08: for content larger than 512 KB the source is split into overlapping
// 256 KB chunks (32 KB overlap) and each chunk is analysed independently.
// Findings are deduplicated by flag code and merged into one report.

pub async fn analyse(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AnalyseRequest>,
) -> Response {
    // ── Auth ──────────────────────────────────────────────────────────────────
    if let Some(expected) = &state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            warn!("analyse rejected: invalid API key");
            return err_resp(StatusCode::UNAUTHORIZED, "invalid or missing X-API-Key");
        }
    }

    // ── Concurrency limit ─────────────────────────────────────────────────────
    let _permit = match state.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!("analyse rejected: at concurrency limit");
            return err_resp(StatusCode::TOO_MANY_REQUESTS, "server busy — try again shortly");
        }
    };

    // ── Resolve source content ────────────────────────────────────────────────
    const DEFAULT_MAX_SIZE: u64 = 2 * 1024 * 1024; // 2 MB

    let url_for_response = req.url.clone().unwrap_or_else(|| "inline".to_string());
    let source_label = req.source_name
        .or_else(|| req.url.clone())
        .unwrap_or_else(|| "inline".to_string());

    let js_bytes: Vec<u8> = if let Some(content) = req.content {
        content.into_bytes()
    } else if let Some(ref url) = req.url {
        use crate::fetcher::{FetchOptions, SafeFetcher};
        let options = FetchOptions {
            block_private_ips: state.block_private_ips,
            https_only: state.https_only,
            max_size: Some(req.max_size.unwrap_or(DEFAULT_MAX_SIZE)),
            max_redirects: 5,
            timeout_secs: state.timeout_secs,
            no_assets: false,
        };
        let fetcher = match SafeFetcher::new(options) {
            Ok(f) => f,
            Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        match fetcher.fetch(url).await {
            Ok(r) => r.body.to_vec(),
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, &e.to_string()),
        }
    } else {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "either 'url' or 'content' must be provided",
        );
    };

    info!("API analyse: {} ({} bytes)", source_label, js_bytes.len());

    // ── Run analysis in a blocking thread ─────────────────────────────────────
    let wall_clock = Duration::from_secs(state.timeout_secs + 30);
    let source_label_for_log = source_label.clone();

    let task = tokio::time::timeout(
        wall_clock,
        tokio::task::spawn_blocking(move || -> crate::threat::ThreatReport {
            let source = String::from_utf8_lossy(&js_bytes).into_owned();
            let mut report = crate::threat::ThreatReport::new(&source_label);

            // LJS-08: overlapping-chunk analysis for large files.
            // Patterns split at a chunk boundary are caught by the 32 KB overlap.
            // Sequential — rayon is not in the dependency tree.
            const CHUNK_THRESHOLD: usize = 512 * 1024; // 512 KB
            const CHUNK_SIZE: usize      = 256 * 1024; // 256 KB per chunk
            const OVERLAP: usize         =  32 * 1024; // 32 KB overlap

            if source.len() > CHUNK_THRESHOLD {
                let bytes = source.as_bytes();
                let mut start = 0usize;
                loop {
                    let end = (start + CHUNK_SIZE).min(bytes.len());
                    // from_utf8_lossy handles any multi-byte char cut at the boundary.
                    let chunk = String::from_utf8_lossy(&bytes[start..end]).into_owned();
                    let mut chunk_report = crate::threat::ThreatReport::new(&source_label);
                    crate::js::analysis::analyse(&chunk, &source_label, &mut chunk_report);
                    report.merge_flags(chunk_report);
                    if end >= bytes.len() {
                        break;
                    }
                    start = end.saturating_sub(OVERLAP);
                }
            } else {
                crate::js::analysis::analyse(&source, &source_label, &mut report);
            }

            report
        }),
    )
    .await;

    let report = match task {
        Err(_elapsed) => {
            warn!("analyse timed out for {}", source_label_for_log);
            return err_resp(StatusCode::GATEWAY_TIMEOUT, "analysis timed out");
        }
        Ok(Err(e)) => {
            warn!("analyse task panicked for {}: {}", source_label_for_log, e);
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("task panicked: {e}"),
            );
        }
        Ok(Ok(r)) => r,
    };

    // ── Serialise + return ────────────────────────────────────────────────────
    let threat_json = match serde_json::to_value(&report) {
        Ok(v)  => v,
        Err(e) => return err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("serialisation error: {e}"),
        ),
    };

    info!(
        "API analyse complete: {} risk_score={}",
        source_label_for_log, report.risk_score,
    );

    Json(RenderResponse {
        url: url_for_response,
        format: "json".to_string(),
        output: None,
        mobile_output: None,
        content_type: "application/json".to_string(),
        threat_report: threat_json,
    })
    .into_response()
}
