//! `POST /triage` — sink index for a batch of scripts (JS triage Phase 4).
//!
//! Insight calls this once per page with the script bodies it has already fetched, and
//! gets back, per script, every dangerous operation with its resolved argument and the
//! span of its enclosing function (see `js::sinks`).
//!
//! Safety properties, by design:
//! * **Content only.** There is no `url` field: this endpoint never fetches anything,
//!   so it adds no SSRF surface.
//! * **Static only.** Parsing + semantic analysis; nothing is executed.
//! * **Its own concurrency limit.** `/render` and `/analyse` share `AppState::semaphore`
//!   (1 in production). Triage is millisecond-scale CPU work and must not 429 because
//!   another scan is rendering, nor delay a render.
//! * **Bounded.** ≤ `MAX_SCRIPTS` scripts per request, scripts over `MAX_SCRIPT_BYTES`
//!   skipped (reported, not silently dropped), the router's 4 MB body limit, and a
//!   wall-clock timeout around the blocking work.
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::AppState;
use crate::js::sinks::{self, SinkIndex};

const MAX_SCRIPTS: usize = 64;
const MAX_SCRIPT_BYTES: usize = 2 * 1024 * 1024;
const WALL_CLOCK: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
pub struct TriageRequest {
    pub scripts: Vec<TriageScript>,
}

#[derive(Debug, Deserialize)]
pub struct TriageScript {
    /// Caller-chosen identifier, echoed back.
    pub id: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct TriageResult {
    pub id: String,
    /// Set when the script was not indexed (`too_large`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<&'static str>,
    #[serde(flatten)]
    pub index: SinkIndex,
}

#[derive(Debug, Serialize)]
pub struct TriageResponse {
    pub results: Vec<TriageResult>,
}

fn err_resp(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

pub async fn triage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TriageRequest>,
) -> Response {
    if let Some(expected) = &state.api_key {
        let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");
        if provided != expected {
            warn!("triage rejected: invalid API key");
            return err_resp(StatusCode::UNAUTHORIZED, "invalid or missing X-API-Key");
        }
    }
    if req.scripts.len() > MAX_SCRIPTS {
        return err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("at most {MAX_SCRIPTS} scripts per request"),
        );
    }
    let _permit = match state.triage_semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!("triage rejected: at concurrency limit");
            return err_resp(StatusCode::TOO_MANY_REQUESTS, "server busy — try again shortly");
        }
    };

    let count = req.scripts.len();
    let task = tokio::time::timeout(
        WALL_CLOCK,
        tokio::task::spawn_blocking(move || -> Vec<TriageResult> {
            req.scripts
                .into_iter()
                .map(|s| {
                    if s.content.len() > MAX_SCRIPT_BYTES {
                        TriageResult { id: s.id, skipped: Some("too_large"), index: SinkIndex::default() }
                    } else {
                        TriageResult { id: s.id, skipped: None, index: sinks::index(&s.content) }
                    }
                })
                .collect()
        }),
    )
    .await;

    match task {
        Err(_elapsed) => {
            warn!("triage timed out ({count} scripts)");
            err_resp(StatusCode::GATEWAY_TIMEOUT, "triage timed out")
        }
        Ok(Err(e)) => {
            warn!("triage task panicked: {e}");
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, "triage failed")
        }
        Ok(Ok(results)) => {
            let n_sinks: usize = results.iter().map(|r| r.index.sinks.len()).sum();
            info!("API triage: {count} script(s), {n_sinks} sink(s)");
            Json(TriageResponse { results }).into_response()
        }
    }
}
