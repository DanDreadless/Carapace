use thiserror::Error;

#[derive(Debug, Error)]
pub enum CarapaceError {
    // ── Network ───────────────────────────────────────────────────────────────
    #[error("HTTP error: {0}")]
    Fetch(#[from] reqwest::Error),

    #[error("SSRF protection triggered: {0}")]
    Ssrf(String),

    #[error("Invalid redirect: {0}")]
    InvalidRedirect(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Response exceeded size limit (decompression bomb protection)")]
    DecompressionBomb,

    // ── HTML ─────────────────────────────────────────────────────────────────
    #[error("HTML parse error: {0}")]
    HtmlParse(String),

    // ── JS ───────────────────────────────────────────────────────────────────
    #[error("JS runtime error: {0}")]
    JsRuntime(String),

    #[error("JS static analysis error: {0}")]
    JsAnalysis(String),

    // ── CSS ──────────────────────────────────────────────────────────────────
    #[error("CSS processing error: {0}")]
    CssProcessing(String),

    // ── Rendering ─────────────────────────────────────────────────────────────
    #[error("Layout error: {0}")]
    Layout(String),

    #[error("Render error: {0}")]
    Render(String),

    // ── I/O ──────────────────────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // ── URL ──────────────────────────────────────────────────────────────────
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    // ── Serialisation ─────────────────────────────────────────────────────────
    #[error("Serialisation error: {0}")]
    Serde(#[from] serde_json::Error),

    // ── Generic ───────────────────────────────────────────────────────────────
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CarapaceError>;
