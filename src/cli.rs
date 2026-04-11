use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Carapace — safe HTML/CSS/JS renderer for security researchers.
///
/// Fetches a URL and renders it to PNG or PDF without executing malicious code.
/// A threat report is written alongside the rendered output.
#[derive(Debug, Parser)]
#[command(name = "carapace", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Render a URL to PNG, PDF, or JSON
    Render(RenderArgs),
    /// Start the HTTP API server
    Serve(ServeArgs),
}

// ── Render subcommand ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Parser)]
pub struct RenderArgs {
    /// URL to fetch and render
    pub url: String,

    /// Output file path (extension determines format if --output-format is omitted)
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,

    /// Output format (overrides file extension)
    #[arg(long, value_enum, default_value = "png")]
    pub output_format: OutputFormat,

    /// Block requests to private/loopback/link-local IP ranges (SSRF protection)
    #[arg(long, default_value_t = true)]
    pub block_private_ips: bool,

    /// Reject HTTP (non-TLS) URLs
    #[arg(long, default_value_t = false)]
    pub https_only: bool,

    /// Skip fetching sub-resources (images, stylesheets, fonts)
    #[arg(long, default_value_t = false)]
    pub no_assets: bool,

    /// Maximum response size, e.g. "5MB", "500KB" (decompression bomb limit)
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    pub max_size: Option<u64>,

    /// Maximum redirect hops to follow
    #[arg(long, default_value_t = 5)]
    pub max_redirects: u32,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Viewport width in pixels
    #[arg(long, default_value_t = 1280)]
    pub width: u32,

    /// Viewport height in pixels (0 = full-page capture)
    #[arg(long, default_value_t = 800)]
    pub height: u32,

    /// Write threat report JSON alongside output (default: true)
    #[arg(long, default_value_t = true)]
    pub threat_report: bool,

    /// Disable the rquickjs sandbox (static analysis only, no framework rendering)
    #[arg(long, default_value_t = false)]
    pub no_js_sandbox: bool,

    /// Use the built-in Rust renderer instead of a headless browser.
    /// The browser backend gives pixel-perfect output; use this flag only if
    /// chromium and wkhtmltoimage are not installed.
    #[arg(long, default_value_t = false)]
    pub no_browser: bool,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

impl RenderArgs {
    pub fn fetch_options(&self) -> crate::fetcher::FetchOptions {
        crate::fetcher::FetchOptions {
            block_private_ips: self.block_private_ips,
            https_only: self.https_only,
            max_size: self.max_size,
            max_redirects: self.max_redirects,
            timeout_secs: self.timeout,
            no_assets: self.no_assets,
        }
    }
}

// ── Serve subcommand ──────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct ServeArgs {
    /// Port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Host address to bind
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// API key required in X-API-Key header (also read from CARAPACE_API_KEY env var)
    #[arg(long, env = "CARAPACE_API_KEY")]
    pub api_key: Option<String>,

    /// Maximum number of concurrent render jobs
    #[arg(long, default_value_t = 4)]
    pub max_concurrent: usize,

    /// Block requests to private/loopback IP ranges in submitted URLs (SSRF protection)
    #[arg(long, default_value_t = true)]
    pub block_private_ips: bool,

    /// Reject HTTP (non-TLS) URLs submitted to the API
    #[arg(long, default_value_t = false)]
    pub https_only: bool,

    /// Request timeout in seconds for each fetch
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Rasterised PNG image
    Png,
    /// Annotated JSON DOM tree + threat report
    Json,
}

/// Parse human-readable size strings like "5MB", "500KB", "10mb".
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_ascii_uppercase();
    if let Some(n) = s.strip_suffix("GB") {
        n.trim().parse::<u64>().map(|v| v * 1024 * 1024 * 1024).map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix("MB") {
        n.trim().parse::<u64>().map(|v| v * 1024 * 1024).map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix("KB") {
        n.trim().parse::<u64>().map(|v| v * 1024).map_err(|e| e.to_string())
    } else if let Some(n) = s.strip_suffix('B') {
        n.trim().parse::<u64>().map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("5MB").unwrap(), 5 * 1024 * 1024);
        assert_eq!(parse_size("500KB").unwrap(), 500 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("10mb").unwrap(), 10 * 1024 * 1024);
    }
}
