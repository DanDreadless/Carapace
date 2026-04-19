pub mod ssrf;

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{Client, ClientBuilder, Response};
use tracing::{debug, info, warn};
use url::Url;

use crate::error::{CarapaceError, Result};
use ssrf::{is_safe_ip, validate_scheme};

const DEFAULT_MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Options forwarded from CLI args.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub block_private_ips: bool,
    pub https_only: bool,
    pub max_size: Option<u64>,
    pub max_redirects: u32,
    pub timeout_secs: u64,
    pub no_assets: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            https_only: false,
            max_size: None,
            max_redirects: 5,
            timeout_secs: 30,
            no_assets: false,
        }
    }
}

/// The result of a successful fetch.
#[derive(Debug)]
pub struct FetchResult {
    pub url: Url,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub content_type: String,
}

/// Safe HTTP client with SSRF protection, redirect validation,
/// and decompression-bomb limits.
pub struct SafeFetcher {
    client: Client,
    options: FetchOptions,
}

impl SafeFetcher {
    pub fn new(options: FetchOptions) -> Result<Self> {
        let client = ClientBuilder::new()
            .use_rustls_tls()
            // Load both the Mozilla-bundled root certs and the system native root
            // certs. Using both ensures we trust CAs that are in the OS store but
            // not yet in webpki-roots (e.g. recently added or corporate CAs), and
            // vice-versa.
            .tls_built_in_root_certs(true)
            .tls_built_in_native_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(options.timeout_secs))
            .connect_timeout(Duration::from_secs(10))
            // Mimic a real Windows Chrome browser so that servers performing
            // User-Agent fingerprinting serve their real content (including
            // conditional malicious payloads like ClickFix overlays) rather
            // than a bot-safe clean page.
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
            .build()?;

        Ok(Self { client, options })
    }

    /// Fetch `url_str`, validating SSRF constraints at every step.
    pub async fn fetch(&self, url_str: &str) -> Result<FetchResult> {
        let url = Url::parse(url_str)?;
        self.validate_url(&url)?;
        self.fetch_url(url, 0).await
    }

    // ── Validation helpers ────────────────────────────────────────────────────

    fn validate_url(&self, url: &Url) -> Result<()> {
        validate_scheme(url.scheme())?;

        if self.options.https_only && url.scheme() == "http" {
            return Err(CarapaceError::Ssrf("HTTPS-only mode: plain HTTP rejected".into()));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(CarapaceError::Ssrf("URL contains embedded credentials".into()));
        }

        let host = url
            .host_str()
            .ok_or_else(|| CarapaceError::Ssrf("URL has no host".into()))?;

        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.options.block_private_ips {
                is_safe_ip(&ip)?;
            }
        }

        Ok(())
    }

    async fn validate_dns(&self, url: &Url) -> Result<()> {
        let host = url
            .host_str()
            .ok_or_else(|| CarapaceError::Ssrf("no host".into()))?;

        // Raw IP literals were already validated in validate_url.
        if host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        let port = url.port_or_known_default().unwrap_or(443);
        debug!("resolving DNS for {}:{}", host, port);

        let addrs = tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|e| CarapaceError::DnsResolution(e.to_string()))?;

        for addr in addrs {
            is_safe_ip(&addr.ip())?;
        }

        Ok(())
    }

    // ── Core fetch loop ───────────────────────────────────────────────────────
    //
    // `fetch_url` is async-recursive (follows redirects). Rust cannot determine
    // the size of such a future at compile time, so it must be heap-boxed.

    fn fetch_url<'a>(
        &'a self,
        url: Url,
        redirect_depth: u32,
    ) -> Pin<Box<dyn Future<Output = Result<FetchResult>> + Send + 'a>> {
        Box::pin(async move {
            if redirect_depth > self.options.max_redirects {
                return Err(CarapaceError::InvalidRedirect(format!(
                    "exceeded {} redirect hops",
                    self.options.max_redirects
                )));
            }

            if self.options.block_private_ips {
                self.validate_dns(&url).await?;
            }

            info!("fetching {} (hop {})", url, redirect_depth);

            let response = self.client.get(url.as_str()).send().await?;
            let status = response.status().as_u16();

            // ── Manual redirect following ─────────────────────────────────────
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| {
                        CarapaceError::InvalidRedirect("redirect with no Location header".into())
                    })?
                    .to_str()
                    .map_err(|_| {
                        CarapaceError::InvalidRedirect("Location header is not valid UTF-8".into())
                    })?;

                let redirect_url = url
                    .join(location)
                    .map_err(|e| CarapaceError::InvalidRedirect(e.to_string()))?;

                info!("redirect {} → {}", url, redirect_url);
                self.validate_url(&redirect_url)?;
                return self.fetch_url(redirect_url, redirect_depth + 1).await;
            }

            // ── Read body with size limit ─────────────────────────────────────
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/html")
                .to_string();

            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.to_string(), vs.to_string())))
                .collect();

            let final_url = response.url().clone();
            let max_size = self.options.max_size.unwrap_or(DEFAULT_MAX_SIZE);
            let body = read_limited(response, max_size).await?;

            info!(
                "fetched {} — status={} size={} bytes",
                final_url,
                status,
                body.len()
            );

            Ok(FetchResult { url: final_url, status, headers, body, content_type })
        })
    }
}

/// Stream-read a response up to `max_bytes`.
async fn read_limited(response: Response, max_bytes: u64) -> Result<Bytes> {
    if let Some(len) = response.content_length() {
        if len > max_bytes {
            warn!("Content-Length {} exceeds limit {}", len, max_bytes);
            return Err(CarapaceError::DecompressionBomb);
        }
    }

    let mut buf = bytes::BytesMut::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            warn!("response exceeded {} byte limit mid-stream", max_bytes);
            return Err(CarapaceError::DecompressionBomb);
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_block_private() {
        assert!(FetchOptions::default().block_private_ips);
    }

    #[tokio::test]
    async fn rejects_private_ip_url() {
        let fetcher = SafeFetcher::new(FetchOptions::default()).unwrap();
        assert!(matches!(
            fetcher.fetch("http://192.168.1.1/").await,
            Err(CarapaceError::Ssrf(_))
        ));
    }

    #[tokio::test]
    async fn rejects_loopback_url() {
        let fetcher = SafeFetcher::new(FetchOptions::default()).unwrap();
        assert!(matches!(
            fetcher.fetch("http://127.0.0.1/").await,
            Err(CarapaceError::Ssrf(_))
        ));
    }

    #[tokio::test]
    async fn rejects_credentials_in_url() {
        let fetcher = SafeFetcher::new(FetchOptions::default()).unwrap();
        assert!(matches!(
            fetcher.fetch("https://user:pass@example.com/").await,
            Err(CarapaceError::Ssrf(_))
        ));
    }
}
