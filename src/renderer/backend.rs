/// Headless browser rendering backend.
///
/// Tries Chromium first (best CSS fidelity — supports custom properties,
/// modern grid/flexbox). Falls back to wkhtmltoimage if Chromium is absent.
///
/// JavaScript is ENABLED in the browser to allow dynamic content to render
/// (ClickFix overlays, SocGholish dialogs, drainer modals).  Network
/// isolation is maintained via `--proxy-server=socks5://127.0.0.1:1` — all
/// HTTP/HTTPS requests return ECONNREFUSED and no data leaves the machine.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{info, warn};

/// When the caller requests full-page capture (height == 0), Chromium renders
/// at this viewport height.  Trailing blank rows are then trimmed by
/// `trim_bottom_whitespace()`.  8000 px captures all but the most extreme
/// pages; content beyond this is exceedingly rare in real-world sites.
const FULL_PAGE_SENTINEL_H: u32 = 8000;

/// Minimum retained height after trimming.  Prevents cropping a short but
/// legitimate page (404, landing page, redirect stub) to a near-zero sliver.
const MIN_SCREENSHOT_H: u32 = 400;

use crate::error::{CarapaceError, Result};

/// Render `html_path` to `output_path` (PNG) using the best available backend.
/// Returns the list of URLs that JavaScript attempted to fetch at runtime.
pub fn render_to_png(
    html_path: &Path,
    output_path: &Path,
    width: u32,
    height: u32,
) -> Result<Vec<String>> {
    if chromium_available() {
        info!("rendering with Chromium (JS enabled, network isolated)");
        match render_chromium(html_path, output_path, width, height) {
            Ok(intercepted) => return Ok(intercepted),
            Err(e) => warn!("Chromium render failed, trying wkhtmltoimage: {}", e),
        }
    }
    if wkhtmltoimage_available() {
        info!("rendering with wkhtmltoimage (JS disabled)");
        render_wkhtmltoimage(html_path, output_path, width)?;
        return Ok(vec![]);
    }
    Err(CarapaceError::Render(
        "no headless browser found (install chromium or wkhtmltopdf)".into(),
    ))
}

// ── Logging proxy ─────────────────────────────────────────────────────────────

/// A minimal HTTP/CONNECT logging proxy that records every URL Chromium
/// attempts to reach and immediately rejects the connection.
///
/// This replaces the silent dead-socks5 proxy.  Network isolation is
/// maintained (all requests still fail), but we now capture the list of
/// URLs that JavaScript tried to fetch — the evidence set for dynamic
/// attacks like SocGholish payload retrieval.
struct LoggingProxy {
    port: u16,
    intercepted: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl LoggingProxy {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind logging proxy");
        let port = listener.local_addr().expect("no local addr").port();
        listener.set_nonblocking(true).ok();

        let intercepted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

        let intercepted_clone = Arc::clone(&intercepted);
        let stop_clone = Arc::clone(&stop);

        std::thread::spawn(move || {
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        handle_proxy_connection(&mut stream, &intercepted_clone);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { port, intercepted, stop }
    }

    fn proxy_arg(&self) -> String {
        format!("--proxy-server=http://127.0.0.1:{}", self.port)
    }

    fn collect(self) -> Vec<String> {
        // Signal the proxy thread to stop, allow brief drain for in-flight connections
        self.stop.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(50));

        let urls = self.intercepted.lock().unwrap().clone();
        // Deduplicate by domain and cap at 50 entries for the finding
        dedup_by_domain(urls)
    }
}

fn handle_proxy_connection(stream: &mut TcpStream, intercepted: &Mutex<Vec<String>>) {
    stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let mut buf = [0u8; 512];
    if let Ok(n) = stream.read(&mut buf) {
        let req = String::from_utf8_lossy(&buf[..n]);
        if let Some(target) = extract_proxy_target(&req) {
            if !is_known_good_domain(&target) {
                let mut urls = intercepted.lock().unwrap();
                if urls.len() < 100 {
                    urls.push(target);
                }
            }
        }
    }
    // Reject the connection.  For CONNECT (HTTPS): 503.  For plain HTTP: also 503.
    let _ = stream.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn extract_proxy_target(request: &str) -> Option<String> {
    let first = request.lines().next()?;
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT hostname:port HTTP/1.1 — extract hostname
        let host = target.split(':').next().unwrap_or(target);
        Some(format!("https://{}", host))
    } else if target.starts_with("http") {
        // GET http://hostname/path HTTP/1.1
        Some(target.to_string())
    } else {
        None
    }
}

/// Known-good analytics, CDN, and ad-tech domains that are ubiquitous on
/// legitimate sites — intercepting requests to these adds noise, not signal.
fn is_known_good_domain(url: &str) -> bool {
    const SKIP: &[&str] = &[
        "google-analytics.com",
        "googletagmanager.com",
        "googlesyndication.com",
        "doubleclick.net",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "jquery.com",
        "unpkg.com",
        "jsdelivr.net",
        "facebook.com",
        "connect.facebook.net",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "youtube.com",
        "ytimg.com",
        "bing.com",
        "microsoft.com",
        "hotjar.com",
        "intercom.io",
        "segment.com",
        "mixpanel.com",
        "amplitude.com",
        "sentry.io",
        "cloudflare.com",
        "cloudflareinsights.com",
        "stripe.com",
        "js.stripe.com",
        "paypal.com",
        "recaptcha.net",
        "gstatic.com",
    ];
    for skip in SKIP {
        if url.contains(skip) {
            return true;
        }
    }
    false
}

fn dedup_by_domain(urls: Vec<String>) -> Vec<String> {
    let mut seen_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for url in urls {
        // Extract domain as dedup key
        let domain = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(&url)
            .to_string();
        if seen_domains.insert(domain) {
            out.push(url);
            if out.len() >= 50 {
                break;
            }
        }
    }
    out
}

// ── Chromium ──────────────────────────────────────────────────────────────────

fn chromium_available() -> bool {
    for name in &["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        if which_exists(name) {
            return true;
        }
    }
    false
}

fn chromium_cmd() -> &'static str {
    for name in &["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        if which_exists(name) {
            return name;
        }
    }
    "chromium"
}

fn render_chromium(
    html_path: &Path,
    output_path: &Path,
    width: u32,
    height: u32,  // 0 = full-page: use FULL_PAGE_SENTINEL_H, then trim whitespace
) -> Result<Vec<String>> {
    let full_page = height == 0;
    let render_h  = if full_page { FULL_PAGE_SENTINEL_H } else { height };

    let file_url = format!("file://{}", html_path.display());
    let screenshot_arg = format!("--screenshot={}", output_path.display());
    let window_size = format!("--window-size={},{}", width, render_h);

    // Start the logging proxy — replaces the silent dead-socks5.
    // All requests still fail (connection refused immediately), but we
    // record the attempted URLs so callers can surface them as findings.
    let proxy = LoggingProxy::start();
    let proxy_arg = proxy.proxy_arg();

    let out = Command::new(chromium_cmd())
        .args([
            "--headless=new",
            // JavaScript is ENABLED — the dead proxy prevents exfiltration.
            // Without JS, dynamic overlays (ClickFix, SocGholish, drainers)
            // never render and would be invisible in the screenshot and DOM.
            "--no-sandbox",
            "--disable-gpu",
            "--use-angle=swiftshader",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--no-first-run",
            "--hide-scrollbars",
            // Suppress the `navigator.webdriver = true` flag and related
            // automation indicators so that evasive scripts actually execute
            // their attack path rather than their clean-for-scanner path.
            "--disable-blink-features=AutomationControlled",
            // Spoof a Windows 10 Chrome user-agent so that ClickFix, SocGholish,
            // and other Windows-targeted campaigns see a plausible victim browser
            // rather than a Linux headless instance and skip their delivery logic.
            // navigator.platform is overridden in the injected bootstrap script
            // (see HtmlInliner::build_self_contained) for JS-level OS checks.
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            // Virtual time budget: allow CSS transitions and JS timers up to
            // 5s to settle before the screenshot is taken — catches attacks
            // that delay their overlay by a short timeout to evade scanners.
            "--virtual-time-budget=5000",
            // Ensure all compositor stages (layout, paint, compositing) complete
            // before the screenshot is captured, preventing blank/partial renders
            // on slow-rendering pages.
            "--run-all-compositor-stages-before-draw",
            // Network isolation: route all requests through our logging proxy.
            // It records attempted URLs and immediately rejects connections.
            &proxy_arg,
            "--disable-remote-fonts",
            "--force-color-profile=srgb",
            &window_size,
            &screenshot_arg,
            &file_url,
        ])
        .output()
        .map_err(|e| CarapaceError::Render(format!("chromium launch: {}", e)))?;

    // Collect URLs the page attempted to reach at runtime.
    let intercepted = proxy.collect();

    if output_path.exists() {
        let size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
        info!("chromium screenshot saved ({} bytes)", size);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.trim().is_empty() {
            for line in stderr.lines().take(5) {
                warn!("chromium: {}", line);
            }
        }
        // Full-page mode: trim trailing blank (white) rows produced by the
        // oversized sentinel viewport so the delivered image matches the actual
        // page height rather than being padded with 7 000+ px of whitespace.
        if full_page {
            trim_bottom_whitespace(output_path);
        }
        Ok(intercepted)
    } else {
        Err(CarapaceError::Render(format!(
            "chromium exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .take(5)
                .collect::<Vec<_>>()
                .join(" | ")
        )))
    }
}

// ── Full-page whitespace trim ─────────────────────────────────────────────────

/// Trim trailing blank rows from a PNG produced with a tall sentinel viewport.
///
/// Scans rows from the bottom and considers a row blank when every pixel has
/// R, G, B ≥ 250 (near-white tolerance covers sub-pixel anti-aliasing at page
/// borders).  Adds 20 px of padding below the last content row so text at the
/// very bottom isn't visually clipped.  Enforces `MIN_SCREENSHOT_H` as a
/// lower bound so trivially short pages (404s, blanks) keep a sensible height.
///
/// Overwrites the file in place.  Failures are logged and never propagate.
fn trim_bottom_whitespace(path: &Path) {
    use image::GenericImageView as _;

    let img = match image::open(path) {
        Ok(i)  => i,
        Err(e) => { warn!("trim_bottom_whitespace: open {:?}: {}", path, e); return; }
    };

    let (w, h) = img.dimensions();
    let rgba = img.to_rgba8();

    // Walk rows from the bottom; stop at the first row containing a non-white pixel.
    let mut last_content_row = 0u32;
    'outer: for y in (0..h).rev() {
        for x in 0..w {
            let px = rgba.get_pixel(x, y);
            if px[0] < 250 || px[1] < 250 || px[2] < 250 {
                last_content_row = y;
                break 'outer;
            }
        }
    }

    let new_h = (last_content_row + 1 + 20).min(h).max(MIN_SCREENSHOT_H);

    if new_h >= h {
        info!("trim_bottom_whitespace: nothing to trim ({}px, content at {}px)", h, last_content_row);
        return;
    }

    let cropped = image::imageops::crop_imm(&rgba, 0, 0, w, new_h).to_image();
    match cropped.save(path) {
        Ok(())  => info!("trimmed screenshot {}px → {}px", h, new_h),
        Err(e)  => warn!("trim_bottom_whitespace: save {:?}: {}", path, e),
    }
}

// ── wkhtmltoimage ─────────────────────────────────────────────────────────────

fn wkhtmltoimage_available() -> bool {
    which_exists("wkhtmltoimage")
}

fn render_wkhtmltoimage(html_path: &Path, output_path: &Path, width: u32) -> Result<()> {
    let out = Command::new("wkhtmltoimage")
        .args([
            "--disable-javascript",
            "--width",
            &width.to_string(),
            "--format",
            "png",
            "--quality",
            "90",
            "--enable-local-file-access",
            &format!("file://{}", html_path.display()),
            &output_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| CarapaceError::Render(format!("wkhtmltoimage launch: {}", e)))?;

    if output_path.exists() {
        Ok(())
    } else {
        Err(CarapaceError::Render(format!(
            "wkhtmltoimage failed {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ")
        )))
    }
}

/// Run Chromium in `--dump-dom` mode to capture the fully-rendered post-JavaScript DOM.
///
/// The dump reflects page state after the `--virtual-time-budget=5000` ms clock expires —
/// overlays injected by `document.createElement` / `innerHTML` at load time or within the
/// first 5 seconds are captured.  This is the second pass of the CARAPACE-02 pipeline:
/// the screenshot pass (first) captures the visual; this pass captures the structural DOM
/// for injection diffing.
///
/// Returns the serialised DOM as a `String`.  Returns an empty string on any failure;
/// DOM-dump failure is non-fatal and does not affect the screenshot result.
pub fn dump_dom(html_path: &Path) -> String {
    if !chromium_available() {
        return String::new();
    }

    let file_url = format!("file://{}", html_path.display());

    // Run with the same network isolation as the screenshot pass — all requests still
    // fail, preventing any exfiltration during this second Chromium invocation.
    let proxy = LoggingProxy::start();
    let proxy_arg = proxy.proxy_arg();

    let result = Command::new(chromium_cmd())
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--use-angle=swiftshader",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--no-first-run",
            "--disable-blink-features=AutomationControlled",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "--virtual-time-budget=5000",
            "--run-all-compositor-stages-before-draw",
            &proxy_arg,
            "--dump-dom",
            &file_url,
        ])
        .output();

    // URLs from this pass are already captured by the screenshot pass; discard.
    let _ = proxy.collect();

    match result {
        Ok(out) => {
            let dom = String::from_utf8_lossy(&out.stdout).into_owned();
            info!("dump-dom: {} bytes", dom.len());
            dom
        }
        Err(e) => {
            warn!("dump-dom failed: {}", e);
            String::new()
        }
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

fn which_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
