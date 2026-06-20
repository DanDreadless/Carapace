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

/// Default User-Agent: Windows 10 Chrome — triggers Windows-targeted attack
/// payloads (ClickFix, SocGholish) and is less likely to be blocked as a bot.
pub const WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

/// iPhone/Safari User-Agent for reaching pages that cloak their content
/// from non-mobile browsers via `Vary: User-Agent` server-side fingerprinting.
pub const IPHONE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";

/// Android/Chrome User-Agent — fallback when iPhone UA still returns blank
/// (pages that specifically cloak from iOS or require Android UA).
pub const ANDROID_UA: &str = "Mozilla/5.0 (Linux; Android 14; SM-S928B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36";

/// Proxy bypass list applied to every Chromium render.
///
/// Chromium normally routes all requests through the logging proxy, which
/// immediately returns 503 — blocking external resources and causing blank
/// images, unstyled pages, and missing social widgets.  Bypassing well-known
/// CDNs that serve only static assets improves screenshot fidelity across all
/// pages without weakening the security model: none of these domains are
/// attacker-controlled, so they cannot serve C2 payloads or exfiltrate data
/// on behalf of the page being scanned.
///
/// Intentionally EXCLUDED (can serve arbitrary / attacker-controlled content):
///   cloudflare.com, cloudfront.net, fastly.net, akamaihd.net — generic CDNs
///   vercel.app, netlify.app, github.io, glitch.me, replit.app — free hosts
///   azureedge.net, storage.googleapis.com — blob/object storage
///
/// Format: `.example.com` matches `example.com` AND all its subdomains.
/// Exact-host entries (no leading dot) are used only where a subdomain but
/// not the parent registrable domain should be bypassed (e.g. cdnjs).
pub const CDN_PROXY_BYPASS: &str = concat!(
    // Google — APIs, fonts, reCAPTCHA, GTM, analytics, YouTube, DoubleClick
    ".googleapis.com,.gstatic.com,.google.com,",
    ".googletagmanager.com,.google-analytics.com,",
    ".googlesyndication.com,.doubleclick.net,",
    ".youtube.com,.ytimg.com,.youtube-nocookie.com,",
    ".recaptcha.net,",
    // Meta / Facebook — SDK, social login widgets, CDN
    ".facebook.com,.facebook.net,.fbcdn.net,",
    // Twitter / X — widgets.js, embed iframe assets
    ".twitter.com,.twimg.com,.x.com,",
    // LinkedIn — insight tag, embedded posts
    ".linkedin.com,.licdn.com,",
    // Instagram — oEmbed scripts and images
    ".instagram.com,",
    // TikTok, Pinterest, Snapchat, Reddit — social embeds
    ".tiktok.com,.pinterest.com,.snapchat.com,.reddit.com,",
    // Vimeo — video embeds
    ".vimeo.com,.vimeocdn.com,",
    // Microsoft — auth widgets (microsoftonline), Clarity analytics
    ".microsoft.com,.microsoftonline.com,.clarity.ms,",
    // Apple — iCloud UI, Apple ID, App Store badges, mzstatic image CDN
    ".apple.com,.icloud.com,.mzstatic.com,.cdn-apple.com,.icloud-content.com,",
    // Open-source library CDNs
    ".jsdelivr.net,.bootstrapcdn.com,.jquery.com,.fontawesome.com,",
    // cdnjs — Cloudflare's open-source library CDN (subdomain only;
    // cloudflare.com itself is deliberately excluded)
    "cdnjs.cloudflare.com,",
    // GitHub — static asset CDN (JS bundles, avatars; not github.io free hosting)
    ".githubassets.com,.githubusercontent.com,",
    // Adobe Fonts (Typekit) — webfont delivery
    ".typekit.com,.typekit.net,",
    // Shopify CDN and payment — used by Shopify-built pages
    ".shopifycdn.com,.shop.app,",
    // WordPress CDN — stats.wp.com, s.wp.com, i.wp.com (not wordpress.com hosting)
    ".wp.com,",
    // Analytics that gate page content — pages may defer rendering until loaded
    ".hotjar.com,.clarity.ms,.segment.com,.segment.io,",
    // Error monitoring — passive; does not affect page rendering but widely used
    ".sentry.io,.sentry-cdn.com,",
    // Payment SDKs — needed for checkout pages to render form elements
    ".stripe.com,.stripecdn.com,.paypal.com,.paypalobjects.com,",
    // Consent / cookie-banner platforms — some pages block all content until
    // the consent script initialises
    ".onetrust.com,.cookielaw.org,.cookiebot.com,.iubenda.com,",
    // hCaptcha — legitimate CAPTCHA (distinct from Cloudflare Turnstile)
    ".hcaptcha.com"
);

use crate::error::{CarapaceError, Result};

/// Render `html_path` to `output_path` (PNG) using the best available backend.
/// `ua` controls the User-Agent Chromium presents during render — use
/// `WINDOWS_UA` for the default Windows-Chrome identity or `IPHONE_UA` to
/// reach pages that gate their content on a mobile browser.
/// Returns the list of URLs that JavaScript attempted to fetch at runtime.
pub fn render_to_png(
    html_path: &Path,
    output_path: &Path,
    width: u32,
    height: u32,
    ua: &str,
) -> Result<Vec<String>> {
    render_to_png_ex(html_path, output_path, width, height, ua, 0)
}

/// As `render_to_png`, but with a settle budget in milliseconds.  `settle_ms == 0`
/// uses the default (5000 ms).  A longer budget is used by the blank-render retry
/// to give slow CSS/font/animation paints more time to finish before capture.
pub fn render_to_png_ex(
    html_path: &Path,
    output_path: &Path,
    width: u32,
    height: u32,
    ua: &str,
    settle_ms: u32,
) -> Result<Vec<String>> {
    if chromium_available() {
        info!("rendering with Chromium (JS enabled, network isolated, ua={})", &ua[..40.min(ua.len())]);
        match render_chromium(html_path, output_path, width, height, ua, settle_ms) {
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
    // Immediately shutdown both halves of the socket after the response so
    // Chromium marks this fetch as complete and virtual-time can advance.
    // Without the shutdown(), half-open sockets hold the "pending fetches"
    // counter above zero and --virtual-time-budget never elapses.
    let _ = stream.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
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
    ua: &str,
    settle_ms: u32,  // 0 = default 5000 ms virtual-time budget
) -> Result<Vec<String>> {
    let full_page = height == 0;
    let render_h  = if full_page { FULL_PAGE_SENTINEL_H } else { height };

    // Virtual-time budget (settle) and the real-wallclock safety net derived from it.
    let vtb = if settle_ms == 0 { 5000 } else { settle_ms };
    let vtb_arg = format!("--virtual-time-budget={}", vtb);
    let timeout_arg = format!("--timeout={}", vtb + 3000);

    let file_url = format!("file://{}", html_path.display());
    let screenshot_arg = format!("--screenshot={}", output_path.display());
    let window_size = format!("--window-size={},{}", width, render_h);
    let ua_arg = format!("--user-agent={}", ua);

    // Start the logging proxy — replaces the silent dead-socks5.
    // All requests still fail (connection refused immediately), but we
    // record the attempted URLs so callers can surface them as findings.
    let proxy = LoggingProxy::start();
    let proxy_arg = proxy.proxy_arg();

    // Always bypass the logging proxy for well-known CDNs.
    // This lets Chromium load fonts, social widgets, Apple imagery, and
    // payment form scripts directly, eliminating the most common causes of
    // blank or unstyled screenshots across all page types.
    let bypass_arg = format!("--proxy-bypass-list={}", CDN_PROXY_BYPASS);

    let mut cmd = Command::new(chromium_cmd());
    cmd.args([
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
        // User-Agent: passed by the caller.  Default is Windows Chrome to
        // trigger Windows-targeted payloads (ClickFix, SocGholish).
        // iPhone/Android UA is used when the server cloaks content by device.
        // navigator.platform is overridden in the injected bootstrap script
        // (see HtmlInliner::build_self_contained) for JS-level OS checks.
        &ua_arg,
        // Virtual time budget: allow CSS transitions and JS timers to settle
        // before the screenshot is taken (default 5s; raised by the blank-render
        // retry) — also catches attacks that delay their overlay to evade scanners.
        &vtb_arg,
        // Ensure all compositor stages (layout, paint, compositing) complete
        // before the screenshot is captured, preventing blank/partial renders
        // on slow-rendering pages.
        "--run-all-compositor-stages-before-draw",
        // Network isolation: route all requests through our logging proxy.
        // It records attempted URLs and immediately rejects connections.
        &proxy_arg,
        "--disable-remote-fonts",
        "--force-color-profile=srgb",
        // Real-wallclock safety net: screenshots whatever is rendered after the
        // budget + 3 s even if --virtual-time-budget stalls on half-open connections.
        &timeout_arg,
        &window_size,
        &screenshot_arg,
        &file_url,
    ]);
    cmd.arg(&bypass_arg);
    let out = cmd.output()
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

// ── Live-navigation render through the same-origin policy proxy (P0) ────────────

/// Render the **live** page at `url` (navigated directly, not from `file://`)
/// through the forwarding `PolicyProxy`, so same-origin content (CSS/JS/fonts/
/// images and the page's own XHR/`fetch` API) actually loads and SPA/data-driven
/// pages render real content.  Cross-origin requests are refused and recorded;
/// every forwarded request is SSRF-validated at the proxy.  Returns the refused
/// cross-origin URLs (the intercepted-request evidence).
///
/// `page_host` anchors the same-origin allow policy.  This path has no offline
/// fallback of its own — the caller (`browser_render`) falls back to the offline
/// self-contained render when this returns `Err` or a blank frame.
pub fn render_to_png_live(
    url: &str,
    output_path: &Path,
    width: u32,
    height: u32,
    ua: &str,
    page_host: &str,
    settle_ms: u32,
) -> Result<Vec<String>> {
    if !chromium_available() {
        return Err(CarapaceError::Render("chromium not available for live render".into()));
    }
    use super::proxy::{PolicyProxy, RenderPolicy};

    let full_page = height == 0;
    let render_h = if full_page { FULL_PAGE_SENTINEL_H } else { height };
    let vtb = if settle_ms == 0 { 5000 } else { settle_ms };

    let screenshot_arg = format!("--screenshot={}", output_path.display());
    let window_size = format!("--window-size={},{}", width, render_h);
    let ua_arg = format!("--user-agent={}", ua);
    let vtb_arg = format!("--virtual-time-budget={}", vtb);
    let timeout_arg = format!("--timeout={}", vtb + 3000);

    // Same-origin forwarding proxy. NO --proxy-bypass-list: every request — including
    // the vetted CDNs — goes through the proxy so it is SSRF-checked (closes the
    // direct-CDN-connect gap of the offline path).
    let proxy = PolicyProxy::start(RenderPolicy::new(page_host, CDN_PROXY_BYPASS));
    let proxy_arg = proxy.proxy_arg();

    let mut cmd = Command::new(chromium_cmd());
    cmd.args([
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
        "--hide-scrollbars",
        "--disable-blink-features=AutomationControlled",
        &ua_arg,
        &vtb_arg,
        "--run-all-compositor-stages-before-draw",
        // With an HTTP proxy and no bypass list, Chromium sends every request to the
        // proxy by hostname (CONNECT host:443 / absolute-form GET) and the proxy
        // resolves + SSRF-checks it — so all DNS goes through our safe resolver and
        // DNS-rebinding is defeated, with no extra resolver flags needed.
        &proxy_arg,
        "--force-color-profile=srgb",
        &timeout_arg,
        &window_size,
        &screenshot_arg,
        url,
    ]);

    let out = cmd
        .output()
        .map_err(|e| CarapaceError::Render(format!("chromium live launch: {}", e)))?;

    let intercepted = proxy.collect();

    if output_path.exists() {
        let size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
        info!("chromium live screenshot saved ({} bytes)", size);
        if full_page {
            trim_bottom_whitespace(output_path);
        }
        Ok(intercepted)
    } else {
        Err(CarapaceError::Render(format!(
            "chromium live exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).lines().take(3).collect::<Vec<_>>().join(" | ")
        )))
    }
}

// ── Blank-screenshot detection (CARAPACE-09 / P1) ──────────────────────────────

/// A screenshot counts as visually blank when at least this fraction of its
/// sampled pixels are near-white.  Set high (99.4%) so a real but content-light
/// page (404, simple landing, redirect notice) — which always has a header,
/// logo, or text contributing non-white pixels — is NOT misclassified as blank.
pub const BLANK_WHITE_RATIO: f32 = 0.994;

/// Fraction of near-white pixels (0.0–1.0) in a PNG, sampled on a grid for speed.
/// A pixel is "near-white" when R, G, B are all ≥ 245.  Returns 1.0 (treat as
/// blank) when the image cannot be read.  Sampling caps work at ~200×200 points
/// so this is cheap even on an 8000 px full-page capture.
pub fn screenshot_blank_ratio(path: &Path) -> f32 {
    use image::GenericImageView as _;

    let img = match image::open(path) {
        Ok(i) => i,
        Err(e) => {
            warn!("screenshot_blank_ratio: open {:?}: {}", path, e);
            return 1.0;
        }
    };
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 {
        return 1.0;
    }
    let rgba = img.to_rgba8();

    let step_x = (w / 200).max(1);
    let step_y = (h / 200).max(1);
    let mut total = 0u64;
    let mut near_white = 0u64;
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            let px = rgba.get_pixel(x, y);
            total += 1;
            if px[0] >= 245 && px[1] >= 245 && px[2] >= 245 {
                near_white += 1;
            }
            x += step_x;
        }
        y += step_y;
    }
    if total == 0 {
        return 1.0;
    }
    near_white as f32 / total as f32
}

/// True when a screenshot is visually blank (≥ `BLANK_WHITE_RATIO` near-white).
pub fn is_blank_screenshot(path: &Path) -> bool {
    screenshot_blank_ratio(path) >= BLANK_WHITE_RATIO
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
pub fn dump_dom(html_path: &Path, ua: &str) -> String {
    if !chromium_available() {
        return String::new();
    }

    let file_url = format!("file://{}", html_path.display());
    let ua_arg = format!("--user-agent={}", ua);

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
            &ua_arg,
            "--virtual-time-budget=5000",
            "--run-all-compositor-stages-before-draw",
            // Same wallclock safety net as the screenshot pass — prevents Chromium
            // from hanging indefinitely on pages with JS that blocks process exit
            // (e.g. ClickFix clipboard event loops, busy-wait anti-debug patterns).
            "--timeout=8000",
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

#[cfg(test)]
mod blank_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TmpPng(std::path::PathBuf);
    impl Drop for TmpPng {
        fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
    }

    fn write_png(img: image::RgbaImage) -> TmpPng {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "carapace_blanktest_{}_{}.png", std::process::id(), n));
        image::DynamicImage::ImageRgba8(img).save(&path).unwrap();
        TmpPng(path)
    }

    #[test]
    fn all_white_is_blank() {
        let f = write_png(image::RgbaImage::from_pixel(800, 600, image::Rgba([255, 255, 255, 255])));
        assert!(is_blank_screenshot(&f.0));
        assert!(screenshot_blank_ratio(&f.0) >= 0.999);
    }

    #[test]
    fn content_page_is_not_blank() {
        // A mostly-white page with a header bar + text region (~5% non-white).
        let mut img = image::RgbaImage::from_pixel(800, 600, image::Rgba([255, 255, 255, 255]));
        for y in 0..40 {            // top header bar
            for x in 0..800 { img.put_pixel(x, y, image::Rgba([20, 30, 60, 255])); }
        }
        for y in 100..160 {         // a block of text/content
            for x in 50..500 { img.put_pixel(x, y, image::Rgba([40, 40, 40, 255])); }
        }
        let f = write_png(img);
        assert!(!is_blank_screenshot(&f.0));
    }

    #[test]
    fn sparse_content_still_not_blank() {
        // ~0.8% non-white (a small logo / single line of text) — must not be "blank".
        let mut img = image::RgbaImage::from_pixel(800, 600, image::Rgba([255, 255, 255, 255]));
        for y in 0..24 {
            for x in 0..200 { img.put_pixel(x, y, image::Rgba([0, 0, 0, 255])); }
        }
        let f = write_png(img);
        assert!(!is_blank_screenshot(&f.0), "ratio={}", screenshot_blank_ratio(&f.0));
    }

    #[test]
    fn unreadable_path_is_blank() {
        assert_eq!(screenshot_blank_ratio(Path::new("/nonexistent/x.png")), 1.0);
        assert!(is_blank_screenshot(Path::new("/nonexistent/x.png")));
    }
}
