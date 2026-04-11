/// Headless browser rendering backend.
///
/// Tries Chromium first (best CSS fidelity — supports custom properties,
/// modern grid/flexbox). Falls back to wkhtmltoimage if Chromium is absent.
///
/// Both are invoked with JavaScript fully disabled. The HTML fed to the
/// browser is already sanitised and has all external resources inlined as
/// data URIs, so the browser makes zero network requests.
use std::path::Path;
use std::process::Command;

use tracing::{info, warn};

use crate::error::{CarapaceError, Result};

/// Render `html_path` to `output_path` (PNG) using the best available backend.
pub fn render_to_png(html_path: &Path, output_path: &Path, width: u32) -> Result<()> {
    if chromium_available() {
        info!("rendering with Chromium (JS disabled)");
        match render_chromium(html_path, output_path, width) {
            Ok(()) => return Ok(()),
            Err(e) => warn!("Chromium render failed, trying wkhtmltoimage: {}", e),
        }
    }
    if wkhtmltoimage_available() {
        info!("rendering with wkhtmltoimage (JS disabled)");
        return render_wkhtmltoimage(html_path, output_path, width);
    }
    Err(CarapaceError::Render(
        "no headless browser found (install chromium or wkhtmltopdf)".into(),
    ))
}

// ── Chromium ──────────────────────────────────────────────────────────────────

fn chromium_available() -> bool {
    for name in &["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        if which_exists(name) { return true; }
    }
    false
}

fn chromium_cmd() -> &'static str {
    for name in &["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        if which_exists(name) { return name; }
    }
    "chromium"
}

fn render_chromium(html_path: &Path, output_path: &Path, width: u32) -> Result<()> {
    let file_url = format!("file://{}", html_path.display());
    let screenshot_arg = format!("--screenshot={}", output_path.display());
    let window_size = format!("--window-size={},900", width);

    let out = Command::new(chromium_cmd())
        .args([
            "--headless=new",
            "--disable-javascript",
            "--no-sandbox",
            "--disable-gpu",
            // Force software GL (SwiftShader/SwANGLE) so compositing works
            // without a real GPU. Without this, headless-new mode produces a
            // blank white screenshot when the GPU process is unavailable.
            "--use-angle=swiftshader",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--no-first-run",
            "--hide-scrollbars",
            // Network kill-switch: route all HTTP/HTTPS through a dead proxy.
            // file:// URLs are unaffected; all web requests get ECONNREFUSED.
            "--proxy-server=socks5://127.0.0.1:1",
            // Disable remote font loading as a second layer
            "--disable-remote-fonts",
            "--force-color-profile=srgb",
            &window_size,
            &screenshot_arg,
            &file_url,
        ])
        .output()
        .map_err(|e| CarapaceError::Render(format!("chromium launch: {}", e)))?;

    if output_path.exists() {
        let size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
        info!("chromium screenshot saved ({} bytes)", size);
        // Surface any warnings Chromium printed even on success.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.trim().is_empty() {
            for line in stderr.lines().take(5) {
                warn!("chromium: {}", line);
            }
        }
        Ok(())
    } else {
        Err(CarapaceError::Render(format!(
            "chromium exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).lines().take(5).collect::<Vec<_>>().join(" | ")
        )))
    }
}

// ── wkhtmltoimage ─────────────────────────────────────────────────────────────

fn wkhtmltoimage_available() -> bool { which_exists("wkhtmltoimage") }

fn render_wkhtmltoimage(html_path: &Path, output_path: &Path, width: u32) -> Result<()> {
    let out = Command::new("wkhtmltoimage")
        .args([
            "--disable-javascript",
            "--width", &width.to_string(),
            "--format", "png",
            "--quality", "90",
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
            String::from_utf8_lossy(&out.stderr).lines().take(3).collect::<Vec<_>>().join(" | ")
        )))
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

fn which_exists(name: &str) -> bool {
    Command::new("which").arg(name).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
