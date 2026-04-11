pub mod api;
pub mod cli;
pub mod css;
pub mod error;
pub mod fetcher;
pub mod html;
pub mod js;
pub mod layout;
pub mod renderer;
pub mod tech;
pub mod threat;

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use cli::{OutputFormat, RenderArgs};
use error::Result;
use fetcher::SafeFetcher;
use html::HtmlProcessor;
use html::inliner::HtmlInliner;
use js::JsProcessor;
use css::CssProcessor;
use layout::LayoutEngine;
use renderer::{ImageCache, Renderer};
use renderer::backend;
use threat::ThreatReport;

/// Top-level render pipeline.
///
/// Returns the completed `ThreatReport` so callers (CLI and API) can decide
/// how to surface it — the CLI writes it to disk, the API returns it inline.
pub async fn run(args: &RenderArgs) -> Result<ThreatReport> {
    let mut report = ThreatReport::new(&args.url);

    // ── 1. Fetch ───────────────────────────────────────────────────────────────
    info!("fetching {}", args.url);
    let fetcher = SafeFetcher::new(args.fetch_options())?;
    let fetch_result = fetcher.fetch(&args.url).await?;
    let base_url = fetch_result.url.clone();

    // Check for drive-by download on the primary URL.
    check_drive_by_download(&fetch_result, &mut report);

    // ── 2. Parse + sanitise HTML ───────────────────────────────────────────────
    info!("parsing HTML ({} bytes)", fetch_result.body.len());
    let html_processor = HtmlProcessor::new(base_url.clone());
    let mut page = html_processor.process(&fetch_result.body, &mut report)?;

    // Tech stack was detected pre-sanitisation inside HtmlProcessor::process.
    report.set_tech_stack(std::mem::take(&mut page.tech_stack));
    info!("framework: {:?}", page.framework);

    // ── 3. JS static analysis ─────────────────────────────────────────────────
    info!("analysing JS");
    let js_processor = JsProcessor::new(!args.no_js_sandbox);
    let _js_output = js_processor.process(&page, &mut report)?;

    // ── 4. Fetch sub-resources (CSS + images) unless --no-assets ──────────────
    // We always collect the raw fetched CSS bytes so we can inject them into
    // the self-contained HTML that the browser backend will render.
    let mut css_sheets: Vec<String> = page.styles.inline_styles.clone();
    let mut image_bytes: HashMap<String, Vec<u8>> = HashMap::new();

    if !args.no_assets {
        // CSS
        for sheet_url in &page.styles.external_sheets {
            match fetcher.fetch(sheet_url.as_str()).await {
                Ok(r) => {
                    check_drive_by_download(&r, &mut report);
                    if let Ok(s) = std::str::from_utf8(&r.body) {
                        css_sheets.push(s.to_string());
                    }
                }
                Err(e) => tracing::warn!("failed to fetch stylesheet {}: {}", sheet_url, e),
            }
        }

        // Images — collect raw bytes so the inliner can base64-encode them.
        let img_urls = collect_image_urls_from_dom(&page.dom, &base_url);
        info!("fetching {} images", img_urls.len());
        for (src_attr, resolved_url) in img_urls {
            match fetcher.fetch(resolved_url.as_str()).await {
                Ok(r) => {
                    check_drive_by_download(&r, &mut report);
                    image_bytes.insert(src_attr, r.body.to_vec());
                }
                Err(e) => tracing::warn!("failed to fetch image {}: {}", resolved_url, e),
            }
        }
    }

    // ── 5. Render ─────────────────────────────────────────────────────────────
    if args.output_format == OutputFormat::Png {
        if args.no_browser {
            // Fallback: built-in Rust renderer (approximate)
            rust_render(args, &page.dom, &css_sheets, &image_bytes, &mut report)?;
        } else {
            // Primary: headless browser (exact)
            browser_render(args, &page, &css_sheets, &image_bytes)?;
        }
    }

    // ── 6. Write threat report ────────────────────────────────────────────────
    if args.threat_report {
        let report_path = args.output.with_extension("threat.json");
        let json = report.to_json()?;
        std::fs::write(&report_path, &json)?;
        info!("threat report written to {}", report_path.display());
    }

    if args.output_format == OutputFormat::Json {
        let json = report.to_json()?;
        std::fs::write(&args.output, &json)?;
        info!("JSON output written to {}", args.output.display());
    }

    Ok(report)
}

// ── Browser render path ───────────────────────────────────────────────────────

fn browser_render(
    args: &RenderArgs,
    page: &html::ProcessedHtml,
    css_sheets: &[String],
    image_bytes: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    // Build a fully self-contained HTML file: inline CSS + images.
    let inliner = HtmlInliner::new(css_sheets.to_vec(), image_bytes.clone());
    let self_contained_html = inliner.build_self_contained(&page.dom);

    // Write to a temp file with a non-predictable name.
    let tmp_path = std::env::temp_dir().join(format!(
        "carapace_{}_{}.html",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    ));

    std::fs::write(&tmp_path, self_contained_html.as_bytes())
        .map_err(|e| crate::error::CarapaceError::Io(e))?;

    info!("self-contained HTML written to {} ({} bytes)", tmp_path.display(), self_contained_html.len());

    let result = backend::render_to_png(&tmp_path, &args.output, args.width);

    // Always clean up the temp file.
    let _ = std::fs::remove_file(&tmp_path);

    result
}

// ── Fallback Rust renderer ────────────────────────────────────────────────────

fn rust_render(
    args: &RenderArgs,
    dom: &markup5ever_rcdom::RcDom,
    css_sheets: &[String],
    image_bytes: &HashMap<String, Vec<u8>>,
    _report: &mut ThreatReport,
) -> Result<()> {
    // Decode image bytes into DynamicImages for the Rust renderer.
    let image_cache: ImageCache = image_bytes
        .iter()
        .filter_map(|(k, v)| decode_image(v).map(|img| (k.clone(), img)))
        .collect();

    let css_processor = CssProcessor::new();
    let (style_map, _vars) = css_processor.process_sheets(css_sheets)?;

    let dom_snapshot = html::rcdom_to_snapshot(dom);

    let layout_engine = LayoutEngine::new(args.width, args.height);
    let layout_tree = layout_engine.compute(&dom_snapshot, &style_map)?;

    let renderer = Renderer::new(args.width, args.height);
    renderer.render_png(&layout_tree, &args.output, &image_cache)?;
    Ok(())
}

// ── Image collection (from raw RcDom) ────────────────────────────────────────

fn collect_image_urls_from_dom(
    dom: &markup5ever_rcdom::RcDom,
    base_url: &url::Url,
) -> Vec<(String, url::Url)> {
    let mut out = Vec::new();
    collect_img_inner(&dom.document, base_url, &mut out);
    // Deduplicate by resolved URL so we don't fetch the same image twice.
    out.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()));
    out.dedup_by(|a, b| a.1 == b.1);
    out
}

fn collect_img_inner(
    handle: &markup5ever_rcdom::Handle,
    base_url: &url::Url,
    out: &mut Vec<(String, url::Url)>,
) {
    use markup5ever_rcdom::NodeData;
    if let NodeData::Element { name, attrs, .. } = &handle.data {
        if name.local.as_ref().eq_ignore_ascii_case("img") {
            let attrs_ref = attrs.borrow();
            if let Some(src) = attrs_ref.iter().find_map(|a| {
                if a.name.local.as_ref().eq_ignore_ascii_case("src") {
                    Some(a.value.as_ref().to_string())
                } else {
                    None
                }
            }) {
                if !src.starts_with("data:") {
                    if let Ok(url) = base_url.join(&src) {
                        out.push((src, url));
                    }
                }
            }
        }
    }
    for child in handle.children.borrow().iter() {
        collect_img_inner(child, base_url, out);
    }
}

// ── Image decoding (for Rust fallback renderer) ───────────────────────────────

fn decode_image(bytes: &[u8]) -> Option<image::DynamicImage> {
    let is_svg = bytes.starts_with(b"<svg")
        || bytes.starts_with(b"<?xml")
        || bytes.windows(4).any(|w| w == b"<svg");

    if is_svg {
        return rasterise_svg(bytes);
    }
    image::load_from_memory(bytes).ok()
}

// ── Drive-by download detection ───────────────────────────────────────────────

/// Inspect a `FetchResult` for auto-download signals.
///
/// Triggers when:
/// - `Content-Disposition` header contains `attachment`, OR
/// - The MIME type is a known executable/archive type that browsers auto-save.
///
/// If triggered: computes SHA256 of the body, extracts the filename hint, and
/// records a `DRIVE_BY_DOWNLOAD` flag at Critical severity.  The body is never
/// written to disk by this function.
fn check_drive_by_download(result: &fetcher::FetchResult, report: &mut ThreatReport) {
    let content_disposition = result
        .headers
        .get("content-disposition")
        .map(|v| v.as_str())
        .unwrap_or("");

    let is_attachment = content_disposition
        .to_ascii_lowercase()
        .contains("attachment");

    let is_download_mime = is_download_content_type(&result.content_type);

    if !is_attachment && !is_download_mime {
        return;
    }

    let sha256 = compute_sha256(&result.body);
    let filename = extract_filename(content_disposition, &result.url);
    let size = result.body.len() as u64;

    warn!(
        "drive-by download detected: {:?} ({}) {} bytes — SHA256: {}",
        filename, result.content_type, size, sha256
    );

    report.add_drive_by_download(&filename, &sha256, &result.content_type, size);
}

/// Returns `true` for MIME types that would trigger a browser save-file dialog
/// or silently download to the user's Downloads folder.
fn is_download_content_type(ct: &str) -> bool {
    // Strip parameters (e.g. "; charset=utf-8")
    let bare = ct.split(';').next().unwrap_or(ct).trim().to_ascii_lowercase();
    matches!(
        bare.as_str(),
        "application/octet-stream"
            | "application/zip"
            | "application/x-zip-compressed"
            | "application/x-rar-compressed"
            | "application/x-7z-compressed"
            | "application/x-tar"
            | "application/gzip"
            | "application/x-gzip"
            | "application/x-bzip2"
            | "application/x-xz"
            | "application/x-msdownload"
            | "application/x-msdos-program"
            | "application/vnd.microsoft.portable-executable"
            | "application/x-executable"
            | "application/x-elf"
            | "application/x-sh"
            | "application/x-bat"
            | "application/java-archive"
            | "application/vnd.android.package-archive"
            | "application/x-apple-diskimage"
            | "application/x-iso9660-image"
    )
}

/// Compute the hex-encoded SHA256 digest of `bytes`.
fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Extract a human-readable filename from the response.
///
/// Priority:
/// 1. `Content-Disposition: attachment; filename="foo.exe"` (RFC 6266)
/// 2. Last path segment of the URL
/// 3. `"unknown"`
fn extract_filename(content_disposition: &str, url: &url::Url) -> String {
    // Try RFC 6266 filename= parameter (handles both quoted and unquoted forms).
    let cd_lower = content_disposition.to_ascii_lowercase();
    if let Some(pos) = cd_lower.find("filename=") {
        let after = &content_disposition[pos + "filename=".len()..].trim_start();
        let name = after
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        if !name.is_empty() {
            return name.to_string();
        }
    }

    // Fall back to the last non-empty URL path segment.
    if let Some(segment) = url.path_segments().and_then(|mut s| s.next_back()) {
        if !segment.is_empty() {
            return segment.to_string();
        }
    }

    "unknown".to_string()
}

fn rasterise_svg(bytes: &[u8]) -> Option<image::DynamicImage> {
    let svg_str = std::str::from_utf8(bytes).ok()?;
    let tree = usvg::Tree::from_str(svg_str, &usvg::Options::default()).ok()?;
    let size = tree.size();
    let (w, h) = (size.width() as u32, size.height() as u32);
    if w == 0 || h == 0 { return None; }
    let mut pixmap = resvg::tiny_skia::Pixmap::new(w, h)?;
    resvg::render(&tree, resvg::tiny_skia::Transform::identity(), &mut pixmap.as_mut());
    let raw = pixmap.data();
    let mut rgba = image::RgbaImage::new(w, h);
    for (i, pixel) in rgba.pixels_mut().enumerate() {
        let off = i * 4;
        let (r, g, b, a) = (raw[off], raw[off+1], raw[off+2], raw[off+3]);
        let u = |c: u8| if a == 0 { 0 } else { (c as u32 * 255 / a as u32).min(255) as u8 };
        *pixel = image::Rgba([u(r), u(g), u(b), a]);
    }
    Some(image::DynamicImage::ImageRgba8(rgba))
}
