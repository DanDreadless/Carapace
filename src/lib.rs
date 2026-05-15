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

    // ── LJS-05: Content-type gate ─────────────────────────────────────────────
    // If the fetched resource is not an HTML document, skip the full render
    // pipeline.  Feeding raw JS/CSS/JSON to Chromium executes it in a blank-page
    // context where async code never resolves — causing the process to hang.
    // Instead, run the OXC-based static JS analyser directly on the raw body and
    // return immediately.  `render_skipped: true` signals to the caller that no
    // screenshot was produced.
    if !fetch_result.content_type.contains("text/html") {
        info!(
            "non-HTML content-type {:?} — skipping render, running JS static analysis only",
            fetch_result.content_type,
        );
        if let Ok(source) = std::str::from_utf8(&fetch_result.body) {
            crate::js::analysis::analyse(source, base_url.as_str(), &mut report);
        }
        report.render_skipped = true;
        if args.threat_report {
            let report_path = args.output.with_extension("threat.json");
            let json = report.to_json()?;
            std::fs::write(&report_path, &json)?;
        }
        if args.output_format == OutputFormat::Json {
            let json = report.to_json()?;
            std::fs::write(&args.output, &json)?;
        }
        return Ok(report);
    }

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

    // ── 4.5. CSS overlay threat analysis ─────────────────────────────────────
    // Scan collected CSS (both <style> blocks and external sheets) for
    // fullscreen fixed-position overlays — the structural signature of
    // ClickFix fake-CAPTCHA and SocGholish browser-update injections.
    check_css_overlay_threat(&css_sheets, &mut report);

    // ── 5. Render ─────────────────────────────────────────────────────────────
    if args.output_format == OutputFormat::Png {
        if args.no_browser {
            // Fallback: built-in Rust renderer (approximate)
            rust_render(args, &page.dom, &css_sheets, &image_bytes, &mut report)?;
        } else {
            // Primary: headless browser (exact, JS enabled)
            browser_render(args, &page, &base_url, &css_sheets, &image_bytes, &mut report)?;
        }

        // CARAPACE-08: annotate screenshot(s) with risk badge.
        // Called after render so risk_score reflects all findings including DOM dump.
        let domain    = base_url.host_str().unwrap_or("unknown");
        let scan_time = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        if args.output.exists() {
            crate::renderer::annotate_screenshot(&args.output, report.risk_score, domain, &scan_time);
        }
        // Annotate mobile screenshot if it was produced.
        let mobile_path = args.output.with_extension("mobile.png");
        if mobile_path.exists() {
            crate::renderer::annotate_screenshot(&mobile_path, report.risk_score, domain, &scan_time);
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
    base_url: &url::Url,
    css_sheets: &[String],
    image_bytes: &HashMap<String, Vec<u8>>,
    report: &mut ThreatReport,
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

    // Pass 1: desktop screenshot.
    let screenshot_result = backend::render_to_png(&tmp_path, &args.output, args.width, args.height);

    // Pass 2: post-JS DOM dump (CARAPACE-02 — dynamic overlay detection).
    // Only run when the screenshot succeeded: confirms Chromium is available and
    // the page rendered.  The temp file must stay alive until all passes complete.
    let dumped_dom = if screenshot_result.is_ok() {
        backend::dump_dom(&tmp_path)
    } else {
        String::new()
    };

    // Pass 3: mobile viewport screenshot (CARAPACE-05).
    // Fixed at 375×844 (iPhone viewport ratio) — full-page mode produced
    // excessively tall captures on overlay-heavy phishing pages.
    // Non-fatal: a mobile render failure does not affect the desktop result.
    if args.mobile_screenshot && screenshot_result.is_ok() {
        let mobile_path = args.output.with_extension("mobile.png");
        let _ = backend::render_to_png(&tmp_path, &mobile_path, 375, 844);
    }

    // Clean up temp file after all passes.
    let _ = std::fs::remove_file(&tmp_path);

    // Surface any URLs that JavaScript attempted to fetch at runtime.
    // Filter out same-site requests (own domain / subdomains) — these are
    // normal WordPress REST API calls, lazy-load fetches, etc. and are not
    // evidence of C2 communication or payload retrieval.
    if let Ok(ref intercepted) = screenshot_result {
        let external: Vec<String> = intercepted
            .iter()
            .filter(|u| !is_same_site(&base_url, u))
            .cloned()
            .collect();
        if !external.is_empty() {
            report.add_intercepted_requests(&external);
        }
    }

    // Analyse the post-JS DOM for viewport-spanning overlays injected at runtime.
    if !dumped_dom.is_empty() {
        check_dynamic_overlay_injected(&self_contained_html, &dumped_dom, report);
    }

    screenshot_result.map(|_| ())
}

// ── CSS overlay threat analysis ───────────────────────────────────────────────

/// Returns true when `needle` appears in `haystack` as a standalone CSS
/// property — i.e. not as a suffix of another property name such as
/// `max-width` or `min-width`.  The character immediately before the match
/// must be a semicolon, ASCII whitespace, or the start of the string; a
/// hyphen or letter indicates the match is part of a longer property name.
pub(crate) fn standalone_prop(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let nlen = needle.len();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let prev_ok = abs == 0 || {
            let b = bytes[abs - 1];
            b == b';' || b.is_ascii_whitespace()
        };
        if prev_ok {
            return true;
        }
        start = abs + nlen;
    }
    false
}

/// Scan CSS (both `<style>` blocks and fetched external sheets) for the
/// fullscreen-overlay structural pattern used by ClickFix, SocGholish, and
/// ClearFake injections.
///
/// The canonical pattern: `position:fixed` + full viewport width + full
/// viewport height.  This creates a page-covering layer that blocks all
/// legitimate content behind a social-engineering prompt.
fn check_css_overlay_threat(css_sheets: &[String], report: &mut ThreatReport) {
    use regex::Regex;
    use std::sync::OnceLock;

    // Match a CSS declaration block (between braces), capturing selector + content.
    static BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    let block_re = BLOCK_RE.get_or_init(|| {
        Regex::new(r"(?s)\{([^{}]+)\}").unwrap()
    });

    static Z_RE: OnceLock<Regex> = OnceLock::new();
    let z_re = Z_RE.get_or_init(|| Regex::new(r"z-index\s*:\s*(-?\d+)").unwrap());

    static OPACITY_RE: OnceLock<Regex> = OnceLock::new();
    let opacity_re = OPACITY_RE.get_or_init(|| Regex::new(r"opacity\s*:\s*0?\.[0-9]").unwrap());

    // rgba() with fractional alpha — e.g. rgba(0,0,0,.7) or rgba(0,0,0,0.5).
    // A ClickFix overlay needs to fully obscure the page; any rgba() alpha < 1
    // means the overlay is a semi-transparent modal backdrop, not an attack layer.
    static RGBA_BACKDROP_RE: OnceLock<Regex> = OnceLock::new();
    let rgba_backdrop_re = RGBA_BACKDROP_RE.get_or_init(|| {
        Regex::new(r"rgba\s*\([^)]*,\s*0?\.[0-9]").unwrap()
    });

    for css in css_sheets {
        for caps in block_re.captures_iter(css) {
            let block = &caps[1];
            let lower = block.to_ascii_lowercase();

            // Must have position:fixed (or position:absolute for off-canvas attacks)
            let has_fixed = lower.contains("position:fixed")
                || lower.contains("position: fixed");
            if !has_fixed {
                continue;
            }

            // Must span full viewport width.
            // Use standalone_prop() to avoid matching max-width:100% or
            // min-width:100% — both contain "width:100%" as a substring
            // but represent a capped width, not a full-viewport width.
            let has_full_width = standalone_prop(&lower, "width:100%")
                || standalone_prop(&lower, "width: 100%")
                || lower.contains("width:100vw")
                || lower.contains("width: 100vw");

            // Must span full viewport height
            let has_full_height = standalone_prop(&lower, "height:100%")
                || standalone_prop(&lower, "height: 100%")
                || lower.contains("height:100vh")
                || lower.contains("height: 100vh");

            if !has_full_width || !has_full_height {
                continue;
            }

            // Suppress off-screen overlays — an element translated completely
            // off-screen (translate3d(±100%,...) or translateX(±100%)) is a
            // slide-in drawer or off-canvas menu, not a visible attack overlay.
            // ClickFix / SocGholish overlays are always fully on-screen.
            let is_offscreen = lower.contains("translate3d(-100%")
                || lower.contains("translate3d(100%")
                || lower.contains("translatex(-100%")
                || lower.contains("translatex(100%")
                || lower.contains("translate(-100%,")
                || lower.contains("translate(100%,");
            if is_offscreen {
                continue;
            }

            // Suppress hidden overlays — display:none and visibility:hidden both
            // indicate a modal/dialog that is not currently visible to the visitor.
            // Active ClickFix/SocGholish overlays are always visible.
            let is_hidden = lower.contains("display:none")
                || lower.contains("display: none")
                || lower.contains("visibility:hidden")
                || lower.contains("visibility: hidden");
            if is_hidden {
                continue;
            }

            // Suppress non-interactive overlays — pointer-events:none means the
            // element passes all mouse events through to underlying content.
            // A ClickFix overlay must capture clicks to socially engineer the visitor;
            // an overlay that cannot receive pointer events is decorative only.
            if lower.contains("pointer-events:none") || lower.contains("pointer-events: none") {
                continue;
            }

            // Capture z-index — used both for filtering and evidence quality.
            // Real ClickFix/SocGholish overlays use extreme z-index values
            // (typically 99999–2147483647) to guarantee they sit above every page
            // element. A value < 9999 means the overlay would be covered by other
            // stacking-context elements, making it useless as a social-engineering
            // prompt. Legitimate CSS frameworks use much lower values:
            //   Bootstrap 4 modal backdrop = 1040; Bootstrap dialog = 1050.
            //   Most cookie banners and plugins stay below 5000.
            // Raising the threshold to 9999 eliminates Bootstrap and all common
            // plugin z-indices while retaining every real attack pattern seen in
            // ClickFix and SocGholish campaigns.
            // Fire on overlays with no z-index (attacker omitted it — unusual but
            // possible when no competing stacking contexts exist on the page).
            let z_index = z_re
                .captures(&lower)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<i32>().ok());
            if let Some(z) = z_index {
                if z < 0 {
                    // Negative z-index: element is stacked behind page content and
                    // cannot obscure anything.  GitHub uses z-index:-1 on ::before
                    // pseudo-element backdrops for modal dialogs — these are CSS
                    // decoration, not attack overlays.
                    continue;
                }
                if z < 9999 {
                    continue;
                }
            }

            // Suppress semi-transparent backdrops (modal/lightbox backgrounds)
            // at any z-index. Plugins like WP Popup Maker legitimately use extreme
            // z-index values (e.g. 1999992) for their backdrop layer. A partially-
            // transparent rgba() overlay cannot fully obscure page content regardless
            // of z-index — it dims rather than hides. ClickFix attacks that rely on
            // social engineering need to fully block the page; a 70% opacity backdrop
            // alone does not accomplish that.
            let is_backdrop = opacity_re.is_match(&lower) || rgba_backdrop_re.is_match(&lower);
            if is_backdrop {
                continue;
            }

            // Require the overlay to have a visible background colour.
            // A ClickFix / SocGholish overlay must visually present a fake prompt
            // to the visitor — it cannot socially engineer anyone if it has no
            // background (a transparent fixed layer is invisible).  GDPR cookie
            // consent banners (Complianz, CookieYes, Borlabs) use the same
            // position:fixed + full-viewport structure but put the background colour
            // on an inner content element, leaving the outer container transparent.
            // Requiring an explicit background here eliminates these false positives
            // while keeping all known real ClickFix / SocGholish patterns (which
            // always define background or background-color on the overlay element).
            let has_background = lower.contains("background")
                && !lower.contains("background:none")
                && !lower.contains("background: none")
                && !lower.contains("background:transparent")
                && !lower.contains("background: transparent")
                // Also suppress background-color:transparent (longhand form).
                // AWS WAF challenge.js uses background-color:transparent on its
                // overlay container — the visible content is in child elements.
                && !lower.contains("background-color:transparent")
                && !lower.contains("background-color: transparent");
            if !has_background {
                continue;
            }

            // Suppress overlays whose background is set exclusively via a CSS custom
            // property (var(--...)).  Real ClickFix / SocGholish overlays always use
            // concrete colour values — they must control the exact visual appearance
            // to be convincing as fake CAPTCHA or browser-update dialogs.  CSS variable
            // backgrounds belong to SPA loading screens and CMS design-token themes.
            let has_only_css_var_bg = {
                let has_var = lower.contains("background:var(--") || lower.contains("background: var(--")
                    || lower.contains("background-color:var(--") || lower.contains("background-color: var(--");
                let has_concrete = lower.contains("background:#") || lower.contains("background: #")
                    || lower.contains("background:rgb") || lower.contains("background: rgb")
                    || lower.contains("background:hsl") || lower.contains("background: hsl")
                    || lower.contains("background:black") || lower.contains("background: black")
                    || lower.contains("background:white") || lower.contains("background: white")
                    || lower.contains("background-color:#") || lower.contains("background-color: #")
                    || lower.contains("background-color:rgb") || lower.contains("background-color: rgb");
                has_var && !has_concrete
            };
            if has_only_css_var_bg {
                continue;
            }

            // Normalise whitespace for a readable evidence snippet
            let snippet: String = block
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(300)
                .collect();

            let detail = match z_index {
                Some(z) => format!("position:fixed, width:100%/100vw, height:100%/100vh, z-index:{} — {}", z, snippet),
                None    => format!("position:fixed, width:100%/100vw, height:100%/100vh — {}", snippet),
            };

            report.add_css_overlay(&detail);
            return; // one finding per page is sufficient
        }
    }
}

// ── Dynamic overlay detection (CARAPACE-02) ───────────────────────────────────

/// Detect ClickFix / SocGholish / ClearFake overlays injected by JavaScript at runtime.
///
/// Strategy:
///   1. Scan the post-JS DOM dump for block-level elements with inline
///      `position:fixed` styles that span the full viewport (width+height 100%/vw/vh).
///   2. Apply the same guard conditions as `check_css_overlay_threat`:
///      high z-index, visible background, not hidden, not pointer-events:none,
///      not off-screen, no semi-transparent rgba backdrop.
///   3. Check whether the element is present in the original static HTML via
///      three fingerprints (id attribute → primary class → style prefix).
///      Elements that pass all overlay guards AND are absent from the static
///      source were injected by JavaScript — the defining mark of ClickFix,
///      SocGholish, and ClearFake.
///   4. Escalate to CRITICAL when a clipboard write was also detected (the
///      complete ClickFix attack chain: fake prompt + pre-loaded shell command).
fn check_dynamic_overlay_injected(
    static_html: &str,
    dumped_dom:  &str,
    report:      &mut ThreatReport,
) {
    use regex::Regex;
    use std::sync::OnceLock;

    // Match any block-level opening tag that carries an inline style attribute.
    // Groups: 1 = tag name, 2 = attrs area (between tag name and >), 3 = style value.
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)<([a-zA-Z][a-zA-Z0-9]*)([^>]*\bstyle\s*=\s*"([^"]{15,})"[^>]*)>"#
        ).unwrap()
    });

    static ID_RE: OnceLock<Regex> = OnceLock::new();
    let id_re = ID_RE.get_or_init(|| {
        Regex::new(r#"(?i)\bid\s*=\s*"([^"]{1,80})""#).unwrap()
    });

    static CLASS_RE: OnceLock<Regex> = OnceLock::new();
    let class_re = CLASS_RE.get_or_init(|| {
        Regex::new(r#"(?i)\bclass\s*=\s*"([^"]{1,200})""#).unwrap()
    });

    static Z_RE: OnceLock<Regex> = OnceLock::new();
    let z_re = Z_RE.get_or_init(|| Regex::new(r"z-index\s*:\s*(-?\d+)").unwrap());

    static RGBA_ALPHA_RE: OnceLock<Regex> = OnceLock::new();
    let rgba_alpha_re = RGBA_ALPHA_RE.get_or_init(|| {
        Regex::new(r"rgba\s*\([^)]*,\s*0?\.[0-9]").unwrap()
    });

    static OPACITY_RE: OnceLock<Regex> = OnceLock::new();
    let opacity_re = OPACITY_RE.get_or_init(|| {
        Regex::new(r"opacity\s*:\s*0?\.[0-9]").unwrap()
    });

    // Inline-only HTML elements that cannot realistically be fullscreen overlays.
    const INLINE_TAGS: &[&str] = &[
        "span", "a", "img", "input", "button", "label", "em", "strong",
        "i", "b", "small", "sup", "sub", "code", "abbr", "time", "select",
    ];

    let static_lower = static_html.to_ascii_lowercase();

    for cap in tag_re.captures_iter(dumped_dom) {
        let tag    = cap[1].to_ascii_lowercase();
        let attrs  = &cap[2]; // everything between tag name and closing >
        let style  = &cap[3];
        let full_tag = &cap[0]; // the complete <tag ... > string

        // Skip inline elements.
        if INLINE_TAGS.iter().any(|&t| t == tag.as_str()) {
            continue;
        }

        // Normalise style for gate checks.
        let compact: String = style
            .to_ascii_lowercase()
            .chars()
            .filter(|&c| c != ' ' && c != '\t' && c != '\n' && c != '\r')
            .collect();

        // Must be position:fixed (position:absolute has too many legitimate uses).
        if !compact.contains("position:fixed") {
            continue;
        }

        // Must span full viewport width.
        if !compact.contains("width:100%") && !compact.contains("width:100vw") {
            continue;
        }

        // Must span full viewport height.
        if !compact.contains("height:100%") && !compact.contains("height:100vh") {
            continue;
        }

        // Suppress hidden elements — not currently visible to the visitor.
        if compact.contains("display:none") || compact.contains("visibility:hidden") {
            continue;
        }

        // Suppress pointer-events:none — cannot capture user interaction.
        if compact.contains("pointer-events:none") {
            continue;
        }

        // Suppress off-screen elements (slide-in drawers, off-canvas menus).
        if compact.contains("left:-")
            || compact.contains("top:-")
            || compact.contains("translatex(-100%")
            || compact.contains("translate3d(-100%")
        {
            continue;
        }

        // z-index must be extreme (≥9999) or absent.  Below 9999 the overlay
        // would be covered by other stacking contexts (modals, Bootstrap, etc.).
        let z_index = z_re
            .captures(&compact)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<i32>().ok());
        if let Some(z) = z_index {
            if z < 0 || z < 9999 {
                continue;
            }
        }

        // Suppress semi-transparent backdrops — rgba() with fractional alpha or
        // opacity < 1 means the overlay dims rather than hides the page, which
        // is a modal/lightbox pattern, not an attack overlay.
        if rgba_alpha_re.is_match(style) || opacity_re.is_match(style) {
            continue;
        }

        // Must have an explicit opaque background — ClickFix/SocGholish overlays
        // always define one.  Transparent fixed layers cannot obscure page content.
        let has_bg = compact.contains("background")
            && !compact.contains("background:none")
            && !compact.contains("background:transparent")
            && !compact.contains("background-color:transparent");
        if !has_bg {
            continue;
        }

        // ── DOM diff: verify this element was NOT in the original static HTML ──
        //
        // ClickFix / SocGholish / ClearFake inject NEW elements via createElement.
        // Legitimate overlays (GDPR banners, modals, cookie notices) exist in the
        // static source and are merely made visible by JavaScript.
        //
        // Three fingerprints checked in order of reliability:
        //   (1) id attribute — most unique; strong discriminator
        //   (2) Primary CSS class — useful when no id is set
        //   (3) First 50 compact chars of the style value — catches purely
        //       inline-styled injections that carry neither id nor class
        let mut found_in_original = false;

        // (1) id fingerprint
        if let Some(id_cap) = id_re.captures(attrs) {
            let id_val = id_cap[1].to_ascii_lowercase();
            if !id_val.is_empty()
                && (static_lower.contains(&format!(r#"id="{id_val}""#))
                    || static_lower.contains(&format!(r#"id='{id_val}'"#)))
            {
                found_in_original = true;
            }
        }

        // (2) primary-class fingerprint
        if !found_in_original {
            if let Some(cls_cap) = class_re.captures(attrs) {
                let classes_lower = cls_cap[1].to_ascii_lowercase();
                if let Some(first) = classes_lower.split_whitespace().next() {
                    // Require the class name to be at least 4 chars — single-char
                    // or very short utility classes (Bootstrap "d", "w", etc.) are
                    // too common to be a reliable fingerprint.
                    if first.len() >= 4
                        && static_lower.contains(&format!("class=\"{first}"))
                    {
                        found_in_original = true;
                    }
                }
            }
        }

        // (3) style prefix fingerprint
        if !found_in_original {
            let style_fp: String = compact.chars().take(50).collect();
            if style_fp.len() >= 20 && static_lower.contains(&style_fp) {
                found_in_original = true;
            }
        }

        if found_in_original {
            continue;
        }

        // All gates passed and the element is absent from the original static HTML —
        // it was injected by JavaScript at runtime.
        let evidence: String = full_tag.chars().take(400).collect();
        let has_clipboard = report.has_flag_code("CLIPBOARD_HIJACK")
            || report.has_flag_code("CLIPBOARD_HIJACK_CLICKFIX");
        report.add_dynamic_overlay_injected(&evidence, has_clipboard);
        return; // one finding per page
    }
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

    // Suppress false positives: safe non-executable types (CSS, fonts, images, plain text)
    // served with Content-Disposition: attachment are harmless downloads, not malware delivery.
    if is_safe_content_type(&result.content_type) {
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

/// Returns `true` for MIME types that cannot execute code in a browser — CSS, fonts,
/// images, plain text.  A Content-Disposition: attachment on these is a benign download,
/// not a malware delivery vector.
fn is_safe_content_type(ct: &str) -> bool {
    let bare = ct.split(';').next().unwrap_or(ct).trim().to_ascii_lowercase();
    bare.starts_with("text/css")
        || bare.starts_with("text/plain")
        || bare.starts_with("image/")
        || bare.starts_with("font/")
        || bare.starts_with("audio/")
        || bare.starts_with("video/")
        || matches!(
            bare.as_str(),
            "application/font-woff"
                | "application/font-woff2"
                | "application/vnd.ms-fontobject"
                | "application/x-font-ttf"
                | "application/x-font-opentype"
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

/// Returns `true` when `intercepted_url` belongs to the same site as `base`.
///
/// Filters out own-domain requests (WordPress REST API calls, lazy-load XHR,
/// etc.) that are not evidence of external C2 or payload retrieval.
/// Matching is done on normalised hostname after stripping a leading `www.`:
/// subdomains of the base host are also considered same-site.
fn is_same_site(base: &url::Url, intercepted_url: &str) -> bool {
    let Ok(iurl) = url::Url::parse(intercepted_url) else { return false };
    let normalise = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_ascii_lowercase();
    match (base.host_str(), iurl.host_str()) {
        (Some(b), Some(i)) => {
            let bn = normalise(b);
            let iln = normalise(i);
            iln == bn || iln.ends_with(&format!(".{}", bn))
        }
        _ => false,
    }
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
