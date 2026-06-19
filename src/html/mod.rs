pub mod inliner;
pub mod sanitizer;

use std::io::Cursor;

use indexmap::IndexMap;

use html5ever::{driver::ParseOpts, parse_document, tendril::TendrilSink};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use tracing::debug;
use url::Url;

use crate::error::{CarapaceError, Result};
use crate::tech::TechDetection;
use crate::threat::ThreatReport;
use sanitizer::Sanitizer;

/// Which JS framework (if any) was detected on the page.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Framework {
    React,
    Vue,
    Angular,
    Svelte,
    NextJs,
    Nuxt,
    Unknown,
}

/// Collected inline `<script>` blocks and external script URLs.
#[derive(Debug, Default)]
pub struct ScriptInventory {
    pub inline_scripts: Vec<String>,
    pub external_scripts: Vec<Url>,
}

/// Collected stylesheet references.
#[derive(Debug, Default)]
pub struct StyleInventory {
    pub inline_styles: Vec<String>,
    pub external_sheets: Vec<Url>,
}

/// The output of the HTML processing stage.
/// RcDom does not implement Debug, so we provide a manual impl.
pub struct ProcessedHtml {
    pub dom: RcDom,
    pub base_url: Url,
    pub framework: Framework,
    /// Full tech stack detected from the pre-sanitisation DOM.
    pub tech_stack: Vec<TechDetection>,
    pub scripts: ScriptInventory,
    pub styles: StyleInventory,
}

impl std::fmt::Debug for ProcessedHtml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessedHtml")
            .field("base_url", &self.base_url)
            .field("framework", &self.framework)
            .finish_non_exhaustive()
    }
}

pub struct HtmlProcessor {
    base_url: Url,
}

impl HtmlProcessor {
    pub fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    /// Parse, sanitise, and inventory a raw HTML byte slice.
    pub fn process(&self, html_bytes: &[u8], report: &mut ThreatReport) -> Result<ProcessedHtml> {
        // Wrap in Cursor so we have a &mut Read without needing mut binding on the slice.
        let mut cursor = Cursor::new(html_bytes);

        let dom = parse_document(RcDom::default(), ParseOpts::default())
            .from_utf8()
            .read_from(&mut cursor)
            .map_err(|e| CarapaceError::HtmlParse(e.to_string()))?;

        // Collect scripts & styles *before* sanitising (sanitiser removes them).
        let mut scripts = ScriptInventory::default();
        let mut styles = StyleInventory::default();
        collect_resources(&dom.document, &self.base_url, &mut scripts, &mut styles);

        let framework = detect_framework(&dom.document, &scripts);
        debug!("framework detected: {:?}", framework);

        // Detect tech stack BEFORE sanitisation — the sanitiser removes custom
        // elements (e.g. <app-root ng-version="…">) and non-standard attributes
        // (hx-*, x-data, wire:*) that carry framework fingerprints.
        let tech_stack = crate::tech::detect(
            &dom.document,
            &scripts.external_scripts,
            &scripts.inline_scripts,
            &styles.external_sheets,
        );
        debug!("tech_stack: {} technologies detected", tech_stack.len());

        // Browser-in-the-Browser detection runs on the intact pre-sanitisation DOM
        // (the sanitiser strips iframes/attributes the detector relies on).
        detect_bitb(&dom.document, &self.base_url, report);

        let mut sanitizer = Sanitizer::new(Some(self.base_url.clone()), report);
        sanitizer.sanitize(&dom);

        Ok(ProcessedHtml {
            dom,
            base_url: self.base_url.clone(),
            framework,
            tech_stack,
            scripts,
            styles,
        })
    }
}

// ── Resource collection ───────────────────────────────────────────────────────

fn collect_resources(
    handle: &Handle,
    base_url: &Url,
    scripts: &mut ScriptInventory,
    styles: &mut StyleInventory,
) {
    if let NodeData::Element { name, attrs, .. } = &handle.data {
        let tag = name.local.as_ref().to_ascii_lowercase();
        let attrs_ref = attrs.borrow();

        match tag.as_str() {
            "script" => {
                if let Some(src) = get_attr(&attrs_ref, "src") {
                    if let Ok(url) = base_url.join(&src) {
                        scripts.external_scripts.push(url);
                    }
                } else {
                    let text = collect_text(handle);
                    if !text.trim().is_empty() {
                        scripts.inline_scripts.push(text);
                    }
                }
            }
            "style" => {
                let text = collect_text(handle);
                if !text.trim().is_empty() {
                    styles.inline_styles.push(text);
                }
            }
            "link" => {
                let rel = get_attr(&attrs_ref, "rel")
                    .map(|r| r.to_ascii_lowercase())
                    .unwrap_or_default();
                if rel == "stylesheet" {
                    if let Some(href) = get_attr(&attrs_ref, "href") {
                        if let Ok(url) = base_url.join(&href) {
                            styles.external_sheets.push(url);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for child in handle.children.borrow().iter() {
        collect_resources(child, base_url, scripts, styles);
    }
}

// ── Framework detection ───────────────────────────────────────────────────────

fn detect_framework(document: &Handle, scripts: &ScriptInventory) -> Framework {
    for url in &scripts.external_scripts {
        let path = url.path().to_ascii_lowercase();
        if path.contains("react") || path.contains("react-dom") {
            return Framework::React;
        }
        if path.contains("/vue") {
            return Framework::Vue;
        }
        if path.contains("angular") {
            return Framework::Angular;
        }
        if path.contains("svelte") {
            return Framework::Svelte;
        }
        if path.contains("_next/static") {
            return Framework::NextJs;
        }
        if path.contains("/_nuxt") {
            return Framework::Nuxt;
        }
    }

    for script in &scripts.inline_scripts {
        if script.contains("__NEXT_DATA__") {
            return Framework::NextJs;
        }
        if script.contains("__NUXT__") {
            return Framework::Nuxt;
        }
        if script.contains("React.createElement") || script.contains("ReactDOM") {
            return Framework::React;
        }
        if script.contains("new Vue(") || script.contains("createApp(") {
            return Framework::Vue;
        }
    }

    if has_attribute_pattern(document, "ng-version") {
        return Framework::Angular;
    }
    if has_attribute_starting_with(document, "data-v-") {
        return Framework::Vue;
    }

    Framework::Unknown
}

// ── DOM walking helpers ────────────────────────────────────────────────────────

fn collect_text(handle: &Handle) -> String {
    let mut buf = String::new();
    collect_text_inner(handle, &mut buf);
    buf
}

fn collect_text_inner(handle: &Handle, buf: &mut String) {
    if let NodeData::Text { contents } = &handle.data {
        buf.push_str(contents.borrow().as_ref());
    }
    for child in handle.children.borrow().iter() {
        collect_text_inner(child, buf);
    }
}

fn get_attr(attrs: &[html5ever::Attribute], name: &str) -> Option<String> {
    attrs.iter().find_map(|a| {
        if a.name.local.as_ref().eq_ignore_ascii_case(name) {
            Some(a.value.as_ref().to_string())
        } else {
            None
        }
    })
}

fn has_attribute_pattern(handle: &Handle, attr_name: &str) -> bool {
    if let NodeData::Element { attrs, .. } = &handle.data {
        if attrs
            .borrow()
            .iter()
            .any(|a| a.name.local.as_ref().eq_ignore_ascii_case(attr_name))
        {
            return true;
        }
    }
    handle
        .children
        .borrow()
        .iter()
        .any(|c| has_attribute_pattern(c, attr_name))
}

fn has_attribute_starting_with(handle: &Handle, prefix: &str) -> bool {
    if let NodeData::Element { attrs, .. } = &handle.data {
        if attrs
            .borrow()
            .iter()
            .any(|a| a.name.local.as_ref().starts_with(prefix))
        {
            return true;
        }
    }
    handle
        .children
        .borrow()
        .iter()
        .any(|c| has_attribute_starting_with(c, prefix))
}

// ── Browser-in-the-Browser (BitB) detection ────────────────────────────────────

/// Brand login hostnames that BitB kits render as visible address-bar TEXT to make
/// the fake popup look native (Sneaky2FA / Microsoft 365 / Facebook BitB, 2026).
const BITB_BRAND_LOGIN_HOSTS: &[&str] = &[
    "login.microsoftonline.com", "login.microsoft.com", "login.live.com",
    "login.windows.net", "login.microsoftonline.us",
    "accounts.google.com", "appleid.apple.com", "idmsa.apple.com",
    "www.facebook.com", "m.facebook.com", "www.linkedin.com",
    "login.yahoo.com", "signin.aws.amazon.com", "auth.services.adobe.com",
];

/// Fake browser-window chrome tokens (class/id) used to draw the spoofed titlebar.
const BITB_CHROME_TOKENS: &[&str] = &[
    "titlebar", "title-bar", "title_bar", "window-controls", "window-header",
    "window-top", "window-bar", "window-buttons", "fake-browser", "fakebrowser",
    "fake-window", "browser-window", "browser-top", "browser-chrome",
    "browser-header", "browser-bar", "url-bar", "urlbar", "address-bar",
    "addressbar", "tab-bar", "tabbar",
];

/// macOS / Windows traffic-light window-control colours (the three dots).
const BITB_TRAFFICLIGHT_COLORS: &[&str] = &[
    "#ff5f56", "#ff5f57", "#febc2e", "#ffbd2e", "#28c840", "#27c93f",
    "#ff605c", "#ffbd44", "#00ca4e",
];

#[derive(Default)]
struct BitbSignals {
    visible_text: String,
    attr_blob: String,
    has_password: bool,
    has_login_iframe: bool,
}

fn walk_bitb(handle: &Handle, s: &mut BitbSignals) {
    // Whether to descend into this node's children. <script>/<style> text is not
    // visible page content — skip those subtrees so an inline script mentioning a
    // brand login URL cannot trip the visible-text gate.
    let mut descend = true;
    match &handle.data {
        NodeData::Text { contents } => {
            s.visible_text.push_str(contents.borrow().as_ref());
            s.visible_text.push(' ');
        }
        NodeData::Element { name, attrs, .. } => {
            let tag = name.local.as_ref().to_ascii_lowercase();
            let attrs_ref = attrs.borrow();
            // Accumulate class/id/style for chrome-token matching.
            for key in ["class", "id", "style"] {
                if let Some(v) = get_attr(&attrs_ref, key) {
                    s.attr_blob.push_str(&v);
                    s.attr_blob.push(' ');
                }
            }
            match tag.as_str() {
                "input" => {
                    let itype = get_attr(&attrs_ref, "type")
                        .map(|t| t.to_ascii_lowercase())
                        .unwrap_or_else(|| "text".into());
                    let iname = get_attr(&attrs_ref, "name")
                        .or_else(|| get_attr(&attrs_ref, "id"))
                        .map(|v| v.to_ascii_lowercase())
                        .unwrap_or_default();
                    if itype == "password"
                        || matches!(iname.as_str(), "password" | "passwd" | "pwd" | "pass")
                    {
                        s.has_password = true;
                    }
                    // The spoofed URL is often an <input readonly value="https://login...">.
                    for key in ["value", "placeholder"] {
                        if let Some(v) = get_attr(&attrs_ref, key) {
                            s.visible_text.push_str(&v);
                            s.visible_text.push(' ');
                        }
                    }
                }
                "iframe" => {
                    let src = get_attr(&attrs_ref, "src").unwrap_or_default().to_ascii_lowercase();
                    let sandboxed = get_attr(&attrs_ref, "sandbox").is_some()
                        && get_attr(&attrs_ref, "allow").is_some();
                    if src.contains("login") || src.contains("auth") || sandboxed {
                        s.has_login_iframe = true;
                    }
                }
                "script" | "style" => {
                    descend = false;
                }
                _ => {}
            }
        }
        _ => {}
    }
    if descend {
        for child in handle.children.borrow().iter() {
            walk_bitb(child, s);
        }
    }
}

/// Last two dot-labels of a host — a good-enough registrable for the specific
/// single-suffix brand hosts handled here (none use a multi-part public suffix).
fn last_two_labels(host: &str) -> String {
    let parts: Vec<&str> = host.rsplitn(3, '.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[1], parts[0])
    } else {
        host.to_string()
    }
}

fn detect_bitb(document: &Handle, base_url: &Url, report: &mut ThreatReport) {
    let mut s = BitbSignals::default();
    walk_bitb(document, &mut s);

    let visible_lower = s.visible_text.to_ascii_lowercase();
    let page_host = base_url.host_str().unwrap_or("").to_ascii_lowercase();

    // (1) A brand login URL must appear as visible TEXT / input value (the spoofed
    // address bar), matched via the "://host" form so a script src= reference does
    // not trip it.
    let spoofed = BITB_BRAND_LOGIN_HOSTS.iter().find(|h| {
        visible_lower.contains(&format!("://{}", h))
    });
    let spoofed = match spoofed {
        Some(h) => *h,
        None => return,
    };

    // Suppress when the page IS the brand's own domain (a real login page).
    let spoofed_reg = last_two_labels(spoofed);
    if !page_host.is_empty() && page_host.ends_with(&spoofed_reg) {
        return;
    }

    // (2) Fake window-chrome structure: a chrome class/id token, ≥2 traffic-light
    // colours, or ≥3 circular window controls (border-radius:50%).
    let attr_lower = s.attr_blob.to_ascii_lowercase();
    let chrome_token = BITB_CHROME_TOKENS.iter().any(|t| attr_lower.contains(t));
    let trafficlights =
        BITB_TRAFFICLIGHT_COLORS.iter().filter(|c| attr_lower.contains(**c)).count() >= 2;
    let radius_dots = attr_lower.matches("border-radius:50%").count()
        + attr_lower.matches("border-radius: 50%").count()
        >= 3;
    let chrome_evidence = if chrome_token {
        "window-chrome class/id tokens"
    } else if trafficlights {
        "traffic-light window controls"
    } else if radius_dots {
        "≥3 circular window-control elements"
    } else {
        return;
    };

    // (3) Credential capture present.
    if !(s.has_password || s.has_login_iframe) {
        return;
    }

    let detail = format!(
        "spoofed login URL in page text: {} | fake window chrome: {} | credential capture: {} | serving host: {}",
        spoofed,
        chrome_evidence,
        if s.has_password { "password input" } else { "login/sandboxed iframe" },
        if page_host.is_empty() { "(unknown)" } else { page_host.as_str() },
    );
    report.add_bitb_fake_window(&detail);
}

#[cfg(test)]
mod bitb_tests {
    use super::*;
    use crate::threat::ThreatReport;

    fn run(html: &str, page_url: &str) -> ThreatReport {
        let mut report = ThreatReport::new(page_url);
        let processor = HtmlProcessor::new(Url::parse(page_url).unwrap());
        let _ = processor.process(html.as_bytes(), &mut report);
        report
    }

    const BITB_HTML: &str = r#"<html><head><style>
        .titlebar{border-radius:8px 8px 0 0}
        .dot{width:12px;height:12px;border-radius:50%;background:#ff5f56}</style></head>
        <body><div class="fake-browser"><div class="titlebar">
        <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        <span class="url-bar">https://login.microsoftonline.com/common/oauth2/authorize</span></div>
        <form><input type="password" name="passwd"></form></div></body></html>"#;

    #[test]
    fn fires_on_bitb_non_official_domain() {
        let r = run(BITB_HTML, "https://evil-login.com/");
        assert!(r.has_flag_code("BITB_FAKE_WINDOW"));
    }

    #[test]
    fn clean_on_official_brand_domain() {
        let r = run(BITB_HTML, "https://login.microsoftonline.com/");
        assert!(!r.has_flag_code("BITB_FAKE_WINDOW"));
    }

    #[test]
    fn clean_on_gsi_button_script_src() {
        // Google Sign-In: brand URL only in a <script src>, not visible text; no chrome.
        let html = r#"<html><body>
            <script src="https://accounts.google.com/gsi/client"></script>
            <form><input type="password"></form></body></html>"#;
        let r = run(html, "https://myshop.com/");
        assert!(!r.has_flag_code("BITB_FAKE_WINDOW"));
    }

    #[test]
    fn clean_when_brand_url_only_in_inline_script() {
        // An inline script mentioning the brand login URL must NOT trip the gate.
        let html = r#"<html><head><style>.titlebar{}</style></head><body>
            <script>var x="redirect to https://login.microsoftonline.com later";</script>
            <div class="titlebar url-bar"></div>
            <form><input type="password"></form></body></html>"#;
        let r = run(html, "https://evil.com/");
        assert!(!r.has_flag_code("BITB_FAKE_WINDOW"));
    }
}

// ── RcDom → DomSnapshot ───────────────────────────────────────────────────────

/// Convert a sanitised `RcDom` into the same `DomSnapshot` format that the JS
/// runtime produces, so the layout/render pipeline always has a snapshot to work
/// from even when no JS sandbox is needed.
pub fn rcdom_to_snapshot(dom: &RcDom) -> crate::js::vdom::DomSnapshot {
    node_to_snapshot(&dom.document)
}

fn node_to_snapshot(handle: &Handle) -> crate::js::vdom::DomSnapshot {
    match &handle.data {
        NodeData::Document => {
            // Wrap document children in a synthetic root.
            let children: Vec<_> = handle
                .children
                .borrow()
                .iter()
                .map(node_to_snapshot)
                .collect();
            crate::js::vdom::DomSnapshot {
                tag: "#document".into(),
                attrs: IndexMap::new(),
                style: IndexMap::new(),
                text: None,
                children,
            }
        }
        NodeData::Element { name, attrs, .. } => {
            let tag = name.local.as_ref().to_ascii_lowercase();
            let attrs_ref = attrs.borrow();

            let mut attr_map: IndexMap<String, String> = IndexMap::new();
            let mut style_map: IndexMap<String, String> = IndexMap::new();

            for attr in attrs_ref.iter() {
                let key = attr.name.local.as_ref().to_ascii_lowercase();
                let val = attr.value.as_ref().to_string();
                if key == "style" {
                    // Parse "prop: value; prop: value" into the style map.
                    for decl in val.split(';') {
                        if let Some((k, v)) = decl.split_once(':') {
                            let k = k.trim().to_ascii_lowercase();
                            let v = v.trim().to_string();
                            if !k.is_empty() {
                                style_map.insert(k, v);
                            }
                        }
                    }
                } else {
                    attr_map.insert(key, val);
                }
            }

            let children: Vec<_> = handle
                .children
                .borrow()
                .iter()
                .map(node_to_snapshot)
                .collect();

            crate::js::vdom::DomSnapshot {
                tag,
                attrs: attr_map,
                style: style_map,
                text: None,
                children,
            }
        }
        NodeData::Text { contents } => {
            let text = contents.borrow().as_ref().to_string();
            crate::js::vdom::DomSnapshot {
                tag: "#text".into(),
                attrs: IndexMap::new(),
                style: IndexMap::new(),
                text: if text.trim().is_empty() { None } else { Some(text) },
                children: Vec::new(),
            }
        }
        NodeData::Comment { .. } | NodeData::ProcessingInstruction { .. } | NodeData::Doctype { .. } => {
            // Skip non-content nodes — return a placeholder that the layout
            // engine will ignore (no tag match → treated as inline).
            crate::js::vdom::DomSnapshot {
                tag: "#comment".into(),
                attrs: IndexMap::new(),
                style: IndexMap::new(),
                text: None,
                children: Vec::new(),
            }
        }
    }
}
