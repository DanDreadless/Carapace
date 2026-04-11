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
