/// Walks the sanitised RcDom and produces a fully self-contained HTML string:
/// - Removes every `<link rel="stylesheet">` element.
/// - Injects all fetched CSS as `<style>` blocks inside `<head>`.
/// - Replaces every `<img src="…">` attribute with a base64 data URI.
/// - Serialises the modified tree back to an HTML byte string.
///
/// The result is a single file with no external dependencies that a headless
/// browser can render without any network access.
use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine as _;
use crate::css::sanitize_css_for_browser;
use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
use html5ever::{namespace_url, ns, LocalName, QualName};
use markup5ever_rcdom::{Handle, Node, NodeData, RcDom, SerializableHandle};
use tracing::debug;

pub struct HtmlInliner {
    /// Ordered list of CSS sheet contents to inject.
    pub css_sheets: Vec<String>,
    /// Image bytes keyed by the original `src` attribute value from the HTML.
    pub images: HashMap<String, Vec<u8>>,
}

impl HtmlInliner {
    pub fn new(css_sheets: Vec<String>, images: HashMap<String, Vec<u8>>) -> Self {
        Self { css_sheets, images }
    }

    /// Inline all resources into `dom` and return the serialised HTML string.
    pub fn build_self_contained(&self, dom: &RcDom) -> String {
        // Pass 1 – remove <link rel="stylesheet"> and replace <img src> with data URIs.
        self.process_subtree(&dom.document);

        // Pass 2 – sanitise and inject <style> blocks into <head>, plus a
        // Windows platform bootstrap script as the very first child of <head>.
        //
        // The bootstrap script overrides navigator.platform to 'Win32' so that
        // ClickFix and SocGholish payloads that gate on OS fingerprinting
        // (e.g. `if (navigator.platform === 'Win32')`) believe they are
        // running on a Windows host and execute their full attack path.
        // Combined with the --user-agent Chromium flag (which makes
        // navigator.userAgent report Windows Chrome), this causes the complete
        // ClickFix delivery chain to run and become visible to Carapace's
        // DOM-level analysis.
        //
        // Security note: the injected script runs entirely inside the sandboxed
        // Chromium render with all network requests blocked by the logging proxy.
        // No data can reach an external host regardless of what the page does.
        if let Some(head) = find_element(&dom.document, "head") {
            const WINDOWS_BOOTSTRAP: &str = r#"
(function() {
  try {
    Object.defineProperty(navigator, 'platform',    {get: function() { return 'Win32'; }});
    Object.defineProperty(navigator, 'oscpu',       {get: function() { return 'Windows NT 10.0; Win64; x64'; }});
    Object.defineProperty(navigator, 'appVersion',  {get: function() { return '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'; }});
  } catch(e) {}
})();
"#;
            let bootstrap = make_script_node(WINDOWS_BOOTSTRAP);
            head.children.borrow_mut().insert(0, bootstrap);

            for css in &self.css_sheets {
                let safe_css = sanitize_css_for_browser(css);
                let style = make_style_node(&safe_css);
                head.children.borrow_mut().push(style);
            }
            debug!("injected {} CSS sheets + Windows bootstrap into <head>", self.css_sheets.len());
        }

        // Pass 3 – serialise.
        let html = serialize_dom(dom);
        debug!("self-contained HTML: {} bytes", html.len());
        html
    }

    fn process_subtree(&self, handle: &Handle) {
        let mut idx = 0;
        loop {
            let child = match handle.children.borrow().get(idx).cloned() {
                Some(c) => c,
                None => break,
            };

            // Determine action without holding a borrow across mutations.
            let action = match &child.data {
                NodeData::Element { name, attrs, .. } => {
                    let tag = name.local.as_ref().to_ascii_lowercase();
                    let attrs_snap = attrs.borrow();

                    let action = match tag.as_str() {
                        "link" => {
                            let rel = get_attr(&attrs_snap, "rel")
                                .map(|r| r.to_ascii_lowercase())
                                .unwrap_or_default();
                            if rel.contains("stylesheet") {
                                Action::DetachLink
                            } else {
                                Action::Recurse
                            }
                        }
                        "img" => {
                            let src = get_attr(&attrs_snap, "src").unwrap_or_default();
                            Action::InlineImg { src }
                        }
                        _ => Action::Recurse,
                    };
                    drop(attrs_snap);
                    action
                }
                _ => Action::Recurse,
            };

            match action {
                Action::DetachLink => {
                    detach(&child);
                    // After detach the next sibling slides into `idx`.
                }
                Action::InlineImg { src } => {
                    if let Some(bytes) = self.images.get(&src) {
                        if let NodeData::Element { attrs, .. } = &child.data {
                            let mime = detect_mime(bytes);
                            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                            let data_uri = format!("data:{};base64,{}", mime, b64);
                            let mut attrs_mut = attrs.borrow_mut();
                            for attr in attrs_mut.iter_mut() {
                                if attr.name.local.as_ref().eq_ignore_ascii_case("src") {
                                    attr.value = data_uri.into();
                                    break;
                                }
                            }
                        }
                    }
                    self.process_subtree(&child);
                    idx += 1;
                }
                Action::Recurse => {
                    self.process_subtree(&child);
                    idx += 1;
                }
            }
        }
    }
}

// ── Action enum ───────────────────────────────────────────────────────────────

enum Action {
    DetachLink,
    InlineImg { src: String },
    Recurse,
}

// ── DOM helpers ───────────────────────────────────────────────────────────────

fn find_element(handle: &Handle, tag_name: &str) -> Option<Handle> {
    if let NodeData::Element { name, .. } = &handle.data {
        if name.local.as_ref().eq_ignore_ascii_case(tag_name) {
            return Some(handle.clone());
        }
    }
    for child in handle.children.borrow().iter() {
        if let Some(found) = find_element(child, tag_name) {
            return Some(found);
        }
    }
    None
}

fn make_script_node(js: &str) -> Handle {
    let name = QualName::new(None, ns!(html), LocalName::from("script"));
    let script = Node::new(NodeData::Element {
        name,
        attrs: RefCell::new(vec![]),
        template_contents: RefCell::new(None),
        mathml_annotation_xml_integration_point: false,
    });
    let text = Node::new(NodeData::Text {
        contents: RefCell::new(js.into()),
    });
    script.children.borrow_mut().push(text);
    script
}

fn make_style_node(css: &str) -> Handle {
    let name = QualName::new(None, ns!(html), LocalName::from("style"));
    let style = Node::new(NodeData::Element {
        name,
        attrs: RefCell::new(vec![]),
        template_contents: RefCell::new(None),
        mathml_annotation_xml_integration_point: false,
    });
    let text = Node::new(NodeData::Text {
        contents: RefCell::new(css.into()),
    });
    style.children.borrow_mut().push(text);
    style
}

fn detach(node: &Handle) {
    if let Some(weak_parent) = node.parent.take() {
        if let Some(parent) = weak_parent.upgrade() {
            use std::rc::Rc;
            parent.children.borrow_mut().retain(|c| !Rc::ptr_eq(c, node));
        }
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

// ── Serialisation ─────────────────────────────────────────────────────────────

pub fn serialize_dom(dom: &RcDom) -> String {
    let handle: SerializableHandle = dom.document.clone().into();
    let mut output = Vec::new();
    serialize(&mut output, &handle, SerializeOpts {
        traversal_scope: TraversalScope::ChildrenOnly(None),
        ..Default::default()
    })
    .ok();
    String::from_utf8_lossy(&output).into_owned()
}

// ── MIME detection ────────────────────────────────────────────────────────────

fn detect_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x89PNG")                                      { return "image/png"; }
    if bytes.starts_with(b"\xFF\xD8\xFF")                                 { return "image/jpeg"; }
    if bytes.starts_with(b"GIF8")                                         { return "image/gif"; }
    if bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" { return "image/webp"; }
    if bytes.starts_with(b"<svg") || (bytes.starts_with(b"<?xml") && bytes.windows(4).any(|w| w == b"<svg")) {
        return "image/svg+xml";
    }
    "image/png"
}
