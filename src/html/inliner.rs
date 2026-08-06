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
    /// External JS file contents in document order.  The sanitiser strips all
    /// `<script>` tags from the DOM before the inliner runs, so SPA pages
    /// (React/Vue/Angular) would otherwise render blank in Chromium.  Injecting
    /// the fetched scripts back as inline `<script>` blocks restores JS execution
    /// and lets dynamic overlays (ClickFix, SocGholish) actually render.
    pub js_scripts: Vec<String>,
    /// Original page URL injected as `<base href="...">`.
    ///
    /// When Chromium loads the self-contained HTML from a `file://` path,
    /// protocol-relative URLs (`//host/path`) in JS-created elements would
    /// otherwise resolve to `file://host/path` and fail immediately —
    /// bypassing the proxy bypass list entirely.  Setting the base href to
    /// the real page URL makes `//connect.facebook.net/sdk.js` resolve to
    /// `https://connect.facebook.net/sdk.js`, allowing CDN bypass to apply.
    pub base_url: String,
}

impl HtmlInliner {
    pub fn new(css_sheets: Vec<String>, images: HashMap<String, Vec<u8>>, js_scripts: Vec<String>, base_url: String) -> Self {
        Self { css_sheets, images, js_scripts, base_url }
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
            // Offline-path bootstrap = shared identity/nav/loader handling + the
            // offline-only fetch/XHR mock (CARAPACE-09 P2 split; behaviourally
            // identical to the former single WINDOWS_BOOTSTRAP blob). The CDP live
            // path injects only the shared IDENTITY_NAV_BOOTSTRAP so it keeps real
            // same-origin fetch through the SSRF proxy.
            let windows_bootstrap = crate::renderer::bootstrap::offline_bootstrap();

            // <base href> must be the first element in <head> so that all
            // subsequent elements — and JS-created elements at runtime — resolve
            // protocol-relative URLs against the original page's HTTPS origin
            // rather than the local file:// path.
            let base_tag = make_base_tag(&self.base_url);
            head.children.borrow_mut().insert(0, base_tag);

            let bootstrap = make_script_node(&windows_bootstrap);
            head.children.borrow_mut().insert(1, bootstrap);

            // Inject a CSS rule that hides common loading-screen elements via
            // the cascade before Vue/React even mounts.  This fires earlier
            // than any setTimeout and cannot be overridden by Vue re-rendering
            // the element with inline styles — !important wins the cascade.
            // The JS _removeLoaders() fallback then .remove()s the nodes so
            // they don't consume layout space.
            const HIDE_LOADERS_CSS: &str = "\
#app-loading,#loading,#preloader,#loader,#splash,#page-loader,\
[id*='loading'],[id*='preloader'],[id*='splash'],\
[class*='app-loading'],[class*='loading-screen'],[class*='page-loader'] \
{ display: none !important; visibility: hidden !important; opacity: 0 !important; }";
            let loader_style = make_style_node(HIDE_LOADERS_CSS);
            head.children.borrow_mut().insert(1, loader_style);

            // Inject a viewport meta if the page doesn't already have one.
            // Without it, Chromium's layout viewport defaults to 980px and scales
            // it to fit the 375px mobile window — all content appears tiny.
            let has_viewport = head.children.borrow().iter().any(|child| {
                if let NodeData::Element { name, attrs, .. } = &child.data {
                    if name.local.as_ref().eq_ignore_ascii_case("meta") {
                        let a = attrs.borrow();
                        return a.iter().any(|attr|
                            attr.name.local.as_ref().eq_ignore_ascii_case("name")
                            && attr.value.as_ref().eq_ignore_ascii_case("viewport")
                        );
                    }
                }
                false
            });
            if !has_viewport {
                let viewport = make_meta_viewport();
                head.children.borrow_mut().push(viewport);
            }

            for css in &self.css_sheets {
                let safe_css = sanitize_css_for_browser(css);
                let style = make_style_node(&safe_css);
                head.children.borrow_mut().push(style);
            }
            debug!(
                "injected Windows bootstrap + {} CSS sheets into <head> (viewport={})",
                self.css_sheets.len(),
                if has_viewport { "existing" } else { "injected" }
            );
        }

        // Inject page scripts at the end of <body> so the full DOM is parsed
        // and mount points like <div id="root"> exist when React/Vue/Angular run.
        // The bootstrap in <head> has already suppressed navigation at this point.
        if !self.js_scripts.is_empty() {
            if let Some(body) = find_element(&dom.document, "body") {
                for js in &self.js_scripts {
                    // Use type="module" so bundles with `export default` syntax
                    // (Vite/Vue/React ES module output) execute without SyntaxError.
                    let script = make_module_script_node(js);
                    body.children.borrow_mut().push(script);
                }
                debug!("injected {} JS scripts at end of <body>", self.js_scripts.len());
            }
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

            // Offline-render fidelity (CARAPACE-09 P2/P3): force below-fold images
            // to paint and stop the browser preferring a non-inlined responsive
            // candidate over the inlined src. Pure DOM rewrite, no network.
            normalize_render_hints(&child);

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

/// Classic `<script>` — used for the bootstrap (must run synchronously, no export).
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

/// ES module `<script type="module">` — used for page JS bundles that may contain
/// `export default` or other ES module syntax.  Modules are deferred by default
/// (execute after DOMContentLoaded) which is fine since we inject at end of `<body>`.
fn make_module_script_node(js: &str) -> Handle {
    let name = QualName::new(None, ns!(html), LocalName::from("script"));
    let attrs = vec![html5ever::Attribute {
        name: QualName::new(None, ns!(), LocalName::from("type")),
        value: "module".into(),
    }];
    let script = Node::new(NodeData::Element {
        name,
        attrs: RefCell::new(attrs),
        template_contents: RefCell::new(None),
        mathml_annotation_xml_integration_point: false,
    });
    let text = Node::new(NodeData::Text {
        contents: RefCell::new(js.into()),
    });
    script.children.borrow_mut().push(text);
    script
}

/// Create `<base href="url">` — sets the document base URL so that
/// protocol-relative URLs (`//host/path`) in dynamically-created elements
/// resolve as HTTPS rather than the file:// scheme Chromium loads the page from.
fn make_base_tag(url: &str) -> Handle {
    let name = QualName::new(None, ns!(html), LocalName::from("base"));
    let attrs = vec![html5ever::Attribute {
        name:  QualName::new(None, ns!(), LocalName::from("href")),
        value: url.into(),
    }];
    Node::new(NodeData::Element {
        name,
        attrs: RefCell::new(attrs),
        template_contents: RefCell::new(None),
        mathml_annotation_xml_integration_point: false,
    })
}

fn make_meta_viewport() -> Handle {
    let name = QualName::new(None, ns!(html), LocalName::from("meta"));
    let attrs = vec![
        html5ever::Attribute {
            name: QualName::new(None, ns!(), LocalName::from("name")),
            value: "viewport".into(),
        },
        html5ever::Attribute {
            name: QualName::new(None, ns!(), LocalName::from("content")),
            value: "width=device-width, initial-scale=1".into(),
        },
    ];
    Node::new(NodeData::Element {
        name,
        attrs: RefCell::new(attrs),
        template_contents: RefCell::new(None),
        mathml_annotation_xml_integration_point: false,
    })
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

/// Normalise render hints on a single element for the offline `file://` render
/// (CARAPACE-09 P2/P3). Pure DOM rewrite — issues no network requests:
///   * `<img>`/`<iframe loading="lazy">` -> `eager` so below-the-fold content
///     paints in the screenshot instead of waiting for a scroll that never happens.
///   * `<img>`: drop `srcset`/`sizes` so the browser uses the inlined `src` data
///     URI rather than fetching a responsive candidate (offline-blocked -> blank).
///   * `<source>`: drop `srcset` so a `<picture>` falls back to its inlined `<img>`.
fn normalize_render_hints(handle: &Handle) {
    let NodeData::Element { name, attrs, .. } = &handle.data else { return };
    let tag = name.local.as_ref().to_ascii_lowercase();
    if !matches!(tag.as_str(), "img" | "iframe" | "source") {
        return;
    }
    let mut attrs = attrs.borrow_mut();
    if tag == "img" || tag == "iframe" {
        for a in attrs.iter_mut() {
            if a.name.local.as_ref().eq_ignore_ascii_case("loading")
                && a.value.as_ref().eq_ignore_ascii_case("lazy")
            {
                a.value = "eager".into();
            }
        }
    }
    if tag == "img" {
        attrs.retain(|a| {
            let n = a.name.local.as_ref();
            !n.eq_ignore_ascii_case("srcset") && !n.eq_ignore_ascii_case("sizes")
        });
    } else if tag == "source" {
        attrs.retain(|a| !a.name.local.as_ref().eq_ignore_ascii_case("srcset"));
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

#[cfg(test)]
mod render_hint_tests {
    use super::*;
    use html5ever::{driver::ParseOpts, parse_document, tendril::TendrilSink};

    // Run only the DOM-normalisation pass (process_subtree) on parsed HTML, then
    // serialise — no bootstrap/JS injection, so assertions target normalisation alone.
    fn normalise(html: &str) -> String {
        let dom = parse_document(RcDom::default(), ParseOpts::default())
            .from_utf8()
            .read_from(&mut html.as_bytes())
            .unwrap();
        let inliner = HtmlInliner::new(vec![], HashMap::new(), vec![], "https://example.test/".into());
        inliner.process_subtree(&dom.document);
        serialize_dom(&dom).to_ascii_lowercase()
    }

    #[test]
    fn lazy_becomes_eager_and_responsive_hints_stripped() {
        let out = normalise(
            r#"<html><body>
                <img src="a.png" srcset="a-2x.png 2x" sizes="50vw" loading="lazy">
                <iframe src="x" loading="lazy"></iframe>
                <picture><source srcset="b.webp" type="image/webp"><img src="b.png"></picture>
            </body></html>"#,
        );
        assert!(!out.contains("srcset"), "srcset/source-srcset must be stripped: {out}");
        assert!(!out.contains("sizes="), "img sizes must be stripped: {out}");
        assert!(!out.contains(r#"loading="lazy""#), "no lazy loading may remain: {out}");
        assert!(out.contains(r#"loading="eager""#), "lazy must be rewritten to eager: {out}");
        // The inlinable src attributes are preserved for later data-URI inlining.
        assert!(out.contains("a.png") && out.contains("b.png"), "img src preserved: {out}");
    }

    #[test]
    fn plain_images_are_untouched() {
        let out = normalise(r#"<html><body><img src="a.png"><img src="b.png" loading="eager"></body></html>"#);
        assert!(out.contains("a.png") && out.contains("b.png"));
        assert!(!out.contains("lazy"), "must not introduce lazy loading: {out}");
        assert!(!out.contains("srcset"), "must not introduce srcset: {out}");
    }
}
