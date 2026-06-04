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
            const WINDOWS_BOOTSTRAP: &str = r#"
(function() {
  try {
    Object.defineProperty(navigator, 'platform',    {get: function() { return 'Win32'; }});
    Object.defineProperty(navigator, 'oscpu',       {get: function() { return 'Windows NT 10.0; Win64; x64'; }});
    Object.defineProperty(navigator, 'appVersion',  {get: function() { return '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'; }});
  } catch(e) {}
  // Suppress navigation so overlays render fully before the screenshot is taken.
  try {
    window.location.replace = function() {};
    window.location.assign  = function() {};
    window.location.reload  = function() {};
  } catch(e) {}
  try {
    var _d = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (_d) {
      Object.defineProperty(Location.prototype, 'href', {
        get: _d.get,
        set: function() {},
        configurable: true
      });
    }
  } catch(e) {}
  // Mock fetch() and XMLHttpRequest so Vue/React apps that wait on API calls
  // receive an immediate empty-but-successful response and can render their UI.
  try {
    window.fetch = function(url, opts) {
      return Promise.resolve(new Response('{}', {
        status: 200,
        headers: {'Content-Type': 'application/json'}
      }));
    };
  } catch(e) {}
  try {
    window.XMLHttpRequest = function() {
      var self = this;
      self.open = function() {};
      self.setRequestHeader = function() {};
      self.send = function() {
        var me = self;
        setTimeout(function() {
          Object.defineProperty(me, 'readyState',   {get: function(){return 4;}});
          Object.defineProperty(me, 'status',       {get: function(){return 200;}});
          Object.defineProperty(me, 'responseText', {get: function(){return '{}';}});
          Object.defineProperty(me, 'response',     {get: function(){return '{}';}});
          if (me.onreadystatechange) me.onreadystatechange();
          if (me.onload) me.onload();
        }, 0);
      };
    };
  } catch(e) {}
  // Loader-screen killer — MutationObserver fires synchronously on every DOM
  // mutation so it does NOT depend on virtual-time advancing (unlike setTimeout).
  // When Vue/React mounts and creates #app-loading, the observer fires immediately
  // in the same microtask checkpoint and removes it before the next paint.
  //
  // Two strategies are combined:
  //   1. Named-selector kill: targets IDs/classes used by common phishing kits.
  //   2. Appearance-based kill: removes ANY fullscreen white/near-white fixed
  //      overlay regardless of what name the kit chose, by checking computed
  //      position, size, and background colour.
  function _killLoaders() {
    try {
      var sel = '#app-loading,#loading,#preloader,#loader,#splash,#page-loader,' +
                '[id*="loading"],[id*="preloader"],[id*="spinner"],[id*="splash"],' +
                '[class*="app-loading"],[class*="loading-screen"],[class*="page-loader"],' +
                '[class*="preloader"],[class*="spinner"]';
      document.querySelectorAll(sel).forEach(function(el) {
        try {
          // setProperty with 'important' beats inline style="display:x !important"
          el.style.setProperty('display',     'none',   'important');
          el.style.setProperty('visibility',  'hidden', 'important');
          el.remove();
        } catch(ex) {}
      });
      // Kill any white/near-white fullscreen fixed overlay regardless of name.
      document.querySelectorAll('div,section,main,aside,header,footer').forEach(function(el) {
        try {
          var cs = window.getComputedStyle(el);
          if (cs.position !== 'fixed' && cs.position !== 'absolute') return;
          var r = el.getBoundingClientRect();
          if (!r || r.width < window.innerWidth * 0.8 || r.height < window.innerHeight * 0.8) return;
          var m = cs.backgroundColor.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
          if (m && +m[1] >= 230 && +m[2] >= 230 && +m[3] >= 230) {
            el.style.setProperty('display', 'none', 'important');
            el.remove();
          }
        } catch(ex) {}
      });
    } catch(e) {}
  }
  // Install observer before any page script runs.
  try {
    var _obs = new MutationObserver(function() { _killLoaders(); });
    _obs.observe(document.documentElement || document, {
      childList: true, subtree: true,
      attributes: true, attributeFilter: ['style','class','id']
    });
  } catch(e) {}
  // Also sweep on DOMContentLoaded and first rAF as belt-and-braces.
  try { document.addEventListener('DOMContentLoaded', _killLoaders, {once:true}); } catch(e) {}
  try { requestAnimationFrame(_killLoaders); } catch(e) {}
})();
"#;
            // <base href> must be the first element in <head> so that all
            // subsequent elements — and JS-created elements at runtime — resolve
            // protocol-relative URLs against the original page's HTTPS origin
            // rather than the local file:// path.
            let base_tag = make_base_tag(&self.base_url);
            head.children.borrow_mut().insert(0, base_tag);

            let bootstrap = make_script_node(WINDOWS_BOOTSTRAP);
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
