use std::cell::RefCell;
use std::rc::Rc;

use markup5ever_rcdom::{Handle, NodeData, RcDom};
use tracing::warn;

use crate::threat::{HtmlFlag, ThreatReport};

/// Tags whose entire subtree is removed (children are NOT kept).
const REMOVE_WITH_CHILDREN: &[&str] = &[
    "script", "noscript", "iframe", "frame", "frameset",
    "object", "embed", "applet", "base",
];

/// Element allowlist — these tags pass through with attribute sanitisation.
fn is_allowed_tag(name: &str) -> bool {
    matches!(
        name,
        "a" | "abbr" | "address" | "article" | "aside"
        | "b" | "blockquote" | "br" | "caption" | "cite"
        | "code" | "col" | "colgroup" | "dd" | "del"
        | "details" | "dfn" | "div" | "dl" | "dt"
        | "em" | "figcaption" | "figure" | "footer"
        | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
        | "header" | "hr" | "html" | "head" | "body"
        | "i" | "img" | "ins" | "kbd" | "li" | "main"
        | "mark" | "nav" | "ol" | "p" | "picture"
        | "pre" | "q" | "s" | "section" | "small"
        | "source" | "span" | "strong" | "sub"
        | "summary" | "sup" | "table" | "tbody"
        | "td" | "tfoot" | "th" | "thead" | "time"
        | "title" | "tr" | "u" | "ul" | "var"
        | "video" | "wbr"
        | "link" | "meta" | "style"
    )
}

/// Attribute names that are always removed regardless of element.
fn is_always_blocked_attr(name: &str) -> bool {
    name.starts_with("on") || matches!(name, "formaction" | "srcdoc" | "ping")
}

pub struct Sanitizer<'a> {
    #[allow(dead_code)] // reserved for future relative-URL resolution
    base_url: Option<url::Url>,
    report: &'a mut ThreatReport,
}

impl<'a> Sanitizer<'a> {
    pub fn new(base_url: Option<url::Url>, report: &'a mut ThreatReport) -> Self {
        Self { base_url, report }
    }

    pub fn sanitize(&mut self, dom: &RcDom) {
        self.walk(&dom.document);
    }

    fn walk(&mut self, handle: &Handle) {
        // Read from the *live* children list on each iteration.
        //
        // Why not snapshot upfront: after `unwrap_element` replaces a node
        // with its own children, those children land at the current index in
        // the live list and must be visited.  A pre-built snapshot would miss
        // them entirely, leaving dangerous content unsanitised.
        //
        // After `detach` or `unwrap_element` the next child slides into the
        // current index, so we do NOT advance `idx` in those cases.
        let mut idx = 0;
        loop {
            // Clone the Rc handle so we drop the borrow before mutating.
            let child = match handle.children.borrow().get(idx).cloned() {
                Some(c) => c,
                None => break,
            };

            match &child.data {
                NodeData::Element { name, attrs, .. } => {
                    let tag = name.local.as_ref().to_ascii_lowercase();

                    if REMOVE_WITH_CHILDREN.contains(&tag.as_str()) {
                        self.report.add_html_flag(HtmlFlag::BlockedElement(tag));
                        detach(&child);
                        // After detach the next sibling slides into `idx`.
                        continue;
                    }

                    if !is_allowed_tag(&tag) {
                        // Replace this node with its children in the live list.
                        unwrap_element(handle, &child);
                        // First inserted child is now at `idx` — visit it next.
                        continue;
                    }

                    // Allowed element: sanitise attributes.
                    self.sanitize_attrs(&tag, attrs);

                    match tag.as_str() {
                        "meta" => self.handle_meta(&child, attrs),
                        _ => {}
                    }

                    self.walk(&child);
                    idx += 1;
                }
                _ => {
                    idx += 1;
                }
            }
        }
    }

    fn sanitize_attrs(&mut self, tag: &str, attrs: &RefCell<Vec<html5ever::Attribute>>) {
        let mut to_remove: Vec<usize> = Vec::new();

        {
            let attrs_ref = attrs.borrow();
            for (i, attr) in attrs_ref.iter().enumerate() {
                let name = attr.name.local.as_ref().to_ascii_lowercase();
                let value = attr.value.as_ref();

                if is_always_blocked_attr(&name) {
                    self.report.add_html_flag(HtmlFlag::BlockedAttribute {
                        element: tag.to_string(),
                        attr: name,
                        value: value.to_string(),
                    });
                    to_remove.push(i);
                    continue;
                }

                if matches!(
                    name.as_str(),
                    "href" | "src" | "action" | "xlink:href" | "poster"
                ) {
                    if let Some(reason) = check_url_value(value) {
                        self.report.add_html_flag(HtmlFlag::BlockedAttribute {
                            element: tag.to_string(),
                            attr: name,
                            value: value.to_string(),
                        });
                        warn!("stripped dangerous URL ({reason}): {:?}", value);
                        to_remove.push(i);
                        continue;
                    }
                }

                if name == "style" {
                    let lower = value.to_ascii_lowercase();
                    if lower.contains("expression(")
                        || lower.contains("javascript:")
                        || lower.contains("-moz-binding")
                        || lower.contains("behavior:")
                    {
                        self.report.add_html_flag(HtmlFlag::BlockedAttribute {
                            element: tag.to_string(),
                            attr: "style".to_string(),
                            value: value.to_string(),
                        });
                        to_remove.push(i);
                    }
                }
            }
        }

        // Remove in reverse so indices stay valid.
        let mut attrs_mut = attrs.borrow_mut();
        for i in to_remove.into_iter().rev() {
            attrs_mut.remove(i);
        }
    }

    fn handle_meta(&mut self, node: &Handle, attrs: &RefCell<Vec<html5ever::Attribute>>) {
        // Extract info before borrowing stops us from calling detach.
        let blocked_kind: Option<String> = {
            let attrs_ref = attrs.borrow();
            attrs_ref.iter().find_map(|attr| {
                if attr.name.local.as_ref().eq_ignore_ascii_case("http-equiv") {
                    let val = attr.value.as_ref().to_ascii_lowercase();
                    if matches!(val.as_str(), "refresh" | "content-security-policy") {
                        return Some(format!("http-equiv={}", val));
                    }
                }
                None
            })
        };

        if let Some(kind) = blocked_kind {
            self.report.add_html_flag(HtmlFlag::SuspiciousMeta { kind });
            detach(node);
        }
    }
}

// ── URL safety check ──────────────────────────────────────────────────────────

/// Returns `Some(reason)` if the URL value should be stripped.
fn check_url_value(value: &str) -> Option<&'static str> {
    // Strip control characters and null bytes (common obfuscation).
    let cleaned: String = value
        .chars()
        .filter(|c| !matches!(c, '\x00'..='\x1F' | '\x7F'))
        .collect();
    let lower = cleaned.trim().to_ascii_lowercase();

    if lower.starts_with("javascript:") {
        return Some("javascript: URL");
    }
    if lower.starts_with("vbscript:") {
        return Some("vbscript: URL");
    }
    if lower.starts_with("data:text/html") || lower.starts_with("data:text/xml") {
        return Some("data: HTML/XML URI");
    }
    if lower.starts_with("data:application/") {
        return Some("data: application URI");
    }
    None
}

// ── DOM manipulation helpers ──────────────────────────────────────────────────

/// Detach a node from its parent's children list.
fn detach(node: &Handle) {
    if let Some(weak_parent) = node.parent.take() {
        if let Some(parent) = weak_parent.upgrade() {
            parent.children.borrow_mut().retain(|c| !Rc::ptr_eq(c, node));
        }
    }
}

/// Replace `node` in `parent`'s child list with `node`'s own children.
fn unwrap_element(parent: &Handle, node: &Handle) {
    let node_children: Vec<Handle> = node.children.borrow().iter().cloned().collect();

    let mut parent_children = parent.children.borrow_mut();
    if let Some(pos) = parent_children.iter().position(|c| Rc::ptr_eq(c, node)) {
        parent_children.remove(pos);
        for (offset, child) in node_children.iter().enumerate() {
            // Re-parent: set child's parent to the new parent
            child.parent.set(Some(Rc::downgrade(parent)));
            parent_children.insert(pos + offset, child.clone());
        }
    }
    // Clear node's parent reference
    node.parent.set(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_elements_list() {
        assert!(REMOVE_WITH_CHILDREN.contains(&"script"));
        assert!(REMOVE_WITH_CHILDREN.contains(&"iframe"));
        assert!(REMOVE_WITH_CHILDREN.contains(&"object"));
        assert!(REMOVE_WITH_CHILDREN.contains(&"embed"));
    }

    #[test]
    fn event_handler_attrs_blocked() {
        assert!(is_always_blocked_attr("onclick"));
        assert!(is_always_blocked_attr("onload"));
        assert!(is_always_blocked_attr("onerror"));
        assert!(!is_always_blocked_attr("href"));
        assert!(!is_always_blocked_attr("class"));
    }

    #[test]
    fn url_checks() {
        assert!(check_url_value("javascript:alert(1)").is_some());
        assert!(check_url_value("JAVASCRIPT:void(0)").is_some());
        assert!(check_url_value("  javascript:x").is_some());
        assert!(check_url_value("data:text/html,<b>hi</b>").is_some());
        assert!(check_url_value("https://example.com").is_none());
        // data:image is allowed (safe for rendering)
        assert!(check_url_value("data:image/png;base64,abc").is_none());
    }
}
