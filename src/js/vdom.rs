use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub type NodeId = usize;

/// The virtual DOM tree — a simple arena-allocated tree that JS can mutate
/// inside the rquickjs sandbox.
#[derive(Debug, Default)]
pub struct VDom {
    nodes: Vec<VNode>,
    next_id: NodeId,
    pub document_id: NodeId,
    pub html_id: NodeId,
    pub head_id: NodeId,
    pub body_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct VNode {
    pub id: NodeId,
    pub kind: VNodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub attrs: IndexMap<String, String>,
    pub style: IndexMap<String, String>,
    pub text: Option<String>,
    pub event_listeners: Vec<String>, // event names (not handlers — never stored)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VNodeKind {
    Document,
    Element(String), // lowercase tag name
    Text,
    Comment,
    Fragment,
}

/// Serialisable snapshot of the entire virtual DOM — output of `__snapshot__()`.
#[derive(Debug, Serialize, Deserialize)]
pub struct DomSnapshot {
    pub tag: String,
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub attrs: IndexMap<String, String>,
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub style: IndexMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<DomSnapshot>,
}

impl VDom {
    /// Create a new VDom with the standard document structure pre-populated.
    pub fn new() -> Self {
        let mut dom = VDom {
            nodes: Vec::new(),
            next_id: 0,
            document_id: 0,
            html_id: 0,
            head_id: 0,
            body_id: 0,
        };

        let doc_id = dom.alloc(VNodeKind::Document);
        let html_id = dom.alloc(VNodeKind::Element("html".into()));
        let head_id = dom.alloc(VNodeKind::Element("head".into()));
        let body_id = dom.alloc(VNodeKind::Element("body".into()));

        dom.document_id = doc_id;
        dom.html_id = html_id;
        dom.head_id = head_id;
        dom.body_id = body_id;

        dom.append_child(doc_id, html_id);
        dom.append_child(html_id, head_id);
        dom.append_child(html_id, body_id);

        dom
    }

    fn alloc(&mut self, kind: VNodeKind) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(VNode {
            id,
            kind,
            parent: None,
            children: Vec::new(),
            attrs: IndexMap::new(),
            style: IndexMap::new(),
            text: None,
            event_listeners: Vec::new(),
        });
        id
    }

    pub fn create_element(&mut self, tag: &str) -> NodeId {
        self.alloc(VNodeKind::Element(tag.to_ascii_lowercase()))
    }

    pub fn create_text_node(&mut self, text: &str) -> NodeId {
        let id = self.alloc(VNodeKind::Text);
        self.nodes[id].text = Some(text.to_string());
        id
    }

    pub fn create_comment(&mut self, text: &str) -> NodeId {
        let id = self.alloc(VNodeKind::Comment);
        self.nodes[id].text = Some(text.to_string());
        id
    }

    pub fn create_fragment(&mut self) -> NodeId {
        self.alloc(VNodeKind::Fragment)
    }

    pub fn append_child(&mut self, parent: NodeId, child: NodeId) {
        // Remove from existing parent
        if let Some(old_parent) = self.nodes[child].parent {
            self.nodes[old_parent].children.retain(|&c| c != child);
        }
        self.nodes[child].parent = Some(parent);
        self.nodes[parent].children.push(child);
    }

    pub fn insert_before(&mut self, parent: NodeId, new_child: NodeId, ref_child: NodeId) {
        if let Some(old_parent) = self.nodes[new_child].parent {
            self.nodes[old_parent].children.retain(|&c| c != new_child);
        }
        self.nodes[new_child].parent = Some(parent);
        let pos = self.nodes[parent]
            .children
            .iter()
            .position(|&c| c == ref_child)
            .unwrap_or(self.nodes[parent].children.len());
        self.nodes[parent].children.insert(pos, new_child);
    }

    pub fn remove_child(&mut self, parent: NodeId, child: NodeId) {
        self.nodes[parent].children.retain(|&c| c != child);
        self.nodes[child].parent = None;
    }

    pub fn set_attribute(&mut self, node: NodeId, name: &str, value: &str) {
        // Block dangerous attribute mutations from JS
        let lower_name = name.to_ascii_lowercase();
        if lower_name.starts_with("on") {
            warn!("vdom: blocked setAttribute '{}' (event handler)", name);
            return;
        }
        if lower_name == "href" || lower_name == "src" || lower_name == "action" {
            let lower_val = value.to_ascii_lowercase();
            if lower_val.trim_start().starts_with("javascript:")
                || lower_val.trim_start().starts_with("data:text")
            {
                warn!("vdom: blocked setAttribute '{}' = {:?}", name, value);
                return;
            }
        }
        self.nodes[node].attrs.insert(lower_name, value.to_string());
    }

    pub fn get_attribute(&self, node: NodeId, name: &str) -> Option<String> {
        self.nodes[node].attrs.get(&name.to_ascii_lowercase()).cloned()
    }

    pub fn remove_attribute(&mut self, node: NodeId, name: &str) {
        self.nodes[node].attrs.shift_remove(&name.to_ascii_lowercase());
    }

    pub fn set_style_property(&mut self, node: NodeId, property: &str, value: &str) {
        self.nodes[node]
            .style
            .insert(property.to_string(), value.to_string());
    }

    pub fn set_text_content(&mut self, node: NodeId, text: &str) {
        // Replace children with a single text node
        let children: Vec<NodeId> = self.nodes[node].children.clone();
        for child in children {
            self.nodes[child].parent = None;
        }
        self.nodes[node].children.clear();
        let text_id = self.create_text_node(text);
        self.append_child(node, text_id);
    }

    pub fn text_content(&self, node: NodeId) -> String {
        let mut buf = String::new();
        self.collect_text(node, &mut buf);
        buf
    }

    fn collect_text(&self, node: NodeId, buf: &mut String) {
        if let Some(text) = &self.nodes[node].text {
            buf.push_str(text);
        }
        for &child in &self.nodes[node].children.clone() {
            self.collect_text(child, buf);
        }
    }

    pub fn get_element_by_id(&self, id: &str) -> Option<NodeId> {
        self.find_by_attr(self.document_id, "id", id)
    }

    pub fn get_elements_by_tag_name(&self, tag: &str) -> Vec<NodeId> {
        let mut results = Vec::new();
        self.find_by_tag(self.document_id, &tag.to_ascii_lowercase(), &mut results);
        results
    }

    fn find_by_attr(&self, node: NodeId, attr: &str, value: &str) -> Option<NodeId> {
        if let Some(v) = self.nodes[node].attrs.get(attr) {
            if v == value {
                return Some(node);
            }
        }
        for &child in &self.nodes[node].children.clone() {
            if let Some(found) = self.find_by_attr(child, attr, value) {
                return Some(found);
            }
        }
        None
    }

    fn find_by_tag(&self, node: NodeId, tag: &str, results: &mut Vec<NodeId>) {
        if let VNodeKind::Element(ref t) = self.nodes[node].kind {
            if t == tag {
                results.push(node);
            }
        }
        for &child in &self.nodes[node].children.clone() {
            self.find_by_tag(child, tag, results);
        }
    }

    /// Add a record that an event listener was attached (never actually called).
    pub fn add_event_listener(&mut self, node: NodeId, event_type: &str) {
        self.nodes[node].event_listeners.push(event_type.to_string());
    }

    // ── Snapshot serialisation ────────────────────────────────────────────────

    /// Serialise the VDom starting from `body` for use by the layout engine.
    pub fn snapshot(&self) -> DomSnapshot {
        self.snapshot_node(self.body_id)
    }

    fn snapshot_node(&self, node: NodeId) -> DomSnapshot {
        let vnode = &self.nodes[node];
        let tag = match &vnode.kind {
            VNodeKind::Element(t) => t.clone(),
            VNodeKind::Text => "#text".into(),
            VNodeKind::Comment => "#comment".into(),
            VNodeKind::Fragment => "#fragment".into(),
            VNodeKind::Document => "#document".into(),
        };

        DomSnapshot {
            tag,
            attrs: vnode.attrs.clone(),
            style: vnode.style.clone(),
            text: vnode.text.clone(),
            children: vnode
                .children
                .iter()
                .map(|&c| self.snapshot_node(c))
                .collect(),
        }
    }
}

/// Thread-safe shared reference used by the rquickjs sandbox.
pub type SharedVDom = Arc<Mutex<VDom>>;

pub fn new_shared_vdom() -> SharedVDom {
    Arc::new(Mutex::new(VDom::new()))
}
