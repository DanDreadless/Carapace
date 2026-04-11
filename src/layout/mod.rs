use std::collections::HashMap;

use indexmap::IndexMap;
use taffy::prelude::*;
use tracing::debug;

use crate::css::{parse_color, parse_font_size, resolve_styles, StyleMap};
use crate::error::{CarapaceError, Result};
use crate::js::vdom::DomSnapshot;

#[derive(Debug, Clone, Copy)]
pub struct LayoutRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone)]
pub struct VisualProps {
    pub background: Option<[u8; 4]>,
    pub color: [u8; 4],
    pub font_size: f32,
    pub font_weight: u16,
    pub text_align: TextAlign,
    pub text_content: Option<String>,
    pub image_src: Option<String>,   // resolved src for <img> tags
    pub opacity: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign { Left, Center, Right }

impl Default for VisualProps {
    fn default() -> Self {
        Self {
            background: None,
            color: [0, 0, 0, 255],
            font_size: 16.0,
            font_weight: 400,
            text_align: TextAlign::Left,
            text_content: None,
            image_src: None,
            opacity: 1.0,
        }
    }
}

#[derive(Debug)]
pub struct LayoutNode {
    pub path: String,
    pub tag: String,
    pub rect: LayoutRect,
    pub visual: VisualProps,
    pub attrs: IndexMap<String, String>,
    pub children: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct LayoutTree {
    pub nodes: Vec<LayoutNode>,
    pub viewport_width: f32,
    pub viewport_height: f32,
}

impl LayoutTree {
    /// Actual content height — may exceed viewport for long pages.
    pub fn content_height(&self) -> f32 {
        self.nodes.iter()
            .map(|n| n.rect.y + n.rect.height)
            .fold(0.0f32, f32::max)
    }
}

pub struct LayoutEngine {
    pub viewport_width: f32,
    pub viewport_height: f32,
}

impl LayoutEngine {
    pub fn new(viewport_width: u32, viewport_height: u32) -> Self {
        Self { viewport_width: viewport_width as f32, viewport_height: viewport_height as f32 }
    }

    pub fn compute(&self, snapshot: &DomSnapshot, style_map: &StyleMap) -> Result<LayoutTree> {
        let mut taffy = TaffyTree::new();
        let inherited = InheritedProps { color: [0, 0, 0, 255], font_size: 16.0, font_weight: 400 };

        let root_node = self
            .build_taffy_tree(&mut taffy, snapshot, style_map, &inherited)
            .map_err(|e| CarapaceError::Layout(format!("taffy build: {:?}", e)))?;

        taffy.compute_layout(
            root_node,
            Size {
                width: AvailableSpace::Definite(self.viewport_width),
                height: AvailableSpace::MaxContent,  // expand to full page height
            },
        ).map_err(|e| CarapaceError::Layout(format!("taffy layout: {:?}", e)))?;

        let mut layout_tree = LayoutTree {
            nodes: Vec::new(),
            viewport_width: self.viewport_width,
            viewport_height: self.viewport_height,
        };

        self.extract_layout(&taffy, root_node, snapshot, style_map, 0.0, 0.0, "0", &inherited, &mut layout_tree);

        debug!("layout: {} nodes, content height {:.0}px", layout_tree.nodes.len(), layout_tree.content_height());
        Ok(layout_tree)
    }

    fn build_taffy_tree(
        &self,
        taffy: &mut TaffyTree,
        snapshot: &DomSnapshot,
        style_map: &StyleMap,
        inherited: &InheritedProps,
    ) -> std::result::Result<NodeId, taffy::TaffyError> {
        let resolved = resolve_node_styles(snapshot, style_map);
        let font_size = resolved.get("font-size")
            .and_then(|v| parse_font_size(v))
            .unwrap_or(inherited.font_size);
        let eff_font_size = heading_font_size(&snapshot.tag, font_size).unwrap_or(font_size);

        let child_inherited = InheritedProps {
            color: resolved.get("color").and_then(|v| parse_color(v)).unwrap_or(inherited.color),
            font_size: eff_font_size,
            font_weight: if is_bold_tag(&snapshot.tag) { 700 } else { inherited.font_weight },
        };

        let style = self.resolved_to_taffy_style(snapshot, &resolved, eff_font_size);

        let children: Vec<NodeId> = snapshot.children.iter()
            .map(|child| self.build_taffy_tree(taffy, child, style_map, &child_inherited))
            .collect::<std::result::Result<_, _>>()?;

        taffy.new_with_children(style, &children)
    }

    fn resolved_to_taffy_style(
        &self, snapshot: &DomSnapshot, resolved: &HashMap<String, String>, font_size: f32,
    ) -> Style {
        let mut style = Style::DEFAULT;

        // display
        style.display = match resolved.get("display").map(|s| s.trim()) {
            Some("flex")  => Display::Flex,
            Some("grid")  => Display::Grid,
            Some("none")  => Display::None,
            _ => Display::Block,
        };

        // flex direction & wrap
        if let Some(dir) = resolved.get("flex-direction") {
            style.flex_direction = match dir.trim() {
                "row"            => FlexDirection::Row,
                "column"         => FlexDirection::Column,
                "row-reverse"    => FlexDirection::RowReverse,
                "column-reverse" => FlexDirection::ColumnReverse,
                _ => FlexDirection::Row,
            };
        }
        if resolved.get("flex-wrap").map(|s| s.trim()) == Some("wrap") {
            style.flex_wrap = FlexWrap::Wrap;
        }
        // align-items
        if let Some(ai) = resolved.get("align-items") {
            style.align_items = match ai.trim() {
                "center"      => Some(AlignItems::Center),
                "flex-start" | "start" => Some(AlignItems::FlexStart),
                "flex-end"   | "end"   => Some(AlignItems::FlexEnd),
                "stretch"     => Some(AlignItems::Stretch),
                _ => None,
            };
        }
        // justify-content
        if let Some(jc) = resolved.get("justify-content") {
            style.justify_content = match jc.trim() {
                "center"        => Some(JustifyContent::Center),
                "flex-start"   | "start"         => Some(JustifyContent::FlexStart),
                "flex-end"     | "end"           => Some(JustifyContent::FlexEnd),
                "space-between" => Some(JustifyContent::SpaceBetween),
                "space-around"  => Some(JustifyContent::SpaceAround),
                "space-evenly"  => Some(JustifyContent::SpaceEvenly),
                _ => None,
            };
        }

        // gap
        if let Some(gap) = resolved.get("gap").and_then(|v| parse_length(v)) {
            style.gap = taffy::geometry::Size { width: LengthPercentage::Length(gap), height: LengthPercentage::Length(gap) };
        }

        // width / height
        if let Some(w) = resolved.get("width").and_then(|v| parse_dimension(v)) {
            style.size.width = w;
        } else if is_block_tag(&snapshot.tag) {
            style.size.width = Dimension::Percent(1.0);
        }
        if let Some(h) = resolved.get("height").and_then(|v| parse_dimension(v)) {
            style.size.height = h;
        }

        // min/max
        if let Some(v) = resolved.get("min-width").and_then(|v| parse_dimension(v)) { style.min_size.width = v; }
        if let Some(v) = resolved.get("max-width").and_then(|v| parse_dimension(v)) { style.max_size.width = v; }
        if let Some(v) = resolved.get("min-height").and_then(|v| parse_dimension(v)) { style.min_size.height = v; }

        // padding (handle all four sides or shorthand)
        let pad = parse_box4(resolved, "padding");
        style.padding = taffy::geometry::Rect {
            top:    LengthPercentage::Length(pad[0]),
            right:  LengthPercentage::Length(pad[1]),
            bottom: LengthPercentage::Length(pad[2]),
            left:   LengthPercentage::Length(pad[3]),
        };

        // margin
        let mar = parse_box4(resolved, "margin");
        style.margin = taffy::geometry::Rect {
            top:    LengthPercentageAuto::Length(mar[0]),
            right:  LengthPercentageAuto::Length(mar[1]),
            bottom: LengthPercentageAuto::Length(mar[2]),
            left:   LengthPercentageAuto::Length(mar[3]),
        };

        // Text nodes: give them height based on font size
        if snapshot.tag == "#text" {
            if snapshot.text.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(false) {
                let line_count = estimate_line_count(
                    snapshot.text.as_deref().unwrap_or(""),
                    self.viewport_width,
                    font_size,
                );
                style.size.height = Dimension::Length(font_size * 1.4 * line_count as f32);
                style.size.width = Dimension::Percent(1.0);
            }
        }

        // Headings / paragraphs: min-height so empty ones still take space
        if style.min_size.height == Dimension::Auto {
            if let Some(min_h) = tag_min_height(&snapshot.tag, font_size) {
                style.min_size.height = Dimension::Length(min_h);
            }
        }

        style
    }

    fn extract_layout(
        &self, taffy: &TaffyTree, node: NodeId, snapshot: &DomSnapshot,
        style_map: &StyleMap, parent_x: f32, parent_y: f32, path: &str,
        inherited: &InheritedProps, tree: &mut LayoutTree,
    ) {
        let layout = taffy.layout(node).unwrap();
        let x = parent_x + layout.location.x;
        let y = parent_y + layout.location.y;

        let resolved = resolve_node_styles(snapshot, style_map);
        let font_size = resolved.get("font-size").and_then(|v| parse_font_size(v)).unwrap_or(inherited.font_size);
        let eff_font_size = heading_font_size(&snapshot.tag, font_size).unwrap_or(font_size);
        let font_weight = if is_bold_tag(&snapshot.tag) { 700 }
            else { resolved.get("font-weight").and_then(|v| parse_font_weight(v)).unwrap_or(inherited.font_weight) };
        let color = resolved.get("color").and_then(|v| parse_color(v)).unwrap_or(inherited.color);
        let text_align = match resolved.get("text-align").map(|s| s.trim()) {
            Some("center") => TextAlign::Center,
            Some("right")  => TextAlign::Right,
            _ => TextAlign::Left,
        };

        // Background: check background-color first, then background shorthand (only if it's a plain colour)
        let background = resolved.get("background-color")
            .and_then(|v| parse_color(v))
            .or_else(|| resolved.get("background").and_then(|v| parse_color(v)));

        let opacity = resolved.get("opacity")
            .and_then(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(1.0);

        // For <img>, capture resolved src URL
        let image_src = if snapshot.tag == "img" {
            snapshot.attrs.get("src").cloned()
        } else {
            None
        };

        let idx = tree.nodes.len();
        tree.nodes.push(LayoutNode {
            path: path.to_string(),
            tag: snapshot.tag.clone(),
            rect: LayoutRect { x, y, width: layout.size.width, height: layout.size.height },
            visual: VisualProps {
                background,
                color,
                font_size: eff_font_size,
                font_weight,
                text_align,
                text_content: snapshot.text.clone(),
                image_src,
                opacity,
            },
            attrs: snapshot.attrs.clone(),
            children: Vec::new(),
        });

        let child_inherited = InheritedProps { color, font_size: eff_font_size, font_weight };

        let child_nodes: Vec<NodeId> = taffy.children(node).unwrap_or_default();
        for (i, (child_node, child_snapshot)) in child_nodes.iter().zip(snapshot.children.iter()).enumerate() {
            let child_path = format!("{}.{}", path, i);
            let child_idx = tree.nodes.len();
            self.extract_layout(taffy, *child_node, child_snapshot, style_map, x, y, &child_path, &child_inherited, tree);
            tree.nodes[idx].children.push(child_idx);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct InheritedProps { color: [u8; 4], font_size: f32, font_weight: u16 }

fn resolve_node_styles(snapshot: &DomSnapshot, style_map: &StyleMap) -> HashMap<String, String> {
    let tag = snapshot.tag.as_str();
    let class_str = snapshot.attrs.get("class").map(|s| s.as_str()).unwrap_or("");
    let classes: Vec<&str> = class_str.split_whitespace().collect();
    let id = snapshot.attrs.get("id").map(|s| s.as_str());
    let inline: HashMap<String, String> = snapshot.style.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    resolve_styles(tag, &classes, id, &inline, style_map)
}

fn is_block_tag(tag: &str) -> bool {
    matches!(tag,
        "div"|"p"|"section"|"article"|"header"|"footer"|"main"|"nav"|"aside"
        |"ul"|"ol"|"li"|"table"|"thead"|"tbody"|"tr"|"td"|"th"|"form"|"fieldset"
        |"h1"|"h2"|"h3"|"h4"|"h5"|"h6"|"blockquote"|"pre"|"figure"|"figcaption"
        |"details"|"summary"|"html"|"body"|"img"
    )
}

fn is_bold_tag(tag: &str) -> bool {
    matches!(tag, "b"|"strong"|"h1"|"h2"|"h3"|"h4"|"h5"|"h6")
}

fn heading_font_size(tag: &str, base: f32) -> Option<f32> {
    match tag {
        "h1" => Some(base * 2.0),
        "h2" => Some(base * 1.5),
        "h3" => Some(base * 1.17),
        "h4" => Some(base * 1.0),
        "h5" => Some(base * 0.83),
        "h6" => Some(base * 0.67),
        _ => None,
    }
}

fn tag_min_height(tag: &str, font_size: f32) -> Option<f32> {
    match tag {
        "h1" => Some(font_size * 2.0 * 1.6),
        "h2" => Some(font_size * 1.5 * 1.6),
        "h3" => Some(font_size * 1.17 * 1.6),
        "h4"|"h5"|"h6" => Some(font_size * 1.6),
        "p"  => Some(font_size * 1.6),
        "li" => Some(font_size * 1.6),
        _ => None,
    }
}

fn parse_font_weight(v: &str) -> Option<u16> {
    match v.trim() {
        "bold"   => Some(700),
        "normal" => Some(400),
        "lighter" => Some(300),
        "bolder" => Some(700),
        s => s.parse::<u16>().ok(),
    }
}

fn parse_dimension(value: &str) -> Option<Dimension> {
    let v = value.trim();
    if v == "auto"  { return Some(Dimension::Auto); }
    if v == "100%"  { return Some(Dimension::Percent(1.0)); }
    if let Some(pct) = v.strip_suffix('%') {
        return pct.trim().parse::<f32>().ok().map(|x| Dimension::Percent(x / 100.0));
    }
    if let Some(px) = v.strip_suffix("px") { return px.trim().parse::<f32>().ok().map(Dimension::Length); }
    if let Some(em) = v.strip_suffix("em") { return em.trim().parse::<f32>().ok().map(|x| Dimension::Length(x * 16.0)); }
    if let Some(rem) = v.strip_suffix("rem") { return rem.trim().parse::<f32>().ok().map(|x| Dimension::Length(x * 16.0)); }
    if v == "0" { return Some(Dimension::Length(0.0)); }
    None
}

fn parse_length(value: &str) -> Option<f32> {
    let v = value.trim();
    if v == "0" { return Some(0.0); }
    if let Some(px) = v.strip_suffix("px") { return px.trim().parse::<f32>().ok(); }
    if let Some(em) = v.strip_suffix("em") { return em.trim().parse::<f32>().ok().map(|x| x * 16.0); }
    None
}

/// Parse CSS box shorthand + individual sides into [top, right, bottom, left]
fn parse_box4(resolved: &HashMap<String, String>, prop: &str) -> [f32; 4] {
    // Individual sides override shorthand
    let shorthand = parse_box_shorthand(resolved.get(prop).map(|s| s.as_str()).unwrap_or(""));
    let top    = resolved.get(&format!("{}-top",    prop)).and_then(|v| parse_length(v)).unwrap_or(shorthand[0]);
    let right  = resolved.get(&format!("{}-right",  prop)).and_then(|v| parse_length(v)).unwrap_or(shorthand[1]);
    let bottom = resolved.get(&format!("{}-bottom", prop)).and_then(|v| parse_length(v)).unwrap_or(shorthand[2]);
    let left   = resolved.get(&format!("{}-left",   prop)).and_then(|v| parse_length(v)).unwrap_or(shorthand[3]);
    [top, right, bottom, left]
}

fn parse_box_shorthand(value: &str) -> [f32; 4] {
    let parts: Vec<f32> = value.split_whitespace()
        .filter_map(|v| parse_length(v).or(if v == "auto" { Some(0.0) } else { None }))
        .collect();
    match parts.len() {
        1 => [parts[0]; 4],
        2 => [parts[0], parts[1], parts[0], parts[1]],
        3 => [parts[0], parts[1], parts[2], parts[1]],
        4 => [parts[0], parts[1], parts[2], parts[3]],
        _ => [0.0; 4],
    }
}

/// Rough line count estimate for pre-sizing text nodes in taffy
fn estimate_line_count(text: &str, container_width: f32, font_size: f32) -> usize {
    let chars_per_line = (container_width / (font_size * 0.55)).max(1.0) as usize;
    let word_count: usize = text.split_whitespace().count();
    let words_per_line = (chars_per_line / 6).max(1);
    (word_count / words_per_line + 1).max(1)
}
