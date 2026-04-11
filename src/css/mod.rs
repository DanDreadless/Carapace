use std::collections::HashMap;
use tracing::{debug, warn};

use crate::error::{CarapaceError, Result};

/// selector → (property → value) with all `var()` references already resolved.
pub type StyleMap = HashMap<String, HashMap<String, String>>;

/// CSS custom property name (without `--`) → raw value.
pub type CssVarMap = HashMap<String, String>;

pub struct CssProcessor;

impl CssProcessor {
    pub fn new() -> Self { Self }

    /// Process a collection of CSS source strings.
    /// Returns a merged `StyleMap` and a map of all CSS custom properties found.
    pub fn process_sheets(&self, sheets: &[String]) -> Result<(StyleMap, CssVarMap)> {
        let mut merged_vars: CssVarMap = HashMap::new();
        let mut merged_rules: Vec<(String, HashMap<String, String>)> = Vec::new();

        for (i, css) in sheets.iter().enumerate() {
            debug!("processing stylesheet {}", i);
            match self.process_one(css) {
                Ok((rules, vars)) => {
                    merged_vars.extend(vars);
                    merged_rules.extend(rules);
                }
                Err(e) => warn!("stylesheet {} error: {}", i, e),
            }
        }

        // Now do a single pass substituting vars across all collected rules.
        let mut map: StyleMap = HashMap::new();
        for (sel, props) in merged_rules {
            let resolved_props: HashMap<String, String> = props
                .into_iter()
                .map(|(k, v)| (k, substitute_vars(&v, &merged_vars)))
                .collect();
            map.entry(sel).or_default().extend(resolved_props);
        }

        debug!("CSS: {} selectors, {} custom props", map.len(), merged_vars.len());
        Ok((map, merged_vars))
    }

    pub fn process_scss(&self, scss: &str) -> Result<(StyleMap, CssVarMap)> {
        let css = grass::from_string(scss.to_string(), &grass::Options::default())
            .map_err(|e| CarapaceError::CssProcessing(e.to_string()))?;
        self.process_one(&css).map(|(rules, vars)| {
            let map = rules.into_iter().collect();
            (map, vars)
        })
    }

    fn process_one(&self, css: &str) -> Result<(Vec<(String, HashMap<String, String>)>, CssVarMap)> {
        let css = self.strip_dangerous(css);
        let css = strip_comments(&css);

        let mut rules: Vec<(String, HashMap<String, String>)> = Vec::new();
        let mut vars: CssVarMap = HashMap::new();

        let mut i = 0;
        let bytes = css.as_bytes();
        let len = bytes.len();

        while i < len {
            // Skip whitespace
            while i < len && matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t') { i += 1; }
            if i >= len { break; }

            // @-rules
            if bytes[i] == b'@' {
                // @font-face, @keyframes, @media etc. — skip entire block
                // @charset / @import have no block
                let line_end = css[i..].find('\n').map(|p| i + p).unwrap_or(len);
                if let Some(open) = css[i..].find('{').map(|p| i + p) {
                    if open < line_end {
                        i = open + 1;
                        let mut depth = 1usize;
                        while i < len && depth > 0 {
                            match bytes[i] { b'{' => depth += 1, b'}' => depth -= 1, _ => {} }
                            i += 1;
                        }
                    } else {
                        i = line_end + 1;
                    }
                } else {
                    i = line_end + 1;
                }
                continue;
            }

            // Find opening brace
            let brace_open = match css[i..].find('{').map(|p| i + p) {
                Some(p) => p,
                None => break,
            };

            let selector_text = css[i..brace_open].trim();
            i = brace_open + 1;

            // Collect block content (matching braces)
            let mut depth = 1usize;
            let block_start = i;
            while i < len && depth > 0 {
                match bytes[i] { b'{' => depth += 1, b'}' => depth -= 1, _ => {} }
                i += 1;
            }
            let block = &css[block_start..i.saturating_sub(1)];

            if selector_text.is_empty() { continue; }

            let props = parse_declarations(block);

            // Handle :root — extract CSS custom properties
            let lower_sel = selector_text.to_ascii_lowercase();
            if lower_sel == ":root" || lower_sel == "html" || lower_sel == ":root,html" {
                for (k, v) in &props {
                    if k.starts_with("--") {
                        vars.insert(k[2..].to_string(), v.clone());
                    }
                }
                // Also add html as a real rule (for body defaults)
                if lower_sel != ":root" {
                    rules.push(("html".to_string(), props));
                }
                continue;
            }

            if props.is_empty() { continue; }

            // Comma-separated selectors
            for raw_sel in selector_text.split(',') {
                if let Some(s) = normalise_selector(raw_sel.trim()) {
                    rules.push((s, props.clone()));
                }
            }
        }

        Ok((rules, vars))
    }

    fn strip_dangerous(&self, css: &str) -> String {
        let mut out = css.to_string();
        for pattern in &[
            r"(?i)expression\s*\(",
            r#"(?i)url\s*\(\s*["']?\s*javascript:"#,
            r"(?i)-moz-binding\s*:",
            r"(?i)\bbehavior\s*:",
        ] {
            if let Ok(re) = regex::Regex::new(pattern) {
                out = re.replace_all(&out, "/* blocked */").into_owned();
            }
        }
        out
    }
}

/// Sanitise a raw CSS string for safe injection into the headless browser.
///
/// Strips anything that would cause the browser to make outbound network
/// requests: `@import` rules, external `url()` references in properties
/// (backgrounds, fonts, cursors, etc.), and `@font-face` blocks pointing at
/// remote sources.  Relative and `data:` `url()` references are kept.
pub fn sanitize_css_for_browser(css: &str) -> String {
    // Remove @import statements
    let import_re = regex::Regex::new(r#"(?im)@import\s+[^;]+;"#).unwrap();
    let mut out = import_re.replace_all(css, "/* @import blocked */").into_owned();

    // Remove external url() references — keeps data: and relative paths
    let ext_url_re = regex::Regex::new(
        r#"(?i)url\s*\(\s*['"]?\s*(?:https?://|//)[^)]*\)"#,
    ).unwrap();
    out = ext_url_re.replace_all(&out, "url(/* external blocked */)").into_owned();

    // Remove @font-face blocks (they almost always point to remote font files)
    let font_face_re = regex::Regex::new(r"(?is)@font-face\s*\{[^}]*\}").unwrap();
    out = font_face_re.replace_all(&out, "/* @font-face blocked */").into_owned();

    out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn strip_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            loop {
                match chars.next() {
                    None => break,
                    Some('*') if chars.peek() == Some(&'/') => { chars.next(); break; }
                    _ => {}
                }
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_declarations(block: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for decl in block.split(';') {
        if let Some((k, v)) = decl.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            if !k.is_empty() && !v.is_empty() {
                map.insert(k, v);
            }
        }
    }
    map
}

fn normalise_selector(sel: &str) -> Option<String> {
    if sel.contains(':') || sel.contains('>') || sel.contains('+') || sel.contains('~') { return None; }
    if sel.contains('[') { return None; }
    let trimmed = sel.trim();
    if trimmed.contains(' ') || trimmed.is_empty() { return None; }
    Some(trimmed.to_ascii_lowercase())
}

/// Substitute `var(--name)` and `var(--name, fallback)` using the given var map.
/// Handles one level of substitution; chained vars are resolved iteratively.
fn substitute_vars(value: &str, vars: &CssVarMap) -> String {
    if !value.contains("var(") { return value.to_string(); }

    let mut result = value.to_string();
    // Up to 8 substitution rounds to handle chained vars
    for _ in 0..8 {
        if !result.contains("var(") { break; }
        let mut new_result = String::new();
        let mut rest = result.as_str();
        while let Some(start) = rest.find("var(") {
            new_result.push_str(&rest[..start]);
            rest = &rest[start + 4..]; // skip "var("
            // Find matching closing paren
            let mut depth = 1usize;
            let mut end = 0;
            for (idx, ch) in rest.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => { depth -= 1; if depth == 0 { end = idx; break; } }
                    _ => {}
                }
            }
            let inner = &rest[..end];
            rest = &rest[end + 1..]; // skip closing ")"

            let (var_name, fallback): (&str, Option<&str>) = match inner.find(',') {
                Some(comma) => (inner[..comma].trim(), Some(inner[comma + 1..].trim())),
                None => (inner.trim(), None),
            };
            // Strip leading "--"
            let lookup_name = var_name.strip_prefix("--").unwrap_or(var_name);
            let replacement = vars.get(lookup_name)
                .map(|v| v.as_str())
                .or(fallback)
                .unwrap_or("initial");
            new_result.push_str(replacement);
        }
        new_result.push_str(rest);
        result = new_result;
    }
    result
}

// ── Style resolution ──────────────────────────────────────────────────────────

pub fn resolve_styles(
    tag: &str,
    classes: &[&str],
    id: Option<&str>,
    inline: &HashMap<String, String>,
    map: &StyleMap,
) -> HashMap<String, String> {
    let mut resolved: HashMap<String, String> = HashMap::new();

    if let Some(props) = map.get("*") {
        resolved.extend(props.clone());
    }
    if let Some(props) = map.get(tag) {
        resolved.extend(props.clone());
    }
    for class in classes {
        let key = format!(".{}", class);
        if let Some(props) = map.get(&key) { resolved.extend(props.clone()); }
        let key2 = format!("{}.{}", tag, class);
        if let Some(props) = map.get(&key2) { resolved.extend(props.clone()); }
    }
    if let Some(id_val) = id {
        let key = format!("#{}", id_val);
        if let Some(props) = map.get(&key) { resolved.extend(props.clone()); }
    }
    // Inline styles are highest priority
    resolved.extend(inline.clone());
    resolved
}

// ── Color / size parsing (used by layout + renderer) ─────────────────────────

pub fn parse_color(value: &str) -> Option<[u8; 4]> {
    let v = value.trim().to_ascii_lowercase();
    // Skip unresolved variables or functions we can't evaluate
    if v.starts_with("var(") || v.starts_with("calc(") || v.starts_with("linear-gradient") { return None; }

    match v.as_str() {
        "black"       => return Some([0,0,0,255]),
        "white"       => return Some([255,255,255,255]),
        "red"         => return Some([255,0,0,255]),
        "green"       => return Some([0,128,0,255]),
        "blue"        => return Some([0,0,255,255]),
        "yellow"      => return Some([255,255,0,255]),
        "orange"      => return Some([255,165,0,255]),
        "purple"      => return Some([128,0,128,255]),
        "pink"        => return Some([255,192,203,255]),
        "gray"|"grey" => return Some([128,128,128,255]),
        "darkgray"|"darkgrey" => return Some([169,169,169,255]),
        "lightgray"|"lightgrey" => return Some([211,211,211,255]),
        "transparent" => return Some([0,0,0,0]),
        "navy"   => return Some([0,0,128,255]),
        "teal"   => return Some([0,128,128,255]),
        "silver" => return Some([192,192,192,255]),
        "maroon" => return Some([128,0,0,255]),
        "lime"   => return Some([0,255,0,255]),
        "aqua"|"cyan" => return Some([0,255,255,255]),
        "fuchsia"|"magenta" => return Some([255,0,255,255]),
        "olive"   => return Some([128,128,0,255]),
        "coral"   => return Some([255,127,80,255]),
        "tomato"  => return Some([255,99,71,255]),
        "gold"    => return Some([255,215,0,255]),
        "indigo"  => return Some([75,0,130,255]),
        "violet"  => return Some([238,130,238,255]),
        "brown"   => return Some([165,42,42,255]),
        "crimson" => return Some([220,20,60,255]),
        "beige"   => return Some([245,245,220,255]),
        "lavender" => return Some([230,230,250,255]),
        "ivory"   => return Some([255,255,240,255]),
        "slategray"|"slategrey" => return Some([112,128,144,255]),
        _ => {}
    }

    if let Some(hex) = v.split_whitespace().next().and_then(|s| s.strip_prefix('#')) {
        return match hex.len() {
            3 => Some([
                u8::from_str_radix(&hex[0..1].repeat(2), 16).ok()?,
                u8::from_str_radix(&hex[1..2].repeat(2), 16).ok()?,
                u8::from_str_radix(&hex[2..3].repeat(2), 16).ok()?,
                255,
            ]),
            6 => Some([
                u8::from_str_radix(&hex[0..2], 16).ok()?,
                u8::from_str_radix(&hex[2..4], 16).ok()?,
                u8::from_str_radix(&hex[4..6], 16).ok()?,
                255,
            ]),
            8 => Some([
                u8::from_str_radix(&hex[0..2], 16).ok()?,
                u8::from_str_radix(&hex[2..4], 16).ok()?,
                u8::from_str_radix(&hex[4..6], 16).ok()?,
                u8::from_str_radix(&hex[6..8], 16).ok()?,
            ]),
            _ => None,
        };
    }

    if v.starts_with("rgb") {
        let inner = v.trim_start_matches("rgba(").trim_start_matches("rgb(").trim_end_matches(')');
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() >= 3 {
            let r = parts[0].trim().parse::<f32>().ok()? as u8;
            let g = parts[1].trim().parse::<f32>().ok()? as u8;
            let b = parts[2].trim().parse::<f32>().ok()? as u8;
            let a = if parts.len() >= 4 { (parts[3].trim().parse::<f32>().ok()? * 255.0) as u8 } else { 255 };
            return Some([r, g, b, a]);
        }
    }

    if v.starts_with("hsl") {
        let inner = v.trim_start_matches("hsla(").trim_start_matches("hsl(").trim_end_matches(')');
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() >= 3 {
            let h = parts[0].trim().parse::<f32>().ok()? / 360.0;
            let s = parts[1].trim().trim_end_matches('%').parse::<f32>().ok()? / 100.0;
            let l = parts[2].trim().trim_end_matches('%').parse::<f32>().ok()? / 100.0;
            let a = if parts.len() >= 4 { (parts[3].trim().parse::<f32>().ok()? * 255.0) as u8 } else { 255 };
            let [r, g, b] = hsl_to_rgb(h, s, l);
            return Some([r, g, b, a]);
        }
    }

    None
}

fn hsl_to_rgb(h: f32, s: f32, l: f32) -> [u8; 3] {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h * 6.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = if h < 1.0/6.0      { (c, x, 0.0) }
                   else if h < 2.0/6.0  { (x, c, 0.0) }
                   else if h < 3.0/6.0  { (0.0, c, x) }
                   else if h < 4.0/6.0  { (0.0, x, c) }
                   else if h < 5.0/6.0  { (x, 0.0, c) }
                   else                  { (c, 0.0, x) };
    [((r + m) * 255.0) as u8, ((g + m) * 255.0) as u8, ((b + m) * 255.0) as u8]
}

pub fn parse_font_size(value: &str) -> Option<f32> {
    let v = value.trim().to_ascii_lowercase();
    if let Some(px)  = v.strip_suffix("px")  { return px.trim().parse::<f32>().ok(); }
    if let Some(em)  = v.strip_suffix("em")  { return em.trim().parse::<f32>().ok().map(|x| x * 16.0); }
    if let Some(rem) = v.strip_suffix("rem") { return rem.trim().parse::<f32>().ok().map(|x| x * 16.0); }
    if let Some(pt)  = v.strip_suffix("pt")  { return pt.trim().parse::<f32>().ok().map(|x| x * 1.333); }
    match v.as_str() {
        "xx-small" => Some(9.0),
        "x-small"  => Some(10.0),
        "small"    => Some(13.0),
        "medium"   => Some(16.0),
        "large"    => Some(18.0),
        "x-large"  => Some(24.0),
        "xx-large" => Some(32.0),
        _ => None,
    }
}

pub fn parse_px(value: &str) -> Option<f32> {
    let v = value.trim().to_ascii_lowercase();
    if v == "0" { return Some(0.0); }
    if let Some(px) = v.strip_suffix("px") { return px.trim().parse::<f32>().ok(); }
    if let Some(em) = v.strip_suffix("em") { return em.trim().parse::<f32>().ok().map(|x| x * 16.0); }
    if let Some(rem) = v.strip_suffix("rem") { return rem.trim().parse::<f32>().ok().map(|x| x * 16.0); }
    None
}
