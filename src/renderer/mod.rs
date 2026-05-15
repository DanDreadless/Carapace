pub mod backend;

use std::collections::HashMap;
use std::path::Path;

use ab_glyph::{Font as _, FontArc, PxScale, ScaleFont};
use fontdb::Database;
use image::DynamicImage;
use tiny_skia::{Color, Paint, Pixmap, Rect as SkRect, Transform};
use tracing::{info, warn};

use crate::error::{CarapaceError, Result};
use crate::layout::{LayoutNode, LayoutTree, TextAlign};

/// Decoded images keyed by the original `src` attribute value from HTML.
pub type ImageCache = HashMap<String, DynamicImage>;

pub struct Renderer {
    pub viewport_width: u32,
    pub viewport_height: u32,
    font: Option<FontArc>,
    bold_font: Option<FontArc>,
}

impl Renderer {
    pub fn new(viewport_width: u32, viewport_height: u32) -> Self {
        let (font, bold_font) = load_fonts();
        Self { viewport_width, viewport_height, font, bold_font }
    }

    pub fn render_png(&self, layout: &LayoutTree, output_path: &Path, images: &ImageCache) -> Result<()> {
        // Expand canvas to full page height (content may exceed the viewport arg)
        let canvas_h = layout.content_height().ceil() as u32;
        let canvas_h = canvas_h.max(self.viewport_height).min(32_000); // guard against runaway pages

        let mut pixmap = Pixmap::new(self.viewport_width, canvas_h)
            .ok_or_else(|| CarapaceError::Render("failed to allocate pixmap".into()))?;

        pixmap.fill(Color::WHITE);

        // Paint order: backgrounds → images → text (so text is always on top)
        for node in &layout.nodes { self.paint_background(&mut pixmap, node); }
        for node in &layout.nodes { self.paint_image(&mut pixmap, node, images); }
        for node in &layout.nodes { self.paint_text(&mut pixmap, node); }

        pixmap.save_png(output_path).map_err(|e| CarapaceError::Render(e.to_string()))?;
        info!("PNG written to {} ({}×{})", output_path.display(), self.viewport_width, canvas_h);
        Ok(())
    }

    // ── Painting ─────────────────────────────────────────────────────────────

    fn paint_background(&self, pixmap: &mut Pixmap, node: &LayoutNode) {
        let bg = match node.visual.background {
            Some(c) if c[3] > 0 => c,
            _ => return,
        };
        if let Some(rect) = clip_rect(&node.rect, pixmap.width(), pixmap.height()) {
            let mut paint = Paint::default();
            paint.set_color(Color::from_rgba8(bg[0], bg[1], bg[2], bg[3]));
            paint.anti_alias = false;
            pixmap.fill_rect(rect, &paint, Transform::identity(), None);
        }
    }

    fn paint_image(&self, pixmap: &mut Pixmap, node: &LayoutNode, images: &ImageCache) {
        if node.tag != "img" { return; }
        let r = &node.rect;
        if r.width < 1.0 || r.height < 1.0 { return; }

        let src = match &node.visual.image_src {
            Some(s) => s.as_str(),
            None => return,
        };
        let img = match images.get(src) {
            Some(i) => i,
            None => {
                // Draw a placeholder grey box with an X
                if let Some(rect) = clip_rect(r, pixmap.width(), pixmap.height()) {
                    let mut paint = Paint::default();
                    paint.set_color(Color::from_rgba8(200, 200, 200, 255));
                    pixmap.fill_rect(rect, &paint, Transform::identity(), None);
                }
                return;
            }
        };

        blit_image(pixmap, img, r.x as i32, r.y as i32, r.width as u32, r.height as u32);
    }

    fn paint_text(&self, pixmap: &mut Pixmap, node: &LayoutNode) {
        let text = match &node.visual.text_content {
            Some(t) if !t.trim().is_empty() => t.clone(),
            _ => return,
        };
        if node.tag != "#text" { return; }
        if node.rect.width < 1.0 || node.rect.height < 1.0 { return; }
        if node.rect.y > pixmap.height() as f32 { return; }

        let font = if node.visual.font_weight >= 700 {
            self.bold_font.as_ref().or(self.font.as_ref())
        } else {
            self.font.as_ref()
        };
        let font = match font { Some(f) => f, None => return };

        let size = node.visual.font_size.clamp(6.0, 96.0);
        let scale = PxScale::from(size);
        let [cr, cg, cb, ca] = node.visual.color;
        let max_width = node.rect.width.max(1.0);

        let lines = wrap_text(font, scale, &text, max_width);
        let line_height = size * 1.4;
        let mut cursor_y = node.rect.y + size * 0.85; // ascender offset

        for line in &lines {
            if cursor_y > pixmap.height() as f32 { break; }
            let line_w = measure_text(font, scale, line);
            let cursor_x = match node.visual.text_align {
                TextAlign::Left   => node.rect.x,
                TextAlign::Center => node.rect.x + (max_width - line_w) / 2.0,
                TextAlign::Right  => node.rect.x + max_width - line_w,
            };
            draw_text_line(pixmap, font, line, cursor_x, cursor_y, scale, [cr, cg, cb, ca]);
            cursor_y += line_height;
        }
    }
}

// ── Font loading ──────────────────────────────────────────────────────────────

fn load_fonts() -> (Option<FontArc>, Option<FontArc>) {
    let mut db = Database::new();
    db.load_system_fonts();
    let regular = load_best_font(&db, false);
    let bold    = load_best_font(&db, true);
    (regular, bold)
}

fn load_best_font(db: &Database, bold: bool) -> Option<FontArc> {
    let weight = if bold { fontdb::Weight::BOLD } else { fontdb::Weight::NORMAL };
    let families = [
        fontdb::Family::Name("DejaVu Sans"),
        fontdb::Family::Name("Liberation Sans"),
        fontdb::Family::Name("FreeSans"),
        fontdb::Family::Name("Noto Sans"),
        fontdb::Family::SansSerif,
    ];
    for family in &families {
        let query = fontdb::Query {
            families: std::slice::from_ref(family),
            weight, style: fontdb::Style::Normal, stretch: fontdb::Stretch::Normal,
        };
        if let Some(id) = db.query(&query) {
            if let Some(face) = db.face(id) {
                let data = match &face.source {
                    fontdb::Source::File(path) => std::fs::read(path).ok()?,
                    fontdb::Source::Binary(data) => data.as_ref().as_ref().to_vec(),
                    fontdb::Source::SharedFile(path, _) => std::fs::read(path).ok()?,
                };
                match FontArc::try_from_vec(data) {
                    Ok(f) => { info!("loaded font: {:?} bold={}", family, bold); return Some(f); }
                    Err(e) => warn!("font parse error: {}", e),
                }
            }
        }
    }
    warn!("no suitable {} font found", if bold { "bold" } else { "regular" });
    None
}

// ── Image blitting ────────────────────────────────────────────────────────────

fn blit_image(pixmap: &mut Pixmap, img: &DynamicImage, dst_x: i32, dst_y: i32, dst_w: u32, dst_h: u32) {
    if dst_w == 0 || dst_h == 0 { return; }

    let rgba = img.to_rgba8();
    let (src_w, src_h) = (rgba.width(), rgba.height());

    // Scale the image to the destination rectangle
    let scaled = if src_w != dst_w || src_h != dst_h {
        image::imageops::resize(&rgba, dst_w, dst_h, image::imageops::FilterType::Lanczos3)
    } else {
        rgba
    };

    let pw = pixmap.width() as i32;
    let ph = pixmap.height() as i32;

    for dy in 0..dst_h {
        for dx in 0..dst_w {
            let px = dst_x + dx as i32;
            let py = dst_y + dy as i32;
            if px < 0 || py < 0 || px >= pw || py >= ph { continue; }

            let pixel = scaled.get_pixel(dx, dy);
            let [r, g, b, a] = pixel.0;
            if a == 0 { continue; }

            // Premultiply for tiny-skia
            let af = a as f32 / 255.0;
            if let Some(p) = tiny_skia::PremultipliedColorU8::from_rgba(
                (r as f32 * af) as u8,
                (g as f32 * af) as u8,
                (b as f32 * af) as u8,
                a,
            ) {
                let idx = (py as u32 * pixmap.width() + px as u32) as usize;
                pixmap.pixels_mut()[idx] = p;
            }
        }
    }
}

// ── Text helpers ──────────────────────────────────────────────────────────────

fn measure_text(font: &FontArc, scale: PxScale, text: &str) -> f32 {
    let scaled = font.as_scaled(scale);
    let mut width = 0.0f32;
    let mut prev: Option<ab_glyph::GlyphId> = None;
    for c in text.chars() {
        let gid = font.glyph_id(c);
        if let Some(p) = prev { width += scaled.kern(p, gid); }
        width += scaled.h_advance(gid);
        prev = Some(gid);
    }
    width
}

fn wrap_text(font: &FontArc, scale: PxScale, text: &str, max_width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        let mut line_w = 0.0f32;
        let scaled = font.as_scaled(scale);
        let space_w = scaled.h_advance(font.glyph_id(' '));

        for word in para.split_whitespace() {
            let word_w = measure_text(font, scale, word);
            if line.is_empty() {
                line.push_str(word);
                line_w = word_w;
            } else if line_w + space_w + word_w <= max_width {
                line.push(' ');
                line.push_str(word);
                line_w += space_w + word_w;
            } else {
                lines.push(std::mem::take(&mut line));
                line.push_str(word);
                line_w = word_w;
            }
        }
        lines.push(line);
    }
    if lines.is_empty() { lines.push(String::new()); }
    lines
}

fn draw_text_line(
    pixmap: &mut Pixmap, font: &FontArc,
    text: &str, mut x: f32, y: f32, scale: PxScale, color: [u8; 4],
) {
    let scaled = font.as_scaled(scale);
    let mut prev: Option<ab_glyph::GlyphId> = None;

    for c in text.chars() {
        let gid = font.glyph_id(c);
        if let Some(p) = prev { x += scaled.kern(p, gid); }
        let advance = scaled.h_advance(gid);

        if let Some(outlined) = font.outline_glyph(gid.with_scale_and_position(scale, ab_glyph::point(x, y))) {
            let bounds = outlined.px_bounds();
            let pw = pixmap.width() as i32;
            let ph = pixmap.height() as i32;
            let stride = pixmap.width();

            outlined.draw(|rx, ry, coverage| {
                if coverage < 0.01 { return; }
                let px = bounds.min.x as i32 + rx as i32;
                let py = bounds.min.y as i32 + ry as i32;
                if px < 0 || py < 0 || px >= pw || py >= ph { return; }
                let alpha = (coverage * color[3] as f32) as u8;
                let fa = alpha as f32 / 255.0;
                let idx = (py as u32 * stride + px as u32) as usize;
                let existing = pixmap.pixels()[idx];
                let ea = existing.alpha() as f32 / 255.0;
                let out_a = fa + ea * (1.0 - fa);
                if out_a < 0.001 { return; }
                let blend = |fg: u8, bg: u8| ((fg as f32 * fa + bg as f32 * ea * (1.0 - fa)) / out_a) as u8;
                let nr = blend(color[0], existing.red());
                let ng = blend(color[1], existing.green());
                let nb = blend(color[2], existing.blue());
                let na = (out_a * 255.0) as u8;
                if let Some(p) = tiny_skia::PremultipliedColorU8::from_rgba(nr, ng, nb, na) {
                    pixmap.pixels_mut()[idx] = p;
                }
            });
        }

        x += advance;
        prev = Some(gid);
    }
}

// ── Screenshot annotation (CARAPACE-08) ──────────────────────────────────────

const BADGE_H: u32 = 52;
/// Near-black at 90% opacity — sits over any page background colour.
const BADGE_BG: [u8; 4] = [12, 17, 23, 230];

fn risk_badge(risk: u8) -> ([u8; 4], &'static str) {
    if      risk >= 40 { ([239,  68,  68, 255], "MALICIOUS")  }
    else if risk >= 20 { ([249, 115,  22, 255], "SUSPICIOUS") }
    else if risk >=  1 { ([234, 179,   8, 255], "ELEVATED")   }
    else               { ([ 34, 197,  94, 255], "CLEAN")      }
}

fn truncate_text(font: &FontArc, scale: PxScale, text: &str, max_width: f32) -> String {
    let ellipsis_w = measure_text(font, scale, "...");
    let mut width = 0.0_f32;
    let scaled = font.as_scaled(scale);
    let mut prev: Option<ab_glyph::GlyphId> = None;
    let mut last_fit = text.len();
    for (i, c) in text.char_indices() {
        let gid = font.glyph_id(c);
        if let Some(p) = prev { width += scaled.kern(p, gid); }
        width += scaled.h_advance(gid);
        if width > max_width - ellipsis_w { last_fit = i; break; }
        prev = Some(gid);
    }
    if last_fit == text.len() { text.to_string() } else { format!("{}...", &text[..last_fit]) }
}

/// Fill a rectangle on an `RgbaImage` with alpha blending.
fn fill_rgba(img: &mut image::RgbaImage, x: u32, y: u32, w: u32, h: u32, color: [u8; 4]) {
    let (iw, ih) = img.dimensions();
    let fa = color[3] as f32 / 255.0;
    for py in y..(y + h).min(ih) {
        for px in x..(x + w).min(iw) {
            let [er, eg, eb, ea] = img.get_pixel(px, py).0;
            let ea_f = ea as f32 / 255.0;
            let out_a = (fa + ea_f * (1.0 - fa)).max(0.001);
            let blend = |fg: u8, bg: u8| ((fg as f32 * fa + bg as f32 * ea_f * (1.0 - fa)) / out_a) as u8;
            img.put_pixel(px, py, image::Rgba([blend(color[0], er), blend(color[1], eg), blend(color[2], eb), (out_a * 255.0) as u8]));
        }
    }
}

/// Render a text run onto an `RgbaImage` using `ab_glyph`.
fn draw_text_rgba(img: &mut image::RgbaImage, font: &FontArc, text: &str, mut x: f32, y: f32, scale: PxScale, color: [u8; 4]) {
    let scaled = font.as_scaled(scale);
    let mut prev: Option<ab_glyph::GlyphId> = None;
    let (iw, ih) = img.dimensions();
    for c in text.chars() {
        let gid = font.glyph_id(c);
        if let Some(p) = prev { x += scaled.kern(p, gid); }
        let advance = scaled.h_advance(gid);
        if let Some(outlined) = font.outline_glyph(gid.with_scale_and_position(scale, ab_glyph::point(x, y))) {
            let bounds = outlined.px_bounds();
            outlined.draw(|rx, ry, coverage| {
                if coverage < 0.01 { return; }
                let px = bounds.min.x as i32 + rx as i32;
                let py = bounds.min.y as i32 + ry as i32;
                if px < 0 || py < 0 || px >= iw as i32 || py >= ih as i32 { return; }
                let alpha = (coverage * color[3] as f32) as u8;
                let fa = alpha as f32 / 255.0;
                let [er, eg, eb, ea] = img.get_pixel(px as u32, py as u32).0;
                let ea_f = ea as f32 / 255.0;
                let out_a = (fa + ea_f * (1.0 - fa)).max(0.001);
                let blend = |fg: u8, bg: u8| ((fg as f32 * fa + bg as f32 * ea_f * (1.0 - fa)) / out_a) as u8;
                img.put_pixel(px as u32, py as u32, image::Rgba([blend(color[0], er), blend(color[1], eg), blend(color[2], eb), (out_a * 255.0) as u8]));
            });
        }
        x += advance;
        prev = Some(gid);
    }
}

/// Composite a risk annotation badge onto the bottom of a PNG screenshot in place.
///
/// Badge layout (36 px strip, full width):
///   `[VERDICT]  domain.com                      Risk: N  ·  YYYY-MM-DD HH:MM UTC`
///
/// Colours are keyed to Carapace risk score (≥40 MALICIOUS red, ≥20 SUSPICIOUS orange,
/// ≥1 ELEVATED amber, 0 CLEAN green).  No-ops on any load/save failure.
pub fn annotate_screenshot(path: &Path, risk_score: u8, domain: &str, scan_time: &str) {
    use image::GenericImage as _;

    let mut img = match image::open(path) {
        Ok(i)  => i.to_rgba8(),
        Err(e) => { warn!("annotate_screenshot: open {:?}: {}", path, e); return; }
    };

    let (w, h) = img.dimensions();
    if w == 0 || h == 0 { return; }

    let (font, bold) = load_fonts();
    let regular = font.as_ref().or(bold.as_ref());
    let bfont   = bold.as_ref().or(font.as_ref());

    let badge_y    = h.saturating_sub(BADGE_H);
    let font_sz    = PxScale::from(15.0);
    let center_y   = badge_y as f32 + BADGE_H as f32 / 2.0 + 5.0;  // text baseline

    // ── Background strip ──────────────────────────────────────────────────────
    fill_rgba(&mut img, 0, badge_y, w, BADGE_H, BADGE_BG);

    // ── Verdict pill ──────────────────────────────────────────────────────────
    let (pill_color, label) = risk_badge(risk_score);
    let pill_pad = 8.0_f32;
    let label_w  = bfont.map(|f| measure_text(f, font_sz, label)).unwrap_or(65.0);
    let pill_w   = (label_w + pill_pad * 2.0) as u32;
    let pill_h   = 32u32;
    let pill_x   = 12u32;
    let pill_y   = badge_y + (BADGE_H - pill_h) / 2;

    fill_rgba(&mut img, pill_x, pill_y, pill_w, pill_h, pill_color);

    if let Some(f) = bfont {
        let ty = pill_y as f32 + pill_h as f32 / 2.0 + 5.0;
        draw_text_rgba(&mut img, f, label, pill_x as f32 + pill_pad, ty, font_sz, [255, 255, 255, 255]);
    }

    // ── Domain ────────────────────────────────────────────────────────────────
    let domain_x = pill_x as f32 + pill_w as f32 + 12.0;
    // Right-side reserve is proportional to width so text doesn't cramp on 375px mobile captures.
    let right_reserve = (w as f32 * 0.38).min(220.0).max(80.0);
    if let Some(f) = regular {
        let max_domain_w = (w as f32 - domain_x - right_reserve).max(40.0);
        let truncated = truncate_text(f, font_sz, domain, max_domain_w);
        draw_text_rgba(&mut img, f, &truncated, domain_x, center_y, font_sz, [210, 210, 210, 255]);
    }

    // ── Right-aligned: "Risk: N  ·  timestamp" ───────────────────────────────
    // On narrow captures (mobile, <500 px) omit the timestamp to avoid overflow.
    let right_text = if w >= 500 {
        format!("Risk: {}  ·  {}", risk_score, scan_time)
    } else {
        format!("Risk: {}", risk_score)
    };
    let right_pad  = 12.0_f32;
    if let Some(f) = regular {
        let right_w = measure_text(f, font_sz, &right_text);
        let rx = w as f32 - right_pad - right_w;
        let [rc, gc, bc, _] = pill_color;
        draw_text_rgba(&mut img, f, &right_text, rx, center_y, font_sz, [rc, gc, bc, 220]);
    }

    if let Err(e) = img.save(path) {
        warn!("annotate_screenshot: save {:?}: {}", path, e);
    }
}

// ── Geometry helpers ──────────────────────────────────────────────────────────

fn clip_rect(r: &crate::layout::LayoutRect, pw: u32, ph: u32) -> Option<SkRect> {
    if r.width < 0.5 || r.height < 0.5 { return None; }
    if r.x >= pw as f32 || r.y >= ph as f32 { return None; }
    let x = r.x.max(0.0);
    let y = r.y.max(0.0);
    let w = (r.width - (x - r.x)).min(pw as f32 - x);
    let h = (r.height - (y - r.y)).min(ph as f32 - y);
    if w < 0.5 || h < 0.5 { return None; }
    SkRect::from_xywh(x, y, w, h)
}
