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
