//! Visual identity: solder-mask green ground, copper accent, silkscreen ink.
use eframe::egui::{self, Color32, FontFamily, FontId, Rounding, Sense, Stroke, TextStyle, Ui};

pub const GROUND: Color32 = Color32::from_rgb(0x12, 0x1E, 0x18);
pub const SURFACE: Color32 = Color32::from_rgb(0x1B, 0x2B, 0x23);
pub const EDGE: Color32 = Color32::from_rgb(0x34, 0x4A, 0x3E);
pub const INK: Color32 = Color32::from_rgb(0xE4, 0xE6, 0xDA);
#[allow(dead_code)]
pub const INK_DIM: Color32 = Color32::from_rgb(0x8F, 0xA3, 0x96);
pub const COPPER: Color32 = Color32::from_rgb(0xC9, 0x8B, 0x4B);
pub const OK: Color32 = Color32::from_rgb(0x7F, 0xC8, 0xA0);
pub const WARN: Color32 = Color32::from_rgb(0xE0, 0xB0, 0x4A);
pub const BAD: Color32 = Color32::from_rgb(0xE5, 0x68, 0x5C);

pub fn apply(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = GROUND;
    v.window_fill = SURFACE;
    v.extreme_bg_color = Color32::from_rgb(0x0C, 0x15, 0x11);
    v.faint_bg_color = Color32::from_rgb(0x16, 0x24, 0x1D);
    v.override_text_color = Some(INK);
    v.hyperlink_color = COPPER;
    v.selection.bg_fill = Color32::from_rgb(0x5A, 0x41, 0x24);
    v.selection.stroke = Stroke::new(1.0_f32, COPPER);
    let r = Rounding::same(3.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.rounding = r;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, EDGE);
    v.widgets.inactive.weak_bg_fill = SURFACE;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, EDGE);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x25, 0x3A, 0x2F);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, COPPER);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x5A, 0x41, 0x24);
    ctx.set_visuals(v);

    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(10.0, 7.0);
        s.spacing.button_padding = egui::vec2(14.0, 6.0);
        s.spacing.interact_size.y = 26.0;
        let p = FontFamily::Proportional;
        s.text_styles = [
            (TextStyle::Heading, FontId::new(22.0, p.clone())),
            (TextStyle::Body, FontId::new(14.5, p.clone())),
            (TextStyle::Button, FontId::new(14.5, p.clone())),
            (TextStyle::Small, FontId::new(12.0, p)),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
    });
}

/// Flash-layout strip: one segment per partition, width proportional to size.
/// Copper = selected for extraction, dark = skipped.
pub fn partition_strip(ui: &mut Ui, parts: &[(&str, u64, bool)]) {
    let total: f32 = parts.iter().map(|p| p.1.max(1) as f32).sum();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 18.0), Sense::hover());
    ui.painter().rect_filled(
        rect,
        Rounding::same(2.0),
        Color32::from_rgb(0x0C, 0x15, 0x11),
    );
    let mut x = rect.left();
    for (i, (name, size, on)) in parts.iter().enumerate() {
        let w = (rect.width() * (*size).max(1) as f32 / total).max(2.0);
        let right = (x + w).min(rect.right());
        if right - x < 1.0 {
            break;
        }
        let seg = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2(right - 1.0, rect.bottom()),
        );
        ui.painter()
            .rect_filled(seg, Rounding::same(1.0), if *on { COPPER } else { EDGE });
        let resp = ui.interact(seg, ui.id().with(("seg", i)), Sense::hover());
        resp.on_hover_text(format!(
            "{} \u{2013} {}",
            name,
            super::app::format_bytes(*size)
        ));
        x += w;
    }
}
