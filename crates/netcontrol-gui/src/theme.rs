#![allow(dead_code)] // full theme palette kept as a reference set
//! Dark-Tech theme ported from the original Avalonia `App.axaml` palette.

use egui::Color32;

// ── Backgrounds / surfaces ──
pub const APP_BACKGROUND: Color32 = Color32::from_rgb(0x0D, 0x11, 0x17);
pub const CARD_BACKGROUND: Color32 = Color32::from_rgb(0x16, 0x1B, 0x22);
pub const CARD_ELEVATED: Color32 = Color32::from_rgb(0x21, 0x26, 0x2D);
pub const HEADER_BACKGROUND: Color32 = Color32::from_rgb(0x12, 0x16, 0x1D);
pub const BORDER_DEFAULT: Color32 = Color32::from_rgb(0x30, 0x36, 0x3D);
pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(0x21, 0x26, 0x2D);

// ── Text ──
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xF0, 0xF6, 0xFC);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(0x8B, 0x94, 0x9E);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x6E, 0x76, 0x81);

// ── Accents ──
pub const ACCENT_PRIMARY: Color32 = Color32::from_rgb(0x2F, 0x81, 0xF7);
pub const ACCENT_PRIMARY_HOVER: Color32 = Color32::from_rgb(0x38, 0x8B, 0xFD);

pub const ACCENT_DANGER: Color32 = Color32::from_rgb(0xF8, 0x51, 0x49);
pub const ACCENT_DANGER_BG: Color32 = Color32::from_rgb(0x26, 0x12, 0x14);

pub const ACCENT_SUCCESS: Color32 = Color32::from_rgb(0x3F, 0xB9, 0x50);
pub const ACCENT_SUCCESS_BG: Color32 = Color32::from_rgb(0x12, 0x26, 0x16);

pub const ACCENT_WARNING: Color32 = Color32::from_rgb(0xD2, 0x99, 0x22);
pub const ACCENT_WARNING_BG: Color32 = Color32::from_rgb(0x27, 0x1E, 0x0B);

pub const ACCENT_CYAN: Color32 = Color32::from_rgb(0x58, 0xA6, 0xFF);
pub const ACCENT_CYAN_BG: Color32 = Color32::from_rgb(0x0D, 0x27, 0x44);

/// Muted traffic color (idle rows), matching the C# "#6E7681".
pub const TRAFFIC_IDLE: Color32 = TEXT_MUTED;
/// Active download color, matching "#3FB950".
pub const TRAFFIC_DOWN: Color32 = ACCENT_SUCCESS;
/// Active upload color, matching "#58A6FF".
pub const TRAFFIC_UP: Color32 = ACCENT_CYAN;

/// Parses one of the brush-hex strings the core returns (e.g. "#3FB950").
pub fn parse_hex(hex: &str) -> Color32 {
    let h = hex.trim_start_matches('#');
    if h.len() == 6 {
        if let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&h[0..2], 16),
            u8::from_str_radix(&h[2..4], 16),
            u8::from_str_radix(&h[4..6], 16),
        ) {
            return Color32::from_rgb(r, g, b);
        }
    }
    TEXT_MUTED
}

/// Applies the dark visuals to the egui context so panels, widgets, and text
/// match the original theme.
pub fn apply(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = APP_BACKGROUND;
    visuals.window_fill = CARD_BACKGROUND;
    visuals.extreme_bg_color = APP_BACKGROUND;
    visuals.faint_bg_color = CARD_ELEVATED;
    visuals.override_text_color = Some(TEXT_PRIMARY);
    visuals.hyperlink_color = ACCENT_CYAN;
    visuals.selection.bg_fill = ACCENT_PRIMARY.linear_multiply(0.35);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, ACCENT_PRIMARY);

    // Widget styling (checkboxes, drag values, combo).
    visuals.widgets.inactive.bg_fill = CARD_ELEVATED;
    visuals.widgets.inactive.weak_bg_fill = CARD_ELEVATED;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, BORDER_DEFAULT);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, TEXT_SECONDARY);
    visuals.widgets.hovered.bg_fill = CARD_ELEVATED;
    visuals.widgets.hovered.weak_bg_fill = CARD_ELEVATED;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT_PRIMARY);
    visuals.widgets.active.bg_fill = ACCENT_PRIMARY;
    visuals.widgets.active.weak_bg_fill = ACCENT_PRIMARY;
    visuals.widgets.open.bg_fill = CARD_BACKGROUND;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}

/// A rounded card frame with the standard card background + border.
pub fn card() -> egui::Frame {
    egui::Frame::none()
        .fill(CARD_BACKGROUND)
        .stroke(egui::Stroke::new(1.0_f32, BORDER_DEFAULT))
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
}

/// A small rounded badge frame with a given fill + stroke color.
pub fn badge(fill: Color32, stroke: Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0_f32, stroke))
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(5.0, 1.0))
}
