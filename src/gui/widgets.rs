//! Shared styling, light/dark palette and small widgets.

use eframe::egui::{self, Color32, RichText, Stroke};

use super::ACCENT;
use crate::log::{Level, LogLine};

pub const MAX_LOG_LINES: usize = 2000;

/// Colors not covered by egui's own visuals, per theme.
pub struct Palette {
    pub bg: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub soft: Color32,
    pub stroke: Color32,
    pub log_bg: Color32,
    pub warn: Color32,
    pub error: Color32,
}

const LIGHT: Palette = Palette {
    bg: Color32::WHITE,
    text: Color32::from_rgb(0x05, 0x08, 0x10),
    muted: Color32::from_rgb(0x24, 0x2B, 0x36),
    soft: Color32::from_rgb(0xE8, 0xED, 0xF6),
    stroke: Color32::from_rgb(0xD9, 0xDE, 0xE7),
    log_bg: Color32::from_rgb(0xF8, 0xF9, 0xFB),
    warn: Color32::from_rgb(0xA1, 0x62, 0x07),
    error: Color32::from_rgb(0xB9, 0x1C, 0x1C),
};

const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x1B, 0x1F, 0x24),
    text: Color32::from_rgb(0xE5, 0xE7, 0xEB),
    muted: Color32::from_rgb(0x9C, 0xA3, 0xAF),
    soft: Color32::from_rgb(0x2A, 0x31, 0x3B),
    stroke: Color32::from_rgb(0x3A, 0x42, 0x4D),
    log_bg: Color32::from_rgb(0x14, 0x17, 0x1B),
    warn: Color32::from_rgb(0xF2, 0xB8, 0x4B),
    error: Color32::from_rgb(0xF8, 0x71, 0x71),
};

/// State shown by a tab badge (a side that is off shows no badge at all).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Pending,
    On,
}

impl Activity {
    pub fn color(self, p: &Palette) -> Color32 {
        match self {
            Activity::Pending => p.warn,
            Activity::On => Color32::from_rgb(0x22, 0xC5, 0x5E),
        }
    }
}

pub fn pal(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode { &DARK } else { &LIGHT }
}

pub fn style(ctx: &egui::Context) {
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        s.visuals.selection.bg_fill = ACCENT;
        s.visuals.widgets.inactive.corner_radius = 6.0.into();
        s.visuals.widgets.hovered.corner_radius = 6.0.into();
        s.visuals.widgets.active.corner_radius = 6.0.into();
        s.text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        s.text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    });
    // egui's light theme draws plain labels and buttons in mid-gray, which is hard to read
    // with the thin default font on white.
    ctx.style_mut_of(egui::Theme::Light, |s| {
        let w = &mut s.visuals.widgets;
        w.noninteractive.fg_stroke.color = LIGHT.text;
        w.inactive.fg_stroke.color = LIGHT.text;
        w.hovered.fg_stroke.color = Color32::BLACK;
        w.active.fg_stroke.color = Color32::BLACK;
        w.open.fg_stroke.color = LIGHT.text;
        // Hint texts and other "weak" text.
        s.visuals.weak_text_color = Some(LIGHT.muted);
    });
}

/// A running side's tab badge: download, upload and latency in the state's color, each
/// "—" until known (waiting for a client, connecting).
pub struct Badge {
    pub activity: Activity,
    pub traffic: Option<(u64, u64)>,
    pub rtt: Option<std::time::Duration>,
}

impl Badge {
    pub fn new(activity: Activity) -> Badge {
        Badge {
            activity,
            traffic: None,
            rtt: None,
        }
    }

    /// Throughput (rx, tx) and, once measured, the round-trip time through the tunnel.
    pub fn traffic(mut self, rx_tx: (u64, u64), rtt: Option<std::time::Duration>) -> Badge {
        self.traffic = Some(rx_tx);
        self.rtt = rtt;
        self
    }
}

/// Small vertical arrow (drawn, not a glyph) whose right edge is at `right`; returns its left edge.
fn paint_arrow(painter: &egui::Painter, right: f32, y: f32, color: Color32, up: bool) -> f32 {
    let (w, h) = (7.0, 9.0);
    let cx = right - w / 2.0;
    let (tip, base) = if up {
        (y - h / 2.0, y + h / 2.0)
    } else {
        (y + h / 2.0, y - h / 2.0)
    };
    let head = if up { tip + 3.5 } else { tip - 3.5 };
    painter.line_segment(
        [egui::pos2(cx, base), egui::pos2(cx, head)],
        Stroke::new(1.5_f32, color),
    );
    painter.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(cx, tip),
            egui::pos2(cx - w / 2.0, head),
            egui::pos2(cx + w / 2.0, head),
        ],
        color,
        Stroke::NONE,
    ));
    right - w
}

/// Tab badge, right-aligned at (`right`, `y`): `↓ rx ↑ tx · rtt` in the state's color, with
/// "— B/s" / "— ms" for what is not known yet.
pub fn paint_badge(painter: &egui::Painter, right: f32, y: f32, color: Color32, badge: &Badge) {
    use crate::log::{format_rate, format_rtt};
    let font = egui::FontId::proportional(12.5);
    // Not known yet: the smallest unit, so the badge reads the same as with numbers.
    let rate = |v: Option<u64>| v.map_or_else(|| "— B/s".to_string(), format_rate);
    let texts = [
        badge.rtt.map_or_else(|| "— ms".to_string(), format_rtt),
        rate(badge.traffic.map(|t| t.1)),
        rate(badge.traffic.map(|t| t.0)),
    ];
    let galleys = texts.map(|s| painter.layout_no_wrap(s, font.clone(), color));
    // Each value is right-aligned in a fixed slot as wide as the widest text its format gives
    // (three significant digits, so "888 KB/s" or "8.88 MB/s"): the arrows and dots stay put,
    // with no gap left over from a once wider value.
    let widest = |samples: &[&str]| {
        samples
            .iter()
            .map(|s| painter.layout_no_wrap(s.to_string(), font.clone(), color).size().x)
            .fold(0.0, f32::max)
    };
    let rate_slot = widest(&["888 B/s", "888 KB/s", "8.88 KB/s", "8.88 MB/s", "888 MB/s"]);
    let slots = [widest(&["888 ms", "8.8 s", "<1 ms"]), rate_slot, rate_slot];
    let [rtt, tx, rx] = galleys;
    let text_right = |x: f32, g: std::sync::Arc<egui::Galley>| {
        painter.galley(egui::pos2(x - g.size().x, y - g.size().y / 2.0), g, color);
    };
    // Each mark (dot, arrows) sits right before its number; a slot's spare room goes to the left
    // of the mark, so the groups stay put while the mark follows the number.
    let mut x = right;
    let rtt_w = rtt.size().x;
    text_right(x, rtt);
    let dot = painter.layout_no_wrap("·".into(), font.clone(), color);
    let dot_w = dot.size().x;
    text_right(x - rtt_w - 4.0, dot);
    x -= slots[0] + 4.0 + dot_w + 10.0;
    let (tx_w, rx_w) = (tx.size().x, rx.size().x);
    text_right(x, tx);
    paint_arrow(painter, x - tx_w - 3.0, y, color, true);
    x -= slots[1] + 3.0 + 7.0 + 10.0;
    text_right(x, rx);
    paint_arrow(painter, x - rx_w - 3.0, y, color, false);
}

fn paint_sun(painter: &egui::Painter, c: egui::Pos2, color: Color32) {
    painter.circle_filled(c, 3.5, color);
    for i in 0..8 {
        let a = i as f32 * std::f32::consts::FRAC_PI_4;
        let d = egui::vec2(a.cos(), a.sin());
        painter.line_segment([c + d * 5.5, c + d * 7.5], Stroke::new(1.5_f32, color));
    }
}

fn paint_moon(painter: &egui::Painter, c: egui::Pos2, color: Color32, bg: Color32) {
    painter.circle_filled(c, 6.0, color);
    // Cut a crescent out of the disc with the background color.
    painter.circle_filled(c + egui::vec2(3.0, -2.5), 5.0, bg);
}

/// Applies "System" / "Light" / "Dark".
pub fn apply_theme(ctx: &egui::Context, theme: &str) {
    let pref = match theme {
        "Light" => egui::ThemePreference::Light,
        "Dark" => egui::ThemePreference::Dark,
        _ => egui::ThemePreference::System,
    };
    ctx.set_theme(pref);
}

pub fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .stroke(Stroke::new(1.0_f32, pal(ui).stroke))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

pub fn title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(19.0).strong().color(pal(ui).text));
}

/// Small upper-case caption above an input.
pub fn caption(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).size(11.5).color(pal(ui).muted));
}

/// Secondary/explanatory text.
pub fn muted(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).color(pal(ui).muted));
}

pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).color(Color32::WHITE).strong())
        .fill(ACCENT)
        .min_size(egui::vec2(84.0, 32.0))
}

/// Theme-aware default button.
pub fn secondary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(text.to_string()).min_size(egui::vec2(84.0, 32.0))
}

/// Height of the settings row under the fields, the same on both tabs: fits the password text,
/// so toggling Secure does not make the panel jump.
pub const SETTINGS_ROW_HEIGHT: f32 = 26.0;

/// "Copied to clipboard" shown under the control that copied, for two seconds.
#[derive(Default)]
pub struct Copied {
    shown: Option<(std::time::Instant, egui::Pos2)>,
}

impl Copied {
    /// Copies `text` and notes where to show the confirmation (under `from`).
    pub fn copy(&mut self, ctx: &egui::Context, text: String, from: &egui::Response) {
        ctx.copy_text(text);
        self.shown = Some((
            std::time::Instant::now(),
            from.rect.left_bottom() + egui::vec2(0.0, 4.0),
        ));
    }

    /// Whether the confirmation is still shown (a hover text of the same control would cover it).
    pub fn active(&self) -> bool {
        self.shown.is_some_and(|(at, _)| at.elapsed() < Self::SHOWN_FOR)
    }

    const SHOWN_FOR: std::time::Duration = std::time::Duration::from_secs(2);

    /// Draws the confirmation while it lasts; call once per frame.
    pub fn ui(&mut self, ui: &egui::Ui) {
        let Some((at, pos)) = self.shown else { return };
        let Some(left) = Self::SHOWN_FOR.checked_sub(at.elapsed()) else {
            self.shown = None;
            return;
        };
        egui::Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), egui::Id::unique("copied"), pos).show(|ui| {
            ui.label("Copied to clipboard");
        });
        ui.ctx().request_repaint_after(left);
    }
}

/// A small button, like the log's Copy / Clear, for the settings rows.
pub fn small_button(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(enabled, egui::Button::new(text.to_string()).small())
}

/// Modal dialog with a dimmed backdrop: title, body, and right-aligned `[cancel] [primary]`.
/// Returns `Some(true)` for the primary button, `Some(false)` for cancel / Esc / click outside.
pub fn modal(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    primary: &str,
    cancel: &str,
    body: impl FnOnce(&mut egui::Ui),
) -> Option<bool> {
    let mut answer = None;
    let resp = egui::Modal::new(egui::Id::unique(id)).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.label(RichText::new(title).size(17.0).strong().color(pal(ui).text));
        ui.add_space(6.0);
        body(ui);
        ui.add_space(14.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(primary_button(primary)).clicked() {
                answer = Some(true);
            }
            if ui.add(secondary_button(cancel)).clicked() {
                answer = Some(false);
            }
        });
    });
    if answer.is_none() && resp.should_close() {
        answer = Some(false);
    }
    answer
}

/// Modal notice with a single OK button; returns true when dismissed.
pub fn info_modal(ctx: &egui::Context, id: &str, title: &str, text: &str) -> bool {
    let mut closed = false;
    let resp = egui::Modal::new(egui::Id::unique(id)).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.label(RichText::new(title).size(17.0).strong().color(pal(ui).text));
        ui.add_space(6.0);
        muted(ui, text);
        ui.add_space(14.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(primary_button("OK")).clicked() {
                closed = true;
            }
        });
    });
    closed || resp.should_close()
}

/// Compact segmented control: `Auto | sun | moon` (icons are drawn, not emoji).
/// Returns the newly chosen theme.
pub fn theme_switch(ui: &mut egui::Ui, current: &str) -> Option<&'static str> {
    let p = pal(ui);
    let mut chosen = None;
    egui::Frame::new()
        .fill(p.soft)
        .corner_radius(14.0)
        .inner_margin(egui::Margin::same(3))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                for (theme, width) in [("System", 44.0), ("Light", 32.0), ("Dark", 32.0)] {
                    let selected = current == theme;
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, 24.0), egui::Sense::click());
                    let bg = if selected {
                        ACCENT
                    } else if resp.hovered() {
                        p.stroke
                    } else {
                        p.soft
                    };
                    let fg = if selected { Color32::WHITE } else { p.muted };
                    let painter = ui.painter();
                    painter.rect_filled(rect, 11.0, bg);
                    match theme {
                        "Light" => paint_sun(painter, rect.center(), fg),
                        "Dark" => paint_moon(painter, rect.center(), fg, bg),
                        _ => {
                            painter.text(
                                rect.center(),
                                egui::Align2::CENTER_CENTER,
                                "Auto",
                                egui::FontId::proportional(13.0),
                                fg,
                            );
                        }
                    }
                    if resp.clicked() && !selected {
                        chosen = Some(theme);
                    }
                }
            });
        });
    chosen
}

/// Status line under a tab's controls. The tab itself shows the state, so this shows details:
/// who is connected and for how long, retries, why it ended.
pub fn status_bar(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) {
    let p = pal(ui);
    egui::Frame::new()
        .fill(p.soft)
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(content);
        });
}

/// A label cut with "…" when it does not fit, for the status bar (egui shows the full text on
/// hover only then).
pub fn truncated(ui: &mut egui::Ui, text: String, color: Color32) {
    ui.add(egui::Label::new(RichText::new(text).color(color)).truncate());
}

/// Log panel: one read-only text area, so a selection can span many lines while scrolling,
/// plus Copy / Clear buttons. The text and its colored layout are cached and rebuilt only
/// when a line is added, the log is cleared or the theme changes, not on every repaint.
#[derive(Default)]
pub struct LogView {
    lines: Vec<LogLine>,
    text: String,
    job: egui::text::LayoutJob,
    /// Theme the cache was built for; `None` = needs a rebuild.
    built_for_dark: Option<bool>,
}

impl LogView {
    pub fn push(&mut self, line: LogLine) {
        self.lines.push(line);
        if self.lines.len() > MAX_LOG_LINES {
            // Drop a chunk at a time so this O(n) move is rare.
            self.lines.drain(..MAX_LOG_LINES / 10);
        }
        self.built_for_dark = None;
    }

    fn clear(&mut self) {
        self.lines.clear();
        self.built_for_dark = None;
    }

    fn rebuild(&mut self, p: &Palette, dark: bool) {
        self.text.clear();
        self.job = egui::text::LayoutJob::default();
        let font = egui::FontId::proportional(12.5);
        for (i, l) in self.lines.iter().enumerate() {
            let color = match l.level {
                Level::Info => p.text,
                Level::Warning => p.warn,
                Level::Error => p.error,
            };
            let mut line = l.to_string();
            if i + 1 < self.lines.len() {
                line.push('\n');
            }
            self.job.append(
                &line,
                0.0,
                egui::TextFormat {
                    font_id: font.clone(),
                    color,
                    ..Default::default()
                },
            );
            self.text.push_str(&line);
        }
        self.built_for_dark = Some(dark);
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, heading: &str) {
        let p = pal(ui);
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(heading).size(16.0).strong().color(p.text));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().interact_size.y = 24.0;
                if ui.small_button("Clear").clicked() {
                    self.clear();
                }
                if ui.small_button("Copy").on_hover_text("Copy the whole log").clicked() {
                    ui.ctx().copy_text(self.text.clone());
                }
            });
        });

        let dark = ui.visuals().dark_mode;
        if self.built_for_dark != Some(dark) {
            self.rebuild(p, dark);
        }

        egui::Frame::new()
            .fill(p.log_bg)
            .stroke(Stroke::new(1.0_f32, p.stroke))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // The job hash is unchanged between frames, so egui's galley cache hits.
                        let job = &self.job;
                        let mut layouter = |ui: &egui::Ui, _buf: &dyn egui::TextBuffer, wrap_width: f32| {
                            let mut job = job.clone();
                            job.wrap.max_width = wrap_width;
                            ui.fonts_mut(|f| f.layout_job(job))
                        };
                        // `&str` as the buffer makes the field selectable but not editable.
                        ui.add(
                            egui::TextEdit::multiline(&mut self.text.as_str())
                                .frame(egui::Frame::NONE)
                                .desired_width(f32::INFINITY)
                                .layouter(&mut layouter),
                        );
                    });
            });
    }
}
