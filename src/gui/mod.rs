//! egui front-end: header, Server/Client tabs, confirmation dialogs.

mod client;
mod server;
mod tray;
mod widgets;
mod worker;

use eframe::egui::{self, Color32, RichText, TextureHandle, Vec2};

use crate::settings::Settings;
use client::ClientTab;
use server::ServerTab;

pub const ACCENT: Color32 = Color32::from_rgb(0x14, 0x78, 0x6B);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Server,
    Client,
}

/// Actions that need a confirmation first.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    StopServer,
    Disconnect,
    Quit,
    /// New password while a client is connected.
    NewPassword,
}

pub struct App {
    settings: Settings,
    tab: Tab,
    logo: Option<TextureHandle>,
    server: ServerTab,
    client: ClientTab,
    confirm: Option<Confirm>,
    allow_close: bool,
    /// Missing drivers reported at startup (Windows); shown until dismissed.
    driver_prompt: Vec<&'static str>,
    tray: Option<tray::Tray>,
    tray_hint_shown: bool,
    /// "Cannot exit while drivers are being installed" notice.
    install_notice: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> App {
        widgets::style(&cc.egui_ctx);
        let settings = Settings::load();
        widgets::apply_theme(&cc.egui_ctx, &settings.theme);
        let logo = crate::logo::rgba(128).map(|rgba| {
            let img = egui::ColorImage::from_rgba_unmultiplied([128, 128], rgba);
            cc.egui_ctx.load_texture("logo", img, egui::TextureOptions::LINEAR)
        });
        let tab = if settings.last_tab == "Client" {
            Tab::Client
        } else {
            Tab::Server
        };
        let server = ServerTab::new(&cc.egui_ctx, &settings);
        let driver_prompt = server.missing_drivers();
        let tray = match tray::Tray::new(cc) {
            Ok(t) => Some(t),
            Err(e) => {
                server
                    .worker
                    .logger
                    .warn(format!("No system tray available ({e}); closing the window will quit."));
                None
            }
        };
        App {
            tray,
            tray_hint_shown: false,
            install_notice: false,
            client: ClientTab::new(&cc.egui_ctx, &settings),
            server,
            settings,
            tab,
            logo,
            confirm: None,
            allow_close: false,
            driver_prompt,
        }
    }

    fn is_active(&self) -> bool {
        self.server.is_running() || self.client.is_running()
    }

    /// Exit from the tray menu: confirm first if a tunnel is active.
    fn request_exit(&mut self, ctx: &egui::Context) {
        if self.server.is_installing() {
            if let Some(t) = &self.tray {
                t.show_window();
            }
            self.install_notice = true;
        } else if self.is_active() {
            if let Some(t) = &self.tray {
                t.show_window();
            }
            self.confirm = Some(Confirm::Quit);
        } else {
            self.allow_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    /// "Driver installation in progress" notice shown when the user tries to exit meanwhile:
    /// quitting in the middle of netcfg/SetupAPI could leave the drivers half installed.
    fn install_notice_dialog(&mut self, ctx: &egui::Context) {
        if !self.install_notice {
            return;
        }
        if widgets::info_modal(
            ctx,
            "installing",
            "Driver installation in progress",
            "Please wait until the drivers are installed before exiting.",
        ) {
            self.install_notice = false;
        }
    }

    fn driver_dialog(&mut self, ctx: &egui::Context) {
        if self.driver_prompt.is_empty() || self.confirm.is_some() {
            return;
        }
        let missing = self.driver_prompt.clone();
        let answer = widgets::modal(ctx, "drivers", "Drivers required", "Install drivers", "Later", |ui| {
            ui.label("The following SoftEther drivers are not installed:");
            for d in &missing {
                ui.label(RichText::new(format!("  •  {d}")).strong());
            }
            ui.add_space(4.0);
            widgets::muted(ui, "They are included in the 'drivers' folder next to the program.");
        });
        match answer {
            Some(true) => {
                self.driver_prompt.clear();
                self.tab = Tab::Server;
                self.server.install_drivers();
            }
            Some(false) => self.driver_prompt.clear(),
            None => {}
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(logo) = &self.logo {
                ui.add(egui::Image::new(logo).fit_to_exact_size(Vec2::splat(64.0)));
            }
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.label(
                        RichText::new("EasyEther")
                            .size(26.0)
                            .strong()
                            .color(widgets::pal(ui).text),
                    );
                    ui.label(
                        RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                            .size(13.0)
                            .color(widgets::pal(ui).muted),
                    );
                });
                widgets::muted(ui, "Peer-to-peer Ethernet (L2) sharing over the local network");
            });
            // Theme switch, top right.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(theme) = widgets::theme_switch(ui, &self.settings.theme) {
                    self.settings.theme = theme.to_string();
                    self.settings.save();
                    widgets::apply_theme(ui.ctx(), theme);
                }
            });
        });
    }

    fn tabs(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        egui::Frame::new()
            .fill(p.soft)
            .corner_radius(10.0)
            .inner_margin(egui::Margin::same(4))
            .show(ui, |ui| {
                let badges = [self.server.badge(), self.client.badge()];
                ui.columns(2, |cols| {
                    for (col, tab, label) in [(0, Tab::Server, "Server"), (1, Tab::Client, "Client")] {
                        let selected = self.tab == tab;
                        // Drawn by hand (no Button widget): hovering only changes the background,
                        // so the text and badge never move.
                        let ui = &mut cols[col];
                        let (rect, resp) =
                            ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), egui::Sense::click());
                        let bg = if selected {
                            ACCENT
                        } else if resp.hovered() {
                            p.stroke
                        } else {
                            Color32::TRANSPARENT
                        };
                        let painter = ui.painter();
                        painter.rect_filled(rect, 8.0, bg);
                        painter.text(
                            egui::pos2(rect.left() + 14.0, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            label,
                            egui::FontId::proportional(15.0),
                            if selected { Color32::WHITE } else { p.muted },
                        );
                        // State badge on the right side of the tab: "● Connected · ↓ rx ↑ tx", "○ Off", ...
                        let badge = &badges[col];
                        let color = if selected && badge.activity == widgets::Activity::Off {
                            Color32::from_white_alpha(200)
                        } else if selected {
                            Color32::WHITE
                        } else {
                            badge.activity.color(p)
                        };
                        widgets::paint_badge(
                            painter,
                            rect.right() - 12.0,
                            rect.center().y,
                            color,
                            badge.state,
                            badge.activity,
                            badge.traffic,
                        );
                        if resp.clicked() && !selected {
                            self.tab = tab;
                            self.settings.last_tab = label.to_string();
                            self.settings.save();
                        }
                    }
                });
            });
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(what) = self.confirm else { return };
        let (title, text, yes) = match what {
            Confirm::StopServer => (
                "Stop sharing?",
                "The connected client will lose access to the shared adapter.",
                "Stop",
            ),
            Confirm::Disconnect => (
                "Disconnect?",
                "The virtual adapter will be disconnected from the remote network.",
                "Disconnect",
            ),
            Confirm::Quit => ("Exit EasyEther?", "Active sharing/connection will be closed.", "Exit"),
            Confirm::NewPassword => (
                "Generate a new password?",
                "A client is connected and will be disconnected; it needs the new password to connect again.",
                "New password",
            ),
        };
        let answer = widgets::modal(ctx, "confirm", title, yes, "Cancel", |ui| {
            widgets::muted(ui, text);
        });
        match answer {
            Some(true) => {
                self.confirm = None;
                match what {
                    Confirm::StopServer => self.server.stop(),
                    Confirm::NewPassword => self.server.new_password(),
                    Confirm::Disconnect => self.client.disconnect(),
                    Confirm::Quit => {
                        self.server.stop();
                        self.client.disconnect();
                        self.allow_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

impl eframe::App for App {
    /// Runs before every frame and also while the window is hidden in the tray
    /// (worker threads call `request_repaint` when they log).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.server.poll();
        self.client.poll();

        while let Some(cmd) = self.tray.as_ref().and_then(|t| t.poll()) {
            match cmd {
                tray::TrayCmd::Open => {
                    if let Some(t) = &self.tray {
                        t.show_window();
                    }
                }
                tray::TrayCmd::Exit => self.request_exit(ctx),
            }
        }

        // The window's X hides to the tray; Exit is in the tray menu.
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            if let Some(tray) = &self.tray {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                tray.hide_window();
                if !self.tray_hint_shown {
                    self.tray_hint_shown = true;
                    self.server
                        .worker
                        .logger
                        .info("EasyEther keeps running in the system tray (tray menu: Open / Exit).");
                }
            } else {
                // No tray: X quits, with the same safeguards as the tray's Exit.
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.request_exit(ctx);
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(widgets::pal(ui).bg)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ui, |ui| {
                let modal_open = self.confirm.is_some() || !self.driver_prompt.is_empty() || self.install_notice;
                ui.add_enabled_ui(!modal_open, |ui| {
                    self.header(ui);
                    ui.add_space(12.0);
                    self.tabs(ui);
                    ui.add_space(12.0);
                    widgets::card(ui, |ui| match self.tab {
                        Tab::Server => self.server.ui(ui, &mut self.settings, &mut self.confirm),
                        Tab::Client => self.client.ui(ui, &mut self.settings, &mut self.confirm),
                    });
                });
            });
        self.confirm_dialog(&ctx);
        self.driver_dialog(&ctx);
        self.install_notice_dialog(&ctx);
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.settings.save();
        self.server.shutdown();
        self.client.shutdown();
    }
}
