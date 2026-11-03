//! Server tab: waits for the client to connect, and either shares a local Ethernet adapter
//! with it or uses the client's (virtual adapter here). The second mode is for a client
//! behind NAT that shares its adapter by connecting out to this, publicly reachable, side.

use eframe::egui::{self, RichText};

use super::device::{AdapterPicker, NetSettings};
use super::worker::{Invite, Worker, parse_port};
use super::{Confirm, widgets};
use crate::settings::Settings;
use crate::tunnel;

pub struct ServerTab {
    pub(super) worker: Worker,
    picker: AdapterPicker,
    net: NetSettings,
    port: String,
    /// The password and address to give the client.
    invite: Invite,
    #[cfg(windows)]
    installer: Option<std::thread::JoinHandle<()>>,
    #[cfg(windows)]
    drivers: Option<crate::l2::windows::install::DriverStatus>,
}

impl ServerTab {
    pub fn new(ctx: &egui::Context, settings: &Settings) -> ServerTab {
        let worker = Worker::new(ctx, "Stopped");
        worker
            .logger
            .info(concat!("EasyEther ", env!("CARGO_PKG_VERSION"), " started."));
        let mut tab = ServerTab {
            worker,
            picker: AdapterPicker::default(),
            net: NetSettings::default(),
            port: settings.server_port.to_string(),
            invite: Invite::new(),
            #[cfg(windows)]
            installer: None,
            #[cfg(windows)]
            drivers: None,
        };
        tab.refresh(settings);
        tab
    }

    fn refresh(&mut self, settings: &Settings) {
        self.invite.refresh();
        #[cfg(windows)]
        {
            self.drivers = Some(crate::l2::windows::install::status());
        }
        self.picker.refresh(&settings.server_adapter_id, &self.worker.logger);
    }

    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    /// Forgets how the last run ended ("Error"), once the other side has been started.
    pub fn clear_outcome(&mut self) {
        if !self.is_running() && self.worker.status != "Stopped" {
            self.worker.status = "Stopped".into();
        }
    }

    /// What the tray icon's hover text says while running: mode and port, the client and,
    /// once connected, the traffic. `None` while off.
    pub fn tray_status(&self, settings: &Settings) -> Option<String> {
        if !self.is_running() {
            return None;
        }
        let mode = if settings.server_secure { "Secure" } else { "Insecure" };
        let what = if settings.reverse {
            "using the client's adapter"
        } else {
            "sharing"
        };
        let head = format!("Server ({mode}, port {}, {what})", self.port.trim());
        Some(format!("{head}\n{}", self.worker.tray_session("waiting for a client")))
    }

    /// Short state for the tab badge: the live connection, or that we wait for one.
    pub fn badge(&self) -> Option<widgets::Badge> {
        self.worker.badge()
    }

    pub fn poll(&mut self) {
        self.worker.poll();
    }

    fn start(&mut self, settings: &mut Settings) {
        let log = &self.worker.logger;
        let device = if settings.reverse {
            NetSettings::device(settings, log)
        } else {
            self.picker.device(log).map(|(device, id)| {
                settings.server_adapter_id = id;
                device
            })
        };
        let Some(device) = device else { return };
        let Some(port) = parse_port(&self.port, log) else {
            return;
        };
        settings.server_port = port;
        settings.save();
        let cfg = tunnel::ServerConfig {
            device,
            port,
            secure: settings.server_secure,
            password: self.invite.password.clone(),
        };
        self.worker.handle = Some(tunnel::start_server(cfg, log.clone()));
    }

    pub fn stop(&mut self) {
        self.worker.stop("Stopping...");
    }

    pub fn shutdown(&mut self) {
        self.worker.shutdown();
    }

    /// Generates a new password. A connected client (confirmed by the user) is disconnected,
    /// since the old password is no longer valid.
    pub fn new_password(&mut self) {
        self.invite.new_password(&self.worker, "client");
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, settings: &mut Settings, confirm: &mut Option<Confirm>) {
        let running = self.is_running();
        // Reverse: the client shares its adapter and this computer uses it.
        let virt = settings.reverse;
        widgets::title(
            ui,
            if virt {
                "Use the client's Ethernet adapter"
            } else {
                "Share a local Ethernet adapter"
            },
        );
        ui.add_space(4.0);

        #[cfg(windows)]
        self.drivers_ui(ui);

        ui.horizontal(|ui| {
            if virt {
                // The virtual adapter that will carry the client's network.
                ui.vertical(|ui| {
                    widgets::caption(ui, "Local end");
                    ui.horizontal(|ui| {
                        ui.set_min_height(32.0);
                        self.net.summary(ui, settings, !running, 150.0);
                    });
                });
            } else {
                // Refresh (84) + gap (16) + port (70) + Share/Stop (96) + spacing.
                let combo_width = (ui.available_width() - 320.0).max(160.0);
                ui.vertical(|ui| {
                    widgets::caption(ui, "Network adapter");
                    self.picker.combo(ui, !running, combo_width);
                });
                // Refresh belongs to the adapter list; a gap separates it from port + Share/Stop.
                ui.vertical(|ui| {
                    widgets::caption(ui, " ");
                    if ui.add_enabled(!running, widgets::secondary_button("Refresh")).clicked() {
                        self.refresh(settings);
                    }
                });
            }
            // Port and the button at the right end, the same place in both modes.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Max), |ui| {
                // One button that toggles: Share/Listen while off, Stop while running.
                let size = egui::vec2(96.0, 32.0);
                if running {
                    if ui.add(widgets::secondary_button("Stop").min_size(size)).clicked() {
                        *confirm = Some(Confirm::StopServer);
                    }
                } else if ui
                    .add(widgets::primary_button(if virt { "Listen" } else { "Share" }).min_size(size))
                    .clicked()
                {
                    self.start(settings);
                }
                ui.vertical(|ui| {
                    widgets::caption(ui, "Port");
                    ui.add_enabled(!running, egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
                });
            });
        });

        ui.horizontal(|ui| {
            ui.set_min_height(widgets::SETTINGS_ROW_HEIGHT);
            // The checkbox would otherwise be as tall as the big buttons.
            ui.spacing_mut().interact_size.y = 22.0;
            let toggle = ui
                .add_enabled(!running, egui::Checkbox::new(&mut settings.server_secure, "Secure"))
                .on_hover_text("TLS 1.3 encryption, and only clients that know the password can connect.");
            if toggle.changed() {
                settings.save();
            }
            ui.separator();
            if settings.server_secure {
                widgets::caption(ui, "Password");
                if self.invite.password_ui(ui) {
                    if self.worker.connected() {
                        *confirm = Some(Confirm::NewPassword);
                    } else {
                        self.new_password();
                    }
                }
            } else {
                // Short enough for the narrow window; the details are on hover.
                let warn = widgets::pal(ui).warn;
                ui.label(RichText::new("Insecure:").strong().color(warn));
                ui.label(RichText::new("anyone who reaches this port can join").color(warn))
                    .on_hover_text("No encryption and no password. Use it only on a trusted LAN.");
            }
            // What to give the client, on the right of the settings row.
            self.invite.address_ui(ui, self.port.trim());
        });
        self.invite.copied_ui(ui);

        let p = widgets::pal(ui);
        let off = if virt { "not listening" } else { "not sharing" };
        let (text, color) = self.worker.listen_status(p, running, "client", off);
        widgets::status_bar(ui, |ui| {
            // Details the tab does not show: who is connected and for how long, who left,
            // and what is wrong. One color for the message, the warning color for problems.
            widgets::muted(ui, "Status");
            widgets::truncated(ui, text, color);
        });

        self.worker.log.ui(ui, "Server Log");
        self.net.dialog(ui.ctx(), settings);
    }

    #[cfg(windows)]
    fn drivers_ui(&mut self, ui: &mut egui::Ui) {
        if self.installer.as_ref().is_some_and(|t| t.is_finished()) {
            let _ = self.installer.take().unwrap().join();
            let settings = Settings::load();
            self.refresh(&settings);
        }
        let installing = self.installer.is_some();
        let Some(st) = &self.drivers else { return };
        if st.selow && st.neo && !installing {
            return;
        }
        let missing = self.missing_drivers();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Drivers missing: {}", missing.join(", "))).color(widgets::pal(ui).warn));
            let label = if installing { "Installing..." } else { "Install drivers" };
            if ui.add_enabled(!installing, widgets::primary_button(label)).clicked() {
                self.install_drivers();
            }
        });
    }

    /// Starts the driver installation in the background (Windows only).
    pub fn install_drivers(&mut self) {
        #[cfg(windows)]
        if self.installer.is_none() {
            let log = self.worker.logger.clone();
            log.info("Installing drivers...");
            self.installer = Some(std::thread::spawn(move || {
                if let Err(e) = crate::l2::windows::install::install_all(&log) {
                    log.error(format!("Driver installation failed: {e}"));
                }
            }));
        }
    }

    /// Whether a driver installation is running in the background (Windows only).
    pub fn is_installing(&self) -> bool {
        #[cfg(windows)]
        {
            self.installer.as_ref().is_some_and(|t| !t.is_finished())
        }
        #[cfg(not(windows))]
        false
    }

    /// Human readable names of drivers that are not installed (always empty off Windows).
    pub fn missing_drivers(&self) -> Vec<&'static str> {
        #[cfg(windows)]
        if let Some(st) = &self.drivers {
            return [
                (!st.selow, "SeLow (needed to share an adapter)"),
                (!st.neo, "virtual adapter VPN127 (needed to use a shared one)"),
            ]
            .into_iter()
            .filter(|(m, _)| *m)
            .map(|(_, n)| n)
            .collect();
        }
        Vec::new()
    }
}
