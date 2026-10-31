//! Server tab: share a local Ethernet adapter.

use eframe::egui::{self, RichText};

use super::worker::{Worker, parse_port};
use super::{Confirm, widgets};
use crate::l2::{self, AdapterInfo};
use crate::secure;
use crate::settings::Settings;
use crate::tunnel;

pub struct ServerTab {
    pub(super) worker: Worker,
    adapters: Vec<AdapterInfo>,
    selected: Option<usize>,
    port: String,
    password: String,
    local_ip: String,
    #[cfg(windows)]
    installer: Option<std::thread::JoinHandle<()>>,
    #[cfg(windows)]
    drivers: Option<crate::l2::windows::install::DriverStatus>,
}

/// Primary local IPv4 (no packets are sent; this only asks the routing table).
fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("192.0.2.1:9")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

impl ServerTab {
    pub fn new(ctx: &egui::Context, settings: &Settings) -> ServerTab {
        let worker = Worker::new(ctx, "Stopped");
        worker
            .logger
            .info(concat!("EasyEther ", env!("CARGO_PKG_VERSION"), " started."));
        let mut tab = ServerTab {
            worker,
            adapters: Vec::new(),
            selected: None,
            port: settings.server_port.to_string(),
            password: secure::generate_password(),
            local_ip: local_ip(),
            #[cfg(windows)]
            installer: None,
            #[cfg(windows)]
            drivers: None,
        };
        tab.refresh(settings);
        tab
    }

    fn refresh(&mut self, settings: &Settings) {
        self.local_ip = local_ip();
        #[cfg(windows)]
        {
            self.drivers = Some(crate::l2::windows::install::status());
        }
        match l2::list_adapters() {
            Ok(list) => {
                self.adapters = list;
                if self.adapters.is_empty() {
                    self.worker.logger.warn("No shareable Ethernet adapters found.");
                }
            }
            Err(e) => {
                self.adapters.clear();
                self.worker.logger.error(e.to_string());
            }
        }
        self.selected = self
            .adapters
            .iter()
            .position(|a| a.id == settings.server_adapter_id)
            .or(if self.adapters.is_empty() { None } else { Some(0) });
    }

    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    /// Short state for the tab badge.
    pub fn badge(&self) -> widgets::Badge {
        if !self.is_running() {
            if self.worker.status.starts_with("Error") {
                widgets::Badge::new("Error", widgets::Activity::Pending)
            } else {
                widgets::Badge::new("Off", widgets::Activity::Off)
            }
        } else if self.worker.status.contains("client connected") {
            widgets::Badge::new("Client connected", widgets::Activity::On).traffic(self.worker.traffic, self.worker.rtt)
        } else {
            widgets::Badge::new("Active · waiting for a client", widgets::Activity::On)
        }
    }

    pub fn poll(&mut self) {
        self.worker.poll();
    }

    fn start(&mut self, settings: &mut Settings) {
        let Some(adapter) = self.selected.and_then(|i| self.adapters.get(i)).cloned() else {
            self.worker.logger.error("Choose a network adapter first.");
            return;
        };
        let Some(port) = parse_port(&self.port, &self.worker.logger) else {
            return;
        };
        settings.server_adapter_id = adapter.id.clone();
        settings.server_port = port;
        settings.save();
        let cfg = tunnel::ServerConfig {
            adapter_id: adapter.id,
            adapter_name: adapter.name,
            port,
            secure: settings.server_secure,
            password: self.password.clone(),
        };
        self.worker.handle = Some(tunnel::start_server(cfg, self.worker.logger.clone()));
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
        self.password = secure::generate_password();
        if let Some(h) = &self.worker.handle {
            h.set_password(&self.password);
            if h.disconnect_client() {
                self.worker
                    .logger
                    .info("A new password was generated; the connected client was disconnected.");
                return;
            }
        }
        self.worker.logger.info("A new password was generated.");
    }

    /// Whether a client session is running (for the New password confirmation).
    pub fn has_client(&self) -> bool {
        self.is_running() && self.worker.handle.as_ref().is_some_and(|h| h.has_client())
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, settings: &mut Settings, confirm: &mut Option<Confirm>) {
        let running = self.is_running();
        widgets::title(
            ui,
            "Share a local Ethernet adapter",
            "Choose an adapter and a free TCP port.",
        );
        ui.add_space(4.0);

        #[cfg(windows)]
        self.drivers_ui(ui);

        ui.horizontal(|ui| {
            // Refresh (84) + gap (16) + port (70) + Share/Stop (2 x 84) + spacing.
            let combo_width = (ui.available_width() - 430.0).max(160.0);
            ui.vertical(|ui| {
                widgets::caption(ui, "Network adapter");
                let current = self
                    .selected
                    .and_then(|i| self.adapters.get(i))
                    .map(|a| format!("{}   {}", a.name, a.detail))
                    .unwrap_or_else(|| "(no adapter)".into());
                ui.add_enabled_ui(!running, |ui| {
                    egui::ComboBox::from_id_salt("adapter")
                        .width(combo_width)
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for (i, a) in self.adapters.iter().enumerate() {
                                ui.selectable_value(&mut self.selected, Some(i), format!("{}   {}", a.name, a.detail));
                            }
                        });
                });
            });
            // Refresh belongs to the adapter list; a gap separates it from port + Share/Stop.
            ui.vertical(|ui| {
                widgets::caption(ui, " ");
                if ui.add_enabled(!running, widgets::secondary_button("Refresh")).clicked() {
                    self.refresh(settings);
                }
            });
            ui.add_space(16.0);
            ui.vertical(|ui| {
                widgets::caption(ui, "Port");
                ui.add_enabled(!running, egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
            });
            ui.vertical(|ui| {
                widgets::caption(ui, " ");
                ui.horizontal(|ui| {
                    if ui.add_enabled(!running, widgets::primary_button("Share")).clicked() {
                        self.start(settings);
                    }
                    if ui.add_enabled(running, widgets::secondary_button("Stop")).clicked() {
                        *confirm = Some(Confirm::StopServer);
                    }
                });
            });
        });

        ui.horizontal(|ui| {
            // Same height with and without the password controls, so toggling Secure does not
            // make the panel jump.
            ui.set_min_height(36.0);
            let toggle = ui
                .add_enabled(!running, egui::Checkbox::new(&mut settings.server_secure, "Secure"))
                .on_hover_text("TLS 1.3 encryption, and only clients that know the password can connect.");
            if toggle.changed() {
                settings.save();
            }
            ui.separator();
            if settings.server_secure {
                widgets::caption(ui, "Password");
                ui.label(
                    RichText::new(secure::display_password(&self.password))
                        .monospace()
                        .size(20.0)
                        .strong(),
                );
                if ui.add(widgets::secondary_button("Copy")).clicked() {
                    ui.ctx().copy_text(self.password.clone());
                }
                let new_pw = ui
                    .add(widgets::secondary_button("New password"))
                    .on_hover_text("A connected client is disconnected, since its password stops being valid.");
                if new_pw.clicked() {
                    if self.has_client() {
                        *confirm = Some(Confirm::NewPassword);
                    } else {
                        self.new_password();
                    }
                }
                widgets::muted(ui, "Give the client your address, port and password.");
            } else {
                let warn = widgets::pal(ui).warn;
                ui.label(RichText::new("Insecure:").strong().color(warn));
                ui.label(
                    RichText::new("no encryption and no password - anyone who can reach this port can join.")
                        .color(warn),
                );
            }
        });

        let address = format!("{}:{}", self.local_ip, self.port.trim());
        widgets::status_bar(ui, &self.worker.status, |ui| {
            ui.label(RichText::new(address).strong());
            widgets::muted(ui, "Address");
        });

        self.worker.log.ui(ui, "Server Log");
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
                (!st.selow, "SeLow (needed for Server)"),
                (!st.neo, "virtual adapter VPN127 (needed for Client)"),
            ]
            .into_iter()
            .filter(|(m, _)| *m)
            .map(|(_, n)| n)
            .collect();
        }
        Vec::new()
    }
}
