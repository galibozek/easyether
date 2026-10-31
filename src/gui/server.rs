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
    /// All IPv4 addresses with their interface names, for the "My address" hover.
    addresses: Vec<(String, std::net::Ipv4Addr)>,
    /// "Copied to clipboard" after Copy or a click on the address.
    copied: widgets::Copied,
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
            addresses: l2::local_ipv4(),
            copied: widgets::Copied::default(),
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
        self.addresses = l2::local_ipv4();
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

    /// Forgets how the last run ended ("Error"), once the other side has been started.
    pub fn clear_outcome(&mut self) {
        if !self.is_running() && self.worker.status != "Stopped" {
            self.worker.status = "Stopped".into();
        }
    }

    /// What the tray icon's hover text says while sharing: mode and port, the client and, once
    /// connected, the traffic. `None` while off.
    pub fn tray_status(&self, settings: &Settings) -> Option<String> {
        if !self.is_running() {
            return None;
        }
        let mode = if settings.server_secure { "Secure" } else { "Insecure" };
        let head = format!("Server ({mode}, port {})", self.port.trim());
        let session = self.worker.handle.as_ref().and_then(|h| h.client_session());
        Some(match session {
            Some((addr, since)) => format!(
                "{head}\nclient {addr} connected · {}\n{}",
                crate::log::format_uptime(since.elapsed()),
                widgets::traffic_line(self.worker.traffic, self.worker.rtt)
            ),
            None => format!("{head}\nwaiting for a client"),
        })
    }

    /// Short state for the tab badge: the live connection, or that we wait for one. Nothing
    /// while off; errors and other details are in the status bar only.
    pub fn badge(&self) -> Option<widgets::Badge> {
        use widgets::{Activity, Badge};
        if !self.is_running() {
            None
        } else if self
            .worker
            .handle
            .as_ref()
            .is_some_and(|h| h.client_session().is_some())
        {
            Some(Badge::new(Activity::On).traffic(self.worker.traffic, self.worker.rtt))
        } else {
            Some(Badge::new(Activity::Pending))
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
        widgets::title(ui, "Share a local Ethernet adapter");
        ui.add_space(4.0);

        #[cfg(windows)]
        self.drivers_ui(ui);

        ui.horizontal(|ui| {
            // Refresh (84) + gap (16) + port (70) + Share/Stop (96) + spacing.
            let combo_width = (ui.available_width() - 320.0).max(160.0);
            ui.vertical(|ui| {
                widgets::caption(ui, "Network adapter");
                let current = self
                    .selected
                    .and_then(|i| self.adapters.get(i))
                    .map(|a| format!("{}   {}", a.name, a.detail))
                    .unwrap_or_else(|| "(no adapter)".into());
                // egui truncates text only to the width it is given: the box gets its own width,
                // the list a fixed one up to the window's edge; long names (Windows) end in "…",
                // complete on hover.
                let list_width = ui.ctx().content_rect().right() - ui.cursor().left() - 16.0;
                ui.add_enabled_ui(!running, |ui| {
                    ui.set_max_width(combo_width);
                    egui::ComboBox::from_id_salt("adapter")
                        .width(combo_width)
                        .truncate()
                        .selected_text(&current)
                        .show_ui(ui, |ui| {
                            ui.set_width(list_width.max(combo_width));
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                            for (i, a) in self.adapters.iter().enumerate() {
                                let name = format!("{}   {}", a.name, a.detail);
                                ui.selectable_value(&mut self.selected, Some(i), &name)
                                    .on_hover_text(&name);
                            }
                        })
                        .response
                        .on_hover_text(&current);
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
            // One button that toggles: Share while off, Stop while sharing (same place and width).
            ui.vertical(|ui| {
                widgets::caption(ui, " ");
                let size = egui::vec2(96.0, 32.0);
                if running {
                    if ui.add(widgets::secondary_button("Stop").min_size(size)).clicked() {
                        *confirm = Some(Confirm::StopServer);
                    }
                } else if ui.add(widgets::primary_button("Share").min_size(size)).clicked() {
                    self.start(settings);
                }
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
                ui.label(
                    RichText::new(secure::display_password(&self.password))
                        .monospace()
                        .size(20.0)
                        .strong(),
                );
                let copy = widgets::small_button(ui, true, "Copy");
                if copy.clicked() {
                    self.copied.copy(ui.ctx(), self.password.clone(), &copy);
                }
                let new_pw = widgets::small_button(ui, true, "New password")
                    .on_hover_text("A connected client is disconnected, since its password stops being valid.");
                if new_pw.clicked() {
                    if self.has_client() {
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
            // What to give the client, on the right of the settings row: a click copies it, the
            // hover lists every address of this computer (the client may be on another network).
            let port = self.port.trim();
            let address = format!("{}:{port}", self.local_ip);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let resp = ui
                    .add(egui::Label::new(RichText::new(&address).strong()).sense(egui::Sense::click()))
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                // egui hides a tooltip on click; the "Copied" note replaces it meanwhile.
                let resp = if self.copied.active() || self.addresses.is_empty() {
                    resp
                } else {
                    resp.on_hover_ui(|ui| {
                        widgets::muted(ui, "All addresses of this computer:");
                        egui::Grid::new("my_addresses")
                            .num_columns(2)
                            .spacing([12.0, 2.0])
                            // Rows default to the height of a button (30 px here); text lines need less.
                            .min_row_height(0.0)
                            .show(ui, |ui| {
                                for (name, ip) in &self.addresses {
                                    ui.label(format!("{ip}:{port}"));
                                    widgets::muted(ui, name);
                                    ui.end_row();
                                }
                            });
                    })
                };
                if resp.clicked() {
                    self.copied.copy(ui.ctx(), address.clone(), &resp);
                }
                widgets::caption(ui, "My address");
            });
        });
        self.copied.ui(ui);

        let handle = self.worker.handle.as_ref();
        let client = handle.and_then(|h| h.client_session());
        let last = handle.and_then(|h| h.last_client());
        let status = self.worker.status.as_str();
        let p = widgets::pal(ui);
        let uptime = |since: std::time::Instant| crate::log::format_uptime(since.elapsed());
        widgets::status_bar(ui, |ui| {
            // Details the tab does not show: who is connected and for how long, who left,
            // and what is wrong. One color for the message, the warning color for problems.
            widgets::muted(ui, "Status");
            let (text, color) = match client {
                Some((addr, since)) if running => (format!("client {addr} connected · {}", uptime(since)), p.text),
                _ if running && status.starts_with("Adapter unavailable") => {
                    ("adapter unplugged · waiting for it".into(), p.warn)
                }
                _ if running && status.starts_with("Starting") => ("starting…".into(), p.text),
                _ if running => match last {
                    Some((addr, left)) => (
                        format!("client {} left {} ago · waiting", addr.ip(), uptime(left)),
                        p.text,
                    ),
                    None => ("waiting for a client".into(), p.text),
                },
                _ if status.starts_with("Error") => ("could not start · see log".into(), p.warn),
                _ => ("not sharing".into(), p.text),
            };
            widgets::truncated(ui, text, color);
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
