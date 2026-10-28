//! Client tab: connect to a shared adapter.

use std::net::Ipv4Addr;

use eframe::egui::{self, RichText};

use super::worker::{Worker, parse_port};
use super::{Confirm, widgets};
use crate::l2;
use crate::settings::{self, Settings};
use crate::tunnel;

pub struct ClientTab {
    worker: Worker,
    host: String,
    port: String,
    password: String,
    net_dialog: Option<NetDialog>,
}

/// Editable copy of the network settings while the dialog is open.
struct NetDialog {
    static_ip: bool,
    address: String,
    mask: String,
    error: String,
}

impl ClientTab {
    pub fn new(ctx: &egui::Context, settings: &Settings) -> ClientTab {
        ClientTab {
            worker: Worker::new(ctx, "Disconnected"),
            host: settings.client_host.clone(),
            port: settings.client_port.to_string(),
            password: String::new(),
            net_dialog: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    /// Short state for the tab badge.
    pub fn badge(&self) -> widgets::Badge {
        use widgets::{Activity, Badge};
        if !self.is_running() {
            // Ended by the server or an error (not by the user): draw attention.
            if self.worker.status.starts_with("Disconnected -") {
                Badge::new("Disconnected", Activity::Pending)
            } else {
                Badge::new("Off", Activity::Off)
            }
        } else if self.worker.status.starts_with("Connected") {
            Badge::new("Connected", Activity::On).traffic(self.worker.traffic)
        } else if self.worker.status.starts_with("Connection lost") {
            Badge::new("Reconnecting…", Activity::Pending)
        } else if self.worker.status.starts_with("Server unreachable") {
            Badge::new("Waiting for server…", Activity::Pending)
        } else if self.worker.status.starts_with("Disconnecting") {
            Badge::new("Disconnecting…", Activity::Pending)
        } else {
            Badge::new("Connecting…", Activity::Pending)
        }
    }

    pub fn poll(&mut self) {
        self.worker.poll();
    }

    fn connect(&mut self, settings: &mut Settings) {
        let host = self.host.trim().to_string();
        if host.is_empty() {
            self.worker.logger.error("Enter the server address.");
            return;
        }
        let Some(port) = parse_port(&self.port, &self.worker.logger) else { return };
        if settings.client_secure && crate::secure::normalize_password(&self.password).len() != crate::secure::PASSWORD_LEN {
            self.worker.logger.error("Enter the 8-character password shown on the server.");
            return;
        }
        let static_ipv4 = if settings.static_ipv4_enabled {
            match static_config(&settings.static_ipv4_address, &settings.static_ipv4_mask) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.worker.logger.error(format!("Network settings: {e}"));
                    return;
                }
            }
        } else {
            None
        };
        settings.client_host = host.clone();
        settings.client_port = port;
        settings.save();
        let cfg = tunnel::ClientConfig {
            host,
            port,
            secure: settings.client_secure,
            password: self.password.clone(),
            static_ipv4,
            mac: settings.client_mac(),
        };
        self.worker.handle = Some(tunnel::start_client(cfg, self.worker.logger.clone()));
    }

    pub fn disconnect(&mut self) {
        self.worker.stop("Disconnecting...");
    }

    pub fn shutdown(&mut self) {
        self.worker.shutdown();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, settings: &mut Settings, confirm: &mut Option<Confirm>) {
        let running = self.is_running();
        ui.horizontal(|ui| {
            widgets::title(ui, "Connect to a shared adapter", "");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!running, widgets::secondary_button("Network settings")).clicked() {
                    self.net_dialog = Some(NetDialog {
                        static_ip: settings.static_ipv4_enabled,
                        address: settings.static_ipv4_address.clone(),
                        mask: settings.static_ipv4_mask.clone(),
                        error: String::new(),
                    });
                }
            });
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let host_width = (ui.available_width() - 540.0).max(180.0);
            ui.vertical(|ui| {
                widgets::caption(ui, "Server address");
                ui.add_enabled(
                    !running,
                    egui::TextEdit::singleline(&mut self.host)
                        .hint_text("IPv4, IPv6 or host name")
                        .desired_width(host_width),
                );
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Port");
                ui.add_enabled(!running, egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Security");
                let toggle = ui
                    .add_enabled(!running, egui::Checkbox::new(&mut settings.client_secure, "Secure"))
                    .on_hover_text("TLS 1.3 + password. Must match the setting on the sharing computer.");
                if toggle.changed() {
                    settings.save();
                }
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Password");
                let edit = egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text(if settings.client_secure { "abcd 1234" } else { "not needed" })
                    .desired_width(110.0);
                let resp = ui.add_enabled(!running && settings.client_secure, edit);
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !running {
                    self.connect(settings);
                }
            });
            ui.vertical(|ui| {
                widgets::caption(ui, " ");
                ui.horizontal(|ui| {
                    if ui.add_enabled(!running, widgets::primary_button("Connect")).clicked() {
                        self.connect(settings);
                    }
                    if ui.add_enabled(running, widgets::secondary_button("Disconnect")).clicked() {
                        *confirm = Some(Confirm::Disconnect);
                    }
                });
            });
        });

        let net = if settings.static_ipv4_enabled {
            format!("Static {} / {}", settings.static_ipv4_address, settings.static_ipv4_mask)
        } else {
            "Automatic (DHCP)".into()
        };
        widgets::status_bar(ui, &self.worker.status, |ui| {
            ui.label(RichText::new(net).strong());
            widgets::muted(ui, l2::client_adapter_name());
        });

        self.worker.log.ui(ui, "Client Log");
        self.net_dialog_ui(ui.ctx(), settings);
    }

    fn net_dialog_ui(&mut self, ctx: &egui::Context, settings: &mut Settings) {
        let Some(d) = &mut self.net_dialog else { return };
        let answer = widgets::modal(ctx, "network_settings", "Network settings", "Save", "Cancel", |ui| {
            widgets::muted(ui, format!("IPv4 configuration of '{}'", l2::client_adapter_name()));
            ui.add_space(6.0);
            ui.radio_value(&mut d.static_ip, false, "Automatic (DHCP / system default)");
            ui.radio_value(&mut d.static_ip, true, "Static IPv4");
            ui.add_enabled_ui(d.static_ip, |ui| {
                ui.indent("static_ip_fields", |ui| {
                    egui::Grid::new("static_ip").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                        ui.label("IP address");
                        ui.add(egui::TextEdit::singleline(&mut d.address).hint_text("192.168.1.50").desired_width(170.0));
                        ui.end_row();
                        ui.label("Subnet mask");
                        ui.add(egui::TextEdit::singleline(&mut d.mask).hint_text("255.255.255.0").desired_width(170.0));
                        ui.end_row();
                    });
                    ui.label(
                        RichText::new("Applied after connecting and removed on disconnect.")
                            .size(12.0)
                            .color(widgets::pal(ui).muted),
                    );
                });
            });
            if !d.error.is_empty() {
                ui.colored_label(widgets::pal(ui).error, &d.error);
            }
        });
        match answer {
            Some(true) => {
                let valid = if d.static_ip { static_config(&d.address, &d.mask).map(|_| ()) } else { Ok(()) };
                match valid {
                    Ok(()) => {
                        settings.static_ipv4_enabled = d.static_ip;
                        settings.static_ipv4_address = d.address.trim().to_string();
                        settings.static_ipv4_mask = d.mask.trim().to_string();
                        settings.save();
                        self.net_dialog = None;
                    }
                    Err(e) => d.error = e,
                }
            }
            Some(false) => self.net_dialog = None,
            None => {}
        }
    }
}

fn static_config(address: &str, mask: &str) -> Result<(Ipv4Addr, u8), String> {
    let addr: Ipv4Addr = address.trim().parse().map_err(|_| format!("'{}' is not a valid IPv4 address", address.trim()))?;
    let prefix = settings::parse_prefix(mask).ok_or_else(|| format!("'{}' is not a valid subnet mask", mask.trim()))?;
    if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() || addr.is_loopback() {
        return Err(format!("{addr} cannot be used as an adapter address"));
    }
    Ok((addr, prefix))
}
