//! Client tab: connects to the server, and either uses the adapter it shares (virtual
//! adapter here) or, in reverse, shares a local adapter with it. Reverse is for a sharing
//! computer behind NAT: it connects out to a publicly reachable server.

use eframe::egui;

use super::device::{AdapterPicker, NetSettings};
use super::worker::{Worker, host_port_text, parse_port};
use super::{Confirm, widgets};
use crate::settings::Settings;
use crate::tunnel;

pub struct ClientTab {
    worker: Worker,
    host: String,
    port: String,
    password: String,
    picker: AdapterPicker,
    net: NetSettings,
}

impl ClientTab {
    pub fn new(ctx: &egui::Context, settings: &Settings) -> ClientTab {
        let mut tab = ClientTab {
            worker: Worker::new(ctx, "Disconnected"),
            host: settings.client_host.clone(),
            port: settings.client_port.to_string(),
            password: String::new(),
            picker: AdapterPicker::default(),
            net: NetSettings::default(),
        };
        // Listed only when this side shares; switching to reverse lists them then.
        if settings.reverse {
            tab.refresh_adapters(settings);
        }
        tab
    }

    /// Lists the adapters to share again, problems logged: after switching to reverse (the
    /// list was read at startup, quietly when reverse was off) and after a driver install.
    pub fn refresh_adapters(&mut self, settings: &Settings) {
        self.picker.refresh(&settings.server_adapter_id, &self.worker.logger);
    }

    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    /// Forgets how the last connection ended ("Disconnected"), once the other side has been
    /// started.
    pub fn clear_outcome(&mut self) {
        if !self.is_running() && self.worker.status != "Disconnected" {
            self.worker.status = "Disconnected".into();
        }
    }

    /// What the tray icon's hover text says while connecting or connected: mode and server,
    /// then how long it is connected and the traffic, or that it is (re)connecting. `None`
    /// while off.
    pub fn tray_status(&self, settings: &Settings) -> Option<String> {
        if !self.is_running() {
            return None;
        }
        let mode = if settings.client_secure { "Secure" } else { "Insecure" };
        let link = self.worker.handle.as_ref().map(|h| h.client_link()).unwrap_or_default();
        let server = link.peer.map_or_else(|| self.server_text(), |p| p.to_string());
        let what = if settings.reverse { ", sharing" } else { "" };
        let head = format!("Client ({mode}{what}) → {server}");
        Some(format!("{head}\n{}", self.worker.tray_session("connecting…")))
    }

    /// The server as typed, an IPv6 address in brackets so the port is not read as part of it.
    fn server_text(&self) -> String {
        host_port_text(&self.host, &self.port)
    }

    /// Short state for the tab badge: the live connection, or that we are getting there.
    pub fn badge(&self) -> Option<widgets::Badge> {
        self.worker.badge()
    }

    pub fn poll(&mut self) {
        self.worker.poll();
    }

    fn connect(&mut self, settings: &mut Settings) {
        let log = &self.worker.logger;
        let host = self.host.trim().to_string();
        if host.is_empty() {
            log.error("Enter the server address.");
            return;
        }
        let Some(port) = parse_port(&self.port, log) else {
            return;
        };
        if settings.client_secure
            && crate::secure::normalize_password(&self.password).len() != crate::secure::PASSWORD_LEN
        {
            log.error("Enter the 8-character password shown on the server.");
            return;
        }
        let device = if settings.reverse {
            self.picker.device(log).map(|(device, id)| {
                settings.server_adapter_id = id;
                device
            })
        } else {
            NetSettings::device(settings, log)
        };
        let Some(device) = device else { return };
        settings.client_host = host.clone();
        settings.client_port = port;
        settings.save();
        let cfg = tunnel::ClientConfig {
            host,
            port,
            secure: settings.client_secure,
            password: self.password.clone(),
            device,
        };
        self.worker.handle = Some(tunnel::start_client(cfg, log.clone()));
    }

    pub fn disconnect(&mut self) {
        self.worker.stop("Disconnecting...");
    }

    pub fn shutdown(&mut self) {
        self.worker.shutdown();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, settings: &mut Settings, confirm: &mut Option<Confirm>) {
        let running = self.is_running();
        let shares = settings.reverse;
        widgets::title(
            ui,
            if shares {
                "Share a local Ethernet adapter with the server"
            } else {
                "Connect to a shared adapter"
            },
        );
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            // Port, Secure, password, Connect/Disconnect (104) and spacing.
            let host_width = (ui.available_width() - 468.0).max(180.0);
            ui.vertical(|ui| {
                widgets::caption(ui, "Server address");
                let edit = ui.add_enabled(
                    !running,
                    egui::TextEdit::singleline(&mut self.host)
                        .hint_text("IPv4, IPv6 or host name")
                        .desired_width(host_width),
                );
                // "address:port" as given by the server ("My address"): the port goes to its
                // field, on paste or when leaving the field (not while typing, or the rest of
                // the port would land in the address).
                let pasted =
                    edit.changed() && ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Paste(_))));
                if (pasted || edit.lost_focus())
                    && let Some((host, port)) = split_host_port(&self.host)
                {
                    self.host = host;
                    self.port = port.to_string();
                }
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Port");
                ui.add_enabled(!running, egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Security");
                let toggle = ui
                    .add_enabled(!running, egui::Checkbox::new(&mut settings.client_secure, "Secure"))
                    .on_hover_text("TLS 1.3 + password. Must match the setting on the server.");
                if toggle.changed() {
                    settings.save();
                }
            });
            ui.vertical(|ui| {
                widgets::caption(ui, "Password");
                let edit = egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text(if settings.client_secure {
                        "abcd 1234"
                    } else {
                        "not needed"
                    })
                    .desired_width(110.0);
                let resp = ui.add_enabled(!running && settings.client_secure, edit);
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !running {
                    self.connect(settings);
                }
            });
            // One button that toggles: Connect while off, Disconnect while running. At the
            // right end, where the server tab has its button.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Max), |ui| {
                let size = egui::vec2(104.0, 32.0);
                if running {
                    if ui.add(widgets::secondary_button("Disconnect").min_size(size)).clicked() {
                        *confirm = Some(Confirm::Disconnect);
                    }
                } else if ui.add(widgets::primary_button("Connect").min_size(size)).clicked() {
                    self.connect(settings);
                }
            });
        });

        // Settings row: the local end of the tunnel. The virtual adapter's IPv4 setup, or in
        // reverse the adapter to share.
        ui.horizontal(|ui| {
            ui.set_min_height(widgets::SETTINGS_ROW_HEIGHT);
            // Compact controls, as in the server tab's settings row, so both tabs have the
            // same row heights and nothing shifts when switching tabs.
            ui.spacing_mut().interact_size.y = 22.0;
            if shares {
                widgets::caption(ui, "Adapter");
                let width = (ui.available_width() - 110.0).max(160.0);
                self.picker.combo(ui, !running, width);
                // As tall as the list next to it.
                let refresh = egui::Button::new("Refresh").min_size(egui::vec2(84.0, ui.spacing().interact_size.y));
                if ui.add_enabled(!running, refresh).clicked() {
                    self.picker.refresh(&settings.server_adapter_id, &self.worker.logger);
                }
            } else {
                self.net.summary(ui, settings, !running, 150.0);
            }
        });

        let p = widgets::pal(ui);
        let (text, color) = self
            .worker
            .connect_status(p, running, &self.server_text(), "server", "not connected");
        widgets::status_bar(ui, |ui| {
            // Details the tab does not show: where we are connected, for how long, how
            // stable it has been, when the next attempt comes, and why it ended. One color for
            // the message, the warning color for problems.
            widgets::muted(ui, "Status");
            widgets::truncated(ui, text, color);
        });

        self.worker.log.ui(ui, "Client Log");
        self.net.dialog(ui.ctx(), settings);
    }
}

/// "1.2.3.4:5000", "[fe80::1%12]:5000" or "host:5000" split into address and port (an IPv6
/// zone is kept). A bare IPv6 address ("fe80::1") is left alone.
fn split_host_port(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        if host.is_empty() {
            return None;
        }
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = text.split_once(':')?;
    if host.is_empty() || host.contains(':') || port.contains(':') {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::super::worker::retry;
    use super::*;

    #[test]
    fn pasted_port_is_split_off() {
        let split = split_host_port;
        assert_eq!(split("192.168.10.116:5000"), Some(("192.168.10.116".into(), 5000)));
        assert_eq!(split(" [fe80::1]:5000 "), Some(("fe80::1".into(), 5000)));
        assert_eq!(split("[fe80::1%12]:5000"), Some(("fe80::1%12".into(), 5000)));
        assert_eq!(split("[]:5000"), None);
        assert_eq!(split("vci.local:6000"), Some(("vci.local".into(), 6000)));
        assert_eq!(split("fe80::1"), None);
        assert_eq!(split("192.168.10.116"), None);
        assert_eq!(split("192.168.10.116:"), None);
        assert_eq!(split("host:99999"), None);
    }

    #[test]
    fn retry_status_is_shortened() {
        assert_eq!(
            retry("Unreachable - retrying in 5 s (attempt 3)"),
            Some(("Unreachable", "retry in 5 s (#3)".to_string()))
        );
        assert_eq!(
            retry("Connection lost - retrying in 10 s (attempt 12)"),
            Some(("Connection lost", "retry in 10 s (#12)".to_string()))
        );
        assert_eq!(retry("Connecting (attempt 2)..."), None);
        assert_eq!(retry("Connected to 1.2.3.4:5555 via 'eeth0'"), None);
    }
}
