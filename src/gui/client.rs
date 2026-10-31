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
        let head = format!("Client ({mode}) → {server}");
        Some(match link.since {
            Some(since) => format!(
                "{head}\nconnected · {}\n{}",
                crate::log::format_uptime(since.elapsed()),
                widgets::traffic_line(self.worker.traffic, self.worker.rtt)
            ),
            None if retry(&self.worker.status).is_some() => format!("{head}\nconnection lost · reconnecting"),
            None => format!("{head}\nconnecting…"),
        })
    }

    /// The server as typed, an IPv6 address in brackets so the port is not read as part of it.
    fn server_text(&self) -> String {
        let host = self.host.trim();
        if host.contains(':') {
            format!("[{host}]:{}", self.port.trim())
        } else {
            format!("{host}:{}", self.port.trim())
        }
    }

    /// Short state for the tab badge: the live connection, or that we are getting there.
    /// Nothing while off; why it ended and retry details are in the status bar only.
    pub fn badge(&self) -> Option<widgets::Badge> {
        use widgets::{Activity, Badge};
        if !self.is_running() {
            None
        } else if self
            .worker
            .handle
            .as_ref()
            .is_some_and(|h| h.client_link().since.is_some())
        {
            Some(Badge::new(Activity::On).traffic(self.worker.traffic, self.worker.rtt))
        } else {
            Some(Badge::new(Activity::Pending))
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
        let Some(port) = parse_port(&self.port, &self.worker.logger) else {
            return;
        };
        if settings.client_secure
            && crate::secure::normalize_password(&self.password).len() != crate::secure::PASSWORD_LEN
        {
            self.worker
                .logger
                .error("Enter the 8-character password shown on the server.");
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
        widgets::title(ui, "Connect to a shared adapter");
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
                // "address:port" as given by the server ("My address"): the port goes to its field,
                // on paste or when leaving the field (not while typing, or the rest of the port
                // would land in the address).
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
                    .on_hover_text("TLS 1.3 + password. Must match the setting on the sharing computer.");
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
            // One button that toggles: Connect while off, Disconnect while running.
            ui.vertical(|ui| {
                widgets::caption(ui, " ");
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

        // Settings row, like the server's Secure / password / address row: the virtual
        // adapter's IPv4 setup, and the button that changes it.
        let net = if settings.static_ipv4_enabled {
            format!(
                "Static {} / {}",
                settings.static_ipv4_address, settings.static_ipv4_mask
            )
        } else {
            "Automatic (DHCP)".into()
        };
        ui.horizontal(|ui| {
            ui.set_min_height(widgets::SETTINGS_ROW_HEIGHT);
            widgets::caption(ui, "IPv4");
            ui.label(RichText::new(net).strong());
            widgets::muted(ui, "on");
            // The adapter's name can be long (Windows); it fades out with "…" instead of
            // pushing the button away, and is complete on hover.
            let name = l2::client_adapter_name();
            ui.scope(|ui| {
                ui.set_max_width(150.0);
                ui.add(egui::Label::new(RichText::new(name).color(widgets::pal(ui).text)).truncate())
                    .on_hover_text(name);
            });
            if widgets::small_button(ui, !running, "Network settings").clicked() {
                self.net_dialog = Some(NetDialog {
                    static_ip: settings.static_ipv4_enabled,
                    address: settings.static_ipv4_address.clone(),
                    mask: settings.static_ipv4_mask.clone(),
                    error: String::new(),
                });
            }
        });

        let server = self.server_text();
        let status = self.worker.status.as_str();
        let link = self
            .worker
            .handle
            .as_ref()
            .filter(|_| running)
            .map(|h| h.client_link())
            .unwrap_or_default();
        let p = widgets::pal(ui);
        widgets::status_bar(ui, |ui| {
            // Details the tab does not show: where we are connected, for how long, how
            // stable it has been, when the next attempt comes, and why it ended. One color for
            // the message, the warning color for problems.
            widgets::muted(ui, "Status");
            let (text, color) = if let Some(since) = link.since {
                // The resolved address (a host name typed above may stand for several).
                let peer = link.peer.map_or_else(|| server.clone(), |p| p.to_string());
                let mut text = format!("connected to {peer} · {}", crate::log::format_uptime(since.elapsed()));
                match link.reconnects {
                    0 => {}
                    1 => text.push_str(" · 1 reconnect"),
                    n => text.push_str(&format!(" · {n} reconnects")),
                }
                (text, p.text)
            } else if let (true, Some((reason, next))) = (running, retry(status)) {
                let text = if reason.starts_with("Server unreachable") {
                    format!("{server} unreachable · {next}")
                } else {
                    format!("connection lost · {next}")
                };
                (text, p.warn)
            } else if running && status.starts_with("Disconnecting") {
                ("disconnecting…".into(), p.text)
            } else if running {
                (format!("connecting to {server}…"), p.text)
            } else if let Some(reason) = status.strip_prefix("Disconnected - error: ") {
                (format!("{reason} · see log"), p.warn)
            } else if status.starts_with("Disconnected - ") {
                ("ended by the server".into(), p.warn)
            } else {
                ("not connected".into(), p.text)
            };
            widgets::truncated(ui, text, color);
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
                    egui::Grid::new("static_ip")
                        .num_columns(2)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            ui.label("IP address");
                            ui.add(
                                egui::TextEdit::singleline(&mut d.address)
                                    .hint_text("192.168.1.50")
                                    .desired_width(170.0),
                            );
                            ui.end_row();
                            ui.label("Subnet mask");
                            ui.add(
                                egui::TextEdit::singleline(&mut d.mask)
                                    .hint_text("255.255.255.0")
                                    .desired_width(170.0),
                            );
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
                let valid = if d.static_ip {
                    static_config(&d.address, &d.mask).map(|_| ())
                } else {
                    Ok(())
                };
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
    let addr: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not a valid IPv4 address", address.trim()))?;
    let prefix = settings::parse_prefix(mask).ok_or_else(|| format!("'{}' is not a valid subnet mask", mask.trim()))?;
    if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() || addr.is_loopback() {
        return Err(format!("{addr} cannot be used as an adapter address"));
    }
    Ok((addr, prefix))
}

/// From the tunnel's "<reason> - retrying in <s> s (attempt <n>)" status: the reason and
/// "retry in <s> s (#<n>)".
fn retry(status: &str) -> Option<(&str, String)> {
    let (reason, rest) = status.split_once(" - retrying in ")?;
    let (secs, rest) = rest.split_once(" s")?;
    let attempt = rest.split_once("(attempt ")?.1.trim_end_matches(')');
    Some((reason, format!("retry in {secs} s (#{attempt})")))
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
            retry("Server unreachable - retrying in 5 s (attempt 3)"),
            Some(("Server unreachable", "retry in 5 s (#3)".to_string()))
        );
        assert_eq!(
            retry("Connection lost - retrying in 10 s (attempt 12)"),
            Some(("Connection lost", "retry in 10 s (#12)".to_string()))
        );
        assert_eq!(retry("Connecting (attempt 2)..."), None);
        assert_eq!(retry("Connected to 1.2.3.4:5555 via 'eeth0'"), None);
    }
}
