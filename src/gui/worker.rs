//! What the Server and Client tabs have in common: a background worker (`TunnelHandle`), its
//! event channel, status line, log and throughput.

use std::sync::mpsc::Receiver;

use eframe::egui::{self, Color32, RichText};

use super::widgets::{self, LogView};
use crate::log::{Event, Logger};
use crate::tunnel::TunnelHandle;

pub struct Worker {
    pub logger: Logger,
    rx: Receiver<Event>,
    pub handle: Option<TunnelHandle>,
    pub status: String,
    pub log: LogView,
    /// Current throughput (rx, tx) in bytes per second.
    pub traffic: (u64, u64),
    /// Round-trip time through the tunnel, once measured.
    pub rtt: Option<std::time::Duration>,
}

impl Worker {
    pub fn new(ctx: &egui::Context, status: &str) -> Worker {
        let (logger, rx) = Logger::new(Some(ctx.clone()));
        Worker {
            logger,
            rx,
            handle: None,
            status: status.into(),
            log: LogView::default(),
            traffic: (0, 0),
            rtt: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Drains worker events; joins the thread once it has finished.
    pub fn poll(&mut self) {
        for ev in self.rx.try_iter() {
            match ev {
                Event::Log(l) => self.log.push(l),
                Event::Status(s) => self.status = s,
                Event::Traffic { rx, tx, rtt } => (self.traffic, self.rtt) = ((rx, tx), rtt),
            }
        }
        if self.handle.as_ref().is_some_and(|h| h.is_finished()) {
            self.handle.take().unwrap().join();
        }
    }

    /// Asks the worker to stop; `status` is shown until it reports its own final status.
    pub fn stop(&mut self, status: &str) {
        if let Some(h) = &self.handle {
            h.stop();
            self.status = status.into();
        }
    }

    /// Stops and waits for the worker (application exit).
    pub fn shutdown(&mut self) {
        if let Some(h) = self.handle.take() {
            h.join();
        }
    }
}

impl Worker {
    /// Status bar text while waiting for the other side (`peer`: "client" / "sharing
    /// computer"); `off` when not running.
    pub fn listen_status(&self, p: &widgets::Palette, running: bool, peer: &str, off: &str) -> (String, Color32) {
        let handle = self.handle.as_ref();
        let session = handle.and_then(|h| h.client_session());
        let last = handle.and_then(|h| h.last_client());
        let status = self.status.as_str();
        let uptime = |since: std::time::Instant| crate::log::format_uptime(since.elapsed());
        match session {
            Some((addr, since)) if running => (format!("{peer} {addr} connected · {}", uptime(since)), p.text),
            _ if running && status.starts_with("Adapter unavailable") => {
                ("adapter unavailable · waiting for it".into(), p.warn)
            }
            _ if running && status.starts_with("Starting") => ("starting…".into(), p.text),
            _ if running => match last {
                Some((addr, left)) => (
                    format!("{peer} {} left {} ago · waiting", addr.ip(), uptime(left)),
                    p.text,
                ),
                None => (format!("waiting for the {peer}"), p.text),
            },
            _ if status.starts_with("Error") => ("could not start · see log".into(), p.warn),
            _ => (off.into(), p.text),
        }
    }

    /// Status bar text while connecting to `target` (the address as typed); `peer` names the
    /// other side ("server" / "client") and `off` is shown when not running.
    pub fn connect_status(
        &self,
        p: &widgets::Palette,
        running: bool,
        target: &str,
        peer: &str,
        off: &str,
    ) -> (String, Color32) {
        let status = self.status.as_str();
        let link = self
            .handle
            .as_ref()
            .filter(|_| running)
            .map(|h| h.client_link())
            .unwrap_or_default();
        if let Some(since) = link.since {
            // The resolved address (a host name typed above may stand for several).
            let addr = link.peer.map_or_else(|| target.to_string(), |a| a.to_string());
            let mut text = format!("connected to {addr} · {}", crate::log::format_uptime(since.elapsed()));
            match link.reconnects {
                0 => {}
                1 => text.push_str(" · 1 reconnect"),
                n => text.push_str(&format!(" · {n} reconnects")),
            }
            (text, p.text)
        } else if let (true, Some((reason, next))) = (running, retry(status)) {
            let text = if reason.ends_with("nreachable") {
                format!("{target} unreachable · {next}")
            } else {
                format!("connection lost · {next}")
            };
            (text, p.warn)
        } else if running && status.starts_with("Disconnecting") {
            ("disconnecting…".into(), p.text)
        } else if running {
            (format!("connecting to {target}…"), p.text)
        } else if let Some(reason) = status.strip_prefix("Disconnected - error: ") {
            (format!("{reason} · see log"), p.warn)
        } else if status.starts_with("Disconnected - ") {
            (format!("ended by the {peer}"), p.warn)
        } else {
            (off.into(), p.text)
        }
    }

    /// The tray text's second part while running: the session and its traffic, or what it
    /// waits for.
    pub fn tray_session(&self, waiting: &str) -> String {
        match self.handle.as_ref().and_then(|h| h.session()) {
            Some((addr, since)) => format!(
                "{addr} connected · {}\n{}",
                crate::log::format_uptime(since.elapsed()),
                widgets::traffic_line(self.traffic, self.rtt)
            ),
            None if retry(&self.status).is_some() => "connection lost · reconnecting".into(),
            None => waiting.into(),
        }
    }

    /// Whether a session with the other side runs (for the tab badge).
    pub fn connected(&self) -> bool {
        self.is_running() && self.handle.as_ref().is_some_and(|h| h.session().is_some())
    }

    /// The tab badge: the live connection, or that we are getting there. Nothing while off.
    pub fn badge(&self) -> Option<widgets::Badge> {
        use widgets::{Activity, Badge};
        if !self.is_running() {
            None
        } else if self.connected() {
            Some(Badge::new(Activity::On).traffic(self.traffic, self.rtt))
        } else {
            Some(Badge::new(Activity::Pending))
        }
    }
}

/// From the tunnel's "<reason> - retrying in <s> s (attempt <n>)" status: the reason and
/// "retry in <s> s (#<n>)".
pub fn retry(status: &str) -> Option<(&str, String)> {
    let (reason, rest) = status.split_once(" - retrying in ")?;
    let (secs, rest) = rest.split_once(" s")?;
    let attempt = rest.split_once("(attempt ")?.1.trim_end_matches(')');
    Some((reason, format!("retry in {secs} s (#{attempt})")))
}

/// What the waiting side tells the other one: the password and this computer's address.
pub struct Invite {
    pub password: String,
    local_ip: String,
    /// The primary global IPv6 address, if this computer has one.
    local_ip6: Option<std::net::Ipv6Addr>,
    /// All IPv4 addresses with their interface names, for the "My address" hover.
    addresses: Vec<(String, std::net::Ipv4Addr)>,
    /// "Copied to clipboard" after Copy or a click on the address.
    copied: widgets::Copied,
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

/// Primary global IPv6, the one used towards the internet (again only the routing table is
/// asked). Link-local and unique-local addresses are left out: nobody outside can reach them.
fn local_ip6() -> Option<std::net::Ipv6Addr> {
    let s = std::net::UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:db8::1]:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(ip) if is_global_v6(&ip) => Some(ip),
        _ => None,
    }
}

/// Global unicast (2000::/3), the only range reachable from the internet.
fn is_global_v6(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xE000) == 0x2000 && !is_documentation_v6(ip)
}

fn is_documentation_v6(ip: &std::net::Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

impl Invite {
    pub fn new() -> Invite {
        Invite {
            password: crate::secure::generate_password(),
            local_ip: local_ip(),
            local_ip6: local_ip6(),
            addresses: crate::l2::local_ipv4(),
            copied: widgets::Copied::default(),
        }
    }

    pub fn refresh(&mut self) {
        self.local_ip = local_ip();
        self.local_ip6 = local_ip6();
        self.addresses = crate::l2::local_ipv4();
    }

    /// The password with Copy and New password. Returns true when New password was clicked.
    pub fn password_ui(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label(
            RichText::new(crate::secure::display_password(&self.password))
                .monospace()
                .size(20.0)
                .strong(),
        );
        let copy = widgets::small_button(ui, true, "Copy");
        if copy.clicked() {
            self.copied.copy(ui.ctx(), self.password.clone(), &copy);
        }
        widgets::small_button(ui, true, "New password")
            .on_hover_text("A connected peer is disconnected, since its password stops being valid.")
            .clicked()
    }

    /// Replaces the password; a connected peer (confirmed by the user) is disconnected.
    pub fn new_password(&mut self, worker: &Worker, peer: &str) {
        self.password = crate::secure::generate_password();
        if let Some(h) = &worker.handle {
            h.set_password(&self.password);
            if h.disconnect_client() {
                worker.logger.info(format!(
                    "A new password was generated; the connected {peer} was disconnected."
                ));
                return;
            }
        }
        worker.logger.info("A new password was generated.");
    }

    /// "My address" at the right end of the row: a click copies it, the hover lists every
    /// address of this computer (the other side may be on another network).
    pub fn address_ui(&mut self, ui: &mut egui::Ui, port: &str) {
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
                            if let Some(ip6) = self.local_ip6 {
                                ui.label(format!("[{ip6}]:{port}"));
                                widgets::muted(ui, "IPv6");
                                ui.end_row();
                            }
                        });
                })
            };
            if resp.clicked() {
                self.copied.copy(ui.ctx(), address.clone(), &resp);
            }
            // A global IPv6 is too long for the row: a button copies it, the hover shows it.
            if let Some(ip6) = self.local_ip6 {
                let v6 = format!("[{ip6}]:{port}");
                let b = widgets::small_button(ui, true, "IPv6");
                let b = if self.copied.active() {
                    b
                } else {
                    b.on_hover_text(format!(
                        "Copy {v6}\nNo NAT on IPv6: no port forwarding needed, but the router's IPv6 \
                         firewall must allow incoming TCP on this port."
                    ))
                };
                if b.clicked() {
                    self.copied.copy(ui.ctx(), v6, &b);
                }
            }
            widgets::caption(ui, "My address");
        });
    }

    /// Draws the "Copied" note; call once per frame.
    pub fn copied_ui(&mut self, ui: &egui::Ui) {
        self.copied.ui(ui);
    }
}

/// An address as typed plus the port, an IPv6 address in brackets.
pub fn host_port_text(host: &str, port: &str) -> String {
    let host = host.trim();
    if host.contains(':') {
        format!("[{host}]:{}", port.trim())
    } else {
        format!("{host}:{}", port.trim())
    }
}

/// TCP port from a text field; logs the error and returns None when invalid.
pub fn parse_port(text: &str, logger: &Logger) -> Option<u16> {
    match text.trim().parse::<u16>() {
        Ok(p) if p > 0 => Some(p),
        _ => {
            logger.error("The port must be a number between 1 and 65535.");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_global_ipv6_is_offered() {
        let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
        assert!(is_global_v6(&v6("2a01:4f8::1")));
        assert!(!is_global_v6(&v6("fe80::1")));
        assert!(!is_global_v6(&v6("fd00::1")));
        assert!(!is_global_v6(&v6("::1")));
        assert!(!is_global_v6(&v6("2001:db8::5")));
    }
}
