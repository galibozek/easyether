//! The local end of the tunnel, for either tab: a physical adapter to share (picker), or the
//! virtual adapter with its IPv4 setup (summary + Network settings dialog).

use std::net::Ipv4Addr;

use eframe::egui::{self, RichText};

use super::widgets;
use crate::l2::{self, AdapterInfo};
use crate::log::Logger;
use crate::settings::{self, Settings};
use crate::tunnel;

/// The list of shareable adapters and the chosen one.
#[derive(Default)]
pub struct AdapterPicker {
    adapters: Vec<AdapterInfo>,
    selected: Option<usize>,
}

impl AdapterPicker {
    /// Lists the adapters again, keeping `preferred` (an adapter id) selected if it exists.
    pub fn refresh(&mut self, preferred: &str, log: &Logger) {
        match l2::list_adapters() {
            Ok(list) => {
                self.adapters = list;
                if self.adapters.is_empty() {
                    log.warn("No shareable Ethernet adapters found.");
                }
            }
            Err(e) => {
                self.adapters.clear();
                log.error(e.to_string());
            }
        }
        self.selected = self
            .adapters
            .iter()
            .position(|a| a.id == preferred)
            .or(if self.adapters.is_empty() { None } else { Some(0) });
    }

    /// The chosen adapter as a tunnel device (and its id, for the settings); logs when none.
    pub fn device(&self, log: &Logger) -> Option<(tunnel::Device, String)> {
        let Some(a) = self.selected.and_then(|i| self.adapters.get(i)) else {
            log.error("Choose a network adapter first.");
            return None;
        };
        Some((
            tunnel::Device::Share {
                id: a.id.clone(),
                name: a.name.clone(),
            },
            a.id.clone(),
        ))
    }

    /// The combo box, `width` wide.
    pub fn combo(&mut self, ui: &mut egui::Ui, enabled: bool, width: f32) {
        let current = self
            .selected
            .and_then(|i| self.adapters.get(i))
            .map(|a| format!("{}   {}", a.name, a.detail))
            .unwrap_or_else(|| "(no adapter)".into());
        // egui truncates text only to the width it is given: the box gets its own width, the
        // list a fixed one up to the window's edge; long names (Windows) end in "…", complete
        // on hover.
        let list_width = ui.ctx().content_rect().right() - ui.cursor().left() - 16.0;
        ui.add_enabled_ui(enabled, |ui| {
            ui.set_max_width(width);
            egui::ComboBox::from_id_salt("adapter")
                .width(width)
                .truncate()
                .selected_text(&current)
                .show_ui(ui, |ui| {
                    ui.set_width(list_width.max(width));
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
    }
}

/// The virtual adapter's IPv4 setup: the summary line, and the dialog that changes it.
#[derive(Default)]
pub struct NetSettings {
    dialog: Option<NetDialog>,
}

/// Editable copy of the network settings while the dialog is open.
struct NetDialog {
    static_ip: bool,
    address: String,
    mask: String,
    error: String,
}

impl NetSettings {
    /// The virtual adapter as a tunnel device; logs and returns `None` when the static IPv4
    /// in the settings is invalid.
    pub fn device(settings: &mut Settings, log: &Logger) -> Option<tunnel::Device> {
        let static_ipv4 = if settings.static_ipv4_enabled {
            match static_config(&settings.static_ipv4_address, &settings.static_ipv4_mask) {
                Ok(v) => Some(v),
                Err(e) => {
                    log.error(format!("Network settings: {e}"));
                    return None;
                }
            }
        } else {
            None
        };
        Some(tunnel::Device::Virtual {
            mac: settings.client_mac(),
            static_ipv4,
        })
    }

    /// "IPv4 Automatic (DHCP) on <adapter> [Network settings]"; `name_width` limits the
    /// adapter's name (long on Windows), which then ends in "…" and is complete on hover.
    pub fn summary(&mut self, ui: &mut egui::Ui, settings: &Settings, enabled: bool, name_width: f32) {
        let net = if settings.static_ipv4_enabled {
            format!(
                "Static {} / {}",
                settings.static_ipv4_address, settings.static_ipv4_mask
            )
        } else {
            "Automatic (DHCP)".into()
        };
        widgets::caption(ui, "IPv4");
        ui.label(RichText::new(net).strong());
        widgets::muted(ui, "on");
        let name = l2::client_adapter_name();
        ui.scope(|ui| {
            ui.set_max_width(name_width);
            ui.add(egui::Label::new(RichText::new(name).color(widgets::pal(ui).text)).truncate())
                .on_hover_text(name);
        });
        if widgets::small_button(ui, enabled, "Network settings").clicked() {
            self.dialog = Some(NetDialog {
                static_ip: settings.static_ipv4_enabled,
                address: settings.static_ipv4_address.clone(),
                mask: settings.static_ipv4_mask.clone(),
                error: String::new(),
            });
        }
    }

    /// The dialog while open; call once per frame.
    pub fn dialog(&mut self, ctx: &egui::Context, settings: &mut Settings) {
        let Some(d) = &mut self.dialog else { return };
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
                        self.dialog = None;
                    }
                    Err(e) => d.error = e,
                }
            }
            Some(false) => self.dialog = None,
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
