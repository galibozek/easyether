//! Persistent user settings (JSON in the OS config directory).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub server_adapter_id: String,
    pub server_port: u16,
    pub server_secure: bool,
    pub client_host: String,
    pub client_port: u16,
    pub client_secure: bool,
    pub static_ipv4_enabled: bool,
    pub static_ipv4_address: String,
    pub static_ipv4_mask: String,
    /// MAC of the client's virtual adapter where we can choose it (Linux TAP), generated once.
    pub client_mac: String,
    pub last_tab: String,
    /// "System", "Light" or "Dark".
    pub theme: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            server_adapter_id: String::new(),
            server_port: DEFAULT_PORT,
            server_secure: true,
            client_host: String::new(),
            client_port: DEFAULT_PORT,
            client_secure: true,
            static_ipv4_enabled: false,
            static_ipv4_address: String::new(),
            static_ipv4_mask: "255.255.255.0".into(),
            client_mac: String::new(),
            last_tab: "Server".into(),
            theme: "System".into(),
        }
    }
}

pub const DEFAULT_PORT: u16 = 5555;

fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "EasyEther").map(|d| d.config_dir().join("settings.json"))
}

impl Settings {
    pub fn load() -> Settings {
        path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let Some(p) = path() else { return };
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            // Write then rename so a crash never leaves a half-written file.
            let tmp = p.with_extension("json.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(tmp, p);
            }
        }
    }

    /// The client MAC, generating (and saving) a random locally administered one if needed.
    pub fn client_mac(&mut self) -> [u8; 6] {
        if let Some(mac) = parse_mac(&self.client_mac) {
            return mac;
        }
        let mut mac = [0u8; 6];
        crate::secure::random_fill(&mut mac);
        mac[0] = 0x5E; // unicast, locally administered
        self.client_mac = crate::l2::format_mac(&mac);
        self.save();
        mac
    }
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<u8> = s
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<_>>()?;
    parts.try_into().ok()
}

/// "255.255.255.0" or "24" -> 24.
pub fn parse_prefix(mask: &str) -> Option<u8> {
    let mask = mask.trim();
    if let Ok(n) = mask.trim_start_matches('/').parse::<u8>() {
        return (n <= 32).then_some(n);
    }
    let m: std::net::Ipv4Addr = mask.parse().ok()?;
    let bits = u32::from(m);
    let n = bits.leading_ones();
    (bits.checked_shl(n).unwrap_or(0) == 0).then_some(n as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parsing() {
        assert_eq!(parse_prefix("255.255.255.0"), Some(24));
        assert_eq!(parse_prefix("255.255.0.0"), Some(16));
        assert_eq!(parse_prefix("255.255.255.255"), Some(32));
        assert_eq!(parse_prefix("/20"), Some(20));
        assert_eq!(parse_prefix("255.0.255.0"), None);
        assert_eq!(parse_prefix("33"), None);
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(parse_mac("5E:00:01:02:03:FF"), Some([0x5e, 0, 1, 2, 3, 0xff]));
        assert_eq!(parse_mac("5E:00"), None);
    }
}
