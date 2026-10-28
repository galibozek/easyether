//! Registry lookups for network adapters (Microsoft's `windows-registry` crate).

use windows_registry::LOCAL_MACHINE;

/// GUID_DEVCLASS_NET
pub const NET_CLASS: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";

fn class_path() -> String {
    format!(r"SYSTEM\CurrentControlSet\Control\Class\{NET_CLASS}")
}

/// Subkey names ("0000", "0001", ...) of network adapters with their NetCfgInstanceId and DriverDesc.
fn adapters() -> Vec<(String, String, String)> {
    let Ok(root) = LOCAL_MACHINE.open(class_path()) else {
        return Vec::new();
    };
    let Ok(keys) = root.keys() else { return Vec::new() };
    keys.filter_map(|name| {
        let k = root.open(&name).ok()?;
        let id = k.get_string("NetCfgInstanceId").ok()?;
        let desc = k.get_string("DriverDesc").unwrap_or_default();
        Some((name, id, desc))
    })
    .collect()
}

/// DriverDesc (device description) of the adapter with the given `{GUID}`.
pub fn driver_desc(guid: &str) -> Option<String> {
    adapters()
        .into_iter()
        .find(|(_, id, _)| id.eq_ignore_ascii_case(guid))
        .map(|(_, _, d)| d)
}

/// `{GUID}` of the adapter whose DriverDesc matches.
pub fn guid_by_desc(desc: &str) -> Option<String> {
    adapters()
        .into_iter()
        .find(|(_, _, d)| d.eq_ignore_ascii_case(desc))
        .map(|(_, id, _)| id)
}

/// Writes a string value into the adapter's class key (found by DriverDesc).
pub fn set_adapter_param(desc: &str, name: &str, value: &str) -> std::io::Result<()> {
    let sub = adapters()
        .into_iter()
        .find(|(_, _, d)| d.eq_ignore_ascii_case(desc))
        .map(|(sub, _, _)| sub)
        .ok_or_else(|| std::io::Error::other(format!("adapter '{desc}' not found in the registry")))?;
    let key = LOCAL_MACHINE
        .create(format!(r"{}\{sub}", class_path()))
        .map_err(std::io::Error::other)?;
    key.set_string(name, value).map_err(std::io::Error::other)
}

/// Writes a DWORD value, creating the key if needed.
pub fn set_u32(path: &str, name: &str, value: u32) -> std::io::Result<()> {
    let key = LOCAL_MACHINE.create(path).map_err(std::io::Error::other)?;
    key.set_u32(name, value).map_err(std::io::Error::other)
}

/// Connection name shown in Windows ("Ethernet", "Wi-Fi", ...).
pub fn connection_name(guid: &str) -> Option<String> {
    LOCAL_MACHINE
        .open(format!(
            r"SYSTEM\CurrentControlSet\Control\Network\{NET_CLASS}\{guid}\Connection"
        ))
        .ok()?
        .get_string("Name")
        .ok()
}
