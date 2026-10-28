//! Registry lookups for network adapters (Microsoft's `windows-registry` crate).

use windows_registry::LOCAL_MACHINE;

/// GUID_DEVCLASS_NET
pub const NET_CLASS: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";

fn class_path() -> String {
    format!(r"SYSTEM\CurrentControlSet\Control\Class\{NET_CLASS}")
}

/// A network adapter's class key ("0000", "0001", ...).
struct Adapter {
    subkey: String,
    /// NetCfgInstanceId, `{GUID}`.
    guid: String,
    /// Shown description; we may rename it.
    desc: String,
    /// Hardware id ("NeoAdapter_VPN127"): `ComponentId`, written by the Net class installer,
    /// and `Ndi\DeviceID`, written by the INF itself. Neither changes after installation.
    component_id: String,
    ndi_device_id: String,
}

impl Adapter {
    fn is_component(&self, component_id: &str) -> bool {
        self.component_id.eq_ignore_ascii_case(component_id) || self.ndi_device_id.eq_ignore_ascii_case(component_id)
    }
}

fn adapters() -> Vec<Adapter> {
    let Ok(root) = LOCAL_MACHINE.open(class_path()) else {
        return Vec::new();
    };
    let Ok(keys) = root.keys() else { return Vec::new() };
    keys.filter_map(|subkey| {
        let k = root.open(&subkey).ok()?;
        Some(Adapter {
            guid: k.get_string("NetCfgInstanceId").ok()?,
            desc: k.get_string("DriverDesc").unwrap_or_default(),
            component_id: k.get_string("ComponentId").unwrap_or_default(),
            ndi_device_id: k.open("Ndi").and_then(|n| n.get_string("DeviceID")).unwrap_or_default(),
            subkey,
        })
    })
    .collect()
}

fn by_component(component_id: &str) -> Option<Adapter> {
    adapters().into_iter().find(|a| a.is_component(component_id))
}

/// DriverDesc (device description) of the adapter with the given `{GUID}`.
pub fn driver_desc(guid: &str) -> Option<String> {
    adapters()
        .into_iter()
        .find(|a| a.guid.eq_ignore_ascii_case(guid))
        .map(|a| a.desc)
}

/// `{GUID}` of the adapter installed from the given hardware id.
pub fn guid_by_component(component_id: &str) -> Option<String> {
    by_component(component_id).map(|a| a.guid)
}

/// Writes a string value into the class key of the adapter with the given hardware id.
pub fn set_adapter_param(component_id: &str, name: &str, value: &str) -> std::io::Result<()> {
    let sub = by_component(component_id)
        .map(|a| a.subkey)
        .ok_or_else(|| std::io::Error::other(format!("adapter '{component_id}' not found in the registry")))?;
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
