//! Neo6: SoftEther's virtual Ethernet adapter (see SoftEtherVPN_Stable/src/Cedar/VLanWin32.c).
//! Opening the device "plugs in the cable"; closing the handle disconnects it.

use std::io;

use super::ffi;
use super::{CLIENT_ADAPTER_NAME, DevicePort, NEO_INSTANCE};
use crate::l2::L2Port;
use crate::log::Logger;

fn device_path() -> String {
    format!(r"\\.\NEO_NEOADAPTER_{NEO_INSTANCE}_DEVICE")
}

/// True when the adapter exists. Checked in the registry: opening the device would
/// briefly signal "cable connected" to Windows.
pub fn is_installed() -> bool {
    super::reg::guid_by_desc(CLIENT_ADAPTER_NAME).is_some()
}

pub fn open(log: &Logger) -> io::Result<DevicePort> {
    // Neo allows exactly one opener.
    let dev = ffi::open_device(&device_path(), 0).map_err(|e| {
        let hint = match e.raw_os_error() {
            Some(ffi::ERROR_FILE_NOT_FOUND) | Some(ffi::ERROR_PATH_NOT_FOUND) => {
                "the virtual adapter is not installed. Click \"Install drivers\" (requires administrator)".to_string()
            }
            Some(ffi::ERROR_SHARING_VIOLATION) | Some(ffi::ERROR_ACCESS_DENIED) => format!(
                "'{CLIENT_ADAPTER_NAME}' is in use by another program (another EasyEther instance or a SoftEther VPN Client)"
            ),
            _ => e.to_string(),
        };
        io::Error::new(e.kind(), format!("Cannot open {CLIENT_ADAPTER_NAME}: {hint}."))
    })?;
    // The event only exists after the device was opened.
    let event = ffi::open_event(&format!(r"Global\NEO_EVENT_NEOADAPTER_{NEO_INSTANCE}"))?;
    let port = DevicePort::new(dev, event);
    port.drain();
    log.info(format!("Virtual adapter '{CLIENT_ADAPTER_NAME}' connected."));
    Ok(port)
}
