//! SeLow: raw access to a physical NIC (see SoftEtherVPN_Stable/src/Cedar/SeLowUser.c).

use std::io;
use std::time::Duration;

use super::ffi::{self, Handle};
use super::{DevicePort, reg};
use crate::l2::exchange::{SL_ADAPTER_LIST_SIZE, SeLowAdapterList, parse_selow_adapter_list, unique_by_mac};
use crate::l2::{AdapterInfo, L2Port, format_mac};
use crate::log::Logger;

const BASIC_DEVICE: &str = r"\\.\SELOW_BASIC_DEVICE";
/// CTL_CODE(0x8000, 1, METHOD_NEITHER, FILE_ANY_ACCESS)
const IOCTL_GET_EVENT_NAME: u32 = 0x8000_0007;

fn not_installed(e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!(
            "The SeLow driver is not installed or not running ({e}). Click \"Install drivers\" (requires administrator)."
        ),
    )
}

pub fn is_available() -> bool {
    ffi::open_device(BASIC_DEVICE, ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE).is_ok()
}

fn read_list() -> io::Result<SeLowAdapterList> {
    let h = ffi::open_device(BASIC_DEVICE, ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE).map_err(not_installed)?;
    let mut buf = vec![0u8; SL_ADAPTER_LIST_SIZE];
    // Right after boot/installation SeLow may still be binding to adapters.
    for attempt in 0..20 {
        let mut read = 0u32;
        // SAFETY: buf has the size the driver requires. The returned byte count is not
        // checked: the driver reports sizeof(SL_ADAPTER_INFO) instead of the list size.
        let ok = unsafe { ffi::ReadFile(h.0, buf.as_mut_ptr(), buf.len() as u32, &mut read, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let list = parse_selow_adapter_list(&buf).map_err(io::Error::other)?;
        if list.enum_completed || attempt == 19 {
            return Ok(list);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    unreachable!()
}

/// MAC of the adapter with this GUID, if SeLow lists it.
pub fn mac_of(guid: &str) -> Option<[u8; 6]> {
    let list = read_list().ok()?;
    list.adapters
        .iter()
        .find(|a| a.guid().eq_ignore_ascii_case(guid))
        .map(|a| a.mac)
}

/// GUID of the one adapter with this MAC (see `unique_by_mac`).
pub fn guid_by_mac(mac: [u8; 6]) -> Option<String> {
    let list = read_list().ok()?;
    unique_by_mac(&list.adapters, mac).map(|a| a.guid().to_string())
}

pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    let list = read_list()?;
    let own = reg::guid_by_component(super::NEO_HWID);
    let mut out: Vec<AdapterInfo> = list
        .adapters
        .iter()
        .map(|a| {
            let guid = a.guid().to_string();
            let desc = if a.friendly_name.is_empty() {
                reg::driver_desc(&guid).unwrap_or_default()
            } else {
                a.friendly_name
                    .trim_end_matches(" (Microsoft's Packet Scheduler)")
                    .to_string()
            };
            let name = match reg::connection_name(&guid) {
                Some(conn) if !desc.is_empty() => format!("{conn} ({desc})"),
                Some(conn) => conn,
                None => desc,
            };
            AdapterInfo {
                id: guid,
                name,
                detail: format_mac(&a.mac),
            }
        })
        // Never offer our own client adapter (renamed, so matched by GUID) or other SoftEther
        // virtual adapters.
        .filter(|a| {
            !own.as_deref().is_some_and(|g| a.id.eq_ignore_ascii_case(g)) && !a.name.contains("VPN Client Adapter")
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn open(guid: &str, log: &Logger) -> io::Result<DevicePort> {
    let path = format!(r"\\.\SELOW_A_{guid}");
    // USB adapters can briefly disappear while re-enumerating; retry for ~5 s.
    let mut attempt = 0;
    let dev = loop {
        match ffi::open_device(&path, ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE) {
            Ok(h) => break h,
            Err(e) if attempt < 20 && e.raw_os_error() == Some(ffi::ERROR_FILE_NOT_FOUND) => {
                if !is_available() {
                    return Err(not_installed(e));
                }
                attempt += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot open SeLow adapter {guid}: {e}"),
                ));
            }
        }
    };

    let mut name = [0u8; 128];
    let mut ret = 0u32;
    // SAFETY: METHOD_NEITHER: the driver writes the event name directly into `name`.
    let ok = unsafe {
        ffi::DeviceIoControl(
            dev.0,
            IOCTL_GET_EVENT_NAME,
            name.as_ptr().cast(),
            name.len() as u32,
            name.as_mut_ptr().cast(),
            name.len() as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let event_name = String::from_utf8_lossy(&name[..end]).into_owned();
    let event: Handle = ffi::open_event(&event_name)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot open SeLow event {event_name}: {e}")))?;

    let port = DevicePort::new(dev, event);
    port.drain();
    log.info("SeLow adapter opened (the driver switches it to promiscuous mode while open).");
    Ok(port)
}
