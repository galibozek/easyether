//! IPv4 on the Neo adapter via IP Helper: an optional static address, removed again when the
//! guard is dropped (on disconnect), or reporting the address Windows' DHCP assigned.

use std::io;
use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, IpDadStatePreferred};

use super::ffi::{self, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW};
use super::{CLIENT_ADAPTER_NAME, NEO_HWID, reg};
use crate::log::Logger;

/// Interface metric of the tunnel adapter: far above the automatic metrics Windows gives real
/// adapters (5 to 55), so any route through it loses against the same route via a local
/// network. The same value the Linux client uses for its routes.
const TUNNEL_METRIC: u32 = 9000;

struct AddressGuard {
    row: Box<MIB_UNICASTIPADDRESS_ROW>,
    owned: bool,
}

// SAFETY: the row is plain data.
unsafe impl Send for AddressGuard {}

impl Drop for AddressGuard {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: the row was initialised by apply().
            unsafe { ffi::DeleteUnicastIpAddressEntry(&*self.row) };
        }
    }
}

fn neo_luid() -> io::Result<NET_LUID_LH> {
    let guid_str = reg::guid_by_component(NEO_HWID)
        .ok_or_else(|| io::Error::other(format!("'{CLIENT_ADAPTER_NAME}' not found")))?;
    let guid = ffi::parse_guid(&guid_str).ok_or_else(|| io::Error::other("invalid adapter GUID"))?;
    // SAFETY: NET_LUID_LH is a plain union; zero is valid.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to a GUID and a NET_LUID.
    let r = unsafe { ffi::ConvertInterfaceGuidToLuid(&guid, &mut luid) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r as i32));
    }
    Ok(luid)
}

/// Usable IPv4 addresses of all adapters but loopback, with the adapter's name.
pub fn local_ipv4() -> Vec<(String, Ipv4Addr)> {
    let mut table: *mut ffi::MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: on success the table is allocated by IP Helper and freed below.
    if unsafe { ffi::GetUnicastIpAddressTable(AF_INET, &mut table) } != 0 {
        return Vec::new();
    }
    // SAFETY: the table holds NumEntries rows; the union fields read match AF_INET rows.
    let rows: Vec<(NET_LUID_LH, Ipv4Addr)> = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            .iter()
            .filter(|r| r.DadState == IpDadStatePreferred)
            .map(|r| {
                (
                    r.InterfaceLuid,
                    Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()),
                )
            })
            .filter(|(_, a)| !a.is_loopback())
            .collect()
    };
    // SAFETY: allocated by GetUnicastIpAddressTable.
    unsafe { ffi::FreeMibTable(table.cast()) };
    let mut list: Vec<_> = rows
        .into_iter()
        .map(|(luid, a)| {
            let mut alias = [0u16; 257];
            // SAFETY: the buffer holds `alias.len()` UTF-16 units, NDIS_IF_MAX_STRING_SIZE + 1.
            let r = unsafe { ffi::ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) };
            let len = alias.iter().position(|&c| c == 0).unwrap_or(0);
            let name = if r == 0 {
                String::from_utf16_lossy(&alias[..len])
            } else {
                String::new()
            };
            (name, a)
        })
        .collect();
    list.sort();
    list
}

/// The adapter's usable IPv4 addresses (duplicate detection finished).
fn current_ipv4(luid: u64) -> Vec<Ipv4Addr> {
    let mut table: *mut ffi::MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: on success the table is allocated by IP Helper and freed below.
    if unsafe { ffi::GetUnicastIpAddressTable(AF_INET, &mut table) } != 0 {
        return Vec::new();
    }
    // SAFETY: the table holds NumEntries rows; the union fields read match AF_INET rows.
    let found = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            .iter()
            .filter(|r| r.InterfaceLuid.Value == luid && r.DadState == IpDadStatePreferred)
            .map(|r| Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
            .collect()
    };
    // SAFETY: allocated by GetUnicastIpAddressTable.
    unsafe { ffi::FreeMibTable(table.cast()) };
    found
}

/// Keeps the remote network from taking over this computer's routing. Windows' DHCP client
/// accepts a default gateway (and IPv6 router advertisements a default route) on the tunnel
/// adapter like on any other; with an automatic metric (Neo6 reports 100 Mbit/s) that route
/// can win against Wi-Fi, and then even the tunnel's own connection to the server would be
/// sent into the tunnel and the client could not reconnect. A fixed high metric makes every
/// local route win; where Windows supports it, default routes on the adapter are also ignored
/// outright. Applied on every connect and after the adapter was reopened, since a restarted
/// adapter loses it. Best effort.
pub fn prefer_local_networks(log: &Logger) {
    let luid = match neo_luid() {
        Ok(l) => l,
        Err(e) => {
            log.warn(format!(
                "Could not lower the route priority of '{CLIENT_ADAPTER_NAME}': {e}"
            ));
            return;
        }
    };
    // Right after the adapter was (re)enabled, its IP interfaces can appear a moment after the
    // device does: keep trying for a few seconds, but only while IPv4 is missing. IPv6 is
    // often unbound from the adapter and then never appears; waiting for it would delay every
    // connect. It gets an attempt in each round, and only IPv4 gets a warning in the end.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut pending = vec![AF_INET, AF_INET6];
    loop {
        pending.retain(|&family| !set_tunnel_metric(luid, family, log));
        if !pending.contains(&AF_INET) || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if pending.contains(&AF_INET) {
        log.warn(format!(
            "'{CLIENT_ADAPTER_NAME}' has no IPv4 interface to set the route priority on: routes from the remote network may compete with local ones."
        ));
    }
}

/// One attempt for one address family. `false` only when the interface does not exist (yet);
/// a failure to set it is logged and counts as done.
fn set_tunnel_metric(luid: NET_LUID_LH, family: u16, log: &Logger) -> bool {
    // SAFETY: MIB_IPINTERFACE_ROW is plain old data; all-zero is a valid value.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: `row` is a valid, exclusively borrowed row for the call.
    unsafe { ffi::InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    // SAFETY: `row` names the interface by family and LUID; the call fills in the rest.
    if unsafe { ffi::GetIpInterfaceEntry(&mut row) } != 0 {
        return false;
    }
    // SetIpInterfaceEntry rejects IPv4 rows that carry a site prefix length.
    if family == AF_INET {
        row.SitePrefixLength = 0;
    }
    row.UseAutomaticMetric = false;
    row.Metric = TUNNEL_METRIC;
    // SAFETY: `row` was filled by GetIpInterfaceEntry and only adjusted above.
    let r = unsafe { ffi::SetIpInterfaceEntry(&mut row) };
    if r != 0 {
        log.warn(format!(
            "Could not lower the route priority of '{CLIENT_ADAPTER_NAME}' ({}): routes from the remote network may compete with local ones.",
            io::Error::from_raw_os_error(r as i32)
        ));
        return true;
    }
    // Separate call: older Windows versions reject the field, and the metric must not depend
    // on it.
    row.DisableDefaultRoutes = true;
    // SAFETY: as above.
    let _ = unsafe { ffi::SetIpInterfaceEntry(&mut row) };
    true
}

/// Windows runs DHCP (with the 169.254.x.x fallback) on the adapter by itself; only report
/// the address it gets.
pub fn start_dhcp(log: &Logger) -> io::Result<Option<Box<dyn Send>>> {
    // SAFETY: Value covers the whole union.
    let luid = unsafe { neo_luid()?.Value };
    Ok(Some(Box::new(crate::l2::watch_ipv4(move || current_ipv4(luid), log))))
}

pub fn apply(addr: Ipv4Addr, prefix: u8, log: &Logger) -> io::Result<Box<dyn Send>> {
    let luid = neo_luid()?;

    // SAFETY: a zeroed row is valid input for InitializeUnicastIpAddressEntry.
    let mut row: Box<MIB_UNICASTIPADDRESS_ROW> = Box::new(unsafe { std::mem::zeroed() });
    // SAFETY: `row` is a valid, exclusively borrowed row for the call.
    unsafe { ffi::InitializeUnicastIpAddressEntry(&mut *row) };
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    row.InterfaceLuid = luid;
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;

    // SAFETY: row is fully initialised.
    let r = unsafe { ffi::CreateUnicastIpAddressEntry(&*row) };
    let owned = match r {
        0 => true,
        ffi::ERROR_OBJECT_ALREADY_EXISTS => {
            log.info(format!("{addr}/{prefix} is already configured on the adapter."));
            false
        }
        e => return Err(io::Error::from_raw_os_error(e as i32)),
    };
    log.info(format!("Static IPv4 {addr}/{prefix} set on '{CLIENT_ADAPTER_NAME}'."));
    Ok(Box::new(AddressGuard { row, owned }))
}
