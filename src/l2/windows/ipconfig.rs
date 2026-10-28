//! IPv4 on the Neo adapter via IP Helper: an optional static address, removed again when the
//! guard is dropped (on disconnect), or reporting the address Windows' DHCP assigned.

use std::io;
use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, IpDadStatePreferred};

use super::ffi::{self, MIB_UNICASTIPADDRESS_ROW};
use super::{CLIENT_ADAPTER_NAME, NEO_HWID, reg};
use crate::log::Logger;

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
