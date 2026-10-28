//! Optional static IPv4 on the Neo adapter via IP Helper. The address is removed again
//! when the guard is dropped (on disconnect).

use std::io;
use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, IpDadStatePreferred};

use super::ffi::{self, MIB_UNICASTIPADDRESS_ROW};
use super::{CLIENT_ADAPTER_NAME, reg};
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

pub fn apply(addr: Ipv4Addr, prefix: u8, log: &Logger) -> io::Result<Box<dyn Send>> {
    let guid_str = reg::guid_by_desc(CLIENT_ADAPTER_NAME)
        .ok_or_else(|| io::Error::other(format!("'{CLIENT_ADAPTER_NAME}' not found")))?;
    let guid = ffi::parse_guid(&guid_str).ok_or_else(|| io::Error::other("invalid adapter GUID"))?;
    // SAFETY: NET_LUID_LH is a plain union; zero is valid.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to a GUID and a NET_LUID.
    let r = unsafe { ffi::ConvertInterfaceGuidToLuid(&guid, &mut luid) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r as i32));
    }

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
