//! Placeholder backend for platforms without L2 support yet (e.g. macOS).

use std::io;
use std::net::Ipv4Addr;

use super::{AdapterInfo, L2Port};
use crate::log::Logger;

pub const CLIENT_ADAPTER_NAME: &str = "(unsupported)";

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Ethernet sharing is not supported on this platform yet",
    )
}

pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    Ok(Vec::new())
}

pub fn local_ipv4() -> Vec<(String, Ipv4Addr)> {
    Vec::new()
}

pub fn server_opener(_id: &str, _log: &Logger) -> super::Opener {
    Box::new(|| Err(unsupported()))
}

pub fn open_client(_mac: [u8; 6], _log: &Logger) -> io::Result<Box<dyn L2Port>> {
    Err(unsupported())
}

pub fn apply_static_ipv4(_addr: Ipv4Addr, _prefix: u8, _log: &Logger) -> io::Result<Box<dyn Send>> {
    Err(unsupported())
}
