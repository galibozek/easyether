//! Platform access to raw Ethernet (layer 2).
//!
//! * Server side: a physical adapter opened for raw frame capture/injection
//!   (SeLow on Windows, AF_PACKET on Linux).
//! * Client side: a virtual adapter whose frames are carried through the tunnel
//!   (Neo6 on Windows, TAP on Linux).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::log::Logger;

#[cfg(any(windows, test))]
pub mod exchange;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use self::windows as platform;

#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported;
#[cfg(not(any(windows, target_os = "linux")))]
use unsupported as platform;

/// A raw Ethernet port. `recv` and `send` may be called concurrently from two threads.
pub trait L2Port: Send + Sync {
    /// Waits up to `timeout` for frames and appends everything available (up to 256) to `out`.
    fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()>;
    /// Sends frames out of the port.
    fn send(&self, frames: &[Vec<u8>]) -> io::Result<()>;

    /// Physical link state (cable plugged in), when the platform can tell.
    fn link_up(&self) -> Option<bool> {
        None
    }

    /// Discards frames queued while nobody was listening.
    fn drain(&self) {
        let mut tmp = Vec::new();
        for _ in 0..64 {
            tmp.clear();
            if self.recv(&mut tmp, Duration::ZERO).is_err() || tmp.is_empty() {
                break;
            }
        }
    }
}

type Opener = Box<dyn Fn() -> io::Result<Box<dyn L2Port>> + Send + Sync>;

/// Watches a physical adapter and survives it disappearing (USB unplug, driver restart):
/// errors are logged once, frames are dropped while it is gone, and it is reopened every
/// second until it comes back. Link (cable) changes are logged too where available.
pub struct ResilientPort {
    name: String,
    open: Opener,
    log: Logger,
    state: Mutex<WatchState>,
}

struct WatchState {
    port: Option<Arc<dyn L2Port>>,
    last_reopen: Instant,
    last_link_check: Instant,
    link: Option<bool>,
}

impl ResilientPort {
    /// Opens the adapter; the first open must succeed.
    pub fn open(name: &str, open: Opener, log: &Logger) -> io::Result<ResilientPort> {
        let port: Arc<dyn L2Port> = Arc::from(open()?);
        let rp = ResilientPort {
            name: name.to_string(),
            open,
            log: log.clone(),
            state: Mutex::new(WatchState {
                port: Some(port),
                last_reopen: Instant::now(),
                last_link_check: Instant::now() - Duration::from_secs(10),
                link: None,
            }),
        };
        rp.current();
        Ok(rp)
    }

    /// The open port, reopening it (at most once a second) if it was lost.
    fn current(&self) -> Option<Arc<dyn L2Port>> {
        let mut st = self.state.lock().unwrap();
        if st.port.is_none() && st.last_reopen.elapsed() >= Duration::from_secs(1) {
            st.last_reopen = Instant::now();
            if let Ok(p) = (self.open)() {
                self.log.info(format!("Adapter '{}' is back; forwarding resumed.", self.name));
                st.port = Some(Arc::from(p));
                st.link = None;
            }
        }
        let port = st.port.clone()?;
        if st.last_link_check.elapsed() >= Duration::from_secs(1) {
            st.last_link_check = Instant::now();
            let link = port.link_up();
            if link.is_some() && link != st.link {
                match (st.link, link) {
                    (_, Some(false)) => self.log.warn(format!("Adapter '{}': link is down (cable unplugged?).", self.name)),
                    (Some(false), Some(true)) => self.log.info(format!("Adapter '{}': link is up.", self.name)),
                    _ => {}
                }
                st.link = link;
            }
        }
        Some(port)
    }

    fn lost(&self, port: &Arc<dyn L2Port>, e: io::Error) {
        let mut st = self.state.lock().unwrap();
        let same = st.port.as_ref().is_some_and(|p| std::ptr::addr_eq(Arc::as_ptr(p), Arc::as_ptr(port)));
        if same {
            st.port = None;
            st.last_reopen = Instant::now();
            self.log.warn(format!(
                "Adapter '{}' disappeared ({e}). Waiting for it to come back (e.g. USB re-plug)...",
                self.name
            ));
        }
    }

    pub fn is_present(&self) -> bool {
        self.state.lock().unwrap().port.is_some()
    }
}

impl L2Port for ResilientPort {
    fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
        match self.current() {
            Some(p) => {
                if let Err(e) = p.recv(out, timeout) {
                    self.lost(&p, e);
                }
            }
            None => std::thread::sleep(timeout.min(Duration::from_millis(200))),
        }
        Ok(())
    }

    fn send(&self, frames: &[Vec<u8>]) -> io::Result<()> {
        if let Some(p) = self.current()
            && let Err(e) = p.send(frames)
        {
            self.lost(&p, e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    /// Stable identifier passed back to `open_server` (GUID on Windows, ifname on Linux).
    pub id: String,
    /// Human readable name for the adapter list.
    pub name: String,
    /// Extra detail shown next to the name (MAC / IPv4).
    pub detail: String,
}

/// Lists physical adapters that can be shared.
pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    platform::list_adapters()
}

/// Opens a physical adapter for sharing (server side), watched for disappearance.
pub fn open_server(id: &str, name: &str, log: &Logger) -> io::Result<ResilientPort> {
    let (id, log2) = (id.to_string(), log.clone());
    ResilientPort::open(name, Box::new(move || platform::open_server(&id, &log2)), log)
}

/// Opens the virtual adapter (client side). `mac` is used where the platform lets us choose it.
pub fn open_client(mac: [u8; 6], log: &Logger) -> io::Result<Box<dyn L2Port>> {
    platform::open_client(mac, log)
}

/// Optional static IPv4 on the client's virtual adapter. Dropping the guard removes it.
pub fn apply_static_ipv4(
    addr: std::net::Ipv4Addr,
    prefix: u8,
    log: &Logger,
) -> io::Result<Box<dyn Send>> {
    platform::apply_static_ipv4(addr, prefix, log)
}

/// Linux: the root helper started by pkexec (see linux/helper.rs).
#[cfg(target_os = "linux")]
pub const PRIVILEGED_HELPER_ARG: &str = linux::helper::ARG;

#[cfg(target_os = "linux")]
pub fn run_privileged_helper() -> i32 {
    linux::helper::run()
}

/// Platform preparation before listening on `port` (Windows: firewall rule).
pub fn prepare_listen(port: u16, log: &Logger) {
    #[cfg(windows)]
    windows::firewall::allow_inbound(port, log);
    #[cfg(not(windows))]
    let _ = (port, log);
}

/// Name of the client's virtual adapter as the OS shows it.
pub fn client_adapter_name() -> &'static str {
    platform::CLIENT_ADAPTER_NAME
}

pub fn format_mac(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Re-inserts an 802.1Q tag the OS stripped into out-of-band data.
#[cfg(any(target_os = "linux", test))]
pub fn insert_vlan_tag(frame: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() + 4);
    out.extend_from_slice(&frame[..12]);
    out.extend_from_slice(&tpid.to_be_bytes());
    out.extend_from_slice(&tci.to_be_bytes());
    out.extend_from_slice(&frame[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_tag_insertion() {
        let mut frame = vec![0xAA; 12];
        frame.extend_from_slice(&[0x08, 0x00, 1, 2]);
        let tagged = insert_vlan_tag(&frame, 0x8100, 0x2005);
        assert_eq!(&tagged[12..16], &[0x81, 0x00, 0x20, 0x05]);
        assert_eq!(&tagged[16..], &[0x08, 0x00, 1, 2]);
    }

    #[test]
    fn mac_format() {
        assert_eq!(format_mac(&[0x5e, 0, 1, 2, 3, 0xff]), "5E:00:01:02:03:FF");
    }
}
