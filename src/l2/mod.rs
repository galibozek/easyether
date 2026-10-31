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

pub(crate) type Opener = Box<dyn Fn() -> io::Result<Box<dyn L2Port>> + Send + Sync>;
type ReopenHook = Arc<dyn Fn() + Send + Sync>;

/// Watches an adapter and survives it disappearing (USB unplug, driver restart, adapter
/// disabled): errors are logged once, frames are dropped while it is gone, and it is reopened
/// every second until it comes back. Link (cable) changes are logged too where available.
pub struct ResilientPort {
    name: String,
    open: Opener,
    log: Logger,
    state: Mutex<WatchState>,
    /// Runs (on its own thread) after a successful reopen, e.g. to configure the adapter's IP
    /// again.
    on_reopen: Mutex<Option<ReopenHook>>,
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
            on_reopen: Mutex::new(None),
        };
        rp.current();
        Ok(rp)
    }

    /// Sets what to do after the adapter was reopened. It runs on a thread of its own, so it
    /// may wait (for the OS to finish bringing the adapter up, for a DHCP helper) without
    /// holding up the frames that start flowing again.
    pub fn set_on_reopen(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_reopen.lock().unwrap() = Some(Arc::new(hook));
    }

    /// The open port, reopening it (at most once a second) if it was lost.
    fn current(&self) -> Option<Arc<dyn L2Port>> {
        let mut st = self.state.lock().unwrap();
        if st.port.is_none() && st.last_reopen.elapsed() >= Duration::from_secs(1) {
            st.last_reopen = Instant::now();
            if let Ok(p) = (self.open)() {
                self.log
                    .info(format!("Adapter '{}' is back; forwarding resumed.", self.name));
                st.port = Some(Arc::from(p));
                st.link = None;
                if let Some(hook) = self.on_reopen.lock().unwrap().clone() {
                    std::thread::spawn(move || hook());
                }
            }
        }
        let port = st.port.clone()?;
        if st.last_link_check.elapsed() >= Duration::from_secs(1) {
            st.last_link_check = Instant::now();
            let link = port.link_up();
            if link.is_some() && link != st.link {
                match (st.link, link) {
                    (_, Some(false)) => self
                        .log
                        .warn(format!("Adapter '{}': link is down (cable unplugged?).", self.name)),
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
        let same = st
            .port
            .as_ref()
            .is_some_and(|p| std::ptr::addr_eq(Arc::as_ptr(p), Arc::as_ptr(port)));
        if same {
            st.port = None;
            st.last_reopen = Instant::now();
            self.log.warn(format!(
                "Adapter '{}' disappeared ({e}). Waiting for it to come back (USB re-plug, driver restart)...",
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
    ResilientPort::open(name, platform::server_opener(id, log), log)
}

/// Opens the virtual adapter (client side), watched like the server's so that a driver restart
/// or a disabled-and-enabled adapter does not end the client. `mac` is used where the platform
/// lets us choose it.
pub fn open_client(mac: [u8; 6], log: &Logger) -> io::Result<ResilientPort> {
    let log2 = log.clone();
    ResilientPort::open(
        platform::CLIENT_ADAPTER_NAME,
        Box::new(move || platform::open_client(mac, &log2)),
        log,
    )
}

/// Makes the client's virtual adapter lose against every local network when routes compete
/// (Windows: interface metric 9000, default routes ignored where supported), so a gateway or
/// route handed out by a DHCP server on the shared network cannot pull this computer's own
/// traffic, the tunnel's connection included, into the tunnel. Linux does the same through
/// its dhcpcd options. Best effort; logs what it could not do.
pub fn prefer_local_networks(log: &Logger) {
    #[cfg(windows)]
    windows::prefer_local_networks(log);
    #[cfg(not(windows))]
    let _ = log;
}

/// Optional static IPv4 on the client's virtual adapter. Dropping the guard removes it.
pub fn apply_static_ipv4(addr: std::net::Ipv4Addr, prefix: u8, log: &Logger) -> io::Result<Box<dyn Send>> {
    platform::apply_static_ipv4(addr, prefix, log)
}

/// "Automatic" IPv4 on the client's virtual adapter (Linux: dhcpcd; Windows runs DHCP on the
/// adapter itself) and logs the address once it is there. Dropping the guard stops both.
pub fn start_dhcp(log: &Logger) -> io::Result<Option<Box<dyn Send>>> {
    #[cfg(any(windows, target_os = "linux"))]
    return platform::start_dhcp(log);
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = log;
        Ok(None)
    }
}

/// Stops the thread started by `watch_ipv4` when dropped.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) struct AddressWatch(Arc<std::sync::atomic::AtomicBool>);

#[cfg(any(windows, target_os = "linux"))]
impl Drop for AddressWatch {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Logs the client adapter's IPv4 address (`lookup` lists its current ones) once the OS has
/// one. A link-local fallback is logged too, and watching goes on in case a DHCP lease
/// replaces it later; a lease wins over a link-local address that is still present.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn watch_ipv4(lookup: impl Fn() -> Vec<std::net::Ipv4Addr> + Send + 'static, log: &Logger) -> AddressWatch {
    // Windows waits about a minute for DHCP before it falls back to 169.254.x.x; dhcpcd on
    // Linux is much quicker (IPv4LL after ~10 s).
    #[cfg(windows)]
    const WAIT: Duration = Duration::from_secs(65);
    #[cfg(not(windows))]
    const WAIT: Duration = Duration::from_secs(60);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (done2, log) = (done.clone(), log.clone());
    std::thread::spawn(move || {
        let name = client_adapter_name();
        let deadline = Instant::now() + WAIT;
        let mut last = None;
        while !done2.load(std::sync::atomic::Ordering::Relaxed) {
            let addrs = lookup();
            let best = addrs.iter().find(|ip| !ip.is_link_local()).or(addrs.first()).copied();
            if let Some(ip) = best.filter(|ip| Some(*ip) != last) {
                if ip.is_link_local() {
                    log.info(format!("IPv4 {ip} (link-local, no DHCP server answered) on '{name}'."));
                    last = Some(ip);
                } else {
                    log.info(format!("IPv4 {ip} on '{name}'."));
                    return;
                }
            }
            if Instant::now() >= deadline {
                if last.is_none() {
                    log.warn(format!(
                        "No IPv4 on '{name}' after {} s (no DHCP answer and no link-local address). \
                         Set a static IPv4 in Network settings.",
                        WAIT.as_secs()
                    ));
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    AddressWatch(done)
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

    /// Fails its first `recv` (adapter gone), works afterwards.
    struct FailsOnce(std::sync::atomic::AtomicBool);

    impl L2Port for FailsOnce {
        fn recv(&self, _out: &mut Vec<Vec<u8>>, _timeout: Duration) -> io::Result<()> {
            if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(io::Error::other("device removed"));
            }
            Ok(())
        }
        fn send(&self, _frames: &[Vec<u8>]) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lost_adapter_is_reopened_and_the_hook_runs() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let opens = Arc::new(AtomicUsize::new(0));
        let hooks = Arc::new(AtomicUsize::new(0));
        let (log, _rx) = Logger::new(None);
        let opener = {
            let opens = opens.clone();
            Box::new(move || {
                // The first port loses its device; the reopened one is fine.
                let first = opens.fetch_add(1, Ordering::SeqCst) == 0;
                Ok(Box::new(FailsOnce(std::sync::atomic::AtomicBool::new(first))) as Box<dyn L2Port>)
            })
        };
        let port = ResilientPort::open("test", opener, &log).unwrap();
        let h = hooks.clone();
        port.set_on_reopen(move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let mut out = Vec::new();
        // The error is absorbed: the session using the port does not end.
        port.recv(&mut out, Duration::ZERO).unwrap();
        assert!(!port.is_present());
        assert_eq!(hooks.load(Ordering::SeqCst), 0);
        // Reopened at most once a second; the hook runs right after, on its own thread.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !port.is_present() && Instant::now() < deadline {
            port.recv(&mut out, Duration::from_millis(100)).unwrap();
        }
        assert!(port.is_present());
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        while hooks.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(hooks.load(Ordering::SeqCst), 1);
    }
}
