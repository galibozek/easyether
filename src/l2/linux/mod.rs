//! Linux backend: AF_PACKET raw socket (server) and TAP device (client).

pub mod helper;
mod packet;
mod tap;

use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use super::{AdapterInfo, L2Port, format_mac};
use crate::log::Logger;

pub const CLIENT_ADAPTER_NAME: &str = tap::IFNAME;

pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    let addrs = ipv4_addresses();
    let mut list = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let read = |f: &str| std::fs::read_to_string(entry.path().join(f)).unwrap_or_default();
        // ARPHRD_ETHER only; skip loopback and our own TAP device.
        if read("type").trim() != "1" || name == "lo" || name.starts_with("eeth") {
            continue;
        }
        let mut detail = read("address").trim().to_uppercase();
        if tap::is_bridge(&name) {
            detail.push_str("  (bridge)");
        }
        if let Some(ips) = addrs.get(&name) {
            for ip in ips {
                detail.push_str(&format!("  {ip}"));
            }
        }
        list.push(AdapterInfo { id: name.clone(), name, detail });
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(list)
}

fn ipv4_addresses() -> HashMap<String, Vec<Ipv4Addr>> {
    let mut map: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list we walk read-only and free afterwards.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return map;
        }
        let mut p = ifap;
        while !p.is_null() {
            let ifa = &*p;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                map.entry(name).or_default().push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    map
}

fn is_permission(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
}

/// Random locally administered MAC for a TAP port we create.
fn random_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    let _ = getrandom::fill(&mut mac);
    mac[0] = 0x5E;
    mac
}

pub fn open_server(id: &str, log: &Logger) -> io::Result<Box<dyn L2Port>> {
    // A Linux bridge (docker0, br0, virbr0...) gets a TAP *port*: frames from the client then
    // enter the bridge like from any other port, so the host itself and every other port see
    // them and reply. Capturing the bridge device instead would make the host unreachable.
    if tap::is_bridge(id) {
        let mac = random_mac();
        let fd = match tap::open_bridge_port(id, mac) {
            Ok(fd) => fd,
            Err(e) if is_permission(&e) => helper::open_bridge_port(id, mac, log)?,
            Err(e) => return Err(e),
        };
        log.info(format!(
            "'{id}' is a bridge: attached TAP port '{}' to it (the host and all bridge ports are reachable).",
            tap::BRIDGE_PORT
        ));
        // With STP on, a new port spends forward_delay in listening/learning and forwards
        // nothing meanwhile (NetworkManager bridges default to 15 s; docker0/virbr0 have 0).
        let sys = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{id}/bridge/{f}")).unwrap_or_default();
        let delay_ticks: u64 = sys("forward_delay").trim().parse().unwrap_or(0);
        if sys("stp_state").trim() == "1" && delay_ticks > 0 {
            log.warn(format!(
                "Bridge '{id}' has STP enabled: the new port starts forwarding after about {} s (forward_delay).",
                delay_ticks / 100 * 2
            ));
        }
        return Ok(Box::new(tap::TapPort::bridge_port(fd, id)));
    }

    // Physical adapter: raw socket. Directly when we have the rights (root / setcap),
    // otherwise through the polkit helper.
    let opened = match packet::open_raw(id) {
        Ok(v) => v,
        Err(e) if is_permission(&e) => helper::open_packet(id, log)?,
        Err(e) => return Err(e),
    };
    for w in opened.warnings {
        log.warn(w);
    }
    Ok(Box::new(packet::PacketPort::from_fd(opened.fd, id, opened.restore, log)))
}

/// Puts GRO/LRO back the way they were, directly or through the helper.
pub(crate) fn restore_offload(ifname: &str, prev: packet::Offload) {
    if packet::offload_set(ifname, prev).is_err() {
        let _ = helper::restore_offload(ifname, prev);
    }
}

pub fn open_client(mac: [u8; 6], log: &Logger) -> io::Result<Box<dyn L2Port>> {
    let fd = match tap::open_tap(tap::IFNAME, mac) {
        Ok(fd) => fd,
        Err(e) if is_permission(&e) => helper::open_tap(mac, log)?,
        Err(e) => return Err(e),
    };
    log.info(format!("TAP adapter '{}' is up (MAC {}).", tap::IFNAME, format_mac(&mac)));
    Ok(Box::new(tap::TapPort::from_fd(fd)))
}

/// `ip addr <add|del> <cidr> dev eeth0`, with validated arguments (also run by the root helper).
pub(crate) fn ip_addr(action: &str, cidr: &str) -> io::Result<()> {
    let valid = cidr
        .split_once('/')
        .is_some_and(|(a, p)| a.parse::<Ipv4Addr>().is_ok() && p.parse::<u8>().is_ok_and(|p| p <= 32));
    if !valid || !matches!(action, "replace" | "del") {
        return Err(io::Error::other("invalid address"));
    }
    let out = system_tool("ip").args(["addr", action, cidr, "dev", tap::IFNAME]).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip addr {action} {cidr} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Applies an address change directly or, without the rights, through the helper.
fn ip_addr_privileged(action: &str, cidr: &str, log: &Logger) -> io::Result<()> {
    match ip_addr(action, cidr) {
        // `ip` reports EPERM/EACCES as text, so look for it there too.
        Err(e) if is_permission(&e) || e.to_string().contains("not permitted") => helper::ip_addr(action, cidr, log),
        r => r,
    }
}

struct StaticAddr(String, Logger);

impl Drop for StaticAddr {
    fn drop(&mut self) {
        // The TAP device disappears with its addresses when closed; this is just tidy-up.
        let _ = ip_addr_privileged("del", &self.0, &self.1);
    }
}

pub fn apply_static_ipv4(addr: Ipv4Addr, prefix: u8, log: &Logger) -> io::Result<Box<dyn Send>> {
    let cidr = format!("{addr}/{prefix}");
    ip_addr_privileged("replace", &cidr, log)?;
    log.info(format!("Static IPv4 {cidr} set on '{}'.", tap::IFNAME));
    Ok(Box::new(StaticAddr(cidr, log.clone())))
}

/// A system tool by absolute path (we run with root/capabilities; never trust PATH).
pub(crate) fn system_tool(name: &str) -> Command {
    let path = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|d| std::path::Path::new(d).join(name))
        .find(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin").join(name));
    Command::new(path)
}

// --- small libc helpers shared by both ports ---

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: fd was just returned by a successful syscall and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(cvt(fd)?) })
}

/// Waits until `fd` is readable. Returns false on timeout.
fn poll_readable(fd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r > 0 && pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("network device error (adapter removed?)"));
        }
        return Ok(r > 0);
    }
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::ENOBUFS))
}

fn permission_hint(e: io::Error) -> io::Error {
    if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
        io::Error::new(
            e.kind(),
            format!("{e}. Run EasyEther as root or grant it: sudo setcap cap_net_admin,cap_net_raw+ep <path to easyether>"),
        )
    } else {
        e
    }
}
