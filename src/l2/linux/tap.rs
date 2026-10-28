//! TAP devices on Linux: the client's virtual adapter (`eeth0`), and on the server a port
//! added to a shared Linux bridge (`eeths0`), through which the host itself is reachable too.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use super::{cvt, owned, permission_hint, poll_readable, would_block};
use crate::l2::L2Port;
use crate::proto::{MAX_BATCH, MAX_FRAME, MIN_FRAME};

/// The client's virtual adapter.
pub const IFNAME: &str = "eeth0";
/// The server's port into a shared Linux bridge.
pub const BRIDGE_PORT: &str = "eeths0";

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const SIOCBRADDIF: libc::c_ulong = 0x89a2;
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;

/// `struct ifreq`: 16-byte name followed by a 24-byte union.
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> IfReq {
        let mut r = IfReq { name: [0; 16], data: [0; 24] };
        let n = name.len().min(15);
        r.name[..n].copy_from_slice(&name.as_bytes()[..n]);
        r
    }

    fn flags(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    fn set_flags(&mut self, f: i16) {
        self.data[..2].copy_from_slice(&f.to_ne_bytes());
    }
}

fn ioctl(fd: &OwnedFd, req: libc::c_ulong, ifr: &mut IfReq) -> io::Result<()> {
    // SAFETY: ifr is a properly sized struct ifreq for these requests.
    cvt(unsafe { libc::ioctl(fd.as_raw_fd(), req as _, ifr as *mut IfReq) }).map(|_| ())
}

pub struct TapPort {
    fd: OwnedFd,
    /// Interface whose carrier reflects this port's link (the bridge, for a bridge port).
    carrier_of: Option<String>,
}

fn config_socket() -> io::Result<OwnedFd> {
    // Interface configuration goes through an ordinary datagram socket.
    // SAFETY: plain socket(2) call.
    owned(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })
}

/// The privileged part (needs root / CAP_NET_ADMIN): creates TAP device `name`, sets its MAC
/// and brings it up. The returned descriptor can then be used by an unprivileged process; the
/// device disappears when it is closed.
pub fn open_tap(name: &str, mac: [u8; 6]) -> io::Result<OwnedFd> {
    // SAFETY: plain open(2) call with a static path.
    let fd = owned(unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) })
        .map_err(|e| io::Error::new(e.kind(), format!("/dev/net/tun: {}", permission_hint(e))))?;

    let mut ifr = IfReq::new(name);
    ifr.set_flags(IFF_TAP | IFF_NO_PI);
    ioctl(&fd, TUNSETIFF, &mut ifr).map_err(permission_hint)?;

    let sock = config_socket()?;
    let mut ifr = IfReq::new(name);
    ifr.data[..2].copy_from_slice(&(libc::ARPHRD_ETHER).to_ne_bytes());
    ifr.data[2..8].copy_from_slice(&mac);
    ioctl(&sock, libc::SIOCSIFHWADDR as _, &mut ifr).map_err(permission_hint)?;

    let mut ifr = IfReq::new(name);
    ioctl(&sock, libc::SIOCGIFFLAGS as _, &mut ifr)?;
    ifr.set_flags(ifr.flags() | libc::IFF_UP as i16);
    ioctl(&sock, libc::SIOCSIFFLAGS as _, &mut ifr).map_err(permission_hint)?;
    Ok(fd)
}

/// Creates TAP `BRIDGE_PORT` and adds it as a port of the Linux bridge `bridge` (privileged).
/// Frames written to it enter the bridge like from any other port, so the host and every other
/// port see them, and the bridge forwards replies back to it. The port vanishes with the fd.
pub fn open_bridge_port(bridge: &str, mac: [u8; 6]) -> io::Result<OwnedFd> {
    let fd = open_tap(BRIDGE_PORT, mac)?;
    let cname = CString::new(BRIDGE_PORT).expect("static name");
    // SAFETY: cname is a valid C string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::other("the TAP port disappeared right after creation"));
    }
    let sock = config_socket()?;
    let mut ifr = IfReq::new(bridge);
    ifr.data[..4].copy_from_slice(&(index as i32).to_ne_bytes());
    ioctl(&sock, SIOCBRADDIF, &mut ifr).map_err(|e| {
        io::Error::new(e.kind(), format!("cannot add {BRIDGE_PORT} to bridge '{bridge}': {}", permission_hint(e)))
    })?;
    Ok(fd)
}

/// True when `ifname` is a Linux bridge (docker0, br0, virbr0, ...).
pub fn is_bridge(ifname: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{ifname}/bridge")).exists()
}

impl TapPort {
    pub fn from_fd(fd: OwnedFd) -> TapPort {
        TapPort { fd, carrier_of: None }
    }

    /// A bridge port: report the bridge's carrier as this port's link state.
    pub fn bridge_port(fd: OwnedFd, bridge: &str) -> TapPort {
        TapPort { fd, carrier_of: Some(bridge.to_string()) }
    }
}

impl L2Port for TapPort {
    fn link_up(&self) -> Option<bool> {
        let name = self.carrier_of.as_ref()?;
        let carrier = std::fs::read_to_string(format!("/sys/class/net/{name}/carrier")).ok()?;
        Some(carrier.trim() == "1")
    }

    fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
        if !poll_readable(&self.fd, timeout)? {
            return Ok(());
        }
        let mut buf = [0u8; MAX_FRAME + 64];
        for _ in 0..MAX_BATCH {
            // SAFETY: buf is valid for buf.len() bytes.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if would_block(&e) || e.kind() == io::ErrorKind::Interrupted {
                    break;
                }
                return Err(e);
            }
            let n = n as usize;
            if (MIN_FRAME..=MAX_FRAME).contains(&n) {
                out.push(buf[..n].to_vec());
            }
        }
        Ok(())
    }

    fn send(&self, frames: &[Vec<u8>]) -> io::Result<()> {
        for f in frames {
            // SAFETY: f is valid for f.len() bytes.
            let r = unsafe { libc::write(self.fd.as_raw_fd(), f.as_ptr() as *const libc::c_void, f.len()) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if would_block(&e) || e.raw_os_error() == Some(libc::EIO) {
                    // EIO: interface is down; drop the frame like an unplugged NIC.
                    continue;
                }
                return Err(e);
            }
        }
        Ok(())
    }
}
