//! Server side on Linux: a physical interface opened with an AF_PACKET raw socket.

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use super::{owned, permission_hint, poll_readable, would_block};
use crate::l2::{L2Port, insert_vlan_tag};
use crate::log::Logger;
use crate::proto::{MAX_BATCH, MAX_FRAME, MIN_FRAME};

const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
/// Smallest Ethernet frame (without FCS). A NIC pads shorter frames in hardware, but a raw
/// socket rejects anything shorter than the device's `hard_header_len` with EINVAL, and USB
/// drivers raise that above 14 by their TX header (rndis_host 58, lan78xx/smsc95xx 22,
/// asix 18). A 42-byte ARP request from the peer would never get out otherwise.
const MIN_ETH_FRAME: usize = 60;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

#[repr(C)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

pub struct PacketPort {
    fd: OwnedFd,
    ifname: String,
    log: Logger,
    /// Offload settings to put back when the port closes.
    restore: Option<Offload>,
    warned_oversized: std::sync::atomic::AtomicBool,
    warned_rejected: std::sync::atomic::AtomicBool,
}

impl Drop for PacketPort {
    fn drop(&mut self) {
        if let Some(prev) = self.restore {
            super::restore_offload(&self.ifname, prev);
        }
    }
}

// --- GRO/LRO via the ethtool ioctl (what `ethtool -K` does) ---

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GFLAGS: u32 = 0x25;
const ETHTOOL_SFLAGS: u32 = 0x26;
const ETHTOOL_GGRO: u32 = 0x2b;
const ETHTOOL_SGRO: u32 = 0x2c;
const ETH_FLAG_LRO: u32 = 1 << 15;

/// Receive-offload state of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offload {
    pub gro: bool,
    pub lro: bool,
}

/// `struct ifreq` with `ifr_data` pointing at an `ethtool_value { cmd, data }`.
#[repr(C)]
struct EthtoolReq {
    name: [u8; 16],
    data: *mut EthtoolValue,
    _pad: [u8; 16],
}

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

fn ethtool(ifname: &str, cmd: u32, data: u32) -> io::Result<u32> {
    if ifname.len() >= 16 {
        return Err(io::Error::other("interface name too long"));
    }
    let mut value = EthtoolValue { cmd, data };
    let mut req = EthtoolReq {
        name: [0; 16],
        data: &mut value,
        _pad: [0; 16],
    };
    req.name[..ifname.len()].copy_from_slice(ifname.as_bytes());
    // SAFETY: plain socket(2) call.
    let sock = owned(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
    // SAFETY: req and value are valid for the duration of the ioctl.
    super::cvt(unsafe { libc::ioctl(sock.as_raw_fd(), SIOCETHTOOL as _, &mut req as *mut EthtoolReq) })?;
    Ok(value.data)
}

pub fn offload_get(ifname: &str) -> io::Result<Offload> {
    Ok(Offload {
        gro: ethtool(ifname, ETHTOOL_GGRO, 0)? != 0,
        lro: ethtool(ifname, ETHTOOL_GFLAGS, 0)
            .map(|f| f & ETH_FLAG_LRO != 0)
            .unwrap_or(false),
    })
}

pub fn offload_set(ifname: &str, o: Offload) -> io::Result<()> {
    ethtool(ifname, ETHTOOL_SGRO, o.gro as u32)?;
    // LRO is rare; ignore interfaces that do not support the flag.
    if let Ok(flags) = ethtool(ifname, ETHTOOL_GFLAGS, 0) {
        let new = if o.lro {
            flags | ETH_FLAG_LRO
        } else {
            flags & !ETH_FLAG_LRO
        };
        if new != flags {
            let _ = ethtool(ifname, ETHTOOL_SFLAGS, new);
        }
    }
    Ok(())
}

fn setsockopt<T>(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: value points to a live T of the given size.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            value as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    };
    super::cvt(r).map(|_| ())
}

/// Result of the privileged open: the bound socket, warnings for the log and the offload
/// state to restore when done.
pub struct Opened {
    pub fd: OwnedFd,
    pub warnings: Vec<String>,
    pub restore: Option<Offload>,
}

/// The privileged part of opening an adapter (needs root / CAP_NET_RAW): creates and binds the
/// raw socket and disables GRO/LRO. The socket can then be used by an unprivileged process.
pub fn open_raw(ifname: &str) -> io::Result<Opened> {
    let mut warnings = Vec::new();
    let cname = CString::new(ifname).map_err(|_| io::Error::other("invalid interface name"))?;
    // SAFETY: cname is a valid C string.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{ifname}' not found"),
        ));
    }
    let proto_be = (libc::ETH_P_ALL as u16).to_be();
    // SAFETY: plain socket(2) call.
    let fd = owned(unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto_be as i32) })
        .map_err(permission_hint)?;

    // SAFETY: sockaddr_ll is plain old data; zero is a valid initial state.
    let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto_be;
    sll.sll_ifindex = ifindex as i32;
    // SAFETY: sll is a valid sockaddr_ll and its size is passed along.
    super::cvt(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    })?;

    // Promiscuous membership is dropped by the kernel automatically when the socket closes.
    // SAFETY: packet_mreq is plain old data.
    let mut mreq: libc::packet_mreq = unsafe { zeroed() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
    setsockopt(&fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &mreq)?;
    setsockopt(&fd, libc::SOL_PACKET, libc::PACKET_AUXDATA, &1 as &libc::c_int)?;
    if setsockopt(&fd, libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, &1 as &libc::c_int).is_err() {
        warnings.push("Kernel lacks PACKET_IGNORE_OUTGOING; filtering outgoing frames in user space.".into());
    }

    // GRO/LRO merge received packets into frames far larger than the MTU, which cannot be
    // forwarded as Ethernet frames. Same approach as SoftEther's bridge; restored on close.
    let restore = match offload_get(ifname) {
        Ok(prev) if prev.gro || prev.lro => match offload_set(ifname, Offload { gro: false, lro: false }) {
            Ok(()) => Some(prev),
            Err(e) => {
                warnings.push(format!(
                    "Could not disable GRO/LRO on '{ifname}' ({e}). Oversized frames will be dropped."
                ));
                None
            }
        },
        _ => None,
    };
    Ok(Opened { fd, warnings, restore })
}

impl PacketPort {
    /// Wraps an already opened and bound raw socket (see `open_raw`).
    pub fn from_fd(fd: OwnedFd, ifname: &str, restore: Option<Offload>, log: &Logger) -> PacketPort {
        let port = PacketPort {
            fd,
            ifname: ifname.to_string(),
            log: log.clone(),
            restore,
            warned_oversized: std::sync::atomic::AtomicBool::new(false),
            warned_rejected: std::sync::atomic::AtomicBool::new(false),
        };
        port.drain();
        log.info(format!("Raw socket opened on '{ifname}' (promiscuous mode)."));
        port
    }

    /// Receives one frame without blocking. `Ok(None)` when the queue is empty.
    fn recv_one(&self, buf: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg = [0u64; 16];
        // SAFETY: zeroed sockaddr_ll / msghdr are valid; all pointers stay alive for the call.
        let mut from: libc::sockaddr_ll = unsafe { zeroed() };
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = &mut from as *mut libc::sockaddr_ll as *mut libc::c_void;
        msg.msg_namelen = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = size_of::<[u64; 16]>() as _;
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            // ENETDOWN is reported once when the link goes down; the link monitor logs that.
            let transient =
                would_block(&e) || e.kind() == io::ErrorKind::Interrupted || e.raw_os_error() == Some(libc::ENETDOWN);
            return if transient { Ok(None) } else { Err(e) };
        }
        let n = n as usize;
        // Skip frames sent by this host (incl. our own injected ones) and oversized frames.
        if from.sll_pkttype == libc::PACKET_OUTGOING || n < MIN_FRAME {
            return Ok(Some(Vec::new()));
        }
        if n > buf.len() {
            if !self.warned_oversized.swap(true, std::sync::atomic::Ordering::Relaxed) {
                self.log.warn(format!(
                    "Dropping frames larger than {MAX_FRAME} bytes on '{}' ({n} bytes seen): jumbo frames or receive offload (GRO/LRO) are not supported.",
                    self.ifname
                ));
            }
            return Ok(Some(Vec::new()));
        }
        // A VLAN tag the NIC stripped into out-of-band data, if any: (tpid, tci).
        let mut vlan: Option<(u16, u16)> = None;
        // SAFETY: walking the control messages the kernel filled into `cmsg`.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_PACKET && (*c).cmsg_type == libc::PACKET_AUXDATA {
                    let aux = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const TpacketAuxdata);
                    if aux.tp_vlan_tci != 0 || aux.tp_status & TP_STATUS_VLAN_VALID != 0 {
                        let tpid = if aux.tp_status & TP_STATUS_VLAN_TPID_VALID != 0 {
                            aux.tp_vlan_tpid
                        } else {
                            0x8100
                        };
                        vlan = Some((tpid, aux.tp_vlan_tci));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        match vlan {
            // Re-inserting the 4-byte tag must not exceed the frame limit.
            Some(_) if n + 4 > MAX_FRAME => Ok(Some(Vec::new())),
            Some((tpid, tci)) => Ok(Some(insert_vlan_tag(&buf[..n], tpid, tci))),
            None => Ok(Some(buf[..n].to_vec())),
        }
    }
}

impl L2Port for PacketPort {
    fn link_up(&self) -> Option<bool> {
        let carrier = std::fs::read_to_string(format!("/sys/class/net/{}/carrier", self.ifname)).ok()?;
        Some(carrier.trim() == "1")
    }

    fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
        if !poll_readable(&self.fd, timeout)? {
            return Ok(());
        }
        let mut buf = [0u8; MAX_FRAME];
        let start = out.len();
        // Count attempts too, so a stream of skipped frames cannot spin forever.
        for _ in 0..MAX_BATCH * 2 {
            if out.len() - start >= MAX_BATCH {
                break;
            }
            match self.recv_one(&mut buf)? {
                None => break,
                Some(f) if f.is_empty() => continue,
                Some(f) => out.push(f),
            }
        }
        Ok(())
    }

    fn send(&self, frames: &[Vec<u8>]) -> io::Result<()> {
        let mut padded = [0u8; MIN_ETH_FRAME];
        for f in frames {
            let (ptr, len) = if f.len() < MIN_ETH_FRAME {
                padded[..f.len()].copy_from_slice(f);
                padded[f.len()..].fill(0);
                (padded.as_ptr(), MIN_ETH_FRAME)
            } else {
                (f.as_ptr(), f.len())
            };
            // SAFETY: ptr points to a valid buffer of len bytes.
            let r = unsafe { libc::send(self.fd.as_raw_fd(), ptr as *const libc::c_void, len, 0) };
            if r < 0 {
                let e = io::Error::last_os_error();
                // Full queue or a frame larger than the interface MTU: drop it, like a switch would.
                if would_block(&e) || matches!(e.raw_os_error(), Some(libc::EMSGSIZE) | Some(libc::ENETDOWN)) {
                    continue;
                }
                // The driver refused this frame (see MIN_ETH_FRAME); the adapter itself is fine.
                if e.raw_os_error() == Some(libc::EINVAL) {
                    if !self.warned_rejected.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        self.log.warn(format!(
                            "The driver of '{}' rejected a {len}-byte frame (EINVAL); such frames are dropped.",
                            self.ifname
                        ));
                    }
                    continue;
                }
                return Err(e);
            }
        }
        Ok(())
    }
}
