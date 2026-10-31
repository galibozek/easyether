//! Privilege separation on Linux. The GUI runs as a normal user; the few operations that
//! need root (opening a raw socket or TAP device, `ip addr`, offload settings) are done by a
//! helper process started with `pkexec` (polkit shows the system password dialog, like other
//! desktop apps). The helper hands the opened descriptors back over a Unix socket
//! (SCM_RIGHTS), so all frame forwarding happens unprivileged. It is started on first use and
//! kept for the rest of the session, so the password is asked once.
//!
//! Protocol (one line per request, replies `warn <text>`* then `ok [args]` or `err <text>`):
//!
//! ```text
//! hello
//! packet <ifname>              -> ok gro=<0|1|-> lro=<0|1|->   + socket fd
//! tap <mac 12 hex digits>      -> ok                           + tap fd
//! brtap <bridge> <mac>         -> ok                           + tap fd (port of the bridge)
//! ip <replace|del> <cidr>      -> ok
//! offload <ifname> <gro> <lro> -> ok
//! dhcp <start|stop>            -> ok                           (dhcpcd on the TAP adapter)
//! ```

use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use super::packet::{self, Offload, Opened};
use super::{dhcp, tap};
use crate::log::Logger;

pub const ARG: &str = "--privileged-helper";

struct Helper {
    sock: UnixStream,
    /// Bytes received but not yet consumed as a line.
    pending: Vec<u8>,
    child: Child,
}

static HELPER: Mutex<Option<Helper>> = Mutex::new(None);

fn pkexec() -> Option<&'static str> {
    ["/usr/bin/pkexec", "/bin/pkexec"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

fn spawn(log: &Logger) -> io::Result<Helper> {
    let Some(pkexec) = pkexec() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "opening network adapters needs administrator rights and pkexec (polkit) is not installed. \
             Either install polkit, or run: sudo setcap cap_net_admin,cap_net_raw+ep <path to easyether>",
        ));
    };
    let exe = std::env::current_exe()?;
    // Replaced on disk while running (an update, a rebuild): the kernel reports the old path
    // with " (deleted)", pkexec cannot find it and exits at once with the same code as a
    // refused password, without any dialog.
    if exe.to_string_lossy().ends_with(" (deleted)") {
        return Err(io::Error::other(
            "EasyEther's program file was replaced while it was running (an update?). Close EasyEther and start it again.",
        ));
    }
    let (ours, theirs) = UnixStream::pair()?;
    log.info("Asking for administrator rights (polkit) to open network adapters...");
    let child = Command::new(pkexec)
        .arg(&exe)
        .arg(ARG)
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut h = Helper {
        sock: ours,
        pending: Vec::new(),
        child,
    };
    // A first round trip confirms the helper is running (i.e. the password dialog succeeded).
    match h.request("hello", log) {
        Ok(_) => Ok(h),
        Err(e) => {
            // pkexec exits right after the dialog; give it a moment so the code is available.
            let status = super::wait_timeout(&mut h.child, std::time::Duration::from_secs(1))
                .ok()
                .flatten()
                .and_then(|s| s.code());
            Err(match status {
                Some(126) => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "administrator authorization was cancelled",
                ),
                Some(127) => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "administrator authorization was denied",
                ),
                _ => io::Error::new(e.kind(), format!("privileged helper failed to start: {e}")),
            })
        }
    }
}

struct Reply {
    args: String,
    fd: Option<OwnedFd>,
}

impl Helper {
    fn request(&mut self, line: &str, log: &Logger) -> io::Result<Reply> {
        self.sock.write_all(format!("{line}\n").as_bytes())?;
        let mut fd = None;
        loop {
            // Replies are lines; the descriptor rides along with the "ok" line.
            let (text, got_fd) = self.read_line()?;
            if got_fd.is_some() {
                fd = got_fd;
            }
            let Some(line) = text else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the privileged helper exited",
                ));
            };
            if let Some(w) = line.strip_prefix("warn ") {
                log.warn(w.to_string());
            } else if let Some(args) = line.strip_prefix("ok") {
                return Ok(Reply {
                    args: args.trim().to_string(),
                    fd,
                });
            } else if let Some(e) = line.strip_prefix("err ") {
                return Err(io::Error::other(e.to_string()));
            }
        }
    }

    /// Reads one line (`None` at EOF) and any descriptor that arrived with it.
    fn read_line(&mut self) -> io::Result<(Option<String>, Option<OwnedFd>)> {
        let mut fd = None;
        loop {
            if let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=pos).collect();
                return Ok((Some(String::from_utf8_lossy(&line).trim_end().to_string()), fd));
            }
            let mut buf = [0u8; 4096];
            let (n, got) = recv_with_fd(self.sock.as_raw_fd(), &mut buf)?;
            if got.is_some() {
                fd = got;
            }
            if n == 0 {
                return Ok((None, fd));
            }
            self.pending.extend_from_slice(&buf[..n]);
        }
    }
}

/// Runs `line` through the (started on demand) helper.
fn call(line: &str, log: &Logger) -> io::Result<Reply> {
    let mut guard = HELPER.lock().unwrap();
    if guard.is_none() {
        *guard = Some(spawn(log)?);
    }
    let result = guard.as_mut().unwrap().request(line, log);
    if matches!(&result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe) {
        // Helper gone (killed, crashed): forget it so the next call starts a new one.
        if let Some(mut h) = guard.take() {
            let _ = h.child.wait();
        }
    }
    result
}

/// 12 hex digits -> MAC.
fn parse_mac(hex: &str) -> Option<[u8; 6]> {
    if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..6)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    bytes.try_into().ok()
}

fn valid_ifname(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c))
}

pub fn open_packet(ifname: &str, log: &Logger) -> io::Result<Opened> {
    if !valid_ifname(ifname) {
        return Err(io::Error::other("invalid interface name"));
    }
    let reply = call(&format!("packet {ifname}"), log)?;
    let fd = reply.fd.ok_or_else(|| io::Error::other("helper sent no socket"))?;
    let flag = |key: &str| {
        reply
            .args
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix(key))
            .and_then(|v| match v {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            })
    };
    let restore = match (flag("gro="), flag("lro=")) {
        (Some(gro), Some(lro)) => Some(Offload { gro, lro }),
        _ => None,
    };
    Ok(Opened {
        fd,
        warnings: Vec::new(),
        restore,
    })
}

fn mac_hex(mac: [u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn open_tap(mac: [u8; 6], log: &Logger) -> io::Result<OwnedFd> {
    let reply = call(&format!("tap {}", mac_hex(mac)), log)?;
    reply
        .fd
        .ok_or_else(|| io::Error::other("helper sent no TAP descriptor"))
}

pub fn open_bridge_port(bridge: &str, mac: [u8; 6], log: &Logger) -> io::Result<OwnedFd> {
    if !valid_ifname(bridge) {
        return Err(io::Error::other("invalid bridge name"));
    }
    let reply = call(&format!("brtap {bridge} {}", mac_hex(mac)), log)?;
    reply
        .fd
        .ok_or_else(|| io::Error::other("helper sent no TAP descriptor"))
}

pub fn ip_addr(action: &str, cidr: &str, log: &Logger) -> io::Result<()> {
    call(&format!("ip {action} {cidr}"), log).map(|_| ())
}

pub fn dhcp_start(log: &Logger) -> io::Result<()> {
    call("dhcp start", log).map(|_| ())
}

/// Stops dhcpcd if the helper is still running; never starts a new helper for it.
pub fn dhcp_stop(log: &Logger) {
    let mut guard = HELPER.lock().unwrap();
    if let Some(h) = guard.as_mut() {
        let _ = h.request("dhcp stop", log);
    }
}

pub fn restore_offload(ifname: &str, prev: Offload) -> io::Result<()> {
    let log = Logger::new(None).0;
    call(&format!("offload {ifname} {} {}", prev.gro as u8, prev.lro as u8), &log).map(|_| ())
}

// ----------------------------------------------------------------------------- helper process

/// Entry point of `easyether --privileged-helper` (started by pkexec, as root). Serves
/// requests on the socket it got as stdin until the GUI closes it.
pub fn run() -> i32 {
    // SAFETY: fd 0 is the socketpair end the parent passed as stdin; we take ownership once.
    let sock = unsafe { UnixStream::from_raw_fd(0) };
    let Ok(mut reader) = sock.try_clone().map(BufReader::new) else {
        return 1;
    };
    let mut line = String::new();
    let mut dhcpcd: Option<Child> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                // The GUI is gone: do not leave dhcpcd behind.
                if let Some(child) = dhcpcd.take() {
                    dhcp::stop(child);
                }
                return 0;
            }
            Ok(_) => {}
        }
        let mut words = line.split_whitespace();
        let (reply, fd): (String, Option<OwnedFd>) = match (words.next(), words.next(), words.next(), words.next()) {
            (Some("hello"), ..) => ("ok".into(), None),
            (Some("packet"), Some(ifname), ..) if valid_ifname(ifname) => match packet::open_raw(ifname) {
                Ok(opened) => {
                    for w in &opened.warnings {
                        let _ = writeln!(&sock, "warn {w}");
                    }
                    let (gro, lro) = match opened.restore {
                        Some(o) => ((o.gro as u8).to_string(), (o.lro as u8).to_string()),
                        None => ("-".into(), "-".into()),
                    };
                    (format!("ok gro={gro} lro={lro}"), Some(opened.fd))
                }
                Err(e) => (format!("err {e}"), None),
            },
            (Some("tap"), Some(hex), ..) => match parse_mac(hex).map(|mac| tap::open_tap(tap::IFNAME, mac)) {
                Some(Ok(fd)) => ("ok".into(), Some(fd)),
                Some(Err(e)) => (format!("err {e}"), None),
                None => ("err invalid MAC".into(), None),
            },
            (Some("brtap"), Some(bridge), Some(hex), _) if valid_ifname(bridge) => {
                match parse_mac(hex).map(|mac| tap::open_bridge_port(bridge, mac)) {
                    Some(Ok(fd)) => ("ok".into(), Some(fd)),
                    Some(Err(e)) => (format!("err {e}"), None),
                    None => ("err invalid MAC".into(), None),
                }
            }
            (Some("ip"), Some(action), Some(cidr), _) => match super::ip_addr(action, cidr) {
                Ok(()) => ("ok".into(), None),
                Err(e) => (format!("err {e}"), None),
            },
            (Some("offload"), Some(ifname), Some(gro), Some(lro)) if valid_ifname(ifname) => {
                let prev = Offload {
                    gro: gro == "1",
                    lro: lro == "1",
                };
                match packet::offload_set(ifname, prev) {
                    Ok(()) => ("ok".into(), None),
                    Err(e) => (format!("err {e}"), None),
                }
            }
            (Some("dhcp"), Some(action @ ("start" | "stop")), ..) => {
                if let Some(child) = dhcpcd.take() {
                    dhcp::stop(child);
                }
                if action == "start" {
                    match dhcp::spawn() {
                        Ok(child) => {
                            dhcpcd = Some(child);
                            ("ok".into(), None)
                        }
                        Err(e) => (format!("err {e}"), None),
                    }
                } else {
                    ("ok".into(), None)
                }
            }
            _ => ("err unknown request".into(), None),
        };
        if send_with_fd(
            sock.as_raw_fd(),
            format!("{reply}\n").as_bytes(),
            fd.as_ref().map(|f| f.as_raw_fd()),
        )
        .is_err()
        {
            return 0;
        }
    }
}

// ----------------------------------------------------------------------------- SCM_RIGHTS

/// Sends `data`, attaching `fd` as an ancillary SCM_RIGHTS message when given.
fn send_with_fd(sock: RawFd, data: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut cmsg = [0u8; 32];
    // SAFETY: msghdr is plain old data; all-zero is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        // SAFETY: CMSG_SPACE only computes a size.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
        // SAFETY: msg_control points at `cmsg`, which is larger than CMSG_SPACE(4), so the
        // first header and its 4-byte payload are inside it.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
        }
    }
    // SAFETY: msg and every buffer it points to (iov, data, cmsg) stay alive for the call.
    let n = unsafe { libc::sendmsg(sock, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cmsg = [0u8; 64];
    // SAFETY: msghdr is plain old data; all-zero is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.len() as _;
    // SAFETY: msg and every buffer it points to (iov, buf, cmsg) stay alive for the call.
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd = None;
    // SAFETY: walking the control messages the kernel filled in.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let raw = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const RawFd);
                fd = Some(OwnedFd::from_raw_fd(raw));
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((n as usize, fd))
}
