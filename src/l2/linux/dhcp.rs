//! Automatic IPv4 on the client's TAP adapter. NetworkManager and systemd-networkd leave a TAP
//! created by another program alone, so in "Automatic" mode we run dhcpcd on it ourselves:
//! IPv4 only, no default route (the remote network must not take over the host's traffic),
//! no hook script (DNS, hostname, NTP stay untouched), falling back to IPv4LL (169.254/16)
//! when nobody answers – which is what many vehicles expect for DoIP.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use super::{system_tool, tap};

/// Starts dhcpcd in the foreground on the TAP adapter. Needs root.
pub(crate) fn spawn() -> io::Result<Child> {
    let mut cmd = system_tool("dhcpcd");
    if !std::path::Path::new(cmd.get_program()).exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "dhcpcd is not installed"));
    }
    cmd.args([
        "--nobackground",
        "--ipv4only",
        "--nogateway",
        "--quiet",
        "--config",
        "/dev/null",
        "--script",
        "/bin/true",
        tap::IFNAME,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // SAFETY: prctl is async-signal-safe; it makes dhcpcd exit if its parent dies unexpectedly.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    // Bad options or an unusable interface make it quit at once; report that as an error.
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait()? {
        return Err(io::Error::other(format!("dhcpcd exited at start ({status})")));
    }
    Ok(child)
}

/// Asks dhcpcd to exit (it then removes the address it set), killing it if it does not.
pub(crate) fn stop(mut child: Child) {
    // SAFETY: plain kill(2) on our own child's pid.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}
