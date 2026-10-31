//! Automatic IPv4 on the client's TAP adapter. NetworkManager and systemd-networkd leave a TAP
//! created by another program alone, so in "Automatic" mode we run dhcpcd on it ourselves:
//! IPv4 only, no routes other than the on-link subnet (the remote network must not take over
//! the host's traffic), no hook script (DNS, hostname, NTP stay untouched), falling back to
//! IPv4LL (169.254/16) when nobody answers, which is what many vehicles expect for DoIP.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::Duration;

use super::{system_tool, tap, wait_timeout};

/// Whether a system-wide dhcpcd (manager mode, `dhcpcd.service`) is running. `dhcpcd eeth0`
/// would then only hand the interface to it, and it would apply /etc/dhcpcd.conf (default
/// route, DNS hooks) instead of our restricted options. Our own per-interface instance uses
/// `<ifname>…` names, so these paths belong to the manager only.
pub(crate) fn system_instance_running() -> bool {
    [
        "/run/dhcpcd/pid",
        "/run/dhcpcd/sock",
        "/run/dhcpcd.pid",
        "/var/run/dhcpcd.pid",
        "/var/run/dhcpcd.sock",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists())
}

/// Starts dhcpcd in the foreground on the TAP adapter. Needs root.
pub(crate) fn spawn() -> io::Result<Child> {
    let mut cmd = system_tool("dhcpcd");
    if !std::path::Path::new(cmd.get_program()).exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "dhcpcd is not installed"));
    }
    cmd.args(["--nobackground", "--ipv4only", "--nogateway", "--quiet"])
        .args(["--config", "/dev/null", "--script", "/bin/true"]);
    // The local network must always win over the tunnel, so the host never cuts itself off:
    // 9000 loses to NetworkManager (50..800), networkd (1024) and the system dhcpcd
    // (1000+ifindex). dhcpcd's own default could beat networkd on a low ifindex.
    cmd.args(["--metric", "9000"]);
    // `--nogateway` only drops default routes. A DHCP server on the shared network could still
    // push static routes (options 121/33/249, cf. CVE-2024-3661 "TunnelVision") and so pull
    // the host's traffic into the tunnel, or change the adapter's MTU. Strip those options
    // before dhcpcd processes them; only the on-link subnet route remains.
    for opt in [
        "classless_static_routes",
        "static_routes",
        "ms_classless_static_routes",
        "routers",
        "interface_mtu",
    ] {
        cmd.args(["--nooption", opt]);
    }
    cmd.arg(tap::IFNAME)
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
    match wait_timeout(&mut child, Duration::from_millis(300))? {
        // Exit 0 right away means it forwarded the request to a manager we did not detect.
        Some(status) if status.success() => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "dhcpcd handed '{}' to an already running system-wide dhcpcd",
                tap::IFNAME
            ),
        )),
        Some(status) => Err(io::Error::other(format!("dhcpcd exited at start ({status})"))),
        None => Ok(child),
    }
}

/// Asks dhcpcd to exit (it then removes the address it set), killing it if it does not.
pub(crate) fn stop(mut child: Child) {
    // SAFETY: plain kill(2) on our own child's pid.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    if !matches!(wait_timeout(&mut child, Duration::from_secs(3)), Ok(Some(_))) {
        let _ = child.kill();
        let _ = child.wait();
    }
}
