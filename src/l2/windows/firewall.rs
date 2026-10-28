//! Windows Firewall: without an inbound rule the sharing computer silently drops client
//! connections. We run as administrator, so we add a rule for our own executable.

use std::io;

use super::install::run;
use crate::log::Logger;

const RULE: &str = "EasyEther";

/// Makes sure an inbound TCP rule for this executable and `port` exists (replacing an older one).
pub fn allow_inbound(port: u16, log: &Logger) {
    let result = (|| -> io::Result<()> {
        let exe = std::env::current_exe()?;
        let program = format!("program={}", exe.display());
        let _ = run(
            "netsh.exe",
            &["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}")],
        );
        run(
            "netsh.exe",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={RULE}"),
                "dir=in",
                "action=allow",
                "enable=yes",
                "profile=any",
                "protocol=TCP",
                &format!("localport={port}"),
                &program,
            ],
        )
    })();
    match result {
        Ok(()) => log.info(format!(
            "Windows Firewall: inbound rule '{RULE}' allows TCP port {port}."
        )),
        Err(e) => log.warn(format!(
            "Could not add a Windows Firewall rule ({e}); clients may be unable to connect."
        )),
    }
}
