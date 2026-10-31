//! Windows Firewall: without an inbound rule the sharing computer silently drops client
//! connections. We run as administrator, so we add a rule for our own executable, then check
//! the firewall's configuration for the cases where that rule exists but does not help: a block
//! rule (block wins over allow), a profile set to block all incoming connections, or group
//! policy ignoring local rules. The block rule Windows leaves behind when "Cancel" was clicked
//! in its firewall prompt for our program is removed; other block rules are only reported.

use std::io;
use std::path::Path;

use windows_registry::{Key, LOCAL_MACHINE};

use super::install::run;
use crate::l2::fwrule::Rule;
use crate::log::Logger;

const RULE: &str = "EasyEther";

const LOCAL_POLICY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
const GROUP_POLICY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";

/// The three firewall profiles: shown name, local key, group policy key.
const PROFILES: [(&str, &str, &str); 3] = [
    ("Domain", "DomainProfile", "DomainProfile"),
    ("Private", "StandardProfile", "PrivateProfile"),
    ("Public", "PublicProfile", "PublicProfile"),
];

/// Makes sure an inbound TCP rule for this executable and `port` exists (replacing an older one)
/// and logs whether clients can actually get through.
pub fn allow_inbound(port: u16, log: &Logger) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log.warn(format!(
                "Could not add a Windows Firewall rule ({e}); clients may be unable to connect."
            ));
            return;
        }
    };
    if let Err(e) = add_rule(port, &exe) {
        log.warn(format!(
            "Could not add a Windows Firewall rule ({e}); clients may be unable to connect. \
             If another firewall product is installed, allow TCP port {port} there."
        ));
        return;
    }
    check(port, &exe, log);
}

fn add_rule(port: u16, exe: &Path) -> io::Result<()> {
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
}

/// One firewall profile's effective settings (group policy wins over local settings).
struct Profile {
    name: &'static str,
    enabled: bool,
    /// "Block all incoming connections, including those in the list of allowed apps".
    blocks_all: bool,
    /// Group policy applies only its own rules, so ours is ignored.
    ignores_local_rules: bool,
}

fn profiles() -> Vec<Profile> {
    PROFILES
        .iter()
        .map(|&(name, local, policy)| {
            let local = LOCAL_MACHINE.open(format!(r"{LOCAL_POLICY}\{local}")).ok();
            let policy = LOCAL_MACHINE.open(format!(r"{GROUP_POLICY}\{policy}")).ok();
            let get = |value: &str| {
                let read = |k: &Option<Key>| k.as_ref().and_then(|k| k.get_u32(value).ok());
                read(&policy).or_else(|| read(&local))
            };
            Profile {
                name,
                enabled: get("EnableFirewall").is_none_or(|v| v != 0),
                blocks_all: get("DoNotAllowExceptions") == Some(1),
                ignores_local_rules: policy.as_ref().and_then(|k| k.get_u32("AllowLocalPolicyMerge").ok()) == Some(0),
            }
        })
        .collect()
}

/// The rules in one store, parsed (unparseable entries are skipped).
fn rules(base: &str) -> Vec<Rule> {
    let Ok(key) = LOCAL_MACHINE.open(format!(r"{base}\FirewallRules")) else {
        return Vec::new();
    };
    let Ok(values) = key.values() else { return Vec::new() };
    values
        .filter_map(|(_, v)| String::try_from(v).ok())
        .filter_map(|s| Rule::parse(&s))
        .collect()
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn check(port: u16, exe: &Path, log: &Logger) {
    let exe_str = exe.display().to_string();
    let profiles = profiles();
    if profiles.iter().all(|p| !p.enabled) {
        log.info("Windows Firewall is off; no rule is needed for clients to connect.");
        return;
    }
    let mut problems = 0;

    let local = rules(LOCAL_POLICY);
    if !local.iter().any(|r| r.name() == RULE && r.allows(port, &exe_str, env)) {
        problems += 1;
        log.warn(format!(
            "Windows Firewall: the rule '{RULE}' was added but is not in the firewall configuration; clients may be unable to connect."
        ));
    }

    // Block rules win over allow rules. The ones a cancelled firewall prompt leaves for exactly
    // this program are removed: the prompt names them after the file ("easyether.exe", the
    // program has no version resource). Anything else, a rule someone made on purpose
    // included, is only reported. So is a prompt rule with an "Allow" twin of the same name
    // (allowed on one profile, cancelled on another): netsh deletes by name, not by action,
    // and would take the allow rules with it.
    let file_name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for r in local.iter().filter(|r| r.blocks(port, &exe_str, env)) {
        let from_prompt = r.app().is_some() && !file_name.is_empty() && r.name().eq_ignore_ascii_case(&file_name);
        let allow_twin = local
            .iter()
            .any(|a| a.name().eq_ignore_ascii_case(r.name()) && a.allows(port, &exe_str, env));
        if from_prompt && !allow_twin && remove_block_rule(r.name(), exe).is_ok() {
            log.info(format!(
                "Windows Firewall: removed inbound rule '{}' that blocked EasyEther (usually left by a cancelled firewall prompt).",
                r.name()
            ));
            continue;
        }
        problems += 1;
        log.warn(format!(
            "Windows Firewall: inbound rule '{}' blocks TCP port {port} for EasyEther{}; block rules win over allow rules. Disable or remove it in Windows Defender Firewall.",
            r.name(),
            profile_note(r)
        ));
    }
    for r in rules(GROUP_POLICY).iter().filter(|r| r.blocks(port, &exe_str, env)) {
        problems += 1;
        log.warn(format!(
            "Windows Firewall: group policy rule '{}' blocks TCP port {port}{}; ask your administrator to allow it.",
            r.name(),
            profile_note(r)
        ));
    }

    for p in profiles.iter().filter(|p| p.enabled) {
        if p.blocks_all {
            problems += 1;
            log.warn(format!(
                "Windows Firewall: the {} profile blocks all incoming connections, allowed apps included. If this computer's network is {}, clients cannot connect: turn that option off (Windows Security > Firewall & network protection > {} network).",
                p.name,
                p.name.to_lowercase(),
                p.name
            ));
        }
        if p.ignores_local_rules {
            problems += 1;
            log.warn(format!(
                "Windows Firewall: group policy ignores local rules in the {} profile, so EasyEther's rule has no effect there; ask your administrator to allow TCP port {port}.",
                p.name
            ));
        }
    }

    if problems == 0 {
        log.info(format!(
            "Windows Firewall: inbound TCP port {port} is allowed for EasyEther. If another firewall product is installed, allow it there too."
        ));
    }
}

/// " (Public profile)" when the rule is limited to some profiles.
fn profile_note(r: &Rule) -> String {
    match r.profiles().as_slice() {
        [] => String::new(),
        p => format!(" ({} profile)", p.join(", ")),
    }
}

/// Deletes the inbound rules with this name for exactly our program.
fn remove_block_rule(name: &str, exe: &Path) -> io::Result<()> {
    run(
        "netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
            "dir=in",
            &format!("program={}", exe.display()),
        ],
    )
}
