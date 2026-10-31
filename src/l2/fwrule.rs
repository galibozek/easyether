//! Windows Firewall rules as the firewall service stores them in the registry, one string per
//! rule: `v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5555|App=C:\x.exe|Name=x|`.
//! The format is not formally documented but has been stable since Windows 7 and, unlike
//! `netsh` output, does not depend on the system language. Used only to check that clients
//! will get through, never to create rules. Platform independent so it can be tested anywhere.

/// TCP in the rule's `Protocol` field.
const TCP: &str = "6";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Allow,
    Block,
    Other,
}

#[derive(Debug)]
pub struct Rule {
    fields: Vec<(String, String)>,
}

impl Rule {
    /// Parses one rule string; `None` if it is not in the `v2.x|key=value|...` form.
    pub fn parse(s: &str) -> Option<Rule> {
        let mut parts = s.split('|');
        if !parts.next()?.starts_with("v2.") {
            return None;
        }
        let fields = parts
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Some(Rule { fields })
    }

    fn get(&self, key: &'static str) -> Option<&str> {
        self.all(key).next()
    }

    fn all<'a>(&'a self, key: &'static str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// The rule's display name; may be an indirect `@resource` string.
    pub fn name(&self) -> &str {
        self.get("Name").unwrap_or("")
    }

    fn action(&self) -> Action {
        match self.get("Action") {
            Some(a) if a.eq_ignore_ascii_case("Allow") => Action::Allow,
            Some(a) if a.eq_ignore_ascii_case("Block") => Action::Block,
            _ => Action::Other,
        }
    }

    fn is_active(&self) -> bool {
        self.get("Active").is_some_and(|a| a.eq_ignore_ascii_case("TRUE"))
    }

    fn is_inbound(&self) -> bool {
        self.get("Dir").is_some_and(|d| d.eq_ignore_ascii_case("In"))
    }

    /// No protocol means every protocol.
    fn covers_tcp(&self) -> bool {
        self.get("Protocol").is_none_or(|p| p == TCP)
    }

    /// No local port means every port. The ports are in `LPort` and, in newer rules, in
    /// `LPort2_10` / `LPort2_20`; values are numbers, ranges `a-b` or keywords (RPC...), which
    /// never match an ordinary port.
    fn covers_port(&self, port: u16) -> bool {
        let mut ports = self
            .fields
            .iter()
            .filter(|(k, _)| k.len() >= 5 && k[..5].eq_ignore_ascii_case("LPort"))
            .map(|(_, v)| v.as_str())
            .peekable();
        if ports.peek().is_none() {
            return true;
        }
        ports
            .flat_map(|v| v.split(','))
            .any(|v| match v.trim().split_once('-') {
                Some((a, b)) => {
                    matches!((a.parse::<u16>(), b.parse::<u16>()), (Ok(a), Ok(b)) if (a..=b).contains(&port))
                }
                None => v.trim().parse::<u16>() == Ok(port),
            })
    }

    /// The program the rule is limited to, if any (environment variables not expanded).
    pub fn app(&self) -> Option<&str> {
        self.get("App")
    }

    /// No program means every program. `env` looks up environment variables (`%ProgramFiles%`).
    /// A rule limited to a service or to a Store app package never applies to a desktop program.
    fn covers_app(&self, exe: &str, env: impl Fn(&str) -> Option<String>) -> bool {
        let other_kind = ["Svc", "AppPkgId", "PFN"].iter().any(|k| self.get(k).is_some());
        !other_kind && self.app().is_none_or(|app| same_path(&expand_env(app, env), exe))
    }

    /// Profiles the rule applies to; empty means all of them.
    pub fn profiles(&self) -> Vec<&str> {
        self.all("Profile").collect()
    }

    /// Whether this rule lets TCP `port` in for program `exe`.
    pub fn allows(&self, port: u16, exe: &str, env: impl Fn(&str) -> Option<String>) -> bool {
        self.action() == Action::Allow && self.lets_in(port, exe, env)
    }

    /// Whether this rule stops TCP `port` for program `exe` (block rules win over allow rules).
    pub fn blocks(&self, port: u16, exe: &str, env: impl Fn(&str) -> Option<String>) -> bool {
        self.action() == Action::Block && self.lets_in(port, exe, env)
    }

    /// Limited to some remote addresses or interfaces: whether that covers a client cannot be
    /// told here, and such rules ("block this host") are not about us.
    fn is_scoped(&self) -> bool {
        ["RA4", "RA6", "RA42", "RA62", "IF", "IFType"]
            .iter()
            .any(|k| self.get(k).is_some())
    }

    fn lets_in(&self, port: u16, exe: &str, env: impl Fn(&str) -> Option<String>) -> bool {
        self.is_active()
            && self.is_inbound()
            && !self.is_scoped()
            && self.covers_tcp()
            && self.covers_port(port)
            && self.covers_app(exe, env)
    }
}

/// Replaces `%NAME%` with the variable's value (unknown ones are left as they are).
fn expand_env(s: &str, env: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else { break };
        let name = &rest[start + 1..start + 1 + len];
        out.push_str(&rest[..start]);
        match env(name) {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    out.push_str(rest);
    out
}

/// Windows paths compare case-insensitively, with either slash and with or without `\\?\`.
fn same_path(a: &str, b: &str) -> bool {
    let norm = |p: &str| p.trim_start_matches(r"\\?\").replace('/', r"\").to_lowercase();
    norm(a) == norm(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\Tools\EasyEther\easyether.exe";

    fn env(name: &str) -> Option<String> {
        (name.eq_ignore_ascii_case("SystemDrive")).then(|| "C:".to_string())
    }

    #[test]
    fn our_allow_rule_is_recognised() {
        let r = Rule::parse(
            r"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5555|App=C:\Tools\EasyEther\easyether.exe|Name=EasyEther|",
        )
        .unwrap();
        assert_eq!(r.name(), "EasyEther");
        assert!(r.allows(5555, EXE, env));
        assert!(!r.allows(5556, EXE, env));
        assert!(!r.allows(5555, r"C:\Other\easyether.exe", env));
        assert!(!r.blocks(5555, EXE, env));
    }

    #[test]
    fn block_rule_left_by_a_cancelled_prompt_matches() {
        // What Windows writes when "Cancel" is clicked in its firewall prompt: every port,
        // TCP (and a twin for UDP), path in another case and with an environment variable.
        let r = Rule::parse(
            r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=%SystemDrive%\TOOLS\EasyEther\easyether.exe|Name=easyether.exe|Desc=easyether.exe|Defer=User|",
        )
        .unwrap();
        assert!(r.blocks(5555, EXE, env));
        assert_eq!(r.profiles(), ["Public"]);
        let udp = Rule::parse(r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|App=C:\Tools\EasyEther\easyether.exe|Name=easyether.exe|").unwrap();
        assert!(!udp.blocks(5555, EXE, env));
    }

    #[test]
    fn port_rules_and_inactive_or_outbound_rules() {
        let any_app_range =
            Rule::parse("v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=5000-6000|Name=Range|").unwrap();
        assert!(any_app_range.blocks(5555, EXE, env));
        let list = Rule::parse("v2.30|Action=Block|Active=TRUE|Dir=In|LPort=80|LPort=443,5555|Name=List|").unwrap();
        assert!(list.blocks(5555, EXE, env));
        let keyword = Rule::parse("v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|Name=Rpc|").unwrap();
        assert!(!keyword.blocks(5555, EXE, env));
        // Newer rules keep keywords and ranges in LPort2_10: still a port limit, not "any port".
        let keyword2 = Rule::parse("v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=RPC|Name=Rpc|").unwrap();
        assert!(!keyword2.blocks(5555, EXE, env));
        let range2 = Rule::parse("v2.10|Action=Block|Active=TRUE|Dir=In|LPort2_10=5000-6000|Name=R|").unwrap();
        assert!(range2.blocks(5555, EXE, env));
        // Limited to a remote host or an interface: not about our clients.
        let host = Rule::parse("v2.31|Action=Block|Active=TRUE|Dir=In|RA4=203.0.113.7|Name=Bad host|").unwrap();
        assert!(!host.blocks(5555, EXE, env));
        let iface = Rule::parse("v2.31|Action=Block|Active=TRUE|Dir=In|IFType=Wireless|Name=Wifi|").unwrap();
        assert!(!iface.blocks(5555, EXE, env));
        let off = Rule::parse("v2.30|Action=Block|Active=FALSE|Dir=In|Protocol=6|Name=Off|").unwrap();
        assert!(!off.blocks(5555, EXE, env));
        let out = Rule::parse("v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Name=Out|").unwrap();
        assert!(!out.blocks(5555, EXE, env));
    }

    #[test]
    fn service_and_store_app_rules_do_not_apply_to_us() {
        for limit in ["Svc=Dnscache", "AppPkgId=S-1-15-2-1", "PFN=Microsoft.App_8wekyb3d8bbwe"] {
            let r = Rule::parse(&format!("v2.31|Action=Block|Active=TRUE|Dir=In|{limit}|Name=x|")).unwrap();
            assert!(!r.blocks(5555, EXE, env), "{limit}");
        }
    }

    #[test]
    fn junk_is_not_a_rule() {
        assert!(Rule::parse("").is_none());
        assert!(Rule::parse("Action=Block|Dir=In").is_none());
    }

    #[test]
    fn environment_expansion() {
        assert_eq!(expand_env(r"%SystemDrive%\x\%Unknown%\y", env), r"C:\x\%Unknown%\y");
        assert_eq!(expand_env("100%", env), "100%");
    }
}
