//! Server and client workers. Each runs on its own thread and reports through a `Logger`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::l2::{self, L2Port, ResilientPort};
use crate::log::Logger;
use crate::proto::{self, BatchDecoder, MAX_BATCH};
use crate::secure::{self, SecureStream, ServerHandshake, ServerIdentity};

const POLL: Duration = Duration::from_millis(50);

/// No data (not even a keepalive) for this long ends the session. Short stalls (Wi-Fi roaming,
/// retransmissions) below this ride on the same session; anything longer is detected within
/// this time and the client reconnects. A compromise between surviving stalls (longer) and
/// recovering fast when the connection is really dead, e.g. the client's IP changed (shorter).
const LINK_TIMEOUT: Duration = Duration::from_secs(15);
/// Keepalive interval, well below `LINK_TIMEOUT`.
const KEEPALIVE: Duration = Duration::from_secs(2);
/// A session whose peer has been silent this long may be replaced by a newly authenticated
/// client. Equal to the dead-link timeout on purpose: a session that still *could* be alive is
/// never taken away from its client (remote ECU work must not be interrupted by someone else
/// who knows the password).
const STALE_SESSION: Duration = LINK_TIMEOUT;
/// A send that blocked this long means the link stalled badly; frames queued in the adapter
/// meanwhile are treated as stale and dropped (higher layers have retransmitted by then).
/// Shorter blips are simply delivered late, which is what TCP inside the tunnel prefers.
const STALL: Duration = Duration::from_secs(2);
/// Reconnect delays in seconds: first retry at once, then backing off.
const RECONNECT_DELAYS: [u64; 5] = [0, 1, 2, 5, 10];
/// Hard limit for the whole handshake (TLS + password), against slow or stalled clients.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-attempt TCP connect limit. Short on purpose: while the network is down each attempt
/// just waits this long, so a shorter value means a faster return once it is back.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Unauthenticated connections handled at once; more are closed immediately.
const MAX_HANDSHAKES: usize = 8;
/// Wrong passwords from one IP before it is blocked for `BAN_TIME`.
const MAX_FAILURES_PER_IP: u32 = 5;
const BAN_TIME: Duration = Duration::from_secs(10 * 60);
/// Pending handshakes allowed from one address, so one host cannot hold all the slots.
const MAX_HANDSHAKES_PER_IP: u32 = 2;
/// Minimum interval between log lines about the same misbehaving IP.
const LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Handle to a running server or client worker.
pub struct TunnelHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    password: Arc<Mutex<String>>,
    /// Client only: the current connection, cut on stop so a stalled link cannot block the GUI.
    sock: Arc<Mutex<Option<TcpStream>>>,
    /// Server only: the running client session, if any.
    active: Arc<Mutex<Option<ActiveSession>>>,
}

impl TunnelHandle {
    /// Requests a stop; the worker finishes within a fraction of a second (or after a pending
    /// connect attempt times out).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(s) = self.sock.lock().unwrap().as_ref() {
            // Give the session a moment to send Close, then make sure nothing stays blocked
            // in a LINK_TIMEOUT-long read/write.
            let s = s.try_clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                if let Ok(s) = s {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            });
        }
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }

    /// Waits for the worker to exit.
    pub fn join(mut self) {
        self.stop();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Server only: replaces the password for new connections.
    pub fn set_password(&self, pw: &str) {
        *self.password.lock().unwrap() = secure::normalize_password(pw);
    }

    /// Server only: ends the current client session gracefully (the client gets Close and
    /// does not reconnect). Returns false when no client is connected.
    pub fn disconnect_client(&self) -> bool {
        match self.active.lock().unwrap().as_ref() {
            Some(s) => {
                s.stop.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    /// Server only: whether a client session is running.
    pub fn has_client(&self) -> bool {
        self.active.lock().unwrap().is_some()
    }
}

/// Socket tuning for a link that may stall briefly (Wi-Fi roaming, retransmissions):
/// TCP itself retransmits and a stall shorter than the peer timeout is ridden out on the same
/// session; longer outages end the session and the client reconnects.
fn configure_socket(tcp: &TcpStream) -> io::Result<()> {
    let peer_timeout = LINK_TIMEOUT;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(peer_timeout))?;
    tcp.set_write_timeout(Some(peer_timeout))?;
    let s = socket2::SockRef::from(tcp);
    let _ = s.set_recv_buffer_size(1 << 20);
    // A modest send buffer, so that during a stall only a bounded amount of stale frames (this
    // buffer plus the batch being written) is delivered late, instead of seconds' worth of them.
    let _ = s.set_send_buffer_size(256 << 10);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = s.set_tcp_keepalive(&ka);
    // Linux: give up on unacknowledged data after the same time as the app-level timeout
    // (the default is ~15 minutes of retransmissions).
    #[cfg(target_os = "linux")]
    let _ = s.set_tcp_user_timeout(Some(peer_timeout));
    // Windows equivalent: TCP_MAXRT, the maximum retransmission time in seconds.
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{IPPROTO_TCP, TCP_MAXRT, setsockopt};
        let secs = peer_timeout.as_secs() as i32;
        // SAFETY: valid socket handle and a pointer to a live i32 of the given length.
        unsafe {
            setsockopt(
                tcp.as_raw_socket() as _,
                IPPROTO_TCP,
                TCP_MAXRT,
                &secs as *const i32 as *const u8,
                4,
            );
        }
    }
    Ok(())
}

/// The running session on the server: its stop flag plus a socket handle so it can be
/// cut immediately (takeover by a reconnecting client, Stop), even if it is blocked in I/O.
struct ActiveSession {
    stop: Arc<AtomicBool>,
    sock: Option<TcpStream>,
    /// When the peer last sent anything (keepalives count), to tell a live session from a dead one.
    last_rx: Arc<Mutex<Instant>>,
}

impl ActiveSession {
    fn kill(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(s) = &self.sock {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[derive(Default)]
struct Counters {
    to_peer: AtomicU64,
    from_peer: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

/// Why a session ended.
enum End {
    /// Stopped on this side (Stop / Disconnect / takeover).
    Stopped,
    /// The peer ended the session on purpose (it sent Close): no reconnect.
    PeerClosed,
    /// The connection broke (timeout, reset, EOF without Close): the client reconnects.
    Peer(String),
    Adapter(String),
}

/// Forwards frames both ways until stop, peer loss or an adapter error. `last_rx`, when given,
/// is updated whenever the peer sends something.
fn run_session(
    stream: SecureStream,
    port: Arc<dyn L2Port>,
    stop: &Arc<AtomicBool>,
    last_rx: Option<&Mutex<Instant>>,
    log: &Logger,
) -> End {
    let stream = Arc::new(stream);
    let done = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());
    port.drain();

    // Device -> peer, plus keepalives.
    let tx = {
        let (stream, port, done, stop, counters, log) = (
            stream.clone(),
            port.clone(),
            done.clone(),
            stop.clone(),
            counters.clone(),
            log.clone(),
        );
        std::thread::spawn(move || -> End {
            let mut frames = Vec::new();
            let mut buf = Vec::new();
            let mut last_send = Instant::now();
            let (mut last_report, mut prev_tx, mut prev_rx) = (Instant::now(), 0u64, 0u64);
            let mut last_rates = (0u64, 0u64);
            let end = loop {
                // Throughput for the GUI, once a second (skipped while idle so the GUI is not
                // repainted for nothing).
                let elapsed = last_report.elapsed();
                if elapsed >= Duration::from_secs(1) {
                    let (tx_b, rx_b) = (
                        counters.tx_bytes.load(Ordering::Relaxed),
                        counters.rx_bytes.load(Ordering::Relaxed),
                    );
                    let secs = elapsed.as_secs_f64();
                    let rates = (
                        ((rx_b - prev_rx) as f64 / secs) as u64,
                        ((tx_b - prev_tx) as f64 / secs) as u64,
                    );
                    if rates != last_rates {
                        log.traffic(rates.0, rates.1);
                        last_rates = rates;
                    }
                    (last_report, prev_tx, prev_rx) = (Instant::now(), tx_b, rx_b);
                }
                if stop.load(Ordering::SeqCst) {
                    // Tell the peer this is intentional (best effort; the link may be dead).
                    proto::encode_close(&mut buf);
                    let _ = stream.send(&buf);
                    break End::Stopped;
                }
                if done.load(Ordering::SeqCst) {
                    break End::Peer(String::new());
                }
                frames.clear();
                if let Err(e) = port.recv(&mut frames, POLL) {
                    break End::Adapter(e.to_string());
                }
                let result = if !frames.is_empty() {
                    counters.to_peer.fetch_add(frames.len() as u64, Ordering::Relaxed);
                    let started = Instant::now();
                    let r = frames.chunks(MAX_BATCH).try_for_each(|chunk| {
                        proto::encode_batch(chunk, &mut buf);
                        counters.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
                        stream.send(&buf)
                    });
                    if started.elapsed() >= STALL {
                        // The link was stuck: what piled up in the adapter meanwhile is stale
                        // (higher layers retransmit), so do not deliver it late.
                        port.drain();
                    }
                    r
                } else if last_send.elapsed() >= KEEPALIVE {
                    proto::encode_batch(&[], &mut buf);
                    stream.send(&buf)
                } else {
                    continue;
                };
                if let Err(e) = result {
                    break End::Peer(e.to_string());
                }
                last_send = Instant::now();
            };
            done.store(true, Ordering::SeqCst);
            stream.shutdown();
            end
        })
    };

    // Peer -> device on this thread.
    let mut dec = BatchDecoder::default();
    let mut frames = Vec::new();
    let rx_end = 'outer: loop {
        // Plaintext goes straight into the decoder's buffer (it only ever appends).
        match stream.recv(dec.buffer_mut()) {
            Ok(0) => break End::Peer("the connection was closed unexpectedly".into()),
            Ok(n) => {
                counters.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(t) = last_rx {
                    *t.lock().unwrap() = Instant::now();
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                break End::Peer(format!("no data from the peer for {} s", LINK_TIMEOUT.as_secs()));
            }
            Err(e) => break End::Peer(e.to_string()),
        }
        loop {
            frames.clear();
            match dec.next(&mut frames) {
                Ok(None) => break,
                Ok(Some(proto::Msg::Close)) => break 'outer End::PeerClosed,
                Ok(Some(proto::Msg::Batch)) if frames.is_empty() => {}
                Ok(Some(proto::Msg::Batch)) => {
                    counters.from_peer.fetch_add(frames.len() as u64, Ordering::Relaxed);
                    if let Err(e) = port.send(&frames) {
                        break 'outer End::Adapter(e.to_string());
                    }
                }
                Err(e) => break 'outer End::Peer(format!("protocol error: {e}")),
            }
        }
    };
    done.store(true, Ordering::SeqCst);
    stream.shutdown();
    let tx_end = tx.join().unwrap_or(End::Peer("sender thread panicked".into()));
    log.traffic(0, 0);

    log.info(format!(
        "Frames forwarded: {} to the peer, {} from the peer.",
        counters.to_peer.load(Ordering::Relaxed),
        counters.from_peer.load(Ordering::Relaxed)
    ));
    if stop.load(Ordering::SeqCst) {
        return End::Stopped;
    }
    // Prefer the most informative reason.
    match (tx_end, rx_end) {
        (End::Adapter(e), _) | (_, End::Adapter(e)) => End::Adapter(e),
        (_, End::PeerClosed) => End::PeerClosed,
        (_, End::Peer(e)) if !e.is_empty() => End::Peer(e),
        (End::Peer(e), _) if !e.is_empty() => End::Peer(e),
        _ => End::Stopped,
    }
}

/// Runs `f`, shutting the socket down if it takes longer than `limit`.
fn with_deadline<T>(tcp: &TcpStream, limit: Duration, f: impl FnOnce() -> T) -> T {
    let done = Arc::new(AtomicBool::new(false));
    if let Ok(killer) = tcp.try_clone() {
        let done = done.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::SeqCst) {
                if start.elapsed() >= limit {
                    let _ = killer.shutdown(std::net::Shutdown::Both);
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }
    let r = f();
    done.store(true, Ordering::SeqCst);
    r
}

// ----------------------------------------------------------------------------- server

pub struct ServerConfig {
    pub adapter_id: String,
    pub adapter_name: String,
    pub port: u16,
    /// TLS + password; when false the tunnel is plain TCP without a password.
    pub secure: bool,
    pub password: String,
}

pub fn start_server(cfg: ServerConfig, log: Logger) -> TunnelHandle {
    let stop = Arc::new(AtomicBool::new(false));
    // Same normalization as the client applies to what the user types.
    let password = Arc::new(Mutex::new(secure::normalize_password(&cfg.password)));
    let active: Arc<Mutex<Option<ActiveSession>>> = Arc::default();
    let thread = {
        let (stop, password, active) = (stop.clone(), password.clone(), active.clone());
        std::thread::spawn(move || {
            if let Err(e) = server_main(&cfg, stop, password, active, &log) {
                // Full message in the log; the status line stays short.
                log.error(e.to_string());
                log.status("Error - see log");
            } else {
                log.status("Stopped");
            }
            log.info("Ethernet sharing stopped.");
        })
    };
    TunnelHandle {
        stop,
        thread: Some(thread),
        password,
        sock: Arc::default(),
        active,
    }
}

#[derive(Default)]
struct IpRecord {
    failures: u32,
    banned_until: Option<Instant>,
    last_log: Option<Instant>,
    /// Handshakes in progress from this address.
    pending: u32,
}

/// Brute-force and scanner protection. With an 8-character `0-9a-z` password (36^8
/// combinations) and one guess per second per connection, online guessing is hopeless; the
/// per-IP ban mostly keeps the log quiet and the slots free.
#[derive(Default)]
struct Abuse {
    per_ip: HashMap<IpAddr, IpRecord>,
}

impl Abuse {
    fn is_banned(&mut self, ip: IpAddr) -> bool {
        self.per_ip
            .get(&ip)
            .and_then(|r| r.banned_until)
            .is_some_and(|t| Instant::now() < t)
    }

    /// Reserves a handshake slot for `ip`; false when it already has `MAX_HANDSHAKES_PER_IP`.
    fn begin_handshake(&mut self, ip: IpAddr) -> bool {
        self.prune();
        let r = self.per_ip.entry(ip).or_default();
        if r.pending >= MAX_HANDSHAKES_PER_IP {
            return false;
        }
        r.pending += 1;
        true
    }

    fn end_handshake(&mut self, ip: IpAddr) {
        if let Some(r) = self.per_ip.get_mut(&ip) {
            r.pending = r.pending.saturating_sub(1);
        }
    }

    /// Rate limits log lines about one IP.
    fn should_log(&mut self, ip: IpAddr) -> bool {
        self.prune();
        let r = self.per_ip.entry(ip).or_default();
        if r.last_log.is_some_and(|t| t.elapsed() < LOG_INTERVAL) {
            return false;
        }
        r.last_log = Some(Instant::now());
        true
    }

    /// Records a wrong password. Returns (failures from this IP, banned now).
    fn failure(&mut self, ip: IpAddr) -> (u32, bool) {
        self.prune();
        let r = self.per_ip.entry(ip).or_default();
        r.failures += 1;
        let n = r.failures;
        let banned = n >= MAX_FAILURES_PER_IP;
        if banned {
            r.banned_until = Some(Instant::now() + BAN_TIME);
            r.failures = 0;
        }
        (n, banned)
    }

    fn success(&mut self, ip: IpAddr) {
        if let Some(r) = self.per_ip.get_mut(&ip) {
            r.failures = 0;
            r.banned_until = None;
        }
    }

    /// Keeps memory bounded when scanned from many addresses.
    fn prune(&mut self) {
        if self.per_ip.len() > 4096 {
            let now = Instant::now();
            self.per_ip
                .retain(|_, r| r.pending > 0 || r.banned_until.is_some_and(|t| t > now));
        }
    }
}

struct Server {
    identity: ServerIdentity,
    secure: bool,
    password: Arc<Mutex<String>>,
    port: Arc<ResilientPort>,
    stop: Arc<AtomicBool>,
    log: Logger,
    abuse: Mutex<Abuse>,
    handshakes: AtomicUsize,
    /// Sockets of handshakes in progress, cut on Stop.
    pending: Mutex<Vec<TcpStream>>,
    /// The running session, if any (shared with TunnelHandle for "disconnect client").
    active: Arc<Mutex<Option<ActiveSession>>>,
    /// Held for the duration of a session (only one client at a time).
    session_slot: Mutex<()>,
}

fn server_main(
    cfg: &ServerConfig,
    stop: Arc<AtomicBool>,
    password: Arc<Mutex<String>>,
    active: Arc<Mutex<Option<ActiveSession>>>,
    log: &Logger,
) -> io::Result<()> {
    // Blocked IPs and wrong-password counters live in this run only, so Stop/Share resets them.
    log.info(format!(
        "Starting Ethernet sharing for adapter '{}' on TCP port {}.",
        cfg.adapter_name, cfg.port
    ));
    log.status("Starting...");
    let port = Arc::new(l2::open_server(&cfg.adapter_id, &cfg.adapter_name, log)?);
    let identity = ServerIdentity::generate()?;
    l2::prepare_listen(cfg.port, log);
    let listener = listen_dual_stack(cfg.port)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot listen on TCP port {}: {e}", cfg.port)))?;
    listener.set_nonblocking(true)?;
    if cfg.secure {
        log.info(format!(
            "Listening on TCP port {} (Secure: TLS 1.3 + password, certificate {}...). Waiting for a client.",
            cfg.port,
            identity.fingerprint_hex()
        ));
    } else {
        log.warn(format!(
            "Listening on TCP port {} in INSECURE mode: no encryption, no password. Waiting for a client.",
            cfg.port
        ));
    }

    let server = Arc::new(Server {
        identity,
        secure: cfg.secure,
        password,
        port,
        stop: stop.clone(),
        log: log.clone(),
        abuse: Mutex::default(),
        handshakes: AtomicUsize::new(0),
        pending: Mutex::default(),
        active,
        session_slot: Mutex::new(()),
    });
    server.idle_status();

    let mut last_idle = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, peer)) => server.clone().incoming(tcp, canonical(peer)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // e.g. ECONNABORTED / EMFILE: keep serving.
            Err(e) => {
                log.warn(format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        // While nobody is connected, keep watching the adapter so a USB unplug is noticed
        // (and logged) right away, and stale frames do not pile up.
        if last_idle.elapsed() >= Duration::from_millis(500) {
            last_idle = Instant::now();
            if let Ok(_slot) = server.session_slot.try_lock() {
                let was_present = server.port.is_present();
                server.port.drain();
                if was_present != server.port.is_present() {
                    server.idle_status();
                }
            }
        }
    }
    // Graceful stop: the session sends Close to the client (so it does not reconnect) within
    // ~50 ms. If the link is stuck, cut it after 2 s.
    if let Some(s) = server.active.lock().unwrap().as_ref() {
        s.stop.store(true, Ordering::SeqCst);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.session_slot.try_lock().is_err() {
        if Instant::now() >= deadline {
            if let Some(s) = server.active.lock().unwrap().as_ref() {
                s.kill();
            }
            let _wait = server.session_slot.lock();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Pending handshakes (scanners, a client mid-reconnect) hold an Arc<Server> and with it
    // the adapter. Cut them so the adapter is released now, not after HANDSHAKE_TIMEOUT:
    // otherwise an immediate Share again would find the TAP port / offload state in use.
    for s in server.pending.lock().unwrap().drain(..) {
        let _ = s.shutdown(std::net::Shutdown::Both);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.handshakes.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

impl Server {
    fn idle_status(&self) {
        if self.port.is_present() {
            self.log.status("Sharing - waiting for a client");
        } else {
            self.log.status("Adapter unavailable - waiting for it to come back");
        }
    }

    fn incoming(self: Arc<Self>, tcp: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();
        {
            let mut abuse = self.abuse.lock().unwrap();
            if abuse.is_banned(ip) {
                return; // dropping closes the connection
            }
            if !abuse.begin_handshake(ip) {
                if abuse.should_log(ip) {
                    self.log
                        .warn(format!("Too many pending connections from {ip}; dropped {peer}."));
                }
                return;
            }
        }
        if self.handshakes.fetch_add(1, Ordering::SeqCst) >= MAX_HANDSHAKES {
            self.handshakes.fetch_sub(1, Ordering::SeqCst);
            let mut abuse = self.abuse.lock().unwrap();
            abuse.end_handshake(ip);
            if abuse.should_log(ip) {
                self.log.warn(format!("Too many pending connections; dropped {peer}."));
            }
            return;
        }
        std::thread::spawn(move || self.handle(tcp, peer));
    }

    fn handle(&self, tcp: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();
        let result = (|| {
            tcp.set_nonblocking(false)?;
            configure_socket(&tcp)?;
            let pw = self.secure.then(|| self.password.lock().unwrap().clone());
            let killer = tcp.try_clone()?;
            // Registered so Stop can cut a handshake that is still in progress.
            self.pending.lock().unwrap().push(tcp.try_clone()?);
            with_deadline(&killer, HANDSHAKE_TIMEOUT, || {
                secure::server_handshake(tcp, &self.identity, pw.as_deref())
            })
        })();
        // Keep the registry small: entries whose handshake ended are of no use any more.
        self.pending
            .lock()
            .unwrap()
            .retain(|s| s.peer_addr().map(canonical).is_ok_and(|p| p != peer));
        self.handshakes.fetch_sub(1, Ordering::SeqCst);
        // The per-IP slot covers the handshake only, not the session (several clients may sit
        // behind one NAT address).
        self.abuse.lock().unwrap().end_handshake(ip);

        let auth = match result {
            Ok(ServerHandshake::Authenticated(a)) => a,
            Ok(ServerHandshake::WrongPassword) => {
                let (n, banned) = self.abuse.lock().unwrap().failure(ip);
                self.log
                    .warn(format!("{peer}: wrong password ({n}/{MAX_FAILURES_PER_IP})."));
                if banned {
                    self.log.warn(format!(
                        "{ip} blocked for {} minutes after repeated wrong passwords.",
                        BAN_TIME.as_secs() / 60
                    ));
                }
                return;
            }
            Err(e) => {
                // Scanners, port probes, non-EasyEther clients, timeouts.
                if self.abuse.lock().unwrap().should_log(ip) {
                    self.log.warn(format!("Rejected connection from {peer}: {e}"));
                }
                return;
            }
        };
        self.abuse.lock().unwrap().success(ip);

        // An authenticated client takes over from a previous session, which after a network
        // hiccup is usually the same client's dead connection still waiting for its timeout.
        // A live session is never taken away from its client. Only a dead one (peer silent for
        // STALE_SESSION, e.g. the same client's old connection after a network drop) is replaced.
        let old = {
            let mut active = self.active.lock().unwrap();
            match active.as_ref() {
                Some(cur) if cur.last_rx.lock().unwrap().elapsed() < STALE_SESSION => {
                    drop(active);
                    self.log
                        .info(format!("Rejected {peer}: another client is connected and active."));
                    auth.reject("The sharing computer already has a client connected.");
                    return;
                }
                _ => active.take(),
            }
        };
        if let Some(old) = &old {
            self.log
                .info(format!("{peer} replaces the previous (unresponsive) client session."));
            // Stop flag first: within ~50 ms the old session sends Close (so that client does
            // not reconnect and fight over the slot); cut the socket only if it does not end.
            old.stop.store(true, Ordering::SeqCst);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let _slot = loop {
            if let Ok(g) = self.session_slot.try_lock() {
                break g;
            }
            if let Some(old) = &old
                && Instant::now() >= deadline - Duration::from_millis(2700)
            {
                old.kill();
            }
            if Instant::now() >= deadline || self.stop.load(Ordering::SeqCst) {
                auth.reject("The sharing computer is busy; please retry in a few seconds.");
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if self.stop.load(Ordering::SeqCst) {
            auth.reject("Sharing is stopping.");
            return;
        }
        let stream = match auth.accept() {
            Ok(s) => s,
            Err(e) => {
                self.log.warn(format!("{peer}: {e}"));
                return;
            }
        };
        let my_stop = Arc::new(AtomicBool::new(false));
        let last_rx = Arc::new(Mutex::new(Instant::now()));
        *self.active.lock().unwrap() = Some(ActiveSession {
            stop: my_stop.clone(),
            sock: stream.shutdown_handle().ok(),
            last_rx: last_rx.clone(),
        });
        self.log
            .info(format!("Client {peer} authenticated; Ethernet tunnel established."));
        self.log.status(format!("Sharing - client connected ({peer})"));
        match run_session(stream, self.port.clone(), &my_stop, Some(&last_rx), &self.log) {
            End::Stopped => self.log.info(format!("Session with {peer} closed.")),
            End::PeerClosed => self.log.info(format!("Client {peer} disconnected.")),
            End::Peer(e) => self
                .log
                .warn(format!("Connection to {peer} lost: {e}. The client will reconnect.")),
            End::Adapter(e) => self.log.error(format!("Adapter error: {e}")),
        }
        self.clear_active(&my_stop);
        if !self.stop.load(Ordering::SeqCst) && self.active.lock().unwrap().is_none() {
            self.idle_status();
        }
    }

    fn clear_active(&self, mine: &Arc<AtomicBool>) {
        let mut a = self.active.lock().unwrap();
        if a.as_ref().is_some_and(|s| Arc::ptr_eq(&s.stop, mine)) {
            *a = None;
        }
    }
}

/// One listening socket for IPv6 and IPv4 (`[::]` with V6ONLY off; Windows defaults to on).
/// Falls back to IPv4 only where IPv6 is disabled.
fn listen_dual_stack(port: u16) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = (|| -> io::Result<TcpListener> {
        let s = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        s.set_only_v6(false)?;
        #[cfg(unix)]
        s.set_reuse_address(true)?;
        s.bind(&SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port).into())?;
        s.listen(16)?;
        Ok(s.into())
    })();
    match v6 {
        Ok(l) => Ok(l),
        Err(_) => TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)),
    }
}

/// Resolves what the user typed as the server address: a host name, an IPv4 or IPv6 literal
/// (with or without brackets), or a link-local IPv6 with a zone (`fe80::1%eth0`, `fe80::1%12`).
fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Some((addr, zone)) = host.split_once('%') {
        let addr: Ipv6Addr = addr.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{host}' is not a valid IPv6 address"),
            )
        })?;
        let scope = match zone.parse::<u32>() {
            Ok(n) => n,
            Err(_) => interface_index(zone)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("unknown interface '{zone}'")))?,
        };
        return Ok(vec![SocketAddrV6::new(addr, port, 0, scope).into()]);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    Ok((host, port)
        .to_socket_addrs()
        .map_err(|e| io::Error::new(e.kind(), format!("cannot resolve '{host}': {e}")))?
        .collect())
}

/// Interface index for an IPv6 zone given by name (Linux: `eth0`; Windows zones are numeric).
fn interface_index(name: &str) -> Option<u32> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: c is a valid C string.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (idx != 0).then_some(idx)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        None
    }
}

/// Peer address for logs and the per-IP limits: IPv4 clients on the dual-stack socket arrive
/// as `::ffff:a.b.c.d`; show and count them as plain IPv4.
fn canonical(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

// ----------------------------------------------------------------------------- client

pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    /// TLS + password; when false the tunnel is plain TCP without a password.
    pub secure: bool,
    pub password: String,
    pub static_ipv4: Option<(Ipv4Addr, u8)>,
    pub mac: [u8; 6],
}

pub fn start_client(cfg: ClientConfig, log: Logger) -> TunnelHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let sock: Arc<Mutex<Option<TcpStream>>> = Arc::default();
    let thread = {
        let (stop, sock) = (stop.clone(), sock.clone());
        std::thread::spawn(move || match client_main(&cfg, &stop, &sock, &log) {
            // "Disconnected" alone = the user's own Disconnect; with a reason the GUI shows
            // the client as disconnected in a warning color.
            Ok(()) => log.status("Disconnected"),
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => log.status(format!("Disconnected - {e}")),
            Err(e) => {
                log.error(e.to_string());
                log.status("Disconnected - see log");
            }
        })
    };
    TunnelHandle {
        stop,
        thread: Some(thread),
        password: Arc::default(),
        sock,
        active: Arc::default(),
    }
}

fn connect(host: &str, port: u16, stop: &AtomicBool) -> io::Result<TcpStream> {
    let addrs = resolve(host, port)?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for '{host}'"));
    for a in addrs {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = io::Error::new(e.kind(), format!("cannot connect to {a}: {e}")),
        }
    }
    Err(last)
}

/// Connects and authenticates; returns the stream and the server address.
fn connect_and_auth(cfg: &ClientConfig, stop: &AtomicBool, log: &Logger) -> io::Result<(SecureStream, SocketAddr)> {
    log.info(format!("Connecting to {}:{}...", cfg.host, cfg.port));
    let tcp = connect(&cfg.host, cfg.port, stop)?;
    let peer = tcp.peer_addr()?;
    configure_socket(&tcp)?;
    let killer = tcp.try_clone()?;
    let password = cfg.secure.then(|| secure::normalize_password(&cfg.password));
    let stream = with_deadline(&killer, HANDSHAKE_TIMEOUT, || {
        secure::client_handshake(tcp, password.as_deref())
    })?;
    if cfg.secure {
        log.info(format!(
            "Authenticated with {peer}; encrypted Ethernet tunnel established."
        ));
    } else {
        log.warn(format!(
            "Connected to {peer} in INSECURE mode (no encryption, no password)."
        ));
    }
    Ok((stream, peer))
}

/// Sleeps up to `d`, returning early (false) when stop is requested.
fn sleep_unless_stopped(d: Duration, stop: &AtomicBool) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !stop.load(Ordering::SeqCst)
}

/// Connects with back-off (`RECONNECT_DELAYS`) until it works. `None` = the user stopped;
/// `Some(Err)` = an error a retry cannot fix (wrong password, Secure mismatch).
fn retry_connect(
    cfg: &ClientConfig,
    stop: &AtomicBool,
    log: &Logger,
    reason: &str,
) -> Option<io::Result<(SecureStream, SocketAddr)>> {
    let mut attempt = 0usize;
    loop {
        let delay = RECONNECT_DELAYS[attempt.min(RECONNECT_DELAYS.len() - 1)];
        attempt += 1;
        if delay > 0 {
            log.status(format!("{reason} - retrying in {delay} s (attempt {attempt})"));
            if !sleep_unless_stopped(Duration::from_secs(delay), stop) {
                return None;
            }
        }
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        log.status(format!("Connecting (attempt {attempt})..."));
        match connect_and_auth(cfg, stop, log) {
            Ok(s) => return Some(Ok(s)),
            Err(e) if secure::is_fatal_handshake_error(&e) => return Some(Err(e)),
            Err(_) if stop.load(Ordering::SeqCst) => return None,
            Err(e) => log.warn(format!("Connection attempt {attempt} failed: {e}")),
        }
    }
}

fn client_main(
    cfg: &ClientConfig,
    stop: &Arc<AtomicBool>,
    sock: &Mutex<Option<TcpStream>>,
    log: &Logger,
) -> io::Result<()> {
    log.status("Connecting...");
    // Keep trying until the server is reachable (it may not be sharing yet, the network may be
    // down for a moment); only wrong password / Secure mismatch, or Disconnect, end this.
    let (mut stream, mut peer) = match retry_connect(cfg, stop, log, "Server unreachable") {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    // The virtual adapter stays open across reconnects, so the OS keeps its link, IP and routes.
    let port: Arc<dyn L2Port> = Arc::from(l2::open_client(cfg.mac, log)?);
    let ip_guard = match cfg.static_ipv4 {
        Some((addr, prefix)) => match l2::apply_static_ipv4(addr, prefix, log) {
            Ok(g) => Some(g),
            Err(e) => {
                log.error(format!("Could not set static IPv4 {addr}/{prefix}: {e}"));
                None
            }
        },
        None => match l2::start_dhcp(log) {
            Ok(g) => g,
            Err(e) => {
                let fix = if e.kind() == io::ErrorKind::NotFound {
                    "Install dhcpcd or set"
                } else {
                    "Set"
                };
                log.warn(format!(
                    "No automatic IPv4 on '{}': {e}. {fix} a static IPv4 in Network settings.",
                    l2::client_adapter_name()
                ));
                None
            }
        },
    };

    let result = loop {
        log.status(format!("Connected to {peer} via '{}'", l2::client_adapter_name()));
        // Lets TunnelHandle::stop cut a stalled connection instead of waiting for timeouts.
        *sock.lock().unwrap() = stream.shutdown_handle().ok();
        match run_session(stream, port.clone(), stop, None, log) {
            End::Stopped => {
                log.info("Disconnected.");
                break Ok(());
            }
            End::PeerClosed => {
                log.info("The sharing computer ended the session; disconnected.");
                break Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the sharing computer ended the session",
                ));
            }
            End::Adapter(e) => break Err(io::Error::other(format!("virtual adapter error: {e}"))),
            End::Peer(e) => log.warn(format!("Connection lost: {e}")),
        }
        match retry_connect(cfg, stop, log, "Connection lost") {
            None => {
                log.info("Disconnected.");
                break Ok(());
            }
            Some(Err(e)) => break Err(e),
            Some(Ok((s, p))) => {
                log.info("Reconnected; forwarding resumed.");
                (stream, peer) = (s, p);
            }
        }
    };
    drop(ip_guard);
    drop(port);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for an Ethernet adapter: no frames, accepts everything.
    struct NullPort;

    impl L2Port for NullPort {
        fn recv(&self, _out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
            Ok(())
        }
        fn send(&self, _frames: &[Vec<u8>]) -> io::Result<()> {
            Ok(())
        }
    }

    /// A connected (server, client) pair in insecure mode.
    fn pair() -> (SecureStream, SecureStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let id = ServerIdentity::generate().unwrap();
            let (tcp, _) = listener.accept().unwrap();
            match secure::server_handshake(tcp, &id, None).unwrap() {
                ServerHandshake::Authenticated(a) => a.accept().unwrap(),
                ServerHandshake::WrongPassword => unreachable!(),
            }
        });
        let client = secure::client_handshake(TcpStream::connect(addr).unwrap(), None).unwrap();
        (server.join().unwrap(), client)
    }

    fn session(stream: SecureStream, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<End> {
        std::thread::spawn(move || run_session(stream, Arc::new(NullPort), &stop, None, &Logger::new(None).0))
    }

    #[test]
    fn resolves_literals_and_zones() {
        let v4 = resolve("192.168.1.5", 5555).unwrap();
        assert_eq!(v4[0].to_string(), "192.168.1.5:5555");
        let v6 = resolve("[fe80::1]", 5555).unwrap();
        assert_eq!(v6[0].to_string(), "[fe80::1]:5555");
        let zoned = resolve("fe80::1%7", 5555).unwrap();
        match zoned[0] {
            SocketAddr::V6(a) => assert_eq!(a.scope_id(), 7),
            _ => panic!("expected IPv6"),
        }
        assert!(resolve("fe80::1%no-such-interface", 5555).is_err());
        assert_eq!(
            canonical("[::ffff:10.0.0.1]:1".parse().unwrap()).to_string(),
            "10.0.0.1:1"
        );
    }

    #[test]
    fn dual_stack_listener_accepts_v4_and_v6() {
        let l = listen_dual_stack(0).unwrap();
        let port = l.local_addr().unwrap().port();
        if l.local_addr().unwrap().is_ipv6() {
            TcpStream::connect(("::1", port)).unwrap();
        }
        TcpStream::connect(("127.0.0.1", port)).unwrap();
    }

    #[test]
    fn intentional_stop_is_reported_as_close() {
        let (s, c) = pair();
        let client_stop = Arc::new(AtomicBool::new(false));
        let server = session(s, Arc::new(AtomicBool::new(false)));
        let client = session(c, client_stop.clone());
        std::thread::sleep(Duration::from_millis(200));
        client_stop.store(true, Ordering::SeqCst);
        assert!(matches!(client.join().unwrap(), End::Stopped));
        assert!(matches!(server.join().unwrap(), End::PeerClosed));
    }

    #[test]
    fn broken_connection_is_not_a_close() {
        let (s, c) = pair();
        let cut = c.shutdown_handle().unwrap();
        let server = session(s, Arc::new(AtomicBool::new(false)));
        let client = session(c, Arc::new(AtomicBool::new(false)));
        std::thread::sleep(Duration::from_millis(200));
        // Like a reset/dead link: no Close message is sent.
        cut.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(matches!(server.join().unwrap(), End::Peer(_)));
        assert!(matches!(client.join().unwrap(), End::Peer(_)));
    }
}
