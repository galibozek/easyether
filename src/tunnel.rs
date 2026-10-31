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

/// How long the device thread waits for frames before it looks at the stop flag and the
/// keepalive timer. On Windows it also bounds the delay of a frame whose "packets available"
/// event got lost in the drivers' set/reset race (see `DevicePort::recv`).
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
/// Linux: at most this much not-yet-sent data waits in the tunnel socket (TCP_NOTSENT_LOWAT).
/// Bounds the queue in front of diagnostic frames under bulk traffic; data in flight is not
/// limited, so throughput is not either.
#[cfg(target_os = "linux")]
const NOTSENT_LOWAT: i32 = 128 << 10;
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
    /// Server only: the last client whose session ended, and when.
    last_client: Arc<Mutex<Option<(SocketAddr, Instant)>>>,
    /// Client only: the current connection, for the GUI.
    link: Arc<Mutex<ClientLink>>,
}

/// The client's connection as the GUI shows it.
#[derive(Clone, Copy, Default)]
pub struct ClientLink {
    /// The server, once connected.
    pub peer: Option<SocketAddr>,
    /// Since when the current session runs; `None` while (re)connecting.
    pub since: Option<Instant>,
    /// How often the connection was lost and re-established since Connect.
    pub reconnects: u32,
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

    /// Server only: the connected client's address and since when it is connected, if any.
    pub fn client_session(&self) -> Option<(SocketAddr, Instant)> {
        self.active.lock().unwrap().as_ref().map(|s| (s.peer, s.since))
    }

    /// Server only: the last client whose session ended, and when.
    pub fn last_client(&self) -> Option<(SocketAddr, Instant)> {
        *self.last_client.lock().unwrap()
    }

    /// Client only: the current connection.
    pub fn client_link(&self) -> ClientLink {
        *self.link.lock().unwrap()
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
    // No SO_RCVBUF/SO_SNDBUF: setting them disables the OS autotuning (and Linux caps them at
    // rmem_max/wmem_max, 208 KiB by default), which capped throughput per round trip. Autotuned
    // buffers can grow large under sustained bulk traffic on a buffered path (LTE, VPN), and
    // then more queues in front of diagnostic frames and more arrives late after a stall
    // (stall detection only fires once a write blocks). On Linux TCP_NOTSENT_LOWAT keeps the
    // not-yet-sent part short without limiting throughput; Windows sizes its send buffer from
    // the measured bandwidth-delay product.
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let lowat: libc::c_int = NOTSENT_LOWAT;
        // SAFETY: valid socket descriptor and a pointer to a live c_int of the given length.
        unsafe {
            libc::setsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                &lowat as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
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
    /// The client's id, so that client (and only it) can take its own session over.
    client_id: proto::ClientId,
    /// Where the client connects from, and since when, for the GUI.
    peer: SocketAddr,
    since: Instant,
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
    /// A ping from the peer still to be answered: its token and when it arrived. Answered by
    /// the sending thread, so the receiving thread never blocks on a send (with both sides'
    /// receivers blocked on full send buffers, neither would read again).
    pending_pong: Mutex<Option<(u64, Instant)>>,
    /// Token of our latest ping while it is unanswered, 0 once its pong came (or before the
    /// first); only that pong counts.
    last_ping: AtomicU64,
    /// Last measured round trip in microseconds; 0 while none.
    rtt_us: AtomicU64,
    /// How many round trips were measured, so the reporter can tell a new one from the last.
    rtt_count: AtomicU64,
    /// Longest frame write to the peer since the last link report, in microseconds.
    max_send_us: AtomicU64,
    /// How often the adapter's backlog was dropped after a stuck write.
    stall_drops: AtomicU64,
}

/// How often the session's state goes to the log, so a slowdown can be traced afterwards.
const LINK_REPORT: Duration = Duration::from_secs(30);
/// Whether that report is written (`--link-log`).
pub static LINK_LOG: AtomicBool = AtomicBool::new(false);
/// The shown throughput is the average over this long, so it does not flicker.
const RATE_WINDOW: Duration = Duration::from_secs(3);
/// The shown latency is the median of this many pings (one a second).
const RTT_SAMPLES: usize = 5;

/// The round trip shown: the last measured one, or, once our latest ping has waited a second or
/// more, that wait (a stalled link shows a growing latency, not an old one). A shorter wait is
/// not shown: it includes the time the peer holds a ping until its next adapter poll (up to
/// 50 ms), which the measurement subtracts, so it would make the latency jump for nothing.
fn shown_rtt(measured_us: u64, waiting: Option<Duration>) -> Option<Duration> {
    let measured = (measured_us > 0).then(|| Duration::from_micros(measured_us));
    match waiting {
        Some(w) if w >= Duration::from_secs(1) => Some(measured.map_or(w, |m| m.max(w))),
        _ => measured,
    }
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
    // Ping tokens are nanoseconds since this instant (never 0), so a pong tells when its ping
    // was sent without keeping a table.
    let base = Instant::now();
    port.drain();

    // Device -> peer, plus keepalives and pings.
    let tx = {
        let (stream, port, done, stop, counters) = (
            stream.clone(),
            port.clone(),
            done.clone(),
            stop.clone(),
            counters.clone(),
        );
        std::thread::spawn(move || -> End {
            let mut frames = Vec::new();
            let mut buf = Vec::new();
            let mut last_send = Instant::now();
            let mut last_ping = Instant::now();
            let end = loop {
                // A ping once a second, for the latency shown by the reporter, but never while
                // one is still unanswered: a new one would replace it and a round trip near or
                // above a second could never be measured. Pings and pongs are not counted as
                // throughput, so an idle tunnel shows 0 B/s.
                if last_ping.elapsed() >= Duration::from_secs(1) && counters.last_ping.load(Ordering::Relaxed) == 0 {
                    last_ping = Instant::now();
                    let token = (base.elapsed().as_nanos() as u64).max(1);
                    counters.last_ping.store(token, Ordering::Relaxed);
                    proto::encode_ping(token, &mut buf);
                    if let Err(e) = stream.send(&buf) {
                        break End::Peer(e.to_string());
                    }
                    last_send = Instant::now();
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
                let polling = Instant::now();
                if let Err(e) = port.recv(&mut frames, POLL) {
                    break End::Adapter(e.to_string());
                }
                // Answer the peer's ping. It may have waited here for the adapter poll, which
                // frames never do; that wait is reported so the peer can subtract it. Time
                // spent behind our own sends is not: frames wait there too, so it is latency.
                let pong = counters.pending_pong.lock().unwrap().take();
                if let Some((token, arrived)) = pong {
                    let hold = arrived.elapsed().min(polling.elapsed());
                    let hold_us = hold.as_micros().min(u32::MAX as u128) as u32;
                    proto::encode_pong(token, hold_us, &mut buf);
                    if let Err(e) = stream.send(&buf) {
                        break End::Peer(e.to_string());
                    }
                    last_send = Instant::now();
                }
                let result = if !frames.is_empty() {
                    counters.to_peer.fetch_add(frames.len() as u64, Ordering::Relaxed);
                    let started = Instant::now();
                    let r = frames.chunks(MAX_BATCH).try_for_each(|chunk| {
                        proto::encode_batch(chunk, &mut buf);
                        counters.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
                        stream.send(&buf)
                    });
                    let took = started.elapsed();
                    counters
                        .max_send_us
                        .fetch_max(took.as_micros() as u64, Ordering::Relaxed);
                    if took >= STALL {
                        // The link was stuck: what piled up in the adapter meanwhile is stale
                        // (higher layers retransmit), so do not deliver it late.
                        counters.stall_drops.fetch_add(1, Ordering::Relaxed);
                        port.drain();
                    }
                    r
                } else if last_send.elapsed() >= KEEPALIVE {
                    // Normally the pings keep the link busy; this covers a ping left unanswered
                    // for long (the peer must still hear from us within its LINK_TIMEOUT).
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

    // Throughput and latency for the GUI, once a second, only sent when they change (so an
    // idle GUI is not repainted for nothing). A thread of its own: the sender can sit in a
    // blocked write for seconds when the link stalls, and that is exactly when the growing
    // latency and the dropping rates should show. Both are smoothed so the tab does not flicker:
    // the rate over the last few seconds, the latency as the median of the last few pings.
    let reporter = {
        let (done, counters, log) = (done.clone(), counters.clone(), log.clone());
        std::thread::spawn(move || {
            let mut last_report = Instant::now();
            // (when, tx bytes, rx bytes), oldest first, spanning RATE_WINDOW.
            let mut history = std::collections::VecDeque::from([(Instant::now(), 0u64, 0u64)]);
            let (mut rtts, mut rtt_seen) = (std::collections::VecDeque::new(), 0u64);
            let mut last_shown = ((0u64, 0u64), None::<u64>);
            // For the link report in the log: when, and the counters at that time.
            let mut link_at = Instant::now();
            let mut link_prev = [0u64; 5];
            while !done.load(Ordering::SeqCst) {
                // Woken at once when the session ends (see below), so the end is not delayed.
                std::thread::park_timeout(Duration::from_millis(100));
                if done.load(Ordering::SeqCst) {
                    break;
                }
                if last_report.elapsed() < Duration::from_secs(1) {
                    continue;
                }
                last_report = Instant::now();
                let (tx_b, rx_b) = (
                    counters.tx_bytes.load(Ordering::Relaxed),
                    counters.rx_bytes.load(Ordering::Relaxed),
                );
                history.push_back((Instant::now(), tx_b, rx_b));
                while history.len() > 2 && history[0].0.elapsed() > RATE_WINDOW {
                    history.pop_front();
                }
                let (since, prev_tx, prev_rx) = history[0];
                let secs = since.elapsed().as_secs_f64().max(0.001);
                // Saturating: a ping's bytes are taken off the count after it was read, which can
                // fall just after a snapshot.
                let rates = (
                    (rx_b.saturating_sub(prev_rx) as f64 / secs) as u64,
                    (tx_b.saturating_sub(prev_tx) as f64 / secs) as u64,
                );
                let count = counters.rtt_count.load(Ordering::Relaxed);
                if count != rtt_seen {
                    rtt_seen = count;
                    rtts.push_back(counters.rtt_us.load(Ordering::Relaxed));
                    if rtts.len() > RTT_SAMPLES {
                        rtts.pop_front();
                    }
                }
                let mut sorted: Vec<u64> = rtts.iter().copied().collect();
                sorted.sort_unstable();
                let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
                // The token of an unanswered ping is when it was sent.
                let token = counters.last_ping.load(Ordering::Relaxed);
                let waiting = (token != 0).then(|| base.elapsed().saturating_sub(Duration::from_nanos(token)));
                let rtt = shown_rtt(median, waiting);
                // Compared at 1 ms, the precision shown.
                let shown = (rates, rtt.map(|d| d.as_millis() as u64));
                if shown != last_shown {
                    log.traffic(rates.0, rates.1, rtt);
                    last_shown = shown;
                }

                // With --link-log, every LINK_REPORT: what went through and how the link
                // behaved, so a slowdown can be located afterwards: frames not coming from the
                // adapter, writes stuck on TCP, or the peer not answering.
                if LINK_LOG.load(Ordering::Relaxed) && link_at.elapsed() >= LINK_REPORT {
                    let now = [
                        counters.to_peer.load(Ordering::Relaxed),
                        counters.from_peer.load(Ordering::Relaxed),
                        tx_b,
                        rx_b,
                        counters.stall_drops.load(Ordering::Relaxed),
                    ];
                    let d: Vec<u64> = now.iter().zip(link_prev).map(|(n, p)| n.saturating_sub(p)).collect();
                    let secs = link_at.elapsed().as_secs();
                    let longest = counters.max_send_us.swap(0, Ordering::Relaxed) / 1000;
                    let latency = rtt.map_or_else(|| "-".to_string(), crate::log::format_rtt);
                    log.info(format!(
                        "Link, last {secs} s: {} frames ({} KB) to the peer, {} frames ({} KB) from the peer, \
                         latency {latency}{}, longest write {longest} ms, stalls {}.",
                        d[0],
                        d[2] / 1000,
                        d[1],
                        d[3] / 1000,
                        if token != 0 { " (ping unanswered)" } else { "" },
                        d[4],
                    ));
                    (link_at, link_prev) = (Instant::now(), now);
                }
            }
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
                Ok(Some(proto::Msg::Ping(token))) => {
                    counters.rx_bytes.fetch_sub(proto::PING_LEN as u64, Ordering::Relaxed);
                    *counters.pending_pong.lock().unwrap() = Some((token, Instant::now()));
                }
                Ok(Some(proto::Msg::Pong { token, hold_us })) => {
                    counters.rx_bytes.fetch_sub(proto::PONG_LEN as u64, Ordering::Relaxed);
                    // Only the pong to our latest ping counts; a token that is not ours (or
                    // would overflow the clock) is ignored. Taking the token in one step means
                    // a newer ping sent meanwhile stays unanswered.
                    if let Some(sent) = base.checked_add(Duration::from_nanos(token))
                        && counters
                            .last_ping
                            .compare_exchange(token, 0, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        let rtt = Instant::now()
                            .saturating_duration_since(sent)
                            .saturating_sub(Duration::from_micros(hold_us.into()));
                        counters
                            .rtt_us
                            .store((rtt.as_micros() as u64).max(1), Ordering::Relaxed);
                        counters.rtt_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
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
    // Joined first, so no late report follows the reset.
    reporter.thread().unpark();
    let _ = reporter.join();
    log.traffic(0, 0, None);

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
    let last_client: Arc<Mutex<Option<(SocketAddr, Instant)>>> = Arc::default();
    let thread = {
        let (stop, password, active, last) = (stop.clone(), password.clone(), active.clone(), last_client.clone());
        std::thread::spawn(move || {
            if let Err(e) = server_main(&cfg, stop, password, active, last, &log) {
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
        last_client,
        link: Arc::default(),
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
    /// The last client whose session ended, and when (shared with TunnelHandle for the GUI).
    last_client: Arc<Mutex<Option<(SocketAddr, Instant)>>>,
    /// Held for the duration of a session (only one client at a time).
    session_slot: Mutex<()>,
}

fn server_main(
    cfg: &ServerConfig,
    stop: Arc<AtomicBool>,
    password: Arc<Mutex<String>>,
    active: Arc<Mutex<Option<ActiveSession>>>,
    last_client: Arc<Mutex<Option<(SocketAddr, Instant)>>>,
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
    if cfg.secure {
        log.info(format!(
            "Listening on TCP port {} (Secure: TLS 1.3 + password, certificate {}...).",
            cfg.port,
            identity.fingerprint_hex()
        ));
    } else {
        log.warn(format!(
            "Listening on TCP port {} in INSECURE mode: no encryption, no password.",
            cfg.port
        ));
    }

    let server = Arc::new(Server {
        identity,
        secure: cfg.secure,
        password,
        port,
        stop,
        log: log.clone(),
        abuse: Mutex::default(),
        handshakes: AtomicUsize::new(0),
        pending: Mutex::default(),
        active,
        last_client,
        session_slot: Mutex::new(()),
    });
    serve(listener, server)
}

/// The accept loop and the graceful stop. Separate from `server_main` (which opens the adapter
/// and the listener) so tests can run the real server over a stand-in adapter.
fn serve(listener: TcpListener, server: Arc<Server>) -> io::Result<()> {
    let stop = server.stop.clone();
    let log = server.log.clone();
    listener.set_nonblocking(true)?;
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
        // A live session is never taken away from its client: another client may only replace
        // a dead one (peer silent for STALE_SESSION). The same client (same id) may replace its
        // own session at once: it has given that connection up (it reconnects only after its
        // side failed), but the server may not have noticed yet, e.g. when the client's network
        // changed and no FIN/RST arrived. Waiting for STALE_SESSION there would stall the
        // traffic for up to ~18 s, long enough to break an ECU programming session.
        let client_id = auth.client_id();
        let old = {
            let mut active = self.active.lock().unwrap();
            match active.as_ref() {
                Some(cur) if cur.last_rx.lock().unwrap().elapsed() < STALE_SESSION && cur.client_id != client_id => {
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
            if old.client_id == client_id {
                self.log.info(format!(
                    "{peer}: the client reconnected; replacing its previous connection."
                ));
            } else {
                self.log
                    .info(format!("{peer} replaces the previous (unresponsive) client session."));
            }
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
            client_id,
            peer,
            since: Instant::now(),
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
        if a.as_ref().is_some_and(|s| Arc::ptr_eq(&s.stop, mine))
            && let Some(s) = a.take()
        {
            *self.last_client.lock().unwrap() = Some((s.peer, Instant::now()));
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
    let link: Arc<Mutex<ClientLink>> = Arc::default();
    let thread = {
        let (stop, sock, link) = (stop.clone(), sock.clone(), link.clone());
        std::thread::spawn(move || match client_main(&cfg, &stop, &sock, &link, &log) {
            // "Disconnected" alone = the user's own Disconnect; with a reason the GUI shows
            // the client as disconnected in a warning color.
            Ok(()) => log.status("Disconnected"),
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => log.status(format!("Disconnected - {e}")),
            // The reason (wrong password, Secure mismatch, adapter error...) also goes to the
            // status, where the GUI shows it next to "see log".
            Err(e) => {
                log.error(e.to_string());
                log.status(format!("Disconnected - error: {e}"));
            }
        })
    };
    TunnelHandle {
        stop,
        thread: Some(thread),
        password: Arc::default(),
        sock,
        active: Arc::default(),
        last_client: Arc::default(),
        link,
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
fn connect_and_auth(
    cfg: &ClientConfig,
    client_id: &proto::ClientId,
    stop: &AtomicBool,
    log: &Logger,
) -> io::Result<(SecureStream, SocketAddr)> {
    log.info(format!("Connecting to {}:{}...", cfg.host, cfg.port));
    let tcp = connect(&cfg.host, cfg.port, stop)?;
    let peer = tcp.peer_addr()?;
    configure_socket(&tcp)?;
    let killer = tcp.try_clone()?;
    let password = cfg.secure.then(|| secure::normalize_password(&cfg.password));
    let stream = with_deadline(&killer, HANDSHAKE_TIMEOUT, || {
        secure::client_handshake(tcp, password.as_deref(), client_id)
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
    client_id: &proto::ClientId,
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
        match connect_and_auth(cfg, client_id, stop, log) {
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
    link: &Mutex<ClientLink>,
    log: &Logger,
) -> io::Result<()> {
    log.status("Connecting...");
    // One id for this whole connection, reused by every reconnect, so the server lets this
    // client replace its own dead connection without waiting (see Server::handle).
    let client_id = secure::new_client_id();
    // Keep trying until the server is reachable (it may not be sharing yet, the network may be
    // down for a moment); only wrong password / Secure mismatch, or Disconnect, end this.
    let (mut stream, mut peer) = match retry_connect(cfg, &client_id, stop, log, "Server unreachable") {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    // The virtual adapter stays open across reconnects, so the OS keeps its link, IP and routes.
    let adapter = Arc::new(l2::open_client(cfg.mac, log)?);
    l2::prefer_local_networks(log);
    let ip_guard = Arc::new(Mutex::new(configure_client_ip(cfg.static_ipv4, log)));
    // Set when the client is closing: a reopen hook still running then must not configure the
    // adapter again (it runs on its own thread and can outlive this function).
    let closing = Arc::new(AtomicBool::new(false));
    {
        // A restarted adapter (driver restart, adapter disabled and enabled) comes back without
        // its route priority and addresses: set them up again. The old guard goes first, so a
        // static address is removed and added rather than left twice.
        let (ip_guard, closing, log, static_ipv4) = (ip_guard.clone(), closing.clone(), log.clone(), cfg.static_ipv4);
        adapter.set_on_reopen(move || {
            if closing.load(Ordering::SeqCst) {
                return;
            }
            l2::prefer_local_networks(&log);
            let mut guard = ip_guard.lock().unwrap();
            // Checked again under the lock that the teardown below also takes, so either this
            // hook configures before the teardown removes it, or it sees the flag and stops.
            if closing.load(Ordering::SeqCst) {
                return;
            }
            *guard = None;
            *guard = configure_client_ip(static_ipv4, &log);
        });
    }
    let port: Arc<dyn L2Port> = adapter.clone();

    let result = loop {
        log.status(format!("Connected to {peer} via '{}'", l2::client_adapter_name()));
        // Lets TunnelHandle::stop cut a stalled connection instead of waiting for timeouts.
        *sock.lock().unwrap() = stream.shutdown_handle().ok();
        {
            let mut l = link.lock().unwrap();
            (l.peer, l.since) = (Some(peer), Some(Instant::now()));
        }
        let end = run_session(stream, port.clone(), stop, None, log);
        link.lock().unwrap().since = None;
        match end {
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
        match retry_connect(cfg, &client_id, stop, log, "Connection lost") {
            None => {
                log.info("Disconnected.");
                break Ok(());
            }
            Some(Err(e)) => break Err(e),
            Some(Ok((s, p))) => {
                log.info("Reconnected; forwarding resumed.");
                (stream, peer) = (s, p);
                link.lock().unwrap().reconnects += 1;
            }
        }
    };
    // Remove the IP configuration while the adapter still exists, then close it. The flag first,
    // so a reopen hook still running does not configure it again.
    closing.store(true, Ordering::SeqCst);
    ip_guard.lock().unwrap().take();
    drop(port);
    drop(adapter);
    result
}

/// IPv4 on the client adapter: the static address, or DHCP. The guard undoes it when dropped.
fn configure_client_ip(static_ipv4: Option<(Ipv4Addr, u8)>, log: &Logger) -> Option<Box<dyn Send>> {
    match static_ipv4 {
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
    }
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

    /// A connected (server, client) pair in insecure mode, with the sockets configured as in
    /// the real server and client (TCP_NODELAY above all: without it Nagle's algorithm holds
    /// small messages such as a pong until the previous one is acknowledged).
    fn pair() -> (SecureStream, SecureStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let id = ServerIdentity::generate().unwrap();
            let (tcp, _) = listener.accept().unwrap();
            configure_socket(&tcp).unwrap();
            match secure::server_handshake(tcp, &id, None).unwrap() {
                ServerHandshake::Authenticated(a) => a.accept().unwrap(),
                ServerHandshake::WrongPassword => unreachable!(),
            }
        });
        let tcp = TcpStream::connect(addr).unwrap();
        configure_socket(&tcp).unwrap();
        let client = secure::client_handshake(tcp, None, &secure::new_client_id()).unwrap();
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
    fn latency_is_measured_through_the_tunnel() {
        let (s, c) = pair();
        let (log, events) = Logger::new(None);
        let stop = Arc::new(AtomicBool::new(false));
        let server = session(s, Arc::new(AtomicBool::new(false)));
        let client = {
            let stop = stop.clone();
            std::thread::spawn(move || run_session(c, Arc::new(NullPort), &stop, None, &log))
        };
        // One ping a second; the second report carries the first measurement.
        std::thread::sleep(Duration::from_millis(2300));
        stop.store(true, Ordering::SeqCst);
        assert!(matches!(client.join().unwrap(), End::Stopped));
        assert!(matches!(server.join().unwrap(), End::PeerClosed));
        let rtts: Vec<Duration> = events
            .try_iter()
            .filter_map(|e| match e {
                crate::log::Event::Traffic { rtt, .. } => rtt,
                _ => None,
            })
            .collect();
        assert!(!rtts.is_empty(), "no latency was reported");
        // Loopback: well under the 50 ms poll interval the pong may wait for, which is
        // reported by the peer and subtracted.
        assert!(rtts.iter().all(|r| *r < Duration::from_millis(20)), "{rtts:?}");
    }

    #[test]
    fn shown_latency_grows_while_a_ping_is_unanswered() {
        let ms = Duration::from_millis;
        assert_eq!(shown_rtt(0, None), None);
        assert_eq!(shown_rtt(5_000, None), Some(ms(5)));
        assert_eq!(shown_rtt(5_000, Some(ms(2))), Some(ms(5)));
        // A ping held up to 50 ms by the peer's adapter poll does not make the latency jump.
        assert_eq!(shown_rtt(5_000, Some(ms(60))), Some(ms(5)));
        assert_eq!(shown_rtt(5_000, Some(ms(1500))), Some(ms(1500)));
        assert_eq!(shown_rtt(0, Some(ms(800))), None);
        assert_eq!(shown_rtt(0, Some(ms(1500))), Some(ms(1500)));
    }

    /// The tunnel socket keeps OS-tuned buffers and, on Linux, a bounded not-yet-sent queue.
    #[cfg(target_os = "linux")]
    #[test]
    fn tunnel_socket_bounds_unsent_data() {
        use std::os::fd::AsRawFd;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        configure_socket(&tcp).unwrap();
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid descriptor; value and len are live and sized for the option.
        let r = unsafe {
            libc::getsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                &mut value as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(r, 0);
        assert_eq!(value, NOTSENT_LOWAT);
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

    // --- The real server under hostile traffic -------------------------------------------
    //
    // These run the actual accept loop, handshake limits, bans and session takeover rules
    // over loopback. The car side is a stand-in adapter that emits a frame every few ms; the
    // client counts what arrives, so "the session survived" means frames kept flowing the
    // whole time, not just that a thread is still alive. Attackers connect from other
    // loopback addresses (127.0.0.2 and up), so the per-IP limits apply as on a real network.

    /// The car side: a frame every ~5 ms, counts frames coming from the client.
    struct TickPort {
        seq: AtomicU64,
    }

    impl L2Port for TickPort {
        fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
            std::thread::sleep(timeout.min(Duration::from_millis(5)));
            let n = self.seq.fetch_add(1, Ordering::Relaxed);
            let mut f = vec![0u8; 60];
            f[..8].copy_from_slice(&n.to_be_bytes());
            out.push(f);
            Ok(())
        }
        fn send(&self, _frames: &[Vec<u8>]) -> io::Result<()> {
            Ok(())
        }
    }

    /// The client's virtual adapter: counts frames delivered from the server.
    struct CountPort(Arc<AtomicU64>);

    impl L2Port for CountPort {
        fn recv(&self, _out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
            Ok(())
        }
        fn send(&self, frames: &[Vec<u8>]) -> io::Result<()> {
            self.0.fetch_add(frames.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    struct TestServer {
        addr: SocketAddr,
        password: String,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<io::Result<()>>>,
        active: Arc<Mutex<Option<ActiveSession>>>,
        log: std::sync::mpsc::Receiver<crate::log::Event>,
    }

    impl TestServer {
        fn start() -> TestServer {
            TestServer::start_with(true)
        }

        fn start_with(secure: bool) -> TestServer {
            let (log, rx) = Logger::new(None);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let password = secure::generate_password();
            let stop = Arc::new(AtomicBool::new(false));
            let active: Arc<Mutex<Option<ActiveSession>>> = Arc::default();
            let port = ResilientPort::open(
                "test",
                Box::new(|| Ok(Box::new(TickPort { seq: AtomicU64::new(0) }) as Box<dyn L2Port>)),
                &log,
            )
            .unwrap();
            let server = Arc::new(Server {
                identity: ServerIdentity::generate().unwrap(),
                secure,
                password: Arc::new(Mutex::new(password.clone())),
                port: Arc::new(port),
                stop: stop.clone(),
                log,
                abuse: Mutex::default(),
                handshakes: AtomicUsize::new(0),
                pending: Mutex::default(),
                active: active.clone(),
                last_client: Arc::default(),
                session_slot: Mutex::new(()),
            });
            let thread = std::thread::spawn(move || serve(listener, server));
            TestServer {
                addr,
                password,
                stop,
                thread: Some(thread),
                active,
                log: rx,
            }
        }

        /// Log lines written so far.
        fn log_lines(&self) -> Vec<String> {
            self.log
                .try_iter()
                .filter_map(|e| match e {
                    crate::log::Event::Log(l) => Some(l.message),
                    _ => None,
                })
                .collect()
        }

        /// Identity of the running session (its stop flag), to tell it was not replaced.
        fn session_id(&self) -> Option<usize> {
            self.active
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| Arc::as_ptr(&s.stop) as usize)
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// A TCP connection to `addr` from the loopback source address `src` (e.g. "127.0.0.2").
    fn connect_from(src: &str, addr: SocketAddr) -> io::Result<TcpStream> {
        use socket2::{Domain, Socket, Type};
        let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        s.bind(&SocketAddr::new(src.parse().unwrap(), 0).into())?;
        s.connect_timeout(&addr.into(), Duration::from_secs(2))?;
        Ok(s.into())
    }

    /// Authenticates from `src` with `password` as a new client (fresh id).
    fn handshake_from(src: &str, addr: SocketAddr, password: &str) -> io::Result<SecureStream> {
        handshake_as(src, addr, password, &secure::new_client_id())
    }

    /// Authenticates like the real client does, with a given client id.
    fn handshake_as(src: &str, addr: SocketAddr, password: &str, id: &proto::ClientId) -> io::Result<SecureStream> {
        let tcp = connect_from(src, addr)?;
        configure_socket(&tcp)?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        secure::client_handshake(tcp, Some(password), id)
    }

    struct TestClient {
        received: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        /// Cuts the connection like a dead link (no Close message).
        cut: TcpStream,
        thread: std::thread::JoinHandle<End>,
    }

    impl TestClient {
        fn connect(srv: &TestServer) -> TestClient {
            TestClient::connect_as(srv, &secure::new_client_id())
        }

        fn connect_as(srv: &TestServer, id: &proto::ClientId) -> TestClient {
            let stream = handshake_as("127.0.0.1", srv.addr, &srv.password, id).expect("client handshake");
            let cut = stream.shutdown_handle().unwrap();
            let received = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (port, stop) = (Arc::new(CountPort(received.clone())), stop.clone());
                std::thread::spawn(move || run_session(stream, port, &stop, None, &Logger::new(None).0))
            };
            let c = TestClient {
                received,
                stop,
                cut,
                thread,
            };
            c.assert_flowing("after connecting");
            c
        }

        /// Frames from the car keep arriving.
        fn assert_flowing(&self, when: &str) {
            let before = self.received.load(Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(300));
            let after = self.received.load(Ordering::Relaxed);
            assert!(
                after > before + 10,
                "traffic stalled {when}: {before} -> {after} frames"
            );
            assert!(!self.thread.is_finished(), "session ended {when}");
        }

        fn disconnect(self) -> End {
            self.stop.store(true, Ordering::SeqCst);
            self.thread.join().unwrap()
        }
    }

    /// Runs `attack` on several threads while checking every 300 ms that traffic still flows.
    fn under_attack(client: &TestClient, attackers: Vec<Box<dyn FnOnce() + Send>>) {
        let handles: Vec<_> = attackers.into_iter().map(std::thread::spawn).collect();
        while !handles.iter().all(|h| h.is_finished()) {
            client.assert_flowing("during the attack");
        }
        for h in handles {
            h.join().unwrap();
        }
        client.assert_flowing("after the attack");
    }

    #[test]
    fn session_survives_port_scans_and_garbage() {
        let srv = TestServer::start();
        let client = TestClient::connect(&srv);
        let session = srv.session_id();
        let addr = srv.addr;
        let send_and_close = move |src: &'static str, payload: Vec<u8>| {
            move || {
                for _ in 0..10 {
                    if let Ok(mut s) = connect_from(src, addr) {
                        use std::io::Write;
                        let _ = s.write_all(&payload);
                    }
                }
            }
        };
        let attackers: Vec<Box<dyn FnOnce() + Send>> = vec![
            // Port scan: connect and drop at once.
            Box::new(send_and_close("127.0.0.2", Vec::new())),
            // HTTP probe.
            Box::new(send_and_close(
                "127.0.0.3",
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            )),
            // Random bytes, and bytes that look like a TLS record but are not.
            Box::new(send_and_close(
                "127.0.0.4",
                (0..4096u32).map(|i| (i * 7919) as u8).collect(),
            )),
            Box::new(send_and_close(
                "127.0.0.5",
                [&[0x16, 0x03, 0x01, 0xff, 0xff][..], &[0xAB; 600]].concat(),
            )),
            // Plain-mode hello against a Secure server, and a bogus magic.
            Box::new(send_and_close("127.0.0.6", b"EETHR-P1\x00\x01".to_vec())),
            Box::new(send_and_close("127.0.0.7", b"EETHR-XX\x00\x01junk".to_vec())),
            // Slow connections holding every handshake slot for a while, from several IPs.
            Box::new(move || {
                let held: Vec<_> = (10..16)
                    .flat_map(|i| (0..3).map(move |_| i))
                    .filter_map(|i| connect_from(&format!("127.0.0.{i}"), addr).ok())
                    .collect();
                std::thread::sleep(Duration::from_millis(1500));
                drop(held);
            }),
        ];
        under_attack(&client, attackers);
        assert_eq!(srv.session_id(), session, "the session was replaced");
        assert!(matches!(client.disconnect(), End::Stopped));
    }

    #[test]
    fn wrong_passwords_and_a_second_client_cannot_take_over() {
        let srv = TestServer::start();
        let client = TestClient::connect(&srv);
        let session = srv.session_id();
        let (addr, password) = (srv.addr, srv.password.clone());
        let attackers: Vec<Box<dyn FnOnce() + Send>> = vec![
            // Guessing: banned after 5 tries, later attempts are dropped.
            Box::new(move || {
                for _ in 0..8 {
                    assert!(handshake_from("127.0.0.2", addr, "aaaaaaaa").is_err());
                }
            }),
            // Someone else who knows the password: refused while the client is active.
            Box::new(move || {
                for _ in 0..3 {
                    let e = handshake_from("127.0.0.3", addr, &password)
                        .err()
                        .expect("second client accepted");
                    assert!(e.to_string().contains("already has a client"), "unexpected: {e}");
                    assert!(!secure::is_fatal_handshake_error(&e));
                }
            }),
        ];
        under_attack(&client, attackers);
        assert_eq!(srv.session_id(), session, "the session was replaced");
        let log = srv.log_lines();
        assert!(
            log.iter().any(|l| l.contains("127.0.0.2 blocked")),
            "no ban logged: {log:?}"
        );
        assert!(!log.iter().any(|l| l.contains("127.0.0.1 blocked")));
        assert!(matches!(client.disconnect(), End::Stopped));
    }

    #[test]
    fn client_reconnects_at_once_after_its_link_was_cut() {
        let srv = TestServer::start();
        let first = TestClient::connect(&srv);
        // A broken link the server notices (reset / FIN): no Close message is sent, so the
        // client treats it as a loss and reconnects, and the server must free the slot for it.
        first.cut.shutdown(std::net::Shutdown::Both).unwrap();
        let started = Instant::now();
        assert!(matches!(first.thread.join().unwrap(), End::Peer(_)));
        let second = TestClient::connect(&srv);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "reconnect took {:?}",
            started.elapsed()
        );
        assert!(matches!(second.disconnect(), End::Stopped));
    }

    #[test]
    fn same_client_takes_over_its_live_looking_session_at_once() {
        // The client's network changed: its side failed and it reconnects, while the server
        // still sees the old connection as alive (no FIN/RST arrived). Here the old session is
        // even still running, the harshest form of that.
        let srv = TestServer::start();
        let id = secure::new_client_id();
        let old = TestClient::connect_as(&srv, &id);
        let old_session = srv.session_id();
        let started = Instant::now();
        let new = TestClient::connect_as(&srv, &id);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "takeover took {:?}",
            started.elapsed()
        );
        assert_ne!(srv.session_id(), old_session, "the old session was not replaced");
        // The old connection is ended by the server (with Close), the new one carries traffic.
        assert!(matches!(old.thread.join().unwrap(), End::PeerClosed | End::Peer(_)));
        new.assert_flowing("after the takeover");
        assert!(srv.log_lines().iter().any(|l| l.contains("the client reconnected")));
        assert!(matches!(new.disconnect(), End::Stopped));
    }

    #[test]
    fn other_protocol_version_is_told_to_update() {
        // A client speaking another protocol version gets a clear, final answer instead of a
        // hang or a reset, so it stops retrying.
        use std::io::Write;
        let srv = TestServer::start_with(false);
        let mut tcp = connect_from("127.0.0.1", srv.addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let other = proto::VERSION + 1;
        tcp.write_all(&[&b"EETHR-P1"[..], &other.to_be_bytes()].concat())
            .unwrap();
        let e = proto::read_hello(&mut tcp, proto::MAGIC_SERVER).unwrap_err();
        assert!(
            e.to_string().contains(&format!("Unsupported protocol version {other}")),
            "unexpected: {e}"
        );
        assert!(secure::is_fatal_handshake_error(&e));
    }
}
