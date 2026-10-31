//! TLS transport plus password authentication.
//!
//! The server presents a fresh self-signed certificate. The client accepts any certificate,
//! but both sides then run SPAKE2 on the 8-character password and exchange HMAC confirmations
//! bound to the certificate fingerprint. A wrong password or a man-in-the-middle (which
//! would present a different certificate) makes the confirmation fail, and the password
//! cannot be brute-forced offline from what goes over the wire.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use ring::rand::SecureRandom;
use ring::{digest, hmac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, Connection, DigitallySignedStruct, ServerConfig};
use rustls::{ServerConnection, SignatureScheme, StreamOwned};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::proto::{self, ClientId};

const SPAKE_ID: &[u8] = b"easyether-v1";
/// Appended to a TLS protocol error when the server is probably not in Secure mode.
pub const SECURE_MISMATCH_HINT: &str = "is \"Secure\" set the same way on both computers?";

/// Errors a reconnect cannot fix: wrong password, different Secure settings on the two sides,
/// incompatible protocol version, or an address that cannot be parsed.
pub fn is_fatal_handshake_error(e: &io::Error) -> bool {
    let msg = e.to_string();
    match e.kind() {
        // Explicit messages from the server (not the transient "busy" one).
        io::ErrorKind::PermissionDenied => {
            msg.contains("Wrong password") || msg.contains("Secure mode") || msg.contains("protocol version")
        }
        io::ErrorKind::InvalidData => msg.contains(SECURE_MISMATCH_HINT),
        // Bad IPv6 literal / unknown zone typed by the user.
        io::ErrorKind::InvalidInput => true,
        _ => msg.contains("unsupported protocol version"),
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Fills `buf` from the OS random generator (through ring, which rustls already uses).
pub fn random_fill(buf: &mut [u8]) {
    ring::rand::SystemRandom::new().fill(buf).expect("OS random generator");
}

fn sha256(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

const PASSWORD_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub const PASSWORD_LEN: usize = 8;

/// Generates a random 8-character password from `0-9a-z` (36^8 ≈ 2.8e12 combinations).
pub fn generate_password() -> String {
    let mut out = String::with_capacity(PASSWORD_LEN);
    let mut b = [0u8; 64];
    while out.len() < PASSWORD_LEN {
        random_fill(&mut b);
        // Rejection sampling keeps every character equally likely (252 = 7 * 36).
        for &x in b.iter().filter(|&&x| x < 252) {
            if out.len() == PASSWORD_LEN {
                break;
            }
            out.push(PASSWORD_ALPHABET[(x % 36) as usize] as char);
        }
    }
    out
}

/// Lower-cases and strips spaces and dashes, so "ABCD 1234" and "abcd-1234" are accepted.
pub fn normalize_password(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Groups a password for display: "abcd1234" -> "abcd 1234".
pub fn display_password(pw: &str) -> String {
    if pw.chars().count() == PASSWORD_LEN {
        let (a, b): (String, String) = (pw.chars().take(4).collect(), pw.chars().skip(4).collect());
        format!("{a} {b}")
    } else {
        pw.to_string()
    }
}

/// Server identity created once per "Share" session.
pub struct ServerIdentity {
    config: Arc<ServerConfig>,
    fingerprint: [u8; 32],
}

impl ServerIdentity {
    pub fn generate() -> io::Result<ServerIdentity> {
        let ck = rcgen::generate_simple_self_signed(vec!["easyether".to_string()]).map_err(other)?;
        let cert: CertificateDer<'static> = ck.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let fingerprint = sha256(cert.as_ref());
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(other)?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(other)?;
        Ok(ServerIdentity {
            config: Arc::new(config),
            fingerprint,
        })
    }

    pub fn fingerprint_hex(&self) -> String {
        crate::l2::format_mac(&self.fingerprint[..8])
    }
}

/// Confirmation message: role followed by the certificate fingerprint.
fn confirmation_msg(role: &[u8], fingerprint: &[u8; 32]) -> Vec<u8> {
    [role, fingerprint.as_slice()].concat()
}

/// HMAC-SHA256(key, role ‖ fingerprint).
fn confirmation(key: &[u8], role: &[u8], fingerprint: &[u8; 32]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, &confirmation_msg(role, fingerprint)).as_ref().to_vec()
}

/// Constant-time check of a peer's confirmation tag.
fn confirmation_ok(key: &[u8], role: &[u8], fingerprint: &[u8; 32], tag: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&key, &confirmation_msg(role, fingerprint), tag).is_ok()
}

/// Outcome of the server-side handshake.
pub enum ServerHandshake {
    Authenticated(Authenticated),
    WrongPassword,
}

/// A client that passed the handshake (and proved it knows the password in Secure mode);
/// the server still decides whether to admit it.
pub enum Authenticated {
    Tls {
        s: Box<StreamOwned<ServerConnection, TcpStream>>,
        server_tag: Vec<u8>,
        client_id: ClientId,
    },
    Plain {
        tcp: TcpStream,
        client_id: ClientId,
    },
}

impl Authenticated {
    /// The client's id: the same for all reconnects of one client run.
    pub fn client_id(&self) -> ClientId {
        match self {
            Authenticated::Tls { client_id, .. } | Authenticated::Plain { client_id, .. } => *client_id,
        }
    }

    /// Sends the final confirmation and switches to frame exchange.
    pub fn accept(self) -> io::Result<SecureStream> {
        match self {
            Authenticated::Tls { mut s, server_tag, .. } => {
                proto::write_tagged(&mut *s, proto::MAGIC_OK, &server_tag)?;
                let s = *s;
                SecureStream::new(Some(Connection::Server(s.conn)), s.sock)
            }
            Authenticated::Plain { mut tcp, .. } => {
                proto::write_tagged(&mut tcp, proto::MAGIC_OK, &[])?;
                SecureStream::new(None, tcp)
            }
        }
    }

    pub fn reject(self, message: &str) {
        let _ = match self {
            Authenticated::Tls { mut s, .. } => proto::write_error(&mut *s, message),
            Authenticated::Plain { mut tcp, .. } => proto::write_error(&mut tcp, message),
        };
    }
}

fn read_client_id(r: &mut impl Read) -> io::Result<ClientId> {
    let mut id = ClientId::default();
    r.read_exact(&mut id)?;
    Ok(id)
}

/// A fresh random client id, made once per client run.
pub fn new_client_id() -> ClientId {
    let mut id = ClientId::default();
    random_fill(&mut id);
    id
}

/// Server handshake. `password: None` is the insecure mode (plain TCP, no password).
/// The first byte tells a TLS ClientHello (0x16) from a plain hello, so a mismatch between
/// the two sides' Secure settings gets a clear message instead of garbage.
pub fn server_handshake(tcp: TcpStream, id: &ServerIdentity, password: Option<&str>) -> io::Result<ServerHandshake> {
    let mut first = [0u8; 1];
    if tcp.peek(&mut first)? == 0 {
        return Err(other("connection closed"));
    }
    let is_tls = first[0] == 0x16;
    let password = match (password, is_tls) {
        (Some(pw), true) => pw,
        (Some(_), false) => {
            let mut tcp = tcp;
            if proto::read_hello(&mut tcp, proto::MAGIC_CLIENT_PLAIN).is_ok() {
                let _ = proto::write_error(
                    &mut tcp,
                    "This computer shares in Secure mode. Enable \"Secure\" and enter the password.",
                );
            }
            return Err(other("client tried to connect without Secure mode"));
        }
        (None, false) => {
            let mut tcp = tcp;
            let ver = proto::read_hello(&mut tcp, proto::MAGIC_CLIENT_PLAIN)?;
            if ver != proto::VERSION {
                proto::write_error(
                    &mut tcp,
                    &format!("Unsupported protocol version {ver}; please update EasyEther."),
                )?;
                return Err(other(format!("client uses unsupported protocol version {ver}")));
            }
            // The client sends its id only after this hello, so every error above is written
            // with nothing unread on the socket (unread data turns the close into RST, which
            // Windows lets discard the reply before the client reads it).
            proto::write_hello(&mut tcp, proto::MAGIC_SERVER)?;
            let client_id = read_client_id(&mut tcp)?;
            return Ok(ServerHandshake::Authenticated(Authenticated::Plain { tcp, client_id }));
        }
        // A TLS client cannot read this text, but the non-TLS bytes make its TLS layer fail
        // with a protocol error (rather than a bare EOF), which it reports as a Secure mismatch.
        (None, true) => {
            let mut tcp = tcp;
            let _ = proto::write_error(&mut tcp, "This computer shares without Secure mode.");
            // Drain the unread ClientHello before closing: closing with unread data makes the
            // kernel send RST, which could discard our reply before the client reads it.
            let _ = tcp.shutdown(std::net::Shutdown::Write);
            let _ = tcp.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let mut sink = [0u8; 4096];
            while matches!(tcp.read(&mut sink), Ok(n) if n > 0) {}
            return Err(other("client uses Secure mode, but sharing is not secure"));
        }
    };

    let mut conn = ServerConnection::new(id.config.clone()).map_err(other)?;
    // A frame batch can be 410 KiB; rustls' default 64 KiB plaintext buffer would make
    // write_all fail. We drain the TLS output right after every write anyway.
    conn.set_buffer_limit(None);
    let mut s = StreamOwned::new(conn, tcp);
    let ver = proto::read_hello(&mut s, proto::MAGIC_CLIENT)?;
    if ver != proto::VERSION {
        proto::write_error(
            &mut s,
            &format!("Unsupported protocol version {ver}; please update EasyEther."),
        )?;
        return Err(other(format!("client uses unsupported protocol version {ver}")));
    }
    proto::write_hello(&mut s, proto::MAGIC_SERVER)?;

    let (spake, outbound) =
        Spake2::<Ed25519Group>::start_symmetric(&Password::new(password.as_bytes()), &Identity::new(SPAKE_ID));
    let inbound = proto::read_blob(&mut s)?;
    proto::write_blob(&mut s, &outbound)?;
    let key = spake.finish(&inbound).map_err(|e| other(format!("SPAKE2: {e:?}")))?;

    let mut client_tag = [0u8; 32];
    s.read_exact(&mut client_tag)?;
    // Read with the tag, before checking it: it is sent together with the tag, and closing
    // with it unread would make the kernel send RST, which can discard the "Wrong password"
    // reply below before the client reads it (the client would then keep retrying). It is
    // only used once the password is proven.
    let client_id = read_client_id(&mut s)?;
    if !confirmation_ok(&key, b"client", &id.fingerprint, &client_tag) {
        // Slow down guessing; the caller counts failures.
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = proto::write_error(&mut s, "Wrong password.");
        return Ok(ServerHandshake::WrongPassword);
    }
    let server_tag = confirmation(&key, b"server", &id.fingerprint);
    Ok(ServerHandshake::Authenticated(Authenticated::Tls {
        s: Box::new(s),
        server_tag,
        client_id,
    }))
}

/// Client handshake. `password: None` is the insecure mode (plain TCP, no password).
/// `client_id` stays the same across this client's reconnects (see `new_client_id`).
pub fn client_handshake(tcp: TcpStream, password: Option<&str>, client_id: &ClientId) -> io::Result<SecureStream> {
    let Some(password) = password else {
        let mut tcp = tcp;
        proto::write_hello(&mut tcp, proto::MAGIC_CLIENT_PLAIN)?;
        let ver = proto::read_hello(&mut tcp, proto::MAGIC_SERVER)?;
        if ver != proto::VERSION {
            return Err(other(format!("server uses unsupported protocol version {ver}")));
        }
        tcp.write_all(client_id)?;
        proto::read_tag(&mut tcp, proto::MAGIC_OK)?;
        return SecureStream::new(None, tcp);
    };
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider().signature_verification_algorithms)))
        .with_no_client_auth();
    let name = ServerName::try_from("easyether").map_err(other)?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(other)?;
    conn.set_buffer_limit(None);
    let mut s = StreamOwned::new(conn, tcp);

    // The TLS handshake happens here. A TLS protocol error (InvalidData) at this point means
    // the other side answered with something that is not TLS, i.e. it is not in Secure mode.
    // Other errors (reset, EOF, timeout) are ordinary connection failures.
    let ver = proto::write_hello(&mut s, proto::MAGIC_CLIENT)
        .and_then(|_| proto::read_hello(&mut s, proto::MAGIC_SERVER))
        .map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidData {
                io::Error::new(e.kind(), format!("{e} ({SECURE_MISMATCH_HINT})"))
            } else {
                e
            }
        })?;
    if ver != proto::VERSION {
        return Err(other(format!("server uses unsupported protocol version {ver}")));
    }
    let fingerprint: [u8; 32] = match s.conn.peer_certificates().and_then(|c| c.first()) {
        Some(cert) => sha256(cert.as_ref()),
        None => return Err(other("server did not present a certificate")),
    };

    let (spake, outbound) =
        Spake2::<Ed25519Group>::start_symmetric(&Password::new(password.as_bytes()), &Identity::new(SPAKE_ID));
    proto::write_blob(&mut s, &outbound)?;
    let inbound = proto::read_blob(&mut s)?;
    let key = spake.finish(&inbound).map_err(|e| other(format!("SPAKE2: {e:?}")))?;

    let client_tag = confirmation(&key, b"client", &fingerprint);
    s.write_all(&client_tag)?;
    s.write_all(client_id)?;
    s.flush()?;
    proto::read_tag(&mut s, proto::MAGIC_OK)?;
    let mut server_tag = [0u8; 32];
    s.read_exact(&mut server_tag)?;
    if !confirmation_ok(&key, b"server", &fingerprint, &server_tag) {
        return Err(other(
            "the server could not prove it knows the password (possible man-in-the-middle)",
        ));
    }
    SecureStream::new(Some(Connection::Client(s.conn)), s.sock)
}

/// Accepts any server certificate: authentication is done by the SPAKE2 exchange above,
/// which is bound to the certificate fingerprint. Signatures are still checked so the
/// TLS session really belongs to the presented certificate.
#[derive(Debug)]
struct AnyCert(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// The session transport, usable from two threads at once: one thread blocks in `recv`
/// while the other calls `send`. With TLS, the rustls state is only locked for in-memory
/// work, never across blocking socket I/O; socket writes are serialized so TLS records stay
/// in order. Without TLS (insecure mode) data goes straight to the socket.
pub struct SecureStream {
    conn: Option<Mutex<Connection>>,
    /// Write side with its reusable TLS output buffer (no per-batch allocation).
    write_sock: Mutex<(TcpStream, Vec<u8>)>,
    /// Read side with its reusable raw input buffer.
    read_sock: Mutex<(TcpStream, Vec<u8>)>,
    shutdown_sock: TcpStream,
}

/// Moves all plaintext rustls has deframed into `out`.
fn drain_plaintext(conn: &mut Connection, out: &mut Vec<u8>) -> io::Result<()> {
    // read_to_end keeps what it appended before reporting WouldBlock (= nothing more buffered).
    match conn.reader().read_to_end(out) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

impl SecureStream {
    fn new(conn: Option<Connection>, sock: TcpStream) -> io::Result<SecureStream> {
        Ok(SecureStream {
            conn: conn.map(Mutex::new),
            write_sock: Mutex::new((sock.try_clone()?, Vec::new())),
            shutdown_sock: sock.try_clone()?,
            read_sock: Mutex::new((sock, vec![0u8; 64 * 1024])),
        })
    }

    /// Unblocks both directions; used to stop a session.
    pub fn shutdown(&self) {
        let _ = self.shutdown_sock.shutdown(std::net::Shutdown::Both);
    }

    /// A socket handle that can cut this connection from another thread.
    pub fn shutdown_handle(&self) -> io::Result<TcpStream> {
        self.shutdown_sock.try_clone()
    }

    /// Sends `data` (encrypted in Secure mode).
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut guard = self.write_sock.lock().unwrap();
        let (sock, out) = &mut *guard;
        let Some(conn) = &self.conn else {
            return sock.write_all(data);
        };
        out.clear();
        {
            let mut conn = conn.lock().unwrap();
            conn.writer().write_all(data)?;
            while conn.wants_write() {
                conn.write_tls(out)?;
            }
        }
        sock.write_all(out)
    }

    /// Flushes TLS records rustls queued on its own (alerts, key updates).
    fn flush_pending(&self, conn: &Mutex<Connection>) -> io::Result<()> {
        let mut guard = self.write_sock.lock().unwrap();
        let (sock, out) = &mut *guard;
        out.clear();
        {
            let mut conn = conn.lock().unwrap();
            while conn.wants_write() {
                conn.write_tls(out)?;
            }
        }
        if !out.is_empty() {
            sock.write_all(out)?;
        }
        Ok(())
    }

    /// Blocks until some plaintext arrives and appends it to `out`. Returns `Ok(0)` on EOF.
    pub fn recv(&self, out: &mut Vec<u8>) -> io::Result<usize> {
        let mut guard = self.read_sock.lock().unwrap();
        let (sock, raw) = &mut *guard;
        // Plaintext rustls already deframed (e.g. a batch that arrived together with the last
        // handshake message) must be delivered before blocking on the socket.
        if let Some(tls) = &self.conn {
            let before = out.len();
            drain_plaintext(&mut tls.lock().unwrap(), out)?;
            if out.len() > before {
                return Ok(out.len() - before);
            }
        }
        loop {
            let n = sock.read(raw)?;
            if n == 0 {
                return Ok(0);
            }
            let Some(tls) = &self.conn else {
                out.extend_from_slice(&raw[..n]);
                return Ok(n);
            };
            let before = out.len();
            let needs_flush = {
                let mut conn = tls.lock().unwrap();
                let mut input = &raw[..n];
                while !input.is_empty() {
                    if conn.read_tls(&mut input)? == 0 {
                        break;
                    }
                    conn.process_new_packets().map_err(other)?;
                    // Drain plaintext every round so rustls' buffer never fills up.
                    drain_plaintext(&mut conn, out)?;
                }
                conn.wants_write()
            };
            if needs_flush {
                self.flush_pending(tls)?;
            }
            if out.len() > before {
                return Ok(out.len() - before);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn digest_and_hmac_known_answers() {
        // FIPS 180-2 "abc".
        assert_eq!(
            sha256(b"abc"),
            *b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\
               \xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"
        );
        // HMAC over role ‖ fingerprint, the same bytes the earlier streaming version hashed.
        let fp = sha256(b"cert");
        let tag = confirmation(b"key", b"client", &fp);
        assert_eq!(tag.len(), 32);
        assert!(confirmation_ok(b"key", b"client", &fp, &tag));
        assert!(!confirmation_ok(b"key", b"server", &fp, &tag));
        assert!(!confirmation_ok(b"other", b"client", &fp, &tag));
        // RFC 4231 test case 2 through the same ring API.
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        assert_eq!(
            hmac::sign(&key, b"what do ya want for nothing?").as_ref(),
            b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\
              \x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43"
        );
    }

    fn run(server_pw: Option<&str>, client_pw: Option<&str>) -> (io::Result<bool>, io::Result<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_pw = server_pw.map(str::to_string);
        let server = std::thread::spawn(move || {
            let id = ServerIdentity::generate().unwrap();
            let (tcp, _) = listener.accept().unwrap();
            match server_handshake(tcp, &id, server_pw.as_deref())? {
                ServerHandshake::Authenticated(a) => {
                    let s = a.accept()?;
                    let mut buf = Vec::new();
                    s.recv(&mut buf)?;
                    s.send(&buf)?;
                    Ok(true)
                }
                ServerHandshake::WrongPassword => Ok(false),
            }
        });
        let client = (|| {
            let s = client_handshake(TcpStream::connect(addr)?, client_pw, &new_client_id())?;
            s.send(b"ping")?;
            let mut buf = Vec::new();
            while buf.len() < 4 {
                s.recv(&mut buf)?;
            }
            assert_eq!(buf, b"ping");
            Ok(())
        })();
        (server.join().unwrap(), client)
    }

    #[test]
    fn correct_password_connects() {
        let (server, client) = run(Some("12345678"), Some("12345678"));
        assert!(server.unwrap());
        client.unwrap();
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (server, client) = run(Some("12345678"), Some("87654321"));
        assert!(!server.unwrap());
        assert_eq!(client.unwrap_err().to_string(), "Wrong password.");
    }

    /// Regression: rustls' default 64 KiB buffer limit made a full 410 KB frame batch fail.
    #[test]
    fn large_message_round_trip_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload: Vec<u8> = (0..crate::proto::MAX_PAYLOAD + 4).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let server = std::thread::spawn(move || {
            let id = ServerIdentity::generate().unwrap();
            let (tcp, _) = listener.accept().unwrap();
            let ServerHandshake::Authenticated(a) = server_handshake(tcp, &id, Some("abcd1234")).unwrap() else {
                panic!("wrong password")
            };
            let s = a.accept().unwrap();
            s.send(&payload).unwrap();
            let mut echo = Vec::new();
            while echo.len() < payload.len() {
                assert!(s.recv(&mut echo).unwrap() > 0);
            }
            assert_eq!(echo, payload);
        });
        let c = client_handshake(TcpStream::connect(addr).unwrap(), Some("abcd1234"), &new_client_id()).unwrap();
        let mut got = Vec::new();
        while got.len() < expected.len() {
            assert!(c.recv(&mut got).unwrap() > 0);
        }
        assert_eq!(got, expected);
        c.send(&got).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn insecure_mode_connects() {
        let (server, client) = run(None, None);
        assert!(server.unwrap());
        client.unwrap();
    }

    #[test]
    fn insecure_client_gets_a_clear_message_from_secure_server() {
        let (server, client) = run(Some("12345678"), None);
        assert!(server.is_err());
        assert!(client.unwrap_err().to_string().contains("Secure mode"));
    }

    #[test]
    fn secure_client_against_insecure_server_fails_with_hint() {
        let (server, client) = run(None, Some("12345678"));
        assert!(server.is_err());
        assert!(client.unwrap_err().to_string().contains("\"Secure\""));
    }

    #[test]
    fn password_helpers() {
        let pw = generate_password();
        assert_eq!(pw.len(), 8);
        assert!(pw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(normalize_password(" AbCd-12 34 "), "abcd1234");
        assert_eq!(display_password("abcd1234"), "abcd 1234");
        // Non-ASCII input must not panic (byte 4 is inside a multi-byte char here).
        assert_eq!(display_password("aąąąb"), "aąąąb");
        assert!(is_fatal_handshake_error(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad address"
        )));
        assert!(!is_fatal_handshake_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "busy"
        )));
    }
}
