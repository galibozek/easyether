//! EasyEther wire protocol (all integers big-endian).
//!
//! Insecure mode (plain TCP, no password):
//!   C -> S  hello   "EETHR-P1" u16 version
//!   S -> C  hello   "EETHR-S1" u16 version          | error
//!
//! Secure mode handshake (inside TLS):
//!   C -> S  hello   "EETHR-C1" u16 version
//!   S -> C  hello   "EETHR-S1" u16 version          | error
//!   C -> S  spake   u16 len, bytes
//!   S -> C  spake   u16 len, bytes
//!   C -> S  confirm 32 bytes HMAC(key, "client" || cert fingerprint)
//!   S -> C  "EETHR-OK" + 32 bytes HMAC(key, "server" || cert fingerprint) | error
//!
//! error  = "EETHR-ER" u16 len, UTF-8 message
//!
//! After the handshake both sides exchange frame batches:
//!   u32 payload_len | u16 count (0..=256) | count * [u16 len | frame]
//! A batch with count 0 is a keepalive. Count 0xFFFF (no frames) is "Close": the peer ends the
//! session on purpose (Stop / Disconnect), so the client does not try to reconnect.

use std::io::{self, Read, Write};

pub const MAGIC_CLIENT: &[u8; 8] = b"EETHR-C1";
/// Client hello in insecure mode (plain TCP, no TLS, no password).
pub const MAGIC_CLIENT_PLAIN: &[u8; 8] = b"EETHR-P1";
pub const MAGIC_SERVER: &[u8; 8] = b"EETHR-S1";
pub const MAGIC_OK: &[u8; 8] = b"EETHR-OK";
pub const MAGIC_ERROR: &[u8; 8] = b"EETHR-ER";
pub const VERSION: u16 = 1;

pub const MIN_FRAME: usize = 14;
pub const MAX_FRAME: usize = 1600;
pub const MAX_BATCH: usize = 256;
pub const MAX_PAYLOAD: usize = 2 + MAX_BATCH * (2 + MAX_FRAME);
const MAX_MESSAGE: usize = 4096;
const CLOSE_COUNT: u16 = 0xFFFF;

/// What `BatchDecoder::next` found.
#[derive(Debug, PartialEq, Eq)]
pub enum Msg {
    /// A frame batch (frames were appended; none for a keepalive).
    Batch,
    /// The peer is closing the session on purpose.
    Close,
}

/// The "Close" message.
pub fn encode_close(out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&CLOSE_COUNT.to_be_bytes());
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn write_tagged(w: &mut impl Write, tag: &[u8; 8], body: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(10 + body.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

pub fn write_hello(w: &mut impl Write, magic: &[u8; 8]) -> io::Result<()> {
    write_tagged(w, magic, &VERSION.to_be_bytes())
}

pub fn write_error(w: &mut impl Write, message: &str) -> io::Result<()> {
    let msg = &message.as_bytes()[..message.len().min(MAX_MESSAGE)];
    let mut body = (msg.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(msg);
    write_tagged(w, MAGIC_ERROR, &body)
}

pub fn write_blob(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let mut buf = (data.len() as u16).to_be_bytes().to_vec();
    buf.extend_from_slice(data);
    w.write_all(&buf)?;
    w.flush()
}

pub fn read_blob(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(invalid("handshake message too long"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(data)
}

/// Reads an 8-byte tag. An error tag is turned into an `Err` carrying the peer's message.
pub fn read_tag(r: &mut impl Read, expected: &[u8; 8]) -> io::Result<()> {
    let mut tag = [0u8; 8];
    r.read_exact(&mut tag)?;
    if &tag == expected {
        return Ok(());
    }
    if &tag == MAGIC_ERROR {
        let msg = read_blob(r)?;
        // The text comes from the peer and ends up in the log: keep it short and printable.
        let text: String = String::from_utf8_lossy(&msg)
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, text));
    }
    Err(invalid("the peer is not a EasyEther endpoint"))
}

pub fn read_hello(r: &mut impl Read, expected: &[u8; 8]) -> io::Result<u16> {
    read_tag(r, expected)?;
    let mut ver = [0u8; 2];
    r.read_exact(&mut ver)?;
    Ok(u16::from_be_bytes(ver))
}

/// Encodes up to `MAX_BATCH` frames (a keepalive when empty) into `out`.
pub fn encode_batch(frames: &[Vec<u8>], out: &mut Vec<u8>) {
    debug_assert!(frames.len() <= MAX_BATCH);
    out.clear();
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(frames.len() as u16).to_be_bytes());
    for f in frames {
        out.extend_from_slice(&(f.len() as u16).to_be_bytes());
        out.extend_from_slice(f);
    }
    let payload_len = (out.len() - 4) as u32;
    out[..4].copy_from_slice(&payload_len.to_be_bytes());
}

/// Decodes a batch payload (without the u32 length prefix) into `frames`.
pub fn decode_payload(payload: &[u8], frames: &mut Vec<Vec<u8>>) -> io::Result<()> {
    if payload.len() < 2 {
        return Err(invalid("truncated batch"));
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if count > MAX_BATCH {
        return Err(invalid("too many frames in batch"));
    }
    let mut pos = 2;
    for _ in 0..count {
        if pos + 2 > payload.len() {
            return Err(invalid("truncated batch"));
        }
        let len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return Err(invalid(format!("invalid frame length {len}")));
        }
        if pos + len > payload.len() {
            return Err(invalid("truncated batch"));
        }
        frames.push(payload[pos..pos + len].to_vec());
        pos += len;
    }
    if pos != payload.len() {
        return Err(invalid("trailing bytes in batch"));
    }
    Ok(())
}

/// Incremental batch decoder for a byte stream.
#[derive(Default)]
pub struct BatchDecoder {
    buf: Vec<u8>,
    /// Start of the first unconsumed message in `buf`. Consumed messages are removed only when
    /// no complete message is left, so many small messages in one read cost one move, not one
    /// move of the remainder per message.
    pos: usize,
}

impl BatchDecoder {
    /// Appends bytes by copying; the session reads straight into `buffer_mut` instead.
    #[cfg(test)]
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Lets a reader append incoming bytes directly, saving a copy. Whatever is appended
    /// stays after the pending data; the caller must not touch what is already there.
    pub fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    /// Decodes one complete message if available; frames of a batch are appended to `frames`.
    pub fn next(&mut self, frames: &mut Vec<Vec<u8>>) -> io::Result<Option<Msg>> {
        let pending = &self.buf[self.pos..];
        if pending.len() < 4 {
            return Ok(self.compact());
        }
        let len = u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD {
            return Err(invalid("batch too large"));
        }
        if pending.len() < 4 + len {
            return Ok(self.compact());
        }
        let payload = &pending[4..4 + len];
        let msg = if payload == CLOSE_COUNT.to_be_bytes() {
            Msg::Close
        } else {
            decode_payload(payload, frames)?;
            Msg::Batch
        };
        self.pos += 4 + len;
        Ok(Some(msg))
    }

    /// Drops the consumed prefix (at most one partial message stays).
    fn compact(&mut self) -> Option<Msg> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: usize, fill: u8) -> Vec<u8> {
        vec![fill; n]
    }

    #[test]
    fn batch_round_trip() {
        let frames = vec![frame(14, 1), frame(60, 2), frame(1600, 3)];
        let mut out = Vec::new();
        encode_batch(&frames, &mut out);
        let mut dec = BatchDecoder::default();
        // Feed byte by byte to exercise partial input.
        let mut got = Vec::new();
        let mut batches = 0;
        for b in &out {
            dec.push(std::slice::from_ref(b));
            while dec.next(&mut got).unwrap().is_some() {
                batches += 1;
            }
        }
        assert_eq!(batches, 1);
        assert_eq!(got, frames);
    }

    #[test]
    fn many_messages_in_one_push() {
        // Three batches plus the first half of a fourth arrive in one read.
        let mut stream = Vec::new();
        let mut one = Vec::new();
        for i in 0..3u8 {
            encode_batch(&[frame(20 + i as usize, i)], &mut one);
            stream.extend_from_slice(&one);
        }
        encode_batch(&[frame(100, 9)], &mut one);
        let half = one.len() / 2;
        stream.extend_from_slice(&one[..half]);
        let mut dec = BatchDecoder::default();
        dec.push(&stream);
        let mut got = Vec::new();
        for _ in 0..3 {
            assert_eq!(dec.next(&mut got).unwrap(), Some(Msg::Batch));
        }
        assert_eq!(got, vec![frame(20, 0), frame(21, 1), frame(22, 2)]);
        assert_eq!(dec.next(&mut got).unwrap(), None);
        // Only the partial message is kept; the rest completes it.
        assert_eq!(dec.buf.len(), half);
        dec.push(&one[half..]);
        assert_eq!(dec.next(&mut got).unwrap(), Some(Msg::Batch));
        assert_eq!(got.last().unwrap(), &frame(100, 9));
        assert_eq!(dec.next(&mut got).unwrap(), None);
        assert!(dec.buf.is_empty());
    }

    #[test]
    fn keepalive_is_empty_batch() {
        let mut out = Vec::new();
        encode_batch(&[], &mut out);
        assert_eq!(out, [0, 0, 0, 2, 0, 0]);
        let mut dec = BatchDecoder::default();
        dec.push(&out);
        let mut got = Vec::new();
        assert_eq!(dec.next(&mut got).unwrap(), Some(Msg::Batch));
        assert!(got.is_empty());
    }

    #[test]
    fn close_message() {
        let mut out = Vec::new();
        encode_close(&mut out);
        let mut dec = BatchDecoder::default();
        dec.push(&out);
        let mut got = Vec::new();
        assert_eq!(dec.next(&mut got).unwrap(), Some(Msg::Close));
        assert_eq!(dec.next(&mut got).unwrap(), None);
    }

    #[test]
    fn rejects_bad_batches() {
        let mut got = Vec::new();
        // Truncated frame.
        assert!(decode_payload(&[0, 1, 0, 20, 1, 2, 3], &mut got).is_err());
        // Frame shorter than an Ethernet header.
        let mut p = vec![0, 1, 0, 4];
        p.extend_from_slice(&[0; 4]);
        assert!(decode_payload(&p, &mut got).is_err());
        // Trailing bytes.
        let mut out = Vec::new();
        encode_batch(&[frame(20, 0)], &mut out);
        let mut p = out[4..].to_vec();
        p.push(0);
        assert!(decode_payload(&p, &mut got).is_err());
        // Oversized length prefix.
        let mut dec = BatchDecoder::default();
        dec.push(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        assert!(dec.next(&mut got).is_err());
    }

    #[test]
    fn error_message_round_trip() {
        let mut out = Vec::new();
        write_error(&mut out, "busy").unwrap();
        let err = read_hello(&mut &out[..], MAGIC_SERVER).unwrap_err();
        assert_eq!(err.to_string(), "busy");
    }
}
