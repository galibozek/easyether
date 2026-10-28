//! Binary layouts shared with SoftEther's SeLow and Neo6 drivers
//! (see SoftEtherVPN_Stable/src/SeLow/SeLowCommon.h and Neo6/Neo6.h).
//! Kept platform independent so they can be unit tested anywhere.

/// Packets per ReadFile/WriteFile (the drivers' limits happen to equal our batch limits).
pub const MAX_PACKETS: usize = crate::proto::MAX_BATCH;
/// Data area per packet slot.
pub const SLOT_DATA: usize = crate::proto::MAX_FRAME;
const SLOT: usize = 4 + SLOT_DATA;
/// u32 count + 257 slots (the last slot's length field is the "left" flag) + u32 left flag.
pub const EXCHANGE_SIZE: usize = 4 + 4 + SLOT * (MAX_PACKETS + 1);
const LEFT_FLAG_OFFSET: usize = 4 + SLOT * MAX_PACKETS;

pub const MIN_PACKET: usize = crate::proto::MIN_FRAME;

// SoftEther's constants (SL_/NEO_MAX_PACKET_EXCHANGE, *_MAX_PACKET_SIZE, *_MIN_PACKET_SIZE).
const _: () = assert!(MAX_PACKETS == 256 && SLOT_DATA == 1600 && MIN_PACKET == 14);

/// The packet exchange buffer used by both drivers. Integers are little-endian (x86/x64).
pub struct ExchangeBuffer {
    buf: Vec<u8>,
}

impl Default for ExchangeBuffer {
    fn default() -> Self {
        ExchangeBuffer {
            buf: vec![0u8; EXCHANGE_SIZE],
        }
    }
}

impl ExchangeBuffer {
    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.buf[off..off + 4].try_into().unwrap())
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Used by the Windows backend only; the module is also compiled for tests on Linux.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub fn num_packets(&self) -> usize {
        (self.u32_at(0) as usize).min(MAX_PACKETS)
    }

    /// Set by the driver when more packets are queued than fit in one buffer.
    pub fn more_left(&self) -> bool {
        self.u32_at(LEFT_FLAG_OFFSET) != 0
    }

    /// Appends the received packets to `out`, skipping malformed lengths.
    pub fn take_packets(&self, out: &mut Vec<Vec<u8>>) {
        for i in 0..self.num_packets() {
            let off = 4 + i * SLOT;
            let len = self.u32_at(off) as usize;
            if (MIN_PACKET..=SLOT_DATA).contains(&len) {
                out.push(self.buf[off + 4..off + 4 + len].to_vec());
            }
        }
    }

    /// Fills the buffer with up to `MAX_PACKETS` frames; returns how many were stored.
    /// Frames outside 14..=1600 bytes are skipped.
    pub fn fill(&mut self, frames: &[Vec<u8>]) -> usize {
        let mut n = 0;
        for f in frames.iter().take(MAX_PACKETS) {
            if !(MIN_PACKET..=SLOT_DATA).contains(&f.len()) {
                continue;
            }
            let off = 4 + n * SLOT;
            self.set_u32(off, f.len() as u32);
            self.buf[off + 4..off + 4 + f.len()].copy_from_slice(f);
            n += 1;
        }
        self.set_u32(0, n as u32);
        self.set_u32(LEFT_FLAG_OFFSET, 0);
        n
    }
}

// --- SeLow adapter list (SL_ADAPTER_INFO_LIST) ---

pub const SL_SIGNATURE: u32 = 0xDEAD_BEEF;
const SL_ADAPTER_INFO_SIZE: usize = 652;
pub const SL_ADAPTER_LIST_SIZE: usize = 16 + SL_ADAPTER_INFO_SIZE * 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeLowAdapter {
    /// "SELOW_A_{GUID}"
    pub adapter_id: String,
    pub mac: [u8; 6],
    pub mtu: u32,
    /// May be empty (NetAdapterCx drivers); fill from the registry then.
    pub friendly_name: String,
}

impl SeLowAdapter {
    /// "{GUID}" part of the adapter id.
    pub fn guid(&self) -> &str {
        self.adapter_id.strip_prefix("SELOW_A_").unwrap_or(&self.adapter_id)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SeLowAdapterList {
    pub version: u32,
    pub enum_completed: bool,
    pub adapters: Vec<SeLowAdapter>,
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Parses the buffer returned by ReadFile on \\.\SELOW_BASIC_DEVICE.
pub fn parse_selow_adapter_list(b: &[u8]) -> Result<SeLowAdapterList, String> {
    if b.len() < SL_ADAPTER_LIST_SIZE {
        return Err("SeLow adapter list is too short".into());
    }
    if le32(b, 0) != SL_SIGNATURE {
        return Err("SeLow adapter list has an invalid signature".into());
    }
    let version = le32(b, 4);
    let enum_completed = le32(b, 8) != 0;
    let count = (le32(b, 12) as usize).min(256);
    let mut adapters = Vec::with_capacity(count);
    for i in 0..count {
        let e = &b[16 + i * SL_ADAPTER_INFO_SIZE..16 + (i + 1) * SL_ADAPTER_INFO_SIZE];
        let id: Vec<u16> = e[..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&c| c != 0)
            .collect();
        let name_bytes: Vec<u8> = e[140..396].iter().copied().take_while(|&c| c != 0).collect();
        adapters.push(SeLowAdapter {
            adapter_id: String::from_utf16_lossy(&id),
            mac: e[128..134].try_into().unwrap(),
            mtu: le32(e, 136),
            friendly_name: String::from_utf8_lossy(&name_bytes).into_owned(),
        });
    }
    Ok(SeLowAdapterList {
        version,
        enum_completed,
        adapters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_softether() {
        assert_eq!(EXCHANGE_SIZE, 412_236);
        assert_eq!(LEFT_FLAG_OFFSET, 410_628);
        assert_eq!(SL_ADAPTER_LIST_SIZE, 166_928);
    }

    #[test]
    fn exchange_round_trip() {
        let mut b = ExchangeBuffer::default();
        let frames = vec![vec![1u8; 14], vec![2u8; 1600], vec![3u8; 5], vec![4u8; 60]];
        assert_eq!(b.fill(&frames), 3);
        assert_eq!(b.num_packets(), 3);
        assert!(!b.more_left());
        let mut out = Vec::new();
        b.take_packets(&mut out);
        assert_eq!(out, vec![frames[0].clone(), frames[1].clone(), frames[3].clone()]);
        b.set_u32(LEFT_FLAG_OFFSET, 1);
        assert!(b.more_left());
    }

    #[test]
    fn parses_selow_list() {
        let mut b = vec![0u8; SL_ADAPTER_LIST_SIZE];
        b[0..4].copy_from_slice(&SL_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&48u32.to_le_bytes());
        b[8..12].copy_from_slice(&8u32.to_le_bytes());
        b[12..16].copy_from_slice(&1u32.to_le_bytes());
        let e = 16;
        let id = "SELOW_A_{11111111-2222-3333-4444-555555555555}";
        for (i, c) in id.encode_utf16().enumerate() {
            b[e + i * 2..e + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        b[e + 128..e + 134].copy_from_slice(&[0, 0x1b, 0x21, 1, 2, 3]);
        b[e + 136..e + 140].copy_from_slice(&1500u32.to_le_bytes());
        b[e + 140..e + 148].copy_from_slice(b"Intel(R)");
        let list = parse_selow_adapter_list(&b).unwrap();
        assert_eq!(list.version, 48);
        assert!(list.enum_completed);
        let a = &list.adapters[0];
        assert_eq!(a.adapter_id, id);
        assert_eq!(a.guid(), "{11111111-2222-3333-4444-555555555555}");
        assert_eq!(a.mac, [0, 0x1b, 0x21, 1, 2, 3]);
        assert_eq!(a.mtu, 1500);
        assert_eq!(a.friendly_name, "Intel(R)");
    }
}
