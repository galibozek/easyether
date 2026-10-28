//! The application logo, pre-rendered from `assets/logo.svg` by build.rs.

/// Straight (non-premultiplied) RGBA bitmap of the logo, `size` x `size` pixels.
/// Available sizes: 256 (window icon), 128 (header), 64 (tray).
pub fn rgba(size: u32) -> Option<&'static [u8]> {
    Some(match size {
        256 => include_bytes!(concat!(env!("OUT_DIR"), "/logo256.rgba")),
        128 => include_bytes!(concat!(env!("OUT_DIR"), "/logo128.rgba")),
        64 => include_bytes!(concat!(env!("OUT_DIR"), "/logo64.rgba")),
        _ => return None,
    })
}
