//! Windows backend built on SoftEther's signed kernel drivers:
//! * SeLow: NDIS protocol driver giving raw L2 access to a physical NIC (server side)
//! * Neo6: virtual Ethernet adapter, instance "VPN127" (client side)

mod ffi;
pub mod firewall;
pub mod install;
mod ipconfig;
mod neo;
mod reg;
mod selow;

use std::io;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

use super::exchange::{EXCHANGE_SIZE, ExchangeBuffer, MAX_PACKETS};
use super::{AdapterInfo, L2Port};
use crate::log::Logger;
use ffi::Handle;

pub const NEO_INSTANCE: &str = "VPN127";
/// Hardware id of the virtual adapter (from the INF); how we find it in the registry.
pub const NEO_HWID: &str = "NeoAdapter_VPN127";
/// Shown name of the virtual adapter. The signed INF calls it "VPN Client Adapter - VPN127";
/// the installer renames it (see install::configure_neo).
pub const CLIENT_ADAPTER_NAME: &str = "EasyEther Adapter";

pub fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    selow::list_adapters()
}

pub fn open_server(id: &str, log: &Logger) -> io::Result<Box<dyn L2Port>> {
    Ok(Box::new(selow::open(id, log)?))
}

pub fn open_client(_mac: [u8; 6], log: &Logger) -> io::Result<Box<dyn L2Port>> {
    // The Neo adapter's MAC is fixed in the registry at install time.
    Ok(Box::new(neo::open(log)?))
}

pub fn start_dhcp(log: &Logger) -> io::Result<Option<Box<dyn Send>>> {
    ipconfig::start_dhcp(log)
}

pub fn apply_static_ipv4(addr: Ipv4Addr, prefix: u8, log: &Logger) -> io::Result<Box<dyn Send>> {
    ipconfig::apply(addr, prefix, log)
}

/// A SeLow or Neo device handle plus its "packets available" event.
/// Both drivers use the same exchange buffer and never block in ReadFile.
pub struct DevicePort {
    dev: Handle,
    event: Handle,
    rbuf: Mutex<ExchangeBuffer>,
    wbuf: Mutex<ExchangeBuffer>,
}

impl DevicePort {
    fn new(dev: Handle, event: Handle) -> DevicePort {
        DevicePort {
            dev,
            event,
            rbuf: Mutex::default(),
            wbuf: Mutex::default(),
        }
    }
}

impl L2Port for DevicePort {
    fn recv(&self, out: &mut Vec<Vec<u8>>, timeout: Duration) -> io::Result<()> {
        let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
        // The queue is read after a timeout too. Both drivers reset the event after a read
        // that emptied the queue *outside* the lock that guards it, and set it outside that
        // lock as well, so a frame queued in that gap is left with the event reset. Waiting for
        // the event alone would then hold that frame until the next one arrives, which in a
        // request/response exchange is a TCP retransmission hundreds of milliseconds later.
        // SoftEther reads after every wait for the same reason. An empty read costs a few tens
        // of microseconds per poll interval.
        // SAFETY: event is a valid handle owned by self.
        match unsafe { ffi::WaitForSingleObject(self.event.0, ms) } {
            ffi::WAIT_OBJECT_0 | ffi::WAIT_TIMEOUT => {}
            _ => return Err(io::Error::last_os_error()),
        }
        let mut b = self.rbuf.lock().unwrap();
        loop {
            let mut read = 0u32;
            // SAFETY: the buffer is EXCHANGE_SIZE bytes, as the driver requires.
            let ok = unsafe {
                ffi::ReadFile(
                    self.dev.0,
                    b.as_mut_ptr(),
                    EXCHANGE_SIZE as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let n = b.num_packets();
            b.take_packets(out);
            if n == 0 || !b.more_left() || out.len() >= MAX_PACKETS {
                return Ok(());
            }
        }
    }

    fn send(&self, frames: &[Vec<u8>]) -> io::Result<()> {
        let mut b = self.wbuf.lock().unwrap();
        for chunk in frames.chunks(MAX_PACKETS) {
            if b.fill(chunk) == 0 {
                continue;
            }
            let mut written = 0u32;
            // SAFETY: the buffer is EXCHANGE_SIZE bytes, as the driver requires.
            let ok = unsafe {
                ffi::WriteFile(
                    self.dev.0,
                    b.as_ptr(),
                    EXCHANGE_SIZE as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
