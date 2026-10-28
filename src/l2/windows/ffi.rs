//! Win32 items used by the backend (from Microsoft's `windows-sys` bindings) plus small helpers.

use std::io;

pub use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DICD_GENERATE_ID, DIF_REGISTERDEVICE, DIF_REMOVE, DIGCF_ALLCLASSES, HDEVINFO, INSTALLFLAG_FORCE, SP_DEVINFO_DATA,
    SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME, SPDRP_HARDWAREID, SetupDiCallClassInstaller, SetupDiCreateDeviceInfoList,
    SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW, SetupDiGetINFClassW, SetupDiRemoveDevice,
    SetupDiSetDeviceRegistryPropertyW, UpdateDriverForPlugAndPlayDevicesW,
};
pub use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT};
pub use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceGuidToLuid, CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry,
    InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};
pub use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE, ReadFile, WriteFile};
pub use windows_sys::Win32::System::IO::DeviceIoControl;
pub use windows_sys::Win32::System::Threading::WaitForSingleObject;
pub use windows_sys::core::{BOOL, GUID};

use windows_sys::Win32::Foundation as F;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::System::Threading::{OpenEventA, SYNCHRONIZATION_SYNCHRONIZE};

/// Win32 error codes as returned by `io::Error::raw_os_error`.
pub const ERROR_FILE_NOT_FOUND: i32 = F::ERROR_FILE_NOT_FOUND as i32;
pub const ERROR_PATH_NOT_FOUND: i32 = F::ERROR_PATH_NOT_FOUND as i32;
pub const ERROR_ACCESS_DENIED: i32 = F::ERROR_ACCESS_DENIED as i32;
pub const ERROR_SHARING_VIOLATION: i32 = F::ERROR_SHARING_VIOLATION as i32;
pub const ERROR_OBJECT_ALREADY_EXISTS: u32 = F::ERROR_OBJECT_ALREADY_EXISTS;

/// NUL-terminated UTF-16 string.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// An SP_DEVINFO_DATA with cbSize set, ready for SetupAPI.
pub fn devinfo_data() -> SP_DEVINFO_DATA {
    // SAFETY: plain C struct; all-zero is valid before cbSize is set.
    let mut d: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
    d.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
    d
}

/// Owned kernel handle.
pub struct Handle(pub HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Opens a device for synchronous read/write.
pub fn open_device(path: &str, share: u32) -> io::Result<Handle> {
    let w = wide(path);
    // SAFETY: w is a valid NUL-terminated wide string.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            F::GENERIC_READ | F::GENERIC_WRITE,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(h))
}

/// Opens a named event for waiting.
pub fn open_event(name: &str) -> io::Result<Handle> {
    let mut n = name.as_bytes().to_vec();
    n.push(0);
    // SAFETY: n is NUL-terminated.
    let h = unsafe { OpenEventA(SYNCHRONIZATION_SYNCHRONIZE, 0, n.as_ptr()) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(h))
}

/// Parses "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
pub fn parse_guid(s: &str) -> Option<GUID> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 || parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let tail = format!("{}{}", parts[3], parts[4]);
    let mut data4 = [0u8; 8];
    for (i, b) in data4.iter_mut().enumerate() {
        *b = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(GUID {
        data1: u32::from_str_radix(parts[0], 16).ok()?,
        data2: u16::from_str_radix(parts[1], 16).ok()?,
        data3: u16::from_str_radix(parts[2], 16).ok()?,
        data4,
    })
}
