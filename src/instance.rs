//! Only one EasyEther GUI at a time. A second start brings the running window to the front on
//! Windows; on Linux (Wayland allows no raising of other windows) it says that one is running.

use std::io;

/// Held for the lifetime of the GUI; dropping it lets the next start through.
pub struct Lock {
    #[cfg(windows)]
    mutex: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(unix)]
    _file: std::fs::File,
}

#[cfg(windows)]
impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.mutex) };
    }
}

/// `Ok(None)` when another instance holds the lock.
#[cfg(windows)]
pub fn acquire() -> io::Result<Option<Lock>> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Global\\EasyEther".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: name is NUL-terminated; a mutex with no security attributes and not owned.
    let (mutex, err) = unsafe { (CreateMutexW(std::ptr::null(), 0, name.as_ptr()), GetLastError()) };
    if mutex.is_null() {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    if err == ERROR_ALREADY_EXISTS {
        // SAFETY: handle from a successful CreateMutexW.
        unsafe { CloseHandle(mutex) };
        return Ok(None);
    }
    Ok(Some(Lock { mutex }))
}

#[cfg(unix)]
pub fn acquire() -> io::Result<Option<Lock>> {
    use std::os::fd::AsRawFd;
    // Per user: the runtime dir ($XDG_RUNTIME_DIR) where there is one, else the temp dir.
    let path = directories::ProjectDirs::from("", "", "EasyEther")
        .and_then(|d| d.runtime_dir().map(|p| p.join("gui.lock")))
        // SAFETY: getuid has no preconditions.
        .unwrap_or_else(|| std::env::temp_dir().join(format!("easyether-{}.lock", unsafe { libc::getuid() })));
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    // SAFETY: plain flock(2) on our own open descriptor; the lock goes with the file.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(Lock { _file: file }));
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(e)
    }
}

/// What a second start does: raise the running window where the OS allows it, otherwise
/// show a short notice.
pub fn already_running() {
    #[cfg(windows)]
    if raise_existing() {
        return;
    }
    eprintln!("EasyEther is already running.");
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_title("EasyEther")
        .with_inner_size([340.0, 110.0])
        .with_resizable(false);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let _ = eframe::run_ui_native("EasyEther", options, |ui, _| {
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            ui.label("EasyEther is already running.");
            ui.add_space(12.0);
            if ui.button("  OK  ").clicked() {
                ui.ctx().send_viewport_cmd(eframe::egui::ViewportCommand::Close);
            }
        });
    });
}

/// Shows and focuses the running instance's window, also when it is hidden in the tray
/// (the same calls as gui/tray.rs uses from inside).
#[cfg(windows)]
fn raise_existing() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow,
    };
    let title: Vec<u16> = "EasyEther".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: title is NUL-terminated; the window handle is only used for these calls.
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return false;
        }
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }
    true
}
