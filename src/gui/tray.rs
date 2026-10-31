//! System tray icon with "Open" and "Exit" (Windows/macOS, `tray-icon`). Minimizing the window
//! hides it to the tray. On Windows the window is shown/hidden directly through its HWND,
//! which also works while egui is not painting.
//!
//! No tray on Linux: Wayland lets a program neither hide, show, un-minimize nor focus its own
//! window, so a tray icon could only offer Exit, at the cost of a whole D-Bus stack. There the
//! window stays in the taskbar; `Tray` has no values, so `Option<Tray>` is always `None`.
//!
//! Tray callbacks run on other threads; they only send a command and wake egui, and
//! `App::logic` (which also runs while the window is hidden) acts on it.

#[cfg(not(target_os = "linux"))]
use std::sync::mpsc::{Receiver, Sender, channel};

#[cfg(not(target_os = "linux"))]
use eframe::egui;

#[cfg_attr(target_os = "linux", allow(dead_code))]
pub enum TrayCmd {
    Open,
    Exit,
}

#[cfg(target_os = "linux")]
pub enum Tray {}

#[cfg(target_os = "linux")]
impl Tray {
    pub fn poll(&self) -> Option<TrayCmd> {
        match *self {}
    }

    pub fn show_window(&self) {
        match *self {}
    }

    pub fn hide_window(&self) {
        match *self {}
    }

    pub fn notify(&self, _text: &str) -> Result<(), String> {
        match *self {}
    }

    pub fn set_tooltip(&self, _text: &str) {
        match *self {}
    }
}

#[cfg(not(target_os = "linux"))]
pub struct Tray {
    rx: Receiver<TrayCmd>,
    ctx: egui::Context,
    #[cfg(windows)]
    hwnd: isize,
    /// Explorer's id of our tray icon (see find_icon_id), for balloon notifications.
    #[cfg(windows)]
    icon_id: Option<u32>,
    backend: Backend,
}

#[cfg(not(target_os = "linux"))]
impl Tray {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Result<Tray, String> {
        let (tx, rx) = channel();
        let ctx = cc.egui_ctx.clone();
        // A second start of EasyEther asks us to show the window; same path as tray "Open".
        #[cfg(windows)]
        {
            let (tx, ctx) = (tx.clone(), ctx.clone());
            crate::instance::on_show_request(move || send(&tx, &ctx, TrayCmd::Open));
        }
        let backend = Backend::start(tx, ctx.clone())?;
        Ok(Tray {
            rx,
            #[cfg(windows)]
            icon_id: find_icon_id(backend.0.window_handle()),
            #[cfg(windows)]
            hwnd: {
                use raw_window_handle::{HasWindowHandle, RawWindowHandle};
                match cc.window_handle().map_err(|e| e.to_string())?.as_raw() {
                    RawWindowHandle::Win32(h) => h.hwnd.get(),
                    _ => return Err("unexpected window handle type".into()),
                }
            },
            ctx,
            backend,
        })
    }

    pub fn poll(&self) -> Option<TrayCmd> {
        self.rx.try_recv().ok()
    }

    pub fn show_window(&self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow};
            let hwnd = self.hwnd as _;
            // SAFETY: hwnd is our own top-level window, alive for the program's lifetime.
            unsafe {
                ShowWindow(hwnd, SW_SHOW);
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
        }
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        self.ctx.request_repaint();
    }

    /// Hides the window (minimizing goes to the tray).
    pub fn hide_window(&self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, ShowWindow};
            // SAFETY: see show_window().
            unsafe { ShowWindow(self.hwnd as _, SW_HIDE) };
        }
        #[cfg(not(windows))]
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    /// The text shown when hovering the tray icon (what runs, connected to whom).
    pub fn set_tooltip(&self, text: &str) {
        let _ = self.backend.0.set_tooltip(Some(text));
    }

    /// A short notification at the tray icon that disappears by itself (Windows balloon).
    /// The error says why it could not be shown, so the caller can log instead.
    pub fn notify(&self, text: &str) -> Result<(), String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::Shell::{NIF_INFO, NIIF_INFO, NIM_MODIFY, Shell_NotifyIconW};
            let Some(id) = self.icon_id else {
                return Err("tray icon id unknown".into());
            };
            let mut nid = notify_icon_data(self.backend.0.window_handle(), id);
            nid.uFlags = NIF_INFO;
            nid.dwInfoFlags = NIIF_INFO;
            nid.szInfoTitle = utf16("EasyEther");
            nid.szInfo = utf16(text);
            // SAFETY: nid is fully initialised and refers to the icon tray-icon registered.
            if unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = text;
            Err("no tray notifications on this platform".into())
        }
    }
}

/// `NOTIFYICONDATAW` addressing the icon `id` on `hwnd`.
#[cfg(windows)]
fn notify_icon_data(
    hwnd: windows_sys::Win32::Foundation::HWND,
    id: u32,
) -> windows_sys::Win32::UI::Shell::NOTIFYICONDATAW {
    use windows_sys::Win32::UI::Shell::NOTIFYICONDATAW;
    // SAFETY: NOTIFYICONDATAW is plain data; all-zero is valid before the fields are set.
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = id;
    nid
}

/// The id under which tray-icon registered its icon with Explorer. The library keeps it
/// private (and takes it from a counter shared with other ids), so find it by probing:
/// Explorer accepts a tooltip change only for an icon that exists on the window.
#[cfg(windows)]
fn find_icon_id(hwnd: windows_sys::Win32::Foundation::HWND) -> Option<u32> {
    use windows_sys::Win32::UI::Shell::{NIF_TIP, NIM_MODIFY, Shell_NotifyIconW};
    (1..=16).find(|&id| {
        let mut nid = notify_icon_data(hwnd, id);
        nid.uFlags = NIF_TIP;
        nid.szTip = utf16("EasyEther");
        // SAFETY: nid is fully initialised; a wrong id only makes the call fail.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 }
    })
}

/// NUL-terminated, truncated to the field. Built as a value: NOTIFYICONDATAW is packed on
/// x86, so its fields cannot be borrowed.
#[cfg(windows)]
fn utf16<const N: usize>(s: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (d, c) in out.iter_mut().zip(s.encode_utf16().take(N - 1)) {
        *d = c;
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn send(tx: &Sender<TrayCmd>, ctx: &egui::Context, cmd: TrayCmd) {
    let _ = tx.send(cmd);
    ctx.request_repaint();
}

#[cfg(not(target_os = "linux"))]
struct Backend(#[allow(dead_code)] tray_icon::TrayIcon);

#[cfg(not(target_os = "linux"))]
impl Backend {
    fn start(tx: Sender<TrayCmd>, ctx: egui::Context) -> Result<Backend, String> {
        use tray_icon::menu::{Menu, MenuEvent, MenuItem};
        use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

        let open = MenuItem::new("Open", true, None);
        let exit = MenuItem::new("Exit", true, None);
        let menu = Menu::new();
        menu.append_items(&[&open, &exit]).map_err(|e| e.to_string())?;
        // Left click opens the window; the menu is on the right button only.
        let mut builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("EasyEther");
        if let Some(icon) = crate::logo::rgba(64).and_then(|rgba| Icon::from_rgba(rgba.to_vec(), 64, 64).ok()) {
            builder = builder.with_icon(icon);
        }
        let tray = builder.build().map_err(|e| e.to_string())?;

        let (open_id, exit_id) = (open.id().clone(), exit.id().clone());
        let (tx2, ctx2) = (tx.clone(), ctx.clone());
        MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
            if ev.id == open_id {
                send(&tx2, &ctx2, TrayCmd::Open);
            } else if ev.id == exit_id {
                send(&tx2, &ctx2, TrayCmd::Exit);
            }
        }));
        TrayIconEvent::set_event_handler(Some(move |ev: TrayIconEvent| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                send(&tx, &ctx, TrayCmd::Open);
            }
        }));
        Ok(Backend(tray))
    }
}
