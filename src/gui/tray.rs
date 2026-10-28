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
}

#[cfg(not(target_os = "linux"))]
pub struct Tray {
    rx: Receiver<TrayCmd>,
    ctx: egui::Context,
    #[cfg(windows)]
    hwnd: isize,
    _backend: Backend,
}

#[cfg(not(target_os = "linux"))]
impl Tray {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Result<Tray, String> {
        let (tx, rx) = channel();
        let ctx = cc.egui_ctx.clone();
        let backend = Backend::start(tx, ctx.clone())?;
        Ok(Tray {
            rx,
            #[cfg(windows)]
            hwnd: {
                use raw_window_handle::{HasWindowHandle, RawWindowHandle};
                match cc.window_handle().map_err(|e| e.to_string())?.as_raw() {
                    RawWindowHandle::Win32(h) => h.hwnd.get(),
                    _ => return Err("unexpected window handle type".into()),
                }
            },
            ctx,
            _backend: backend,
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

    /// Hides the window (minimize → tray).
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
