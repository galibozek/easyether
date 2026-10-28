//! System tray icon with "Open" and "Exit". Closing the window hides it to the tray.
//!
//! * Linux: `ksni` – a native StatusNotifierItem over D-Bus (what KDE and the GNOME
//!   AppIndicator extension expect), no XEmbed/GTK.
//! * Windows/macOS: `tray-icon`. On Windows the window is shown/hidden directly through its
//!   HWND, which also works while egui is not painting.
//!
//! Tray callbacks run on other threads; they only send a command and wake egui, and
//! `App::logic` (which also runs while the window is hidden) acts on it.

use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui;

pub enum TrayCmd {
    Open,
    Exit,
}

pub struct Tray {
    rx: Receiver<TrayCmd>,
    ctx: egui::Context,
    #[cfg(windows)]
    hwnd: isize,
    _backend: Backend,
}

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

fn send(tx: &Sender<TrayCmd>, ctx: &egui::Context, cmd: TrayCmd) {
    let _ = tx.send(cmd);
    ctx.request_repaint();
}

// ----------------------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
struct Backend(#[allow(dead_code)] ksni::blocking::Handle<SniTray>);

#[cfg(target_os = "linux")]
struct SniTray {
    tx: Sender<TrayCmd>,
    ctx: egui::Context,
    icon: Vec<ksni::Icon>,
}

#[cfg(target_os = "linux")]
impl ksni::Tray for SniTray {
    fn id(&self) -> String {
        "easyether".into()
    }

    fn title(&self) -> String {
        "EasyEther".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icon.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "EasyEther".into(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        send(&self.tx, &self.ctx, TrayCmd::Open);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(|t: &mut Self| send(&t.tx, &t.ctx, TrayCmd::Open)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Exit".into(),
                activate: Box::new(|t: &mut Self| send(&t.tx, &t.ctx, TrayCmd::Exit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

#[cfg(target_os = "linux")]
impl Backend {
    fn start(tx: Sender<TrayCmd>, ctx: egui::Context) -> Result<Backend, String> {
        use ksni::blocking::TrayMethods;
        // SNI wants ARGB32 in network byte order.
        let icon = crate::logo::rgba(64)
            .map(|rgba| {
                let data = rgba
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .flat_map(|p| [p[3], p[0], p[1], p[2]])
                    .collect();
                vec![ksni::Icon {
                    width: 64,
                    height: 64,
                    data,
                }]
            })
            .unwrap_or_default();
        let tray = SniTray { tx, ctx, icon };
        // The session bus only accepts its own user. When started with sudo, connect from a
        // helper thread that switched (only itself) back to the invoking user; threads it
        // spawns for the tray service inherit that identity. The rest of EasyEther keeps root.
        let (done_tx, done_rx) = channel();
        std::thread::spawn(move || {
            if let Err(e) = become_sudo_user() {
                let _ = done_tx.send(Err(e));
                return;
            }
            let _ = done_tx.send(tray.spawn().map(Backend).map_err(|e| e.to_string()));
        });
        done_rx.recv().map_err(|e| e.to_string())?
    }
}

/// For the calling thread only (raw syscalls; glibc's setuid would change every thread).
#[cfg(target_os = "linux")]
fn become_sudo_user() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let id = |name| std::env::var(name).ok().and_then(|v| v.parse::<libc::uid_t>().ok());
    let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
        return Ok(());
    };
    // SAFETY: plain credential syscalls affecting only this thread.
    unsafe {
        if libc::syscall(libc::SYS_setresgid, gid, gid, gid) != 0
            || libc::syscall(libc::SYS_setresuid, uid, uid, uid) != 0
        {
            return Err(format!(
                "cannot switch the tray thread to uid {uid}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------------- Windows / macOS

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
