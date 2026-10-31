#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

//! EasyEther: share a physical Ethernet adapter with another computer over the network,
//! at layer 2, like plugging the remote machine into the same switch.

mod gui;
mod instance;
mod l2;
mod log;
mod logo;
mod proto;
mod secure;
mod settings;
mod tunnel;

use std::sync::Arc;

const USAGE: &str = concat!(
    "EasyEther ",
    env!("CARGO_PKG_VERSION"),
    " - peer-to-peer Ethernet (L2) sharing

Usage:
  easyether                                  start the GUI
  easyether --cli list                       list shareable adapters
  easyether --cli server <adapter> [port] [--insecure]
                                             share an adapter (prints the password)
  easyether --cli client <host> [port] (--password <8 chars> | --insecure) [--ip <addr>/<prefix>]

  --insecure: plain TCP without encryption or password (must be used on both sides)
  easyether --install-drivers                Windows: install the SeLow and virtual adapter drivers
  easyether --uninstall-drivers              Windows: remove them again
"
);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return run_gui();
    }
    #[cfg(target_os = "linux")]
    if args[0] == l2::PRIVILEGED_HELPER_ARG {
        std::process::exit(l2::run_privileged_helper());
    }
    let console = console::attach();
    let code = match args[0].as_str() {
        "--cli" => cli(&args[1..]),
        "--install-drivers" => drivers(true),
        "--uninstall-drivers" => drivers(false),
        _ => {
            eprint!("{USAGE}");
            2
        }
    };
    console.finish();
    std::process::exit(code);
}

/// The Windows release build is a GUI program without a console. Command-line modes attach to
/// the parent console (cmd / .bat), or open their own window when started elevated by UAC
/// (which gives the process no parent console) and keep it open until Enter is pressed.
mod console {
    pub struct Console {
        #[cfg(windows)]
        own_window: bool,
    }

    #[cfg(windows)]
    pub fn attach() -> Console {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AllocConsole, AttachConsole};
        // SAFETY: plain Win32 call without pointers.
        let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0;
        // SAFETY: plain Win32 call without pointers.
        let own_window = !attached && unsafe { AllocConsole() } != 0;
        Console { own_window }
    }

    #[cfg(not(windows))]
    pub fn attach() -> Console {
        Console {}
    }

    impl Console {
        pub fn finish(self) {
            #[cfg(windows)]
            if self.own_window {
                println!("\nPress Enter to close.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
        }
    }
}

fn run_gui() {
    // One GUI at a time (the CLI modes are not restricted).
    let _lock = match instance::acquire() {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => return instance::already_running(),
        Err(e) => {
            eprintln!("EasyEther: cannot check for another instance: {e}");
            None
        }
    };
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("EasyEther")
        .with_inner_size([760.0, 540.0])
        .with_min_inner_size([760.0, 540.0]);
    if let Some(rgba) = logo::rgba(256) {
        viewport = viewport.with_icon(Arc::new(eframe::egui::IconData {
            rgba: rgba.to_vec(),
            width: 256,
            height: 256,
        }));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    if let Err(e) = eframe::run_native("EasyEther", options, Box::new(|cc| Ok(Box::new(gui::App::new(cc))))) {
        eprintln!("EasyEther: {e}");
        std::process::exit(1);
    }
}

/// Set by Ctrl-C / SIGTERM / console close so the CLI can stop gracefully (the peer then gets
/// Close instead of a dropped connection). A second signal forces an immediate exit.
static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set when the worker has finished (console-close on Windows waits for it).
static STOPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn install_interrupt_handler() {
    use std::sync::atomic::Ordering::SeqCst;
    #[cfg(unix)]
    {
        extern "C" fn on_signal(_: libc::c_int) {
            if INTERRUPTED.swap(true, SeqCst) {
                // Second Ctrl-C while still shutting down: give up waiting (async-signal-safe).
                // SAFETY: _exit only terminates the process.
                unsafe { libc::_exit(130) };
            }
        }
        // SAFETY: the handler only touches an atomic (or exits).
        unsafe {
            for sig in [libc::SIGINT, libc::SIGTERM] {
                if libc::signal(sig, on_signal as *const () as libc::sighandler_t) == libc::SIG_ERR {
                    eprintln!(
                        "warning: cannot install handler for signal {sig}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
        };
        unsafe extern "system" fn on_ctrl(event: u32) -> windows_sys::core::BOOL {
            if INTERRUPTED.swap(true, SeqCst) {
                std::process::exit(130);
            }
            // Windows kills the process as soon as this returns for close/logoff/shutdown,
            // so wait here (bounded) for the graceful stop to finish.
            if matches!(event, CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT) {
                for _ in 0..30 {
                    if STOPPED.load(SeqCst) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            1
        }
        // SAFETY: registering a handler that only touches atomics and sleeps.
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    }
}

/// Prints worker events to the terminal until the worker exits; Ctrl-C stops it gracefully.
fn print_events(rx: std::sync::mpsc::Receiver<log::Event>, handle: &tunnel::TunnelHandle) {
    use std::sync::atomic::Ordering::SeqCst;
    install_interrupt_handler();
    let mut stopping = false;
    loop {
        if !stopping && INTERRUPTED.load(SeqCst) {
            println!("-- Stopping... (press Ctrl-C again to force)");
            handle.stop();
            stopping = true;
        }
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(log::Event::Log(l)) => println!("{l}"),
            Ok(log::Event::Status(s)) => println!("-- {s}"),
            Ok(log::Event::Traffic { .. }) => {}
            // Exit once the worker is done and everything it sent was printed.
            Err(_) if handle.is_finished() => break,
            Err(_) => {}
        }
    }
    STOPPED.store(true, SeqCst);
}

fn cli(args: &[String]) -> i32 {
    let (logger, rx) = log::Logger::new(None);
    match args.first().map(String::as_str) {
        Some("list") => match l2::list_adapters() {
            Ok(list) => {
                for a in list {
                    println!("{:<40} {}  {}", a.id, a.name, a.detail);
                }
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Some("server") if args.len() >= 2 => {
            let port = args
                .get(2)
                .and_then(|p| p.parse().ok())
                .unwrap_or(settings::DEFAULT_PORT);
            let secure = !args.iter().any(|a| a == "--insecure");
            let password = std::env::var("EASYETHER_PASSWORD")
                .map(|p| secure::normalize_password(&p))
                .unwrap_or_else(|_| secure::generate_password());
            if secure {
                println!("Password: {}", secure::display_password(&password));
            }
            let cfg = tunnel::ServerConfig {
                adapter_id: args[1].clone(),
                adapter_name: args[1].clone(),
                port,
                secure,
                password,
            };
            let handle = tunnel::start_server(cfg, logger);
            print_events(rx, &handle);
            0
        }
        Some("client") if args.len() >= 2 => {
            let mut port = settings::DEFAULT_PORT;
            let mut password = String::new();
            let mut secure = true;
            let mut static_ipv4 = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--insecure" => secure = false,
                    "--password" => {
                        password = args.get(i + 1).cloned().unwrap_or_default();
                        i += 1;
                    }
                    "--ip" => {
                        let v = args.get(i + 1).cloned().unwrap_or_default();
                        let parsed = v
                            .split_once('/')
                            .and_then(|(a, p)| Some((a.parse().ok()?, p.parse().ok()?)));
                        if parsed.is_none() {
                            eprintln!("--ip expects <addr>/<prefix>, e.g. 169.254.1.20/16");
                            return 2;
                        }
                        static_ipv4 = parsed;
                        i += 1;
                    }
                    p => match p.parse() {
                        Ok(p) => port = p,
                        Err(_) => {
                            eprint!("{USAGE}");
                            return 2;
                        }
                    },
                }
                i += 1;
            }
            let mut settings = settings::Settings::load();
            let cfg = tunnel::ClientConfig {
                host: args[1].clone(),
                port,
                secure,
                password,
                static_ipv4,
                mac: settings.client_mac(),
            };
            let handle = tunnel::start_client(cfg, logger);
            print_events(rx, &handle);
            0
        }
        _ => {
            eprint!("{USAGE}");
            2
        }
    }
}

/// `--install-drivers` / `--uninstall-drivers`.
#[cfg(windows)]
fn drivers(install: bool) -> i32 {
    use l2::windows::install;
    let (logger, rx) = log::Logger::new(None);
    println!(
        "{} SoftEther drivers...",
        if install { "Installing" } else { "Uninstalling" }
    );
    let result = if install {
        install::install_all(&logger)
    } else {
        install::uninstall_all(&logger)
    };
    for ev in rx.try_iter() {
        if let log::Event::Log(l) = ev {
            println!("{}", l.message);
        }
    }
    match result {
        Ok(()) => 0,
        Err(e) => {
            println!("Failed: {e}");
            1
        }
    }
}

#[cfg(not(windows))]
fn drivers(_install: bool) -> i32 {
    eprintln!("Driver installation is only needed on Windows.");
    0
}
