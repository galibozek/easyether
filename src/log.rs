//! Log lines and state updates sent from worker threads to the GUI (or stdout in CLI mode).

use std::sync::mpsc::{Receiver, Sender, channel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warning => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub message: String,
}

impl std::fmt::Display for LogLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}] {}", self.time, self.level.label(), self.message)
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Log(LogLine),
    Status(String),
    /// Current tunnel throughput in bytes per second (received from / sent to the peer).
    Traffic { rx: u64, tx: u64 },
}

/// Cloneable sender used by worker threads.
#[derive(Clone)]
pub struct Logger {
    tx: Sender<Event>,
    wake: Option<eframe::egui::Context>,
}

impl Logger {
    pub fn new(wake: Option<eframe::egui::Context>) -> (Logger, Receiver<Event>) {
        let (tx, rx) = channel();
        (Logger { tx, wake }, rx)
    }

    fn send(&self, ev: Event) {
        let _ = self.tx.send(ev);
        if let Some(ctx) = &self.wake {
            ctx.request_repaint();
        }
    }

    pub fn log(&self, level: Level, message: impl Into<String>) {
        self.send(Event::Log(LogLine {
            time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            level,
            message: message.into(),
        }));
    }

    pub fn info(&self, message: impl Into<String>) {
        self.log(Level::Info, message)
    }

    pub fn warn(&self, message: impl Into<String>) {
        self.log(Level::Warning, message)
    }

    pub fn error(&self, message: impl Into<String>) {
        self.log(Level::Error, message)
    }

    pub fn status(&self, status: impl Into<String>) {
        self.send(Event::Status(status.into()))
    }

    pub fn traffic(&self, rx: u64, tx: u64) {
        self.send(Event::Traffic { rx, tx })
    }
}

/// "12.3 KB/s" style formatting of a byte rate.
pub fn format_rate(bytes_per_sec: u64) -> String {
    let b = bytes_per_sec as f64;
    if b < 1000.0 {
        format!("{bytes_per_sec} B/s")
    } else if b < 1_000_000.0 {
        format!("{:.1} KB/s", b / 1000.0)
    } else {
        format!("{:.2} MB/s", b / 1_000_000.0)
    }
}
