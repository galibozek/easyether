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
    /// Current tunnel throughput in bytes per second (received from / sent to the peer) and
    /// round-trip time through the tunnel, when measured.
    Traffic {
        rx: u64,
        tx: u64,
        rtt: Option<std::time::Duration>,
    },
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

    pub fn traffic(&self, rx: u64, tx: u64, rtt: Option<std::time::Duration>) {
        self.send(Event::Traffic { rx, tx, rtt })
    }
}

/// "45 s", "12 min 03 s", "2 h 05 min": how long a connection has been up.
pub fn format_uptime(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min {:02} s", s / 60, s % 60)
    } else {
        format!("{} h {:02} min", s / 3600, s % 3600 / 60)
    }
}

/// "<1 ms", "23 ms", "1.2 s": a round-trip time as shown next to the throughput.
pub fn format_rtt(rtt: std::time::Duration) -> String {
    let ms = rtt.as_secs_f64() * 1000.0;
    if ms < 0.5 {
        "<1 ms".into()
    } else if ms < 999.5 {
        format!("{ms:.0} ms")
    } else {
        format!("{:.1} s", ms / 1000.0)
    }
}

/// A byte rate with three significant digits ("842 B/s", "8.42 KB/s", "84.2 KB/s",
/// "842 KB/s", "8.42 MB/s"), so the text keeps about the same width as the value changes.
pub fn format_rate(bytes_per_sec: u64) -> String {
    let b = bytes_per_sec as f64;
    let three = |v: f64, unit: &str| {
        if v < 9.995 {
            format!("{v:.2} {unit}")
        } else if v < 99.95 {
            format!("{v:.1} {unit}")
        } else {
            format!("{v:.0} {unit}")
        }
    };
    if b < 999.5 {
        format!("{bytes_per_sec} B/s")
    } else if b < 999_500.0 {
        three(b / 1e3, "KB/s")
    } else {
        three(b / 1e6, "MB/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn durations_as_shown() {
        assert_eq!(format_uptime(Duration::from_secs(45)), "45 s");
        assert_eq!(format_uptime(Duration::from_secs(12 * 60 + 3)), "12 min 03 s");
        assert_eq!(format_uptime(Duration::from_secs(2 * 3600 + 5 * 60 + 59)), "2 h 05 min");
        assert_eq!(format_rtt(Duration::from_micros(420)), "<1 ms");
        assert_eq!(format_rtt(Duration::from_micros(4_600)), "5 ms");
        assert_eq!(format_rtt(Duration::from_millis(23)), "23 ms");
        assert_eq!(format_rtt(Duration::from_millis(1234)), "1.2 s");
    }

    #[test]
    fn rates_have_three_digits() {
        assert_eq!(format_rate(0), "0 B/s");
        assert_eq!(format_rate(842), "842 B/s");
        assert_eq!(format_rate(999), "999 B/s");
        assert_eq!(format_rate(1_000), "1.00 KB/s");
        assert_eq!(format_rate(8_423), "8.42 KB/s");
        assert_eq!(format_rate(9_999), "10.0 KB/s");
        assert_eq!(format_rate(84_230), "84.2 KB/s");
        assert_eq!(format_rate(842_300), "842 KB/s");
        assert_eq!(format_rate(999_600), "1.00 MB/s");
        assert_eq!(format_rate(17_314_000), "17.3 MB/s");
    }
}
