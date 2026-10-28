//! What the Server and Client tabs have in common: a background worker (`TunnelHandle`), its
//! event channel, status line, log and throughput.

use std::sync::mpsc::Receiver;

use eframe::egui;

use super::widgets::LogView;
use crate::log::{Event, Logger};
use crate::tunnel::TunnelHandle;

pub struct Worker {
    pub logger: Logger,
    rx: Receiver<Event>,
    pub handle: Option<TunnelHandle>,
    pub status: String,
    pub log: LogView,
    /// Current throughput (rx, tx) in bytes per second.
    pub traffic: (u64, u64),
}

impl Worker {
    pub fn new(ctx: &egui::Context, status: &str) -> Worker {
        let (logger, rx) = Logger::new(Some(ctx.clone()));
        Worker { logger, rx, handle: None, status: status.into(), log: LogView::default(), traffic: (0, 0) }
    }

    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Drains worker events; joins the thread once it has finished.
    pub fn poll(&mut self) {
        for ev in self.rx.try_iter() {
            match ev {
                Event::Log(l) => self.log.push(l),
                Event::Status(s) => self.status = s,
                Event::Traffic { rx, tx } => self.traffic = (rx, tx),
            }
        }
        if self.handle.as_ref().is_some_and(|h| h.is_finished()) {
            self.handle.take().unwrap().join();
        }
    }

    /// Asks the worker to stop; `status` is shown until it reports its own final status.
    pub fn stop(&mut self, status: &str) {
        if let Some(h) = &self.handle {
            h.stop();
            self.status = status.into();
        }
    }

    /// Stops and waits for the worker (application exit).
    pub fn shutdown(&mut self) {
        if let Some(h) = self.handle.take() {
            h.join();
        }
    }
}

/// TCP port from a text field; logs the error and returns None when invalid.
pub fn parse_port(text: &str, logger: &Logger) -> Option<u16> {
    match text.trim().parse::<u16>() {
        Ok(p) if p > 0 => Some(p),
        _ => {
            logger.error("The port must be a number between 1 and 65535.");
            None
        }
    }
}
