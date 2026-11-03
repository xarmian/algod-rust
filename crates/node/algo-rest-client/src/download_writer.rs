// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The dedicated writer thread of one catchpoint download attempt (issue
//! #2139).
//!
//! `tokio::fs` runs every operation on a `spawn_blocking` thread that nobody
//! can wait for once the awaiting future is dropped, and plain `std::fs` calls
//! inside the future would block a runtime worker for the whole multi-GB
//! download. Instead each attempt owns one [`DownloadWriter`]: a `std::thread`
//! that performs the create / write / flush / rename, fed through a bounded
//! channel, so the async side never blocks and never has more than a bounded
//! number of chunks queued.
//!
//! Every writer is counted by a [`WriterTracker`]. Dropping the writer (the
//! download future being dropped by an abort) tells the thread to stop after
//! the operation it is in; [`WriterTracker::wait_idle`] then waits for every
//! such thread to have exited, so that the caller deletes the catchpoint files
//! only when no file operation of the download can still land.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

/// Chunks that may be queued for the writer thread (bounds memory and gives
/// the network side backpressure).
const QUEUED_COMMANDS: usize = 16;

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Counts the live writer threads so a caller can wait until none is left.
#[derive(Default)]
pub(crate) struct WriterTracker {
    active: Mutex<usize>,
    idle: Condvar,
}

impl WriterTracker {
    fn enter(self: &Arc<Self>) -> WriterGuard {
        *locked(&self.active) += 1;
        WriterGuard(Arc::clone(self))
    }

    /// Block until no writer thread is running, or `timeout` passes. True when
    /// idle. Blocking: call it from a thread that may block.
    pub(crate) fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut active = locked(&self.active);
        while *active > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            active = self
                .idle
                .wait_timeout(active, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        true
    }
}

struct WriterGuard(Arc<WriterTracker>);

impl Drop for WriterGuard {
    fn drop(&mut self) {
        *locked(&self.0.active) -= 1;
        self.0.idle.notify_all();
    }
}

type Ack = oneshot::Sender<std::io::Result<()>>;

enum Command {
    Create(PathBuf, Ack),
    Write(Bytes),
    Flush(Ack),
    Rename(PathBuf, PathBuf, Ack),
}

/// The writer thread of one download attempt. See the module documentation.
pub(crate) struct DownloadWriter {
    tx: Option<mpsc::Sender<Command>>,
    stop: Arc<AtomicBool>,
    done: Option<oneshot::Receiver<()>>,
    /// The first failed chunk write, reported by the next write or flush.
    failure: Arc<Mutex<Option<std::io::Error>>>,
}

fn stopped() -> std::io::Error {
    std::io::Error::other("the download writer stopped")
}

impl DownloadWriter {
    /// Start a writer thread, counted by `tracker`. `op_delay` stalls each
    /// operation (a test hook for a slow disk; zero in production).
    pub(crate) fn spawn(tracker: &Arc<WriterTracker>, op_delay: Duration) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel(QUEUED_COMMANDS);
        let (done_tx, done_rx) = oneshot::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let guard = tracker.enter();
        let thread_stop = Arc::clone(&stop);
        let thread_failure = Arc::clone(&failure);
        std::thread::Builder::new()
            .name("catchpoint-writer".to_string())
            .spawn(move || {
                run(rx, thread_stop, thread_failure, op_delay);
                let _ = done_tx.send(());
                drop(guard);
            })?;
        Ok(Self {
            tx: Some(tx),
            stop,
            done: Some(done_rx),
            failure,
        })
    }

    async fn request(&self, make: impl FnOnce(Ack) -> Command) -> std::io::Result<()> {
        let (ack, reply) = oneshot::channel();
        let tx = self.tx.as_ref().ok_or_else(stopped)?;
        tx.send(make(ack)).await.map_err(|_| stopped())?;
        reply.await.map_err(|_| stopped())?
    }

    /// Create (truncate) the file the following writes go to.
    pub(crate) async fn create(&self, path: PathBuf) -> std::io::Result<()> {
        self.request(|ack| Command::Create(path, ack)).await
    }

    /// Queue `data` for writing. A failure of an earlier queued write is
    /// reported here or by [`Self::flush`].
    pub(crate) async fn write(&self, data: Bytes) -> std::io::Result<()> {
        if let Some(e) = locked(&self.failure).as_ref() {
            return Err(std::io::Error::new(e.kind(), e.to_string()));
        }
        let tx = self.tx.as_ref().ok_or_else(stopped)?;
        tx.send(Command::Write(data)).await.map_err(|_| stopped())
    }

    /// Wait until everything queued is written and flushed; reports the first
    /// failed write.
    pub(crate) async fn flush(&self) -> std::io::Result<()> {
        self.request(Command::Flush).await
    }

    /// Close the file and move it to `to`.
    pub(crate) async fn rename(&self, from: PathBuf, to: PathBuf) -> std::io::Result<()> {
        self.request(|ack| Command::Rename(from, to, ack)).await
    }

    /// Stop the thread (after the operation it is in) and wait for it to
    /// exit, so the caller may delete the file.
    pub(crate) async fn close(mut self) {
        self.stop.store(true, Ordering::Release);
        self.tx = None;
        if let Some(done) = self.done.take() {
            let _ = done.await;
        }
    }
}

impl Drop for DownloadWriter {
    /// The download future was dropped: tell the thread to stop. It exits
    /// after the operation it is in; [`WriterTracker::wait_idle`] waits for
    /// that.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn run(
    mut rx: mpsc::Receiver<Command>,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<std::io::Error>>>,
    op_delay: Duration,
) {
    let mut file: Option<std::fs::File> = None;
    while let Some(command) = rx.blocking_recv() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !op_delay.is_zero() {
            std::thread::sleep(op_delay);
        }
        match command {
            Command::Create(path, ack) => {
                let created = std::fs::File::create(&path).map(|f| file = Some(f));
                let _ = ack.send(created);
            }
            Command::Write(data) => {
                let mut failed = locked(&failure);
                if failed.is_none() {
                    let written = match file.as_mut() {
                        Some(f) => f.write_all(&data),
                        None => Err(std::io::Error::other("no file to write to")),
                    };
                    if let Err(e) = written {
                        *failed = Some(e);
                    }
                }
            }
            Command::Flush(ack) => {
                let flushed = match locked(&failure).take() {
                    Some(e) => Err(e),
                    None => file.as_mut().map_or(Ok(()), |f| f.flush()),
                };
                let _ = ack.send(flushed);
            }
            Command::Rename(from, to, ack) => {
                file = None;
                let _ = ack.send(std::fs::rename(from, to));
            }
        }
    }
}
