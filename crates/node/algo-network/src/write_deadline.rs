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

//! The write deadline of an HTTP-over-P2P stream (go v5.1.1
//! `network/p2p/http.go`, `deadlineHost`; issue #2618).
//!
//! go sets an absolute write deadline on every inbound `/algorand-http/1.0.0`
//! stream when it is opened (`httpServerWriteTimeout`, 60 s): a write that is
//! still pending, or starts, after it fails, and the stream is closed. A
//! handler that needs longer (the ledger service serving a catchpoint file)
//! moves it with `http.ResponseController.SetWriteDeadline`. [`WriteDeadline`]
//! is that controller (a handler reads it from the request extensions) and
//! [`DeadlineIo`] enforces it on the byte stream.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// go v5.1.1 `httpServerWriteTimeout`: the write deadline of an inbound
/// HTTP-over-P2P stream, counted from the moment the stream is opened.
pub const HTTP_SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// The movable write deadline of one stream: go's
/// `http.ResponseController.SetWriteDeadline`.
#[derive(Clone, Debug)]
pub struct WriteDeadline {
    at: Arc<Mutex<Instant>>,
}

impl WriteDeadline {
    /// A deadline at `at`.
    pub fn new(at: Instant) -> Self {
        Self {
            at: Arc::new(Mutex::new(at)),
        }
    }

    /// Move the deadline to `at` (earlier or later, like go's).
    pub fn set(&self, at: Instant) {
        *self.at.lock().expect("write deadline mutex poisoned") = at;
    }

    /// The current deadline.
    pub fn get(&self) -> Instant {
        *self.at.lock().expect("write deadline mutex poisoned")
    }
}

/// A byte stream whose writes fail with [`io::ErrorKind::TimedOut`] once its
/// [`WriteDeadline`] has passed, including a write that was already pending
/// when it passed. Reads are untouched (go's read deadline is separate).
pub struct DeadlineIo<S> {
    io: S,
    deadline: WriteDeadline,
    sleep: Pin<Box<Sleep>>,
}

impl<S> DeadlineIo<S> {
    /// Wrap `io`, enforcing `deadline`.
    pub fn new(io: S, deadline: WriteDeadline) -> Self {
        let sleep = Box::pin(tokio::time::sleep_until(deadline.get()));
        Self {
            io,
            deadline,
            sleep,
        }
    }

    /// `Err` once the deadline passed; otherwise registers `cx` to be woken
    /// when it does, so a write blocked on a stalled peer is failed.
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let at = self.deadline.get();
        if self.sleep.deadline() != at {
            self.sleep.as_mut().reset(at);
        }
        match self.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the stream's write deadline passed",
            )),
            Poll::Pending => Ok(()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DeadlineIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DeadlineIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(e) = this.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn write_timeout_matches_go() {
        assert_eq!(HTTP_SERVER_WRITE_TIMEOUT, Duration::from_secs(60));
    }

    /// A write blocked on a peer that does not read fails when the deadline
    /// passes (go: the stream's write deadline fires).
    #[tokio::test(start_paused = true)]
    async fn a_blocked_write_fails_at_the_deadline() {
        let (client, server) = tokio::io::duplex(8);
        let deadline = WriteDeadline::new(Instant::now() + Duration::from_secs(60));
        let mut io = DeadlineIo::new(server, deadline);
        let started = Instant::now();
        let err = io.write_all(&[7u8; 64]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        drop(client);
    }

    /// Moving the deadline later (the ledger service) keeps a slow reader that
    /// makes progress alive past the original one.
    #[tokio::test(start_paused = true)]
    async fn an_extended_deadline_keeps_a_progressing_write() {
        let (mut client, server) = tokio::io::duplex(8);
        let deadline = WriteDeadline::new(Instant::now() + Duration::from_secs(60));
        let mut io = DeadlineIo::new(server, deadline.clone());
        deadline.set(Instant::now() + Duration::from_secs(600));
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut chunk = [0u8; 8];
            while got.len() < 64 {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let n = client.read(&mut chunk).await.unwrap();
                got.extend_from_slice(&chunk[..n]);
            }
            got
        });
        io.write_all(&[7u8; 64]).await.unwrap();
        assert_eq!(reader.await.unwrap(), vec![7u8; 64]);
    }

    /// A deadline moved to the past fails the next write at once.
    #[tokio::test(start_paused = true)]
    async fn a_deadline_in_the_past_fails_the_next_write() {
        let (_client, server) = tokio::io::duplex(1024);
        let deadline = WriteDeadline::new(Instant::now() + Duration::from_secs(60));
        let mut io = DeadlineIo::new(server, deadline.clone());
        io.write_all(b"ok").await.unwrap();
        deadline.set(Instant::now());
        assert_eq!(
            io.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
