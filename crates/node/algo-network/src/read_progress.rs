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

//! The per-message read deadline of a websocket peer (go v5.1.1
//! `network/wsPeer.go` `readLoop`, `maxMessageReadDuration`; issue #2612).
//!
//! go waits for the next message with no read deadline, and once a message has
//! started (`NextReader` returned: the header of its first data frame was read)
//! gives the peer `maxMessageReadDuration` to deliver the rest of it, so a peer
//! that sends the first frame and stalls cannot keep the partially received
//! message's buffers allocated forever. The websocket libraries algod-rust uses
//! (tokio-tungstenite outbound, axum inbound) only ever yield complete
//! messages, so the start of a partial one is not visible to the read loop.
//! [`ProgressIo`] sits under the websocket on the plain TCP stream, follows the
//! websocket frame boundaries in the bytes that pass through, and publishes
//! when the message in flight must be complete by; the read loops race their
//! `next()` against [`read_deadline_passed`].
//!
//! Control frames (ping, pong, close) are not part of a message, exactly as in
//! go, where `NextReader` handles them inside the call, before the deadline is
//! set. `wss` connections are not followed (their bytes are TLS records), the
//! same limit as the response header cap in `connect.rs`.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::time::Instant;

/// go `maxMessageQueueDuration` (`network/wsNetwork.go`): how long a message
/// may wait in a send queue before it is dropped.
pub const MAX_MESSAGE_QUEUE_DURATION: Duration = Duration::from_secs(25);

/// go `maxMessageReadDuration` (`network/wsPeer.go`): how long a peer has to
/// deliver the rest of a message once it has started, twice
/// [`MAX_MESSAGE_QUEUE_DURATION`].
pub const MAX_MESSAGE_READ_DURATION: Duration = Duration::from_secs(2 * 25);

/// go `peerDisconnectionAckDuration` (`network/wsNetwork.go`): how long a close
/// frame may take to be written before the socket is dropped.
pub const PEER_DISCONNECTION_ACK_DURATION: Duration = Duration::from_secs(5);

/// Follows the websocket frames of the bytes it is fed and says when a data
/// message has started and not yet completed.
#[derive(Debug)]
struct FrameTracker {
    state: State,
    /// When the message in flight started (its first data frame header was read).
    started: Option<Instant>,
}

#[derive(Debug)]
enum State {
    /// Reading a frame header: the bytes so far, and how many it needs.
    Head { buf: [u8; 14], have: usize },
    /// Skipping a payload of `left` more bytes.
    Payload {
        left: u64,
        /// A data frame (text, binary or continuation), as opposed to control.
        data: bool,
        fin: bool,
    },
}

impl FrameTracker {
    fn new() -> Self {
        Self {
            state: State::Head {
                buf: [0; 14],
                have: 0,
            },
            started: None,
        }
    }

    /// Bytes a header needs, once its first two bytes are known.
    fn head_len(first_two: &[u8]) -> usize {
        let ext = match first_two[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let mask = if first_two[1] & 0x80 != 0 { 4 } else { 0 };
        2 + ext + mask
    }

    fn feed(&mut self, mut bytes: &[u8], now: Instant) {
        while !bytes.is_empty() {
            match &mut self.state {
                State::Head { buf, have } => {
                    // the header's length is known after its first two bytes
                    let need = if *have < 2 {
                        2
                    } else {
                        Self::head_len(&buf[..2])
                    };
                    let take = (need - *have).min(bytes.len());
                    buf[*have..*have + take].copy_from_slice(&bytes[..take]);
                    *have += take;
                    bytes = &bytes[take..];
                    if *have < 2 || *have < Self::head_len(&buf[..2]) {
                        continue;
                    }
                    let b0 = buf[0];
                    let opcode = b0 & 0x0f;
                    let fin = b0 & 0x80 != 0;
                    let ext = match buf[1] & 0x7f {
                        126 => u64::from(u16::from_be_bytes([buf[2], buf[3]])),
                        127 => u64::from_be_bytes([
                            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                        ]),
                        n => u64::from(n),
                    };
                    let data = opcode < 8;
                    // go: the deadline is set when `NextReader` returns, after the
                    // header of the first data frame of a message
                    if data && opcode != 0 && self.started.is_none() {
                        self.started = Some(now);
                    }
                    self.state = State::Payload {
                        left: ext,
                        data,
                        fin,
                    };
                    self.finish_if_empty();
                }
                State::Payload { left, .. } => {
                    let take = (*left).min(bytes.len() as u64);
                    *left -= take;
                    bytes = &bytes[take as usize..];
                    self.finish_if_empty();
                }
            }
        }
    }

    /// A payload that has been read completely ends its frame, and a data
    /// frame with FIN ends the message.
    fn finish_if_empty(&mut self) {
        if let State::Payload { left: 0, data, fin } = self.state {
            if data && fin {
                self.started = None;
            }
            self.state = State::Head {
                buf: [0; 14],
                have: 0,
            };
        }
    }
}

/// What the read loops wait on: when the message in flight started (`None`
/// while no message is in flight, an idle peer is kept).
#[derive(Clone, Debug)]
pub struct ReadProgress {
    rx: watch::Receiver<Option<Instant>>,
    armed: Arc<AtomicBool>,
    max_duration: Duration,
}

impl ReadProgress {
    /// Start following the stream's bytes as websocket frames. An accepted
    /// connection's stream carries the HTTP upgrade request first; the upgrade
    /// handler arms it, when everything the peer may send before our `101`
    /// response has been read, so the next byte is the start of a frame.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Resolves once a message that has started is still incomplete after the
    /// read duration; never otherwise. Cancel safe.
    pub async fn deadline_passed(&mut self) {
        read_deadline_passed(Some(self)).await
    }

    /// When the message in flight started, if any.
    pub fn started(&self) -> Option<Instant> {
        *self.rx.borrow()
    }
}

/// [`ReadProgress::deadline_passed`] for a connection that may have none: with
/// `None` it never resolves.
///
/// go sets its deadline when `NextReader` returns, so only time the loop spends
/// reading counts: a message whose first bytes were read ahead while the loop
/// was busy with the previous one starts its clock when the loop comes back to
/// wait (this call), not when the bytes arrived.
pub async fn read_deadline_passed(progress: Option<&mut ReadProgress>) {
    let Some(progress) = progress else {
        return std::future::pending().await;
    };
    let entered = Instant::now();
    let max = progress.max_duration;
    loop {
        let started = *progress.rx.borrow_and_update();
        match started {
            Some(t0) => {
                let at = t0.max(entered) + max;
                tokio::select! {
                    _ = tokio::time::sleep_until(at) => {
                        // re-read: the message may have completed in the meantime
                        if progress
                            .started()
                            .is_some_and(|s| s.max(entered) + max <= Instant::now())
                        {
                            return;
                        }
                    }
                    changed = progress.rx.changed() => {
                        if changed.is_err() {
                            return std::future::pending().await;
                        }
                    }
                }
            }
            None => {
                if progress.rx.changed().await.is_err() {
                    return std::future::pending().await;
                }
            }
        }
    }
}

/// The frame follower of one connection, attachable to any byte stream
/// ([`ProgressIo::with_tap`]); the TLS case builds its handle before the
/// decrypted stream exists.
pub struct ProgressTap {
    tracker: FrameTracker,
    tx: watch::Sender<Option<Instant>>,
    /// Whether the bytes read are frames yet (see [`ReadProgress::arm`]).
    armed: Arc<AtomicBool>,
    max_duration: Duration,
}

impl ProgressTap {
    /// A follower, and the handle the read loops wait on. `armed` false for a
    /// stream whose first bytes are not frames yet.
    pub fn new(max_duration: Duration, armed: bool) -> (Self, ReadProgress) {
        let (tx, rx) = watch::channel(None);
        let armed = Arc::new(AtomicBool::new(armed));
        let progress = ReadProgress {
            rx,
            armed: armed.clone(),
            max_duration,
        };
        (
            Self {
                tracker: FrameTracker::new(),
                tx,
                armed,
                max_duration,
            },
            progress,
        )
    }

    fn on_read(&mut self, bytes: &[u8]) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        let was = self.tracker.started;
        self.tracker.feed(bytes, Instant::now());
        if self.tracker.started != was {
            self.tx.send_replace(self.tracker.started);
        }
    }
}

/// A byte stream that follows the websocket frames read from it (see the
/// module docs). Writes and everything else pass through untouched.
pub struct ProgressIo<S> {
    io: S,
    /// `None` when the stream is not followed.
    tap: Option<ProgressTap>,
}

impl<S> std::fmt::Debug for ProgressIo<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressIo")
            .field("tracked", &self.tap.is_some())
            .finish_non_exhaustive()
    }
}

impl<S> ProgressIo<S> {
    /// Follow the frames read from `io`; a message that has started must be
    /// complete after `max_duration`.
    pub fn new(io: S, max_duration: Duration) -> Self {
        Self::with_tap(io, ProgressTap::new(max_duration, true).0)
    }

    /// Attach `tap` to `io`.
    pub fn with_tap(io: S, tap: ProgressTap) -> Self {
        Self { io, tap: Some(tap) }
    }

    /// [`Self::new`] for a stream that has already delivered `read_ahead` (the
    /// bytes after the handshake response that the dialer read with it).
    pub fn new_after(io: S, max_duration: Duration, read_ahead: &[u8]) -> Self {
        let (mut tap, _) = ProgressTap::new(max_duration, true);
        tap.on_read(read_ahead);
        Self::with_tap(io, tap)
    }

    /// Pass `io` through without following it (a TLS stream's bytes are not
    /// websocket frames).
    pub fn untracked(io: S) -> Self {
        Self { io, tap: None }
    }

    /// The handle the read loops wait on, or `None` for an untracked stream.
    pub fn progress(&self) -> Option<ReadProgress> {
        self.tap.as_ref().map(|tap| ReadProgress {
            rx: tap.tx.subscribe(),
            armed: tap.armed.clone(),
            max_duration: tap.max_duration,
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProgressIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(tap)) = (&polled, this.tap.as_mut()) {
            tap.on_read(&buf.filled()[before..]);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProgressIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MAX: Duration = Duration::from_secs(50);

    /// A masked (client to server) or unmasked frame.
    fn frame(opcode: u8, fin: bool, payload: &[u8], masked: bool) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
        let mbit = if masked { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(mbit | n as u8),
            n if n <= 0xffff => {
                f.push(mbit | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(mbit | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if masked {
            f.extend_from_slice(&[1, 2, 3, 4]);
        }
        f.extend_from_slice(payload);
        f
    }

    fn feed_in_chunks(t: &mut FrameTracker, bytes: &[u8], chunk: usize, now: Instant) {
        for c in bytes.chunks(chunk) {
            t.feed(c, now);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_is_in_flight_from_its_first_header_to_its_last_byte() {
        let now = Instant::now();
        for (payload_len, masked) in [(5, false), (300, true), (70_000, false)] {
            let bytes = frame(2, true, &vec![9u8; payload_len], masked);
            for chunk in [1, 3, 7, bytes.len()] {
                let mut t = FrameTracker::new();
                // all but the last byte: started, not complete
                feed_in_chunks(&mut t, &bytes[..bytes.len() - 1], chunk, now);
                assert_eq!(t.started, Some(now), "len {payload_len} chunk {chunk}");
                t.feed(&bytes[bytes.len() - 1..], now);
                assert_eq!(t.started, None);
            }
        }
    }

    /// The deadline starts at the first header, not at the later bytes, and a
    /// header alone starts it.
    #[tokio::test(start_paused = true)]
    async fn the_deadline_counts_from_the_first_header() {
        let mut t = FrameTracker::new();
        let start = Instant::now();
        let bytes = frame(2, true, &[1u8; 100], true);
        t.feed(&bytes[..6], start); // header only (2 + 4 mask)
        assert_eq!(t.started, Some(start));
        t.feed(&bytes[6..50], start + Duration::from_secs(10));
        assert_eq!(t.started, Some(start), "later bytes do not move it");
    }

    #[tokio::test(start_paused = true)]
    async fn a_fragmented_message_ends_with_its_fin_frame() {
        let now = Instant::now();
        let mut t = FrameTracker::new();
        t.feed(&frame(2, false, b"abc", false), now);
        assert!(t.started.is_some(), "no FIN yet");
        t.feed(&frame(0, false, b"def", false), now);
        assert!(t.started.is_some());
        t.feed(&frame(0, true, b"g", false), now);
        assert_eq!(t.started, None);
    }

    /// go: control frames are handled inside `NextReader`, so a ping, even a
    /// partial one, does not start a message, and one in the middle of a message
    /// does not end it.
    #[tokio::test(start_paused = true)]
    async fn control_frames_are_not_part_of_a_message() {
        let now = Instant::now();
        let mut t = FrameTracker::new();
        let ping = frame(9, true, b"12345678", false);
        t.feed(&ping[..5], now);
        assert_eq!(t.started, None, "a partial ping starts nothing");
        t.feed(&ping[5..], now);
        assert_eq!(t.started, None);

        t.feed(&frame(2, false, b"abc", false), now);
        t.feed(&frame(9, true, b"", false), now);
        t.feed(&frame(10, true, b"x", false), now);
        assert!(
            t.started.is_some(),
            "a ping inside a message does not end it"
        );
        t.feed(&frame(0, true, b"z", false), now);
        assert_eq!(t.started, None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_message_completes_at_its_header() {
        let now = Instant::now();
        let mut t = FrameTracker::new();
        t.feed(&frame(2, true, b"", true), now);
        assert_eq!(t.started, None);
        t.feed(&frame(2, true, b"", false), now);
        assert_eq!(t.started, None);
    }

    /// A stalled message resolves `deadline_passed` at the deadline; an idle
    /// connection, and a message that completes in time, never do.
    #[tokio::test(start_paused = true)]
    async fn deadline_passed_fires_only_for_a_stalled_message() {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let mut io = ProgressIo::new(server, MAX);
        let mut progress = io.progress().unwrap();
        let bytes = frame(2, true, &[1u8; 100], false);
        let mut sink = vec![0u8; 1024];

        // idle: nothing happens for far longer than the duration
        let idle = tokio::time::timeout(MAX * 4, progress.deadline_passed()).await;
        assert!(idle.is_err(), "an idle peer is kept");

        // a message that completes in time
        client.write_all(&bytes[..20]).await.unwrap();
        let n = io.read(&mut sink).await.unwrap();
        assert_eq!(n, 20);
        assert!(progress.started().is_some());
        let started = Instant::now();
        tokio::time::sleep(Duration::from_secs(40)).await;
        client.write_all(&bytes[20..]).await.unwrap();
        let _ = io.read(&mut sink).await.unwrap();
        assert_eq!(progress.started(), None);
        let still = tokio::time::timeout(MAX * 4, progress.deadline_passed()).await;
        assert!(still.is_err(), "a message completed in time is not dropped");

        // a stalled one
        client.write_all(&bytes[..20]).await.unwrap();
        let _ = io.read(&mut sink).await.unwrap();
        let stalled_at = Instant::now();
        progress.deadline_passed().await;
        assert_eq!(stalled_at.elapsed(), MAX);
        assert!(started < stalled_at);
    }

    /// go counts only the time the loop spends reading: a message whose first
    /// bytes were read ahead while the loop was busy starts its clock when the
    /// loop waits for it again.
    #[tokio::test(start_paused = true)]
    async fn time_the_loop_is_busy_does_not_count() {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let mut io = ProgressIo::new(server, MAX);
        let mut progress = io.progress().unwrap();
        let bytes = frame(2, true, &[1u8; 100], false);
        let mut sink = vec![0u8; 1024];

        // the first bytes of a message arrive, and nobody waits for it for 40 s
        client.write_all(&bytes[..20]).await.unwrap();
        let _ = io.read(&mut sink).await.unwrap();
        tokio::time::sleep(Duration::from_secs(40)).await;

        // the loop is back: the peer has the whole duration from here
        let back = Instant::now();
        progress.deadline_passed().await;
        assert_eq!(back.elapsed(), MAX);
    }
}
