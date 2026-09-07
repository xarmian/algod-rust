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

//! Outbound connection-rate-limiting wrapper (issue #1088, Phase 17 gap).
//!
//! Mirrors the wait-loop at the heart of go-algorand's
//! `network/limitcaller` package (`RateLimitingBoundTransport::RoundTrip`
//! and `Dialer::DialContext`, both of which loop on
//! `phonebook.GetConnectionWaitTime`/`UpdateConnectionTime`): before making
//! an outbound connection attempt to an address, consult the phonebook's
//! per-address rate limiter and sleep as needed, bounded by a queueing
//! timeout, before actually attempting the connection.
//!
//! [`crate::phonebook::Phonebook::get_connection_wait_time`] and
//! [`crate::phonebook::Phonebook::update_connection_time`] already port
//! go's `phonebook.ConnectionTimeStore` interface faithfully (with their
//! own direct unit tests) — what go-algorand's `limitcaller` package adds
//! on top is just the wait-then-call-then-record loop that drives them from
//! an actual outbound call. [`rate_limited_call`] is that loop, generic
//! over the outbound operation so it isn't tied to `http.RoundTripper` or
//! `net.Dialer` specifically (algod-rust's outbound gossip connections are
//! WebSocket dials via `tokio_tungstenite`, not raw HTTP round trips) —
//! wiring it into `connect.rs`'s actual dial path is left as documented
//! follow-up, since that requires passing a `Phonebook` reference through
//! call sites that don't currently have one (see the follow-up issue filed
//! alongside this port).

use std::future::Future;
use std::time::{Duration, Instant};

use crate::phonebook::Phonebook;

/// Default time budget for waiting in the rate-limit queue before giving up
/// (go: `limitcaller.DefaultQueueingTimeout`).
pub const DEFAULT_QUEUEING_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors returned by [`rate_limited_call`].
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError<E> {
    /// The queueing timeout elapsed before the rate limiter allowed the
    /// call to proceed (go: `ErrConnectionQueueingTimeout`).
    #[error("rate_limited_call: queueing timeout")]
    QueueingTimeout,
    /// The wrapped call itself failed.
    #[error(transparent)]
    Inner(E),
}

/// Waits (bounded by `queueing_timeout`) for `phonebook`'s per-address rate
/// limiter to admit a new connection to `addr`, then runs `call` and
/// records the connection time.
///
/// Mirrors go's `RateLimitingBoundTransport::RoundTrip` /
/// `Dialer::DialContext` loop: repeatedly ask the phonebook how long to
/// wait, sleep that long (unless it would blow the queueing deadline, in
/// which case give up), and retry until the wait is zero.
pub async fn rate_limited_call<F, Fut, T, E>(
    phonebook: &Phonebook,
    addr: &str,
    queueing_timeout: Duration,
    call: F,
) -> Result<T, RateLimitError<E>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let queueing_deadline = Instant::now() + queueing_timeout;
    let provisional_time;
    loop {
        let (_, wait_time, provisional) = phonebook.get_connection_wait_time(addr);
        if wait_time.is_zero() {
            provisional_time = provisional;
            break;
        }
        let wait_deadline = Instant::now() + wait_time;
        if wait_deadline < queueing_deadline {
            tokio::time::sleep(wait_time).await;
            continue;
        }
        return Err(RateLimitError::QueueingTimeout);
    }

    let result = call().await.map_err(RateLimitError::Inner)?;
    phonebook.update_connection_time(addr, provisional_time);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_role::RELAY_ROLE;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Builds a phonebook with the given rate-limit parameters and
    /// registers `addr` in it — `Phonebook::get_connection_wait_time` only
    /// rate-limits addresses it already knows about (an address it has
    /// never seen always gets `wait == 0`, per that method's own doc
    /// comment), so every test needs its address registered via
    /// `replace_peer_list` first, exactly as the real dial path would after
    /// a DNS-bootstrap/phonebook-file load.
    fn phonebook_with(addr: &str, count: usize, window: Duration) -> Phonebook {
        let pb = Phonebook::new(count, window);
        pb.replace_peer_list(&[addr.to_string()], "default", RELAY_ROLE);
        pb
    }

    #[tokio::test]
    async fn proceeds_immediately_when_under_the_limit() {
        let pb = phonebook_with("10.0.0.1:4160", 5, Duration::from_secs(60));

        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let result: Result<u32, RateLimitError<()>> = rate_limited_call(
            &pb,
            "10.0.0.1:4160",
            Duration::from_secs(1),
            || async move {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok(42u32)
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn waits_out_the_rate_limit_window_before_calling() {
        // Capacity of 1 within a short window: the first call fills the
        // window immediately; a second call to the same address must wait
        // roughly the window duration before the rate limiter admits it.
        let window = Duration::from_millis(120);
        let addr = "10.0.0.2:4160";
        let pb = phonebook_with(addr, 1, window);

        let first: Result<(), RateLimitError<()>> =
            rate_limited_call(&pb, addr, Duration::from_secs(5), || async { Ok(()) }).await;
        assert!(first.is_ok());

        let start = Instant::now();
        let second: Result<(), RateLimitError<()>> =
            rate_limited_call(&pb, addr, Duration::from_secs(5), || async { Ok(()) }).await;
        let elapsed = start.elapsed();

        assert!(second.is_ok());
        assert!(
            elapsed >= window / 2,
            "expected a real wait close to the rate-limit window, got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn gives_up_when_the_wait_would_exceed_the_queueing_timeout() {
        let window = Duration::from_secs(30);
        let addr = "10.0.0.3:4160";
        let pb = phonebook_with(addr, 1, window);

        // Fill the one available slot.
        let first: Result<(), RateLimitError<()>> =
            rate_limited_call(&pb, addr, Duration::from_secs(1), || async { Ok(()) }).await;
        assert!(first.is_ok());

        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let result: Result<(), RateLimitError<()>> = rate_limited_call(
            &pb,
            addr,
            Duration::from_millis(20), // far shorter than the 30s window
            || async move {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(matches!(result, Err(RateLimitError::QueueingTimeout)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the wrapped call must not run once the queueing timeout gives up"
        );
    }

    #[tokio::test]
    async fn propagates_the_inner_call_error() {
        let addr = "10.0.0.4:4160";
        let pb = phonebook_with(addr, 5, Duration::from_secs(60));

        let result: Result<(), RateLimitError<&'static str>> =
            rate_limited_call(&pb, addr, Duration::from_secs(1), || async {
                Err("dial refused")
            })
            .await;

        match result {
            Err(RateLimitError::Inner(e)) => assert_eq!(e, "dial refused"),
            other => panic!("expected Inner(\"dial refused\"), got {other:?}"),
        }
    }
}
