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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_error::AlgoError;
use algo_types::{BlockResponse, Round};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::BlockSource;

/// Default number of concurrent block fetches, matching Go's `CatchupParallelBlocks`.
pub const DEFAULT_CONCURRENCY: usize = 16;

/// Default bound on how long the pipeline keeps draining already-started
/// fetches after the first failure (see
/// [`ParallelBlockFetcher::with_drain_timeout`]). Long enough for ordinary
/// in-flight requests to report so the lowest failed round normally still
/// gets a recorded outcome, short enough that failure reporting is not held
/// hostage by one hung request.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Slot holding the error of the LOWEST round whose fetch failed (after the
/// [`BlockSource`]'s own retries), with that round. The pipeline closes its
/// channel on a failure; this is how a caller learns *why* (issue #1719), so
/// it can tell "the peer does not have that round" (404) from a transient or
/// auth failure. The lowest failed round is what matters: blocks are
/// delivered in order, so it is the round the consumer is stuck on, and a
/// fast 404 on a later round must not mask a slow/transient failure on an
/// earlier one.
pub type FirstFetchError = Arc<Mutex<Option<(Round, AlgoError)>>>;

/// Fetches blocks in parallel while delivering them in strict round order.
///
/// Mirrors Go's `pipelinedFetch` pattern from `catchup/service.go`:
/// - Spawns up to `concurrency` tasks fetching blocks ahead
/// - Uses a reorder buffer to deliver blocks in order through a bounded channel
/// - On any fetch failure (after `BlockSource`'s built-in retries), cancels the
///   entire pipeline
/// - Supports cancellation by dropping the receiver or via an explicit token
pub struct ParallelBlockFetcher {
    source: Arc<dyn BlockSource>,
    concurrency: usize,
    drain_timeout: Duration,
}

impl ParallelBlockFetcher {
    /// Create a new fetcher with the given block source and concurrency limit.
    pub fn new(source: Arc<dyn BlockSource>, concurrency: usize) -> Self {
        let concurrency = concurrency.max(1);
        Self {
            source,
            concurrency,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }

    /// Bound how long the pipeline keeps draining fetches that were already
    /// in flight when the first one failed (default
    /// [`DEFAULT_DRAIN_TIMEOUT`]).
    ///
    /// Draining lets the in-order prefix below the failure still be delivered
    /// and lets every already-started round record its outcome (so the
    /// lowest failed round's error is known). Without a bound, one hung
    /// request would delay failure reporting for every caller. When the bound
    /// expires the pipeline is cancelled: rounds that had not reported by
    /// then have no recorded outcome.
    #[must_use]
    pub fn with_drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    /// Create a new fetcher with the default concurrency of 16.
    pub fn with_defaults(source: Arc<dyn BlockSource>) -> Self {
        Self::new(source, DEFAULT_CONCURRENCY)
    }

    /// Fetch blocks in the range `[start, end)` and deliver them in order.
    ///
    /// Returns a receiver that yields `(Round, BlockResponse)` pairs in
    /// ascending round order. The channel is bounded to `concurrency` to
    /// provide backpressure.
    ///
    /// On any fetch failure, the pipeline is cancelled: all in-flight tasks
    /// are stopped and the channel is closed.
    ///
    /// Dropping the returned receiver also cancels all in-flight fetches.
    pub fn fetch_range(
        &self,
        start: Round,
        end: Round,
        cancel: CancellationToken,
    ) -> mpsc::Receiver<(Round, BlockResponse)> {
        self.fetch_range_tracked(start, end, cancel).0
    }

    /// Like [`Self::fetch_range`], but also returns a [`FirstFetchError`]
    /// slot that is filled with the lowest failed round's error before the
    /// channel closes. A closed channel with an empty slot means the range
    /// was cancelled externally (or finished). After the first failure no new
    /// rounds are started, but fetches already in flight are drained (for at
    /// most [`Self::with_drain_timeout`]) so the in-order prefix below the
    /// failure is still delivered and every already-started round that
    /// reports in time gets a recorded outcome.
    pub fn fetch_range_tracked(
        &self,
        start: Round,
        end: Round,
        cancel: CancellationToken,
    ) -> (mpsc::Receiver<(Round, BlockResponse)>, FirstFetchError) {
        let (tx, rx) = mpsc::channel(self.concurrency);
        let source = Arc::clone(&self.source);
        let concurrency = self.concurrency;
        let drain_timeout = self.drain_timeout;
        let first_error: FirstFetchError = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&first_error);

        tokio::spawn(async move {
            Self::run_pipeline(
                source,
                concurrency,
                drain_timeout,
                start,
                end,
                tx,
                cancel,
                slot,
            )
            .await;
        });

        (rx, first_error)
    }

    /// Core pipeline loop. Spawns fetch tasks with bounded concurrency via a
    /// semaphore and reorders results before sending them downstream.
    #[allow(clippy::too_many_arguments)]
    async fn run_pipeline(
        source: Arc<dyn BlockSource>,
        concurrency: usize,
        drain_timeout: Duration,
        start: Round,
        end: Round,
        tx: mpsc::Sender<(Round, BlockResponse)>,
        cancel: CancellationToken,
        first_error: FirstFetchError,
    ) {
        use std::collections::BTreeMap;

        if start.0 >= end.0 {
            return;
        }

        let semaphore = Arc::new(Semaphore::new(concurrency));

        // Channel for individual fetch results (unbounded so tasks don't block).
        let (result_tx, mut result_rx) =
            mpsc::unbounded_channel::<(Round, Result<BlockResponse, AlgoError>)>();

        let total = end.0 - start.0;
        let mut spawned: u64 = 0;
        let mut next_to_deliver = start.0;
        let mut reorder_buf: BTreeMap<u64, BlockResponse> = BTreeMap::new();
        let mut received: u64 = 0;
        // Set on the first failed fetch: stop starting rounds, drain the rest.
        let mut failed = false;
        // Set with `failed`: when the bounded drain gives up on stragglers.
        let mut drain_deadline: Option<tokio::time::Instant> = None;

        loop {
            // Spawn new tasks up to the semaphore limit, as long as we haven't
            // spawned everything yet and aren't cancelled.
            while spawned < total && !failed && !cancel.is_cancelled() {
                // Try to acquire the semaphore without blocking.
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => break, // at concurrency limit, wait for results
                };

                let round = Round(start.0 + spawned);
                let src = Arc::clone(&source);
                let rtx = result_tx.clone();
                let tok = cancel.clone();

                tokio::spawn(async move {
                    let _permit = permit; // held until task completes
                    let result = tokio::select! {
                        _ = tok.cancelled() => return,
                        r = src.get_block(round) => r,
                    };
                    match result {
                        Ok(block) => {
                            let _ = rtx.send((round, Ok(block)));
                        }
                        Err(e) => {
                            warn!(round = %round, error = %e, "block fetch failed, draining pipeline");
                            let _ = rtx.send((round, Err(e)));
                        }
                    }
                });

                spawned += 1;
            }

            if cancel.is_cancelled() {
                debug!("pipeline cancelled");
                return;
            }

            // Wait for the next result, or cancellation.
            let (round, result) = tokio::select! {
                _ = cancel.cancelled() => {
                    debug!("pipeline cancelled while waiting for results");
                    return;
                }
                _ = async {
                    match drain_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {
                    // The first failure was recorded and the prefix below it
                    // delivered; do not let a hung in-flight fetch delay
                    // failure reporting any longer. Rounds that have not
                    // reported by now have no recorded outcome.
                    warn!(
                        in_flight = spawned - received,
                        timeout = ?drain_timeout,
                        "drain after block fetch failure timed out; cancelling pipeline"
                    );
                    cancel.cancel();
                    return;
                }
                msg = result_rx.recv() => match msg {
                    Some(v) => v,
                    None => return,
                }
            };

            received += 1;

            match result {
                Err(e) => {
                    // Record why before the channel closes; the lowest
                    // failed round wins.
                    if let Ok(mut slot) = first_error.lock() {
                        if slot.as_ref().is_none_or(|(r, _)| round.0 < r.0) {
                            *slot = Some((round, e));
                        }
                    }
                    if !failed {
                        drain_deadline = Some(tokio::time::Instant::now() + drain_timeout);
                    }
                    failed = true;
                }
                Ok(block) => {
                    reorder_buf.insert(round.0, block);
                }
            }

            // Deliver as many consecutive blocks as possible.
            while let Some(block) = reorder_buf.remove(&next_to_deliver) {
                let round = Round(next_to_deliver);
                if tx.send((round, block)).await.is_err() {
                    // Receiver dropped -- cancel the pipeline.
                    debug!("receiver dropped, cancelling pipeline");
                    cancel.cancel();
                    return;
                }
                next_to_deliver += 1;
            }

            // All done? (After a failure: once every started round reported.)
            if received == total {
                return;
            }
            if failed && received == spawned {
                // Everything started has reported; the prefix below the
                // lowest failure is delivered. Cancel like a failure always
                // has, so a shared token observes it.
                cancel.cancel();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_error::Result;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use crate::NodeStatus;

    /// Per-round scripted source: `(delay_ms, error)` per round.
    struct Scripted(fn(u64) -> (u64, Option<AlgoError>));

    #[async_trait]
    impl BlockSource for Scripted {
        async fn get_block_raw(&self, _round: Round) -> Result<Vec<u8>> {
            unimplemented!()
        }
        async fn get_block(&self, round: Round) -> Result<BlockResponse> {
            let (delay, err) = (self.0)(round.0);
            tokio::time::sleep(Duration::from_millis(delay)).await;
            match err {
                Some(e) => Err(e),
                None => Ok(MockBlockSource::make_block(round.0)),
            }
        }
        async fn get_status(&self) -> Result<NodeStatus> {
            unimplemented!()
        }
        async fn wait_for_round(&self, _round: Round) -> Result<NodeStatus> {
            unimplemented!()
        }
    }

    async fn run_scripted(
        script: fn(u64) -> (u64, Option<AlgoError>),
    ) -> (Vec<u64>, Option<(u64, AlgoError)>) {
        let fetcher = ParallelBlockFetcher::new(Arc::new(Scripted(script)), 8);
        let (mut rx, slot) =
            fetcher.fetch_range_tracked(Round(1), Round(9), CancellationToken::new());
        let mut got = Vec::new();
        while let Some((r, _)) = rx.recv().await {
            got.push(r.0);
        }
        let err = slot.lock().unwrap().take().map(|(r, e)| (r.0, e));
        (got, err)
    }

    /// A fast failure on a later round must not mask the lowest failed round:
    /// round 1 is slow and fails transiently, round 2 fails fast with a 404.
    #[tokio::test]
    async fn tracked_fetch_records_the_lowest_failed_round_not_the_first_to_arrive() {
        let (got, err) = run_scripted(|r| match r {
            1 => (
                80,
                Some(AlgoError::Network {
                    message: "reset".into(),
                }),
            ),
            2 => (0, Some(AlgoError::NotFound("404".into()))),
            _ => (0, None),
        })
        .await;
        assert!(got.is_empty());
        let (round, e) = err.expect("an error must be recorded");
        assert_eq!(round, 1);
        assert!(matches!(e, AlgoError::Network { .. }), "{e:?}");
    }

    /// The other ordering: round 1 is merely slow but succeeds, round 2 is a
    /// 404. The prefix `[1]` is delivered and the 404 is recorded for round 2.
    #[tokio::test]
    async fn tracked_fetch_delivers_the_prefix_then_records_the_404() {
        let (got, err) = run_scripted(|r| match r {
            1 => (60, None),
            2 => (0, Some(AlgoError::NotFound("404".into()))),
            3.. => (0, Some(AlgoError::NotFound("404".into()))),
            _ => (0, None),
        })
        .await;
        assert_eq!(got, vec![1]);
        let (round, e) = err.expect("an error must be recorded");
        assert_eq!(round, 2);
        assert!(matches!(e, AlgoError::NotFound(_)), "{e:?}");
    }

    /// Issue #1725: after the first failure the pipeline drains in-flight
    /// fetches, but only for a bounded time -- one hung request must not
    /// delay failure reporting. Virtual time: round 2 would take an hour.
    #[tokio::test(start_paused = true)]
    async fn tracked_fetch_bounds_the_drain_after_the_first_failure() {
        let fetcher = ParallelBlockFetcher::new(
            Arc::new(Scripted(|r| match r {
                1 => (
                    0,
                    Some(AlgoError::Network {
                        message: "reset".into(),
                    }),
                ),
                2 => (3_600_000, None),
                _ => (0, None),
            })),
            8,
        )
        .with_drain_timeout(Duration::from_secs(30));
        let started = tokio::time::Instant::now();
        let (mut rx, slot) =
            fetcher.fetch_range_tracked(Round(1), Round(9), CancellationToken::new());
        assert!(rx.recv().await.is_none(), "nothing is deliverable");
        let waited = started.elapsed();
        assert!(
            waited <= Duration::from_secs(31),
            "failure reporting waited {waited:?} for a hung in-flight fetch"
        );
        let (round, e) = slot.lock().unwrap().take().expect("error recorded");
        assert_eq!(round.0, 1);
        assert!(matches!(e, AlgoError::Network { .. }), "{e:?}");
    }

    /// A slow in-flight round that finishes inside the drain bound is still
    /// drained: its block is delivered (prefix) and the later 404 recorded.
    #[tokio::test(start_paused = true)]
    async fn tracked_fetch_still_drains_a_slow_round_within_the_bound() {
        let fetcher = ParallelBlockFetcher::new(
            Arc::new(Scripted(|r| match r {
                1 => (10_000, None),
                2 => (0, Some(AlgoError::NotFound("404".into()))),
                _ => (0, None),
            })),
            8,
        )
        .with_drain_timeout(Duration::from_secs(30));
        let (mut rx, slot) =
            fetcher.fetch_range_tracked(Round(1), Round(9), CancellationToken::new());
        let mut got = Vec::new();
        while let Some((r, _)) = rx.recv().await {
            got.push(r.0);
        }
        assert_eq!(got, vec![1]);
        assert_eq!(slot.lock().unwrap().take().unwrap().0 .0, 2);
    }

    /// A clean fetch leaves the slot empty.
    #[tokio::test]
    async fn tracked_fetch_leaves_the_slot_empty_on_success() {
        let (got, err) = run_scripted(|_| (0, None)).await;
        assert_eq!(got.len(), 8);
        assert!(err.is_none());
    }

    /// A mock block source that returns blocks after a variable delay.
    /// If `fail_round` is set, fetching that round returns an error.
    struct MockBlockSource {
        fail_round: Option<u64>,
        fetch_count: AtomicU64,
        /// Maximum delay in millis for each fetch.
        max_delay_ms: u64,
    }

    impl MockBlockSource {
        fn new() -> Self {
            Self {
                fail_round: None,
                fetch_count: AtomicU64::new(0),
                max_delay_ms: 20,
            }
        }

        fn with_fail_round(round: u64) -> Self {
            Self {
                fail_round: Some(round),
                fetch_count: AtomicU64::new(0),
                max_delay_ms: 20,
            }
        }

        fn with_max_delay(mut self, ms: u64) -> Self {
            self.max_delay_ms = ms;
            self
        }

        fn get_fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }

        fn make_block(round: u64) -> BlockResponse {
            // Construct via JSON deserialization since Block has many fields
            // but all except `rnd` have `#[serde(default)]`.
            let json = serde_json::json!({
                "block": { "rnd": round }
            });
            serde_json::from_value(json).expect("mock block construction")
        }
    }

    #[async_trait]
    impl BlockSource for MockBlockSource {
        async fn get_block_raw(&self, _round: Round) -> Result<Vec<u8>> {
            unimplemented!("not used in tests")
        }

        async fn get_block(&self, round: Round) -> Result<BlockResponse> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);

            // Simulate variable latency for out-of-order completion.
            let delay = if self.max_delay_ms > 0 {
                // Simple deterministic "random" based on round number.
                let delay_ms = (round.0 * 7 + 3) % self.max_delay_ms;
                Duration::from_millis(delay_ms)
            } else {
                Duration::ZERO
            };
            tokio::time::sleep(delay).await;

            if self.fail_round == Some(round.0) {
                return Err(algo_error::AlgoError::Conformance {
                    message: format!("mock failure at round {round}"),
                });
            }

            Ok(Self::make_block(round.0))
        }

        async fn get_status(&self) -> Result<NodeStatus> {
            unimplemented!("not used in tests")
        }

        async fn wait_for_round(&self, _round: Round) -> Result<NodeStatus> {
            unimplemented!("not used in tests")
        }
    }

    #[tokio::test]
    async fn test_in_order_delivery() {
        let source = Arc::new(MockBlockSource::new().with_max_delay(20));
        let fetcher = ParallelBlockFetcher::new(source, 4);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(10), Round(30), cancel);

        let mut expected = 10u64;
        while let Some((round, block)) = rx.recv().await {
            assert_eq!(round.0, expected, "blocks must arrive in order");
            assert_eq!(block.block.round.0, expected);
            expected += 1;
        }
        assert_eq!(expected, 30, "should have received all 20 blocks");
    }

    #[tokio::test]
    async fn test_empty_range() {
        let source = Arc::new(MockBlockSource::new());
        let fetcher = ParallelBlockFetcher::new(source, 4);
        let cancel = CancellationToken::new();

        // start == end
        let mut rx = fetcher.fetch_range(Round(5), Round(5), cancel.clone());
        assert!(rx.recv().await.is_none());

        // start > end
        let mut rx = fetcher.fetch_range(Round(10), Round(5), cancel);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_single_block() {
        let source = Arc::new(MockBlockSource::new().with_max_delay(0));
        let fetcher = ParallelBlockFetcher::new(source, 4);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(42), Round(43), cancel);

        let (round, block) = rx.recv().await.expect("should get one block");
        assert_eq!(round.0, 42);
        assert_eq!(block.block.round.0, 42);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_backpressure() {
        // Use a large range with concurrency=2 and channel capacity=2.
        // The fetcher should not run ahead unbounded.
        let source = Arc::new(MockBlockSource::new().with_max_delay(0));
        let fetcher = ParallelBlockFetcher::new(Arc::clone(&source) as Arc<dyn BlockSource>, 2);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(0), Round(50), cancel);

        // Let the fetcher run for a bit without consuming.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The fetcher should be bounded: channel(2) + semaphore(2) means at
        // most ~4 blocks can be in flight/buffered at once. The fetch count
        // should be well below 50.
        let fetched = source.get_fetch_count();
        assert!(
            fetched < 20,
            "fetcher should be bounded by backpressure, but fetched {fetched}"
        );

        // Now drain everything.
        let mut count = 0u64;
        while let Some((round, _)) = rx.recv().await {
            assert_eq!(round.0, count);
            count += 1;
        }
        assert_eq!(count, 50);
    }

    #[tokio::test]
    async fn test_cancellation_by_dropping_receiver() {
        let source = Arc::new(MockBlockSource::new().with_max_delay(5));
        let fetcher = ParallelBlockFetcher::new(source.clone(), 4);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(0), Round(100), cancel.clone());

        // Consume a few blocks then drop.
        for _ in 0..3 {
            let _ = rx.recv().await;
        }
        drop(rx);

        // Give tasks time to notice cancellation.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The pipeline should have stopped well before fetching all 100 blocks.
        let fetched = source.get_fetch_count();
        assert!(
            fetched < 50,
            "pipeline should stop after receiver drop, but fetched {fetched}"
        );
    }

    #[tokio::test]
    async fn test_cancellation_by_token() {
        let source = Arc::new(MockBlockSource::new().with_max_delay(10));
        let fetcher = ParallelBlockFetcher::new(source.clone(), 4);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(0), Round(100), cancel.clone());

        // Consume a couple of blocks.
        let _ = rx.recv().await;
        let _ = rx.recv().await;

        // Cancel via token.
        cancel.cancel();

        // Give tasks time to wind down.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Channel should close soon after cancellation.
        // Drain any buffered blocks.
        let mut count = 0;
        while rx.recv().await.is_some() {
            count += 1;
            if count > 100 {
                panic!("channel should have closed after cancellation");
            }
        }

        let fetched = source.get_fetch_count();
        assert!(
            fetched < 50,
            "pipeline should stop after token cancel, but fetched {fetched}"
        );
    }

    #[tokio::test]
    async fn test_error_cancels_pipeline() {
        // Fail at round 5 out of [0, 20).
        let source = Arc::new(MockBlockSource::with_fail_round(5).with_max_delay(5));
        let fetcher = ParallelBlockFetcher::new(source.clone(), 4);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(0), Round(20), cancel.clone());

        // Collect whatever we get -- we should get rounds 0..5 in order,
        // then the channel closes because round 5 failed.
        let mut received = Vec::new();
        while let Some((round, _)) = rx.recv().await {
            received.push(round.0);
        }

        // We should have gotten rounds 0 through 4 (the ones before the failure).
        assert_eq!(
            received,
            vec![0, 1, 2, 3, 4],
            "should deliver blocks before the failing round, got: {received:?}"
        );

        // The cancellation token should be set.
        assert!(
            cancel.is_cancelled(),
            "pipeline should have cancelled on error"
        );
    }

    #[tokio::test]
    async fn test_high_concurrency() {
        // Concurrency larger than the range -- should still work fine.
        let source = Arc::new(MockBlockSource::new().with_max_delay(5));
        let fetcher = ParallelBlockFetcher::new(source, 32);
        let cancel = CancellationToken::new();
        let mut rx = fetcher.fetch_range(Round(0), Round(10), cancel);

        let mut expected = 0u64;
        while let Some((round, _)) = rx.recv().await {
            assert_eq!(round.0, expected);
            expected += 1;
        }
        assert_eq!(expected, 10);
    }
}
