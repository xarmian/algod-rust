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

//! `algod-rust health-monitor`: an `algoh`-equivalent block-stall health
//! monitor daemon (issue #966, epic #830/Phase 17).
//!
//! go-algorand's `cmd/algoh` is a standalone operator tool that supervises a
//! running `algod` process and, in parallel, polls its `/v2/status` and
//! `/v2/blocks/{round}` endpoints to detect when block production stalls and
//! to emit per-block telemetry (agreement time, active users, network
//! downtime). This module ports the polling/telemetry half of that —
//! `cmd/algoh/blockstats.go` and `cmd/algoh/blockWatcher.go` — as a
//! `NodeStatus`/`BlockSource`-driven library usable from a CLI subcommand.
//! It intentionally does *not* port `cmd/algoh/main.go`'s process
//! supervision (spawning/restarting a child `algod` binary,
//! `deadman.go`'s watchdog-triggered restart, or telemetry/log upload) —
//! algod-rust's node runs its own REST server in-process rather than being
//! externally supervised the way go's split `algod`/`algoh` binaries are, so
//! there is no child process for this tool to launch or kill. What remains
//! (the stall/catchup/caught-up state machine and block-stats event
//! reporting) is exactly what the issue's acceptance criteria call out.
//!
//! Two pieces, mirroring the two go-algorand files:
//! - [`BlockStats`]: per-block agreement-time/active-user/downtime
//!   tracking, mirroring `blockstats.onBlock` (`blockstats.go`).
//! - [`BlockWatcher`]: the stall → catchup → caught-up polling state
//!   machine, mirroring `blockWatcher.blockIfStalled` /
//!   `blockIfCatchup` / `run` / `runBlockWatcher` (`blockWatcher.go`).
//!
//! Both are generic over a [`HealthClient`] trait (go's `Client` interface,
//! `client.go`) so the state-machine tests below can pin exact call-count
//! and transition behavior against an in-memory mock, exactly as go's own
//! `mockClient`-driven tests do (`blockWatcher_test.go`/
//! `blockstats_test.go`).

use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::info;

use algo_codec::decode_block_response;
use algo_rest_client::AlgodClient;
use algo_rest_client::BlockSource;
use algo_types::{Address, Block, Round};

/// Downtime threshold beyond which the excess inter-block gap is reported
/// as `network_downtime_ms` rather than folded into `agreement_duration_ms`.
/// Matches go's `downtimeLimit` (`cmd/algoh/blockstats.go`).
pub const DOWNTIME_LIMIT: Duration = Duration::from_secs(5 * 60);

/// A client abstraction over "ask a node how far it's gotten" and "fetch
/// one block by round" — go's `Client` interface (`cmd/algoh/client.go`),
/// trimmed to the two methods `blockWatcher` actually calls
/// (`Status`/`RawBlock`; `GetGoRoutines`/`HealthCheck` back go's deadman
/// watcher, which this module doesn't port — see the module doc).
///
/// Every method returns a plain `HealthMonitorError` on failure: go's
/// `blockWatcher` never inspects the error's *kind*, only whether one
/// occurred (a status/block-fetch failure and "no new block yet" are
/// indistinguishable to the polling loop), so there is nothing for a richer
/// error type to buy here.
#[async_trait]
pub trait HealthClient: Send + Sync {
    /// Returns the node's last known committed round (`NodeStatusResponse.LastRound`).
    async fn status(&self) -> Result<u64, HealthMonitorError>;

    /// Fetches and decodes the block at `round`.
    async fn block(&self, round: u64) -> Result<Block, HealthMonitorError>;
}

/// Opaque error used throughout this module — see [`HealthClient`]'s doc
/// for why a richer type isn't warranted.
#[derive(Debug, Clone)]
pub struct HealthMonitorError(pub String);

impl fmt::Display for HealthMonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HealthMonitorError {}

/// [`HealthClient`] backed by a real `algod` REST endpoint, via
/// [`algo_rest_client::AlgodClient`].
pub struct RestHealthClient {
    client: AlgodClient,
}

impl RestHealthClient {
    pub fn new(algod_url: impl Into<String>, algod_token: impl Into<String>) -> Self {
        Self {
            client: AlgodClient::new(algod_url, algod_token),
        }
    }
}

#[async_trait]
impl HealthClient for RestHealthClient {
    async fn status(&self) -> Result<u64, HealthMonitorError> {
        self.client
            .get_status()
            .await
            .map(|s| s.last_round)
            .map_err(|e| HealthMonitorError(e.to_string()))
    }

    async fn block(&self, round: u64) -> Result<Block, HealthMonitorError> {
        let raw = self
            .client
            .get_block_raw(Round(round))
            .await
            .map_err(|e| HealthMonitorError(e.to_string()))?;
        let resp = decode_block_response(&raw).map_err(|e| HealthMonitorError(e.to_string()))?;
        Ok(resp.block)
    }
}

/// Mirrors go's `telemetryspec.BlockStatsEventDetails`
/// (`logging/telemetryspec/events.go`) — the per-block record `blockstats`
/// reports.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockStatsEventDetails {
    pub hash: String,
    pub original_proposer: String,
    pub round: u64,
    pub transactions: u64,
    pub active_users: u64,
    pub agreement_duration_ms: u64,
    pub network_downtime_ms: u64,
}

/// Sink for [`BlockStatsEventDetails`] — go's `EventSender` interface
/// (`blockstats.go`), which in production is `logging.Logger.EventWithDetails`
/// and in go's own tests is a `MockEventSender` capturing every call.
pub trait EventSender: Send {
    fn event_with_details(&mut self, details: BlockStatsEventDetails);
}

/// Production [`EventSender`]: emits every block-stats record as a
/// structured `tracing` event.
#[derive(Default)]
pub struct TracingEventSender;

impl EventSender for TracingEventSender {
    fn event_with_details(&mut self, details: BlockStatsEventDetails) {
        info!(
            round = details.round,
            hash = %details.hash,
            original_proposer = %details.original_proposer,
            transactions = details.transactions,
            active_users = details.active_users,
            agreement_duration_ms = details.agreement_duration_ms,
            network_downtime_ms = details.network_downtime_ms,
            "algoh: block stats"
        );
    }
}

/// Per-block agreement-time/active-user/downtime tracker. Mirrors go's
/// `blockstats` struct and its `init`/`onBlock` methods
/// (`cmd/algoh/blockstats.go`) exactly, including the "only consecutive
/// blocks produce a stats event" behavior and the downtime-over-limit
/// split.
pub struct BlockStats<S: EventSender> {
    log: S,
    last_block: u64,
    last_block_time: Instant,
}

impl<S: EventSender> BlockStats<S> {
    pub fn new(log: S) -> Self {
        Self {
            log,
            last_block: 0,
            last_block_time: Instant::now(),
        }
    }

    /// Mirrors go's `blockstats.init` — an intentional no-op in go itself
    /// (the method body is empty); kept for interface parity with
    /// [`BlockWatcher::run`]'s per-watcher `init` call.
    pub fn init(&mut self, _round: u64) {}

    /// Mirrors go's `blockstats.onBlock` (`blockstats.go:38`).
    pub fn on_block(&mut self, block: &Block) {
        let now = Instant::now();
        let round = block.round.0;

        // Ensure we only create stats from consecutive blocks.
        if self.last_block + 1 != round {
            self.last_block = round;
            self.last_block_time = now;
            return;
        }

        // Grab unique users.
        let mut users: HashSet<Address> = HashSet::new();
        for txn in &block.payset {
            users.insert(txn.txn.sender);
        }

        let duration = now.saturating_duration_since(self.last_block_time);
        let downtime = duration.saturating_sub(DOWNTIME_LIMIT);

        self.log.event_with_details(BlockStatsEventDetails {
            hash: algo_codec::compute_block_digest(block).to_string(),
            original_proposer: block.proposer.to_algorand_string(),
            round,
            transactions: block.payset.len() as u64,
            active_users: users.len() as u64,
            agreement_duration_ms: duration.as_millis() as u64,
            network_downtime_ms: downtime.as_millis() as u64,
        });

        self.last_block = round;
        self.last_block_time = now;
    }
}

/// A block-arrival listener — go's `blockListener` interface
/// (`blockWatcher.go`). [`BlockStats`] implements it via a blanket impl
/// below; this trait is what [`BlockWatcher::run`] fans blocks out to.
pub trait BlockListener: Send {
    fn init(&mut self, round: u64);
    fn on_block(&mut self, block: &Block);
}

impl<S: EventSender> BlockListener for BlockStats<S> {
    fn init(&mut self, round: u64) {
        BlockStats::init(self, round)
    }

    fn on_block(&mut self, block: &Block) {
        BlockStats::on_block(self, block)
    }
}

/// The result of one `run()` pass — go's `run` returns a single `bool`
/// meaning "keep going" (`true`: hit a stall, restart via
/// `blockUntilReady`; `false`: aborted, shut down). Split into an enum here
/// for readability at call sites; [`RunOutcome::Stalled`] corresponds to
/// go's `true`, [`RunOutcome::Aborted`] to `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// No new block arrived within the stall-detection window — go's
    /// `run` returning `true`. The caller should re-run
    /// [`BlockWatcher::block_until_ready`] and resume.
    Stalled,
    /// The watcher was cancelled — go's `run` (or the sleep it's blocked
    /// on) returning `false`.
    Aborted,
}

/// The stall → catchup → caught-up polling state machine. Mirrors go's
/// `blockWatcher` struct and free functions in `cmd/algoh/blockWatcher.go`.
///
/// Cancellation is modeled with a [`CancellationToken`] rather than go's
/// `<-chan struct{}` abort channel — functionally identical: every
/// interruptible sleep in this module races the sleep against
/// cancellation and returns `None`/[`RunOutcome::Aborted`] the instant the
/// token fires, exactly as go's `sleep` helper returns `false` the instant
/// `<-bw.abort` fires.
pub struct BlockWatcher<C: HealthClient> {
    client: C,
    delay: Duration,
    cancel: CancellationToken,
}

impl<C: HealthClient> BlockWatcher<C> {
    pub fn new(client: C, delay: Duration, cancel: CancellationToken) -> Self {
        Self {
            client,
            delay,
            cancel,
        }
    }

    /// Mirrors go's `sleep`: waits `duration`, or returns early (`false`)
    /// if cancelled first.
    async fn sleep(&self, duration: Duration) -> bool {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => false,
            () = tokio::time::sleep(duration) => true,
        }
    }

    /// Mirrors go's `getLastRound`: retries `Status()` forever (subject to
    /// cancellation) until a call succeeds.
    async fn get_last_round(&self) -> Option<u64> {
        loop {
            match self.client.status().await {
                Ok(round) => return Some(round),
                Err(_) => {
                    if !self.sleep(self.delay).await {
                        return None;
                    }
                }
            }
        }
    }

    /// Mirrors go's `blockIfStalled`: keeps polling status until it
    /// changes from the first-observed value, returning the new round.
    pub async fn block_if_stalled(&self) -> Option<u64> {
        let mut cur = self.get_last_round().await?;
        loop {
            let next = self.get_last_round().await?;
            if next != cur {
                return Some(next);
            }
            cur = next;
            if !self.sleep(self.delay).await {
                return None;
            }
        }
    }

    /// Mirrors go's `blockIfCatchup`: blocks until the last-round value
    /// stops changing between two consecutive polls (i.e. catchup has
    /// finished), returning the settled round.
    pub async fn block_if_catchup(&self, start: u64) -> Option<u64> {
        let mut last = start;
        loop {
            if !self.sleep(self.delay).await {
                return None;
            }
            let next = self.get_last_round().await?;
            if last == next {
                return Some(last);
            }
            last = next;
        }
    }

    /// Mirrors go's `blockUntilReady`: `blockIfStalled` then
    /// `blockIfCatchup`.
    pub async fn block_until_ready(&self) -> Option<u64> {
        let cur = self.block_if_stalled().await?;
        self.block_if_catchup(cur).await
    }

    /// Mirrors go's `run`: fetches blocks starting at `cur_block`
    /// sequentially, fanning each one out to every listener, until either
    /// no new block has arrived for `stall_detect` ([`RunOutcome::Stalled`])
    /// or the watcher is cancelled ([`RunOutcome::Aborted`]).
    ///
    /// Go's `run` nests two `for` loops where the outer one immediately
    /// restarts the inner one on `break` with no state change between
    /// iterations — behaviorally a single loop, flattened here.
    async fn run(
        &self,
        watchers: &mut [Box<dyn BlockListener>],
        stall_detect: Duration,
        mut cur_block: u64,
    ) -> RunOutcome {
        let mut last_block = Instant::now();
        loop {
            match self.client.block(cur_block).await {
                Err(_) => {
                    // Generally this error is because the new block isn't
                    // ready yet. In the case of a stall, restart to let the
                    // caller handle any possible stall/catchup.
                    if last_block.elapsed() > stall_detect {
                        return RunOutcome::Stalled;
                    }
                    if !self.sleep(self.delay).await {
                        return RunOutcome::Aborted;
                    }
                }
                Ok(block) => {
                    cur_block += 1;
                    for watcher in watchers.iter_mut() {
                        watcher.on_block(&block);
                    }
                    last_block = Instant::now();
                    if !self.sleep(self.delay).await {
                        return RunOutcome::Aborted;
                    }
                }
            }
        }
    }

    /// Mirrors go's `runBlockWatcher`: the top-level driver loop —
    /// `blockUntilReady` to establish/re-establish a starting round
    /// (initializing every listener on the very first pass, matching go's
    /// single `watcher.init(curBlock)` call before the loop), then `run`
    /// until cancelled, re-synchronizing via `blockUntilReady` after every
    /// stall.
    pub async fn run_block_watcher(
        &self,
        watchers: &mut [Box<dyn BlockListener>],
        stall_detect: Duration,
    ) {
        let Some(mut cur_block) = self.block_until_ready().await else {
            return;
        };

        for watcher in watchers.iter_mut() {
            watcher.init(cur_block);
        }

        loop {
            match self.run(watchers, stall_detect, cur_block).await {
                RunOutcome::Aborted => return,
                RunOutcome::Stalled => match self.block_until_ready().await {
                    Some(next) => cur_block = next,
                    None => return,
                },
            }
        }
    }
}

/// `algod-rust health-monitor` entry point: connects to `algod_url` and
/// runs the block watcher (with [`TracingEventSender`]-backed
/// [`BlockStats`] as its sole listener) until interrupted with Ctrl-C.
pub async fn run(
    algod_url: String,
    algod_token: String,
    poll_interval: Duration,
    stall_detect: Duration,
) -> anyhow::Result<()> {
    let client = RestHealthClient::new(algod_url, algod_token);
    let cancel = CancellationToken::new();
    let watcher = BlockWatcher::new(client, poll_interval, cancel.clone());

    let mut watchers: Vec<Box<dyn BlockListener>> =
        vec![Box::new(BlockStats::new(TracingEventSender))];

    let cancel_for_signal = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("health-monitor: received Ctrl-C, shutting down");
        cancel_for_signal.cancel();
    });

    info!("health-monitor: starting block watcher");
    watcher.run_block_watcher(&mut watchers, stall_detect).await;
    info!("health-monitor: exiting");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use algo_types::{SignedTransaction, Transaction, TxnType};

    fn make_test_block(round: u64) -> Block {
        Block {
            round: Round(round),
            ..Block::default()
        }
    }

    fn make_stxn_with_addr(addr: Address) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender: addr,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ---- BlockStats tests, mirroring blockstats_test.go ----

    #[derive(Default, Clone)]
    struct MockEventSender {
        events: Arc<Mutex<Vec<BlockStatsEventDetails>>>,
    }

    impl EventSender for MockEventSender {
        fn event_with_details(&mut self, details: BlockStatsEventDetails) {
            self.events.lock().unwrap().push(details);
        }
    }

    /// Mirrors go's `TestConsecutiveBlocks` (`blockstats_test.go:54`): only
    /// genuinely consecutive rounds produce a stats event.
    #[test]
    fn consecutive_blocks_only_emit_for_consecutive_rounds() {
        let sender = MockEventSender::default();
        let events = sender.events.clone();
        let mut bs = BlockStats::new(sender);

        bs.on_block(&make_test_block(300));
        // first consecutive block
        bs.on_block(&make_test_block(301));
        // reset
        bs.on_block(&make_test_block(303));
        // second consecutive block
        bs.on_block(&make_test_block(304));

        assert_eq!(events.lock().unwrap().len(), 2);
    }

    /// Mirrors go's `TestEventWithDetails` (`blockstats_test.go:72`):
    /// active-user dedup and per-round transaction counts.
    #[test]
    fn event_with_details_reports_unique_active_users_and_txn_count() {
        let sender = MockEventSender::default();
        let events = sender.events.clone();
        let mut bs = BlockStats::new(sender);

        let addr = Address([0xff; 32]);
        let other_addr = Address([0x07; 32]);

        let mut test_block = make_test_block(300);
        test_block.payset = vec![
            make_stxn_with_addr(addr),
            make_stxn_with_addr(other_addr),
            make_stxn_with_addr(addr),
        ];

        bs.on_block(&make_test_block(299));
        bs.on_block(&test_block);
        bs.on_block(&make_test_block(301));

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].round, 300);
        assert_eq!(events[0].active_users, 2);
        assert_eq!(events[0].transactions, 3);
        assert_eq!(events[1].round, 301);
        assert_eq!(events[1].active_users, 0);
        assert_eq!(events[1].transactions, 0);
    }

    /// Mirrors go's `TestAgreementTime` (`blockstats_test.go:114`): the
    /// reported agreement duration reflects the real wall-clock gap
    /// between consecutive `onBlock` calls.
    #[test]
    fn agreement_time_reflects_wall_clock_gap_between_blocks() {
        let sleep_time = Duration::from_millis(50);

        let sender = MockEventSender::default();
        let events = sender.events.clone();
        let mut bs = BlockStats::new(sender);

        bs.on_block(&make_test_block(300));
        std::thread::sleep(sleep_time);
        bs.on_block(&make_test_block(301));

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].agreement_duration_ms >= sleep_time.as_millis() as u64);
    }

    /// Pins go's downtime-over-limit split (`blockstats.go:56-59`): once the
    /// inter-block gap exceeds `DOWNTIME_LIMIT`, the excess is reported as
    /// `network_downtime_ms` rather than folded silently into
    /// `agreement_duration_ms`.
    #[test]
    fn downtime_over_limit_is_split_into_network_downtime() {
        let sender = MockEventSender::default();
        let events = sender.events.clone();
        let mut bs = BlockStats::new(sender);

        bs.on_block(&make_test_block(300));
        // Simulate a long gap by rewinding last_block_time directly rather
        // than actually sleeping 5+ minutes in a unit test.
        bs.last_block_time = Instant::now() - (DOWNTIME_LIMIT + Duration::from_secs(10));
        bs.on_block(&make_test_block(301));

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        // downtime = duration - DOWNTIME_LIMIT, so it should land close to
        // the 10-second excess (allow scheduling slack).
        assert!(events[0].network_downtime_ms >= 9_000);
        assert!(events[0].agreement_duration_ms >= DOWNTIME_LIMIT.as_millis() as u64);
    }

    // ---- BlockWatcher tests, mirroring blockWatcher_test.go ----

    /// Sequenced [`HealthClient`] mock — mirrors go's `mockClient`: each
    /// call consumes the next queued value, repeating the last one once
    /// the queue is exhausted (`nextError`/`Status`'s "repeat last" logic).
    struct MockClient {
        statuses: Mutex<Vec<u64>>,
        status_calls: Arc<Mutex<u64>>,
        blocks: std::collections::HashMap<u64, Block>,
        block_calls: Arc<Mutex<std::collections::HashMap<u64, u64>>>,
    }

    impl MockClient {
        fn new(statuses: Vec<u64>) -> Self {
            Self {
                statuses: Mutex::new(statuses),
                status_calls: Arc::new(Mutex::new(0)),
                blocks: std::collections::HashMap::new(),
                block_calls: Arc::new(Mutex::new(std::collections::HashMap::new())),
            }
        }

        fn with_blocks(mut self, rounds: &[u64]) -> Self {
            for &r in rounds {
                self.blocks.insert(r, make_test_block(r));
            }
            self
        }
    }

    #[async_trait]
    impl HealthClient for MockClient {
        async fn status(&self) -> Result<u64, HealthMonitorError> {
            *self.status_calls.lock().unwrap() += 1;
            let mut statuses = self.statuses.lock().unwrap();
            if statuses.is_empty() {
                return Err(HealthMonitorError("no status queued".into()));
            }
            let v = statuses[0];
            if statuses.len() > 1 {
                statuses.remove(0);
            }
            Ok(v)
        }

        async fn block(&self, round: u64) -> Result<Block, HealthMonitorError> {
            *self.block_calls.lock().unwrap().entry(round).or_insert(0) += 1;
            self.blocks
                .get(&round)
                .cloned()
                .ok_or_else(|| HealthMonitorError(format!("test is missing block {round}")))
        }
    }

    fn watcher(client: MockClient) -> BlockWatcher<MockClient> {
        BlockWatcher::new(client, Duration::ZERO, CancellationToken::new())
    }

    /// Mirrors go's `TestBlockIfStalled` (`blockWatcher_test.go:43`): status
    /// repeats 300 three times, then reports 301 — `block_if_stalled`
    /// blocks until it observes the change, having made exactly 4 status
    /// calls.
    #[tokio::test]
    async fn block_if_stalled_blocks_until_status_changes() {
        let client = MockClient::new(vec![300, 300, 300, 301]);
        let calls = client.status_calls.clone();
        let bw = watcher(client);

        let ret = bw.block_if_stalled().await;
        assert_eq!(ret, Some(301));
        assert_eq!(*calls.lock().unwrap(), 4);
    }

    /// Mirrors go's `TestBlockIfCatchup` (`blockWatcher_test.go:67`): status
    /// increases every poll; `block_if_catchup` keeps following it until it
    /// repeats twice in a row.
    #[tokio::test]
    async fn block_if_catchup_follows_a_rapidly_advancing_status() {
        let client = MockClient::new(vec![301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 310]);
        let calls = client.status_calls.clone();
        let bw = watcher(client);

        let ret = bw.block_if_catchup(300).await;
        assert_eq!(ret, Some(310));
        assert_eq!(*calls.lock().unwrap(), 11);
    }

    /// Mirrors go's `TestBlockIfCaughtUp` (`blockWatcher_test.go:91`): a
    /// status that isn't changing returns immediately after the first poll.
    #[tokio::test]
    async fn block_if_catchup_returns_immediately_when_already_caught_up() {
        let client = MockClient::new(vec![300]);
        let calls = client.status_calls.clone();
        let bw = watcher(client);

        let ret = bw.block_if_catchup(300).await;
        assert_eq!(ret, Some(300));
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    /// Mirrors go's `TestAbortDuringStall` (`blockWatcher_test.go:176`):
    /// cancelling while `run_block_watcher` is blocked waiting for status
    /// to change must return promptly rather than hanging.
    #[tokio::test]
    async fn run_block_watcher_returns_promptly_on_cancel_during_stall() {
        let client = MockClient::new(vec![300]);
        let cancel = CancellationToken::new();
        // Non-zero delay: without cancellation this would poll forever at
        // this cadence, mirroring go's real (1s delay, 2s stallDetect)
        // scaled down for a fast test.
        let bw = BlockWatcher::new(client, Duration::from_millis(50), cancel.clone());

        let mut watchers: Vec<Box<dyn BlockListener>> = vec![];
        let handle = tokio::spawn(async move {
            bw.run_block_watcher(&mut watchers, Duration::from_millis(200))
                .await;
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run_block_watcher must return promptly after cancellation")
            .expect("task must not panic");
    }

    /// Mirrors go's `TestE2E` (`blockWatcher_test.go:125`): drives the full
    /// `run_block_watcher` loop through an initial catchup, a stall, and a
    /// recovery, and checks that each listener sees exactly the blocks it
    /// should (skipping the stalled round, not double-delivering after
    /// recovery).
    #[tokio::test]
    async fn run_block_watcher_end_to_end_through_catchup_stall_and_recovery() {
        // Status sequence: settle at 302 (catchup), stay there through the
        // stall window, then jump to 322 and settle.
        let client = MockClient::new(vec![
            300, 301, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302,
            322, 322,
        ])
        .with_blocks(&[302, 322]);
        let block_calls = client.block_calls.clone();

        let cancel = CancellationToken::new();
        let bw = BlockWatcher::new(client, Duration::from_millis(10), cancel.clone());

        struct CountingListener {
            init_count: Arc<Mutex<u32>>,
            block_count: Arc<Mutex<u32>>,
        }
        impl BlockListener for CountingListener {
            fn init(&mut self, _round: u64) {
                *self.init_count.lock().unwrap() += 1;
            }
            fn on_block(&mut self, _block: &Block) {
                *self.block_count.lock().unwrap() += 1;
            }
        }

        let init_count = Arc::new(Mutex::new(0));
        let block_count = Arc::new(Mutex::new(0));
        let mut watchers: Vec<Box<dyn BlockListener>> = vec![Box::new(CountingListener {
            init_count: init_count.clone(),
            block_count: block_count.clone(),
        })];

        let handle = tokio::spawn(async move {
            bw.run_block_watcher(&mut watchers, Duration::from_millis(80))
                .await;
        });

        // Poll (rather than a fixed sleep) until both the pre-stall block
        // (302) and the post-recovery block (322) have been delivered, or
        // time out. A fixed-delay checkpoint here is inherently racy: the
        // exact wall-clock point at which each block lands depends on how
        // many `delay`-spaced polls the stall/catchup state machine needs
        // to drain the mock's queued statuses, which is sensitive to
        // scheduler jitter on a loaded CI runner.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if *block_count.lock().unwrap() >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for both blocks to be delivered"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run_block_watcher must return promptly after cancellation")
            .expect("task must not panic");

        assert_eq!(*init_count.lock().unwrap(), 1, "init called exactly once");

        assert_eq!(
            *block_count.lock().unwrap(),
            2,
            "both block 302 (pre-stall) and 322 (post-recovery) delivered"
        );
        // Block 302 fetched exactly once; recovery resumed at 322 without
        // re-fetching every intermediate round (block_until_ready only
        // reads status, never RawBlock).
        let calls = block_calls.lock().unwrap();
        assert_eq!(*calls.get(&302).unwrap(), 1);
        assert_eq!(*calls.get(&322).unwrap(), 1);
    }
}
