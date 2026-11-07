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

//! Catchup service: fetches missing blocks identified by agreement certificates.
//!
//! When the agreement service has a valid certificate but not the corresponding
//! block, it sends a [`PendingUnmatchedCertificate`] on a channel.  The
//! `CatchupService` receives from that channel, fetches the block from the
//! network, and commits it to the ledger via [`LedgerWriter::ensure_block`].
//!
//! Mirrors Go's `catchup.Service` in `go-algorand/catchup/service.go`,
//! specifically the `syncCert` / `fetchRound` path that handles certificate-
//! driven single-block fetches.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{self, Receiver, Select};
use tracing::{debug, error, info, trace, warn};

use algo_agreement::{Certificate, PendingUnmatchedCertificate};
use algo_types::{Block, Round};

// ---------------------------------------------------------------------------
// FetchedBlockCert
// ---------------------------------------------------------------------------

/// A block together with its optional agreement certificate, as returned by
/// a [`BlockFetcher`].
///
/// The certificate may be `None` when the fetcher's transport does not
/// provide certificate data (e.g. some mock implementations). When present,
/// it can be used for fork-detection checks mirroring Go's `fetchRound`.
#[derive(Debug, Clone)]
pub struct FetchedBlockCert {
    /// The fetched block.
    pub block: Block,
    /// The agreement certificate, if the transport provided one.
    pub cert: Option<Certificate>,
    /// Raw msgpack blobs for each SignedTxnInBlock entry, preserved from the
    /// wire format. When present these are used for payset commitment
    /// verification instead of re-encoding from typed structs.
    pub raw_payset_blobs: Option<Vec<Vec<u8>>>,
}

// ---------------------------------------------------------------------------
// CatchupLedger trait
// ---------------------------------------------------------------------------

/// Abstraction over the ledger operations needed by the catchup service.
///
/// This decouples `CatchupService` from concrete types like `SqliteLedger`
/// and `AgreementLedgerBridge`, making it easy to supply lightweight mocks
/// in tests.
///
/// Implementations must be thread-safe (`Send + Sync`) because the catchup
/// service runs on a dedicated background thread.
pub trait CatchupLedger: Send + Sync {
    /// Returns the next round the ledger expects (i.e. `last_committed + 1`).
    ///
    /// Used to decide whether a certificate's round has already been committed.
    fn next_round(&self) -> Round;

    /// Commit a block together with its authenticating certificate.
    ///
    /// Semantically identical to [`algo_agreement::LedgerWriter::ensure_block`].
    fn ensure_block(&self, block: &Block, cert: &Certificate);

    /// Check whether `round` requires a protocol version this node does not
    /// support.
    ///
    /// Mirrors Go's `Service.roundIsNotSupported()` from
    /// `catchup/service.go`. The Go implementation reads the last committed
    /// block header and checks whether:
    ///
    /// 1. A protocol upgrade is pending (`NextProtocolSwitchOn != 0`).
    /// 2. The upgrade target (`NextProtocol`) is **not** in the supported
    ///    consensus map.
    /// 3. The requested `round` is >= the switch-on round.
    ///
    /// If all three conditions hold, the round requires an unsupported
    /// protocol and this method should return `true`.
    ///
    /// The default implementation returns `false` (optimistic: assume all
    /// rounds are supported). Concrete implementations backed by a real
    /// ledger should override this once block-header access is available.
    fn round_is_not_supported(&self, _round: Round) -> bool {
        false
    }

    /// Whether the ledger is currently lagging on committing account-delta
    /// changes to disk and catchup should apply backpressure.
    ///
    /// Mirrors Go's `Ledger.IsBehindCommittingDeltas()`
    /// (`catchup/service.go`), checked by `pipelinedFetch` after each round
    /// commits successfully: `if s.ledger.IsBehindCommittingDeltas() { ...
    /// return errCatchupBehindDeltas }`. When this returns `true`,
    /// [`CatchupService`]'s periodic sync pass stops early (after
    /// committing whatever it has already fetched) rather than continuing
    /// to pile up unflushed state, the same partial-but-bounded-progress
    /// behavior go's `TestServiceLedgerUnavailable` pins.
    ///
    /// The default implementation returns `false` (never behind), so
    /// existing `CatchupLedger` implementations are unaffected unless they
    /// opt in.
    fn is_behind_committing_deltas(&self) -> bool {
        false
    }

    /// Authenticate a block fetched by the *periodic* catchup path against
    /// the certificate the serving peer supplied.
    ///
    /// The certificate-driven path ([`CatchupService::sync_cert`]) already
    /// holds a certificate its own agreement service verified, so it only
    /// needs a digest comparison. The periodic path has no such anchor: the
    /// block and the certificate both come from an untrusted peer, so the
    /// certificate's quorum has to be checked before the block is committed.
    ///
    /// Mirrors Go's `s.auth.Authenticate(block, cert)` in
    /// `catchup/service.go`'s `fetchAndWrite`.
    ///
    /// The default implementation refuses everything, so an implementation
    /// that cannot authenticate never silently accepts unverified blocks;
    /// [`crate::AgreementLedgerBridge`] overrides it with a real quorum
    /// check.
    fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
        Err("this ledger cannot authenticate certificates".to_string())
    }

    /// While the ledger is stalled on a block that deterministically fails
    /// to apply (issue #1677), how long the periodic sync must still wait
    /// before retrying it; `None` when not stalled (the normal cadence).
    ///
    /// [`crate::AgreementLedgerBridge`] answers from its shared
    /// [`crate::ApplyStallTracker`]. The default (`None`) keeps every other
    /// implementation on the unchanged ~8 s retry.
    ///
    /// `next_round` is the ledger's next round as the caller already read it
    /// (so implementations need no second ledger lock); a stall on a round
    /// below it is stale.
    fn apply_stall_retry_in(&self, _next_round: Round) -> Option<Duration> {
        None
    }

    /// Digest of the block that failed to apply while stalled (issue
    /// #1677), so the certificate path can skip only that same bad block.
    fn apply_stall_failed_digest(&self) -> Option<algo_types::Digest> {
        None
    }
}

// ---------------------------------------------------------------------------
// FetchError
// ---------------------------------------------------------------------------

/// Error type returned by [`BlockFetcher::fetch_block`].
///
/// Provides structured error variants so callers can distinguish between
/// transient failures (network, timeout) and permanent ones (no peers),
/// enabling smarter retry logic in the catchup service.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The peer(s) did not have a block for the requested round.
    #[error("no block available for round {round}")]
    NoBlockForRound { round: Round },

    /// A network-level error occurred while fetching.
    #[error("network error: {0}")]
    NetworkError(String),

    /// The fetch request timed out.
    #[error("fetch timed out")]
    Timeout,

    /// No peers are available to fetch from.
    #[error("no peers available")]
    NoPeersAvailable,
}

// ---------------------------------------------------------------------------
// BlockFetcher trait
// ---------------------------------------------------------------------------

/// Abstraction for fetching blocks from the network.
///
/// This decouples the catchup service from any specific transport (HTTP, WS,
/// mock, etc.).  Implementations should attempt to fetch the block for the
/// given round, retrying across peers as appropriate.
///
/// The method is synchronous (blocking) because the catchup service runs on
/// a dedicated background thread.  Async implementations can use
/// `tokio::runtime::Handle::block_on` or a similar mechanism.
pub trait BlockFetcher: Send + Sync {
    /// Fetch the block (and optional certificate) for the given round.
    ///
    /// Returns `Ok(FetchedBlockCert)` on success, or a [`FetchError`] on
    /// failure.
    ///
    /// Implementations **must** apply a reasonable timeout (e.g. via the
    /// HTTP client's connection/request timeout) so that a single call does
    /// not block the catchup worker thread indefinitely. The
    /// `GossipBlockFetcher` in `participate.rs` inherits the 4-second
    /// per-peer timeout from `GossipBlockSource`, and `HttpBlockFetcher`
    /// uses a 30-second default.
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError>;
}

// ---------------------------------------------------------------------------
// CatchupService
// ---------------------------------------------------------------------------

/// Service that fetches missing blocks identified by agreement certificates.
///
/// Mirrors Go's `catchup.Service`, specifically the `periodicSync` select
/// branch that receives from `unmatchedPendingCertificates` and calls
/// `syncCert` / `fetchRound`.
///
/// # Lifecycle
///
/// 1. Call [`CatchupService::start`] to spawn the background worker thread.
/// 2. The worker loops, selecting on the certificate channel and a shutdown
///    signal.
/// 3. Call [`CatchupService::stop`] to signal shutdown and join the thread.
pub struct CatchupService {
    /// Shutdown signal sender for the periodic-sync worker thread —
    /// dropping or sending signals it to exit.
    shutdown_tx: Option<crossbeam_channel::Sender<()>>,
    /// Join handle for the periodic-sync background worker thread.
    join_handle: Option<JoinHandle<()>>,
    /// Shutdown signal sender for the certificate-driven worker thread
    /// (issue #1576) — see [`Self::cert_loop`]'s doc comment for why this
    /// is a second, independent thread rather than a branch of the same
    /// select loop `join_handle` drives.
    cert_shutdown_tx: Option<crossbeam_channel::Sender<()>>,
    /// Join handle for the certificate-driven background worker thread.
    cert_join_handle: Option<JoinHandle<()>>,
    /// Counter tracking the number of fork detections observed.
    /// Callers can query this via [`CatchupService::fork_count`] for
    /// monitoring / alerting purposes.
    fork_count: Arc<AtomicU64>,
    /// Nanosecond `UNIX_EPOCH` timestamp at which the current periodic
    /// sync pass ([`Self::sync_pass`]) started, or `0` when no pass is
    /// currently running.
    ///
    /// Mirrors Go's `Service.syncStartNS` (`catchup/service.go`), read by
    /// [`Self::synchronizing_time`] (go's `SynchronizingTime()`). Unlike
    /// Go's `sync()`, which covers both the certificate-driven and
    /// periodic-timer entry points into the same function, this only wraps
    /// [`Self::sync_pass`] — the periodic (certificate-less) pass that
    /// mirrors go's `sync()`/`pipelinedFetch`. `sync_cert`'s single-round
    /// certificate-driven fetch has no `sync()`-equivalent wrapper in Go
    /// either (`syncCert` never touches `syncStartNS`), so it is
    /// intentionally excluded here too.
    syncing_since_ns: Arc<AtomicI64>,
    /// Sender for [`Self::sync_now`]'s trigger-and-wait requests. The
    /// worker thread selects on the matching receiver alongside the
    /// certificate channel and shutdown signal (mirrors go's `syncNow`
    /// channel selected in `periodicSync`), runs a [`Self::sync_pass`], and
    /// replies with the [`SyncExitReason`] on the one-shot channel sent
    /// along with the request.
    trigger_tx: Option<crossbeam_channel::Sender<SyncWaiter>>,
}

/// Outcome of a single worker's fetch attempt in [`CatchupService::sync_pass`],
/// sent back to the main thread for in-order validation/apply.
///
/// Validation itself (round match, certificate presence, authentication,
/// contents-match-header) stays single-threaded so it runs exactly once per
/// round, in round order, identically to the pre-#753 serial code — only
/// the network I/O is parallelized across workers.
///
/// Boxed so `Unsupported`'s zero-data variant doesn't force every message
/// (including the common `Unsupported` case) to be sized for the much
/// larger `Ok(FetchedBlockCert)` payload.
enum FetchOutcome {
    /// The round requires a protocol version this node does not support
    /// (checked before fetching).
    Unsupported,
    /// The fetch itself failed or returned the wrong round's block.
    Fetch(Box<Result<FetchedBlockCert, FetchError>>),
}

/// Typed exit reason for a sync pass ([`CatchupService::sync_pass_inner`])
/// or a single certificate-driven fetch ([`CatchupService::sync_cert`]).
///
/// Mirrors go's typed `pipelinedFetch`/`fetchAndWrite` exit errors
/// (`errCatchupNoPeer`, `errFetchNoBlock`/`errFetchRetryLimit`,
/// `errCatchupStopping`, `errCatchupBehindDeltas`, and — implicitly, via a
/// `nil` error — successful/normal completion) from `catchup/service.go`.
/// Every outcome used to be only observable indirectly via tracing log
/// level or mock-state polling; this gives callers (and tests, mirroring
/// go's `TestPipelinedFetchExitReason`) a value to assert on directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncExitReason {
    /// The pass/fetch completed normally: every requested round was
    /// fetched and committed (or, for `sync_cert`, the target round was
    /// already in the ledger). Go's `nil` return from `pipelinedFetch` /
    /// `fetchAndWrite` (the loop exits only because there is nothing left
    /// to do, not because of an error).
    Done,
    /// No peer was available to fetch from. Mirrors go's
    /// `errCatchupNoPeer`.
    NoPeer,
    /// The remote peer(s) do not have the block, or repeated fetch
    /// attempts exhausted the retry budget without success. Mirrors go's
    /// `errFetchNoBlock` / `errFetchRetryLimit`. Also the exit of a pass that
    /// could not start any fetch worker thread: it is retried at the next
    /// tick like a pass that reached the tip (`sync_now` has no caller that
    /// reads this as "synced").
    NoBlock,
    /// Shutdown was signaled mid-pass. Mirrors go's `errCatchupStopping`.
    Stopping,
    /// The ledger reported it is behind on committing deltas and catchup
    /// backed off to relieve memory pressure. Mirrors go's
    /// `errCatchupBehindDeltas`; see
    /// [`CatchupLedger::is_behind_committing_deltas`].
    BehindDeltas,
    /// The next round requires a protocol version this node does not
    /// support. Not a distinct typed error in go (go's
    /// `unsupportedRoundMonitor` cancels the whole service's context
    /// instead of `pipelinedFetch` returning a specific error for it), but
    /// distinguished here since it is a meaningfully different exit cause
    /// from the fetch failures above.
    Unsupported,
}

/// What one periodic-sync timeout tick should do (see
/// [`CatchupService::periodic_tick_action`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeriodicTick {
    /// The ledger advanced since the last tick: reset the stuck counter.
    Advanced,
    /// First tick without progress: re-arm for one more interval.
    Rearm,
    /// Stuck, but the ledger is stalled on an invalid block and its
    /// exponential backoff has not elapsed (issue #1677): do nothing.
    BackOff,
    /// Stuck: run a sync pass.
    Sync,
}

/// A `sync_now` caller waiting for the answer of the pass that serves it.
type SyncWaiter = crossbeam_channel::Sender<SyncExitReason>;

/// Minimum spacing of the "no fetch worker could be started" warning.
const NO_WORKER_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Starts one fetch worker thread. Production uses `Builder::spawn`; a test
/// injects one that fails, to reach the real `Err` arm of the spawn
/// (issue #1650).
type SpawnFn = dyn Fn(
        thread::Builder,
        Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<thread::JoinHandle<()>>
    + Send
    + Sync;

#[derive(Clone)]
struct WorkerSpawner(Arc<SpawnFn>);

impl WorkerSpawner {
    fn spawn(
        &self,
        builder: thread::Builder,
        body: Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        (self.0)(builder, body)
    }
}

impl std::fmt::Debug for WorkerSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkerSpawner")
    }
}

/// Retry timing of a pass's fetch workers (see
/// [`CatchupService::fetch_round_with_retries`]). Production uses
/// [`FetchPolicy::default`]; tests shorten it.
#[derive(Debug, Clone)]
struct FetchPolicy {
    /// go's `errNoBlockForRoundThreshold`.
    no_block_threshold: u32,
    /// Pause between attempts after a transport error / timeout.
    retry_backoff: Duration,
    /// Pause between "no block" answers: go's `followLatestBackoff`.
    no_block_backoff: Duration,
    /// Consecutive transport failures of one round after which the worker
    /// gives up and the pass ends, so the service loop regains control.
    wall_bound: Duration,
    /// How a fetch worker thread is started.
    spawner: WorkerSpawner,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            no_block_threshold: 5,
            retry_backoff: Duration::from_millis(100),
            no_block_backoff: Duration::from_millis(100),
            wall_bound: Duration::from_secs(30),
            spawner: WorkerSpawner(Arc::new(|builder, body| builder.spawn(body))),
        }
    }
}

/// State shared by one pass's fetch workers and its apply loop.
struct PassCtx {
    policy: FetchPolicy,
    /// Rounds `> window_limit` are not fetched: set to `U` when round `U`
    /// turned out to need an unsupported protocol (the apply loop stops there).
    window_limit: AtomicU64,
    /// A worker has seen the network tip (a "no block" answer or a final
    /// fetch failure): the pass is in its tip-probe / exit phase and no
    /// longer takes `sync_now` requests.
    tip_seen: AtomicBool,
    /// Rounds currently probing the tip; only the lowest keeps retrying.
    probing: std::sync::Mutex<std::collections::BTreeSet<u64>>,
    /// The round the apply loop waits for next (its cursor), for the workers'
    /// tip gate (issue #2204).
    applied: AtomicU64,
    /// A round's fetch FINALLY failed (its worker returned an error result:
    /// retries exhausted, or given up because a lower round is probing): the
    /// apply loop stops the pass at the first failed round, so no round far
    /// beyond it is worth claiming (the workers' tip gate). Unlike `tip_seen`,
    /// one transient "no block" answer that a later attempt resolves does not
    /// set it.
    fetch_failed: AtomicBool,
    /// The number of fetch workers that actually started: the tip gate's
    /// bound and the window are both derived from it.
    workers: AtomicU64,
    /// Bumped by every [`Self::notify_progress`]; a gated worker that read it
    /// before its failed claim does not sleep when it has changed since, so no
    /// wake-up can be missed.
    progress_version: AtomicU64,
    /// Gated workers sleep here until the cursor moves or the pass stops
    /// (no polling).
    progress: (std::sync::Mutex<()>, std::sync::Condvar),
}

impl PassCtx {
    fn new(policy: FetchPolicy) -> Self {
        Self {
            policy,
            window_limit: AtomicU64::new(u64::MAX),
            tip_seen: AtomicBool::new(false),
            probing: std::sync::Mutex::new(Default::default()),
            applied: AtomicU64::new(0),
            fetch_failed: AtomicBool::new(false),
            workers: AtomicU64::new(0),
            progress_version: AtomicU64::new(0),
            progress: (std::sync::Mutex::new(()), std::sync::Condvar::new()),
        }
    }

    /// Wake the gated workers (the cursor moved, or the pass is stopping).
    fn notify_progress(&self) {
        self.progress_version.fetch_add(1, Ordering::SeqCst);
        let _guard = self.progress.0.lock().unwrap_or_else(|e| e.into_inner());
        self.progress.1.notify_all();
    }

    /// The version a gated worker reads BEFORE it tries to claim.
    fn progress_version(&self) -> u64 {
        self.progress_version.load(Ordering::SeqCst)
    }

    /// Sleep until [`Self::notify_progress`] unless it already happened since
    /// `seen` (the version read before the failed claim): the check is made
    /// under the lock the notifier takes, so a notification between the claim
    /// and the sleep is never lost. The 100 ms timeout is only a safety net.
    fn wait_for_progress(&self, seen: u64, stop: &AtomicBool) {
        let guard = self.progress.0.lock().unwrap_or_else(|e| e.into_inner());
        if stop.load(Ordering::SeqCst) || self.progress_version() != seen {
            return;
        }
        let _ = self
            .progress
            .1
            .wait_timeout(guard, Duration::from_millis(100));
    }
}

/// Claim the next round to fetch: atomically take `next_to_fetch` and move it
/// on by one, but, when `limit` is set (the tip gate: the apply cursor plus
/// `parallel_blocks`), only while the round is below it. The check and the
/// claim are ONE compare-and-swap, so concurrent workers can never claim
/// more rounds than the bound allows between them.
fn claim_round(next_to_fetch: &AtomicU64, limit: Option<u64>) -> Option<u64> {
    let mut cur = next_to_fetch.load(Ordering::SeqCst);
    loop {
        if limit.is_some_and(|l| cur >= l) {
            return None;
        }
        match next_to_fetch.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(cur),
            Err(actual) => cur = actual,
        }
    }
}

impl CatchupService {
    /// Run one periodic pass for the service thread: answer every `sync_now`
    /// waiter (the one that triggered it and any that arrived meanwhile) with
    /// the pass's exit reason.
    fn run_pass(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        trigger_rx: &Receiver<SyncWaiter>,
        syncing_since_ns: &Arc<AtomicI64>,
        parallel_blocks: u64,
        mut waiters: Vec<SyncWaiter>,
    ) -> SyncExitReason {
        let reason = Self::sync_pass(
            ledger,
            fetcher,
            shutdown_rx,
            syncing_since_ns,
            parallel_blocks,
            Some(trigger_rx),
            &mut waiters,
        );
        for w in waiters {
            let _ = w.send(reason);
        }
        // A request that arrived once the pass was at the tip stays queued:
        // the service loop runs ONE fresh pass for it. When the service is
        // stopping there is no further pass, so answer it now.
        if reason == SyncExitReason::Stopping {
            Self::answer_stopping(trigger_rx);
        }
        reason
    }

    /// Answer every queued `sync_now` request with `Stopping`.
    fn answer_stopping(trigger_rx: &Receiver<SyncWaiter>) {
        while let Ok(w) = trigger_rx.try_recv() {
            let _ = w.send(SyncExitReason::Stopping);
        }
    }

    /// Whether the certificate-driven path must skip its fetch: the ledger
    /// is stalled on an invalid block and the backoff window is pending
    /// (issue #1677). Pure, so the gate is testable without sleeping.
    ///
    /// Gated only when the certificate carries the very block that failed
    /// (same digest); a certificate for a *different* block is the recovery
    /// path and proceeds. Unknown failed digest: not gated.
    fn cert_sync_gated(
        stall_wait: Option<Duration>,
        failed_digest: Option<algo_types::Digest>,
        cert_digest: algo_types::Digest,
    ) -> bool {
        stall_wait.is_some() && failed_digest == Some(cert_digest)
    }

    /// Pure decision for a periodic-sync timeout tick, kept separate from
    /// the loop so the issue #1677 backoff gate is testable without sleeping.
    fn periodic_tick_action(
        next_round: Round,
        last_round: Round,
        stuck_once: bool,
        stall_wait: Option<Duration>,
    ) -> PeriodicTick {
        if next_round != last_round {
            PeriodicTick::Advanced
        } else if !stuck_once {
            PeriodicTick::Rearm
        } else if stall_wait.is_some() {
            PeriodicTick::BackOff
        } else {
            PeriodicTick::Sync
        }
    }

    /// Create and start a new `CatchupService`.
    ///
    /// # Parameters
    ///
    /// - `cert_rx`: receiver for pending unmatched certificates from the
    ///   agreement service (produced by [`AgreementLedgerBridge::new_with_catchup`]).
    /// - `ledger`: trait object providing round checking and block commit
    ///   capabilities (typically an [`AgreementLedgerBridge`](crate::AgreementLedgerBridge)).
    /// - `fetcher`: a block fetcher implementation for retrieving blocks from
    ///   the network.
    ///
    /// Uses [`Self::DEFAULT_PARALLEL_BLOCKS`] for the periodic path's fetch
    /// concurrency, matching go's `CatchupParallelBlocks` default (16 at
    /// v5.0.1-stable, `config/localTemplate.go:313`). Callers that have a
    /// configured value (e.g. from `algo_config::Local::catchup_parallel_blocks`)
    /// should use [`Self::start_with_parallelism`] instead.
    pub fn start(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
    ) -> Self {
        Self::start_with_parallelism(cert_rx, ledger, fetcher, Self::DEFAULT_PARALLEL_BLOCKS)
    }

    /// Go's v5.0.1-stable `CatchupParallelBlocks` default
    /// (`config/localTemplate.go:313`, `version[5]:"16"`).
    pub const DEFAULT_PARALLEL_BLOCKS: u64 = 16;

    /// Same as [`Self::start`], but with an explicit fetch-concurrency
    /// budget for the periodic sync path (issue #753) — go's
    /// `CatchupParallelBlocks`. Values are clamped to
    /// `1..=`[`Self::MAX_PARALLEL_BLOCKS`]; `0` is treated as `1`
    /// (serial), matching "at least one fetch in flight" rather than a
    /// stalled service.
    pub fn start_with_parallelism(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        parallel_blocks: u64,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let (trigger_tx, trigger_rx) =
            crossbeam_channel::unbounded::<crossbeam_channel::Sender<SyncExitReason>>();
        let fork_count = Arc::new(AtomicU64::new(0));
        let fork_count_cert = Arc::clone(&fork_count);
        let syncing_since_ns = Arc::new(AtomicI64::new(0));
        let syncing_since_ns_inner = Arc::clone(&syncing_since_ns);
        let parallel_blocks = parallel_blocks.clamp(1, Self::MAX_PARALLEL_BLOCKS);

        // Issue #1576: the certificate-driven fetch path gets its own
        // thread (and its own shutdown channel), independent of the
        // periodic-sync select loop below — see `Self::cert_loop`'s doc
        // comment for why.
        let (cert_shutdown_tx, cert_shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let cert_ledger = Arc::clone(&ledger);
        let cert_fetcher = Arc::clone(&fetcher);
        let cert_join_handle = thread::Builder::new()
            .name("catchup-cert-service".to_string())
            .spawn(move || {
                Self::cert_loop(
                    cert_rx,
                    cert_shutdown_rx,
                    cert_ledger,
                    cert_fetcher,
                    fork_count_cert,
                );
            })
            .expect("failed to spawn catchup-cert-service thread");

        let join_handle = thread::Builder::new()
            .name("catchup-service".to_string())
            .spawn(move || {
                Self::run_loop(
                    shutdown_rx,
                    trigger_rx,
                    ledger,
                    fetcher,
                    syncing_since_ns_inner,
                    parallel_blocks,
                );
            })
            .expect("failed to spawn catchup-service thread");

        Self {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
            cert_shutdown_tx: Some(cert_shutdown_tx),
            cert_join_handle: Some(cert_join_handle),
            fork_count,
            syncing_since_ns,
            trigger_tx: Some(trigger_tx),
        }
    }

    /// Returns how long the periodic (certificate-less) sync path has been
    /// actively running its current pass, or [`Duration::ZERO`] if it is
    /// not currently mid-pass.
    ///
    /// Mirrors Go's `Service.SynchronizingTime()` (`catchup/service.go`):
    /// `time.Duration(0)` when `syncStartNS` is unset, else the elapsed
    /// time since it was set.
    pub fn synchronizing_time(&self) -> Duration {
        let start_ns = self.syncing_since_ns.load(Ordering::SeqCst);
        if start_ns == 0 {
            return Duration::ZERO;
        }
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(start_ns);
        Duration::from_nanos(now_ns.saturating_sub(start_ns).max(0) as u64)
    }

    /// Returns the number of fork detections observed so far.
    ///
    /// Callers can poll this to detect forks for monitoring or alerting.
    pub fn fork_count(&self) -> u64 {
        self.fork_count.load(Ordering::SeqCst)
    }

    /// Signal the service to stop and wait for the background thread to exit.
    ///
    /// Mirrors Go's `Service.Stop()`.
    pub fn stop(&mut self) {
        debug!("catchup service is stopping");

        // Signal shutdown to both worker threads by sending (or dropping
        // the sender) on each of their independent shutdown channels —
        // issue #1576's split means one `shutdown_tx.send` no longer
        // reaches both (a bounded(1) channel delivers to exactly one
        // waiting receiver, not both).
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.cert_shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Join both worker threads.
        if let Some(handle) = self.join_handle.take() {
            if let Err(e) = handle.join() {
                warn!("catchup service thread panicked: {e:?}");
            }
        }
        if let Some(handle) = self.cert_join_handle.take() {
            if let Err(e) = handle.join() {
                warn!("catchup cert-service thread panicked: {e:?}");
            }
        }

        debug!("catchup service has stopped");
    }

    /// The main loop of the periodic-sync catchup service worker thread.
    ///
    /// Mirrors Go's `periodicSync` select loop, minus the
    /// `case cert := <-s.unmatchedPendingCertificates` branch — issue
    /// #1576 moved that branch to its own thread/loop
    /// ([`Self::cert_loop`]) so a certificate-driven fetch is never stuck
    /// behind an in-flight periodic pass. See `cert_loop`'s doc comment
    /// for the full rationale.
    ///
    /// A pass runs the whole catch-up to the tip (issue #2165), so this loop
    /// only regains control when it ends. The single shutdown message may be
    /// consumed by the pass itself; every call site therefore treats a
    /// [`SyncExitReason::Stopping`] result as the stop request and exits,
    /// instead of waiting for a second message that will never come.
    fn run_loop(
        shutdown_rx: Receiver<()>,
        trigger_rx: Receiver<SyncWaiter>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        syncing_since_ns: Arc<AtomicI64>,
        parallel_blocks: u64,
    ) {
        info!("catchup service started");

        // Mirrors Go's `periodicSync`, which runs one `sync()` immediately
        // on startup before entering its select loop
        // (`catchup/service.go:611-619`).
        if Self::run_pass(
            &ledger,
            &fetcher,
            &shutdown_rx,
            &trigger_rx,
            &syncing_since_ns,
            parallel_blocks,
            Vec::new(),
        ) == SyncExitReason::Stopping
        {
            // The pass consumed the one shutdown message: a stop request
            // must end the loop here, never be re-awaited (that would hang
            // `stop()`'s join forever).
            info!("catchup service exiting");
            Self::answer_stopping(&trigger_rx);
            return;
        }

        let mut last_round = ledger.next_round();

        // Mirrors Go's `periodicSync` two-stage backoff (`catchup/service.go:664-705`):
        // the FIRST tick that observes no ledger advance since the previous
        // check does not resync — it only re-arms for one more interval
        // (Go: `sleepDuration = s.roundTimeEstimate; continue`, having
        // already burned a shorter, randomized "de-synchronizing" wait on
        // the tick right after the last real advance). Only a SECOND
        // consecutive no-advance tick (a full extra `PERIODIC_SYNC_INTERVAL`
        // with zero progress) is treated as "the ledger has genuinely
        // stalled" and triggers `sync_pass`.
        //
        // Without this hysteresis, any round whose own agreement-driven
        // vote/cert collection takes longer than one `PERIODIC_SYNC_INTERVAL`
        // (routine under load, and essentially guaranteed for a node that
        // just resumed from a large post-restart catch-up gap) gets its
        // `RoundInterruption` fired by this periodic path's own
        // network-fetched block before the local player ever finishes
        // voting. That commit itself then counts as "an advance", so the
        // very next tick again sees no *further* progress and fires
        // another periodic fetch — a self-sustaining loop that permanently
        // pre-empts the agreement service's own vote-based commit path and
        // silences it (issue #1564: post-SIGKILL-restart nodes rejoin and
        // stay in lockstep via this loop, but never cast another vote).
        let mut stuck_once = false;

        loop {
            let mut sel = Select::new();
            let shutdown_idx = sel.recv(&shutdown_rx);
            let trigger_idx = sel.recv(&trigger_rx);

            let oper = match sel.select_timeout(Self::PERIODIC_SYNC_INTERVAL) {
                Ok(oper) => oper,
                Err(_) => {
                    // Timed out: the ledger has not been advanced by
                    // agreement recently, so try to pull whatever the
                    // network already has.  This is Go's
                    // `case <-time.After(sleepDuration): ... s.sync()`
                    // branch (catchup/service.go:641-662) and it is the
                    // only thing that lets a node which started *behind*
                    // the network tip ever join: agreement will not emit
                    // an unmatched certificate for a round it is not
                    // playing, so the certificate-driven path (now
                    // `Self::cert_loop`, on its own thread) never fires in
                    // that situation (issue #478).
                    let now = ledger.next_round();
                    // Issue #1677: while the ledger is stalled on a block
                    // that deterministically fails to apply, wait out the
                    // exponential backoff instead of re-fetching and
                    // re-applying it every ~8 s. An explicit `sync_now` is
                    // never gated.
                    let stall_wait = ledger.apply_stall_retry_in(now);
                    match Self::periodic_tick_action(now, last_round, stuck_once, stall_wait) {
                        PeriodicTick::Advanced => {
                            // Agreement is making progress on its own. Reset
                            // the stall counter too — go's
                            // `WaitMem(currBlock+1)` branch resets
                            // `stuckInARow` the same way on every genuine
                            // advance.
                            last_round = now;
                            stuck_once = false;
                            continue;
                        }
                        PeriodicTick::Rearm => {
                            // First tick with no progress since the last
                            // check: give the local agreement service one
                            // more full interval before assuming it has
                            // actually stalled (see `stuck_once`'s
                            // definition above — issue #1564).
                            stuck_once = true;
                            continue;
                        }
                        PeriodicTick::BackOff => {
                            trace!(
                                retry_in_ms = stall_wait.map_or(0, |w| w.as_millis() as u64),
                                "catchup service: stalled on an invalid block, backing off"
                            );
                            continue;
                        }
                        PeriodicTick::Sync => {}
                    }
                    if Self::run_pass(
                        &ledger,
                        &fetcher,
                        &shutdown_rx,
                        &trigger_rx,
                        &syncing_since_ns,
                        parallel_blocks,
                        Vec::new(),
                    ) == SyncExitReason::Stopping
                    {
                        break;
                    }
                    last_round = ledger.next_round();
                    stuck_once = false;
                    continue;
                }
            };

            match oper.index() {
                i if i == shutdown_idx => {
                    // Shutdown signal received (or sender dropped).
                    // `SelectedOperation` must be completed before it is
                    // dropped, or crossbeam panics — so consume it even
                    // though the value is irrelevant.
                    let _ = oper.recv(&shutdown_rx);
                    debug!("catchup service received shutdown signal");
                    break;
                }
                i if i == trigger_idx => {
                    // Mirrors go's `case <-s.syncNow: ... s.sync()` branch
                    // in `periodicSync` — an explicit, caller-triggered
                    // sync pass, answered synchronously via the one-shot
                    // reply channel sent along with the request.
                    if let Ok(reply_tx) = oper.recv(&trigger_rx) {
                        let reason = Self::run_pass(
                            &ledger,
                            &fetcher,
                            &shutdown_rx,
                            &trigger_rx,
                            &syncing_since_ns,
                            parallel_blocks,
                            vec![reply_tx],
                        );
                        if reason == SyncExitReason::Stopping {
                            break;
                        }
                        last_round = ledger.next_round();
                    }
                }
                _ => unreachable!(),
            }
            drop(sel);
        }

        Self::answer_stopping(&trigger_rx);
        info!("catchup service exiting");
    }

    /// The certificate-driven catchup worker thread (issue #1576).
    ///
    /// Mirrors the `case cert := <-s.unmatchedPendingCertificates:` branch
    /// of Go's `periodicSync` — but on its own thread, not as a branch of
    /// [`Self::run_loop`]'s select loop the way go's (and this crate's
    /// pre-#1576) single loop handles it.
    ///
    /// # Why a separate thread
    ///
    /// Go's `periodicSync` handles both the periodic (certificate-less)
    /// `s.sync()` pass and the certificate-driven `s.syncCert()` fetch in
    /// the same `for { select { ... } }` loop, on one goroutine — a
    /// pending certificate is only noticed between iterations of that
    /// loop, i.e. only once whichever branch is currently running
    /// (`s.sync()`, which can take a while: it fetches and applies
    /// everything up to the network tip, one round at a time) returns.
    /// This crate mirrored that exact structure prior to #1576.
    ///
    /// That structure means a certificate agreement already has (and is
    /// actively waiting on, to keep voting) can sit unprocessed in the
    /// channel for as long as an in-flight periodic sync pass takes to
    /// finish. This is routine, not a corner case: a node's own
    /// `sync_pass` right after a large post-restart catch-up gap is
    /// exactly the moment agreement is also most likely to need a
    /// certificate-driven fetch (its own StageDigestAction path,
    /// `algo_agreement::service::do_stage_digest_action`) for the very
    /// first round(s) it resumes participating in — so the two compete
    /// for the same single thread at precisely the worst time. The
    /// longer a concurrent/preceding periodic pass takes (more blocks to
    /// fetch, slower/contended network), the longer the certificate stays
    /// stuck, which delays the `RoundInterruption` that lets agreement's
    /// player re-zero its next round's clock in phase with the rest of
    /// the (uninterrupted) committee — compounding a single self-
    /// correcting missed round (see issue #1576's investigation notes)
    /// into a longer streak.
    ///
    /// Running `sync_cert` on its own thread, selecting only on its own
    /// certificate + shutdown channels, means a certificate is served
    /// the moment it arrives, regardless of whether `run_loop`'s
    /// periodic-sync thread is mid-pass. This changes algod-rust's
    /// *internal concurrency structure* relative to go-algorand, not the
    /// certificate-verification or block-application *rules* — the same
    /// `sync_cert`/`sync_pass_inner` functions, unchanged, run the exact
    /// same validation either way — so it does not diverge from any
    /// consensus-visible behavior, only from an implementation detail of
    /// how quickly a certificate-driven fetch can be serviced.
    fn cert_loop(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        shutdown_rx: Receiver<()>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        fork_count: Arc<AtomicU64>,
    ) {
        debug!("catchup cert-service started");

        loop {
            let mut sel = Select::new();
            let cert_idx = sel.recv(&cert_rx);
            let shutdown_idx = sel.recv(&shutdown_rx);

            let oper = sel.select();
            match oper.index() {
                i if i == shutdown_idx => {
                    let _ = oper.recv(&shutdown_rx);
                    debug!("catchup cert-service received shutdown signal");
                    break;
                }
                i if i == cert_idx => match oper.recv(&cert_rx) {
                    Ok(pending) => {
                        // `sync_cert` consumes the one shutdown message when
                        // it sees it: exit instead of waiting for another.
                        if Self::sync_cert(&pending, &ledger, &fetcher, &shutdown_rx, &fork_count)
                            == SyncExitReason::Stopping
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        // Certificate channel closed — the agreement
                        // service has shut down (or never had a sender).
                        // Nothing more for this thread to do; the
                        // periodic-sync thread keeps the ledger following
                        // the chain on its own until `stop()`.
                        info!("catchup cert-service: certificate channel closed, exiting");
                        break;
                    }
                },
                _ => unreachable!(),
            }
            drop(sel);
        }

        debug!("catchup cert-service exiting");
    }

    /// How long the ledger may stand still before the periodic path tries
    /// to fetch from the network. Go derives this from
    /// `agreement.DeadlineTimeout()` (`roundTimeEstimate`); 4s is that
    /// value for the default filter timeout.
    const PERIODIC_SYNC_INTERVAL: Duration = Duration::from_secs(4);

    /// Upper bound on the number of fetch workers (`CatchupParallelBlocks`;
    /// the window of rounds ahead of the apply cursor is
    /// [`Self::fetch_window`] of it). A pass is
    /// not bounded in length (issue #2165): like go's `pipelinedFetch` it
    /// runs until a fetch fails at the network tip, and checks for shutdown
    /// before applying every block.
    const MAX_PARALLEL_BLOCKS: u64 = 256;

    /// Most rounds, beyond the workers' own, a pass may have fetched and
    /// waiting ahead of the apply cursor (issue #2204): the memory and the
    /// discarded work an invalid round costs are bounded by a BLOCK COUNT
    /// (no byte cap), `workers + min(workers, FETCH_AHEAD_MAX_EXTRA)`. The
    /// extra is at most this many blocks at ANY worker count, so the worst
    /// case at the clamp ceiling (`MAX_PARALLEL_BLOCKS` = 256 workers: a window
    /// of 288 rounds, about 1.4 GiB of completely full 5 MiB blocks) is the
    /// operator's own `CatchupParallelBlocks` choice (256 blocks, 1.25 GiB,
    /// before this change) plus at most 32 blocks (160 MiB).
    const FETCH_AHEAD_MAX_EXTRA: u64 = 32;

    /// The worker count at or below which a pass does not prefetch: the
    /// strictly serial setting (`CatchupParallelBlocks: 1`) keeps a window of
    /// one round. Deliberate (DIV-010): with two or more workers the window
    /// is `workers + min(workers, FETCH_AHEAD_MAX_EXTRA)` (two workers: four
    /// rounds), because there is concurrency a slow round can idle.
    const NO_PREFETCH_WORKERS: u64 = 1;

    /// Rounds a pass may have claimed ahead of the apply cursor (in flight
    /// plus fetched and waiting) for `workers` fetch workers (at least one);
    /// at most `workers` of them are being fetched at any time (issue #2204).
    ///
    /// DIVERGENCE DIV-010: go's window holds `limitedParallelRequests` rounds
    /// in total (in flight and fetched-and-waiting), so one slow round idles
    /// the workers behind it; here the window is up to twice as long
    /// (`workers + min(workers, FETCH_AHEAD_MAX_EXTRA)`) and the number of
    /// concurrent fetches stays the worker count; up to
    /// [`Self::NO_PREFETCH_WORKERS`] workers keep a window of one round.
    fn fetch_window(workers: u64) -> u64 {
        debug_assert!(workers >= 1, "a pass needs at least one worker");
        if workers <= Self::NO_PREFETCH_WORKERS {
            1
        } else {
            workers + workers.min(Self::FETCH_AHEAD_MAX_EXTRA)
        }
    }

    /// Pull consecutive blocks from the network starting at the ledger's
    /// next round, until a fetch fails (normally the network tip).
    ///
    /// Mirrors Go's `Service.sync()` / `pipelinedFetch`: up to
    /// `parallel_blocks` rounds are fetched concurrently by a small worker
    /// pool (go's `CatchupParallelBlocks`), while validation and ledger
    /// commit happen strictly in round order on this thread — a worker
    /// only ever does the network I/O, never decides whether a block gets
    /// applied, so the applied sequence is byte-for-byte the same as the
    /// old serial implementation for the same inputs.
    ///
    /// Every block committed here is authenticated against the certificate
    /// the serving peer returned — see
    /// [`CatchupLedger::authenticate_block`]. A peer that cannot supply a
    /// certificate, or supplies one that does not carry a quorum for the
    /// block, is not trusted and the pass stops.
    fn sync_pass(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        syncing_since_ns: &Arc<AtomicI64>,
        parallel_blocks: u64,
        triggers: Option<&Receiver<SyncWaiter>>,
        waiters: &mut Vec<SyncWaiter>,
    ) -> SyncExitReason {
        // Mirrors Go's `sync()`: `syncStartNS.CompareAndSwap(0, timeInNS)`.
        // A CAS (not an unconditional store) so a pass that starts while
        // `synchronizing_time()` observers are mid-read never resets the
        // start instant they're measuring against — matching Go's comment
        // that a nonzero `syncStartNS` means "resuming previous sync".
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(1);
        let _ =
            syncing_since_ns.compare_exchange(0, now_ns.max(1), Ordering::SeqCst, Ordering::SeqCst);

        let exit_reason = Self::sync_pass_core(
            ledger,
            fetcher,
            shutdown_rx,
            parallel_blocks,
            triggers,
            waiters,
            FetchPolicy::default(),
        );

        // Mirrors Go's `s.syncStartNS.Store(0)` at the end of `sync()`
        // (algod-rust has no `suspendForLedgerOps`-equivalent state that
        // would keep the timer running across a pass, so this always
        // clears it).
        syncing_since_ns.store(0, Ordering::SeqCst);

        exit_reason
    }

    /// Public, directly-callable range-sync entry point mirroring go's
    /// `Service.sync()` (`catchup/service.go`) as exercised by
    /// `TestServiceFetchBlocksSameRange`: fetch and commit whatever
    /// consecutive range of rounds `[ledger.next_round(), ...]` the
    /// configured peers have, driven entirely by the peer-selecting
    /// `fetcher` with no certificate required per round — the block's own
    /// fetcher-supplied certificate is what gets authenticated (see
    /// [`CatchupLedger::authenticate_block`]), exactly like go's
    /// certificate-less `pipelinedFetch`/`fetchAndWrite` path.
    ///
    /// Unlike [`Self::sync_cert`] (which waits on a specific
    /// agreement-verified certificate for one round), this can be called
    /// directly — by a running [`CatchupService`] via
    /// [`CatchupService::sync_now`], or standalone in a test with mock
    /// `ledger`/`fetcher` implementations — without requiring the
    /// background worker thread to be involved at all.
    pub fn sync_range(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        parallel_blocks: u64,
    ) -> SyncExitReason {
        Self::sync_pass_inner(ledger, fetcher, shutdown_rx, parallel_blocks)
    }

    /// Trigger an immediate, synchronous range-sync pass on a running
    /// [`CatchupService`] and block until it completes, returning the
    /// [`SyncExitReason`].
    ///
    /// Mirrors go's `syncer.sync()` being callable directly on a live
    /// `Service` (as `TestServiceFetchBlocksSameRange` does after
    /// `testStart()`), rather than only ever running implicitly off the
    /// periodic timer. Internally this hands the request to the worker
    /// thread (so it still runs serialized with any certificate-driven
    /// fetch already in flight) and waits for the reply.
    ///
    /// Contract (issue #2165): a pass is one continuous pipeline that runs
    /// until the network tip, not a bounded batch. What a `sync_now` gets
    /// depends on when it arrives:
    ///
    /// - while the service is idle: it starts a pass and gets its result;
    /// - while a pass is still making progress (no worker has seen the tip, a
    ///   fetch failure or a stop yet): it is coalesced into that pass. The
    ///   apply loop notices it within one fetch-wait tick (100 ms) and the
    ///   caller gets that pass's [`SyncExitReason`] when it ends;
    /// - once the pass has entered its tip-probe / exit phase (a worker got a
    ///   "no block" answer or gave up on a round): it is NOT answered with
    ///   that stale result. It stays queued and the service runs exactly one
    ///   fresh pass for it after the current one, so blocks that appeared
    ///   meanwhile are picked up.
    ///
    /// The call blocks for as long as the catch-up it asked for takes, like
    /// go's `sync()`. It returns [`SyncExitReason::Stopping`] if the service
    /// is stopped meanwhile.
    pub fn sync_now(&self) -> SyncExitReason {
        let (reply_tx, reply_rx) = crossbeam_channel::bounded::<SyncExitReason>(1);
        if let Some(tx) = &self.trigger_tx {
            if tx.send(reply_tx).is_ok() {
                if let Ok(reason) = reply_rx.recv() {
                    return reason;
                }
            }
        }
        // The worker thread is gone (already stopped) or dropped the
        // reply sender without answering — nothing more to synchronize on.
        SyncExitReason::Stopping
    }

    /// The actual periodic-sync fetch/apply work, wrapped by
    /// [`Self::sync_pass`]'s `syncing_since_ns` bookkeeping.
    fn sync_pass_inner(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        parallel_blocks: u64,
    ) -> SyncExitReason {
        Self::sync_pass_core(
            ledger,
            fetcher,
            shutdown_rx,
            parallel_blocks,
            None,
            &mut Vec::new(),
            FetchPolicy::default(),
        )
    }

    /// Fetch one round for the pass's worker, retrying like go's
    /// `fetchAndWrite`: up to [`Self::CATCHUP_RETRY_LIMIT`] attempts (go's
    /// `catchupRetryLimit`), giving up early once peers have said "no such
    /// block" more than `no_block_threshold` times
    /// (`errNoBlockForRoundThreshold`, the tip) and at once when there are no
    /// peers (`errCatchupNoPeer`). The fetcher rotates peers inside each
    /// attempt. A transient error therefore no longer ends the whole pass.
    ///
    /// Beyond go's count bound this is also bounded by wall time
    /// (`wall_bound` of consecutive transport failures), so one persistently
    /// failing round cannot keep the single service thread inside a pass for
    /// minutes (500 attempts of timeout + backoff).
    ///
    /// Tip probing: go sleeps `followLatestBackoff` (100 ms) between
    /// "no block" answers, and so does this. Only the lowest round that has
    /// seen a "no block" keeps probing; a worker for a higher round gives up
    /// at once (it cannot succeed before the lower one), so a window of N
    /// workers sends about `N + threshold` requests at the tip, not
    /// `N * threshold`.
    fn fetch_round_with_retries(
        fetcher: &dyn BlockFetcher,
        round: Round,
        stop: &AtomicBool,
        ctx: &PassCtx,
    ) -> Result<FetchedBlockCert, FetchError> {
        struct ProbeGuard<'a>(&'a PassCtx, u64);
        impl Drop for ProbeGuard<'_> {
            fn drop(&mut self) {
                if let Ok(mut set) = self.0.probing.lock() {
                    set.remove(&self.1);
                }
            }
        }
        let _guard = ProbeGuard(ctx, round.0);
        let policy = &ctx.policy;
        let mut no_block = 0u32;
        let mut last = FetchError::Timeout;
        let mut failing_since: Option<std::time::Instant> = None;
        for _ in 0..Self::CATCHUP_RETRY_LIMIT {
            // Stopped, or past an unsupported round the apply loop will stop at.
            if stop.load(Ordering::SeqCst) || round.0 > ctx.window_limit.load(Ordering::SeqCst) {
                return Err(FetchError::NetworkError("catchup pass stopping".into()));
            }
            match fetcher.fetch_block(round) {
                Ok(b) => return Ok(b),
                Err(FetchError::NoPeersAvailable) => return Err(FetchError::NoPeersAvailable),
                Err(e @ FetchError::NoBlockForRound { .. }) => {
                    ctx.tip_seen.store(true, Ordering::SeqCst);
                    no_block += 1;
                    if no_block > policy.no_block_threshold {
                        return Err(e);
                    }
                    let lowest = |ctx: &PassCtx| {
                        ctx.probing.lock().map_or(true, |mut set| {
                            set.insert(round.0);
                            set.iter().next() == Some(&round.0)
                        })
                    };
                    if !lowest(ctx) {
                        return Err(e);
                    }
                    thread::sleep(policy.no_block_backoff);
                    // A lower round may have started probing meanwhile.
                    if !lowest(ctx) {
                        return Err(e);
                    }
                    last = e;
                }
                Err(e) => {
                    last = e;
                    let since = *failing_since.get_or_insert_with(std::time::Instant::now);
                    if since.elapsed() >= policy.wall_bound {
                        return Err(last);
                    }
                    thread::sleep(policy.retry_backoff);
                }
            }
        }
        Err(last)
    }

    /// Whether the "no fetch worker could be started" warning is due: at most
    /// one per [`NO_WORKER_WARN_INTERVAL`] for the process.
    fn no_worker_warning_due(now: std::time::Instant) -> bool {
        static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        Self::warning_due(&mut last, now, NO_WORKER_WARN_INTERVAL)
    }

    /// The pure part of the warning rate limit.
    fn warning_due(
        last: &mut Option<std::time::Instant>,
        now: std::time::Instant,
        interval: Duration,
    ) -> bool {
        if last.is_some_and(|at| now.duration_since(at) < interval) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// Stop the pass's workers and wake any that sleep at the tip gate.
    fn raise_stop(stop: &AtomicBool, ctx: &PassCtx) {
        stop.store(true, Ordering::SeqCst);
        ctx.notify_progress();
    }

    /// [`Self::sync_pass_inner`] plus the live service's `sync_now`
    /// coalescing: requests arriving on `triggers` during the pass are pushed
    /// to `waiters`, for the caller to answer with the pass's exit reason.
    fn sync_pass_core(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        parallel_blocks: u64,
        triggers: Option<&Receiver<SyncWaiter>>,
        waiters: &mut Vec<SyncWaiter>,
        policy: FetchPolicy,
    ) -> SyncExitReason {
        let mut exit_reason = SyncExitReason::Done;
        let start_round = ledger.next_round();
        let parallel_blocks = parallel_blocks.clamp(1, Self::MAX_PARALLEL_BLOCKS);

        // Shared dispatch counter (next round any idle worker should try
        // next) and a stop flag any thread can raise once a permanent
        // failure/stop condition is found — either a worker discovering an
        // unsupported round, or the main thread's validation loop below.
        let next_to_fetch = Arc::new(AtomicU64::new(start_round.0));
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(PassCtx::new(policy));
        // go's `pipelinedFetch` is a sliding window: it only issues a fetch
        // for rounds `firstRound .. firstRound+limitedParallelRequests`, and
        // the window moves up by one each time the first round is written.
        // The same here with permits: a worker must hold one before it claims
        // a round, and the apply loop hands one back after each round it
        // applies. The invariant (DIV-010): the window is
        // `fetch_window(started workers)` rounds claimed ahead of the apply
        // cursor (in flight plus fetched and waiting), with at most ONE
        // in-flight round per worker. With a window equal to the worker count
        // one slow round would park every worker whose round had finished
        // (11 of 16 fetches in flight on average on a live betanet catchup).
        // The window also caps what is wasted when an invalid round stops the
        // pass. The channels are sized for the largest window; the permits are
        // handed out once the workers are spawned, for the workers that really
        // started. A result channel with room for the window means a worker's
        // `send` never blocks.
        let max_window = Self::fetch_window(parallel_blocks);
        ctx.applied.store(start_round.0, Ordering::SeqCst);
        let (permit_tx, permit_rx) = crossbeam_channel::bounded::<()>(max_window as usize);
        let permit_tx = Some(permit_tx);
        let (result_tx, result_rx) =
            crossbeam_channel::bounded::<(u64, FetchOutcome)>(max_window as usize);

        let mut workers = Vec::with_capacity(parallel_blocks as usize);
        for _ in 0..parallel_blocks {
            let next_to_fetch = Arc::clone(&next_to_fetch);
            let stop = Arc::clone(&stop);
            let ctx = Arc::clone(&ctx);
            let tx = result_tx.clone();
            let permits = permit_rx.clone();
            let ledger = Arc::clone(ledger);
            let fetcher = Arc::clone(fetcher);
            // Issue #1650: a live soak died with `thread::spawn` panicking
            // (`Os { code: 11, WouldBlock }`, EAGAIN) once OS thread budget
            // ran out. Spawn via `Builder` and degrade to fewer workers
            // instead of panicking the catchup thread; with no worker at all
            // the pass ends (below) as a retryable `NoBlock`.
            let policy_spawner = ctx.policy.spawner.clone();
            let spawned = policy_spawner.spawn(
                thread::Builder::new().name("catchup-fetch".to_string()),
                Box::new(move || loop {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    // Wait for a window slot; the pass dropping its permit
                    // sender (it is over) wakes and ends every idle worker.
                    if permits.recv().is_err() || stop.load(Ordering::SeqCst) {
                        return;
                    }
                    // Tip gate (issue #2204): once the lowest probing round's
                    // fetch has finally failed (the tip), do not claim a round
                    // more than the started workers' number beyond the apply
                    // cursor, as go's window (go stops launching fetches after
                    // the first failure): already claimed rounds stay claimed,
                    // only new claims are bounded;
                    // the extra window only pays off while blocks exist, and
                    // past the tip every claimed round is a request for a
                    // block that is not there. The check and the claim are one
                    // atomic step (`claim_round`); a gated worker holds its
                    // slot and sleeps until the cursor moves or the pass ends.
                    let round = loop {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        let seen = ctx.progress_version();
                        let limit = ctx.fetch_failed.load(Ordering::SeqCst).then(|| {
                            ctx.applied.load(Ordering::SeqCst) + ctx.workers.load(Ordering::SeqCst)
                        });
                        match claim_round(&next_to_fetch, limit) {
                            Some(round) => break round,
                            None => ctx.wait_for_progress(seen, &stop),
                        }
                    };
                    // Past an unsupported round the apply loop stops at: the
                    // result could never be used.
                    if round > ctx.window_limit.load(Ordering::SeqCst) {
                        return;
                    }
                    let r = Round(round);
                    // A panic inside the fetcher must still produce a result
                    // for the claimed round, or the apply loop would wait for
                    // it forever while the other workers park on permits.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if ledger.round_is_not_supported(r) {
                            return FetchOutcome::Unsupported;
                        }
                        FetchOutcome::Fetch(Box::new(Self::fetch_round_with_retries(
                            fetcher.as_ref(),
                            r,
                            &stop,
                            &ctx,
                        )))
                    }))
                    .unwrap_or_else(|_| {
                        FetchOutcome::Fetch(Box::new(Err(FetchError::NetworkError(format!(
                            "fetch worker panicked fetching round {round}"
                        )))))
                    });
                    let unsupported = matches!(outcome, FetchOutcome::Unsupported);
                    if unsupported {
                        // Workers fetching or retrying later rounds stop now.
                        ctx.window_limit.fetch_min(round, Ordering::SeqCst);
                    }
                    if matches!(&outcome, FetchOutcome::Fetch(r) if r.is_err()) {
                        ctx.tip_seen.store(true, Ordering::SeqCst);
                        // ANY round's final failure engages the tip gate, a
                        // higher round that gave up at once because a lower one
                        // is probing included: the apply loop stops the pass at
                        // the first round with a failed result, so even if the
                        // lower round later succeeds, the pass ends at the
                        // higher one and nothing beyond it can be used.
                        ctx.fetch_failed.store(true, Ordering::SeqCst);
                    }
                    if tx.send((round, outcome)).is_err() || unsupported {
                        return;
                    }
                }),
            );
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    warn!(
                        error = %e,
                        workers = workers.len(),
                        "catchup service: could not spawn a fetch worker thread;                          continuing with the workers already started"
                    );
                    break;
                }
            }
        }
        // No worker could be started (issue #1650: the OS thread budget ran
        // out): nothing can be fetched, so end the pass as a retryable
        // failure for the service loop to try again at its next tick, instead
        // of reporting `Done` for a pass that fetched nothing.
        if workers.is_empty() {
            // The service loop treats this exactly like any other `NoBlock`
            // exit (the tip included): it retries at its next tick, and
            // `sync_now` waiters are answered `NoBlock`. The warning is rate
            // limited so a persistent spawn failure does not log every tick.
            if Self::no_worker_warning_due(std::time::Instant::now()) {
                warn!(
                    "catchup service: no fetch worker could be started; the pass ends without \
                     fetching and is retried at the next tick"
                );
            } else {
                debug!("catchup service: no fetch worker could be started");
            }
            return SyncExitReason::NoBlock;
        }
        // The window of the workers that really started (fewer than
        // `parallel_blocks` when a thread could not be spawned).
        ctx.workers.store(workers.len() as u64, Ordering::SeqCst);
        let window = Self::fetch_window(workers.len() as u64);
        if let Some(tx) = &permit_tx {
            for _ in 0..window {
                let _ = tx.send(());
            }
        }
        let mut permit_tx = permit_tx;
        // Drop this thread's sender clone so the channel closes once every
        // worker has exited (each worker holds its own clone until then).
        drop(result_tx);
        drop(permit_rx);

        let mut buffer: BTreeMap<u64, FetchOutcome> = BTreeMap::new();
        let mut next_apply = start_round.0;
        let mut fetched = 0u64;
        // Once `true`, the main loop below applies nothing more and only
        // waits for the workers to finish, discarding their results. The
        // loop ends when the result channel closes, i.e. when every worker's
        // sender clone has dropped (workers exit on `stop`, on the permit
        // channel closing, or after reporting `Unsupported`).
        let mut stopped = false;
        let recv_started = std::time::Instant::now();
        let mut first_result_logged = false;

        loop {
            // A `sync_now` that arrives while this pass is still making
            // progress is answered by this pass (see `sync_now`): collect it,
            // reply when it ends. Once a worker has seen the tip (or the pass
            // is stopping) a request is left queued for a fresh pass.
            if let Some(t) = triggers {
                if !stopped && !ctx.tip_seen.load(Ordering::SeqCst) {
                    while let Ok(w) = t.try_recv() {
                        waiters.push(w);
                    }
                }
            }
            let (round, outcome) = match result_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(r) => r,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // The round the apply cursor waits for may take a while
                    // (retries, slow peers): still notice a stop request.
                    if !stopped && shutdown_rx.try_recv().is_ok() {
                        debug!("catchup service: shutdown received while waiting for a fetch");
                        exit_reason = SyncExitReason::Stopping;
                        Self::raise_stop(&stop, &ctx);
                        stopped = true;
                        permit_tx = None;
                    }
                    continue;
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            };
            if !first_result_logged {
                first_result_logged = true;
                if recv_started.elapsed() > Duration::from_secs(5) {
                    warn!(
                        round,
                        elapsed_ms = recv_started.elapsed().as_millis() as u64,
                        "catchup service: first fetch result of this pass arrived slowly"
                    );
                }
            }
            if stopped {
                continue;
            }
            buffer.insert(round, outcome);
            'apply: while let Some(outcome) = buffer.remove(&next_apply) {
                if shutdown_rx.try_recv().is_ok() {
                    debug!("catchup service: shutdown received during periodic sync");
                    exit_reason = SyncExitReason::Stopping;
                    Self::raise_stop(&stop, &ctx);
                    stopped = true;
                    break 'apply;
                }

                match outcome {
                    FetchOutcome::Unsupported => {
                        info!(
                            round = %Round(next_apply),
                            "catchup service: periodic sync stopping, round requires \
                             an unsupported protocol version"
                        );
                        exit_reason = SyncExitReason::Unsupported;
                        Self::raise_stop(&stop, &ctx);
                        stopped = true;
                        break 'apply;
                    }
                    FetchOutcome::Fetch(boxed) if boxed.is_err() => {
                        // Reaching the network tip is the normal exit from
                        // this loop, so only report at debug level.
                        let e = boxed.unwrap_err();
                        debug!(
                            round = %Round(next_apply),
                            error = %e,
                            "catchup service: periodic sync stopping"
                        );
                        exit_reason = match &e {
                            FetchError::NoPeersAvailable => SyncExitReason::NoPeer,
                            FetchError::NoBlockForRound { .. }
                            | FetchError::NetworkError(_)
                            | FetchError::Timeout => SyncExitReason::NoBlock,
                        };
                        Self::raise_stop(&stop, &ctx);
                        stopped = true;
                        break 'apply;
                    }
                    FetchOutcome::Fetch(boxed) => {
                        let fetched_block = boxed.expect("checked Ok above via is_err guard");
                        let expected_round = Round(next_apply);
                        let block = fetched_block.block;
                        if block.round != expected_round {
                            warn!(
                                expected_round = %expected_round,
                                fetched_round = %block.round,
                                "catchup service: periodic sync got wrong round, stopping"
                            );
                            exit_reason = SyncExitReason::NoBlock;
                            Self::raise_stop(&stop, &ctx);
                            stopped = true;
                            break 'apply;
                        }

                        let Some(cert) = fetched_block.cert else {
                            warn!(
                                round = %expected_round,
                                "catchup service: periodic sync got a block with no \
                                 certificate, refusing to commit it"
                            );
                            exit_reason = SyncExitReason::NoBlock;
                            Self::raise_stop(&stop, &ctx);
                            stopped = true;
                            break 'apply;
                        };

                        // Issue #1654 diagnostics: a freshly caught-up node was
                        // unresponsive for minutes on its first sync pass;
                        // log any step of the apply path that is slow so the
                        // next live run names the culprit.
                        let step_started = std::time::Instant::now();
                        let auth_result = ledger.authenticate_block(&block, &cert);
                        if step_started.elapsed() > Duration::from_secs(1) {
                            warn!(
                                round = %expected_round,
                                elapsed_ms = step_started.elapsed().as_millis() as u64,
                                "catchup service: slow authenticate_block"
                            );
                        }
                        if let Err(reason) = auth_result {
                            warn!(
                                round = %expected_round,
                                reason = %reason,
                                "catchup service: periodic sync could not authenticate \
                                 the fetched block, stopping"
                            );
                            exit_reason = SyncExitReason::NoBlock;
                            Self::raise_stop(&stop, &ctx);
                            stopped = true;
                            break 'apply;
                        }

                        let step_started = std::time::Instant::now();
                        let contents_result = algo_validate::contents_match_header(
                            &block,
                            fetched_block.raw_payset_blobs.as_deref(),
                        );
                        if step_started.elapsed() > Duration::from_secs(1) {
                            warn!(
                                round = %expected_round,
                                elapsed_ms = step_started.elapsed().as_millis() as u64,
                                "catchup service: slow contents_match_header"
                            );
                        }
                        match contents_result {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!(
                                    round = %expected_round,
                                    "catchup service: periodic sync block contents do not \
                                     match header commitments, stopping"
                                );
                                exit_reason = SyncExitReason::NoBlock;
                                Self::raise_stop(&stop, &ctx);
                                stopped = true;
                                break 'apply;
                            }
                            Err(reason) => {
                                warn!(
                                    round = %expected_round,
                                    error = %reason,
                                    "catchup service: periodic sync cannot verify block \
                                     contents, stopping"
                                );
                                exit_reason = SyncExitReason::NoBlock;
                                Self::raise_stop(&stop, &ctx);
                                stopped = true;
                                break 'apply;
                            }
                        }

                        let step_started = std::time::Instant::now();
                        ledger.ensure_block(&block, &cert);
                        if step_started.elapsed() > Duration::from_secs(1) {
                            warn!(
                                round = %expected_round,
                                elapsed_ms = step_started.elapsed().as_millis() as u64,
                                "catchup service: slow ensure_block"
                            );
                        }
                        fetched += 1;

                        // `ensure_block` is best-effort; if the ledger did
                        // not actually advance there is no point spinning
                        // on the same round.
                        if ledger.next_round().0 <= expected_round.0 {
                            warn!(
                                round = %expected_round,
                                "catchup service: periodic sync committed a block but the \
                                 ledger did not advance, stopping"
                            );
                            exit_reason = SyncExitReason::NoBlock;
                            Self::raise_stop(&stop, &ctx);
                            stopped = true;
                            break 'apply;
                        }

                        // Backpressure: mirrors go's `pipelinedFetch` check
                        // after a round successfully commits —
                        // `if s.ledger.IsBehindCommittingDeltas() { ...
                        // return errCatchupBehindDeltas }`. Stop here so
                        // the pass reports genuine partial-but-bounded
                        // progress (this round and everything before it
                        // committed; nothing after it was even fetched)
                        // rather than piling on more unflushed state.
                        if ledger.is_behind_committing_deltas() {
                            info!(
                                round = %expected_round,
                                "catchup service: periodic sync stopping, ledger is \
                                 behind on committing deltas"
                            );
                            exit_reason = SyncExitReason::BehindDeltas;
                            Self::raise_stop(&stop, &ctx);
                            stopped = true;
                            break 'apply;
                        }
                    }
                }
                next_apply += 1;
                ctx.applied.store(next_apply, Ordering::SeqCst);
                // Gated workers exist only once `fetch_failed` is set. Both
                // sides are SeqCst: a worker that sets the flag after this
                // check reads `applied` afterwards and sees this store; one
                // that was gated before it is woken here.
                if ctx.fetch_failed.load(Ordering::SeqCst) {
                    ctx.notify_progress();
                }
                // The window slides: the applied round's slot is free again.
                if let Some(tx) = &permit_tx {
                    let _ = tx.try_send(());
                }
            }
            if stopped {
                // Wake every worker parked waiting for a slot so they exit and
                // the result channel closes.
                permit_tx = None;
            }
        }

        // The result channel only closes once every worker's sender clone has
        // dropped, i.e. once every worker has returned — so by the time the
        // loop above ends, these `join`s return immediately. `stop` is set
        // defensively.
        Self::raise_stop(&stop, &ctx);
        drop(permit_tx);
        for w in workers {
            let _ = w.join();
        }

        if fetched > 0 {
            info!(
                from = %start_round,
                to = %ledger.next_round(),
                blocks = fetched,
                "catchup service: periodic sync advanced the ledger"
            );
        }

        exit_reason
    }

    /// Base delay between retry attempts (doubles with each attempt,
    /// capped at [`Self::MAX_RETRY_DELAY`]).
    const RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

    /// Maximum delay between retry attempts (cap for exponential backoff).
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

    /// Process a single pending unmatched certificate.
    ///
    /// Mirrors Go's `syncCert` / `fetchRound`:
    /// 1. Check if the ledger already has the block for this round.
    /// 2. If not, fetch it from the network (with retries).
    /// 3. Validate the fetched block's digest against the certificate.
    /// 4. Commit it to the ledger via `ensure_block`.
    ///
    /// Unlike an unconditionally-bounded retry loop, this mirrors Go's
    /// `fetchRound` (`for s.ledger.LastRound() < cert.Round`): it keeps
    /// retrying until the block is committed (by any path), shutdown is
    /// signaled, *or* [`Self::CATCHUP_RETRY_LIMIT`] attempts have been made
    /// — go's `catchupRetryLimit` (`catchup/service.go:47`), which exists
    /// specifically so a round that genuinely has no block available
    /// anywhere eventually gives up (with one log line) instead of
    /// retrying, and logging, forever.
    fn sync_cert(
        pending: &PendingUnmatchedCertificate,
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        fork_count: &Arc<AtomicU64>,
    ) -> SyncExitReason {
        Self::sync_cert_with_retry_limit(
            pending,
            ledger,
            fetcher,
            shutdown_rx,
            fork_count,
            Self::CATCHUP_RETRY_LIMIT,
        )
    }

    /// Go's `catchupRetryLimit` (`catchup/service.go:47`): "this should be
    /// at least the number of relays". Bounds [`Self::sync_cert`]'s retry
    /// loop so a round with no block available anywhere eventually gives up
    /// with a single log line instead of retrying (and logging) forever.
    const CATCHUP_RETRY_LIMIT: u32 = 500;

    /// [`Self::sync_cert`]'s actual implementation, parameterized on the
    /// retry-attempt cap so tests can pin exhaustion behavior without
    /// waiting through 500 real backoff delays.
    fn sync_cert_with_retry_limit(
        pending: &PendingUnmatchedCertificate,
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        fork_count: &Arc<AtomicU64>,
        retry_limit: u32,
    ) -> SyncExitReason {
        let cert = &pending.cert;
        let target_round = cert.round;

        debug!(
            round = %target_round,
            "catchup service: processing certificate for round"
        );

        // Guard: bail out if the round requires a protocol version that
        // this node does not support. Mirrors Go's
        // `if s.roundIsNotSupported(cert.Round) { return }` check at the
        // top of `fetchRound` in `catchup/service.go`.
        if ledger.round_is_not_supported(target_round) {
            info!(
                round = %target_round,
                "catchup service: round requires unsupported protocol version, skipping"
            );
            return SyncExitReason::Unsupported;
        }

        // Retry loop: mirrors Go's `for s.ledger.LastRound() < cert.Round`.
        // Continues until the ledger has the block, shutdown is signaled,
        // the retry limit is exceeded, or the block is successfully
        // fetched and committed.
        let mut attempt: u32 = 0;
        loop {
            // Check if the ledger already has this block (committed by
            // agreement or a previous iteration of this loop).
            // next_round = last_committed + 1, so if next_round > target
            // the block is already committed.
            let next_now = ledger.next_round();
            if next_now.0 > target_round.0 {
                debug!(
                    round = %target_round,
                    next_round = %next_now,
                    "catchup service: ledger already has block, skipping"
                );
                return SyncExitReason::Done;
            }

            // Check for shutdown before attempting a fetch.
            if shutdown_rx.try_recv().is_ok() {
                debug!(
                    round = %target_round,
                    "catchup service: shutdown received during sync_cert"
                );
                return SyncExitReason::Stopping;
            }

            // Issue #1677: a certificate for the round the ledger is stalled
            // on (it deterministically fails to apply) must not re-fetch and
            // re-apply it on every gossip of that certificate; wait out the
            // same exponential backoff as the periodic path.
            if Self::cert_sync_gated(
                ledger.apply_stall_retry_in(next_now),
                ledger.apply_stall_failed_digest(),
                cert.proposal.block_digest,
            ) {
                debug!(
                    round = %target_round,
                    "catchup service: stalled on an invalid block, skipping certificate-driven fetch"
                );
                return SyncExitReason::Done;
            }

            attempt = attempt.saturating_add(1);

            // Stop retrying after a while. Mirrors go's
            // `if i > catchupRetryLimit { ... return errFetchRetryLimit }`
            // (`catchup/service.go`'s `fetchAndWrite`) — this is the
            // certificate-driven path's analog, since a certificate that
            // agreement already committed to means the round must
            // eventually be applied, so this only fires for a genuinely
            // unfetchable round (or a test exercising the bound directly).
            if attempt > retry_limit {
                warn!(
                    round = %target_round,
                    attempts = attempt - 1,
                    retry_limit = retry_limit,
                    "catchup service: certificate-driven fetch exceeded retry limit, giving up"
                );
                return SyncExitReason::NoBlock;
            }

            match fetcher.fetch_block(target_round) {
                Ok(fetched) => {
                    let raw_payset_blobs = fetched.raw_payset_blobs;
                    let block = fetched.block;

                    // Validate round match.
                    if block.round != target_round {
                        warn!(
                            expected_round = %target_round,
                            fetched_round = %block.round,
                            attempt = attempt,
                            "catchup service: fetched block round mismatch, retrying"
                        );
                        let delay = Self::backoff_with_jitter(attempt);
                        if shutdown_rx.recv_timeout(delay).is_ok() {
                            debug!(
                                round = %target_round,
                                "catchup service: shutdown received during backoff"
                            );
                            return SyncExitReason::Stopping;
                        }
                        continue;
                    }

                    // Validate that the fetched block's digest matches the
                    // certificate's proposal digest.
                    //
                    // Mirrors Go's `block.Hash() == blockHash` check in
                    // fetchRound (catchup/service.go). The block hash is
                    // SHA512/256("BH" || canonical_encode(block_header)),
                    // matching Go's `bookkeeping.BlockHash`.
                    let block_digest = algo_codec::compute_block_digest(&block);
                    let cert_digest = cert.proposal.block_digest;
                    if block_digest != cert_digest {
                        warn!(
                            round = %target_round,
                            attempt = attempt,
                            block_digest = ?block_digest,
                            cert_digest = ?cert_digest,
                            "catchup service: fetched block digest does not match certificate, retrying"
                        );

                        // Fork detection: mirrors Go's fetchRound failsafe
                        // (catchup/service.go lines 819-839).
                        //
                        // If the fetched response included a certificate, and
                        // that certificate is for the same round but claims to
                        // authenticate a *different* block (i.e. the fetched
                        // block), this indicates a network fork — two valid
                        // certificates exist for different blocks in the same
                        // round.
                        //
                        // We perform a lightweight "claims to authenticate"
                        // check (round + digest match) rather than full quorum
                        // verification, since full authentication requires a
                        // LedgerReader which is not available through the
                        // CatchupLedger trait.
                        //
                        // TODO(fork-auth): Go's implementation (catchup/service.go ~line 822)
                        // calls `fetchedCert.Authenticate(*block, s.ledger, verifier)` which
                        // performs full quorum verification before raising a fork alarm. Our
                        // current lightweight digest comparison could produce false positives
                        // if a malicious peer sends a fabricated certificate. We should
                        // eventually perform full certificate authentication (signature +
                        // quorum check) here to prevent false fork alarms from untrusted peers.
                        if let Some(ref fetched_cert) = fetched.cert {
                            let fetched_cert_digest = fetched_cert.proposal.block_digest;
                            if fetched_cert.round == cert.round
                                && fetched_cert_digest != cert_digest
                                && fetched_cert_digest == block_digest
                            {
                                // Increment the fork detection counter so callers
                                // can observe fork events programmatically.
                                fork_count.fetch_add(1, Ordering::SeqCst);

                                error!(
                                    round = %target_round,
                                    agreement_digest = ?cert_digest,
                                    fetched_digest = ?fetched_cert_digest,
                                    fork_count = fork_count.load(Ordering::SeqCst),
                                    "FORK DETECTED: two certificates authenticate \
                                     different blocks for the same round. \
                                     Agreement cert digest={:?}, \
                                     fetched cert digest={:?}, \
                                     round={}",
                                    cert_digest, fetched_cert_digest, target_round,
                                );

                                // TODO(fork-response): Future work for fork detection response:
                                // - Expose a metrics counter (e.g. Prometheus gauge) for fork events
                                // - Integrate with an alerting system (e.g. webhook, PagerDuty)
                                // - Add an optional configurable halt mechanism that stops the node
                                //   on fork detection, similar to Go's `logging.Base().EventWithDetails()`
                                //   which can trigger external monitoring
                            }
                        }

                        // A malicious or wrong peer returned a bad block.
                        // Retry with a different peer (the fetcher may rotate).
                        let delay = Self::backoff_with_jitter(attempt);
                        // Use recv_timeout so shutdown can interrupt the wait.
                        if shutdown_rx.recv_timeout(delay).is_ok() {
                            debug!(
                                round = %target_round,
                                "catchup service: shutdown received during backoff"
                            );
                            return SyncExitReason::Stopping;
                        }
                        continue;
                    }

                    // Validate that the block body matches header commitments.
                    // Mirrors Go's `block.ContentsMatchHeader()` check in
                    // fetchRound (catchup/service.go). The block hash only
                    // authenticates the header; this ensures the transactions
                    // are consistent with it.
                    match algo_validate::contents_match_header(&block, raw_payset_blobs.as_deref())
                    {
                        Ok(true) => { /* commitments match, proceed */ }
                        Ok(false) => {
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                "catchup service: block contents do not match header commitments, retrying"
                            );
                            let delay = Self::backoff_with_jitter(attempt);
                            if shutdown_rx.recv_timeout(delay).is_ok() {
                                debug!(
                                    round = %target_round,
                                    "catchup service: shutdown received during backoff"
                                );
                                return SyncExitReason::Stopping;
                            }
                            continue;
                        }
                        Err(reason) => {
                            // An Err means the protocol version is empty or
                            // unsupported — a deterministic failure that won't
                            // resolve on retry. Abort instead of looping forever.
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                error = %reason,
                                "catchup service: cannot verify block contents (fatal), aborting"
                            );
                            return SyncExitReason::NoBlock;
                        }
                    }

                    // Commit the block to the ledger.
                    // EnsureBlock is idempotent — if the block was already
                    // committed by normal agreement between fetch and now,
                    // this is a harmless no-op.
                    debug!(
                        round = %target_round,
                        "catchup service: committing fetched block to ledger"
                    );
                    ledger.ensure_block(&block, cert);

                    info!(
                        round = %target_round,
                        "catchup service: successfully fetched and committed block"
                    );
                    return SyncExitReason::Done;
                }
                Err(e) => {
                    // Mirror Go's pattern: NoBlockForRound is a normal
                    // condition during catchup (the peer simply doesn't
                    // have it yet), so log at trace/debug level and use a
                    // shorter backoff.  Other errors are unexpected and
                    // warrant warning-level logging.
                    let delay = match &e {
                        FetchError::NoBlockForRound { .. } => {
                            trace!(
                                round = %target_round,
                                attempt = attempt,
                                "catchup service: block not yet available, will retry"
                            );
                            // Use base delay without exponential backoff —
                            // the block may appear momentarily.
                            Self::RETRY_BASE_DELAY
                        }
                        FetchError::NetworkError(_)
                        | FetchError::Timeout
                        | FetchError::NoPeersAvailable => {
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                error = %e,
                                "catchup service: failed to fetch block, will retry"
                            );
                            Self::backoff_with_jitter(attempt)
                        }
                    };
                    // Use recv_timeout so shutdown can interrupt the wait.
                    if shutdown_rx.recv_timeout(delay).is_ok() {
                        debug!(
                            round = %target_round,
                            "catchup service: shutdown received during backoff"
                        );
                        return SyncExitReason::Stopping;
                    }
                }
            }
        }
    }

    /// Compute an exponential backoff delay with jitter, capped at
    /// [`Self::MAX_RETRY_DELAY`].
    ///
    /// The jitter is derived from the current timestamp to avoid adding a
    /// `rand` dependency to this crate. It adds ±50% variation to the base
    /// exponential delay, preventing thundering-herd effects when multiple
    /// nodes retry simultaneously.
    fn backoff_with_jitter(attempt: u32) -> Duration {
        let base = Self::RETRY_BASE_DELAY * 2u32.saturating_pow(attempt.saturating_sub(1));
        let base = std::cmp::min(base, Self::MAX_RETRY_DELAY);

        // Lightweight jitter: use the low bits of the current timestamp
        // (nanoseconds) to add ±50% variation.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        // Map nanos to [0.5, 1.5) multiplier: 0.5 + (nanos % 1000) / 1000.0
        let jitter_frac = 0.5 + (nanos % 1000) as f64 / 1000.0;
        let jittered_millis = (base.as_millis() as f64 * jitter_frac) as u64;

        Duration::from_millis(jittered_millis)
    }
}

impl Drop for CatchupService {
    fn drop(&mut self) {
        // Ensure the background thread is stopped if the service is dropped
        // without an explicit `stop()` call.
        if self.shutdown_tx.is_some() || self.join_handle.is_some() {
            self.stop();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::{AsyncVoteVerifier, PendingUnmatchedCertificate};
    use algo_types::Round;
    use std::sync::Mutex;
    use std::time::Duration;

    // -- Mock CatchupLedger --

    /// A lightweight mock ledger for tests — no SQLite required.
    struct MockCatchupLedger {
        round: Mutex<Round>,
    }

    impl MockCatchupLedger {
        fn new(current_round: Round) -> Self {
            Self {
                round: Mutex::new(current_round),
            }
        }
    }

    impl CatchupLedger for MockCatchupLedger {
        fn next_round(&self) -> Round {
            let r = self.round.lock().unwrap();
            Round(r.0.saturating_add(1))
        }

        fn ensure_block(&self, block: &Block, _cert: &Certificate) {
            // Advance the round when a block is committed, mimicking real ledger behaviour.
            let mut r = self.round.lock().unwrap();
            if block.round.0 >= r.0 {
                *r = Round(block.round.0);
            }
        }
    }

    // -- Mock BlockFetcher --

    struct MockBlockFetcher {
        /// The block to return for any fetch request.
        block: Mutex<Option<Block>>,
    }

    impl MockBlockFetcher {
        fn new(block: Option<Block>) -> Self {
            Self {
                block: Mutex::new(block),
            }
        }
    }

    impl BlockFetcher for MockBlockFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            let guard = self.block.lock().unwrap();
            match guard.as_ref() {
                Some(b) => {
                    let mut block = b.clone();
                    block.round = round;
                    Ok(FetchedBlockCert {
                        block,
                        cert: None,
                        raw_payset_blobs: None,
                    })
                }
                None => Err(FetchError::NoBlockForRound { round }),
            }
        }
    }

    // -- Helper to create a minimal certificate --

    fn make_cert(round: u64) -> Certificate {
        Certificate::for_test(Round(round))
    }

    fn make_pending_cert(round: u64) -> PendingUnmatchedCertificate {
        PendingUnmatchedCertificate {
            cert: make_cert(round),
            vote_verifier: AsyncVoteVerifier::new(),
        }
    }

    // -- Helpers --

    /// Poll a condition function until it returns `true`, sleeping briefly
    /// between checks.  Panics if the timeout elapses before the condition
    /// is met.  This replaces fixed `thread::sleep` calls in tests,
    /// reducing flakiness on slow CI runners while still being responsive.
    fn poll_until(
        condition: impl Fn() -> bool,
        poll_interval: Duration,
        timeout: Duration,
        msg: &str,
    ) {
        let start = std::time::Instant::now();
        while !condition() {
            if start.elapsed() >= timeout {
                panic!("poll_until timed out after {timeout:?}: {msg}");
            }
            thread::sleep(poll_interval);
        }
    }

    /// Create a block with a known protocol version and correct commitments
    /// for an empty payset. This ensures `contents_match_header` passes.
    fn make_valid_empty_block(round: u64) -> Block {
        use algo_validate::merkle::{compute_vector_commitment, HashAlgo};

        let mut block = Block {
            round: Round(round),
            current_protocol: "future".to_string(),
            ..Default::default()
        };

        // For "future" protocol with empty payset:
        // - txn_commitment: Merkle root of empty payset = [0u8; 32] (already default)
        // - txn256: SHA-256 vector commitment of empty payset
        // - txn512: SHA-512 vector commitment of empty payset
        let vc256 = compute_vector_commitment(&block, HashAlgo::Sha256);
        let vc512 = compute_vector_commitment(&block, HashAlgo::Sha512);
        block.txn256.copy_from_slice(&vc256);
        block.txn512.copy_from_slice(&vc512);

        block
    }

    // -- Mocks for the periodic (certificate-less) sync path --

    /// A ledger that authenticates any certificate, so periodic-sync tests
    /// can focus on the fetch/commit loop rather than on quorum crypto.
    struct PermissiveCatchupLedger {
        inner: MockCatchupLedger,
    }

    impl CatchupLedger for PermissiveCatchupLedger {
        fn next_round(&self) -> Round {
            self.inner.next_round()
        }
        fn ensure_block(&self, block: &Block, cert: &Certificate) {
            self.inner.ensure_block(block, cert)
        }
        fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
            Ok(())
        }
    }

    /// Serves rounds `1..=up_to`, each with a certificate, and reports
    /// `NoBlockForRound` beyond that — i.e. behaves like a peer that is
    /// itself at round `up_to`.
    struct BoundedBlockFetcher {
        up_to: u64,
        calls: AtomicU64,
    }

    impl BlockFetcher for BoundedBlockFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if round.0 > self.up_to {
                return Err(FetchError::NoBlockForRound { round });
            }
            let block = make_valid_empty_block(round.0);
            Ok(FetchedBlockCert {
                block,
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// A ledger whose every `ensure_block` fails to apply, modelling the
    /// real bridge: it records the failure in a shared
    /// [`crate::ApplyStallTracker`] and does not advance. `errors` picks the
    /// error text per attempt (same text = deterministic).
    struct FailingApplyLedger {
        round: Mutex<Round>,
        tracker: Arc<crate::ApplyStallTracker>,
        attempts: AtomicU64,
        /// Fake clock origin: failure `n` happens at `base + 9 s * n`, i.e.
        /// each attempt lands just after the previous backoff window.
        base: std::time::Instant,
        deterministic: AtomicBool,
        succeed: AtomicBool,
    }

    impl FailingApplyLedger {
        fn new(deterministic: bool) -> Arc<Self> {
            Arc::new(Self {
                round: Mutex::new(Round(0)),
                tracker: Arc::new(crate::ApplyStallTracker::new()),
                attempts: AtomicU64::new(0),
                base: std::time::Instant::now(),
                deterministic: AtomicBool::new(deterministic),
                succeed: AtomicBool::new(false),
            })
        }
    }

    impl CatchupLedger for FailingApplyLedger {
        fn next_round(&self) -> Round {
            Round(self.round.lock().unwrap().0 + 1)
        }
        fn ensure_block(&self, block: &Block, _cert: &Certificate) {
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.succeed.load(Ordering::SeqCst) {
                *self.round.lock().unwrap() = block.round;
                self.tracker.observe_ledger_round(block.round.0);
                return;
            }
            let err = if self.deterministic.load(Ordering::SeqCst) {
                "tx 0xabc: balance below minimum".to_string()
            } else {
                format!("transient io error #{n}")
            };
            let at = self.base + Duration::from_secs(9 * n);
            self.tracker.record_failure_at_with_digest(
                block.round.0,
                &err,
                at,
                Some(algo_codec::compute_block_digest(block)),
            );
        }
        fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
            Ok(())
        }
        fn apply_stall_failed_digest(&self) -> Option<algo_types::Digest> {
            self.tracker.failed_block_digest()
        }
        fn apply_stall_retry_in(&self, _next_round: Round) -> Option<Duration> {
            let n = self.attempts.load(Ordering::SeqCst).saturating_sub(1);
            self.tracker
                .retry_in_at(self.base + Duration::from_secs(9 * n))
        }
    }

    fn bounded_fetcher() -> Arc<BoundedBlockFetcher> {
        Arc::new(BoundedBlockFetcher {
            up_to: 5,
            calls: AtomicU64::new(0),
        })
    }

    /// Issue #1677: a block that fails to apply twice
    /// puts the ledger in the stalled state, with a growing backoff; a
    /// success clears it.
    #[test]
    fn deterministic_apply_failure_stalls_then_recovers() {
        let ledger = FailingApplyLedger::new(true);
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = bounded_fetcher();
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(1);

        CatchupService::sync_range(&ledger_dyn, &fetcher, &stop_rx, 1);
        assert!(
            ledger.tracker.stall().is_none(),
            "one failure is not a stall"
        );
        assert!(ledger_dyn
            .apply_stall_retry_in(ledger_dyn.next_round())
            .is_none());

        CatchupService::sync_range(&ledger_dyn, &fetcher, &stop_rx, 1);
        let stall = ledger
            .tracker
            .stall()
            .expect("second failed attempt stalls");
        assert_eq!(stall.round, 1);
        assert_eq!(stall.consecutive_failures, 2);
        let first = ledger_dyn
            .apply_stall_retry_in(ledger_dyn.next_round())
            .expect("must back off");

        CatchupService::sync_range(&ledger_dyn, &fetcher, &stop_rx, 1);
        assert_eq!(ledger.tracker.stall().unwrap().consecutive_failures, 3);
        let second = ledger_dyn
            .apply_stall_retry_in(ledger_dyn.next_round())
            .expect("must back off");
        assert!(second > first, "backoff must grow: {first:?} -> {second:?}");

        ledger.succeed.store(true, Ordering::SeqCst);
        CatchupService::sync_range(&ledger_dyn, &fetcher, &stop_rx, 1);
        assert!(ledger.tracker.stall().is_none(), "commit clears the stall");
        assert!(ledger_dyn
            .apply_stall_retry_in(ledger_dyn.next_round())
            .is_none());
    }

    /// Issue #1677: the periodic loop must not re-run the fetch+apply pass
    /// while the stall backoff is pending, but still runs it normally
    /// otherwise (transient behaviour unchanged) and never gates progress.
    #[test]
    fn periodic_tick_honours_the_stall_backoff() {
        let wait = Some(Duration::from_secs(5));
        let (r, same) = (Round(3), Round(3));
        // Stuck + stalled + backoff pending: no pass.
        assert_eq!(
            CatchupService::periodic_tick_action(r, same, true, wait),
            PeriodicTick::BackOff
        );
        // Backoff elapsed (or never stalled): the pass runs, as before.
        assert_eq!(
            CatchupService::periodic_tick_action(r, same, true, None),
            PeriodicTick::Sync
        );
        // The first idle tick only re-arms, stalled or not.
        assert_eq!(
            CatchupService::periodic_tick_action(r, same, false, wait),
            PeriodicTick::Rearm
        );
        // Ledger progress (e.g. agreement committed a different block) is
        // never held back by a stale stall.
        assert_eq!(
            CatchupService::periodic_tick_action(Round(4), same, true, wait),
            PeriodicTick::Advanced
        );
    }

    /// Issue #1677: the certificate path skips only the very block that
    /// failed; a certificate for a different block (the recovery path) and
    /// an unknown failed digest are never gated.
    #[test]
    fn cert_sync_gate_skips_only_the_same_bad_block() {
        let (bad, other) = (algo_types::Digest([1; 32]), algo_types::Digest([2; 32]));
        let wait = Some(Duration::from_secs(3));
        assert!(CatchupService::cert_sync_gated(wait, Some(bad), bad));
        assert!(!CatchupService::cert_sync_gated(wait, Some(bad), other));
        assert!(!CatchupService::cert_sync_gated(wait, None, bad));
        assert!(!CatchupService::cert_sync_gated(None, Some(bad), bad));
    }

    /// Issue #1677: a stalled ledger makes sync_cert skip the fetch entirely.
    #[test]
    fn sync_cert_skips_the_fetch_while_stalled() {
        let ledger = FailingApplyLedger::new(true);
        let err = "tx 0xabc: balance below minimum";
        // Fake time: failures at base, so the wait is the full 8 s.
        let pending = make_pending_cert(1);
        let digest = Some(pending.cert.proposal.block_digest);
        for _ in 0..2 {
            ledger
                .tracker
                .record_failure_at_with_digest(1, err, ledger.base, digest);
        }
        ledger.attempts.store(1, Ordering::SeqCst);
        let fetcher = bounded_fetcher();
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(1);
        let reason = CatchupService::sync_cert(
            &pending,
            &ledger_dyn,
            &fetcher_dyn,
            &stop_rx,
            &Arc::new(AtomicU64::new(0)),
        );
        assert_eq!(reason, SyncExitReason::Done);
        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            0,
            "no fetch while stalled"
        );
    }

    /// Issue #1677: the bridge-facing stall wait feeds the tick decision.
    #[test]
    fn stalled_ledger_wait_gates_the_tick() {
        let ledger = FailingApplyLedger::new(true);
        let t0 = std::time::Instant::now();
        let err = "tx 0xabc: balance below minimum";
        ledger.tracker.record_failure_at(1, err, t0);
        ledger.tracker.record_failure_at(1, err, t0);
        let wait = ledger.tracker.retry_in_at(t0 + Duration::from_secs(1));
        assert_eq!(
            CatchupService::periodic_tick_action(Round(1), Round(1), true, wait),
            PeriodicTick::BackOff
        );
        let wait = ledger.tracker.retry_in_at(t0 + Duration::from_secs(9));
        assert_eq!(
            CatchupService::periodic_tick_action(Round(1), Round(1), true, wait),
            PeriodicTick::Sync
        );
    }

    /// Regression test for issue #478.
    ///
    /// A Rust node that joins an already-running network starts its
    /// agreement service at `ledger_round + 1` while the network is far
    /// ahead. Agreement never emits an unmatched certificate for a round it
    /// is not playing, so the certificate-driven path alone can never close
    /// that gap: the node sat at round 1 escalating periods forever. Go
    /// closes it with `periodicSync`'s `time.After` branch calling `sync()`
    /// (`catchup/service.go:641-662`), which this mirrors.
    ///
    /// No certificate is ever sent on `cert_rx` here — the ledger must still
    /// catch up.
    #[test]
    fn periodic_sync_catches_up_without_any_certificate() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 5,
            calls: AtomicU64::new(0),
        });

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher);

        poll_until(
            || ledger.next_round() == Round(6),
            Duration::from_millis(20),
            Duration::from_secs(10),
            "periodic sync should have pulled rounds 1..=5 with no certificate from agreement",
        );

        svc.stop();
    }

    /// Regression test for issue #1564.
    ///
    /// After a node resumes from a large post-restart catch-up gap, its own
    /// agreement service can take noticeably longer than one
    /// `PERIODIC_SYNC_INTERVAL` tick to complete a round's own soft/cert
    /// vote collection — that is routine, not a stall. Before this fix, the
    /// periodic path treated the very first such missed tick as "the
    /// ledger has stalled" and immediately ran its own network `sync_pass`,
    /// which — being certificate-free and needing no timers — always won
    /// the race and committed the round out from under the local player.
    /// That commit itself counted as "progress", so the next tick saw no
    /// *further* advance and fired again: a self-sustaining loop that
    /// permanently silenced the agreement service's own vote/attest path
    /// (reproduced live in `consensus-cluster.yml`'s restart-rejoin suite:
    /// `sigkill/resumed_voting` and `proposer-1/resumed_voting` failed for
    /// the rest of the run after a SIGKILL restart with a large catch-up
    /// gap, while a graceful restart's small gap recovered in one round).
    ///
    /// Here a slower-but-live writer (standing in for the local agreement
    /// service) commits one round every 5.5s — longer than the single 4s
    /// `PERIODIC_SYNC_INTERVAL`, but well inside the fixed two-tick (~8s)
    /// grace window this fix adds, mirroring go's `periodicSync` two-stage
    /// backoff (`catchup/service.go:664-705`). The fetcher can never supply
    /// a real block (`up_to: 0`), so if the periodic path ever actually
    /// fires a fresh `sync_pass` during the writer's run, that is
    /// observable as a `calls` increase past the startup baseline —
    /// proving the starvation bug would still be present.
    #[test]
    fn periodic_sync_does_not_race_a_slower_but_live_writer() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(BoundedBlockFetcher {
            up_to: 0,
            calls: AtomicU64::new(0),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher_dyn);

        // Let the startup `sync_pass` (unconditional, mirrors go running one
        // `sync()` immediately) settle before measuring — it ends after its
        // tip probe (round 1 > up_to 0: six "no block" answers 100 ms apart)
        // and is unrelated to the periodic hysteresis under test here.
        thread::sleep(Duration::from_millis(1_200));
        let baseline_calls = fetcher.calls.load(Ordering::SeqCst);

        // Simulate a live-but-slower agreement service: one committed round
        // every 5.5s, for three rounds (~16.5s total, comfortably spanning
        // several `PERIODIC_SYNC_INTERVAL` ticks).
        for round in 1..=3u64 {
            thread::sleep(Duration::from_millis(5_500));
            let block = make_valid_empty_block(round);
            ledger.inner.ensure_block(&block, &make_cert(round));
        }

        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            baseline_calls,
            "periodic sync must not attempt a network fetch while a slower \
             but live writer is still making progress within the grace \
             window (issue #1564)"
        );
        assert_eq!(
            ledger.next_round(),
            Round(4),
            "the writer's own commits (not periodic sync) must be what \
             advanced the ledger"
        );

        svc.stop();
    }

    /// A fetcher that answers one designated "cert round" instantly with a
    /// valid block, but sleeps for `periodic_delay` before failing every
    /// other round — standing in for a periodic-sync pass that is slow (a
    /// large post-restart backlog, a contended/slow network) at exactly
    /// the moment agreement needs a certificate-driven fetch serviced.
    /// Used by `cert_driven_fetch_is_not_blocked_behind_a_slow_periodic_pass`
    /// (issue #1576).
    struct SlowPeriodicFastCertFetcher {
        cert_round: Round,
        cert_block: Block,
        periodic_delay: Duration,
    }

    impl BlockFetcher for SlowPeriodicFastCertFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            if round == self.cert_round {
                return Ok(FetchedBlockCert {
                    block: self.cert_block.clone(),
                    cert: None,
                    raw_payset_blobs: None,
                });
            }
            thread::sleep(self.periodic_delay);
            Err(FetchError::NoBlockForRound { round })
        }
    }

    /// Regression test for issue #1576.
    ///
    /// Root cause (confirmed via a live SIGKILL-restart reproduction
    /// against `ops/mixed-cluster`, correlated timestamp-for-timestamp
    /// against the Go peers' own `ThresholdReached` telemetry): a
    /// certificate-driven fetch (`Self::sync_cert`, triggered by
    /// agreement's `StageDigestAction` when it has a certificate but not
    /// yet the block) and the periodic, certificate-less catch-up pass
    /// (`Self::sync_pass`) used to share one thread's single `Select`
    /// loop — mirroring go-algorand's `periodicSync`, which has the exact
    /// same structure (`catchup/service.go:611-711`: `s.sync()` and
    /// `s.syncCert()` are both called synchronously from the same
    /// goroutine's `for { select { ... } } ` body). A certificate arriving
    /// on `cert_rx` while a `sync_pass` was already in flight therefore
    /// sat unprocessed until that pass returned — which, right after a
    /// large post-restart catch-up gap (exactly when agreement is also
    /// most likely to need a certificate-driven fetch for the first
    /// round(s) it resumes participating in), can take a long time. The
    /// longer that certificate sits stuck, the longer the
    /// `RoundInterruption` that lets agreement's player re-zero its next
    /// round's clock in phase with the rest of the (uninterrupted)
    /// committee is delayed — turning a single, inherently self-
    /// correcting missed round into a longer streak of consecutive
    /// missed local votes.
    ///
    /// This is a purely internal-concurrency-structure difference from
    /// go-algorand, not a consensus-visible one: `sync_cert` and
    /// `sync_pass_inner` still run the exact same validation
    /// (digest match, `contents_match_header`, `ensure_block`) either
    /// way — only *how promptly* a certificate-driven fetch can be
    /// serviced changes, which is safe to improve unilaterally.
    ///
    /// Here the fetcher sleeps for `periodic_delay` (2s) before failing
    /// every round the *periodic* path asks for (it starts at round 1,
    /// since the ledger starts at round 0), simulating a slow/contended
    /// network during the unconditional startup `sync_pass`. A
    /// certificate for a much later round is sent immediately. Before
    /// the #1576 fix (a single shared thread/loop), servicing that
    /// certificate would have to wait for the periodic path's slow fetch
    /// to fail out first — at least `periodic_delay`. After the fix (the
    /// certificate-driven path on its own thread), it is serviced
    /// immediately regardless.
    #[test]
    fn cert_driven_fetch_is_not_blocked_behind_a_slow_periodic_pass() {
        let cert_round = Round(999);
        let block = make_valid_empty_block(cert_round.0);
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(SlowPeriodicFastCertFetcher {
            cert_round,
            cert_block: block,
            periodic_delay: Duration::from_secs(2),
        });

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher);

        // Send the certificate right away — the startup periodic
        // `sync_pass` (round 1, mirrors go running one `sync()`
        // immediately) is still in flight, sleeping out its
        // `periodic_delay` before it can even report failure.
        tx.send(make_pending_cert_with_digest(cert_round.0, digest))
            .unwrap();

        poll_until(
            || ledger.next_round() == Round(cert_round.0 + 1),
            Duration::from_millis(20),
            Duration::from_millis(500),
            "a certificate-driven fetch must be serviced promptly even while a slow \
             periodic sync pass is in flight (issue #1576's priority-inversion fix) — \
             this would take at least `periodic_delay` before the #1576 fix",
        );

        svc.stop();
    }

    /// A block offered without a certificate must not be committed: the
    /// periodic path has no agreement-verified certificate to fall back on,
    /// so an unauthenticated block would be trusted purely on a peer's word.
    #[test]
    fn periodic_sync_refuses_a_block_with_no_certificate() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        // `MockBlockFetcher` always returns `cert: None`.
        let fetcher: Arc<dyn BlockFetcher> =
            Arc::new(MockBlockFetcher::new(Some(make_valid_empty_block(1))));

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            ledger.next_round(),
            Round(1),
            "a certificate-less block must not be committed by the periodic path"
        );
        svc.stop();
    }

    /// The default `authenticate_block` refuses, so a ledger that has not
    /// opted in cannot have unverified blocks written under it.
    #[test]
    fn periodic_sync_refuses_when_ledger_cannot_authenticate() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(MockCatchupLedger::new(Round(0)));
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 5,
            calls: AtomicU64::new(0),
        });

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(ledger.next_round(), Round(1));
        svc.stop();
    }

    // -- Tests --

    #[test]
    fn stop_without_certs_is_clean() {
        // The service should start and stop cleanly even if no certs arrive.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, fetcher);
        svc.stop();
    }

    #[test]
    fn drop_triggers_stop() {
        // Dropping the service should stop the background thread cleanly.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let svc = CatchupService::start(rx, ledger, fetcher);
        drop(svc); // should not panic
    }

    #[test]
    fn cert_channel_closed_stops_cleanly() {
        // Closing the cert channel must NOT end the service (the periodic
        // path keeps the ledger following the network); `stop()` must still
        // shut it down cleanly.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, fetcher);

        // Drop the sender to close the channel.
        drop(tx);

        svc.stop();
    }

    #[test]
    fn fetch_failure_does_not_crash() {
        // If the block fetcher fails, the service retries indefinitely.
        // Verify it stays alive and handles failures gracefully, then
        // shut it down to stop the retry loop.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(CountingFailFetcher::new(make_valid_empty_block(0), 999));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert — the fetch will fail but the service should survive.
        tx.send(make_pending_cert(5)).unwrap();

        // Poll until at least two retries have been attempted, verifying
        // the service survives failures and keeps retrying.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.total_calls() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should have been called at least twice (retry after failure)",
        );

        assert!(
            fetcher.total_calls() >= 2,
            "expected at least two fetch attempts (verifying retry), got {}",
            fetcher.total_calls()
        );

        svc.stop();
    }

    #[test]
    fn skips_already_committed_round() {
        // If the ledger is already at or past the certificate round, no fetch
        // should occur. We verify this using a sentinel cert: after sending
        // the skipped cert, we send a second cert for the next expected round.
        // When that sentinel is fetched, we know the first cert was processed
        // (and skipped) without any fetch.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(2);
        // Ledger at round 10 (past the cert round of 5).
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(10)));

        // Create a block for the sentinel round (11 = next expected round).
        let sentinel_block = make_valid_empty_block(11);
        let sentinel_digest = algo_codec::compute_block_digest(&sentinel_block);

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(sentinel_block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        // Parallelism pinned to 1: this test asserts a tight fetch-count
        // bound to prove no wasteful re-fetching of an already-committed
        // round, which is only a meaningful guarantee in strictly serial
        // mode — `DigestMatchingBlockFetcher` ignores the requested round
        // and always returns the same block, so a concurrent worker pool
        // would race ahead fetching many rounds before the mismatch is
        // detected (that speculative-fetch cost is expected and covered by
        // `periodic_sync_fetches_blocks_in_parallel` instead).
        let mut svc = CatchupService::start_with_parallelism(rx, ledger, fetcher_ref, 1);

        // Send a cert for round 5 — already committed, should be skipped.
        tx.send(make_pending_cert(5)).unwrap();
        // Send a sentinel cert for round 11 — should be fetched.
        tx.send(make_pending_cert_with_digest(11, sentinel_digest))
            .unwrap();

        // Poll until the sentinel fetch completes.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "sentinel cert for round 11 should have been fetched",
        );

        // Roughly two fetches: the one startup periodic probe the service
        // makes for `next_round()` (Go's `periodicSync` does the same,
        // catchup/service.go:611-619) plus exactly one certificate-driven
        // fetch for the sentinel. Crucially, the already-committed round 5
        // must not add one. `start_with_parallelism(.., 1)`'s single
        // periodic-sync worker can race one extra (wasted, discarded)
        // speculative fetch ahead of the main thread noticing the startup
        // probe should stop (a worker claims its next round of the
        // fetch window before the main thread notices), so this allows a
        // small, explicitly-bounded slack rather than an exact count.
        assert!(
            fetcher.fetch_count() <= 4,
            "fetcher should be called only for the startup probe (plus at most one \
             speculative pipeline fetch) and the sentinel, not for the skipped round \
             (got {})",
            fetcher.fetch_count()
        );

        svc.stop();
    }

    /// A fetcher that serves rounds `1..=up_to`, each with a correctly
    /// digest-matched block, and injects a small per-round delay to widen
    /// the race window against a concurrent writer.
    struct DelayedRoundServingBlockFetcher {
        up_to: u64,
        calls: AtomicU64,
    }

    impl BlockFetcher for DelayedRoundServingBlockFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if round.0 > self.up_to {
                return Err(FetchError::NoBlockForRound { round });
            }
            // Deterministic (not random) small stagger, varying by round,
            // to widen the window in which the racing writer thread below
            // can commit the same round out from under this fetch.
            thread::sleep(Duration::from_micros(200 * (round.0 % 5)));
            let block = make_valid_empty_block(round.0);
            Ok(FetchedBlockCert {
                block,
                cert: None,
                raw_payset_blobs: None,
            })
        }
    }

    /// Regression-shaped analog of Go's `TestAbruptWrites`
    /// (`catchup/service_test.go:419`): Go's test races a concurrent
    /// goroutine that writes blocks directly to the local ledger (emulating
    /// agreement making progress on its own) against `Service.sync()`
    /// fetching the same rounds, and asserts the final round matches
    /// without any panic, deadlock, or corrupted state from the two writers
    /// racing on `Ledger.AddBlock`.
    ///
    /// algod-rust's `CatchupService` is certificate-driven: `sync_cert`
    /// already re-checks `ledger.next_round()` at the top of its retry loop
    /// (see `skips_already_committed_round` above) specifically so a round
    /// committed by a concurrent writer — real agreement in production, the
    /// `writer` thread here — is detected and skipped rather than
    /// re-applied. This test proves that guard actually holds under a real
    /// race, not just when the racing write happens strictly before
    /// `sync_cert` starts: a background thread commits blocks for rounds
    /// `1..=NUM_ROUNDS` directly to the shared `MockCatchupLedger` (racing
    /// with `MockCatchupLedger::ensure_block`'s own `Mutex`) while the
    /// catchup service concurrently fetches and commits certificates for
    /// the very same rounds through `DelayedRoundServingBlockFetcher`.
    #[test]
    fn abrupt_writes_race_with_concurrent_ledger_commits() {
        const NUM_ROUNDS: u64 = 20;

        let (tx, rx) =
            crossbeam_channel::bounded::<PendingUnmatchedCertificate>(NUM_ROUNDS as usize);
        let ledger_ref = Arc::new(MockCatchupLedger::new(Round(0)));
        let ledger: Arc<dyn CatchupLedger> = Arc::clone(&ledger_ref) as Arc<dyn CatchupLedger>;

        let fetcher = Arc::new(DelayedRoundServingBlockFetcher {
            up_to: NUM_ROUNDS,
            calls: AtomicU64::new(0),
        });
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start_with_parallelism(rx, ledger, fetcher_ref, 4);

        // Background "agreement" writer: commits every round directly to
        // the shared ledger, racing the catchup service's own commits of
        // the same rounds via certificates sent below.
        let writer_ledger = Arc::clone(&ledger_ref);
        let writer = thread::spawn(move || {
            for round in 1..=NUM_ROUNDS {
                // Deterministic stagger, offset from the fetcher's so the
                // two writers interleave rather than always racing in
                // lockstep.
                thread::sleep(Duration::from_micros(150 * ((round * 3) % 7)));
                let block = make_valid_empty_block(round);
                let cert = make_cert(round);
                writer_ledger.ensure_block(&block, &cert);
            }
        });

        // Send certs for every round with the correct digest, so the
        // catchup service races the writer thread above to commit each one.
        for round in 1..=NUM_ROUNDS {
            let digest = algo_codec::compute_block_digest(&make_valid_empty_block(round));
            tx.send(make_pending_cert_with_digest(round, digest))
                .unwrap();
        }

        writer.join().expect("writer thread should not panic");

        // Both writers target the same final round; whichever one gets
        // there last, the ledger should end up fully caught up with no
        // corruption (mirrors Go's `require.Equal(t, remote.LastRound(),
        // local.LastRound())`).
        poll_until(
            move || ledger_ref.next_round() == Round(NUM_ROUNDS + 1),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "ledger should reach the final round despite racing writers",
        );

        svc.stop();
    }

    // -- DigestMatchingBlockFetcher: returns a block whose digest matches the cert --

    /// A fetcher that returns a block whose digest can be pre-computed.
    /// Unlike `MockBlockFetcher`, this does NOT modify the round on the
    /// returned block, allowing tests to control digest matching.
    struct DigestMatchingBlockFetcher {
        block: Block,
        fetch_count: AtomicU64,
    }

    impl DigestMatchingBlockFetcher {
        fn new(block: Block) -> Self {
            Self {
                block,
                fetch_count: AtomicU64::new(0),
            }
        }

        fn fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for DigestMatchingBlockFetcher {
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedBlockCert {
                block: self.block.clone(),
                cert: None,
                raw_payset_blobs: None,
            })
        }
    }

    /// Helper to make a certificate with a specific block digest.
    fn make_cert_with_digest(round: u64, digest: algo_types::Digest) -> Certificate {
        use algo_agreement::ProposalValue;
        Certificate {
            proposal: ProposalValue {
                block_digest: digest,
                ..Default::default()
            },
            ..Certificate::for_test(Round(round))
        }
    }

    fn make_pending_cert_with_digest(
        round: u64,
        digest: algo_types::Digest,
    ) -> PendingUnmatchedCertificate {
        PendingUnmatchedCertificate {
            cert: make_cert_with_digest(round, digest),
            vote_verifier: AsyncVoteVerifier::new(),
        }
    }

    #[test]
    fn happy_path_fetch_and_commit() {
        // Create a block for round 1 with valid commitments and compute its digest.
        let block = make_valid_empty_block(1);
        let digest = algo_codec::compute_block_digest(&block);

        // Set up the service with a fetcher that returns this block.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        // Ledger is at round 0, so round 1 is the next expected.
        let ledger_ref = Arc::new(MockCatchupLedger::new(Round(0)));
        let ledger: Arc<dyn CatchupLedger> = Arc::clone(&ledger_ref) as Arc<dyn CatchupLedger>;

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        // Parallelism pinned to 1 — see `skips_already_committed_round`'s
        // comment for why this test's tight fetch-count bound only holds
        // in strictly serial mode against `DigestMatchingBlockFetcher`.
        let mut svc = CatchupService::start_with_parallelism(rx, ledger, fetcher_ref, 1);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Poll until the fetcher has been called, rather than a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should be called for a valid block",
        );

        // Roughly two fetches: the startup periodic probe plus one
        // certificate-driven fetch, no retries for a valid block — plus a
        // small bounded slack for the periodic pass of
        // `start_with_parallelism(.., 1)`, whose single fetch-window slot
        // may hold one more in-flight fetch (see
        // `skips_already_committed_round`'s comment on the same bound).
        assert!(
            fetcher.fetch_count() <= 4,
            "a valid block should need no retries (got {} fetches)",
            fetcher.fetch_count()
        );

        // The block should have been committed to the ledger.
        // Poll until the ledger has advanced (ensure_block was called).
        let ledger_poll = Arc::clone(&ledger_ref);
        poll_until(
            move || ledger_poll.next_round() == Round(2),
            Duration::from_millis(50),
            Duration::from_secs(5),
            "ledger should have advanced to round 1 (next_round == 2)",
        );

        assert_eq!(
            ledger_ref.next_round(),
            Round(2),
            "ledger should have advanced to round 1"
        );

        svc.stop();
    }

    #[test]
    fn digest_mismatch_triggers_retry() {
        // Create a block for round 1, but make the certificate have a
        // different digest. This should cause digest validation to fail
        // and trigger retries indefinitely until shutdown.
        let block = make_valid_empty_block(1);
        // The actual digest of this block will NOT match the cert.

        let wrong_digest = algo_types::Digest([0xff; 32]);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with a wrong digest.
        tx.send(make_pending_cert_with_digest(1, wrong_digest))
            .unwrap();

        // Poll until the fetcher has been called at least twice (retry on
        // digest mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on digest mismatch",
        );

        // Shutdown stops the retry loop.
        svc.stop();
    }

    // -- CountingFailFetcher: fails N times then succeeds --

    /// A fetcher that fails the first N calls, then succeeds.
    struct CountingFailFetcher {
        block: Block,
        fail_count: AtomicU64,
        fail_until: u64,
        total_calls: AtomicU64,
    }

    impl CountingFailFetcher {
        fn new(block: Block, fail_until: u64) -> Self {
            Self {
                block,
                fail_count: AtomicU64::new(0),
                fail_until,
                total_calls: AtomicU64::new(0),
            }
        }

        fn total_calls(&self) -> u64 {
            self.total_calls.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for CountingFailFetcher {
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            let call_num = self.total_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_num <= self.fail_until {
                self.fail_count.fetch_add(1, Ordering::SeqCst);
                Err(FetchError::NetworkError(format!(
                    "transient error on attempt {call_num}"
                )))
            } else {
                Ok(FetchedBlockCert {
                    block: self.block.clone(),
                    cert: None,
                    raw_payset_blobs: None,
                })
            }
        }
    }

    #[test]
    fn retry_logic_retries_on_fetch_failure() {
        // The fetcher fails on the first call, succeeds on the second.
        // Verify that fetch is called multiple times.
        let block = make_valid_empty_block(1);
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        // Fail once, then succeed.
        let fetcher = Arc::new(CountingFailFetcher::new(block, 1));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Poll until the fetcher has been called at least twice
        // (1 failure + 1 success), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.total_calls() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "expected at least 2 fetch calls (1 fail + 1 success)",
        );

        svc.stop();
    }

    #[test]
    fn persistent_failure_retries_until_shutdown() {
        // The service now retries indefinitely on persistent failure,
        // mirroring Go's fetchRound. Verify that it keeps retrying
        // and stops cleanly on shutdown.
        let block = make_valid_empty_block(0); // won't be used since we always fail
        let fetcher = Arc::new(CountingFailFetcher::new(block, 999)); // always fail

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert(5)).unwrap();

        // Poll until the fetcher has been called at least twice
        // (verifies indefinite retry), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.total_calls() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should be called multiple times during indefinite retry",
        );

        // Shutdown should interrupt the retry loop cleanly.
        svc.stop();
    }

    // -- ForkDetectionBlockFetcher: returns a block with mismatched digest + cert --

    /// A fetcher that returns a block whose digest does NOT match the
    /// agreement cert, but includes a fetched certificate that *does*
    /// claim to authenticate the block. This simulates a fork scenario.
    struct ForkDetectionBlockFetcher {
        block: Block,
        /// Certificate included in the fetch response (claims to auth
        /// the fetched block, not the agreement cert's block).
        fetched_cert: Certificate,
        fetch_count: AtomicU64,
    }

    impl ForkDetectionBlockFetcher {
        fn new(block: Block, fetched_cert: Certificate) -> Self {
            Self {
                block,
                fetched_cert,
                fetch_count: AtomicU64::new(0),
            }
        }

        fn fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for ForkDetectionBlockFetcher {
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedBlockCert {
                block: self.block.clone(),
                cert: Some(self.fetched_cert.clone()),
                raw_payset_blobs: None,
            })
        }
    }

    #[test]
    fn fork_detection_fires_on_digest_mismatch_with_cert() {
        // Simulate a fork: the agreement cert expects digest A, but the
        // fetcher returns a block with digest B and a fetched cert that
        // also claims digest B. The fork detection code should execute
        // without panicking, log the alarm, and continue retrying.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };
        let block_digest = algo_codec::compute_block_digest(&block);

        // The agreement cert has a *different* digest (not matching the block).
        let agreement_digest = algo_types::Digest([0xff; 32]);
        assert_ne!(
            block_digest, agreement_digest,
            "test setup: digests must differ to trigger fork detection"
        );

        // The fetched cert claims to authenticate the fetched block.
        let fetched_cert = make_cert_with_digest(1, block_digest);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(ForkDetectionBlockFetcher::new(block, fetched_cert));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with the "wrong" (agreement) digest.
        tx.send(make_pending_cert_with_digest(1, agreement_digest))
            .unwrap();

        // Poll until the fork counter itself has been incremented, rather
        // than polling on `fetch_count` (incremented at the *start* of
        // `fetch_block`, well before the digest comparison and fork_count
        // increment later in the service's retry loop) and then
        // immediately asserting on `fork_count`. Polling on fetch_count
        // races the very increment the assertion below depends on: under
        // scheduling contention (e.g. full-workspace parallel test runs)
        // poll_until can observe fetch_count >= 1 and return before the
        // service has gotten around to incrementing fork_count, causing
        // the assertion to fail spuriously (see issue #905).
        poll_until(
            || svc.fork_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fork_count should have been incremented after digest mismatch with cert",
        );

        // Verify that the fork counter was incremented.
        assert!(
            svc.fork_count() >= 1,
            "fork_count should be >= 1 after fork detection, got {}",
            svc.fork_count()
        );

        // The service should still be alive (fork detection logs but
        // does not panic or halt, matching Go's behavior).
        svc.stop();
    }

    #[test]
    fn no_fork_detection_without_fetched_cert() {
        // When the fetcher returns a block with wrong digest but no
        // certificate, the fork detection path should NOT fire (no cert
        // to compare). The service should retry normally.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };

        let wrong_digest = algo_types::Digest([0xff; 32]);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        // DigestMatchingBlockFetcher returns cert: None.
        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert_with_digest(1, wrong_digest))
            .unwrap();

        // Poll until the fetcher has retried at least twice (digest
        // mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on digest mismatch",
        );

        svc.stop();
    }

    #[test]
    fn no_fork_when_fetched_cert_matches_agreement() {
        // When the fetched cert has the SAME digest as the agreement
        // cert (but the block has a different digest), this is NOT a
        // fork — just a bad block from a peer. Fork detection should
        // not fire.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };

        let agreement_digest = algo_types::Digest([0xaa; 32]);

        // The fetched cert has the SAME digest as agreement (not the block's).
        let fetched_cert = make_cert_with_digest(1, agreement_digest);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(ForkDetectionBlockFetcher::new(block, fetched_cert));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert_with_digest(1, agreement_digest))
            .unwrap();

        // Poll until the fetcher has been called at least once. It will
        // retry because the block digest won't match agreement_digest,
        // but no fork alarm should fire.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should have been called at least once",
        );

        svc.stop();
    }

    // -- ConcurrencyTrackingFetcher: records how many fetches overlap --

    /// Serves rounds `1..=up_to`, sleeping `delay` inside each fetch and
    /// recording the maximum number of concurrently in-flight calls it
    /// observed. Used to pin down issue #753's real behavioral gap: the
    /// periodic catchup path fetched blocks strictly serially, with no
    /// worker pool honoring go's `CatchupParallelBlocks`
    /// (`config/localTemplate.go:310-313`). A correct parallel
    /// implementation must show `max_concurrent() > 1` when given a
    /// `parallel_blocks` budget greater than 1; the old serial
    /// implementation could never exceed 1 no matter how large that
    /// budget was, which is exactly what this test pins down.
    struct ConcurrencyTrackingFetcher {
        up_to: u64,
        delay: Duration,
        current: AtomicU64,
        max_concurrent: AtomicU64,
        calls: AtomicU64,
    }

    impl ConcurrencyTrackingFetcher {
        fn new(up_to: u64, delay: Duration) -> Self {
            Self {
                up_to,
                delay,
                current: AtomicU64::new(0),
                max_concurrent: AtomicU64::new(0),
                calls: AtomicU64::new(0),
            }
        }

        fn max_concurrent(&self) -> u64 {
            self.max_concurrent.load(Ordering::SeqCst)
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for ConcurrencyTrackingFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if round.0 > self.up_to {
                return Err(FetchError::NoBlockForRound { round });
            }
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_concurrent.fetch_max(now, Ordering::SeqCst);
            thread::sleep(self.delay);
            self.current.fetch_sub(1, Ordering::SeqCst);

            let block = make_valid_empty_block(round.0);
            Ok(FetchedBlockCert {
                block,
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// Regression test for issue #753: the periodic catchup path
    /// (`sync_pass`) must fetch up to `parallel_blocks` blocks concurrently,
    /// not one at a time. Before the fix, `sync_pass` had no worker pool at
    /// all, so `max_concurrent()` could never rise above 1 regardless of
    /// how many blocks were pending — this test fails against that old
    /// implementation and passes once a real concurrency budget is honored.
    #[test]
    fn periodic_sync_fetches_blocks_in_parallel() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(ConcurrencyTrackingFetcher::new(
            20,
            Duration::from_millis(50),
        ));
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();

        let mut svc = CatchupService::start_with_parallelism(rx, ledger_dyn, fetcher_dyn, 8);

        poll_until(
            || ledger.next_round() == Round(21),
            Duration::from_millis(20),
            Duration::from_secs(10),
            "periodic sync should have pulled rounds 1..=20",
        );

        assert!(
            fetcher.max_concurrent() > 1,
            "expected multiple blocks to be fetched concurrently (parallel_blocks=8), \
             but max observed concurrency was {} out of {} total calls",
            fetcher.max_concurrent(),
            fetcher.calls()
        );

        svc.stop();
    }

    /// With `parallel_blocks` clamped to 1, the behavior must match the old
    /// strictly-serial path: never more than one fetch in flight.
    #[test]
    fn periodic_sync_with_parallelism_one_stays_serial() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(ConcurrencyTrackingFetcher::new(
            6,
            Duration::from_millis(20),
        ));
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();

        let mut svc = CatchupService::start_with_parallelism(rx, ledger_dyn, fetcher_dyn, 1);

        poll_until(
            || ledger.next_round() == Round(7),
            Duration::from_millis(20),
            Duration::from_secs(10),
            "periodic sync should have pulled rounds 1..=6",
        );

        assert_eq!(
            fetcher.max_concurrent(),
            1,
            "parallel_blocks=1 must behave serially"
        );

        svc.stop();
    }

    // -- Protocol-switch interruption during catchup (issue #976) --
    //
    // Ports of go's `TestOnSwitchToUnSupportedProtocol1-4`
    // (`catchup/service_test.go`), which exercise `roundIsNotSupported`'s
    // effect on the periodic sync loop at four different interruption
    // timings. `round_is_not_supported`/its use in `sync_pass_inner` and
    // `sync_cert` were already implemented (mirroring go's guard at the top
    // of `fetchRound`), but no test previously exercised any of these
    // timings — these are direct, synchronous calls into `sync_pass_inner`
    // (rather than the background-thread `CatchupService::start`) so the
    // outcome can be asserted deterministically with no polling/timing
    // races, mirroring how go's tests inspect `local.LastRound()`
    // synchronously after `syncer.sync()` returns.

    /// A permissive ledger (authenticates every certificate, like
    /// [`PermissiveCatchupLedger`]) whose [`CatchupLedger::round_is_not_supported`]
    /// becomes `true` once `round.0 >= switch_round` — mirroring go's
    /// `roundIsNotSupported` once a pending upgrade's `NextProtocolSwitchOn`
    /// has been set to `switch_round`.
    struct SwitchingCatchupLedger {
        inner: MockCatchupLedger,
        switch_round: u64,
    }

    impl CatchupLedger for SwitchingCatchupLedger {
        fn next_round(&self) -> Round {
            self.inner.next_round()
        }
        fn ensure_block(&self, block: &Block, cert: &Certificate) {
            self.inner.ensure_block(block, cert)
        }
        fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
            Ok(())
        }
        fn round_is_not_supported(&self, round: Round) -> bool {
            round.0 >= self.switch_round
        }
    }

    /// A shutdown receiver that never fires, for direct `sync_pass_inner`
    /// calls that don't need to exercise shutdown handling.
    fn never_shutdown() -> Receiver<()> {
        crossbeam_channel::bounded::<()>(0).1
    }

    /// A ledger that reports [`CatchupLedger::is_behind_committing_deltas`]
    /// once the last committed round reaches `behind_after_round`, so tests
    /// can simulate go's `mockedLedger.behindDeltas` commit-backpressure
    /// signal (`TestServiceLedgerUnavailable`).
    struct BehindDeltasAfterCatchupLedger {
        inner: MockCatchupLedger,
        behind_after_round: u64,
    }

    impl CatchupLedger for BehindDeltasAfterCatchupLedger {
        fn next_round(&self) -> Round {
            self.inner.next_round()
        }
        fn ensure_block(&self, block: &Block, cert: &Certificate) {
            self.inner.ensure_block(block, cert)
        }
        fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
            Ok(())
        }
        fn is_behind_committing_deltas(&self) -> bool {
            self.inner.next_round().0.saturating_sub(1) >= self.behind_after_round
        }
    }

    /// Port of go's `TestOnSwitchToUnSupportedProtocol1`: the interruption
    /// happens on the very first round of the pass ("This cannot happen in
    /// practice, but is used to test the code" — go's own comment). No
    /// block should ever be committed.
    #[test]
    fn sync_pass_interrupted_in_initial_loop() {
        let ledger = Arc::new(SwitchingCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
            switch_round: 1,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 10,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);

        assert_eq!(
            ledger.next_round(),
            Round(1),
            "round 1 is already unsupported, so the ledger must not advance at all"
        );
    }

    /// Port of go's `TestOnSwitchToUnSupportedProtocol2`: the interruption
    /// happens partway through a pass, after several rounds have already
    /// been fetched and committed. Sync must stop exactly at the last
    /// supported round.
    #[test]
    fn sync_pass_interrupted_mid_loop() {
        let ledger = Arc::new(SwitchingCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
            switch_round: 8,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 20,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);

        assert_eq!(
            ledger.next_round(),
            Round(8),
            "rounds 1..=7 are supported and should be committed; round 8 is not"
        );
    }

    /// Port of go's `TestOnSwitchToUnSupportedProtocol3`: interruption with
    /// short notice — the switch boundary is reached with fewer rounds of
    /// warning than the fetch-ahead window (`fetch_window(parallel_blocks)`), so a worker
    /// may already be mid-fetch on the unsupported round when the boundary
    /// is discovered. go's assertion is `< lastRoundLocal+2` (i.e. the extra
    /// prefetched round is buffered but never *applied*) — the strict
    /// in-order apply loop in `sync_pass_inner` gives the same guarantee
    /// here: applying stops exactly at the boundary regardless of how many
    /// rounds beyond it were concurrently prefetched.
    #[test]
    fn sync_pass_interrupted_with_short_notice() {
        let ledger = Arc::new(SwitchingCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
            switch_round: 2,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 20,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        // parallel_blocks=2 (a window of 4): workers may prefetch round 2 (unsupported)
        // concurrently with round 1 (supported), but the boundary must
        // still be honored exactly — no partial/out-of-order commit.
        CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);

        assert_eq!(
            ledger.next_round(),
            Round(2),
            "only round 1 is supported; round 2 must never be applied even if prefetched"
        );
    }

    /// Port of go's `TestOnSwitchToUnSupportedProtocol4`: a variation of the
    /// short-notice case that happens when the catchup service restarts
    /// exactly at the switch round (e.g. after a crash/restart at the
    /// boundary) — the ledger already holds every supported round, so a
    /// fresh pass must decline to fetch anything at all, not just stop
    /// after an extra prefetch.
    #[test]
    fn sync_pass_interrupted_restart_at_switch_round() {
        let ledger = Arc::new(SwitchingCatchupLedger {
            inner: MockCatchupLedger::new(Round(7)),
            switch_round: 8,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 20,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);

        assert_eq!(
            ledger.next_round(),
            Round(8),
            "the ledger already sits at the switch boundary on restart; a fresh pass must \
             not advance past it"
        );
    }

    /// The same guard, exercised through `sync_cert` (the certificate-driven
    /// path) rather than `sync_pass_inner` (the periodic path) — go's
    /// `fetchRound` applies the identical `roundIsNotSupported` check before
    /// any network fetch is attempted, and this pins that algod-rust never
    /// even calls the fetcher for an unsupported round's certificate.
    #[test]
    fn sync_cert_bails_out_for_unsupported_round() {
        let ledger = Arc::new(SwitchingCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
            switch_round: 1,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(BoundedBlockFetcher {
            up_to: 20,
            calls: AtomicU64::new(0),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let shutdown_rx = never_shutdown();
        let fork_count = Arc::new(AtomicU64::new(0));

        CatchupService::sync_cert(
            &make_pending_cert(1),
            &ledger_dyn,
            &fetcher_dyn,
            &shutdown_rx,
            &fork_count,
        );

        assert_eq!(
            ledger.next_round(),
            Round(1),
            "certificate for an unsupported round must not be committed"
        );
        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            0,
            "the guard must bail out before ever calling the fetcher"
        );
    }

    #[test]
    fn contents_mismatch_triggers_retry() {
        // Create a block with a valid digest but tampered txn_commitment.
        // The digest check passes but contents_match_header should fail,
        // triggering retries.
        let mut block = make_valid_empty_block(1);
        // Tamper the txn_commitment so contents_match_header returns Ok(false).
        block.txn_commitment = [0xFF; 32];
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with the correct digest (header matches) but the block
        // body won't match the header commitments.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // The fetcher should have been called multiple times since
        // contents_match_header fails and triggers retries.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on contents mismatch",
        );

        svc.stop();
    }

    // -- synchronizing_time (issue #917, TestSynchronizingTime port) --

    /// Direct port of go's `TestSynchronizingTime`
    /// (`catchup/service_test.go`): before any sync pass has run,
    /// `synchronizing_time()` must be zero, and once a pass is in flight it
    /// must report nonzero elapsed time.
    ///
    /// Unlike go's test — which pokes `syncStartNS` directly since it lives
    /// in the same package — this drives the real state transition through
    /// a slow fetcher so `sync_pass`'s own start/reset logic is exercised,
    /// not just the getter.
    #[test]
    fn synchronizing_time_is_zero_before_any_sync_and_nonzero_during_one() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        // A fetcher slow enough that the startup sync_pass is still running
        // well after the service has spawned, giving the test a reliable
        // window to observe a nonzero synchronizing_time().
        let fetcher = Arc::new(ConcurrencyTrackingFetcher::new(
            3,
            Duration::from_millis(200),
        ));
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();

        let mut svc = CatchupService::start_with_parallelism(rx, ledger_dyn, fetcher_dyn, 1);

        poll_until(
            || svc.synchronizing_time() > Duration::ZERO,
            Duration::from_millis(5),
            Duration::from_secs(5),
            "synchronizing_time() should become nonzero once the startup sync pass begins",
        );

        poll_until(
            || ledger.next_round() == Round(4),
            Duration::from_millis(20),
            Duration::from_secs(10),
            "periodic sync should have pulled rounds 1..=3",
        );

        // Mirrors go's `SynchronizingTime()` doc: 0 once no sync is active.
        poll_until(
            || svc.synchronizing_time() == Duration::ZERO,
            Duration::from_millis(5),
            Duration::from_secs(5),
            "synchronizing_time() should reset to zero once the sync pass completes",
        );

        svc.stop();
    }

    /// A freshly constructed service that never gets a chance to run its
    /// startup pass (immediately stopped) still reports zero — mirrors go's
    /// initial `require.Equal(t, time.Duration(0), s.SynchronizingTime())`
    /// assertion against a service that has not yet called `sync()`.
    #[test]
    fn synchronizing_time_is_zero_immediately_after_stop() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, fetcher);
        svc.stop();

        assert_eq!(svc.synchronizing_time(), Duration::ZERO);
    }

    // -- Issue #1504 batch 3: closing the remaining catchup parity rows --

    /// Row 1: port of go's `TestServiceFetchBlocksSameRange`
    /// (`catchup/service_test.go`). `CatchupService::sync_range` is a
    /// directly-callable, certificate-less, arbitrary-range entry point —
    /// mirroring go's `Service.sync()` — reachable with no running worker
    /// thread at all, proving the range-sync logic is its own callable unit
    /// and not only ever reachable implicitly off the periodic timer.
    #[test]
    fn sync_range_static_entry_point_fetches_arbitrary_range() {
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 10,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        let exit = CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 4);

        assert_eq!(
            ledger.next_round(),
            Round(11),
            "local ledger must catch up to remote's last round (10) with no certificate involved"
        );
        assert_eq!(
            exit,
            SyncExitReason::NoBlock,
            "the pass should stop because the peer has nothing past round 10"
        );
    }

    /// Issue #2165: go's `pipelinedFetch` is ONE continuous pipeline that
    /// runs until a fetch fails at the network tip. algod-rust used to stop a
    /// pass after 256 blocks and then idle two `PERIODIC_SYNC_INTERVAL`s (the
    /// "no advance yet" hysteresis) before the next pass, capping a long
    /// replay at about 256 blocks per 12 s regardless of fetch speed (22
    /// blocks/s live against go's 133). One call must now carry the ledger
    /// all the way to the tip.
    #[test]
    fn sync_range_pipelines_past_the_old_256_block_pass_limit() {
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 700,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        let exit = CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 8);

        assert_eq!(
            ledger.next_round(),
            Round(701),
            "one pass must keep going until the peer has nothing more"
        );
        assert_eq!(exit, SyncExitReason::NoBlock);
    }

    /// Records, at the start of each fetch, how far ahead of the ledger's
    /// apply cursor the requested round is, and how many fetches run at once.
    struct AheadTrackingFetcher {
        ledger: Arc<PermissiveCatchupLedger>,
        up_to: u64,
        max_ahead: AtomicU64,
        inflight: AtomicU64,
        max_inflight: AtomicU64,
    }

    impl BlockFetcher for AheadTrackingFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            if round.0 > self.up_to {
                return Err(FetchError::NoBlockForRound { round });
            }
            let ahead = round.0.saturating_sub(self.ledger.next_round().0);
            self.max_ahead.fetch_max(ahead, Ordering::SeqCst);
            let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_inflight.fetch_max(now, Ordering::SeqCst);
            // A little latency so the workers really do run ahead.
            thread::sleep(Duration::from_millis(1));
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            Ok(FetchedBlockCert {
                block: make_valid_empty_block(round.0),
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// The pipeline is a sliding window: at most `parallel_blocks` fetches
    /// run at once and a round is never claimed `fetch_window(parallel_blocks)`
    /// or more rounds beyond the apply cursor, however long the pass runs.
    #[test]
    fn sync_range_fetch_window_never_exceeds_the_parallel_budget() {
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(AheadTrackingFetcher {
            ledger: Arc::clone(&ledger),
            up_to: 600,
            max_ahead: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            max_inflight: AtomicU64::new(0),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let shutdown_rx = never_shutdown();

        let exit = CatchupService::sync_range(&ledger_dyn, &fetcher_dyn, &shutdown_rx, 8);

        assert_eq!(ledger.next_round(), Round(601));
        assert_eq!(exit, SyncExitReason::NoBlock);
        let window = CatchupService::fetch_window(8);
        assert_eq!(window, 16);
        let ahead = fetcher.max_ahead.load(Ordering::SeqCst);
        // `ahead` is measured against the cursor at the start of the fetch, so
        // it is below the window by construction of the permits.
        assert!(
            ahead < window,
            "a fetch ran {ahead} rounds ahead of the apply cursor, window {window}"
        );
        assert!(ahead > 0, "the workers never ran ahead: not a pipeline");
        let concurrent = fetcher.max_inflight.load(Ordering::SeqCst);
        assert!(
            concurrent <= 8,
            "{concurrent} fetches ran at once with parallel_blocks=8"
        );
        assert!(concurrent > 1, "the fetches never overlapped: not parallel");
    }

    /// A single worker (`CatchupParallelBlocks: 1`, strictly serial catchup)
    /// keeps a window of one round: no prefetch; larger counts are capped by
    /// `FETCH_AHEAD_MAX_EXTRA` (issue #2204).
    #[test]
    fn the_fetch_window_is_exact_for_one_worker_and_capped_for_many() {
        assert_eq!(CatchupService::fetch_window(1), 1);
        assert_eq!(CatchupService::fetch_window(2), 4);
        assert_eq!(CatchupService::fetch_window(16), 32);
        assert_eq!(CatchupService::fetch_window(64), 96);
        assert_eq!(
            CatchupService::fetch_window(256),
            256 + CatchupService::FETCH_AHEAD_MAX_EXTRA
        );
    }

    /// Fetch-latency-bound catchup (issue #2204): one slow round must not
    /// idle the other workers, and the window is exactly
    /// `fetch_window(parallel_blocks)`. Round 1 is held; the workers behind
    /// it must claim rounds up to the window (8 of them for 4 workers) and not
    /// one more, and nothing is released by timing: the test waits on the
    /// fetchers' own notifications.
    #[test]
    fn a_slow_round_does_not_idle_the_other_workers() {
        use std::sync::{Condvar, Mutex};

        struct HoldFirstFetcher {
            started: Mutex<Vec<u64>>,
            started_cv: Condvar,
            released: Mutex<bool>,
            released_cv: Condvar,
            up_to: u64,
        }
        impl BlockFetcher for HoldFirstFetcher {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 > self.up_to {
                    return Err(FetchError::NoBlockForRound { round });
                }
                {
                    self.started.lock().unwrap().push(round.0);
                    self.started_cv.notify_all();
                }
                if round.0 == 1 {
                    let mut released = self.released.lock().unwrap();
                    while !*released {
                        let (guard, timeout) = self
                            .released_cv
                            .wait_timeout(released, Duration::from_secs(30))
                            .unwrap();
                        released = guard;
                        assert!(!timeout.timed_out(), "round 1 was never released");
                    }
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }

        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(HoldFirstFetcher {
            started: Mutex::new(Vec::new()),
            started_cv: Condvar::new(),
            released: Mutex::new(false),
            released_cv: Condvar::new(),
            up_to: 40,
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            no_block_backoff: Duration::from_millis(1),
            retry_backoff: Duration::from_millis(1),
            ..FetchPolicy::default()
        };
        let window = CatchupService::fetch_window(4) as usize;
        assert_eq!(window, 8);
        let pass = {
            let ledger_dyn = ledger_dyn.clone();
            thread::spawn(move || sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 4, policy))
        };

        // Wait (by notification) until the window is claimed.
        {
            let mut started = fetcher.started.lock().unwrap();
            while started.len() < window {
                let (guard, timeout) = fetcher
                    .started_cv
                    .wait_timeout(started, Duration::from_secs(30))
                    .unwrap();
                started = guard;
                assert!(
                    !timeout.timed_out(),
                    "only {} rounds started while round 1 was held: the workers idled behind \
                     the slow round",
                    started.len()
                );
            }
        }
        // Not one round beyond the window may be claimed meanwhile (a negative
        // observation: it can only miss a violation, never invent one).
        thread::sleep(Duration::from_millis(200));
        {
            let mut started = fetcher.started.lock().unwrap().clone();
            started.sort_unstable();
            assert_eq!(
                started,
                (1..=window as u64).collect::<Vec<_>>(),
                "exactly rounds 1..={window} are claimed while round 1 is held"
            );
        }
        *fetcher.released.lock().unwrap() = true;
        fetcher.released_cv.notify_all();
        let exit = pass.join().unwrap();
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(41));
    }

    /// The tip gate claims atomically (issue #2204): with the gate set, however
    /// many workers race, exactly the rounds below the limit are claimed.
    #[test]
    fn the_tip_gate_claims_exactly_up_to_the_limit_however_many_workers_race() {
        // Single-threaded: exact.
        let next = AtomicU64::new(10);
        let claimed: Vec<_> = std::iter::from_fn(|| claim_round(&next, Some(14)))
            .take(20)
            .collect();
        assert_eq!(claimed, vec![10, 11, 12, 13]);
        assert_eq!(claim_round(&next, Some(14)), None);
        assert_eq!(
            next.load(Ordering::SeqCst),
            14,
            "a refused claim moves nothing"
        );
        // No gate: always claims.
        assert_eq!(claim_round(&next, None), Some(14));

        // Raced by many threads: exactly `limit - start` claims succeed, each
        // round once.
        let next = Arc::new(AtomicU64::new(100));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let next = Arc::clone(&next);
            handles.push(thread::spawn(move || {
                let mut mine = Vec::new();
                for _ in 0..50 {
                    if let Some(r) = claim_round(&next, Some(108)) {
                        mine.push(r);
                    }
                }
                mine
            }));
        }
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        assert_eq!(all, (100..108).collect::<Vec<_>>());
    }

    /// Fetcher for the tip-gate bound: nothing exists. The first attempt of
    /// round 1 is held until all `want` workers have started a fetch, so every
    /// worker has made its first (ungated) claim before round 1 reports the
    /// tip; the other rounds report it at once.
    struct TipHoldFetcher {
        calls: std::sync::Mutex<u64>,
        calls_cv: std::sync::Condvar,
        want: u64,
        max_round: AtomicU64,
        round1_held: AtomicBool,
    }

    impl BlockFetcher for TipHoldFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.max_round.fetch_max(round.0, Ordering::SeqCst);
            {
                let mut calls = self.calls.lock().unwrap();
                *calls += 1;
                self.calls_cv.notify_all();
            }
            if round.0 == 1 && !self.round1_held.swap(true, Ordering::SeqCst) {
                let mut calls = self.calls.lock().unwrap();
                while *calls < self.want {
                    let (g, t) = self
                        .calls_cv
                        .wait_timeout(calls, Duration::from_secs(30))
                        .unwrap();
                    calls = g;
                    assert!(!t.timed_out(), "the other workers never started");
                }
            }
            Err(FetchError::NoBlockForRound { round })
        }
    }

    /// Exact bound at the tip (issue #2204): nothing is available, so the
    /// cursor stays at round 1. All 8 workers make their first claim (round 1
    /// is held until they have), so rounds 1..=8 are requested; every later
    /// claim is bounded by `cursor + workers` = 9, so the highest round ever
    /// requested is exactly 8. Without the gate the workers keep claiming up
    /// to the window and reach 16 (the mutation check).
    #[test]
    fn past_the_tip_no_round_beyond_the_cursor_plus_the_workers_is_requested() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(TipHoldFetcher {
            calls: std::sync::Mutex::new(0),
            calls_cv: std::sync::Condvar::new(),
            want: 8,
            max_round: AtomicU64::new(0),
            round1_held: AtomicBool::new(false),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            no_block_backoff: Duration::from_millis(50),
            ..FetchPolicy::default()
        };
        let exit = finishes_within(Duration::from_secs(60), move || {
            sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 8, policy)
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(1));
        assert_eq!(
            fetcher.max_round.load(Ordering::SeqCst),
            8,
            "rounds 1..=8 are claimed first, and the gate allows nothing beyond cursor (1) + 8 - 1"
        );
    }

    /// The "no fetch worker" warning is rate limited (issue #2204 review): the
    /// first is due, the following ones inside the interval are not, one after
    /// it is.
    #[test]
    fn the_no_worker_warning_is_rate_limited() {
        let t0 = std::time::Instant::now();
        let mut last = None;
        let interval = Duration::from_secs(30);
        assert!(CatchupService::warning_due(&mut last, t0, interval));
        assert!(!CatchupService::warning_due(
            &mut last,
            t0 + Duration::from_secs(4),
            interval
        ));
        assert!(!CatchupService::warning_due(
            &mut last,
            t0 + Duration::from_secs(29),
            interval
        ));
        assert!(CatchupService::warning_due(
            &mut last,
            t0 + Duration::from_secs(31),
            interval
        ));
    }

    /// One transient "no block" answer mid-catchup that a later attempt
    /// resolves must not shrink the window (issue #2204): the gate only
    /// engages once a round's fetch has finally failed.
    #[test]
    fn a_transient_no_block_answer_does_not_engage_the_tip_gate() {
        use std::sync::{Condvar, Mutex};

        struct TransientFetcher {
            started: Mutex<Vec<u64>>,
            started_cv: Condvar,
            released: Mutex<bool>,
            released_cv: Condvar,
            missed_once: AtomicBool,
        }
        impl BlockFetcher for TransientFetcher {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 > 40 {
                    return Err(FetchError::NoBlockForRound { round });
                }
                // Round 3 misses once, then is there.
                if round.0 == 3 && !self.missed_once.swap(true, Ordering::SeqCst) {
                    return Err(FetchError::NoBlockForRound { round });
                }
                {
                    self.started.lock().unwrap().push(round.0);
                    self.started_cv.notify_all();
                }
                if round.0 == 1 {
                    let mut released = self.released.lock().unwrap();
                    while !*released {
                        let (g, t) = self
                            .released_cv
                            .wait_timeout(released, Duration::from_secs(30))
                            .unwrap();
                        released = g;
                        assert!(!t.timed_out(), "round 1 was never released");
                    }
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }

        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(TransientFetcher {
            started: Mutex::new(Vec::new()),
            started_cv: Condvar::new(),
            released: Mutex::new(false),
            released_cv: Condvar::new(),
            missed_once: AtomicBool::new(false),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            no_block_backoff: Duration::from_millis(1),
            ..FetchPolicy::default()
        };
        let window = CatchupService::fetch_window(4) as usize;
        let pass = {
            let ledger_dyn = ledger_dyn.clone();
            thread::spawn(move || sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 4, policy))
        };
        // All `window` rounds start (round 3 after its retry) while round 1 is
        // held: the miss did not engage the gate, whose bound is 4 rounds.
        {
            let mut started = fetcher.started.lock().unwrap();
            while started.len() < window {
                let (g, t) = fetcher
                    .started_cv
                    .wait_timeout(started, Duration::from_secs(30))
                    .unwrap();
                started = g;
                assert!(
                    !t.timed_out(),
                    "only {} rounds started: a transient miss shrank the window",
                    started.len()
                );
            }
        }
        *fetcher.released.lock().unwrap() = true;
        fetcher.released_cv.notify_all();
        assert_eq!(pass.join().unwrap(), SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(41));
    }

    /// A spawner that starts `n` real workers and then fails like an
    /// exhausted OS thread budget (`EAGAIN`): the real `Err` arm of the spawn.
    fn spawner_failing_after(n: usize) -> WorkerSpawner {
        let started = Arc::new(AtomicU64::new(0));
        WorkerSpawner(Arc::new(move |builder, body| {
            if started.fetch_add(1, Ordering::SeqCst) as usize >= n {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            builder.spawn(body)
        }))
    }

    /// No fetch worker can be started (issue #1650): the pass ends as a
    /// retryable `NoBlock`, it does not report `Done` for a pass that fetched
    /// nothing; with one worker out of four it still works, and its tip gate
    /// and window follow the one worker that started.
    #[test]
    fn a_pass_without_a_worker_is_a_retryable_failure_not_done() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 12,
            calls: AtomicU64::new(0),
        });
        let none = FetchPolicy {
            spawner: spawner_failing_after(0),
            ..FetchPolicy::default()
        };
        let exit = sync_range_with_policy(&ledger_dyn, &fetcher, 4, none);
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(1), "nothing was fetched");

        let one = FetchPolicy {
            spawner: spawner_failing_after(1),
            no_block_backoff: Duration::from_millis(1),
            ..FetchPolicy::default()
        };
        let exit = sync_range_with_policy(&ledger_dyn, &fetcher, 4, one);
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(
            ledger.next_round(),
            Round(13),
            "one worker still catches up"
        );
    }

    /// Two rounds miss at once, the lower one (R) then succeeds (issue #2204):
    /// the higher one (R + 1) gives up immediately and ITS failed result ends
    /// the pass when the apply cursor reaches it, whatever R does, so engaging
    /// the tip gate on it costs nothing: R is applied, the pass ends `NoBlock`
    /// at R + 1 and does not hang. (The claims before the early give-up are
    /// the whole window; the gate then holds new claims at `cursor + workers`.)
    #[test]
    fn two_missed_rounds_with_the_lower_one_succeeding_end_the_pass_at_the_higher_one() {
        use std::sync::{Condvar, Mutex};

        struct TwoMissFetcher {
            started: Mutex<Vec<u64>>,
            started_cv: Condvar,
            released: Mutex<bool>,
            released_cv: Condvar,
            miss3: AtomicBool,
            miss4: AtomicBool,
            three_missed: Mutex<bool>,
            three_missed_cv: Condvar,
        }
        impl BlockFetcher for TwoMissFetcher {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 > 40 {
                    return Err(FetchError::NoBlockForRound { round });
                }
                if round.0 == 3 && !self.miss3.swap(true, Ordering::SeqCst) {
                    *self.three_missed.lock().unwrap() = true;
                    self.three_missed_cv.notify_all();
                    return Err(FetchError::NoBlockForRound { round });
                }
                if round.0 == 4 && !self.miss4.swap(true, Ordering::SeqCst) {
                    // Miss only after round 3 has missed, so 3 is probing.
                    let mut missed = self.three_missed.lock().unwrap();
                    while !*missed {
                        missed = self.three_missed_cv.wait(missed).unwrap();
                    }
                    return Err(FetchError::NoBlockForRound { round });
                }
                {
                    self.started.lock().unwrap().push(round.0);
                    self.started_cv.notify_all();
                }
                if round.0 == 1 {
                    let mut released = self.released.lock().unwrap();
                    while !*released {
                        let (g, t) = self
                            .released_cv
                            .wait_timeout(released, Duration::from_secs(30))
                            .unwrap();
                        released = g;
                        assert!(!t.timed_out(), "round 1 was never released");
                    }
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }

        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(TwoMissFetcher {
            started: Mutex::new(Vec::new()),
            started_cv: Condvar::new(),
            released: Mutex::new(false),
            released_cv: Condvar::new(),
            miss3: AtomicBool::new(false),
            miss4: AtomicBool::new(false),
            three_missed: Mutex::new(false),
            three_missed_cv: Condvar::new(),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            no_block_backoff: Duration::from_millis(1),
            ..FetchPolicy::default()
        };
        let pass = {
            let ledger_dyn = ledger_dyn.clone();
            thread::spawn(move || sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 4, policy))
        };
        // Wait until rounds 1 and 2 have started, then release round 1.
        {
            let mut started = fetcher.started.lock().unwrap();
            while started.len() < 2 {
                let (g, t) = fetcher
                    .started_cv
                    .wait_timeout(started, Duration::from_secs(30))
                    .unwrap();
                started = g;
                assert!(!t.timed_out(), "rounds 1 and 2 never started");
            }
        }
        *fetcher.released.lock().unwrap() = true;
        fetcher.released_cv.notify_all();
        assert_eq!(pass.join().unwrap(), SyncExitReason::NoBlock);
        // Rounds 1..=3 applied; round 4 (gave up) ends the pass.
        assert_eq!(ledger.next_round(), Round(4));
    }

    // -- Issue #2165 review: liveness of the unbounded pass --

    /// Run `f` on its own thread and fail (instead of hanging the test run)
    /// when it does not finish within `limit`.
    fn finishes_within<T: Send + 'static>(
        limit: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = crossbeam_channel::bounded(1);
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit)
            .expect("timed out: the operation hung")
    }

    fn permissive_ledger() -> (Arc<PermissiveCatchupLedger>, Arc<dyn CatchupLedger>) {
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let dynamic: Arc<dyn CatchupLedger> = ledger.clone();
        (ledger, dynamic)
    }

    /// Serves any round after `delay`, but nothing while `closed` is set.
    struct GatedFetcher {
        open: Arc<AtomicBool>,
        delay: Duration,
    }

    impl BlockFetcher for GatedFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            if !self.open.load(Ordering::SeqCst) {
                return Err(FetchError::NoBlockForRound { round });
            }
            thread::sleep(self.delay);
            Ok(FetchedBlockCert {
                block: make_valid_empty_block(round.0),
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// A stop request must never be lost to a pass that consumed it: with a
    /// pass that runs for the whole replay, `stop()` during the initial
    /// periodic pass must return (its join must complete).
    #[test]
    fn stop_during_a_long_periodic_pass_returns_promptly() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(ConcurrencyTrackingFetcher::new(
            u64::MAX,
            Duration::from_millis(10),
        ));
        let mut svc = CatchupService::start_with_parallelism(rx, ledger_dyn, fetcher, 8);
        poll_until(
            || ledger.next_round().0 > 20,
            Duration::from_millis(10),
            Duration::from_secs(10),
            "the pass should be well under way",
        );
        finishes_within(Duration::from_secs(10), move || svc.stop());
    }

    /// Same for the pass a `sync_now` request starts (the second `run_loop`
    /// call site): the loop exits on `Stopping`, and the waiting caller is
    /// answered with it.
    #[test]
    fn stop_during_a_sync_now_pass_returns_promptly() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let open = Arc::new(AtomicBool::new(false));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(GatedFetcher {
            open: Arc::clone(&open),
            delay: Duration::from_millis(10),
        });
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let (trigger_tx, trigger_rx) = crossbeam_channel::unbounded::<SyncWaiter>();
        let syncing = Arc::new(AtomicI64::new(0));
        let handle = thread::spawn(move || {
            CatchupService::run_loop(shutdown_rx, trigger_rx, ledger_dyn, fetcher, syncing, 8)
        });
        // The startup pass finds nothing and ends; then open the peer and
        // ask for a sync.
        thread::sleep(Duration::from_millis(500));
        open.store(true, Ordering::SeqCst);
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        trigger_tx.send(reply_tx).unwrap();
        poll_until(
            || ledger.next_round().0 > 20,
            Duration::from_millis(10),
            Duration::from_secs(10),
            "the sync_now pass should be well under way",
        );
        shutdown_tx.send(()).unwrap();
        finishes_within(Duration::from_secs(10), move || handle.join().unwrap());
        assert_eq!(
            reply_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            SyncExitReason::Stopping
        );
    }

    /// And for the certificate-driven thread: a stop that `sync_cert`
    /// consumes while retrying must end `cert_loop`.
    #[test]
    fn stop_during_a_cert_driven_fetch_returns_promptly() {
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let (_ledger, ledger_dyn) = permissive_ledger();
        // No peer ever has the block: sync_cert keeps retrying.
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));
        let mut svc = CatchupService::start_with_parallelism(rx, ledger_dyn, fetcher, 2);
        tx.send(make_pending_cert(50)).unwrap();
        thread::sleep(Duration::from_millis(700));
        finishes_within(Duration::from_secs(15), move || svc.stop());
    }

    /// A transient fetch failure of one round is retried in the pass (go's
    /// `fetchAndWrite` loop) instead of ending the pass and idling for
    /// several seconds.
    #[test]
    fn a_transient_fetch_error_is_retried_without_ending_the_pass() {
        struct FlakyFetcher {
            failures_left: AtomicU64,
            calls_for_5: AtomicU64,
        }
        impl BlockFetcher for FlakyFetcher {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 > 20 {
                    return Err(FetchError::NoBlockForRound { round });
                }
                if round.0 == 5 {
                    self.calls_for_5.fetch_add(1, Ordering::SeqCst);
                    // Round 5 has one fetcher call at a time (window order),
                    // so a plain check-then-decrement is race-free here.
                    let left = self.failures_left.load(Ordering::SeqCst);
                    if left > 0 {
                        self.failures_left.store(left - 1, Ordering::SeqCst);
                        return Err(FetchError::NetworkError("transient".into()));
                    }
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }
        let (ledger, ledger_dyn) = permissive_ledger();
        let flaky = Arc::new(FlakyFetcher {
            failures_left: AtomicU64::new(2),
            calls_for_5: AtomicU64::new(0),
        });
        let fetcher: Arc<dyn BlockFetcher> = flaky.clone();
        let shutdown_rx = never_shutdown();
        let exit = finishes_within(Duration::from_secs(20), move || {
            CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 4)
        });
        assert_eq!(
            exit,
            SyncExitReason::NoBlock,
            "ended at the tip, not at round 5"
        );
        assert_eq!(ledger.next_round(), Round(21));
        assert_eq!(flaky.calls_for_5.load(Ordering::SeqCst), 3);
    }

    /// A fetcher that panics must not strand the apply loop.
    #[test]
    fn a_panicking_fetch_worker_ends_the_pass_instead_of_hanging_it() {
        struct PanicAt(u64);
        impl BlockFetcher for PanicAt {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 == self.0 {
                    panic!("fetcher bug at round {}", round.0);
                }
                thread::sleep(Duration::from_millis(2));
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(PanicAt(12));
        let shutdown_rx = never_shutdown();
        let exit = finishes_within(Duration::from_secs(20), move || {
            CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 8)
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(
            ledger.next_round(),
            Round(12),
            "rounds before the panic applied"
        );
    }

    /// A permanent failure of one round with a full window of parked workers
    /// ends the pass.
    #[test]
    fn a_round_that_never_arrives_ends_the_pass_with_a_full_window() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(ConcurrencyTrackingFetcher::new(
            40,
            Duration::from_millis(3),
        ));
        let shutdown_rx = never_shutdown();
        let exit = finishes_within(Duration::from_secs(20), move || {
            CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 8)
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(41));
    }

    /// An invalid block mid-window (its certificate does not authenticate)
    /// ends the pass although workers are parked waiting for permits.
    #[test]
    fn an_invalid_block_mid_window_ends_the_pass() {
        struct RejectsRound {
            inner: PermissiveCatchupLedger,
            bad: u64,
        }
        impl CatchupLedger for RejectsRound {
            fn next_round(&self) -> Round {
                self.inner.next_round()
            }
            fn ensure_block(&self, block: &Block, cert: &Certificate) {
                self.inner.ensure_block(block, cert)
            }
            fn authenticate_block(&self, block: &Block, _cert: &Certificate) -> Result<(), String> {
                if block.round.0 == self.bad {
                    Err("bad certificate".into())
                } else {
                    Ok(())
                }
            }
        }
        let ledger = Arc::new(RejectsRound {
            inner: PermissiveCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
            },
            bad: 30,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(ConcurrencyTrackingFetcher::new(
            u64::MAX,
            Duration::from_millis(3),
        ));
        let shutdown_rx = never_shutdown();
        let exit = finishes_within(Duration::from_secs(20), move || {
            CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 8)
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(30));
    }

    /// A stop request during a pass with a full window ends it promptly.
    #[test]
    fn a_stop_request_mid_window_ends_sync_range_promptly() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(ConcurrencyTrackingFetcher::new(
            u64::MAX,
            Duration::from_millis(10),
        ));
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let handle = thread::spawn(move || {
            CatchupService::sync_range(&ledger_dyn, &fetcher, &shutdown_rx, 8)
        });
        poll_until(
            || ledger.next_round().0 > 20,
            Duration::from_millis(10),
            Duration::from_secs(10),
            "the pass should be under way",
        );
        shutdown_tx.send(()).unwrap();
        let exit = finishes_within(Duration::from_secs(10), move || handle.join().unwrap());
        assert_eq!(exit, SyncExitReason::Stopping);
    }

    /// Run a sync pass with an explicit retry policy.
    fn sync_range_with_policy(
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        parallel_blocks: u64,
        policy: FetchPolicy,
    ) -> SyncExitReason {
        let shutdown_rx = never_shutdown();
        CatchupService::sync_pass_core(
            ledger,
            fetcher,
            &shutdown_rx,
            parallel_blocks,
            None,
            &mut Vec::new(),
            policy,
        )
    }

    /// Serves rounds `1..=up_to`; `gate_round` blocks (once) until released.
    struct GateAtFetcher {
        up_to: u64,
        gate_round: u64,
        reached: crossbeam_channel::Sender<()>,
        release: Receiver<()>,
    }

    impl BlockFetcher for GateAtFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            if round.0 > self.up_to {
                return Err(FetchError::NoBlockForRound { round });
            }
            if round.0 == self.gate_round {
                let _ = self.reached.send(());
                let _ = self.release.recv();
            }
            Ok(FetchedBlockCert {
                block: make_valid_empty_block(round.0),
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// Deterministic: a `sync_now` that arrives while the pass is still
    /// applying blocks (the cursor is held at a gated round, no worker has
    /// seen the tip) is consumed by that pass and answered with its result.
    #[test]
    fn sync_now_during_a_progressing_pass_is_coalesced_deterministically() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let (reached_tx, reached_rx) = crossbeam_channel::unbounded();
        let (release_tx, release_rx) = crossbeam_channel::unbounded();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(GateAtFetcher {
            up_to: 60,
            gate_round: 30,
            reached: reached_tx,
            release: release_rx,
        });
        let (_shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let (trigger_tx, trigger_rx) = crossbeam_channel::unbounded::<SyncWaiter>();
        let syncing = Arc::new(AtomicI64::new(0));
        let pass = thread::spawn(move || {
            CatchupService::run_pass(
                &ledger_dyn,
                &fetcher,
                &shutdown_rx,
                &trigger_rx,
                &syncing,
                4,
                Vec::new(),
            )
        });
        reached_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        trigger_tx.send(reply_tx).unwrap();
        // The apply loop (held at round 30) takes the request on its next tick.
        poll_until(
            || trigger_tx.is_empty(),
            Duration::from_millis(10),
            Duration::from_secs(10),
            "the running pass should have taken the sync_now request",
        );
        release_tx.send(()).unwrap();
        let reason = finishes_within(Duration::from_secs(20), move || pass.join().unwrap());
        assert_eq!(reason, SyncExitReason::NoBlock);
        assert_eq!(
            reply_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            SyncExitReason::NoBlock,
            "answered by the pass it was coalesced into"
        );
        assert_eq!(ledger.next_round(), Round(61));
        assert!(trigger_tx.is_empty(), "no second pass was queued for it");
    }

    /// A peer that lacks round 11 for its first six answers (one tip probe),
    /// then has rounds 11..=20.
    struct LateBlocksFetcher {
        probes_of_11: AtomicU64,
        second_probe: crossbeam_channel::Sender<()>,
    }

    impl BlockFetcher for LateBlocksFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            let have = if round.0 == 11 {
                let n = self.probes_of_11.fetch_add(1, Ordering::SeqCst) + 1;
                if n == 2 {
                    let _ = self.second_probe.send(());
                }
                n >= 7
            } else {
                round.0 <= 20
            };
            if !have {
                return Err(FetchError::NoBlockForRound { round });
            }
            Ok(FetchedBlockCert {
                block: make_valid_empty_block(round.0),
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// A `sync_now` issued during the tip probe is not answered with the
    /// stale tip result: one fresh pass runs for it and picks up the blocks
    /// that became available since.
    #[test]
    fn sync_now_during_the_tip_probe_triggers_a_fresh_pass() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let (probe_tx, probe_rx) = crossbeam_channel::unbounded();
        let fetcher = Arc::new(LateBlocksFetcher {
            probes_of_11: AtomicU64::new(0),
            second_probe: probe_tx,
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let (trigger_tx, trigger_rx) = crossbeam_channel::unbounded::<SyncWaiter>();
        let syncing = Arc::new(AtomicI64::new(0));
        // One fetch slot: the only tip prober is the worker for round 11.
        let handle = thread::spawn(move || {
            CatchupService::run_loop(shutdown_rx, trigger_rx, ledger_dyn, fetcher_dyn, syncing, 1)
        });
        // The startup pass applied 1..=10 and is probing round 11 (2nd probe).
        probe_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(ledger.next_round(), Round(11));
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        trigger_tx.send(reply_tx).unwrap();
        let reason = reply_rx.recv_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!(reason, SyncExitReason::NoBlock);
        assert_eq!(
            ledger.next_round(),
            Round(21),
            "the answer must come from a fresh pass that saw the new blocks"
        );
        shutdown_tx.send(()).unwrap();
        finishes_within(Duration::from_secs(10), move || handle.join().unwrap());
    }

    /// Counts requests for rounds beyond `up_to` (the tip probe traffic).
    struct TipProbeCountingFetcher {
        up_to: u64,
        beyond: AtomicU64,
        /// The highest round requested.
        max_round: AtomicU64,
    }

    impl BlockFetcher for TipProbeCountingFetcher {
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.max_round.fetch_max(round.0, Ordering::SeqCst);
            if round.0 > self.up_to {
                self.beyond.fetch_add(1, Ordering::SeqCst);
                return Err(FetchError::NoBlockForRound { round });
            }
            thread::sleep(Duration::from_millis(1));
            Ok(FetchedBlockCert {
                block: make_valid_empty_block(round.0),
                cert: Some(make_cert(round.0)),
                raw_payset_blobs: None,
            })
        }
    }

    /// At the tip only the lowest missing round keeps probing, with go's
    /// 100 ms pause: about `window + threshold` requests, not
    /// `window * (threshold + 1)`.
    #[test]
    fn the_tip_probe_is_not_multiplied_by_the_window() {
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(TipProbeCountingFetcher {
            up_to: 20,
            beyond: AtomicU64::new(0),
            max_round: AtomicU64::new(0),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let started = std::time::Instant::now();
        let exit = finishes_within(Duration::from_secs(30), move || {
            sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 8, FetchPolicy::default())
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(21));
        let beyond = fetcher.beyond.load(Ordering::SeqCst);
        // Past the tip the workers' gate keeps the claims within
        // `parallel_blocks` of the apply cursor (go's window), not the larger
        // fetch-ahead window (issue #2204): 8 workers each ask once; the lowest
        // asks `threshold + 1` times. Without the gate this count was 21.
        assert!(
            beyond <= 8 + 6 + 4,
            "{beyond} tip probe requests for 8 workers (multiplied would be 48)"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "the probe must pause between attempts like go's followLatestBackoff"
        );
    }

    /// A round that fails persistently ends the pass within the wall-time
    /// bound instead of after 500 attempts.
    #[test]
    fn a_persistently_failing_round_ends_the_pass_within_the_wall_bound() {
        struct SlowFailing {
            calls: AtomicU64,
        }
        impl BlockFetcher for SlowFailing {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 >= 3 {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(20));
                    return Err(FetchError::Timeout);
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }
        let (ledger, ledger_dyn) = permissive_ledger();
        let fetcher = Arc::new(SlowFailing {
            calls: AtomicU64::new(0),
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            retry_backoff: Duration::from_millis(10),
            wall_bound: Duration::from_millis(300),
            ..FetchPolicy::default()
        };
        let started = std::time::Instant::now();
        let exit = finishes_within(Duration::from_secs(10), move || {
            sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 4, policy)
        });
        assert_eq!(exit, SyncExitReason::NoBlock);
        assert_eq!(ledger.next_round(), Round(3));
        assert!(started.elapsed() < Duration::from_secs(5));
        // 4 workers x ~300 ms / 30 ms per attempt; nowhere near 4 x 500.
        assert!(fetcher.calls.load(Ordering::SeqCst) < 100);
    }

    /// Only round `bad` needs an unsupported protocol (non-monotone, unlike
    /// [`SwitchingCatchupLedger`]).
    struct OneUnsupportedRound {
        inner: PermissiveCatchupLedger,
        bad: u64,
    }

    impl CatchupLedger for OneUnsupportedRound {
        fn next_round(&self) -> Round {
            self.inner.next_round()
        }
        fn ensure_block(&self, block: &Block, cert: &Certificate) {
            self.inner.ensure_block(block, cert)
        }
        fn authenticate_block(&self, _block: &Block, _cert: &Certificate) -> Result<(), String> {
            Ok(())
        }
        fn round_is_not_supported(&self, round: Round) -> bool {
            round.0 == self.bad
        }
    }

    /// Once round U is reported unsupported, window workers stop fetching and
    /// retrying later rounds even though the apply cursor is still behind U.
    #[test]
    fn workers_stop_fetching_past_an_unsupported_round() {
        struct SlowFirstFailingLater {
            beyond: AtomicU64,
            bad: u64,
        }
        impl BlockFetcher for SlowFirstFailingLater {
            fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
                if round.0 > self.bad {
                    self.beyond.fetch_add(1, Ordering::SeqCst);
                    return Err(FetchError::NetworkError("down".into()));
                }
                if round.0 == 1 {
                    // Holds the apply cursor behind U while later workers run.
                    thread::sleep(Duration::from_millis(800));
                }
                Ok(FetchedBlockCert {
                    block: make_valid_empty_block(round.0),
                    cert: Some(make_cert(round.0)),
                    raw_payset_blobs: None,
                })
            }
        }
        let ledger = Arc::new(OneUnsupportedRound {
            inner: PermissiveCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
            },
            bad: 3,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher = Arc::new(SlowFirstFailingLater {
            beyond: AtomicU64::new(0),
            bad: 3,
        });
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let policy = FetchPolicy {
            retry_backoff: Duration::from_millis(5),
            ..FetchPolicy::default()
        };
        let exit = finishes_within(Duration::from_secs(20), move || {
            sync_range_with_policy(&ledger_dyn, &fetcher_dyn, 8, policy)
        });
        assert_eq!(exit, SyncExitReason::Unsupported);
        assert_eq!(ledger.next_round(), Round(3));
        // 8 workers hold rounds 1..=8; rounds 4..=8 are past U. Each may have
        // tried once before U was reported, none may retry (800 ms / 5 ms
        // would otherwise give ~150 attempts each).
        let beyond = fetcher.beyond.load(Ordering::SeqCst);
        assert!(beyond <= 8, "{beyond} fetches beyond the unsupported round");
    }

    /// Row 1: same scenario, but driven through a live [`CatchupService`]'s
    /// [`CatchupService::sync_now`] — a caller can trigger an immediate,
    /// synchronous range-sync pass on a running service and get back its
    /// [`SyncExitReason`], the same shape as go's `syncer.testStart();
    /// syncer.sync()` in `TestServiceFetchBlocksSameRange`.
    #[test]
    fn sync_now_fetches_arbitrary_range_without_certificate() {
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(PermissiveCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 10,
            calls: AtomicU64::new(0),
        });

        let mut svc = CatchupService::start(rx, ledger_dyn, fetcher);

        // `start()`'s own startup pass (mirroring go's `periodicSync`
        // running one `sync()` immediately) runs to completion on the
        // worker thread before it ever reaches the select loop that reads
        // `sync_now()`'s trigger channel, so by the time this returns the
        // ledger is guaranteed to reflect the outcome of at least one full
        // range-sync pass — deterministic, not a race with the startup
        // pass.
        let exit = svc.sync_now();

        assert_eq!(
            ledger.next_round(),
            Round(11),
            "local ledger must catch up to remote's last round (10) with no certificate involved"
        );
        assert_eq!(
            exit,
            SyncExitReason::NoBlock,
            "the pass should stop because the peer has nothing past round 10"
        );

        svc.stop();
    }

    /// Row 2: port of go's `TestServiceLedgerUnavailable`
    /// (`catchup/service_test.go`). When the ledger reports it is behind on
    /// committing deltas ([`CatchupLedger::is_behind_committing_deltas`]),
    /// the periodic sync pass must make partial-but-bounded progress:
    /// commit whatever it already has in hand and then stop, rather than
    /// stalling forever or piling on more unflushed state.
    #[test]
    fn sync_pass_inner_stops_early_when_ledger_behind_committing_deltas() {
        let ledger = Arc::new(BehindDeltasAfterCatchupLedger {
            inner: MockCatchupLedger::new(Round(0)),
            behind_after_round: 3,
        });
        let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
        // The peer has far more than the pass should ever reach.
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
            up_to: 50,
            calls: AtomicU64::new(0),
        });
        let shutdown_rx = never_shutdown();

        let exit = CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);

        assert_eq!(
            exit,
            SyncExitReason::BehindDeltas,
            "pass must report it stopped for backpressure, not just silently stall"
        );
        assert_eq!(
            ledger.next_round(),
            Round(4),
            "rounds 1..=3 should commit (partial progress) before backpressure stops the pass"
        );
        assert!(
            ledger.next_round().0 < 50,
            "progress must be bounded — the pass must not run all the way to the peer's tip"
        );
    }

    /// Row 3: port of go's `TestServiceNoBlockForRound`
    /// (`catchup/service_test.go`). Go bounds `fetchAndWrite`'s retry loop
    /// at `catchupRetryLimit = 500` specifically so a round that genuinely
    /// has no block available anywhere eventually gives up (one log line)
    /// instead of retrying forever. This exercises
    /// `sync_cert_with_retry_limit` with a small limit so the exhaustion
    /// path itself — not just the existence of a cap — is proven, without
    /// waiting through hundreds of real backoff delays.
    #[test]
    fn sync_cert_gives_up_after_retry_limit_exceeded() {
        // Always fails — this round genuinely has no block anywhere.
        let unused_block = make_valid_empty_block(0);
        let fetcher = Arc::new(CountingFailFetcher::new(unused_block, u64::MAX));
        let fetcher_dyn: Arc<dyn BlockFetcher> = fetcher.clone();
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fork_count = Arc::new(AtomicU64::new(0));
        let shutdown_rx = never_shutdown();

        let exit = CatchupService::sync_cert_with_retry_limit(
            &make_pending_cert(5),
            &ledger,
            &fetcher_dyn,
            &shutdown_rx,
            &fork_count,
            3,
        );

        assert_eq!(
            exit,
            SyncExitReason::NoBlock,
            "must give up with a typed exit reason once the retry limit is exceeded"
        );
        assert_eq!(
            fetcher.total_calls(),
            3,
            "should attempt exactly retry_limit fetches before giving up, not fewer or more"
        );
    }

    /// Row 4: port of go's `TestPipelinedFetchExitReason`
    /// (`catchup/service_test.go`). `pipelinedFetch`/`fetchAndWrite` return
    /// a typed exit reason distinguishing *why* a pass stopped. This
    /// exercises a representative subset of [`SyncExitReason`]'s variants
    /// across both `sync_pass_inner` (the periodic, certificate-less path)
    /// and `sync_cert` (the certificate-driven path).
    #[test]
    fn sync_pass_inner_and_sync_cert_report_typed_exit_reasons() {
        // -- Done: sync_cert finds the target round already committed --
        {
            let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(5)));
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));
            let fork_count = Arc::new(AtomicU64::new(0));
            let shutdown_rx = never_shutdown();
            let exit = CatchupService::sync_cert(
                &make_pending_cert(3),
                &ledger,
                &fetcher,
                &shutdown_rx,
                &fork_count,
            );
            assert_eq!(
                exit,
                SyncExitReason::Done,
                "round 3 is already committed (ledger is at round 5)"
            );
        }

        // -- Unsupported: sync_cert bails out on an unsupported round --
        {
            let ledger = Arc::new(SwitchingCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
                switch_round: 1,
            });
            let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));
            let fork_count = Arc::new(AtomicU64::new(0));
            let shutdown_rx = never_shutdown();
            let exit = CatchupService::sync_cert(
                &make_pending_cert(1),
                &ledger_dyn,
                &fetcher,
                &shutdown_rx,
                &fork_count,
            );
            assert_eq!(exit, SyncExitReason::Unsupported);
        }

        // -- Stopping: shutdown already signaled before the first fetch --
        {
            let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));
            let fork_count = Arc::new(AtomicU64::new(0));
            let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
            shutdown_tx.send(()).unwrap();
            let exit = CatchupService::sync_cert(
                &make_pending_cert(5),
                &ledger,
                &fetcher,
                &shutdown_rx,
                &fork_count,
            );
            assert_eq!(exit, SyncExitReason::Stopping);
        }

        // -- NoBlock: sync_pass_inner stops because the peer has nothing to offer --
        {
            let ledger = Arc::new(PermissiveCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
            });
            let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
                up_to: 0,
                calls: AtomicU64::new(0),
            });
            let shutdown_rx = never_shutdown();
            let exit = CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);
            assert_eq!(exit, SyncExitReason::NoBlock);
            assert_eq!(
                ledger.next_round(),
                Round(1),
                "no blocks were available; nothing should have been committed"
            );
        }

        // -- Unsupported: sync_pass_inner stops at an unsupported protocol switch --
        {
            let ledger = Arc::new(SwitchingCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
                switch_round: 1,
            });
            let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
                up_to: 10,
                calls: AtomicU64::new(0),
            });
            let shutdown_rx = never_shutdown();
            let exit = CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);
            assert_eq!(exit, SyncExitReason::Unsupported);
        }

        // -- BehindDeltas: sync_pass_inner stops once backpressure kicks in --
        {
            let ledger = Arc::new(BehindDeltasAfterCatchupLedger {
                inner: MockCatchupLedger::new(Round(0)),
                behind_after_round: 3,
            });
            let ledger_dyn: Arc<dyn CatchupLedger> = ledger.clone();
            let fetcher: Arc<dyn BlockFetcher> = Arc::new(BoundedBlockFetcher {
                up_to: 10,
                calls: AtomicU64::new(0),
            });
            let shutdown_rx = never_shutdown();
            let exit = CatchupService::sync_pass_inner(&ledger_dyn, &fetcher, &shutdown_rx, 2);
            assert_eq!(exit, SyncExitReason::BehindDeltas);
            assert_eq!(ledger.next_round(), Round(4));
        }
    }
}
