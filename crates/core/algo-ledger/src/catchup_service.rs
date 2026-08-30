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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// Shutdown signal sender — dropping or sending signals the worker to exit.
    shutdown_tx: Option<crossbeam_channel::Sender<()>>,
    /// Join handle for the background worker thread.
    join_handle: Option<JoinHandle<()>>,
    /// Counter tracking the number of fork detections observed.
    /// Callers can query this via [`CatchupService::fork_count`] for
    /// monitoring / alerting purposes.
    fork_count: Arc<AtomicU64>,
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

impl CatchupService {
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
    /// v5.0.0-stable, `config/localTemplate.go:313`). Callers that have a
    /// configured value (e.g. from `algo_config::Local::catchup_parallel_blocks`)
    /// should use [`Self::start_with_parallelism`] instead.
    pub fn start(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
    ) -> Self {
        Self::start_with_parallelism(cert_rx, ledger, fetcher, Self::DEFAULT_PARALLEL_BLOCKS)
    }

    /// Go's v5.0.0-stable `CatchupParallelBlocks` default
    /// (`config/localTemplate.go:313`, `version[5]:"16"`).
    pub const DEFAULT_PARALLEL_BLOCKS: u64 = 16;

    /// Same as [`Self::start`], but with an explicit fetch-concurrency
    /// budget for the periodic sync path (issue #753) — go's
    /// `CatchupParallelBlocks`. Values are clamped to
    /// `1..=`[`Self::MAX_BLOCKS_PER_SYNC_PASS`]; `0` is treated as `1`
    /// (serial), matching "at least one fetch in flight" rather than a
    /// stalled service.
    pub fn start_with_parallelism(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        parallel_blocks: u64,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let fork_count = Arc::new(AtomicU64::new(0));
        let fork_count_inner = Arc::clone(&fork_count);
        let parallel_blocks = parallel_blocks.clamp(1, Self::MAX_BLOCKS_PER_SYNC_PASS);

        let join_handle = thread::Builder::new()
            .name("catchup-service".to_string())
            .spawn(move || {
                Self::run_loop(
                    cert_rx,
                    shutdown_rx,
                    ledger,
                    fetcher,
                    fork_count_inner,
                    parallel_blocks,
                );
            })
            .expect("failed to spawn catchup-service thread");

        Self {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
            fork_count,
        }
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

        // Signal shutdown by sending (or dropping the sender).
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Join the worker thread.
        if let Some(handle) = self.join_handle.take() {
            if let Err(e) = handle.join() {
                warn!("catchup service thread panicked: {e:?}");
            }
        }

        debug!("catchup service has stopped");
    }

    /// The main loop of the catchup service worker thread.
    ///
    /// Mirrors the `case cert := <-s.unmatchedPendingCertificates` branch of
    /// Go's `periodicSync`.
    fn run_loop(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        shutdown_rx: Receiver<()>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        fork_count: Arc<AtomicU64>,
        parallel_blocks: u64,
    ) {
        info!("catchup service started");

        // Mirrors Go's `periodicSync`, which runs one `sync()` immediately
        // on startup before entering its select loop
        // (`catchup/service.go:611-619`).
        Self::sync_pass(&ledger, &fetcher, &shutdown_rx, parallel_blocks);

        let mut last_round = ledger.next_round();

        // Once the certificate channel closes we still want the periodic
        // path to keep the ledger following the network, so the closed
        // receiver is swapped for one that never fires rather than ending
        // the service (Go's `periodicSync` likewise only exits on
        // `ctx.Done()`).
        let never = crossbeam_channel::never::<PendingUnmatchedCertificate>();
        let mut cert_rx = cert_rx;

        loop {
            let mut sel = Select::new();
            let cert_idx = sel.recv(&cert_rx);
            let shutdown_idx = sel.recv(&shutdown_rx);

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
                    // playing, so the certificate-driven path below never
                    // fires in that situation (issue #478).
                    let now = ledger.next_round();
                    if now != last_round {
                        // Agreement is making progress on its own.
                        last_round = now;
                        continue;
                    }
                    Self::sync_pass(&ledger, &fetcher, &shutdown_rx, parallel_blocks);
                    last_round = ledger.next_round();
                    continue;
                }
            };

            let mut certs_closed = false;
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
                i if i == cert_idx => {
                    match oper.recv(&cert_rx) {
                        Ok(pending) => {
                            Self::sync_cert(&pending, &ledger, &fetcher, &shutdown_rx, &fork_count);
                            last_round = ledger.next_round();
                        }
                        Err(_) => {
                            // Certificate channel closed — the agreement
                            // service has shut down (or never had a sender).
                            // Keep running the periodic path so the node
                            // still follows the chain; only `stop()` ends
                            // the service.
                            info!(
                                "catchup service: certificate channel closed, \
                                 continuing with periodic sync only"
                            );
                            certs_closed = true;
                        }
                    }
                }
                _ => unreachable!(),
            }
            drop(sel);
            if certs_closed {
                cert_rx = never.clone();
            }
        }

        info!("catchup service exiting");
    }

    /// How long the ledger may stand still before the periodic path tries
    /// to fetch from the network. Go derives this from
    /// `agreement.DeadlineTimeout()` (`roundTimeEstimate`); 4s is that
    /// value for the default filter timeout.
    const PERIODIC_SYNC_INTERVAL: Duration = Duration::from_secs(4);

    /// Upper bound on the number of blocks fetched in a single periodic
    /// pass, so the worker returns to its select loop (and can observe
    /// shutdown / certificates) even while far behind.
    const MAX_BLOCKS_PER_SYNC_PASS: u64 = 256;

    /// Pull consecutive blocks from the network starting at the ledger's
    /// next round, until a fetch fails or the batch limit is reached.
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
        parallel_blocks: u64,
    ) {
        let start_round = ledger.next_round();
        let limit_round = start_round.0.saturating_add(Self::MAX_BLOCKS_PER_SYNC_PASS);
        let parallel_blocks = parallel_blocks.clamp(1, Self::MAX_BLOCKS_PER_SYNC_PASS);

        // Shared dispatch counter (next round any idle worker should try
        // next) and a stop flag any thread can raise once a permanent
        // failure/stop condition is found — either a worker discovering an
        // unsupported round, or the main thread's validation loop below.
        let next_to_fetch = Arc::new(AtomicU64::new(start_round.0));
        let stop = Arc::new(AtomicBool::new(false));
        // A zero-capacity (rendezvous) channel: a worker's `send` only
        // completes once the main loop below is actively receiving, so a
        // worker can be at most one completed-but-unconsumed fetch ahead of
        // validation at any time. Without this, a fast/misbehaving peer
        // answering every round instantly could let all `parallel_blocks`
        // workers race arbitrarily far ahead, wasting up to the full
        // `MAX_BLOCKS_PER_SYNC_PASS` batch on fetches that get discarded
        // the moment the first invalid round is found. Rendezvous caps that
        // waste at roughly one per worker — the fetch-ahead budget
        // `CatchupParallelBlocks` is meant to express — while still letting
        // every worker's actual network I/O run fully in parallel.
        let (result_tx, result_rx) = crossbeam_channel::bounded::<(u64, FetchOutcome)>(0);

        let mut workers = Vec::with_capacity(parallel_blocks as usize);
        for _ in 0..parallel_blocks {
            let next_to_fetch = Arc::clone(&next_to_fetch);
            let stop = Arc::clone(&stop);
            let tx = result_tx.clone();
            let ledger = Arc::clone(ledger);
            let fetcher = Arc::clone(fetcher);
            workers.push(thread::spawn(move || loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let round = next_to_fetch.fetch_add(1, Ordering::SeqCst);
                if round >= limit_round {
                    return;
                }
                let r = Round(round);
                if ledger.round_is_not_supported(r) {
                    let _ = tx.send((round, FetchOutcome::Unsupported));
                    return;
                }
                let outcome = fetcher.fetch_block(r);
                if tx
                    .send((round, FetchOutcome::Fetch(Box::new(outcome))))
                    .is_err()
                {
                    return;
                }
            }));
        }
        // Drop this thread's sender clone so the channel closes once every
        // worker has exited (each worker holds its own clone until then).
        drop(result_tx);

        let mut buffer: BTreeMap<u64, FetchOutcome> = BTreeMap::new();
        let mut next_apply = start_round.0;
        let mut fetched = 0u64;
        // Once `true`, the main loop below only drains the channel (never
        // applies anything more). This is essential, not just tidy: a
        // worker can be parked mid-`send` on the bounded channel when the
        // stop condition is discovered, and it only re-checks `stop` after
        // that `send` unblocks — so this thread must keep receiving (even
        // if it throws every further message away) until every worker's
        // sender clone drops and the channel closes, or `join` below would
        // deadlock waiting on a worker that is waiting on us.
        let mut stopped = false;

        for (round, outcome) in result_rx.iter() {
            if stopped {
                continue;
            }
            buffer.insert(round, outcome);
            'apply: while let Some(outcome) = buffer.remove(&next_apply) {
                if shutdown_rx.try_recv().is_ok() {
                    debug!("catchup service: shutdown received during periodic sync");
                    stop.store(true, Ordering::SeqCst);
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
                        stop.store(true, Ordering::SeqCst);
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
                        stop.store(true, Ordering::SeqCst);
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
                            stop.store(true, Ordering::SeqCst);
                            stopped = true;
                            break 'apply;
                        }

                        let Some(cert) = fetched_block.cert else {
                            warn!(
                                round = %expected_round,
                                "catchup service: periodic sync got a block with no \
                                 certificate, refusing to commit it"
                            );
                            stop.store(true, Ordering::SeqCst);
                            stopped = true;
                            break 'apply;
                        };

                        if let Err(reason) = ledger.authenticate_block(&block, &cert) {
                            warn!(
                                round = %expected_round,
                                reason = %reason,
                                "catchup service: periodic sync could not authenticate \
                                 the fetched block, stopping"
                            );
                            stop.store(true, Ordering::SeqCst);
                            stopped = true;
                            break 'apply;
                        }

                        match algo_validate::contents_match_header(
                            &block,
                            fetched_block.raw_payset_blobs.as_deref(),
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!(
                                    round = %expected_round,
                                    "catchup service: periodic sync block contents do not \
                                     match header commitments, stopping"
                                );
                                stop.store(true, Ordering::SeqCst);
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
                                stop.store(true, Ordering::SeqCst);
                                stopped = true;
                                break 'apply;
                            }
                        }

                        ledger.ensure_block(&block, &cert);
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
                            stop.store(true, Ordering::SeqCst);
                            stopped = true;
                            break 'apply;
                        }
                    }
                }
                next_apply += 1;
            }
        }

        // The channel only closes once every worker's sender clone has
        // dropped, i.e. once every worker has returned — so by the time
        // `result_rx.iter()` above ends, every worker has already noticed
        // `stop` (or run out of rounds) and these `join`s return immediately.
        // `stop` is set defensively in case the batch limit was reached
        // without any validation failure ever setting it.
        stop.store(true, Ordering::SeqCst);
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
    /// Unlike a bounded retry loop, this mirrors Go's `fetchRound` which
    /// retries indefinitely (`for s.ledger.LastRound() < cert.Round`) until
    /// either the block is committed (by any path) or shutdown is signaled.
    fn sync_cert(
        pending: &PendingUnmatchedCertificate,
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        fork_count: &Arc<AtomicU64>,
    ) {
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
            return;
        }

        // Retry loop: mirrors Go's `for s.ledger.LastRound() < cert.Round`.
        // Continues until the ledger has the block, shutdown is signaled,
        // or the block is successfully fetched and committed.
        let mut attempt: u32 = 0;
        loop {
            // Check if the ledger already has this block (committed by
            // agreement or a previous iteration of this loop).
            // next_round = last_committed + 1, so if next_round > target
            // the block is already committed.
            {
                let next = ledger.next_round();
                if next.0 > target_round.0 {
                    debug!(
                        round = %target_round,
                        next_round = %next,
                        "catchup service: ledger already has block, skipping"
                    );
                    return;
                }
            }

            // Check for shutdown before attempting a fetch.
            if shutdown_rx.try_recv().is_ok() {
                debug!(
                    round = %target_round,
                    "catchup service: shutdown received during sync_cert"
                );
                return;
            }

            attempt = attempt.saturating_add(1);

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
                            return;
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
                            return;
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
                                return;
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
                            return;
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
                    return;
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
                        return;
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
        Certificate {
            round: Round(round),
            ..Certificate::default()
        }
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
        // probe should stop (issue #753's rendezvous-channel pipelining —
        // see `sync_pass`'s worker-loop doc comment), so this allows a
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
            round: Round(round),
            proposal: ProposalValue {
                block_digest: digest,
                ..Default::default()
            },
            ..Certificate::default()
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
        // small bounded slack for `start_with_parallelism(.., 1)`'s
        // rendezvous-pipelined periodic worker (see
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

        // Poll until the fetcher has been called at least once (the service
        // retries on digest mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should have been called at least once",
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
}
