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

//! Live catchpoint-catchup mode toggling for a running node (issue #937).
//!
//! Mirrors go-algorand's `AlgorandFullNode.StartCatchup`/`AbortCatchup`/
//! `SetCatchpointCatchupMode` (`node/node.go`) and
//! `catchup.CatchpointCatchupService`'s run loop
//! (`catchup/catchpointService.go` @ `v5.0.0-stable`): a REST client can
//! toggle a *running* node into catchpoint-catchup mode and back without
//! restarting the process or dropping the REST server.
//!
//! # Design
//!
//! go's version is a hand-rolled stage machine
//! (`CatchpointCatchupStateInactive` → `...LedgerDownload` →
//! `...LatestBlockDownload` → `...BlocksDownload` → `...Switch`) that
//! directly drives ledger accessor calls. algod-rust already has an
//! equivalent, independently-tested state machine for exactly this
//! fetch/verify/replay sequence: [`algo_ledger::sync::SyncOrchestrator`],
//! used today by the standalone `algod-rust sync`/`catchpoint_sync`
//! subcommand. Rather than duplicate that logic, [`LiveCatchupManager`]
//! reuses it in-process via the [`CatchupRunner`] trait — production code
//! goes through [`OrchestratorCatchupRunner`], tests inject a lightweight
//! fake so the manager's start/abort/pause/resume bookkeeping is covered
//! without any network I/O.
//!
//! The [`NormalSyncControl`] trait is the Rust analogue of go's
//! `node.mu`-guarded service stop/start dance in `SetCatchpointCatchupMode`:
//! whatever background task is the node's "normal sync loop" gets
//! `pause()`d before the catchpoint fetch starts and `resume()`d once it
//! finishes (successfully, on error, or aborted) — mirroring go's
//! `updateNodeCatchupMode(true)`/`updateNodeCatchupMode(false)` calls in
//! `processStageInactive`/`processStageSwitch`/`abort`
//! (`catchup/catchpointService.go`).
//!
//! # Current wiring
//!
//! [`crate::commands::node::run_start`] (`node start --follow <peer>`)
//! wires a real [`NormalSyncControl`] that pauses/resumes the `--follow`
//! background sync loop. `algod-rust participate` (a full consensus
//! participant) does **not** attach a [`LiveCatchupManager`] yet — its
//! "normal sync loop" is the live agreement service, and go's
//! `SetCatchpointCatchupMode` stops seven independent services
//! (`agreementService`, `catchupService`, `txHandler`, `blockService`,
//! `ledgerService`, `txPoolSyncerService`, `heartbeatService`/
//! `stateProofWorker`) before recreating the node context — safely
//! quiescing algod-rust's equivalents (in particular, cleanly restarting
//! `algo_agreement::service::Service`, whose `shutdown` consumes `self`)
//! is substantial additional work, tracked as a follow-up (issue #937's
//! PR references the exact number). `start_catchup`/`abort_catchup` on a
//! `participate` node therefore still report
//! [`algo_rest_api::node::NodeError::NotImplemented`] until that lands.

use std::sync::{Arc, Mutex as StdMutex};

use algo_rest_api::node::CatchupStartResult;
use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Granular catchpoint-catchup progress counters (issue #941), mirroring
/// go-algorand's `catchup.CatchpointCatchupStats`
/// (`catchup/catchpointService.go`) — the struct `node.go`'s
/// `catchpointCatchupStatus` copies field-for-field into `StatusReport`'s
/// `CatchpointCatchup*` fields, which `GET /v2/status` serializes as
/// `catchpoint-total-accounts`/etc.
///
/// Populated live from [`algo_ledger::sync::SyncProgress`]'s matching
/// `catchpoint_*` fields via [`OrchestratorCatchupRunner`]'s progress
/// callback, and surfaced by [`LiveCatchupManager::catchpoint_counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CatchpointCounters {
    /// go: `CatchpointCatchupStats.TotalAccounts`.
    pub total_accounts: u64,
    /// go: `CatchpointCatchupStats.ProcessedAccounts`.
    pub processed_accounts: u64,
    /// go: `CatchpointCatchupStats.VerifiedAccounts`.
    pub verified_accounts: u64,
    /// go: `CatchpointCatchupStats.TotalKVs`.
    pub total_kvs: u64,
    /// go: `CatchpointCatchupStats.ProcessedKVs`.
    pub processed_kvs: u64,
    /// go: `CatchpointCatchupStats.VerifiedKVs`.
    pub verified_kvs: u64,
    /// go: `CatchpointCatchupStats.TotalBlocks`.
    pub total_blocks: u64,
    /// go: `CatchpointCatchupStats.AcquiredBlocks`.
    pub acquired_blocks: u64,
}

/// Controls the node's "normal sync loop" so it can be quiesced while a
/// live catchpoint catchup owns the ledger, then resumed afterward.
///
/// Mirrors go's `CatchpointCatchupNodeServices`/`SetCatchpointCatchupMode`
/// (`catchup/catchpointService.go`, `node/node.go`) — the abstraction that
/// lets the catchup service stop/restart the node's regular services
/// without the two pieces of code being directly coupled.
#[async_trait]
pub trait NormalSyncControl: Send + Sync {
    /// Pause the normal sync loop and wait for it to fully stop before
    /// returning, so the catchup task is the ledger's only writer once
    /// this resolves.
    async fn pause(&self);

    /// Resume the normal sync loop. A no-op if it's already running.
    async fn resume(&self);
}

/// A [`NormalSyncControl`] with nothing to pause — used where no
/// concurrent writer exists (e.g. a read-only `node start` with neither
/// `--dev` nor `--follow`). Not yet constructed by any production wiring
/// (only `node start --follow` attaches a [`LiveCatchupManager`] today, and
/// it always has a real writer to pause) — kept `pub` as the natural
/// building block for the next command that does, and exercised directly
/// by [`node_interface_impl`](crate::node_interface_impl)'s
/// `start_and_abort_catchup_round_trip_through_status` test.
#[allow(dead_code)]
pub struct NoopSyncControl;

#[async_trait]
impl NormalSyncControl for NoopSyncControl {
    async fn pause(&self) {}
    async fn resume(&self) {}
}

/// Drives a single catchpoint-catchup run to completion or cancellation.
///
/// Production code implements this over
/// [`algo_ledger::sync::SyncOrchestrator`] (see
/// [`OrchestratorCatchupRunner`]); tests inject fakes so
/// [`LiveCatchupManager`]'s bookkeeping can be verified without a network.
#[async_trait]
pub trait CatchupRunner: Send + Sync {
    /// Run the fetch/verify/replay sequence for `catchpoint`, honoring
    /// `cancel` the way [`algo_ledger::sync::SyncOrchestrator::run`] already
    /// does (checked between phases and between block downloads).
    ///
    /// `counters` is a shared sink the runner should update live as it
    /// progresses (issue #941) — [`OrchestratorCatchupRunner`] wires it to
    /// [`algo_ledger::sync::SyncOrchestrator::set_progress_callback`]. Test
    /// fakes that don't model fine-grained progress may leave it untouched.
    async fn run(
        &self,
        catchpoint: &str,
        cancel: CancellationToken,
        counters: Arc<StdMutex<CatchpointCounters>>,
    ) -> anyhow::Result<()>;
}

/// State for the currently-running catchup, if any.
struct RunningCatchup {
    catchpoint: String,
    cancel: CancellationToken,
}

/// Live catchpoint-catchup mode toggle for a running node.
///
/// One instance is shared (via `Arc`) between the REST
/// [`NodeInterface`](algo_rest_api::node::NodeInterface) adapter (which
/// calls [`Self::start_catchup`]/[`Self::abort_catchup`] from the
/// `POST`/`DELETE /v2/catchup/:catchpoint` handlers) and nothing else —
/// unlike go's `AlgorandFullNode`, no other subsystem needs to observe
/// catchup state directly.
pub struct LiveCatchupManager {
    runner: Arc<dyn CatchupRunner>,
    control: Arc<dyn NormalSyncControl>,
    running: AsyncMutex<Option<RunningCatchup>>,
    /// The most recently *completed* catchpoint label, surfaced by
    /// `GET /v2/status`'s `last-catchpoint` field once catchup finishes.
    last_catchpoint: StdMutex<String>,
    /// Live granular progress counters for the in-flight (or most recently
    /// finished) catchup — see [`Self::catchpoint_counters`] (issue #941).
    counters: Arc<StdMutex<CatchpointCounters>>,
}

impl LiveCatchupManager {
    /// Construct a manager. `runner` performs the actual fetch/replay work;
    /// `control` pauses/resumes whatever the node's normal sync loop is.
    pub fn new(runner: Arc<dyn CatchupRunner>, control: Arc<dyn NormalSyncControl>) -> Arc<Self> {
        Arc::new(Self {
            runner,
            control,
            running: AsyncMutex::new(None),
            last_catchpoint: StdMutex::new(String::new()),
            counters: Arc::new(StdMutex::new(CatchpointCounters::default())),
        })
    }

    /// Start a live catchpoint catchup, mirroring go's
    /// `AlgorandFullNode.StartCatchup` (`node/node.go`).
    ///
    /// Returns [`CatchupStartResult::AlreadyInProgress`] if a catchup for
    /// the same label is already running (go: "No need to return an
    /// error"), [`CatchupStartResult::Unable`] if a catchup for a
    /// *different* label is running, and otherwise pauses the normal sync
    /// loop and spawns the fetch/replay task before returning
    /// [`CatchupStartResult::Created`].
    pub async fn start_catchup(self: &Arc<Self>, catchpoint: &str) -> CatchupStartResult {
        if catchpoint.is_empty() {
            // Mirrors `MakeNewCatchpointCatchupService`'s
            // "catchpoint is invalid" guard.
            return CatchupStartResult::StartError("catchpoint is invalid".to_string());
        }

        let mut guard = self.running.lock().await;
        if let Some(running) = guard.as_ref() {
            if running.catchpoint == catchpoint {
                return CatchupStartResult::AlreadyInProgress;
            }
            return CatchupStartResult::Unable(format!(
                "unable to start catchup for '{catchpoint}' - already catching up '{}'",
                running.catchpoint
            ));
        }

        // Pause the node's normal sync loop before starting, mirroring
        // `processStageInactive`'s `updateNodeCatchupMode(true)` call —
        // go performs this at the *start* of the fetch state machine, not
        // before it, but the net effect (no other writer once ledger
        // download begins) is the same and simpler to reason about here
        // since `SyncOrchestrator` doesn't expose a mid-run pause hook.
        self.control.pause().await;

        // Reset progress counters for the new run — mirrors go building a
        // fresh `CatchpointCatchupStats{}` per `CatchpointCatchupService`
        // instance (`MakeResumedCatchpointCatchupService`).
        if let Ok(mut counters) = self.counters.lock() {
            *counters = CatchpointCounters::default();
        }

        let cancel = CancellationToken::new();
        let manager = Arc::clone(self);
        let catchpoint_owned = catchpoint.to_string();
        let cancel_task = cancel.clone();
        tokio::spawn(async move {
            manager.drive(catchpoint_owned, cancel_task).await;
        });

        *guard = Some(RunningCatchup {
            catchpoint: catchpoint.to_string(),
            cancel,
        });
        CatchupStartResult::Created
    }

    /// Abort an in-progress catchup, mirroring go's
    /// `AlgorandFullNode.AbortCatchup` (`node/node.go`): a no-op (not an
    /// error) if nothing is running, an error if a *different* catchpoint
    /// is running, and otherwise cancels the in-flight run. The run's own
    /// cleanup (clearing state, resuming normal operation) happens
    /// asynchronously once the cancellation is observed — this call does
    /// not block on it, matching go's `Abort()` (fire-and-forget cancel).
    pub async fn abort_catchup(&self, catchpoint: &str) -> Result<(), String> {
        let guard = self.running.lock().await;
        match guard.as_ref() {
            None => Ok(()),
            Some(running) if running.catchpoint == catchpoint => {
                running.cancel.cancel();
                Ok(())
            }
            Some(running) => Err(format!(
                "unable to abort catchpoint catchup for '{catchpoint}' - already catching up '{}'",
                running.catchpoint
            )),
        }
    }

    /// The catchpoint label currently being caught up to, if any. Backs
    /// `GET /v2/status`'s `catchpoint` field.
    pub async fn current_catchpoint(&self) -> Option<String> {
        self.running
            .lock()
            .await
            .as_ref()
            .map(|r| r.catchpoint.clone())
    }

    /// The current live progress counters for the in-flight (or most
    /// recently finished) catchup (issue #941). Callers gate on
    /// [`Self::current_catchpoint`] being non-empty the way go gates on
    /// `catchpointCatchupService != nil` — go-algorand does not report
    /// these fields at all once catchup is no longer running.
    pub fn catchpoint_counters(&self) -> CatchpointCounters {
        self.counters.lock().map(|g| *g).unwrap_or_default()
    }

    /// The most recently *completed* catchpoint label (empty if none has
    /// completed yet). Backs `GET /v2/status`'s `last-catchpoint` field.
    pub fn last_catchpoint(&self) -> String {
        self.last_catchpoint
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Runs the catchup to completion/cancellation/error, then clears the
    /// running state and resumes normal operation — mirroring go's
    /// `processStageSwitch`/`abort` both calling
    /// `updateNodeCatchupMode(false)` on the way out, regardless of
    /// success or failure.
    async fn drive(self: Arc<Self>, catchpoint: String, cancel: CancellationToken) {
        let result = self
            .runner
            .run(&catchpoint, cancel, Arc::clone(&self.counters))
            .await;
        match &result {
            Ok(()) => {
                info!(catchpoint = %catchpoint, "live catchpoint catchup completed");
                if let Ok(mut last) = self.last_catchpoint.lock() {
                    *last = catchpoint.clone();
                }
            }
            Err(e) => {
                warn!(catchpoint = %catchpoint, error = %e, "live catchpoint catchup failed");
            }
        }

        {
            let mut guard = self.running.lock().await;
            *guard = None;
        }
        self.control.resume().await;
    }
}

// ---------------------------------------------------------------------------
// Production CatchupRunner — backed by SyncOrchestrator
// ---------------------------------------------------------------------------

/// Static parameters needed to run a catchpoint catchup against a peer,
/// resolved once at node startup (algod URL/token, genesis identity, the
/// ledger's on-disk prefix).
#[derive(Debug, Clone)]
pub struct LiveCatchupParams {
    /// REST URL of the peer to fetch the catchpoint and blocks from.
    pub algod_url: String,
    /// Auth token for `algod_url`.
    pub algod_token: String,
    /// Ledger prefix (see [`algo_ledger::sync::SyncConfig::db_path`]) — the
    /// *same* database the live node's own `SqliteLedger` handle already
    /// has open. Safe for concurrent use because `SqliteLedger::open` sets
    /// `journal_mode=WAL`/`busy_timeout` (`erasable_db.rs`) and the normal
    /// sync loop is paused for the duration (see [`NormalSyncControl`]).
    pub db_path: std::path::PathBuf,
    /// Genesis ID, e.g. `"mainnet-v1.0"`.
    pub genesis_id: String,
    /// Genesis hash (32 bytes).
    pub genesis_hash: [u8; 32],
    /// Concurrent block-download tasks during the post-catchpoint replay.
    pub concurrency: usize,
    /// Extra ranked catchpoint-file peer URLs (issue #901), beyond
    /// `algod_url` itself.
    pub catchpoint_peer_urls: Vec<String>,
}

/// Production [`CatchupRunner`]: builds a
/// [`algo_ledger::sync::SyncOrchestrator`] against [`LiveCatchupParams`]
/// and drives it to completion, exactly like `commands/catchpoint_sync.rs`'s
/// standalone CLI path, but callable in-process from a live node.
pub struct OrchestratorCatchupRunner {
    params: LiveCatchupParams,
}

impl OrchestratorCatchupRunner {
    pub fn new(params: LiveCatchupParams) -> Self {
        Self { params }
    }
}

#[async_trait]
impl CatchupRunner for OrchestratorCatchupRunner {
    async fn run(
        &self,
        catchpoint: &str,
        cancel: CancellationToken,
        counters: Arc<StdMutex<CatchpointCounters>>,
    ) -> anyhow::Result<()> {
        use algo_ledger::sync::{SyncConfig, SyncOrchestrator};

        let backend = crate::commands::catchpoint_sync::build_algod_sync_backend(
            &self.params.algod_url,
            &self.params.algod_token,
            &self.params.catchpoint_peer_urls,
        );

        let config = SyncConfig {
            catchpoint_label: Some(catchpoint.to_string()),
            algod_url: self.params.algod_url.clone(),
            algod_token: self.params.algod_token.clone(),
            genesis_id: self.params.genesis_id.clone(),
            genesis_hash: self.params.genesis_hash,
            db_path: self.params.db_path.clone(),
            concurrency: self.params.concurrency,
            // One-shot: catch up to the labeled catchpoint plus the lookback
            // window, then hand back to the node's normal sync loop (which
            // `LiveCatchupManager::drive` resumes) rather than looping here.
            follow_after_sync: false,
            compare_mode: false,
            trie_path: None,
            avm_execute: false,
            fail_fast: true,
            end_round: None,
            accounts_rebuild_synchronous_mode: 0,
        };

        let mut orchestrator = SyncOrchestrator::with_backend(config, backend);
        orchestrator.set_cancel(cancel);
        // Mirror the eight `catchpoint_*` counters from `SyncProgress` into
        // the shared sink `LiveCatchupManager::catchpoint_counters()` reads
        // (issue #941), on every progress notification (state transitions
        // and periodic within-phase updates).
        orchestrator.set_progress_callback(Box::new(move |progress| {
            if let Ok(mut c) = counters.lock() {
                *c = CatchpointCounters {
                    total_accounts: progress.catchpoint_total_accounts,
                    processed_accounts: progress.catchpoint_processed_accounts,
                    verified_accounts: progress.catchpoint_verified_accounts,
                    total_kvs: progress.catchpoint_total_kvs,
                    processed_kvs: progress.catchpoint_processed_kvs,
                    verified_kvs: progress.catchpoint_verified_kvs,
                    total_blocks: progress.catchpoint_total_blocks,
                    acquired_blocks: progress.catchpoint_acquired_blocks,
                };
            }
        }));
        orchestrator.run().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// A [`NormalSyncControl`] fake that counts pause/resume calls and
    /// tracks whether it's currently "paused", so tests can assert the
    /// manager pauses before starting and resumes after finishing.
    #[derive(Default)]
    struct CountingControl {
        pauses: AtomicU32,
        resumes: AtomicU32,
    }

    #[async_trait]
    impl NormalSyncControl for CountingControl {
        async fn pause(&self) {
            self.pauses.fetch_add(1, Ordering::SeqCst);
        }
        async fn resume(&self) {
            self.resumes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A [`CatchupRunner`] fake that completes immediately with a
    /// configurable result, recording the catchpoint label and whether it
    /// observed cancellation.
    struct ImmediateRunner {
        result: StdMutex<Option<Result<(), String>>>,
    }

    impl ImmediateRunner {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                result: StdMutex::new(Some(Ok(()))),
            })
        }
        fn err(msg: &str) -> Arc<Self> {
            Arc::new(Self {
                result: StdMutex::new(Some(Err(msg.to_string()))),
            })
        }
    }

    #[async_trait]
    impl CatchupRunner for ImmediateRunner {
        async fn run(
            &self,
            _catchpoint: &str,
            _cancel: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<()> {
            match self.result.lock().unwrap().take() {
                Some(Ok(())) | None => Ok(()),
                Some(Err(e)) => Err(anyhow::anyhow!(e)),
            }
        }
    }

    /// A [`CatchupRunner`] fake that blocks until `cancel` fires, so tests
    /// can exercise `abort_catchup` against a genuinely in-flight run.
    struct BlockingRunner {
        cancel_observed: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl CatchupRunner for BlockingRunner {
        async fn run(
            &self,
            _catchpoint: &str,
            cancel: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<()> {
            cancel.cancelled().await;
            self.cancel_observed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // Mirrors `SyncOrchestrator::run` returning an error on
            // cancellation (`sync/mod.rs`'s `handle_cancellation`) — a
            // cancelled run is not a "completed" catchup.
            Err(anyhow::anyhow!("sync cancelled by user"))
        }
    }

    /// Polls `current_catchpoint()` until it's `None` (i.e. the manager
    /// has returned to idle), bounded so a bug can't hang the test suite.
    async fn wait_idle(manager: &LiveCatchupManager) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if manager.current_catchpoint().await.is_none() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "manager did not return to idle in time"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // -- start_catchup: happy path -----------------------------------------

    #[tokio::test]
    async fn start_catchup_pauses_runs_and_resumes() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());

        let result = manager
            .start_catchup("1000#abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop")
            .await;
        assert_eq!(result, CatchupStartResult::Created);

        wait_idle(&manager).await;

        assert_eq!(control.pauses.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        assert_eq!(
            manager.last_catchpoint(),
            "1000#abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop"
        );
    }

    #[tokio::test]
    async fn start_catchup_resumes_control_even_on_runner_error() {
        // Mirrors go's `abort()` still calling `updateNodeCatchupMode(false)`
        // on failure — a failed catchup must not leave the node stuck
        // paused.
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::err("boom"), control.clone());

        let result = manager.start_catchup("1000#deadbeef").await;
        assert_eq!(result, CatchupStartResult::Created);

        wait_idle(&manager).await;

        assert_eq!(control.pauses.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        // A failed run must not be recorded as the last *completed*
        // catchpoint.
        assert_eq!(manager.last_catchpoint(), "");
    }

    #[tokio::test]
    async fn start_catchup_rejects_empty_catchpoint() {
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), Arc::new(NoopSyncControl));
        let result = manager.start_catchup("").await;
        assert!(matches!(result, CatchupStartResult::StartError(_)));
    }

    // -- start_catchup: already-running semantics ---------------------------

    #[tokio::test]
    async fn start_catchup_same_label_reports_already_in_progress() {
        let control = Arc::new(CountingControl::default());
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            control.clone(),
        );

        let first = manager.start_catchup("1000#deadbeef").await;
        assert_eq!(first, CatchupStartResult::Created);

        let second = manager.start_catchup("1000#deadbeef").await;
        assert_eq!(second, CatchupStartResult::AlreadyInProgress);
        // Must not have paused a second time for the duplicate request.
        assert_eq!(control.pauses.load(Ordering::SeqCst), 1);

        manager.abort_catchup("1000#deadbeef").await.unwrap();
        wait_idle(&manager).await;
        assert!(cancel_observed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn start_catchup_different_label_reports_unable() {
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            Arc::new(NoopSyncControl),
        );

        let first = manager.start_catchup("1000#aaaa").await;
        assert_eq!(first, CatchupStartResult::Created);

        let second = manager.start_catchup("2000#bbbb").await;
        match second {
            CatchupStartResult::Unable(msg) => {
                assert!(msg.contains("2000#bbbb"));
                assert!(msg.contains("1000#aaaa"));
            }
            other => panic!("expected Unable, got {other:?}"),
        }

        manager.abort_catchup("1000#aaaa").await.unwrap();
        wait_idle(&manager).await;
    }

    // -- abort_catchup --------------------------------------------------------

    #[tokio::test]
    async fn abort_catchup_when_nothing_running_is_a_no_op() {
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), Arc::new(NoopSyncControl));
        let result = manager.abort_catchup("1000#deadbeef").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn abort_catchup_wrong_label_is_an_error() {
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            Arc::new(NoopSyncControl),
        );

        manager.start_catchup("1000#aaaa").await;
        let result = manager.abort_catchup("2000#bbbb").await;
        assert!(result.is_err());
        assert!(!cancel_observed.load(std::sync::atomic::Ordering::SeqCst));

        manager.abort_catchup("1000#aaaa").await.unwrap();
        wait_idle(&manager).await;
    }

    #[tokio::test]
    async fn abort_catchup_cancels_in_flight_run_and_resumes_control() {
        let control = Arc::new(CountingControl::default());
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            control.clone(),
        );

        manager.start_catchup("1000#deadbeef").await;
        assert_eq!(control.pauses.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 0);

        manager.abort_catchup("1000#deadbeef").await.unwrap();
        wait_idle(&manager).await;

        assert!(cancel_observed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        // An aborted run is not a "completed" catchup.
        assert_eq!(manager.last_catchpoint(), "");
    }

    // -- current_catchpoint / last_catchpoint --------------------------------

    #[tokio::test]
    async fn current_catchpoint_reflects_the_in_flight_label() {
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            Arc::new(NoopSyncControl),
        );

        assert_eq!(manager.current_catchpoint().await, None);
        manager.start_catchup("1000#deadbeef").await;
        assert_eq!(
            manager.current_catchpoint().await,
            Some("1000#deadbeef".to_string())
        );

        manager.abort_catchup("1000#deadbeef").await.unwrap();
        wait_idle(&manager).await;
        assert_eq!(manager.current_catchpoint().await, None);
    }

    #[tokio::test]
    async fn a_new_catchup_can_start_after_the_previous_one_finishes() {
        // Regression guard: the manager must not get permanently wedged
        // after a completed run — a fresh `start_catchup` for a different
        // label must succeed once the previous run has cleared state.
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());

        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;

        let manager2 = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        let result = manager2.start_catchup("2000#bbbb").await;
        assert_eq!(result, CatchupStartResult::Created);
        wait_idle(&manager2).await;

        assert_eq!(control.pauses.load(Ordering::SeqCst), 2);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 2);
    }
}
