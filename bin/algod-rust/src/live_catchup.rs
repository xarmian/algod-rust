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
//! (`catchup/catchpointService.go` @ `v5.0.1-stable`): a REST client can
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

/// How a live catchpoint catchup run ended when it did not fail (issue
/// #1725).
///
/// go-algorand's catchpoint service ends at the catchpoint round and its
/// normal catchup service closes the gap to the tip; it has no concept of a
/// replay that "stopped short". algod-rust's orchestrator can end its
/// post-catchpoint block replay early when the catchup peer cannot serve the
/// remaining rounds (issue #1719), so a successful run is one of these two
/// states, kept apart in logs, metrics and [`LiveCatchupManager`]'s own
/// bookkeeping. `GET /v2/status` is deliberately unchanged: go has no
/// counterpart field, and the node's normal catchup continues either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatchupOutcome {
    /// The catchpoint was applied and block replay reached its target.
    Complete,
    /// The catchpoint was applied and the ledger is consistent at
    /// `stopped_at_round`, but the peer could not serve the rest; normal
    /// catchup continues from there.
    StoppedShort {
        /// Last round applied to the ledger.
        stopped_at_round: u64,
        /// Round replay was trying to reach.
        target_round: u64,
    },
}

impl CatchupOutcome {
    /// Derive the outcome of a finished orchestrator run.
    pub fn from_sync_result(result: &algo_ledger::sync::SyncResult) -> Self {
        match &result.stopped_early {
            Some(stop) => Self::StoppedShort {
                stopped_at_round: stop.stopped_at_round,
                target_round: stop.target_round,
            },
            None => Self::Complete,
        }
    }
}

/// Finished-run bookkeeping behind [`LiveCatchupManager::metrics_text`] and
/// [`LiveCatchupManager::last_outcome`], kept in one struct under one lock so
/// the two can never be observed out of step.
#[derive(Debug, Clone, Default)]
struct CatchupStats {
    completed: u64,
    stopped_short: u64,
    last_outcome: Option<CatchupOutcome>,
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

    /// Reload any ledger handle this control owns from disk, after a live
    /// catchpoint catchup has finished importing (issue #1616).
    ///
    /// A live catchup writes through its own, separate database connection
    /// (see [`OrchestratorCatchupRunner::run`]'s `SyncOrchestrator`) --
    /// entirely independent of whatever long-lived `SqliteLedger` handle
    /// this control's `resume()` reads from. That handle's in-memory
    /// caches (current round, rewards state, account/trie/lease caches)
    /// are populated once at open time and never automatically notice a
    /// different connection's writes, so without an explicit reload here
    /// `resume()` would rebuild the normal sync loop against pre-catchup
    /// state forever -- the node made no further progress despite the
    /// ledger file on disk actually sitting at the new round (the
    /// round-65379680 mainnet soak halt).
    ///
    /// Called by [`LiveCatchupManager::drive`] after a successful run and
    /// before [`Self::resume`]. Default no-op for controls with nothing to
    /// reload (e.g. [`NoopSyncControl`], or test fakes with no real
    /// ledger).
    async fn reload_ledger(&self) {}
}

/// Resets a follower node's sync round when a live catchpoint catchup
/// finishes, mirroring go's `AlgorandFollowerNode.SetCatchpointCatchupMode
/// (false)` (`node/follower_node.go`), which calls
/// `node.SetSyncRound(node.ledger.LastRound())` before restarting the
/// normal catchup/block services — the behavior `TestFastCatchupResume`
/// (`node/follower_node_test.go`) pins (issue #951).
///
/// Optional: only `node start --follow <peer>` attaches one (via
/// [`LiveCatchupManager::set_sync_round_reset_hook`]), since only a
/// follower node has a sync round to reset in the first place.
#[async_trait]
pub trait SyncRoundResetHook: Send + Sync {
    /// Reset the sync round to the ledger's current last round.
    async fn reset_sync_round(&self);
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
    ///
    /// `abort` fires, before `cancel`, only when the user aborts the catchup
    /// (`DELETE /v2/catchup`): the run then discards its state, where a
    /// plain `cancel` (node shutdown) keeps it for the next start to resume
    /// (issue #2121; go `Abort` vs `Stop`).
    async fn run(
        &self,
        catchpoint: &str,
        cancel: CancellationToken,
        abort: CancellationToken,
        counters: Arc<StdMutex<CatchpointCounters>>,
    ) -> anyhow::Result<CatchupOutcome>;
}

/// How long node shutdown waits for an in-flight live catchup to observe its
/// cancellation and return ([`LiveCatchupManager::shutdown`], issue #2121).
/// Every blocking request ends at once on cancel; this bounds a phase that
/// only checks the token between steps (a catchpoint import, say).
///
/// # Shutdown budget
///
/// This covers only the waits the live catchup adds or affects, not a real
/// bound on the whole shutdown: `participate`'s other teardown joins (pool
/// follower, heartbeat, state-proof service, tx syncer, gossip stop) are
/// unbounded today (issue #2138 tracks one overall shutdown deadline).
/// `participate` runs these waits one after another:
///
/// | step | bound |
/// |---|---|
/// | this catchup stop | 5 s |
/// | the REST server drain (`REST_SHUTDOWN_HARD_CAP`) | 5 s |
/// | an in-flight automatic catchpoint export (`CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT`) | 30 s |
/// | `main`'s runtime drop (`RUNTIME_SHUTDOWN_TIMEOUT`) | 3 s |
///
/// - Normal case, the image smoke's included: well under a second. A
///   cancelled catchup returns at once, the REST drain is immediate, and no
///   export is pending (the export wait returns at once when none is).
/// - A live catchup that does not stop in time (a phase that checks the
///   token only between steps): 5 + 5 + 3 = 13 s, inside the smoke's 20 s
///   `docker stop` limit. `participate` skips the export wait then (see
///   [`LiveCatchupManager::shutdown`]), and the abandoned run's
///   import/verify keeps running through the remaining teardown on its own
///   database connection until `main`'s runtime drop ends the process: a
///   crash as far as its sync state goes, which the next start resumes.
/// - A pending automatic export: only a node in normal sync runs one, so
///   the catchup step is instant: at most 5 + 30 + 3 = 38 s. That pre-dates
///   issue #2121 (issue #794) and lets the newest catchpoint land; its
///   writes are atomic, so a container runtime that kills earlier leaves no
///   corrupt file.
pub const LIVE_CATCHUP_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Clears [`LiveCatchupManager`]'s `running` entry for run `generation` when
/// [`LiveCatchupManager::drive`] ends by an abnormal path (a panic in its
/// hand-back), so the manager is never left wedged "catching up" (issue
/// #2121). It never clears blindly: only an entry that is still this run's
/// (same generation) is removed, so a later run registered meanwhile is left
/// alone. The normal exit path clears the entry itself and disarms this.
struct ClearRunningOnDrop {
    manager: Arc<LiveCatchupManager>,
    generation: u64,
    armed: bool,
}

impl ClearRunningOnDrop {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ClearRunningOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let generation = self.generation;
        if let Ok(mut running) = self.manager.running.try_lock() {
            clear_if_generation(&mut running, generation);
        } else {
            // Someone holds the lock for a moment: clear it right after, still
            // only if the entry is this run's.
            let manager = Arc::clone(&self.manager);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    clear_if_generation(&mut *manager.running.lock().await, generation);
                });
            }
        }
    }
}

/// Remove `running`'s entry only if it belongs to run `generation`.
fn clear_if_generation(running: &mut Option<RunningCatchup>, generation: u64) {
    if running.as_ref().is_some_and(|r| r.generation == generation) {
        *running = None;
    }
}

/// `start_catchup`'s answer once the node is shutting down.
const SHUTTING_DOWN: &str = "the node is shutting down";

/// Undoes a reservation whose starter task ends abnormally (a panic in
/// `pause()`, or the runtime cancelling the task): removes the entry of run
/// `generation` (only that run's, never a later one's), and if normal sync
/// was already paused, resumes it, so the manager is never left wedged with
/// normal sync stopped (issue #2121). The normal paths disarm it.
struct ReservationGuard {
    manager: Arc<LiveCatchupManager>,
    generation: u64,
    paused: bool,
    armed: bool,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        drop(ClearRunningOnDrop {
            manager: Arc::clone(&self.manager),
            generation: self.generation,
            armed: true,
        });
        if self.paused && !self.manager.is_shutting_down() {
            let manager = Arc::clone(&self.manager);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move { manager.control.resume().await });
            }
        }
    }
}

/// Where a registered catchup is in its lifecycle (issue #2121). Each
/// phase holds the handle of the task that is doing the work at that point,
/// joined by [`LiveCatchupManager::shutdown`]; it is `None` once a shutdown
/// has taken it (and then timed out waiting for it).
enum Phase {
    /// `start_catchup` reserved the slot; its starter task is pausing
    /// normal sync and then spawns the run.
    Starting(Option<tokio::task::JoinHandle<()>>),
    /// The [`LiveCatchupManager::drive`] task runs the catchup.
    Running(Option<tokio::task::JoinHandle<()>>),
    /// The run itself has ended and the drive task is handing the node back
    /// to normal sync (reload, sync-round reset, resume). Like go, which
    /// keeps `catchpointCatchupService` set until
    /// `SetCatchpointCatchupMode(false)` clears it, the catchup is still
    /// reported and a new one cannot start until this is done; only
    /// `abort_catchup` treats it differently (a no-op for this label, since
    /// the run is over).
    HandingBack(Option<tokio::task::JoinHandle<()>>),
}

/// The registered catchup, if any.
struct RunningCatchup {
    /// Identifies this run: cleanup only ever removes the entry of the run
    /// doing it.
    generation: u64,
    catchpoint: String,
    cancel: CancellationToken,
    /// Fired (before `cancel`) by [`LiveCatchupManager::abort_catchup`] only,
    /// so the run discards its state instead of keeping it for a resume
    /// (issue #2121; go `Abort` vs `Stop`).
    abort: CancellationToken,
    phase: Phase,
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
    /// Successful-run counters and how the most recent one ended (issue
    /// #1725), under one lock; exported by [`Self::metrics_text`].
    stats: StdMutex<CatchupStats>,
    /// Live granular progress counters for the in-flight (or most recently
    /// finished) catchup — see [`Self::catchpoint_counters`] (issue #941).
    counters: Arc<StdMutex<CatchpointCounters>>,
    /// Optional follower-node sync-round reset hook (issue #951) — see
    /// [`SyncRoundResetHook`]. `None` for every command except `node start
    /// --follow <peer>`, which attaches one via
    /// [`Self::set_sync_round_reset_hook`] right after construction (the
    /// hook and this manager are built from the same `run_start` call but
    /// need each other, so it can't be threaded through [`Self::new`]
    /// without a circular constructor dependency).
    sync_round_reset: StdMutex<Option<Arc<dyn SyncRoundResetHook>>>,
    /// Set by [`Self::shutdown`]: no new catchup starts, and a run that ends
    /// does not resume the node's normal sync services (they are being
    /// stopped).
    shutting_down: std::sync::atomic::AtomicBool,
    /// Source of `RunningCatchup::generation`.
    next_generation: std::sync::atomic::AtomicU64,
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
            stats: StdMutex::new(CatchupStats::default()),
            counters: Arc::new(StdMutex::new(CatchpointCounters::default())),
            sync_round_reset: StdMutex::new(None),
            shutting_down: std::sync::atomic::AtomicBool::new(false),
            next_generation: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Stop for node shutdown (issue #2121), mirroring go's
    /// `AlgorandFullNode.Stop` stopping the catchpoint catchup service and
    /// waiting for its goroutines: cancel the in-flight run, if any, and wait
    /// up to `timeout` for it to return, so no catchup work still drives
    /// requests (and registers timers) on the runtime when it is dropped.
    /// Every blocking call of the run's backend ends at once on the
    /// cancellation, so this normally returns well under a second.
    ///
    /// After this no catchup starts, and a run that ends does not resume the
    /// normal sync services (see [`Self::drive`]).
    ///
    /// A catchup that is still starting (pausing normal sync) is waited for
    /// too, within the same timeout, so the teardown that follows never
    /// races `pause()` on the same services.
    ///
    /// Returns `false` when the run did not stop cleanly: on a timeout (a
    /// phase that only checks the token between steps, e.g. a catchpoint
    /// import, or a pause that does not end; the work is then still going,
    /// and a later call says so again) or when its task failed.
    /// The caller carries on with its teardown, which is safe because the
    /// catchup writes through its own database connection, never the node's
    /// shared ledger handle or the services torn down next, and once it does
    /// stop it does not resume them. The one step that should not overlap it
    /// is waiting for a catchpoint export of the ledger the import is
    /// replacing, so `participate` skips that wait on `false`. The bounded
    /// runtime shutdown in `main` then ends the process with the run
    /// abandoned mid-phase, which is a crash as far as the sync state is
    /// concerned: the orchestrator persists that state per phase and resumes
    /// from it on the next start.
    pub async fn shutdown(&self, timeout: std::time::Duration) -> bool {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + timeout;
        // (The lock is only ever held briefly: pausing normal sync happens on
        // the starter task, outside it.)
        loop {
            let (starter, task) = {
                let mut guard = self.running.lock().await;
                let Some(running) = guard.as_mut() else {
                    return true;
                };
                running.cancel.cancel();
                let (starter, slot) = match &mut running.phase {
                    Phase::Starting(slot) => (true, slot),
                    Phase::Running(slot) | Phase::HandingBack(slot) => (false, slot),
                };
                match slot.take() {
                    Some(task) => (starter, task),
                    // An earlier shutdown() timed out and took the handle:
                    // that work is still going.
                    None => return false,
                }
            };
            match tokio::time::timeout_at(deadline, task).await {
                // The starter finished pausing normal sync. It saw
                // `shutting_down` (raised above, before the lock) and gave up,
                // or, if it got there first, spawned the run: look again.
                Ok(Ok(())) if starter => continue,
                Ok(Ok(())) => return true,
                Ok(Err(e)) if e.is_cancelled() => {
                    // The runtime is going away under it: not a clean stop.
                    warn!(error = %e, "live catchpoint catchup task was cancelled during shutdown");
                    return false;
                }
                Ok(Err(e)) => {
                    // Not a clean stop: the task panicked (its entry is
                    // cleared by its drop guard).
                    tracing::error!(error = %e, "live catchpoint catchup task panicked during shutdown");
                    return false;
                }
                Err(_) => {
                    warn!(
                        ?timeout,
                        starting = starter,
                        "live catchpoint catchup did not stop within the shutdown timeout; continuing the shutdown without it"
                    );
                    return false;
                }
            }
        }
    }

    fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Attach a [`SyncRoundResetHook`] so a finished catchup resets the
    /// follower node's sync round (issue #951), mirroring go's
    /// `SetCatchpointCatchupMode(false)`. Idempotent — a later call
    /// replaces any previously attached hook.
    pub fn set_sync_round_reset_hook(&self, hook: Arc<dyn SyncRoundResetHook>) {
        if let Ok(mut guard) = self.sync_round_reset.lock() {
            *guard = Some(hook);
        }
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
        if self.is_shutting_down() {
            return CatchupStartResult::StartError(SHUTTING_DOWN.to_string());
        }
        if let Some(running) = guard.as_ref() {
            // (In every phase, the hand-back included, as go answers until
            // `SetCatchpointCatchupMode(false)` clears its service.)
            if running.catchpoint == catchpoint {
                return CatchupStartResult::AlreadyInProgress;
            }
            return CatchupStartResult::Unable(format!(
                "unable to start catchup for '{catchpoint}' - already catching up '{}'",
                running.catchpoint
            ));
        }

        // Reserve the slot (so a concurrent start sees this catchup) and hand
        // the slow part, pausing normal sync, to a starter task: status,
        // abort and shutdown never wait on it (issue #2121), and a caller that
        // goes away mid-pause (a client disconnect, a request timeout) cannot
        // leave the slot reserved with normal sync half-paused. The accepted
        // request completes regardless, as go's `StartCatchup` does.
        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cancel = CancellationToken::new();
        let abort = CancellationToken::new();
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let starter = {
            let manager = Arc::clone(self);
            let catchpoint = catchpoint.to_string();
            let (cancel, abort) = (cancel.clone(), abort.clone());
            tokio::spawn(async move {
                let outcome = manager
                    .start_run(generation, catchpoint, cancel, abort)
                    .await;
                let _ = outcome_tx.send(outcome);
            })
        };
        *guard = Some(RunningCatchup {
            generation,
            catchpoint: catchpoint.to_string(),
            cancel,
            abort,
            phase: Phase::Starting(Some(starter)),
        });
        drop(guard);

        outcome_rx.await.unwrap_or_else(|_| {
            CatchupStartResult::StartError(
                "the catchpoint catchup could not be started".to_string(),
            )
        })
    }

    /// The starter task of run `generation` (issue #2121): pause normal sync,
    /// then spawn the run, unless the node started shutting down meanwhile.
    async fn start_run(
        self: Arc<Self>,
        generation: u64,
        catchpoint: String,
        cancel: CancellationToken,
        abort: CancellationToken,
    ) -> CatchupStartResult {
        let mut reservation = ReservationGuard {
            manager: Arc::clone(&self),
            generation,
            paused: false,
            armed: true,
        };

        // Pause the node's normal sync loop before starting, mirroring
        // `processStageInactive`'s `updateNodeCatchupMode(true)` call —
        // go performs this at the *start* of the fetch state machine, not
        // before it, but the net effect (no other writer once ledger
        // download begins) is the same and simpler to reason about here
        // since `SyncOrchestrator` doesn't expose a mid-run pause hook.
        self.control.pause().await;
        reservation.paused = true;

        // Reset progress counters for the new run — mirrors go building a
        // fresh `CatchpointCatchupStats{}` per `CatchpointCatchupService`
        // instance (`MakeResumedCatchpointCatchupService`).
        if let Ok(mut counters) = self.counters.lock() {
            *counters = CatchpointCounters::default();
        }

        // Spawn under the lock, after a final shutdown check: a shutdown
        // raises its flag before taking the lock, so either it finds the run
        // here and joins it, or this sees the flag and never starts.
        let mut guard = self.running.lock().await;
        reservation.armed = false;
        let ours = guard.as_ref().is_some_and(|r| r.generation == generation);
        if self.is_shutting_down() || !ours {
            clear_if_generation(&mut guard, generation);
            return CatchupStartResult::StartError(SHUTTING_DOWN.to_string());
        }
        let manager = Arc::clone(&self);
        let task = tokio::spawn(async move {
            manager.drive(generation, catchpoint, cancel, abort).await;
        });
        if let Some(running) = guard.as_mut() {
            running.phase = Phase::Running(Some(task));
        }
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
            Some(running) if running.catchpoint != catchpoint => Err(format!(
                "unable to abort catchpoint catchup for '{catchpoint}' - already catching up '{}'",
                running.catchpoint
            )),
            Some(running) => {
                match running.phase {
                    // The run already ended (go: `Abort()` on a finished
                    // service).
                    Phase::HandingBack(_) => {}
                    // go `Abort()`: the abort flag first, then the
                    // cancellation the run's stages wait on (issue #2121). A
                    // starting run is spawned with both already fired.
                    Phase::Starting(_) | Phase::Running(_) => {
                        running.abort.cancel();
                        running.cancel.cancel();
                    }
                }
                Ok(())
            }
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

    /// The most recently *applied* catchpoint label (empty if none has
    /// been applied yet), tracked purely as this manager's own internal
    /// bookkeeping. Set for a [`CatchupOutcome::StoppedShort`] run too: the
    /// catchpoint itself was applied there and only the follow-on replay
    /// stopped short (issue #1725; see [`Self::last_outcome`]).
    ///
    /// No longer backs `GET /v2/status`'s `last-catchpoint` field (issue
    /// #827 theme 4): go's own `LastCatchpoint` (`node/node.go`) is
    /// populated only from `ledger.GetLastCatchpointLabel()` -- the
    /// ledger's self-generated-catchpoint bookkeeping -- never from a
    /// completed *download*, so `AlgodNodeInterface::status` now reads
    /// `SqliteLedger::last_catchpoint_label` directly instead of this
    /// method. Kept `pub` and still exercised directly by this module's
    /// own tests, since the underlying state is genuinely useful for a
    /// caller that wants to know "did my own `start_catchup` call
    /// succeed" without going through `NodeStatus`.
    #[allow(dead_code)]
    pub fn last_catchpoint(&self) -> String {
        self.last_catchpoint
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// How the most recent successful run ended, or `None` if none has
    /// (issue #1725). Internal bookkeeping only: `GET /v2/status` is
    /// unchanged because go-algorand has no counterpart (its catchpoint
    /// service ends at the catchpoint round).
    #[cfg(test)]
    pub fn last_outcome(&self) -> Option<CatchupOutcome> {
        self.stats.lock().ok().and_then(|g| g.last_outcome.clone())
    }

    /// Prometheus text for finished live catchups (issue #1725); empty until
    /// one has finished, so a node that never ran a live catchup adds nothing
    /// to `/metrics`.
    pub fn metrics_text(&self) -> String {
        // One lock for the counters AND the last outcome: a scrape never sees
        // a counter bumped without its outcome (or vice versa).
        let CatchupStats {
            completed,
            stopped_short,
            last_outcome,
        } = self.stats.lock().map(|g| g.clone()).unwrap_or_default();
        if completed + stopped_short == 0 {
            return String::new();
        }
        // Rounds the last successful run's replay fell short of its target
        // by; 0 when it reached the target.
        let behind = match last_outcome {
            Some(CatchupOutcome::StoppedShort {
                stopped_at_round,
                target_round,
            }) => target_round.saturating_sub(stopped_at_round),
            _ => 0,
        };
        let mut out = String::new();
        for (name, kind, help, value) in [
            (
                "algod_rust_catchpoint_catchup_completed_total",
                "counter",
                "Live catchpoint catchups whose replay reached its target.",
                completed,
            ),
            (
                "algod_rust_catchpoint_catchup_stopped_short_total",
                "counter",
                "Live catchpoint catchups whose replay stopped short of its target (normal catchup continues).",
                stopped_short,
            ),
            (
                "algod_rust_catchpoint_catchup_stopped_short_behind_rounds",
                "gauge",
                "Rounds the most recent successful live catchup stopped short of its target by (0 if it reached it).",
                behind,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}
# TYPE {name} {kind}
{name} {value}
"
            ));
        }
        out
    }

    fn set_last_catchpoint(&self, catchpoint: &str) {
        if let Ok(mut last) = self.last_catchpoint.lock() {
            *last = catchpoint.to_string();
        }
    }

    /// Count a successful run and remember how it ended, atomically.
    fn record_outcome(&self, outcome: CatchupOutcome) {
        if let Ok(mut stats) = self.stats.lock() {
            match outcome {
                CatchupOutcome::Complete => stats.completed += 1,
                CatchupOutcome::StoppedShort { .. } => stats.stopped_short += 1,
            }
            stats.last_outcome = Some(outcome);
        }
    }

    /// Runs the catchup to completion/cancellation/error, then clears the
    /// running state and resumes normal operation — mirroring go's
    /// `processStageSwitch`/`abort` both calling
    /// `updateNodeCatchupMode(false)` on the way out, regardless of
    /// success or failure.
    async fn drive(
        self: Arc<Self>,
        generation: u64,
        catchpoint: String,
        cancel: CancellationToken,
        abort: CancellationToken,
    ) {
        // Clears this run's `running` entry on an abnormal exit (a panic);
        // the normal paths below clear it themselves (issue #2121).
        let mut clear_running = ClearRunningOnDrop {
            manager: Arc::clone(&self),
            generation,
            armed: true,
        };
        // Run on a task of its own, so a panicking runner ends as an error
        // and the hand-back below still resumes normal sync.
        let run = {
            let runner = Arc::clone(&self.runner);
            let catchpoint = catchpoint.clone();
            let counters = Arc::clone(&self.counters);
            tokio::spawn(async move { runner.run(&catchpoint, cancel, abort, counters).await })
        };
        let result = match run.await {
            Ok(result) => result,
            Err(e) if e.is_panic() => {
                tracing::error!(catchpoint = %catchpoint, error = %e, "live catchpoint catchup runner panicked");
                Err(anyhow::anyhow!(
                    "live catchpoint catchup runner panicked: {e}"
                ))
            }
            // Cancelled, not panicked: the runtime is shutting down.
            Err(e) => {
                info!(catchpoint = %catchpoint, error = %e, "live catchpoint catchup runner task cancelled");
                Err(anyhow::anyhow!(
                    "live catchpoint catchup runner task cancelled: {e}"
                ))
            }
        };
        // The run is over; the hand-back below follows (issue #2121).
        if let Some(running) = self
            .running
            .lock()
            .await
            .as_mut()
            .filter(|r| r.generation == generation)
        {
            if let Phase::Running(task) = &mut running.phase {
                running.phase = Phase::HandingBack(task.take());
            }
        }
        match &result {
            Ok(CatchupOutcome::Complete) => {
                info!(catchpoint = %catchpoint, "live catchpoint catchup completed");
                self.set_last_catchpoint(&catchpoint);
                self.record_outcome(CatchupOutcome::Complete);
            }
            // Issue #1725: the catchpoint itself WAS applied (so
            // `last_catchpoint` is set as before) but block replay stopped
            // short of the tip. Log and count that apart from a completed
            // catchup; the node's normal catchup, resumed below, closes the
            // gap.
            Ok(CatchupOutcome::StoppedShort {
                stopped_at_round,
                target_round,
            }) => {
                warn!(
                    catchpoint = %catchpoint,
                    stopped_at_round,
                    target_round,
                    "live catchpoint catchup stopped short at round {stopped_at_round} \
                     (target {target_round}); normal catchup continues"
                );
                self.set_last_catchpoint(&catchpoint);
                self.record_outcome(CatchupOutcome::StoppedShort {
                    stopped_at_round: *stopped_at_round,
                    target_round: *target_round,
                });
            }
            Err(e) if self.is_shutting_down() => {
                info!(catchpoint = %catchpoint, error = %e, "live catchpoint catchup stopped for shutdown");
            }
            Err(e) => {
                warn!(catchpoint = %catchpoint, error = %e, "live catchpoint catchup failed");
            }
        }

        // Issue #2121: the hand-back (reload, sync-round reset, resume) runs
        // WITHOUT the `running` lock, so `GET /v2/status`, `start_catchup` and
        // `abort_catchup` answer while it is in progress; `running` (and with
        // it this task's handle) is cleared only at its very end. A shutdown
        // that lands meanwhile finds the run still registered, takes the
        // handle and waits for this task inside its own timeout, and the
        // shutting-down flag is re-checked right before `resume()`, so a
        // shutdown that has begun is never answered by restarting the
        // services it is stopping.
        //
        // Node shutdown: the services `resume()` would restart are being
        // stopped, so only clear the running state.
        if self.is_shutting_down() {
            clear_if_generation(&mut *self.running.lock().await, generation);
            clear_running.disarm();
            return;
        }

        // Issue #1616 established that the catchup wrote through its own
        // DB connection, so the normal sync loop's ledger handle must be
        // explicitly reloaded before `resume()` rebuilds anything against
        // it. Issue #1647's evidence (mainnet-node-soak run 36539158300)
        // showed that reload must happen unconditionally, not only on
        // `Ok(())`: `SyncOrchestrator::run` can return `Err` *after* its
        // catchpoint import has already cutover and been finalized on
        // disk (`catchpoint cutover finalized: pre-cutover backups
        // dropped` in the log) -- e.g. a later, independent phase like
        // "download lookback blocks for lease reconstruction" failing
        // against a peer that no longer serves an old-enough block. When
        // that happens the on-disk ledger genuinely is at the new round,
        // but skipping the reload left the in-process ledger handle
        // (and therefore the rebuilt agreement/catchup cycle) stuck at
        // its stale pre-catchup round -- observed live as the node
        // resuming consensus participation at `latest_round=0` and
        // retrying round-by-round genesis catchup forever, i.e. exactly
        // the "zero follow-mode progress after a clean catchpoint
        // import" symptom #1647 reported. Reloading is safe even when
        // nothing was actually committed (download/verify failed before
        // any cutover): it just reopens the same, unchanged ledger file.
        self.control.reload_ledger().await;

        // Reset the follower node's sync round before resuming normal
        // operation, regardless of success/failure/abort — mirrors go's
        // `processStageSwitch`/`abort` both calling
        // `updateNodeCatchupMode(false)` (which resets the sync round via
        // `SetCatchpointCatchupMode(false)`) unconditionally on the way
        // out (issue #951, `TestFastCatchupResume`).
        let reset_hook = self
            .sync_round_reset
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(hook) = reset_hook {
            hook.reset_sync_round().await;
        }

        if !self.is_shutting_down() {
            self.control.resume().await;
        }
        clear_if_generation(&mut *self.running.lock().await, generation);
        clear_running.disarm();
    }
}

// ---------------------------------------------------------------------------
// Production CatchupRunner — backed by SyncOrchestrator
// ---------------------------------------------------------------------------

/// Static parameters needed to run a catchpoint catchup against a peer,
/// resolved once at node startup (algod URL/token, genesis identity, the
/// ledger's on-disk prefix).
#[derive(Clone)]
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
    /// The node's live, running P2P transport, if P2P is enabled and
    /// connected (issue #1130) — every currently-connected peer is added to
    /// the same ranked catchpoint-file candidate pool `catchpoint_peer_urls`
    /// populates, routed over `/algorand-http/1.0.0` instead of plain HTTP.
    /// `None` when P2P isn't enabled (`NetworkMode::WsOnly`, the default) or
    /// the call site has no P2P transport to offer (e.g. `node start
    /// --follow`, which doesn't run a P2P transport at all yet) — in both
    /// cases catchpoint download stays exactly as it was before this issue,
    /// HTTP-peer-only.
    pub p2p_transport: Option<Arc<crate::commands::p2p_transport::P2pTransport>>,
}

// `P2pTransport` deliberately does not implement `Debug` (it owns a
// background swarm-driving task and several mutex-guarded live-state
// fields not meaningful to print), so `LiveCatchupParams` can't `derive`
// `Debug` — this manual impl reports only whether a P2P transport is
// attached, mirroring how a bare `Option<T: !Debug>` field would normally
// be elided from a derived impl.
impl std::fmt::Debug for LiveCatchupParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCatchupParams")
            .field("algod_url", &self.algod_url)
            .field("algod_token", &self.algod_token)
            .field("db_path", &self.db_path)
            .field("genesis_id", &self.genesis_id)
            .field("genesis_hash", &self.genesis_hash)
            .field("concurrency", &self.concurrency)
            .field("catchpoint_peer_urls", &self.catchpoint_peer_urls)
            .field("p2p_transport", &self.p2p_transport.is_some())
            .finish()
    }
}

/// Production [`CatchupRunner`]: builds a
/// [`algo_ledger::sync::SyncOrchestrator`] against [`LiveCatchupParams`]
/// and drives it to completion, exactly like `commands/catchpoint_sync.rs`'s
/// standalone CLI path, but callable in-process from a live node.
pub struct OrchestratorCatchupRunner {
    params: LiveCatchupParams,
}

/// Bounded retry budget for a catchup attempt that fails specifically at
/// the verification phase (issue #1636): the first attempt plus this many
/// extra retries, each against a peer the previous failure's data came
/// from having just been deprioritized (via
/// [`SyncBackend::rank_last_catchpoint_peer_down`]).
///
/// Deliberately small and fixed — this is a defensive mitigation for a
/// bad/corrupted download from one specific peer, not a general-purpose
/// unbounded retry loop, and it does not touch the verification logic
/// itself. go-algorand's equivalent (`catchup/catchpointService.go`'s
/// `processStageLedgerDownload`) retries `BuildMerkleTrie` failures up to
/// `Config.CatchupLedgerDownloadRetryAttempts` (default 50) times, ranking
/// the failing peer down each time; algod-rust's verification pass is a
/// single, much more expensive (tens-of-minutes, whole-mainnet-scale)
/// operation rather than go's incremental per-chunk trie build, so retrying
/// anywhere near that many times is impractical here — a small fixed cap
/// is the pragmatic analogue.
const MAX_VERIFY_FAILURE_RETRIES: u32 = 2;

/// Classify a [`algo_ledger::sync::SyncOrchestrator::run`] error message as
/// specifically a catchpoint-verification failure (issue #1636), as opposed
/// to a download/import/lookback/replay failure.
///
/// `SyncOrchestrator::run` always transitions its *state* to
/// `SyncState::Failed(msg)` on any phase error — every state can transition
/// to `Failed` (`crates/core/algo-ledger/src/sync/state_machine.rs`) — so by
/// the time `run()` returns `Err`, `orchestrator.state()` is never left at
/// `SyncState::VerifyingLedger` itself; checking the state enum variant
/// alone (an earlier version of this function did exactly that) therefore
/// never matches a real failure and silently disables the retry entirely.
/// Live-dispatch evidence (`mainnet-node-soak.yml` run 36295601322, PR
/// #1638) confirmed this: the rollback in `run_verify_ledger` fired
/// correctly, but no second download/verify attempt was ever made. The
/// error *message* `run_verify_ledger` produces
/// (`crates/core/algo-ledger/src/sync/mod.rs`) is the only reliable signal
/// left, so match on that instead.
fn is_verify_failure_message(msg: &str) -> bool {
    msg.contains("catchpoint label mismatch") || msg.contains("catchpoint verification failed")
}

/// A thin [`SyncBackend`] wrapper that delegates every call to a shared,
/// reference-counted inner backend.
///
/// [`SyncOrchestrator::with_backend`] takes ownership of the backend it's
/// given, so a fresh [`SyncOrchestrator`] has to be constructed per retry
/// attempt — but the whole point of a verify-failure retry is for the
/// *same* peer-ranking state (in particular,
/// [`SyncBackend::rank_last_catchpoint_peer_down`]'s effect) to carry over
/// from one attempt to the next. Wrapping the backend in an `Arc` and handing
/// out cheap clones of this wrapper lets each attempt get its own
/// orchestrator while all attempts still share one backend instance.
struct SharedSyncBackend(Arc<dyn algo_ledger::sync::SyncBackend>);

impl algo_ledger::sync::SyncBackend for SharedSyncBackend {
    fn is_noop(&self) -> bool {
        self.0.is_noop()
    }

    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> anyhow::Result<(), algo_error::AlgoError> {
        self.0.download_catchpoint(genesis_id, round, dest_path)
    }

    fn rank_last_catchpoint_peer_down(&self) {
        self.0.rank_last_catchpoint_peer_down();
    }

    fn fetch_block_raw(
        &self,
        round: u64,
    ) -> anyhow::Result<(String, Vec<u8>, Vec<u8>), algo_error::AlgoError> {
        self.0.fetch_block_raw(round)
    }

    fn fetch_block(&self, round: u64) -> anyhow::Result<algo_types::Block, algo_error::AlgoError> {
        self.0.fetch_block(round)
    }

    fn get_current_round(&self) -> anyhow::Result<u64, algo_error::AlgoError> {
        self.0.get_current_round()
    }

    fn discover_catchpoint(&self) -> anyhow::Result<Option<String>, algo_error::AlgoError> {
        self.0.discover_catchpoint()
    }

    fn fetch_block_range(
        &self,
        start: u64,
        end: u64,
        concurrency: usize,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> algo_ledger::sync::BatchFetch {
        self.0.fetch_block_range(start, end, concurrency, cancel)
    }
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
        abort: CancellationToken,
        counters: Arc<StdMutex<CatchpointCounters>>,
    ) -> anyhow::Result<CatchupOutcome> {
        use algo_ledger::sync::{SyncConfig, SyncOrchestrator};

        let backend: Arc<dyn algo_ledger::sync::SyncBackend> =
            Arc::new(crate::commands::catchpoint_sync::build_algod_sync_backend(
                &self.params.algod_url,
                &self.params.algod_token,
                &self.params.catchpoint_peer_urls,
                self.params.p2p_transport.as_ref(),
                // Live catchup has no `config.json`-carrying params struct of
                // its own to source real `MaxCatchpointDownloadDuration`/
                // `MinCatchpointFileDownloadBytesPerSecond`/
                // `CatchupLedgerDownloadRetryAttempts` values from yet (mirrors
                // `accounts_rebuild_synchronous_mode: 0` and
                // `DEFAULT_CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS` below, issue
                // #1289) — these defaults already match go's own defaults, so
                // this is still real, bounded behavior rather than a no-op.
                algo_rest_client::CatchpointDownloadConfig::default(),
                algo_rest_client::RankedCatchpointSource::DEFAULT_LEDGER_DOWNLOAD_RETRY_ATTEMPTS,
                crate::commands::catchpoint_sync::network_name_for_genesis_id(
                    &self.params.genesis_id,
                ),
                &self.params.genesis_id,
                // Issue #2121: the backend's blocking calls end at once when
                // the run is cancelled (node shutdown, abort).
                &cancel,
            ));

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
            // Live catchup has no `config.json`-carrying params struct of
            // its own to source a real value from yet (mirrors
            // `accounts_rebuild_synchronous_mode: 0` above) — the go
            // default (`Config.CatchupBlockDownloadRetryAttempts`, issue
            // #1287) is still a real bounded-retry-then-abort budget rather
            // than the previous unbounded-retry behavior.
            catchup_block_download_retry_attempts:
                algo_ledger::catchpoint::DEFAULT_CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS,
            handoff_min_lag_rounds: crate::commands::catchpoint_sync::sync_tuning()
                .handoff_min_lag_rounds,
        };

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let mut orchestrator = SyncOrchestrator::with_backend(
                config.clone(),
                SharedSyncBackend(Arc::clone(&backend)),
            );
            orchestrator.set_cancel(cancel.clone());
            orchestrator.set_abort(abort.clone());
            // Mirror the eight `catchpoint_*` counters from `SyncProgress` into
            // the shared sink `LiveCatchupManager::catchpoint_counters()` reads
            // (issue #941), on every progress notification (state transitions
            // and periodic within-phase updates).
            let counters_for_callback = Arc::clone(&counters);
            orchestrator.set_progress_callback(Box::new(move |progress| {
                if let Ok(mut c) = counters_for_callback.lock() {
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

            match orchestrator.run().await {
                Ok(result) => {
                    // Issue #1719: `Ok` means the catchpoint cutover is done
                    // and the ledger is consistent -- not that it reached the
                    // tip. If the peer could not serve the rest, say so
                    // explicitly (issue #1725): the node's normal catchup
                    // continues from `stopped_at_round`, and the manager
                    // records this as a stopped-short outcome, not a
                    // completed catchup.
                    return Ok(CatchupOutcome::from_sync_result(&result));
                }
                Err(e) => {
                    // `SyncOrchestrator::run` always transitions to
                    // `SyncState::Failed(msg)` on any phase error (any state
                    // can transition to `Failed` — `state_machine.rs`), so
                    // `orchestrator.state()` is never left at
                    // `VerifyingLedger` itself by the time `run()` returns;
                    // the only way to tell a verify-specific failure apart
                    // from a download/import/lookback/replay one is the
                    // error message `run_verify_ledger` produces
                    // (`"catchpoint label mismatch: ..."` or
                    // `"catchpoint verification failed: ..."`, both from
                    // `crates/core/algo-ledger/src/sync/mod.rs`). Any other
                    // failure kind is left exactly as before — no retry, no
                    // peer-ranking change.
                    let is_verify_failure = is_verify_failure_message(&e.to_string());
                    if is_verify_failure && attempt < MAX_VERIFY_FAILURE_RETRIES {
                        warn!(
                            catchpoint,
                            attempt,
                            max_attempts = MAX_VERIFY_FAILURE_RETRIES,
                            error = %e,
                            "catchpoint verification failed — deprioritizing the serving peer \
                             and retrying with a fresh download"
                        );
                        backend.rank_last_catchpoint_peer_down();
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }
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

    // -----------------------------------------------------------------------
    // is_verify_failure_message
    // -----------------------------------------------------------------------

    /// Regression pin for the classification bug live-dispatch found (PR
    /// #1638, run 36295601322): the retry must actually fire for the real
    /// error messages `run_verify_ledger` produces, not just an
    /// SyncState-based check that never matches by the time `run()` returns.
    #[test]
    fn is_verify_failure_message_matches_label_mismatch() {
        let msg = "ledger error: catchpoint label mismatch: expected \
                    '65420000#JX3S4TJ3BM656U7ZF7ATZSA7M2LTIY75BNH3GXIWENDNEPG5WHFQ', computed \
                    '65420000#5GSVZ5PS3XKT5SQHGDCRTCR3O3JYLVGPIBN7NOJN6GLDU24T6SFQ'";
        assert!(is_verify_failure_message(msg));
    }

    #[test]
    fn is_verify_failure_message_matches_verification_error() {
        let msg = "ledger error: catchpoint verification failed: some inner error";
        assert!(is_verify_failure_message(msg));
    }

    #[test]
    fn is_verify_failure_message_rejects_other_failure_kinds() {
        assert!(!is_verify_failure_message(
            "ledger error: catchpoint import failed: truncated file"
        ));
        assert!(!is_verify_failure_message(
            "network error: connection refused"
        ));
        assert!(!is_verify_failure_message(
            "ledger error: block header digest not available — import phase did not complete"
        ));
    }

    /// A [`NormalSyncControl`] fake that counts pause/resume/reload calls
    /// and tracks whether it's currently "paused", so tests can assert the
    /// manager pauses before starting and resumes after finishing, and
    /// (issue #1616) reloads the ledger exactly when a run actually
    /// completed successfully.
    #[derive(Default)]
    struct CountingControl {
        pauses: AtomicU32,
        resumes: AtomicU32,
        reloads: AtomicU32,
        /// Records the reload/resume call order (`"reload"`/`"resume"`)
        /// so a test can assert `reload_ledger` runs strictly before
        /// `resume`, not merely "also gets called somewhere".
        order: StdMutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl NormalSyncControl for CountingControl {
        async fn pause(&self) {
            self.pauses.fetch_add(1, Ordering::SeqCst);
        }
        async fn resume(&self) {
            self.resumes.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut order) = self.order.lock() {
                order.push("resume");
            }
        }
        async fn reload_ledger(&self) {
            self.reloads.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut order) = self.order.lock() {
                order.push("reload");
            }
        }
    }

    /// A [`CatchupRunner`] fake that completes immediately with a
    /// configurable result, recording the catchpoint label and whether it
    /// observed cancellation.
    struct ImmediateRunner {
        result: StdMutex<Option<Result<CatchupOutcome, String>>>,
    }

    impl ImmediateRunner {
        fn ok() -> Arc<Self> {
            Self::outcome(CatchupOutcome::Complete)
        }
        fn outcome(outcome: CatchupOutcome) -> Arc<Self> {
            Arc::new(Self {
                result: StdMutex::new(Some(Ok(outcome))),
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
            _abort: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<CatchupOutcome> {
            match self.result.lock().unwrap().take() {
                Some(Ok(outcome)) => Ok(outcome),
                None => Ok(CatchupOutcome::Complete),
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
            _abort: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<CatchupOutcome> {
            cancel.cancelled().await;
            self.cancel_observed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // Mirrors `SyncOrchestrator::run` returning an error on
            // cancellation (`sync/mod.rs`'s `handle_cancellation`) — a
            // cancelled run is not a "completed" catchup.
            Err(anyhow::anyhow!("sync cancelled by user"))
        }
    }

    /// A [`CatchupRunner`] fake that blocks until `cancel` fires and
    /// records whether it was an abort (the `abort` token had fired first).
    struct StopReasonRunner {
        aborted: Arc<StdMutex<Option<bool>>>,
    }

    #[async_trait]
    impl CatchupRunner for StopReasonRunner {
        async fn run(
            &self,
            _catchpoint: &str,
            cancel: CancellationToken,
            abort: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<CatchupOutcome> {
            cancel.cancelled().await;
            *self.aborted.lock().unwrap() = Some(abort.is_cancelled());
            Err(anyhow::anyhow!("sync cancelled by user"))
        }
    }

    /// Polls until no catchup is registered at all, the hand-back included
    /// (i.e. the manager has returned to idle), bounded so a bug can't hang
    /// the test suite.
    async fn wait_idle(manager: &LiveCatchupManager) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            // Fully idle: the hand-back is over too.
            if manager.running.lock().await.is_none() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "manager did not return to idle in time"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // -- shutdown (issue #2121) ---------------------------------------------

    /// Node shutdown must cancel the in-flight run and wait for it to
    /// return, so no catchup work outlives the runtime, and must not resume
    /// the normal sync services the node is stopping.
    #[tokio::test]
    async fn shutdown_cancels_and_joins_the_running_catchup_without_resuming() {
        let control = Arc::new(CountingControl::default());
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            control.clone(),
        );
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );

        assert!(manager.shutdown(Duration::from_secs(5)).await);

        // Joined, not merely signalled: the run already returned.
        assert!(cancel_observed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(manager.current_catchpoint().await, None);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 0);
        assert_eq!(control.reloads.load(Ordering::SeqCst), 0);
        // No catchup starts once the node is shutting down.
        assert!(matches!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::StartError(_)
        ));
        assert_eq!(control.pauses.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_with_no_running_catchup_returns_at_once() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        let started = std::time::Instant::now();
        assert!(manager.shutdown(Duration::from_secs(5)).await);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown() with nothing running took {:?}",
            started.elapsed()
        );
        assert_eq!(control.resumes.load(Ordering::SeqCst), 0);
    }

    /// A [`NormalSyncControl`] whose `reload_ledger` (`gate_resume: false`)
    /// or `resume` (`gate_resume: true`) announces itself on `entered` and
    /// then blocks until `release`, so a test can land `shutdown()` exactly
    /// inside the run's hand-back (issue #2121).
    struct GatedControl {
        gate_resume: bool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        reloads: AtomicU32,
        resumes: AtomicU32,
    }

    impl GatedControl {
        fn new(gate_resume: bool) -> Arc<Self> {
            Arc::new(Self {
                gate_resume,
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                reloads: AtomicU32::new(0),
                resumes: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl NormalSyncControl for GatedControl {
        async fn pause(&self) {}
        async fn resume(&self) {
            if self.gate_resume {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.resumes.fetch_add(1, Ordering::SeqCst);
        }
        async fn reload_ledger(&self) {
            if !self.gate_resume {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.reloads.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_shutting_down(manager: &LiveCatchupManager) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !manager.is_shutting_down() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "shutdown never started"
            );
            tokio::task::yield_now().await;
        }
    }

    /// A shutdown that lands while a finished run is handing back (here,
    /// reloading the ledger) must keep the run from resuming the services
    /// the node is stopping. Before the fix the run had checked the flag
    /// before the reload and went on to resume them.
    #[tokio::test]
    async fn shutdown_during_the_hand_back_skips_the_resume() {
        let control = GatedControl::new(false);
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        control.entered.notified().await;

        let shutdown = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.shutdown(Duration::from_secs(5)).await })
        };
        wait_shutting_down(&manager).await;
        control.release.notify_one();
        shutdown.await.unwrap();
        // shutdown() returned, and the hand-back is over (the run cleared
        // its state), without a resume.
        wait_idle(&manager).await;
        assert_eq!(control.reloads.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 0);
    }

    /// A shutdown that lands while the run is already resuming the services
    /// must not return before that resume is over, so the node's teardown
    /// that follows stops what was resumed. Before the fix the run cleared
    /// its state first, so shutdown() saw nothing running and returned at
    /// once, with the resume still in flight.
    #[tokio::test]
    async fn shutdown_during_the_resume_waits_for_it() {
        let control = GatedControl::new(true);
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        control.entered.notified().await;

        let mut shutdown = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.shutdown(Duration::from_secs(5)).await })
        };
        wait_shutting_down(&manager).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut shutdown)
                .await
                .is_err(),
            "shutdown() returned while the resume was still running"
        );
        control.release.notify_one();
        shutdown.await.unwrap();
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        assert_eq!(manager.current_catchpoint().await, None);
    }

    /// The hand-back holds no lock: while it is in progress (here, a slow
    /// ledger reload) every call answers at once, and as in go (which keeps
    /// its catchup service set until `SetCatchpointCatchupMode(false)`)
    /// `current_catchpoint()` still reports the label, `start_catchup` gives
    /// "already in progress" for that label and "unable" for another, and
    /// `abort_catchup` is a no-op for that label and an error for another.
    #[tokio::test]
    async fn status_start_and_abort_answer_promptly_during_the_hand_back() {
        let control = GatedControl::new(false);
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        control.entered.notified().await;

        let status = tokio::time::timeout(Duration::from_secs(1), manager.current_catchpoint())
            .await
            .expect("current_catchpoint() blocked behind the hand-back");
        assert_eq!(status.as_deref(), Some("1000#deadbeef"));
        let same = tokio::time::timeout(
            Duration::from_secs(1),
            manager.start_catchup("1000#deadbeef"),
        )
        .await
        .expect("start_catchup() blocked behind the hand-back");
        assert_eq!(same, CatchupStartResult::AlreadyInProgress);
        let other =
            tokio::time::timeout(Duration::from_secs(1), manager.start_catchup("2000#other"))
                .await
                .expect("start_catchup() blocked behind the hand-back");
        assert!(matches!(other, CatchupStartResult::Unable(_)), "{other:?}");
        tokio::time::timeout(
            Duration::from_secs(1),
            manager.abort_catchup("1000#deadbeef"),
        )
        .await
        .expect("abort_catchup() blocked behind the hand-back")
        .expect("aborting the label that just ran is a no-op during the hand-back");
        // Any other label still gets go's "unable to abort" error.
        let other = manager
            .abort_catchup("2000#other")
            .await
            .expect_err("a different label must be rejected during the hand-back");
        assert!(
            other.contains("unable to abort catchpoint catchup for '2000#other'"),
            "{other}"
        );

        control.release.notify_one();
        wait_idle(&manager).await;
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        // Once handed back, the catchup can start again.
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
    }

    /// shutdown() waits for a slow hand-back only within its own timeout
    /// (here the reload is held well past it), and the hand-back, once it
    /// does go on, still sees the shutdown and does not resume.
    #[tokio::test]
    async fn shutdown_returns_within_its_timeout_when_the_hand_back_is_slow() {
        let control = GatedControl::new(false);
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        control.entered.notified().await;

        let started = std::time::Instant::now();
        let stopped = tokio::time::timeout(
            Duration::from_secs(5),
            manager.shutdown(Duration::from_millis(200)),
        )
        .await
        .expect("shutdown() overran its own timeout behind the hand-back");
        assert!(
            !stopped,
            "a timed-out shutdown must say the run is still going"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "shutdown() took {:?} with a 200 ms timeout",
            started.elapsed()
        );

        control.release.notify_one();
        wait_idle(&manager).await;
        assert_eq!(control.resumes.load(Ordering::SeqCst), 0);
    }

    /// go `Abort()` vs `Stop()` (issue #2121): `abort_catchup` marks the
    /// cancellation as an abort, so the run discards its state; a node
    /// shutdown does not, so the run keeps it for the next start.
    #[tokio::test]
    async fn abort_and_shutdown_tell_the_run_why_it_stops() {
        for abort in [true, false] {
            let aborted = Arc::new(StdMutex::new(None));
            let manager = LiveCatchupManager::new(
                Arc::new(StopReasonRunner {
                    aborted: aborted.clone(),
                }),
                Arc::new(CountingControl::default()),
            );
            assert_eq!(
                manager.start_catchup("1000#deadbeef").await,
                CatchupStartResult::Created
            );
            if abort {
                manager.abort_catchup("1000#deadbeef").await.unwrap();
                wait_idle(&manager).await;
            } else {
                manager.shutdown(Duration::from_secs(5)).await;
            }
            assert_eq!(*aborted.lock().unwrap(), Some(abort), "abort = {abort}");
        }
    }

    /// A [`CatchupRunner`] that ignores the cancellation and never returns:
    /// a phase that cannot be interrupted.
    struct StuckRunner;

    #[async_trait]
    impl CatchupRunner for StuckRunner {
        async fn run(
            &self,
            _catchpoint: &str,
            _cancel: CancellationToken,
            _abort: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<CatchupOutcome> {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }

    /// Issue #2121: once a shutdown() timed out (and took the task handle),
    /// a later shutdown() must still report the stale run as not stopped,
    /// rather than `true` for a handle it no longer has.
    #[tokio::test]
    async fn a_second_shutdown_still_reports_a_run_that_never_stopped() {
        let manager =
            LiveCatchupManager::new(Arc::new(StuckRunner), Arc::new(CountingControl::default()));
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        assert!(!manager.shutdown(Duration::from_millis(100)).await);
        assert!(
            !manager.shutdown(Duration::from_millis(100)).await,
            "the stuck run is still registered, so it has not stopped"
        );
    }

    /// A [`CatchupRunner`] that panics.
    struct PanickingRunner;

    #[async_trait]
    impl CatchupRunner for PanickingRunner {
        async fn run(
            &self,
            _catchpoint: &str,
            _cancel: CancellationToken,
            _abort: CancellationToken,
            _counters: Arc<StdMutex<CatchpointCounters>>,
        ) -> anyhow::Result<CatchupOutcome> {
            panic!("runner bug");
        }
    }

    /// Issue #2121: a panicking runner must not wedge the manager: the run
    /// ends as a failure, normal sync is resumed (reload, then resume), and a
    /// new catchup can start.
    #[tokio::test]
    async fn a_panicking_runner_still_hands_back_and_frees_the_manager() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(Arc::new(PanickingRunner), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        wait_idle(&manager).await;
        assert_eq!(control.reloads.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        assert_eq!(manager.current_catchpoint().await, None);
        assert_eq!(
            manager.start_catchup("2000#next").await,
            CatchupStartResult::Created
        );
    }

    /// A [`NormalSyncControl`] whose `reload_ledger` waits for `release` and
    /// then panics: a hand-back that dies.
    struct PanickingReloadControl {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl NormalSyncControl for PanickingReloadControl {
        async fn pause(&self) {}
        async fn resume(&self) {}
        async fn reload_ledger(&self) {
            self.entered.notify_one();
            self.release.notified().await;
            panic!("reload bug");
        }
    }

    /// Issue #2121: a drive task that panics while shutdown() waits for it
    /// is reported as not stopped cleanly, and still leaves the manager idle.
    #[tokio::test]
    async fn shutdown_reports_a_panicked_hand_back_and_the_manager_is_freed() {
        let control = Arc::new(PanickingReloadControl {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        assert_eq!(
            manager.start_catchup("1000#deadbeef").await,
            CatchupStartResult::Created
        );
        control.entered.notified().await;
        let shutdown = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.shutdown(Duration::from_secs(5)).await })
        };
        wait_shutting_down(&manager).await;
        control.release.notify_one();
        assert!(
            !shutdown.await.unwrap(),
            "a panicked task is not a clean stop"
        );
        wait_idle(&manager).await;
    }

    fn reserved_entry(generation: u64, catchpoint: &str) -> RunningCatchup {
        RunningCatchup {
            generation,
            catchpoint: catchpoint.to_string(),
            cancel: CancellationToken::new(),
            abort: CancellationToken::new(),
            phase: Phase::Running(None),
        }
    }

    /// Issue #2121: the drop guard of a finished run (generation 1) never
    /// clears the entry of a later run (generation 2) registered meanwhile,
    /// on either of its paths: the direct one and the deferred one it takes
    /// when the lock is busy at drop time.
    #[tokio::test]
    async fn the_drop_guard_never_clears_a_later_run() {
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), Arc::new(NoopSyncControl));
        *manager.running.lock().await = Some(reserved_entry(2, "2000#later"));

        // Direct path.
        drop(ClearRunningOnDrop {
            manager: Arc::clone(&manager),
            generation: 1,
            armed: true,
        });
        assert_eq!(
            manager.current_catchpoint().await.as_deref(),
            Some("2000#later")
        );

        // Deferred path: the lock is held while the guard drops.
        {
            let _held = manager.running.lock().await;
            drop(ClearRunningOnDrop {
                manager: Arc::clone(&manager),
                generation: 1,
                armed: true,
            });
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            manager.current_catchpoint().await.as_deref(),
            Some("2000#later")
        );

        // Its own run's entry is cleared.
        drop(ClearRunningOnDrop {
            manager: Arc::clone(&manager),
            generation: 2,
            armed: true,
        });
        assert_eq!(manager.current_catchpoint().await, None);
    }

    /// A [`NormalSyncControl`] whose `pause` announces itself and then waits
    /// for `release`: a slow pause of normal sync.
    struct SlowPauseControl {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl NormalSyncControl for SlowPauseControl {
        async fn pause(&self) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        async fn resume(&self) {}
    }

    /// Issue #2121: start_catchup no longer holds the lock while it pauses
    /// normal sync. While the pause is slow, a status read answers at once
    /// and a second start is refused (the slot is reserved). A shutdown
    /// waits for the pause, inside its timeout, so the teardown never races
    /// it, and then wins: the run is never spawned.
    #[tokio::test]
    async fn a_slow_pause_blocks_neither_status_nor_shutdown() {
        let control = Arc::new(SlowPauseControl {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let cancel_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let manager = LiveCatchupManager::new(
            Arc::new(BlockingRunner {
                cancel_observed: cancel_observed.clone(),
            }),
            control.clone(),
        );
        let start = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.start_catchup("1000#deadbeef").await })
        };
        control.entered.notified().await;

        let status = tokio::time::timeout(Duration::from_secs(1), manager.current_catchpoint())
            .await
            .expect("current_catchpoint() blocked behind the pause");
        assert_eq!(status.as_deref(), Some("1000#deadbeef"));
        let second =
            tokio::time::timeout(Duration::from_secs(1), manager.start_catchup("2000#other"))
                .await
                .expect("start_catchup() blocked behind the pause");
        assert!(
            matches!(second, CatchupStartResult::Unable(_)),
            "{second:?}"
        );

        let mut shutdown = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.shutdown(Duration::from_secs(5)).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut shutdown)
                .await
                .is_err(),
            "shutdown() must not report a clean stop while the pause still runs"
        );
        control.release.notify_one();
        assert!(
            shutdown.await.unwrap(),
            "the pause ended and nothing was spawned"
        );
        assert!(matches!(
            start.await.unwrap(),
            CatchupStartResult::StartError(_)
        ));
        assert_eq!(manager.current_catchpoint().await, None);
        assert!(
            !cancel_observed.load(std::sync::atomic::Ordering::SeqCst),
            "the run must never have been spawned"
        );
    }

    /// Issue #2121: a pause that never ends makes shutdown() give up at its
    /// timeout and say the catchup did not stop cleanly.
    #[tokio::test]
    async fn shutdown_times_out_on_a_pause_that_never_ends() {
        let control = Arc::new(SlowPauseControl {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        let _start = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.start_catchup("1000#deadbeef").await })
        };
        control.entered.notified().await;
        let started = std::time::Instant::now();
        assert!(!manager.shutdown(Duration::from_millis(200)).await);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        // And a later call still says so.
        assert!(!manager.shutdown(Duration::from_millis(100)).await);
    }

    /// Issue #2121: a start request dropped mid-pause (a client disconnect,
    /// a request timeout) does not wedge the manager: the accepted catchup
    /// still starts once the pause ends, runs, hands back, and the manager
    /// is free again.
    #[tokio::test]
    async fn dropping_the_start_request_mid_pause_does_not_wedge_the_manager() {
        let control = Arc::new(SlowPauseControl {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        let start = {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { manager.start_catchup("1000#deadbeef").await })
        };
        control.entered.notified().await;
        start.abort();
        assert!(
            start.await.unwrap_err().is_cancelled(),
            "the request was dropped"
        );

        control.release.notify_one();
        wait_idle(&manager).await;
        assert_eq!(
            manager.last_catchpoint(),
            "1000#deadbeef",
            "the catchup ran"
        );
        control.release.notify_one();
        assert_eq!(
            manager.start_catchup("2000#next").await,
            CatchupStartResult::Created
        );
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

    /// Pins issue #1616's fix: a successful live catchup must reload the
    /// ledger from disk before resuming normal operation, or every
    /// subsystem sharing that ledger handle (agreement, pool,
    /// pool-block-follower) keeps operating against pre-catchup state
    /// forever, even though the ledger file on disk is already at the new
    /// round -- the round-65379680 mainnet soak halt. `reload_ledger` must
    /// fire exactly once, strictly before `resume`.
    #[tokio::test]
    async fn start_catchup_reloads_ledger_before_resuming_on_success() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());

        let result = manager
            .start_catchup("1000#abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop")
            .await;
        assert_eq!(result, CatchupStartResult::Created);

        wait_idle(&manager).await;

        assert_eq!(control.reloads.load(Ordering::SeqCst), 1);
        assert_eq!(
            control.order.lock().unwrap().as_slice(),
            &["reload", "resume"],
            "reload_ledger must run before resume, not merely also get called"
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

    /// Pins issue #1647's fix: `SyncOrchestrator::run` can return `Err`
    /// *after* it has already finalized a catchpoint cutover on disk (a
    /// later, independent phase failing, e.g. the post-cutover lookback
    /// block download) -- so a failed run is not proof "nothing new on
    /// disk to reload". `reload_ledger` must fire unconditionally, before
    /// `resume`, exactly as it does on success, or the resumed
    /// agreement/catchup cycle keeps operating against the stale
    /// pre-catchup ledger handle forever even though the ledger file on
    /// disk genuinely advanced -- the mainnet-node-soak run 36539158300
    /// "zero follow-mode progress" symptom.
    #[tokio::test]
    async fn start_catchup_reloads_ledger_before_resuming_even_on_runner_error() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::err("boom"), control.clone());

        let result = manager.start_catchup("1000#deadbeef").await;
        assert_eq!(result, CatchupStartResult::Created);

        wait_idle(&manager).await;

        assert_eq!(control.reloads.load(Ordering::SeqCst), 1);
        assert_eq!(
            control.order.lock().unwrap().as_slice(),
            &["reload", "resume"],
            "reload_ledger must run before resume even when the run failed"
        );
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

    // -- stopped-short vs complete (issue #1725) -----------------------------

    fn stopped_short() -> CatchupOutcome {
        CatchupOutcome::StoppedShort {
            stopped_at_round: 1320,
            target_round: 1421,
        }
    }

    /// A replay that stopped short is NOT a completed catchup: the manager
    /// records it as stopped short (the catchpoint itself is still recorded
    /// as applied in `last_catchpoint`), and still
    /// resumes normal operation (whose catchup closes the gap).
    #[tokio::test]
    async fn stopped_short_catchup_is_not_reported_as_complete() {
        let control = Arc::new(CountingControl::default());
        let manager =
            LiveCatchupManager::new(ImmediateRunner::outcome(stopped_short()), control.clone());
        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;

        // The catchpoint itself was applied; only the replay stopped short.
        assert_eq!(manager.last_catchpoint(), "1000#aaaa");
        assert_eq!(manager.last_outcome(), Some(stopped_short()));
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
        let text = manager.metrics_text();
        assert!(
            text.contains("algod_rust_catchpoint_catchup_stopped_short_total 1"),
            "{text}"
        );
        assert!(
            text.contains("algod_rust_catchpoint_catchup_completed_total 0"),
            "{text}"
        );
        assert!(
            text.contains("algod_rust_catchpoint_catchup_stopped_short_behind_rounds 101"),
            "{text}"
        );
    }

    /// Every non-empty line of the exposition must start at column 0 with
    /// `#` or a metric name (strict parsers reject the whole payload
    /// otherwise), and the full text is pinned.
    #[tokio::test]
    async fn metrics_text_is_a_strictly_formatted_exposition() {
        let manager = LiveCatchupManager::new(
            ImmediateRunner::outcome(stopped_short()),
            Arc::new(CountingControl::default()),
        );
        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;
        let text = manager.metrics_text();
        assert!(text.ends_with('\n'));
        for line in text.lines() {
            assert!(!line.is_empty(), "blank line in {text:?}");
            assert!(!line.starts_with(char::is_whitespace), "{line:?}");
            let first = line.chars().next().unwrap();
            assert!(
                first == '#' || first.is_ascii_alphabetic() || first == '_',
                "{line:?}"
            );
        }
        let expected = [
            "# HELP algod_rust_catchpoint_catchup_completed_total Live catchpoint catchups whose replay reached its target.",
            "# TYPE algod_rust_catchpoint_catchup_completed_total counter",
            "algod_rust_catchpoint_catchup_completed_total 0",
            "# HELP algod_rust_catchpoint_catchup_stopped_short_total Live catchpoint catchups whose replay stopped short of its target (normal catchup continues).",
            "# TYPE algod_rust_catchpoint_catchup_stopped_short_total counter",
            "algod_rust_catchpoint_catchup_stopped_short_total 1",
            "# HELP algod_rust_catchpoint_catchup_stopped_short_behind_rounds Rounds the most recent successful live catchup stopped short of its target by (0 if it reached it).",
            "# TYPE algod_rust_catchpoint_catchup_stopped_short_behind_rounds gauge",
            "algod_rust_catchpoint_catchup_stopped_short_behind_rounds 101",
        ]
        .join("\n")
            + "\n";
        assert_eq!(text, expected);
    }

    #[tokio::test]
    async fn complete_catchup_is_recorded_as_complete() {
        let manager =
            LiveCatchupManager::new(ImmediateRunner::ok(), Arc::new(CountingControl::default()));
        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;

        assert_eq!(manager.last_catchpoint(), "1000#aaaa");
        assert_eq!(manager.last_outcome(), Some(CatchupOutcome::Complete));
        let text = manager.metrics_text();
        assert!(
            text.contains("algod_rust_catchpoint_catchup_completed_total 1"),
            "{text}"
        );
        assert!(
            text.contains("algod_rust_catchpoint_catchup_stopped_short_total 0"),
            "{text}"
        );
        assert!(
            text.contains("algod_rust_catchpoint_catchup_stopped_short_behind_rounds 0"),
            "{text}"
        );
    }

    /// Failed and aborted runs are neither; nothing finished -> no metrics.
    #[tokio::test]
    async fn failed_catchup_records_no_outcome_and_no_metrics() {
        let manager = LiveCatchupManager::new(
            ImmediateRunner::err("boom"),
            Arc::new(CountingControl::default()),
        );
        assert_eq!(manager.metrics_text(), "");
        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;
        assert_eq!(manager.last_outcome(), None);
        assert_eq!(manager.last_catchpoint(), "");
        assert_eq!(manager.metrics_text(), "");
    }

    #[test]
    fn outcome_is_derived_from_the_orchestrator_result() {
        use algo_ledger::sync::{ReplayStoppedEarly, SyncResult};
        let mut result = SyncResult {
            final_round: 1421,
            accounts_imported: 0,
            blocks_replayed: 101,
            duration: Duration::ZERO,
            stopped_early: None,
        };
        assert_eq!(
            CatchupOutcome::from_sync_result(&result),
            CatchupOutcome::Complete
        );
        result.stopped_early = Some(ReplayStoppedEarly {
            stopped_at_round: 1320,
            target_round: 1421,
        });
        assert_eq!(CatchupOutcome::from_sync_result(&result), stopped_short());
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

    // -- SyncRoundResetHook (issue #951) -------------------------------------

    /// A [`SyncRoundResetHook`] fake that just counts invocations.
    #[derive(Default)]
    struct CountingResetHook {
        resets: AtomicU32,
    }

    #[async_trait]
    impl SyncRoundResetHook for CountingResetHook {
        async fn reset_sync_round(&self) {
            self.resets.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Mirrors go's `TestFastCatchupResume` (`node/follower_node_test.go`):
    /// `SetCatchpointCatchupMode(false)` — i.e. a catchup run finishing —
    /// must reset the follower node's sync round. Here that's proven by
    /// the attached hook firing exactly once after a *successful* run,
    /// before the normal sync loop resumes.
    #[tokio::test]
    async fn successful_catchup_resets_sync_round_before_resuming() {
        let control = Arc::new(CountingControl::default());
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), control.clone());
        let hook = Arc::new(CountingResetHook::default());
        manager.set_sync_round_reset_hook(hook.clone());

        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;

        assert_eq!(hook.resets.load(Ordering::SeqCst), 1);
        assert_eq!(control.resumes.load(Ordering::SeqCst), 1);
    }

    /// The reset must fire on every completion path, not just success —
    /// go's `abort()` calls `updateNodeCatchupMode(false)` (hence resets
    /// the sync round) exactly like the success path
    /// (`processStageSwitch`), matching `LiveCatchupManager::drive`'s own
    /// unconditional `self.control.resume()` after it.
    #[tokio::test]
    async fn failed_catchup_still_resets_sync_round() {
        let manager =
            LiveCatchupManager::new(ImmediateRunner::err("boom"), Arc::new(NoopSyncControl));
        let hook = Arc::new(CountingResetHook::default());
        manager.set_sync_round_reset_hook(hook.clone());

        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;

        assert_eq!(hook.resets.load(Ordering::SeqCst), 1);
    }

    /// Without an attached hook (every command except `node start --follow
    /// <peer>`), a completed catchup must not panic or otherwise behave
    /// differently — the hook is genuinely optional.
    #[tokio::test]
    async fn no_reset_hook_is_a_no_op() {
        let manager = LiveCatchupManager::new(ImmediateRunner::ok(), Arc::new(NoopSyncControl));
        manager.start_catchup("1000#aaaa").await;
        wait_idle(&manager).await;
        // No assertion beyond "did not panic" — absence of a hook must be
        // silently fine.
    }
}
