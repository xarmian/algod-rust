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

// Agreement Service — the central integration piece of the agreement protocol.
//
// Mirrors go-algorand/agreement/service.go.
//
// The Service owns the main loop and demux loop, tying together the Player
// state machine, Demux, AsyncPseudonode, and all bridge implementations
// (network, ledger, key manager, block factory, block validator).
//
// Architecture:
//   - `main_loop` drives the Player state machine: bootstrap, then loop
//     { send actions -> receive signals -> receive event -> player.handle }.
//   - `demux_loop` executes actions produced by the main loop and fetches the
//     next external event from the Demux.
//   - The two loops communicate via channels, mirroring Go's goroutine pattern.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tracing::{debug, info, warn};

use algo_types::{Address, Round};

use crate::actions::{
    Action, ActionType, CryptoAction, EnsureAction, NetworkAction, PseudonodeAction, RezeroAction,
    StageDigestAction,
};
use crate::clock::Clock;
use crate::codec;
use crate::demux::{Demux, ExternalDemuxSignals, ExternalEvent};
use crate::events::ConsensusVersionView;
use crate::ledger_reader::LedgerReader;
use crate::metrics::ParticipationMetrics;
use crate::persistence::{self, AsyncPersistenceLoop, ClockState, PersistentRequest};
use crate::player::{Player, Tracer};
use crate::pseudonode::{AccountSigningKeys, AsyncPseudonode, Pseudonode};
use crate::router::RootRouter;
use crate::step::{Period, Step, PROPOSE, SOFT};
use crate::traits::{
    AgreementKeyManager, AgreementNetwork, AsyncVoteVerifier, BlockFactory, BlockValidator,
    CryptoBundleRequest, CryptoProposalRequest, CryptoVerifier, CryptoVoteRequest,
    EventsProcessingMonitor, LedgerWriter, RandomSource, Tag, AGREEMENT_VOTE_TAG,
    PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
use crate::types::{
    filter_timeout, CredentialArrivalHistory, Deadline, TimeoutType,
    DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
};

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Parameters necessary to run the agreement protocol.
///
/// Mirrors Go's `agreement.Parameters`.
pub struct Parameters<N, L, K, BF, BV, R, M, C>
where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    BV: BlockValidator + Send + 'static,
    R: RandomSource + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    /// The network interface for sending/receiving agreement messages.
    pub network: N,
    /// The ledger interface (read + write).
    pub ledger: L,
    /// Key manager holding participation keys.
    pub key_manager: K,
    /// Block factory for assembling proposals.
    pub block_factory: BF,
    /// Block validator for validating incoming proposals.
    pub block_validator: BV,
    /// Random source for sortition timing.
    pub random_source: R,
    /// Events processing monitor for queue length reporting.
    pub monitor: M,
    /// Asynchronous crypto verifier for votes, proposals, and bundles.
    pub crypto: C,
    /// Clock driving deadline-based timeouts in the demux.
    ///
    /// Production code passes `SystemClock::new()`, which preserves the
    /// wall-clock timing behavior the service had before this field existed.
    /// The `agreementtest::simulate` harness (TASK-81) injects a mock clock
    /// so tests can advance deterministically without real time.
    ///
    /// Mirrors Go's `agreement.Parameters.Clock`
    /// (`../go-algorand/agreement/service.go`).
    pub clock: Arc<dyn Clock>,
    /// Optional SQLite connection for crash recovery persistence.
    ///
    /// When `Some`, agreement state is persisted to this database before
    /// broadcasting votes, enabling crash recovery without double-voting.
    /// When `None`, no persistence is performed (existing behavior).
    pub crash_db: Option<rusqlite::Connection>,
    /// Per-account signing secrets (VRF keypair + OTS secrets) the
    /// pseudonode uses to produce real, cryptographically valid
    /// proposals and votes for each address.
    ///
    /// An empty map preserves the prior no-local-signing behavior:
    /// the pseudonode falls back to zero placeholder signatures and
    /// credentials, which the verifier rejects before they ever reach
    /// the state machine — so peers / the rest of the protocol never
    /// see invalid traffic from a local source. All current production
    /// call sites pass an empty map; the `agreementtest::simulate`
    /// harness (TASK-90) is the first caller to inject real secrets
    /// here so the pseudonode can drive multi-round consensus against
    /// a sortition-aware test ledger.
    ///
    /// `Service::start()` forwards each entry into the constructed
    /// `AsyncPseudonode` via the existing
    /// [`AsyncPseudonode::register_signing_keys`] API, then proceeds.
    pub signing_keys: HashMap<Address, AccountSigningKeys>,
}

// ---------------------------------------------------------------------------
// ServiceHandle
// ---------------------------------------------------------------------------

/// A handle returned by `Service::start()` that allows shutting down the
/// agreement service.
pub struct ServiceHandle {
    /// Signal to tell both loops to quit.
    quit: Arc<AtomicBool>,
    /// Join handles for the spawned threads.
    threads: Vec<thread::JoinHandle<()>>,
}

impl ServiceHandle {
    /// Shut down the agreement service, waiting for all threads to finish.
    ///
    /// Mirrors Go's `Service.Shutdown()`.
    pub fn shutdown(self) {
        debug!("agreement service is stopping");
        self.quit.store(true, Ordering::SeqCst);
        for handle in self.threads {
            let _ = handle.join();
        }
        debug!("agreement service has stopped");
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// An instance of the Algorand agreement protocol.
///
/// The `Service` is the central integration piece that ties together all the
/// bridge implementations. Call `start()` to begin execution, which spawns
/// two background threads (main loop and demux loop). Call `shutdown()` on
/// the returned `ServiceHandle` to stop.
///
/// Mirrors Go's `agreement.Service`.
pub struct Service<N, L, K, BF, BV, R, M, C>
where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    BV: BlockValidator + Send + 'static,
    R: RandomSource + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    params: Parameters<N, L, K, BF, BV, R, M, C>,
    /// Consensus-participation counters and round timings (issue #473).
    ///
    /// Deliberately *not* a `Parameters` field: every existing construction
    /// site builds `Parameters` with a struct literal, and metrics are
    /// observability, not a protocol input. `Service::new` always creates one
    /// so the counters exist unconditionally; a caller that wants to scrape
    /// them (the `participate` command, which must hand the same handle to
    /// the REST adapter it starts *before* agreement) injects its own via
    /// [`Service::with_metrics`] or takes a handle with [`Service::metrics`].
    metrics: Arc<ParticipationMetrics>,
    /// go's `s.tracer` (`agreement/service.go:52`), constructed from
    /// `EnableAgreementReporting`/`EnableAgreementTimeMetrics`
    /// (`config.Local`, issue #755). Defaults to `Tracer::default()`
    /// (both flags false, matching go's own default), overridden via
    /// [`Service::with_tracer`]. Driven every dispatch via
    /// `RootRouter::submit_top`'s `tracer` argument.
    tracer: Tracer,
}

impl<N, L, K, BF, BV, R, M, C> Service<N, L, K, BF, BV, R, M, C>
where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    BV: BlockValidator + Send + 'static,
    R: RandomSource + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    /// Create a new Agreement Service.
    ///
    /// Mirrors Go's `MakeService`.
    pub fn new(params: Parameters<N, L, K, BF, BV, R, M, C>) -> Self {
        Self {
            params,
            metrics: Arc::new(ParticipationMetrics::new()),
            tracer: Tracer::default(),
        }
    }

    /// Use a caller-supplied metrics collector instead of the one
    /// `Service::new` created.
    ///
    /// Lets the node share one collector between the agreement service and a
    /// REST server that was already started (see `participate`).
    pub fn with_metrics(mut self, metrics: Arc<ParticipationMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// A handle to this service's participation metrics.
    pub fn metrics(&self) -> Arc<ParticipationMetrics> {
        self.metrics.clone()
    }

    /// Use a caller-supplied tracer instead of the default
    /// (both-flags-false) one `Service::new` created. Lets the node build
    /// its `Tracer` from `EnableAgreementReporting`/
    /// `EnableAgreementTimeMetrics` (`config.Local`, issue #755) before
    /// starting the service.
    pub fn with_tracer(mut self, tracer: Tracer) -> Self {
        self.tracer = tracer;
        self
    }

    /// This service's tracer, as configured (test/introspection use).
    pub fn tracer(&self) -> &Tracer {
        &self.tracer
    }

    /// Start executing the agreement protocol.
    ///
    /// This:
    /// 1. Calls `network.start()` to signal readiness.
    /// 2. Creates the `Demux` and `AsyncPseudonode`.
    /// 3. Spawns the main loop and demux loop as std threads.
    /// 4. Returns a `ServiceHandle` for shutdown.
    ///
    /// Mirrors Go's `Service.Start()`.
    pub fn start(self) -> ServiceHandle {
        let quit = Arc::new(AtomicBool::new(false));
        let metrics = self.metrics.clone();
        let tracer = self.tracer.clone();

        // Signal the network that the agreement service is ready.
        self.params.network.start();

        // Decompose parameters into individual fields for move into threads.
        let Parameters {
            network,
            ledger,
            key_manager,
            block_factory,
            block_validator,
            random_source,
            monitor,
            crypto,
            clock,
            crash_db,
            signing_keys,
        } = self.params;

        // Try to restore persisted state BEFORE creating the persistence loop
        // (which takes ownership of the connection). We need a separate
        // connection for restore, or we do restore first with the same one.
        let restored_state = crash_db.as_ref().and_then(restore_crash_state);

        // Create the persistence loop if crash_db is available.
        let persistence_loop = crash_db.map(|conn| {
            let mut pl = AsyncPersistenceLoop::new(conn);
            pl.start();
            pl
        });

        // Wrap shared state in Arc for cross-thread access.
        let ledger = Arc::new(ledger);
        let network = Arc::new(network);
        let monitor: Arc<Mutex<M>> = Arc::new(Mutex::new(monitor));

        // --- Obtain channel receivers for the Demux ---

        // Network message channels (one per tag).
        let av_rx = network.messages(&Tag(AGREEMENT_VOTE_TAG));
        let pp_rx = network.messages(&Tag(PROPOSAL_PAYLOAD_TAG));
        let vb_rx = network.messages(&Tag(VOTE_BUNDLE_TAG));

        // Crypto verifier result channels.
        let verified_votes_rx = crypto.verified_votes().clone();
        let verified_proposals_rx = crypto.verified(PROPOSAL_PAYLOAD_TAG).clone();
        let verified_bundles_rx = crypto.verified(VOTE_BUNDLE_TAG).clone();

        // Initial ledger round notification channel.
        let current_round = ledger.next_round();
        let ledger_round_rx = ledger.round_notify(current_round);

        // Quit channel for the Demux.
        let (quit_demux_tx, quit_demux_rx) = crossbeam_channel::bounded(1);

        // The demux_loop needs its own handle to the clock so it can rezero
        // on `Action::Rezero` — clone before the Demux takes ownership.
        let clock_for_actions = clock.clone();

        // Construct the Demux with all channel receivers and the clock.
        let mut demux = Demux::new(
            av_rx,
            pp_rx,
            vb_rx,
            verified_votes_rx,
            verified_proposals_rx,
            verified_bundles_rx,
            ledger_round_rx,
            quit_demux_rx,
            clock,
        );
        // Wire up network and ledger references for peer disconnect on decode
        // errors (G8) and round re-sampling on interruption (G9).
        demux.set_network(network.clone() as Arc<dyn AgreementNetwork + Send + Sync>);
        demux.set_ledger(ledger.clone() as Arc<dyn LedgerReader + Send + Sync>);

        // Create channels for communication between main loop and demux loop.
        // These mirror Go's `input`, `output`, and `ready` channels.
        let (input_tx, input_rx) = mpsc::channel::<Option<ExternalEvent>>();
        let (output_tx, output_rx) = mpsc::channel::<Vec<Action>>();
        let (ready_tx, ready_rx) = mpsc::channel::<ExternalDemuxSignals>();

        // Acknowledgement channel: the demux loop signals here once it has
        // finished executing an action batch, so the main loop can run that
        // batch's pseudonode actions strictly afterwards (issue #482).
        let (actions_done_tx, actions_done_rx) = mpsc::channel::<()>();

        // Channel for pseudonode events from the main loop to the demux loop.
        // In Go, pseudonode actions are executed in the demux goroutine and
        // results are prioritized via `s.demux.prioritize()`. Since the
        // pseudonode is owned by the main loop, we execute pseudonode actions
        // there and send the resulting events to the demux loop for
        // prioritization.
        let (pseudo_tx, pseudo_rx) = mpsc::channel::<Vec<ExternalEvent>>();

        let quit_main = quit.clone();
        let quit_demux = quit.clone();
        let ledger_main = ledger.clone();
        let ledger_demux = ledger.clone();
        let network_demux = network.clone();
        let monitor_demux = monitor.clone();
        let metrics_main = metrics.clone();
        let metrics_demux = metrics.clone();

        // Spawn main loop thread.
        let main_handle = thread::Builder::new()
            .name("agreement-main".into())
            .spawn(move || {
                main_loop(
                    ledger_main,
                    key_manager,
                    block_factory,
                    random_source,
                    quit_main,
                    input_rx,
                    output_tx,
                    actions_done_rx,
                    ready_tx,
                    pseudo_tx,
                    persistence_loop,
                    restored_state,
                    signing_keys,
                    metrics_main,
                    tracer,
                );
            })
            .expect("failed to spawn agreement main loop thread");

        // Create the async vote verifier, mirroring Go's `MakeAsyncVoteVerifier`.
        // This is passed to `EnsureDigest` so the catchup service can
        // authenticate certificates for blocks it fetches.
        let vote_verifier = Arc::new(AsyncVoteVerifier::new());

        // Spawn demux loop thread.
        let demux_handle = thread::Builder::new()
            .name("agreement-demux".into())
            .spawn(move || {
                demux_loop(
                    network_demux,
                    ledger_demux,
                    block_validator,
                    quit_demux,
                    input_tx,
                    output_rx,
                    actions_done_tx,
                    ready_rx,
                    pseudo_rx,
                    demux,
                    quit_demux_tx,
                    crypto,
                    monitor_demux,
                    vote_verifier,
                    clock_for_actions,
                    metrics_demux,
                );
            })
            .expect("failed to spawn agreement demux loop thread");

        ServiceHandle {
            quit,
            threads: vec![main_handle, demux_handle],
        }
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

/// The main loop drives the Player state machine.
///
/// After bootstrapping (initializing the player at the current round), it runs:
/// 1. Send actions to the demux loop via the `output` channel.
/// 2. Send external demux signals via the `ready` channel.
/// 3. Receive the next external event from the `input` channel.
/// 4. Feed the event into the player to produce new actions.
/// 5. Repeat.
///
/// Mirrors Go's `Service.mainLoop`.
#[allow(clippy::too_many_arguments)]
fn main_loop<L, K, BF, R>(
    ledger: Arc<L>,
    key_manager: K,
    block_factory: BF,
    random_source: R,
    quit: Arc<AtomicBool>,
    input: mpsc::Receiver<Option<ExternalEvent>>,
    output: mpsc::Sender<Vec<Action>>,
    actions_done: mpsc::Receiver<()>,
    ready: mpsc::Sender<ExternalDemuxSignals>,
    pseudo_events: mpsc::Sender<Vec<ExternalEvent>>,
    mut persistence_loop: Option<AsyncPersistenceLoop>,
    restored_state: Option<(RootRouter, Player, ClockState, Vec<Action>)>,
    signing_keys: HashMap<Address, AccountSigningKeys>,
    metrics: Arc<ParticipationMetrics>,
    mut tracer: Tracer,
) where
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    R: RandomSource + Send + 'static,
{
    // Bootstrap: initialize the player at the current round, or use
    // restored state from a crash recovery database.
    let next_round = ledger.next_round();
    let next_version = ledger
        .consensus_version(next_round)
        .unwrap_or_else(|_| {
            warn!(
                "unable to retrieve consensus version for round {}, defaulting to binary consensus version",
                next_round
            );
            algo_types::CONSENSUS_V41.to_string()
        });

    // Look up consensus params for the filter timeout.
    let cparams = ledger.consensus_params(next_round).unwrap_or_else(|_| {
        algo_types::consensus::consensus_params_for_version(&next_version).unwrap_or_else(|| {
            algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
                .expect("v41 params must exist")
        })
    });

    // Determine initial state: restored from crash DB or fresh bootstrap.
    //
    // When restoring, recover the wall-clock stamp that was written into
    // the persisted `ClockState` at checkpoint time and clamp the restored
    // player's outstanding deadlines by the interval elapsed since that
    // stamp — i.e. the crash downtime. Mirrors Go's `s.Clock = clock`
    // assignment in `agreement/service.go:252` so timeouts continue to
    // fire on their original schedule rather than being reset by the
    // restart (DOC-21 §3.8).
    let (mut router, mut player, mut actions) =
        initial_state(restored_state, next_round, &cparams, SystemTime::now());

    // Create the pseudonode for local proposal/vote generation.
    // We share ledger via a clone of the Arc, but AsyncPseudonode wants
    // owned references. We use a LedgerReaderRef wrapper below.
    let mut async_pseudo =
        AsyncPseudonode::new(block_factory, key_manager, LedgerReaderRef(ledger.clone()));
    // Register caller-supplied signing secrets so the pseudonode can
    // produce real VRF proofs and OTS signatures (used by the
    // agreementtest::simulate harness — TASK-90). Empty map is a no-op
    // and matches prior production behavior.
    for (addr, keys) in signing_keys {
        async_pseudo.register_signing_keys(addr, keys);
    }
    let mut pseudonode: Box<dyn Pseudonode + Send> = Box::new(async_pseudo);

    // Persistence state — saved when actions contain a persistent action (attest).
    // These snapshots are used to encode the state for the persistence loop.
    let mut persist_router: Option<RootRouter> = None;
    let mut persist_player: Option<Player> = None;
    let mut persist_actions: Option<Vec<Action>> = None;

    info!(
        event = "service_started",
        round = next_round.0,
        "agreement service started at round {}",
        next_round
    );

    loop {
        if quit.load(Ordering::SeqCst) {
            break;
        }

        // Step 1: Hand the demux loop every action it owns and *wait* for it
        // to finish executing them, then run this batch's pseudonode actions.
        //
        // Mirrors go-algorand's demux dispatch path (`agreement/service.go:195`
        // → `pseudonodeAction.do` in `agreement/actions.go:387`). In Go the
        // demux loop calls `s.do(ctx, a)` on every action batch, executing the
        // actions **in slice order**; pseudonode actions are routed to
        // `s.loopback.MakeProposals/MakeVotes` and the resulting events are
        // prioritized back into the demux. The Rust port owns the pseudonode
        // in the main loop (because it captures BlockFactory/KeyManager by
        // value), so pseudonode actions run here while everything else runs on
        // the demux thread.
        //
        // That split makes the ordering explicit and consensus-critical: a
        // round-advancing batch is `[Ensure(block N-1), Rezero(N),
        // Pseudonode(Assemble N), ...]`, so `Ensure` — which commits block
        // N-1 to the ledger — MUST complete before `Assemble` asks the block
        // factory to build a proposal for round N (assembling round N needs
        // round N-1's header). Running the pseudonode first (as this loop used
        // to) meant `assemble_block(N)` always ran against a ledger whose
        // latest committed round was still N-2, and every proposal attempt
        // failed with
        // `TransactionPool.assembleEmptyBlock: cannot get prev header for N-1`
        // — the node voted normally but never proposed a block (issue #482).
        //
        // The `actions_done` handshake below restores Go's ordering: the batch
        // is sent first, the demux thread acknowledges after `do_actions`
        // returns, and only then do the pseudonode actions run. The resulting
        // events are still delivered to the demux before its next `next()`
        // call (the demux drains `pseudo_rx` after receiving `ready` signals,
        // which this loop sends after the pseudonode step), so the bootstrap
        // batch's `Pseudonode(Assemble)` still produces round 1's first
        // proposal.
        //
        // The demux's `do_action` arm for `Action::Pseudonode` is a no-op, so
        // strip pseudonode actions out of the batch it receives; its monitor
        // queue counts then reflect only the actions it actually handles.
        let pseudonode_actions: Vec<PseudonodeAction> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Pseudonode(pa) => Some(pa.clone()),
                _ => None,
            })
            .collect();
        actions.retain(|a| !matches!(a, Action::Pseudonode(_)));

        if output.send(actions).is_err() {
            break;
        }
        // Block until the demux thread has executed the batch (in particular
        // any `Ensure`, which commits the previous round's block).
        if actions_done.recv().is_err() {
            break;
        }

        // Step 2: Execute this batch's pseudonode actions and forward the
        // resulting events to the demux's prioritize queue.
        let mut pseudonode_events = Vec::new();
        for pa in &pseudonode_actions {
            execute_pseudonode_action(
                pa,
                &mut *pseudonode,
                &mut pseudonode_events,
                &persistence_loop,
                &persist_router,
                &persist_player,
                &persist_actions,
                &metrics,
            );
        }
        // Persistence snapshots are consumed by the attest above; reset so
        // the next attest batch captures a fresh snapshot from its own
        // `submit_top` result.
        persist_router = None;
        persist_player = None;
        persist_actions = None;
        if !pseudonode_events.is_empty() && pseudo_events.send(pseudonode_events).is_err() {
            break;
        }

        // Step 3: Send signals so demux loop knows what events to look for.
        let fast_recovery_deadline = Deadline {
            duration: player.fast_recovery_deadline,
            timeout_type: TimeoutType::FastRecovery,
        };
        let current_consensus_version = match ledger.consensus_version(player.round) {
            Ok(v) => ConsensusVersionView {
                err: None,
                version: v,
            },
            Err(e) => ConsensusVersionView {
                err: Some(e.to_string()),
                version: String::new(),
            },
        };
        let signals = ExternalDemuxSignals {
            deadline: player.deadline,
            fast_recovery_deadline,
            current_round: player.round,
            random_source_entropy: random_source.uint64(),
            current_consensus_version,
        };
        if ready.send(signals).is_err() {
            break;
        }

        // Step 4: Receive the next external event from the demux loop.
        let event = match input.recv() {
            Ok(Some(e)) => e,
            Ok(None) | Err(_) => break,
        };

        // Step 5: Look up consensus params for this event's round.
        //
        // Go looks these up at `ParamsRound(e.ConsensusRound())`, i.e. two
        // rounds back (`agreement/demux.go:200`), never at the event's own
        // round — the event's round is by definition the one still being
        // agreed, so its block header does not exist yet and the lookup
        // would always fail. Using the raw round here meant every event
        // fell back to the binary's built-in consensus version and params
        // instead of the network's, and logged
        // "failed to read valid protocol version" once per round
        // (issue #478).
        let event_round = crate::lookback::params_round(event.consensus_round());
        let params = ledger
            .consensus_params(event_round)
            .unwrap_or_else(|_| cparams.clone());

        // Attach consensus version to the event.
        let version_view = match ledger.consensus_version(event_round) {
            Ok(v) => ConsensusVersionView {
                err: None,
                version: v,
            },
            Err(e) => ConsensusVersionView {
                err: Some(e.to_string()),
                version: String::new(),
            },
        };
        let event = event.attach_consensus_version(version_view);

        // Step 6: Drive the state machine.
        let (new_player, new_actions) =
            router.submit_top(player, event.event, &params, Some(&mut tracer));
        player = new_player;
        actions = new_actions;

        // Step 7: Snapshot state for the next iteration's persistent attest
        // dispatch. Mirrors go-algorand's `s.persistRouter = router` block
        // after `router.submitTop` (`agreement/service.go:266-270`): the
        // snapshot is consumed at the top of the *next* iteration, so the
        // attest's persist-then-broadcast ordering is preserved.
        if persistence::persistent(&actions) {
            persist_router = Some(router.clone());
            persist_player = Some(player.clone());
            persist_actions = Some(actions.clone());
        }
    }

    // Clean up.
    pseudonode.quit();
    if let Some(ref mut pl) = persistence_loop {
        pl.quit();
    }
    drop(output);
    info!("agreement main loop exited");
}

/// Execute a single pseudonode action and collect resulting events.
///
/// Mirrors Go's `pseudonodeAction.do(ctx, s)`. Results are converted to
/// `ExternalEvent`s for prioritization in the demux.
///
/// For `Attest` actions, if a persistence loop is available and we have saved
/// state, the state is persisted to SQLite before votes are generated. The
/// persistence-done channel is passed to `make_votes` so the pseudonode waits
/// for the write to complete before returning votes (matching Go's pattern of
/// persist-before-broadcast).
#[allow(clippy::too_many_arguments)]
fn execute_pseudonode_action(
    pa: &PseudonodeAction,
    pseudonode: &mut dyn Pseudonode,
    events_out: &mut Vec<ExternalEvent>,
    persistence_loop: &Option<AsyncPersistenceLoop>,
    persist_router: &Option<RootRouter>,
    persist_player: &Option<Player>,
    persist_actions: &Option<Vec<Action>>,
    metrics: &ParticipationMetrics,
) {
    match pa.t {
        ActionType::Assemble => {
            match pseudonode.make_proposals(pa.round, pa.period) {
                Ok(message_events) => {
                    // Sortition only hands back proposal messages when this
                    // node actually holds a proposer credential for
                    // (round, period), so a non-empty result is the moment
                    // the node becomes a candidate proposer. Logged at INFO
                    // because it is the only externally visible signal of
                    // that fact — issue #471's restart-during-own-proposal
                    // scenario keys its restart off this line, and it makes
                    // "did we propose this round?" answerable from the node's
                    // own log instead of only from the committed block.
                    if !message_events.is_empty() {
                        // The digests of the blocks we just proposed. Recorded
                        // so a later `Ensure` can tell whether *our* proposal
                        // is the one that won the round.
                        let digests: Vec<algo_types::Digest> = message_events
                            .iter()
                            .filter_map(|me| {
                                me.input
                                    .vote
                                    .as_ref()
                                    .map(|v| v.raw_vote.proposal.block_digest)
                            })
                            .collect();
                        // Structured fields first-class; the human message is
                        // byte-identical to the pre-#473 line because
                        // `ops/mixed-cluster/scripts/restart-rejoin.sh` greps
                        // for it verbatim.
                        info!(
                            event = "proposal_made",
                            round = pa.round.0,
                            period = pa.period.0,
                            count = message_events.len(),
                            "assembled {} proposal message(s) at ({}, {})",
                            message_events.len(),
                            pa.round,
                            pa.period
                        );
                        metrics.record_proposal_made(pa.round, pa.period, &digests);
                    }
                    let ext_events: Vec<ExternalEvent> = message_events
                        .into_iter()
                        .map(|me| ExternalEvent {
                            event: crate::events::Event::Message(me),
                        })
                        .collect();
                    events_out.extend(ext_events);
                }
                Err(crate::pseudonode::PseudonodeError::NoProposals) => {
                    // No participation keys — do nothing.
                }
                Err(e) => {
                    warn!("pseudonode.make_proposals failed: {}", e);
                }
            }
        }
        ActionType::Repropose => {
            info!(
                event = "reproposal_made",
                round = pa.round.0,
                period = pa.period.0,
                step = %PROPOSE,
                block_digest = %pa.proposal.block_digest,
                "repropose to {:?} at ({}, {}, {})",
                pa.proposal,
                pa.round,
                pa.period,
                PROPOSE
            );
            metrics.record_reproposal(pa.round, pa.period);
            match pseudonode.make_votes(pa.round, pa.period, PROPOSE, pa.proposal, None) {
                Ok(message_events) => {
                    metrics.record_votes_cast(
                        pa.round,
                        pa.period,
                        PROPOSE,
                        message_events.len() as u64,
                    );
                    let ext_events: Vec<ExternalEvent> = message_events
                        .into_iter()
                        .map(|me| ExternalEvent {
                            event: crate::events::Event::Message(me),
                        })
                        .collect();
                    events_out.extend(ext_events);
                }
                Err(crate::pseudonode::PseudonodeError::NoVotes) => {
                    // No participation keys — do nothing.
                }
                Err(e) => {
                    warn!(
                        "pseudonode.make_votes failed for reproposal({}): {}",
                        pa.t, e
                    );
                }
            }
        }
        ActionType::Attest => {
            // Structured fields are additive: the human message keeps the
            // exact `attested to <ProposalValue> at (r, p, step)` shape that
            // `ops/mixed-cluster/scripts/{analyze,equivocation}.py` and
            // `restart-rejoin.sh` match on. tracing's default text formatter
            // prints `message` ahead of the other fields, so both consumers
            // — regex and key=value — see what they expect.
            info!(
                event = "attest",
                round = pa.round.0,
                period = pa.period.0,
                step = %pa.step,
                block_digest = %pa.proposal.block_digest,
                "attested to {:?} at ({}, {}, {})",
                pa.proposal,
                pa.round,
                pa.period,
                pa.step
            );

            // If persistence is available and we have saved state, persist
            // before making votes (matching Go's persist-before-broadcast).
            // Persistence failure aborts the attest entirely — votes must not
            // be broadcast without a crash-recovery record.
            let persistence_ok = if let (
                Some(ref pl),
                Some(ref p_router),
                Some(ref p_player),
                Some(ref p_actions),
            ) = (
                persistence_loop,
                persist_router,
                persist_player,
                persist_actions,
            ) {
                // Snapshot the wall-clock at checkpoint time. On a later
                // restore, `resume_from_clock_zero` measures elapsed since
                // this stamp — i.e. the crash downtime — and clamps the
                // restored player's outstanding deadlines by that interval.
                //
                // Using `SystemTime::now()` per-checkpoint (rather than a
                // fixed service-startup zero) ensures the elapsed math
                // reflects only downtime, not uptime, so a node that has
                // been up for hours still recovers correctly from a crash.
                // Mirrors go-algorand's encode-fresh-each-checkpoint
                // pattern in `agreement/service.go:282`.
                let clock_state = ClockState::with_zero(SystemTime::now());
                match persistence::encode(p_router, p_player, &clock_state, p_actions) {
                    Ok(raw) if !raw.is_empty() => {
                        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
                        let (events_tx, _events_rx) = crossbeam_channel::bounded(1);

                        let request = PersistentRequest {
                            round: pa.round,
                            period: pa.period,
                            step: pa.step,
                            raw,
                            done: done_tx,
                            clock: clock_state,
                            events: events_tx,
                        };

                        pl.enqueue(request);

                        // Wait synchronously for persistence to complete.
                        // The persistence loop runs in its own thread, so we
                        // just block here until it signals completion.
                        const PERSIST_TIMEOUT: Duration = Duration::from_secs(5);
                        match done_rx.recv_timeout(PERSIST_TIMEOUT) {
                            Ok(Ok(())) => true,
                            Ok(Err(e)) => {
                                warn!("persistence write failed, skipping attest: {}", e);
                                false
                            }
                            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                                warn!(
                                    "persistence write timed out after {:?}, skipping attest",
                                    PERSIST_TIMEOUT
                                );
                                false
                            }
                            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                                warn!("persistence loop disconnected, skipping attest");
                                false
                            }
                        }
                    }
                    Ok(_) => {
                        // Empty raw — encode produced nothing; skip attest.
                        warn!("persistence encode produced empty output, skipping attest");
                        false
                    }
                    Err(e) => {
                        // Encode failure — skip attest to preserve
                        // persist-before-broadcast guarantee.
                        warn!("persistence encode failed, skipping attest: {}", e);
                        false
                    }
                }
            } else {
                // No persistence configured — proceed without it.
                true
            };

            if persistence_ok {
                match pseudonode.make_votes(pa.round, pa.period, pa.step, pa.proposal, None) {
                    Ok(message_events) => {
                        // One message event per vote actually produced — i.e.
                        // per local account that won sortition at this step.
                        // Counting here (rather than at the log line above)
                        // means the counter reflects votes that exist, not
                        // attest actions that were attempted.
                        if !message_events.is_empty() {
                            info!(
                                event = "vote_cast",
                                round = pa.round.0,
                                period = pa.period.0,
                                step = %pa.step,
                                count = message_events.len(),
                                "cast {} vote(s) at ({}, {}, {})",
                                message_events.len(),
                                pa.round,
                                pa.period,
                                pa.step
                            );
                        }
                        metrics.record_votes_cast(
                            pa.round,
                            pa.period,
                            pa.step,
                            message_events.len() as u64,
                        );
                        let ext_events: Vec<ExternalEvent> = message_events
                            .into_iter()
                            .map(|me| ExternalEvent {
                                event: crate::events::Event::Message(me),
                            })
                            .collect();
                        events_out.extend(ext_events);
                    }
                    Err(crate::pseudonode::PseudonodeError::NoVotes) => {
                        // No participation keys — do nothing.
                    }
                    Err(e) => {
                        warn!("pseudonode.make_votes failed({}): {}", pa.t, e);
                    }
                }
            }
        }
        _ => {
            warn!("unexpected pseudonode action type: {}", pa.t);
        }
    }
}

/// Resume from a restored `ClockState` by clamping the restored player's
/// outstanding deadlines by the elapsed wall-clock crash downtime.
/// Returns the `SystemTime` adopted as the reference point (informational;
/// current persists always stamp `SystemTime::now()` fresh at checkpoint).
///
/// Semantics (mirrors go-algorand v4.6.0-stable `agreement/service.go:226-253`):
///
/// * `ClockState` carries the wall-clock stamp taken at the most recent
///   checkpoint (the last `Attest` before the crash). On restore we
///   measure `now - stamp` — this is exactly the crash downtime, not
///   service uptime — and reduce each outstanding player deadline by
///   that interval (saturating at zero so an already-expired timeout
///   fires immediately). Using checkpoint-time (not service-startup) as
///   the reference ensures nodes that have been up for hours still
///   recover correctly; otherwise the elapsed value would include total
///   uptime and over-subtract the deadlines.
/// * If the persisted stamp is in the future (wall-clock moved backwards
///   or the crash.sqlite state is bogus), we refuse to adjust deadlines
///   and return `now` — safer to run one round as if fresh than to
///   time-travel the state machine.
/// * If no stamp was persisted (legacy pre-TASK-62 state), we leave the
///   restored deadlines as-is and return `now`.
fn resume_from_clock_zero(player: &mut Player, clock: &ClockState, now: SystemTime) -> SystemTime {
    match clock.zero() {
        Some(zero) => match now.duration_since(zero) {
            Ok(elapsed) => {
                let deadline_before = player.deadline.duration;
                let fast_before = player.fast_recovery_deadline;
                player.deadline.duration = deadline_before.saturating_sub(elapsed);
                player.fast_recovery_deadline = fast_before.saturating_sub(elapsed);
                info!(
                    elapsed_ms = elapsed.as_millis() as u64,
                    deadline_before_ms = deadline_before.as_millis() as u64,
                    deadline_after_ms = player.deadline.duration.as_millis() as u64,
                    fast_before_ms = fast_before.as_millis() as u64,
                    fast_after_ms = player.fast_recovery_deadline.as_millis() as u64,
                    "resumed agreement clock; clamped restored deadlines by elapsed wall-clock",
                );
                zero
            }
            Err(_) => {
                warn!("restored clock zero is in the future; starting a fresh clock epoch");
                now
            }
        },
        None => {
            info!("restored agreement state has no clock zero; starting fresh clock epoch");
            now
        }
    }
}

/// The restored agreement state read back out of the crash-recovery
/// database: `(router, player, clock, pending actions)`.
pub(crate) type RestoredState = (RootRouter, Player, ClockState, Vec<Action>);

/// Read and decode crash-recovery state, mirroring go-algorand
/// v4.6.0-stable `agreement/service.go:mainLoop` lines 220-232.
///
/// Returns `None` when there is nothing usable to restore, in which case
/// the caller bootstraps a fresh player.
///
/// ## Go parity: reset on undecodable state
///
/// Go's `mainLoop` does:
///
/// ```text
/// raw, err := restore(...)
/// if err == nil {
///     clock, router, status, a, err = decode(raw, ...)
///     if err != nil {
///         reset(s.log, s.Accessor)   // <-- wipe the undecodable blob
///     }
/// }
/// ```
///
/// The `reset` is load-bearing for crash recovery: without it an
/// undecodable blob stays in the `Service` table across every subsequent
/// restart, so each boot re-reads and re-fails on the same bytes, and
/// (worse) any later code that treats "a row exists" as "we have crash
/// state" sees stale, unusable state. Go throws it away immediately and
/// starts clean. This port previously logged the decode error and moved
/// on without clearing the row; `reset` is now called to match.
///
/// A failure of `restore` itself (an I/O/SQL-level error) is NOT reset —
/// Go doesn't either, because the database is not known to be readable
/// or writable at that point.
pub(crate) fn restore_crash_state(conn: &rusqlite::Connection) -> Option<RestoredState> {
    match persistence::restore(conn) {
        Ok(Some(raw)) => match persistence::decode(&raw) {
            Ok((router, player, clock, actions)) => {
                info!(
                    "restored persisted agreement state at round {}, period {}, step {}",
                    player.round, player.period, player.step
                );
                Some((router, player, clock, actions))
            }
            Err(e) => {
                warn!(
                    "failed to decode persisted agreement state: {}; \
                     resetting crash state and starting fresh",
                    e
                );
                if let Err(reset_err) = persistence::reset(conn) {
                    warn!("failed to reset crash state after decode failure: {reset_err}");
                }
                None
            }
        },
        Ok(None) => {
            debug!("no persisted agreement state found; starting fresh");
            None
        }
        Err(e) => {
            warn!("failed to restore agreement state: {}; starting fresh", e);
            None
        }
    }
}

/// Decide the state the main loop starts from: the crash-recovered state
/// when it is still relevant, otherwise a fresh bootstrap at the ledger's
/// next round.
///
/// Mirrors go-algorand v4.6.0-stable `agreement/service.go:232-252`:
///
/// ```text
/// if err != nil || status.Round < s.Ledger.NextRound() {
///     ... fresh player at NextRound, actions = [assemble, rezero] ...
/// } else {
///     s.Clock = clock
/// }
/// ```
///
/// Restored state whose round has *already been committed* by the ledger
/// (`player.round < ledger.next_round`) is stale — the network moved on
/// while we were down and replaying it would re-drive a decided round —
/// so it is discarded. Restored state at or ahead of the ledger's next
/// round is adopted verbatim, together with its pending actions.
///
/// ## Why this is the equivocation guard
///
/// The pending-action list persisted alongside the player is written
/// *before* the corresponding `Attest` is broadcast (see the
/// `ActionType::Attest` arm above), so any vote that reached the wire had
/// its `(round, period, step, proposal)` durably recorded first. Adopting
/// the restored player verbatim therefore restarts the state machine at
/// the same `(round, period, step)` it crashed at, with the same staged
/// proposal — so a replayed attest re-signs the *identical* value rather
/// than a second, different one at the same step. Rewinding to an earlier
/// step (or bootstrapping fresh at a round already voted in) is what would
/// permit a double vote, and neither branch here does that.
fn initial_state(
    restored_state: Option<RestoredState>,
    next_round: Round,
    cparams: &algo_types::ConsensusParams,
    now: SystemTime,
) -> (RootRouter, Player, Vec<Action>) {
    let Some((r_router, mut r_player, r_clock, r_actions)) = restored_state else {
        return bootstrap_fresh(next_round, cparams);
    };

    // Use restored state only if it is still relevant (round >= ledger's next round).
    if r_player.round.0 >= next_round.0 {
        info!(
            "using restored agreement state at round {} (ledger next round {})",
            r_player.round, next_round
        );
        resume_from_clock_zero(&mut r_player, &r_clock, now);
        (r_router, r_player, r_actions)
    } else {
        info!(
            "restored agreement state at round {} is stale (ledger next round {}); \
             bootstrapping fresh",
            r_player.round, next_round
        );
        bootstrap_fresh(next_round, cparams)
    }
}

/// Create a fresh bootstrap state for the given round.
///
/// Returns (router, player, initial_actions).
fn bootstrap_fresh(
    next_round: Round,
    cparams: &algo_types::ConsensusParams,
) -> (RootRouter, Player, Vec<Action>) {
    let status = Player {
        round: next_round,
        step: SOFT,
        deadline: Deadline {
            duration: filter_timeout(Period(0), cparams),
            timeout_type: TimeoutType::Filter,
        },
        lowest_credential_arrivals: CredentialArrivalHistory::new(
            DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
        ),
        ..Player::default()
    };

    let router = RootRouter::new(&status);
    let player = status;

    let initial_actions = vec![
        Action::Pseudonode(PseudonodeAction {
            t: ActionType::Assemble,
            round: next_round,
            period: Period(0),
            step: Step(0),
            proposal: crate::vote::BOTTOM,
        }),
        Action::Rezero(RezeroAction { round: next_round }),
    ];

    (router, player, initial_actions)
}

// ---------------------------------------------------------------------------
// Demux loop
// ---------------------------------------------------------------------------

/// The demux loop executes pending actions and then retrieves the next event.
///
/// For each batch of actions from the main loop:
/// 1. Execute each action (network broadcasts, ledger writes, pseudonode ops).
/// 2. Wait for signals from the main loop indicating the current deadline.
/// 3. Retrieve the next external event from the Demux (blocks on channels).
/// 4. Send it to the main loop.
///
/// Mirrors Go's `Service.demuxLoop`.
#[allow(clippy::too_many_arguments)]
fn demux_loop<N, L, BV, C, M>(
    network: Arc<N>,
    ledger: Arc<L>,
    block_validator: BV,
    quit: Arc<AtomicBool>,
    input: mpsc::Sender<Option<ExternalEvent>>,
    output: mpsc::Receiver<Vec<Action>>,
    actions_done: mpsc::Sender<()>,
    ready: mpsc::Receiver<ExternalDemuxSignals>,
    pseudo_rx: mpsc::Receiver<Vec<ExternalEvent>>,
    mut demux: Demux,
    quit_demux_tx: crossbeam_channel::Sender<()>,
    crypto: C,
    monitor: Arc<Mutex<M>>,
    vote_verifier: Arc<AsyncVoteVerifier>,
    clock: Arc<dyn Clock>,
    metrics: Arc<ParticipationMetrics>,
) where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    BV: BlockValidator + Send + 'static,
    C: CryptoVerifier + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
{
    // Retain old rounds' period 0 start times for late credential tracking.
    let mut historical_clocks: HashMap<Round, Instant> = HashMap::new();

    for action_batch in output.iter() {
        if quit.load(Ordering::SeqCst) {
            break;
        }

        // Report the action batch size before executing.
        if let Ok(m) = monitor.lock() {
            m.update_events_queue(crate::demux::EVENT_QUEUE_DEMUX, action_batch.len());
        }

        // Execute each action.
        do_actions(
            &action_batch,
            &*network,
            &*ledger,
            &block_validator,
            &mut demux,
            &mut historical_clocks,
            &crypto,
            &vote_verifier,
            &clock,
            &metrics,
        );

        // Actions consumed — report queue drained.
        if let Ok(m) = monitor.lock() {
            m.update_events_queue(crate::demux::EVENT_QUEUE_DEMUX, 0);
        }

        // Acknowledge that the batch has been fully executed. The main loop
        // blocks on this before running the same batch's pseudonode actions,
        // which is what keeps Go's action ordering: `Ensure` (commit block
        // N-1) always completes before `Assemble` (build a proposal for round
        // N) runs. See the comment in `main_loop` (issue #482).
        if actions_done.send(()).is_err() {
            break;
        }

        // Get the signals from the main loop.
        let signals = match ready.recv() {
            Ok(s) => s,
            Err(_) => break,
        };

        // Drain any pseudonode events that the main loop produced and
        // prioritize them in the demux so they are returned first. The main
        // loop runs its pseudonode actions between the acknowledgement above
        // and the `ready` send received here, so by this point every event
        // from this batch's pseudonode actions is already queued.
        let mut pseudo_count = 0usize;
        while let Ok(events) = pseudo_rx.try_recv() {
            pseudo_count += events.len();
            demux.prioritize(events);
        }
        if pseudo_count > 0 {
            if let Ok(m) = monitor.lock() {
                m.update_events_queue(crate::demux::EVENT_QUEUE_PSEUDONODE, pseudo_count);
            }
        }

        // Refresh the ledger round notification channel before each select,
        // matching Go's `ledgerNextRoundCh := s.Ledger.Wait(nextRound)` which
        // is called on every invocation of `demux.next()`. This ensures the
        // one-shot channel is always fresh for the current round.
        let next_round = signals.current_round;
        demux.set_ledger_round_rx(ledger.round_notify(next_round));

        // Get the next event from the Demux. This blocks on channels via
        // crossbeam_channel::Select — no polling or sleep needed.
        let event = demux.next(&signals, Some(&crypto));

        match event {
            Some(e) => {
                // Report that we received an event from the demux.
                if let Ok(m) = monitor.lock() {
                    m.update_events_queue(crate::demux::EVENT_QUEUE_DEMUX, 1);
                }
                // Attach the credential/proposal validated-at timestamp,
                // mirroring Go's `demux.next()` deferred
                // `AttachValidatedAt(clockForRound(currentRound, s.Clock,
                // s.historicalClocks))` (agreement/demux.go:216-223). Must
                // happen before the event reaches the main loop, since
                // `player.updateCredentialArrivalHistory` reads
                // `Vote.validated_at` off the proposal-vote stored by the
                // proposal tracker.
                let e = e.attach_validated_at(|event_round| {
                    crate::clock::clock_for_round(
                        event_round,
                        next_round,
                        &clock,
                        &historical_clocks,
                    )
                });
                // Attach the proposal-payload received-at timestamp,
                // mirroring Go's `demux.next()` deferred
                // `AttachReceivedAt(clockForRound(currentRound, s.Clock,
                // s.historicalClocks))` (agreement/demux.go:217-218). Must
                // happen before the event reaches the main loop, since
                // `blockAssembler.bind` reads `pipeline.received_at` off
                // the proposal-store's pending payload.
                let e = e.attach_received_at(|event_round| {
                    crate::clock::clock_for_round(
                        event_round,
                        next_round,
                        &clock,
                        &historical_clocks,
                    )
                });
                if input.send(Some(e)).is_err() {
                    break;
                }
                // Pseudonode events consumed by demux.next().
                if let Ok(m) = monitor.lock() {
                    m.update_events_queue(crate::demux::EVENT_QUEUE_PSEUDONODE, 0);
                }
            }
            None => {
                // Demux returned None — quit signal received.
                let _ = input.send(None);
                break;
            }
        }
    }

    demux.quit();
    crypto.quit();
    vote_verifier.quit();
    let _ = quit_demux_tx.send(());
    let _ = input.send(None);
    debug!("agreement demux loop exited");
}

// ---------------------------------------------------------------------------
// Action execution
// ---------------------------------------------------------------------------

/// Execute a batch of actions.
///
/// Mirrors Go's `Service.do(ctx, actions)`.
#[allow(clippy::too_many_arguments)]
fn do_actions<N, L, BV, C>(
    actions: &[Action],
    network: &N,
    ledger: &L,
    block_validator: &BV,
    _demux: &mut Demux,
    historical_clocks: &mut HashMap<Round, Instant>,
    crypto: &C,
    vote_verifier: &AsyncVoteVerifier,
    clock: &Arc<dyn Clock>,
    metrics: &ParticipationMetrics,
) where
    N: AgreementNetwork,
    L: LedgerReader + LedgerWriter,
    BV: BlockValidator,
    C: CryptoVerifier,
{
    for action in actions {
        do_action(
            action,
            network,
            ledger,
            block_validator,
            historical_clocks,
            crypto,
            vote_verifier,
            clock,
            metrics,
        );
    }
}

/// Execute a single action.
///
/// Mirrors each action type's `do(ctx, s)` in Go.
#[allow(clippy::too_many_arguments)]
fn do_action<N, L, BV, C>(
    action: &Action,
    network: &N,
    ledger: &L,
    block_validator: &BV,
    historical_clocks: &mut HashMap<Round, Instant>,
    crypto: &C,
    vote_verifier: &AsyncVoteVerifier,
    clock: &Arc<dyn Clock>,
    metrics: &ParticipationMetrics,
) where
    N: AgreementNetwork,
    L: LedgerReader + LedgerWriter,
    BV: BlockValidator,
    C: CryptoVerifier,
{
    match action {
        Action::Noop(_) => {}

        Action::Network(ref na) => {
            do_network_action(na, network, metrics);
        }

        Action::Crypto(ref ca) => {
            do_crypto_action(ca, crypto);
        }

        Action::Ensure(ref ea) => {
            do_ensure_action(ea, ledger, block_validator, metrics);
        }

        Action::StageDigest(ref sda) => {
            do_stage_digest_action(sda, ledger, vote_verifier);
        }

        Action::Rezero(ref ra) => {
            // `Rezero` is the agreement service's own definition of "a new
            // round starts now" — it is the action that resets the deadline
            // clock the state machine measures every timeout against. Every
            // timing in `ParticipationMetrics` is anchored here so
            // round-start → vote / proposal / commit intervals are measured
            // against the same instant the protocol itself uses.
            metrics.record_round_started(ra.round);
            do_rezero_action(ra, historical_clocks, clock);
        }

        Action::Pseudonode(ref pa) => {
            // Pseudonode actions are executed by the main loop and results
            // are prioritized in the demux via the pseudo_rx channel.
            // If we still see one here, it was not filtered — just log.
            debug!("pseudonode action: {} (already handled by main loop)", pa);
        }

        Action::Checkpoint(ref ca) => {
            info!(
                event = "checkpoint",
                round = ca.round.0,
                period = ca.period.0,
                step = %ca.step,
                "checkpoint at ({}, {}, {})",
                ca.round,
                ca.period,
                ca.step
            );
        }
    }
}

/// Execute a network action (broadcast, relay, disconnect, ignore).
///
/// Mirrors Go's `networkAction.do`.
fn do_network_action<N: AgreementNetwork>(
    na: &NetworkAction,
    network: &N,
    metrics: &ParticipationMetrics,
) {
    match na.t {
        ActionType::BroadcastVotes => {
            let tag = Tag(AGREEMENT_VOTE_TAG);
            for uv in &na.unauthenticated_votes {
                let data = codec::encode_vote(uv);
                if let Err(e) = network.broadcast(&tag, &data) {
                    metrics.record_vote_broadcast_failure();
                    warn!(
                        event = "vote_broadcast_failed",
                        round = uv.raw_vote.round.0,
                        period = uv.raw_vote.period.0,
                        step = %uv.raw_vote.step,
                        err = %e,
                        "failed to broadcast vote: {}",
                        e
                    );
                    break;
                }
            }
        }
        ActionType::Broadcast => {
            if let Some((tag_str, data)) = encode_network_payload(na) {
                let tag = Tag(tag_str);
                if let Err(e) = network.broadcast(&tag, &data) {
                    warn!("failed to broadcast {}: {}", tag_str, e);
                }
            }
        }
        ActionType::Relay => {
            if let Some((tag_str, data)) = encode_network_payload(na) {
                let tag = Tag(tag_str);
                if let Err(e) = network.relay(&na.message_handle, &tag, &data) {
                    warn!("failed to relay {}: {}", tag_str, e);
                }
            }
        }
        ActionType::Disconnect => {
            debug!(
                event = "message_disconnect",
                err = na.err.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                "disconnecting peer over invalid message"
            );
            network.disconnect(&na.message_handle);
        }
        ActionType::Ignore => {
            // Intentionally no network side effect; log the filter reason so
            // dropped-message diagnosis (issue #497) doesn't require a rebuild.
            debug!(
                event = "message_ignored",
                err = na.err.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                "ignoring filtered message"
            );
        }
        _ => {
            warn!("unexpected network action type: {}", na.t);
        }
    }
}

/// Execute a crypto action (verify vote, verify payload, verify bundle).
///
/// Dispatches the verification request to the crypto verifier, which places
/// the result on its output channel. The demux loop will later pick up the
/// result via `verified_votes()` or `verified(tag)`.
///
/// Mirrors Go's `cryptoAction.do(ctx, s)` in agreement/actions.go.
fn do_crypto_action<C: CryptoVerifier>(ca: &CryptoAction, crypto: &C) {
    match ca.t {
        ActionType::VerifyVote => {
            crypto.verify_vote(CryptoVoteRequest {
                message: ca.m.clone(),
                task_index: ca.task_index,
                round: ca.round,
                period: ca.period,
            });
        }
        ActionType::VerifyPayload => {
            crypto.verify_proposal(CryptoProposalRequest {
                message: ca.m.clone(),
                task_index: ca.task_index,
                round: ca.round,
                period: ca.period,
                pinned: ca.pinned,
            });
        }
        ActionType::VerifyBundle => {
            crypto.verify_bundle(CryptoBundleRequest {
                message: ca.m.clone(),
                task_index: ca.task_index,
                round: ca.round,
                period: ca.period,
                certify: ca.step == crate::step::CERT,
            });
        }
        _ => {
            warn!("unexpected crypto action type: {}", ca.t);
        }
    }
}

/// Encode the network payload for a network action based on its tag.
///
/// Returns `None` for unknown tags — the caller should skip the action
/// rather than broadcast garbage data.
fn encode_network_payload(na: &NetworkAction) -> Option<(&'static str, Vec<u8>)> {
    if na.tag == AGREEMENT_VOTE_TAG {
        Some((
            AGREEMENT_VOTE_TAG,
            codec::encode_vote(&na.unauthenticated_vote),
        ))
    } else if na.tag == VOTE_BUNDLE_TAG {
        Some((
            VOTE_BUNDLE_TAG,
            codec::encode_bundle(&na.unauthenticated_bundle),
        ))
    } else if na.tag == PROPOSAL_PAYLOAD_TAG {
        // For proposal payloads, we encode the compound message as a
        // transmittedPayload (unauthenticatedProposal + PriorVote).
        Some((
            PROPOSAL_PAYLOAD_TAG,
            codec::encode_compound_message(&na.compound_message),
        ))
    } else {
        warn!("unknown network tag: {}, skipping action", na.tag);
        None
    }
}

/// Execute an ensure action (write a certified block to the ledger).
///
/// When the proposal carries a pre-validated block (`validated_block` is
/// `Some`), we use `ensure_validated_block` which skips re-validation.
/// Otherwise we fall back to `ensure_block`.  Mirrors Go's
/// `ensureAction.do` which checks `a.Payload.ve != nil`.
fn do_ensure_action<L: LedgerWriter, BV: BlockValidator>(
    ea: &EnsureAction,
    ledger: &L,
    block_validator: &BV,
    metrics: &ParticipationMetrics,
) {
    let block = &ea.payload.unauthenticated_proposal.block;

    // Recorded before the (blocking) ledger write so the round's measured
    // duration is agreement's own decision latency, not the ledger's commit
    // cost — the former is what "keeps pace with the Go nodes" is about.
    metrics.record_round_committed(ea.certificate.round, ea.certificate.proposal.block_digest);

    if let Some(ref vb) = ea.payload.validated_block {
        info!(
            event = "round_committed",
            round = ea.certificate.round.0,
            block_digest = %ea.certificate.proposal.block_digest,
            pre_validated = true,
            "committed round {} with pre-validated block {:?}",
            ea.certificate.round,
            ea.certificate.proposal.block_digest,
        );
        ledger.ensure_validated_block(vb.as_ref(), &ea.certificate);
    } else {
        info!(
            event = "round_committed",
            round = ea.certificate.round.0,
            block_digest = %ea.certificate.proposal.block_digest,
            pre_validated = false,
            "committed round {} with block {:?}",
            ea.certificate.round,
            ea.certificate.proposal.block_digest,
        );
        ledger.ensure_block(block, &ea.certificate);
    }

    // Update the block validator's previous timestamp so subsequent
    // validations use the correct reference point.
    block_validator.set_prev_timestamp(block.timestamp);
}

/// Execute a stage-digest action (signal the ledger to fetch a block).
///
/// Mirrors Go's `stageDigestAction.do`.
fn do_stage_digest_action<L: LedgerWriter>(
    sda: &StageDigestAction,
    ledger: &L,
    vote_verifier: &AsyncVoteVerifier,
) {
    info!(
        "round {} concluded without block for {:?}; waiting on ledger",
        sda.certificate.round, sda.certificate.proposal,
    );
    ledger.ensure_digest(&sda.certificate, vote_verifier);
}

/// Execute a rezero action (reset the clock).
///
/// Mirrors Go's `rezeroAction.do`, which does `s.Clock = s.Clock.Zero()`.
/// Resetting the active clock is **consensus-critical**: without it, after
/// the process has been up for longer than the step timeout the demux's
/// `clock.timeout_at(delta)` receivers would surface as "already elapsed"
/// immediately, firing spurious `Timeout`/`FastTimeout` events on every new
/// round / period boundary.
///
/// The `clock` `Arc<dyn Clock>` here is the same instance the `Demux` holds,
/// so the in-place `zero()` is visible to the next `timeout_at(...)` call.
fn do_rezero_action(
    ra: &RezeroAction,
    historical_clocks: &mut HashMap<Round, Instant>,
    clock: &Arc<dyn Clock>,
) {
    // Reset the active clock's zero reference to "now" — this is the
    // Rust equivalent of Go's `s.Clock = s.Clock.Zero()`.
    clock.zero();

    // Record the start time for this round (period 0) for late-credential
    // tracking / cadaver replay (orthogonal to the active clock).
    historical_clocks
        .entry(ra.round)
        .or_insert_with(Instant::now);

    // Garbage collect old clocks.
    let cred_lag = crate::types::credential_round_lag();
    historical_clocks.retain(|&rnd, _| ra.round.0 <= rnd.0.saturating_add(cred_lag));
}

// ---------------------------------------------------------------------------
// LedgerReaderRef — wrapper to pass Arc<L> as a LedgerReader
// ---------------------------------------------------------------------------

/// A wrapper that implements `LedgerReader` by delegating to an `Arc<L>`.
///
/// This is needed because `AsyncPseudonode` takes owned type parameters,
/// and we need to share the ledger between the main loop and demux loop.
struct LedgerReaderRef<L: LedgerReader + Send + Sync + 'static>(Arc<L>);

impl<L: LedgerReader + Send + Sync + 'static> LedgerReader for LedgerReaderRef<L> {
    fn next_round(&self) -> Round {
        self.0.next_round()
    }

    fn seed(&self, round: Round) -> Result<crate::seed::Seed, crate::ledger_reader::LedgerError> {
        self.0.seed(round)
    }

    fn lookup_agreement(
        &self,
        round: Round,
        addr: &algo_types::Address,
    ) -> Result<crate::ledger_reader::OnlineAccountData, crate::ledger_reader::LedgerError> {
        self.0.lookup_agreement(round, addr)
    }

    fn circulation(
        &self,
        rnd: Round,
        vote_rnd: Round,
    ) -> Result<u64, crate::ledger_reader::LedgerError> {
        self.0.circulation(rnd, vote_rnd)
    }

    fn lookup_digest(
        &self,
        round: Round,
    ) -> Result<algo_types::Digest, crate::ledger_reader::LedgerError> {
        self.0.lookup_digest(round)
    }

    fn consensus_params(
        &self,
        round: Round,
    ) -> Result<algo_types::ConsensusParams, crate::ledger_reader::LedgerError> {
        self.0.consensus_params(round)
    }

    fn consensus_version(&self, round: Round) -> Result<String, crate::ledger_reader::LedgerError> {
        self.0.consensus_version(round)
    }

    fn wait_for_round(&self, round: Round) -> Result<(), crate::ledger_reader::LedgerError> {
        self.0.wait_for_round(round)
    }

    fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
        self.0.round_notify(round)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::Certificate;
    use crate::stubs::{
        StubBlockFactory, StubBlockValidator, StubCryptoVerifier, StubEventsProcessingMonitor,
        StubLedger, StubNetwork, StubRandomSource,
    };
    use crate::traits::AgreementKeyManager;
    use algo_types::{Address, ConsensusParams, Round};
    use std::time::Duration;

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    struct TestKeyManager;

    impl AgreementKeyManager for TestKeyManager {
        fn voting_keys(
            &self,
            _voting_round: Round,
            _keys_round: Round,
        ) -> Vec<crate::traits::ParticipationRecord> {
            Vec::new()
        }

        fn record(
            &self,
            _account: &Address,
            _round: Round,
            _action: crate::traits::ParticipationAction,
        ) {
        }
    }

    #[test]
    fn service_construction() {
        let params = Parameters {
            network: StubNetwork::new(),
            ledger: StubLedger::new(v41_params(), Round(100)),
            key_manager: TestKeyManager,
            block_factory: StubBlockFactory::new(),
            block_validator: StubBlockValidator::accepting(),
            random_source: StubRandomSource::constant(42),
            monitor: StubEventsProcessingMonitor::new(),
            crypto: StubCryptoVerifier::new(),
            clock: crate::SystemClock::new(),
            crash_db: None,
            signing_keys: std::collections::HashMap::new(),
        };

        let _service = Service::new(params);
    }

    #[test]
    fn service_start_and_shutdown() {
        let params = Parameters {
            network: StubNetwork::new(),
            ledger: StubLedger::new(v41_params(), Round(100)),
            key_manager: TestKeyManager,
            block_factory: StubBlockFactory::new(),
            block_validator: StubBlockValidator::accepting(),
            random_source: StubRandomSource::constant(42),
            monitor: StubEventsProcessingMonitor::new(),
            crypto: StubCryptoVerifier::new(),
            clock: crate::SystemClock::new(),
            crash_db: None,
            signing_keys: std::collections::HashMap::new(),
        };

        let service = Service::new(params);
        let handle = service.start();

        // Give the service a moment to start up and run a few iterations.
        thread::sleep(Duration::from_millis(50));

        // Shutdown should complete without hanging.
        handle.shutdown();
    }

    #[test]
    fn service_handle_shutdown_signals_quit() {
        let quit = Arc::new(AtomicBool::new(false));
        let quit_clone = quit.clone();
        let handle = ServiceHandle {
            quit: quit_clone,
            threads: Vec::new(),
        };

        assert!(!quit.load(Ordering::SeqCst));
        handle.shutdown();
        assert!(quit.load(Ordering::SeqCst));
    }

    /// Port of go-algorand's `TestAgreementServiceStartDeadline`
    /// (`agreement/service_test.go:2513`) — theme 3 of issue #825
    /// ("service-level fast-recovery and regression scenarios").
    ///
    /// Drives `main_loop` directly (bypassing `Service::start`'s spawned
    /// demux thread, exactly as Go's test calls `s.mainLoop(...)` directly
    /// on the test goroutine) with a closed `input` channel so the loop
    /// bootstraps, emits exactly one `ExternalDemuxSignals` on `ready`, then
    /// exits on the very next (disconnected) `input.recv()`.
    ///
    /// Asserts the first `ready` signal reports:
    ///   - `deadline.duration` == `AgreementFilterTimeoutPeriod0` (period 0's
    ///     filter timeout — `bootstrap_fresh` seeds `player.deadline` from
    ///     `filter_timeout(Period(0), cparams)`), using a params fixture
    ///     whose period-0 filter timeout has been scaled 100x from the
    ///     default so a bug that instead used the steady-state
    ///     `agreement_filter_timeout` would be caught.
    ///   - `current_round` == the ledger's `next_round()`.
    ///
    /// A background thread stands in for the demux thread that
    /// `Service::start` would normally spawn: it drains `output` and acks
    /// each batch on `actions_done`, satisfying the handshake `main_loop`
    /// blocks on before it can reach the `ready.send(...)` call (see the
    /// "Step 1"/"Step 2" comments above `main_loop`'s body) — without this,
    /// `main_loop` would deadlock waiting for `actions_done.recv()`.
    #[test]
    fn main_loop_start_deadline_uses_period0_filter_timeout() {
        // Scale AgreementFilterTimeoutPeriod0 100x off the v41 default so a
        // regression that fell back to the steady-state filter timeout (or
        // any other duration) would fail this assertion, mirroring Go's
        // `testConsensusParams.AgreementFilterTimeoutPeriod0 *= 100`.
        let mut cparams = v41_params();
        cparams.agreement_filter_timeout_period0 *= 100;
        let expected_deadline = cparams.agreement_filter_timeout_period0;

        let next_round = Round(100);
        let ledger = Arc::new(StubLedger::new(cparams, next_round));

        let quit = Arc::new(AtomicBool::new(false));
        // Immediately-closed input channel: main_loop's first `input.recv()`
        // (after sending the bootstrap batch + the first ready signal)
        // observes a disconnected sender and breaks out of the loop, mirroring
        // Go's `close(inputCh)` before `s.mainLoop(...)` is called.
        let (input_tx, input_rx) = mpsc::channel::<Option<crate::demux::ExternalEvent>>();
        drop(input_tx);

        let (output_tx, output_rx) = mpsc::channel::<Vec<Action>>();
        let (actions_done_tx, actions_done_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<ExternalDemuxSignals>();
        let (pseudo_events_tx, _pseudo_events_rx) =
            mpsc::channel::<Vec<crate::demux::ExternalEvent>>();

        // Stand-in for the demux thread: ack every action batch so main_loop's
        // `actions_done.recv()` handshake unblocks and the loop can proceed to
        // send the ready signal.
        let drain_handle = thread::Builder::new()
            .name("test-drain-output".into())
            .spawn(move || {
                while output_rx.recv().is_ok() {
                    if actions_done_tx.send(()).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn drain thread");

        main_loop(
            ledger,
            TestKeyManager,
            StubBlockFactory::new(),
            StubRandomSource::constant(0),
            quit,
            input_rx,
            output_tx,
            actions_done_rx,
            ready_tx,
            pseudo_events_tx,
            None,
            None,
            std::collections::HashMap::new(),
            Arc::new(ParticipationMetrics::new()),
            Tracer::default(),
        );

        drain_handle.join().expect("drain thread should not panic");

        let signals = ready_rx
            .try_recv()
            .expect("main_loop must send exactly one ready signal before observing closed input");
        assert_eq!(
            signals.deadline.duration, expected_deadline,
            "bootstrap deadline must be period 0's filter timeout, not the steady-state one"
        );
        assert_eq!(
            signals.current_round, next_round,
            "bootstrap ready signal must report the ledger's next round"
        );

        // Exactly one signal — main_loop must exit on the next input.recv()
        // (disconnected) rather than looping again.
        assert!(
            ready_rx.try_recv().is_err(),
            "main_loop must exit after the input channel disconnects, not send a second signal"
        );
    }

    #[test]
    fn do_rezero_action_records_clock() {
        let mut clocks = HashMap::new();
        let ra = RezeroAction { round: Round(10) };
        let clock = crate::SystemClock::new();

        do_rezero_action(&ra, &mut clocks, &clock);

        assert!(clocks.contains_key(&Round(10)));
    }

    #[test]
    fn do_rezero_action_gc_old_clocks() {
        let mut clocks = HashMap::new();
        clocks.insert(Round(1), Instant::now());
        clocks.insert(Round(5), Instant::now());
        clocks.insert(Round(20), Instant::now());

        let ra = RezeroAction { round: Round(20) };
        let clock = crate::SystemClock::new();
        do_rezero_action(&ra, &mut clocks, &clock);

        // Round 1 should be GC'd (credential_round_lag = 8, 20 > 1 + 8 = 9)
        assert!(!clocks.contains_key(&Round(1)));
        // Round 5 should be GC'd (20 > 5 + 8 = 13)
        assert!(!clocks.contains_key(&Round(5)));
        // Round 20 should be kept
        assert!(clocks.contains_key(&Round(20)));
    }

    #[test]
    fn do_rezero_action_zeroes_active_clock() {
        // Regression: do_rezero_action must reset the active clock's zero
        // reference, not just record the historical_clocks entry. Without this,
        // the demux's clock.timeout_at(delta) returns already-elapsed receivers
        // once the service has been up longer than one step timeout, firing
        // spurious Timeout/FastTimeout events on every round boundary.
        let mut clocks = HashMap::new();
        let ra = RezeroAction { round: Round(10) };
        let clock = crate::SystemClock::new();

        // Accumulate wall-clock time on the clock.
        thread::sleep(Duration::from_millis(30));
        let before = clock.since();
        assert!(
            before >= Duration::from_millis(20),
            "test precondition: expected ~30ms elapsed, got {before:?}"
        );

        do_rezero_action(&ra, &mut clocks, &clock);

        let after = clock.since();
        assert!(
            after < before,
            "do_rezero_action did not reset the active clock (before={before:?}, after={after:?})"
        );
        assert!(
            after < Duration::from_millis(10),
            "clock.since() immediately after rezero was {after:?}; expected < 10ms"
        );
    }

    // ---------------- TASK-62: clock-state restore on agreement start ------

    /// Build a minimal player with known outstanding deadlines for clock
    /// resume tests. Only the fields the helper touches are set.
    fn player_with_deadlines(deadline: Duration, fast_recovery: Duration) -> Player {
        Player {
            deadline: Deadline {
                duration: deadline,
                timeout_type: TimeoutType::Filter,
            },
            fast_recovery_deadline: fast_recovery,
            ..Player::default()
        }
    }

    /// Persisting state at t=T and restoring at t=T+elapsed must clamp the
    /// player's outstanding deadlines by `elapsed`, mirroring the wall-clock
    /// anchoring that go-algorand does via `s.Clock = clock` at
    /// `agreement/service.go:252`. Covers TASK-62 / DOC-21 §3.8.
    #[test]
    fn resume_from_clock_zero_clamps_deadlines_by_elapsed_wall_clock() {
        let persist_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000);
        let clock = ClockState::with_zero(persist_time);

        // At persist time the player had 5s left on the main deadline and
        // 10s left on the fast-recovery deadline.
        let mut player = player_with_deadlines(Duration::from_secs(5), Duration::from_secs(10));

        // Simulate a restart 3 seconds later.
        let restart_time = persist_time + Duration::from_secs(3);
        let adopted_zero = resume_from_clock_zero(&mut player, &clock, restart_time);

        // The adopted epoch must be the persisted zero — subsequent
        // persists have to anchor against the same reference point.
        assert_eq!(adopted_zero, persist_time);
        // Deadlines are clamped by the wall-clock elapsed (3s).
        assert_eq!(player.deadline.duration, Duration::from_secs(2));
        assert_eq!(player.fast_recovery_deadline, Duration::from_secs(7));
    }

    /// A deadline that has already fully elapsed pre-restart must come back
    /// as zero so the agreement service fires it immediately rather than
    /// waiting the full original duration all over again.
    #[test]
    fn resume_from_clock_zero_saturates_past_deadlines_to_zero() {
        let persist_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000);
        let clock = ClockState::with_zero(persist_time);

        // 2s of outstanding deadline, but we restart 10s later.
        let mut player = player_with_deadlines(Duration::from_secs(2), Duration::from_secs(4));
        let restart_time = persist_time + Duration::from_secs(10);
        let zero = resume_from_clock_zero(&mut player, &clock, restart_time);

        assert_eq!(zero, persist_time);
        assert_eq!(player.deadline.duration, Duration::ZERO);
        assert_eq!(player.fast_recovery_deadline, Duration::ZERO);
    }

    /// Pre-TASK-62 persisted state has no zero. The helper must not touch
    /// the deadlines and must adopt `now` as the new epoch.
    #[test]
    fn resume_from_clock_zero_with_no_persisted_zero_keeps_deadlines() {
        let clock = ClockState::default();
        let mut player = player_with_deadlines(Duration::from_secs(5), Duration::from_secs(10));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);

        let zero = resume_from_clock_zero(&mut player, &clock, now);

        assert_eq!(zero, now);
        assert_eq!(player.deadline.duration, Duration::from_secs(5));
        assert_eq!(player.fast_recovery_deadline, Duration::from_secs(10));
    }

    /// If the persisted zero is in the future (clock drift, bogus state)
    /// the helper must refuse to adjust deadlines and rebase the epoch to
    /// `now`. Better to run one round as if fresh than to time-travel.
    #[test]
    fn resume_from_clock_zero_rejects_future_zero() {
        let persist_time = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000_000);
        let clock = ClockState::with_zero(persist_time);

        let mut player = player_with_deadlines(Duration::from_secs(5), Duration::from_secs(10));
        // "now" is before the persisted zero.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let zero = resume_from_clock_zero(&mut player, &clock, now);

        assert_eq!(zero, now);
        assert_eq!(player.deadline.duration, Duration::from_secs(5));
        assert_eq!(player.fast_recovery_deadline, Duration::from_secs(10));
    }

    /// End-to-end: encode a `ClockState` with a specific zero, persist it
    /// through the SQLite `persist`/`restore`/`decode` pipeline, and confirm
    /// `resume_from_clock_zero` still clamps by the right amount after
    /// everything round-trips. This is the acceptance-criterion test from
    /// TASK-62: "persist state at t=T, simulate restart, verify clock offset
    /// restored."
    #[test]
    fn persist_then_restore_preserves_clock_offset_end_to_end() {
        use crate::persistence::{decode, encode, persist, restore};

        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");

        let persist_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000);
        let clock = ClockState::with_zero(persist_time);
        let router = RootRouter::default();
        // The player's round has to be >= ledger next round for the
        // service-level restore branch to apply; the helper itself does not
        // care about round, so we use a non-zero one for realism.
        let persisted_player = Player {
            round: Round(42),
            deadline: Deadline {
                duration: Duration::from_secs(5),
                timeout_type: TimeoutType::Filter,
            },
            fast_recovery_deadline: Duration::from_secs(10),
            ..Player::default()
        };
        let raw = encode(&router, &persisted_player, &clock, &[]).expect("encode");
        persist(&conn, &raw).expect("persist");

        // Simulate a crash + restart 3 seconds later.
        let raw_back = restore(&conn).expect("restore").expect("state present");
        let (_dec_router, mut dec_player, dec_clock, _dec_actions) =
            decode(&raw_back).expect("decode");

        // Sanity: the encoded player matches what we persisted.
        assert_eq!(dec_player.round, Round(42));
        assert_eq!(dec_player.deadline.duration, Duration::from_secs(5));
        assert_eq!(dec_player.fast_recovery_deadline, Duration::from_secs(10));
        assert_eq!(dec_clock.zero(), Some(persist_time));

        // Apply the service-level restore logic.
        let restart_time = persist_time + Duration::from_secs(3);
        let adopted_zero = resume_from_clock_zero(&mut dec_player, &dec_clock, restart_time);

        assert_eq!(adopted_zero, persist_time);
        assert_eq!(dec_player.deadline.duration, Duration::from_secs(2));
        assert_eq!(dec_player.fast_recovery_deadline, Duration::from_secs(7));
    }

    #[test]
    fn do_ensure_action_writes_block() {
        let ledger = StubLedger::new(v41_params(), Round(100));
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: crate::vote::ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: algo_types::Digest([0xaa; 32]),
                encoding_digest: algo_types::Digest([0xbb; 32]),
            },
            votes: vec![],
        };
        let ea = EnsureAction {
            payload: crate::events::Proposal::default(),
            certificate: cert.clone(),
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        };

        let validator = StubBlockValidator::accepting();
        do_ensure_action(&ea, &ledger, &validator, &ParticipationMetrics::new());

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].cert.round, Round(100));
    }

    /// The ensure action is the wiring point for the commit counters and the
    /// round-duration timing (issue #473): committing a round the node
    /// proposed must credit `proposals_accepted`, and the measured duration
    /// must be anchored at the `Rezero` for that round.
    #[test]
    fn do_ensure_action_records_participation_metrics() {
        use crate::metrics::ManualMetricsClock;

        let clock = Arc::new(ManualMetricsClock::new());
        let metrics = ParticipationMetrics::with_clock(clock.clone());
        let own_digest = algo_types::Digest([0xaa; 32]);

        // Round start, then our own proposal, then the commit.
        metrics.record_round_started(Round(100));
        clock.advance_ms(250);
        metrics.record_proposal_made(Round(100), Period(0), &[own_digest]);
        clock.advance_ms(1750);

        let ledger = StubLedger::new(v41_params(), Round(100));
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: crate::vote::ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: own_digest,
                encoding_digest: algo_types::Digest([0xbb; 32]),
            },
            votes: vec![],
        };
        let ea = EnsureAction {
            payload: crate::events::Proposal::default(),
            certificate: cert,
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        };

        do_ensure_action(&ea, &ledger, &StubBlockValidator::accepting(), &metrics);

        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_committed, 1);
        assert_eq!(snap.last_committed_round, 100);
        assert_eq!(snap.proposals_accepted, 1);
        assert_eq!(snap.proposals_rejected, 0);
        assert_eq!(snap.round_duration.last_ms, 2000);
        assert_eq!(snap.round_start_to_proposal.last_ms, 250);
    }

    /// A round committed with someone else's block, while this node also
    /// proposed, must count as a rejection rather than an acceptance.
    #[test]
    fn do_ensure_action_records_rejected_own_proposal() {
        let metrics = ParticipationMetrics::new();
        metrics.record_round_started(Round(100));
        metrics.record_proposal_made(Round(100), Period(0), &[algo_types::Digest([0x11; 32])]);

        let ledger = StubLedger::new(v41_params(), Round(100));
        let ea = EnsureAction {
            payload: crate::events::Proposal::default(),
            certificate: Certificate {
                round: Round(100),
                period: Period(0),
                proposal: crate::vote::ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x02; 32]),
                    block_digest: algo_types::Digest([0x99; 32]),
                    encoding_digest: algo_types::Digest([0xbb; 32]),
                },
                votes: vec![],
            },
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        };

        do_ensure_action(&ea, &ledger, &StubBlockValidator::accepting(), &metrics);

        let snap = metrics.snapshot();
        assert_eq!(snap.proposals_accepted, 0);
        assert_eq!(snap.proposals_rejected, 1);
    }

    /// `Action::Rezero` is what stamps "round start"; dispatching it through
    /// `do_action` must move the metrics' current round.
    #[test]
    fn do_action_rezero_starts_a_metrics_round() {
        let metrics = ParticipationMetrics::new();
        let network = StubNetwork::new();
        let ledger = StubLedger::new(v41_params(), Round(7));
        let validator = StubBlockValidator::accepting();
        let crypto = StubCryptoVerifier::new();
        let verifier = AsyncVoteVerifier::new();
        let clock: Arc<dyn Clock> = crate::system_clock::SystemClock::new();
        let mut historical = HashMap::new();

        do_action(
            &Action::Rezero(RezeroAction { round: Round(7) }),
            &network,
            &ledger,
            &validator,
            &mut historical,
            &crypto,
            &verifier,
            &clock,
            &metrics,
        );

        let snap = metrics.snapshot();
        assert_eq!(snap.rounds_started, 1);
        assert_eq!(snap.current_round, 7);
    }

    /// When the proposal has `validated_block: None`, the ensure action must
    /// take the slow path (`ensure_block`) and the written block record must
    /// have `pre_validated: false`.
    #[test]
    fn do_ensure_action_none_validated_block_uses_slow_path() {
        let ledger = StubLedger::new(v41_params(), Round(100));
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: crate::vote::ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: algo_types::Digest([0xaa; 32]),
                encoding_digest: algo_types::Digest([0xbb; 32]),
            },
            votes: vec![],
        };
        let ea = EnsureAction {
            payload: crate::events::Proposal {
                validated_block: None,
                ..crate::events::Proposal::default()
            },
            certificate: cert,
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        };

        let validator = StubBlockValidator::accepting();
        do_ensure_action(&ea, &ledger, &validator, &ParticipationMetrics::new());

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
        assert!(
            !written[0].pre_validated,
            "expected slow path (pre_validated: false) when validated_block is None"
        );
    }

    /// When the proposal carries a pre-validated block (`validated_block:
    /// Some(...)`), the ensure action must take the fast path
    /// (`ensure_validated_block`) and the written block record must have
    /// `pre_validated: true`.
    #[test]
    fn do_ensure_action_with_pre_validated_block_uses_fast_path() {
        use crate::stubs::StubValidatedBlock;
        use std::sync::Arc;

        let ledger = StubLedger::new(v41_params(), Round(100));
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: crate::vote::ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: algo_types::Digest([0xaa; 32]),
                encoding_digest: algo_types::Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let stub_vb = StubValidatedBlock {
            block: algo_types::Block::default(),
        };
        let validated_block: Arc<dyn crate::traits::ValidatedBlock + Send + Sync> =
            Arc::new(stub_vb);

        let ea = EnsureAction {
            payload: crate::events::Proposal {
                validated_block: Some(validated_block),
                ..crate::events::Proposal::default()
            },
            certificate: cert,
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        };

        let validator = StubBlockValidator::accepting();
        do_ensure_action(&ea, &ledger, &validator, &ParticipationMetrics::new());

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
        assert!(
            written[0].pre_validated,
            "expected fast path (pre_validated: true) when validated_block is Some"
        );
    }

    #[test]
    fn do_stage_digest_action_records() {
        let ledger = StubLedger::new(v41_params(), Round(100));
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: crate::vote::ProposalValue::default(),
            votes: vec![],
        };
        let sda = StageDigestAction {
            certificate: cert.clone(),
        };
        let verifier = AsyncVoteVerifier::new();

        do_stage_digest_action(&sda, &ledger, &verifier);

        let ensured = ledger.get_ensured_digests();
        assert_eq!(ensured.len(), 1);
        assert_eq!(ensured[0].round, Round(100));
    }

    #[test]
    fn do_network_action_ignore() {
        let network = StubNetwork::new();
        let na = NetworkAction {
            t: ActionType::Ignore,
            ..NetworkAction::default()
        };

        do_network_action(&na, &network, &ParticipationMetrics::new());

        // Ignore should not send anything.
        assert!(network.get_sent().is_empty());
    }

    #[test]
    fn do_network_action_broadcast() {
        let network = StubNetwork::new();
        let na = NetworkAction {
            t: ActionType::Broadcast,
            tag: AGREEMENT_VOTE_TAG.to_string(),
            ..NetworkAction::default()
        };

        do_network_action(&na, &network, &ParticipationMetrics::new());

        let sent = network.get_sent();
        assert_eq!(sent.len(), 1);
        assert!(!sent[0].is_relay);
    }

    #[test]
    fn do_network_action_relay() {
        let network = StubNetwork::new();
        let na = NetworkAction {
            t: ActionType::Relay,
            tag: AGREEMENT_VOTE_TAG.to_string(),
            ..NetworkAction::default()
        };

        do_network_action(&na, &network, &ParticipationMetrics::new());

        let sent = network.get_sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].is_relay);
    }

    #[test]
    fn do_network_action_disconnect() {
        let network = StubNetwork::new();
        let na = NetworkAction {
            t: ActionType::Disconnect,
            ..NetworkAction::default()
        };

        do_network_action(&na, &network, &ParticipationMetrics::new());

        // Should have recorded a disconnect.
        let disc = network.disconnected.lock().unwrap();
        assert_eq!(disc.len(), 1);
    }

    #[test]
    fn ledger_reader_ref_delegates() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(42)));
        let reader_ref = LedgerReaderRef(ledger.clone());

        assert_eq!(reader_ref.next_round(), Round(42));
        assert!(reader_ref.consensus_params(Round(1)).is_ok());
    }

    // -----------------------------------------------------------------
    // Issue #471 — restart / rejoin crash-recovery semantics.
    //
    // These exercise the two functions the agreement service uses to
    // decide what state it wakes up in after a restart:
    //
    //   * `restore_crash_state` — read + decode the crash DB, mirroring
    //     go-algorand `agreement/service.go:220-231` (including the
    //     `reset()` on an undecodable blob).
    //   * `initial_state`       — adopt vs. discard the restored state,
    //     mirroring `agreement/service.go:232-252`.
    //
    // The safety property under test is *no equivocation*: a restart
    // must never put the player back at a `(round, period, step)` it has
    // already voted in with a different value, and must never rewind to
    // an earlier step within a round it already voted in.
    // -----------------------------------------------------------------

    use crate::actions::{NoopAction, PseudonodeAction};
    use crate::persistence::{encode, persist};
    use crate::router::{PeriodRouter, RoundRouter};
    use crate::step::{CERT, NEXT, PROPOSE};
    use crate::vote::{ProposalValue, BOTTOM};
    use algo_types::Digest;

    fn crash_db() -> rusqlite::Connection {
        rusqlite::Connection::open_in_memory().expect("in-memory crash db")
    }

    fn proposal(seed: u8) -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([seed; 32]),
            block_digest: Digest([seed; 32]),
            encoding_digest: Digest([seed.wrapping_add(0x10); 32]),
        }
    }

    /// Build the state a node would have persisted at the checkpoint just
    /// before broadcasting a vote for `value` at `(round, period, step)`:
    /// a player parked at that coordinate, a router with `value` staged in
    /// that period, and the pending `Attest` action itself.
    ///
    /// This mirrors the `ActionType::Attest` arm of `do_pseudonode_action`,
    /// which encodes `persist_router` / `persist_player` / `persist_actions`
    /// and waits for the write to land *before* the vote reaches the wire.
    fn checkpoint_before_vote(
        round: Round,
        period: Period,
        step: Step,
        value: ProposalValue,
    ) -> (RootRouter, Player, Vec<Action>) {
        let player = Player {
            round,
            period,
            step,
            deadline: Deadline {
                duration: Duration::from_secs(4),
                timeout_type: TimeoutType::Deadline,
            },
            ..Player::default()
        };

        let mut period_router = PeriodRouter::default();
        period_router.proposal_tracker.staging = value;
        let mut round_router = RoundRouter::default();
        round_router.children.insert(period, period_router);
        let mut router = RootRouter::default();
        router.children.insert(round, round_router);

        let actions = vec![Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            round,
            period,
            step,
            proposal: value,
        })];

        (router, player, actions)
    }

    /// Write a checkpoint into `conn` exactly as the persistence loop would.
    fn write_checkpoint(
        conn: &rusqlite::Connection,
        router: &RootRouter,
        player: &Player,
        actions: &[Action],
        zero: SystemTime,
    ) {
        let raw = encode(router, player, &ClockState::with_zero(zero), actions).expect("encode");
        persist(conn, &raw).expect("persist");
    }

    // -- restore_crash_state ------------------------------------------

    #[test]
    fn restore_crash_state_returns_none_on_empty_db() {
        let conn = crash_db();
        assert!(
            restore_crash_state(&conn).is_none(),
            "an empty crash DB must yield a fresh bootstrap, not a restore"
        );
    }

    #[test]
    fn restore_crash_state_round_trips_a_checkpoint() {
        let conn = crash_db();
        let value = proposal(0x7A);
        let (router, player, actions) = checkpoint_before_vote(Round(880), Period(3), SOFT, value);
        write_checkpoint(&conn, &router, &player, &actions, SystemTime::now());

        let (dec_router, dec_player, _clock, dec_actions) =
            restore_crash_state(&conn).expect("checkpoint must be restorable");

        assert_eq!(dec_player.round, Round(880));
        assert_eq!(dec_player.period, Period(3));
        assert_eq!(dec_player.step, SOFT);
        assert_eq!(
            dec_router.children[&Round(880)].children[&Period(3)]
                .proposal_tracker
                .staging,
            value,
            "the staged proposal must survive the restart"
        );
        assert_eq!(dec_actions.len(), 1);
        match &dec_actions[0] {
            Action::Pseudonode(pa) => {
                assert_eq!(pa.t, ActionType::Attest);
                assert_eq!(
                    (pa.round, pa.period, pa.step),
                    (Round(880), Period(3), SOFT)
                );
                assert_eq!(pa.proposal, value);
            }
            other => panic!("expected a pending Attest action, got {other:?}"),
        }
    }

    /// go-algorand wipes the `Service` row when `decode` fails
    /// (`agreement/service.go:225-227`, `reset(s.log, s.Accessor)`), so a
    /// corrupt blob never survives to be re-read on the next boot. This
    /// port previously only logged and left the row in place.
    #[test]
    fn restore_crash_state_resets_the_db_on_a_corrupt_blob() {
        let conn = crash_db();
        persist(&conn, &[0xDE, 0xAD, 0xBE, 0xEF]).expect("persist garbage");

        assert!(
            restore_crash_state(&conn).is_none(),
            "a corrupt blob must not be adopted as agreement state"
        );
        assert!(
            crate::persistence::restore(&conn)
                .expect("restore")
                .is_none(),
            "go-algorand resets the crash DB after a decode failure; \
             the undecodable row must be gone"
        );
    }

    /// A truncated blob is the realistic SIGKILL failure mode (the write
    /// was in flight when the process died). Same handling as garbage.
    #[test]
    fn restore_crash_state_resets_the_db_on_a_truncated_blob() {
        let conn = crash_db();
        let (router, player, actions) =
            checkpoint_before_vote(Round(12), Period(0), SOFT, proposal(1));
        let raw = encode(
            &router,
            &player,
            &ClockState::with_zero(SystemTime::now()),
            &actions,
        )
        .expect("encode");
        persist(&conn, &raw[..raw.len() / 2]).expect("persist truncated");

        assert!(restore_crash_state(&conn).is_none());
        assert!(crate::persistence::restore(&conn)
            .expect("restore")
            .is_none());
    }

    // -- initial_state: adopt vs. discard ------------------------------

    /// Restart mid-period: the ledger has NOT moved past the crashed
    /// round, so the restored player is adopted verbatim — same round,
    /// same period, same step, same pending attest. Go:
    /// `status.Round >= s.Ledger.NextRound()` takes the `else` branch and
    /// keeps the decoded player.
    #[test]
    fn initial_state_adopts_restored_state_mid_period() {
        let value = proposal(0x33);
        let (router, player, actions) = checkpoint_before_vote(Round(500), Period(4), NEXT, value);
        let now = SystemTime::now();
        let restored = Some((router, player, ClockState::with_zero(now), actions));

        let (out_router, out_player, out_actions) =
            initial_state(restored, Round(500), &v41_params(), now);

        assert_eq!(out_player.round, Round(500));
        assert_eq!(
            out_player.period,
            Period(4),
            "a restart must not rewind the period — re-voting in an earlier \
             period is exactly how a node equivocates"
        );
        assert_eq!(
            out_player.step, NEXT,
            "a restart must not rewind the step within the period"
        );
        assert_eq!(
            out_router.children[&Round(500)].children[&Period(4)]
                .proposal_tracker
                .staging,
            value
        );
        assert_eq!(out_actions.len(), 1);
    }

    /// Restart with a pending proposal to re-broadcast: the whole action
    /// list is replayed, unchanged, so the replayed vote carries the same
    /// value the pre-crash vote did.
    #[test]
    fn initial_state_replays_the_pending_attest_unchanged() {
        let value = proposal(0x91);
        let (router, player, actions) = checkpoint_before_vote(Round(77), Period(0), SOFT, value);
        let now = SystemTime::now();
        let restored = Some((router, player, ClockState::with_zero(now), actions.clone()));

        let (_r, _p, out_actions) = initial_state(restored, Round(77), &v41_params(), now);

        assert_eq!(out_actions.len(), actions.len());
        for (replayed, original) in out_actions.iter().zip(actions.iter()) {
            let (Action::Pseudonode(a), Action::Pseudonode(b)) = (replayed, original) else {
                panic!("expected pseudonode actions");
            };
            assert_eq!(
                (a.t, a.round, a.period, a.step, a.proposal),
                (b.t, b.round, b.period, b.step, b.proposal),
                "the replayed attest must be byte-for-byte the vote that was \
                 already signed — a *different* value at the same coordinate \
                 would be an equivocation"
            );
        }
    }

    /// Stale restored state (the network committed the crashed round while
    /// we were down) is discarded in favour of a fresh bootstrap at the
    /// ledger's next round. Go: `status.Round < s.Ledger.NextRound()`.
    #[test]
    fn initial_state_discards_stale_restored_state() {
        let (router, player, actions) =
            checkpoint_before_vote(Round(100), Period(2), CERT, proposal(0x44));
        let now = SystemTime::now();
        let restored = Some((router, player, ClockState::with_zero(now), actions));

        let (out_router, out_player, out_actions) =
            initial_state(restored, Round(104), &v41_params(), now);

        assert_eq!(
            out_player.round,
            Round(104),
            "must jump to the ledger round"
        );
        assert_eq!(out_player.period, Period(0));
        assert_eq!(out_player.step, SOFT);
        assert!(
            !out_router.children.contains_key(&Round(100)),
            "stale router state must not be carried into the fresh bootstrap"
        );
        // Fresh bootstrap actions: [Assemble(next_round), Rezero(next_round)].
        assert_eq!(out_actions.len(), 2);
        match (&out_actions[0], &out_actions[1]) {
            (Action::Pseudonode(a), Action::Rezero(r)) => {
                assert_eq!(a.t, ActionType::Assemble);
                assert_eq!(a.round, Round(104));
                assert_eq!(a.proposal, BOTTOM);
                assert_eq!(r.round, Round(104));
            }
            other => panic!("unexpected bootstrap actions: {other:?}"),
        }
        assert!(
            !crate::persistence::persistent(&out_actions),
            "a fresh bootstrap must not carry a pending attest — it would \
             be a vote at a coordinate this node never reached"
        );
    }

    /// Boundary: restored round == ledger next round is *not* stale. Go
    /// uses a strict `<` for the stale test, so the equal case is adopted.
    /// Getting this wrong by one would throw away the state for exactly
    /// the round the node was mid-vote in — the equivocation-critical one.
    #[test]
    fn initial_state_boundary_equal_round_is_adopted() {
        let (router, player, actions) =
            checkpoint_before_vote(Round(300), Period(1), CERT, proposal(0x55));
        let now = SystemTime::now();
        let restored = Some((router, player, ClockState::with_zero(now), actions));

        let (_r, out_player, out_actions) = initial_state(restored, Round(300), &v41_params(), now);

        assert_eq!(out_player.round, Round(300));
        assert_eq!(out_player.period, Period(1));
        assert_eq!(out_player.step, CERT);
        assert!(crate::persistence::persistent(&out_actions));
    }

    /// Restored state *ahead* of the ledger (the node voted in round R+1
    /// before the ledger finished committing R) is also adopted.
    #[test]
    fn initial_state_adopts_future_restored_round() {
        let (router, player, actions) =
            checkpoint_before_vote(Round(301), Period(0), SOFT, proposal(0x66));
        let now = SystemTime::now();
        let restored = Some((router, player, ClockState::with_zero(now), actions));

        let (_r, out_player, _a) = initial_state(restored, Round(300), &v41_params(), now);

        assert_eq!(out_player.round, Round(301));
    }

    /// No crash DB / nothing persisted → fresh bootstrap.
    #[test]
    fn initial_state_bootstraps_when_nothing_was_restored() {
        let (_router, player, actions) =
            initial_state(None, Round(9), &v41_params(), SystemTime::now());
        assert_eq!(player.round, Round(9));
        assert_eq!(player.step, SOFT);
        assert_eq!(actions.len(), 2);
    }

    // -- end-to-end: crash DB -> restart, at every step ----------------

    /// The scope-1 sweep: for each step a node can be parked at when it
    /// crashes, drive the *full* production path — checkpoint written by
    /// the persistence encoder, process dies, `restore_crash_state` +
    /// `initial_state` on the way back up — and assert the node resumes at
    /// the identical `(round, period, step)` with the identical staged
    /// value and pending vote.
    #[test]
    fn restart_at_every_step_resumes_at_the_same_coordinate() {
        for (i, step) in [PROPOSE, SOFT, CERT, NEXT, Step(4), Step(9)]
            .into_iter()
            .enumerate()
        {
            for period in [Period(0), Period(1), Period(5)] {
                let conn = crash_db();
                let value = proposal(0xA0 + i as u8);
                let round = Round(1_000 + i as u64);
                let (router, player, actions) = checkpoint_before_vote(round, period, step, value);
                let zero = SystemTime::now();
                write_checkpoint(&conn, &router, &player, &actions, zero);

                // ---- process dies here; everything above is on disk ----

                let restored = restore_crash_state(&conn).expect("restorable");
                let (out_router, out_player, out_actions) =
                    initial_state(Some(restored), round, &v41_params(), zero);

                assert_eq!(
                    (out_player.round, out_player.period, out_player.step),
                    (round, period, step),
                    "restart at step {step} period {period} must resume at the \
                     same coordinate"
                );
                assert_eq!(
                    out_router.children[&round].children[&period]
                        .proposal_tracker
                        .staging,
                    value,
                    "restart at step {step} must resume with the same staged value"
                );
                let Action::Pseudonode(pa) = &out_actions[0] else {
                    panic!("expected replayed attest");
                };
                assert_eq!(
                    (pa.round, pa.period, pa.step, pa.proposal),
                    (round, period, step, value),
                    "restart at step {step} must replay the identical vote, \
                     never a second value at the same coordinate"
                );
            }
        }
    }

    /// The explicit no-equivocation assertion for the soft-vote case named
    /// in issue #471: a node that already soft-voted for value X in
    /// `(R, P)` and then crashed comes back staged on X — the restart can
    /// only ever reproduce that vote, never manufacture a vote for a
    /// different value at `(R, P, soft)`.
    #[test]
    fn restart_after_a_soft_vote_cannot_produce_a_second_soft_value() {
        let conn = crash_db();
        let voted_for = proposal(0xC1);
        let other = proposal(0xC2);
        assert_ne!(voted_for, other);

        let (router, player, actions) =
            checkpoint_before_vote(Round(4_242), Period(2), SOFT, voted_for);
        let zero = SystemTime::now();
        write_checkpoint(&conn, &router, &player, &actions, zero);

        let restored = restore_crash_state(&conn).expect("restorable");
        let (out_router, out_player, out_actions) =
            initial_state(Some(restored), Round(4_242), &v41_params(), zero);

        assert_eq!(
            (out_player.round, out_player.period, out_player.step),
            (Round(4_242), Period(2), SOFT)
        );

        // Every attest the restart is about to replay is for `voted_for`.
        let replayed: Vec<_> = out_actions
            .iter()
            .filter_map(|a| match a {
                Action::Pseudonode(pa) if pa.t == ActionType::Attest => Some(pa.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].proposal, voted_for);
        assert_ne!(replayed[0].proposal, other);

        // And the staged value the state machine will keep voting for in
        // this period is the same one, so a later step in the same period
        // cannot diverge onto `other` either.
        assert_eq!(
            out_router.children[&Round(4_242)].children[&Period(2)]
                .proposal_tracker
                .staging,
            voted_for
        );
    }

    /// A crash checkpoint with no persistent action (e.g. only a `Noop`)
    /// still restores, and still must not be treated as a pending vote.
    #[test]
    fn restart_with_a_non_persistent_action_list_replays_no_vote() {
        let conn = crash_db();
        let player = Player {
            round: Round(60),
            period: Period(1),
            step: CERT,
            ..Player::default()
        };
        write_checkpoint(
            &conn,
            &RootRouter::default(),
            &player,
            &[Action::Noop(NoopAction)],
            SystemTime::now(),
        );

        let restored = restore_crash_state(&conn).expect("restorable");
        let (_r, out_player, out_actions) =
            initial_state(Some(restored), Round(60), &v41_params(), SystemTime::now());

        assert_eq!(
            (out_player.round, out_player.period, out_player.step),
            (Round(60), Period(1), CERT)
        );
        assert!(!crate::persistence::persistent(&out_actions));
    }

    /// A corrupt crash DB degrades to a fresh bootstrap at the ledger's
    /// round — never to a half-decoded player at some arbitrary step.
    #[test]
    fn corrupt_crash_db_bootstraps_fresh_rather_than_half_restoring() {
        let conn = crash_db();
        persist(&conn, b"not-msgpack-at-all").expect("persist garbage");

        let restored = restore_crash_state(&conn);
        assert!(restored.is_none());

        let (_r, player, actions) =
            initial_state(restored, Round(7), &v41_params(), SystemTime::now());
        assert_eq!(player.round, Round(7));
        assert_eq!(player.period, Period(0));
        assert_eq!(player.step, SOFT);
        assert!(!crate::persistence::persistent(&actions));
    }

    /// The restart clock clamp and the coordinate restore compose: after a
    /// 2s outage the player is at the same step with 2s less deadline.
    #[test]
    fn restart_clamps_deadlines_without_moving_the_coordinate() {
        let conn = crash_db();
        let (router, player, actions) =
            checkpoint_before_vote(Round(21), Period(1), CERT, proposal(0x0E));
        assert_eq!(player.deadline.duration, Duration::from_secs(4));
        let zero = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        write_checkpoint(&conn, &router, &player, &actions, zero);

        let restored = restore_crash_state(&conn).expect("restorable");
        let (_r, out_player, _a) = initial_state(
            Some(restored),
            Round(21),
            &v41_params(),
            zero + Duration::from_secs(2),
        );

        assert_eq!(
            (out_player.round, out_player.period, out_player.step),
            (Round(21), Period(1), CERT)
        );
        assert_eq!(out_player.deadline.duration, Duration::from_secs(2));
    }
}
