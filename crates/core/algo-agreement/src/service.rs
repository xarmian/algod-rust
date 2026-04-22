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

use algo_types::Round;

use crate::actions::{
    Action, ActionType, CryptoAction, EnsureAction, NetworkAction, PseudonodeAction, RezeroAction,
    StageDigestAction,
};
use crate::codec;
use crate::demux::{Demux, ExternalDemuxSignals, ExternalEvent};
use crate::events::ConsensusVersionView;
use crate::ledger_reader::LedgerReader;
use crate::persistence::{self, AsyncPersistenceLoop, ClockState, PersistentRequest};
use crate::player::Player;
use crate::pseudonode::{AsyncPseudonode, Pseudonode};
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
    /// Optional SQLite connection for crash recovery persistence.
    ///
    /// When `Some`, agreement state is persisted to this database before
    /// broadcasting votes, enabling crash recovery without double-voting.
    /// When `None`, no persistence is performed (existing behavior).
    pub crash_db: Option<rusqlite::Connection>,
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
        Self { params }
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
            crash_db,
        } = self.params;

        // Try to restore persisted state BEFORE creating the persistence loop
        // (which takes ownership of the connection). We need a separate
        // connection for restore, or we do restore first with the same one.
        let restored_state = if let Some(ref conn) = crash_db {
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
                            "failed to decode persisted agreement state: {}; starting fresh",
                            e
                        );
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
        } else {
            None
        };

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

        // Construct the Demux with all channel receivers.
        let mut demux = Demux::new(
            av_rx,
            pp_rx,
            vb_rx,
            verified_votes_rx,
            verified_proposals_rx,
            verified_bundles_rx,
            ledger_round_rx,
            quit_demux_rx,
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
                    ready_tx,
                    pseudo_tx,
                    persistence_loop,
                    restored_state,
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
                    ready_rx,
                    pseudo_rx,
                    demux,
                    quit_demux_tx,
                    crypto,
                    monitor_demux,
                    vote_verifier,
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
    ready: mpsc::Sender<ExternalDemuxSignals>,
    pseudo_events: mpsc::Sender<Vec<ExternalEvent>>,
    mut persistence_loop: Option<AsyncPersistenceLoop>,
    restored_state: Option<(RootRouter, Player, ClockState, Vec<Action>)>,
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
    let (mut router, mut player, mut actions) = if let Some((
        r_router,
        mut r_player,
        r_clock,
        r_actions,
    )) = restored_state
    {
        // Use restored state only if it is still relevant (round >= ledger's next round).
        if r_player.round.0 >= next_round.0 {
            info!(
                "using restored agreement state at round {} (ledger next round {})",
                r_player.round, next_round
            );
            resume_from_clock_zero(&mut r_player, &r_clock, SystemTime::now());
            (r_router, r_player, r_actions)
        } else {
            info!(
                    "restored agreement state at round {} is stale (ledger next round {}); bootstrapping fresh",
                    r_player.round, next_round
                );
            bootstrap_fresh(next_round, &cparams)
        }
    } else {
        bootstrap_fresh(next_round, &cparams)
    };

    // Create the pseudonode for local proposal/vote generation.
    // We share ledger via a clone of the Arc, but AsyncPseudonode wants
    // owned references. We use a LedgerReaderRef wrapper below.
    let pseudonode =
        AsyncPseudonode::new(block_factory, key_manager, LedgerReaderRef(ledger.clone()));
    let mut pseudonode: Box<dyn Pseudonode + Send> = Box::new(pseudonode);

    // Persistence state — saved when actions contain a persistent action (attest).
    // These snapshots are used to encode the state for the persistence loop.
    let mut persist_router: Option<RootRouter> = None;
    let mut persist_player: Option<Player> = None;
    let mut persist_actions: Option<Vec<Action>> = None;

    info!("agreement service started at round {}", next_round);

    loop {
        if quit.load(Ordering::SeqCst) {
            break;
        }

        // Step 1: Send actions to demux loop.
        if output.send(actions).is_err() {
            break;
        }

        // Step 2: Send signals so demux loop knows what events to look for.
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

        // Step 3: Receive the next external event from the demux loop.
        let event = match input.recv() {
            Ok(Some(e)) => e,
            Ok(None) | Err(_) => break,
        };

        // Step 4: Look up consensus params for this event's round.
        let event_round = event.consensus_round();
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

        // Step 5: Drive the state machine.
        let (new_player, new_actions) = router.submit_top(player, event.event, &params);
        player = new_player;
        actions = new_actions;

        // Track state for persistence when actions contain a persistent
        // action (attest). The snapshot is taken BEFORE executing the
        // pseudonode actions, matching Go's pattern where state is persisted
        // before votes are broadcast.
        if persistence::persistent(&actions) {
            persist_router = Some(router.clone());
            persist_player = Some(player.clone());
            persist_actions = Some(actions.clone());
        }

        // Execute pseudonode actions inline and send resulting events to the
        // demux loop for prioritization. In Go these are executed in the demux
        // goroutine's `do()` method; since our pseudonode is owned by the main
        // loop, we execute them here and forward the results.
        let mut pseudonode_events = Vec::new();
        for action in &actions {
            if let Action::Pseudonode(ref pa) = action {
                execute_pseudonode_action(
                    pa,
                    &mut *pseudonode,
                    &mut pseudonode_events,
                    &persistence_loop,
                    &persist_router,
                    &persist_player,
                    &persist_actions,
                );
            }
        }

        // Clear persistence snapshots after pseudonode actions are executed.
        persist_router = None;
        persist_player = None;
        persist_actions = None;

        if !pseudonode_events.is_empty() && pseudo_events.send(pseudonode_events).is_err() {
            break;
        }

        // Filter out pseudonode actions before sending to the demux loop
        // since they have already been executed above.
        actions.retain(|a| !matches!(a, Action::Pseudonode(_)));
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
) {
    match pa.t {
        ActionType::Assemble => {
            match pseudonode.make_proposals(pa.round, pa.period) {
                Ok(message_events) => {
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
                "repropose to {:?} at ({}, {}, {})",
                pa.proposal, pa.round, pa.period, PROPOSE
            );
            match pseudonode.make_votes(pa.round, pa.period, PROPOSE, pa.proposal, None) {
                Ok(message_events) => {
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
            info!(
                "attested to {:?} at ({}, {}, {})",
                pa.proposal, pa.round, pa.period, pa.step
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
/// Semantics (mirrors go-algorand v4.5.1-stable `agreement/service.go:226-253`):
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
    ready: mpsc::Receiver<ExternalDemuxSignals>,
    pseudo_rx: mpsc::Receiver<Vec<ExternalEvent>>,
    mut demux: Demux,
    quit_demux_tx: crossbeam_channel::Sender<()>,
    crypto: C,
    monitor: Arc<Mutex<M>>,
    vote_verifier: Arc<AsyncVoteVerifier>,
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

        // Drain any pseudonode events that the main loop produced and
        // prioritize them in the demux so they are returned first.
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
        );

        // Actions consumed — report queue drained.
        if let Ok(m) = monitor.lock() {
            m.update_events_queue(crate::demux::EVENT_QUEUE_DEMUX, 0);
        }

        // Get the signals from the main loop.
        let signals = match ready.recv() {
            Ok(s) => s,
            Err(_) => break,
        };

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
) where
    N: AgreementNetwork,
    L: LedgerReader + LedgerWriter,
    BV: BlockValidator,
    C: CryptoVerifier,
{
    match action {
        Action::Noop(_) => {}

        Action::Network(ref na) => {
            do_network_action(na, network);
        }

        Action::Crypto(ref ca) => {
            do_crypto_action(ca, crypto);
        }

        Action::Ensure(ref ea) => {
            do_ensure_action(ea, ledger, block_validator);
        }

        Action::StageDigest(ref sda) => {
            do_stage_digest_action(sda, ledger, vote_verifier);
        }

        Action::Rezero(ref ra) => {
            do_rezero_action(ra, historical_clocks);
        }

        Action::Pseudonode(ref pa) => {
            // Pseudonode actions are executed by the main loop and results
            // are prioritized in the demux via the pseudo_rx channel.
            // If we still see one here, it was not filtered — just log.
            debug!("pseudonode action: {} (already handled by main loop)", pa);
        }

        Action::Checkpoint(ref ca) => {
            info!("checkpoint at ({}, {}, {})", ca.round, ca.period, ca.step);
        }
    }
}

/// Execute a network action (broadcast, relay, disconnect, ignore).
///
/// Mirrors Go's `networkAction.do`.
fn do_network_action<N: AgreementNetwork>(na: &NetworkAction, network: &N) {
    match na.t {
        ActionType::BroadcastVotes => {
            let tag = Tag(AGREEMENT_VOTE_TAG);
            for uv in &na.unauthenticated_votes {
                let data = codec::encode_vote(uv);
                if let Err(e) = network.broadcast(&tag, &data) {
                    warn!("failed to broadcast vote: {}", e);
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
            network.disconnect(&na.message_handle);
        }
        ActionType::Ignore => {
            // Intentionally do nothing.
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
) {
    let block = &ea.payload.unauthenticated_proposal.block;

    if let Some(ref vb) = ea.payload.validated_block {
        info!(
            "committed round {} with pre-validated block {:?}",
            ea.certificate.round, ea.certificate.proposal.block_digest,
        );
        ledger.ensure_validated_block(vb.as_ref(), &ea.certificate);
    } else {
        info!(
            "committed round {} with block {:?}",
            ea.certificate.round, ea.certificate.proposal.block_digest,
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
/// Mirrors Go's `rezeroAction.do`.
fn do_rezero_action(ra: &RezeroAction, historical_clocks: &mut HashMap<Round, Instant>) {
    // Record the start time for this round (period 0).
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
            crash_db: None,
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
            crash_db: None,
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

    #[test]
    fn do_rezero_action_records_clock() {
        let mut clocks = HashMap::new();
        let ra = RezeroAction { round: Round(10) };

        do_rezero_action(&ra, &mut clocks);

        assert!(clocks.contains_key(&Round(10)));
    }

    #[test]
    fn do_rezero_action_gc_old_clocks() {
        let mut clocks = HashMap::new();
        clocks.insert(Round(1), Instant::now());
        clocks.insert(Round(5), Instant::now());
        clocks.insert(Round(20), Instant::now());

        let ra = RezeroAction { round: Round(20) };
        do_rezero_action(&ra, &mut clocks);

        // Round 1 should be GC'd (credential_round_lag = 8, 20 > 1 + 8 = 9)
        assert!(!clocks.contains_key(&Round(1)));
        // Round 5 should be GC'd (20 > 5 + 8 = 13)
        assert!(!clocks.contains_key(&Round(5)));
        // Round 20 should be kept
        assert!(clocks.contains_key(&Round(20)));
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
        do_ensure_action(&ea, &ledger, &validator);

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].cert.round, Round(100));
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
        do_ensure_action(&ea, &ledger, &validator);

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
        do_ensure_action(&ea, &ledger, &validator);

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

        do_network_action(&na, &network);

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

        do_network_action(&na, &network);

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

        do_network_action(&na, &network);

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

        do_network_action(&na, &network);

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
}
