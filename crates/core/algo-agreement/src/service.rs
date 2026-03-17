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
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use tracing::{debug, info, warn};

use algo_types::Round;

use crate::actions::{
    Action, ActionType, EnsureAction, NetworkAction, PseudonodeAction, RezeroAction,
    StageDigestAction,
};
use crate::codec;
use crate::demux::{Demux, ExternalDemuxSignals, ExternalEvent};
use crate::events::ConsensusVersionView;
use crate::ledger_reader::LedgerReader;
use crate::player::Player;
use crate::pseudonode::{AsyncPseudonode, Pseudonode};
use crate::router::RootRouter;
use crate::step::{Period, Step, PROPOSE, SOFT};
use crate::traits::{
    AgreementKeyManager, AgreementNetwork, BlockFactory, BlockValidator, CryptoVerifier,
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
            monitor: _monitor,
            crypto,
        } = self.params;

        warn!("events monitor not yet wired into service");

        // Wrap shared state in Arc for cross-thread access.
        let ledger = Arc::new(ledger);
        let network = Arc::new(network);

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
        let demux = Demux::new(
            av_rx,
            pp_rx,
            vb_rx,
            verified_votes_rx,
            verified_proposals_rx,
            verified_bundles_rx,
            ledger_round_rx,
            quit_demux_rx,
        );

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
                );
            })
            .expect("failed to spawn agreement main loop thread");

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
) where
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    R: RandomSource + Send + 'static,
{
    // Bootstrap: initialize the player at the current round.
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

    let status = Player {
        round: next_round,
        step: SOFT,
        deadline: Deadline {
            duration: filter_timeout(Period(0), &cparams),
            timeout_type: TimeoutType::Filter,
        },
        lowest_credential_arrivals: CredentialArrivalHistory::new(
            DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
        ),
        ..Player::default()
    };

    let mut router = RootRouter::new(&status);
    let mut player = status;

    // Initial actions: assemble a proposal + rezero the clock.
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

    let mut actions = initial_actions;

    // Create the pseudonode for local proposal/vote generation.
    // We share ledger via a clone of the Arc, but AsyncPseudonode wants
    // owned references. We use a LedgerReaderRef wrapper below.
    let pseudonode =
        AsyncPseudonode::new(block_factory, key_manager, LedgerReaderRef(ledger.clone()));
    let mut pseudonode: Box<dyn Pseudonode + Send> = Box::new(pseudonode);

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

        // Execute pseudonode actions inline and send resulting events to the
        // demux loop for prioritization. In Go these are executed in the demux
        // goroutine's `do()` method; since our pseudonode is owned by the main
        // loop, we execute them here and forward the results.
        let mut pseudonode_events = Vec::new();
        for action in &actions {
            if let Action::Pseudonode(ref pa) = action {
                execute_pseudonode_action(pa, &mut *pseudonode, &mut pseudonode_events);
            }
        }
        if !pseudonode_events.is_empty() && pseudo_events.send(pseudonode_events).is_err() {
            break;
        }

        // Filter out pseudonode actions before sending to the demux loop
        // since they have already been executed above.
        actions.retain(|a| !matches!(a, Action::Pseudonode(_)));
    }

    // Clean up.
    pseudonode.quit();
    drop(output);
    info!("agreement main loop exited");
}

/// Execute a single pseudonode action and collect resulting events.
///
/// Mirrors Go's `pseudonodeAction.do(ctx, s)`. Results are converted to
/// `ExternalEvent`s for prioritization in the demux.
fn execute_pseudonode_action(
    pa: &PseudonodeAction,
    pseudonode: &mut dyn Pseudonode,
    events_out: &mut Vec<ExternalEvent>,
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
            match pseudonode.make_votes(pa.round, pa.period, PROPOSE, pa.proposal) {
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
            match pseudonode.make_votes(pa.round, pa.period, pa.step, pa.proposal) {
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
        _ => {
            warn!("unexpected pseudonode action type: {}", pa.t);
        }
    }
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
fn demux_loop<N, L, BV, C>(
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
) where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    BV: BlockValidator + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    // Retain old rounds' period 0 start times for late credential tracking.
    let mut historical_clocks: HashMap<Round, Instant> = HashMap::new();

    for action_batch in output.iter() {
        if quit.load(Ordering::SeqCst) {
            break;
        }

        // Drain any pseudonode events that the main loop produced and
        // prioritize them in the demux so they are returned first.
        while let Ok(events) = pseudo_rx.try_recv() {
            demux.prioritize(events);
        }

        // Execute each action.
        do_actions(
            &action_batch,
            &*network,
            &*ledger,
            &block_validator,
            &mut demux,
            &mut historical_clocks,
        );

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
                if input.send(Some(e)).is_err() {
                    break;
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
fn do_actions<N, L, BV>(
    actions: &[Action],
    network: &N,
    ledger: &L,
    block_validator: &BV,
    _demux: &mut Demux,
    historical_clocks: &mut HashMap<Round, Instant>,
) where
    N: AgreementNetwork,
    L: LedgerReader + LedgerWriter,
    BV: BlockValidator,
{
    for action in actions {
        do_action(action, network, ledger, block_validator, historical_clocks);
    }
}

/// Execute a single action.
///
/// Mirrors each action type's `do(ctx, s)` in Go.
fn do_action<N, L, BV>(
    action: &Action,
    network: &N,
    ledger: &L,
    block_validator: &BV,
    historical_clocks: &mut HashMap<Round, Instant>,
) where
    N: AgreementNetwork,
    L: LedgerReader + LedgerWriter,
    BV: BlockValidator,
{
    match action {
        Action::Noop(_) => {}

        Action::Network(ref na) => {
            do_network_action(na, network);
        }

        Action::Crypto(ref _ca) => {
            // In Go, crypto actions are dispatched to the demux's async vote
            // verifier. For now, crypto verification is done inline in the
            // pseudonode, so we log and skip.
            debug!("crypto action: async verification not yet implemented");
        }

        Action::Ensure(ref ea) => {
            do_ensure_action(ea, ledger, block_validator);
        }

        Action::StageDigest(ref sda) => {
            do_stage_digest_action(sda, ledger);
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
                // Use None as handle since we don't track message handles yet.
                if let Err(e) = network.relay(&None, &tag, &data) {
                    warn!("failed to relay {}: {}", tag_str, e);
                }
            }
        }
        ActionType::Disconnect => {
            network.disconnect(&None);
        }
        ActionType::Ignore => {
            // Intentionally do nothing.
        }
        _ => {
            warn!("unexpected network action type: {}", na.t);
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
/// Validates the block before writing it. Mirrors Go's `ensureAction.do`.
fn do_ensure_action<L: LedgerWriter, BV: BlockValidator>(
    ea: &EnsureAction,
    ledger: &L,
    block_validator: &BV,
) {
    let block = &ea.payload.unauthenticated_proposal.block;

    // Validate the block before writing to the ledger.
    if let Err(e) = block_validator.validate(block) {
        warn!(
            "block validation failed for round {}: {}",
            ea.certificate.round, e
        );
        return;
    }

    info!(
        "committed round {} with block {:?}",
        ea.certificate.round, ea.certificate.proposal.block_digest,
    );
    ledger.ensure_block(block, &ea.certificate);

    // Update the block validator's previous timestamp so subsequent
    // validations use the correct reference point.
    block_validator.set_prev_timestamp(block.timestamp);
}

/// Execute a stage-digest action (signal the ledger to fetch a block).
///
/// Mirrors Go's `stageDigestAction.do`.
fn do_stage_digest_action<L: LedgerWriter>(sda: &StageDigestAction, ledger: &L) {
    info!(
        "round {} concluded without block for {:?}; waiting on ledger",
        sda.certificate.round, sda.certificate.proposal,
    );
    ledger.ensure_digest(&sda.certificate);
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

        do_stage_digest_action(&sda, &ledger);

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
