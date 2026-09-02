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

// Async event multiplexer for the agreement protocol.
//
// Mirrors go-algorand/agreement/demux.go.
//
// The Demux supplies the state machine with the next relevant external input
// event. It multiplexes events from multiple sources using
// `crossbeam_channel::select!` for proper blocking without polling:
//   - Network messages (votes, proposals, bundles)
//   - Timeout events (filter, deadline, fast recovery)
//   - Verification results (async vote/payload/bundle verification completions)
//   - Round interruptions from the ledger
//   - Pseudonode events (locally generated proposals/votes)

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use algo_types::Round;
use crossbeam_channel::{self, Receiver};
use tracing::warn;

use crate::clock::Clock;
use crate::codec;
use crate::events::{
    CompoundMessage, ConsensusVersionView, Event, EventType, InternalMessage, MessageEvent,
    RoundInterruptionEvent, TimeoutEvent,
};
use crate::ledger_reader::LedgerReader;
use crate::traits::{
    AgreementNetwork, CryptoResult, CryptoVerifier, CryptoVoteVerifyResult, Message,
    AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
use crate::types::{Deadline, TimeoutType};
use crate::vote::BOTTOM;
use algo_types::Address;

// ---------------------------------------------------------------------------
// Event queue names (for monitoring)
// ---------------------------------------------------------------------------

/// Queue name for the demux itself.
pub const EVENT_QUEUE_DEMUX: &str = "demux";
/// Queue name for the crypto verifier vote results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_VOTE: &str = "cryptoVerifierVote";
/// Queue name for the crypto verifier proposal results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_PROPOSAL: &str = "cryptoVerifierProposal";
/// Queue name for the crypto verifier bundle results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_BUNDLE: &str = "cryptoVerifierBundle";
/// Queue name for pseudonode events.
pub const EVENT_QUEUE_PSEUDONODE: &str = "pseudonode";

/// Default timeout when no deadline is set (5 minutes).
const DEFAULT_SELECT_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// ExternalEvent
// ---------------------------------------------------------------------------

/// An external event to be delivered to the state machine.
///
/// Wraps an `Event` along with metadata about its source and consensus version.
#[derive(Debug, Clone)]
pub struct ExternalEvent {
    /// The underlying event.
    pub event: Event,
}

impl ExternalEvent {
    /// Returns the event type.
    pub fn event_type(&self) -> EventType {
        self.event.event_type()
    }

    /// Returns the consensus round for this event.
    pub fn consensus_round(&self) -> Round {
        match &self.event {
            Event::Message(me) => me.consensus_round(),
            Event::FilterableMessage(fme) => fme.message_event.consensus_round(),
            Event::RoundInterruption(rie) => rie.consensus_round(),
            Event::Timeout(te) => te.consensus_round(),
            _ => Round(0),
        }
    }

    /// Returns a new ExternalEvent with the consensus version attached.
    pub fn attach_consensus_version(mut self, v: ConsensusVersionView) -> Self {
        match &mut self.event {
            Event::Message(me) => {
                me.proto = v;
            }
            Event::RoundInterruption(rie) => {
                rie.proto = v;
            }
            Event::Timeout(te) => {
                te.proto = v;
            }
            _ => {}
        }
        self
    }
}

// ---------------------------------------------------------------------------
// ExternalDemuxSignals
// ---------------------------------------------------------------------------

/// Signals used to synchronize the external signals that go to the demux with
/// the main loop.
///
/// Mirrors Go's `externalDemuxSignals`.
#[derive(Debug, Clone)]
pub struct ExternalDemuxSignals {
    /// The current player deadline.
    pub deadline: Deadline,
    /// The fast recovery deadline.
    pub fast_recovery_deadline: Deadline,
    /// The current round.
    pub current_round: Round,
    /// Random entropy for timeout events (from `RandomSource::uint64()`).
    ///
    /// Mirrors Go's `s.RandomSource.Uint64()` used in timeout event creation.
    pub random_source_entropy: u64,
    /// The consensus version for the current round, used to attach to compound
    /// message tail events.
    ///
    /// Mirrors Go's `l.ConsensusVersion(ParamsRound(...))` in `setupCompoundMessage`.
    pub current_consensus_version: ConsensusVersionView,
}

// ---------------------------------------------------------------------------
// Demux
// ---------------------------------------------------------------------------

/// The demultiplexer for the agreement state machine.
///
/// Supplies the state machine with the next relevant external input event,
/// multiplexing events from network, crypto verification, timeouts, and the
/// ledger using `crossbeam_channel::select!`.
///
/// Unlike the previous polling-based implementation, this version blocks
/// efficiently on all event sources simultaneously, matching Go's `select {}`
/// pattern in `demux.next()`.
///
/// Mirrors Go's `demux`.
pub struct Demux {
    // -- Network message channels (raw incoming, already decoded) --
    /// Receiver for agreement vote messages (tag "AV").
    av_rx: Receiver<Message>,
    /// Receiver for proposal payload messages (tag "PP").
    pp_rx: Receiver<Message>,
    /// Receiver for vote bundle messages (tag "VB").
    vb_rx: Receiver<Message>,

    // -- Crypto verifier result channels --
    /// Receiver for verified vote results.
    verified_votes_rx: Receiver<CryptoVoteVerifyResult>,
    /// Receiver for verified proposal results.
    verified_proposals_rx: Receiver<CryptoResult>,
    /// Receiver for verified bundle results.
    verified_bundles_rx: Receiver<CryptoResult>,

    // -- Ledger round-change channel --
    /// Receiver that fires when the ledger reaches a new round.
    /// Refreshed each round by the caller.
    ledger_round_rx: Receiver<Round>,

    // -- Quit channel --
    /// Receiver for the shutdown signal.
    quit_rx: Receiver<()>,

    // -- Priority queue of pseudonode events --
    /// Queued pseudonode events that take priority over all other sources.
    /// These are drained first on each call to `next()`.
    pseudo_queue: VecDeque<ExternalEvent>,

    // -- Network reference for disconnecting peers on decode failures --
    /// Network handle used to disconnect peers that send malformed messages.
    ///
    /// Mirrors Go's `demux.net` used in `demux.next()` for disconnect-on-error.
    network: Option<Arc<dyn AgreementNetwork + Send + Sync>>,

    // -- Ledger reference for re-sampling round on interruption --
    /// Ledger handle used to re-sample the current round when the ledger
    /// round channel fires, matching Go's `nextRound = s.Ledger.NextRound()`.
    ledger: Option<Arc<dyn LedgerReader + Send + Sync>>,

    // -- Clock for deadline-based timeouts --
    /// Clock used to derive the `Receiver<()>` endpoints fed into the select
    /// for the current player's deadline + fast-recovery deadline.
    ///
    /// Production uses `SystemClock`; the simulate harness injects a mock
    /// `Clock` so tests can advance deterministically. Mirrors Go's
    /// `demux.s.Clock` access pattern.
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Demux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Demux")
            .field("pseudo_queue_len", &self.pseudo_queue.len())
            .finish()
    }
}

impl Demux {
    /// Create a new demux from the given channel receivers and clock.
    ///
    /// Mirrors Go's `makeDemux`. The `clock` drives deadline-based timeouts
    /// via `Clock::timeout_at`; production code passes a `SystemClock`, while
    /// tests and the simulation harness can inject their own impls.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        av_rx: Receiver<Message>,
        pp_rx: Receiver<Message>,
        vb_rx: Receiver<Message>,
        verified_votes_rx: Receiver<CryptoVoteVerifyResult>,
        verified_proposals_rx: Receiver<CryptoResult>,
        verified_bundles_rx: Receiver<CryptoResult>,
        ledger_round_rx: Receiver<Round>,
        quit_rx: Receiver<()>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            av_rx,
            pp_rx,
            vb_rx,
            verified_votes_rx,
            verified_proposals_rx,
            verified_bundles_rx,
            ledger_round_rx,
            quit_rx,
            pseudo_queue: VecDeque::new(),
            network: None,
            ledger: None,
            clock,
        }
    }

    /// Set the network reference used for disconnecting peers on decode errors.
    pub fn set_network(&mut self, network: Arc<dyn AgreementNetwork + Send + Sync>) {
        self.network = Some(network);
    }

    /// Set the ledger reference used for re-sampling the round on interruption.
    pub fn set_ledger(&mut self, ledger: Arc<dyn LedgerReader + Send + Sync>) {
        self.ledger = Some(ledger);
    }

    /// Push pseudonode events into the priority queue.
    ///
    /// These events will be returned by `next()` before any channel events.
    ///
    /// Mirrors Go's `demux.prioritize`.
    pub fn queue_pseudo_events(&mut self, events: Vec<ExternalEvent>) {
        self.pseudo_queue.extend(events);
    }

    /// Sets a channel of events to deliver ahead of other input.
    ///
    /// Alias for `queue_pseudo_events` to maintain API compatibility.
    ///
    /// Mirrors Go's `demux.prioritize`.
    pub fn prioritize(&mut self, events: Vec<ExternalEvent>) {
        self.queue_pseudo_events(events);
    }

    /// Update the ledger round notification channel.
    ///
    /// Called when the current round changes so the demux can select on the
    /// new round's notification.
    pub fn set_ledger_round_rx(&mut self, rx: Receiver<Round>) {
        self.ledger_round_rx = rx;
    }

    /// Returns the next event to process, blocking until one is available.
    ///
    /// Priority order (matching Go's `demux.next`):
    /// 1. Pseudonode events from the priority queue
    /// 2. Select across all channels:
    ///    - Raw network messages (votes, proposals, bundles)
    ///    - Verified crypto results (votes, proposals, bundles)
    ///    - Ledger round advancement
    ///    - Deadline timeout
    ///    - Fast recovery timeout
    ///    - Quit signal
    ///
    /// When a raw network message fails to decode or a non-quit channel
    /// closes, the select loops back and tries again. Returns `None` only
    /// on quit (shutdown).
    ///
    /// Mirrors Go's `demux.next`.
    pub fn next(
        &mut self,
        signals: &ExternalDemuxSignals,
        crypto: Option<&dyn CryptoVerifier>,
    ) -> Option<ExternalEvent> {
        // First, drain pseudo_queue — highest priority.
        if let Some(event) = self.pseudo_queue.pop_front() {
            return Some(event);
        }

        // Compute the timeout duration from the deadline signal.
        // A `Duration::ZERO` signals "no deadline set"; we substitute the
        // default fallback so the clock still produces a (far-future) receiver
        // the select can pend on.
        let deadline_dur = if signals.deadline.duration > Duration::ZERO {
            signals.deadline.duration
        } else {
            DEFAULT_SELECT_TIMEOUT
        };
        let fast_deadline_dur = if signals.fast_recovery_deadline.duration > Duration::ZERO {
            signals.fast_recovery_deadline.duration
        } else {
            DEFAULT_SELECT_TIMEOUT
        };

        // Loop until we get a valid event or a quit signal. Decode errors
        // and non-quit channel closures are logged and retried, matching
        // Go's behavior where bad messages are skipped.
        loop {
            // Check crypto verifier backpressure before selecting on raw
            // channels. If the crypto verifier queue is full for a tag,
            // skip the corresponding raw channel to prevent deadlock.
            // Mirrors Go's `d.crypto.ChannelFull(tag)` nil-channel pattern.
            let av_full = crypto
                .map(|c| c.channel_full(AGREEMENT_VOTE_TAG))
                .unwrap_or(false);
            let pp_full = crypto
                .map(|c| c.channel_full(PROPOSAL_PAYLOAD_TAG))
                .unwrap_or(false);
            let vb_full = crypto
                .map(|c| c.channel_full(VOTE_BUNDLE_TAG))
                .unwrap_or(false);

            // In Go, when the AV queue is full, both rawVotes and rawProposals
            // are disabled (a vote may be attached to proposal payloads).
            let skip_av = av_full;
            let skip_pp = pp_full || av_full;
            let skip_vb = vb_full;

            // Resolve the two deadline receivers via the clock. Mirrors Go's
            // `s.Clock.TimeoutAt(d.deadline.Duration, TimeoutDeadline)` pair of
            // select cases in `demux.next()`. The sender-dropped semantics on
            // these receivers is the crossbeam analogue of Go's channel close.
            let deadline_rx = self.clock.timeout_at(deadline_dur, TimeoutType::Deadline);
            let fast_deadline_rx = self
                .clock
                .timeout_at(fast_deadline_dur, TimeoutType::FastRecovery);

            // Use the runtime Select builder so we can conditionally include
            // channels based on crypto backpressure state.
            let mut sel = crossbeam_channel::Select::new();

            // Assign indices for each channel we add to the select set.
            // We track which index maps to which channel.
            let quit_idx = sel.recv(&self.quit_rx);
            let ledger_idx = sel.recv(&self.ledger_round_rx);

            // Raw network channels — conditionally included.
            let av_idx = if !skip_av {
                Some(sel.recv(&self.av_rx))
            } else {
                None
            };
            let pp_idx = if !skip_pp {
                Some(sel.recv(&self.pp_rx))
            } else {
                None
            };
            let vb_idx = if !skip_vb {
                Some(sel.recv(&self.vb_rx))
            } else {
                None
            };

            // Verified results channels — always included.
            let vv_idx = sel.recv(&self.verified_votes_rx);
            let vp_idx = sel.recv(&self.verified_proposals_rx);
            let vbr_idx = sel.recv(&self.verified_bundles_rx);

            // Clock-provided deadline receivers — always included. Under the
            // mock `instant` clock (see TASK-81) these surface as
            // already-closed receivers, letting simulation run with zero real
            // wall time.
            let deadline_idx = sel.recv(&deadline_rx);
            let fast_deadline_idx = sel.recv(&fast_deadline_rx);

            // Block until any channel is ready. crossbeam_channel::Select
            // chooses fairly (random) when multiple are ready simultaneously,
            // matching Go's `select {}` behavior.
            //
            // Semantic note (vs. pre-clock Rust): previously the demux used
            // `select_timeout(min(deadline, fast_deadline))` and deterministically
            // returned `FastTimeout` only when `fast_deadline_dur < deadline_dur`.
            // The new clock-based path leaves tie-breaking to crossbeam's fair
            // random selection — which is what Go does at its own `select { case
            // <-fastCh: ... case <-slowCh: ... }` sites in `agreement/demux.go`,
            // so this is an intentional alignment rather than a regression. The
            // "both already elapsed" tie is also far rarer now that `do_rezero_action`
            // re-zeros the active clock on `Action::Rezero`.
            let oper = sel.select();
            let index = oper.index();

            // -- Deadline timeouts (clock-provided) --
            //
            // A deadline receiver becoming "ready" means the clock's underlying
            // `crossbeam_channel::after(...)` fired (or the pre-closed sender
            // was dropped for an already-elapsed delta). We consume via
            // `oper.recv(...)` to satisfy the Select contract; the payload
            // (`Instant`) or `Err(Disconnected)` is discarded — we only care
            // about readiness.
            if index == deadline_idx {
                let _ = oper.recv(&deadline_rx);
                return Some(make_timeout_event(
                    signals.random_source_entropy,
                    signals.current_round,
                ));
            }
            if index == fast_deadline_idx {
                let _ = oper.recv(&fast_deadline_rx);
                return Some(make_fast_timeout_event(
                    signals.random_source_entropy,
                    signals.current_round,
                ));
            }

            // -- Quit signal --
            if index == quit_idx {
                let _ = oper.recv(&self.quit_rx);
                return None;
            }

            // -- Ledger round advancement --
            if index == ledger_idx {
                match oper.recv(&self.ledger_round_rx) {
                    Ok(round) => {
                        // Re-sample the actual current round from the ledger,
                        // matching Go's `nextRound = s.Ledger.NextRound()`.
                        let actual_round = self
                            .ledger
                            .as_ref()
                            .map(|l| l.next_round())
                            .unwrap_or(round);
                        return Some(make_round_interruption_event(actual_round));
                    }
                    Err(_) => {
                        // Ledger channel closed — replace with a never-channel
                        // so it is no longer selected (a disconnected channel
                        // would be selected immediately, causing a busy-loop).
                        warn!("ledger round notification channel closed");
                        self.ledger_round_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Raw network: agreement votes (AV) --
            if av_idx == Some(index) {
                match oper.recv(&self.av_rx) {
                    Ok(msg) => {
                        if let Some(event) = self.handle_raw_vote(msg) {
                            return Some(event);
                        }
                        // Decode error — loop back and try again.
                        continue;
                    }
                    Err(_) => {
                        warn!("agreement vote channel closed");
                        self.av_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Raw network: proposal payloads (PP) --
            if pp_idx == Some(index) {
                match oper.recv(&self.pp_rx) {
                    Ok(msg) => {
                        if let Some(event) =
                            self.handle_raw_proposal(msg, &signals.current_consensus_version)
                        {
                            return Some(event);
                        }
                        continue;
                    }
                    Err(_) => {
                        warn!("proposal payload channel closed");
                        self.pp_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Raw network: vote bundles (VB) --
            if vb_idx == Some(index) {
                match oper.recv(&self.vb_rx) {
                    Ok(msg) => {
                        if let Some(event) = self.handle_raw_bundle(msg) {
                            return Some(event);
                        }
                        continue;
                    }
                    Err(_) => {
                        warn!("vote bundle channel closed");
                        self.vb_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Verified vote results --
            if index == vv_idx {
                match oper.recv(&self.verified_votes_rx) {
                    Ok(r) => return Some(self.handle_verified_vote(r)),
                    Err(_) => {
                        warn!("verified votes channel closed");
                        self.verified_votes_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Verified proposal results --
            if index == vp_idx {
                match oper.recv(&self.verified_proposals_rx) {
                    Ok(r) => return Some(self.handle_verified_proposal(r)),
                    Err(_) => {
                        warn!("verified proposals channel closed");
                        self.verified_proposals_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // -- Verified bundle results --
            if index == vbr_idx {
                match oper.recv(&self.verified_bundles_rx) {
                    Ok(r) => return Some(self.handle_verified_bundle(r)),
                    Err(_) => {
                        warn!("verified bundles channel closed");
                        self.verified_bundles_rx = crossbeam_channel::never();
                        continue;
                    }
                }
            }

            // Should not be reached — all indices are covered above.
            warn!("unexpected select index {}", index);
        }
    }

    // -- Private helpers for decoding and constructing events --

    /// Handle a raw vote message from the network.
    ///
    /// Decodes the vote from wire format and constructs a `VotePresent` event.
    fn handle_raw_vote(&self, msg: Message) -> Option<ExternalEvent> {
        match codec::decode_vote(&msg.data) {
            Ok(vote) => {
                let internal = InternalMessage {
                    message_handle: msg.handle,
                    tag: AGREEMENT_VOTE_TAG.to_string(),
                    unauthenticated_vote: vote,
                    ..InternalMessage::default()
                };
                Some(ExternalEvent {
                    event: Event::Message(MessageEvent {
                        t: EventType::VotePresent,
                        input: internal,
                        ..MessageEvent::default()
                    }),
                })
            }
            Err(e) => {
                warn!("error decoding vote message: {}", e);
                // Disconnect the peer that sent the malformed message,
                // matching Go's behavior.
                if let Some(ref net) = self.network {
                    net.disconnect(&msg.handle);
                }
                None
            }
        }
    }

    /// Handle a raw proposal message from the network.
    ///
    /// Decodes the compound message (proposal payload + optional vote) and
    /// constructs the appropriate event(s).
    ///
    /// Mirrors Go's `setupCompoundMessage`.
    fn handle_raw_proposal(
        &self,
        msg: Message,
        consensus_version: &ConsensusVersionView,
    ) -> Option<ExternalEvent> {
        match codec::decode_compound_message(&msg.data) {
            Ok(compound) => {
                // Group-level structural screen (Go: `agreement/message.go`'s
                // `proposalCarriesInvalidTxn`, called from `demux.go`'s
                // `tokenizeMessages`). A proposal whose payset fails this
                // screen is silently dropped — logged, but the peer is NOT
                // disconnected, unlike a raw decode failure below.
                if let Err(e) = algo_validate::check_payset(&compound.proposal.block.payset) {
                    warn!(
                        len = msg.data.len(),
                        prefix = %hex_prefix(&msg.data, 96),
                        "dropping proposal with a malformed transaction payload: {}",
                        e
                    );
                    return None;
                }
                // go-algorand v4.7.4-stable (`checks: recompute group IDs`,
                // commit b07049dfb) folded a cryptographic check into this
                // same early screen: each payset group's claimed `Group`
                // digest must actually commit to (be the hash of) its
                // member transactions, and the group must not exceed the
                // max group size. `check_payset` above only detects group
                // *boundaries*; it never recomputes the hash. Without this,
                // a proposal whose `Group` field doesn't commit to its
                // transactions would pass this early screen and only be
                // caught later, in full block validation.
                if let Err(e) =
                    algo_validate::validate_transaction_group(&compound.proposal.block.payset)
                {
                    warn!(
                        len = msg.data.len(),
                        prefix = %hex_prefix(&msg.data, 96),
                        "dropping proposal with a transaction group that fails group-ID verification: {}",
                        e
                    );
                    return None;
                }
                Some(setup_compound_message_from_network(
                    compound,
                    msg.handle,
                    consensus_version,
                ))
            }
            Err(e) => {
                warn!(
                    len = msg.data.len(),
                    prefix = %hex_prefix(&msg.data, 96),
                    "error decoding proposal message: {}",
                    e
                );
                // Disconnect the peer that sent the malformed message.
                if let Some(ref net) = self.network {
                    net.disconnect(&msg.handle);
                }
                None
            }
        }
    }

    /// Handle a raw bundle message from the network.
    ///
    /// Decodes the bundle from wire format and constructs a `BundlePresent` event.
    fn handle_raw_bundle(&self, msg: Message) -> Option<ExternalEvent> {
        match codec::decode_bundle(&msg.data) {
            Ok(bundle) => {
                let internal = InternalMessage {
                    message_handle: msg.handle,
                    tag: VOTE_BUNDLE_TAG.to_string(),
                    unauthenticated_bundle: bundle,
                    ..InternalMessage::default()
                };
                Some(ExternalEvent {
                    event: Event::Message(MessageEvent {
                        t: EventType::BundlePresent,
                        input: internal,
                        ..MessageEvent::default()
                    }),
                })
            }
            Err(e) => {
                warn!("error decoding bundle message: {}", e);
                // Disconnect the peer that sent the malformed message.
                if let Some(ref net) = self.network {
                    net.disconnect(&msg.handle);
                }
                None
            }
        }
    }

    /// Handle a verified vote result from the crypto verifier.
    ///
    /// Go forwards only `r.message` into the `voteVerified` event
    /// (`agreement/demux.go:345`) and relies on the verifier having already
    /// stored the authenticated vote on it
    /// (`asyncVoteVerifier.go:107`: `req.message.Vote = v`). Downstream —
    /// `proposalManager`, `proposalStore`, `proposalTracker` — all read
    /// `input.vote` unconditionally, so a result whose message lost the
    /// vote makes the whole proposal pipeline fail (issue #478). Restore it
    /// here if a verifier implementation did not.
    fn handle_verified_vote(&self, r: CryptoVoteVerifyResult) -> ExternalEvent {
        let mut input = r.message;
        if input.vote.is_none() {
            input.vote = r.vote;
        }
        ExternalEvent {
            event: Event::Message(MessageEvent {
                t: EventType::VoteVerified,
                input,
                task_index: r.task_index,
                err: r.err,
                cancelled: r.cancelled,
                ..MessageEvent::default()
            }),
        }
    }

    /// Handle a verified proposal result from the crypto verifier.
    fn handle_verified_proposal(&self, r: CryptoResult) -> ExternalEvent {
        ExternalEvent {
            event: Event::Message(MessageEvent {
                t: EventType::PayloadVerified,
                input: r.message,
                task_index: r.task_index,
                err: r.err,
                cancelled: r.cancelled,
                ..MessageEvent::default()
            }),
        }
    }

    /// Handle a verified bundle result from the crypto verifier.
    fn handle_verified_bundle(&self, r: CryptoResult) -> ExternalEvent {
        ExternalEvent {
            event: Event::Message(MessageEvent {
                t: EventType::BundleVerified,
                input: r.message,
                task_index: r.task_index,
                err: r.err,
                cancelled: r.cancelled,
                ..MessageEvent::default()
            }),
        }
    }

    /// Shut down the demux.
    ///
    /// Mirrors Go's `demux.quit`.
    pub fn quit(&mut self) {
        self.pseudo_queue.clear();
    }

    /// Returns the number of pending pseudonode events.
    pub fn pending_count(&self) -> usize {
        self.pseudo_queue.len()
    }
}

// ---------------------------------------------------------------------------
// Helper: setupCompoundMessage
// ---------------------------------------------------------------------------

/// Process compound messages from the network: a proposal payload that may
/// also contain a proposal-vote.
///
/// When a compound message has a non-default vote, the vote becomes the
/// primary event (VotePresent) with the payload as a tail (PayloadPresent).
/// When there is no vote, only a PayloadPresent event is returned.
///
/// Mirrors Go's `setupCompoundMessage`.
pub fn setup_compound_message(
    vote_present: bool,
    payload_event: MessageEvent,
    vote_event: Option<MessageEvent>,
) -> ExternalEvent {
    if !vote_present {
        // No vote attached: just a payload
        ExternalEvent {
            event: Event::Message(payload_event),
        }
    } else {
        // Vote + payload: vote is primary, payload is the tail
        let mut ve = vote_event.unwrap_or_default();
        ve.tail = Some(Box::new(payload_event));
        ExternalEvent {
            event: Event::Message(ve),
        }
    }
}

/// Internal helper to construct a compound message event from a decoded
/// `CompoundMessage` and its network handle.
///
/// Mirrors Go's `setupCompoundMessage(l, m)` where the ledger is used to
/// attach consensus version to the tail event. The consensus version is
/// passed in from the caller (via `ExternalDemuxSignals`).
fn setup_compound_message_from_network(
    compound: CompoundMessage,
    handle: crate::traits::MessageHandle,
    consensus_version: &ConsensusVersionView,
) -> ExternalEvent {
    // Check if the compound message has a non-default vote attached.
    // Mirrors Go's `compound.Vote == (unauthenticatedVote{})` zero-value check.
    let has_vote = !(compound.vote.raw_vote.sender == Address([0u8; 32])
        && compound.vote.raw_vote.round == Round(0)
        && compound.vote.raw_vote.proposal == BOTTOM);

    if !has_vote {
        // No vote attached: just a payload
        let internal = InternalMessage {
            message_handle: handle,
            tag: PROPOSAL_PAYLOAD_TAG.to_string(),
            unauthenticated_proposal: compound.proposal,
            ..InternalMessage::default()
        };
        ExternalEvent {
            event: Event::Message(MessageEvent {
                t: EventType::PayloadPresent,
                input: internal,
                ..MessageEvent::default()
            }),
        }
    } else {
        // Vote + payload: vote is primary, payload is the tail.
        // The tail message carries the proposal payload AND a clone of
        // the same network handle. Mirrors Go's `setupCompoundMessage`
        // which assigns `synthetic.MessageHandle = e.MessageHandle` on
        // both the vote event and the payload tail. With `MessageHandle =
        // Option<Arc<dyn Any + Send + Sync>>` this is a refcount bump,
        // not a deep copy. Critically, the Player relies on the tail
        // having a non-None handle: otherwise the post-verify
        // PayloadVerified event triggers the `relay as proposer` branch
        // and emits a redundant compound relay for a peer-originated
        // message.
        let tail_internal = InternalMessage {
            message_handle: handle.as_ref().map(std::sync::Arc::clone),
            tag: PROPOSAL_PAYLOAD_TAG.to_string(),
            unauthenticated_proposal: compound.proposal,
            ..InternalMessage::default()
        };
        // Attach the consensus version to the tail event, matching Go's
        // `synthetic.AttachConsensusVersion(...)` in `setupCompoundMessage`.
        let tail = MessageEvent {
            t: EventType::PayloadPresent,
            input: tail_internal,
            proto: consensus_version.clone(),
            ..MessageEvent::default()
        };

        let vote_internal = InternalMessage {
            message_handle: handle,
            tag: AGREEMENT_VOTE_TAG.to_string(),
            unauthenticated_vote: compound.vote,
            ..InternalMessage::default()
        };
        ExternalEvent {
            event: Event::Message(MessageEvent {
                t: EventType::VotePresent,
                input: vote_internal,
                tail: Some(Box::new(tail)),
                ..MessageEvent::default()
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: make timeout events
// ---------------------------------------------------------------------------

/// Create a regular timeout event.
pub fn make_timeout_event(random_entropy: u64, round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::Timeout(TimeoutEvent {
            t: EventType::Timeout,
            random_entropy,
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

/// Create a fast timeout event.
pub fn make_fast_timeout_event(random_entropy: u64, round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::Timeout(TimeoutEvent {
            t: EventType::FastTimeout,
            random_entropy,
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

/// Create a round interruption event.
pub fn make_round_interruption_event(round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::RoundInterruption(RoundInterruptionEvent {
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

/// Hex-encode the first `n` bytes of `data`, for diagnostics on a wire
/// message this node could not decode.
fn hex_prefix(data: &[u8], n: usize) -> String {
    use std::fmt::Write as _;
    let take = std::cmp::min(n, data.len());
    let mut s = String::with_capacity(take * 2 + 3);
    for b in &data[..take] {
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > take {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::events::EmptyEvent;
    use crate::system_clock::SystemClock;
    use crate::vote::UnauthenticatedVote;

    /// Helper to create a Demux with dummy channels for testing.
    #[allow(clippy::type_complexity)]
    fn make_test_demux() -> (
        Demux,
        crossbeam_channel::Sender<Message>,
        crossbeam_channel::Sender<Message>,
        crossbeam_channel::Sender<Message>,
        crossbeam_channel::Sender<CryptoVoteVerifyResult>,
        crossbeam_channel::Sender<CryptoResult>,
        crossbeam_channel::Sender<CryptoResult>,
        crossbeam_channel::Sender<Round>,
        crossbeam_channel::Sender<()>,
    ) {
        let (av_tx, av_rx) = crossbeam_channel::unbounded();
        let (pp_tx, pp_rx) = crossbeam_channel::unbounded();
        let (vb_tx, vb_rx) = crossbeam_channel::unbounded();
        let (vv_tx, vv_rx) = crossbeam_channel::unbounded();
        let (vp_tx, vp_rx) = crossbeam_channel::unbounded();
        let (vb_res_tx, vb_res_rx) = crossbeam_channel::unbounded();
        let (lr_tx, lr_rx) = crossbeam_channel::unbounded();
        let (quit_tx, quit_rx) = crossbeam_channel::unbounded();

        let demux = Demux::new(
            av_rx,
            pp_rx,
            vb_rx,
            vv_rx,
            vp_rx,
            vb_res_rx,
            lr_rx,
            quit_rx,
            SystemClock::new(),
        );
        (
            demux, av_tx, pp_tx, vb_tx, vv_tx, vp_tx, vb_res_tx, lr_tx, quit_tx,
        )
    }

    /// Regression test for issue #478.
    ///
    /// The demux forwards only `r.message` into the `voteVerified` event, so
    /// the authenticated vote has to be on the message. Whether the verifier
    /// put it there or only on `r.vote`, the emitted event must carry it —
    /// `proposalManager`/`proposalStore`/`proposalTracker` all read
    /// `input.vote` unconditionally, and before this fix the field was
    /// always `None`, which took the agreement thread down on the first
    /// successfully-verified proposal-vote from a Go peer.
    #[test]
    fn verified_vote_event_carries_the_authenticated_vote() {
        use crate::step::{Period, Step};
        use crate::test_support::vote_maker::VoteMakerHelper;

        let (demux, ..) = make_test_demux();

        let mut helper = VoteMakerHelper::new();
        let prop = helper.make_random_proposal_value();
        let vote = helper.make_verified_vote(0, Round(1), Period(0), Step(1), prop);

        let result = CryptoVoteVerifyResult {
            vote: Some(vote),
            // A message that does NOT already carry the vote.
            message: InternalMessage::default(),
            task_index: 7,
            err: None,
            cancelled: false,
        };

        let ev = demux.handle_verified_vote(result);
        let Event::Message(me) = ev.event else {
            panic!("expected a message event");
        };
        assert_eq!(me.t, EventType::VoteVerified);
        assert!(
            me.input.vote.is_some(),
            "voteVerified must carry the authenticated vote"
        );
    }

    fn default_signals() -> ExternalDemuxSignals {
        ExternalDemuxSignals {
            deadline: Deadline::default(),
            fast_recovery_deadline: Deadline::default(),
            current_round: Round(1),
            random_source_entropy: 0,
            current_consensus_version: ConsensusVersionView::default(),
        }
    }

    #[test]
    fn demux_pseudo_queue_priority() {
        let (mut demux, ..) = make_test_demux();

        // Queue a pseudonode event
        demux.queue_pseudo_events(vec![ExternalEvent {
            event: Event::Empty(EmptyEvent),
        }]);
        assert_eq!(demux.pending_count(), 1);

        // Should return the pseudonode event immediately
        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::None);
        assert_eq!(demux.pending_count(), 0);
    }

    #[test]
    fn demux_prioritize() {
        let (mut demux, ..) = make_test_demux();

        // Prioritize events should come first
        demux.prioritize(vec![ExternalEvent {
            event: Event::Empty(EmptyEvent),
        }]);

        let signals = default_signals();

        // First call should return the priority event
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::None);
    }

    #[test]
    fn demux_quit_signal() {
        let (mut demux, _, _, _, _, _, _, _, quit_tx) = make_test_demux();

        // Send quit signal
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_none());
    }

    #[test]
    fn demux_round_interruption() {
        let (mut demux, _av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, lr_tx, _quit_tx) =
            make_test_demux();

        // Send a round notification
        lr_tx.send(Round(42)).unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.event_type(), EventType::RoundInterruption);
        assert_eq!(event.consensus_round(), Round(42));
    }

    #[test]
    fn demux_timeout_on_no_events() {
        let (mut demux, _av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, _quit_tx) =
            make_test_demux();

        // Set a very short deadline so the timeout fires quickly
        let signals = ExternalDemuxSignals {
            deadline: Deadline {
                duration: Duration::from_millis(1),
                ..Deadline::default()
            },
            fast_recovery_deadline: Deadline::default(),
            current_round: Round(5),
            random_source_entropy: 42,
            current_consensus_version: ConsensusVersionView::default(),
        };
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.event_type(), EventType::Timeout);
        if let Event::Timeout(te) = &event.event {
            assert_eq!(te.random_entropy, 42);
            assert_eq!(te.round, Round(5));
        } else {
            panic!("expected timeout event");
        }
    }

    #[test]
    fn demux_fast_timeout() {
        let (mut demux, _av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, _quit_tx) =
            make_test_demux();

        // Set fast recovery deadline shorter than regular deadline
        let signals = ExternalDemuxSignals {
            deadline: Deadline {
                duration: Duration::from_secs(60),
                ..Deadline::default()
            },
            fast_recovery_deadline: Deadline {
                duration: Duration::from_millis(1),
                ..Deadline::default()
            },
            current_round: Round(7),
            random_source_entropy: 99,
            current_consensus_version: ConsensusVersionView::default(),
        };
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.event_type(), EventType::FastTimeout);
        if let Event::Timeout(te) = &event.event {
            assert_eq!(te.random_entropy, 99);
            assert_eq!(te.round, Round(7));
        } else {
            panic!("expected fast timeout event");
        }
    }

    #[test]
    fn demux_quit() {
        let (mut demux, ..) = make_test_demux();
        demux.queue_pseudo_events(vec![ExternalEvent {
            event: Event::Empty(EmptyEvent),
        }]);
        assert!(demux.pending_count() > 0);

        demux.quit();
        assert_eq!(demux.pending_count(), 0);
    }

    #[test]
    fn make_timeout_event_type() {
        let e = make_timeout_event(42, Round(1));
        assert_eq!(e.event_type(), EventType::Timeout);
    }

    #[test]
    fn make_fast_timeout_event_type() {
        let e = make_fast_timeout_event(42, Round(1));
        assert_eq!(e.event_type(), EventType::FastTimeout);
    }

    #[test]
    fn make_round_interruption_event_type() {
        let e = make_round_interruption_event(Round(5));
        assert_eq!(e.event_type(), EventType::RoundInterruption);
    }

    #[test]
    fn external_event_consensus_round() {
        let e = make_round_interruption_event(Round(42));
        assert_eq!(e.consensus_round(), Round(42));
    }

    // -- L2: Raw message handling tests --

    #[test]
    fn demux_raw_vote_decode_and_return() {
        let (mut demux, av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, _quit_tx) =
            make_test_demux();

        // Encode a default vote and send it as a raw message.
        let vote = UnauthenticatedVote::default();
        let encoded = codec::encode_vote(&vote);
        av_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::VotePresent);
    }

    #[test]
    fn demux_raw_bundle_decode_and_return() {
        let (mut demux, _av_tx, _pp_tx, vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, _quit_tx) =
            make_test_demux();

        // Encode a default bundle and send it as a raw message.
        let bundle = crate::bundle::UnauthenticatedBundle::default();
        let encoded = codec::encode_bundle(&bundle);
        vb_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::BundlePresent);
    }

    #[test]
    fn demux_raw_proposal_decode_and_return() {
        let (mut demux, _av_tx, pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, _quit_tx) =
            make_test_demux();

        // Encode a compound message with a valid block and send it.
        let compound = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: crate::proposal::UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(1),
                    ..algo_types::Block::default()
                },
                seed_proof: [0u8; crate::VRF_PROOF_SIZE],
                original_period: crate::step::Period(0),
                original_proposer: Address([0u8; 32]),
            },
        };
        let encoded = codec::encode_compound_message(&compound);
        pp_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);
        assert!(result.is_some());
        let event = result.unwrap();
        // The compound message has a zero/default vote, so only payload is returned.
        assert_eq!(event.event_type(), EventType::PayloadPresent);
    }

    #[test]
    fn demux_raw_proposal_with_malformed_payset_is_dropped_not_disconnected() {
        // go-algorand v4.7.2-stable: `agreement/message.go`'s
        // `proposalCarriesInvalidTxn`, called from `demux.go`'s
        // `tokenizeMessages`. A proposal that decodes fine but whose block
        // payset fails the group-level `CheckPayset` screen is silently
        // dropped — logged, but NOT a disconnect-worthy malformed message
        // like an actual decode failure is.
        use crate::stubs::StubNetwork;
        use algo_types::{SignedTransaction, Transaction, TxnType};

        let (mut demux, _av_tx, pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, quit_tx) =
            make_test_demux();

        let stub = Arc::new(StubNetwork::new());
        demux.set_network(stub.clone() as Arc<dyn AgreementNetwork + Send + Sync>);

        // A payset containing a transaction of an unrecognized type — one of
        // the five checkTxnGroup rejection cases.
        let bogus_txn = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::from("bogus"),
                sender: Address([1u8; 32]),
                ..Transaction::default()
            },
            ..SignedTransaction::default()
        };
        let compound = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: crate::proposal::UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(1),
                    payset: vec![bogus_txn],
                    ..algo_types::Block::default()
                },
                seed_proof: [0u8; crate::VRF_PROOF_SIZE],
                original_period: crate::step::Period(0),
                original_proposer: Address([0u8; 32]),
            },
        };
        let encoded = codec::encode_compound_message(&compound);
        pp_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();
        // Quit so `next()` returns after retrying past the dropped message,
        // rather than blocking forever waiting for a next event.
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);

        assert!(result.is_none(), "dropped proposal yields no event");
        assert!(
            stub.disconnected.lock().unwrap().is_empty(),
            "a malformed-payset proposal must be dropped, not disconnect the peer"
        );
    }

    #[test]
    fn demux_raw_proposal_with_group_id_mismatch_is_dropped_not_disconnected() {
        // go-algorand v4.7.4-stable commit b07049dfb ("checks: recompute
        // group IDs"): `proposalCarriesInvalidTxn` now recomputes each
        // payset group's ID (`transactions.CheckPaysetGroup`) rather than
        // only checking group boundaries (`CheckPayset`), so a proposal
        // whose claimed `Group` field does not actually commit to (hash)
        // its member transactions is dropped at this early screen, not
        // just later during full block validation.
        use crate::stubs::StubNetwork;
        use algo_types::{SignedTransaction, Transaction, TxnType};

        let (mut demux, _av_tx, pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, quit_tx) =
            make_test_demux();

        let stub = Arc::new(StubNetwork::new());
        demux.set_network(stub.clone() as Arc<dyn AgreementNetwork + Send + Sync>);

        // Two transactions sharing the same nonzero `group` value, but that
        // value does not commit to (hash) these two transactions — a
        // maliciously (or corruptly) reordered/incomplete group.
        let bogus_group = [9u8; 32];
        let txn1 = Transaction {
            txn_type: TxnType::from("pay"),
            sender: Address([1u8; 32]),
            group: bogus_group,
            ..Transaction::default()
        };
        let txn2 = Transaction {
            txn_type: TxnType::from("pay"),
            sender: Address([2u8; 32]),
            group: bogus_group,
            ..Transaction::default()
        };
        let compound = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: crate::proposal::UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(1),
                    payset: vec![
                        SignedTransaction {
                            txn: txn1,
                            ..SignedTransaction::default()
                        },
                        SignedTransaction {
                            txn: txn2,
                            ..SignedTransaction::default()
                        },
                    ],
                    ..algo_types::Block::default()
                },
                seed_proof: [0u8; crate::VRF_PROOF_SIZE],
                original_period: crate::step::Period(0),
                original_proposer: Address([0u8; 32]),
            },
        };
        let encoded = codec::encode_compound_message(&compound);
        pp_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();
        // Quit so `next()` returns after retrying past the dropped message,
        // rather than blocking forever waiting for a next event.
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);

        assert!(
            result.is_none(),
            "a proposal whose group ID doesn't commit to its transactions must be dropped"
        );
        assert!(
            stub.disconnected.lock().unwrap().is_empty(),
            "a group-ID-mismatch proposal must be dropped, not disconnect the peer"
        );
    }

    #[test]
    fn demux_raw_proposal_with_oversized_txn_group_is_dropped_not_disconnected() {
        // TestProposalCarriesOversizedTxnGroup (go: agreement/message_test.go):
        // a proposal whose payset contains a run of more than
        // MAX_GROUP_SIZE consecutive same-group transactions must be
        // dropped at this same early screen (`check_payset`), not just
        // during full block validation.
        use crate::stubs::StubNetwork;
        use algo_types::{SignedTransaction, Transaction, TxnType};

        let (mut demux, _av_tx, pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, quit_tx) =
            make_test_demux();

        let stub = Arc::new(StubNetwork::new());
        demux.set_network(stub.clone() as Arc<dyn AgreementNetwork + Send + Sync>);

        let group_hash = [7u8; 32];
        let payset: Vec<SignedTransaction> = (0..=algo_validate::rules::MAX_GROUP_SIZE)
            .map(|i| SignedTransaction {
                txn: Transaction {
                    txn_type: TxnType::from("pay"),
                    sender: Address([i as u8 + 1; 32]),
                    group: group_hash,
                    ..Transaction::default()
                },
                ..SignedTransaction::default()
            })
            .collect();
        let compound = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: crate::proposal::UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(1),
                    payset,
                    ..algo_types::Block::default()
                },
                seed_proof: [0u8; crate::VRF_PROOF_SIZE],
                original_period: crate::step::Period(0),
                original_proposer: Address([0u8; 32]),
            },
        };
        let encoded = codec::encode_compound_message(&compound);
        pp_tx
            .send(Message {
                data: encoded,
                handle: None,
            })
            .unwrap();
        // Quit so `next()` returns after retrying past the dropped message,
        // rather than blocking forever waiting for a next event.
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        let result = demux.next(&signals, None);

        assert!(
            result.is_none(),
            "a proposal with a group larger than MAX_GROUP_SIZE must be dropped"
        );
        assert!(
            stub.disconnected.lock().unwrap().is_empty(),
            "an oversized-group proposal must be dropped, not disconnect the peer"
        );
    }

    #[test]
    fn demux_garbage_data_does_not_crash() {
        let (mut demux, av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, quit_tx) =
            make_test_demux();

        // Send garbage data to the vote channel.
        av_tx
            .send(Message {
                data: vec![0xff, 0xfe, 0x00, 0x01],
                handle: None,
            })
            .unwrap();
        // Also send a quit so the demux does not hang after skipping the bad message.
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        // Should not panic — the garbage decode fails, the loop retries,
        // and then the quit signal fires.
        let result = demux.next(&signals, None);
        assert!(result.is_none());
    }

    #[test]
    fn demux_channel_close_does_not_crash() {
        let (mut demux, av_tx, _pp_tx, _vb_tx, _vv_tx, _vp_tx, _vb_res_tx, _lr_tx, quit_tx) =
            make_test_demux();

        // Close the vote channel by dropping the sender.
        drop(av_tx);
        // Send a quit so the demux can exit after retrying.
        quit_tx.send(()).unwrap();

        let signals = default_signals();
        // Should not panic — channel close is logged and retried, then quit fires.
        let result = demux.next(&signals, None);
        assert!(result.is_none());
    }
}
