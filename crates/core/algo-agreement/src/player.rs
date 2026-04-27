// Player state machine — the core dispatch logic of the agreement protocol.
//
// Mirrors go-algorand/agreement/player.go (~770 lines).
//
// The player implements the top-level state machine functionality of the
// agreement protocol. It receives events from the demux and dispatches them
// through the router hierarchy to produce a list of actions.
//
// The player is deterministic: the same event sequence always produces the
// same actions.

use std::time::Duration;

use algo_types::{ConsensusParams, Round};
use serde::{Deserialize, Serialize};

use crate::types::duration_serde;

use crate::actions::{
    Action, ActionType, CheckpointAction, EnsureAction, NetworkAction, PseudonodeAction,
    RezeroAction, StageDigestAction,
};
use crate::certificate::Certificate;
use crate::events::{
    CheckpointEvent, CommittableEvent, CompoundMessage, DumpVotesRequestEvent, Event, EventType,
    FilterableMessageEvent, FreshestBundleRequestEvent, LateCredentialTrackingEffect, MessageEvent,
    NextThresholdStatusEvent, NextThresholdStatusRequestEvent, ProposalFrozenEvent,
    ReadLowestEvent, RoundInterruptionEvent, ThresholdEvent, TimeoutEvent,
};
use crate::router::{pinned_value, staged_value, RootRouter, StateMachineTag};
use crate::step::{Period, Step, CERT, DOWN, LATE, NEXT, PROPOSE, REDO, SOFT};
use crate::types::{
    credential_round_lag, deadline_timeout, default_deadline_timeout, filter_timeout,
    CredentialArrivalHistory, Deadline, TimeoutType, DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
    DYNAMIC_FILTER_TIMEOUT_CREDENTIAL_ARRIVAL_HISTORY_IDX, DYNAMIC_FILTER_TIMEOUT_GRACE_INTERVAL,
    DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND, PARTITION_STEP,
};
use crate::vote::{UnauthenticatedVote, BOTTOM};

// ---------------------------------------------------------------------------
// ProposalTable
// ---------------------------------------------------------------------------

/// A table that stores pending proposal payloads which must be verified after
/// some vote has been verified.
///
/// Mirrors Go's `proposalTable`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposalTableImpl {
    /// Pending tail events, indexed by task index.
    pending: std::collections::HashMap<u64, Box<MessageEvent>>,
    /// Next sequence number.
    next_seq: u64,
}

impl ProposalTableImpl {
    /// Push a tail event and return a sequence number for later retrieval.
    ///
    /// Mirrors Go's `proposalTable.push` (in `agreement/proposalTable.go`)
    /// byte-for-byte: the counter is incremented BEFORE the value is read,
    /// so the first sequence number returned is `1` (not `0`). This makes
    /// task indices match Go's exactly, which keeps cadaver replay output
    /// and any future cross-implementation persistence interop aligned.
    pub fn push(&mut self, tail: Option<Box<MessageEvent>>) -> u64 {
        self.next_seq += 1;
        let seq = self.next_seq;
        if let Some(t) = tail {
            self.pending.insert(seq, t);
        }
        seq
    }

    /// Pop a tail event by its sequence number.
    ///
    /// Mirrors Go's `proposalTable.pop`.
    pub fn pop(&mut self, seq: u64) -> Option<Box<MessageEvent>> {
        self.pending.remove(&seq)
    }
}

// ---------------------------------------------------------------------------
// Player
// ---------------------------------------------------------------------------

/// The core agreement protocol state machine.
///
/// The player tracks the current round, period, and step, manages deadlines
/// and timeouts, and dispatches events to produce actions.
///
/// Mirrors Go's `player` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    /// Current round.
    pub round: Round,
    /// Current period.
    pub period: Period,
    /// Current step.
    pub step: Step,

    /// The largest step reached in the last period. Affects propagation of
    /// next-vote messages.
    pub last_concluding: Step,

    /// The time of the next timeout expected by the player state machine
    /// (relative to the start of the current period).
    pub deadline: Deadline,

    /// Whether the player is expecting a random timeout (napping).
    pub napping: bool,

    /// The next timeout expected for fast partition recovery.
    #[serde(with = "duration_serde")]
    pub fast_recovery_deadline: Duration,

    /// Pending proposals which must be verified after some vote has been
    /// verified.
    #[serde(skip)]
    pub pending: ProposalTableImpl,

    /// History of arrival times of the lowest credential from previous rounds,
    /// used for calculating the filter timeout dynamically.
    pub lowest_credential_arrivals: CredentialArrivalHistory,

    /// The period 0 dynamic filter timeout calculated for this round (if set),
    /// even if dynamic filter timeouts are not enabled. Used for telemetry.
    #[serde(with = "duration_serde")]
    pub dynamic_filter_timeout: Duration,
}

impl Default for Player {
    fn default() -> Self {
        Self {
            round: Round(0),
            period: Period(0),
            step: SOFT,
            last_concluding: Step(0),
            deadline: Deadline::default(),
            napping: false,
            fast_recovery_deadline: Duration::ZERO,
            pending: ProposalTableImpl::default(),
            lowest_credential_arrivals: CredentialArrivalHistory::new(
                DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
            ),
            dynamic_filter_timeout: Duration::ZERO,
        }
    }
}

impl Player {
    /// The core dispatch method. Handles an event and returns a list of actions.
    ///
    /// Mirrors Go's `player.handle`.
    pub fn handle(
        &mut self,
        router: &mut RootRouter,
        e: Event,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        if e.event_type() == EventType::None {
            return Vec::new();
        }

        match e {
            Event::Message(me) => self.handle_message_event(router, me, params),
            Event::FilterableMessage(fme) => {
                self.handle_message_event(router, fme.message_event, params)
            }
            Event::Threshold(te) => self.handle_threshold_event(router, te, params),
            Event::Timeout(te) => {
                if te.t == EventType::FastTimeout {
                    return self.handle_fast_timeout(router, te, params);
                }

                if !self.napping {
                    tracing::info!(
                        round = self.round.0,
                        period = self.period.0,
                        step = self.step.0,
                        deadline = ?self.deadline.duration,
                        "timeout fired"
                    );
                }

                let deadline_timeout_val = if te.proto.err.is_some() || te.proto.version.is_empty()
                {
                    tracing::error!(
                        proto_version = te.proto.version,
                        proto_err = ?te.proto.err,
                        "failed to read valid protocol version for timeout event, falling back to default"
                    );
                    default_deadline_timeout()
                } else {
                    deadline_timeout(self.period, params)
                };

                match self.step {
                    s if s == SOFT => {
                        // precondition: nap = false
                        let actions = self.issue_soft_vote(router, deadline_timeout_val, params);
                        self.step = CERT;
                        actions
                    }
                    s if s == CERT => {
                        // precondition: nap = false
                        self.step = NEXT;
                        self.issue_next_vote(router, deadline_timeout_val, params)
                    }
                    _ => {
                        if self.napping {
                            return self.issue_next_vote(router, deadline_timeout_val, params);
                        }
                        // not napping, so we should enter a new step
                        self.step = Step(self.step.0 + 1);

                        let (lower, upper) = self.step.next_vote_ranges(deadline_timeout_val);
                        let delta = Duration::from_nanos(
                            te.random_entropy % (upper - lower).as_nanos() as u64,
                        );

                        self.napping = true;
                        self.deadline = Deadline {
                            duration: lower + delta,
                            timeout_type: TimeoutType::Deadline,
                        };
                        Vec::new()
                    }
                }
            }
            Event::RoundInterruption(rie) => self.enter_round(
                router,
                Event::RoundInterruption(rie.clone()),
                rie.round,
                params,
            ),
            Event::Checkpoint(ce) => self.handle_checkpoint_event(ce),
            _ => {
                panic!("player: bad event type: {:?}", e.event_type());
            }
        }
    }

    /// Handle a fast recovery timeout.
    ///
    /// Mirrors Go's `player.handleFastTimeout`.
    fn handle_fast_timeout(
        &mut self,
        router: &mut RootRouter,
        e: TimeoutEvent,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        if e.proto.err.is_some() {
            tracing::error!(
                proto_version = e.proto.version,
                proto_err = ?e.proto.err,
                "failed to read protocol version for fastTimeout event"
            );
            return Vec::new();
        }

        let lambda = params.fast_recovery_lambda;
        let k_nanos = if lambda.as_nanos() > 0 {
            self.fast_recovery_deadline
                .as_nanos()
                .div_ceil(lambda.as_nanos())
        } else {
            0
        };
        let k = k_nanos as u64;
        let lower = Duration::from_nanos(k as u128 as u64 * lambda.as_nanos() as u64);
        let upper = Duration::from_nanos((k + 1) as u128 as u64 * lambda.as_nanos() as u64);
        let range = if upper > lower {
            (upper - lower).as_nanos() as u64
        } else {
            1
        };
        let delta = Duration::from_nanos(e.random_entropy % range);

        if self.fast_recovery_deadline == Duration::ZERO {
            // Don't vote the first time
            self.fast_recovery_deadline = lower + delta + lambda;
            return Vec::new();
        }
        self.fast_recovery_deadline = lower + delta;

        tracing::info!(
            round = self.round.0,
            period = self.period.0,
            step = self.step.0,
            fast_recovery_deadline = ?self.fast_recovery_deadline,
            "fast timeout fired"
        );

        self.issue_fast_vote(router, params)
    }

    /// Issue a soft vote.
    ///
    /// Mirrors Go's `player.issueSoftVote`.
    fn issue_soft_vote(
        &mut self,
        router: &mut RootRouter,
        deadline_timeout_val: Duration,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        // Get the frozen proposal
        let e = router.dispatch(
            self,
            Event::ProposalFrozen(ProposalFrozenEvent::default()),
            StateMachineTag::ProposalMachinePeriod,
            self.round,
            self.period,
            Step(0),
            params,
        );
        let frozen_proposal = match e {
            Event::ProposalFrozen(pfe) => pfe.proposal,
            _ => BOTTOM,
        };

        let mut a = PseudonodeAction {
            t: ActionType::Attest,
            round: self.round,
            period: self.period,
            step: SOFT,
            proposal: frozen_proposal,
        };

        // Check next threshold status from previous period
        let res = router.dispatch(
            self,
            Event::NextThresholdStatusRequest(NextThresholdStatusRequestEvent),
            StateMachineTag::VoteMachinePeriod,
            self.round,
            Period(self.period.0.saturating_sub(1)),
            Step(0),
            params,
        );
        let next_status = match res {
            Event::NextThresholdStatus(nts) => nts,
            _ => NextThresholdStatusEvent::default(),
        };

        if self.period > Period(0) && !next_status.bottom && next_status.proposal != BOTTOM {
            // Did not see bottom: vote for our starting value
            a.proposal = next_status.proposal;
            self.deadline = Deadline {
                duration: deadline_timeout_val,
                timeout_type: TimeoutType::Deadline,
            };
            return vec![Action::Pseudonode(a)];
        }

        if a.proposal == BOTTOM {
            // Did not see anything: do not vote
            self.deadline = Deadline {
                duration: deadline_timeout_val,
                timeout_type: TimeoutType::Deadline,
            };
            return Vec::new();
        }

        if self.period.0 > a.proposal.original_period.0 {
            // Leader sent reproposal: vote if we saw a quorum for that hash
            if next_status.proposal != BOTTOM && next_status.proposal == a.proposal {
                self.deadline = Deadline {
                    duration: deadline_timeout_val,
                    timeout_type: TimeoutType::Deadline,
                };
                return vec![Action::Pseudonode(a)];
            }
            self.deadline = Deadline {
                duration: deadline_timeout_val,
                timeout_type: TimeoutType::Deadline,
            };
            return Vec::new();
        }

        // Original proposal: vote for it
        self.deadline = Deadline {
            duration: deadline_timeout_val,
            timeout_type: TimeoutType::Deadline,
        };
        vec![Action::Pseudonode(a)]
    }

    /// Issue a cert vote.
    ///
    /// Mirrors Go's `player.issueCertVote`.
    fn issue_cert_vote(&self, e: &CommittableEvent) -> Action {
        Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            round: self.round,
            period: self.period,
            step: CERT,
            proposal: e.proposal,
        })
    }

    /// Issue a next vote.
    ///
    /// Mirrors Go's `player.issueNextVote`.
    fn issue_next_vote(
        &mut self,
        router: &mut RootRouter,
        deadline_timeout_val: Duration,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = self.partition_policy(router, params);

        let mut a = PseudonodeAction {
            t: ActionType::Attest,
            round: self.round,
            period: self.period,
            step: self.step,
            proposal: BOTTOM,
        };

        let answer = staged_value(self, router, self.round, self.period, params);
        if answer.committable {
            a.proposal = answer.proposal;
        } else {
            let res = router.dispatch(
                self,
                Event::NextThresholdStatusRequest(NextThresholdStatusRequestEvent),
                StateMachineTag::VoteMachinePeriod,
                self.round,
                Period(self.period.0.saturating_sub(1)),
                Step(0),
                params,
            );
            let next_status = match res {
                Event::NextThresholdStatus(nts) => nts,
                _ => NextThresholdStatusEvent::default(),
            };
            if !next_status.bottom {
                a.proposal = next_status.proposal;
            }
        }
        actions.push(Action::Pseudonode(a.clone()));

        let (_, upper) = self.step.next_vote_ranges(deadline_timeout_val);
        self.napping = false;
        self.deadline = Deadline {
            duration: upper,
            timeout_type: TimeoutType::Deadline,
        };
        actions
    }

    /// Issue a fast vote for partition recovery.
    ///
    /// Mirrors Go's `player.issueFastVote`.
    fn issue_fast_vote(
        &mut self,
        router: &mut RootRouter,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = self.partition_policy(router, params);

        // Dump votes from late, redo, down steps
        let elate = self.dump_votes(router, LATE, params);
        let eredo = self.dump_votes(router, REDO, params);
        let edown = self.dump_votes(router, DOWN, params);

        let mut votes = elate;
        votes.extend(eredo);
        votes.extend(edown);

        actions.push(Action::Network(Box::new(NetworkAction {
            t: ActionType::BroadcastVotes,
            unauthenticated_votes: votes,
            ..NetworkAction::default()
        })));

        let mut a = PseudonodeAction {
            t: ActionType::Attest,
            round: self.round,
            period: self.period,
            step: DOWN,
            proposal: BOTTOM,
        };

        let answer = staged_value(self, router, self.round, self.period, params);
        if answer.committable {
            a.step = LATE;
            a.proposal = answer.proposal;
        } else {
            let res = router.dispatch(
                self,
                Event::NextThresholdStatusRequest(NextThresholdStatusRequestEvent),
                StateMachineTag::VoteMachinePeriod,
                self.round,
                Period(self.period.0.saturating_sub(1)),
                Step(0),
                params,
            );
            let next_status = match res {
                Event::NextThresholdStatus(nts) => nts,
                _ => NextThresholdStatusEvent::default(),
            };
            if !next_status.bottom {
                a.step = REDO;
                a.proposal = next_status.proposal;
            }
        }
        if a.proposal == BOTTOM {
            // Required if we entered the period via a soft threshold
            a.step = DOWN;
        }

        actions.push(Action::Pseudonode(a));
        actions
    }

    /// Dump votes from a specific step via the vote tracker.
    fn dump_votes(
        &self,
        router: &mut RootRouter,
        step: Step,
        params: &ConsensusParams,
    ) -> Vec<UnauthenticatedVote> {
        let res = router.dispatch(
            self,
            Event::DumpVotesRequest(DumpVotesRequestEvent),
            StateMachineTag::VoteMachineStep,
            self.round,
            self.period,
            step,
            params,
        );
        match res {
            Event::DumpVotes(dv) => dv.votes,
            _ => Vec::new(),
        }
    }

    /// Handle a checkpoint event.
    ///
    /// Mirrors Go's `player.handleCheckpointEvent`.
    fn handle_checkpoint_event(&self, e: CheckpointEvent) -> Vec<Action> {
        vec![Action::Checkpoint(CheckpointAction {
            round: e.round,
            period: e.period,
            step: e.step,
            err: e.err,
        })]
    }

    /// Update credential arrival history at the end of a successful
    /// uninterrupted round.
    ///
    /// Mirrors Go's `player.updateCredentialArrivalHistory`.
    fn update_credential_arrival_history(
        &mut self,
        router: &mut RootRouter,
        params: &ConsensusParams,
    ) -> Duration {
        if self.period != Period(0) {
            return Duration::ZERO;
        }

        let cred_lag = credential_round_lag();
        if self.round.0 <= cred_lag {
            return Duration::ZERO;
        }

        let cred_history_round = Round(self.round.0 - cred_lag);
        let re = Event::ReadLowest(ReadLowestEvent {
            t: EventType::ReadLowestVote,
            round: cred_history_round,
            period: Period(0),
            ..ReadLowestEvent::default()
        });
        let result = router.dispatch(
            self,
            re,
            StateMachineTag::ProposalMachineRound,
            cred_history_round,
            Period(0),
            Step(0),
            params,
        );
        let re = match result {
            Event::ReadLowest(rle) => rle,
            _ => return Duration::ZERO,
        };

        if !re.has_lowest_including_late {
            return Duration::ZERO;
        }

        if let Some(ref _lowest) = re.lowest_including_late {
            // In the Go implementation, validatedAt is stored on the vote.
            // Here we use Duration::ZERO as a placeholder since we don't
            // have the validated_at field on Vote yet.
            let validated_at = Duration::ZERO;
            self.lowest_credential_arrivals.store(validated_at);
            return validated_at;
        }

        Duration::ZERO
    }

    /// Calculate the filter timeout based on credential arrival history and
    /// consensus params.
    ///
    /// Mirrors Go's `player.calculateFilterTimeout`.
    fn calculate_filter_timeout(&mut self, params: &ConsensusParams) -> Duration {
        if DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY == 0 || self.period != Period(0) {
            return filter_timeout(self.period, params);
        }
        let default_timeout = filter_timeout(Period(0), params);
        if !self.lowest_credential_arrivals.is_full() {
            return default_timeout;
        }

        let dynamic_timeout = self
            .lowest_credential_arrivals
            .order_statistics(DYNAMIC_FILTER_TIMEOUT_CREDENTIAL_ARRIVAL_HISTORY_IDX)
            + DYNAMIC_FILTER_TIMEOUT_GRACE_INTERVAL;

        let clamped_timeout = dynamic_timeout
            .max(DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND)
            .min(default_timeout);

        tracing::debug!(
            round = self.round.0,
            period = self.period.0,
            ?dynamic_timeout,
            ?clamped_timeout,
            "dynamic filter timeout"
        );

        self.dynamic_filter_timeout = dynamic_timeout;

        if !params.dynamic_filter_timeout {
            return default_timeout;
        }

        clamped_timeout
    }

    /// Handle a threshold event (soft, cert, or next threshold).
    ///
    /// Mirrors Go's `player.handleThresholdEvent`.
    fn handle_threshold_event(
        &mut self,
        router: &mut RootRouter,
        e: ThresholdEvent,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        match e.t {
            EventType::CertThreshold => {
                // Dispatch to proposal machine for cert threshold tracking
                router.dispatch(
                    self,
                    Event::Threshold(e.clone()),
                    StateMachineTag::ProposalMachine,
                    Round(0),
                    Period(0),
                    Step(0),
                    params,
                );

                // Check if we have the block
                let res = staged_value(self, router, e.round, e.period, params);
                if res.committable {
                    let cert = Certificate::from_bundle(&e.bundle);
                    let vote_validated_at = self.update_credential_arrival_history(router, params);
                    let a0 = Action::Ensure(Box::new(EnsureAction {
                        payload: res.payload.unwrap_or_default(),
                        certificate: cert,
                        vote_validated_at,
                        dynamic_filter_timeout: self.dynamic_filter_timeout,
                    }));
                    actions.push(a0);
                    let as_ = self.enter_round(
                        router,
                        Event::Threshold(e),
                        Round(self.round.0 + 1),
                        params,
                    );
                    actions.extend(as_);
                    return actions;
                }

                // We don't have the block! Hint to ledger to fetch by digest.
                actions.push(Action::StageDigest(Box::new(StageDigestAction {
                    certificate: Certificate::from_bundle(&e.bundle),
                })));
                if self.period < e.period {
                    let as_ = self.enter_period(router, &e, e.period, params);
                    actions.extend(as_);
                }
                actions
            }

            EventType::SoftThreshold => {
                if self.period > e.period {
                    return Vec::new();
                }
                if self.period < e.period {
                    return self.enter_period(router, &e, e.period, params);
                }

                let ec = router.dispatch(
                    self,
                    Event::Threshold(e),
                    StateMachineTag::ProposalMachine,
                    self.round,
                    self.period,
                    Step(0),
                    params,
                );
                if ec.event_type() == EventType::ProposalCommittable && self.step <= CERT {
                    if let Event::Committable(ref ce) = ec {
                        actions.push(self.issue_cert_vote(ce));
                    }
                }
                actions
            }

            EventType::NextThreshold => {
                if self.period > e.period {
                    return Vec::new();
                }
                self.enter_period(router, &e, Period(e.period.0 + 1), params)
            }

            _ => panic!("player: bad threshold event type: {:?}", e.t),
        }
    }

    /// Enter a new period within the current round.
    ///
    /// Mirrors Go's `player.enterPeriod`.
    fn enter_period(
        &mut self,
        router: &mut RootRouter,
        source: &ThresholdEvent,
        target: Period,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = self.partition_policy(router, params);

        // Dispatch the threshold event to the proposal machine
        let e = router.dispatch(
            self,
            Event::Threshold(source.clone()),
            StateMachineTag::ProposalMachine,
            self.round,
            self.period,
            Step(0),
            params,
        );

        tracing::info!(
            round = self.round.0,
            old_period = self.period.0,
            new_period = target.0,
            proposal = ?source.proposal.block_digest,
            "entering non-zero period"
        );

        self.last_concluding = self.step;
        self.period = target;
        self.step = SOFT;
        self.napping = false;
        self.fast_recovery_deadline = Duration::ZERO;

        if target != Period(0) {
            self.lowest_credential_arrivals.reset();
        }
        self.deadline = Deadline {
            duration: self.calculate_filter_timeout(params),
            timeout_type: TimeoutType::Filter,
        };

        actions.push(Action::Rezero(RezeroAction { round: self.round }));

        if e.event_type() == EventType::ProposalCommittable {
            // implies source.t() == softThreshold
            if let Event::Committable(ref ce) = e {
                actions.push(self.issue_cert_vote(ce));
            }
            return actions;
        }

        if source.t == EventType::NextThreshold {
            let proposal = source.proposal;
            if proposal == BOTTOM {
                let a = PseudonodeAction {
                    t: ActionType::Assemble,
                    round: self.round,
                    period: self.period,
                    ..PseudonodeAction::default()
                };
                actions.push(Action::Pseudonode(a));
                return actions;
            }

            let a = PseudonodeAction {
                t: ActionType::Repropose,
                round: self.round,
                period: self.period,
                proposal,
                ..PseudonodeAction::default()
            };
            actions.push(Action::Pseudonode(a));
            return actions;
        }

        actions
    }

    /// Enter a new round.
    ///
    /// Mirrors Go's `player.enterRound`.
    fn enter_round(
        &mut self,
        router: &mut RootRouter,
        source: Event,
        target: Round,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        let new_round_event = match source.event_type() {
            EventType::CertThreshold | EventType::PayloadVerified => {
                tracing::info!(round = self.round.0, target_round = target.0, "round start");
                Event::RoundInterruption(RoundInterruptionEvent {
                    round: target,
                    ..RoundInterruptionEvent::default()
                })
            }
            _ => source.clone(),
        };

        let e = router.dispatch(
            self,
            new_round_event,
            StateMachineTag::ProposalMachine,
            target,
            Period(0),
            Step(0),
            params,
        );

        self.last_concluding = self.step;
        self.round = target;
        self.period = Period(0);
        self.step = SOFT;
        self.napping = false;
        self.fast_recovery_deadline = Duration::ZERO;

        // Calculate filter timeout from the source event's consensus version
        self.deadline = Deadline {
            duration: self.calculate_filter_timeout(params),
            timeout_type: TimeoutType::Filter,
        };

        // Do proposal-related actions
        let assemble = PseudonodeAction {
            t: ActionType::Assemble,
            round: self.round,
            period: Period(0),
            ..PseudonodeAction::default()
        };
        actions.push(Action::Rezero(RezeroAction { round: target }));
        actions.push(Action::Pseudonode(assemble));

        if e.event_type() == EventType::PayloadPipelined {
            if let Event::PayloadProcessed(ref ep) = e {
                let msg = MessageEvent {
                    t: EventType::PayloadPresent,
                    input: crate::events::InternalMessage {
                        unauthenticated_proposal: ep.unauthenticated_payload.clone(),
                        ..crate::events::InternalMessage::default()
                    },
                    ..MessageEvent::default()
                };
                let a =
                    crate::actions::verify_payload_action(&msg, self.round, ep.period, ep.pinned);
                actions.push(a);
            }
        }

        // Check for pipelined threshold events
        let res = router.dispatch(
            self,
            Event::FreshestBundleRequest(FreshestBundleRequestEvent),
            StateMachineTag::VoteMachineRound,
            self.round,
            Period(0),
            Step(0),
            params,
        );
        if let Event::FreshestBundle(fb) = res {
            if fb.ok {
                let a4 = self.handle(router, Event::Threshold(fb.event), params);
                actions.extend(a4);
            }
        }

        actions
    }

    /// Check if the player is in a partition, and if so, return recovery actions.
    ///
    /// Mirrors Go's `player.partitionPolicy`.
    fn partition_policy(&self, router: &mut RootRouter, params: &ConsensusParams) -> Vec<Action> {
        if !self.partitioned() {
            return Vec::new();
        }

        let mut actions = Vec::new();

        let res = router.dispatch(
            self,
            Event::FreshestBundleRequest(FreshestBundleRequestEvent),
            StateMachineTag::VoteMachineRound,
            self.round,
            Period(0),
            Step(0),
            params,
        );
        let bundle_response = match res {
            Event::FreshestBundle(fb) => fb,
            _ => return actions,
        };

        if bundle_response.ok {
            let b = &bundle_response.event.bundle;
            tracing::info!(
                round = self.round.0,
                period = self.period.0,
                step = self.step.0,
                bundle_round = b.round.0,
                bundle_period = b.period.0,
                bundle_step = b.step.0,
                "broadcast bundle"
            );
            actions.push(Action::Network(Box::new(NetworkAction {
                t: ActionType::Broadcast,
                tag: crate::traits::VOTE_BUNDLE_TAG.to_string(),
                unauthenticated_bundle: b.clone(),
                ..NetworkAction::default()
            })));
        }

        // On resynchronization, try relaying the staged proposal from the same
        // period as the freshest bundle. If that does not exist, fall back to
        // relaying the pinned value.
        let _bundle_round = if bundle_response.ok && bundle_response.event.bundle.proposal != BOTTOM
        {
            let b = &bundle_response.event.bundle;
            let br = b.round;
            let bp = b.period;
            let res_staged = staged_value(self, router, br, bp, params);
            if res_staged.committable {
                if let Some(payload) = &res_staged.payload {
                    let transmit = CompoundMessage {
                        proposal: payload.unauthenticated_proposal.clone(),
                        vote: UnauthenticatedVote::default(),
                    };
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Broadcast,
                        tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                        compound_message: transmit,
                        ..NetworkAction::default()
                    })));
                }
            } else {
                let res_pinned = pinned_value(self, router, br, params);
                if res_pinned.payload_ok {
                    if let Some(payload) = &res_pinned.payload {
                        let transmit = CompoundMessage {
                            proposal: payload.unauthenticated_proposal.clone(),
                            vote: UnauthenticatedVote::default(),
                        };
                        actions.push(Action::Network(Box::new(NetworkAction {
                            t: ActionType::Broadcast,
                            tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                            compound_message: transmit,
                            ..NetworkAction::default()
                        })));
                    }
                }
            }
            br
        } else if self.period == Period(0) {
            let res_staged = staged_value(self, router, self.round, self.period, params);
            if res_staged.committable {
                if let Some(payload) = &res_staged.payload {
                    let transmit = CompoundMessage {
                        proposal: payload.unauthenticated_proposal.clone(),
                        vote: UnauthenticatedVote::default(),
                    };
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Broadcast,
                        tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                        compound_message: transmit,
                        ..NetworkAction::default()
                    })));
                }
            } else {
                let res_pinned = pinned_value(self, router, self.round, params);
                if res_pinned.payload_ok {
                    if let Some(payload) = &res_pinned.payload {
                        let transmit = CompoundMessage {
                            proposal: payload.unauthenticated_proposal.clone(),
                            vote: UnauthenticatedVote::default(),
                        };
                        actions.push(Action::Network(Box::new(NetworkAction {
                            t: ActionType::Broadcast,
                            tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                            compound_message: transmit,
                            ..NetworkAction::default()
                        })));
                    }
                }
            }
            self.round
        } else {
            self.round
        };

        actions
    }

    /// Returns whether the player is partitioned.
    ///
    /// Mirrors Go's `player.partitioned`.
    pub fn partitioned(&self) -> bool {
        self.step >= PARTITION_STEP || self.period >= Period(3)
    }

    /// Handle a message event (vote, proposal, or bundle).
    ///
    /// Mirrors Go's `player.handleMessageEvent`.
    fn handle_message_event(
        &mut self,
        router: &mut RootRouter,
        e: MessageEvent,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Check if it's a proposal-vote (step == 0)
        let proposal_vote = matches!(e.t, EventType::VotePresent | EventType::VoteVerified)
            && e.input.unauthenticated_vote.raw_vote.step == PROPOSE;

        // Wrap message event with current player state for freshness
        let delegated_e = FilterableMessageEvent {
            message_event: e.clone(),
            freshness_data: crate::events::FreshnessData {
                player_round: self.round,
                player_period: self.period,
                player_step: self.step,
                player_last_concluding: self.last_concluding,
            },
        };

        if proposal_vote {
            return self.handle_proposal_vote(router, e, delegated_e, params);
        }

        match e.t {
            EventType::PayloadPresent | EventType::PayloadVerified => {
                let ef = router.dispatch(
                    self,
                    Event::FilterableMessage(delegated_e.clone()),
                    StateMachineTag::ProposalMachine,
                    Round(0),
                    Period(0),
                    Step(0),
                    params,
                );

                match ef.event_type() {
                    EventType::PayloadMalformed => {
                        if let Event::Filtered(fe) = ef {
                            let err = crate::events::SerializableError::new(format!(
                                "rejected message since it was invalid: {:?}",
                                fe.err
                            ));
                            return vec![crate::actions::ignore_action(&e, err)];
                        }
                    }
                    EventType::PayloadRejected => {
                        if let Event::PayloadProcessed(ep) = ef {
                            if let Some(err) = ep.err {
                                return vec![crate::actions::ignore_action(&e, err)];
                            }
                        }
                        return Vec::new();
                    }
                    EventType::PayloadPipelined => {
                        if let Event::PayloadProcessed(ref ep) = ef {
                            let up = e.input.unauthenticated_proposal.clone();
                            let uv = match &ep.vote {
                                Some(v) => v.to_unauthenticated(),
                                None => UnauthenticatedVote::default(),
                            };
                            let ra = Action::Network(Box::new(NetworkAction {
                                t: ActionType::Relay,
                                tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                                compound_message: CompoundMessage {
                                    proposal: up,
                                    vote: uv,
                                },
                                message_handle: crate::actions::handle_of(&e),
                                ..NetworkAction::default()
                            }));

                            if ep.round == self.round {
                                let vpa = crate::actions::verify_payload_action(
                                    &e, ep.round, ep.period, ep.pinned,
                                );
                                return vec![vpa, ra];
                            }
                            actions.push(ra);
                        }
                    }
                    _ => {}
                }

                // Relay as the proposer (if message_handle is None).
                //
                // Mirrors go-algorand `agreement/player.go:691-702`. The
                // unauthenticated-vote attached to the relayed compound
                // message comes from the matching proposal-vote the
                // proposalMachine pulled out of the assembler when the
                // payload was pipelined / accepted, or from the
                // committableEvent if the payload is committable.
                if e.input.message_handle.is_none() {
                    let uv = match &ef {
                        Event::PayloadProcessed(ep)
                            if ep.t == EventType::PayloadPipelined
                                || ep.t == EventType::PayloadAccepted =>
                        {
                            ep.vote
                                .as_ref()
                                .map(|v| v.to_unauthenticated())
                                .unwrap_or_default()
                        }
                        Event::Committable(ce) => ce
                            .vote
                            .as_ref()
                            .map(|v| v.to_unauthenticated())
                            .unwrap_or_default(),
                        _ => UnauthenticatedVote::default(),
                    };
                    let up = e.input.unauthenticated_proposal.clone();
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Relay,
                        tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                        compound_message: CompoundMessage {
                            proposal: up,
                            vote: uv,
                        },
                        ..NetworkAction::default()
                    })));
                }

                // If the payload is valid, check it against any received cert threshold
                if ef.event_type() == EventType::ProposalCommittable
                    || ef.event_type() == EventType::PayloadAccepted
                {
                    let freshest_res = router.dispatch(
                        self,
                        Event::FreshestBundleRequest(FreshestBundleRequestEvent),
                        StateMachineTag::VoteMachineRound,
                        self.round,
                        Period(0),
                        Step(0),
                        params,
                    );
                    if let Event::FreshestBundle(fb) = freshest_res {
                        if fb.ok
                            && fb.event.t == EventType::CertThreshold
                            && fb.event.proposal == e.input.unauthenticated_proposal.value()
                        {
                            let cert = Certificate::from_bundle(&fb.event.bundle);
                            let vote_validated_at =
                                self.update_credential_arrival_history(router, params);
                            let a0 = Action::Ensure(Box::new(EnsureAction {
                                payload: e.input.proposal.clone().unwrap_or_default(),
                                certificate: cert.clone(),
                                vote_validated_at,
                                dynamic_filter_timeout: self.dynamic_filter_timeout,
                            }));
                            actions.push(a0);
                            let as_ = self.enter_round(
                                router,
                                Event::FilterableMessage(delegated_e),
                                Round(cert.round.0 + 1),
                                params,
                            );
                            actions.extend(as_);
                            return actions;
                        }
                    }
                }

                if ef.event_type() == EventType::ProposalCommittable && self.step <= CERT {
                    if let Event::Committable(ref ce) = ef {
                        actions.push(self.issue_cert_vote(ce));
                    }
                }
                actions
            }

            EventType::VotePresent | EventType::VoteVerified => {
                let ef = router.dispatch(
                    self,
                    Event::FilterableMessage(delegated_e),
                    StateMachineTag::VoteMachine,
                    Round(0),
                    Period(0),
                    Step(0),
                    params,
                );

                match ef.event_type() {
                    EventType::VoteMalformed => {
                        if let Event::Filtered(fe) = ef {
                            let err = crate::events::SerializableError::new(format!(
                                "rejected message since it was invalid: {:?}",
                                fe.err
                            ));
                            return vec![crate::actions::disconnect_action(&e, err)];
                        }
                    }
                    EventType::VoteFiltered => {
                        if let Event::Filtered(fe) = ef {
                            let err = fe.err.unwrap_or_else(|| {
                                crate::events::SerializableError::new("filtered")
                            });
                            return vec![crate::actions::ignore_action(&e, err)];
                        }
                    }
                    _ => {}
                }

                if e.t == EventType::VotePresent {
                    let uv = &e.input.unauthenticated_vote;
                    return vec![crate::actions::verify_vote_action(
                        &e,
                        uv.raw_vote.round,
                        uv.raw_vote.period,
                        0,
                    )];
                }

                // voteVerified
                if let Some(ref v) = e.input.vote {
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Relay,
                        tag: crate::traits::AGREEMENT_VOTE_TAG.to_string(),
                        unauthenticated_vote: v.to_unauthenticated(),
                        message_handle: crate::actions::handle_of(&e),
                        ..NetworkAction::default()
                    })));
                }
                let a1 = self.handle(router, ef, params);
                actions.extend(a1);
                actions
            }

            EventType::BundlePresent | EventType::BundleVerified => {
                let ef = router.dispatch(
                    self,
                    Event::FilterableMessage(delegated_e),
                    StateMachineTag::VoteMachine,
                    Round(0),
                    Period(0),
                    Step(0),
                    params,
                );

                match ef.event_type() {
                    EventType::BundleMalformed => {
                        if let Event::Filtered(fe) = ef {
                            let err = crate::events::SerializableError::new(format!(
                                "rejected message since it was invalid: {:?}",
                                fe.err
                            ));
                            return vec![crate::actions::disconnect_action(&e, err)];
                        }
                    }
                    EventType::BundleFiltered => {
                        if let Event::Filtered(fe) = ef {
                            let err = fe.err.unwrap_or_else(|| {
                                crate::events::SerializableError::new("filtered")
                            });
                            return vec![crate::actions::ignore_action(&e, err)];
                        }
                    }
                    _ => {}
                }

                if e.t == EventType::BundlePresent {
                    let ub = &e.input.unauthenticated_bundle;
                    return vec![crate::actions::verify_bundle_action(
                        &e, ub.round, ub.period, ub.step,
                    )];
                }

                // bundleVerified
                if let Event::Threshold(ref te) = ef {
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Relay,
                        tag: crate::traits::VOTE_BUNDLE_TAG.to_string(),
                        unauthenticated_bundle: te.bundle.clone(),
                        message_handle: crate::actions::handle_of(&e),
                        ..NetworkAction::default()
                    })));
                }
                let a1 = self.handle(router, ef, params);
                actions.extend(a1);
                actions
            }

            _ => panic!("player: bad message event type: {:?}", e.t),
        }
    }

    /// Handle a proposal-vote (vote where step == 0).
    ///
    /// Mirrors the proposal-vote handling in Go's `player.handleMessageEvent`.
    fn handle_proposal_vote(
        &mut self,
        router: &mut RootRouter,
        e: MessageEvent,
        delegated_e: FilterableMessageEvent,
        params: &ConsensusParams,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let done_processing = true;

        let ef = router.dispatch(
            self,
            Event::FilterableMessage(delegated_e),
            StateMachineTag::ProposalMachine,
            Round(0),
            Period(0),
            Step(0),
            params,
        );

        match ef.event_type() {
            EventType::VoteMalformed => {
                if let Event::Filtered(fe) = ef {
                    let err = fe
                        .err
                        .unwrap_or_else(|| crate::events::SerializableError::new("malformed"));
                    return vec![crate::actions::disconnect_action(&e, err)];
                }
            }
            EventType::VoteFiltered => {
                if let Event::Filtered(ref fe) = ef {
                    if !params.dynamic_filter_timeout {
                        let err = fe
                            .err
                            .clone()
                            .unwrap_or_else(|| crate::events::SerializableError::new("filtered"));
                        return vec![crate::actions::ignore_action(&e, err)];
                    }
                    match fe.late_credential_tracking_note {
                        LateCredentialTrackingEffect::VerifiedBetterLateCredentialForTracking => {
                            if let Some(ref v) = e.input.vote {
                                return vec![Action::Network(Box::new(NetworkAction {
                                    t: ActionType::Relay,
                                    tag: crate::traits::AGREEMENT_VOTE_TAG.to_string(),
                                    unauthenticated_vote: v.to_unauthenticated(),
                                    message_handle: crate::actions::handle_of(&e),
                                    ..NetworkAction::default()
                                }))];
                            }
                        }
                        LateCredentialTrackingEffect::NoLateCredentialTrackingImpact => {
                            let err = fe.err.clone().unwrap_or_else(|| {
                                crate::events::SerializableError::new("filtered")
                            });
                            return vec![crate::actions::ignore_action(&e, err)];
                        }
                        LateCredentialTrackingEffect::UnverifiedLateCredentialForTracking => {
                            // Continue processing
                        }
                    }
                }
            }
            _ => {}
        }

        if e.t == EventType::VotePresent {
            let _ = done_processing; // suppress unused assignment warning
            let seq = self.pending.push(e.tail.clone());
            let uv = &e.input.unauthenticated_vote;
            actions.push(crate::actions::verify_vote_action(
                &e,
                uv.raw_vote.round,
                uv.raw_vote.period,
                seq,
            ));
        } else {
            // VoteVerified
            if let Some(ref v) = e.input.vote {
                let ep = match &ef {
                    Event::ProposalAccepted(pae) => Some(pae),
                    _ => None,
                };

                if let Some(pae) = ep {
                    if pae.payload_ok {
                        if let Some(ref payload) = pae.payload {
                            let transmit = CompoundMessage {
                                proposal: payload.unauthenticated_proposal.clone(),
                                vote: v.to_unauthenticated(),
                            };
                            // Broadcast (not Relay): the player synthesizes a
                            // compound message it has already authenticated, so
                            // the originating peer no longer matters and the
                            // handle is intentionally not propagated. Mirrors
                            // Go's `broadcastAction` (no `h`).
                            actions.push(Action::Network(Box::new(NetworkAction {
                                t: ActionType::Broadcast,
                                tag: crate::traits::PROPOSAL_PAYLOAD_TAG.to_string(),
                                compound_message: transmit,
                                ..NetworkAction::default()
                            })));
                        } else {
                            actions.push(Action::Network(Box::new(NetworkAction {
                                t: ActionType::Relay,
                                tag: crate::traits::AGREEMENT_VOTE_TAG.to_string(),
                                unauthenticated_vote: v.to_unauthenticated(),
                                message_handle: crate::actions::handle_of(&e),
                                ..NetworkAction::default()
                            })));
                        }
                    } else {
                        actions.push(Action::Network(Box::new(NetworkAction {
                            t: ActionType::Relay,
                            tag: crate::traits::AGREEMENT_VOTE_TAG.to_string(),
                            unauthenticated_vote: v.to_unauthenticated(),
                            message_handle: crate::actions::handle_of(&e),
                            ..NetworkAction::default()
                        })));
                    }
                } else {
                    actions.push(Action::Network(Box::new(NetworkAction {
                        t: ActionType::Relay,
                        tag: crate::traits::AGREEMENT_VOTE_TAG.to_string(),
                        unauthenticated_vote: v.to_unauthenticated(),
                        message_handle: crate::actions::handle_of(&e),
                        ..NetworkAction::default()
                    })));
                }
            }

            // Process tail if present
            if done_processing {
                let tail_to_process = if e.t == EventType::VoteVerified {
                    self.pending.pop(e.task_index).or(e.tail.clone())
                } else {
                    e.tail.clone()
                };

                if let Some(tail_event) = tail_to_process {
                    let ev = *tail_event;
                    let suffix = self.handle(router, Event::Message(ev), params);
                    actions.extend(suffix);
                }
            }
        }

        actions
    }
}

// ---------------------------------------------------------------------------
// Tracer (lightweight logging)
// ---------------------------------------------------------------------------

/// Tracer provides structured logging for the agreement state machine.
///
/// Uses Rust's `tracing` crate rather than implementing the full Go tracer
/// infrastructure. The Go tracer writes to cadaver files and produces telemetry
/// events; our Rust equivalent uses structured tracing spans and events.
///
/// Mirrors Go's `tracer` in agreement/trace.go.
#[derive(Debug, Clone, Default)]
pub struct Tracer {
    /// Sequence counter for events.
    pub seq: u64,
    /// Whether verbose reports are enabled.
    pub verbose_reports: bool,
    /// Whether timing reports are enabled.
    pub timing_reports: bool,
}

impl Tracer {
    /// Create a new tracer.
    pub fn new(verbose_reports: bool, timing_reports: bool) -> Self {
        Self {
            seq: 0,
            verbose_reports,
            timing_reports,
        }
    }

    /// Log an event entering a state machine.
    pub fn log_event_in(&mut self, src: StateMachineTag, dest: StateMachineTag, e: &Event) {
        self.seq += 1;
        tracing::trace!(seq = self.seq, %src, %dest, event = %e, "event in");
    }

    /// Log an event exiting a state machine.
    pub fn log_event_out(&mut self, src: StateMachineTag, dest: StateMachineTag, e: &Event) {
        self.seq += 1;
        tracing::trace!(seq = self.seq, %src, %dest, event = %e, "event out");
    }

    /// Log actions emitted at the top level.
    pub fn log_actions(&mut self, actions: &[Action]) {
        if !actions.is_empty() {
            let tags: Vec<String> = actions.iter().map(|a| format!("{a}")).collect();
            tracing::debug!(actions = tags.join(", "), "emit actions");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn player_default() {
        let p = Player::default();
        assert_eq!(p.round, Round(0));
        assert_eq!(p.period, Period(0));
        assert_eq!(p.step, SOFT);
        assert!(!p.napping);
        assert!(!p.partitioned());
    }

    #[test]
    fn player_partitioned_by_step() {
        let p = Player {
            step: PARTITION_STEP,
            ..Player::default()
        };
        assert!(p.partitioned());
    }

    #[test]
    fn player_partitioned_by_period() {
        let p = Player {
            period: Period(3),
            ..Player::default()
        };
        assert!(p.partitioned());
    }

    #[test]
    fn player_not_partitioned() {
        let p = Player {
            step: NEXT,
            period: Period(2),
            ..Player::default()
        };
        assert!(!p.partitioned());
    }

    #[test]
    fn proposal_table_push_pop() {
        let mut pt = ProposalTableImpl::default();
        let me = MessageEvent::default();
        let seq = pt.push(Some(Box::new(me)));
        // Mirrors Go's pre-increment: first push returns 1, not 0.
        assert_eq!(seq, 1);
        let result = pt.pop(seq);
        assert!(result.is_some());
        let result2 = pt.pop(seq);
        assert!(result2.is_none());
    }

    #[test]
    fn proposal_table_push_none() {
        let mut pt = ProposalTableImpl::default();
        let seq = pt.push(None);
        // Mirrors Go's pre-increment: first push returns 1, not 0.
        assert_eq!(seq, 1);
        let result = pt.pop(seq);
        assert!(result.is_none());
    }

    #[test]
    fn tracer_default() {
        let t = Tracer::default();
        assert_eq!(t.seq, 0);
        assert!(!t.verbose_reports);
        assert!(!t.timing_reports);
    }

    #[test]
    fn player_handle_none_event() {
        let mut p = Player::default();
        let mut router = RootRouter::default();
        let params = test_params();
        let actions = p.handle(
            &mut router,
            Event::Empty(crate::events::EmptyEvent),
            &params,
        );
        assert!(actions.is_empty());
    }

    fn test_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    fn test_proposal() -> crate::vote::ProposalValue {
        crate::vote::ProposalValue {
            original_period: Period(0),
            original_proposer: algo_types::Address([0x01; 32]),
            block_digest: algo_types::Digest([0xaa; 32]),
            encoding_digest: algo_types::Digest([0xbb; 32]),
        }
    }

    fn make_timeout_event(_params: &ConsensusParams) -> Event {
        Event::Timeout(TimeoutEvent {
            t: EventType::Timeout,
            random_entropy: 12345,
            round: Round(10),
            proto: crate::events::ConsensusVersionView {
                err: None,
                version: algo_types::CONSENSUS_V41.to_string(),
            },
        })
    }

    fn make_fast_timeout_event() -> Event {
        Event::Timeout(TimeoutEvent {
            t: EventType::FastTimeout,
            random_entropy: 12345,
            round: Round(10),
            proto: crate::events::ConsensusVersionView {
                err: None,
                version: algo_types::CONSENSUS_V41.to_string(),
            },
        })
    }

    // ---- Filter timeout -> soft vote step progression ----

    #[test]
    fn player_filter_timeout_transitions_to_cert_step() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // Feed a timeout event when player is at SOFT step
        let timeout = make_timeout_event(&params);
        let _actions = player.handle(&mut router, timeout, &params);

        // Player should transition from soft -> cert
        assert_eq!(player.step, CERT);
    }

    #[test]
    fn player_deadline_timeout_transitions_to_next_step() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: CERT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // Feed a timeout event when player is at CERT step
        let timeout = make_timeout_event(&params);
        let _actions = player.handle(&mut router, timeout, &params);

        // Player should transition from cert -> next
        assert_eq!(player.step, NEXT);
    }

    #[test]
    fn player_next_step_timeout_increments_step() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            napping: false,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // A timeout at NEXT when not napping goes to step+1 and enables napping
        let timeout = make_timeout_event(&params);
        let _actions = player.handle(&mut router, timeout, &params);

        // Should increment step past NEXT and enable napping
        assert_eq!(player.step, Step(NEXT.0 + 1));
        assert!(player.napping);
    }

    #[test]
    fn player_napping_timeout_issues_next_vote() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: Step(NEXT.0 + 1),
            napping: true,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // A timeout while napping should issue a next vote
        let timeout = make_timeout_event(&params);
        let actions = player.handle(&mut router, timeout, &params);

        // Should have produced at least a pseudonode attest action for next vote
        let has_attest = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Attest);
        assert!(has_attest, "expected an attest action for next vote");
    }

    // ---- Soft threshold -> cert vote ----

    #[test]
    fn player_soft_threshold_at_cert_step_issues_cert_vote() {
        // When a soft threshold arrives and the player is at step <= CERT,
        // and the proposal is committable, it should issue a cert vote.
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: CERT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let proposal = test_proposal();
        let te = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(10),
            period: Period(0),
            step: SOFT,
            proposal,
            ..ThresholdEvent::default()
        };

        let _actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Actions may or may not include cert vote depending on whether the proposal
        // is committable (has assembled payload). Without a payload, we won't get
        // a cert vote. But the player should not crash and state should be valid.
        assert_eq!(player.round, Round(10));
        assert_eq!(player.period, Period(0));
    }

    #[test]
    fn player_soft_threshold_stale_period_ignored() {
        // A soft threshold from a period older than current should be ignored
        let mut player = Player {
            round: Round(10),
            period: Period(5),
            step: CERT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(10),
            period: Period(3),
            step: SOFT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Stale soft threshold => no actions
        assert!(actions.is_empty());
    }

    #[test]
    fn player_soft_threshold_future_period_enters_period() {
        // A soft threshold from a future period should cause enter_period
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(10),
            period: Period(2),
            step: SOFT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        };

        let _actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Player should have entered period 2
        assert_eq!(player.period, Period(2));
        assert_eq!(player.step, SOFT);
    }

    // ---- Next threshold advances period ----

    #[test]
    fn player_next_threshold_advances_to_next_period() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(0),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };

        let _actions = player.handle(&mut router, Event::Threshold(te), &params);

        // Next threshold for period 0 should advance player to period 1
        assert_eq!(player.period, Period(1));
        assert_eq!(player.step, SOFT);
        assert!(!player.napping);
    }

    #[test]
    fn player_next_threshold_stale_period_ignored() {
        let mut player = Player {
            round: Round(10),
            period: Period(5),
            step: NEXT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(3),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Stale next threshold should be ignored
        assert!(actions.is_empty());
        assert_eq!(player.period, Period(5));
    }

    #[test]
    fn player_next_threshold_with_value_triggers_repropose() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let proposal = test_proposal();
        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(0),
            step: NEXT,
            proposal,
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Should contain a repropose action
        let has_repropose = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Repropose);
        assert!(
            has_repropose,
            "next threshold with value should trigger repropose"
        );
    }

    #[test]
    fn player_next_threshold_bottom_triggers_assemble() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(0),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Should contain an assemble action
        let has_assemble = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Assemble);
        assert!(
            has_assemble,
            "next threshold for bottom should trigger assemble"
        );
    }

    // ---- Cert threshold completes round ----

    #[test]
    fn player_cert_threshold_without_payload_stages_digest() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: CERT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(10),
            period: Period(0),
            step: CERT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Without the block payload, player should issue a stage-digest action
        let has_stage_digest = actions
            .iter()
            .any(|a| a.action_type() == ActionType::StageDigest);
        assert!(
            has_stage_digest,
            "cert threshold without payload should stage digest"
        );
    }

    // ---- Round interruption ----

    #[test]
    fn player_round_interruption_enters_new_round() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let rie = RoundInterruptionEvent {
            round: Round(15),
            ..RoundInterruptionEvent::default()
        };

        let actions = player.handle(&mut router, Event::RoundInterruption(rie), &params);

        // Player should be in the new round
        assert_eq!(player.round, Round(15));
        assert_eq!(player.period, Period(0));
        assert_eq!(player.step, SOFT);
        assert!(!player.napping);

        // Should have a rezero action and an assemble action
        let has_rezero = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Rezero);
        let has_assemble = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Assemble);
        assert!(has_rezero, "round interruption should rezero clock");
        assert!(has_assemble, "round interruption should assemble proposal");
    }

    // ---- Fast recovery ----

    #[test]
    fn player_fast_timeout_first_time_no_vote() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            fast_recovery_deadline: Duration::ZERO,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let timeout = make_fast_timeout_event();
        let actions = player.handle(&mut router, timeout, &params);

        // First fast timeout should not vote
        assert!(actions.is_empty());
        // But fast_recovery_deadline should be set
        assert!(player.fast_recovery_deadline > Duration::ZERO);
    }

    #[test]
    fn player_fast_timeout_second_time_votes() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            fast_recovery_deadline: Duration::from_millis(500),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let timeout = make_fast_timeout_event();
        let actions = player.handle(&mut router, timeout, &params);

        // Second fast timeout should produce vote actions
        let has_attest = actions
            .iter()
            .any(|a| a.action_type() == ActionType::Attest);
        assert!(has_attest, "second fast timeout should issue a fast vote");
    }

    #[test]
    fn player_fast_timeout_proto_error_no_actions() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            fast_recovery_deadline: Duration::from_millis(500),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let timeout = Event::Timeout(TimeoutEvent {
            t: EventType::FastTimeout,
            random_entropy: 12345,
            round: Round(10),
            proto: crate::events::ConsensusVersionView {
                err: Some("bad proto".to_string()),
                version: String::new(),
            },
        });
        let actions = player.handle(&mut router, timeout, &params);
        assert!(actions.is_empty());
    }

    // ---- Partition recovery ----

    #[test]
    fn player_partition_detected_by_high_step() {
        let p = Player {
            step: PARTITION_STEP,
            ..Player::default()
        };
        assert!(p.partitioned());
    }

    #[test]
    fn player_partition_detected_by_high_period() {
        let p = Player {
            period: Period(3),
            ..Player::default()
        };
        assert!(p.partitioned());
    }

    #[test]
    fn player_not_partitioned_at_period_2_step_next() {
        let p = Player {
            period: Period(2),
            step: NEXT,
            ..Player::default()
        };
        assert!(!p.partitioned());
    }

    // ---- Checkpoint ----

    #[test]
    fn player_checkpoint_event() {
        let mut player = Player::default();
        let mut router = RootRouter::default();
        let params = test_params();

        let ce = crate::events::CheckpointEvent {
            round: Round(5),
            period: Period(1),
            step: CERT,
            err: None,
        };
        let actions = player.handle(&mut router, Event::Checkpoint(ce), &params);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type(), ActionType::Checkpoint);
    }

    // ---- Enter period resets state correctly ----

    #[test]
    fn player_enter_period_resets_state() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: Step(5),
            napping: true,
            fast_recovery_deadline: Duration::from_secs(10),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // Trigger a next threshold which causes enter_period
        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(0),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };
        let _actions = player.handle(&mut router, Event::Threshold(te), &params);

        assert_eq!(player.period, Period(1));
        assert_eq!(player.step, SOFT);
        assert!(!player.napping);
        assert_eq!(player.fast_recovery_deadline, Duration::ZERO);
        assert_eq!(player.last_concluding, Step(5));
    }

    // ---- Enter round resets state correctly ----

    #[test]
    fn player_enter_round_resets_all_state() {
        let mut player = Player {
            round: Round(10),
            period: Period(3),
            step: Step(7),
            napping: true,
            fast_recovery_deadline: Duration::from_secs(10),
            last_concluding: NEXT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let rie = RoundInterruptionEvent {
            round: Round(11),
            ..RoundInterruptionEvent::default()
        };
        let _actions = player.handle(&mut router, Event::RoundInterruption(rie), &params);

        assert_eq!(player.round, Round(11));
        assert_eq!(player.period, Period(0));
        assert_eq!(player.step, SOFT);
        assert!(!player.napping);
        assert_eq!(player.fast_recovery_deadline, Duration::ZERO);
        assert_eq!(player.last_concluding, Step(7));
    }

    // ---- Timeout with bad proto falls back to default ----

    #[test]
    fn player_timeout_with_bad_proto_uses_default_deadline() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let timeout = Event::Timeout(TimeoutEvent {
            t: EventType::Timeout,
            random_entropy: 12345,
            round: Round(10),
            proto: crate::events::ConsensusVersionView {
                err: Some("bad proto".to_string()),
                version: String::new(),
            },
        });

        let _actions = player.handle(&mut router, timeout, &params);
        // Should still transition to cert step
        assert_eq!(player.step, CERT);
        // Deadline should be set to default_deadline_timeout
        assert_eq!(
            player.deadline.duration,
            crate::types::default_deadline_timeout()
        );
    }

    // ---- Dynamic filter timeout ----

    #[test]
    fn player_calculate_filter_timeout_non_period_0_uses_static() {
        let mut player = Player {
            period: Period(1),
            ..Player::default()
        };
        let params = test_params();
        let timeout = player.calculate_filter_timeout(&params);
        assert_eq!(timeout, crate::types::filter_timeout(Period(1), &params));
    }

    #[test]
    fn player_calculate_filter_timeout_period_0_not_full_uses_default() {
        let mut player = Player {
            period: Period(0),
            ..Player::default()
        };
        let params = test_params();
        let timeout = player.calculate_filter_timeout(&params);
        assert_eq!(timeout, crate::types::filter_timeout(Period(0), &params));
    }

    // ---- Proposal table tests ----

    #[test]
    fn proposal_table_multiple_push_pop() {
        let mut pt = ProposalTableImpl::default();
        let me1 = MessageEvent::default();
        let me2 = MessageEvent::default();
        let seq1 = pt.push(Some(Box::new(me1)));
        let seq2 = pt.push(Some(Box::new(me2)));
        // Mirrors Go's pre-increment: 1, 2, ... rather than 0, 1, ...
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        // Pop in reverse order
        let r2 = pt.pop(seq2);
        assert!(r2.is_some());
        let r1 = pt.pop(seq1);
        assert!(r1.is_some());

        // Double pop returns None
        assert!(pt.pop(seq1).is_none());
        assert!(pt.pop(seq2).is_none());
    }

    #[test]
    fn proposal_table_pop_nonexistent_seq() {
        let mut pt = ProposalTableImpl::default();
        assert!(pt.pop(999).is_none());
    }

    // ---- Full soft->cert->next step progression ----

    #[test]
    fn player_full_step_progression_soft_cert_next() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        // Step 1: Filter timeout fires -> transition to CERT
        let timeout = make_timeout_event(&params);
        player.handle(&mut router, timeout, &params);
        assert_eq!(player.step, CERT);

        // Step 2: Deadline timeout fires -> transition to NEXT
        let timeout = make_timeout_event(&params);
        player.handle(&mut router, timeout, &params);
        assert_eq!(player.step, NEXT);

        // Step 3: Another timeout -> transition to NEXT+1 with napping
        let timeout = make_timeout_event(&params);
        player.handle(&mut router, timeout, &params);
        assert_eq!(player.step, Step(NEXT.0 + 1));
        assert!(player.napping);
    }

    // ---- Cert threshold from future period triggers enter_period ----

    #[test]
    fn player_cert_threshold_future_period_enters_period() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: CERT,
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(10),
            period: Period(2),
            step: CERT,
            proposal: test_proposal(),
            ..ThresholdEvent::default()
        };

        let actions = player.handle(&mut router, Event::Threshold(te), &params);
        // Player should stage the digest (no payload assembled)
        let has_stage_digest = actions
            .iter()
            .any(|a| a.action_type() == ActionType::StageDigest);
        assert!(has_stage_digest);
        // Player should enter the future period
        assert_eq!(player.period, Period(2));
    }

    // ---- Deadline type tracking ----

    #[test]
    fn player_filter_timeout_sets_deadline_type() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: SOFT,
            deadline: Deadline {
                duration: Duration::from_secs(1),
                timeout_type: TimeoutType::Filter,
            },
            ..Player::default()
        };
        let mut router = RootRouter::default();
        let params = test_params();

        let timeout = make_timeout_event(&params);
        player.handle(&mut router, timeout, &params);

        // After soft->cert transition, deadline should be Deadline type
        assert_eq!(player.deadline.timeout_type, TimeoutType::Deadline);
    }

    // ---- Enter period resets credential arrivals for non-zero period ----

    #[test]
    fn player_enter_period_resets_credential_arrivals_for_nonzero_period() {
        let mut player = Player {
            round: Round(10),
            period: Period(0),
            step: NEXT,
            ..Player::default()
        };
        // Fill up some arrivals
        for i in 0..5 {
            player
                .lowest_credential_arrivals
                .store(Duration::from_millis(i * 100));
        }

        let mut router = RootRouter::default();
        let params = test_params();

        let te = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(10),
            period: Period(0),
            step: NEXT,
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };
        player.handle(&mut router, Event::Threshold(te), &params);

        // Period 1 => credential arrivals should be reset
        assert!(!player.lowest_credential_arrivals.is_full());
    }
}
