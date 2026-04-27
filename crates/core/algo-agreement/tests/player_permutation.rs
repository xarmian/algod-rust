// Player permutation matrix — exhaustive `(player_state, message_event)`
// transitions for the agreement state machine.
//
// Mirrors go-algorand `agreement/player_permutation_test.go` (836 LOC):
// - 7 player permutations × 14 message-event permutations = 98 cases
// - Each case is exercised under stock V41 *and* V41+dynamic-filter-timeout
//   for a total of 196 effective transition assertions.
//
// ## What's being tested
//
// The Player state machine routes incoming events through the router
// hierarchy and emits a deterministic list of actions. This test enumerates
// the cross-product of:
//
// * Player states: same round, next round, prev round w/ pending payload,
//   same round w/ proposal-vote already processed, same round at soft
//   threshold, same round at cert threshold, same round w/ proposal
//   already assembled.
// * Inbound events: soft/propose vote (verified + present + error), payload
//   (present + verified + error + no-message-handle), bundle (verified +
//   present + error).
//
// The expected actions are encoded inline (mirroring Go's giant nested
// switch). When a transition produces unexpected actions, the panic message
// includes `(player, event, dynamic_filter)` so the failure is easy to
// localize against the Go reference.
//
// ## Helpers
//
// All white-box scaffolding lives under `algo_agreement::test_support`:
// `IoAutomataConcretePlayer`, `IoTrace`, `VoteMakerHelper`, `setup_p`,
// `make_random_proposal_payload`, `override_consensus_with_dynamic_filter`.
// See that module for the Go-mapping notes.

use algo_agreement::test_support::{
    make_random_proposal_payload, override_consensus_with_dynamic_filter, random_block_hash,
    setup_p, IoAutomataConcretePlayer, IoTrace, VoteMakerHelper,
};
use algo_agreement::{
    Action, ActionType, BlockAssembler, ConsensusVersionView, EventType, InternalMessage,
    MessageEvent, ProposalValue, SerializableError, AGREEMENT_VOTE_TAG, CERT, PROPOSAL_PAYLOAD_TAG,
    PROPOSE, SOFT, VOTE_BUNDLE_TAG,
};
use algo_types::{Address, ConsensusParams, Round};

// ===========================================================================
// Constants — all permutations operate at (round=209, period=0)
// ===========================================================================

const TEST_ROUND: Round = Round(209);
const TEST_PERIOD: algo_agreement::Period = algo_agreement::Period(0);

// ===========================================================================
// Player permutations (7 variants)
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlayerPermutation {
    /// Same round and period as the proposal.
    SameRound = 0,
    /// One round ahead of the proposal.
    NextRound = 1,
    /// One round behind, with a pending payload-present event.
    PrevRoundPendingPayloadPresent = 2,
    /// Same round, but a proposal-vote from sender 0 has already been
    /// observed (so the period's `ProposalTracker.Duplicate[addr]` is set).
    SameRoundProcessedProposalVote = 3,
    /// Same round, soft-threshold reached for the proposal.
    SameRoundReachedSoftThreshold = 4,
    /// Same round, cert-threshold reached.
    SameRoundReachedCertThreshold = 5,
    /// Same round, full proposal payload already assembled.
    SameRoundProcessedProposal = 6,
}

impl PlayerPermutation {
    fn from_index(i: usize) -> Self {
        match i {
            0 => Self::SameRound,
            1 => Self::NextRound,
            2 => Self::PrevRoundPendingPayloadPresent,
            3 => Self::SameRoundProcessedProposalVote,
            4 => Self::SameRoundReachedSoftThreshold,
            5 => Self::SameRoundReachedCertThreshold,
            6 => Self::SameRoundProcessedProposal,
            _ => panic!("player permutation {i} does not exist"),
        }
    }
}

/// Construct the player + machine + helper for permutation `n`. Mirrors Go's
/// `getPlayerPermutation(t, n)`. The returned `payload` is the proposal-value
/// the precondition seeds into the router; the test event-builder uses
/// `payload.value()` to derive the same `pV` deterministically.
fn get_player_permutation(
    n: PlayerPermutation,
    params: &ConsensusParams,
) -> (
    IoAutomataConcretePlayer,
    VoteMakerHelper,
    algo_agreement::Proposal,
) {
    let r = TEST_ROUND;
    let p = TEST_PERIOD;
    let payload = make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    match n {
        PlayerPermutation::SameRound => {
            let (_, machine, helper) = setup_p(r, p, SOFT, params);
            (machine, helper, payload)
        }
        PlayerPermutation::NextRound => {
            let (_, machine, helper) = setup_p(Round(r.0 + 1), p, SOFT, params);
            (machine, helper, payload)
        }
        PlayerPermutation::PrevRoundPendingPayloadPresent => {
            let (_, mut machine, helper) = setup_p(Round(r.0 - 1), p, SOFT, params);
            // Push a payload-present event into the player's pending table
            // so the precondition matches Go's `plyr.Pending.push(...)`.
            // The Go test seeds `messageHandle: "uniquemessage"` (non-nil)
            // so the player's "relay as proposer" branch — which only fires
            // for messages without a handle — stays out of the way.
            let me = MessageEvent {
                t: EventType::PayloadPresent,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
                    ..InternalMessage::default()
                },
                ..MessageEvent::default()
            };
            machine.player_mut().pending.push(Some(Box::new(me)));
            (machine, helper, payload)
        }
        PlayerPermutation::SameRoundProcessedProposalVote => {
            let (_, mut machine, mut helper) = setup_p(r, p, SOFT, params);
            machine.ensure_round_period(r, p);
            machine.set_proposal_assembler(r, pv, BlockAssembler::default());
            // Override sender 0 with a fresh address, then mark it as duplicate.
            let dup_addr = Address(random_block_hash().0);
            helper.addresses.insert(0, dup_addr);
            machine.set_proposal_duplicate(r, p, dup_addr);
            (machine, helper, payload)
        }
        PlayerPermutation::SameRoundReachedSoftThreshold => {
            let (_, mut machine, mut helper) = setup_p(r, p, SOFT, params);
            machine.ensure_round_period(r, p);
            machine.set_proposal_assembler(r, pv, BlockAssembler::default());
            let dup_addr = Address(random_block_hash().0);
            helper.addresses.insert(0, dup_addr);
            machine.set_proposal_duplicate(r, p, dup_addr);
            machine.set_proposal_staging(r, p, pv);
            (machine, helper, payload)
        }
        PlayerPermutation::SameRoundReachedCertThreshold => {
            let (_, mut machine, mut helper) = setup_p(r, p, SOFT, params);
            machine.ensure_round_period(r, p);
            machine.set_proposal_assembler(r, pv, BlockAssembler::default());
            machine.set_cert_threshold(r, p, pv);
            let dup_addr = Address(random_block_hash().0);
            helper.addresses.insert(0, dup_addr);
            machine.set_proposal_duplicate(r, p, dup_addr);
            machine.set_proposal_staging(r, p, pv);
            (machine, helper, payload)
        }
        PlayerPermutation::SameRoundProcessedProposal => {
            let (_, mut machine, mut helper) = setup_p(r, p, SOFT, params);
            machine.ensure_round_period(r, p);
            // The proposal is already fully assembled.
            let assembled = BlockAssembler {
                pipeline: payload.unauthenticated_proposal.clone(),
                filled: true,
                payload: Some(payload.clone()),
                assembled: true,
                authenticators: Vec::new(),
            };
            machine.set_proposal_assembler(r, pv, assembled);
            let dup_addr = Address(random_block_hash().0);
            helper.addresses.insert(0, dup_addr);
            machine.set_proposal_duplicate(r, p, dup_addr);
            (machine, helper, payload)
        }
    }
}

// ===========================================================================
// Message event permutations (14 variants)
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageEventPermutation {
    SoftVoteVerifiedSamePeriod = 0,
    SoftVotePresentSamePeriod = 1,
    ProposeVoteVerifiedNextPeriod = 2,
    ProposeVoteVerifiedSamePeriod = 3,
    ProposeVotePresentSamePeriod = 4,
    PayloadPresent = 5,
    PayloadVerified = 6,
    PayloadVerifiedNoMessageHandle = 7,
    BundleVerifiedSamePeriod = 8,
    BundlePresentSamePeriod = 9,
    SoftVoteVerifiedErrorSamePeriod = 10,
    ProposeVoteVerifiedErrorSamePeriod = 11,
    BundleVerifiedError = 12,
    PayloadVerifiedError = 13,
}

impl MessageEventPermutation {
    fn from_index(j: usize) -> Self {
        match j {
            0 => Self::SoftVoteVerifiedSamePeriod,
            1 => Self::SoftVotePresentSamePeriod,
            2 => Self::ProposeVoteVerifiedNextPeriod,
            3 => Self::ProposeVoteVerifiedSamePeriod,
            4 => Self::ProposeVotePresentSamePeriod,
            5 => Self::PayloadPresent,
            6 => Self::PayloadVerified,
            7 => Self::PayloadVerifiedNoMessageHandle,
            8 => Self::BundleVerifiedSamePeriod,
            9 => Self::BundlePresentSamePeriod,
            10 => Self::SoftVoteVerifiedErrorSamePeriod,
            11 => Self::ProposeVoteVerifiedErrorSamePeriod,
            12 => Self::BundleVerifiedError,
            13 => Self::PayloadVerifiedError,
            _ => panic!("message event permutation {j} does not exist"),
        }
    }
}

fn unique_handle() -> algo_agreement::MessageHandle {
    // Mirror Go's `messageHandle: "uniquemessage"` — any non-None handle
    // signals "this came from a real peer", which the player checks when
    // deciding whether to relay-back the payload along with the vote
    // (PrevRoundPendingPayloadPresent test). The concrete value doesn't
    // matter as long as it round-trips through `Option<Arc<dyn Any>>`.
    Some(std::sync::Arc::new(()))
}

fn err_test_verify_failed() -> SerializableError {
    SerializableError::new("test error")
}

/// Build the message event for permutation `n`. Mirrors Go's
/// `getMessageEventPermutation(t, n, helper)`. The caller is responsible
/// for stamping `event.proto = view` after this returns (Go does it
/// inline in `playerPermutationCheck`).
fn get_message_event_permutation(
    n: MessageEventPermutation,
    helper: &mut VoteMakerHelper,
    params: &ConsensusParams,
) -> MessageEvent {
    let r = TEST_ROUND;
    let p = TEST_PERIOD;
    let next_p = algo_agreement::Period(p.0 + 1);
    let payload = make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();
    let proto_view = ConsensusVersionView {
        err: None,
        version: algo_types::CONSENSUS_V41.to_string(),
    };

    match n {
        MessageEventPermutation::SoftVoteVerifiedSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, SOFT, pv);
            MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    vote: Some(v.clone()),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::SoftVotePresentSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, SOFT, pv);
            MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::ProposeVoteVerifiedNextPeriod => {
            let v = helper.make_verified_vote(0, r, next_p, PROPOSE, pv);
            MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    vote: Some(v.clone()),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::ProposeVoteVerifiedSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, PROPOSE, pv);
            MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    vote: Some(v.clone()),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                task_index: 1,
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::ProposeVotePresentSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, PROPOSE, pv);
            MessageEvent {
                t: EventType::VotePresent,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::PayloadPresent => MessageEvent {
            t: EventType::PayloadPresent,
            input: InternalMessage {
                message_handle: unique_handle(),
                unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
                ..InternalMessage::default()
            },
            ..MessageEvent::default()
        },
        MessageEventPermutation::PayloadVerified => MessageEvent {
            t: EventType::PayloadVerified,
            input: InternalMessage {
                message_handle: unique_handle(),
                unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
                proposal: Some(payload.clone()),
                ..InternalMessage::default()
            },
            ..MessageEvent::default()
        },
        MessageEventPermutation::PayloadVerifiedNoMessageHandle => MessageEvent {
            t: EventType::PayloadVerified,
            input: InternalMessage {
                message_handle: None,
                unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
                proposal: Some(payload.clone()),
                ..InternalMessage::default()
            },
            ..MessageEvent::default()
        },
        MessageEventPermutation::BundleVerifiedSamePeriod => {
            let bundle = helper.make_verified_bundle(r, p, CERT, pv, params);
            MessageEvent {
                t: EventType::BundleVerified,
                input: InternalMessage {
                    verified_bundle_votes: bundle.votes.clone(),
                    unauthenticated_bundle: bundle.u.clone(),
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::BundlePresentSamePeriod => {
            let unauth = helper.make_unauthenticated_bundle_with_votes(r, p, CERT, pv, params);
            MessageEvent {
                t: EventType::BundlePresent,
                input: InternalMessage {
                    unauthenticated_bundle: unauth,
                    ..InternalMessage::default()
                },
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::SoftVoteVerifiedErrorSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, SOFT, pv);
            MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    vote: Some(v.clone()),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                err: Some(err_test_verify_failed()),
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::ProposeVoteVerifiedErrorSamePeriod => {
            let v = helper.make_verified_vote(0, r, p, PROPOSE, pv);
            MessageEvent {
                t: EventType::VoteVerified,
                input: InternalMessage {
                    message_handle: unique_handle(),
                    vote: Some(v.clone()),
                    unauthenticated_vote: v.to_unauthenticated(),
                    ..InternalMessage::default()
                },
                err: Some(err_test_verify_failed()),
                proto: proto_view,
                ..MessageEvent::default()
            }
        }
        MessageEventPermutation::BundleVerifiedError => MessageEvent {
            t: EventType::BundleVerified,
            input: InternalMessage {
                message_handle: unique_handle(),
                ..InternalMessage::default()
            },
            err: Some(err_test_verify_failed()),
            ..MessageEvent::default()
        },
        MessageEventPermutation::PayloadVerifiedError => MessageEvent {
            t: EventType::PayloadVerified,
            input: InternalMessage {
                unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
                proposal: Some(payload),
                ..InternalMessage::default()
            },
            err: Some(err_test_verify_failed()),
            ..MessageEvent::default()
        },
    }
}

// ===========================================================================
// Action matchers — predicate-based to mirror Go's ComparableStr semantics
// ===========================================================================
//
// Go's `requireTraceContains(t, trace, ev(action), ...)` compares actions
// via `ComparableStr()`, which is a small projection (e.g. `"relay: AV:
// 209-0-1"` for an AgreementVoteTag relay). We use predicate functions
// keyed off the same projection to avoid pulling unrelated fields like
// `messageHandle` into the equality check.

fn is_ignore_with_err(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Ignore && na.err.is_some())
}

fn is_relay_no_err(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Relay && na.err.is_none())
}

fn is_disconnect_with_err(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Disconnect && na.err.is_some())
}

fn is_verify_vote(a: &Action) -> bool {
    matches!(a, Action::Crypto(ca) if ca.t == ActionType::VerifyVote)
}

/// Match a relay of an `AgreementVoteTag` carrying a vote with the given
/// (round, period, step). Mirrors Go's networkAction ComparableStr for AV.
fn is_relay_av(
    a: &Action,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
) -> bool {
    if let Action::Network(na) = a {
        if na.t != ActionType::Relay {
            return false;
        }
        if na.tag != AGREEMENT_VOTE_TAG {
            return false;
        }
        let rv = &na.unauthenticated_vote.raw_vote;
        rv.round == round && rv.period == period && rv.step == step
    } else {
        false
    }
}

/// Match a relay of a `VoteBundleTag`.
fn is_relay_vb(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Relay && na.tag == VOTE_BUNDLE_TAG)
}

/// Match a relay of a `ProposalPayloadTag`.
fn is_relay_pp(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Relay && na.tag == PROPOSAL_PAYLOAD_TAG)
}

/// Match a broadcast of a `ProposalPayloadTag`.
fn is_broadcast_pp(a: &Action) -> bool {
    matches!(a, Action::Network(na) if na.t == ActionType::Broadcast && na.tag == PROPOSAL_PAYLOAD_TAG)
}

/// Match a `verifyVoteAction` with matching round/period/task_index.
fn is_verify_vote_at(
    a: &Action,
    round: Round,
    period: algo_agreement::Period,
    task_index: u64,
) -> bool {
    matches!(a, Action::Crypto(ca)
        if ca.t == ActionType::VerifyVote
            && ca.round == round
            && ca.period == period
            && ca.task_index == task_index)
}

/// Match a `verifyPayloadAction` with matching round/period/pinned.
fn is_verify_payload_at(
    a: &Action,
    round: Round,
    period: algo_agreement::Period,
    pinned: bool,
) -> bool {
    matches!(a, Action::Crypto(ca)
        if ca.t == ActionType::VerifyPayload
            && ca.round == round
            && ca.period == period
            && ca.pinned == pinned)
}

/// Match a `verifyBundleAction` with matching coordinates.
fn is_verify_bundle_at(
    a: &Action,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
) -> bool {
    matches!(a, Action::Crypto(ca)
        if ca.t == ActionType::VerifyBundle
            && ca.round == round
            && ca.period == period
            && ca.step == step)
}

/// Match a `stageDigestAction` for the given (round, period) and proposal
/// block-digest. Mirrors Go `stageDigestAction.ComparableStr` projection.
fn is_stage_digest(
    a: &Action,
    cert_round: Round,
    cert_period: algo_agreement::Period,
    cert_proposal: &ProposalValue,
) -> bool {
    matches!(a, Action::StageDigest(sa)
        if sa.certificate.round == cert_round
            && sa.certificate.period == cert_period
            && sa.certificate.proposal.block_digest == cert_proposal.block_digest)
}

/// Match an `ensureAction` for the given certificate (round + period +
/// block-digest projection).
fn is_ensure(
    a: &Action,
    cert_round: Round,
    cert_period: algo_agreement::Period,
    cert_proposal: &ProposalValue,
) -> bool {
    matches!(a, Action::Ensure(ea)
        if ea.certificate.round == cert_round
            && ea.certificate.period == cert_period
            && ea.certificate.proposal.block_digest == cert_proposal.block_digest)
}

/// Match a `rezeroAction` for round R.
fn is_rezero(a: &Action, round: Round) -> bool {
    matches!(a, Action::Rezero(ra) if ra.round == round)
}

/// Match a pseudonode action with type `t` at `(round, period, step)`.
fn is_pseudonode(
    a: &Action,
    t: ActionType,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
) -> bool {
    matches!(a, Action::Pseudonode(pa)
        if pa.t == t && pa.round == round && pa.period == period && pa.step == step)
}

// ===========================================================================
// Per-case expected-action assertions
// ===========================================================================

/// Assert the player's emitted-action trace matches the expected outcome
/// for `(player_n, event_n)` under the dynamic-filter setting.
///
/// Mirrors Go's `verifyPermutationExpectedActions`. The structure is one
/// match-per-player-permutation, with an inner match per event-permutation.
/// Failures panic with `(playerN, eventN, dynamic_filter_enabled)` in the
/// message so callers can localize against the Go reference.
fn verify_permutation_expected_actions(
    player_n: PlayerPermutation,
    event_n: MessageEventPermutation,
    helper: &mut VoteMakerHelper,
    trace: &IoTrace,
    dynamic_filter_enabled: bool,
) {
    let r = TEST_ROUND;
    let p = TEST_PERIOD;
    let next_p = algo_agreement::Period(p.0 + 1);
    let payload = make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    // Reusable "player should disconnect malformed vote/bundle" branch.
    let assert_disconnect_on_error = |trace: &IoTrace| {
        require_action_count(trace, 1, player_n, event_n);
        require_contains(
            trace,
            is_disconnect_with_err,
            "Player should disconnect malformed vote/bundle",
            player_n,
            event_n,
        );
    };
    // Reusable "player should ignore malformed proposal" branch.
    let assert_ignore_on_payload_error = |trace: &IoTrace| {
        require_action_count(trace, 1, player_n, event_n);
        require_contains(
            trace,
            is_ignore_with_err,
            "Player should ignore malformed proposal",
            player_n,
            event_n,
        );
    };

    use MessageEventPermutation as E;
    use PlayerPermutation as P;

    match player_n {
        P::SameRound => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                let v = helper.make_verified_vote(0, r, p, SOFT, pv);
                let uv = v.to_unauthenticated();
                require_contains(
                    trace,
                    move |a| {
                        is_relay_av(a, r, p, SOFT)
                            && matches!(a, Action::Network(na)
                                if na.unauthenticated_vote.raw_vote.sender == uv.raw_vote.sender)
                    },
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote (taskIndex=0)",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, next_p, PROPOSE),
                    "Player should relay propose vote (next period)",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, PROPOSE),
                    "Player should relay propose vote (same period)",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 1),
                    "Player should issue verifyVote (taskIndex=1)",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent | E::PayloadVerified | E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal with no vvote",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_vb,
                    "Player should relay bundle",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_stage_digest(a, r, p, &pv),
                    "Player should stage digest",
                    player_n,
                    event_n,
                );
            }
            E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_bundle_at(a, r, p, CERT),
                    "Player should issue verifyBundle",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::NextRound => match event_n {
            E::ProposeVoteVerifiedSamePeriod => {
                // Player on R+1 receives a propose vote for R. With dynamic
                // filter enabled and period 0, the player relays for late
                // credential tracking; otherwise it ignores.
                require_action_count(trace, 1, player_n, event_n);
                if dynamic_filter_enabled && p == algo_agreement::Period(0) {
                    require_contains(
                        trace,
                        is_relay_no_err,
                        "Player should relay period-0 msg from past round (dynamic filter)",
                        player_n,
                        event_n,
                    );
                } else {
                    require_contains(
                        trace,
                        is_ignore_with_err,
                        "Player should ignore msg from past round",
                        player_n,
                        event_n,
                    );
                }
            }
            E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                if dynamic_filter_enabled && p == algo_agreement::Period(0) {
                    require_contains(
                        trace,
                        is_verify_vote,
                        "Player should verify period-0 msg from past round (dynamic filter)",
                        player_n,
                        event_n,
                    );
                } else {
                    require_contains(
                        trace,
                        is_ignore_with_err,
                        "Player should ignore msg from past round",
                        player_n,
                        event_n,
                    );
                }
            }
            E::SoftVoteVerifiedSamePeriod
            | E::SoftVotePresentSamePeriod
            | E::ProposeVoteVerifiedNextPeriod
            | E::PayloadPresent
            | E::PayloadVerified
            | E::PayloadVerifiedNoMessageHandle
            | E::BundleVerifiedSamePeriod
            | E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore msg from past round",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::PrevRoundPendingPayloadPresent => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, SOFT),
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote (taskIndex=0)",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore future msg from bad period",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, PROPOSE),
                    "Player should relay propose vote",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay pipelined payload",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 2),
                    "Player should issue verifyVote (taskIndex=2)",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent | E::PayloadVerified | E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal with no vvote",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod | E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore bundle from different round",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::SameRoundProcessedProposalVote => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, SOFT),
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, next_p, PROPOSE),
                    "Player should relay propose vote (next period)",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod | E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal-vvote already received",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_payload_at(a, r, p, false),
                    "Player should verify payload",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
            }
            E::PayloadVerified => {
                require_action_count(trace, 0, player_n, event_n);
            }
            E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_vb,
                    "Player should relay bundle",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_stage_digest(a, r, p, &pv),
                    "Player should stage digest",
                    player_n,
                    event_n,
                );
            }
            E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_bundle_at(a, r, p, CERT),
                    "Player should issue verifyBundle",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::SameRoundReachedSoftThreshold => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, SOFT),
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, next_p, PROPOSE),
                    "Player should relay propose vote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod | E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal-vvote already received",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_payload_at(a, r, p, false),
                    "Player should verify payload",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
            }
            E::PayloadVerified => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_pseudonode(a, ActionType::Attest, r, p, CERT),
                    "Player should attest at cert step",
                    player_n,
                    event_n,
                );
            }
            E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_pseudonode(a, ActionType::Attest, r, p, CERT),
                    "Player should attest at cert step",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_vb,
                    "Player should relay bundle",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_stage_digest(a, r, p, &pv),
                    "Player should stage digest",
                    player_n,
                    event_n,
                );
            }
            E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_bundle_at(a, r, p, CERT),
                    "Player should issue verifyBundle",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::SameRoundReachedCertThreshold => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, SOFT),
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, next_p, PROPOSE),
                    "Player should relay propose vote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod | E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal-vvote already received",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent => {
                require_action_count(trace, 2, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_payload_at(a, r, p, false),
                    "Player should verify payload",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
            }
            E::PayloadVerified => {
                require_action_count(trace, 3, player_n, event_n);
                let bottom_pv = ProposalValue::default();
                require_contains(
                    trace,
                    move |a| is_ensure(a, r, algo_agreement::Period(0), &bottom_pv),
                    "Player should ensure block",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_rezero(a, Round(r.0 + 1)),
                    "Player should rezero for r+1",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| {
                        is_pseudonode(
                            a,
                            ActionType::Assemble,
                            Round(r.0 + 1),
                            algo_agreement::Period(0),
                            algo_agreement::Step(0),
                        )
                    },
                    "Player should assemble next round",
                    player_n,
                    event_n,
                );
            }
            E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 4, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_pp,
                    "Player should relay payload",
                    player_n,
                    event_n,
                );
                let bottom_pv = ProposalValue::default();
                require_contains(
                    trace,
                    move |a| is_ensure(a, r, algo_agreement::Period(0), &bottom_pv),
                    "Player should ensure block",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_rezero(a, Round(r.0 + 1)),
                    "Player should rezero for r+1",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| {
                        is_pseudonode(
                            a,
                            ActionType::Assemble,
                            Round(r.0 + 1),
                            algo_agreement::Period(0),
                            algo_agreement::Step(0),
                        )
                    },
                    "Player should assemble next round",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore — already at cert threshold",
                    player_n,
                    event_n,
                );
            }
            E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_bundle_at(a, r, p, CERT),
                    "Player should issue verifyBundle",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
        P::SameRoundProcessedProposal => match event_n {
            E::SoftVoteVerifiedSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_relay_av(a, r, p, SOFT),
                    "Player should relay soft vote",
                    player_n,
                    event_n,
                );
            }
            E::SoftVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_vote_at(a, r, p, 0),
                    "Player should issue verifyVote",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedNextPeriod => {
                // Special case: player already has proposal payload and a
                // verified vote arrives for next period — broadcast a
                // compound (payload + vote) message instead of a plain relay.
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_broadcast_pp,
                    "Player should broadcast payload+vote compound",
                    player_n,
                    event_n,
                );
            }
            E::ProposeVoteVerifiedSamePeriod | E::ProposeVotePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal-vvote already received",
                    player_n,
                    event_n,
                );
            }
            E::PayloadPresent | E::PayloadVerified | E::PayloadVerifiedNoMessageHandle => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    is_ignore_with_err,
                    "Player should ignore proposal already assembled",
                    player_n,
                    event_n,
                );
            }
            E::BundleVerifiedSamePeriod => {
                require_action_count(trace, 4, player_n, event_n);
                require_contains(
                    trace,
                    is_relay_vb,
                    "Player should relay bundle",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_ensure(a, r, p, &pv),
                    "Player should ensure block",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| is_rezero(a, Round(r.0 + 1)),
                    "Player should rezero for r+1",
                    player_n,
                    event_n,
                );
                require_contains(
                    trace,
                    move |a| {
                        is_pseudonode(
                            a,
                            ActionType::Assemble,
                            Round(r.0 + 1),
                            algo_agreement::Period(0),
                            algo_agreement::Step(0),
                        )
                    },
                    "Player should assemble next round",
                    player_n,
                    event_n,
                );
            }
            E::BundlePresentSamePeriod => {
                require_action_count(trace, 1, player_n, event_n);
                require_contains(
                    trace,
                    move |a| is_verify_bundle_at(a, r, p, CERT),
                    "Player should issue verifyBundle",
                    player_n,
                    event_n,
                );
            }
            E::SoftVoteVerifiedErrorSamePeriod
            | E::ProposeVoteVerifiedErrorSamePeriod
            | E::BundleVerifiedError => assert_disconnect_on_error(trace),
            E::PayloadVerifiedError => assert_ignore_on_payload_error(trace),
        },
    }
}

// ===========================================================================
// Assertion helpers — produce panic messages with `(player, event)` context
// ===========================================================================

#[track_caller]
fn require_action_count(
    trace: &IoTrace,
    expected: usize,
    player_n: PlayerPermutation,
    event_n: MessageEventPermutation,
) {
    let actual = trace.count_actions();
    if actual != expected {
        panic!(
            "expected {expected} actions, got {actual}. player: {player_n:?}, event: {event_n:?}\n\
             trace:\n{trace}"
        );
    }
}

#[track_caller]
fn require_contains<F: Fn(&Action) -> bool>(
    trace: &IoTrace,
    f: F,
    msg: &str,
    player_n: PlayerPermutation,
    event_n: MessageEventPermutation,
) {
    if !trace.contains_action_fn(f) {
        panic!(
            "{msg} — player: {player_n:?}, event: {event_n:?}\n\
             trace:\n{trace}"
        );
    }
}

// ===========================================================================
// Test entry — runs the full 7×14×2 matrix
// ===========================================================================

#[test]
fn player_permutation() {
    for &dynamic_filter in &[false, true] {
        let oc = override_consensus_with_dynamic_filter(dynamic_filter);
        for i in 0..7 {
            for j in 0..14 {
                let player_n = PlayerPermutation::from_index(i);
                let event_n = MessageEventPermutation::from_index(j);

                let (mut machine, mut helper, _payload) =
                    get_player_permutation(player_n, &oc.params);
                machine.set_params(oc.params.clone());
                let mut event = get_message_event_permutation(event_n, &mut helper, &oc.params);
                event.proto = oc.view.clone();

                let result = machine.transition(algo_agreement::Event::Message(event));
                if let Err(panic_msg) = result {
                    panic!(
                        "transition panicked: {panic_msg} — player: {player_n:?}, \
                         event: {event_n:?}, dynamic_filter: {dynamic_filter}"
                    );
                }

                verify_permutation_expected_actions(
                    player_n,
                    event_n,
                    &mut helper,
                    machine.trace(),
                    dynamic_filter,
                );
            }
        }
    }
}
