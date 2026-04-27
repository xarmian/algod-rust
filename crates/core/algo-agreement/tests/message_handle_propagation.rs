// Integration test: a `MessageHandle` attached to an inbound `MessageEvent`
// survives through the player and lands on the resulting
// `Relay` / `Ignore` / `Disconnect` `NetworkAction`.
//
// Surfaced by Codex review on PR #259 (TASK-82) — fixes the gap where the
// inline `..NetworkAction::default()` constructions in `player.rs` and the
// old `disconnect_action(err)` / `ignore_action(err)` helpers silently
// dropped the originating peer reference, so the bridge could neither
// exclude the sender on relay nor disconnect the offending peer.
//
// Verifies the post-fix behavior end-to-end: drive a real player, fish the
// emitted action out of the trace, downcast the propagated `Arc<dyn Any>`
// back to a marker struct, and check the value travelled intact.
//
// Reference: go-algorand `agreement/actions.go` — `relayAction(e, ...)`,
// `disconnectAction(e, ...)`, `ignoreAction(e, ...)` all capture
// `e.Input.messageHandle` at construction time.

use std::sync::Arc;

use algo_agreement::test_support::{
    make_random_proposal_payload, override_consensus_with_dynamic_filter, random_block_hash,
    setup_p,
};
use algo_agreement::{
    Action, ActionType, BlockAssembler, ConsensusVersionView, Event, EventType, InternalMessage,
    MessageEvent, MessageHandle, SerializableError, AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG,
    PROPOSE, SOFT,
};
use algo_types::{Address, Round, CONSENSUS_V41};

const TEST_ROUND: Round = Round(209);
const TEST_PERIOD: algo_agreement::Period = algo_agreement::Period(0);

/// Marker type carried inside the [`MessageHandle`] `Arc`. Kept simple and
/// `Eq` so the test asserts handle identity by value rather than by Arc
/// pointer (cloning the Arc through the action pipeline preserves both, but
/// the value comparison is the more readable assertion).
#[derive(Debug, PartialEq, Eq)]
struct PeerMarker(u32);

fn marker_handle(id: u32) -> MessageHandle {
    Some(Arc::new(PeerMarker(id)))
}

fn proto_view() -> ConsensusVersionView {
    ConsensusVersionView {
        err: None,
        version: CONSENSUS_V41.to_string(),
    }
}

/// Find the first `Action::Network` of the given action-type in the trace
/// and return its `message_handle`'s downcast `PeerMarker`. Panics with a
/// descriptive message if no matching action exists or the handle is
/// missing / not a `PeerMarker`.
fn extract_peer_marker(
    trace: &algo_agreement::test_support::IoTrace,
    expected_type: ActionType,
) -> &PeerMarker {
    let mut saw_types = Vec::new();
    for action in trace.actions() {
        if let Action::Network(na) = action {
            saw_types.push(na.t);
            if na.t == expected_type {
                let h = na.message_handle.as_ref().unwrap_or_else(|| {
                    panic!("Network/{expected_type} carried no MessageHandle; trace:\n{trace}")
                });
                return h.downcast_ref::<PeerMarker>().unwrap_or_else(|| {
                    panic!("MessageHandle did not downcast to PeerMarker; trace:\n{trace}")
                });
            }
        }
    }
    panic!(
        "no Network/{expected_type} action found; saw network types {saw_types:?}; trace:\n{trace}",
    );
}

// ---------------------------------------------------------------------------
// Relay path: VoteVerified for a soft vote → player relays the vote and the
// relay carries the originating peer's handle.
// ---------------------------------------------------------------------------

#[test]
fn handle_propagates_through_vote_relay() {
    let oc = override_consensus_with_dynamic_filter(false);
    let (_, mut machine, mut helper) = setup_p(TEST_ROUND, TEST_PERIOD, SOFT, &oc.params);

    let payload = make_random_proposal_payload(TEST_ROUND);
    let pv = payload.unauthenticated_proposal.value();

    // Build a verified soft vote. VoteVerified for a fresh sender lands on
    // the player's relay path (player.rs ~1259 — `Relay AGREEMENT_VOTE_TAG`).
    let vote = helper.make_verified_vote(0, TEST_ROUND, TEST_PERIOD, SOFT, pv);
    let me = MessageEvent {
        t: EventType::VoteVerified,
        input: InternalMessage {
            message_handle: marker_handle(101),
            vote: Some(vote.clone()),
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };

    machine
        .transition(Event::Message(me))
        .expect("transition produced no panic");

    let marker = extract_peer_marker(machine.trace(), ActionType::Relay);
    assert_eq!(marker, &PeerMarker(101));

    // And the relayed payload tag must be the agreement-vote tag (the path
    // we wanted to exercise).
    let na = machine
        .trace()
        .actions()
        .find_map(|a| match a {
            Action::Network(na) if na.t == ActionType::Relay => Some(na),
            _ => None,
        })
        .expect("relay present");
    assert_eq!(na.tag, AGREEMENT_VOTE_TAG);
}

// ---------------------------------------------------------------------------
// Ignore path: a duplicate proposal-vote is filtered, player emits ignore
// carrying the originating peer's handle. Mirrors Go's
// `playerSameRoundProcessedProposalVote × proposeVoteVerifiedSamePeriod` arm.
// ---------------------------------------------------------------------------

#[test]
fn handle_propagates_through_ignore_on_filtered_propose_vote() {
    let oc = override_consensus_with_dynamic_filter(false);
    let (_, mut machine, mut helper) = setup_p(TEST_ROUND, TEST_PERIOD, SOFT, &oc.params);

    let payload = make_random_proposal_payload(TEST_ROUND);
    let pv = payload.unauthenticated_proposal.value();

    // Seed the per-round/period state and pre-mark sender 0 as duplicate so
    // the next propose-vote from the same address is filtered.
    machine.ensure_round_period(TEST_ROUND, TEST_PERIOD);
    machine.set_proposal_assembler(TEST_ROUND, pv, BlockAssembler::default());
    let dup_addr = Address(random_block_hash().0);
    helper.addresses.insert(0, dup_addr);
    machine.set_proposal_duplicate(TEST_ROUND, TEST_PERIOD, dup_addr);

    let vote = helper.make_verified_vote(0, TEST_ROUND, TEST_PERIOD, PROPOSE, pv);
    let me = MessageEvent {
        t: EventType::VoteVerified,
        input: InternalMessage {
            message_handle: marker_handle(202),
            vote: Some(vote.clone()),
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };

    machine
        .transition(Event::Message(me))
        .expect("transition produced no panic");

    let marker = extract_peer_marker(machine.trace(), ActionType::Ignore);
    assert_eq!(marker, &PeerMarker(202));
}

// ---------------------------------------------------------------------------
// VotePresent → verifyVote crypto action. The crypto action stores the
// `InternalMessage` (which itself owns `message_handle`), so the verified
// vote that comes back from the verifier still carries the handle. This
// guards the second hop of the pipeline: handle survives even when the
// player emits a *crypto* action rather than a network action directly.
// ---------------------------------------------------------------------------

#[test]
fn handle_round_trips_through_verify_vote_action() {
    let oc = override_consensus_with_dynamic_filter(false);
    let (_, mut machine, mut helper) = setup_p(TEST_ROUND, TEST_PERIOD, SOFT, &oc.params);

    let payload = make_random_proposal_payload(TEST_ROUND);
    let pv = payload.unauthenticated_proposal.value();

    let vote = helper.make_verified_vote(0, TEST_ROUND, TEST_PERIOD, SOFT, pv);
    let me = MessageEvent {
        t: EventType::VotePresent,
        input: InternalMessage {
            message_handle: marker_handle(303),
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };

    machine
        .transition(Event::Message(me))
        .expect("transition produced no panic");

    // VotePresent → VerifyVote (crypto action). Confirm the crypto action's
    // captured `InternalMessage.message_handle` survived as the same Arc.
    let ca = machine
        .trace()
        .actions()
        .find_map(|a| match a {
            Action::Crypto(ca) if ca.t == ActionType::VerifyVote => Some(ca),
            _ => None,
        })
        .expect("verify_vote crypto action present");

    let h =
        ca.m.message_handle
            .as_ref()
            .expect("verify_vote crypto action carried handle");
    let marker = h
        .downcast_ref::<PeerMarker>()
        .expect("downcast to PeerMarker");
    assert_eq!(marker, &PeerMarker(303));
}

// ---------------------------------------------------------------------------
// Disconnect path: a verified soft vote whose `MessageEvent.err` is set
// signals "verification failed" → dispatch returns VoteMalformed → player
// emits disconnect_action carrying the originating peer's handle. Mirrors
// the `SoftVoteVerifiedErrorSamePeriod` arm of the permutation matrix.
// ---------------------------------------------------------------------------

#[test]
fn handle_propagates_through_disconnect_on_malformed_vote() {
    let oc = override_consensus_with_dynamic_filter(false);
    let (_, mut machine, mut helper) = setup_p(TEST_ROUND, TEST_PERIOD, SOFT, &oc.params);

    let payload = make_random_proposal_payload(TEST_ROUND);
    let pv = payload.unauthenticated_proposal.value();
    let vote = helper.make_verified_vote(0, TEST_ROUND, TEST_PERIOD, SOFT, pv);

    let me = MessageEvent {
        t: EventType::VoteVerified,
        input: InternalMessage {
            message_handle: marker_handle(404),
            vote: Some(vote.clone()),
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        // Non-None `err` flags this verified vote as malformed; the
        // VoteMachine dispatch turns it into a Filtered/VoteMalformed which
        // the player turns into `disconnect_action(&e, err)`.
        err: Some(SerializableError::new("verify failed")),
        proto: proto_view(),
        ..MessageEvent::default()
    };

    machine
        .transition(Event::Message(me))
        .expect("transition produced no panic");

    let marker = extract_peer_marker(machine.trace(), ActionType::Disconnect);
    assert_eq!(marker, &PeerMarker(404));
}

// ---------------------------------------------------------------------------
// Payload-relay path: PayloadPresent for the same round → dispatch returns
// PayloadPipelined → player.rs ~1107 emits a compound-message Relay tagged
// `PROPOSAL_PAYLOAD_TAG`. Asserts the inline `..NetworkAction::default()`
// site now propagates the originating peer's handle. Mirrors the
// `playerSameRound × payloadPresent` arm of the permutation matrix.
// ---------------------------------------------------------------------------

#[test]
fn handle_propagates_through_payload_relay() {
    let oc = override_consensus_with_dynamic_filter(false);
    let (_, mut machine, _helper) = setup_p(TEST_ROUND, TEST_PERIOD, SOFT, &oc.params);

    let payload = make_random_proposal_payload(TEST_ROUND);
    let pv = payload.unauthenticated_proposal.value();

    // Seed the per-round/period state with a pipelining-ready assembler so
    // the dispatch returns PayloadPipelined rather than rejecting the
    // payload outright. Mirrors the `SameRoundProcessedProposalVote` setup
    // in the permutation matrix.
    machine.ensure_round_period(TEST_ROUND, TEST_PERIOD);
    machine.set_proposal_assembler(TEST_ROUND, pv, BlockAssembler::default());

    let me = MessageEvent {
        t: EventType::PayloadPresent,
        input: InternalMessage {
            message_handle: marker_handle(505),
            unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };

    machine
        .transition(Event::Message(me))
        .expect("transition produced no panic");

    let marker = extract_peer_marker(machine.trace(), ActionType::Relay);
    assert_eq!(marker, &PeerMarker(505));

    // Confirm the relayed payload is the proposal-payload (not the vote
    // path): the relay we matched must carry the proposal-payload tag.
    let na = machine
        .trace()
        .actions()
        .find_map(|a| match a {
            Action::Network(na) if na.t == ActionType::Relay => Some(na),
            _ => None,
        })
        .expect("relay present");
    assert_eq!(na.tag, PROPOSAL_PAYLOAD_TAG);
}
