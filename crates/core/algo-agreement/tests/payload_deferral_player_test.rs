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

// Player-level tests of go v5.1.1's deferred proposal-payload decoding
// (`player.decodePayloadIfWanted`, `agreement/player.go`, commit 11f6cc2ea):
// a payload arrives undecoded (`decodeProposal` read only its prefix) and the
// player decodes it only if a proposal-value in its round's proposalStore is
// waiting for a payload with that encoding digest. Issue #2552.

use std::sync::Arc;

use algo_agreement::codec::encode_compound_message;
use algo_agreement::payload_deferral::decode_proposal;
use algo_agreement::test_support::{
    make_random_proposal_payload, override_consensus_with_dynamic_filter, setup_p,
    IoAutomataConcretePlayer, VoteMakerHelper,
};
use algo_agreement::{
    Action, ActionType, CompoundMessage, ConsensusVersionView, Event, EventType, InternalMessage,
    MessageEvent, ProposalValue, UnauthenticatedProposal, CERT, PROPOSE,
};
use algo_types::{ConsensusParams, Round, CONSENSUS_V41};

fn proto_view() -> ConsensusVersionView {
    ConsensusVersionView {
        err: None,
        version: CONSENSUS_V41.to_string(),
    }
}

fn test_params() -> ConsensusParams {
    override_consensus_with_dynamic_filter(false).params
}

/// The proposal go's `decodeProposal` hands the player for the payload `wire`.
fn received(wire: &[u8]) -> UnauthenticatedProposal {
    decode_proposal(Arc::from(wire)).expect("prefix").proposal
}

fn wire_of(proposal: &UnauthenticatedProposal) -> Vec<u8> {
    encode_compound_message(&CompoundMessage {
        vote: Default::default(),
        proposal: proposal.clone(),
    })
}

fn send_propose_vote(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    round: Round,
    value: ProposalValue,
) {
    let vote = helper.make_verified_vote(0, round, algo_agreement::Period(0), PROPOSE, value);
    machine
        .transition(Event::Message(MessageEvent {
            t: EventType::VoteVerified,
            input: InternalMessage {
                vote: Some(vote.clone()),
                unauthenticated_vote: vote.to_unauthenticated(),
                ..InternalMessage::default()
            },
            proto: proto_view(),
            ..MessageEvent::default()
        }))
        .expect("voteVerified");
}

fn send_payload(machine: &mut IoAutomataConcretePlayer, proposal: UnauthenticatedProposal) {
    machine
        .transition(Event::Message(MessageEvent {
            t: EventType::PayloadPresent,
            input: InternalMessage {
                unauthenticated_proposal: proposal,
                ..InternalMessage::default()
            },
            proto: proto_view(),
            ..MessageEvent::default()
        }))
        .expect("payloadPresent");
}

fn verifies_payload(machine: &IoAutomataConcretePlayer, round: Round) -> bool {
    machine.trace().contains_action_fn(
        |a| matches!(a, Action::Crypto(ca) if ca.t == ActionType::VerifyPayload && ca.round == round),
    )
}

/// Whether the trace holds an ignore action whose error mentions `text`.
fn ignored_with(machine: &IoAutomataConcretePlayer, text: &str) -> bool {
    machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Network(na)
            if na.t == ActionType::Ignore
                && na.err.as_ref().is_some_and(|e| e.to_string().contains(text)))
    })
}

#[test]
fn deferred_payload_is_decoded_once_its_value_is_waiting() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let payload = make_random_proposal_payload(r).unauthenticated_proposal;
    send_propose_vote(&mut machine, &mut helper, r, payload.value());

    send_payload(&mut machine, received(&wire_of(&payload)));

    assert!(
        verifies_payload(&machine, r),
        "a wanted deferred payload is decoded and verified; trace:\n{}",
        machine.trace()
    );
    // what the player relays and verifies is the decoded proposal, not the
    // prefix-only stub
    let relayed_full = machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Network(na)
            if na.t == ActionType::Relay
                && na.compound_message.proposal.deferred_payload.is_none()
                && na.compound_message.proposal.value() == payload.value())
    });
    assert!(relayed_full, "trace:\n{}", machine.trace());
}

#[test]
fn deferred_payload_no_proposal_value_waits_for_is_ignored() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, _helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let payload = make_random_proposal_payload(r).unauthenticated_proposal;

    send_payload(&mut machine, received(&wire_of(&payload)));

    assert!(
        ignored_with(&machine, "wants a payload"),
        "trace:\n{}",
        machine.trace()
    );
    assert!(!verifies_payload(&machine, r));
}

#[test]
fn deferred_payload_of_a_round_the_player_is_not_near_is_ignored() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let far = make_random_proposal_payload(Round(r.0 + 5)).unauthenticated_proposal;
    send_propose_vote(&mut machine, &mut helper, r, far.value());

    send_payload(&mut machine, received(&wire_of(&far)));

    assert!(
        ignored_with(&machine, "ignoring proposal payload for round"),
        "trace:\n{}",
        machine.trace()
    );
}

#[test]
fn deferred_payload_whose_encoding_is_not_the_waited_for_one_is_ignored() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let payload = make_random_proposal_payload(r).unauthenticated_proposal;
    send_propose_vote(&mut machine, &mut helper, r, payload.value());

    // the same proposal, encoded with a trailing byte: a different digest,
    // so it matches no proposal-value and is not decoded
    let mut wire = wire_of(&payload);
    wire.push(0x00);
    send_payload(&mut machine, received(&wire));

    assert!(
        ignored_with(&machine, "matches no proposal-value"),
        "trace:\n{}",
        machine.trace()
    );
    assert!(!verifies_payload(&machine, r));
}

#[test]
fn deferred_payload_is_not_wanted_twice() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let payload = make_random_proposal_payload(r).unauthenticated_proposal;
    send_propose_vote(&mut machine, &mut helper, r, payload.value());
    let wire = wire_of(&payload);

    send_payload(&mut machine, received(&wire));
    assert!(verifies_payload(&machine, r));
    let before = machine.trace().actions().count();
    send_payload(&mut machine, received(&wire));

    // the blockAssembler is filled: the second copy is refused before it is
    // hashed or decoded
    let new_actions: Vec<_> = machine.trace().actions().skip(before).collect();
    assert!(
        new_actions.iter().all(|a| !matches!(a, Action::Crypto(_))),
        "a duplicate payload must not be verified again"
    );
    assert!(
        new_actions.iter().any(|a| matches!(a, Action::Network(na)
            if na.t == ActionType::Ignore
                && na.err.as_ref().is_some_and(|e| e.to_string().contains("wants a payload")))),
        "the duplicate is ignored"
    );
}

#[test]
fn deferred_payload_of_the_next_round_is_decoded_but_not_verified_yet() {
    let r = Round(201221);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, algo_agreement::Period(0), CERT, &params);
    let next = make_random_proposal_payload(Round(r.0 + 1)).unauthenticated_proposal;
    send_propose_vote(&mut machine, &mut helper, Round(r.0 + 1), next.value());

    send_payload(&mut machine, received(&wire_of(&next)));

    assert!(
        !verifies_payload(&machine, Round(r.0 + 1)),
        "a payload of the next round is verified once that round starts"
    );
    let relayed = machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Network(na)
            if na.t == ActionType::Relay && na.compound_message.proposal.value() == next.value())
    });
    assert!(relayed, "it is decoded, pipelined and relayed");
}
