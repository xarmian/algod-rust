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

// Helpers for driving `player.lowestCredentialArrivals` scenarios through
// `IoAutomataConcretePlayer`, mirroring the `sendVoteVerified`,
// `sendPayloadPresent`, `sendCompoundMessage`, `moveToRound`,
// `testClockForRound`, `assertSingleCredentialArrival`, and
// `assertPayloadTimings` helpers in go-algorand's `agreement/player_test.go`.
//
// `received_at` (mirroring Go's `unauthenticatedProposal.receivedAt`) is
// threaded through via `UnauthenticatedProposal::received_at` +
// `MessageEvent::attach_received_at`, wired at the demux boundary in
// `service.rs` and at `BlockAssembler::bind` in `proposal_store.rs` —
// see those sites for the field-level plumbing. `send_payload_present`
// (no timing) is kept for the five existing tests that don't check
// `received_at`; `send_payload_present_at` and `send_compound_message*`
// below are the timing-aware counterparts needed by the `OneSample`/`PP`/
// `AVPP` scenarios.

use std::collections::HashMap;
use std::time::Duration;

use algo_types::Round;

use crate::actions::Action;
use crate::events::EventType;
use crate::events::{Event, InternalMessage, MessageEvent, Proposal, PIPELINED_MESSAGE_TIMESTAMP};
use crate::step::{Period, CERT, PROPOSE};
use crate::vote::{ProposalValue, Vote};

use super::io_automata::IoAutomataConcretePlayer;
use super::vote_maker::VoteMakerHelper;

/// Resolve a fixed test timestamp for `event_round`, falling back to
/// `historical_clocks` for rounds other than `current_round` and to the
/// pipelined-message timestamp for rounds still in the future.
///
/// Mirrors Go's `testClockForRound` (`agreement/player_test.go:3328`),
/// itself a thin wrapper over `clockForRound` with a
/// `constantRoundStartTimer`.
pub fn test_clock_for_round(
    fixed_duration: Duration,
    current_round: Round,
    historical_clocks: HashMap<Round, Duration>,
) -> impl Fn(Round) -> Duration {
    move |event_round| {
        if event_round.0 > current_round.0 {
            return PIPELINED_MESSAGE_TIMESTAMP;
        }
        if event_round == current_round {
            return fixed_duration;
        }
        historical_clocks
            .get(&event_round)
            .copied()
            .unwrap_or(Duration::ZERO)
    }
}

/// Fabricate and dispatch a `voteVerified` event for a fresh proposal-vote
/// at `(vote_round, vote_period)`, with `validated_at` resolved via
/// `test_clock_for_round(validated_at, cur_round, historical_clocks)`.
///
/// Mirrors Go's `sendVoteVerified` (`agreement/player_test.go:3862`).
#[allow(clippy::too_many_arguments)]
pub fn send_vote_verified(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    addr_index: usize,
    cur_round: Round,
    vote_round: Round,
    vote_period: Period,
    value: ProposalValue,
    validated_at: Duration,
    historical_clocks: HashMap<Round, Duration>,
) {
    let vote = helper.make_verified_vote(addr_index, vote_round, vote_period, PROPOSE, value);
    send_vote_verified_for_vote(machine, vote, cur_round, validated_at, historical_clocks, 0);
}

/// Dispatch a `voteVerified` event for an already-fabricated `Vote`.
///
/// Mirrors Go's `sendVoteVerifiedForVote` (`agreement/player_test.go:3869`).
pub fn send_vote_verified_for_vote(
    machine: &mut IoAutomataConcretePlayer,
    vote: Vote,
    cur_round: Round,
    validated_at: Duration,
    historical_clocks: HashMap<Round, Duration>,
    task_index: u64,
) {
    let unauthenticated_vote = vote.to_unauthenticated();
    let msg = MessageEvent {
        t: EventType::VoteVerified,
        input: InternalMessage {
            vote: Some(vote),
            unauthenticated_vote,
            ..InternalMessage::default()
        },
        task_index,
        ..MessageEvent::default()
    };
    let msg = msg.attach_validated_at(test_clock_for_round(
        validated_at,
        cur_round,
        historical_clocks,
    ));
    machine
        .transition(Event::Message(msg))
        .expect("voteVerified transition should not panic");
}

/// Fabricate a fresh proposal-vote for `(vote_round, vote_period, value)`
/// and dispatch it as a standalone `votePresent` event (no tail), returning
/// the fabricated `Vote` so callers can later verify it.
///
/// Mirrors Go's `sendVotePresent` (`agreement/player_test.go:3878`).
pub fn send_vote_present(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    addr_index: usize,
    vote_round: Round,
    vote_period: Period,
    value: ProposalValue,
) -> Vote {
    let vote = helper.make_verified_vote(addr_index, vote_round, vote_period, PROPOSE, value);
    let msg = MessageEvent {
        t: EventType::VotePresent,
        input: InternalMessage {
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("votePresent transition should not panic");
    vote
}

/// Dispatch a `payloadPresent` event carrying `proposal`'s unauthenticated
/// payload, without attaching a `received_at` timing (left at
/// `Duration::ZERO`). Mirrors Go's `sendPayloadPresent`
/// (`agreement/player_test.go:3889`) for callers that don't need to assert
/// `received_at` — use [`send_payload_present_at`] when the test needs a
/// specific timing (mirroring Go's non-nil `receivedAt`/`historicalClocks`
/// arguments).
pub fn send_payload_present(machine: &mut IoAutomataConcretePlayer, proposal: &Proposal) {
    let msg = MessageEvent {
        t: EventType::PayloadPresent,
        input: InternalMessage {
            unauthenticated_proposal: proposal.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("payloadPresent transition should not panic");
}

/// Dispatch a `payloadPresent` event carrying `proposal`'s unauthenticated
/// payload, with `received_at` resolved via `test_clock_for_round(received_at,
/// cur_round, historical_clocks)` and attached through
/// `MessageEvent::attach_received_at` — mirroring the real demux boundary.
///
/// Mirrors Go's `sendPayloadPresent` (`agreement/player_test.go:3889`) in
/// full (including its `receivedAt`/`historicalClocks` parameters).
pub fn send_payload_present_at(
    machine: &mut IoAutomataConcretePlayer,
    cur_round: Round,
    proposal: &Proposal,
    received_at: Duration,
    historical_clocks: HashMap<Round, Duration>,
) {
    let msg = MessageEvent {
        t: EventType::PayloadPresent,
        input: InternalMessage {
            unauthenticated_proposal: proposal.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    let msg = msg.attach_received_at(test_clock_for_round(
        received_at,
        cur_round,
        historical_clocks,
    ));
    machine
        .transition(Event::Message(msg))
        .expect("payloadPresent transition should not panic");
}

/// Fabricate a fresh proposal-vote for `(vote_round, vote_period, value)`
/// and dispatch it as a `votePresent` event with a synthetic `payloadPresent`
/// tail carrying `proposal`'s unauthenticated payload (a `PP`/compound
/// message, as used on the wire for `protocol.ProposalPayloadTag`), with
/// `received_at` attached to the tail via `attach_received_at`.
///
/// Mirrors Go's `sendCompoundMessage` (`agreement/player_test.go:3899`).
/// Returns the fabricated `Vote` so callers can later verify it (mirroring
/// Go returning the `vote` for use in `verifyVoteAction`/`sendVoteVerifiedForVote`
/// assertions).
#[allow(clippy::too_many_arguments)]
pub fn send_compound_message(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    cur_round: Round,
    vote_round: Round,
    vote_period: Period,
    proposal: &Proposal,
    value: ProposalValue,
    received_at: Duration,
    historical_clocks: HashMap<Round, Duration>,
) -> Vote {
    let vote = helper.make_verified_vote(0, vote_round, vote_period, PROPOSE, value);
    send_compound_message_for_vote(
        machine,
        vote.clone(),
        cur_round,
        proposal,
        received_at,
        historical_clocks,
    );
    vote
}

/// Dispatch an already-fabricated `Vote` as a `votePresent` event with a
/// synthetic `payloadPresent` tail carrying `proposal`'s unauthenticated
/// payload, with `received_at` attached to the tail via
/// `attach_received_at`.
///
/// Mirrors Go's `sendCompoundMessageForVote` (`agreement/player_test.go:3905`).
pub fn send_compound_message_for_vote(
    machine: &mut IoAutomataConcretePlayer,
    vote: Vote,
    cur_round: Round,
    proposal: &Proposal,
    received_at: Duration,
    historical_clocks: HashMap<Round, Duration>,
) {
    let tail = MessageEvent {
        t: EventType::PayloadPresent,
        input: InternalMessage {
            unauthenticated_proposal: proposal.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    let msg = MessageEvent {
        t: EventType::VotePresent,
        input: InternalMessage {
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        tail: Some(Box::new(tail)),
        ..MessageEvent::default()
    };
    let msg = msg.attach_received_at(test_clock_for_round(
        received_at,
        cur_round,
        historical_clocks,
    ));
    machine
        .transition(Event::Message(msg))
        .expect("votePresent transition should not panic");
}

/// Submit a `payloadVerified` message for `proposal` (with `validated_at`
/// attached relative to `target_round - 1`) followed by a synthetic
/// `bundleVerified` cert-threshold bundle for `(target_round - 1, period,
/// value)`, driving the player from `target_round - 1` into
/// `(target_round, period 0)`.
///
/// Mirrors Go's `moveToRound` (`agreement/player_test.go:3935`) minus the
/// `verifyPayloadAction`/`ensureAction` trace assertions (callers that need
/// those can inspect `machine.trace()` themselves) and minus the
/// `receivedAt` check (see module-level doc comment).
#[allow(clippy::too_many_arguments)]
pub fn move_to_round(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    target_round: Round,
    period: Period,
    proposal: &Proposal,
    value: ProposalValue,
    validated_at: Duration,
    params: &algo_types::ConsensusParams,
) {
    let prev_round = Round(target_round.0 - 1);

    // payloadVerified for prev_round's proposal.
    let msg = MessageEvent {
        t: EventType::PayloadVerified,
        input: InternalMessage {
            unauthenticated_proposal: proposal.unauthenticated_proposal.clone(),
            proposal: Some(proposal.clone()),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    let msg = msg.attach_validated_at(test_clock_for_round(
        validated_at,
        prev_round,
        HashMap::new(),
    ));
    machine
        .transition(Event::Message(msg))
        .expect("payloadVerified transition should not panic");

    // bundleVerified: a cert-threshold bundle for (prev_round, period, value).
    let bundle = helper.make_verified_bundle(prev_round, period, CERT, value, params);
    let msg = MessageEvent {
        t: EventType::BundleVerified,
        input: InternalMessage {
            verified_bundle_votes: bundle.votes.clone(),
            unauthenticated_bundle: bundle.u.clone(),
            ..InternalMessage::default()
        },
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("bundleVerified transition should not panic");

    assert_eq!(
        machine.player().round,
        target_round,
        "player did not enter new round"
    );
    assert_eq!(
        machine.player().period,
        Period(0),
        "player did not enter period 0 in new round"
    );
}

/// Assert `player.lowest_credential_arrivals` holds exactly one sample,
/// equal to `expected`.
///
/// Mirrors Go's `assertSingleCredentialArrival`
/// (`agreement/player_test.go:3925`).
pub fn assert_single_credential_arrival(machine: &IoAutomataConcretePlayer, expected: Duration) {
    let history = &machine.player().lowest_credential_arrivals;
    assert_eq!(
        history.write_ptr(),
        1,
        "expected exactly one recorded credential arrival sample"
    );
    assert!(
        !history.is_full(),
        "history should not be full after a single sample"
    );
    assert_eq!(history.raw_history()[0], expected);
}

/// Inspect the trace for an `EnsureAction` whose payload is for round `r`,
/// and assert its certificate proposal equals `value` and its payload's
/// `received_at`/`validated_at` equal `received_at`/`validated_at`.
///
/// Mirrors Go's `assertPayloadTimings` (`agreement/player_test.go:3988`).
pub fn assert_payload_timings(
    machine: &IoAutomataConcretePlayer,
    r: Round,
    value: ProposalValue,
    received_at: Duration,
    validated_at: Duration,
) {
    let mut found = None;
    for action in machine.trace().actions() {
        if let Action::Ensure(ea) = action {
            if ea.payload.unauthenticated_proposal.round() == r {
                assert!(
                    found.is_none(),
                    "found more than one EnsureAction for round {r:?}"
                );
                found = Some(ea.clone());
            }
        }
    }
    let ea = found.unwrap_or_else(|| panic!("expected an EnsureAction for round {r:?}"));
    assert_eq!(ea.certificate.proposal, value);
    assert_eq!(ea.payload.unauthenticated_proposal.round(), r);
    assert_eq!(
        ea.payload.validated_at, validated_at,
        "unexpected validated_at"
    );
    assert_eq!(
        ea.payload.received_at, received_at,
        "unexpected received_at"
    );
}
