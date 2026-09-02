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
// `sendPayloadPresent`, `moveToRound`, `testClockForRound`, and
// `assertSingleCredentialArrival` helpers in go-algorand's
// `agreement/player_test.go`.
//
// ## Known gap: `receivedAt` is not ported
//
// Go's `unauthenticatedProposal` carries a `receivedAt time.Duration` field
// that `AttachReceivedAt`/`blockAssembler.bind` thread through to the
// ensured `EnsureAction.Payload.receivedAt`. algod-rust's
// `UnauthenticatedProposal` does not have an equivalent field (tracked as a
// follow-up — see the PR/issue this module was introduced in), so
// `send_payload_present` below does not attempt to attach or verify a
// `receivedAt` timing, unlike Go's `sendPayloadPresent`/`assertPayloadTimings`.
// Only `validated_at` (on `Vote` and `Proposal`, both of which already carry
// the field) is threaded through, which is sufficient for the
// credential-arrival-history behavior these helpers exist to exercise.

use std::collections::HashMap;
use std::time::Duration;

use algo_types::Round;

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

/// Dispatch a `payloadPresent` event carrying `proposal`'s unauthenticated
/// payload. Mirrors Go's `sendPayloadPresent`
/// (`agreement/player_test.go:3889`) **except** it does not attach a
/// `receivedAt` timing — see the module-level doc comment.
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
