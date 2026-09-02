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

// Player-integration tests for the remainder of go-algorand's fourteen
// `TestPlayerRetains*ReceivedValidatedAt*` scenarios
// (`agreement/player_test.go:3240-3859`) not covered by
// `credential_arrival_history_test.rs` (PR #868) — Phase 17 issue #825,
// theme 2 ("Credential-arrival-history retention across periods").
//
// PR #868 ported 5 of the 14 scenarios and left the remaining 9 open,
// noting they were blocked on `UnauthenticatedProposal.received_at` /
// `MessageEvent::attach_received_at` plumbing that didn't exist yet. That
// plumbing is added in this change (see `proposal.rs`, `events.rs`,
// `demux.rs`, `service.rs`, `proposal_store.rs`), which also fixes a real
// bug: `EnsureAction.payload.received_at` was always `Duration::ZERO` in a
// running node (the crypto verifier hardcoded it, and nothing ever
// overwrote it — the telemetry `BlockAcceptedEvent.ReceivedAt` field was
// therefore always zero). This mirrors the `Vote.validated_at` bug PR #868
// found and fixed for votes.
//
// Ported scenarios (see also `docs/phase17/parity_agreement.md`):
// - `TestPlayerRetainsReceivedValidatedAtOneSample`
// - `TestPlayerRetainsReceivedValidatedAtPPOneSample`
// - `TestPlayerRetainsEarlyReceivedValidatedAtPPOneSample`
// - `TestPlayerRetainsLateReceivedValidatedAtPPOneSample`
// - `TestPlayerRetainsReceivedValidatedAtPPForHistoryWindow`
// - `TestPlayerRetainsReceivedValidatedAtAVPPOneSample`
// - `TestPlayerRetainsEarlyReceivedValidatedAtAVPPOneSample`
// - `TestPlayerRetainsLateReceivedValidatedAtAVPPOneSample`
// - `TestPlayerRetainsReceivedValidatedAtAVPPHistoryWindow`
//
// This closes out all 14 `TestPlayerRetains*ReceivedValidatedAt*` scenarios
// for issue #825 theme 2.

use std::collections::HashMap;
use std::time::Duration;

use algo_agreement::test_support::{
    assert_payload_timings, assert_single_credential_arrival, make_random_proposal_payload,
    move_to_round, override_consensus_with_dynamic_filter, send_compound_message,
    send_compound_message_for_vote, send_payload_present, send_payload_present_at,
    send_vote_present, send_vote_verified, send_vote_verified_for_vote, setup_p,
};
use algo_agreement::types::credential_round_lag;
use algo_agreement::{Period, PIPELINED_MESSAGE_TIMESTAMP, SOFT};
use algo_types::{ConsensusParams, Round};

/// Stock (non-dynamic-filter) V41 params.
fn stock_params() -> ConsensusParams {
    override_consensus_with_dynamic_filter(false).params
}

/// V41 params with the dynamic-filter-timeout flag enabled.
fn dynamic_filter_params() -> ConsensusParams {
    override_consensus_with_dynamic_filter(true).params
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtOneSample`
/// (`agreement/player_test.go:3240`).
///
/// Basic one-round `payloadPresent` + `voteVerified` + `moveToRound` flow
/// (non-zero starting period, no dynamic filter), asserting the resulting
/// `EnsureAction`'s payload carries both the `received_at` from
/// `payloadPresent` and the `validated_at` from `payloadVerified`
/// (via `moveToRound`).
#[test]
fn player_retains_received_validated_at_one_sample() {
    let r = Round(20239);
    let p = Period(131);
    let params = stock_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(502),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );

    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );

    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtPPOneSample`
/// (`agreement/player_test.go:3449`).
///
/// After moving to round `r` with no credentials arrived, delivers the
/// credential-history sample as a `PP` compound message (votePresent with a
/// payloadPresent tail) for round `r - credentialRoundLag`, and asserts it
/// lands in `lowest_credential_arrivals` once round `r` concludes.
#[test]
fn player_retains_received_validated_at_pp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = dynamic_filter_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    // Move to round r, no credentials arrived.
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    let mut historical_clocks = HashMap::new();
    historical_clocks.insert(
        Round(r.0 - cred_lag),
        Duration::from_millis(900),
    );

    // PP message for the round we'll take the sample from.
    let lag_round = Round(r.0 - cred_lag);
    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = helper.make_verified_vote(0, lag_round, p, algo_agreement::PROPOSE, lag_value);
    send_vote_verified_for_vote(
        &mut machine,
        vote.clone(),
        r,
        Duration::from_millis(502),
        historical_clocks,
        1,
    );
    send_payload_present(&mut machine, &lag_proposal);

    // Move to round r+1, triggering history update.
    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, Duration::from_millis(900));
}

/// Mirrors Go's `TestPlayerRetainsEarlyReceivedValidatedAtPPOneSample`
/// (`agreement/player_test.go:3505`).
///
/// Same as above but the `PP` compound message for the sample round
/// arrives one round early (dispatched while the player is still at
/// `r - credentialRoundLag - 1`), so its `voteVerified` timing is taken
/// as-is (502ms) rather than looked up from `historicalClocks`.
#[test]
fn player_retains_early_received_validated_at_pp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = dynamic_filter_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    // Create a PP message for the sample round, but dispatch it as though
    // it arrived one round early (curRound = r - credentialRoundLag - 1,
    // i.e. before the player has even reached r - credentialRoundLag - 1
    // itself) — this only affects the compound message's own `received_at`
    // (irrelevant here), not the vote's `validated_at`.
    let lag_round = Round(r.0 - cred_lag);
    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = send_compound_message(
        &mut machine,
        &mut helper,
        Round(r.0 - cred_lag - 1),
        lag_round,
        p,
        &lag_proposal,
        lag_value,
        Duration::from_secs(1),
        HashMap::new(),
    );

    // voteVerified is processed on-time (curRound = lag_round), so it
    // records the real 502ms timing rather than a pipelined one.
    send_vote_verified_for_vote(
        &mut machine,
        vote,
        lag_round,
        Duration::from_millis(502),
        HashMap::new(),
        1,
    );
    send_payload_present(&mut machine, &lag_proposal);

    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, Duration::from_millis(502));
}

/// Mirrors Go's `TestPlayerRetainsLateReceivedValidatedAtPPOneSample`
/// (`agreement/player_test.go:3559`).
///
/// Same as `player_retains_received_validated_at_pp_one_sample`, but the
/// sample-round vote is verified `credentialRoundLag` rounds too late, so
/// its timing must be looked up from `historicalClocks` (900ms) rather than
/// the fixed 502ms passed to `voteVerified`.
#[test]
fn player_retains_late_received_validated_at_pp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = dynamic_filter_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    let lag_round = Round(r.0 - cred_lag);
    let mut historical_clocks = HashMap::new();
    historical_clocks.insert(lag_round, Duration::from_millis(900));

    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = helper.make_verified_vote(0, lag_round, p, algo_agreement::PROPOSE, lag_value);
    // voteVerified pretends we're at round r (credentialRoundLag too late).
    send_vote_verified_for_vote(
        &mut machine,
        vote.clone(),
        r,
        Duration::from_millis(502),
        historical_clocks,
        1,
    );

    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_millis(503),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, Duration::from_millis(900));
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtPPForHistoryWindow`
/// (`agreement/player_test.go:3613`).
///
/// Feeds `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY + credentialRoundLag`
/// rounds' worth of `PP` compound-message proposal-votes with increasing
/// timestamps, asserting only the most recent
/// `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY` samples survive the circular
/// buffer.
#[test]
fn player_retains_received_validated_at_pp_for_history_window() {
    let r = Round(20239);
    let p = Period(0);
    let params = stock_params();
    let history_len = algo_agreement::DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY;
    let cred_lag = credential_round_lag();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);

    for i in 0..(history_len as u64 + cred_lag) {
        let round = Round(r.0 + i - 1);
        let proposal = make_random_proposal_payload(round);
        let value = proposal.unauthenticated_proposal.value();

        let vote = helper.make_verified_vote(0, round, p, algo_agreement::PROPOSE, value);
        send_compound_message_for_vote(
            &mut machine,
            vote,
            round,
            &proposal,
            Duration::from_secs(1),
            HashMap::new(),
        );

        let timestamp = 500 + i;
        let vote2 = helper.make_verified_vote(0, round, p, algo_agreement::PROPOSE, value);
        send_vote_verified_for_vote(
            &mut machine,
            vote2,
            round,
            Duration::from_millis(timestamp),
            HashMap::new(),
            i + 1,
        );

        move_to_round(
            &mut machine,
            &mut helper,
            Round(round.0 + 1),
            p,
            &proposal,
            value,
            Duration::from_secs(2),
            &params,
        );
    }

    let history = &machine.player().lowest_credential_arrivals;
    assert!(history.is_full(), "history should be full");
    for i in 0..history_len {
        let expected_ms = 500 + i as u64;
        assert_eq!(
            history.raw_history()[i],
            Duration::from_millis(expected_ms),
            "history[{i}] mismatch"
        );
    }
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtAVPPOneSample`
/// (`agreement/player_test.go:3654`).
///
/// Same scenario as the `PP` variant, but the sample round's proposal-vote
/// arrives as a standalone `votePresent` ("AV" message) first, is verified
/// via `voteVerified`, and only afterwards does the matching `PP` compound
/// message (carrying the payload) arrive — mirroring gossip's usual
/// vote-then-payload relay order.
#[test]
fn player_retains_received_validated_at_avpp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = dynamic_filter_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    let lag_round = Round(r.0 - cred_lag);
    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = send_vote_present(&mut machine, &mut helper, 0, lag_round, p, lag_value);
    send_vote_verified_for_vote(
        &mut machine,
        vote.clone(),
        lag_round,
        Duration::from_millis(502),
        HashMap::new(),
        1,
    );
    send_compound_message_for_vote(
        &mut machine,
        vote,
        lag_round,
        &lag_proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );

    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_secs(1),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, Duration::from_millis(502));
}

/// Mirrors Go's `TestPlayerRetainsEarlyReceivedValidatedAtAVPPOneSample`
/// (`agreement/player_test.go:3710`).
///
/// Same as the `AVPP` one-sample scenario, but the standalone `votePresent`
/// is verified one round early (pretending the player is still at
/// `r - credentialRoundLag - 1`), so `PIPELINED_MESSAGE_TIMESTAMP` is
/// recorded instead of the real 502ms timing.
#[test]
fn player_retains_early_received_validated_at_avpp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = stock_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    // Enable the dynamic filter only for the remainder of the scenario
    // (mirrors Go re-assigning `version` mid-test via a second
    // `overrideConfigWithDynamicFilterParam(true)` call). We use one
    // dynamic-filter-enabled `params` for the whole test instead, since
    // algod-rust's harness ties `params` to construction time; the initial
    // moveToRound above behaves identically either way (it doesn't touch
    // credential-arrival history).
    let params = dynamic_filter_params();
    machine.set_params(params.clone());

    let lag_round = Round(r.0 - cred_lag);
    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = send_vote_present(&mut machine, &mut helper, 0, lag_round, p, lag_value);
    // voteVerified pretends we're one round early.
    send_vote_verified_for_vote(
        &mut machine,
        vote.clone(),
        Round(r.0 - cred_lag - 1),
        Duration::from_millis(502),
        HashMap::new(),
        1,
    );
    send_compound_message_for_vote(
        &mut machine,
        vote,
        lag_round,
        &lag_proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );

    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_secs(1),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, PIPELINED_MESSAGE_TIMESTAMP);
}

/// Mirrors Go's `TestPlayerRetainsLateReceivedValidatedAtAVPPOneSample`
/// (`agreement/player_test.go:3767`).
///
/// Same as the `AVPP` one-sample scenario, but the standalone `votePresent`
/// is verified `credentialRoundLag` rounds too late (pretending the player
/// is already at round `r`), so the recorded timing is looked up from
/// `historicalClocks` (900ms) instead of the fixed 502ms passed to
/// `voteVerified`.
#[test]
fn player_retains_late_received_validated_at_avpp_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = stock_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);
    let proposal = make_random_proposal_payload(Round(r.0 - 1));
    let value = proposal.unauthenticated_proposal.value();

    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        Round(r.0 - 1),
        p,
        value,
        Duration::from_millis(501),
        HashMap::new(),
    );
    send_payload_present_at(
        &mut machine,
        Round(r.0 - 1),
        &proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_secs(2),
        &params,
    );
    assert_payload_timings(
        &machine,
        Round(r.0 - 1),
        value,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert!(!machine.player().lowest_credential_arrivals.is_full());
    assert_eq!(machine.player().lowest_credential_arrivals.write_ptr(), 0);

    let params = dynamic_filter_params();
    machine.set_params(params.clone());

    let lag_round = Round(r.0 - cred_lag);
    let mut historical_clocks = HashMap::new();
    historical_clocks.insert(lag_round, Duration::from_millis(900));

    let lag_proposal = make_random_proposal_payload(lag_round);
    let lag_value = lag_proposal.unauthenticated_proposal.value();
    let vote = send_vote_present(&mut machine, &mut helper, 0, lag_round, p, lag_value);
    // voteVerified pretends we're credentialRoundLag rounds too late.
    send_vote_verified_for_vote(
        &mut machine,
        vote.clone(),
        r,
        Duration::from_millis(502),
        historical_clocks,
        1,
    );
    send_compound_message_for_vote(
        &mut machine,
        vote,
        lag_round,
        &lag_proposal,
        Duration::from_secs(1),
        HashMap::new(),
    );

    let next_proposal = make_random_proposal_payload(r);
    let next_value = next_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        r,
        r,
        p,
        next_value,
        Duration::from_secs(1),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &next_proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        Round(r.0 + 1),
        p,
        &next_proposal,
        next_value,
        Duration::from_secs(2),
        &params,
    );

    assert_single_credential_arrival(&machine, Duration::from_millis(900));
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtAVPPHistoryWindow`
/// (`agreement/player_test.go:3821`).
///
/// The `AVPP` (votePresent-then-PP) analogue of
/// `player_retains_received_validated_at_pp_for_history_window`: feeds
/// `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY + credentialRoundLag` rounds'
/// worth of standalone-vote-then-compound-message proposal-votes with
/// increasing timestamps, asserting the circular buffer retains only the
/// most recent `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY` samples.
#[test]
fn player_retains_received_validated_at_avpp_history_window() {
    let r = Round(20239);
    let p = Period(0);
    let params = stock_params();
    let history_len = algo_agreement::DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY;
    let cred_lag = credential_round_lag();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);

    for i in 0..(history_len as u64 + cred_lag) {
        let round = Round(r.0 + i - 1);
        let proposal = make_random_proposal_payload(round);
        let value = proposal.unauthenticated_proposal.value();

        let vote = send_vote_present(&mut machine, &mut helper, 0, round, p, value);

        let timestamp = 500 + i;
        send_vote_verified_for_vote(
            &mut machine,
            vote.clone(),
            round,
            Duration::from_millis(timestamp),
            HashMap::new(),
            i + 1,
        );

        send_compound_message_for_vote(
            &mut machine,
            vote,
            round,
            &proposal,
            Duration::from_secs(1),
            HashMap::new(),
        );

        move_to_round(
            &mut machine,
            &mut helper,
            Round(round.0 + 1),
            p,
            &proposal,
            value,
            Duration::from_secs(2),
            &params,
        );
    }

    let history = &machine.player().lowest_credential_arrivals;
    assert!(history.is_full(), "history should be full");
    for i in 0..history_len {
        let expected_ms = 500 + i as u64;
        assert_eq!(
            history.raw_history()[i],
            Duration::from_millis(expected_ms),
            "history[{i}] mismatch"
        );
    }
}
