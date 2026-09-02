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

// Player-integration tests for `player.lowestCredentialArrivals` retention
// across periods/rounds — Phase 17 issue #825, theme 2
// ("Credential-arrival-history retention across periods").
//
// Mirrors a subset of go-algorand's fourteen
// `TestPlayerRetains*ReceivedValidatedAt*` scenarios
// (`agreement/player_test.go:3240-3859`). The underlying
// `CredentialArrivalHistory` data structure already has thorough unit
// coverage in `types.rs`; these tests exercise it end-to-end through the
// real `Player` state machine (`player.update_credential_arrival_history`),
// which is the part issue #825 flagged as untested.
//
// Ported scenarios (see also `docs/phase17/parity_agreement.md`):
// - `TestPlayerRetainsReceivedValidatedAtCredentialHistory`
// - `TestPlayerRetainsEarlyReceivedValidatedAtOneSample`
// - `TestPlayerRetainsLateReceivedValidatedAtOneSample`
// - `TestPlayerRetainsReceivedValidatedAtForHistoryWindow`
// - `TestPlayerRetainsReceivedValidatedAtForHistoryWindowLateBetter`
//
// Not ported in this pass (left open — see issue #825's tracked remainder):
// the `PP`/`AVPP` compound-message variants (require `votePresent`/tail
// wiring beyond this pass's scope) and every `assertPayloadTimings`
// `receivedAt` check (requires `UnauthenticatedProposal.received_at`, which
// algod-rust does not yet have — see `test_support::credential_history`'s
// module doc for the exact gap).

use std::collections::HashMap;
use std::time::Duration;

use algo_agreement::test_support::{
    assert_single_credential_arrival, make_random_proposal_payload, move_to_round,
    override_consensus_with_dynamic_filter, send_payload_present, send_vote_verified,
    send_vote_verified_for_vote, setup_p,
};
use algo_agreement::types::credential_round_lag;
use algo_agreement::{Period, PIPELINED_MESSAGE_TIMESTAMP, SOFT};
use algo_types::{ConsensusParams, Round};

/// Stock (non-dynamic-filter) V41 params, matching Go's default
/// `protocol.ConsensusCurrentVersion` fixture for these tests.
fn test_params() -> ConsensusParams {
    override_consensus_with_dynamic_filter(false).params
}

/// Mirrors Go's `TestPlayerRetainsReceivedValidatedAtCredentialHistory`
/// (`agreement/player_test.go:3262`).
///
/// Advances the player one round at a time from `r - credentialRoundLag - 1`
/// up to `r`, feeding a `voteVerified` proposal-vote with an
/// increasing-by-1ms `validated_at` timestamp each round. Asserts that once
/// round `r` concludes, `lowest_credential_arrivals` holds exactly the
/// sample recorded `credentialRoundLag` rounds ago (501ms — the *first*
/// round's timestamp), proving `update_credential_arrival_history` reads
/// the correct historical round rather than always short-circuiting to
/// zero.
#[test]
fn player_retains_received_validated_at_credential_history() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - cred_lag - 1), p, SOFT, &params);

    let mut vote_verified_timing = Duration::from_millis(501);
    let mut payload_verified_timing = Duration::from_millis(2001);

    let mut rnd = r.0 - cred_lag - 1;
    while rnd < r.0 - 1 {
        let round = Round(rnd);
        let proposal = make_random_proposal_payload(round);
        let value = proposal.unauthenticated_proposal.value();

        send_vote_verified(
            &mut machine,
            &mut helper,
            0,
            round,
            round,
            p,
            value,
            vote_verified_timing,
            HashMap::new(),
        );
        send_payload_present(&mut machine, &proposal);
        move_to_round(
            &mut machine,
            &mut helper,
            Round(rnd + 1),
            p,
            &proposal,
            value,
            payload_verified_timing,
            &params,
        );

        vote_verified_timing += Duration::from_millis(1);
        payload_verified_timing += Duration::from_millis(1);
        rnd += 1;
    }

    // Final round: r-1 -> r.
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
        Duration::from_millis(600),
        HashMap::new(),
    );
    send_payload_present(&mut machine, &proposal);
    move_to_round(
        &mut machine,
        &mut helper,
        r,
        p,
        &proposal,
        value,
        Duration::from_millis(2500),
        &params,
    );

    // The player looks up arrival times from credentialRoundLag rounds ago,
    // so only the very first round's 501ms sample should have landed in
    // lowest_credential_arrivals.
    assert_single_credential_arrival(&machine, Duration::from_millis(501));
}

/// Mirrors Go's `TestPlayerRetainsEarlyReceivedValidatedAtOneSample`
/// (`agreement/player_test.go:3301`).
///
/// A proposal-vote for round `r - credentialRoundLag - 1` arrives
/// "pipelined" — one round before the player has even reached
/// `r - credentialRoundLag - 2` — so it should be timestamped with
/// `PIPELINED_MESSAGE_TIMESTAMP` rather than a real clock reading.
#[test]
fn player_retains_early_received_validated_at_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);

    // Vote for round r-credentialRoundLag-1, submitted while the player is
    // still at r-1 (i.e. "early" relative to its own round).
    let early_round = Round(r.0 - cred_lag - 1);
    let early_proposal = make_random_proposal_payload(early_round);
    let early_value = early_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - cred_lag - 2),
        early_round,
        p,
        early_value,
        Duration::from_millis(401),
        HashMap::new(),
    );

    // Vote + payload for r-1, driving the player from r-1 to r.
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
    send_payload_present(&mut machine, &proposal);
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

    assert_single_credential_arrival(&machine, PIPELINED_MESSAGE_TIMESTAMP);
}

/// Mirrors Go's `TestPlayerRetainsLateReceivedValidatedAtOneSample`
/// (`agreement/player_test.go:3339`).
///
/// A proposal-vote for round `r - credentialRoundLag - 1` arrives *late*
/// (processed as if the player were already at `r-1`), so its recorded
/// timing must come from that round's own historical clock (900ms), not
/// from the player's live clock at the time it was processed.
#[test]
fn player_retains_late_received_validated_at_one_sample() {
    let r = Round(20239);
    let p = Period(0);
    let cred_lag = credential_round_lag();
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);

    let early_round = Round(r.0 - cred_lag - 1);
    let mut historical_clocks = HashMap::new();
    historical_clocks.insert(early_round, Duration::from_millis(900));

    let early_proposal = make_random_proposal_payload(early_round);
    let early_value = early_proposal.unauthenticated_proposal.value();
    send_vote_verified(
        &mut machine,
        &mut helper,
        0,
        Round(r.0 - 1),
        early_round,
        p,
        early_value,
        Duration::from_millis(401),
        historical_clocks,
    );

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
    send_payload_present(&mut machine, &proposal);
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

    assert_single_credential_arrival(&machine, Duration::from_millis(900));
}

/// Shared body for `TestPlayerRetainsReceivedValidatedAtForHistoryWindow`
/// and its `LateBetter` variant (`agreement/player_test.go:3384`).
///
/// Feeds `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY + credentialRoundLag`
/// rounds' worth of proposal-votes with increasing timestamps and asserts
/// only the most recent `DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY` samples
/// survive in the circular buffer (the oldest ones are evicted).
///
/// When `add_better_late` is set, a second, cryptographically "better"
/// (lower-`VrfOut`) vote for the same round arrives *after* the first —
/// this vote should win and its timestamp (`600+i` ms) should be the one
/// retained, superseding the first vote's `500+i` ms sample.
fn run_history_window_scenario(add_better_late: bool) {
    let r = Round(20239);
    let p = Period(0);
    let params = test_params();
    let history_len = algo_agreement::DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY;
    let cred_lag = credential_round_lag();
    let (_player, mut machine, mut helper) = setup_p(Round(r.0 - 1), p, SOFT, &params);

    for i in 0..(history_len as u64 + cred_lag) {
        let round = Round(r.0 + i - 1);
        let proposal = make_random_proposal_payload(round);
        let value = proposal.unauthenticated_proposal.value();

        // First proposal-vote for this round, from sender index 0.
        let mut vote = helper.make_verified_vote(0, round, p, algo_agreement::PROPOSE, value);
        let timestamp = Duration::from_millis(500 + i);
        if add_better_late {
            // Give the first vote a deliberately "worse" credential so the
            // later one (sent below) wins the tie-break.
            vote.cred.vrf_out = algo_types::Digest([1u8; 32]);
        }
        send_vote_verified_for_vote(
            &mut machine,
            vote.clone(),
            round,
            timestamp,
            HashMap::new(),
            0,
        );

        send_payload_present(&mut machine, &proposal);
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

        if add_better_late {
            let mut better_vote =
                helper.make_verified_vote(1, round, p, algo_agreement::PROPOSE, value);
            better_vote.cred.vrf_out = algo_types::Digest([0u8; 32]);
            assert!(
                better_vote.cred.less(&vote.cred),
                "second vote must have the numerically better credential"
            );
            let better_timestamp = Duration::from_millis(600 + i);
            send_vote_verified_for_vote(
                &mut machine,
                better_vote,
                round,
                better_timestamp,
                HashMap::new(),
                0,
            );
        }
    }

    let history = &machine.player().lowest_credential_arrivals;
    assert!(
        history.is_full(),
        "history should be full after {} + credentialRoundLag rounds",
        history_len
    );
    for i in 0..history_len {
        let expected_ms = if add_better_late {
            600 + i as u64
        } else {
            500 + i as u64
        };
        assert_eq!(
            history.raw_history()[i],
            Duration::from_millis(expected_ms),
            "history[{i}] mismatch"
        );
    }
}

#[test]
fn player_retains_received_validated_at_for_history_window() {
    run_history_window_scenario(false);
}

#[test]
fn player_retains_received_validated_at_for_history_window_late_better() {
    run_history_window_scenario(true);
}
