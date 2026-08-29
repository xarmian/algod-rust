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

// Regression tests for issue #497: a verified vote bundle must actually
// deliver its authenticated votes into the vote-tracking state machines.
//
// go-algorand's `unauthenticatedBundle.verify` (agreement/bundle.go:141)
// returns a `bundle` carrying the *authenticated* `Votes []vote`, and
// `voteAggregator.handle` (bundleVerified arm, agreement/voteAggregator.go)
// replays each of those votes into the voteTracker so the threshold the
// bundle proves is observed locally. It also rejects any bundle whose
// verified weight does not reach the step's quorum
// (agreement/bundle.go:263 "bundle: did not see enough votes").
//
// algod-rust's `verify_bundle_impl` verified each vote but returned the
// original message unchanged — the authenticated votes were dropped on the
// floor, `verified_bundle_votes` stayed empty, and the vote aggregator's
// BundleVerified arm replayed nothing. Every recovery bundle (e.g. the
// next-vote bottom bundle go-algorand re-broadcasts from
// `player.partitionPolicy` during partition recovery) was then discarded as
// "failed to cause a significant state change", so a Rust node that missed
// the individual next-votes could never observe the next-threshold and never
// left its period: the exact 3-Go/3-Rust 50/50 liveness failure of #497.

#![deny(unsafe_code)]

// The shared simulate test-support module carries more machinery than this
// test consumes (the full service driver, clocks, networks) — silence the
// per-binary dead-code lint the unused parts would otherwise trip.
#[allow(dead_code, unused_imports)]
mod simulate;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use algo_agreement::crypto_verifier::AsyncCryptoVerifier;
use algo_agreement::events::{
    ConsensusVersionView, Event, EventType, InternalMessage, MessageEvent,
};
use algo_agreement::player::Player;
use algo_agreement::pseudonode::{AsyncPseudonode, Pseudonode};
use algo_agreement::router::RootRouter;
use algo_agreement::stubs::StubBlockFactory;
use algo_agreement::traits::{CryptoBundleRequest, CryptoVerifier, VOTE_BUNDLE_TAG};
use algo_agreement::{
    Period, Step, UnauthenticatedBundle, UnauthenticatedVote, Vote, VoteAuthenticator, BOTTOM, NEXT,
};
use algo_types::{ConsensusParams, Round};

use crate::simulate::test_account::generate_n_accounts;
use crate::simulate::test_factory::{signing_keys_from_accounts, TestKeyManager};
use crate::simulate::test_ledger::TestLedger;

fn v41_params() -> ConsensusParams {
    algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
        .expect("v41 params available")
}

/// Builds `n` accounts with real VRF/OTS keys, a ledger where they hold all
/// online stake, and one real, verifiable next-vote for `BOTTOM` at
/// `(round 1, period 0, step next)` per selected account.
///
/// Returns the ledger, the verified votes (with sortition credentials), and
/// their unauthenticated wire forms.
fn make_next_bottom_votes(
    n: usize,
    salt: u64,
) -> (TestLedger, Vec<Vote>, Vec<UnauthenticatedVote>) {
    make_next_votes(n, salt, BOTTOM)
}

fn make_next_votes(
    n: usize,
    salt: u64,
    proposal: algo_agreement::ProposalValue,
) -> (TestLedger, Vec<Vote>, Vec<UnauthenticatedVote>) {
    let params = v41_params();
    let accounts = generate_n_accounts(n, Round(0), Round(1000), 10_000, salt);
    let ledger = TestLedger::new(
        &accounts,
        1_000_000_000_000,
        params,
        algo_types::CONSENSUS_V41.to_string(),
    );

    let key_manager = TestKeyManager::new(&accounts);
    let (signing_keys, _addrs) = signing_keys_from_accounts(accounts);

    let mut pseudo = AsyncPseudonode::new(StubBlockFactory::default(), key_manager, ledger.clone());
    for (addr, keys) in signing_keys {
        pseudo.register_signing_keys(addr, keys);
    }

    let events = pseudo
        .make_votes(Round(1), Period(0), NEXT, proposal, None)
        .expect("make_votes for next step");

    let mut votes = Vec::new();
    let mut unauth = Vec::new();
    for ev in events {
        let v = ev.input.vote.expect("make_votes emits verified votes");
        votes.push(v);
        unauth.push(ev.input.unauthenticated_vote);
    }
    (ledger, votes, unauth)
}

fn bundle_from_votes(unauth: &[UnauthenticatedVote]) -> UnauthenticatedBundle {
    bundle_from_votes_for(unauth, BOTTOM)
}

fn bundle_from_votes_for(
    unauth: &[UnauthenticatedVote],
    proposal: algo_agreement::ProposalValue,
) -> UnauthenticatedBundle {
    UnauthenticatedBundle {
        round: Round(1),
        period: Period(0),
        step: NEXT,
        proposal,
        votes: unauth
            .iter()
            .map(|uv| VoteAuthenticator {
                sender: uv.raw_vote.sender,
                cred: uv.cred.clone(),
                sig: uv.sig.clone(),
            })
            .collect(),
        equivocation_votes: Vec::new(),
    }
}

fn verify_bundle_via(
    ledger: &TestLedger,
    ub: UnauthenticatedBundle,
) -> algo_agreement::traits::CryptoResult {
    let verifier = AsyncCryptoVerifier::new(Arc::new(ledger.clone()));
    verifier.verify_bundle(CryptoBundleRequest {
        message: InternalMessage {
            tag: VOTE_BUNDLE_TAG.to_string(),
            unauthenticated_bundle: ub,
            ..InternalMessage::default()
        },
        task_index: 0,
        round: Round(1),
        period: Period(0),
        certify: false,
    });
    verifier
        .verified(VOTE_BUNDLE_TAG)
        .recv_timeout(Duration::from_secs(30))
        .expect("bundle verification result")
}

/// Go parity (agreement/bundle.go:230-272): a successfully verified bundle
/// must hand the *authenticated* votes back so the vote aggregator can
/// replay them into the vote tracker. Before the #497 fix the result's
/// `verified_bundle_votes` was always empty.
#[test]
fn verified_bundle_carries_authenticated_votes() {
    let (ledger, votes, unauth) = make_next_bottom_votes(6, 0x497);
    assert!(
        !votes.is_empty(),
        "sortition must select at least one account"
    );

    let params = v41_params();
    let total_weight: u64 = votes.iter().map(|v| v.cred.weight).sum();
    assert!(
        NEXT.reaches_quorum(&params, total_weight),
        "test precondition: all-stake votes must reach the next quorum \
         (got weight {total_weight})"
    );

    let result = verify_bundle_via(&ledger, bundle_from_votes(&unauth));
    assert!(
        result.err.is_none(),
        "quorum bundle must verify: {:?}",
        result.err
    );

    let out = &result.message.verified_bundle_votes;
    assert_eq!(
        out.len(),
        unauth.len(),
        "verified bundle must carry every authenticated vote \
         (Go returns bundle.Votes from unauthenticatedBundle.verify)"
    );
    // Each returned vote must carry its real sortition credential weight —
    // the weights are what the vote tracker sums toward the threshold.
    let mut by_sender: HashMap<_, _> = votes
        .iter()
        .map(|v| (v.raw_vote.sender, v.cred.weight))
        .collect();
    for v in out {
        let expected = by_sender
            .remove(&v.raw_vote.sender)
            .expect("returned vote matches an input sender exactly once");
        assert_eq!(
            v.cred.weight, expected,
            "authenticated weight must match the vote's credential"
        );
        assert_eq!(v.raw_vote.step, NEXT);
        assert_eq!(v.raw_vote.proposal, BOTTOM);
    }
}

/// Go parity (agreement/bundle.go:263): a bundle whose verified weight does
/// not reach the step's quorum must be REJECTED at verification
/// ("bundle: did not see enough votes"). Before the #497 fix algod-rust
/// accepted such bundles (no weight accounting at all).
#[test]
fn under_quorum_bundle_is_rejected() {
    let (ledger, votes, unauth) = make_next_bottom_votes(6, 0x498);
    assert!(votes.len() >= 2, "need at least two selected voters");

    // A single vote cannot reach the next-step quorum on its own.
    let one = &unauth[..1];
    let params = v41_params();
    assert!(
        !NEXT.reaches_quorum(&params, votes[0].cred.weight),
        "test precondition: one voter must be under the quorum"
    );

    let result = verify_bundle_via(&ledger, bundle_from_votes(one));
    assert!(
        result.err.is_some(),
        "bundle under the step quorum must fail verification \
         (Go: 'bundle: did not see enough votes')"
    );
}

/// End-to-end liveness pin for #497: a player deep in next-vote recovery
/// (round 1, period 0, step next+5) that receives a *verified* bottom
/// next-vote bundle proving a (1, 0, next) quorum must observe the
/// nextThreshold and enter period 1 — exactly what go-algorand does when
/// `partitionPolicy` re-broadcasts the freshest bundle to a lagging peer.
#[test]
fn verified_bundle_advances_player_period() {
    let (ledger, votes, unauth) = make_next_bottom_votes(6, 0x499);
    let params = v41_params();
    let total_weight: u64 = votes.iter().map(|v| v.cred.weight).sum();
    assert!(
        NEXT.reaches_quorum(&params, total_weight),
        "test precondition: all-stake votes must reach the next quorum"
    );

    // Run the real crypto-verifier bundle path to produce the
    // BundleVerified message exactly as the demux would deliver it.
    let result = verify_bundle_via(&ledger, bundle_from_votes(&unauth));
    assert!(result.err.is_none(), "bundle verifies: {:?}", result.err);

    let mut player = Player {
        round: Round(1),
        period: Period(0),
        step: Step(8), // next+5 — deep in recovery, like the live repro
        ..Player::default()
    };
    let mut router = RootRouter::new(&player);

    let event = Event::Message(MessageEvent {
        t: EventType::BundleVerified,
        input: result.message,
        proto: ConsensusVersionView {
            err: None,
            version: algo_types::CONSENSUS_V41.to_string(),
        },
        ..MessageEvent::default()
    });

    let actions = player.handle(&mut router, event, &params);

    assert_eq!(
        player.period,
        Period(1),
        "player must enter period 1 after observing the bundle's \
         next-bottom threshold (actions: {})",
        actions.len()
    );
}

/// Go parity for the next-threshold *status* the player consults
/// (`voteTrackerPeriod.Cached`, queried by `issueSoftVote` /
/// `issueNextVote` via `nextThresholdStatusRequestEvent`): after observing
/// a next-VALUE threshold for period 0 and entering period 1, the player's
/// period-1 soft vote must carry that value forward
/// (`player.issueSoftVote`: "did not see bottom: vote for our starting
/// value"). Before the #497 fix the player's `NextThresholdStatusRequest`
/// was routed to an empty mirror `VoteTrackerPeriod` (never fed by real
/// votes), so the carried value was always lost and the node went silent
/// at the soft step of every recovery period.
#[test]
fn value_threshold_carries_into_next_period_soft_vote() {
    use algo_agreement::ProposalValue;
    use algo_types::{Address, Digest};

    let value = ProposalValue {
        original_period: Period(0),
        original_proposer: Address([0x33; 32]),
        block_digest: Digest([0x44; 32]),
        encoding_digest: Digest([0x55; 32]),
    };
    let (ledger, votes, unauth) = make_next_votes(6, 0x49a, value);
    let params = v41_params();
    let total_weight: u64 = votes.iter().map(|v| v.cred.weight).sum();
    assert!(
        NEXT.reaches_quorum(&params, total_weight),
        "test precondition: all-stake votes must reach the next quorum"
    );

    let result = verify_bundle_via(&ledger, bundle_from_votes_for(&unauth, value));
    assert!(result.err.is_none(), "bundle verifies: {:?}", result.err);

    let mut player = Player {
        round: Round(1),
        period: Period(0),
        step: Step(8),
        ..Player::default()
    };
    let mut router = RootRouter::new(&player);

    let event = Event::Message(MessageEvent {
        t: EventType::BundleVerified,
        input: result.message,
        proto: ConsensusVersionView {
            err: None,
            version: algo_types::CONSENSUS_V41.to_string(),
        },
        ..MessageEvent::default()
    });
    let actions = player.handle(&mut router, event, &params);
    assert_eq!(
        player.period,
        Period(1),
        "entered period 1 on the value threshold"
    );
    // Entering a period via a next-VALUE threshold must repropose the value
    // (Go `player.enterPeriod`: pseudonodeAction{T: repropose, ...}).
    assert!(
        actions.iter().any(|a| matches!(
            a,
            algo_agreement::Action::Pseudonode(pa)
                if pa.t == algo_agreement::ActionType::Repropose && pa.proposal == value
        )),
        "period entry via value threshold must repropose the value"
    );

    // Fire the period-1 soft (filter) timeout: the soft vote must carry the
    // period-0 next-threshold value.
    let timeout = Event::Timeout(algo_agreement::TimeoutEvent {
        t: EventType::Timeout,
        random_entropy: 7,
        round: Round(1),
        proto: ConsensusVersionView {
            err: None,
            version: algo_types::CONSENSUS_V41.to_string(),
        },
    });
    let actions = player.handle(&mut router, timeout, &params);
    let soft_attest = actions.iter().find_map(|a| match a {
        algo_agreement::Action::Pseudonode(pa)
            if pa.t == algo_agreement::ActionType::Attest && pa.step == algo_agreement::SOFT =>
        {
            Some(pa.proposal)
        }
        _ => None,
    });
    assert_eq!(
        soft_attest,
        Some(value),
        "period-1 soft vote must carry the period-0 next-threshold value \
         (Go issueSoftVote nextStatus branch)"
    );
}

/// Go parity for `player.partitionPolicy`: a partitioned player
/// (step >= partitionStep) must re-broadcast the freshest bundle it has
/// seen so lagging peers can resynchronize. Before the #497 fix the
/// player's `FreshestBundleRequest` was routed to an empty mirror
/// `VoteTrackerRound`, so algod-rust never re-broadcast any bundle and
/// could not help a desynchronized cluster converge.
#[test]
fn partitioned_player_rebroadcasts_freshest_bundle() {
    let (ledger, votes, unauth) = make_next_bottom_votes(6, 0x49b);
    let params = v41_params();
    let total_weight: u64 = votes.iter().map(|v| v.cred.weight).sum();
    assert!(NEXT.reaches_quorum(&params, total_weight));

    let result = verify_bundle_via(&ledger, bundle_from_votes(&unauth));
    assert!(result.err.is_none(), "bundle verifies: {:?}", result.err);

    let mut player = Player {
        round: Round(1),
        period: Period(0),
        step: Step(8),
        ..Player::default()
    };
    let mut router = RootRouter::new(&player);

    let event = Event::Message(MessageEvent {
        t: EventType::BundleVerified,
        input: result.message,
        proto: ConsensusVersionView {
            err: None,
            version: algo_types::CONSENSUS_V41.to_string(),
        },
        ..MessageEvent::default()
    });
    player.handle(&mut router, event, &params);
    assert_eq!(player.period, Period(1));

    // Push the player deep into recovery again (partitioned), napping so the
    // next timeout issues a next-vote (whose partitionPolicy runs).
    player.step = Step(8);
    player.napping = true;
    let timeout = Event::Timeout(algo_agreement::TimeoutEvent {
        t: EventType::Timeout,
        random_entropy: 7,
        round: Round(1),
        proto: ConsensusVersionView {
            err: None,
            version: algo_types::CONSENSUS_V41.to_string(),
        },
    });
    let actions = player.handle(&mut router, timeout, &params);
    assert!(
        actions.iter().any(|a| matches!(
            a,
            algo_agreement::Action::Network(na)
                if na.t == algo_agreement::ActionType::Broadcast
                    && na.tag == VOTE_BUNDLE_TAG
        )),
        "partitioned player must re-broadcast the freshest bundle \
         (Go partitionPolicy); actions: {}",
        actions.len()
    );
}
