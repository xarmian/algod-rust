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

// Direct-`Player` harness with REAL VRF/OTS-signed accounts and a REAL
// sortition-aware ledger — no `Service`, no threads, no network.
//
// Mirrors go-algorand `agreement/player_test.go`'s `testPlayerSetup` /
// `readOnlyFixture10` / `testBlockFactory` harness (issue #825, theme 1
// remainder). That harness is structurally distinct from the
// `setupP`/`IoAutomataConcretePlayer` harness already ported in
// `player_edge_cases_test.rs`/`player_permutation.rs`: `setupP` drives the
// `Player` with *fabricated* votes/proposals (`VoteMakerHelper`, arbitrary
// digests, no real credentials), while `testPlayerSetup` drives it with
// votes/proposals from `N` REAL accounts (real VRF credentials, real OTS
// signatures, real sortition against a real stake ledger) — exactly what
// `TestPlayerSynchronous`/`TestPlayerOffsetStart`/`TestPlayerLateBlockProposalPeriod0`
// need, since they assert on which value wins via lowest-credential
// tie-breaking among genuinely-selected proposers.
//
// Rather than duplicating go's package-private `readOnlyFixture10`/
// `makeProposalsTesting`/`makeVotesTesting` (which reach into
// `proposalForBlock`/`makeVote`, private free functions in
// `src/pseudonode.rs`), this harness reuses the ALREADY-PUBLIC
// `Pseudonode` trait (`AsyncPseudonode::make_proposals`/`make_votes`) —
// plain synchronous functions returning `Vec<MessageEvent>` directly, no
// channels or threads involved despite the "Async" name — plus the
// existing full-consensus simulate harness's `TestAccount`/`TestLedger`/
// `TestKeyManager`/`AutoBlockFactory` (`tests/simulate/`), which already
// provide real VRF/OTS accounts and a real sortition-aware ledger for the
// 5-node `Service`-level harness. No production-code changes were needed:
// `Pseudonode::make_proposals`/`make_votes` and `RootRouter::submit_top`
// were already `pub` and already synchronous.
//
// One real account per every eligible participant is registered on a
// SINGLE `AsyncPseudonode`, mirroring go's `testAccountData` (which holds
// all 10 accounts' addresses/VRF/OTS secrets so `makeProposalsTesting`/
// `makeVotesTesting` can fabricate a network's worth of messages from a
// single call) — the pseudonode here plays the role of "the rest of the
// committee", not the SUT. The `Player` + `RootRouter` under test never
// signs anything themselves; they only ever receive already-verified
// `voteVerified`/`payloadVerified`/timeout events via `submit_top`, exactly
// like go's `router.submitTop(&playerTracer, *player, e)`.

#[allow(dead_code, unused_imports)]
mod simulate;

use algo_agreement::{
    Action, ActionType, AsyncPseudonode, ConsensusVersionView, CredentialArrivalHistory, Event,
    EventType, LedgerWriter, MessageEvent, Player, ProposalValue, Pseudonode, RootRouter,
    TimeoutEvent, BOTTOM, CERT, DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY, SOFT,
};
use algo_types::{ConsensusParams, Round, CONSENSUS_V41};

use simulate::test_account::generate_n_accounts;
use simulate::test_factory::{signing_keys_from_accounts, AutoBlockFactory, TestKeyManager};
use simulate::test_ledger::TestLedger;

/// Namespacing salt for `generate_n_accounts`, matching the convention in
/// `simulate/setup_agreement.rs` — keeps repeated calls across tests (or
/// within loops) from colliding on VRF-derived addresses.
fn rand_salt() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0xB01D);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn proto_view() -> ConsensusVersionView {
    ConsensusVersionView {
        err: None,
        version: CONSENSUS_V41.to_string(),
    }
}

/// Everything `testPlayerSetup` returns: the real `Player` + `RootRouter`
/// under test, the consensus params driving `submit_top`, a handle to the
/// real ledger (for `EnsureBlock`), and the single `AsyncPseudonode`
/// fabricating real committee messages from 10 real accounts.
///
/// Mirrors go's `testPlayerSetup() (player, rootRouter, testAccountData,
/// testBlockFactory, Ledger)` — `testAccountData`/`testBlockFactory` are
/// folded into the `pseudonode` field here since `Pseudonode::make_proposals`/
/// `make_votes` already combine "which accounts" with "which block factory".
struct RealPlayerHarness {
    player: Player,
    router: RootRouter,
    params: ConsensusParams,
    ledger: TestLedger,
    pseudonode: AsyncPseudonode<AutoBlockFactory, TestKeyManager, TestLedger>,
}

/// Mirrors go's `testPlayerSetup()`. 10 accounts (go's `readOnlyFixture10`),
/// each with real VRF + OTS keys, all online with equal stake.
fn test_player_setup() -> RealPlayerHarness {
    let consensus_version = CONSENSUS_V41;
    let params: ConsensusParams =
        algo_types::consensus::consensus_params_for_version(consensus_version)
            .expect("v41 consensus params available");

    let accounts = generate_n_accounts(10, Round(0), Round(1000), 10_000, rand_salt());
    let ledger = TestLedger::new(
        &accounts,
        1_000_000_000_000,
        params.clone(),
        consensus_version.to_string(),
    );

    let key_manager = TestKeyManager::new(&accounts);
    let (signing_keys, _addresses) = signing_keys_from_accounts(accounts);

    let mut pseudonode = AsyncPseudonode::new(AutoBlockFactory, key_manager, ledger.clone());
    for (address, keys) in signing_keys {
        pseudonode.register_signing_keys(address, keys);
    }

    let round = ledger.next_round();
    let period = algo_agreement::Period(0);
    let player = Player {
        round,
        period,
        step: SOFT,
        lowest_credential_arrivals: CredentialArrivalHistory::new(
            DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
        ),
        ..Player::default()
    };
    let router = RootRouter::new(&player);

    RealPlayerHarness {
        player,
        router,
        params,
        ledger,
        pseudonode,
    }
}

/// Submit one event to the player under test, mirroring go's
/// `*player, res = router.submitTop(&playerTracer, *player, e)`.
fn submit(h: &mut RealPlayerHarness, e: Event) -> Vec<Action> {
    let player = std::mem::take(&mut h.player);
    let (player, actions) = h.router.submit_top(player, e, &h.params, None);
    h.player = player;
    actions
}

fn make_timeout_event() -> Event {
    Event::Timeout(TimeoutEvent {
        t: EventType::Timeout,
        random_entropy: 7,
        round: Round(0),
        proto: proto_view(),
    })
}

/// Mirrors go's `generateProposalEvents`: ask the pseudonode (playing the
/// role of "the rest of the committee") for every real proposal + its
/// proposal-vote at the player's current `(round, period)`, split the
/// interleaved vote/payload events go's code keeps as two aligned slices,
/// and compute the lowest-credential proposal exactly like go's
/// `vote.Cred.Less` scan.
fn generate_proposal_events(h: &mut RealPlayerHarness) -> (Vec<Event>, Vec<Event>, ProposalValue) {
    let events: Vec<MessageEvent> = h
        .pseudonode
        .make_proposals(h.player.round, h.player.period)
        .unwrap_or_default();

    let mut vote_batch = Vec::new();
    let mut payload_batch = Vec::new();
    let mut lowest: Option<(algo_agreement::Credential, ProposalValue)> = None;

    for me in events {
        match me.t {
            EventType::VoteVerified => {
                if let Some(vote) = me.input.vote.clone() {
                    let better = match &lowest {
                        None => true,
                        Some((cred, _)) => vote.cred.less(cred),
                    };
                    if better {
                        lowest = Some((vote.cred.clone(), vote.raw_vote.proposal));
                    }
                }
                vote_batch.push(Event::Message(me));
            }
            EventType::PayloadVerified => {
                payload_batch.push(Event::Message(me));
            }
            _ => {}
        }
    }

    let lowest_proposal = lowest.map(|(_, p)| p).unwrap_or(BOTTOM);
    (vote_batch, payload_batch, lowest_proposal)
}

/// Mirrors go's `generateVoteEvents`: ask the pseudonode for every real
/// account's vote at `(round, period, step, proposal)`.
fn generate_vote_events(
    h: &mut RealPlayerHarness,
    step: algo_agreement::Step,
    proposal: ProposalValue,
) -> Vec<Event> {
    h.pseudonode
        .make_votes(h.player.round, h.player.period, step, proposal, None)
        .unwrap_or_default()
        .into_iter()
        .map(Event::Message)
        .collect()
}

/// Mirrors go's `simulateProposals`: submit each proposal-vote/payload pair
/// in lockstep and assert the payload submission produces the exact same
/// number and types of actions as the vote submission did (go's
/// `len(res) != len(earlier)` / `res[i].t() != earlier[i].t()` panics).
fn simulate_proposals(
    h: &mut RealPlayerHarness,
    vote_batch: Vec<Event>,
    payload_batch: Vec<Event>,
) {
    assert_eq!(
        vote_batch.len(),
        payload_batch.len(),
        "vote/payload batch length mismatch"
    );
    for (ve, pe) in vote_batch.into_iter().zip(payload_batch) {
        let earlier = submit(h, ve);
        let res = submit(h, pe);
        assert_eq!(
            res.len(),
            earlier.len(),
            "proposal action mismatch: payload submission produced a different action count"
        );
        for (a, b) in res.iter().zip(earlier.iter()) {
            assert_eq!(
                a.action_type(),
                b.action_type(),
                "proposal action mismatch: payload submission produced a different action type"
            );
        }
    }
}

/// Mirrors go's `simulateTimeoutExpectSoft`: firing the filter timeout with
/// a real proposal on hand should attest exactly one soft vote for it, and
/// the player should not be napping afterward.
fn simulate_timeout_expect_soft(h: &mut RealPlayerHarness, expected: ProposalValue) {
    let res = submit(h, make_timeout_event());
    assert_eq!(res.len(), 1, "wrong number of actions on filter timeout");
    match &res[0] {
        Action::Pseudonode(a) => {
            assert_eq!(a.t, ActionType::Attest, "action is not attest");
            assert_eq!(a.proposal, expected, "bad soft vote");
            assert_eq!(a.step, SOFT, "bad soft step");
        }
        other => panic!("expected a pseudonode attest action, got {other:?}"),
    }
    assert!(!h.player.napping, "player is napping");
}

/// Mirrors go's `simulateSoftExpectAttest`: submitting the whole batch of
/// real soft votes for the winning proposal should yield exactly one
/// cert-vote attestation (soft-threshold reached).
fn simulate_soft_expect_attest(
    h: &mut RealPlayerHarness,
    expected: ProposalValue,
    batch: Vec<Event>,
) {
    let mut soft_actions = Vec::new();
    for e in batch {
        soft_actions.extend(submit(h, e));
    }

    let attests: Vec<_> = soft_actions
        .iter()
        .filter(|a| a.action_type() == ActionType::Attest)
        .collect();
    assert_eq!(attests.len(), 1, "expected exactly one cert attestation");
    match attests[0] {
        Action::Pseudonode(a) => {
            assert_eq!(a.proposal, expected, "bad cert vote");
            assert_eq!(a.step, CERT, "not cert step");
        }
        other => panic!("expected a pseudonode attest action, got {other:?}"),
    }
}

/// Mirrors go's `simulateCertExpectEnsureAssemble`: submitting the whole
/// batch of real cert votes for the winning proposal should yield exactly
/// one `ensure` action (certifying the block) followed by exactly one
/// `assemble` action (moving on to propose the next round).
fn simulate_cert_expect_ensure_assemble(
    h: &mut RealPlayerHarness,
    expected: ProposalValue,
    batch: Vec<Event>,
) -> algo_agreement::EnsureAction {
    let mut cert_actions = Vec::new();
    for e in batch {
        cert_actions.extend(submit(h, e));
    }

    let mut ensure: Option<algo_agreement::EnsureAction> = None;
    let mut ensure_index: Option<usize> = None;
    let mut assembles_sent = 0usize;
    let mut assemble_after = false;

    for (i, a) in cert_actions.iter().enumerate() {
        match a {
            Action::Ensure(ea) => {
                assert!(ensure.is_none(), "sent too many ensures");
                assert_eq!(ea.certificate.proposal, expected, "bad ensure certificate");
                assert_eq!(
                    ea.payload.unauthenticated_proposal.block_digest(),
                    expected.block_digest,
                    "bad ensure digest"
                );
                ensure = Some((**ea).clone());
                ensure_index = Some(i);
            }
            Action::Pseudonode(pa) if pa.t == ActionType::Assemble => {
                assembles_sent += 1;
                if let Some(ei) = ensure_index {
                    if i >= ei {
                        assemble_after = true;
                    }
                }
            }
            _ => {}
        }
    }

    let ensure = ensure.expect("no ensures sent");
    assert_eq!(assembles_sent, 1, "expected exactly one assemble");
    assert!(assemble_after, "assemble not after ensure");
    ensure
}

/// Mirrors go's `simulateSingleSynchronousRound`: a full, uncontested round
/// — every real account proposes, the lowest credential wins, soft and
/// cert thresholds are reached in period 0, and the resulting block is
/// committed to the ledger.
fn simulate_single_synchronous_round(h: &mut RealPlayerHarness) {
    let (vote_batch, payload_batch, lowest_proposal) = generate_proposal_events(h);
    let soft_batch = generate_vote_events(h, SOFT, lowest_proposal);
    let cert_batch = generate_vote_events(h, CERT, lowest_proposal);

    simulate_proposals(h, vote_batch, payload_batch);
    simulate_timeout_expect_soft(h, lowest_proposal);
    simulate_soft_expect_attest(h, lowest_proposal, soft_batch);

    let act = simulate_cert_expect_ensure_assemble(h, lowest_proposal, cert_batch);
    h.ledger.ensure_block(
        &act.payload.unauthenticated_proposal.block,
        &act.certificate,
    );
}

/// Port of go-algorand's `TestPlayerSynchronous`
/// (`agreement/player_test.go:430`) — the real, uncontested happy path: 20
/// consecutive rounds, each with real proposals from 10 real VRF/OTS
/// accounts, real sortition selecting the lowest credential, real soft/cert
/// vote quorums, and a real block committed to the ledger every round.
///
/// This is the first of theme 1's three remaining named scenarios
/// (`TestPlayerOffsetStart`/`TestPlayerLateBlockProposalPeriod0` are the
/// other two) landed against the newly-built `testPlayerSetup`-equivalent
/// harness above. No `Player`/`Service` divergence was found: the real
/// state machine reaches soft/cert threshold and re-enters the next round
/// exactly as go's version asserts, every one of the 20 rounds, across
/// repeated runs.
#[test]
fn player_synchronous_twenty_rounds() {
    let mut h = test_player_setup();
    let start_round = h.player.round;

    for i in 0..20u64 {
        simulate_single_synchronous_round(&mut h);
        assert_eq!(
            h.player.round,
            Round(start_round.0 + i + 1),
            "player did not advance to the next round after committing"
        );
        assert_eq!(
            h.player.period,
            algo_agreement::Period(0),
            "player did not reset to period 0 after committing"
        );
    }
    assert_eq!(h.ledger.next_round(), Round(start_round.0 + 20));
}
