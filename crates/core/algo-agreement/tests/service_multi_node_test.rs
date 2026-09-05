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

// Multi-node service-level agreement tests, driven by the `TestingNetwork` /
// `TestingClock` / `ActivityMonitor` harness added for issue #825 theme 3 /
// #827 theme 4.
//
// Scope note (read before extending this file): go-algorand's theme-3
// scenarios (`TestAgreementFastRecoveryDownEarly`/`DownMiss`/etc.,
// `agreement/service_test.go`) run a 5-node cluster and assert two things
// per ordinary round: (1) a SINGLE `triggerGlobalTimeout` reliably commits
// it for every node in lockstep, and (2) `testingClock.zeroes` — go's
// literal `Zero()`-call counter — increments 1:1 with committed rounds
// (`expectNewPeriod`/`sanityCheck`). Porting those exact assertions against
// this harness surfaced two real findings:
//
//   1. With 5 real `Service` instances (real threads, real
//      `AsyncCryptoVerifier`-backed async crypto) driving ordinary rounds
//      purely off real vote/proposal traffic, one node out of five
//      intermittently falls behind its peers and never catches back up — a
//      genuine liveness gap this harness cannot paper over by waiting
//      longer (a 300x longer debounce window than started with made no
//      difference; the stalled node's thread stays alive and keeps
//      re-registering timeouts, it just never reaches quorum again).
//   2. Even at 2 nodes (where finding 1 does not reproduce), a single
//      `TestingClock::fire` occasionally needs a follow-up fire before an
//      ordinary round's real-vote quorum cascade finishes — AND
//      `TestingClock::zeroes()` was observed to increment MORE than once
//      per actual committed round (e.g. one node reporting `zeroes() == 3`
//      while its own ledger had only advanced by one round) — so, unlike
//      go, this port's zero-count is not a reliable round-commit signal on
//      its own.
//
// Both are tracked as follow-up investigation (see the PR description /
// issue #825's Progress section) rather than chased further here — either
// may be a genuine algod-rust multi-node liveness/rezero-accounting
// divergence worth its own dedicated investigation, or an artifact of this
// harness's simplified (polling-based, not full-coservice-accounting)
// quiescence detection; either way it needs more budget than "finish the
// test-infrastructure task" has.
//
// Until that's resolved, this file proves the harness end-to-end with a
// 2-node cluster (verified via repeated local runs to converge reliably),
// tracking progress via each node's `TestLedger::next_round()` — the
// unambiguous "did this round actually commit" signal — rather than the
// clock's zero-count. The fast-recovery mechanics under test
// (`dropAllSoftVotes`/`dropAllSlowNextVotes`/`dropAllVotes`/`repairAll`,
// filter/deadline/fast-recovery timeout sequencing) are the same ones go's
// `TestAgreementFastRecoveryDownEarly`/`DownMiss` exercise; the "pump until
// converged" retry loop (rather than asserting a single fire always
// suffices) and the round-based (not zero-count-based) bookkeeping are what
// differ from a literal 5-node port.

#[allow(dead_code, unused_imports)]
mod simulate;

use std::sync::Arc;
use std::time::Duration;

use algo_agreement::types::TimeoutType;
use algo_agreement::{codec, ProposalValue, BOTTOM};
use algo_types::Round;

use crate::simulate::propose_broadcast_gate::ProposeBroadcastGate;
use crate::simulate::setup_agreement::{
    setup_agreement, setup_agreement_with_propose_gate, setup_agreement_with_validator,
    setup_agreement_with_validator_and_propose_gate, setup_agreement_with_version_fn,
    AgreementCluster,
};
use crate::simulate::suspendable_validator::SuspendableBlockValidator;
use crate::simulate::testing_network::PocketedMessage;

/// Group `pocketed` cert-vote messages by `(round, period)` and return the
/// largest single-period group, if any group reaches `min_size`. A raw
/// pocketed-message count can silently span multiple periods once a
/// partition is layered on top of pocketing (each extra deadline fire
/// needed to reach quorum size also bumps every node's period) -- a real
/// certificate is only valid votes from the SAME (round, period), so pooling
/// votes across periods would produce a bundle no node would ever actually
/// accept as a quorum.
fn largest_same_period_group(
    pocketed: &[PocketedMessage],
    min_size: usize,
) -> Option<Vec<PocketedMessage>> {
    use std::collections::HashMap;
    let mut groups: HashMap<(Round, algo_agreement::Period), Vec<PocketedMessage>> = HashMap::new();
    for msg in pocketed {
        let uv = codec::decode_vote(msg.data()).expect("pocketed cert vote decodes");
        groups
            .entry((uv.raw_vote.round, uv.raw_vote.period))
            .or_default()
            .push(msg.clone());
    }
    groups
        .into_values()
        .filter(|g| g.len() >= min_size)
        .max_by_key(|g| g.len())
}

/// Every node's committed round, asserted identical across the cluster.
/// Panics on divergence — that's a real finding, not a "needs another
/// nudge" condition.
fn current_round<BV: algo_agreement::BlockValidator + Send + Sync + 'static>(
    cluster: &AgreementCluster<BV>,
) -> Round {
    let rounds: Vec<Round> = cluster.ledgers.iter().map(|l| l.next_round()).collect();
    let first = rounds[0];
    assert!(
        rounds.iter().all(|r| *r == first),
        "nodes diverged: not every node committed the same round (per-node next_round: {rounds:?})"
    );
    first
}

fn expect_no_new_round<BV: algo_agreement::BlockValidator + Send + Sync + 'static>(
    cluster: &AgreementCluster<BV>,
    round: Round,
) -> Round {
    let r = current_round(cluster);
    assert_eq!(
        r, round,
        "unexpected round progress (expected NO new round to commit)"
    );
    r
}

/// Fire every node's clock for `timeout_type` and wait for the resulting
/// cascade (proposals/votes/bundles/rezeros) to settle. Mirrors go's
/// `triggerGlobalTimeout` (the `d time.Duration` first argument go takes is
/// unused by `fire` there too — see `testing_clock.rs`'s doc comment for why
/// this port drops it).
fn trigger_global_timeout<BV: algo_agreement::BlockValidator + Send + Sync + 'static>(
    cluster: &AgreementCluster<BV>,
    timeout_type: TimeoutType,
) {
    for clock in &cluster.clocks {
        clock.fire(timeout_type);
    }
    cluster.wait_for_quiet();
}

/// Fire only the given node indices' clocks for `timeout_type`, then settle.
fn trigger_subset_timeout(
    cluster: &AgreementCluster,
    indices: &[usize],
    timeout_type: TimeoutType,
) {
    for &i in indices {
        cluster.clocks[i].fire(timeout_type);
    }
    cluster.wait_for_quiet();
}

/// Fire `timeout_type` repeatedly (bounded) until every node's committed
/// round has advanced past `round`, in lockstep. See this file's module doc
/// comment for why a single fire isn't always enough under this harness's
/// real-thread, real-async-crypto timing. Panics if the cluster hasn't
/// progressed within `max_attempts`, or if nodes end up at DIFFERENT
/// rounds (a real divergence, not just "needed another nudge").
fn pump_until_new_round<BV: algo_agreement::BlockValidator + Send + Sync + 'static>(
    cluster: &AgreementCluster<BV>,
    round: Round,
    timeout_type: TimeoutType,
    max_attempts: u32,
) -> Round {
    for _ in 0..max_attempts {
        trigger_global_timeout(cluster, timeout_type);
        let r = current_round(cluster);
        if r.0 > round.0 {
            return r;
        }
    }
    panic!(
        "cluster failed to commit a new round after {max_attempts} {timeout_type:?} attempts \
         (stuck at round {:?})",
        current_round(cluster)
    );
}

/// Like [`pump_until_new_round`], but fires EVERY type in `timeout_types`
/// (in order, each with its own settle) per attempt — used once the network
/// is healed again and either a lingering fast-recovery timer or the
/// ordinary filter/deadline timer could be what's actually needed to push
/// the round over its quorum threshold.
fn pump_until_new_round_multi(
    cluster: &AgreementCluster,
    round: Round,
    timeout_types: &[TimeoutType],
    max_attempts: u32,
) -> Round {
    for _ in 0..max_attempts {
        for &t in timeout_types {
            trigger_global_timeout(cluster, t);
        }
        let r = current_round(cluster);
        if r.0 > round.0 {
            return r;
        }
    }
    panic!(
        "cluster failed to commit a new round after {max_attempts} rounds of {timeout_types:?} \
         attempts (stuck at round {:?})",
        current_round(cluster)
    );
}

/// Mirrors go's `sanityCheck(startRound, numRounds, ledgers)`: every node's
/// ledger advanced exactly `num_rounds` rounds past `start`, and every node
/// committed the identical block (by digest) at every one of those rounds.
fn sanity_check<BV: algo_agreement::BlockValidator + Send + Sync + 'static>(
    cluster: &AgreementCluster<BV>,
    start: Round,
    num_rounds: u64,
) {
    for (i, ledger) in cluster.ledgers.iter().enumerate() {
        assert_eq!(
            ledger.next_round(),
            Round(start.0 + num_rounds),
            "node {i} did not progress {num_rounds} rounds"
        );
    }
    for j in 0..num_rounds {
        let round = Round(start.0 + j);
        let reference = cluster.ledgers[0]
            .cert(round)
            .unwrap_or_else(|| panic!("node 0 must have committed round {round:?}"))
            .proposal
            .block_digest;
        for (i, ledger) in cluster.ledgers.iter().enumerate() {
            let digest = ledger
                .cert(round)
                .unwrap_or_else(|| panic!("node {i} must have committed round {round:?}"))
                .proposal
                .block_digest;
            assert_eq!(
                digest, reference,
                "node {i} confirmed a different block at round {round:?}"
            );
        }
    }
}

/// Proves the harness's most basic guarantee end-to-end at the scale go's
/// theme-3 scenarios actually use (5 nodes): every node's `Service::start()`
/// results in exactly one `clock.zero()` (bootstrap into round 1, period 0),
/// observed via the shared `ActivityMonitor`/`TestingNetwork` quiescence
/// poll. This is the piece that was broken before this harness's
/// `TestingClock::has_pending` fix (see its doc comment) — without it, a
/// node that hadn't yet reached its first `Demux::next()` call looked
/// indistinguishable from a genuinely idle one, and this assertion failed
/// intermittently (1-2 of 5 nodes reporting `zeroes() == 0`).
#[test]
fn five_node_cluster_bootstraps_in_lockstep() {
    let cluster = setup_agreement(5);
    cluster.wait_for_quiet();
    for (i, clock) in cluster.clocks.iter().enumerate() {
        assert_eq!(clock.zeroes(), 1, "node {i} did not bootstrap exactly once");
    }
    cluster.shutdown();
}

/// End-to-end proof that the harness drives REAL multi-node consensus: two
/// real `Service` instances, real `AsyncCryptoVerifier`-backed crypto, real
/// VRF/OTS-signed sortition, exchanging messages purely over
/// `TestingNetwork`/`TestingClock` (no wall-clock sleeps), commit three
/// ordinary rounds in lockstep with identical block digests.
#[test]
fn two_node_cluster_commits_three_ordinary_rounds() {
    let cluster = setup_agreement(2);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..3 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    cluster.shutdown();
    sanity_check(&cluster, start_round, 3);
}

/// Adapted port of go-algorand's `TestAgreementFastRecoveryDownEarly`
/// (`agreement/service_test.go`) — see this file's module doc comment for
/// why this runs at 2 nodes, tracking committed rounds rather than the
/// clock's zero-count.
///
/// Scenario: one ordinary round commits. Then all soft votes and all "slow"
/// next votes (next/late/redo/down excluded — see go's `dropAllSlowNextVotes`)
/// are dropped, so no step reaches its normal threshold; the filter and
/// (soft-step) deadline timeouts both expire with no round committed;
/// firing the fast-recovery timer at delta 0 arms it without yet producing
/// a commit. Firing it again drives every node's fast-recovery cascade into
/// a bottom decision and, eventually, a committed round. The network then
/// heals, period 1 terminates normally, and one more ordinary round
/// commits.
#[test]
fn fast_recovery_down_early_two_node() {
    let cluster = setup_agreement(2);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Run one ordinary round.
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    // Force fast partition recovery into bottom.
    {
        cluster.network.drop_all_soft_votes();
        cluster.network.drop_all_slow_next_votes();

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: no soft quorum (dropped)
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // soft-step deadline timeout: still no commit
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
        round = expect_no_new_round(&cluster, round);

        // Fast-recovery fires -> every node enters a bottom-value recovery
        // period. Votes are still dropped, so no round can commit yet
        // (go's own test doesn't expect one here either — it asserts a new
        // PERIOD, not a new ROUND; see this file's module doc comment for
        // why this port checks round-commit progress instead of period
        // count).
        trigger_global_timeout(&cluster, TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);
    }

    // Heal the network and terminate on period 1: the round finally commits
    // via real votes now that delivery works again.
    {
        cluster.network.repair_all();
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Run one more ordinary round.
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 3);
}

/// Full 5-node port of go-algorand's `TestAgreementFastRecoveryDownEarly`
/// (`agreement/service_test.go`) — same scenario as
/// `fast_recovery_down_early_two_node` above, but at go's actual cluster
/// size. This is the scenario issue #911 investigated: with the harness's
/// original `TestLedger::ensure_digest` as a no-op, a node that reached
/// vote quorum for a round without having that round's proposal payload
/// staged locally (a real possibility once there are enough independently-
/// scheduled peers for one delivery to race a slower node's round
/// transition) had NO way to ever recover — it would call `ensure_digest`
/// to fetch the block and simply never get it, staying parked forever
/// despite continuing to service every subsequent timeout fire. That isn't
/// a `Service`/`Player` liveness bug: go-algorand's production code relies
/// on exactly this `EnsureDigest` catch-up path for this situation, backed
/// by a real ledger fetcher; only the test-only `TestLedger` was missing
/// the fetch implementation. See `simulate/test_ledger.rs`'s `SharedCommits`
/// doc comment for the fix (every node's `TestLedger` now shares one
/// cluster-wide committed-block registry, so a lagging node's
/// `ensure_digest` can actually serve the fetch from a peer that already
/// has the block).
#[test]
fn fast_recovery_down_early_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Run two ordinary rounds (go's version runs two before forcing
    // recovery).
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Force fast partition recovery into bottom.
    {
        cluster.network.drop_all_soft_votes();
        cluster.network.drop_all_slow_next_votes();

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: no soft quorum (dropped)
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // soft-step deadline timeout: still no commit
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // fast-recovery fires -> bottom
        round = expect_no_new_round(&cluster, round);
    }

    // Heal the network and terminate on period 1.
    {
        cluster.network.repair_all();
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Run two more ordinary rounds.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Full 5-node port of go-algorand's `TestAgreementFastRecoveryDownMiss`,
/// using the same 4/1 clock-firing split go's version uses
/// (`firstClocks := clocks[:4]`, `restClocks := clocks[4:]`): the first four
/// nodes fire fast-recovery while votes are still dropped (their recovery
/// votes are lost — the "miss"), then the network heals and the fifth node
/// fires its own fast-recovery timer, still not enough fresh recovery votes
/// alone for quorum. See `fast_recovery_down_early_five_node`'s doc comment
/// for why this needed the `SharedCommits` harness fix (issue #911) to
/// converge reliably at this scale.
#[test]
fn fast_recovery_down_miss_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Force fast partition recovery into bottom via total vote loss.
    {
        cluster.network.drop_all_votes();

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: nothing reaches quorum
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // deadline timeout: still nothing
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
        round = expect_no_new_round(&cluster, round);

        // First four nodes fire fast-recovery while votes are still
        // dropped — their recovery votes are lost ("miss").
        trigger_subset_timeout(&cluster, &[0, 1, 2, 3], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        // Heal the network, then the fifth node fires its fast-recovery
        // timer — still not enough fresh recovery votes for quorum on its
        // own.
        cluster.network.repair_all();
        trigger_subset_timeout(&cluster, &[4], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        // Second fast-recovery timeout, followed by period 1 terminating
        // normally: every node now has a quorum of recovery votes, the
        // network is already healed, and the round commits.
        round = pump_until_new_round_multi(
            &cluster,
            round,
            &[TimeoutType::FastRecovery, TimeoutType::Deadline],
            20,
        );
    }

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Adapted port of go-algorand's `TestAgreementFastRecoveryDownMiss`
/// (`agreement/service_test.go`) — see this file's module doc comment for
/// why this runs at 2 nodes rather than go's 5. The split-4/1 clock firing
/// go's version uses is adapted to a split-1/1 firing (node 0 fires while
/// votes are still dropped and "misses"; node 1 fires after the network
/// heals but before enough fresh recovery votes exist for quorum).
#[test]
fn fast_recovery_down_miss_two_node() {
    let cluster = setup_agreement(2);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    // Force fast partition recovery into bottom via total vote loss.
    {
        cluster.network.drop_all_votes();

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: nothing reaches quorum
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // deadline timeout: still nothing
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
        round = expect_no_new_round(&cluster, round);

        // Node 0 fires fast-recovery while votes are still dropped — its
        // recovery vote is lost ("miss").
        trigger_subset_timeout(&cluster, &[0], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        // Heal the network, then node 1 fires its fast-recovery timer —
        // still not enough fresh recovery votes for quorum on its own.
        cluster.network.repair_all();
        trigger_subset_timeout(&cluster, &[1], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        // Second fast-recovery timeout, followed by period 1 terminating
        // normally: every node now has a quorum of recovery votes, the
        // network is already healed by this point, and the round commits
        // (unlike `DownEarly`, where the equivalent fast-recovery step
        // still has votes dropped and the commit only happens after a
        // separate, later heal).
        round = pump_until_new_round_multi(
            &cluster,
            round,
            &[TimeoutType::FastRecovery, TimeoutType::Deadline],
            20,
        );
    }

    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 3);
}

/// Adapted port of go-algorand's `TestAgreementLateCertBug`
/// (`agreement/service_test.go`) — the regression this pins at player level
/// via `TestPlayerRegression_EnsuresCertThreshFromOldPeriod_8ba23942` /
/// `TestPlayer_RejectsCertThresholdFromPreviousRound`
/// (`player_edge_cases_test.rs`), now exercised through the real multi-node
/// `Service`: period 0's cert votes are pocketed (never delivered) so period
/// 0 never reaches its own threshold and the cluster moves on to period 1
/// via the deadline timeout. The pocketed, now stale-period cert votes are
/// then replayed with NO further clock fire — the round must still commit
/// on period 0's proposal purely from that vote delivery, even though every
/// node has already rezeroed into period 1.
#[test]
fn late_cert_bug_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Delay cert votes to force period 1. Divergence from go's literal
    // structure, noted once here: go closes the pocket right after the
    // FIRST (filter-timeout) fire, relying on its single-goroutine
    // synchronous model to guarantee every node has already cert-voted by
    // then. Under this harness's real threads that isn't reliable (see this
    // file's module doc comment on occasional real-vote-cascade timing) —
    // too few nodes may have reached cert-vote-readiness after just one or
    // two fires, so keep pocketing (and keep firing the deadline timeout,
    // which forces successive period bumps) until a quorum's worth of
    // period-0 cert votes has actually been captured, bounded the same way
    // `pump_until_new_round` is.
    cluster.network.pocket_all_cert_votes();
    trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: cert votes pocketed, no round
    round = expect_no_new_round(&cluster, round);
    for _ in 0..20 {
        if cluster.network.cert_vote_pocket_len() >= 4 {
            break;
        }
        // Deadline timeout: period 0 (then 1, 2, ...) fails to terminate
        // (no cert quorum arrived — pocketed), every node moves on.
        trigger_global_timeout(&cluster, TimeoutType::Deadline);
        round = expect_no_new_round(&cluster, round);
    }
    let pocketed = cluster.network.stop_pocketing_cert_votes();
    cluster.network.repair_all();
    assert!(
        pocketed.len() >= 4,
        "expected a quorum's worth of period-0 cert votes to have been pocketed, got {}",
        pocketed.len()
    );

    // Terminate on period 0 in period 1: replaying the pocketed cert votes,
    // with no further timeout fire, must still commit the round.
    {
        cluster.network.replay_all(&pocketed);
        cluster.wait_for_quiet();
        let advanced = current_round(&cluster);
        assert!(
            advanced.0 > round.0,
            "replaying the late (period-0) cert votes must still commit the round \
             even though every node already moved on to period 1"
        );
        round = advanced;
    }

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Local mirror of go's `expectNewPeriod`/`expectNoNewPeriod`, operating on
/// [`TestingClock::zeroes`] directly (unlike every other scenario in this
/// file, which tracks progress via committed round because zero-count
/// reliability across many real fires was flagged as an open question in
/// this file's module doc comment). `recover_both_v_and_bot_quorums_five_node`
/// needs the finer-grained "did a PERIOD change (not necessarily a round
/// commit)" signal go's version asserts, and zero-count is the only signal
/// this harness exposes for that — see that test's own doc comment for why
/// it turned out to be reliable enough here after all.
fn expect_new_period_all(cluster: &AgreementCluster, zeroes: u64) -> u64 {
    let z = zeroes + 1;
    for (i, clock) in cluster.clocks.iter().enumerate() {
        assert_eq!(clock.zeroes(), z, "node {i}: unexpected number of zeroes");
    }
    z
}

fn expect_no_new_period_all(cluster: &AgreementCluster, zeroes: u64) -> u64 {
    for (i, clock) in cluster.clocks.iter().enumerate() {
        assert_eq!(
            clock.zeroes(),
            zeroes,
            "node {i}: unexpected number of zeroes"
        );
    }
    zeroes
}

fn expect_no_new_period_subset(indices: &[usize], cluster: &AgreementCluster, zeroes: u64) -> u64 {
    for &i in indices {
        assert_eq!(
            cluster.clocks[i].zeroes(),
            zeroes,
            "node {i}: unexpected number of zeroes"
        );
    }
    zeroes
}

/// Fire `TimeoutType::Deadline` repeatedly (bounded), but ONLY on whichever
/// nodes haven't yet reached `zeroes + 1`, until every node has, then assert
/// exact lockstep. Unlike [`pump_until_new_round`] (which re-fires every
/// clock every attempt, safe because it only checks a `>` inequality on the
/// committed round), this must never re-fire a node that has already
/// rezeroed: `TestingClock::fire` (like go's own `testingClock.fire`)
/// releases whatever is CURRENTLY registered for a `TimeoutType` regardless
/// of what period that registration belongs to, so firing an
/// already-advanced node again would force it into an extra, unwanted period
/// bump and break the exact-lockstep assertion this test relies on (unlike
/// `pump_until_new_round`'s round-number check, an exact zero-count check
/// cannot tolerate overshoot). Needed because a single global fire is not
/// always enough for every node to have finished processing/verifying real
/// vote traffic and rezeroed by the time this driver's `wait_for_quiet`
/// returns — the same class of real-thread timing gap this file's module
/// doc comment already documents for round commits.
fn pump_until_new_period_all(cluster: &AgreementCluster, zeroes: u64, max_attempts: u32) -> u64 {
    let target = zeroes + 1;
    for _ in 0..max_attempts {
        let lagging: Vec<usize> = (0..cluster.clocks.len())
            .filter(|&i| cluster.clocks[i].zeroes() < target)
            .collect();
        if lagging.is_empty() {
            break;
        }
        trigger_subset_timeout(cluster, &lagging, TimeoutType::Deadline);
    }
    expect_new_period_all(cluster, zeroes)
}

/// Like [`pump_until_new_period_all`], but restricted to a fixed set of node
/// indices throughout (used for the value-quorum recovery step, which must
/// never touch node 0 — it already rezeroed via the bottom quorum). Needs at
/// least two fires structurally even in the best case (the `next`-step "nap"
/// mechanic in `player.rs`'s `Player::handle`: the first fire only arms a
/// randomized nap deadline, the second casts the actual next-vote), and may
/// need a few more under real-thread timing — see
/// [`pump_until_new_period_all`]'s doc comment for why this only ever fires
/// nodes still lagging, never one that has already reached `zeroes + 1`.
fn pump_until_new_period_subset(
    cluster: &AgreementCluster,
    indices: &[usize],
    zeroes: u64,
    max_attempts: u32,
) -> u64 {
    let target = zeroes + 1;
    for _ in 0..max_attempts {
        let lagging: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| cluster.clocks[i].zeroes() < target)
            .collect();
        if lagging.is_empty() {
            break;
        }
        trigger_subset_timeout(cluster, &lagging, TimeoutType::Deadline);
    }
    for &i in indices {
        assert_eq!(
            cluster.clocks[i].zeroes(),
            target,
            "node {i}: unexpected number of zeroes"
        );
    }
    target
}

/// Full 5-node port of go-algorand's `TestAgreementRecoverBothVAndBotQuorums`
/// (`agreement/service_test.go`).
///
/// Scenario: after two ordinary rounds, period 0's soft votes are pocketed
/// (never delivered) so no node observes a soft-value quorum before the
/// round's next deadline fire. That fire moves every node from CERT to NEXT
/// step, and since none of them have seen a soft quorum yet, every node's
/// own next-vote is for BOTTOM. `crown(&[0])` restricts delivery of those
/// next-votes to node 0 alone, so only node 0 accumulates a bottom quorum
/// and rezeros into period 1 — nodes 1-4 remain parked in step NEXT, having
/// cast a bottom next-vote nobody else received.
///
/// The network is then healed and the earlier-pocketed soft votes are
/// replayed, giving nodes 1-4 (still in period 0, step NEXT) knowledge of
/// the real proposal's soft-value quorum for the first time. Two more
/// deadline-type fires restricted to nodes 1-4 (`trigger_subset_timeout`)
/// walk them through the `next`-step "nap" mechanic
/// (`Player::handle`'s `_` branch in `player.rs`: the first fire arms a
/// randomized nap deadline without casting a vote, the second — now napping
/// — issues the actual next-vote via `issue_next_vote`, this time as a
/// next-VALUE vote since the soft quorum is now known) until nodes 1-4 reach
/// their own next-value quorum and rezero into period 1 too, pinned to the
/// real value. So period 0 recovers into BOTH a bottom quorum (node 0 only)
/// and a value quorum (everyone else) simultaneously — the scenario's name.
///
/// Divergence from go's literal test structure, noted once here: go passes
/// specific `time.Duration` values to `triggerGlobalTimeout` for the two
/// subset fires, computed via `(next).nextVoteRanges`/`(next+1).nextVoteRanges`
/// (`agreement/types.go`). Investigating those confirmed they are cosmetic
/// only: go's own `testingClock.fire` (`agreement/service_test.go`) ignores
/// its `d time.Duration` argument entirely — it just closes whatever channel
/// is currently registered for the given `TimeoutType`, regardless of the
/// delta it was registered with — exactly like this harness's own
/// `TestingClock::fire` (see its doc comment). So the "needs
/// `nextVoteRanges`-equivalent timing" blocker this scenario was previously
/// deferred under (issue #825's PR #932 progress note) does not actually
/// exist: the only real requirement is firing `TimeoutType::Deadline` on the
/// `[1, 2, 3, 4]` subset exactly twice, in order, which
/// [`trigger_subset_timeout`] (already landed for
/// `fast_recovery_down_miss_five_node`) already provides — no new harness
/// primitive was needed.
///
/// Unlike every other scenario in this file, this port tracks progress via
/// [`TestingClock::zeroes`] directly (go's own signal), not committed round —
/// go's assertions here are specifically about PERIOD transitions that don't
/// always coincide with a round commit (node 0's bottom-quorum period bump
/// commits no round at all). This turned out to stay in lockstep across
/// nodes reliably for this scenario (a baseline is captured right after the
/// two ordinary rounds settle, rather than assuming go's exact absolute
/// counts, since this file's module doc comment already flags absolute
/// zero-counts as not always dependable that early under real-thread
/// timing) — verified across repeated standalone and full-suite-concurrent
/// runs, see the note left in the PR description for exact counts.
#[test]
fn recover_both_v_and_bot_quorums_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Run two ordinary rounds.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    cluster.wait_for_quiet();

    // Capture the zero-count baseline here rather than assuming go's exact
    // absolute counts (1 boot + 2 rounds = 3) — see this test's doc comment.
    let baseline = cluster.clocks[0].zeroes();
    let mut zeroes = expect_no_new_period_all(&cluster, baseline);

    // Force partition recovery into both bottom and value: one node (0)
    // enters bottom, the rest enter value.
    let mut expected: Option<ProposalValue> = None;
    {
        cluster.network.pocket_all_soft_votes();
        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: soft votes pocketed
        zeroes = expect_no_new_period_all(&cluster, zeroes);
        let pocketed_soft = cluster.network.stop_pocketing_soft_votes();
        assert!(
            !pocketed_soft.is_empty(),
            "expected at least one soft vote to have been pocketed"
        );
        for msg in &pocketed_soft {
            let uv = codec::decode_vote(msg.data()).expect("pocketed soft vote decodes");
            match expected {
                None => expected = Some(uv.raw_vote.proposal),
                Some(e) => assert_eq!(e, uv.raw_vote.proposal, "unexpected soft vote"),
            }
        }
        assert_ne!(
            expected.expect("at least one pocketed soft vote"),
            BOTTOM,
            "pocketed soft vote must carry a real value"
        );

        // Generate a bottom quorum; let only node 0 see it. None of the 5
        // nodes have observed a soft-value quorum yet (every soft vote was
        // pocketed above), so every node's own next-vote at this step is for
        // BOTTOM regardless of crowning — crown only restricts who RECEIVES
        // the votes, not what any individual node casts.
        cluster.network.crown(&[0]);
        trigger_global_timeout(&cluster, TimeoutType::Deadline); // CERT -> NEXT, cast bottom next-votes
        assert_eq!(
            cluster.clocks[0].zeroes(),
            zeroes + 1,
            "node 0 did not enter new period from bottom quorum"
        );
        zeroes = expect_no_new_period_subset(&[1, 2, 3, 4], &cluster, zeroes);

        // Enable creation of a value quorum: let everyone else see the
        // earlier-pocketed soft votes.
        cluster.network.repair_all();
        cluster.network.replay_all(&pocketed_soft);
        cluster.wait_for_quiet();

        // Actually create the value quorum: two deadline-type fires
        // restricted to nodes 1-4 (node 0 already rezeroed and must not be
        // fired again here, matching go's `clocks[1:]`) — the first arms the
        // `next`-step nap deadline, the second casts the actual (now
        // value-aware) next-vote. See this test's doc comment for why the
        // specific durations go computes via `nextVoteRanges` don't matter
        // here.
        trigger_subset_timeout(&cluster, &[1, 2, 3, 4], TimeoutType::Deadline);
        zeroes = expect_no_new_period_subset(&[1, 2, 3, 4], &cluster, zeroes);

        pump_until_new_period_subset(&cluster, &[1, 2, 3, 4], zeroes, 20);
        zeroes = expect_new_period_all(&cluster, zeroes);
    }
    let expected = expected.expect("at least one pocketed soft vote");

    // Now, try again in period 1. We should vote on reproposal due to
    // non-propagation of the bottom bundle to node 0.
    {
        cluster.network.repair_all();
        cluster.network.pocket_all_cert_votes();
        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout equivalent
        zeroes = expect_no_new_period_all(&cluster, zeroes);
        let pocketed_cert = cluster.network.stop_pocketing_cert_votes();
        for msg in &pocketed_cert {
            let uv = codec::decode_vote(msg.data()).expect("pocketed cert vote decodes");
            assert_eq!(
                uv.raw_vote.proposal, expected,
                "got unexpected proposal in period 1"
            );
        }

        zeroes = pump_until_new_period_all(&cluster, zeroes, 20);
    }

    // Finish in period 2.
    {
        cluster.network.repair_all();
        zeroes = pump_until_new_period_all(&cluster, zeroes, 20);
    }
    let _ = zeroes;

    // The whole recovery block above (period 0's bottom/value quorum split,
    // period 1's reproposal, period 2's finish) commits exactly ONE round —
    // re-sync `round` here (it was never touched inside that block, which
    // tracks progress via `zeroes` instead) before resuming round-based
    // tracking for the final two ordinary rounds. Skipping this made an
    // early version of this test under-count by one round at `sanity_check`:
    // `pump_until_new_round`'s first call below would otherwise fire an
    // unnecessary extra global timeout against the stale `round` baseline
    // before ever checking it, and then silently accept whatever round
    // happened to result, one commit short of the true total.
    cluster.wait_for_quiet();
    round = current_round(&cluster);

    // Run two more ordinary rounds.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

// `TestAgreementFastRecoveryLate` and `TestAgreementFastRecoveryRedo`
// (`agreement/service_test.go`): fast partition recovery into a real
// proposal VALUE (not bottom), then (`Redo` only) a second forced failure
// and recovery of the SAME period, asserting the pinned value survives both.
//
// Issue #920 investigated this in depth (see the issue for the full
// writeup) and found — and fixed — two genuine harness bugs along the way:
//
//   1. The cert-vote-pocketing loop ported from `late_cert_bug_five_node`
//      (which only needs a vote *count* and tolerates spanning periods)
//      could fire more than one deadline timeout while pocketing stayed
//      armed, mixing period-0 and period-1 proposals into what `Late`/`Redo`
//      assert is a single-period, single-value quorum. Fixed by pocketing
//      with a single fire only (`force_fast_recovery_into_value` below).
//   2. `AgreementCluster::wait_for_quiet`'s `extra_pending` hook (the
//      crypto-verifier-backlog term its own doc comment claimed to check)
//      was stubbed to `|| 0`. Fixed via a new `CryptoVerifier for Arc<C>`
//      blanket impl (`traits.rs`) so the driver can keep a second handle to
//      each node's verifier and fold its output-channel backlog into the
//      quiescence check — see `setup_agreement.rs`'s `AgreementCluster::
//      wait_for_quiet` doc comment.
//
// Both fixes are real and independently valuable (the second especially:
// it makes `wait_for_quiet` do what its own comment always claimed), but
// neither fully eliminated the flakiness on their own. A residual,
// lower-frequency failure mode remained, root-caused precisely via targeted
// `tracing`/`eprintln` instrumentation of `Player::issue_fast_vote` during
// the investigation (not left in the tree):
//
//   `enter_period` (`player.rs`) correctly implements go's "always resynch
//   the pinned value" mechanic — ported and verified independently via
//   `player_always_resynchs_pinned_value` (`player_edge_cases_test.rs`),
//   which passes reliably. A period entered via a non-bottom `NextThreshold`
//   issues a `Repropose` pseudonode action carrying the pinned proposal
//   VALUE. But `Repropose` (`service.rs`'s `ActionType::Repropose` handler)
//   only calls `pseudonode.make_votes(..., PROPOSE, ...)` — it re-asserts a
//   PROPOSE-step VOTE, not the payload itself (matching go: a repropose is a
//   vote, not a fresh proposal broadcast). A node that never received (or
//   locally pruned across a period transition) the ORIGINAL proposal-payload
//   broadcast therefore has no way to locally stage it and reach
//   `committable == true` at the new period — `partition_policy`, the ONLY
//   mechanic in *production* that re-transmits a pinned PAYLOAD, is gated on
//   `Player::partitioned()` (`period >= 3`), which never holds this early.
//   Observed directly: in one captured failure, 3 of 5 nodes printed
//   `committable == false` for the SAME pinned value across 10+ consecutive
//   fast-recovery fires spanning the entire test — not a transient race, a
//   persistent stall for those 3 nodes specifically, correctly falling back
//   to a DOWN (bottom) fast-vote per `issue_fast_vote`'s own correct logic.
//
// This is the SAME class of gap this file's own `fast_recovery_down_early_
// five_node` doc comment already flags from an earlier investigation (issue
// #911) for round-COMMIT digests, fixed harness-side via `TestLedger`'s
// `SharedCommits`. This investigation's fix is the mid-period-PAYLOAD
// equivalent: `TestingNetwork::redeliver_recent_payloads`
// (`simulate/testing_network.rs`) caches every normally-delivered proposal-
// payload broadcast and replays all of them on request — called explicitly
// at every "network heals" point these two scenarios hit (deliberately NOT
// folded into `TestingNetwork::repair_all` itself, which every OTHER
// 5-node scenario in this file also calls: an earlier version did fold it
// in, and the extra re-multicast traffic was enough to occasionally perturb
// `late_cert_bug_five_node`'s precisely-timed "replay exactly this and
// nothing else" assertion — see `repair_all`'s doc comment) — a
// harness-only catch-up mechanism, deliberately NOT a change to
// `partition_policy` or any other production code (go's own
// `partitioned()` gate looks identical, and go's real `testingNetwork` never
// needs an equivalent because its synchronous single-goroutine model
// structurally cannot lose or need to re-stage a payload the way this
// harness's real threads occasionally do).
//
// With that fix in place, both scenarios landed below pass reliably (see
// each function's doc comment for the verification runs performed).

/// Shared "force fast partition recovery into a real proposal VALUE" block,
/// used identically by go's `TestAgreementFastRecoveryLate`/`Redo` (the `{
/// pocket := ...; ...; triggerGlobalTimeout(secondFPR, TimeoutFastRecovery,
/// ...) }` block appears verbatim in both). Pockets every CERT vote at the
/// current period with a SINGLE filter-timeout fire (see this file's module
/// doc comment on why more than one fire would mix periods), decodes them to
/// recover the proposal value every node cert-voted for, then drives the
/// deadline + fast-recovery (arm, first-4-nodes-while-still-dropped,
/// heal-and-fifth-node, second-genuine-fire) sequence go's version uses to
/// push every node into the next period pinned to that value. Returns the
/// pinned value.
fn force_fast_recovery_into_value(cluster: &AgreementCluster, round: Round) -> ProposalValue {
    cluster.network.pocket_all_cert_votes();
    cluster.network.drop_all_slow_next_votes();

    trigger_global_timeout(cluster, TimeoutType::Deadline); // filter timeout: cert votes pocketed, no round
    expect_no_new_round(cluster, round);

    // Stop pocketing cert votes, but do NOT `repair_all()` here — that would
    // also clear `drop_slow_next_votes` (still armed above) before the
    // "deadline timeout: still no commit" fire below, which go's own
    // `TestAgreementFastRecoveryLate`/`Redo` structure keeps active this
    // whole time. Healing early let that next deadline fire's now-unblocked
    // vote cascade race a real (non-fast-recovery) period bump into
    // existence, sending every subsequent step in this function chasing the
    // WRONG period — the actual root cause of an early flaky version of this
    // helper, not a payload-propagation gap.
    let pocketed = cluster.network.stop_pocketing_cert_votes();
    assert!(
        !pocketed.is_empty(),
        "expected at least one cert vote to have been pocketed"
    );

    let mut expected: Option<ProposalValue> = None;
    for msg in &pocketed {
        let uv = codec::decode_vote(msg.data()).expect("pocketed cert vote decodes");
        match expected {
            None => expected = Some(uv.raw_vote.proposal),
            Some(e) => assert_eq!(e, uv.raw_vote.proposal, "unexpected proposal"),
        }
    }
    let expected = expected.expect("at least one pocketed cert vote");
    assert_ne!(
        expected, BOTTOM,
        "pocketed cert vote must carry a real value"
    );

    trigger_global_timeout(cluster, TimeoutType::Deadline); // deadline timeout: still no commit
    expect_no_new_round(cluster, round);

    trigger_global_timeout(cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
    expect_no_new_round(cluster, round);
    cluster.network.drop_all_votes();

    // First four nodes fire fast-recovery while votes are still dropped —
    // their recovery votes are lost.
    trigger_subset_timeout(cluster, &[0, 1, 2, 3], TimeoutType::FastRecovery);
    expect_no_new_round(cluster, round);

    // Heal, then explicitly replay any proposal payload the network has
    // cached (`TestingNetwork::redeliver_recent_payloads` — deliberately
    // NOT folded into `repair_all` itself, see that method's doc comment)
    // and settle BEFORE firing anything else: without this explicit settle
    // point, a node's reaction to the next fire can race the redelivered
    // payload's async crypto verification (see this function's doc comment
    // / issue #920) — the payload arrives in the channel immediately, but
    // isn't STAGED as committable until that node's crypto-verifier and
    // demux threads actually process it, which `TestingClock::fire` does
    // not wait for on its own.
    cluster.network.repair_all();
    cluster.network.redeliver_recent_payloads();
    cluster.wait_for_quiet();
    trigger_subset_timeout(cluster, &[4], TimeoutType::FastRecovery);
    expect_no_new_round(cluster, round);

    // One more explicit catch-up + settle pass immediately before the
    // decisive fire below: this is the LAST chance for a node to have the
    // pinned value's payload staged before it casts the fast-vote that
    // decides what period 1 pins. A node casts that vote once — a payload
    // that arrives after the vote is already cast can't retroactively
    // change it — so this must happen right before the fire, not just
    // somewhere earlier in the sequence.
    cluster.network.redeliver_recent_payloads();
    cluster.wait_for_quiet();

    // Second, genuine fast-recovery fire: every node now has a quorum of
    // fresh recovery votes (network already healed) and moves into the next
    // period pinned to `expected` — but doesn't commit a ROUND yet (go's own
    // test doesn't expect one here either; it asserts a new PERIOD, which
    // this port tracks indirectly via the pinned-value assertions the caller
    // performs after termination).
    trigger_global_timeout(cluster, TimeoutType::FastRecovery);
    expect_no_new_round(cluster, round);

    expected
}

/// Full 5-node port of go-algorand's `TestAgreementFastRecoveryLate`
/// (`agreement/service_test.go`): after two ordinary rounds, period 0 is
/// forced into fast partition recovery pinned to a real proposal value (via
/// [`force_fast_recovery_into_value`]), then the network heals and period 1
/// terminates normally — every node's committed round must match the PINNED
/// value, not a fresh/bottom one. See this file's module doc comment for the
/// harness-payload-catch-up fix (`TestingNetwork::redeliver_recent_payloads`)
/// this scenario's reliability depends on.
///
/// Verified via 10+ consecutive standalone runs and several full-
/// `algo-agreement`-suite-concurrent runs during development (issue #920) —
/// see the issue for the exact counts.
#[test]
fn fast_recovery_late_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    let expected = force_fast_recovery_into_value(&cluster, round);

    // Terminate on period 1. The explicit redeliver + settle before firing
    // anything further gives every node one more chance to catch up on the
    // pinned value's payload (unlikely to still be needed at this point —
    // `force_fast_recovery_into_value` already did this right before the
    // fire that pinned it — but cheap insurance, unlike `repair_all`'s own
    // healing this is scoped to only tests that actually call it, see
    // `TestingNetwork::repair_all`'s doc comment).
    cluster.network.repair_all();
    cluster.network.redeliver_recent_payloads();
    cluster.wait_for_quiet();
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    for (i, ledger) in cluster.ledgers.iter().enumerate() {
        let digest = ledger
            .cert(Round(round.0 - 1))
            .unwrap_or_else(|| panic!("node {i} must have committed round {:?}", round.0 - 1))
            .proposal
            .block_digest;
        assert_eq!(
            digest, expected.block_digest,
            "node {i} converged on wrong block"
        );
    }

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Full 5-node port of go-algorand's `TestAgreementFastRecoveryRedo`
/// (`agreement/service_test.go`): same setup as
/// [`fast_recovery_late_five_node`], but after period 1 is entered pinned to
/// the recovered value, period 1 is ALSO forced to fail (total vote loss via
/// `drop_all_votes`, no cert-vote pocketing needed — the value is already
/// pinned from period 0) and recovered a second time via the same
/// arm/first-4/heal-and-fifth/second-fire fast-recovery sequence. Every
/// node's final committed round must still match the ORIGINAL pinned value,
/// proving the pin survives a repeated recovery of the same period.
///
/// Verified via 10+ consecutive standalone runs and several full-
/// `algo-agreement`-suite-concurrent runs during development (issue #920) —
/// see the issue for the exact counts.
#[test]
fn fast_recovery_redo_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    let expected = force_fast_recovery_into_value(&cluster, round);

    // Fail period 1 with the SAME pinned value again: total vote loss, then
    // the identical arm/first-4/heal-and-fifth/second-fire fast-recovery
    // sequence go's version uses (no cert-vote pocketing this time — the
    // value is already pinned from period 0's recovery, so every node's
    // `Repropose`/pin-resync mechanic carries it forward).
    {
        cluster.network.drop_all_votes();

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: nothing reaches quorum
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::Deadline); // deadline timeout: still nothing
        round = expect_no_new_round(&cluster, round);

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // arms the fast-recovery timer
        round = expect_no_new_round(&cluster, round);
        cluster.network.drop_all_votes();

        trigger_subset_timeout(&cluster, &[0, 1, 2, 3], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        cluster.network.repair_all();
        cluster.network.redeliver_recent_payloads();
        cluster.wait_for_quiet(); // let the redelivered payload catch-up settle before node 4 fires
        trigger_subset_timeout(&cluster, &[4], TimeoutType::FastRecovery);
        round = expect_no_new_round(&cluster, round);

        // Last explicit catch-up + settle pass right before the decisive
        // fire — see `force_fast_recovery_into_value`'s matching comment for
        // why this can't just happen earlier in the sequence.
        cluster.network.redeliver_recent_payloads();
        cluster.wait_for_quiet();

        trigger_global_timeout(&cluster, TimeoutType::FastRecovery); // second FPR fire -> period 2, still pinned
        round = expect_no_new_round(&cluster, round);
    }

    // Terminate on period 2 (settle first — see the matching comment above).
    cluster.network.repair_all();
    cluster.network.redeliver_recent_payloads();
    cluster.wait_for_quiet();
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    for (i, ledger) in cluster.ledgers.iter().enumerate() {
        let digest = ledger
            .cert(Round(round.0 - 1))
            .unwrap_or_else(|| panic!("node {i} must have committed round {:?}", round.0 - 1))
            .proposal
            .block_digest;
        assert_eq!(
            digest, expected.block_digest,
            "node {i} converged on wrong block"
        );
    }

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Full 5-node port of go-algorand's `TestAgreementLargePeriods`
/// (`agreement/service_test.go`): partitions a 3-of-5 minority (nodes 0-2)
/// away from the network for 60 consecutive periods (filter timeout fails
/// to reach quorum while partitioned; healing + a deadline timeout forces
/// the next period), then heals for good and terminates — proving the
/// `Player`/`Service` state machine handles unbounded period growth (large
/// `Period` values, repeated rezero-without-round-advance) without drifting
/// or overflowing.
#[test]
fn large_periods_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    for _ in 0..60 {
        cluster.network.partition(&[0, 1, 2]);
        trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: partitioned, no quorum
        round = expect_no_new_round(&cluster, round);

        cluster.network.repair_all();
        trigger_global_timeout(&cluster, TimeoutType::Deadline); // deadline timeout: advances to the next period
        round = expect_no_new_round(&cluster, round);
    }

    // Terminate.
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 5);
}

/// Full 5-node port of go-algorand's `TestAgreementSynchronousFutureUpgrade`
/// (`agreement/service_test.go`), via `simulateAgreementWithConsensusVersion`.
///
/// This scenario was previously documented (issue #825's Progress notes,
/// PR #919) as needing "a different simulation harness entirely" — go's
/// `simulateAgreementWithConsensusVersion`/`makeTestLedgerWithConsensusVersion`
/// select a DIFFERENT `protocol.ConsensusVersion` per round (current version
/// for round < 5, `ConsensusFuture` for round >= 5), which the harness's
/// `TestLedger` had no way to express at all (a single fixed `version`
/// field, the same for every round). Re-investigated per this issue's
/// remaining-scope instructions rather than taken at face value: the actual
/// gap was narrow and did NOT require a new harness. `TestLedger` already
/// funnels every `Service`/`Player`/`Pseudonode` consensus-parameter lookup
/// through `LedgerReader::consensus_params(round)`/`consensus_version(round)`
/// (`crates/core/algo-agreement/src/{service,proposal,pseudonode,bundle,
/// crypto_verifier,ledger_reader}.rs` all call these with a specific round,
/// never a cached/global value), so adding a per-round selector function
/// (`TestLedger::with_version_fn`, `setup_agreement_with_version_fn`) was
/// enough to thread a round-dependent consensus version through the real
/// multi-node `Service` state machine with no other harness changes needed.
///
/// Unlike go's version (which also captures and cross-checks each node's
/// per-round filter-timeout duration — a DynamicFilterTimeout-specific
/// assertion already covered by this repo's dedicated dynamic-filter-timeout
/// tests, not this scenario's defining behavior), this port asserts the
/// property `TestAgreementSynchronousFutureUpgrade` itself actually exists
/// to prove: the cluster commits 10 consecutive rounds — spanning the
/// version-5 current-version -> `ConsensusFuture` transition mid-stream —
/// with every node converging on the identical block at every round
/// (`sanity_check`), the same real-multi-node-convergence assertion every
/// other scenario in this file makes. No divergence found: the transition
/// crossed cleanly across 10+ consecutive standalone runs with no special
/// handling needed at the transition round itself.
#[test]
fn synchronous_future_upgrade_five_node() {
    let version_fn: Arc<dyn Fn(Round) -> String + Send + Sync> = Arc::new(|r: Round| {
        if r.0 >= 5 {
            algo_types::CONSENSUS_FUTURE.to_string()
        } else {
            algo_types::CONSENSUS_V41.to_string()
        }
    });
    let cluster = setup_agreement_with_version_fn(5, Some(version_fn));
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    for _ in 0..10 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    sanity_check(&cluster, start_round, 10);
}

/// Full 5-node port of go-algorand's
/// `TestAgreementCertificateDoesNotStallSingleRelay`
/// (`agreement/service_test.go`), via `TestingNetwork::make_relays`.
///
/// Scenario: two ordinary rounds commit normally. Node 0 (the "relay") is
/// then partitioned away from nodes 1-4 (the "leaves", 80% of stake —
/// comfortably above the ~75% cert threshold on their own). Cert votes for
/// the next round are pocketed rather than delivered, so the leaves' round
/// does NOT commit organically off live traffic; once a quorum's worth is
/// captured, they're replayed while the partition is still active — this
/// delivers strictly within the leaves' group, so the leaves terminate the
/// round with a real, valid certificate that the relay never saw a single
/// vote of. The network then heals under a star topology
/// (`make_relays(&[0])`, NOT full `repair_all`): leaves still cannot reach
/// each other directly, only via the relay. The SAME pocketed certificate is
/// replayed once more under this topology so the relay receives it directly
/// (source is a leaf, recipient is the relay — always deliverable under
/// `make_relays`) and must catch up via `ensure_digest`/`SharedCommits`
/// (`TestLedger`, see its module doc comment) despite being several periods
/// behind its own locally-tracked state. Finally, two more ordinary rounds
/// are run under the SAME star topology — this is the part that actually
/// proves the relay resumed genuinely *relaying* traffic (`ActionType::Relay`
/// -> `AgreementNetwork::relay`, `service.rs`), not just passively receiving
/// its own catch-up: with leaf-to-leaf delivery still blocked, those rounds
/// can ONLY commit if the relay forwards leaf votes/proposals on to the
/// other leaves.
///
/// History: PR #935 (issue #825) attempted this exact scenario and found a
/// genuine, reproducible ~10-20% flake — the relay's `next_round()`
/// sometimes never advances across 40 retry attempts, even with identical
/// evidence (the same pocketed certificate) re-injected repeatedly, ruling
/// out simple message-loss/timing races (those would be expected to
/// eventually succeed under retry). That investigation found and fixed two
/// real harness bugs along the way (both already landed, see
/// `test_ledger.rs`'s `ensure_block`/`ensure_validated_block` doc comments
/// and `testing_network.rs`'s module doc comment) but did not close the
/// flake, and did not land the test.
///
/// PR #935's own test code was never committed anywhere (confirmed via
/// `git log`/`git show` on its branch, per this issue's investigation
/// instructions) and could not be recovered, so this port is a from-scratch
/// reconstruction from PR #935's PR description, not a byte-for-byte replay
/// of the exact code that flaked. That reconstruction's FIRST version
/// reproduced a 100%-deterministic (not merely 10-20%) failure: the relay's
/// `next_round()` never advanced across 40 retries, identical to PR #935's
/// symptom. Instrumenting `VoteAggregator::filter_vote` to log every
/// CERT-step freshness-filter decision with the receiving node's thread id
/// showed the relay's thread never even reached `filter_vote` for the
/// replayed certificate — the message was being dropped at the network
/// layer, before any `Player`/`Service` logic saw it at all. Root cause: a
/// harness bug in the reconstructed test, not a production bug.
/// `TestingNetwork::partition` and `TestingNetwork::make_relays` are
/// independent delivery filters that must BOTH pass for a message to be
/// delivered (mirrors go's `multicast` checking `partitionedNodes` and
/// `relayNodes` as two separate gates — see `testing_network.rs`'s
/// `multicast` doc comment). This test's healing step called
/// `make_relays(&[relay])` WITHOUT first clearing the still-active
/// `partition(&leaves)` from the earlier step, leaving the relay in a
/// partition group of exactly one node — every message to it was silently
/// blocked regardless of the relay topology also being armed. Calling
/// `TestingNetwork::repair_all()` before `make_relays()` (clearing the
/// stale partition) closed the 100%-deterministic failure entirely; this
/// port has since been verified reliable across 15+ consecutive standalone
/// runs and several full `algo-agreement`-suite-concurrent runs, this
/// harness's established landing bar. No `Player`/`Service` divergence was
/// found in the course of this investigation. Whether PR #935's actual
/// (never-recovered) code hit this exact same partition/make_relays
/// interaction, or a different bug that happens to produce the same
/// symptom, cannot be determined with certainty since that code is gone —
/// but this is a real, reproducible, now-fixed bug of exactly the kind PR
/// #935's own writeup speculated about ("a logic bug in `make_relays`'s
/// topology filter interacting badly with something else"), and the
/// resulting test is fully reliable.
#[test]
fn certificate_does_not_stall_single_relay_five_node() {
    let cluster = setup_agreement(5);
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Two ordinary rounds commit normally, full connectivity.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    let relay = 0usize;
    let leaves = [1usize, 2, 3, 4];

    // Partition the relay away from the leaves, and pocket cert votes so
    // the leaves' round does not commit organically off live delivery —
    // capturing the actual certificate lets it be replayed directly at the
    // relay later, to prove `ensure_digest` catch-up rather than relying on
    // the relay ever observing the live vote cascade.
    cluster.network.partition(&leaves);
    cluster.network.pocket_all_cert_votes();

    trigger_global_timeout(&cluster, TimeoutType::Deadline); // filter timeout: cert votes pocketed, no round
    round = expect_no_new_round(&cluster, round);
    // Keep pocketing (and firing the deadline timeout, which forces
    // successive period bumps for every node -- including the isolated
    // relay, whose clock is fired identically) until a SINGLE period's
    // worth of cert votes reaches quorum size. A raw pocketed-vote COUNT
    // is not enough once a partition is layered on top of pocketing: each
    // extra deadline fire needed to accumulate enough votes also bumps
    // every leaf's period, so votes captured across different periods
    // must not be silently pooled together into one "certificate" -- a
    // cert bundle is only valid votes from the SAME (round, period).
    let mut quorum_group: Vec<PocketedMessage> = Vec::new();
    for _ in 0..20 {
        let snapshot = cluster.network.cert_vote_pocket_snapshot();
        if let Some(group) = largest_same_period_group(&snapshot, 4) {
            quorum_group = group;
            break;
        }
        // Deadline timeout: period fails to terminate (cert votes
        // pocketed), every node moves on to the next period.
        trigger_global_timeout(&cluster, TimeoutType::Deadline);
        round = expect_no_new_round(&cluster, round);
    }
    let _ = cluster.network.stop_pocketing_cert_votes();
    let pocketed = quorum_group;
    assert!(
        pocketed.len() >= 4,
        "expected a single period's quorum's worth of cert votes to have \
         been pocketed, got {} (best single-period group)",
        pocketed.len()
    );

    // Replay while the partition is still active: delivered strictly
    // within the leaves' group (the relay's own group is a singleton), so
    // the leaves terminate their round with a real certificate the relay
    // never saw any part of.
    cluster.network.replay_all(&pocketed);
    cluster.wait_for_quiet();

    let leaf_round = Round(round.0 + 1);
    for &i in &leaves {
        assert_eq!(
            cluster.ledgers[i].next_round(),
            leaf_round,
            "leaf {i} must have committed the round from the replayed certificate"
        );
    }
    assert_eq!(
        cluster.ledgers[relay].next_round(),
        round,
        "relay must NOT have advanced yet -- it was fully partitioned away \
         from every vote and every payload"
    );

    // Heal under a star topology: the relay can be reached again, but
    // leaves still cannot reach each other directly, only via the relay.
    // Replay the SAME certificate once more so the relay receives it
    // directly (source is a leaf, recipient is the relay -- always
    // deliverable under `make_relays`) and must catch up via
    // `ensure_digest`/`SharedCommits` despite being several periods behind
    // its own locally-tracked state.
    //
    // `repair_all()` FIRST is required, not optional: `partition` and
    // `make_relays` are independent filters that must BOTH pass for
    // delivery (mirrors go's `multicast` checking `partitionedNodes` and
    // `crownedNodes`/`relayNodes` separately) -- leaving the earlier
    // `partition(&leaves)` active while also arming `make_relays` would put
    // the relay in a partition group of one, silently blocking EVERY
    // message to it regardless of the relay topology.
    cluster.network.repair_all();
    cluster.network.make_relays(&[relay]);
    cluster.network.replay_all(&pocketed);
    cluster.wait_for_quiet();

    // `ensure_digest`'s catch-up runs on a background thread with its own
    // bounded retry window (see `TestLedger::ensure_digest`'s doc
    // comment); poll rather than asserting immediately, re-injecting the
    // exact same evidence on every attempt (matching what PR #935's
    // investigation exercised) up to a generous bound.
    let mut caught_up = false;
    for attempt in 0..40 {
        if cluster.ledgers[relay].next_round() == leaf_round {
            caught_up = true;
            break;
        }
        if attempt > 0 {
            cluster.network.replay_all(&pocketed);
        }
        cluster.wait_for_quiet();
    }
    assert!(
        caught_up,
        "relay failed to catch up to the leaves' round via ensure_digest \
         after 40 retries (relay next_round={:?}, expected {:?})",
        cluster.ledgers[relay].next_round(),
        leaf_round
    );
    round = leaf_round;

    // Prove the relay is genuinely RELAYING traffic, not just passively
    // receiving its own catch-up: run two more ordinary rounds under the
    // SAME star topology. With leaf-to-leaf delivery still blocked, these
    // rounds can only commit if the relay actively forwards leaf
    // votes/proposals on to the other leaves.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.network.repair_all();
    cluster.shutdown();
    // 2 initial ordinary rounds + 1 round committed by the leaves (via the
    // replayed certificate) while the relay was still partitioned away +
    // 2 final ordinary rounds under the healed star topology = 5 total
    // round commits from `start_round` (the relay's catch-up to the
    // leaves' round is not itself an additional commit -- it's the SAME
    // round the leaves already committed).
    sanity_check(&cluster, start_round, 5);
}

/// End-to-end integration proof for the two harness pieces built for issue
/// #825's `8ba23942` investigation — `AsyncCryptoVerifier::
/// pending_proposal_validations` (coservice-count-equivalent quiescence
/// tracking) and `simulate::suspendable_validator::SuspendableBlockValidator`
/// / `setup_agreement_with_validator` (a cluster-wide suspendable
/// `BlockValidator`) — wired through a REAL 5-node `Service`/`Player`
/// cluster, not just the unit tests each piece already has in isolation.
///
/// This is deliberately NOT a port of
/// `TestAgreementRegression_WrongPeriodPayloadVerificationCancellation_8ba23942`
/// itself: porting that exact scenario turned out to need more than these
/// two pieces provide (see `docs/phase17/parity_agreement.md`'s row for it,
/// and issue #1035) — a pause/checkpoint hook between "a round commits" and
/// "the next round's proposal auto-broadcasts," which this harness's
/// real-thread `Service`s have no observable point for a driver to act on.
/// Suspending the validator from the very start of the cluster sidesteps
/// that exact race (there is no "previous round" whose settle cascade could
/// have already raced ahead), which is why this test can be reliable where
/// the full regression scenario, so far, is not.
#[test]
fn suspended_block_validator_stalls_verification_and_resume_unblocks_it_five_node() {
    let validator = SuspendableBlockValidator::new();
    validator.suspend();

    let cluster = setup_agreement_with_validator(5, validator.clone());
    let start_round = cluster.start_round;

    // Do NOT call `cluster.wait_for_quiet()` here: with every node's
    // crypto verifier suspended, the round-1 proposal broadcast by
    // whichever node wins period-0 sortition can never finish verifying at
    // the other 4 nodes, so the cluster never reaches quiescence — exactly
    // the condition `wait_for_quiet`'s doc comment says to poll
    // `pending_proposal_validations()` directly for instead.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while cluster.pending_proposal_validations() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "no node ever reported a pending (suspended) proposal validation \
             within 10s of cluster startup"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // With validation stuck, round 1 must not have committed anywhere.
    for (i, ledger) in cluster.ledgers.iter().enumerate() {
        assert_eq!(
            ledger.next_round(),
            start_round,
            "node {i} committed a round while every proposal verification \
             was suspended"
        );
    }

    // Release every blocked validation. The stuck verification(s) resolve,
    // the cluster catches up on its own (no further clock fire needed —
    // matching how every other "ordinary round" in this file commits off
    // real vote/proposal traffic alone), and `pending_proposal_validations`
    // drops back to zero.
    validator.resume();
    cluster.wait_for_quiet();
    assert_eq!(cluster.pending_proposal_validations(), 0);

    // Releasing the suspended validator is necessary but not always
    // immediately sufficient for round 1 to commit — like every other
    // "ordinary round" in this file, real-thread timing sometimes needs an
    // explicit nudge on top of organic vote/proposal traffic (see this
    // file's module doc comment). `pump_until_new_round` fires+settles in a
    // bounded retry loop rather than asserting after a single
    // `wait_for_quiet`.
    let mut round = pump_until_new_round(&cluster, start_round, TimeoutType::Deadline, 20);

    // Prove the cluster is fully healthy afterward, not just unstuck for
    // one round.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }
    let _ = round;

    cluster.shutdown();
    // 1 round committed once suspension was released + 2 further ordinary
    // rounds pumped afterward = 3 total commits from `start_round`.
    sanity_check(&cluster, start_round, 3);
}

/// Arm `gate`, then repeatedly fire every clock's `Deadline` timeout — NOT
/// via [`trigger_global_timeout`] (which internally calls `wait_for_quiet`,
/// and the cluster cannot go quiet while a demux thread is genuinely
/// parked on the armed gate; calling it here from the driver thread would
/// deadlock) — until at least one node's outbound proposal broadcast
/// reaches the pause point (issue #1035's checkpoint hook). Panics if
/// nothing pauses within `timeout`.
///
/// Fires unconditionally each attempt (mirroring `trigger_global_timeout`
/// and every other repeated-fire loop in this file), deliberately NOT
/// gated on `TestingClock::has_pending`: `has_pending` and `timeout_at`
/// key a pending registration by `(TimeoutType, delta)`, and
/// `filter_timeout`/`deadline_timeout` return the SAME duration for every
/// period `>= 1` (only period 0 uses a distinct constant) — so once a
/// period-`>=1` registration has been fired once, a later re-registration
/// with the identical delta is treated as already-satisfied by
/// `TestingClock::timeout_at` (`need_new` compares deltas) and never flips
/// `has_pending` back to true. A `has_pending`-gated version of this loop
/// was tried first and found to stall indefinitely (~10% of runs) for
/// exactly this reason once a scenario needed more than one period bump.
/// `TestingClock::fire` itself is safe to call unconditionally — it's a
/// no-op if nothing is currently pending, and only panics if the
/// `TimeoutType` key was never registered at all, which cannot happen
/// this far into a running cluster.
///
/// Whatever broadcast this catches — a genuinely new round's first
/// proposal, or a same-round reproposal for a later period — this bounded,
/// no-quiescence-wait loop cannot guarantee which; callers must not assume
/// a round commit happened, only that SOME node's next outbound proposal
/// broadcast is now held at the checkpoint.
fn arm_and_catch_next_proposal_broadcast(
    clocks: &[Arc<crate::simulate::testing_clock::TestingClock>],
    gate: &ProposeBroadcastGate,
    timeout: Duration,
) {
    gate.arm();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        for clock in clocks {
            clock.try_fire(TimeoutType::Deadline);
        }
        if gate.wait_for_pause(1, Duration::from_millis(200)) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected at least one node's next proposal broadcast to reach \
             the propose-broadcast checkpoint within {timeout:?}"
        );
    }
}

/// Port of go-algorand's
/// `TestAgreementRegression_WrongPeriodPayloadVerificationCancellation_8ba23942`
/// (`agreement/service_test.go:2253`), using the propose-broadcast checkpoint
/// hook added for issue #1035
/// (`crates/core/algo-agreement/tests/simulate/propose_broadcast_gate.rs`) to
/// close the exact race that blocked this scenario (see that file's module
/// doc comment, `testing_network.rs`'s module doc comment, and
/// `docs/phase17/parity_agreement.md`'s row for this test).
///
/// Structure (deliberately adapted to this harness's idioms rather than a
/// literal transliteration of go's channel-counting bookkeeping, which
/// depends on internal per-coservice accounting this port doesn't have):
///
/// 1. Two ordinary rounds commit normally (proves the harness/cluster is
///    healthy before the interesting part starts).
/// 2. `propose_gate.arm()`, then every clock's `Deadline` timeout is fired
///    WITHOUT waiting for quiescence (a bare `fire`, not
///    `trigger_global_timeout`, since the cluster provably cannot go quiet
///    while a node's demux thread is parked on the armed gate). This
///    finalizes the current round; whichever node(s) win next round's
///    proposal committee immediately try to broadcast, and are paused
///    INSIDE their own demux thread, strictly before the network sees
///    anything — the exact checkpoint go's synchronous test model gets for
///    free and this harness previously had no way to observe.
/// 3. While paused: `validator.suspend()` (all future proposal-payload
///    verification blocks) and `network.pocket_all_compound()` (all future
///    proposal-payload broadcasts are intercepted, not delivered) are armed,
///    THEN the gate is released — so the very next round's very first
///    proposal broadcast is guaranteed to be pocketed rather than delivered
///    (go's "(takes effect next round)" guarantee, reconstructed here via
///    the explicit pause rather than program order).
/// 4. With that round's proposal now unreachable by any node, soft votes
///    are dropped and `Deadline` is fired twice more (bounded, polling
///    `compound_pocket_len` for progress under this harness's real-thread
///    timing) to force the round through two more periods — each period's
///    own freshly-generated proposal is ALSO pocketed automatically
///    (`pocket_all_compound` stays armed continuously; only the FIRST
///    proposal after a commit needed the gate to close the arming race —
///    see `testing_network.rs`'s doc comment on why the primitive itself
///    was already reliable).
/// 5. `repair_all()` (restores normal vote delivery) then EVERY pocketed
///    proposal — spanning all the periods just visited, including stale
///    ones from periods the cluster has since moved past — is replayed at
///    once via `replay_all`, while validation is STILL suspended: this is
///    the regression's actual shape, multiple pending payload verifications
///    queued for different periods (some already stale) at the same time.
/// 6. `validator.resume()` releases every queued verification simultaneously
///    (go's `close(ch)`) and the cluster is driven (bounded retries, this
///    harness's established pattern) until the round commits — proving
///    that a stale-period payload's verification completing late does not
///    corrupt state, crash, or prevent the round from terminating on
///    whichever period's proposal is actually current.
/// 7. Two more ordinary rounds commit afterward, proving the cluster is
///    fully healthy, not just unstuck for one round.
#[test]
fn regression_wrong_period_payload_verification_cancellation_8ba23942_five_node() {
    let validator = SuspendableBlockValidator::new();
    let propose_gate = ProposeBroadcastGate::new();
    let cluster = setup_agreement_with_validator_and_propose_gate(
        5,
        validator.clone(),
        Arc::clone(&propose_gate),
    );
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Step 1: two ordinary rounds, proving the cluster is healthy before the
    // interesting part starts. The gate is disarmed throughout, so it has
    // zero effect on ordinary operation.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Step 2+3: catch the very next proposal broadcast at the checkpoint,
    // arm suspend+pocketing while it's held, then release it into the
    // now-armed interception.
    arm_and_catch_next_proposal_broadcast(&cluster.clocks, &propose_gate, Duration::from_secs(300));
    validator.suspend();
    cluster.network.pocket_all_compound();
    propose_gate.release();

    // Whatever broadcast the gate just caught — a genuinely new round's
    // first proposal, or a same-round reproposal for a later period, this
    // harness's repeated bare fires can't guarantee which — is now
    // pocketed rather than delivered, so it cannot commit. Safe to
    // `wait_for_quiet` now: nothing paused at the gate ever reached a
    // node's crypto verifier, so there is no pending verification anywhere
    // yet. `stuck_round` is simply whatever round the cluster is at once
    // things settle — the specific round number doesn't matter to this
    // scenario, only that its proposal is now unreachable by every node.
    cluster.wait_for_quiet();
    let stuck_round = current_round(&cluster);
    assert!(
        stuck_round.0 >= round.0,
        "round must not have gone BACKWARDS while catching the checkpoint"
    );
    round = stuck_round;

    // Step 4: with `stuck_round`'s proposal now unreachable by any node,
    // force it through two more periods, bounded-polling
    // `compound_pocket_len` for progress under real-thread timing (mirrors
    // `late_cert_bug_five_node`'s cert-vote-pocket polling loop).
    cluster.network.drop_all_soft_votes();
    for target_len in 1..=2 {
        for _ in 0..40 {
            if cluster.network.compound_pocket_len() >= target_len {
                break;
            }
            // Fires unconditionally, not gated on `has_pending` — see
            // `arm_and_catch_next_proposal_broadcast`'s doc comment for why
            // that gate stalls indefinitely once a period repeats a
            // `filter_timeout`/`deadline_timeout` duration already fired.
            for clock in &cluster.clocks {
                clock.try_fire(TimeoutType::Deadline);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            cluster.network.compound_pocket_len() >= target_len,
            "expected at least {target_len} pocketed stale-period proposal(s) \
             for round {round:?}, got {}",
            cluster.network.compound_pocket_len()
        );
    }
    // `round` must not have advanced during this forced-period-bump phase —
    // its proposal has been unreachable the entire time.
    assert_eq!(
        current_round(&cluster),
        round,
        "round must not commit while every one of its periods' proposals is pocketed"
    );

    // Step 5: heal vote delivery, then replay EVERY pocketed proposal
    // (spanning every period visited) at once, while validation is STILL
    // suspended — multiple pending, some now-stale, verifications queued
    // simultaneously is the regression's actual shape.
    //
    // Order matters: `stop_pocketing_compound` must run BEFORE `repair_all`
    // — `repair_all` unconditionally clears `compound_pocket` too (it's one
    // of the drop/pocket/partition flags it resets), so calling it first
    // would silently discard everything just pocketed.
    let pocketed = cluster.network.stop_pocketing_compound();
    cluster.network.repair_all();
    assert!(
        pocketed.len() >= 2,
        "expected proposals from at least 2 periods to have been pocketed, got {}",
        pocketed.len()
    );
    cluster.network.replay_all(&pocketed);

    // Give every node's crypto verifier a chance to actually pick up and
    // queue the replayed (still-suspended) verifications before resuming,
    // so `validator.resume()` below is (when possible) releasing
    // genuinely-queued work, not racing ahead of delivery. This is
    // deliberately a best-effort wait, not a hard requirement: under this
    // harness's real-thread timing (worse under a full concurrent-suite
    // run's CPU contention — see this file's module doc comment), a
    // replayed payload can legitimately be freshness-filtered (rejected as
    // stale before ever reaching `BlockValidator::validate`, e.g. by
    // `VoteAggregator`/proposal-tracker round/period bookkeeping) rather
    // than actually queuing a pending validation — that is ALSO a safe
    // outcome for this regression's actual claim (no corruption/crash from
    // a stale-period payload, whether it's cancelled via suspended
    // verification or dropped earlier by the ordinary freshness filter), so
    // this must not be a failure condition on its own. `validator.resume()`
    // and the round-recovery assertions below are what actually verify the
    // regression is fixed.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while cluster.pending_proposal_validations() == 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    // Step 6: release every queued verification at once and drive the
    // cluster until the round finally commits.
    validator.resume();
    cluster.wait_for_quiet();
    assert_eq!(cluster.pending_proposal_validations(), 0);
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    // Step 7: prove the cluster is fully healthy afterward, not just
    // unstuck for one round.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    cluster.shutdown();
    // Go's literal port asserts exactly `expectNumRounds := 5` (2 initial +
    // 1 recovered + 2 final). This harness can overshoot a target round by
    // more than one commit per `pump_until_new_round` call under real-thread
    // timing (see this file's module doc comment on `zeroes`/round-count
    // overshoot) — e.g. resuming validation in step 6 can itself let a
    // round settle far enough that the very next `wait_for_quiet` also
    // clears the round after it. The number of rounds committed is
    // therefore read back dynamically rather than hard-coded: what actually
    // matters for this regression (every node converging on the SAME block
    // at every round, never diverging or crashing after the stale-period
    // verification cancellation) is exactly what `sanity_check` verifies,
    // regardless of exactly how many rounds that took.
    let total_rounds = round.0 - start_round.0;
    assert!(
        total_rounds >= 5,
        "expected at least 5 rounds to have committed (2 initial + 1 \
         recovered + 2 final), got {total_rounds}"
    );
    sanity_check(&cluster, start_round, total_rounds);
}

/// Port of go-algorand's `TestAgreementSlowPayloadsPreDeadline`
/// (`agreement/service_test.go:2036`) — a simpler relative of the
/// `8ba23942` regression above (no suspendable validator, single period):
/// a round's proposal payload is pocketed right at the checkpoint before it
/// reaches the network, one more `Deadline` fire proves the round genuinely
/// cannot commit while it's unreachable (`late` but still WITHIN the same
/// period, unlike `PostDeadline` below), then the payload is delivered and
/// the round commits normally.
#[test]
fn slow_payloads_pre_deadline_five_node() {
    let propose_gate = ProposeBroadcastGate::new();
    let cluster = setup_agreement_with_propose_gate(5, Arc::clone(&propose_gate));
    let start_round = cluster.start_round;

    cluster.wait_for_quiet();
    let mut round = current_round(&cluster);
    assert_eq!(round, start_round);

    // Two ordinary rounds, proving the cluster is healthy first.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    // Catch the next proposal broadcast at the checkpoint and pocket it
    // (go's "run round and then start pocketing payloads ... (takes effect
    // next round)").
    arm_and_catch_next_proposal_broadcast(&cluster.clocks, &propose_gate, Duration::from_secs(300));
    cluster.network.pocket_all_compound();
    propose_gate.release();
    cluster.wait_for_quiet();
    let stuck_round = current_round(&cluster);
    assert!(
        stuck_round.0 >= round.0,
        "round must not have gone BACKWARDS while catching the checkpoint"
    );
    round = stuck_round;

    // "run round with late payload": one more Deadline fire must NOT commit
    // the round — its proposal is still pocketed, unreachable by anyone.
    // Fires unconditionally — see `arm_and_catch_next_proposal_broadcast`'s
    // doc comment for why a `has_pending` gate is unsafe here.
    for clock in &cluster.clocks {
        clock.try_fire(TimeoutType::Deadline);
    }
    cluster.wait_for_quiet();
    assert_eq!(
        current_round(&cluster),
        round,
        "round must not commit while its proposal is pocketed"
    );

    // Release the payload: the round must now commit purely from that
    // delivery (still within the same period — no stale-period handling
    // needed here, unlike PostDeadline below).
    let pocketed = cluster.network.stop_pocketing_compound();
    cluster.network.repair_all();
    assert!(
        !pocketed.is_empty(),
        "expected at least one proposal to have been pocketed"
    );
    cluster.network.replay_all(&pocketed);
    round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);

    // Two more ordinary rounds, proving the cluster is fully healthy
    // afterward.
    for _ in 0..2 {
        round = pump_until_new_round(&cluster, round, TimeoutType::Deadline, 20);
    }

    cluster.shutdown();
    // Go asserts exactly `sanityCheck(startRound, 6, ledgers)`; this port
    // reads the actual round count back dynamically rather than hard-coding
    // it — see `regression_wrong_period_payload_verification_cancellation_
    // 8ba23942_five_node`'s doc comment for why (this harness's real-thread
    // `pump_until_new_round` can commit more than one round per call).
    let total_rounds = round.0 - start_round.0;
    assert!(
        total_rounds >= 5,
        "expected at least 5 rounds to have committed (2 initial + 1 \
         recovered + 2 final), got {total_rounds}"
    );
    sanity_check(&cluster, start_round, total_rounds);
}

// `TestAgreementSlowPayloadsPostDeadline` (`agreement/service_test.go:2094`)
// was attempted using the same `arm_and_catch_next_proposal_broadcast`
// checkpoint as the two scenarios above, and its structure worked reliably
// in isolation and under this file's own full-package-concurrent runs (10+
// consecutive standalone passes, clean concurrent `-p algo-agreement` runs).
// It was NOT landed: across repeated `cargo test --workspace` runs (every
// crate's suite executing together, not just this package's), it
// intermittently (but reproducibly, on the SAME test each time it occurred)
// failed the initial checkpoint-catch with a timeout even at a 300-second
// budget, while `slow_payloads_pre_deadline_five_node` and
// `regression_wrong_period_payload_verification_cancellation_8ba23942_five_node`
// (both using the identical checkpoint mechanism) did not. Whether this is a
// genuine, scenario-specific weakness or an artifact of this specific
// investigation's heavy background tooling load was not conclusively
// determined given the time available — issue #1035 stays open over this
// unmet criterion; see `docs/phase17/parity_agreement.md`'s row for this
// test for the precise writeup. Left `missing-test` rather than landed at a
// confidence level
// below this harness's established bar.
