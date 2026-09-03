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

//! Cross-round voters-snapshot cache -- go's `ledger/voters.go::votersTracker`
//! -- wiring `crate::voters`'s selection/commitment math (issue #758) into
//! real block production and validation (issue #780).
//!
//! # The two rounds involved
//!
//! Every state-proof interval boundary involves two distinct rounds:
//!
//! - The **snapshot round** `r`, where `(r + StateProofVotersLookback) %
//!   StateProofInterval == 0`: the round whose *just-committed* online-account
//!   state is captured -- [`record_voters_snapshot`], called from
//!   `apply::apply_block_impl` on every applied block, mirrors go's
//!   `votersTracker.newBlock`.
//! - The **consuming round** `r + StateProofVotersLookback` (a
//!   `StateProofInterval` multiple): the block whose own header's `"spt"`
//!   map's `"v"`/`"t"` fields are filled from that snapshot --
//!   [`expected_voters_tracking`], used identically by block *production*
//!   (`bin/algod-rust`'s `start_evaluator`) and block *validation*
//!   (`apply::apply_block_impl`'s `ctx.validate` branch), mirrors go's
//!   `stateProofVotersAndTotal`.
//!
//! Because algod-rust's ledger backends (`LedgerState`, `SqliteLedger`) hold
//! only the *current* committed state (no historical per-round account
//! snapshots), the snapshot must be taken synchronously, in the same call
//! that applies the snapshot round's block -- there is no way to later ask
//! "what were the online accounts as of round r" after round r+1 has been
//! applied. This differs from go's `votersTracker.loadTree`, which spawns a
//! background goroutine (`VotersForStateProof` blocks on its completion);
//! algod-rust does the equivalent work inline, which is fine at the actual
//! sizes involved (`StateProofTopVoters` truncates the tree to at most 1024
//! participants).
//!
//! # Full participant retention (issue #912)
//!
//! [`record_voters_snapshot`] persists **both** the compact
//! `(voters_commitment, online_total_weight)` pair (via
//! `LedgerStore::put_voters_snapshot`, sufficient to verify a state-proof
//! transaction already in a block, `apply_stateproof.rs`) **and** the full
//! `Vec<Participant>` array itself (via
//! `LedgerStore::put_voters_participants`), under the same round key. The
//! latter is what a state-proof signing/proving daemon needs to *build* a
//! proof: go's equivalent is `ledgercore.VotersForRound.Participants`/
//! `.Tree`, fetched via `Ledger.VotersForStateProof(lookback)`
//! (`stateproof/abstractions.go:44`) and persisted by the `stateproof`
//! package's own `provers` table (`stateproof/db.go`) once the state-proof
//! round is reached. algod-rust collapses this into one persistence point
//! at snapshot time instead of two (see [`voters_participants_and_tree`] for
//! retrieval) -- the vector-commitment tree itself is never stored, since
//! `crate::voters::commit_participants` deterministically rebuilds it
//! byte-for-byte from the persisted array alone.
//!
//! # Retention
//!
//! [`prune_voters_snapshots`] mirrors go's `removeOldVoters`: a snapshot at
//! round `r` is discarded once `r + StateProofVotersLookback +
//! StateProofInterval` (the state-proof round it serves) falls below the
//! oldest state proof round the ledger still expects
//! (`stateproof.GetOldestExpectedStateProof`, ported here as
//! [`get_oldest_expected_state_proof`]). The full participant array (issue
//! #912) is pruned on the identical schedule, alongside the compact
//! snapshot -- matching go's `deleteStaleProver` (`stateproof/builder.go:593`),
//! which likewise retains a persisted prover only until
//! `StateProofNextRound` (the same bound `get_oldest_expected_state_proof`
//! computes) has advanced past it. `stateproof_worker::PROVERS_CACHE_LENGTH`
//! (go's `proversCacheLength`) is a *different* bound -- it caps how many
//! provers a signing/proving daemon keeps in its own *in-memory* map
//! (`stateproof/worker.go:40`), not how long this disk-persisted array is
//! retained, so it is deliberately not reused here.

use algo_consensus_crypto::{merklearray, stateproof as crypto_sp};
use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::AccountData;

use crate::block_header::state_proof_next_round;
use crate::rewards::compute_pending_rewards;
use crate::store_trait::LedgerStore;
use crate::voters::{
    build_voters_tree_and_participants, commit_participants, select_top_online_accounts,
    OnlineAccountCandidate,
};

fn ledger_err(message: impl Into<String>) -> AlgoError {
    AlgoError::Ledger {
        message: message.into(),
    }
}

/// go's `basics.Round.SubSaturate`: `a.saturating_sub(b)`, applied twice --
/// used by both [`voters_round_for_state_proof_round`] and (inverted, as an
/// add) the snapshot/consume round relationship elsewhere in this module.
fn sub_saturate(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

/// go's `votersRoundForStateProofRound` (`ledger/voters.go:108`): the round
/// whose voting participants sign the state proof for `state_proof_round`.
pub fn voters_round_for_state_proof_round(
    state_proof_round: u64,
    interval: u64,
    lookback: u64,
) -> u64 {
    sub_saturate(sub_saturate(state_proof_round, interval), lookback)
}

/// go's `votersTracker.newBlock` snapshot-round predicate
/// (`ledger/voters.go:207`): `(round + lookback) % interval == 0`.
/// `interval == 0` (state proofs disabled) is never a voters round.
pub fn is_voters_round(round: u64, lookback: u64, interval: u64) -> bool {
    interval != 0 && round.saturating_add(lookback) % interval == 0
}

/// Port of go's `stateproof.GetOldestExpectedStateProof`
/// (`stateproof/recovery.go`): the lowest round for which the node should
/// still be able to produce/verify a state proof, given the latest header's
/// round, its protocol's params, and its own tracked `StateProofNextRound`.
pub fn get_oldest_expected_state_proof(
    latest_round: u64,
    state_proof_next_round_value: u64,
    interval: u64,
    max_recovery_intervals: u64,
) -> u64 {
    if interval == 0 {
        return 0;
    }
    let recent_round_on_recovery_period = latest_round - (latest_round % interval);
    let oldest_round_on_recovery_period = sub_saturate(
        recent_round_on_recovery_period,
        interval * max_recovery_intervals,
    );

    if state_proof_next_round_value > oldest_round_on_recovery_period {
        state_proof_next_round_value
    } else {
        oldest_round_on_recovery_period
    }
}

/// go's `votersTracker.removeOldVoters` per-entry deletion predicate
/// (`ledger/voters.go:257`): a snapshot taken at `snapshot_round` is removed
/// once the state-proof round it exists to serve
/// (`snapshot_round + lookback + interval`) falls below
/// `lowest_state_proof_round`.
pub fn should_remove_voters_snapshot(
    snapshot_round: u64,
    lowest_state_proof_round: u64,
    lookback: u64,
    interval: u64,
) -> bool {
    let commit_round = snapshot_round.saturating_add(lookback);
    let state_proof_round = commit_round.saturating_add(interval);
    state_proof_round < lowest_state_proof_round
}

/// Convert a ledger `AccountData` into the [`OnlineAccountCandidate`] shape
/// `crate::voters`'s selection math reads.
fn to_candidate(addr: algo_types::Address, acct: &AccountData) -> OnlineAccountCandidate {
    OnlineAccountCandidate {
        address: addr,
        micro_algos: acct.micro_algos,
        rewards_base: acct.rewards_base,
        vote_first_valid: acct.vote_first_valid,
        vote_last_valid: acct.vote_last_valid,
        state_proof_id: acct.state_proof_id.unwrap_or([0u8; 64]),
    }
}

/// go's `onlineAccounts.TopOnlineAccounts`'s `totalOnlineStake` return value:
/// the rewards-extrapolated balance of *every* online account (not just the
/// selected top-N), minus -- when `exclude_expired` (go's
/// `ExcludeExpiredCirculation`, v38+) -- the stake behind participation keys
/// that will have expired by `vote_rnd` (go's `expiredOnlineCirculation`).
///
/// Unlike go, which draws the total and the expired-subset from two
/// independently-maintained figures that can disagree by a small amount
/// (see `SqliteLedger::online_circulation_at_round`'s own doc comment on
/// exactly that skew), this sums both from the *same* `accounts` slice in
/// one pass, so the subtraction can never underflow.
///
/// Accumulates in `u128` and saturates into `u64` at the end -- deliberately
/// lenient (matching this crate's existing `saturating_*` style for
/// aggregate-money arithmetic, e.g. `block_header::saturating_mul_micros`)
/// rather than erroring: an aggregate over the entire online-account
/// population overflowing `u64` microAlgos is not a realistic condition this
/// code needs to treat as fatal.
fn total_online_stake(
    accounts: &[(algo_types::Address, AccountData)],
    rewards_level: u64,
    vote_rnd: u64,
    exclude_expired: bool,
) -> u64 {
    let mut total: u128 = 0;
    let mut expired: u128 = 0;
    for (_, acct) in accounts {
        let pending = compute_pending_rewards(acct, rewards_level);
        let money = acct.micro_algos as u128 + pending as u128;
        total += money;
        if exclude_expired && acct.vote_last_valid != 0 && vote_rnd > acct.vote_last_valid {
            expired += money;
        }
    }
    let total = total.min(u64::MAX as u128) as u64;
    let expired = expired.min(u64::MAX as u128) as u64;
    if exclude_expired {
        total.saturating_sub(expired)
    } else {
        total
    }
}

/// Record a voters snapshot for the block just applied at `round`, if it's a
/// snapshot round (`is_voters_round`) -- mirrors go's
/// `votersTracker.newBlock`/`loadTree`. A no-op (not an error) when state
/// proofs are disabled or `round` isn't a snapshot round, matching go
/// silently skipping non-snapshot rounds.
///
/// `rewards_level` is the just-applied block's own `RewardsLevel` (governs
/// the rewards-adjusted weight, matching go's `LoadTree`, which reads
/// `hdr.RewardsLevel`).
pub fn record_voters_snapshot<L: LedgerStore>(
    store: &mut L,
    round: u64,
    rewards_level: u64,
    params: &ConsensusParams,
) -> Result<(), AlgoError> {
    let interval = params.state_proof_interval;
    let lookback = params.state_proof_voters_lookback;
    if !is_voters_round(round, lookback, interval) {
        return Ok(());
    }

    // The round whose voting participants this snapshot will serve --
    // go's `stateProofRound := r + lookback + interval` (`LoadTree`).
    let vote_rnd = round.saturating_add(lookback).saturating_add(interval);

    let accounts = store.online_accounts();
    let candidates: Vec<OnlineAccountCandidate> = accounts
        .iter()
        .map(|(addr, acct)| to_candidate(*addr, acct))
        .collect();

    let selected = select_top_online_accounts(
        &candidates,
        params.state_proof_top_voters,
        vote_rnd,
        params.reward_unit,
    );
    let (root, _selected_only_weight, participants) =
        build_voters_tree_and_participants(&selected, rewards_level, params.reward_unit)
            .map_err(|e| ledger_err(format!("record_voters_snapshot: {e}")))?;

    // The real `StateProofOnlineTotalWeight` is the network-wide online
    // total (go's `onlineTotalsEx`), not the sum of the *selected* top-N
    // participants -- see this module's `total_online_stake` doc comment.
    let total_weight = total_online_stake(
        &accounts,
        rewards_level,
        vote_rnd,
        params.exclude_expired_circulation,
    );

    store.put_voters_snapshot(round, root, total_weight)?;
    // Full participant array (issue #912): persisted alongside the compact
    // commitment above, at the same round key, so a state-proof
    // signing/proving daemon can later rebuild the vector-commitment tree
    // and a `stateproof::Prover` -- see `voters_participants_and_tree`.
    store.put_voters_participants(round, &participants)
}

/// Prune voters snapshots no longer needed, given the block just applied at
/// `round` (whose own `state_proof_tracking` carries the ledger's current
/// `StateProofNextRound`) -- mirrors go's
/// `votersTracker.postCommit`/`removeOldVoters`, called every round
/// regardless of whether it was itself a snapshot round.
pub fn prune_voters_snapshots<L: LedgerStore>(
    store: &mut L,
    round: u64,
    state_proof_tracking: &Option<rmpv::Value>,
    params: &ConsensusParams,
) -> Result<(), AlgoError> {
    let interval = params.state_proof_interval;
    if interval == 0 {
        return Ok(());
    }
    let lookback = params.state_proof_voters_lookback;
    let current_next = state_proof_next_round(state_proof_tracking);
    let lowest = get_oldest_expected_state_proof(
        round,
        current_next,
        interval,
        params.state_proof_max_recovery_intervals,
    );

    for r in store.voters_snapshot_rounds()? {
        if should_remove_voters_snapshot(r, lowest, lookback, interval) {
            store.delete_voters_snapshot(r)?;
            // The full participant array (issue #912) is retained under the
            // same round key and is no longer needed once its compact
            // snapshot counterpart is pruned -- both exist to serve the
            // same state-proof round, per `record_voters_snapshot`.
            store.delete_voters_participants(r)?;
        }
    }
    Ok(())
}

/// Retrieve the full participant array + rebuilt vector-commitment tree for
/// the voters snapshot recorded at `round` (a *snapshot* round, i.e. the
/// key [`record_voters_snapshot`] stored under -- not the consuming
/// state-proof round). Lets a state-proof signing/proving daemon
/// reconstruct exactly what `record_voters_snapshot` computed, without the
/// ledger needing to retain the `merklearray::Tree` value itself:
/// `crate::voters::commit_participants` is a pure, deterministic function of
/// the participant array's order/content (see `voters.rs`'s
/// `tree_is_deterministic_for_the_same_input`/`commit_participants_rebuilds_
/// the_same_root_as_build_voters_tree` tests), so rebuilding it here from the
/// persisted `Vec<Participant>` reproduces byte-for-byte the same tree --
/// including its root -- that was computed and committed at snapshot time.
///
/// Returns `None` when no participant array was recorded for `round` (state
/// proofs disabled at the time, `round` wasn't a snapshot round, or the
/// snapshot has since been pruned).
pub fn voters_participants_and_tree<L: LedgerStore>(
    store: &L,
    round: u64,
) -> Result<Option<(Vec<crypto_sp::Participant>, merklearray::Tree)>, AlgoError> {
    let Some(participants) = store.get_voters_participants(round)? else {
        return Ok(None);
    };
    let tree = commit_participants(&participants)
        .map_err(|e| ledger_err(format!("voters_participants_and_tree: {e}")))?;
    Ok(Some((participants, tree)))
}

/// Resolve `(voters_commitment, online_total_weight)` for the block being
/// produced/validated at `next_round` -- mirrors go's
/// `stateProofVotersAndTotal` (`ledger/eval/eval.go:1420`). Used identically
/// by block production (fills the header) and block validation (cross-checks
/// the incoming header).
///
/// Returns `(vec![], 0)` -- not an error -- whenever `next_round` isn't a
/// `StateProofInterval` multiple, or no snapshot has (yet) been recorded for
/// the round it would need: go's own `stateProofVotersAndTotal` returns
/// zeroes in both cases (`voters == nil` is not treated as an error there
/// either).
pub fn expected_voters_tracking<L: LedgerStore>(
    store: &L,
    next_round: u64,
    params: &ConsensusParams,
) -> Result<(Vec<u8>, u64), AlgoError> {
    let interval = params.state_proof_interval;
    if interval == 0 || next_round % interval != 0 {
        return Ok((Vec::new(), 0));
    }
    let lookback_round = sub_saturate(next_round, params.state_proof_voters_lookback);
    Ok(store
        .get_voters_snapshot(lookback_round)?
        .unwrap_or((Vec::new(), 0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::{AccountStatus, Address};

    fn v41() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(CONSENSUS_V41).unwrap()
    }

    fn online_account(micro_algos: u64) -> AccountData {
        AccountData {
            micro_algos,
            status: AccountStatus::Online,
            vote_first_valid: 0,
            vote_last_valid: 10_000_000,
            ..Default::default()
        }
    }

    // ── Pure helpers: oracle values from go's formulas ──────────────────

    #[test]
    fn voters_round_for_state_proof_round_matches_go_formula() {
        // v41: interval 256, lookback 16. state_proof_round 512 -> voters
        // round 512 - 256 - 16 = 240.
        assert_eq!(voters_round_for_state_proof_round(512, 256, 16), 240);
        // Saturates rather than underflowing for small rounds.
        assert_eq!(voters_round_for_state_proof_round(10, 256, 16), 0);
    }

    #[test]
    fn is_voters_round_matches_lookback_offset() {
        // (r + 16) % 256 == 0 => r == 240, 496, ...
        assert!(is_voters_round(240, 16, 256));
        assert!(is_voters_round(496, 16, 256));
        assert!(!is_voters_round(241, 16, 256));
        assert!(!is_voters_round(240, 16, 0), "disabled state proofs");
    }

    #[test]
    fn get_oldest_expected_state_proof_prefers_larger_of_next_and_recovery_floor() {
        // interval 256, max_recovery 10: recovery floor for round 2600 is
        // (2600 - 2600%256) - 2560 = 2560 - 2560 = 0.
        assert_eq!(get_oldest_expected_state_proof(2600, 0, 256, 10), 0);
        // If StateProofNextRound is ahead of the recovery floor, it wins.
        assert_eq!(get_oldest_expected_state_proof(2600, 1500, 256, 10), 1500);
        assert_eq!(
            get_oldest_expected_state_proof(100, 0, 0, 10),
            0,
            "disabled"
        );
    }

    #[test]
    fn should_remove_voters_snapshot_matches_go_formula() {
        // snapshot_round 240 -> commit 256 -> state_proof_round 512.
        assert!(should_remove_voters_snapshot(240, 513, 16, 256));
        assert!(!should_remove_voters_snapshot(240, 512, 16, 256));
        assert!(!should_remove_voters_snapshot(240, 0, 16, 256));
    }

    // ── total_online_stake: the onlineTotalsEx-equivalent ───────────────

    #[test]
    fn total_online_stake_sums_all_online_accounts_not_just_selected() {
        // Unlike build_voters_tree's returned weight (sum of the *selected*
        // top-N only), this must include every online account, even ones
        // that would be truncated out of a small top-N selection.
        let accounts = vec![
            (Address([1u8; 32]), online_account(5_000_000)),
            (Address([2u8; 32]), online_account(3_000_000)),
            (Address([3u8; 32]), online_account(1_000_000)),
        ];
        assert_eq!(total_online_stake(&accounts, 0, 100, false), 9_000_000);
    }

    #[test]
    fn total_online_stake_excludes_expired_when_flagged() {
        let mut expiring = online_account(4_000_000);
        expiring.vote_last_valid = 50; // expires before vote_rnd=100
        let accounts = vec![
            (Address([1u8; 32]), online_account(5_000_000)),
            (Address([2u8; 32]), expiring),
        ];
        // Not excluded: full total.
        assert_eq!(total_online_stake(&accounts, 0, 100, false), 9_000_000);
        // Excluded: the expiring account's stake is subtracted.
        assert_eq!(total_online_stake(&accounts, 0, 100, true), 5_000_000);
    }

    // ── record_voters_snapshot / expected_voters_tracking round trip ────

    #[test]
    fn record_then_expect_round_trips_through_the_lookback_offset() {
        let params = v41(); // interval 256, lookback 16
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));

        // Snapshot round: (240 + 16) % 256 == 0.
        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();

        // Consuming round 256 (interval multiple) looks back to 240.
        let (root, weight) = expected_voters_tracking(&store, 256, &params).unwrap();
        assert!(!root.is_empty(), "must produce a real commitment root");
        assert_eq!(weight, 10_000_000);

        // A round that isn't an interval multiple always yields zeroes.
        let (root2, weight2) = expected_voters_tracking(&store, 257, &params).unwrap();
        assert!(root2.is_empty());
        assert_eq!(weight2, 0);
    }

    #[test]
    fn expected_voters_tracking_is_zero_without_a_snapshot() {
        let params = v41();
        let store = LedgerState::new();
        // Round 256 is an interval multiple, but nothing was ever recorded
        // for round 240 -- must not error, matching go's `voters == nil`
        // zero-fill.
        let (root, weight) = expected_voters_tracking(&store, 256, &params).unwrap();
        assert!(root.is_empty());
        assert_eq!(weight, 0);
    }

    #[test]
    fn record_voters_snapshot_ignores_non_snapshot_rounds() {
        let params = v41();
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 241, 0, &params).unwrap();
        assert!(store.voters_snapshot_rounds().unwrap().is_empty());
    }

    #[test]
    fn prune_voters_snapshots_removes_entries_past_the_recovery_window() {
        let params = v41(); // interval 256, lookback 16, max_recovery 10
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();
        assert_eq!(store.voters_snapshot_rounds().unwrap(), vec![240]);

        // A round far enough ahead that round 240's served state-proof
        // round (512) is below the recovery floor.
        let far_round = 512 + 256 * 10 + 1000;
        prune_voters_snapshots(&mut store, far_round, &None, &params).unwrap();
        assert!(
            store.voters_snapshot_rounds().unwrap().is_empty(),
            "stale snapshot must be pruned"
        );
    }

    #[test]
    fn prune_voters_snapshots_keeps_entries_still_within_window() {
        let params = v41();
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();

        prune_voters_snapshots(&mut store, 300, &None, &params).unwrap();
        assert_eq!(
            store.voters_snapshot_rounds().unwrap(),
            vec![240],
            "snapshot still needed for its state proof round must survive"
        );
    }

    // ── Full participant array persistence (issue #912) ─────────────────

    #[test]
    fn record_voters_snapshot_persists_full_participant_array() {
        let params = v41(); // interval 256, lookback 16
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        store.set_account(&Address([8u8; 32]), online_account(5_000_000));

        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();

        let (participants, tree) = voters_participants_and_tree(&store, 240)
            .unwrap()
            .expect("full participant array must be retrievable at the snapshot round");
        assert_eq!(participants.len(), 2, "both online accounts were selected");

        // The rebuilt tree's root must byte-for-byte match the compact
        // commitment root recorded alongside it -- proving the array
        // round-trips through storage equivalent to what
        // `voters::build_voters_tree` computed at snapshot time.
        let (commitment_root, _weight) = store.get_voters_snapshot(240).unwrap().unwrap();
        assert_eq!(tree.root(), commitment_root);
    }

    #[test]
    fn voters_participants_and_tree_is_none_without_a_snapshot() {
        let store = LedgerState::new();
        assert!(voters_participants_and_tree(&store, 240).unwrap().is_none());
    }

    #[test]
    fn record_voters_snapshot_ignoring_non_snapshot_rounds_stores_no_participants() {
        let params = v41();
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 241, 0, &params).unwrap();
        assert!(voters_participants_and_tree(&store, 241).unwrap().is_none());
    }

    #[test]
    fn prune_voters_snapshots_also_prunes_the_participant_array() {
        let params = v41();
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();
        assert!(voters_participants_and_tree(&store, 240).unwrap().is_some());

        let far_round = 512 + 256 * 10 + 1000;
        prune_voters_snapshots(&mut store, far_round, &None, &params).unwrap();
        assert!(
            voters_participants_and_tree(&store, 240).unwrap().is_none(),
            "the full participant array must be pruned alongside the compact snapshot"
        );
    }

    #[test]
    fn prune_voters_snapshots_keeps_the_participant_array_within_window() {
        let params = v41();
        let mut store = LedgerState::new();
        store.set_account(&Address([9u8; 32]), online_account(10_000_000));
        record_voters_snapshot(&mut store, 240, 0, &params).unwrap();

        prune_voters_snapshots(&mut store, 300, &None, &params).unwrap();
        assert!(
            voters_participants_and_tree(&store, 240).unwrap().is_some(),
            "still within the retention window -- must survive alongside the compact snapshot"
        );
    }
}
