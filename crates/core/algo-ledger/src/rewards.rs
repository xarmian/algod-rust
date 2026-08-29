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

use algo_types::{AccountData, AccountStatus};

/// Reward calculation granularity: microAlgos per whole Algo.
/// Rewards are computed per whole-Algo unit held.
pub const REWARD_UNITS: u64 = 1_000_000;

/// Compute `(a * b) / c` using 128-bit intermediate to avoid overflow.
///
/// Returns `(result, overflowed)` where `overflowed` is `true` if the result
/// does not fit in a `u64`. Matches Go's `Muldiv` in `data/basics/overflow.go`:
/// it uses `bits.Mul64` / `bits.Div64`; we use Rust's native `u128`.
///
/// If `c == 0` and `a * b != 0`, this overflows (returns `(0, true)`).
pub fn muldiv(a: u64, b: u64, c: u64) -> (u64, bool) {
    let product = (a as u128) * (b as u128);
    let hi = (product >> 64) as u64;
    // Match Go: `if c <= hi { return 0, true }`
    if c <= hi {
        return (0, true);
    }
    // Safe: c > hi guarantees the quotient fits in u64
    let quo = product / (c as u128);
    (quo as u64, false)
}

/// Compute the normalized online balance for an account.
///
/// This matches Go's `NormalizedOnlineAccountBalance` in
/// `data/basics/userBalance.go`. The normalization compensates for rewards
/// that have not yet been applied, producing a balance estimate as of round 0.
///
/// Panics on overflow (matching Go's behavior).
pub fn normalized_online_balance(
    status: AccountStatus,
    micro_algos: u64,
    rewards_base: u64,
    reward_unit: u64,
) -> u64 {
    if status != AccountStatus::Online {
        return 0;
    }

    let per_reward_unit = rewards_base
        .checked_add(reward_unit)
        .expect("rewards_base + reward_unit overflow");
    let (norm, overflowed) = muldiv(micro_algos, reward_unit, per_reward_unit);
    if overflowed {
        panic!(
            "overflow computing normalized balance {} * {} / ({} + {})",
            micro_algos, reward_unit, rewards_base, reward_unit
        );
    }
    norm
}

/// Compute pending (unclaimed) rewards for an account given the current
/// rewards level from the block header.
///
/// Returns 0 for accounts that are not participating or have zero balance.
/// Uses wrapping arithmetic to match Go's uint64 overflow behavior.
pub fn compute_pending_rewards(account: &AccountData, rewards_level: u64) -> u64 {
    if account.status == AccountStatus::NotParticipating || account.micro_algos == 0 {
        return 0;
    }

    rewards_level
        .wrapping_sub(account.rewards_base)
        .wrapping_mul(account.micro_algos / REWARD_UNITS)
}

/// Apply pending rewards to an account, updating its balance and rewards
/// tracking fields. Returns the reward amount earned.
///
/// After this call:
/// - `micro_algos` is increased by the pending reward
/// - `rewarded_micro_algos` is increased by the pending reward
/// - `rewards_base` is set to the current `rewards_level`
pub fn apply_rewards(account: &mut AccountData, rewards_level: u64) -> u64 {
    let pending = compute_pending_rewards(account, rewards_level);
    if pending > 0 {
        account.micro_algos = account.micro_algos.wrapping_add(pending);
        account.rewarded_micro_algos = account.rewarded_micro_algos.wrapping_add(pending);
    }
    account.rewards_base = rewards_level;
    pending
}

/// The reward-relevant portion of a block header that advances via the rewards
/// schedule, mirroring the calculation inputs/outputs of go-algorand's
/// `bookkeeping.RewardsState.NextRewardsState`. `fee_sink`/`rewards_pool` are
/// carried in the header directly and are not part of this calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewardsState {
    /// Cumulative rewards per reward unit distributed so far.
    pub rewards_level: u64,
    /// MicroAlgos distributed per reward unit per round.
    pub rewards_rate: u64,
    /// Leftover microAlgos carried to the next round (sub-unit remainder).
    pub rewards_residue: u64,
    /// Round at which the rewards rate is recalculated from the pool balance.
    pub rewards_recalculation_round: u64,
}

/// Advance the rewards state for `next_round`, mirroring go-algorand's
/// `RewardsState.NextRewardsState` (`data/bookkeeping/block.go`).
///
/// `incentive_pool_balance` is the rewards-pool account balance and
/// `total_reward_units` is the network-wide reward-unit count, both read from
/// the ledger by the caller — exactly as go's evaluator does in
/// `eval.StartEvaluator`.
///
/// `params.pending_residue_rewards` (v18+) and `params.rewards_calculation_fix`
/// (v31+) are version-gated so that replaying a historical block from before
/// each fix's real activation round reproduces go-algorand's canonical
/// (pre-fix) result rather than the modern one unconditionally.
///
/// Overflow semantics mirror go's `OverflowTracker`: an overflow in the level
/// advance abandons it and keeps the previous level (with any refreshed
/// rate/recalculation round already applied), rather than panicking.
pub fn next_rewards_state(
    prev: RewardsState,
    next_round: u64,
    params: &algo_types::ConsensusParams,
    incentive_pool_balance: u64,
    total_reward_units: u64,
) -> RewardsState {
    let mut res = prev;

    // Time to refresh the rewards rate from the current pool balance.
    if next_round == res.rewards_recalculation_round {
        // PendingResidueRewards (v18+): the outstanding residue counts
        // against what the pool may spend on the next rate. Before v18, only
        // MinBalance was reserved.
        let max_spent_over = if params.pending_residue_rewards {
            match params.min_balance.checked_add(res.rewards_residue) {
                Some(v) => v,
                // Overflow (go's OAdd overflowed): spend the whole pool so the
                // new rate becomes 0.
                None => incentive_pool_balance,
            }
        } else {
            params.min_balance
        };
        let new_rate = incentive_pool_balance.saturating_sub(max_spent_over);
        // RewardsRateRefreshInterval is a positive consensus param; guard a
        // degenerate 0 to avoid a divide-by-zero.
        res.rewards_rate = new_rate
            .checked_div(params.rewards_rate_refresh_interval)
            .unwrap_or_default();
        // go computes `nextRound + Round(interval)` with plain unsigned
        // (wrapping) arithmetic; use wrapping_add for bit-for-bit parity rather
        // than saturating (which would clamp at u64::MAX) in this consensus
        // state transition.
        res.rewards_recalculation_round =
            next_round.wrapping_add(params.rewards_rate_refresh_interval);
    }

    if total_reward_units == 0 {
        // No reward units in circulation → keep the previous level (the
        // rate/recalculation round refreshed above still stand).
        return res;
    }

    // RewardsCalculationFix (v31+): use the freshly-refreshed rate immediately.
    // Before v31, use the rate as it stood before this round's refresh.
    let rewards_rate = if params.rewards_calculation_fix {
        res.rewards_rate
    } else {
        prev.rewards_rate
    };

    // Mirror go's OverflowTracker: abandon the level advance on overflow.
    let rewards_with_residue = match rewards_rate.checked_add(res.rewards_residue) {
        Some(v) => v,
        None => return res,
    };
    let next_reward_level = match res
        .rewards_level
        .checked_add(rewards_with_residue / total_reward_units)
    {
        Some(v) => v,
        None => return res,
    };
    let next_residue = rewards_with_residue % total_reward_units;

    res.rewards_level = next_reward_level;
    res.rewards_residue = next_residue;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_balance_no_rewards() {
        let account = AccountData::default();
        assert_eq!(compute_pending_rewards(&account, 100), 0);
    }

    #[test]
    fn test_not_participating_no_rewards() {
        let account = AccountData {
            micro_algos: 10_000_000,
            status: AccountStatus::NotParticipating,
            ..Default::default()
        };
        assert_eq!(compute_pending_rewards(&account, 100), 0);
    }

    #[test]
    fn test_basic_reward_computation() {
        let account = AccountData {
            micro_algos: 5_000_000, // 5 Algos = 5 reward units
            rewards_base: 10,
            status: AccountStatus::Online,
            ..Default::default()
        };
        // (20 - 10) * (5_000_000 / 1_000_000) = 10 * 5 = 50
        assert_eq!(compute_pending_rewards(&account, 20), 50);
    }

    #[test]
    fn test_offline_gets_rewards() {
        let account = AccountData {
            micro_algos: 2_000_000,
            rewards_base: 0,
            status: AccountStatus::Offline,
            ..Default::default()
        };
        // Offline accounts still earn rewards (only NotParticipating is excluded)
        assert_eq!(compute_pending_rewards(&account, 100), 200);
    }

    #[test]
    fn test_apply_rewards_updates_fields() {
        let mut account = AccountData {
            micro_algos: 3_000_000,
            rewards_base: 5,
            status: AccountStatus::Online,
            ..Default::default()
        };
        let earned = apply_rewards(&mut account, 15);
        // (15 - 5) * 3 = 30
        assert_eq!(earned, 30);
        assert_eq!(account.micro_algos, 3_000_030);
        assert_eq!(account.rewarded_micro_algos, 30);
        assert_eq!(account.rewards_base, 15);
    }

    #[test]
    fn test_apply_rewards_no_pending() {
        let mut account = AccountData {
            micro_algos: 1_000_000,
            rewards_base: 50,
            status: AccountStatus::Online,
            ..Default::default()
        };
        let earned = apply_rewards(&mut account, 50);
        assert_eq!(earned, 0);
        assert_eq!(account.micro_algos, 1_000_000);
        assert_eq!(account.rewards_base, 50);
    }

    #[test]
    fn test_sub_unit_balance_no_rewards() {
        // Balance < REWARD_UNITS means micro_algos / REWARD_UNITS = 0
        let account = AccountData {
            micro_algos: 999_999,
            rewards_base: 0,
            status: AccountStatus::Online,
            ..Default::default()
        };
        assert_eq!(compute_pending_rewards(&account, 100), 0);
    }

    // ── muldiv tests ──────────────────────────────────────────────────

    #[test]
    fn test_muldiv_basic() {
        // 10 * 20 / 3 = 66 (integer division)
        let (result, overflowed) = muldiv(10, 20, 3);
        assert!(!overflowed);
        assert_eq!(result, 66);
    }

    #[test]
    fn test_muldiv_exact() {
        // 6 * 7 / 42 = 1
        let (result, overflowed) = muldiv(6, 7, 42);
        assert!(!overflowed);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_muldiv_zero_numerator() {
        let (result, overflowed) = muldiv(0, 1_000_000, 500);
        assert!(!overflowed);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_muldiv_large_no_overflow() {
        // u64::MAX * 2 / 3 fits in u64
        let (result, overflowed) = muldiv(u64::MAX, 2, 3);
        assert!(!overflowed);
        assert_eq!(result, 12_297_829_382_473_034_410);
    }

    #[test]
    fn test_muldiv_overflow() {
        // u64::MAX * u64::MAX / 1 — hi word exceeds c
        let (result, overflowed) = muldiv(u64::MAX, u64::MAX, 1);
        assert!(overflowed);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_muldiv_division_by_zero() {
        // c=0 <= hi=0 => overflowed per Go semantics
        let (result, overflowed) = muldiv(5, 3, 0);
        assert!(overflowed);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_muldiv_zero_times_zero_div_zero() {
        // 0*0/0: product=0, hi=0, c=0 <= 0 => overflowed
        let (result, overflowed) = muldiv(0, 0, 0);
        assert!(overflowed);
        assert_eq!(result, 0);
    }

    // ── normalized_online_balance tests ────────────────────────────────

    #[test]
    fn test_nob_offline_returns_zero() {
        assert_eq!(
            normalized_online_balance(AccountStatus::Offline, 10_000_000, 100, REWARD_UNITS),
            0
        );
    }

    #[test]
    fn test_nob_not_participating_returns_zero() {
        assert_eq!(
            normalized_online_balance(
                AccountStatus::NotParticipating,
                10_000_000,
                100,
                REWARD_UNITS
            ),
            0
        );
    }

    #[test]
    fn test_nob_online_zero_balance() {
        assert_eq!(
            normalized_online_balance(AccountStatus::Online, 0, 100, REWARD_UNITS),
            0
        );
    }

    #[test]
    fn test_nob_online_zero_rewards_base() {
        // rewards_base=0, reward_unit=1_000_000
        // per_reward_unit = 0 + 1_000_000 = 1_000_000
        // 1_000_000 * 1_000_000 / 1_000_000 = 1_000_000
        assert_eq!(
            normalized_online_balance(AccountStatus::Online, 1_000_000, 0, REWARD_UNITS),
            1_000_000
        );
    }

    #[test]
    fn test_nob_reference_value_1() {
        // micro_algos=10_000_000_000, rewards_base=100, reward_unit=1_000_000
        // per_reward_unit = 1_000_100
        // 10_000_000_000 * 1_000_000 / 1_000_100 = 9_999_000_099
        assert_eq!(
            normalized_online_balance(AccountStatus::Online, 10_000_000_000, 100, REWARD_UNITS),
            9_999_000_099
        );
    }

    #[test]
    fn test_nob_reference_value_2() {
        // micro_algos=1_000_000, rewards_base=0, reward_unit=1_000_000
        // per_reward_unit = 1_000_000
        // 1_000_000 * 1_000_000 / 1_000_000 = 1_000_000
        assert_eq!(
            normalized_online_balance(AccountStatus::Online, 1_000_000, 0, REWARD_UNITS),
            1_000_000
        );
    }

    #[test]
    fn test_nob_reference_value_3() {
        // micro_algos=50_000_000_000 (50k Algo), rewards_base=500, reward_unit=1_000_000
        // per_reward_unit = 1_000_500
        // 50_000_000_000 * 1_000_000 / 1_000_500 = 49_975_012_493
        assert_eq!(
            normalized_online_balance(AccountStatus::Online, 50_000_000_000, 500, REWARD_UNITS),
            49_975_012_493
        );
    }

    #[test]
    fn test_nob_large_balance() {
        // Near-max balance: 10^18 microAlgos, rewards_base=1000
        // per_reward_unit = 1_001_000
        // 1_000_000_000_000_000_000 * 1_000_000 / 1_001_000
        // This is a large value but should not overflow u64
        let result = normalized_online_balance(
            AccountStatus::Online,
            1_000_000_000_000_000_000,
            1_000,
            REWARD_UNITS,
        );
        // 1e18 * 1e6 / 1_001_000 = 999_000_999_000_999_000 (integer division)
        assert_eq!(result, 999_000_999_000_999_000);
    }

    #[test]
    #[should_panic(expected = "rewards_base + reward_unit overflow")]
    fn test_nob_overflow_panics() {
        // u64::MAX rewards_base + any reward_unit > 0 must overflow the checked_add
        normalized_online_balance(AccountStatus::Online, 1_000_000, u64::MAX, 1);
    }

    // ── next_rewards_state tests (vs go bookkeeping.NextRewardsState) ───

    fn v41() -> algo_types::ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    fn params_for(version: &str) -> algo_types::ConsensusParams {
        algo_types::consensus::consensus_params_for_version(version)
            .unwrap_or_else(|| panic!("{version} params"))
    }

    // ── PendingResidueRewards activation boundary (v17 -> v18) ─────────

    #[test]
    fn test_pending_residue_rewards_flag_activation() {
        let v17 = params_for(algo_types::consensus::CONSENSUS_V17);
        let v18 = params_for(algo_types::consensus::CONSENSUS_V18);
        assert!(!v17.pending_residue_rewards, "v17 must be pre-fix");
        assert!(v18.pending_residue_rewards, "v18 must be post-fix");
    }

    #[test]
    fn test_nrs_pending_residue_rewards_pre_v18_ignores_residue() {
        // Before v18, the residue must NOT count against the pool's
        // max-spend when refreshing the rate: maxSpentOver == MinBalance only.
        let params = params_for(algo_types::consensus::CONSENSUS_V17);
        let pool = 10_000_000_000u64;
        let prev = RewardsState {
            rewards_recalculation_round: 5,
            rewards_residue: 1_000_000,
            ..Default::default()
        };
        let next = next_rewards_state(prev, 5, &params, pool, 0);
        let expected_rate = (pool - params.min_balance) / params.rewards_rate_refresh_interval;
        assert_eq!(
            next.rewards_rate, expected_rate,
            "pre-v18 residue must not reduce the refreshed rate"
        );
    }

    #[test]
    fn test_nrs_pending_residue_rewards_v18_counts_residue() {
        // At/after v18, the residue DOES count against the pool's max-spend.
        let params = params_for(algo_types::consensus::CONSENSUS_V18);
        let pool = 10_000_000_000u64;
        let residue = 1_000_000u64;
        let prev = RewardsState {
            rewards_recalculation_round: 5,
            rewards_residue: residue,
            ..Default::default()
        };
        let next = next_rewards_state(prev, 5, &params, pool, 0);
        let expected_rate =
            (pool - (params.min_balance + residue)) / params.rewards_rate_refresh_interval;
        assert_eq!(
            next.rewards_rate, expected_rate,
            "v18+ residue must reduce the refreshed rate"
        );
    }

    // ── RewardsCalculationFix activation boundary (v30 -> v31) ─────────

    #[test]
    fn test_rewards_calculation_fix_flag_activation() {
        let v30 = params_for(algo_types::consensus::CONSENSUS_V30);
        let v31 = params_for(algo_types::consensus::CONSENSUS_V31);
        assert!(!v30.rewards_calculation_fix, "v30 must be pre-fix");
        assert!(v31.rewards_calculation_fix, "v31 must be post-fix");
    }

    #[test]
    fn test_nrs_rewards_calculation_fix_pre_v31_uses_stale_rate() {
        // Before v31, a rate refresh that happens on the SAME round as a
        // level advance must use the *previous* round's rate for that
        // advance, not the freshly-refreshed one.
        let params = params_for(algo_types::consensus::CONSENSUS_V30);
        let pool = 10_000_000_000u64;
        let prev = RewardsState {
            rewards_level: 100,
            rewards_rate: 42, // stale rate, used pre-fix
            rewards_residue: 0,
            rewards_recalculation_round: 5, // triggers a refresh this round
        };
        let total_reward_units = 100u64;
        let next = next_rewards_state(prev, 5, &params, pool, total_reward_units);
        // rewardsWithResidue = stale rate (42) + residue (0) = 42
        let rewards_with_residue = prev.rewards_rate + prev.rewards_residue;
        let expected_level = prev.rewards_level + rewards_with_residue / total_reward_units;
        let expected_residue = rewards_with_residue % total_reward_units;
        assert_eq!(
            next.rewards_level, expected_level,
            "pre-v31 must advance the level using the stale (pre-refresh) rate"
        );
        assert_eq!(next.rewards_residue, expected_residue);
        // Sanity: the refreshed rate differs from the stale rate used above,
        // proving this test actually exercises the "use stale rate" branch.
        assert_ne!(next.rewards_rate, 42);
    }

    #[test]
    fn test_nrs_rewards_calculation_fix_v31_uses_fresh_rate() {
        // At/after v31, the SAME refresh-and-advance round must use the
        // freshly-refreshed rate for the level advance.
        let params = params_for(algo_types::consensus::CONSENSUS_V31);
        let pool = 10_000_000_000u64;
        let prev = RewardsState {
            rewards_level: 100,
            rewards_rate: 42, // stale rate, must NOT be used post-fix
            rewards_residue: 0,
            rewards_recalculation_round: 5,
        };
        let next = next_rewards_state(prev, 5, &params, pool, 100);
        let refreshed_rate =
            pool.saturating_sub(params.min_balance) / params.rewards_rate_refresh_interval;
        let expected_level = 100 + refreshed_rate / 100;
        let expected_residue = refreshed_rate % 100;
        assert_eq!(
            next.rewards_level, expected_level,
            "v31+ must advance the level using the freshly-refreshed rate"
        );
        assert_eq!(next.rewards_residue, expected_residue);
    }

    #[test]
    fn test_nrs_zero_rate_keeps_level() {
        // No recalc this round, rate 0 → level/residue unchanged.
        let prev = RewardsState {
            rewards_level: 5,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: 1000,
        };
        let next = next_rewards_state(prev, 10, &v41(), 10_000_000, 100);
        assert_eq!(next, prev);
    }

    #[test]
    fn test_nrs_rate_advances_level_and_residue() {
        // rewardsWithResidue = rate + residue = 250 + 30 = 280
        // level += 280 / 100 = 2 → 102 ; residue = 280 % 100 = 80
        let prev = RewardsState {
            rewards_level: 100,
            rewards_rate: 250,
            rewards_residue: 30,
            rewards_recalculation_round: 1000,
        };
        let next = next_rewards_state(prev, 10, &v41(), 10_000_000, 100);
        assert_eq!(
            next,
            RewardsState {
                rewards_level: 102,
                rewards_rate: 250,
                rewards_residue: 80,
                rewards_recalculation_round: 1000,
            }
        );
    }

    #[test]
    fn test_nrs_zero_reward_units_keeps_level() {
        // totalRewardUnits == 0 → level/residue unchanged (no recalc here).
        let prev = RewardsState {
            rewards_level: 7,
            rewards_rate: 999,
            rewards_residue: 5,
            rewards_recalculation_round: 1000,
        };
        let next = next_rewards_state(prev, 10, &v41(), 10_000_000, 0);
        assert_eq!(next, prev);
    }

    #[test]
    fn test_nrs_recalc_round_refreshes_rate() {
        // At the recalculation round, the rate refreshes to
        // (pool - (min_balance + residue)) / refresh_interval and the next
        // recalculation round advances by the refresh interval. Use
        // total_reward_units = 0 so the level stays put and we isolate the
        // refresh. (Mirrors go's PendingResidueRewards + recalc path.)
        let params = v41();
        let pool = 10_000_000_000u64;
        let prev = RewardsState {
            rewards_level: 0,
            rewards_rate: 1,
            rewards_residue: 0,
            rewards_recalculation_round: 5,
        };
        let next = next_rewards_state(prev, 5, &params, pool, 0);
        let expected_rate = (pool - params.min_balance) / params.rewards_rate_refresh_interval;
        assert_eq!(next.rewards_rate, expected_rate, "rate refreshed from pool");
        assert_eq!(
            next.rewards_recalculation_round,
            5 + params.rewards_rate_refresh_interval,
            "recalc round advanced by the refresh interval",
        );
        assert_eq!(
            next.rewards_level, 0,
            "level unchanged when no reward units"
        );
    }

    #[test]
    fn test_nrs_recalc_residue_counts_against_pool() {
        // PendingResidueRewards: residue is subtracted along with min_balance,
        // so a larger residue yields a smaller (or equal) refreshed rate.
        let params = v41();
        let pool = 10_000_000_000u64;
        let base = RewardsState {
            rewards_recalculation_round: 5,
            ..Default::default()
        };
        let no_residue = next_rewards_state(base, 5, &params, pool, 0).rewards_rate;
        let with_residue = next_rewards_state(
            RewardsState {
                rewards_residue: 1_000_000,
                ..base
            },
            5,
            &params,
            pool,
            0,
        )
        .rewards_rate;
        assert!(
            with_residue <= no_residue,
            "residue must not increase the refreshed rate ({with_residue} > {no_residue})",
        );
    }
}
