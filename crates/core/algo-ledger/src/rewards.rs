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
}
