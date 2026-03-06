use algo_types::{AccountData, AccountStatus};

/// Reward calculation granularity: microAlgos per whole Algo.
/// Rewards are computed per whole-Algo unit held.
pub const REWARD_UNITS: u64 = 1_000_000;

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
}
