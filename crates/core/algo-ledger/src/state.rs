use std::collections::HashMap;

use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, Round,
};

/// In-memory ledger state holding all account data, asset/app state, and
/// chain-level parameters (rewards tracking, genesis info).
pub struct LedgerState {
    // Account state
    pub accounts: HashMap<Address, AccountData>,
    pub asset_holdings: HashMap<(Address, u64), AssetHolding>,
    pub app_local_states: HashMap<(Address, u64), AppLocalState>,
    pub asset_params: HashMap<u64, AssetParamsRecord>,
    pub app_params: HashMap<u64, AppParams>,

    // Current round
    pub current_round: Round,

    // Rewards tracking
    pub rewards_level: u64,
    pub rewards_rate: u64,
    pub rewards_residue: u64,
    pub rewards_recalculation_round: u64,

    // Genesis info
    pub fee_sink: Address,
    pub rewards_pool: Address,
    pub genesis_id: String,
    pub genesis_hash: [u8; 32],
    pub protocol: String,
}

impl LedgerState {
    /// Create a new empty ledger state with default values.
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            asset_holdings: HashMap::new(),
            app_local_states: HashMap::new(),
            asset_params: HashMap::new(),
            app_params: HashMap::new(),
            current_round: Round(0),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: 0,
            fee_sink: Address::ZERO,
            rewards_pool: Address::ZERO,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            protocol: String::new(),
        }
    }

    pub fn get_account(&self, addr: &Address) -> Option<&AccountData> {
        self.accounts.get(addr)
    }

    pub fn get_account_mut(&mut self, addr: &Address) -> Option<&mut AccountData> {
        self.accounts.get_mut(addr)
    }

    /// Get a mutable reference to the account, inserting a default if missing.
    pub fn get_or_default_account(&mut self, addr: &Address) -> &mut AccountData {
        self.accounts.entry(*addr).or_default()
    }

    pub fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<&AssetHolding> {
        self.asset_holdings.get(&(*addr, asset_id))
    }

    pub fn get_asset_params(&self, asset_id: u64) -> Option<&AssetParamsRecord> {
        self.asset_params.get(&asset_id)
    }

    pub fn get_app_params(&self, app_id: u64) -> Option<&AppParams> {
        self.app_params.get(&app_id)
    }

    pub fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<&AppLocalState> {
        self.app_local_states.get(&(*addr, app_id))
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state_is_empty() {
        let state = LedgerState::new();
        assert!(state.accounts.is_empty());
        assert!(state.asset_holdings.is_empty());
        assert!(state.fee_sink.is_zero());
        assert_eq!(state.rewards_level, 0);
    }

    #[test]
    fn test_get_or_default_account() {
        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);

        assert!(state.get_account(&addr).is_none());

        let account = state.get_or_default_account(&addr);
        account.micro_algos = 500_000;

        assert_eq!(state.get_account(&addr).unwrap().micro_algos, 500_000);
    }

    #[test]
    fn test_asset_holding_lookup() {
        let mut state = LedgerState::new();
        let addr = Address([2u8; 32]);
        state.asset_holdings.insert(
            (addr, 42),
            AssetHolding {
                amount: 1000,
                frozen: false,
            },
        );

        assert_eq!(state.get_asset_holding(&addr, 42).unwrap().amount, 1000);
        assert!(state.get_asset_holding(&addr, 99).is_none());
    }
}
