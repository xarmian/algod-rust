use std::collections::HashMap;

use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, Round,
    StateSchema,
};

use crate::lease::LeaseTable;
use crate::params::{
    SCHEMA_BYTES_MIN_BALANCE, SCHEMA_MIN_BALANCE_PER_ENTRY, SCHEMA_UINT_MIN_BALANCE,
};

/// Compute the min-balance cost for a single state schema.
///
/// cost = SCHEMA_MIN_BALANCE_PER_ENTRY * (num_uint + num_byte_slice)
///      + SCHEMA_UINT_MIN_BALANCE * num_uint
///      + SCHEMA_BYTES_MIN_BALANCE * num_byte_slice
pub fn schema_min_balance(schema: &StateSchema) -> u64 {
    let num_entries = schema.num_uint + schema.num_byte_slice;
    SCHEMA_MIN_BALANCE_PER_ENTRY * num_entries
        + SCHEMA_UINT_MIN_BALANCE * schema.num_uint
        + SCHEMA_BYTES_MIN_BALANCE * schema.num_byte_slice
}

/// In-memory ledger state holding all account data, asset/app state, and
/// chain-level parameters (rewards tracking, genesis info).
pub struct LedgerState {
    // Account state
    pub accounts: HashMap<Address, AccountData>,
    pub asset_holdings: HashMap<(Address, u64), AssetHolding>,
    pub app_local_states: HashMap<(Address, u64), AppLocalState>,
    pub asset_params: HashMap<u64, AssetParamsRecord>,
    pub app_params: HashMap<u64, AppParams>,

    // Lease tracking
    pub lease_table: LeaseTable,

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
            lease_table: LeaseTable::new(),
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

    /// Compute schema-aware minimum balance for an account.
    ///
    /// Extends the flat min-balance with per-app schema costs:
    /// - Local state schema costs for apps the account has opted into.
    /// - Global state schema costs for apps the account has created.
    ///
    /// Flat costs (APP_FLAT_PARAMS_MIN_BALANCE per created app,
    /// APP_FLAT_OPT_IN_MIN_BALANCE per opted-in app) are already included
    /// via the base `min_balance()`.
    pub fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64 {
        let flat = crate::params::min_balance(account);
        let mut extra: u64 = 0;

        // Opted-in apps: add local state schema cost.
        for ((a, _app_id), local_state) in &self.app_local_states {
            if a == addr {
                extra += schema_min_balance(&local_state.schema);
            }
        }

        // Created apps: add global state schema cost.
        for app in self.app_params.values() {
            if app.creator == *addr {
                extra += schema_min_balance(&app.global_state_schema);
            }
        }

        flat + extra
    }

    // ---- Snapshot / Restore ----

    /// Snapshot the state for the given addresses and related keys, for rollback.
    ///
    /// Returns an opaque `StateSnapshot` that can be passed to `restore_snapshot`.
    /// Captures accounts, asset holdings, and app local states for the given addresses.
    /// Use `snapshot_with_ids` to also capture asset_params and app_params by ID.
    pub fn snapshot(&self, addrs: &[Address]) -> StateSnapshot {
        let accounts: Vec<(Address, Option<AccountData>)> = addrs
            .iter()
            .map(|a| (*a, self.accounts.get(a).cloned()))
            .collect();

        let asset_holdings: Vec<((Address, u64), Option<AssetHolding>)> = self
            .asset_holdings
            .iter()
            .filter(|((addr, _), _)| addrs.contains(addr))
            .map(|(k, v)| (*k, Some(v.clone())))
            .collect();

        let app_local_states: Vec<((Address, u64), Option<AppLocalState>)> = self
            .app_local_states
            .iter()
            .filter(|((addr, _), _)| addrs.contains(addr))
            .map(|(k, v)| (*k, Some(v.clone())))
            .collect();

        StateSnapshot {
            accounts,
            asset_holdings,
            asset_params: Vec::new(),
            app_params: Vec::new(),
            app_local_states,
        }
    }

    /// Snapshot specific asset_params and app_params keys (by ID) in addition to
    /// address-based state. Use this when you know which asset/app IDs are affected.
    pub fn snapshot_with_ids(
        &self,
        addrs: &[Address],
        asset_ids: &[u64],
        app_ids: &[u64],
    ) -> StateSnapshot {
        let mut snap = self.snapshot(addrs);

        for &id in asset_ids {
            snap.asset_params
                .push((id, self.asset_params.get(&id).cloned()));
        }
        for &id in app_ids {
            snap.app_params
                .push((id, self.app_params.get(&id).cloned()));
        }

        snap
    }

    /// Restore state from a snapshot, reverting all changes.
    pub fn restore_snapshot(&mut self, snap: StateSnapshot) {
        // Collect snapshotted addresses so we can clean up newly-created holdings.
        let snapped_addrs: std::collections::HashSet<Address> =
            snap.accounts.iter().map(|(a, _)| *a).collect();

        // Collect snapshotted holding/local-state keys so we know which are original.
        let snapped_holdings: std::collections::HashSet<(Address, u64)> =
            snap.asset_holdings.iter().map(|(k, _)| *k).collect();
        let snapped_locals: std::collections::HashSet<(Address, u64)> =
            snap.app_local_states.iter().map(|(k, _)| *k).collect();

        for (addr, data) in snap.accounts {
            match data {
                Some(d) => {
                    self.accounts.insert(addr, d);
                }
                None => {
                    self.accounts.remove(&addr);
                }
            }
        }

        for (key, data) in snap.asset_holdings {
            match data {
                Some(d) => {
                    self.asset_holdings.insert(key, d);
                }
                None => {
                    self.asset_holdings.remove(&key);
                }
            }
        }

        // Remove any newly-created asset holdings for snapshotted addresses
        // that weren't in the original snapshot.
        self.asset_holdings
            .retain(|k, _| !snapped_addrs.contains(&k.0) || snapped_holdings.contains(k));

        for (id, data) in snap.asset_params {
            match data {
                Some(d) => {
                    self.asset_params.insert(id, d);
                }
                None => {
                    self.asset_params.remove(&id);
                }
            }
        }

        for (id, data) in snap.app_params {
            match data {
                Some(d) => {
                    self.app_params.insert(id, d);
                }
                None => {
                    self.app_params.remove(&id);
                }
            }
        }

        for (key, data) in snap.app_local_states {
            match data {
                Some(d) => {
                    self.app_local_states.insert(key, d);
                }
                None => {
                    self.app_local_states.remove(&key);
                }
            }
        }

        // Remove any newly-created app local states for snapshotted addresses
        // that weren't in the original snapshot.
        self.app_local_states
            .retain(|k, _| !snapped_addrs.contains(&k.0) || snapped_locals.contains(k));
    }
}

/// Opaque snapshot of ledger state for rollback on error.
pub struct StateSnapshot {
    accounts: Vec<(Address, Option<AccountData>)>,
    asset_holdings: Vec<((Address, u64), Option<AssetHolding>)>,
    asset_params: Vec<(u64, Option<AssetParamsRecord>)>,
    app_params: Vec<(u64, Option<AppParams>)>,
    app_local_states: Vec<((Address, u64), Option<AppLocalState>)>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::store_trait::LedgerStore for LedgerState {
    type Snapshot = StateSnapshot;

    // ---- Accounts ----

    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        self.accounts.get(addr).cloned()
    }

    fn set_account(&mut self, addr: &Address, account: AccountData) {
        self.accounts.insert(*addr, account);
    }

    fn remove_account(&mut self, addr: &Address) {
        self.accounts.remove(addr);
    }

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        self.asset_holdings.get(&(*addr, asset_id)).cloned()
    }

    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding) {
        self.asset_holdings.insert((*addr, asset_id), holding);
    }

    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64) {
        self.asset_holdings.remove(&(*addr, asset_id));
    }

    fn has_asset_holding(&self, addr: &Address, asset_id: u64) -> bool {
        self.asset_holdings.contains_key(&(*addr, asset_id))
    }

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        self.asset_params.get(&asset_id).cloned()
    }

    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord) {
        self.asset_params.insert(asset_id, record);
    }

    fn remove_asset_params(&mut self, asset_id: u64) {
        self.asset_params.remove(&asset_id);
    }

    fn has_asset_params(&self, asset_id: u64) -> bool {
        self.asset_params.contains_key(&asset_id)
    }

    // ---- App Params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        self.app_params.get(&app_id).cloned()
    }

    fn set_app_params(&mut self, app_id: u64, params: AppParams) {
        self.app_params.insert(app_id, params);
    }

    fn remove_app_params(&mut self, app_id: u64) {
        self.app_params.remove(&app_id);
    }

    fn has_app_params(&self, app_id: u64) -> bool {
        self.app_params.contains_key(&app_id)
    }

    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams> {
        self.app_params
            .values()
            .filter(|p| p.creator == *creator)
            .cloned()
            .collect()
    }

    // ---- App Local States ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        self.app_local_states.get(&(*addr, app_id)).cloned()
    }

    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState) {
        self.app_local_states.insert((*addr, app_id), local_state);
    }

    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64) {
        self.app_local_states.remove(&(*addr, app_id));
    }

    fn has_app_local_state(&self, addr: &Address, app_id: u64) -> bool {
        self.app_local_states.contains_key(&(*addr, app_id))
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        self.app_local_states
            .iter()
            .filter(|((a, _), _)| a == addr)
            .map(|((_, app_id), state)| (*app_id, state.clone()))
            .collect()
    }

    // ---- Leases ----

    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), algo_error::AlgoError> {
        self.lease_table.check(sender, lease, current_round)
    }

    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        self.lease_table.record(sender, lease, last_valid);
    }

    fn purge_expired_leases(&mut self, current_round: u64) {
        self.lease_table.purge_expired(current_round);
    }

    // ---- Chain-level state (getters) ----

    fn current_round(&self) -> Round {
        self.current_round
    }

    fn rewards_level(&self) -> u64 {
        self.rewards_level
    }

    fn rewards_rate(&self) -> u64 {
        self.rewards_rate
    }

    fn rewards_residue(&self) -> u64 {
        self.rewards_residue
    }

    fn rewards_recalculation_round(&self) -> u64 {
        self.rewards_recalculation_round
    }

    fn fee_sink(&self) -> Address {
        self.fee_sink
    }

    fn rewards_pool(&self) -> Address {
        self.rewards_pool
    }

    fn genesis_id(&self) -> &str {
        &self.genesis_id
    }

    fn genesis_hash(&self) -> &[u8; 32] {
        &self.genesis_hash
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }

    // ---- Chain-level state (setters) ----

    fn set_current_round(&mut self, round: Round) {
        self.current_round = round;
    }

    fn set_rewards_level(&mut self, level: u64) {
        self.rewards_level = level;
    }

    fn set_rewards_rate(&mut self, rate: u64) {
        self.rewards_rate = rate;
    }

    fn set_rewards_residue(&mut self, residue: u64) {
        self.rewards_residue = residue;
    }

    fn set_rewards_recalculation_round(&mut self, round: u64) {
        self.rewards_recalculation_round = round;
    }

    fn set_fee_sink(&mut self, addr: Address) {
        self.fee_sink = addr;
    }

    fn set_rewards_pool(&mut self, addr: Address) {
        self.rewards_pool = addr;
    }

    fn set_genesis_id(&mut self, id: String) {
        self.genesis_id = id;
    }

    fn set_genesis_hash(&mut self, hash: [u8; 32]) {
        self.genesis_hash = hash;
    }

    fn set_protocol(&mut self, protocol: String) {
        self.protocol = protocol;
    }

    // ---- Snapshot / Restore ----

    fn snapshot(&self, addrs: &[Address]) -> StateSnapshot {
        LedgerState::snapshot(self, addrs)
    }

    fn snapshot_with_ids(
        &self,
        addrs: &[Address],
        asset_ids: &[u64],
        app_ids: &[u64],
    ) -> StateSnapshot {
        LedgerState::snapshot_with_ids(self, addrs, asset_ids, app_ids)
    }

    fn restore_snapshot(&mut self, snapshot: StateSnapshot) {
        LedgerState::restore_snapshot(self, snapshot);
    }

    // ---- Min balance ----

    fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64 {
        LedgerState::min_balance_with_state(self, addr, account)
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

    #[test]
    fn test_snapshot_restore_accounts() {
        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.get_or_default_account(&addr).micro_algos = 1_000_000;

        let snap = state.snapshot(&[addr]);

        // Mutate after snapshot.
        state.get_or_default_account(&addr).micro_algos = 500_000;
        assert_eq!(state.get_account(&addr).unwrap().micro_algos, 500_000);

        // Restore.
        state.restore_snapshot(snap);
        assert_eq!(state.get_account(&addr).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_snapshot_restore_removes_new_accounts() {
        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);

        // Snapshot when address doesn't exist.
        let snap = state.snapshot(&[addr]);

        // Create the account.
        state.get_or_default_account(&addr).micro_algos = 100;

        // Restore should remove it.
        state.restore_snapshot(snap);
        assert!(state.get_account(&addr).is_none());
    }

    #[test]
    fn test_snapshot_restore_asset_holdings() {
        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.asset_holdings.insert(
            (addr, 10),
            AssetHolding {
                amount: 500,
                frozen: false,
            },
        );

        let snap = state.snapshot(&[addr]);

        // Mutate.
        state.asset_holdings.get_mut(&(addr, 10)).unwrap().amount = 999;

        // Restore.
        state.restore_snapshot(snap);
        assert_eq!(state.get_asset_holding(&addr, 10).unwrap().amount, 500);
    }

    #[test]
    fn test_snapshot_restore_app_local_states() {
        use std::collections::BTreeMap;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.app_local_states.insert(
            (addr, 5),
            AppLocalState {
                schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 1,
                },
                key_value: BTreeMap::new(),
            },
        );

        let snap = state.snapshot(&[addr]);

        // Remove after snapshot.
        state.app_local_states.remove(&(addr, 5));
        assert!(state.get_app_local_state(&addr, 5).is_none());

        // Restore.
        state.restore_snapshot(snap);
        assert!(state.get_app_local_state(&addr, 5).is_some());
    }

    #[test]
    fn test_snapshot_with_ids_asset_params() {
        use algo_types::AssetParams;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.asset_params.insert(
            42,
            AssetParamsRecord {
                params: AssetParams::default(),
                creator: addr,
            },
        );

        let snap = state.snapshot_with_ids(&[addr], &[42], &[]);

        // Remove.
        state.asset_params.remove(&42);
        assert!(state.get_asset_params(42).is_none());

        // Restore.
        state.restore_snapshot(snap);
        assert!(state.get_asset_params(42).is_some());
    }

    #[test]
    fn test_min_balance_with_state_local_schema() {
        use std::collections::BTreeMap;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);

        let account = AccountData {
            micro_algos: 10_000_000,
            total_apps_opted_in: 1,
            ..Default::default()
        };
        state.accounts.insert(addr, account.clone());

        // Add a local state with schema: 2 uints, 1 byte-slice.
        state.app_local_states.insert(
            (addr, 100),
            AppLocalState {
                schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 1,
                },
                key_value: BTreeMap::new(),
            },
        );

        let mb = state.min_balance_with_state(&addr, &account);

        // Flat: 100_000 (base) + 100_000 (1 opted-in app) = 200_000
        // Schema: 3 entries * 25_000 + 2 * 3_500 + 1 * 25_000 = 75_000 + 7_000 + 25_000 = 107_000
        // Total: 307_000
        assert_eq!(mb, 200_000 + 107_000);
    }

    #[test]
    fn test_schema_min_balance() {
        let schema = StateSchema {
            num_uint: 4,
            num_byte_slice: 2,
        };
        // 6 entries * 25_000 + 4 * 3_500 + 2 * 25_000
        // = 150_000 + 14_000 + 50_000 = 214_000
        assert_eq!(schema_min_balance(&schema), 214_000);
    }

    #[test]
    fn test_schema_min_balance_empty() {
        let schema = StateSchema {
            num_uint: 0,
            num_byte_slice: 0,
        };
        assert_eq!(schema_min_balance(&schema), 0);
    }
}
