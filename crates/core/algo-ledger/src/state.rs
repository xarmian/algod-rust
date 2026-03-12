use std::collections::HashMap;

use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, Round,
    StateSchema,
};

use crate::block_entry::BlockEntry;
use crate::lease::LeaseTable;
use crate::merkle_trie::MerkleTrie;
use crate::params::{
    SCHEMA_BYTES_MIN_BALANCE, SCHEMA_MIN_BALANCE_PER_ENTRY, SCHEMA_UINT_MIN_BALANCE,
};
use crate::trie_hash::{
    account_hash_v6, extract_raw_affinity, resource_hash_v6_with_kind, HashKind, ELEMENT_SIZE,
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

/// Record of state before a mutation, used for trie delta computation.
enum PreMutation {
    Account {
        addr: Address,
        old_data: Option<AccountData>,
    },
    AssetHolding {
        addr: Address,
        asset_id: u64,
        old_holding: Option<AssetHolding>,
        old_params: Option<AssetParamsRecord>,
        old_affinity: u32,
    },
    AssetParams {
        asset_id: u64,
        old_record: Option<AssetParamsRecord>,
        old_holding: Option<(Address, AssetHolding)>,
        old_affinity: u32,
    },
    AppParams {
        app_id: u64,
        old_params: Option<AppParams>,
        old_local: Option<(Address, AppLocalState)>,
        old_affinity: u32,
    },
    AppLocalState {
        addr: Address,
        app_id: u64,
        old_local: Option<AppLocalState>,
        old_params: Option<AppParams>,
        old_affinity: u32,
    },
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
    pub boxes: HashMap<(u64, Vec<u8>), Vec<u8>>,

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

    // Transaction counter (previous block's TxnCounter — base for ID generation)
    pub txn_counter: u64,

    // Merkle trie tracking
    trie: Option<MerkleTrie>,
    pre_mutations: Vec<PreMutation>,

    // Block and txtail storage (in-memory backend for LedgerStore trait)
    block_store: HashMap<u64, BlockEntry>,
    txtail_store: HashMap<u64, Vec<u8>>,
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
            boxes: HashMap::new(),
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
            txn_counter: 0,
            trie: None,
            pre_mutations: Vec::new(),
            block_store: HashMap::new(),
            txtail_store: HashMap::new(),
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
            boxes: Vec::new(),
            snapshotted_box_app_ids: Vec::new(),
        }
    }

    /// Snapshot specific asset_params and app_params keys (by ID) in addition to
    /// address-based state. Use this when you know which asset/app IDs are affected.
    ///
    /// Also captures all box entries for the given `app_ids` so they can be
    /// rolled back on `restore_snapshot`.
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

        // Capture all box entries for the given app IDs.
        for &app_id in app_ids {
            for ((aid, key), value) in &self.boxes {
                if *aid == app_id {
                    snap.boxes.push(((*aid, key.clone()), Some(value.clone())));
                }
            }
        }
        snap.snapshotted_box_app_ids = app_ids.to_vec();

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

        // Restore snapshotted box entries.
        let snapped_box_keys: std::collections::HashSet<(u64, Vec<u8>)> =
            snap.boxes.iter().map(|(k, _)| k.clone()).collect();

        for (key, data) in snap.boxes {
            match data {
                Some(value) => {
                    self.boxes.insert(key, value);
                }
                None => {
                    self.boxes.remove(&key);
                }
            }
        }

        // Remove any newly-created boxes for snapshotted app IDs that weren't
        // in the original snapshot.
        if !snap.snapshotted_box_app_ids.is_empty() {
            let snapped_app_ids: std::collections::HashSet<u64> =
                snap.snapshotted_box_app_ids.into_iter().collect();
            self.boxes
                .retain(|k, _| !snapped_app_ids.contains(&k.0) || snapped_box_keys.contains(k));
        }
    }
}

/// Opaque snapshot of ledger state for rollback on error.
pub struct StateSnapshot {
    accounts: Vec<(Address, Option<AccountData>)>,
    asset_holdings: Vec<((Address, u64), Option<AssetHolding>)>,
    asset_params: Vec<(u64, Option<AssetParamsRecord>)>,
    app_params: Vec<(u64, Option<AppParams>)>,
    app_local_states: Vec<((Address, u64), Option<AppLocalState>)>,
    /// Box entries snapshotted by app ID. Each entry is `((app_id, key), old_value)`.
    /// `None` value means the box did not exist at snapshot time.
    #[allow(clippy::type_complexity)]
    boxes: Vec<((u64, Vec<u8>), Option<Vec<u8>>)>,
    /// App IDs whose boxes were snapshotted (used to clean up newly-created boxes on restore).
    snapshotted_box_app_ids: Vec<u64>,
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
        if self.trie.is_some() {
            let old = self.accounts.get(addr).cloned();
            self.pre_mutations.push(PreMutation::Account {
                addr: *addr,
                old_data: old,
            });
        }
        self.accounts.insert(*addr, account);
    }

    fn remove_account(&mut self, addr: &Address) {
        if self.trie.is_some() {
            let old = self.accounts.get(addr).cloned();
            self.pre_mutations.push(PreMutation::Account {
                addr: *addr,
                old_data: old,
            });
        }
        self.accounts.remove(addr);
    }

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        self.asset_holdings.get(&(*addr, asset_id)).cloned()
    }

    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding) {
        if self.trie.is_some() {
            let old_holding = self.asset_holdings.get(&(*addr, asset_id)).cloned();
            // Capture co-located asset params if creator matches this addr.
            let old_params = self
                .asset_params
                .get(&asset_id)
                .filter(|r| r.creator == *addr)
                .cloned();
            // Derive affinity from the resource blob, not the account,
            // matching Go's ResourcesHashBuilderV6 which uses resData.UpdateRound.
            let old_blob = encode_merged_asset_resource(
                old_holding.as_ref(),
                old_params.as_ref().map(|r| (&r.params, &r.creator)),
            );
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AssetHolding {
                addr: *addr,
                asset_id,
                old_holding,
                old_params,
                old_affinity,
            });
        }
        self.asset_holdings.insert((*addr, asset_id), holding);
    }

    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64) {
        if self.trie.is_some() {
            let old_holding = self.asset_holdings.get(&(*addr, asset_id)).cloned();
            let old_params = self
                .asset_params
                .get(&asset_id)
                .filter(|r| r.creator == *addr)
                .cloned();
            // Derive affinity from the resource blob, not the account.
            let old_blob = encode_merged_asset_resource(
                old_holding.as_ref(),
                old_params.as_ref().map(|r| (&r.params, &r.creator)),
            );
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AssetHolding {
                addr: *addr,
                asset_id,
                old_holding,
                old_params,
                old_affinity,
            });
        }
        self.asset_holdings.remove(&(*addr, asset_id));
    }

    fn has_asset_holding(&self, addr: &Address, asset_id: u64) -> bool {
        self.asset_holdings.contains_key(&(*addr, asset_id))
    }

    fn remove_all_asset_holdings_for_asset(&mut self, asset_id: u64) {
        // Collect keys first to avoid borrowing issues.
        let keys_to_remove: Vec<(Address, u64)> = self
            .asset_holdings
            .keys()
            .filter(|(_, aid)| *aid == asset_id)
            .copied()
            .collect();
        // Collect affected addresses for counter updates.
        let affected_addrs: Vec<Address> = keys_to_remove.iter().map(|(addr, _)| *addr).collect();
        for key in keys_to_remove {
            // Use the trait method so trie pre-mutations are recorded.
            self.remove_asset_holding(&key.0, key.1);
        }
        // Decrement total_assets_opted_in for each affected account.
        for addr in affected_addrs {
            let mut acct = self.accounts.get(&addr).cloned().unwrap_or_default();
            acct.total_assets_opted_in = acct.total_assets_opted_in.saturating_sub(1);
            self.set_account(&addr, acct);
        }
    }

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        self.asset_params.get(&asset_id).cloned()
    }

    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord) {
        if self.trie.is_some() {
            let old_record = self.asset_params.get(&asset_id).cloned();
            // Capture co-located holding if creator holds this asset.
            let old_holding = old_record.as_ref().and_then(|r| {
                self.asset_holdings
                    .get(&(r.creator, asset_id))
                    .map(|h| (r.creator, h.clone()))
            });
            // Derive affinity from the resource blob, not the account.
            let old_blob = encode_merged_asset_resource(
                old_holding.as_ref().map(|(_, h)| h),
                old_record.as_ref().map(|r| (&r.params, &r.creator)),
            );
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AssetParams {
                asset_id,
                old_record,
                old_holding,
                old_affinity,
            });
        }
        self.asset_params.insert(asset_id, record);
    }

    fn remove_asset_params(&mut self, asset_id: u64) {
        if self.trie.is_some() {
            let old_record = self.asset_params.get(&asset_id).cloned();
            let old_holding = old_record.as_ref().and_then(|r| {
                self.asset_holdings
                    .get(&(r.creator, asset_id))
                    .map(|h| (r.creator, h.clone()))
            });
            // Derive affinity from the resource blob, not the account.
            let old_blob = encode_merged_asset_resource(
                old_holding.as_ref().map(|(_, h)| h),
                old_record.as_ref().map(|r| (&r.params, &r.creator)),
            );
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AssetParams {
                asset_id,
                old_record,
                old_holding,
                old_affinity,
            });
        }
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
        if self.trie.is_some() {
            let old_params = self.app_params.get(&app_id).cloned();
            // Capture co-located local state if creator has opted in.
            let old_local = old_params.as_ref().and_then(|p| {
                self.app_local_states
                    .get(&(p.creator, app_id))
                    .map(|s| (p.creator, s.clone()))
            });
            // Derive affinity from the resource blob, not the account.
            let old_blob =
                encode_merged_app_resource(old_local.as_ref().map(|(_, s)| s), old_params.as_ref());
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AppParams {
                app_id,
                old_params,
                old_local,
                old_affinity,
            });
        }
        self.app_params.insert(app_id, params);
    }

    fn remove_app_params(&mut self, app_id: u64) {
        if self.trie.is_some() {
            let old_params = self.app_params.get(&app_id).cloned();
            let old_local = old_params.as_ref().and_then(|p| {
                self.app_local_states
                    .get(&(p.creator, app_id))
                    .map(|s| (p.creator, s.clone()))
            });
            // Derive affinity from the resource blob, not the account.
            let old_blob =
                encode_merged_app_resource(old_local.as_ref().map(|(_, s)| s), old_params.as_ref());
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AppParams {
                app_id,
                old_params,
                old_local,
                old_affinity,
            });
        }
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
        if self.trie.is_some() {
            let old_local = self.app_local_states.get(&(*addr, app_id)).cloned();
            // Capture co-located app params if creator matches this addr.
            let old_params = self
                .app_params
                .get(&app_id)
                .filter(|p| p.creator == *addr)
                .cloned();
            // Derive affinity from the resource blob, not the account.
            let old_blob = encode_merged_app_resource(old_local.as_ref(), old_params.as_ref());
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AppLocalState {
                addr: *addr,
                app_id,
                old_local,
                old_params,
                old_affinity,
            });
        }
        self.app_local_states.insert((*addr, app_id), local_state);
    }

    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64) {
        if self.trie.is_some() {
            let old_local = self.app_local_states.get(&(*addr, app_id)).cloned();
            let old_params = self
                .app_params
                .get(&app_id)
                .filter(|p| p.creator == *addr)
                .cloned();
            // Derive affinity from the resource blob, not the account.
            let old_blob = encode_merged_app_resource(old_local.as_ref(), old_params.as_ref());
            let old_affinity = extract_raw_affinity(&old_blob);
            self.pre_mutations.push(PreMutation::AppLocalState {
                addr: *addr,
                app_id,
                old_local,
                old_params,
                old_affinity,
            });
        }
        self.app_local_states.remove(&(*addr, app_id));
    }

    fn has_app_local_state(&self, addr: &Address, app_id: u64) -> bool {
        self.app_local_states.contains_key(&(*addr, app_id))
    }

    fn remove_all_app_local_states_for_app(&mut self, app_id: u64) {
        // Collect keys first to avoid borrowing issues.
        let keys_to_remove: Vec<(Address, u64)> = self
            .app_local_states
            .keys()
            .filter(|(_, aid)| *aid == app_id)
            .copied()
            .collect();
        // Collect affected addresses and their local schemas before removal.
        let affected: Vec<(Address, StateSchema)> = keys_to_remove
            .iter()
            .map(|(addr, _)| {
                let schema = self
                    .app_local_states
                    .get(&(*addr, app_id))
                    .map(|ls| ls.schema.clone())
                    .unwrap_or_default();
                (*addr, schema)
            })
            .collect();
        for key in keys_to_remove {
            // Use the trait method so trie pre-mutations are recorded.
            self.remove_app_local_state(&key.0, key.1);
        }
        // Decrement total_apps_opted_in and subtract local schema for each affected account.
        for (addr, local_schema) in affected {
            let mut acct = self.accounts.get(&addr).cloned().unwrap_or_default();
            acct.total_apps_opted_in = acct.total_apps_opted_in.saturating_sub(1);
            acct.total_app_schema = acct.total_app_schema.sub_schema(&local_schema);
            self.set_account(&addr, acct);
        }
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        self.app_local_states
            .iter()
            .filter(|((a, _), _)| a == addr)
            .map(|((_, app_id), state)| (*app_id, state.clone()))
            .collect()
    }

    // ---- Box Storage ----

    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        self.boxes.get(&(app_id, key.to_vec())).cloned()
    }

    fn set_box(&mut self, app_id: u64, key: &[u8], value: Vec<u8>) {
        self.boxes.insert((app_id, key.to_vec()), value);
    }

    fn delete_box(&mut self, app_id: u64, key: &[u8]) -> bool {
        self.boxes.remove(&(app_id, key.to_vec())).is_some()
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

    fn txn_counter(&self) -> u64 {
        self.txn_counter
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

    fn set_txn_counter(&mut self, counter: u64) {
        self.txn_counter = counter;
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

    // ---- Trie integration ----

    fn enable_trie(&mut self) {
        use std::collections::HashSet;

        let mut trie = MerkleTrie::new(ELEMENT_SIZE);

        // 1. Add all existing accounts to the trie.
        for (addr, acct) in &self.accounts {
            let elem = account_hash_v6(addr, acct);
            if let Err(e) = trie.add(&elem) {
                tracing::warn!("enable_trie: add account failed: {}", e);
            }
        }

        // 2. Add asset resources (merged holding + params where co-located).
        // Track (addr, asset_id) pairs already added to avoid double-adding.
        let mut added_asset_resources: HashSet<(Address, u64)> = HashSet::new();

        // Iterate asset holdings; merge with co-located params if creator == addr.
        for (&(addr, asset_id), holding) in &self.asset_holdings {
            let params = self
                .asset_params
                .get(&asset_id)
                .filter(|r| r.creator == addr);
            let blob = encode_merged_asset_resource(
                Some(holding),
                params.map(|r| (&r.params, &r.creator)),
            );
            // Derive affinity from the resource blob, matching Go's
            // ResourcesHashBuilderV6 which uses resData.UpdateRound.
            let affinity = extract_raw_affinity(&blob);
            let elem =
                resource_hash_v6_with_kind(&addr, asset_id, &blob, affinity, HashKind::Asset);
            if let Err(e) = trie.add(&elem) {
                tracing::warn!("enable_trie: add asset holding failed: {}", e);
            }
            added_asset_resources.insert((addr, asset_id));
        }

        // Iterate asset params not already covered via holdings (params-only, no holding).
        for (&asset_id, record) in &self.asset_params {
            let creator = record.creator;
            if added_asset_resources.contains(&(creator, asset_id)) {
                continue;
            }
            let blob = encode_merged_asset_resource(None, Some((&record.params, &record.creator)));
            let affinity = extract_raw_affinity(&blob);
            let elem =
                resource_hash_v6_with_kind(&creator, asset_id, &blob, affinity, HashKind::Asset);
            if let Err(e) = trie.add(&elem) {
                tracing::warn!("enable_trie: add asset params failed: {}", e);
            }
        }

        // 3. Add app resources (merged local state + params where co-located).
        let mut added_app_resources: HashSet<(Address, u64)> = HashSet::new();

        // Iterate app local states; merge with co-located params if creator == addr.
        for (&(addr, app_id), local) in &self.app_local_states {
            let params = self.app_params.get(&app_id).filter(|p| p.creator == addr);
            let blob = encode_merged_app_resource(Some(local), params);
            let affinity = extract_raw_affinity(&blob);
            let elem = resource_hash_v6_with_kind(&addr, app_id, &blob, affinity, HashKind::App);
            if let Err(e) = trie.add(&elem) {
                tracing::warn!("enable_trie: add app local state failed: {}", e);
            }
            added_app_resources.insert((addr, app_id));
        }

        // Iterate app params not already covered via local states (params-only).
        for (&app_id, params) in &self.app_params {
            let creator = params.creator;
            if added_app_resources.contains(&(creator, app_id)) {
                continue;
            }
            let blob = encode_merged_app_resource(None, Some(params));
            let affinity = extract_raw_affinity(&blob);
            let elem = resource_hash_v6_with_kind(&creator, app_id, &blob, affinity, HashKind::App);
            if let Err(e) = trie.add(&elem) {
                tracing::warn!("enable_trie: add app params failed: {}", e);
            }
        }

        self.trie = Some(trie);
        self.pre_mutations.clear();
    }

    fn trie_enabled(&self) -> bool {
        self.trie.is_some()
    }

    fn finalize_trie_updates(&mut self) -> Option<[u8; 32]> {
        let trie = self.trie.as_mut()?;

        // Process all recorded pre-mutations.
        let mutations = std::mem::take(&mut self.pre_mutations);

        for mutation in mutations {
            match mutation {
                PreMutation::Account { addr, old_data } => {
                    // Delete old element if it existed.
                    if let Some(ref old) = old_data {
                        let old_elem = account_hash_v6(&addr, old);
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete account failed: {}", e);
                        }
                    }
                    // Add new element if account still exists.
                    if let Some(new_data) = self.accounts.get(&addr) {
                        let new_elem = account_hash_v6(&addr, new_data);
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add account failed: {}", e);
                        }
                    }
                }
                PreMutation::AssetHolding {
                    addr,
                    asset_id,
                    old_holding,
                    old_params,
                    old_affinity,
                } => {
                    // Delete old resource element.
                    if old_holding.is_some() || old_params.is_some() {
                        let old_blob = encode_merged_asset_resource(
                            old_holding.as_ref(),
                            old_params.as_ref().map(|r| (&r.params, &r.creator)),
                        );
                        let old_elem = resource_hash_v6_with_kind(
                            &addr,
                            asset_id,
                            &old_blob,
                            old_affinity,
                            HashKind::Asset,
                        );
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete asset holding failed: {}", e);
                        }
                    }

                    // Add new resource element.
                    let new_holding = self.asset_holdings.get(&(addr, asset_id));
                    let new_params = self
                        .asset_params
                        .get(&asset_id)
                        .filter(|r| r.creator == addr);
                    if new_holding.is_some() || new_params.is_some() {
                        let new_blob = encode_merged_asset_resource(
                            new_holding,
                            new_params.map(|r| (&r.params, &r.creator)),
                        );
                        let new_affinity = extract_raw_affinity(&new_blob);
                        let new_elem = resource_hash_v6_with_kind(
                            &addr,
                            asset_id,
                            &new_blob,
                            new_affinity,
                            HashKind::Asset,
                        );
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add asset holding failed: {}", e);
                        }
                    }
                }
                PreMutation::AssetParams {
                    asset_id,
                    old_record,
                    old_holding,
                    old_affinity,
                } => {
                    if let Some(ref old_rec) = old_record {
                        let creator = old_rec.creator;
                        let old_blob = encode_merged_asset_resource(
                            old_holding.as_ref().map(|(_, h)| h),
                            Some((&old_rec.params, &old_rec.creator)),
                        );
                        let old_elem = resource_hash_v6_with_kind(
                            &creator,
                            asset_id,
                            &old_blob,
                            old_affinity,
                            HashKind::Asset,
                        );
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete asset params failed: {}", e);
                        }
                    }

                    // Add new element.
                    let new_record = self.asset_params.get(&asset_id);
                    if let Some(new_rec) = new_record {
                        let creator = new_rec.creator;
                        let new_holding = self.asset_holdings.get(&(creator, asset_id));
                        let new_blob = encode_merged_asset_resource(
                            new_holding,
                            Some((&new_rec.params, &new_rec.creator)),
                        );
                        let new_affinity = extract_raw_affinity(&new_blob);
                        let new_elem = resource_hash_v6_with_kind(
                            &creator,
                            asset_id,
                            &new_blob,
                            new_affinity,
                            HashKind::Asset,
                        );
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add asset params failed: {}", e);
                        }
                    } else if let Some((creator, _)) = old_holding {
                        let new_h = self.asset_holdings.get(&(creator, asset_id));
                        if let Some(h) = new_h {
                            let new_blob = encode_merged_asset_resource(Some(h), None);
                            let new_affinity = extract_raw_affinity(&new_blob);
                            let new_elem = resource_hash_v6_with_kind(
                                &creator,
                                asset_id,
                                &new_blob,
                                new_affinity,
                                HashKind::Asset,
                            );
                            if let Err(e) = trie.add(&new_elem) {
                                tracing::warn!(
                                    "trie add asset holding (post-params-remove) failed: {}",
                                    e
                                );
                            }
                        }
                    }
                }
                PreMutation::AppParams {
                    app_id,
                    old_params,
                    old_local,
                    old_affinity,
                } => {
                    if let Some(ref old_p) = old_params {
                        let creator = old_p.creator;
                        let old_blob = encode_merged_app_resource(
                            old_local.as_ref().map(|(_, s)| s),
                            Some(old_p),
                        );
                        let old_elem = resource_hash_v6_with_kind(
                            &creator,
                            app_id,
                            &old_blob,
                            old_affinity,
                            HashKind::App,
                        );
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete app params failed: {}", e);
                        }
                    }

                    let new_params = self.app_params.get(&app_id);
                    if let Some(new_p) = new_params {
                        let creator = new_p.creator;
                        let new_local = self.app_local_states.get(&(creator, app_id));
                        let new_blob = encode_merged_app_resource(new_local, Some(new_p));
                        let new_affinity = extract_raw_affinity(&new_blob);
                        let new_elem = resource_hash_v6_with_kind(
                            &creator,
                            app_id,
                            &new_blob,
                            new_affinity,
                            HashKind::App,
                        );
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add app params failed: {}", e);
                        }
                    } else if let Some((creator, _)) = old_local {
                        let new_l = self.app_local_states.get(&(creator, app_id));
                        if let Some(l) = new_l {
                            let new_blob = encode_merged_app_resource(Some(l), None);
                            let new_affinity = extract_raw_affinity(&new_blob);
                            let new_elem = resource_hash_v6_with_kind(
                                &creator,
                                app_id,
                                &new_blob,
                                new_affinity,
                                HashKind::App,
                            );
                            if let Err(e) = trie.add(&new_elem) {
                                tracing::warn!(
                                    "trie add app local (post-params-remove) failed: {}",
                                    e
                                );
                            }
                        }
                    }
                }
                PreMutation::AppLocalState {
                    addr,
                    app_id,
                    old_local,
                    old_params,
                    old_affinity,
                } => {
                    if old_local.is_some() || old_params.is_some() {
                        let old_blob =
                            encode_merged_app_resource(old_local.as_ref(), old_params.as_ref());
                        let old_elem = resource_hash_v6_with_kind(
                            &addr,
                            app_id,
                            &old_blob,
                            old_affinity,
                            HashKind::App,
                        );
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete app local state failed: {}", e);
                        }
                    }

                    let new_local = self.app_local_states.get(&(addr, app_id));
                    let new_params = self.app_params.get(&app_id).filter(|p| p.creator == addr);
                    if new_local.is_some() || new_params.is_some() {
                        let new_blob = encode_merged_app_resource(new_local, new_params);
                        let new_affinity = extract_raw_affinity(&new_blob);
                        let new_elem = resource_hash_v6_with_kind(
                            &addr,
                            app_id,
                            &new_blob,
                            new_affinity,
                            HashKind::App,
                        );
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add app local state failed: {}", e);
                        }
                    }
                }
            }
        }

        // Note: No H2 cascade needed. Resource trie elements use the resource's
        // own UpdateRound for affinity (extracted from the blob via extract_raw_affinity),
        // not the account's. This matches Go's ResourcesHashBuilderV6 which passes
        // resData.UpdateRound. Account affinity changes do not affect resource elements.

        Some(trie.root_hash())
    }

    // ---- Block / Certificate Storage ----

    fn put_block(
        &mut self,
        round: u64,
        proto: &str,
        hdrdata: &[u8],
        blkdata: &[u8],
    ) -> Result<(), algo_error::AlgoError> {
        // Preserve existing certdata on re-insert (matches ON CONFLICT behavior).
        let existing_cert = self
            .block_store
            .get(&round)
            .and_then(|e| e.certdata.clone());
        self.block_store.insert(
            round,
            BlockEntry {
                proto: proto.to_string(),
                hdrdata: hdrdata.to_vec(),
                blkdata: blkdata.to_vec(),
                certdata: existing_cert,
            },
        );
        Ok(())
    }

    fn get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, algo_error::AlgoError> {
        Ok(self.block_store.get(&round).map(|e| e.blkdata.clone()))
    }

    fn get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, algo_error::AlgoError> {
        Ok(self.block_store.get(&round).map(|e| e.hdrdata.clone()))
    }

    fn put_block_cert(&mut self, round: u64, certdata: &[u8]) -> Result<(), algo_error::AlgoError> {
        if let Some(entry) = self.block_store.get_mut(&round) {
            entry.certdata = Some(certdata.to_vec());
        }
        Ok(())
    }

    fn get_block_cert(&self, round: u64) -> Result<Option<Vec<u8>>, algo_error::AlgoError> {
        Ok(self
            .block_store
            .get(&round)
            .and_then(|e| e.certdata.clone()))
    }

    fn get_block_proto(&self, round: u64) -> Result<Option<String>, algo_error::AlgoError> {
        Ok(self.block_store.get(&round).map(|e| e.proto.clone()))
    }

    // ---- TxTail Storage ----

    fn put_txtail(&mut self, round: u64, data: &[u8]) -> Result<(), algo_error::AlgoError> {
        self.txtail_store.insert(round, data.to_vec());
        Ok(())
    }

    fn get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, algo_error::AlgoError> {
        Ok(self.txtail_store.get(&round).cloned())
    }

    // ---- Pruning ----

    fn forget_before(&mut self, round: u64) -> Result<(), algo_error::AlgoError> {
        self.block_store.retain(|&r, _| r >= round);
        self.txtail_store.retain(|&r, _| r >= round);
        Ok(())
    }
}

/// Encode a merged asset resource blob (holding + params) matching Go's format.
///
/// Combines holding fields (l, m) with params fields (a..k) and the resource
/// flags field (y) into a single msgpack map blob.
fn encode_merged_asset_resource(
    holding: Option<&AssetHolding>,
    params: Option<(&algo_types::AssetParams, &Address)>,
) -> Vec<u8> {
    use crate::sqlite::{encode_asset_holding, encode_asset_params};

    match (holding, params) {
        (Some(h), Some((p, creator))) => {
            // Merge both into one blob — combine fields from both encodings.
            // The simplest correct approach: decode both, merge maps, re-encode.
            let h_bytes = encode_asset_holding(h);
            let p_bytes = encode_asset_params(p, creator);

            let h_val: rmpv::Value =
                rmpv::decode::read_value(&mut &h_bytes[..]).unwrap_or(rmpv::Value::Map(vec![]));
            let p_val: rmpv::Value =
                rmpv::decode::read_value(&mut &p_bytes[..]).unwrap_or(rmpv::Value::Map(vec![]));

            let mut merged: std::collections::BTreeMap<String, rmpv::Value> =
                std::collections::BTreeMap::new();

            if let rmpv::Value::Map(m) = p_val {
                for (k, v) in m {
                    if let Some(key) = k.as_str() {
                        // Skip the "y" flags from params — we'll set our own.
                        if key != "y" {
                            merged.insert(key.to_string(), v);
                        }
                    }
                }
            }
            if let rmpv::Value::Map(m) = h_val {
                for (k, v) in m {
                    if let Some(key) = k.as_str() {
                        if key != "y" {
                            merged.insert(key.to_string(), v);
                        }
                    }
                }
            }

            // Set combined flags: holding (0x01) | ownership (0x04) = 0x05
            merged.insert(
                "y".to_string(),
                rmpv::Value::from(
                    crate::sqlite::RESOURCE_FLAGS_HOLDING | crate::sqlite::RESOURCE_FLAGS_OWNERSHIP,
                ),
            );

            let pairs: Vec<(rmpv::Value, rmpv::Value)> = merged
                .into_iter()
                .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                .collect();
            let val = rmpv::Value::Map(pairs);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &val).expect("msgpack encode");
            buf
        }
        (Some(h), None) => encode_asset_holding(h),
        (None, Some((p, creator))) => encode_asset_params(p, creator),
        (None, None) => Vec::new(),
    }
}

/// Encode a merged app resource blob (local state + params) matching Go's format.
fn encode_merged_app_resource(
    local_state: Option<&AppLocalState>,
    params: Option<&AppParams>,
) -> Vec<u8> {
    use crate::sqlite::{encode_app_local_state, encode_app_params};

    match (local_state, params) {
        (Some(s), Some(p)) => {
            let s_bytes = encode_app_local_state(s);
            let p_bytes = encode_app_params(p);

            let s_val: rmpv::Value =
                rmpv::decode::read_value(&mut &s_bytes[..]).unwrap_or(rmpv::Value::Map(vec![]));
            let p_val: rmpv::Value =
                rmpv::decode::read_value(&mut &p_bytes[..]).unwrap_or(rmpv::Value::Map(vec![]));

            let mut merged: std::collections::BTreeMap<String, rmpv::Value> =
                std::collections::BTreeMap::new();

            if let rmpv::Value::Map(m) = p_val {
                for (k, v) in m {
                    if let Some(key) = k.as_str() {
                        if key != "y" {
                            merged.insert(key.to_string(), v);
                        }
                    }
                }
            }
            if let rmpv::Value::Map(m) = s_val {
                for (k, v) in m {
                    if let Some(key) = k.as_str() {
                        if key != "y" {
                            merged.insert(key.to_string(), v);
                        }
                    }
                }
            }

            // Combined flags: holding (0x01) | ownership (0x04) = 0x05
            merged.insert(
                "y".to_string(),
                rmpv::Value::from(
                    crate::sqlite::RESOURCE_FLAGS_HOLDING | crate::sqlite::RESOURCE_FLAGS_OWNERSHIP,
                ),
            );

            let pairs: Vec<(rmpv::Value, rmpv::Value)> = merged
                .into_iter()
                .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                .collect();
            let val = rmpv::Value::Map(pairs);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &val).expect("msgpack encode");
            buf
        }
        (Some(s), None) => encode_app_local_state(s),
        (None, Some(p)) => encode_app_params(p),
        (None, None) => Vec::new(),
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

    #[test]
    fn test_remove_all_asset_holdings_for_asset() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);
        let addr3 = Address([3u8; 32]);

        // Set up accounts with total_assets_opted_in counters.
        // addr1 holds asset 42 and 99 => 2 opted in.
        state.set_account(
            &addr1,
            AccountData {
                micro_algos: 1_000_000,
                total_assets_opted_in: 2,
                ..Default::default()
            },
        );
        // addr2 holds only asset 42 => 1 opted in.
        state.set_account(
            &addr2,
            AccountData {
                micro_algos: 1_000_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );
        // addr3 holds only asset 42 => 1 opted in.
        state.set_account(
            &addr3,
            AccountData {
                micro_algos: 1_000_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );

        // Three addresses hold asset 42; addr1 also holds asset 99.
        state.set_asset_holding(
            &addr1,
            42,
            AssetHolding {
                amount: 100,
                frozen: false,
            },
        );
        state.set_asset_holding(
            &addr2,
            42,
            AssetHolding {
                amount: 200,
                frozen: false,
            },
        );
        state.set_asset_holding(
            &addr3,
            42,
            AssetHolding {
                amount: 300,
                frozen: true,
            },
        );
        state.set_asset_holding(
            &addr1,
            99,
            AssetHolding {
                amount: 50,
                frozen: false,
            },
        );

        state.remove_all_asset_holdings_for_asset(42);

        // All holdings for asset 42 should be gone.
        assert!(state.get_asset_holding(&addr1, 42).is_none());
        assert!(state.get_asset_holding(&addr2, 42).is_none());
        assert!(state.get_asset_holding(&addr3, 42).is_none());
        // Asset 99 holding should be untouched.
        assert_eq!(state.get_asset_holding(&addr1, 99).unwrap().amount, 50);

        // Account counters should be decremented.
        let acct1 = state.get_or_default_account(&addr1);
        assert_eq!(
            acct1.total_assets_opted_in, 1,
            "addr1 had 2 assets, removed 1 => 1 remaining"
        );
        let acct2 = state.get_or_default_account(&addr2);
        assert_eq!(
            acct2.total_assets_opted_in, 0,
            "addr2 had 1 asset, removed 1 => 0 remaining"
        );
        let acct3 = state.get_or_default_account(&addr3);
        assert_eq!(
            acct3.total_assets_opted_in, 0,
            "addr3 had 1 asset, removed 1 => 0 remaining"
        );
    }

    #[test]
    fn test_remove_all_app_local_states_for_app() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);

        let local1 = AppLocalState {
            schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            },
            key_value: std::collections::BTreeMap::new(),
        };
        let local2 = AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 0,
            },
            key_value: std::collections::BTreeMap::new(),
        };
        let local_other = AppLocalState {
            schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 0,
            },
            key_value: std::collections::BTreeMap::new(),
        };

        // Set up accounts with counters reflecting their opt-ins.
        // addr1: opted in to app 50 (schema: 1 uint) and app 99 (schema: 3 uint) => 2 opted in.
        state.set_account(
            &addr1,
            AccountData {
                micro_algos: 1_000_000,
                total_apps_opted_in: 2,
                total_app_schema: StateSchema {
                    num_uint: 4, // 1 (app 50) + 3 (app 99)
                    num_byte_slice: 0,
                },
                ..Default::default()
            },
        );
        // addr2: opted in to app 50 only (schema: 2 uint) => 1 opted in.
        state.set_account(
            &addr2,
            AccountData {
                micro_algos: 1_000_000,
                total_apps_opted_in: 1,
                total_app_schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 0,
                },
                ..Default::default()
            },
        );

        // Two addresses have local state for app 50; addr1 also has local state for app 99.
        state.set_app_local_state(&addr1, 50, local1);
        state.set_app_local_state(&addr2, 50, local2);
        state.set_app_local_state(&addr1, 99, local_other);

        state.remove_all_app_local_states_for_app(50);

        // All local states for app 50 should be gone.
        assert!(state.get_app_local_state(&addr1, 50).is_none());
        assert!(state.get_app_local_state(&addr2, 50).is_none());
        // App 99 local state should be untouched.
        assert!(state.get_app_local_state(&addr1, 99).is_some());

        // Account counters should be updated.
        let acct1 = state.get_or_default_account(&addr1);
        assert_eq!(
            acct1.total_apps_opted_in, 1,
            "addr1 had 2 apps opted in, removed 1 => 1 remaining"
        );
        assert_eq!(
            acct1.total_app_schema.num_uint, 3,
            "addr1 had 4 uint (1+3), subtracted 1 => 3 remaining"
        );
        assert_eq!(acct1.total_app_schema.num_byte_slice, 0);

        let acct2 = state.get_or_default_account(&addr2);
        assert_eq!(
            acct2.total_apps_opted_in, 0,
            "addr2 had 1 app opted in, removed 1 => 0 remaining"
        );
        assert_eq!(
            acct2.total_app_schema.num_uint, 0,
            "addr2 had 2 uint, subtracted 2 => 0 remaining"
        );
        assert_eq!(acct2.total_app_schema.num_byte_slice, 0);
    }

    #[test]
    fn test_rollback_cleans_non_snapshotted_holdings() {
        // Simulate the scenario: snapshot covers addr1, then a nested create
        // adds an asset holding for addr2 (not snapshotted). On rollback +
        // remove_all_asset_holdings_for_asset, addr2's holding should be removed.
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);

        state.set_account(
            &addr1,
            AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            },
        );
        state.set_account(
            &addr2,
            AccountData {
                micro_algos: 500_000,
                ..Default::default()
            },
        );

        // Snapshot only covers addr1.
        let snap = state.snapshot(&[addr1]);

        // Simulate nested inner txn: create asset 42 and opt-in addr2.
        state.set_asset_params(
            42,
            AssetParamsRecord {
                params: algo_types::AssetParams {
                    total: 1000,
                    ..Default::default()
                },
                creator: addr1,
            },
        );
        state.set_asset_holding(
            &addr1,
            42,
            AssetHolding {
                amount: 1000,
                frozen: false,
            },
        );
        state.set_asset_holding(
            &addr2,
            42,
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );

        // Rollback: restore snapshot then clean up created asset.
        state.restore_snapshot(snap);
        state.remove_asset_params(42);
        state.remove_all_asset_holdings_for_asset(42);

        // addr1's holding is cleaned by restore_snapshot (snapshotted addr).
        assert!(state.get_asset_holding(&addr1, 42).is_none());
        // addr2's holding was NOT snapshotted but should be cleaned by
        // remove_all_asset_holdings_for_asset.
        assert!(
            state.get_asset_holding(&addr2, 42).is_none(),
            "non-snapshotted account's holding should be cleaned on rollback"
        );
        // Asset params should be gone.
        assert!(state.get_asset_params(42).is_none());
    }

    // -----------------------------------------------------------------------
    // Box storage tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_box_create_read_update_delete() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();

        // Box does not exist yet.
        assert!(state.get_box(100, b"mybox").is_none());
        assert!(state.box_len(100, b"mybox").is_none());

        // Create.
        state.set_box(100, b"mybox", vec![0u8; 10]);
        assert_eq!(state.get_box(100, b"mybox").unwrap().len(), 10);
        assert_eq!(state.box_len(100, b"mybox").unwrap(), 10);

        // Update.
        state.set_box(100, b"mybox", b"hello world".to_vec());
        assert_eq!(state.get_box(100, b"mybox").unwrap(), b"hello world");
        assert_eq!(state.box_len(100, b"mybox").unwrap(), 11);

        // Delete.
        assert!(state.delete_box(100, b"mybox"));
        assert!(state.get_box(100, b"mybox").is_none());

        // Delete non-existing.
        assert!(!state.delete_box(100, b"mybox"));
    }

    #[test]
    fn test_box_isolation_between_apps() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();

        // Two apps with same box name.
        state.set_box(100, b"shared_name", b"app100_data".to_vec());
        state.set_box(200, b"shared_name", b"app200_data".to_vec());

        assert_eq!(state.get_box(100, b"shared_name").unwrap(), b"app100_data");
        assert_eq!(state.get_box(200, b"shared_name").unwrap(), b"app200_data");

        // Deleting one app's box does not affect the other.
        state.delete_box(100, b"shared_name");
        assert!(state.get_box(100, b"shared_name").is_none());
        assert_eq!(state.get_box(200, b"shared_name").unwrap(), b"app200_data");
    }

    #[test]
    fn test_box_snapshot_and_rollback_create() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.get_or_default_account(&addr).micro_algos = 1_000_000;

        // Snapshot with app_id 100 (no boxes yet).
        let snap = state.snapshot_with_ids(&[addr], &[], &[100]);

        // Create a box after snapshot.
        state.set_box(100, b"newbox", b"data".to_vec());
        assert!(state.get_box(100, b"newbox").is_some());

        // Rollback should remove the newly-created box.
        state.restore_snapshot(snap);
        assert!(
            state.get_box(100, b"newbox").is_none(),
            "newly-created box should be removed on rollback"
        );
    }

    #[test]
    fn test_box_snapshot_and_rollback_modify() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.get_or_default_account(&addr).micro_algos = 1_000_000;
        state.set_box(100, b"mybox", b"original".to_vec());

        // Snapshot with app_id 100.
        let snap = state.snapshot_with_ids(&[addr], &[], &[100]);

        // Modify box after snapshot.
        state.set_box(100, b"mybox", b"modified".to_vec());
        assert_eq!(state.get_box(100, b"mybox").unwrap(), b"modified");

        // Rollback should restore original value.
        state.restore_snapshot(snap);
        assert_eq!(
            state.get_box(100, b"mybox").unwrap(),
            b"original",
            "box should be restored to original value on rollback"
        );
    }

    #[test]
    fn test_box_snapshot_and_rollback_delete() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.get_or_default_account(&addr).micro_algos = 1_000_000;
        state.set_box(100, b"mybox", b"data".to_vec());

        // Snapshot with app_id 100.
        let snap = state.snapshot_with_ids(&[addr], &[], &[100]);

        // Delete box after snapshot.
        state.delete_box(100, b"mybox");
        assert!(state.get_box(100, b"mybox").is_none());

        // Rollback should restore the box.
        state.restore_snapshot(snap);
        assert_eq!(
            state.get_box(100, b"mybox").unwrap(),
            b"data",
            "deleted box should be restored on rollback"
        );
    }

    #[test]
    fn test_box_snapshot_does_not_affect_other_apps() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();
        let addr = Address([1u8; 32]);
        state.get_or_default_account(&addr).micro_algos = 1_000_000;
        state.set_box(100, b"box100", b"data100".to_vec());
        state.set_box(200, b"box200", b"data200".to_vec());

        // Snapshot only app 100.
        let snap = state.snapshot_with_ids(&[addr], &[], &[100]);

        // Modify both apps' boxes.
        state.set_box(100, b"box100", b"modified100".to_vec());
        state.set_box(200, b"box200", b"modified200".to_vec());

        // Rollback only affects app 100.
        state.restore_snapshot(snap);
        assert_eq!(
            state.get_box(100, b"box100").unwrap(),
            b"data100",
            "app 100's box should be restored"
        );
        assert_eq!(
            state.get_box(200, b"box200").unwrap(),
            b"modified200",
            "app 200's box should NOT be affected by rollback"
        );
    }

    #[test]
    fn test_box_multiple_keys_same_app() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();

        state.set_box(100, b"box_a", b"alpha".to_vec());
        state.set_box(100, b"box_b", b"beta".to_vec());
        state.set_box(100, b"box_c", b"gamma".to_vec());

        assert_eq!(state.get_box(100, b"box_a").unwrap(), b"alpha");
        assert_eq!(state.get_box(100, b"box_b").unwrap(), b"beta");
        assert_eq!(state.get_box(100, b"box_c").unwrap(), b"gamma");

        // Delete one, others unaffected.
        state.delete_box(100, b"box_b");
        assert!(state.get_box(100, b"box_b").is_none());
        assert_eq!(state.get_box(100, b"box_a").unwrap(), b"alpha");
        assert_eq!(state.get_box(100, b"box_c").unwrap(), b"gamma");
    }
}
