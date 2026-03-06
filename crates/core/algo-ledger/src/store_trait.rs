use algo_error::AlgoError;
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, Round,
};

/// Abstraction over ledger storage backends.
///
/// Both the in-memory `LedgerState` and a future SQLite backend implement
/// this trait. Methods use owned values (not `&mut` references) so that
/// non-in-memory backends can serialize/deserialize without lifetime issues.
///
/// Used via generics (`<L: LedgerStore>`) for monomorphization — object
/// safety is NOT required.
pub trait LedgerStore {
    /// Opaque snapshot handle for rollback.
    ///
    /// For in-memory: `StateSnapshot` (cloned data).
    /// For SQLite: a SAVEPOINT identifier.
    type Snapshot;

    // ---- Accounts ----

    /// Get a copy of the account data, or `None` if the address has no record.
    fn get_account(&self, addr: &Address) -> Option<AccountData>;

    /// Write account data for the given address (insert or overwrite).
    fn set_account(&mut self, addr: &Address, account: AccountData);

    /// Get a copy of the account data, returning `Default::default()` if absent.
    ///
    /// Does NOT insert a default record — the caller must `set_account` to persist.
    fn get_or_default_account(&self, addr: &Address) -> AccountData {
        self.get_account(addr).unwrap_or_default()
    }

    /// Remove the account record entirely.
    fn remove_account(&mut self, addr: &Address);

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding>;
    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding);
    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64);
    fn has_asset_holding(&self, addr: &Address, asset_id: u64) -> bool {
        self.get_asset_holding(addr, asset_id).is_some()
    }

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord>;
    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord);
    fn remove_asset_params(&mut self, asset_id: u64);
    fn has_asset_params(&self, asset_id: u64) -> bool {
        self.get_asset_params(asset_id).is_some()
    }

    // ---- App Params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams>;
    fn set_app_params(&mut self, app_id: u64, params: AppParams);
    fn remove_app_params(&mut self, app_id: u64);
    fn has_app_params(&self, app_id: u64) -> bool {
        self.get_app_params(app_id).is_some()
    }

    /// Get app params, inserting a default if absent, and return the value.
    ///
    /// This mirrors the `entry().or_insert_with()` pattern used in eval_delta.
    /// The default is constructed via the provided closure.
    fn get_or_insert_app_params(
        &mut self,
        app_id: u64,
        default: impl FnOnce() -> AppParams,
    ) -> AppParams {
        match self.get_app_params(app_id) {
            Some(p) => p,
            None => {
                let p = default();
                self.set_app_params(app_id, p.clone());
                p
            }
        }
    }

    /// Iterate over all app params where the creator matches the given address.
    ///
    /// Used by `min_balance_with_state` to sum global schema costs for created apps.
    /// Returns a `Vec` to avoid lifetime issues with non-in-memory backends.
    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams>;

    // ---- App Local States ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState>;
    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState);
    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64);
    fn has_app_local_state(&self, addr: &Address, app_id: u64) -> bool {
        self.get_app_local_state(addr, app_id).is_some()
    }

    /// Get app local state, inserting a default if absent, and return the value.
    ///
    /// Mirrors the `entry().or_insert_with()` pattern used in eval_delta.
    fn get_or_insert_app_local_state(
        &mut self,
        addr: &Address,
        app_id: u64,
        default: impl FnOnce() -> AppLocalState,
    ) -> AppLocalState {
        match self.get_app_local_state(addr, app_id) {
            Some(s) => s,
            None => {
                let s = default();
                self.set_app_local_state(addr, app_id, s.clone());
                s
            }
        }
    }

    /// Collect all app local states for a given address.
    ///
    /// Used by `min_balance_with_state` to sum local schema costs.
    /// Returns `Vec<(u64, AppLocalState)>` — the app ID and local state.
    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)>;

    // ---- Leases ----

    /// Check whether a lease is active for (sender, lease) at the given round.
    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError>;

    /// Record a lease for (sender, lease) with the given last_valid round.
    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64);

    /// Remove all leases whose last_valid is strictly less than `current_round`.
    fn purge_expired_leases(&mut self, current_round: u64);

    // ---- Chain-level state (getters) ----

    fn current_round(&self) -> Round;
    fn rewards_level(&self) -> u64;
    fn rewards_rate(&self) -> u64;
    fn rewards_residue(&self) -> u64;
    fn rewards_recalculation_round(&self) -> u64;
    fn fee_sink(&self) -> Address;
    fn rewards_pool(&self) -> Address;
    fn genesis_id(&self) -> &str;
    fn genesis_hash(&self) -> &[u8; 32];
    fn protocol(&self) -> &str;

    // ---- Chain-level state (setters) ----

    fn set_current_round(&mut self, round: Round);
    fn set_rewards_level(&mut self, level: u64);
    fn set_rewards_rate(&mut self, rate: u64);
    fn set_rewards_residue(&mut self, residue: u64);
    fn set_rewards_recalculation_round(&mut self, round: u64);
    fn set_fee_sink(&mut self, addr: Address);
    fn set_rewards_pool(&mut self, addr: Address);
    fn set_genesis_id(&mut self, id: String);
    fn set_genesis_hash(&mut self, hash: [u8; 32]);
    fn set_protocol(&mut self, protocol: String);

    // ---- Snapshot / Restore ----

    /// Create a snapshot covering the given addresses (accounts, holdings,
    /// local states) for later rollback.
    fn snapshot(&self, addrs: &[Address]) -> Self::Snapshot;

    /// Create a snapshot that also covers specific asset param and app param
    /// IDs, in addition to address-based state.
    fn snapshot_with_ids(
        &self,
        addrs: &[Address],
        asset_ids: &[u64],
        app_ids: &[u64],
    ) -> Self::Snapshot;

    /// Restore state from a previous snapshot, reverting all changes made
    /// since the snapshot was taken.
    fn restore_snapshot(&mut self, snapshot: Self::Snapshot);

    // ---- Min balance ----

    /// Compute the minimum balance for an account, including schema-based
    /// costs from opted-in and created apps.
    fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64;
}
