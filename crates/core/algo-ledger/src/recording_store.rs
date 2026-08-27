//! A `LedgerStore` wrapper that records the first-touch (pre-mutation) value
//! of every account and resource actually written during a block apply.
//!
//! # Why this exists (issue #604)
//!
//! [`crate::apply::apply_block_with_delta_mode_and_apply_data`] builds
//! `AccountDeltas.app_resources`/`asset_resources`/`StateDelta.creatables`
//! by diffing a pre-apply snapshot against post-apply state, for a set of
//! `(address, id)` resource keys collected from the block's **top-level**
//! transaction fields (issue #586/#603) before the block is applied. An
//! `Appl` call's approval program can, via `itxn_submit`, touch resources
//! that top-level scan never sees -- an inner `acfg`/`axfer`/`afrz`/`appl`
//! at any nesting depth. Those resources need the exact same pre/post
//! diffing, but the set of keys to diff isn't known until *after* the
//! block has been applied and the AVM has actually run the inner
//! transactions -- by which point a plain pre-apply snapshot can no longer
//! be taken (the state has already mutated).
//!
//! Walking `eval_delta::parse_eval_delta`'s `EvalDelta.inner_txns` tree
//! after the fact hits the same problem in a different form: for a
//! freshly-executed block (`ApplyMode::Execute` on an unexecuted payset --
//! e.g. `bin/algod-rust/src/dev_producer.rs`'s self-produced-block path),
//! there is no recorded `EvalDelta` before the apply to walk, so an
//! inner-touched *pre-existing* resource's true pre-image would have to be
//! read from the store *after* the mutation already happened -- silently
//! wrong (it would read the post-value as if it were the pre-value,
//! collapsing the diff to "unchanged").
//!
//! This module solves both problems by recording pre-mutation values as
//! they actually happen, at the point of mutation, regardless of call
//! depth -- mirroring the existing `kv_mods_recorder` pattern
//! (`avm_context.rs`, issue #570) used for box deltas, generalized to
//! every resource kind `LedgerStore` exposes a setter for. Since every
//! mutation (top-level or inner, any nesting depth) ultimately goes
//! through the same `&mut L: LedgerStore` reference threaded through
//! `apply_block_impl`/`avm_context.rs`, wrapping that single reference for
//! the duration of one block's apply captures every touch exactly once,
//! with no need to separately re-derive or bound-walk nesting depth.
//!
//! [`RecordingStore`] otherwise delegates every trait method unchanged --
//! it changes no ledger *semantics*, only what gets recorded alongside.

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, BlockHeader,
    Round,
};

use crate::store_trait::{BoxPage, LedgerStore};

/// First-touch (pre-mutation) values recorded during one wrapped block
/// apply. `None` means the key had no record immediately before its first
/// mutation this round (i.e. that mutation was a create). A key absent
/// from a map entirely was never mutated this round.
#[derive(Debug, Default)]
pub(crate) struct ResourceTouches {
    pub accounts: HashMap<Address, Option<AccountData>>,
    pub asset_holdings: HashMap<(Address, u64), Option<AssetHolding>>,
    pub asset_params: HashMap<u64, Option<AssetParamsRecord>>,
    pub app_params: HashMap<u64, Option<AppParams>>,
    pub app_local_states: HashMap<(Address, u64), Option<AppLocalState>>,
}

/// Wraps `&mut L`, delegating every [`LedgerStore`] method unchanged except
/// that the setters/removers for accounts, asset holdings, asset params,
/// app params, and app local states additionally record the pre-mutation
/// value into `touches` the first time each key is touched (subsequent
/// touches to the same key in the same wrapped apply are no-ops for
/// recording purposes -- first-touch wins, matching `kv_mods_recorder`).
pub(crate) struct RecordingStore<'a, L: LedgerStore> {
    inner: &'a mut L,
    pub touches: ResourceTouches,
}

impl<'a, L: LedgerStore> RecordingStore<'a, L> {
    pub fn new(inner: &'a mut L) -> Self {
        Self {
            inner,
            touches: ResourceTouches::default(),
        }
    }
}

impl<L: LedgerStore> LedgerStore for RecordingStore<'_, L> {
    type Snapshot = L::Snapshot;

    // ---- Accounts ----

    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        self.inner.get_account(addr)
    }

    fn set_account(&mut self, addr: &Address, account: AccountData) {
        let pre = self.inner.get_account(addr);
        self.touches.accounts.entry(*addr).or_insert(pre);
        self.inner.set_account(addr, account);
    }

    fn remove_account(&mut self, addr: &Address) {
        let pre = self.inner.get_account(addr);
        self.touches.accounts.entry(*addr).or_insert(pre);
        self.inner.remove_account(addr);
    }

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        self.inner.get_asset_holding(addr, asset_id)
    }

    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding) {
        let pre = self.inner.get_asset_holding(addr, asset_id);
        self.touches
            .asset_holdings
            .entry((*addr, asset_id))
            .or_insert(pre);
        self.inner.set_asset_holding(addr, asset_id, holding);
    }

    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64) {
        let pre = self.inner.get_asset_holding(addr, asset_id);
        self.touches
            .asset_holdings
            .entry((*addr, asset_id))
            .or_insert(pre);
        self.inner.remove_asset_holding(addr, asset_id);
    }

    fn remove_all_asset_holdings_for_asset(&mut self, asset_id: u64) {
        // Rollback cleanup only (see trait doc comment) -- the holdings it
        // removes were created and unwound within the same failed attempt,
        // so there is nothing real to attribute a round-level touch to.
        self.inner.remove_all_asset_holdings_for_asset(asset_id);
    }

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        self.inner.get_asset_params(asset_id)
    }

    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord) {
        let pre = self.inner.get_asset_params(asset_id);
        self.touches.asset_params.entry(asset_id).or_insert(pre);
        self.inner.set_asset_params(asset_id, record);
    }

    fn remove_asset_params(&mut self, asset_id: u64) {
        let pre = self.inner.get_asset_params(asset_id);
        self.touches.asset_params.entry(asset_id).or_insert(pre);
        self.inner.remove_asset_params(asset_id);
    }

    // ---- App Params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        self.inner.get_app_params(app_id)
    }

    fn set_app_params(&mut self, app_id: u64, params: AppParams) {
        let pre = self.inner.get_app_params(app_id);
        self.touches.app_params.entry(app_id).or_insert(pre);
        self.inner.set_app_params(app_id, params);
    }

    fn remove_app_params(&mut self, app_id: u64) {
        let pre = self.inner.get_app_params(app_id);
        self.touches.app_params.entry(app_id).or_insert(pre);
        self.inner.remove_app_params(app_id);
    }

    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams> {
        self.inner.app_params_created_by(creator)
    }

    // ---- App Local States ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        self.inner.get_app_local_state(addr, app_id)
    }

    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState) {
        let pre = self.inner.get_app_local_state(addr, app_id);
        self.touches
            .app_local_states
            .entry((*addr, app_id))
            .or_insert(pre);
        self.inner.set_app_local_state(addr, app_id, local_state);
    }

    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64) {
        let pre = self.inner.get_app_local_state(addr, app_id);
        self.touches
            .app_local_states
            .entry((*addr, app_id))
            .or_insert(pre);
        self.inner.remove_app_local_state(addr, app_id);
    }

    fn remove_all_app_local_states_for_app(&mut self, app_id: u64) {
        // Rollback cleanup only -- see `remove_all_asset_holdings_for_asset`.
        self.inner.remove_all_app_local_states_for_app(app_id);
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        self.inner.app_local_states_for_addr(addr)
    }

    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        self.inner.asset_holdings_for_addr(addr)
    }

    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        self.inner.created_assets_for_addr(addr)
    }

    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        self.inner.created_apps_for_addr(addr)
    }

    // ---- Box Storage ----

    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get_box(app_id, key)
    }

    fn set_box(&mut self, app_id: u64, key: &[u8], value: Vec<u8>) {
        self.inner.set_box(app_id, key, value);
    }

    fn delete_box(&mut self, app_id: u64, key: &[u8]) -> bool {
        self.inner.delete_box(app_id, key)
    }

    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        self.inner.box_keys_for_app(app_id)
    }

    fn box_keys_by_prefix_paginated(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> (BoxPage, bool) {
        self.inner
            .box_keys_by_prefix_paginated(app_id, prefix, cursor, limit, include_values)
    }

    // ---- Leases ----

    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError> {
        self.inner.check_lease(sender, lease, current_round)
    }

    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        self.inner.record_lease(sender, lease, last_valid);
    }

    fn purge_expired_leases(&mut self, current_round: u64) {
        self.inner.purge_expired_leases(current_round);
    }

    // ---- Chain-level state (getters) ----

    fn current_round(&self) -> Round {
        self.inner.current_round()
    }

    fn rewards_level(&self) -> u64 {
        self.inner.rewards_level()
    }

    fn rewards_rate(&self) -> u64 {
        self.inner.rewards_rate()
    }

    fn rewards_residue(&self) -> u64 {
        self.inner.rewards_residue()
    }

    fn rewards_recalculation_round(&self) -> u64 {
        self.inner.rewards_recalculation_round()
    }

    fn fee_sink(&self) -> Address {
        self.inner.fee_sink()
    }

    fn rewards_pool(&self) -> Address {
        self.inner.rewards_pool()
    }

    fn genesis_id(&self) -> &str {
        self.inner.genesis_id()
    }

    fn genesis_hash(&self) -> &[u8; 32] {
        self.inner.genesis_hash()
    }

    fn protocol(&self) -> &str {
        self.inner.protocol()
    }

    fn txn_counter(&self) -> u64 {
        self.inner.txn_counter()
    }

    fn account_totals(&self) -> crate::state_delta::AccountTotals {
        self.inner.account_totals()
    }

    // ---- Chain-level state (setters) ----

    fn set_current_round(&mut self, round: Round) {
        self.inner.set_current_round(round);
    }

    fn set_rewards_level(&mut self, level: u64) {
        self.inner.set_rewards_level(level);
    }

    fn set_rewards_rate(&mut self, rate: u64) {
        self.inner.set_rewards_rate(rate);
    }

    fn set_rewards_residue(&mut self, residue: u64) {
        self.inner.set_rewards_residue(residue);
    }

    fn set_rewards_recalculation_round(&mut self, round: u64) {
        self.inner.set_rewards_recalculation_round(round);
    }

    fn set_fee_sink(&mut self, addr: Address) {
        self.inner.set_fee_sink(addr);
    }

    fn set_rewards_pool(&mut self, addr: Address) {
        self.inner.set_rewards_pool(addr);
    }

    fn set_genesis_id(&mut self, id: String) {
        self.inner.set_genesis_id(id);
    }

    fn set_genesis_hash(&mut self, hash: [u8; 32]) {
        self.inner.set_genesis_hash(hash);
    }

    fn set_protocol(&mut self, protocol: String) {
        self.inner.set_protocol(protocol);
    }

    fn set_txn_counter(&mut self, counter: u64) {
        self.inner.set_txn_counter(counter);
    }

    // ---- Snapshot / Restore ----

    fn snapshot(&self, addrs: &[Address]) -> Self::Snapshot {
        self.inner.snapshot(addrs)
    }

    fn snapshot_with_ids(
        &self,
        addrs: &[Address],
        asset_ids: &[u64],
        app_ids: &[u64],
    ) -> Self::Snapshot {
        self.inner.snapshot_with_ids(addrs, asset_ids, app_ids)
    }

    fn restore_snapshot(&mut self, snapshot: Self::Snapshot) {
        self.inner.restore_snapshot(snapshot);
    }

    // ---- Min balance ----

    fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64 {
        self.inner.min_balance_with_state(addr, account)
    }

    // ---- Trie integration ----

    fn enable_trie(&mut self) {
        self.inner.enable_trie();
    }

    fn trie_enabled(&self) -> bool {
        self.inner.trie_enabled()
    }

    fn finalize_trie_updates(&mut self) -> Option<[u8; 32]> {
        self.inner.finalize_trie_updates()
    }

    // ---- Block / Certificate Storage ----

    fn put_block(
        &mut self,
        round: u64,
        proto: &str,
        hdrdata: &[u8],
        blkdata: &[u8],
    ) -> Result<(), AlgoError> {
        self.inner.put_block(round, proto, hdrdata, blkdata)
    }

    fn get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.inner.get_block_data(round)
    }

    fn get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.inner.get_block_header_data(round)
    }

    fn get_block_header(&self, round: u64) -> Result<Option<BlockHeader>, AlgoError> {
        self.inner.get_block_header(round)
    }

    fn get_block_cert(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.inner.get_block_cert(round)
    }

    fn get_block_proto(&self, round: u64) -> Result<Option<String>, AlgoError> {
        self.inner.get_block_proto(round)
    }

    fn put_block_cert(&mut self, round: u64, certdata: &[u8]) -> Result<(), AlgoError> {
        self.inner.put_block_cert(round, certdata)
    }

    // ---- TxTail Storage ----

    fn put_txtail(&mut self, round: u64, data: &[u8]) -> Result<(), AlgoError> {
        self.inner.put_txtail(round, data)
    }

    fn get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.inner.get_txtail(round)
    }

    // ---- Pruning ----

    fn forget_before(&mut self, round: u64) -> Result<(), AlgoError> {
        self.inner.forget_before(round)
    }
}
