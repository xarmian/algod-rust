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

//! Copy-on-write overlay over the committed ledger, the Rust counterpart of
//! go's `roundCowState` as used by the transaction pool's pending block
//! evaluator (issue #1776).
//!
//! go's pool admits a group by running it through the pending block
//! evaluator (`data/pools/transactionPool.go` `ingest` ->
//! `pendingBlockEvaluator.TransactionGroup`), i.e. the real transaction
//! apply, including AVM execution, on top of the state left by every group
//! already pending. [`PendingOverlay`] is the state holder that makes the
//! same thing possible here without cloning the ledger and without holding
//! the ledger lock between calls: it records only what the pending groups
//! changed, and every read that it does not override falls through to the
//! committed [`SqliteLedger`].
//!
//! [`OverlayStore`] borrows an overlay together with a (locked) base for the
//! duration of one evaluation call and implements [`LedgerStore`], so the
//! unmodified apply code runs on it. A group that fails part-way is undone
//! with the overlay journal ([`PendingOverlay::rollback_group`]); a group
//! that succeeds is kept ([`PendingOverlay::commit_group`]).
//!
//! Cost: a group evaluation is proportional to the group (reads hit the base
//! only for keys no earlier pending group touched), never to the number of
//! groups already pending.

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, BlockHeader,
    Round,
};

use crate::lease::LeaseTable;
use crate::sqlite::SqliteLedger;
use crate::store_trait::{LedgerStore, VoterAgreementData};

/// One reversible overlay mutation: the previous overlay-map entry
/// (`None` = the key was not in the overlay map at all).
enum Undo {
    Account(Address, Option<Option<AccountData>>),
    Holding((Address, u64), Option<Option<AssetHolding>>),
    AssetParams(u64, Option<Option<AssetParamsRecord>>),
    AppParams(u64, Option<Option<AppParams>>),
    Local((Address, u64), Option<Option<AppLocalState>>),
    Box((u64, Vec<u8>), Option<Option<Vec<u8>>>),
}

/// Chain-level scalars the apply code reads and writes through the store.
#[derive(Clone)]
struct Chain {
    round: Round,
    rewards_level: u64,
    rewards_rate: u64,
    rewards_residue: u64,
    rewards_recalculation_round: u64,
    fee_sink: Address,
    rewards_pool: Address,
    genesis_id: String,
    genesis_hash: [u8; 32],
    protocol: String,
    txn_counter: u64,
}

/// Everything the pending groups changed relative to the committed ledger.
///
/// A map value of `None` is a tombstone (the key was removed).
pub struct PendingOverlay {
    accounts: HashMap<Address, Option<AccountData>>,
    holdings: HashMap<(Address, u64), Option<AssetHolding>>,
    asset_params: HashMap<u64, Option<AssetParamsRecord>>,
    app_params: HashMap<u64, Option<AppParams>>,
    locals: HashMap<(Address, u64), Option<AppLocalState>>,
    boxes: HashMap<(u64, Vec<u8>), Option<Vec<u8>>>,
    /// Leases recorded by pending groups (the committed table is consulted
    /// through the base).
    leases: LeaseTable,
    chain: Chain,
    /// Chain scalars as captured from the base, to reset between groups.
    chain_base: Chain,
    journal: Vec<Undo>,
}

impl PendingOverlay {
    /// An empty overlay on top of `base`'s current committed state.
    pub fn new(base: &SqliteLedger) -> Self {
        let chain = Chain {
            round: base.current_round(),
            rewards_level: base.rewards_level(),
            rewards_rate: base.rewards_rate(),
            rewards_residue: base.rewards_residue(),
            rewards_recalculation_round: base.rewards_recalculation_round(),
            fee_sink: base.fee_sink(),
            rewards_pool: base.rewards_pool(),
            genesis_id: base.genesis_id().to_string(),
            genesis_hash: *base.genesis_hash(),
            protocol: base.protocol().to_string(),
            txn_counter: base.txn_counter(),
        };
        Self {
            accounts: HashMap::new(),
            holdings: HashMap::new(),
            asset_params: HashMap::new(),
            app_params: HashMap::new(),
            locals: HashMap::new(),
            boxes: HashMap::new(),
            leases: LeaseTable::new(),
            chain_base: chain.clone(),
            chain,
            journal: Vec::new(),
        }
    }

    /// The committed round this overlay is layered on.
    pub fn base_round(&self) -> Round {
        self.chain_base.round
    }

    /// The transaction counter after every group committed so far.
    pub fn txn_counter(&self) -> u64 {
        self.chain_base.txn_counter
    }

    /// Start a group: the journal is empty and a lease undo journal is open.
    pub fn begin_group(&mut self) {
        self.journal.clear();
        // A leaked journal (never expected) is closed first.
        self.leases.discard_undo();
        let opened = self.leases.try_begin_undo();
        debug_assert!(opened);
    }

    /// Keep the group effects. `final_txn_counter` is the counter after the
    /// group (the apply probe value).
    pub fn commit_group(&mut self, final_txn_counter: u64) {
        self.journal.clear();
        self.leases.discard_undo();
        self.chain_base.txn_counter = final_txn_counter;
        self.chain = self.chain_base.clone();
    }

    /// Undo every effect of the group in progress.
    pub fn rollback_group(&mut self) {
        self.unwind_to(0);
        self.leases.rollback_undo();
        self.chain = self.chain_base.clone();
    }

    /// Number of overlay entries (diagnostics and tests).
    pub fn len(&self) -> usize {
        self.accounts.len()
            + self.holdings.len()
            + self.asset_params.len()
            + self.app_params.len()
            + self.locals.len()
            + self.boxes.len()
    }

    /// Whether no pending group has changed anything yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn unwind_to(&mut self, mark: usize) {
        while self.journal.len() > mark {
            let Some(u) = self.journal.pop() else { break };
            match u {
                Undo::Account(k, prev) => restore(&mut self.accounts, k, prev),
                Undo::Holding(k, prev) => restore(&mut self.holdings, k, prev),
                Undo::AssetParams(k, prev) => restore(&mut self.asset_params, k, prev),
                Undo::AppParams(k, prev) => restore(&mut self.app_params, k, prev),
                Undo::Local(k, prev) => restore(&mut self.locals, k, prev),
                Undo::Box(k, prev) => restore(&mut self.boxes, k, prev),
            }
        }
    }
}

fn restore<K: std::hash::Hash + Eq, V>(map: &mut HashMap<K, V>, k: K, prev: Option<V>) {
    match prev {
        Some(v) => {
            map.insert(k, v);
        }
        None => {
            map.remove(&k);
        }
    }
}

/// A [`LedgerStore`] view of `base` + `overlay` for one evaluation call.
pub struct OverlayStore<'a> {
    base: &'a SqliteLedger,
    st: &'a mut PendingOverlay,
}

impl<'a> OverlayStore<'a> {
    /// Layer `overlay` on `base`. `base` must be the ledger the overlay was
    /// created from, still at the same committed round.
    pub fn new(base: &'a SqliteLedger, overlay: &'a mut PendingOverlay) -> Self {
        Self { base, st: overlay }
    }
}

macro_rules! put {
    ($self:ident, $map:ident, $variant:ident, $key:expr, $val:expr) => {{
        let key = $key;
        let prev = $self.st.$map.insert(key.clone(), $val);
        $self.st.journal.push(Undo::$variant(key, prev));
    }};
}

impl LedgerStore for OverlayStore<'_> {
    /// Mark = journal length; restoring unwinds the journal to it.
    type Snapshot = usize;

    // ---- Accounts ----

    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        match self.st.accounts.get(addr) {
            Some(v) => v.clone(),
            None => self.base.get_account(addr),
        }
    }

    fn set_account(&mut self, addr: &Address, account: AccountData) {
        put!(self, accounts, Account, *addr, Some(account));
    }

    fn remove_account(&mut self, addr: &Address) {
        put!(self, accounts, Account, *addr, None);
        // `SqliteLedger::remove_account` also drops the account resources.
        for (id, _) in self.asset_holdings_for_addr(addr) {
            put!(self, holdings, Holding, (*addr, id), None);
        }
        for (id, _) in self.app_local_states_for_addr(addr) {
            put!(self, locals, Local, (*addr, id), None);
        }
    }

    // ---- Asset holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        match self.st.holdings.get(&(*addr, asset_id)) {
            Some(v) => v.clone(),
            None => self.base.get_asset_holding(addr, asset_id),
        }
    }

    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding) {
        put!(self, holdings, Holding, (*addr, asset_id), Some(holding));
    }

    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64) {
        put!(self, holdings, Holding, (*addr, asset_id), None);
    }

    fn remove_all_asset_holdings_for_asset(&mut self, asset_id: u64) {
        // Rollback cleanup of an id created inside the evaluation: such
        // holdings only ever exist in the overlay. The committed ledger
        // cannot hold a row for an id above its transaction counter, so
        // tombstoning overlay entries is complete; calling this for any
        // other id would leave committed rows visible.
        debug_assert!(
            asset_id > self.st.chain_base.txn_counter,
            "remove_all_asset_holdings_for_asset is only valid for ids created inside the evaluation"
        );
        let keys: Vec<(Address, u64)> = self
            .st
            .holdings
            .iter()
            .filter(|((_, id), v)| *id == asset_id && v.is_some())
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            put!(self, holdings, Holding, k, None);
        }
    }

    // ---- Asset params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        match self.st.asset_params.get(&asset_id) {
            Some(v) => v.clone(),
            None => self.base.get_asset_params(asset_id),
        }
    }

    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord) {
        put!(self, asset_params, AssetParams, asset_id, Some(record));
    }

    fn remove_asset_params(&mut self, asset_id: u64) {
        put!(self, asset_params, AssetParams, asset_id, None);
    }

    // ---- App params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        match self.st.app_params.get(&app_id) {
            Some(v) => v.clone(),
            None => self.base.get_app_params(app_id),
        }
    }

    fn set_app_params(&mut self, app_id: u64, params: AppParams) {
        put!(self, app_params, AppParams, app_id, Some(params));
    }

    fn remove_app_params(&mut self, app_id: u64) {
        put!(self, app_params, AppParams, app_id, None);
    }

    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams> {
        let mut out: Vec<AppParams> = self
            .base
            .created_apps_for_addr(creator)
            .into_iter()
            .filter(|(id, _)| !self.st.app_params.contains_key(id))
            .map(|(_, p)| p)
            .collect();
        out.extend(
            self.st
                .app_params
                .values()
                .flatten()
                .filter(|p| p.creator == *creator)
                .cloned(),
        );
        out
    }

    // ---- App local states ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        match self.st.locals.get(&(*addr, app_id)) {
            Some(v) => v.clone(),
            None => self.base.get_app_local_state(addr, app_id),
        }
    }

    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState) {
        put!(self, locals, Local, (*addr, app_id), Some(local_state));
    }

    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64) {
        put!(self, locals, Local, (*addr, app_id), None);
    }

    fn remove_all_app_local_states_for_app(&mut self, app_id: u64) {
        // See `remove_all_asset_holdings_for_asset`: only ids created inside
        // the evaluation (above the committed transaction counter).
        debug_assert!(
            app_id > self.st.chain_base.txn_counter,
            "remove_all_app_local_states_for_app is only valid for ids created inside the evaluation"
        );
        let keys: Vec<(Address, u64)> = self
            .st
            .locals
            .iter()
            .filter(|((_, id), v)| *id == app_id && v.is_some())
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            put!(self, locals, Local, k, None);
        }
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        let mut out: Vec<(u64, AppLocalState)> = self
            .base
            .app_local_states_for_addr(addr)
            .into_iter()
            .filter(|(id, _)| !self.st.locals.contains_key(&(*addr, *id)))
            .collect();
        for ((a, id), v) in &self.st.locals {
            if a == addr {
                if let Some(v) = v {
                    out.push((*id, v.clone()));
                }
            }
        }
        out
    }

    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        let mut out: Vec<(u64, AssetHolding)> = self
            .base
            .asset_holdings_for_addr(addr)
            .into_iter()
            .filter(|(id, _)| !self.st.holdings.contains_key(&(*addr, *id)))
            .collect();
        for ((a, id), v) in &self.st.holdings {
            if a == addr {
                if let Some(v) = v {
                    out.push((*id, v.clone()));
                }
            }
        }
        out
    }

    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        let mut out: Vec<(u64, AssetParamsRecord)> = self
            .base
            .created_assets_for_addr(addr)
            .into_iter()
            .filter(|(id, _)| !self.st.asset_params.contains_key(id))
            .collect();
        for (id, v) in &self.st.asset_params {
            if let Some(v) = v {
                if v.creator == *addr {
                    out.push((*id, v.clone()));
                }
            }
        }
        out
    }

    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        let mut out: Vec<(u64, AppParams)> = self
            .base
            .created_apps_for_addr(addr)
            .into_iter()
            .filter(|(id, _)| !self.st.app_params.contains_key(id))
            .collect();
        for (id, v) in &self.st.app_params {
            if let Some(v) = v {
                if v.creator == *addr {
                    out.push((*id, v.clone()));
                }
            }
        }
        out
    }

    // ---- Boxes ----

    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        match self.st.boxes.get(&(app_id, key.to_vec())) {
            Some(v) => v.clone(),
            None => self.base.get_box(app_id, key),
        }
    }

    fn set_box(&mut self, app_id: u64, key: &[u8], value: Vec<u8>) {
        put!(self, boxes, Box, (app_id, key.to_vec()), Some(value));
    }

    fn delete_box(&mut self, app_id: u64, key: &[u8]) -> bool {
        let existed = self.get_box(app_id, key).is_some();
        if existed {
            put!(self, boxes, Box, (app_id, key.to_vec()), None);
        }
        existed
    }

    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self
            .base
            .box_keys_for_app(app_id)
            .into_iter()
            .filter(|k| !self.st.boxes.contains_key(&(app_id, k.clone())))
            .collect();
        for ((id, k), v) in &self.st.boxes {
            if *id == app_id && v.is_some() {
                out.push(k.clone());
            }
        }
        out
    }

    // ---- Leases ----

    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError> {
        self.st.leases.check(sender, lease, current_round)?;
        self.base.check_lease(sender, lease, current_round)
    }

    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        self.st.leases.record(sender, lease, last_valid);
    }

    fn purge_expired_leases(&mut self, current_round: u64) {
        // Expiry of the committed table is the base business; the overlay
        // table only ever holds leases of the current pending block.
        self.st.leases.purge_expired(current_round);
    }

    // ---- Chain-level state ----

    fn current_round(&self) -> Round {
        self.st.chain.round
    }
    fn rewards_level(&self) -> u64 {
        self.st.chain.rewards_level
    }
    fn rewards_rate(&self) -> u64 {
        self.st.chain.rewards_rate
    }
    fn rewards_residue(&self) -> u64 {
        self.st.chain.rewards_residue
    }
    fn rewards_recalculation_round(&self) -> u64 {
        self.st.chain.rewards_recalculation_round
    }
    fn fee_sink(&self) -> Address {
        self.st.chain.fee_sink
    }
    fn rewards_pool(&self) -> Address {
        self.st.chain.rewards_pool
    }
    fn genesis_id(&self) -> &str {
        &self.st.chain.genesis_id
    }
    fn genesis_hash(&self) -> &[u8; 32] {
        &self.st.chain.genesis_hash
    }
    fn protocol(&self) -> &str {
        &self.st.chain.protocol
    }
    fn txn_counter(&self) -> u64 {
        self.st.chain.txn_counter
    }
    fn account_totals(&self) -> crate::state_delta::AccountTotals {
        self.base.account_totals()
    }

    fn set_current_round(&mut self, round: Round) {
        self.st.chain.round = round;
    }
    fn set_rewards_level(&mut self, level: u64) {
        self.st.chain.rewards_level = level;
    }
    fn set_rewards_rate(&mut self, rate: u64) {
        self.st.chain.rewards_rate = rate;
    }
    fn set_rewards_residue(&mut self, residue: u64) {
        self.st.chain.rewards_residue = residue;
    }
    fn set_rewards_recalculation_round(&mut self, round: u64) {
        self.st.chain.rewards_recalculation_round = round;
    }
    fn set_fee_sink(&mut self, addr: Address) {
        self.st.chain.fee_sink = addr;
    }
    fn set_rewards_pool(&mut self, addr: Address) {
        self.st.chain.rewards_pool = addr;
    }
    fn set_genesis_id(&mut self, id: String) {
        self.st.chain.genesis_id = id;
    }
    fn set_genesis_hash(&mut self, hash: [u8; 32]) {
        self.st.chain.genesis_hash = hash;
    }
    fn set_protocol(&mut self, protocol: String) {
        self.st.chain.protocol = protocol;
    }
    fn set_txn_counter(&mut self, counter: u64) {
        self.st.chain.txn_counter = counter;
    }

    // ---- Snapshot / restore (journal marks) ----

    fn snapshot(&self, _addrs: &[Address]) -> usize {
        self.st.journal.len()
    }

    fn snapshot_with_ids(&self, _addrs: &[Address], _asset_ids: &[u64], _app_ids: &[u64]) -> usize {
        self.st.journal.len()
    }

    fn restore_snapshot(&mut self, snapshot: usize) {
        self.st.unwind_to(snapshot);
    }

    // ---- Min balance ----

    fn min_balance_with_state(&self, _addr: &Address, account: &AccountData) -> u64 {
        crate::params::min_balance(account)
    }

    // ---- History reads fall through to the committed ledger ----

    fn get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.base.get_block_data(round)
    }

    fn get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.base.get_block_header_data(round)
    }

    fn get_block_header(&self, round: u64) -> Result<Option<BlockHeader>, AlgoError> {
        self.base.get_block_header(round)
    }

    fn get_block_proto(&self, round: u64) -> Result<Option<String>, AlgoError> {
        self.base.get_block_proto(round)
    }

    fn get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.base.get_txtail(round)
    }

    fn get_state_proof_verification_context(
        &self,
        last_attested_round: u64,
    ) -> Result<Option<Vec<u8>>, AlgoError> {
        self.base
            .get_state_proof_verification_context(last_attested_round)
    }

    fn get_voters_snapshot(&self, round: u64) -> Result<Option<(Vec<u8>, u64)>, AlgoError> {
        self.base.get_voters_snapshot(round)
    }

    fn online_accounts(&self) -> Vec<(Address, AccountData)> {
        self.base.online_accounts()
    }

    fn voter_agreement_data_at_round(
        &self,
        round: u64,
        addr: &Address,
    ) -> Result<VoterAgreementData, AlgoError> {
        self.base.voter_agreement_data_at_round(round, addr)
    }

    fn online_stake_at_round(&self, round: u64, vote_rnd: u64) -> Result<u64, AlgoError> {
        self.base.online_stake_at_round(round, vote_rnd)
    }

    fn balance_round_total_online_stake(
        &self,
        balance_round: u64,
        vote_rnd: u64,
    ) -> Result<u64, AlgoError> {
        self.base
            .balance_round_total_online_stake(balance_round, vote_rnd)
    }

    fn absence_history_uncertain(&self, balance_round: u64) -> Result<bool, AlgoError> {
        self.base.absence_history_uncertain(balance_round)
    }
}
