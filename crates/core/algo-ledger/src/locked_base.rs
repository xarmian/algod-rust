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

//! A committed-ledger base for [`crate::pending_overlay::OverlayStore`] that
//! takes the ledger mutex **per read** instead of for a whole evaluation
//! (issue #1781).
//!
//! Pool admission and block assembly used to hold the
//! `Arc<Mutex<SqliteLedger>>` across the AVM evaluation of a group (or of the
//! whole candidate payset), so agreement commits and REST reads queued behind
//! them. The overlay evaluation only ever *reads* the committed ledger (every
//! write lands in the [`crate::pending_overlay::PendingOverlay`]), so each read
//! can take the mutex for just that read.
//!
//! # Consistency
//!
//! The committed state only changes when a block is committed, and a block
//! commit advances `current_round` while holding the mutex for the whole
//! apply. Every read here checks, under the same lock acquisition, that the
//! ledger is still at the round the evaluation started from. As soon as one
//! read sees another round the base is marked **stale**: the evaluation's
//! result is meaningless and the caller must discard it (the group is not
//! evaluated, the proposal is not built). A result is therefore only ever
//! produced from reads that all saw the same committed state.

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use algo_error::AlgoError;
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, BlockHeader,
    Round,
};

use crate::pending_overlay::OverlayBase;
use crate::sqlite::SqliteLedger;
use crate::store_trait::VoterAgreementData;

/// What an evaluation cost the ledger mutex.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LockStats {
    /// Number of times the mutex was taken.
    pub acquisitions: u64,
    /// Total time spent waiting to acquire it.
    pub wait: Duration,
    /// Total time it was held.
    pub hold: Duration,
    /// Longest single hold.
    pub hold_max: Duration,
}

#[cfg(any(test, feature = "test-hooks"))]
type AcquisitionHook = (u64, Box<dyn FnOnce()>);

/// See the module docs.
pub struct LockedBase<'a> {
    ledger: &'a Mutex<SqliteLedger>,
    base_round: Round,
    stale: Cell<bool>,
    poisoned: Cell<bool>,
    stats: Cell<LockStats>,
    /// Test hook: run once, just before the `n`-th mutex acquisition.
    #[cfg(any(test, feature = "test-hooks"))]
    hook: std::cell::RefCell<Option<AcquisitionHook>>,
}

impl<'a> LockedBase<'a> {
    /// A base expected to stay at committed round `base_round`.
    pub fn new(ledger: &'a Mutex<SqliteLedger>, base_round: Round) -> Self {
        Self {
            ledger,
            base_round,
            stale: Cell::new(false),
            poisoned: Cell::new(false),
            stats: Cell::new(LockStats::default()),
            #[cfg(any(test, feature = "test-hooks"))]
            hook: std::cell::RefCell::new(None),
        }
    }

    /// Run `f` right before the `n`-th (0-based) acquisition of the mutex: a
    /// deterministic stand-in for "a block commit lands in the middle of the
    /// evaluation".
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn before_acquisition(&self, n: u64, f: impl FnOnce() + 'static) {
        *self.hook.borrow_mut() = Some((n, Box::new(f)));
    }

    /// Whether any read saw a ledger that is not at the expected round.
    pub fn is_stale(&self) -> bool {
        self.stale.get()
    }

    /// Whether the ledger mutex was poisoned (treated like a stale base).
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.get()
    }

    /// Mutex usage so far.
    pub fn stats(&self) -> LockStats {
        self.stats.get()
    }

    /// The error to report for a poisoned mutex.
    pub fn poison_error() -> AlgoError {
        AlgoError::Ledger {
            message: "ledger lock poisoned".into(),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&SqliteLedger) -> R) -> R {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let due =
                matches!(&*self.hook.borrow(), Some((n, _)) if *n == self.stats.get().acquisitions);
            if due {
                if let Some((_, hook)) = self.hook.borrow_mut().take() {
                    hook();
                }
            }
        }
        let waited = Instant::now();
        let guard: MutexGuard<'_, SqliteLedger> = match self.ledger.lock() {
            Ok(g) => g,
            Err(p) => {
                self.poisoned.set(true);
                self.stale.set(true);
                p.into_inner()
            }
        };
        let held = Instant::now();
        if crate::store_trait::LedgerStore::current_round(&*guard) != self.base_round {
            self.stale.set(true);
        }
        let r = f(&guard);
        drop(guard);
        let hold = held.elapsed();
        let mut s = self.stats.get();
        s.acquisitions += 1;
        s.wait += held.saturating_duration_since(waited);
        s.hold += hold;
        s.hold_max = s.hold_max.max(hold);
        self.stats.set(s);
        r
    }
}

macro_rules! via_ledger_store {
    ($self:ident, $m:ident ( $($a:expr),* )) => {
        $self.with(|l| crate::store_trait::LedgerStore::$m(l $(, $a)*))
    };
}

impl OverlayBase for LockedBase<'_> {
    fn base_is_stale(&self) -> bool {
        self.stale.get()
    }
    fn base_current_round(&self) -> Round {
        via_ledger_store!(self, current_round())
    }
    fn base_rewards_level(&self) -> u64 {
        via_ledger_store!(self, rewards_level())
    }
    fn base_rewards_rate(&self) -> u64 {
        via_ledger_store!(self, rewards_rate())
    }
    fn base_rewards_residue(&self) -> u64 {
        via_ledger_store!(self, rewards_residue())
    }
    fn base_rewards_recalculation_round(&self) -> u64 {
        via_ledger_store!(self, rewards_recalculation_round())
    }
    fn base_fee_sink(&self) -> Address {
        via_ledger_store!(self, fee_sink())
    }
    fn base_rewards_pool(&self) -> Address {
        via_ledger_store!(self, rewards_pool())
    }
    fn base_genesis_id(&self) -> String {
        self.with(|l| crate::store_trait::LedgerStore::genesis_id(l).to_string())
    }
    fn base_genesis_hash(&self) -> [u8; 32] {
        self.with(|l| *crate::store_trait::LedgerStore::genesis_hash(l))
    }
    fn base_protocol(&self) -> String {
        self.with(|l| crate::store_trait::LedgerStore::protocol(l).to_string())
    }
    fn base_txn_counter(&self) -> u64 {
        via_ledger_store!(self, txn_counter())
    }
    fn base_get_account(&self, addr: &Address) -> Option<AccountData> {
        via_ledger_store!(self, get_account(addr))
    }
    fn base_get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        via_ledger_store!(self, get_asset_holding(addr, asset_id))
    }
    fn base_get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        via_ledger_store!(self, get_asset_params(asset_id))
    }
    fn base_get_app_params(&self, app_id: u64) -> Option<AppParams> {
        via_ledger_store!(self, get_app_params(app_id))
    }
    fn base_get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        via_ledger_store!(self, get_app_local_state(addr, app_id))
    }
    fn base_get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        via_ledger_store!(self, get_box(app_id, key))
    }
    fn base_created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        via_ledger_store!(self, created_apps_for_addr(addr))
    }
    fn base_created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        via_ledger_store!(self, created_assets_for_addr(addr))
    }
    fn base_app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        via_ledger_store!(self, app_local_states_for_addr(addr))
    }
    fn base_asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        via_ledger_store!(self, asset_holdings_for_addr(addr))
    }
    fn base_box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        via_ledger_store!(self, box_keys_for_app(app_id))
    }
    fn base_check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError> {
        via_ledger_store!(self, check_lease(sender, lease, current_round))
    }
    fn base_account_totals(&self) -> crate::state_delta::AccountTotals {
        via_ledger_store!(self, account_totals())
    }
    fn base_get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        via_ledger_store!(self, get_block_data(round))
    }
    fn base_get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        via_ledger_store!(self, get_block_header_data(round))
    }
    fn base_get_block_header(&self, round: u64) -> Result<Option<BlockHeader>, AlgoError> {
        via_ledger_store!(self, get_block_header(round))
    }
    fn base_get_block_proto(&self, round: u64) -> Result<Option<String>, AlgoError> {
        via_ledger_store!(self, get_block_proto(round))
    }
    fn base_get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        via_ledger_store!(self, get_txtail(round))
    }
    fn base_get_state_proof_verification_context(
        &self,
        last_attested_round: u64,
    ) -> Result<Option<Vec<u8>>, AlgoError> {
        via_ledger_store!(
            self,
            get_state_proof_verification_context(last_attested_round)
        )
    }
    fn base_get_voters_snapshot(&self, round: u64) -> Result<Option<(Vec<u8>, u64)>, AlgoError> {
        via_ledger_store!(self, get_voters_snapshot(round))
    }
    fn base_online_accounts(&self) -> Vec<(Address, AccountData)> {
        via_ledger_store!(self, online_accounts())
    }
    fn base_for_each_online_account_ordered(
        &self,
        visit: &mut dyn FnMut(Address, AccountData) -> bool,
    ) {
        self.with(|l| crate::store_trait::LedgerStore::for_each_online_account_ordered(l, visit))
    }
    fn base_for_each_knock_offline_candidate_ordered(
        &self,
        round: u64,
        challenge_round: u64,
        visit: &mut dyn FnMut(Address, AccountData) -> bool,
    ) {
        self.with(|l| {
            crate::store_trait::LedgerStore::for_each_knock_offline_candidate_ordered(
                l,
                round,
                challenge_round,
                visit,
            )
        })
    }
    fn base_voter_agreement_data_at_round(
        &self,
        round: u64,
        addr: &Address,
    ) -> Result<VoterAgreementData, AlgoError> {
        via_ledger_store!(self, voter_agreement_data_at_round(round, addr))
    }
    fn base_online_stake_at_round(&self, round: u64, vote_rnd: u64) -> Result<u64, AlgoError> {
        via_ledger_store!(self, online_stake_at_round(round, vote_rnd))
    }
    fn base_balance_round_total_online_stake(
        &self,
        balance_round: u64,
        vote_rnd: u64,
    ) -> Result<u64, AlgoError> {
        via_ledger_store!(
            self,
            balance_round_total_online_stake(balance_round, vote_rnd)
        )
    }
    fn base_absence_history_uncertain(&self, balance_round: u64) -> Result<bool, AlgoError> {
        via_ledger_store!(self, absence_history_uncertain(balance_round))
    }
}
