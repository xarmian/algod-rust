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

//! Block-scoped read-through memo of the `SqliteLedger` state reads
//! (issue #1757).
//!
//! Profiling the heavy mainnet app-call block 65743637 (issue #1765) showed
//! 27k store reads for ~1.2k distinct keys (`get_account` 54x, `get_box`
//! 126x, `get_app_params` 44x): ~80% of the apply was repeated SQLite
//! round-trips and blob decoding. This memo removes the repeats.
//!
//! The SQLite tables stay authoritative: every write still goes to SQL
//! immediately, the memo only remembers what a read returned. Invariants that
//! keep it exact:
//!
//! - It is consulted and filled only while the ledger is inside a block
//!   (`begin_block` .. `commit_block` / `rollback_block`) and no aborted block
//!   is pending, so writers outside a block (genesis, catchpoint import,
//!   tests, simulate) never see a stale entry.
//! - It is dropped whenever the block boundary or the SQL state changes
//!   underneath it: `begin_block`, `commit_block`, every rollback path,
//!   `restore_snapshot` (`ROLLBACK TO SAVEPOINT`), `restore_scratch_state`,
//!   and any bulk removal (`remove_account`, `remove_all_*`, `remove_*_params`).
//! - Every keyed write invalidates the entries it can change. A resource
//!   write (`(addr, id)`) shares one `resources` row between the holding /
//!   local-state view and the params view, and may create the owner's
//!   `accountbase` row, so it invalidates the account, the holding, the local
//!   state and both params entries of that id.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use algo_types::{AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord};

/// The memoised values; `None` is a memoised absence.
#[derive(Default)]
pub(crate) struct Maps {
    pub accounts: HashMap<Address, Option<AccountData>>,
    pub holdings: HashMap<(Address, u64), Option<AssetHolding>>,
    pub asset_params: HashMap<u64, Option<AssetParamsRecord>>,
    pub app_params: HashMap<u64, Option<AppParams>>,
    pub local_states: HashMap<(Address, u64), Option<AppLocalState>>,
    pub boxes: HashMap<(u64, Vec<u8>), Option<Vec<u8>>>,
}

/// See the module docs.
pub(crate) struct BlockReadCache {
    maps: Mutex<Maps>,
    enabled: bool,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Default for BlockReadCache {
    fn default() -> Self {
        Self {
            maps: Mutex::new(Maps::default()),
            enabled: true,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
}

impl BlockReadCache {
    fn lock(&self) -> MutexGuard<'_, Maps> {
        self.maps.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.clear();
    }

    /// `(hits, misses)` of the memoised reads; a miss is a read that went to
    /// SQL (all of them when the memo is disabled or the ledger is not in a
    /// block).
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Returns the memoised value for `key`, else `load()`s and memoises it.
    /// `active` is false outside a block: then nothing is read or stored.
    pub fn get_or_load<K: Hash + Eq, V: Clone>(
        &self,
        active: bool,
        pick: fn(&mut Maps) -> &mut HashMap<K, Option<V>>,
        key: K,
        load: impl FnOnce() -> Option<V>,
    ) -> Option<V> {
        if !(active && self.enabled) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return load();
        }
        if let Some(v) = pick(&mut self.lock()).get(&key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return v.clone();
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let v = load();
        pick(&mut self.lock()).insert(key, v.clone());
        v
    }

    /// [`Self::get_or_load`] for a fallible load: a successful read (including
    /// an absent row) is memoised, an `Err` is returned and NOT memoised, so a
    /// transient or corrupt-row failure is never remembered as "absent".
    pub fn get_or_try_load<K: Hash + Eq, V: Clone, E>(
        &self,
        active: bool,
        pick: fn(&mut Maps) -> &mut HashMap<K, Option<V>>,
        key: K,
        load: impl FnOnce() -> Result<Option<V>, E>,
    ) -> Result<Option<V>, E> {
        if !(active && self.enabled) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return load();
        }
        if let Some(v) = pick(&mut self.lock()).get(&key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(v.clone());
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let v = load()?;
        pick(&mut self.lock()).insert(key, v.clone());
        Ok(v)
    }

    /// Drops everything.
    pub fn clear(&self) {
        *self.lock() = Maps::default();
    }

    /// `addr`'s account record was just written; `stored` is what a read of
    /// it now returns (write-through).
    pub fn put_account(&self, addr: &Address, stored: Option<AccountData>) {
        if self.enabled {
            self.lock().accounts.insert(*addr, stored);
        }
    }

    /// The box `(app_id, key)` was just written (`Some`) or deleted (`None`).
    pub fn put_box(&self, app_id: u64, key: &[u8], stored: Option<Vec<u8>>) {
        if self.enabled {
            self.lock().boxes.insert((app_id, key.to_vec()), stored);
        }
    }

    /// `addr`'s `accountbase` row was written.
    pub fn inv_account(&self, addr: &Address) {
        self.lock().accounts.remove(addr);
    }

    /// The `resources` row `(addr, id)` was written (any resource kind). This
    /// can also create `addr`'s account row, and the row is shared by the
    /// holding / local-state and the params views of `id`.
    pub fn inv_resource(&self, addr: &Address, id: u64) {
        let mut m = self.lock();
        m.accounts.remove(addr);
        m.holdings.remove(&(*addr, id));
        m.local_states.remove(&(*addr, id));
        m.asset_params.remove(&id);
        m.app_params.remove(&id);
    }

    /// The box `(app_id, key)` was written or deleted.
    pub fn inv_box(&self, app_id: u64, key: &[u8]) {
        self.lock().boxes.remove(&(app_id, key.to_vec()));
    }
}
