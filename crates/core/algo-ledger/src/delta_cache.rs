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

//! In-memory rolling window cache for recent round state deltas.
//!
//! Keeps the most recent `window_size` rounds' `StateDelta` values in memory
//! for fast lookups. Falls back to SQLite for older rounds.

use std::collections::HashMap;

use crate::state_delta::StateDelta;

/// Default number of rounds to keep in the in-memory cache.
///
/// Issue #755 investigated go-algorand's `config.Local.MaxAcctLookback`
/// (default 4 rounds, `config/localTemplate.go:563-565`) as a candidate
/// replacement for this constant, and initially shrank it to 4 to match.
/// **CI's live dual-node parity suite caught a real regression from that
/// change and it was reverted** -- go's `MaxAcctLookback` is documented as
/// "the *minimum* deltas size to keep in memory"
/// (`ledger/acctupdates.go:224`), not a hard ceiling: go's tracker commits
/// balances lazily/in batches (`accountUpdates.produceCommittingTask`,
/// `committedUpTo`), so in practice go retains many more than 4 rounds of
/// in-memory deltas between flushes -- confirmed empirically by this
/// project's own `live_state_delta_parity` test, which queries
/// `/v2/deltas/{round}` several rounds behind the tip against a real
/// go-algorand node with zero special configuration and gets a 200.
/// algod-rust's `DeltaCache` has no equivalent lazy-commit-lag mechanism:
/// it is a hard, fixed-size ceiling. Setting it to go's literal minimum
/// (4) therefore evicts recent, still-relevant deltas that go's own
/// reference behavior keeps -- a real functional regression on
/// `/v2/deltas` and the historical-round box/kv lookup path, not a
/// parity improvement. Kept at 320 (algod-rust's original, live-tested
/// value) for this reason; `MaxAcctLookback`/`SqliteLedger::
/// set_delta_cache_window` is wired as a *floor* on top of this default
/// (matching go's own "minimum" framing), never below it -- see
/// `set_delta_cache_window`'s doc comment.
pub const DEFAULT_WINDOW_SIZE: usize = 320;

/// In-memory rolling window cache for recent round deltas.
pub struct DeltaCache {
    cache: HashMap<u64, StateDelta>,
    window_size: usize,
    min_round: u64,
}

impl DeltaCache {
    /// Create a new cache with the given window size.
    pub fn new(window_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            window_size,
            min_round: 0,
        }
    }

    /// Create a new cache with the default window size (320 rounds).
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }

    /// Insert a delta for the given round and evict old entries.
    pub fn insert(&mut self, round: u64, delta: StateDelta) {
        self.cache.insert(round, delta);
        self.advance_window(round);
    }

    /// Advance the rolling-window cursor to `round` without inserting a
    /// delta, evicting any entries that fall outside the window.
    ///
    /// Used by callers that successfully applied a block but intentionally
    /// did not cache its delta (e.g. blocks whose payset contains
    /// transaction types the current `StateDelta` builder doesn't fully
    /// cover — see `SqliteLedger::apply_block_caching_delta`). Without this,
    /// the only eviction path is [`Self::insert`], so a single cached delta
    /// can remain served indefinitely while the chain advances past it.
    /// PLAN-36 TASK-128.
    pub fn advance(&mut self, round: u64) {
        self.advance_window(round);
    }

    /// Compute the new minimum-retained round given `latest` and evict
    /// anything older. Centralized so `insert` and `advance` cannot drift.
    fn advance_window(&mut self, latest: u64) {
        if latest >= self.window_size as u64 {
            let new_min = latest - self.window_size as u64 + 1;
            if new_min > self.min_round {
                self.evict_before(new_min);
            }
        }
    }

    /// Look up a delta by round.
    pub fn get(&self, round: u64) -> Option<&StateDelta> {
        self.cache.get(&round)
    }

    /// Remove all entries for rounds before `min_round`.
    pub fn evict_before(&mut self, min_round: u64) {
        self.cache.retain(|&r, _| r >= min_round);
        self.min_round = min_round;
    }

    /// The current minimum round kept in the cache.
    pub fn min_round(&self) -> u64 {
        self.min_round
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Change the retained window size (`config.Local.MaxAcctLookback`,
    /// issue #755). Takes effect on the next [`insert`](Self::insert) /
    /// [`advance`](Self::advance) call -- existing cached entries older
    /// than the new, possibly smaller window are evicted then, not
    /// immediately, matching how `set_lru_cache_disabled` /
    /// `set_trie_cache_target` apply lazily elsewhere in `SqliteLedger`.
    pub fn set_window_size(&mut self, window_size: usize) {
        self.window_size = window_size;
    }

    /// The currently configured window size.
    pub fn window_size(&self) -> usize {
        self.window_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = DeltaCache::new(10);
        let delta = StateDelta::default();
        cache.insert(5, delta.clone());
        assert!(cache.get(5).is_some());
        assert!(cache.get(6).is_none());
    }

    #[test]
    fn eviction_within_window() {
        let mut cache = DeltaCache::new(3);
        for r in 0..5 {
            cache.insert(r, StateDelta::default());
        }
        // Window of 3 with latest round 4 => keep rounds 2,3,4
        assert!(cache.get(0).is_none());
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
        assert!(cache.get(4).is_some());
        assert_eq!(cache.len(), 3);
    }

    /// PLAN-36 TASK-128: `advance` must evict stale entries even when no
    /// new delta is inserted, so callers that skip caching for unsupported
    /// blocks still bound the cache by the rolling window.
    #[test]
    fn advance_without_insert_evicts() {
        let mut cache = DeltaCache::new(3);
        cache.insert(0, StateDelta::default());
        cache.insert(1, StateDelta::default());
        cache.insert(2, StateDelta::default());
        assert_eq!(cache.len(), 3);

        // Advance past the window without inserting anything new.
        cache.advance(10);

        assert!(cache.is_empty(), "advance should evict all stale entries");
        assert_eq!(cache.min_round(), 10 - 3 + 1);
    }

    #[test]
    fn default_window_size() {
        let cache = DeltaCache::with_default_window();
        assert_eq!(cache.window_size, DEFAULT_WINDOW_SIZE);
        assert!(cache.is_empty());
    }

    /// Issue #755: `DEFAULT_WINDOW_SIZE` was investigated against
    /// go-algorand's `MaxAcctLookback` default (4 rounds) and deliberately
    /// kept at algod-rust's original 320 -- go's field is a *minimum*
    /// beneath a lazily-batched commit process algod-rust's `DeltaCache`
    /// has no equivalent of (see this constant's doc comment; CI's live
    /// dual-node parity suite caught the regression from an earlier
    /// attempt to shrink this to 4).
    #[test]
    fn default_window_size_kept_at_algod_rust_safe_value() {
        assert_eq!(DEFAULT_WINDOW_SIZE, 320);
    }

    #[test]
    fn set_window_size_changes_future_eviction_but_not_existing_entries() {
        let mut cache = DeltaCache::with_default_window();
        cache.insert(0, StateDelta::default());
        assert_eq!(cache.window_size(), DEFAULT_WINDOW_SIZE);

        // Shrinking the window doesn't retroactively evict until the next
        // insert/advance.
        cache.set_window_size(1);
        assert!(cache.get(0).is_some());

        // The next advance applies the new, smaller window.
        cache.advance(1);
        assert!(cache.get(0).is_none());
    }
}
