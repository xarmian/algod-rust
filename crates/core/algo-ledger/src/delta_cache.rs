//! In-memory rolling window cache for recent round state deltas.
//!
//! Keeps the most recent `window_size` rounds' `StateDelta` values in memory
//! for fast lookups. Falls back to SQLite for older rounds.

use std::collections::HashMap;

use crate::state_delta::StateDelta;

/// Default number of rounds to keep in the in-memory cache.
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

        // Evict entries outside the window.
        if round >= self.window_size as u64 {
            let new_min = round - self.window_size as u64 + 1;
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

    #[test]
    fn default_window_size() {
        let cache = DeltaCache::with_default_window();
        assert_eq!(cache.window_size, DEFAULT_WINDOW_SIZE);
        assert!(cache.is_empty());
    }
}
