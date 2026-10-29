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

//! In-memory transaction-tail duplicate cache.
//!
//! Mirrors go-algorand's `txTail` tracker (`ledger/txtail.go` @
//! v4.6.0-stable): go loads the recent transaction tail from disk **once**
//! (`loadFromDisk`), keeps it entirely in memory (`t.lastValid`, a
//! per-round txid map), appends each newly committed block in memory
//! (`newBlock`), and answers duplicate checks (`checkDup`) without ever
//! touching SQLite.
//!
//! Before this cache existed, algod-rust's pool-side duplicate check
//! (`PoolLedger::contains_confirmed_txid`) re-read and msgpack-decoded the
//! serialized `TxTailRound` blob for **every round in the 1000-round
//! lookback window from SQLite on every single pool submission**, all
//! while holding the global ledger mutex. At 200 TPS on a chain ~100
//! rounds long that is ~20,000 blob decodes (each including a full
//! `BlockHeader`) per second — the dominant CPU sink and allocation-churn
//! source in the issue #100 stress benchmark, and it grows linearly with
//! chain length until the window saturates at 1000 rounds.
//!
//! [`TxTailDupCache`] replaces the per-call scan with:
//! - one incremental `get_txtail` read + decode per **newly committed
//!   round** (not per submission),
//! - an O(1) in-memory hash lookup per duplicate check,
//! - eviction of rounds that fall out of the lookback window.
//!
//! The answer is identical to the SQLite scan by construction: the cache
//! is populated from exactly the same serialized `TxTailRound` rows the
//! scan read, over exactly the same window
//! (`current_round - LOOKBACK_ROUNDS ..= current_round`, floored at round
//! 1), and rounds whose blob is absent or undecodable contribute no txids
//! (the scan's `continue` arms).

use std::collections::{HashMap, VecDeque};

use algo_types::Digest;

/// How many rounds back to remember confirmed txids.
///
/// Matches go-algorand's `MaxTxnLife` (1000 for all current consensus
/// versions, `config/consensus.go`): a transaction confirmed more than
/// `MaxTxnLife` rounds ago can never be a live duplicate, because its own
/// `last_valid` would already have expired.
pub const LOOKBACK_ROUNDS: u64 = 1000;

/// How many absent rows [`TxTailDupCache`] fetches again per new round, at
/// most (issue #2125): a row that never lands costs a bounded number of
/// reads per block, not one per round of the window.
pub const MAX_RETRIES_PER_ROUND: usize = 8;

/// In-memory mirror of the ledger's recent txtail, for duplicate checks.
///
/// Not internally synchronized — wrap in a mutex if shared. Callers must
/// invoke [`sync`](Self::sync) under the same lock that serializes ledger
/// commits (e.g. while holding the `SqliteLedger` mutex) so the cache
/// can never observe a round without its txtail row.
///
/// Callers may ask for different windows (the pool and simulate, a protocol
/// upgrade): the cache keeps the largest window it was asked for and
/// answers a smaller one by filtering on the round a txid was committed in,
/// so it only rebuilds when the window grows.
#[derive(Debug, Default)]
pub struct TxTailDupCache {
    /// Highest round whose txtail has been loaded (0 = nothing loaded).
    loaded_hi: u64,
    /// The largest window size the cache was asked for (0 = nothing loaded).
    lookback: u64,
    /// Per-round confirmed txids, ascending by round, covering the window
    /// `[lo, loaded_hi]`. A round whose row was absent is `missing` and is
    /// fetched again on a later sync (a row can land after its round, e.g.
    /// a catchpoint's lookback download), unless it lies below the
    /// ledger's earliest txtail row. An undecodable row is loaded as empty
    /// and not refetched.
    rounds: VecDeque<CachedRound>,
    /// The `current_round` of the last retry of `missing` rounds.
    retried_at: u64,
    /// Membership index over `rounds`: a reference count (txids cannot
    /// legitimately repeat across rounds, but counting keeps eviction
    /// correct even if a duplicate ever slipped in upstream) and the newest
    /// round holding the txid (for answering a smaller window).
    txids: HashMap<Digest, TxidEntry>,
}

#[derive(Debug)]
struct CachedRound {
    round: u64,
    ids: Vec<Digest>,
    missing: bool,
}

#[derive(Debug, Clone, Copy)]
struct TxidEntry {
    count: u32,
    newest: u64,
}

/// The txids of a decoded `TxTailRound`.
fn ids_of(tail: &algo_types::TxTailRound) -> Vec<Digest> {
    tail.txn_ids
        .iter()
        .filter_map(|id| <[u8; 32]>::try_from(id.as_ref()).ok().map(Digest))
        .collect()
}

/// Count `ids` (committed in `round`) into the membership index.
fn index_ids(index: &mut HashMap<Digest, TxidEntry>, ids: &[Digest], round: u64) {
    for id in ids {
        let entry = index.entry(*id).or_insert(TxidEntry {
            count: 0,
            newest: round,
        });
        entry.count += 1;
        entry.newest = entry.newest.max(round);
    }
}

impl TxTailDupCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// [`sync_window`](Self::sync_window) with the default
    /// [`LOOKBACK_ROUNDS`] window.
    pub fn sync<F>(&mut self, current_round: u64, fetch: F)
    where
        F: FnMut(u64) -> Option<Vec<u8>>,
    {
        self.sync_window(current_round, LOOKBACK_ROUNDS, fetch);
    }

    /// [`sync_window_with`](Self::sync_window_with) with no earliest-row
    /// bound and no row hook.
    pub fn sync_window<F>(&mut self, current_round: u64, lookback: u64, fetch: F)
    where
        F: FnMut(u64) -> Option<Vec<u8>>,
    {
        self.sync_window_with(current_round, lookback, || None, fetch, |_, _| {});
    }

    /// Bring the cache up to date with the committed ledger state, over
    /// the window `[current_round - lookback, current_round]` (floored at
    /// round 1). `lookback` is the active protocol's `MaxTxnLife`.
    ///
    /// `current_round` is the ledger's latest committed round;
    /// `fetch(round)` returns the serialized `TxTailRound` blob for a
    /// round (i.e. `LedgerStore::get_txtail`), or `None` when absent.
    /// `earliest_row()` (asked only when absent rows are due a retry)
    /// returns the ledger's earliest txtail round: absent rounds below it
    /// can never land and leave the retry set for good. `on_row` sees every
    /// row decoded, so a caller can derive more from the same pass (the
    /// lease table on open).
    ///
    /// Fetches only rounds not yet loaded, plus, once per new
    /// `current_round`, up to [`MAX_RETRIES_PER_ROUND`] rounds whose row
    /// was absent. Evicts rounds older than the window. If the ledger moved
    /// *backwards* (e.g. a catchup reset the database) or the window grew,
    /// the cache rebuilds from scratch.
    pub fn sync_window_with<E, F, R>(
        &mut self,
        current_round: u64,
        lookback: u64,
        earliest_row: E,
        mut fetch: F,
        mut on_row: R,
    ) where
        E: FnOnce() -> Option<u64>,
        F: FnMut(u64) -> Option<Vec<u8>>,
        R: FnMut(u64, &algo_types::TxTailRound),
    {
        if current_round < self.loaded_hi || lookback > self.lookback {
            // Ledger regressed (fresh/replaced database) or the window
            // grew — rebuild.
            *self = Self {
                lookback,
                ..Self::default()
            };
        }

        // Same window the SQLite scan used: lo..=current, inclusive,
        // floored at round 1 (round 0 is genesis, no transactions).
        let lo = current_round.saturating_sub(self.lookback).max(1);

        // Evict rounds that fell out of the window (oldest first, so an
        // entry's `newest` round stays valid while its count is > 0).
        while self.rounds.front().is_some_and(|r| r.round < lo) {
            let old = self.rounds.pop_front().expect("front checked above");
            for id in old.ids {
                match self.txids.get_mut(&id) {
                    Some(entry) if entry.count > 1 => entry.count -= 1,
                    _ => {
                        self.txids.remove(&id);
                    }
                }
            }
        }

        let mut decode = |round: u64, bytes: &[u8]| -> Vec<Digest> {
            // Undecodable blob: the scan skipped it — so do we.
            let Ok(tail) = rmp_serde::from_slice::<algo_types::TxTailRound>(bytes) else {
                return Vec::new();
            };
            on_row(round, &tail);
            ids_of(&tail)
        };

        // Retry rounds whose row was absent, once per new round, bounded.
        if current_round > self.retried_at {
            self.retried_at = current_round;
            if self.rounds.iter().any(|r| r.missing) {
                let earliest = earliest_row();
                let mut retries = 0;
                for cached in self.rounds.iter_mut().filter(|r| r.missing) {
                    if earliest.is_some_and(|e| cached.round < e) {
                        // Below the earliest row: it can never land.
                        cached.missing = false;
                        continue;
                    }
                    if retries == MAX_RETRIES_PER_ROUND {
                        break;
                    }
                    retries += 1;
                    if let Some(bytes) = fetch(cached.round) {
                        cached.ids = decode(cached.round, &bytes);
                        cached.missing = false;
                        index_ids(&mut self.txids, &cached.ids, cached.round);
                    }
                }
            }
        }

        // Load newly committed (or never-loaded) rounds.
        let start = (self.loaded_hi + 1).max(lo);
        for round in start..=current_round {
            let (ids, missing) = match fetch(round) {
                Some(bytes) => (decode(round, &bytes), false),
                None => (Vec::new(), true),
            };
            index_ids(&mut self.txids, &ids, round);
            self.rounds.push_back(CachedRound {
                round,
                ids,
                missing,
            });
        }
        self.loaded_hi = self.loaded_hi.max(current_round);
    }

    /// Whether `txid` was confirmed within the largest window synced.
    ///
    /// Call [`sync`](Self::sync) first; this is a pure in-memory lookup.
    #[must_use]
    pub fn contains(&self, txid: &Digest) -> bool {
        self.txids.contains_key(txid)
    }

    /// Whether `txid` was confirmed within the last `lookback` rounds of
    /// the synced round. Allocates nothing.
    #[must_use]
    pub fn contains_within(&self, txid: &Digest, lookback: u64) -> bool {
        let lo = self.loaded_hi.saturating_sub(lookback).max(1);
        self.txids.get(txid).is_some_and(|e| e.newest >= lo)
    }

    /// The members of `txids` confirmed within the last `lookback` rounds.
    #[must_use]
    pub fn confirmed(&self, txids: &[Digest], lookback: u64) -> std::collections::HashSet<Digest> {
        txids
            .iter()
            .filter(|t| self.contains_within(t, lookback))
            .copied()
            .collect()
    }

    /// Number of distinct txids currently tracked (for tests/diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.txids.len()
    }

    /// Whether the cache tracks no txids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_trait::LedgerStore;
    use serde_bytes::ByteBuf;

    fn digest(n: u8) -> Digest {
        Digest([n; 32])
    }

    /// Build a minimal BlockHeader for testing purposes.
    fn minimal_block_header(round: u64) -> algo_types::BlockHeader {
        algo_types::BlockHeader {
            round: algo_types::Round(round),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 0,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: algo_types::Address([0u8; 32]),
            fee_sink: algo_types::Address([0u8; 32]),
            rewards_pool: algo_types::Address([0u8; 32]),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: algo_types::Round(0),
            current_protocol: String::new(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: algo_types::Round(0),
            next_protocol_vote_before: algo_types::Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            load: 0,
            congestion_tax: 0,
        }
    }

    /// Build a serialized TxTailRound with the given txids.
    fn tail_bytes(round: u64, ids: &[Digest]) -> Vec<u8> {
        let tail = algo_types::TxTailRound {
            txn_ids: ids.iter().map(|d| ByteBuf::from(d.0.to_vec())).collect(),
            last_valid: ids.iter().map(|_| round + 1000).collect(),
            leases: Vec::new(),
            hdr: minimal_block_header(round),
        };
        algo_codec::canonical_encode_txtail_round(&tail)
    }

    /// The pre-cache implementation: scan the whole window from the
    /// store on every call. Used as the behavioral oracle.
    fn oracle_scan(ledger: &crate::sqlite::SqliteLedger, txid: Digest) -> bool {
        let current = ledger.current_round().0;
        let lo = current.saturating_sub(LOOKBACK_ROUNDS).max(1);
        for round in (lo..=current).rev() {
            let Ok(Some(bytes)) = ledger.get_txtail(round) else {
                continue;
            };
            let Ok(tail) = rmp_serde::from_slice::<algo_types::TxTailRound>(&bytes) else {
                continue;
            };
            if tail
                .txn_ids
                .iter()
                .any(|id| id.as_ref() == txid.0.as_slice())
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn finds_txid_in_recent_round() {
        let mut cache = TxTailDupCache::new();
        let tails: HashMap<u64, Vec<u8>> = [
            (1, tail_bytes(1, &[digest(1)])),
            (2, tail_bytes(2, &[digest(2), digest(3)])),
        ]
        .into_iter()
        .collect();
        cache.sync(2, |r| tails.get(&r).cloned());
        assert!(cache.contains(&digest(1)));
        assert!(cache.contains(&digest(2)));
        assert!(cache.contains(&digest(3)));
        assert!(!cache.contains(&digest(4)));
    }

    #[test]
    fn incremental_sync_fetches_only_new_rounds() {
        let mut cache = TxTailDupCache::new();
        let mut fetched: Vec<u64> = Vec::new();
        cache.sync(3, |r| {
            fetched.push(r);
            Some(tail_bytes(r, &[digest(r as u8)]))
        });
        assert_eq!(fetched, vec![1, 2, 3]);

        fetched.clear();
        cache.sync(5, |r| {
            fetched.push(r);
            Some(tail_bytes(r, &[digest(r as u8)]))
        });
        assert_eq!(fetched, vec![4, 5], "must not re-fetch rounds 1..=3");
        for n in 1..=5u8 {
            assert!(cache.contains(&digest(n)));
        }
    }

    #[test]
    fn same_round_resync_fetches_nothing() {
        let mut cache = TxTailDupCache::new();
        cache.sync(2, |r| Some(tail_bytes(r, &[digest(r as u8)])));
        cache.sync(2, |_| panic!("no fetch expected when already synced"));
        assert!(cache.contains(&digest(1)));
    }

    #[test]
    fn evicts_rounds_out_of_window() {
        let mut cache = TxTailDupCache::new();
        cache.sync(1, |r| Some(tail_bytes(r, &[digest(r as u8)])));
        assert!(cache.contains(&digest(1)));

        // Advance far enough that round 1 falls out of the window
        // (window = current - LOOKBACK ..= current, so round 1 is out
        // once current >= LOOKBACK_ROUNDS + 2).
        cache.sync(LOOKBACK_ROUNDS + 2, |r| {
            if r == 2 {
                Some(tail_bytes(r, &[digest(2)]))
            } else {
                None
            }
        });
        assert!(!cache.contains(&digest(1)), "round 1 must be evicted");
        assert!(cache.contains(&digest(2)), "round 2 is still in window");
    }

    #[test]
    fn window_boundary_matches_scan_semantics() {
        // At current = LOOKBACK + 1, lo = 1: round 1 still included.
        let mut cache = TxTailDupCache::new();
        cache.sync(LOOKBACK_ROUNDS + 1, |r| {
            (r == 1).then(|| tail_bytes(1, &[digest(1)]))
        });
        assert!(cache.contains(&digest(1)));
    }

    #[test]
    fn ledger_regression_rebuilds() {
        let mut cache = TxTailDupCache::new();
        cache.sync(3, |r| Some(tail_bytes(r, &[digest(r as u8)])));
        assert!(cache.contains(&digest(3)));

        // Ledger reset to round 1 with different contents.
        cache.sync(1, |r| Some(tail_bytes(r, &[digest(9)])));
        assert!(!cache.contains(&digest(3)), "stale txid must be gone");
        assert!(cache.contains(&digest(9)));
    }

    #[test]
    fn absent_and_undecodable_rounds_are_skipped() {
        let mut cache = TxTailDupCache::new();
        cache.sync(3, |r| match r {
            1 => None,                         // absent row
            2 => Some(vec![0xc1, 0xff, 0x00]), // undecodable garbage
            3 => Some(tail_bytes(3, &[digest(3)])),
            _ => unreachable!(),
        });
        assert!(cache.contains(&digest(3)));
        assert_eq!(cache.len(), 1);
    }

    /// Issue #2125: a round whose row was absent is fetched again once the
    /// ledger advances (a catchpoint's lookback rows land after their
    /// round), instead of being remembered as empty forever. An
    /// undecodable row is not refetched.
    #[test]
    fn absent_round_is_retried_once_per_new_round() {
        let mut cache = TxTailDupCache::new();
        cache.sync(2, |r| match r {
            1 => None,
            2 => Some(vec![0xc1, 0xff, 0x00]),
            _ => unreachable!(),
        });
        assert!(!cache.contains(&digest(1)));
        // Same round: no retry.
        cache.sync(2, |_| panic!("no fetch expected at the same round"));
        // The row for round 1 has landed; the next round retries it.
        let mut fetched = Vec::new();
        cache.sync(3, |r| {
            fetched.push(r);
            Some(tail_bytes(r, &[digest(r as u8)]))
        });
        assert_eq!(fetched, vec![1, 3], "round 1 retried, round 2 not");
        assert!(cache.contains(&digest(1)));
        assert!(cache.contains(&digest(3)));
        assert!(!cache.contains(&digest(2)));
    }

    /// The window follows the protocol's `MaxTxnLife`, not a fixed 1000
    /// (issue #2125).
    #[test]
    fn window_follows_max_txn_life_above_1000() {
        let rows = |r: u64| Some(tail_bytes(r, &[rd(r)]));
        let life = 1500;
        let mut cache = TxTailDupCache::new();
        cache.sync_window(1400, life, rows);
        // Round 100 is 1300 rounds back: outside the default 1000-round
        // window, inside a 1500-round one.
        assert!(cache.contains(&rd(100)));
        cache.sync_window(life + 101, life, rows);
        assert!(!cache.contains(&rd(100)), "round 100 left the window");
        assert!(cache.contains(&rd(101)));
        // A different window size rebuilds the cache.
        cache.sync_window(1400, 1000, rows);
        assert!(!cache.contains(&rd(399)));
        assert!(cache.contains(&rd(400)));
    }

    fn rd(r: u64) -> Digest {
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&r.to_be_bytes());
        Digest(d)
    }

    /// Issue #2125: the pool and simulate may ask for different windows.
    /// A smaller window is answered by filtering, without a rebuild; only
    /// a larger one rebuilds.
    #[test]
    fn smaller_window_filters_without_rebuilding() {
        let rows = |r: u64| Some(tail_bytes(r, &[rd(r)]));
        let mut cache = TxTailDupCache::new();
        cache.sync_window(1600, 1500, rows);
        assert!(cache.contains_within(&rd(200), 1500));
        assert!(
            !cache.contains_within(&rd(200), 1000),
            "outside 1000 rounds"
        );
        assert!(cache.contains_within(&rd(600), 1000));
        // A smaller window at the next round fetches only the new round.
        let mut fetched = Vec::new();
        cache.sync_window(1601, 1000, |r| {
            fetched.push(r);
            Some(tail_bytes(r, &[rd(r)]))
        });
        assert_eq!(fetched, vec![1601], "no rebuild for a smaller window");
        assert!(
            cache.contains_within(&rd(200), 1500),
            "the larger window is kept"
        );
        assert_eq!(
            cache.confirmed(&[rd(200), rd(601), rd(7_000)], 1000),
            [rd(601)].into_iter().collect()
        );
        // A larger window rebuilds.
        let mut fetched = 0;
        cache.sync_window(1601, 1600, |r| {
            fetched += 1;
            Some(tail_bytes(r, &[rd(r)]))
        });
        assert_eq!(fetched, 1601, "a larger window rebuilds: rounds 1..=1601");
        assert!(cache.contains_within(&rd(1), 1600));
    }

    /// Issue #2125: retries of absent rows are bounded per round, and rows
    /// below the ledger's earliest txtail round (e.g. before a catchpoint)
    /// are never fetched again.
    #[test]
    fn absent_row_retries_are_bounded_and_skip_rows_below_the_earliest() {
        let mut cache = TxTailDupCache::new();
        // Rounds 1..=100 have no row; 101..=110 do.
        let present = |r: u64| (r > 100).then(|| tail_bytes(r, &[rd(r)]));
        cache.sync_window(110, 1000, present);
        // Next round: the ledger's earliest row is 41, so 1..=40 leave the
        // retry set for good, and at most MAX_RETRIES_PER_ROUND are tried.
        let mut fetched = Vec::new();
        cache.sync_window_with(
            111,
            1000,
            || Some(41),
            |r| {
                fetched.push(r);
                (r > 100).then(|| tail_bytes(r, &[rd(r)]))
            },
            |_, _| {},
        );
        let retried: Vec<u64> = fetched.iter().copied().filter(|&r| r <= 100).collect();
        assert_eq!(
            retried,
            (41..41 + MAX_RETRIES_PER_ROUND as u64).collect::<Vec<_>>()
        );
        // Later rounds never ask for rounds below 41 again.
        for round in 112..130 {
            cache.sync_window_with(
                round,
                1000,
                || Some(41),
                |r| {
                    assert!(r >= 41, "round {r} is below the earliest row");
                    (r > 100).then(|| tail_bytes(r, &[rd(r)]))
                },
                |_, _| {},
            );
        }
    }

    #[test]
    #[ignore = "timing evidence for issue #100; run manually with --ignored --nocapture"]
    fn timing_scan_vs_cache() {
        // Realistic stress-bench shape: 100 committed rounds, ~420 txns
        // per round (200 TPS at ~2.1s rounds).
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        let rounds = 100u64;
        let per_round = 420usize;
        for round in 1..=rounds {
            let ids: Vec<Digest> = (0..per_round)
                .map(|i| {
                    let mut d = [0u8; 32];
                    d[..8].copy_from_slice(&round.to_be_bytes());
                    d[8..16].copy_from_slice(&(i as u64).to_be_bytes());
                    Digest(d)
                })
                .collect();
            ledger.put_txtail(round, &tail_bytes(round, &ids)).unwrap();
        }
        ledger.set_current_round(algo_types::Round(rounds));

        let probe = digest(0xEE); // miss — worst case for the scan
        let iters = 200; // one second's worth of submissions at 200 TPS

        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            assert!(!oracle_scan(&ledger, probe));
        }
        let scan = t0.elapsed();

        let mut cache = TxTailDupCache::new();
        let t1 = std::time::Instant::now();
        for _ in 0..iters {
            cache.sync(rounds, |r| ledger.get_txtail(r).ok().flatten());
            assert!(!cache.contains(&probe));
        }
        let cached = t1.elapsed();

        println!(
            "old full-window scan: {:?} total, {:?}/call; cache: {:?} total (incl. one-time load), {:?}/call",
            scan,
            scan / iters,
            cached,
            cached / iters,
        );
    }

    #[test]
    fn matches_sqlite_scan_oracle() {
        // Populate a real SqliteLedger with txtail rows and verify the
        // cache answers exactly like the old full-window SQLite scan.
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        for round in 1..=20u64 {
            let ids = [digest(round as u8), digest(100 + round as u8)];
            ledger.put_txtail(round, &tail_bytes(round, &ids)).unwrap();
        }
        ledger.set_current_round(algo_types::Round(20));

        let mut cache = TxTailDupCache::new();
        cache.sync(ledger.current_round().0, |r| {
            ledger.get_txtail(r).ok().flatten()
        });

        for n in 0..=255u8 {
            let txid = digest(n);
            assert_eq!(
                cache.contains(&txid),
                oracle_scan(&ledger, txid),
                "cache and scan disagree on txid {n}"
            );
        }
    }
}
