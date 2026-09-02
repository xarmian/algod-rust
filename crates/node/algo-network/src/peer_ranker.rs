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

//! Catchup peer-selection/ranking layer (issue #819, Phase 17 gap #8).
//!
//! Ports go-algorand's `catchup/peerSelector.go` (`rankPooledPeerSelector`)
//! and `catchup/classBasedPeerSelector.go` (`classBasedPeerSelector`) at
//! `v5.0.0-stable`. Both peer classes/pools are re-derived here from the Go
//! source's constants and algorithms so that scoring is bit-for-bit
//! equivalent for the same inputs.
//!
//! # Scope (deliberately standalone)
//!
//! This module implements only the *algorithm*: given a peer's identity,
//! class, and a stream of past download outcomes (durations or failure
//! codes), produce a ranked ordering of peers to try next. It is a pure,
//! self-contained module with no dependency on algod-rust's actual network
//! stack, and it is **not wired into** any live catchup/sync/fetch code
//! path (`block_fetcher.rs`, `block_service.rs`, or algo-ledger's
//! catchpoint sync). Wiring this into the real peer-fetch loop needs live
//! multi-node testing and is left as documented follow-up on issue #819.
//!
//! # go-algorand correspondence
//!
//! | Go (`catchup/peerSelector.go`)          | Rust (this module)                |
//! |------------------------------------------|------------------------------------|
//! | `rankPooledPeerSelector`                  | [`PeerRanker`]                     |
//! | `historicStats`                           | [`HistoricStats`] (private)         |
//! | `peerPool` / `peerPoolEntry`              | [`PeerPool`] / [`PeerPoolEntry`] (private) |
//! | `peerClass`                               | [`PeerClass`]                      |
//! | `peerSelectorPeer`                        | [`PeerSelectorPeer`]               |
//! | `peersRetriever`                          | [`PeersRetriever`]                 |
//! | `downloadDurationToRank`                  | [`download_duration_to_rank`]      |
//! | `classBasedPeerSelector` (`catchup/classBasedPeerSelector.go`) | [`ClassBasedPeerSelector`] |
//! | `wrappedPeerSelector`                     | [`WrappedPeerSelector`]            |
//! | `makeCatchpointPeerSelector`               | [`make_catchpoint_peer_selector`]  |

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;

// ---------------------------------------------------------------------------
// Rank constants (catchup/peerSelector.go lines 32-77)
// ---------------------------------------------------------------------------

/// The high-priority peers group's initial rank.
pub const PEER_RANK_INITIAL_FIRST_PRIORITY: i32 = 0;
pub const PEER_RANK_0_LOW_BLOCK_TIME: i32 = 1;
pub const PEER_RANK_0_HIGH_BLOCK_TIME: i32 = 199;

/// The second priority peers group's initial rank.
pub const PEER_RANK_INITIAL_SECOND_PRIORITY: i32 = 200;
pub const PEER_RANK_1_LOW_BLOCK_TIME: i32 = 201;
pub const PEER_RANK_1_HIGH_BLOCK_TIME: i32 = 399;

pub const PEER_RANK_INITIAL_THIRD_PRIORITY: i32 = 400;
pub const PEER_RANK_2_LOW_BLOCK_TIME: i32 = 401;
pub const PEER_RANK_2_HIGH_BLOCK_TIME: i32 = 599;

pub const PEER_RANK_INITIAL_FOURTH_PRIORITY: i32 = 600;
pub const PEER_RANK_3_LOW_BLOCK_TIME: i32 = 601;
pub const PEER_RANK_3_HIGH_BLOCK_TIME: i32 = 799;

pub const PEER_RANK_INITIAL_FIFTH_PRIORITY: i32 = 800;
pub const PEER_RANK_4_LOW_BLOCK_TIME: i32 = 801;
pub const PEER_RANK_4_HIGH_BLOCK_TIME: i32 = 999;

/// Response failed because of no block for round: the peer is either behind,
/// a block has not happened yet, or it does not have a block old enough.
pub const PEER_RANK_NO_BLOCK_FOR_ROUND: i32 = 2000;

/// Response failed because of no catchpoint for round: the peer is either
/// behind, a catchpoint has not been produced, or this node did not retain
/// this catchpoint (aged out). Numerically identical to
/// [`PEER_RANK_NO_BLOCK_FOR_ROUND`], mirroring Go's two same-valued consts.
pub const PEER_RANK_NO_CATCHPOINT_FOR_ROUND: i32 = 2000;

/// Response could be temporary (missing files, unclear resolution).
pub const PEER_RANK_DOWNLOAD_FAILED: i32 = 10000;

/// Response is likely invalid (wrong content or malicious content).
pub const PEER_RANK_INVALID_DOWNLOAD: i32 = 12000;

/// Once a block is downloaded, the download duration is clamped into this
/// range and then mapped into the ranking range.
pub const LOW_BLOCK_DOWNLOAD_THRESHOLD: Duration = Duration::from_millis(50);
pub const HIGH_BLOCK_DOWNLOAD_THRESHOLD: Duration = Duration::from_secs(8);

/// The lookback window size of peer usage statistics.
pub const PEER_HISTORY_WINDOW_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// Peer classes
// ---------------------------------------------------------------------------

/// The category of peer, mirroring the subset of go-algorand's
/// `network.PeerOption` values actually used by the peer selectors
/// (`PeersPhonebookRelays`, `PeersPhonebookArchivalNodes`,
/// `PeersConnectedOut`, `PeersConnectedIn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerClassKind {
    PhonebookRelays,
    PhonebookArchivalNodes,
    ConnectedOut,
    ConnectedIn,
}

/// Defines the type of peer in a particular "class": its initial rank and
/// the [`PeerClassKind`] used to retrieve that type of peer.
///
/// Mirrors Go's `peerClass` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerClass {
    pub initial_rank: i32,
    pub class: PeerClassKind,
}

fn lower_bound(class: PeerClass) -> i32 {
    match class.initial_rank {
        PEER_RANK_INITIAL_FIRST_PRIORITY => PEER_RANK_0_LOW_BLOCK_TIME,
        PEER_RANK_INITIAL_SECOND_PRIORITY => PEER_RANK_1_LOW_BLOCK_TIME,
        PEER_RANK_INITIAL_THIRD_PRIORITY => PEER_RANK_2_LOW_BLOCK_TIME,
        PEER_RANK_INITIAL_FOURTH_PRIORITY => PEER_RANK_3_LOW_BLOCK_TIME,
        _ => PEER_RANK_4_LOW_BLOCK_TIME,
    }
}

fn upper_bound(class: PeerClass) -> i32 {
    match class.initial_rank {
        PEER_RANK_INITIAL_FIRST_PRIORITY => PEER_RANK_0_HIGH_BLOCK_TIME,
        PEER_RANK_INITIAL_SECOND_PRIORITY => PEER_RANK_1_HIGH_BLOCK_TIME,
        PEER_RANK_INITIAL_THIRD_PRIORITY => PEER_RANK_2_HIGH_BLOCK_TIME,
        PEER_RANK_INITIAL_FOURTH_PRIORITY => PEER_RANK_3_HIGH_BLOCK_TIME,
        _ => PEER_RANK_4_HIGH_BLOCK_TIME,
    }
}

fn bound_rank_by_class(rank: i32, class: PeerClass) -> i32 {
    rank.clamp(lower_bound(class), upper_bound(class))
}

/// Maps the range `[min_download_duration..max_download_duration]` onto the
/// rank range `[min_rank..max_rank]`, clamping the duration first.
///
/// Mirrors Go's `downloadDurationToRank`.
pub fn download_duration_to_rank(
    download_duration: Duration,
    min_download_duration: Duration,
    max_download_duration: Duration,
    min_rank: i32,
    max_rank: i32,
) -> i32 {
    let clamped = download_duration.clamp(min_download_duration, max_download_duration);
    let span_ns = max_download_duration.as_nanos() as i64 - min_download_duration.as_nanos() as i64;
    if span_ns == 0 {
        return min_rank;
    }
    let offset_ns = clamped.as_nanos() as i64 - min_download_duration.as_nanos() as i64;
    min_rank + (offset_ns * (max_rank - min_rank) as i64 / span_ns) as i32
}

// ---------------------------------------------------------------------------
// Historic stats (catchup/peerSelector.go lines 137-296)
// ---------------------------------------------------------------------------

/// Stores the past `window_size` ranks pushed for a peer (no averaging or
/// penalty at push time), plus a penalty history in the form of peer
/// selection gaps and a count of `PEER_RANK_DOWNLOAD_FAILED` incidents.
///
/// Mirrors Go's `historicStats`.
#[derive(Debug, Clone)]
struct HistoricStats {
    window_size: usize,
    rank_samples: VecDeque<i32>,
    rank_sum: u64,
    request_gaps: VecDeque<u64>,
    gap_sum: f64,
    counter: u64,
    download_failures: i32,
}

impl HistoricStats {
    /// Mirrors Go's `makeHistoricStatus`. Initializes the window with zeros
    /// but `rank_sum` with the equivalent sum of the class's initial rank,
    /// so every peer slowly builds up its profile rather than being pinned
    /// by its very first sample.
    fn new(window_size: usize, class: PeerClass) -> Self {
        Self {
            window_size,
            rank_samples: std::iter::repeat(class.initial_rank)
                .take(window_size)
                .collect(),
            rank_sum: class.initial_rank as u64 * window_size as u64,
            request_gaps: VecDeque::with_capacity(window_size),
            gap_sum: 0.0,
            counter: 0,
            download_failures: 0,
        }
    }

    /// Mirrors Go's `computerPenalty`.
    fn compute_penalty(&self) -> f64 {
        1.0 + (self.gap_sum / 10.0).exp() / 1000.0
    }

    /// Mirrors Go's `updateRequestPenalty`.
    fn update_request_penalty(&mut self, counter: u64) -> f64 {
        let new_gap = counter - self.counter;
        self.counter = counter;

        if self.request_gaps.len() == self.window_size {
            if let Some(front) = self.request_gaps.pop_front() {
                self.gap_sum -= 1.0 / front as f64;
            }
        }
        self.request_gaps.push_back(new_gap);
        self.gap_sum += 1.0 / new_gap as f64;

        self.compute_penalty()
    }

    /// Mirrors Go's `resetRequestPenalty`. `steps == 0` means a full reset
    /// (drop all gap values).
    fn reset_request_penalty(&mut self, steps: usize, initial_rank: i32, class: PeerClass) -> i32 {
        if self.request_gaps.is_empty() {
            return initial_rank;
        }
        // Cannot move the peer to a better class if it was demoted (e.g.
        // failed/invalid downloads).
        if upper_bound(class) < initial_rank {
            return initial_rank;
        }
        if steps == 0 {
            self.request_gaps.clear();
            self.gap_sum = 0.0;
            return (self.rank_sum as f64 / self.rank_samples.len() as f64) as i32;
        }

        let steps = steps.min(self.request_gaps.len());
        for _ in 0..steps {
            let gap = self.request_gaps.pop_front().unwrap();
            self.gap_sum -= 1.0 / gap as f64;
        }
        bound_rank_by_class(
            (self.compute_penalty() * (self.rank_sum as f64 / self.rank_samples.len() as f64))
                as i32,
            class,
        )
    }

    /// Pushes a new rank sample and returns the new averaged/penalized rank.
    ///
    /// Mirrors Go's `historicStats.push`.
    fn push(&mut self, value: i32, counter: u64, class: PeerClass) -> i32 {
        // The lowest ranking class is not subject to a second chance.
        if value == PEER_RANK_INVALID_DOWNLOAD {
            return value;
        }

        let initial_rank = value;
        let mut value = value;

        match value {
            PEER_RANK_NO_BLOCK_FOR_ROUND => {
                // For "no block" errors apply a smoother rank increase.
                self.download_failures += 1;
                value =
                    upper_bound(class) * (2f64.powf(self.download_failures as f64 * 0.1)) as i32;
            }
            PEER_RANK_DOWNLOAD_FAILED => {
                self.download_failures += 1;
                value = upper_bound(class) * (2f64.powf(self.download_failures as f64)) as i32;
            }
            _ => {
                if self.download_failures > 0 {
                    self.download_failures -= 1;
                }
            }
        }

        // Moving window: drop the oldest sample, add the new one.
        let old_rank = *self.rank_samples.front().expect("window is never empty");
        self.rank_sum = self.rank_sum - old_rank as u64 + value as u64;
        self.rank_samples.pop_front();
        self.rank_samples.push_back(value);

        let average = self.rank_sum as f64 / self.rank_samples.len() as f64;

        if average as i32 > upper_bound(class)
            && (initial_rank == PEER_RANK_DOWNLOAD_FAILED
                || initial_rank == PEER_RANK_NO_BLOCK_FOR_ROUND)
        {
            // Delay the failure penalty to give the peer time to improve;
            // if it doesn't, the average will exceed the class bound and
            // the peer will be pushed down to the failed class.
            return initial_rank;
        }

        let penalty = self.update_request_penalty(counter);
        let avg_with_penalty = (penalty * average) as i32;
        bound_rank_by_class(avg_with_penalty, class)
    }
}

// ---------------------------------------------------------------------------
// Peer wrapper / retriever trait
// ---------------------------------------------------------------------------

/// A peer identity paired with the class it was retrieved under. There can
/// be multiple entries with the same peer id but different classes, so both
/// fields matter for identity.
///
/// Mirrors Go's `peerSelectorPeer`. `peer_id` stands in for go-algorand's
/// `network.Peer` (compared there via `peerAddress()`); this module has no
/// dependency on the live network stack, so callers identify a peer with
/// whatever stable string id they use (address, node id, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSelectorPeer {
    pub peer_id: String,
    pub peer_class: PeerClassKind,
}

/// Supplies the current set of known peers for a given class. Mirrors Go's
/// `peersRetriever` interface (a subset of `network.GossipNode`).
pub trait PeersRetriever: Send + Sync {
    fn get_peers(&self, class: PeerClassKind) -> Vec<String>;
}

impl<F> PeersRetriever for F
where
    F: Fn(PeerClassKind) -> Vec<String> + Send + Sync,
{
    fn get_peers(&self, class: PeerClassKind) -> Vec<String> {
        self(class)
    }
}

// ---------------------------------------------------------------------------
// Peer pools
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PeerPoolEntry {
    peer_id: String,
    class: PeerClass,
    history: HistoricStats,
}

#[derive(Debug, Clone)]
struct PeerPool {
    rank: i32,
    peers: Vec<PeerPoolEntry>,
}

/// Errors produced by peer selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerRankerError {
    #[error("no peer pools available")]
    NoPeerPoolsAvailable,
}

/// Common interface implemented by both [`PeerRanker`] and
/// [`ClassBasedPeerSelector`]. Mirrors Go's `peerSelector` interface.
pub trait PeerSelector {
    /// Ranks a given peer, returning `(old_rank, new_rank)`, or `(-1, -1)`
    /// if the peer could not be found.
    fn rank_peer(&mut self, psp: &PeerSelectorPeer, rank: i32) -> (i32, i32);

    /// Converts an observed download duration into a rank for this peer's
    /// class, or [`PEER_RANK_INVALID_DOWNLOAD`] if the peer is unknown.
    fn peer_download_duration_to_rank(
        &mut self,
        psp: &PeerSelectorPeer,
        block_download_duration: Duration,
    ) -> i32;

    /// Returns the next peer to try, picked at random from the lowest-rank
    /// non-empty pool.
    fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError>;
}

/// Ranks and pools peers of one or more classes by their historical
/// download performance, so that better-performing/higher-priority peers
/// are preferentially returned by [`PeerRanker::get_next_peer`].
///
/// Mirrors Go's `rankPooledPeerSelector`.
pub struct PeerRanker {
    retriever: Arc<dyn PeersRetriever>,
    peer_classes: Vec<PeerClass>,
    pools: Vec<PeerPool>,
    counter: u64,
}

impl PeerRanker {
    /// Mirrors Go's `makeRankPooledPeerSelector`.
    pub fn new(retriever: Arc<dyn PeersRetriever>, peer_classes: Vec<PeerClass>) -> Self {
        Self {
            retriever,
            peer_classes,
            pools: Vec::new(),
            counter: 0,
        }
    }

    /// Adds a peer to the pool matching `rank`, creating a new pool if
    /// needed. Returns `true` if a new pool was created (the pools list
    /// needs re-sorting).
    fn add_to_pool(
        &mut self,
        peer_id: String,
        rank: i32,
        class: PeerClass,
        history: HistoricStats,
    ) -> bool {
        for pool in &mut self.pools {
            if pool.rank == rank {
                pool.peers.push(PeerPoolEntry {
                    peer_id,
                    class,
                    history,
                });
                return false;
            }
        }
        self.pools.push(PeerPool {
            rank,
            peers: vec![PeerPoolEntry {
                peer_id,
                class,
                history,
            }],
        });
        true
    }

    fn sort_pools(&mut self) {
        self.pools.sort_by_key(|p| p.rank);
    }

    /// Finds `(pool_idx, peer_idx)` for the given peer, or `(-1, -1)` if not
    /// found. Mirrors Go's `findPeer`.
    fn find_peer(&self, psp: &PeerSelectorPeer) -> (i32, i32) {
        if psp.peer_id.is_empty() {
            return (-1, -1);
        }
        for (i, pool) in self.pools.iter().enumerate() {
            for (j, entry) in pool.peers.iter().enumerate() {
                if entry.peer_id == psp.peer_id && entry.class.class == psp.peer_class {
                    return (i as i32, j as i32);
                }
            }
        }
        (-1, -1)
    }

    /// Reloads the available peers from the retriever: adds newly-seen
    /// peers with their class's initial rank, and drops peers no longer
    /// reported. Mirrors Go's `refreshAvailablePeers`.
    fn refresh_available_peers(&mut self) {
        use std::collections::HashMap;

        // existing[(class)] -> map(peer_id -> "still present" flag)
        let mut existing: HashMap<PeerClassKind, HashMap<String, bool>> = HashMap::new();
        for pool in &self.pools {
            for entry in &pool.peers {
                existing
                    .entry(entry.class.class)
                    .or_default()
                    .insert(entry.peer_id.clone(), true);
            }
        }

        let mut sort_needed = false;
        let peer_classes = self.peer_classes.clone();
        for init_class in &peer_classes {
            let peers = self.retriever.get_peers(init_class.class);
            for peer_id in peers {
                if peer_id.is_empty() {
                    continue;
                }
                let class_map = existing.entry(init_class.class).or_default();
                if let Some(present) = class_map.get_mut(&peer_id) {
                    // Setting to false instead of removing, to be safe
                    // against duplicate peer ids.
                    *present = false;
                    continue;
                }
                // An entry we didn't have before.
                let created = self.add_to_pool(
                    peer_id.clone(),
                    init_class.initial_rank,
                    *init_class,
                    HistoricStats::new(PEER_HISTORY_WINDOW_SIZE, *init_class),
                );
                sort_needed = sort_needed || created;
                class_map.insert(peer_id, false);
            }
        }

        // Remove peers that the network no longer reports.
        for pool_idx in (0..self.pools.len()).rev() {
            let class_of = |entry: &PeerPoolEntry| entry.class.class;
            self.pools[pool_idx].peers.retain(|entry| {
                let to_remove = existing
                    .get(&class_of(entry))
                    .and_then(|m| m.get(&entry.peer_id))
                    .copied()
                    .unwrap_or(false);
                !to_remove
            });
            if self.pools[pool_idx].peers.is_empty() {
                self.pools.remove(pool_idx);
                sort_needed = true;
            }
        }

        if sort_needed {
            self.sort_pools();
        }
    }
}

impl PeerSelector for PeerRanker {
    fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError> {
        self.refresh_available_peers();
        for pool in &self.pools {
            if !pool.peers.is_empty() {
                let idx = rand::thread_rng().gen_range(0..pool.peers.len());
                let entry = &pool.peers[idx];
                return Ok(PeerSelectorPeer {
                    peer_id: entry.peer_id.clone(),
                    peer_class: entry.class.class,
                });
            }
        }
        Err(PeerRankerError::NoPeerPoolsAvailable)
    }

    fn rank_peer(&mut self, psp: &PeerSelectorPeer, rank: i32) -> (i32, i32) {
        let (pool_idx, peer_idx) = self.find_peer(psp);
        if pool_idx < 0 || peer_idx < 0 {
            return (-1, -1);
        }
        let (pool_idx, peer_idx) = (pool_idx as usize, peer_idx as usize);

        let mut sort_needed = false;
        self.counter += 1;
        let counter = self.counter;
        let initial_rank = self.pools[pool_idx].rank;
        let class = self.pools[pool_idx].peers[peer_idx].class;
        let new_rank = self.pools[pool_idx].peers[peer_idx]
            .history
            .push(rank, counter, class);

        if self.pools[pool_idx].rank != new_rank {
            let entry = self.pools[pool_idx].peers.remove(peer_idx);
            if self.pools[pool_idx].peers.is_empty() {
                self.pools.remove(pool_idx);
            }
            let created = self.add_to_pool(entry.peer_id, new_rank, entry.class, entry.history);
            sort_needed = sort_needed || created;
        }

        // Reduce the penalty for every other peer, for not having been
        // selected this round (so a good peer's performance can dominate a
        // penalty accumulated purely from being requested frequently).
        let moved_peer_id = psp.peer_id.clone();
        for pl in (0..self.pools.len()).rev() {
            for pr in (0..self.pools[pl].peers.len()).rev() {
                if self.pools[pl].peers[pr].peer_id == moved_peer_id
                    && self.pools[pl].peers[pr].class.class == psp.peer_class
                {
                    continue;
                }
                let pool_rank = self.pools[pl].rank;
                let class = self.pools[pl].peers[pr].class;
                let new_rank = self.pools[pl].peers[pr]
                    .history
                    .reset_request_penalty(5, pool_rank, class);
                if new_rank != pool_rank {
                    let entry = self.pools[pl].peers.remove(pr);
                    if self.pools[pl].peers.is_empty() {
                        self.pools.remove(pl);
                    }
                    let created =
                        self.add_to_pool(entry.peer_id, new_rank, entry.class, entry.history);
                    sort_needed = sort_needed || created;
                }
            }
        }

        if sort_needed {
            self.sort_pools();
        }
        (initial_rank, new_rank)
    }

    fn peer_download_duration_to_rank(
        &mut self,
        psp: &PeerSelectorPeer,
        block_download_duration: Duration,
    ) -> i32 {
        let (pool_idx, peer_idx) = self.find_peer(psp);
        if pool_idx < 0 || peer_idx < 0 {
            return PEER_RANK_INVALID_DOWNLOAD;
        }
        let class = self.pools[pool_idx as usize].peers[peer_idx as usize].class;
        let (lo, hi) = match class.initial_rank {
            PEER_RANK_INITIAL_FIRST_PRIORITY => {
                (PEER_RANK_0_LOW_BLOCK_TIME, PEER_RANK_0_HIGH_BLOCK_TIME)
            }
            PEER_RANK_INITIAL_SECOND_PRIORITY => {
                (PEER_RANK_1_LOW_BLOCK_TIME, PEER_RANK_1_HIGH_BLOCK_TIME)
            }
            PEER_RANK_INITIAL_THIRD_PRIORITY => {
                (PEER_RANK_2_LOW_BLOCK_TIME, PEER_RANK_2_HIGH_BLOCK_TIME)
            }
            PEER_RANK_INITIAL_FOURTH_PRIORITY => {
                (PEER_RANK_3_LOW_BLOCK_TIME, PEER_RANK_3_HIGH_BLOCK_TIME)
            }
            _ => (PEER_RANK_4_LOW_BLOCK_TIME, PEER_RANK_4_HIGH_BLOCK_TIME),
        };
        download_duration_to_rank(
            block_download_duration,
            LOW_BLOCK_DOWNLOAD_THRESHOLD,
            HIGH_BLOCK_DOWNLOAD_THRESHOLD,
            lo,
            hi,
        )
    }
}

// ---------------------------------------------------------------------------
// Class-based peer selector (catchup/classBasedPeerSelector.go)
// ---------------------------------------------------------------------------

/// A [`PeerSelector`] restricted to one peer class, plus bookkeeping for how
/// many consecutive-ish download failures that class has accrued and how
/// many it will tolerate before [`ClassBasedPeerSelector`] moves on to the
/// next class. Mirrors Go's `wrappedPeerSelector`.
pub struct WrappedPeerSelector {
    pub peer_class: PeerClassKind,
    pub selector: Box<dyn PeerSelector + Send>,
    /// Number of net failures tolerated before this class is skipped.
    pub tolerance_factor: i32,
    /// Number of failures accrued since the last reset.
    pub download_failures: i32,
}

/// Selects the most appropriate peer *class* to download from — e.g.
/// whether blocks should come from relay nodes or archival nodes — by
/// trying classes in priority order and skipping a class once its
/// [`WrappedPeerSelector::tolerance_factor`] is exceeded, falling back to
/// unconditional retry (with all classes re-enabled) only once every class
/// is disabled.
///
/// Mirrors Go's `classBasedPeerSelector`.
pub struct ClassBasedPeerSelector {
    peer_selectors: Vec<WrappedPeerSelector>,
}

impl ClassBasedPeerSelector {
    /// Mirrors Go's `makeClassBasedPeerSelector`. The order of
    /// `peer_selectors` determines class priority.
    pub fn new(peer_selectors: Vec<WrappedPeerSelector>) -> Self {
        Self { peer_selectors }
    }

    /// Exposed for tests/introspection: the wrapped selectors in priority
    /// order.
    pub fn selectors(&self) -> &[WrappedPeerSelector] {
        &self.peer_selectors
    }

    fn internal_get_next_peer(
        &mut self,
        recurse_count: i8,
    ) -> Result<PeerSelectorPeer, PeerRankerError> {
        if recurse_count > 1 {
            return Err(PeerRankerError::NoPeerPoolsAvailable);
        }
        let mut selector_disabled_count = 0usize;
        for wp in &mut self.peer_selectors {
            if wp.download_failures > wp.tolerance_factor {
                selector_disabled_count += 1;
                continue;
            }
            match wp.selector.get_next_peer() {
                Ok(psp) => return Ok(psp),
                Err(PeerRankerError::NoPeerPoolsAvailable) => {
                    // Penalize this class the equivalent of one download
                    // failure, in case this is transient.
                    wp.download_failures += 1;
                }
            }
        }
        if !self.peer_selectors.is_empty() && selector_disabled_count == self.peer_selectors.len() {
            for wp in &mut self.peer_selectors {
                wp.download_failures = 0;
            }
            return self.internal_get_next_peer(recurse_count + 1);
        }
        Err(PeerRankerError::NoPeerPoolsAvailable)
    }
}

impl PeerSelector for ClassBasedPeerSelector {
    fn rank_peer(&mut self, psp: &PeerSelectorPeer, rank: i32) -> (i32, i32) {
        for wp in &mut self.peer_selectors {
            if psp.peer_class != wp.peer_class {
                continue;
            }
            let (old_rank, new_rank) = wp.selector.rank_peer(psp, rank);
            if old_rank < 0 || new_rank < 0 {
                // Peer not found in this class's selector.
                continue;
            }
            let failure = rank >= PEER_RANK_NO_BLOCK_FOR_ROUND;
            if failure {
                wp.download_failures += 1;
            } else {
                // A class usually has multiple peers; do not punish the
                // whole class for one peer's failure by decrementing here
                // unconditionally past zero.
                wp.download_failures = (wp.download_failures - 1).max(0);
            }
            return (old_rank, new_rank);
        }
        (-1, -1)
    }

    fn peer_download_duration_to_rank(
        &mut self,
        psp: &PeerSelectorPeer,
        block_download_duration: Duration,
    ) -> i32 {
        for wp in &mut self.peer_selectors {
            let rank = wp
                .selector
                .peer_download_duration_to_rank(psp, block_download_duration);
            if rank >= PEER_RANK_INVALID_DOWNLOAD {
                continue;
            }
            return rank;
        }
        PEER_RANK_INVALID_DOWNLOAD
    }

    fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError> {
        self.internal_get_next_peer(0)
    }
}

/// Returns a [`ClassBasedPeerSelector`] preferring relay nodes (tolerance 3)
/// before falling back to archival nodes (tolerance 10) — the preferred
/// configuration for the catchpoint service.
///
/// Mirrors Go's `makeCatchpointPeerSelector`.
pub fn make_catchpoint_peer_selector(net: Arc<dyn PeersRetriever>) -> ClassBasedPeerSelector {
    let wrapped = vec![
        WrappedPeerSelector {
            peer_class: PeerClassKind::PhonebookRelays,
            selector: Box::new(PeerRanker::new(
                net.clone(),
                vec![PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::PhonebookRelays,
                }],
            )),
            tolerance_factor: 3,
            download_failures: 0,
        },
        WrappedPeerSelector {
            peer_class: PeerClassKind::PhonebookArchivalNodes,
            selector: Box::new(PeerRanker::new(
                net,
                vec![PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::PhonebookArchivalNodes,
                }],
            )),
            tolerance_factor: 10,
            download_failures: 0,
        },
    ];
    ClassBasedPeerSelector::new(wrapped)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test-only [`PeersRetriever`] whose peer list can be swapped between
    /// calls, mirroring Go's `peersRetrieverStub`.
    struct StubRetriever<F: Fn(PeerClassKind) -> Vec<String> + Send + Sync>(F);
    impl<F: Fn(PeerClassKind) -> Vec<String> + Send + Sync> PeersRetriever for StubRetriever<F> {
        fn get_peers(&self, class: PeerClassKind) -> Vec<String> {
            (self.0)(class)
        }
    }

    fn peer(id: &str) -> String {
        id.to_string()
    }

    // -- downloadDurationToRank (TestPeerSelector_DownloadDurationToRank) --

    #[test]
    fn download_duration_to_rank_matches_go_fixture() {
        let ms = Duration::from_millis;
        assert_eq!(
            download_duration_to_rank(ms(50), ms(0), ms(100), 1000, 2000),
            1500
        );
        assert_eq!(
            download_duration_to_rank(ms(0), ms(0), ms(100), 1000, 2000),
            1000
        );
        assert_eq!(
            download_duration_to_rank(ms(100), ms(0), ms(100), 1000, 2000),
            2000
        );
        assert_eq!(
            download_duration_to_rank(ms(0), ms(100), ms(200), 1000, 2000),
            1000
        );
        assert_eq!(
            download_duration_to_rank(ms(205), ms(100), ms(200), 1000, 2000),
            2000
        );

        // zero rank range always yields zero
        assert_eq!(download_duration_to_rank(ms(50), ms(0), ms(100), 0, 0), 0);
        assert_eq!(download_duration_to_rank(ms(0), ms(0), ms(100), 0, 0), 0);
        assert_eq!(download_duration_to_rank(ms(100), ms(0), ms(100), 0, 0), 0);
        assert_eq!(download_duration_to_rank(ms(0), ms(100), ms(200), 0, 0), 0);
        assert_eq!(
            download_duration_to_rank(ms(205), ms(100), ms(200), 0, 0),
            0
        );
    }

    // -- lower/upper bounds (TestPeerSelector_LowerUpperBounds) --

    #[test]
    fn lower_upper_bounds_match_go_fixture() {
        let classes = [
            PeerClass {
                initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                class: PeerClassKind::PhonebookArchivalNodes,
            },
            PeerClass {
                initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
                class: PeerClassKind::PhonebookRelays,
            },
            PeerClass {
                initial_rank: PEER_RANK_INITIAL_THIRD_PRIORITY,
                class: PeerClassKind::ConnectedOut,
            },
            PeerClass {
                initial_rank: PEER_RANK_INITIAL_FOURTH_PRIORITY,
                class: PeerClassKind::ConnectedIn,
            },
            PeerClass {
                initial_rank: PEER_RANK_INITIAL_FIFTH_PRIORITY,
                class: PeerClassKind::ConnectedIn,
            },
        ];
        assert_eq!(lower_bound(classes[0]), PEER_RANK_0_LOW_BLOCK_TIME);
        assert_eq!(lower_bound(classes[1]), PEER_RANK_1_LOW_BLOCK_TIME);
        assert_eq!(lower_bound(classes[2]), PEER_RANK_2_LOW_BLOCK_TIME);
        assert_eq!(lower_bound(classes[3]), PEER_RANK_3_LOW_BLOCK_TIME);
        assert_eq!(lower_bound(classes[4]), PEER_RANK_4_LOW_BLOCK_TIME);

        assert_eq!(upper_bound(classes[0]), PEER_RANK_0_HIGH_BLOCK_TIME);
        assert_eq!(upper_bound(classes[1]), PEER_RANK_1_HIGH_BLOCK_TIME);
        assert_eq!(upper_bound(classes[2]), PEER_RANK_2_HIGH_BLOCK_TIME);
        assert_eq!(upper_bound(classes[3]), PEER_RANK_3_HIGH_BLOCK_TIME);
        assert_eq!(upper_bound(classes[4]), PEER_RANK_4_HIGH_BLOCK_TIME);
    }

    // -- basic ranking / re-pooling (TestPeerSelector_RankPeer) --

    #[test]
    fn rank_peer_moves_peers_between_pools_and_tracks_membership() {
        let peers = Arc::new(Mutex::new(vec![peer("12345")]));
        let peers_clone = peers.clone();
        let retriever: Arc<dyn PeersRetriever> =
            Arc::new(StubRetriever(move |_| peers_clone.lock().unwrap().clone()));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![PeerClass {
                initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                class: PeerClassKind::PhonebookArchivalNodes,
            }],
        );

        let psp = ranker.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "12345");

        *peers.lock().unwrap() = vec![peer("54321")];
        let psp = ranker.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "54321");

        *peers.lock().unwrap() = vec![peer("54321"), peer("abcde")];
        let (r1, r2) = ranker.rank_peer(&psp, 5);
        assert_ne!(r1, r2);

        let psp = ranker.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "abcde");

        let (r1, r2) = ranker.rank_peer(&psp, 200);
        assert_ne!(r1, r2);

        let psp = ranker.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "54321");

        // ranking a peer that isn't tracked returns (-1, -1)
        let unknown = PeerSelectorPeer {
            peer_id: "abc123".into(),
            peer_class: PeerClassKind::PhonebookArchivalNodes,
        };
        let (r1, r2) = ranker.rank_peer(&unknown, 10);
        assert_eq!((r1, r2), (-1, -1));
    }

    #[test]
    fn get_next_peer_errors_when_no_peers_reported() {
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|_| Vec::new()));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![PeerClass {
                initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                class: PeerClassKind::PhonebookArchivalNodes,
            }],
        );
        assert_eq!(
            ranker.get_next_peer(),
            Err(PeerRankerError::NoPeerPoolsAvailable)
        );
    }

    // -- find_peer for a peer that was never seen (TestPeerSelector_FindMissingPeer) --

    #[test]
    fn find_peer_returns_negative_indices_when_missing() {
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|_| Vec::new()));
        let ranker = PeerRanker::new(
            retriever,
            vec![PeerClass {
                initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                class: PeerClassKind::PhonebookArchivalNodes,
            }],
        );
        let missing = PeerSelectorPeer {
            peer_id: "abcd".into(),
            peer_class: PeerClassKind::PhonebookArchivalNodes,
        };
        assert_eq!(ranker.find_peer(&missing), (-1, -1));
    }

    // -- per-class download-duration mapping (TestPeerSelector_PeerDownloadRanking) --

    #[test]
    fn peer_download_duration_to_rank_uses_the_peers_class_bucket() {
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|class| match class {
            PeerClassKind::PhonebookArchivalNodes => vec![peer("1234"), peer("5678")],
            _ => vec![peer("abcd"), peer("efgh")],
        }));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::PhonebookArchivalNodes,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
                    class: PeerClassKind::PhonebookRelays,
                },
            ],
        );

        let archival = ranker.get_next_peer().unwrap();
        assert_eq!(archival.peer_class, PeerClassKind::PhonebookArchivalNodes);
        let expected = download_duration_to_rank(
            Duration::from_millis(500),
            LOW_BLOCK_DOWNLOAD_THRESHOLD,
            HIGH_BLOCK_DOWNLOAD_THRESHOLD,
            PEER_RANK_0_LOW_BLOCK_TIME,
            PEER_RANK_0_HIGH_BLOCK_TIME,
        );
        assert_eq!(
            ranker.peer_download_duration_to_rank(&archival, Duration::from_millis(500)),
            expected
        );

        // an unknown peer/class combo is always ranked "invalid download"
        let unknown = PeerSelectorPeer {
            peer_id: "abc123".into(),
            peer_class: PeerClassKind::PhonebookArchivalNodes,
        };
        assert_eq!(
            ranker.peer_download_duration_to_rank(&unknown, Duration::from_millis(1)),
            PEER_RANK_INVALID_DOWNLOAD
        );
    }

    // -- all four class buckets map through the correct rank range
    //    (TestPeerSelector_PeerDownloadDurationToRank) --

    #[test]
    fn peer_download_duration_to_rank_covers_all_four_class_buckets() {
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|class| match class {
            PeerClassKind::PhonebookRelays => vec![peer("a1"), peer("a2"), peer("a3")],
            PeerClassKind::ConnectedOut => vec![peer("b1"), peer("b2")],
            PeerClassKind::PhonebookArchivalNodes => vec![peer("c1"), peer("c2")],
            PeerClassKind::ConnectedIn => vec![peer("d1"), peer("b2")],
        }));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::PhonebookRelays,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
                    class: PeerClassKind::ConnectedOut,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_THIRD_PRIORITY,
                    class: PeerClassKind::PhonebookArchivalNodes,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FOURTH_PRIORITY,
                    class: PeerClassKind::ConnectedIn,
                },
            ],
        );
        ranker.get_next_peer().unwrap();

        let dur = Duration::from_millis(500);
        assert_eq!(
            ranker.peer_download_duration_to_rank(
                &PeerSelectorPeer {
                    peer_id: "a1".into(),
                    peer_class: PeerClassKind::PhonebookRelays
                },
                dur
            ),
            download_duration_to_rank(
                dur,
                LOW_BLOCK_DOWNLOAD_THRESHOLD,
                HIGH_BLOCK_DOWNLOAD_THRESHOLD,
                PEER_RANK_0_LOW_BLOCK_TIME,
                PEER_RANK_0_HIGH_BLOCK_TIME
            )
        );
        assert_eq!(
            ranker.peer_download_duration_to_rank(
                &PeerSelectorPeer {
                    peer_id: "b1".into(),
                    peer_class: PeerClassKind::ConnectedOut
                },
                dur
            ),
            download_duration_to_rank(
                dur,
                LOW_BLOCK_DOWNLOAD_THRESHOLD,
                HIGH_BLOCK_DOWNLOAD_THRESHOLD,
                PEER_RANK_1_LOW_BLOCK_TIME,
                PEER_RANK_1_HIGH_BLOCK_TIME
            )
        );
        assert_eq!(
            ranker.peer_download_duration_to_rank(
                &PeerSelectorPeer {
                    peer_id: "c1".into(),
                    peer_class: PeerClassKind::PhonebookArchivalNodes
                },
                dur
            ),
            download_duration_to_rank(
                dur,
                LOW_BLOCK_DOWNLOAD_THRESHOLD,
                HIGH_BLOCK_DOWNLOAD_THRESHOLD,
                PEER_RANK_2_LOW_BLOCK_TIME,
                PEER_RANK_2_HIGH_BLOCK_TIME
            )
        );
        assert_eq!(
            ranker.peer_download_duration_to_rank(
                &PeerSelectorPeer {
                    peer_id: "d1".into(),
                    peer_class: PeerClassKind::ConnectedIn
                },
                dur
            ),
            download_duration_to_rank(
                dur,
                LOW_BLOCK_DOWNLOAD_THRESHOLD,
                HIGH_BLOCK_DOWNLOAD_THRESHOLD,
                PEER_RANK_3_LOW_BLOCK_TIME,
                PEER_RANK_3_HIGH_BLOCK_TIME
            )
        );
    }

    // -- penalty bounds (TestPeerSelector_PenaltyBounds) --

    #[test]
    fn penalty_never_demotes_and_reset_never_promotes_past_a_demotion() {
        let class = PeerClass {
            initial_rank: PEER_RANK_INITIAL_THIRD_PRIORITY,
            class: PeerClassKind::PhonebookArchivalNodes,
        };
        let mut hs = HistoricStats::new(PEER_HISTORY_WINDOW_SIZE, class);
        for x in 0..65u64 {
            let r0 = hs.push(PEER_RANK_2_LOW_BLOCK_TIME + 50, x + 1, class);
            assert!(r0 >= PEER_RANK_2_LOW_BLOCK_TIME);
            assert!(r0 <= PEER_RANK_2_HIGH_BLOCK_TIME);
        }

        let r1 = hs.reset_request_penalty(4, PEER_RANK_INITIAL_THIRD_PRIORITY, class);
        let r2 = hs.reset_request_penalty(10, PEER_RANK_INITIAL_THIRD_PRIORITY, class);
        let r3 = hs.reset_request_penalty(10, PEER_RANK_DOWNLOAD_FAILED, class);

        // r2 has one fewer penalty than r1, so it should rank better (lower).
        assert!(r1 > r2);
        // r3 was demoted to peerRankDownloadFailed; resetting must not improve it.
        assert_eq!(r3, PEER_RANK_DOWNLOAD_FAILED);
    }

    #[test]
    fn full_reset_clears_all_gaps() {
        let class = PeerClass {
            initial_rank: 0,
            class: PeerClassKind::PhonebookArchivalNodes,
        };
        let mut hs = HistoricStats::new(10, class);
        hs.push(5, 1, class);
        assert_eq!(hs.request_gaps.len(), 1);
        hs.reset_request_penalty(0, 0, class);
        assert_eq!(hs.request_gaps.len(), 0);
    }

    // -- class upper/lower bound never exceeded across many pushes
    //    (TestPeerSelector_ClassUpperBound / TestPeerSelector_ClassLowerBound) --

    #[test]
    fn ranker_never_exceeds_class_upper_bound() {
        let p_class = PeerClass {
            initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
            class: PeerClassKind::PhonebookArchivalNodes,
        };
        let retriever: Arc<dyn PeersRetriever> =
            Arc::new(StubRetriever(|_| vec![peer("a1"), peer("a2")]));
        let mut ranker = PeerRanker::new(retriever, vec![p_class]);
        ranker.get_next_peer().unwrap();
        for i in 0..200 {
            let psp = ranker.get_next_peer().unwrap();
            if i < 6 {
                ranker.rank_peer(&psp, PEER_RANK_DOWNLOAD_FAILED);
            } else {
                ranker.rank_peer(&psp, upper_bound(p_class));
            }
            for pool in &ranker.pools {
                assert!(pool.rank <= upper_bound(p_class));
            }
        }
    }

    #[test]
    fn ranker_never_goes_under_class_lower_bound() {
        let p_class = PeerClass {
            initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
            class: PeerClassKind::PhonebookArchivalNodes,
        };
        let retriever: Arc<dyn PeersRetriever> =
            Arc::new(StubRetriever(|_| vec![peer("a1"), peer("a2")]));
        let mut ranker = PeerRanker::new(retriever, vec![p_class]);
        ranker.get_next_peer().unwrap();
        for _ in 0..10 {
            let psp = ranker.get_next_peer().unwrap();
            ranker.rank_peer(&psp, lower_bound(p_class));
            for pool in &ranker.pools {
                assert!(pool.rank >= p_class.initial_rank);
            }
        }
    }

    // -- eviction after repeated failures, and upgrade to the next class
    //    (TestPeerSelector_EvictionAndUpgrade) --

    #[test]
    fn repeated_download_failures_evict_the_peer_and_the_next_class_takes_over() {
        let retriever: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|_| vec![peer("a1")]));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::PhonebookArchivalNodes,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
                    class: PeerClassKind::PhonebookRelays,
                },
            ],
        );
        ranker.get_next_peer().unwrap();
        let mut evicted_at = None;
        for i in 0..10 {
            if ranker.pools.last().unwrap().rank == PEER_RANK_DOWNLOAD_FAILED {
                evicted_at = Some(i);
                break;
            }
            let psp = ranker.get_next_peer().unwrap();
            ranker.rank_peer(&psp, PEER_RANK_DOWNLOAD_FAILED);
        }
        assert_eq!(evicted_at, Some(6));

        // The a1 address exists under both classes; once the archival-class
        // entry is evicted (ranked to peerRankDownloadFailed), the
        // second-priority (relay) class entry should still be preferred.
        let psp = ranker.get_next_peer().unwrap();
        assert_eq!(psp.peer_class, PeerClassKind::PhonebookRelays);
    }

    // -- refresh add/remove semantics (TestPeerSelector_RefreshAvailablePeers) --

    #[test]
    fn refresh_adds_new_peers_and_removes_dropped_ones() {
        // Both classes report p1+p2 initially; then the ConnectedOut class
        // drops to reporting only p1, and PhonebookArchivalNodes reports
        // nothing at all.
        let connected_out_peers = Arc::new(Mutex::new(vec![peer("p1"), peer("p2")]));
        let archival_peers = Arc::new(Mutex::new(vec![peer("p1"), peer("p2")]));
        let (co, ar) = (connected_out_peers.clone(), archival_peers.clone());
        let retriever: Arc<dyn PeersRetriever> =
            Arc::new(StubRetriever(move |class| match class {
                PeerClassKind::ConnectedOut => co.lock().unwrap().clone(),
                PeerClassKind::PhonebookArchivalNodes => ar.lock().unwrap().clone(),
                _ => vec![],
            }));
        let mut ranker = PeerRanker::new(
            retriever,
            vec![
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_FIRST_PRIORITY,
                    class: PeerClassKind::ConnectedOut,
                },
                PeerClass {
                    initial_rank: PEER_RANK_INITIAL_SECOND_PRIORITY,
                    class: PeerClassKind::PhonebookArchivalNodes,
                },
            ],
        );
        ranker.refresh_available_peers();
        // both classes see p1+p2 -> two pools of two peers each
        assert_eq!(ranker.pools.len(), 2);
        assert_eq!(ranker.pools[0].peers.len(), 2);
        assert_eq!(ranker.pools[1].peers.len(), 2);

        // Now only the first class reports p1; the second reports nothing.
        *connected_out_peers.lock().unwrap() = vec![peer("p1")];
        *archival_peers.lock().unwrap() = vec![];
        ranker.refresh_available_peers();
        assert_eq!(ranker.pools.len(), 1);
        assert_eq!(ranker.pools[0].peers.len(), 1);
        assert_eq!(ranker.pools[0].peers[0].peer_id, "p1");
    }

    // -- construction preserves caller-supplied priority order
    //    (TestClassBasedPeerSelector_makeClassBasedPeerSelector) --

    #[test]
    fn class_based_selector_preserves_construction_order() {
        let wrapped = vec![
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookRelays,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|_, r| (-1, r)),
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::ConnectedOut,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|_, r| (-1, r)),
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookArchivalNodes,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|_, r| (-1, r)),
                }),
                tolerance_factor: 10,
                download_failures: 0,
            },
        ];
        let cps = ClassBasedPeerSelector::new(wrapped);
        assert_eq!(cps.selectors().len(), 3);
        assert_eq!(
            cps.selectors()[0].peer_class,
            PeerClassKind::PhonebookRelays
        );
        assert_eq!(cps.selectors()[1].peer_class, PeerClassKind::ConnectedOut);
        assert_eq!(
            cps.selectors()[2].peer_class,
            PeerClassKind::PhonebookArchivalNodes
        );
    }

    // -- ClassBasedPeerSelector: per-class failure bookkeeping
    //    (TestClassBasedPeerSelector_rankPeer) --

    type RankPeerFn = Box<dyn FnMut(&PeerSelectorPeer, i32) -> (i32, i32) + Send>;

    struct MockSelector {
        rank_peer: RankPeerFn,
    }
    impl PeerSelector for MockSelector {
        fn rank_peer(&mut self, psp: &PeerSelectorPeer, rank: i32) -> (i32, i32) {
            (self.rank_peer)(psp, rank)
        }
        fn peer_download_duration_to_rank(&mut self, _: &PeerSelectorPeer, _: Duration) -> i32 {
            PEER_RANK_INVALID_DOWNLOAD
        }
        fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError> {
            Err(PeerRankerError::NoPeerPoolsAvailable)
        }
    }

    #[test]
    fn class_based_selector_tracks_failures_only_for_the_owning_class() {
        let mock_peer = PeerSelectorPeer {
            peer_id: String::new(),
            peer_class: PeerClassKind::PhonebookRelays,
        };

        let wrapped = vec![
            WrappedPeerSelector {
                peer_class: PeerClassKind::ConnectedOut,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|_, _| (-1, -1)),
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookRelays,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|psp, rank| {
                        if psp.peer_class == PeerClassKind::PhonebookRelays {
                            (10, rank)
                        } else {
                            (-1, -1)
                        }
                    }),
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookArchivalNodes,
                selector: Box::new(MockSelector {
                    rank_peer: Box::new(|_, _| (-1, -1)),
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
        ];
        let mut cps = ClassBasedPeerSelector::new(wrapped);

        let (old_rank, new_rank) = cps.rank_peer(&mock_peer, 50);
        assert_eq!((old_rank, new_rank), (10, 50));
        assert_eq!(cps.peer_selectors[1].download_failures, 0);

        let (old_rank, new_rank) = cps.rank_peer(&mock_peer, PEER_RANK_NO_BLOCK_FOR_ROUND);
        assert_eq!((old_rank, new_rank), (10, PEER_RANK_NO_BLOCK_FOR_ROUND));
        assert_eq!(cps.peer_selectors[1].download_failures, 1);

        cps.rank_peer(&mock_peer, PEER_RANK_NO_BLOCK_FOR_ROUND);
        cps.rank_peer(&mock_peer, PEER_RANK_NO_BLOCK_FOR_ROUND);
        assert_eq!(cps.peer_selectors[1].download_failures, 3);

        // sibling classes are untouched
        assert_eq!(cps.peer_selectors[0].download_failures, 0);
        assert_eq!(cps.peer_selectors[2].download_failures, 0);
    }

    // -- ClassBasedPeerSelector: duration-to-rank tries classes in order
    //    until one recognizes the peer (TestClassBasedPeerSelector_peerDownloadDurationToRank) --

    struct DurationMockSelector {
        rank: i32,
        matches_id: &'static str,
    }
    impl PeerSelector for DurationMockSelector {
        fn rank_peer(&mut self, _: &PeerSelectorPeer, rank: i32) -> (i32, i32) {
            (-1, rank)
        }
        fn peer_download_duration_to_rank(&mut self, psp: &PeerSelectorPeer, _: Duration) -> i32 {
            if psp.peer_id == self.matches_id {
                self.rank
            } else {
                PEER_RANK_INVALID_DOWNLOAD
            }
        }
        fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError> {
            Err(PeerRankerError::NoPeerPoolsAvailable)
        }
    }

    #[test]
    fn class_based_peer_download_duration_to_rank_uses_first_matching_class() {
        let wrapped = vec![
            WrappedPeerSelector {
                peer_class: PeerClassKind::ConnectedOut,
                selector: Box::new(DurationMockSelector {
                    rank: 0,
                    matches_id: "nobody",
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookRelays,
                selector: Box::new(DurationMockSelector {
                    rank: PEER_RANK_0_HIGH_BLOCK_TIME,
                    matches_id: "p1",
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookArchivalNodes,
                selector: Box::new(DurationMockSelector {
                    rank: 0,
                    matches_id: "nobody",
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
        ];
        let mut cps = ClassBasedPeerSelector::new(wrapped);
        let mock_peer = PeerSelectorPeer {
            peer_id: "p1".into(),
            peer_class: PeerClassKind::PhonebookRelays,
        };

        let rank = cps.peer_download_duration_to_rank(&mock_peer, Duration::from_millis(50));
        assert_eq!(rank, PEER_RANK_0_HIGH_BLOCK_TIME);

        // no class recognizes this peer -> invalid download
        let unrecognized = PeerSelectorPeer {
            peer_id: "someone-else".into(),
            peer_class: PeerClassKind::ConnectedIn,
        };
        let rank = cps.peer_download_duration_to_rank(&unrecognized, Duration::from_millis(50));
        assert_eq!(rank, PEER_RANK_INVALID_DOWNLOAD);
    }

    // -- ClassBasedPeerSelector: disable-on-tolerance and reset-when-all-disabled
    //    (TestClassBasedPeerSelector_getNextPeer) --

    struct CountingMockSelector {
        peer_id: &'static str,
        peer_class: PeerClassKind,
        has_peer: bool,
    }
    impl PeerSelector for CountingMockSelector {
        fn rank_peer(&mut self, psp: &PeerSelectorPeer, rank: i32) -> (i32, i32) {
            if psp.peer_id == self.peer_id {
                (10, rank)
            } else {
                (-1, -1)
            }
        }
        fn peer_download_duration_to_rank(&mut self, _: &PeerSelectorPeer, _: Duration) -> i32 {
            PEER_RANK_INVALID_DOWNLOAD
        }
        fn get_next_peer(&mut self) -> Result<PeerSelectorPeer, PeerRankerError> {
            if self.has_peer {
                Ok(PeerSelectorPeer {
                    peer_id: self.peer_id.into(),
                    peer_class: self.peer_class,
                })
            } else {
                Err(PeerRankerError::NoPeerPoolsAvailable)
            }
        }
    }

    #[test]
    fn disabled_classes_are_skipped_and_reset_together_once_all_disabled() {
        let wrapped = vec![
            WrappedPeerSelector {
                peer_class: PeerClassKind::ConnectedOut,
                selector: Box::new(CountingMockSelector {
                    peer_id: "p1",
                    peer_class: PeerClassKind::ConnectedOut,
                    has_peer: true,
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookRelays,
                selector: Box::new(CountingMockSelector {
                    peer_id: "p2",
                    peer_class: PeerClassKind::PhonebookRelays,
                    has_peer: true,
                }),
                tolerance_factor: 10,
                download_failures: 0,
            },
            WrappedPeerSelector {
                peer_class: PeerClassKind::PhonebookArchivalNodes,
                selector: Box::new(CountingMockSelector {
                    peer_id: "p3",
                    peer_class: PeerClassKind::PhonebookArchivalNodes,
                    has_peer: true,
                }),
                tolerance_factor: 3,
                download_failures: 0,
            },
        ];
        let mut cps = ClassBasedPeerSelector::new(wrapped);

        // top priority class always wins while nothing is disabled.
        for _ in 0..10 {
            let psp = cps.get_next_peer().unwrap();
            assert_eq!(psp.peer_id, "p1");
        }

        // 4 failures > tolerance_factor(3) disables class 0.
        for _ in 0..4 {
            cps.rank_peer(
                &PeerSelectorPeer {
                    peer_id: "p1".into(),
                    peer_class: PeerClassKind::ConnectedOut,
                },
                PEER_RANK_NO_BLOCK_FOR_ROUND,
            );
        }
        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p2");
        assert_eq!(cps.peer_selectors[0].download_failures, 4);

        // drive class 1 to exactly its tolerance (10): still enabled.
        for _ in 0..10 {
            cps.rank_peer(
                &PeerSelectorPeer {
                    peer_id: "p2".into(),
                    peer_class: PeerClassKind::PhonebookRelays,
                },
                PEER_RANK_NO_BLOCK_FOR_ROUND,
            );
        }
        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p2");

        // one more failure disables class 1 too -> falls to class 2.
        cps.rank_peer(
            &PeerSelectorPeer {
                peer_id: "p2".into(),
                peer_class: PeerClassKind::PhonebookRelays,
            },
            PEER_RANK_NO_BLOCK_FOR_ROUND,
        );
        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p3");

        // drive class 2 past its tolerance too -> ALL classes disabled ->
        // failures reset for everyone and class 0 wins again.
        for _ in 0..4 {
            cps.rank_peer(
                &PeerSelectorPeer {
                    peer_id: "p3".into(),
                    peer_class: PeerClassKind::PhonebookArchivalNodes,
                },
                PEER_RANK_NO_BLOCK_FOR_ROUND,
            );
        }
        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p1");
        assert_eq!(cps.peer_selectors[0].download_failures, 0);
        assert_eq!(cps.peer_selectors[1].download_failures, 0);
        assert_eq!(cps.peer_selectors[2].download_failures, 0);
    }

    // -- make_catchpoint_peer_selector integration
    //    (TestClassBasedPeerSelector_integration) --

    #[test]
    fn catchpoint_selector_prefers_relays_then_falls_back_to_archival_on_failures() {
        let net: Arc<dyn PeersRetriever> = Arc::new(StubRetriever(|class| match class {
            PeerClassKind::PhonebookRelays => vec![peer("p1")],
            PeerClassKind::PhonebookArchivalNodes => vec![peer("p2")],
            _ => vec![],
        }));
        let mut cps = make_catchpoint_peer_selector(net);

        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p1");
        assert_eq!(psp.peer_class, PeerClassKind::PhonebookRelays);

        // Note: mirrors go-algorand's integration test, which passes a raw
        // `500` (i.e. 500 *nanoseconds*, not 500ms) as the download
        // duration — well below `LOW_BLOCK_DOWNLOAD_THRESHOLD`, so it
        // clamps to the class's minimum rank. On a peer's very first push,
        // the 100-sample averaging window (all zeros) pulls the averaged
        // rank down to the class lower bound too, so they coincide here.
        let rank = cps.peer_download_duration_to_rank(&psp, Duration::from_nanos(500));
        let (old_rank, new_rank) = cps.rank_peer(&psp, rank);
        assert_eq!(old_rank, 0);
        assert_eq!(new_rank, rank);

        // enough consecutive no-block failures (> tolerance 3) push us to archival.
        for _ in 0..4 {
            let psp = cps.get_next_peer().unwrap();
            assert_eq!(psp.peer_id, "p1");
            cps.rank_peer(&psp, PEER_RANK_NO_BLOCK_FOR_ROUND);
        }
        let psp = cps.get_next_peer().unwrap();
        assert_eq!(psp.peer_id, "p2");
        assert_eq!(psp.peer_class, PeerClassKind::PhonebookArchivalNodes);
    }
}
