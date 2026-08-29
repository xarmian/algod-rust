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

//! Paged node cache for the 256-ary Merkle trie.
//!
//! Mirrors go-algorand's `crypto/merkletrie/cache.go::merkleTrieCache`:
//! groups in-memory nodes into pages of `NODES_PER_PAGE = 116` nodes
//! (matching `MerkleCommitterNodesPerPage` at
//! `ledger/store/trackerdb/catchpoint.go:42`), tracks which pages have
//! been mutated since the last commit, and writes only those dirty pages
//! through a [`PageCommitter`] on `commit`. After commit, an LRU
//! eviction policy bounds the in-memory page count so long replays don't
//! grow unbounded.
//!
//! Persistence is byte-compatible with Go's `accounthashes` table — page
//! `0` carries the trie root metadata (root id, next-node id, element
//! length, nodes-per-page), and pages `≥ 1` carry the serialized node
//! contents in the format owned by [`crate::merkle_page::Page`].
//!
//! Reference (go-algorand v4.6.0-stable):
//! - `crypto/merkletrie/cache.go:46-94`   — `merkleTrieCache` struct
//! - `crypto/merkletrie/cache.go:122-203` — `allocateNewNode`, `getNode`
//! - `crypto/merkletrie/cache.go:242-268` — `loadPage` (on-demand)
//! - `crypto/merkletrie/cache.go:287-341` — transaction scopes
//! - `crypto/merkletrie/cache.go:356-423` — `commit`
//! - `crypto/merkletrie/cache.go:708-731` — `evict`
//! - `crypto/merkletrie/trie.go:251-291`  — root-metadata page (page 0)
//! - `crypto/merkletrie/trie.go:29,32`    — version constants
//!
//! ## Lazy on-demand page loading (PLAN-144 TASK-146)
//!
//! The cache stores an optional `Box<dyn PageCommitter + Send>`
//! (`lazy_loader`) installed by [`crate::merkle_trie::MerkleTrie::load`].
//! On `get` / `get_mut`, a node that isn't in memory triggers a page
//! read via the loader, deserializes the page, and re-tries the lookup.
//! This mirrors Go's `merkleTrieCache::getNode` at `cache.go:166-203`.
//!
//! The `Send` bound is required because `MerkleTrie` rides inside
//! `SqliteLedger`, which `agreement_bridge` moves across thread
//! boundaries when spawning agreement workers. Both shipped committers
//! satisfy it: [`InMemoryPageCommitter`] holds an `Arc<Mutex<…>>`
//! (`Send + Sync`), and the SQLite-backed `OwnedSqliteCommitter` (in
//! `merkle_committer.rs`) owns its own `Connection` outright (rusqlite's
//! `Connection: Send`). The borrowed `SqliteMerkleCommitter<'_>` is
//! deliberately not boxed as a lazy loader — its connection borrow is
//! call-scoped.
//!
//! Tries that never persist (catchpoint-verify ephemeral builds, unit
//! tests that don't commit) leave `lazy_loader = None`; the cache
//! behaves as a pure in-memory store and a miss returns `Ok(None)`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use algo_error::AlgoError;

use crate::merkle_page::{ChildEntry as PageChildEntry, Page, PageNode, NODES_PER_PAGE};
use crate::merkle_trie::{Bitset, ChildEntry, TrieNode};

/// First node ID allocated by a fresh trie. Matches go-algorand's
/// `storedNodeIdentifierBase = 0x4160` at `crypto/merkletrie/cache.go:34`.
///
/// Page 0 is reserved for the trie root metadata blob (see
/// `MerkleTrieCache::write_metadata_page`); pages 1..143 are unused; the
/// first allocated node lives on page `0x4160 / 116 = 144`. Reproducing
/// this offset exactly keeps Rust-written databases byte-compatible with
/// go-algorand at the page-id level.
pub const FIRST_NODE_ID: u64 = 0x4160;

/// Default in-memory node count target (LRU evict threshold). Matches
/// go-algorand `ledger/store/trackerdb/catchpoint.go:46`'s
/// `TrieCachedNodesCount = 9000`.
pub const DEFAULT_CACHED_NODES_TARGET: usize = 9000;

/// Default target fill factor for committed pages. Matches go-algorand's
/// `MemoryConfig.PageFillFactor` at
/// `ledger/store/trackerdb/catchpoint.go:35`. PLAN-144 TASK-148: the
/// `reallocate_pending_pages` heuristic repacks any newly-created page
/// whose fill factor falls below this threshold onto fresh tail pages.
pub const DEFAULT_PAGE_FILL_FACTOR: f32 = 0.95;

/// Default upper bound on the number of distinct child pages a single
/// internal node may reference before its children are relocated onto a
/// single fresh page. Matches go-algorand's
/// `MemoryConfig.MaxChildrenPagesThreshold` at
/// `ledger/store/trackerdb/catchpoint.go:37`.
pub const DEFAULT_MAX_CHILDREN_PAGES_THRESHOLD: u64 = 64;

/// Version word for the trie-root metadata page (page 0). Matches Go's
/// `merkleTreeVersion = 0x1000000010000000` at
/// `crypto/merkletrie/trie.go:29` — note that this is the same value as
/// `merkle_page::NODE_PAGE_VERSION` (both happen to share the constant in
/// go-algorand).
pub const MERKLE_TREE_VERSION: u64 = 0x1000_0000_1000_0000;

/// Fields decoded from the trie-root metadata page (page 0).
///
/// Returned by [`MerkleTrieCache::read_metadata_page`] when page 0 is
/// present. The shape mirrors the five varint fields Go writes via
/// `Trie.serialize` at `crypto/merkletrie/trie.go:251-258`:
///
/// 1. trie root id (`None` ↔ Go's `storedNodeIdentifierNull` sentinel = 0)
/// 2. next-to-allocate node id
/// 3. element length (bytes per stored element)
/// 4. nodes-per-page used at the time of the last commit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieMetadata {
    pub root: Option<u64>,
    pub next_node_id: u64,
    pub element_length: usize,
    pub nodes_per_page: u64,
}

// ---------------------------------------------------------------------------
// PageCommitter trait
// ---------------------------------------------------------------------------

/// Persistence backend for [`MerkleTrieCache`] — the Rust analog of Go's
/// `crypto/merkletrie/committer.go::Committer` interface (`committer.go:22-25`).
///
/// Page `0` carries the trie root metadata; pages `≥ 1` carry serialized
/// node contents. `store_page` with empty `content` deletes the row
/// (matching Go's nil-content delete semantics at
/// `merkle_committer.go:58-61`).
pub trait PageCommitter {
    /// Load the raw bytes of page `id`. Returns `Ok(None)` when the page
    /// does not exist.
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError>;

    /// Persist `content` at page `id`. Empty content deletes the row.
    fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError>;
}

/// In-memory [`PageCommitter`] for tests and the catchpoint-verify path
/// (which builds an ephemeral trie that's never persisted). Mirrors Go's
/// `InMemoryCommitter` at `crypto/merkletrie/committer.go:32-69`.
///
/// Internals are `Arc<Mutex<…>>` so the committer is cheaply [`Clone`].
/// This lets tests retain a handle for inspection (page count, hit
/// counter) after handing an owned clone to
/// [`crate::merkle_trie::MerkleTrie::load`].
///
/// The hit counter — `load_page_hits` — is incremented every time
/// `load_page` is invoked, regardless of whether the page exists. Used
/// by lazy-load tests to assert that on-demand loading touches **exactly**
/// the pages a traversal needs (and not the whole trie).
#[derive(Debug, Default, Clone)]
pub struct InMemoryPageCommitter {
    pages: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    /// `page_id -> hit count`. Incremented by `load_page` for any call,
    /// including misses (so test assertions can detect "the lazy loader
    /// asked for a page that didn't exist").
    load_page_hits: Arc<Mutex<HashMap<u64, u64>>>,
}

impl InMemoryPageCommitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pages currently stored.
    pub fn page_count(&self) -> usize {
        self.pages.lock().unwrap().len()
    }

    /// Total `load_page` invocations across every page id.
    pub fn total_load_page_calls(&self) -> u64 {
        self.load_page_hits.lock().unwrap().values().sum()
    }

    /// Per-page `load_page` invocation counts.
    pub fn load_page_hits(&self) -> HashMap<u64, u64> {
        self.load_page_hits.lock().unwrap().clone()
    }

    /// Reset the hit counter. Useful when a test wants to measure only
    /// the loads triggered by a specific operation (e.g. one `contains`).
    pub fn reset_load_page_hits(&self) {
        self.load_page_hits.lock().unwrap().clear();
    }
}

impl PageCommitter for InMemoryPageCommitter {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        *self.load_page_hits.lock().unwrap().entry(id).or_insert(0) += 1;
        Ok(self.pages.lock().unwrap().get(&id).cloned())
    }

    fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
        let mut pages = self.pages.lock().unwrap();
        if content.is_empty() {
            pages.remove(&id);
        } else {
            pages.insert(id, content.to_vec());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitStats — per-commit accounting, exposed for tests + diagnostics.
// Mirrors Go's `crypto/merkletrie/cache.go::CommitStats` shape.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitStats {
    pub new_page_count: usize,
    pub updated_page_count: usize,
    pub deleted_page_count: usize,
    pub new_node_count: usize,
    pub updated_node_count: usize,
    /// Nodes whose children were relocated to a single page because the
    /// fanout (unique child page count) exceeded
    /// `max_children_pages_threshold`. PLAN-144 TASK-148; mirrors Go's
    /// `CommitStats.FanoutReallocatedNodeCount`.
    pub fanout_reallocated_node_count: usize,
    /// Nodes relocated by the per-page fill-factor pass — pages whose
    /// fill factor fell below `target_page_fill_factor` had every node
    /// moved onto fresh tail pages. Mirrors Go's
    /// `CommitStats.PackingReallocatedNodeCount`.
    pub packing_reallocated_node_count: usize,
}

// ---------------------------------------------------------------------------
// MerkleTrieCache
// ---------------------------------------------------------------------------

/// Page-grouped node store with dirty tracking and LRU eviction.
///
/// Replaces the `HashMap<u64, TrieNode>` that earlier revisions of
/// `MerkleTrie` used as a flat node store. Each node lives in the page
/// computed as `id / nodes_per_page`; modifications dirty the containing
/// page, and `commit` flushes only the dirty pages.
///
/// The cache itself is committer-agnostic: any [`PageCommitter`] (SQLite
/// or in-memory) can drive the persistence. Tries that intend to lazy-
/// load pages on demand install an owned [`PageCommitter`] via the
/// `lazy_loader` field; without one, a cache miss returns `Ok(None)`.
pub struct MerkleTrieCache {
    /// `page_id -> { node_id -> TrieNode }`. The inner map is per-page so
    /// page-level operations (load, write, evict) are O(1) over the
    /// page's node count.
    pages: HashMap<u64, HashMap<u64, TrieNode>>,
    /// Next node id to allocate. Begins at [`FIRST_NODE_ID`].
    next_node_id: u64,
    /// `next_node_id` at the time of the last commit. Used to decide
    /// whether a page was created since the last commit (pages whose
    /// nodes are all in the `> last_committed_node_id` range are "new"
    /// and may be created from scratch; older pages are "updated" — see
    /// [`MerkleTrieCache::commit`].
    last_committed_node_id: u64,
    /// Constant for this cache's lifetime — bounded by the persisted
    /// metadata so a load+commit cycle preserves page IDs.
    nodes_per_page: u64,
    /// IDs created since the last commit, regardless of page. Used to
    /// distinguish "the page contains a brand-new node we must store"
    /// from "the page is in-memory but unchanged", AND to drive the
    /// silent-delete fast-path in [`MerkleTrieCache::delete`] for nodes
    /// that were never persisted.
    pending_created: HashSet<u64>,
    /// Pages with at least one created OR mutated-in-place node since the
    /// last commit. This is the commit write-set: a page is written iff
    /// it appears here. Populated by `allocate` (newly-created nodes)
    /// and `get_mut` (any in-place mutation of an already-cached node);
    /// the latter is critical for `recompute_all_hashes` writing SHA
    /// values back to pre-existing internal nodes via `get_mut`.
    pending_dirty_pages: HashSet<u64>,
    /// Pages that had at least one node removed since the last commit.
    /// On commit, these become either DELETE rows (page is now empty)
    /// or UPDATE rows (page still has live nodes).
    pending_deletion_pages: HashSet<u64>,
    /// LRU order: front = most recently used, back = least recently used.
    /// `evict` removes from the back until the cached node count fits.
    pages_priority: VecDeque<u64>,
    pages_priority_set: HashSet<u64>,
    /// In-memory node count across all pages — kept in sync with
    /// `pages` mutations so `evict` doesn't have to walk every page.
    cached_node_count: usize,
    /// Eviction target. After commit, pages are evicted from the LRU
    /// back until `cached_node_count <= cached_node_count_target`.
    /// `SqliteLedger::commit_block` invokes [`MerkleTrieCache::evict`]
    /// after every commit; the lazy loader installed by
    /// [`crate::merkle_trie::MerkleTrie::load`] re-fetches evicted
    /// pages on demand.
    cached_node_count_target: usize,
    /// Optional owned loader installed by [`crate::merkle_trie::MerkleTrie::load`].
    /// When present, [`MerkleTrieCache::get`] / [`MerkleTrieCache::get_mut`]
    /// lazy-fetch missing pages through this committer. When `None`,
    /// a cache miss simply returns `Ok(None)`.
    ///
    /// No `Send` bound — see module docs.
    lazy_loader: Option<Box<dyn PageCommitter + Send>>,
    /// Target fill factor for committed pages. The
    /// `reallocate_pending_pages` pass (called by `commit`) repacks any
    /// newly-created page whose fill factor falls below this value.
    /// PLAN-144 TASK-148; mirrors Go's `MemoryConfig.PageFillFactor`.
    target_page_fill_factor: f32,
    /// Maximum number of distinct child pages a single internal node
    /// may reference before its children are relocated onto a fresh
    /// page. PLAN-144 TASK-148; mirrors Go's
    /// `MemoryConfig.MaxChildrenPagesThreshold`.
    max_children_pages_threshold: u64,
}

impl std::fmt::Debug for MerkleTrieCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleTrieCache")
            .field("page_count", &self.pages.len())
            .field("next_node_id", &self.next_node_id)
            .field("last_committed_node_id", &self.last_committed_node_id)
            .field("nodes_per_page", &self.nodes_per_page)
            .field("cached_node_count", &self.cached_node_count)
            .field("cached_node_count_target", &self.cached_node_count_target)
            .field("pending_created_count", &self.pending_created.len())
            .field("pending_dirty_pages_count", &self.pending_dirty_pages.len())
            .field(
                "pending_deletion_pages_count",
                &self.pending_deletion_pages.len(),
            )
            .field("has_lazy_loader", &self.lazy_loader.is_some())
            .finish()
    }
}

impl Default for MerkleTrieCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTrieCache {
    /// Construct an empty cache with the default eviction target.
    pub fn new() -> Self {
        Self::with_target(DEFAULT_CACHED_NODES_TARGET)
    }

    /// Construct an empty cache with a custom eviction target.
    pub fn with_target(target: usize) -> Self {
        Self {
            pages: HashMap::new(),
            next_node_id: FIRST_NODE_ID,
            last_committed_node_id: FIRST_NODE_ID,
            nodes_per_page: NODES_PER_PAGE,
            pending_created: HashSet::new(),
            pending_dirty_pages: HashSet::new(),
            pending_deletion_pages: HashSet::new(),
            pages_priority: VecDeque::new(),
            pages_priority_set: HashSet::new(),
            cached_node_count: 0,
            cached_node_count_target: target,
            lazy_loader: None,
            target_page_fill_factor: DEFAULT_PAGE_FILL_FACTOR,
            max_children_pages_threshold: DEFAULT_MAX_CHILDREN_PAGES_THRESHOLD,
        }
    }

    /// Set the in-memory node-count target used by [`MerkleTrieCache::evict`].
    /// Production calls this on every load to apply
    /// `SqliteLedger::trie_cache_target` (default
    /// [`DEFAULT_CACHED_NODES_TARGET`]). Tests use a small value
    /// (e.g. 200) to make the eviction path testable.
    pub fn set_cache_target(&mut self, target: usize) {
        self.cached_node_count_target = target;
    }

    /// Read-only view of the eviction target (for tests + diagnostics).
    pub fn cache_target(&self) -> usize {
        self.cached_node_count_target
    }

    /// Install an owned page committer as the cache's lazy loader.
    /// Called by [`crate::merkle_trie::MerkleTrie::load`] immediately
    /// after reading the metadata page, so subsequent `get` / `get_mut`
    /// can on-demand fetch pages instead of requiring an eager
    /// `load_all` pass.
    pub fn set_lazy_loader(&mut self, loader: Box<dyn PageCommitter + Send>) {
        self.lazy_loader = Some(loader);
    }

    /// True iff this cache has an installed lazy loader. Used by tests
    /// + diagnostics; production code should not branch on this.
    pub fn has_lazy_loader(&self) -> bool {
        self.lazy_loader.is_some()
    }

    /// Page that holds node `id` under the configured page size.
    #[inline]
    pub fn page_of(&self, id: u64) -> u64 {
        id / self.nodes_per_page
    }

    /// Next-id to be allocated (read-only).
    #[inline]
    pub fn next_node_id(&self) -> u64 {
        self.next_node_id
    }

    /// Allocate a new node and return its id. Mirrors Go's
    /// `merkleTrieCache::allocateNewNode` (`cache.go:122-136`).
    pub fn allocate(&mut self, node: TrieNode) -> u64 {
        let id = self.next_node_id;
        self.next_node_id += 1;
        let page = self.page_of(id);
        self.pages.entry(page).or_default().insert(id, node);
        self.cached_node_count += 1;
        self.pending_created.insert(id);
        self.pending_dirty_pages.insert(page);
        self.prioritize_front(page);
        id
    }

    /// Recycle node `old_id`'s storage to a freshly-allocated id at
    /// `next_node_id`. Mirrors Go's `merkleTrieCache::refurbishNode`
    /// (`cache.go:139-164`). PLAN-144 TASK-149.
    ///
    /// Semantics:
    /// - If `old_id` is in `pending_created` (never reached disk), the
    ///   old node + page entry are dropped silently — no deletion
    ///   record is needed.
    /// - Otherwise (old_id is committed), the old slot is removed from
    ///   the page map and the page is marked in `pending_deletion_pages`
    ///   so the next commit will partition it correctly (update vs
    ///   delete depending on remaining nodes).
    ///
    /// In both cases the in-memory `TrieNode` value is moved to the
    /// new id (no clone of `hash` / `children` Vecs), which is the
    /// heap-churn win refurbish exists for.
    ///
    /// Panics if `old_id` is not currently resident — refurbish is
    /// only called on nodes the caller just touched (either via
    /// `allocate` or `get_mut`), so a miss is a logic bug.
    pub fn refurbish(&mut self, old_id: u64) -> u64 {
        let old_page = self.page_of(old_id);
        let node = self
            .pages
            .get_mut(&old_page)
            .and_then(|m| m.remove(&old_id))
            .unwrap_or_else(|| panic!("MerkleTrieCache::refurbish: node {old_id} not resident"));

        if self.pending_created.remove(&old_id) {
            // Old id never went to disk — drop its slot silently.
            // cached_node_count drops by 1; we'll bump it back by 1
            // when we insert at new_id, so the net is conserved.
            self.cached_node_count -= 1;
            if self.pages.get(&old_page).is_some_and(|m| m.is_empty()) {
                self.pages.remove(&old_page);
                self.remove_from_priority(old_page);
                self.pending_dirty_pages.remove(&old_page);
            }
        } else {
            // Old id is committed; record the page so the next commit
            // partitions it correctly. The node is gone from the page
            // map but the page itself may still hold other live nodes.
            self.cached_node_count -= 1;
            self.pending_deletion_pages.insert(old_page);
        }

        let new_id = self.next_node_id;
        self.next_node_id += 1;
        let new_page = self.page_of(new_id);
        self.pages.entry(new_page).or_default().insert(new_id, node);
        self.cached_node_count += 1;
        self.pending_created.insert(new_id);
        self.pending_dirty_pages.insert(new_page);
        self.prioritize_front(new_page);
        new_id
    }

    /// Remove node `id` from the cache. Mirrors Go's
    /// `merkleTrieCache::deleteNode` (`cache.go:272-285`).
    pub fn delete(&mut self, id: u64) {
        let page = self.page_of(id);
        if self.pending_created.remove(&id) {
            // Never committed yet — drop in place without persisting a
            // deletion. Page may also drop entirely if this was its
            // only node.
            if let Some(page_map) = self.pages.get_mut(&page) {
                if page_map.remove(&id).is_some() {
                    self.cached_node_count -= 1;
                }
                if page_map.is_empty() {
                    self.pages.remove(&page);
                    self.remove_from_priority(page);
                }
            }
        } else {
            // Already committed — mark the page dirty (DELETE-or-UPDATE
            // decision happens at commit time).
            if let Some(page_map) = self.pages.get_mut(&page) {
                if page_map.remove(&id).is_some() {
                    self.cached_node_count -= 1;
                }
            }
            self.pending_deletion_pages.insert(page);
        }
    }

    /// Borrow node `id`. Lazy-loads its containing page on miss when a
    /// `lazy_loader` is installed. Mirrors Go's
    /// `merkleTrieCache::getNode` (`cache.go:166-203`).
    ///
    /// Returns:
    /// - `Ok(Some(&node))` — node is (now) in memory.
    /// - `Ok(None)` — node is genuinely absent: either no `lazy_loader`,
    ///   or the page doesn't exist in the committer.
    /// - `Err(_)` — committer returned an error (e.g. SQLite I/O fail).
    pub fn get(&mut self, id: u64) -> Result<Option<&TrieNode>, AlgoError> {
        let page = self.page_of(id);
        if self.pages.contains_key(&page) && self.pages[&page].contains_key(&id) {
            self.prioritize_front(page);
            return Ok(self.pages.get(&page).and_then(|p| p.get(&id)));
        }
        // Miss — attempt lazy load.
        self.try_lazy_load_page(page)?;
        Ok(self.pages.get(&page).and_then(|p| p.get(&id)))
    }

    /// Borrow node `id` mutably. Lazy-loads on miss. Marks the
    /// containing page as dirty — any caller that holds a mutable borrow
    /// may modify fields that participate in the persisted page bytes
    /// (notably `hash`, set by `MerkleTrie::recompute_all_hashes` for
    /// previously-loaded internal nodes), so the page must be included
    /// in the next commit's write set. Conservative-dirty is the only
    /// safe default; we can't ask the borrow what it intends to do.
    pub fn get_mut(&mut self, id: u64) -> Result<Option<&mut TrieNode>, AlgoError> {
        let page = self.page_of(id);
        if !self.pages.contains_key(&page) || !self.pages[&page].contains_key(&id) {
            self.try_lazy_load_page(page)?;
        }
        if !self.pages.contains_key(&page) || !self.pages[&page].contains_key(&id) {
            return Ok(None);
        }
        self.prioritize_front(page);
        self.pending_dirty_pages.insert(page);
        Ok(self.pages.get_mut(&page).and_then(|p| p.get_mut(&id)))
    }

    /// On a cache miss, try to load `page` via the installed lazy
    /// loader. No-op when the loader is absent. Returns `Ok(())` on
    /// success or when the loader is absent; propagates I/O errors.
    fn try_lazy_load_page(&mut self, page: u64) -> Result<(), AlgoError> {
        if self.pages.contains_key(&page) {
            // Already in memory — load_page would be redundant.
            return Ok(());
        }
        let loader = match self.lazy_loader.as_ref() {
            Some(l) => l,
            None => return Ok(()),
        };
        // Page 0 is metadata, not nodes — never lazy-load it as a node
        // page (it has its own dedicated reader).
        if page == 0 {
            return Ok(());
        }
        let Some(bytes) = loader.load_page(page)? else {
            return Ok(());
        };
        if bytes.is_empty() {
            return Ok(());
        }
        let decoded = Page::deserialize(&bytes)?;
        let page_map: HashMap<u64, TrieNode> = decoded
            .nodes
            .into_iter()
            .map(|(nid, pn)| (nid, page_node_to_trie_node(pn)))
            .collect();
        self.cached_node_count += page_map.len();
        self.pages.insert(page, page_map);
        self.prioritize_front(page);
        Ok(())
    }

    /// True iff node `id` is in memory **right now** (no lazy load).
    /// Used by tests + diagnostics; the trie's algorithms always go
    /// through `get` / `get_mut` so they see lazy-loaded pages.
    pub fn contains_in_memory(&self, id: u64) -> bool {
        self.pages
            .get(&self.page_of(id))
            .is_some_and(|p| p.contains_key(&id))
    }

    /// Total node count across all in-memory pages.
    pub fn cached_node_count(&self) -> usize {
        self.cached_node_count
    }

    /// Count of leaf nodes across the cache (used by `MerkleTrie::len`).
    /// Counts only **in-memory** leaves — for a lazily-loaded trie the
    /// returned value is a lower bound on the persisted leaf count until
    /// the cache is fully populated. The trie's `len()` documents this.
    pub fn leaf_count(&self) -> usize {
        self.pages
            .values()
            .flat_map(|p| p.values())
            .filter(|n| n.is_leaf())
            .count()
    }

    // -----------------------------------------------------------------------
    // LRU bookkeeping
    // -----------------------------------------------------------------------

    fn prioritize_front(&mut self, page: u64) {
        if self.pages_priority_set.contains(&page) {
            // Already in the list — move to front. O(n) over the priority
            // list length, which is the unique-pages-in-memory count.
            // Acceptable for the cache sizes we expect; can switch to an
            // intrusive linked list (Go's container/list) if profiling
            // shows this is hot.
            if let Some(pos) = self.pages_priority.iter().position(|&p| p == page) {
                self.pages_priority.remove(pos);
            }
        } else {
            self.pages_priority_set.insert(page);
        }
        self.pages_priority.push_front(page);
    }

    fn remove_from_priority(&mut self, page: u64) {
        if self.pages_priority_set.remove(&page) {
            if let Some(pos) = self.pages_priority.iter().position(|&p| p == page) {
                self.pages_priority.remove(pos);
            }
        }
    }

    /// Evict least-recently-used pages until the cached node count drops
    /// to `cached_node_count_target`. The page containing the trie root
    /// is pinned (front of the priority list) so it's never evicted —
    /// mirrors Go's `cache.go:708-731`.
    ///
    /// Returns the number of pages evicted.
    ///
    /// **Safe usage:** evicted pages are now only on disk; subsequent
    /// `get` / `get_mut` for evicted nodes will lazy-load them back
    /// through the installed [`PageCommitter`] (PLAN-144 TASK-146).
    /// Without a lazy loader, evicted pages effectively vanish — calls
    /// will return `Ok(None)`, which downstream algorithms will surface
    /// as missing-node errors.
    ///
    /// Caller must guarantee no dirty pages remain (i.e. `commit` was
    /// called immediately before, or the cache is read-only) — evicting
    /// a dirty page would lose data. The wrapper
    /// [`crate::merkle_trie::MerkleTrie::evict`] enforces this.
    ///
    /// Wired into `SqliteLedger::commit_block` (PLAN-144 TASK-147).
    pub fn evict(&mut self, root_id: Option<u64>) -> usize {
        // Pin the root page at the front.
        let root_page = root_id.map(|rid| self.page_of(rid));
        if let Some(rp) = root_page {
            if self.pages_priority_set.contains(&rp) {
                if let Some(pos) = self.pages_priority.iter().position(|&p| p == rp) {
                    self.pages_priority.remove(pos);
                }
                self.pages_priority.push_front(rp);
            }
        }

        let mut evicted = 0;
        while self.cached_node_count > self.cached_node_count_target {
            // Peek the back; if it's the pinned root page, stop — the
            // "pin" must hold even when the root is the only page left
            // (otherwise root_hash + algorithm traversal would panic).
            // Mirrors Go's invariant at `cache.go:710-716` that the root
            // page never appears in the eviction back-pop.
            let Some(&back_page) = self.pages_priority.back() else {
                break;
            };
            if Some(back_page) == root_page {
                break;
            }
            self.pages_priority.pop_back();
            self.pages_priority_set.remove(&back_page);
            if let Some(page_map) = self.pages.remove(&back_page) {
                self.cached_node_count -= page_map.len();
                evicted += 1;
            }
        }
        evicted
    }

    // -----------------------------------------------------------------------
    // Commit + load
    // -----------------------------------------------------------------------

    /// Persist all dirty pages, then write the root-metadata page.
    ///
    /// `root_id` is `None` for an empty trie; in that case the metadata
    /// page records root = 0 (matching Go's `storedNodeIdentifierNull`
    /// sentinel). Mirrors Go's `merkleTrieCache::commit` (`cache.go:356-423`)
    /// followed by `Trie::Commit` writing the metadata page
    /// (`trie.go:224-231`).
    pub fn commit<C: PageCommitter>(
        &mut self,
        root_id: &mut Option<u64>,
        element_length: usize,
        committer: &C,
    ) -> Result<CommitStats, AlgoError> {
        // PLAN-144 TASK-148: full port of go-algorand's
        // `reallocatePendingPages` (cache.go:425-530) + helpers. The
        // trie has already recomputed hashes via `recompute_all_hashes`
        // before this call, so the reallocation pass below only
        // restructures page layout — child IDs change, hashes do not.
        let mut stats = CommitStats::default();
        let (pages_to_create, pages_to_delete, pages_to_update) =
            self.reallocate_pending_pages(root_id, &mut stats);

        // Write created + updated pages.
        let mut write_page = |page_id: u64, is_create: bool| -> Result<(), AlgoError> {
            let nodes = match self.pages.get(&page_id) {
                Some(p) if !p.is_empty() => p,
                _ => return Ok(()),
            };
            let mut wire = Page::new();
            let node_count = nodes.len();
            for (&nid, node) in nodes {
                wire.nodes.insert(nid, trie_node_to_page_node(node));
            }
            let bytes = wire.serialize();
            committer.store_page(page_id, &bytes)?;
            if is_create {
                stats.new_page_count += 1;
                stats.new_node_count += node_count;
            } else {
                stats.updated_page_count += 1;
                stats.updated_node_count += node_count;
            }
            Ok(())
        };
        for &page in &pages_to_create {
            write_page(page, true)?;
        }
        for &page in &pages_to_update {
            write_page(page, false)?;
        }

        // Delete pages — empty store_page payload signals delete.
        for &page in &pages_to_delete {
            committer.store_page(page, &[])?;
            self.pages.remove(&page);
            self.remove_from_priority(page);
            stats.deleted_page_count += 1;
        }

        // Write root-metadata page (page 0). `*root_id` reflects any
        // root relocation performed by `reallocate_pending_pages`.
        self.write_metadata_page(*root_id, element_length, committer)?;

        // Reset dirty tracking.
        self.pending_created.clear();
        self.pending_dirty_pages.clear();
        self.pending_deletion_pages.clear();
        self.last_committed_node_id = self.next_node_id;

        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // PLAN-144 TASK-148: page-packing heuristic.
    //
    // Mirrors go-algorand's `crypto/merkletrie/cache.go::reallocatePendingPages`
    // (cache.go:425-530) and its helpers `calculatePageHashes`,
    // `getPageFillFactor`, `reallocatePage`, `reallocateNode`. The Rust
    // version is split into two passes the way Go's combined function
    // operates internally:
    //
    //   Pass A — fanout-driven child relocation.
    //     For each newly-created page in ascending order, walk its
    //     pending-created nodes in id-ascending order; for any internal
    //     node whose fanout (unique child page count) exceeds
    //     `max_children_pages_threshold`, relocate every child onto a
    //     single fresh tail page. (Hashes do NOT need re-computation —
    //     the parent's hash is over child *hashes*, not child IDs.)
    //
    //   Pass B — per-page fill-factor repack.
    //     For each newly-created page whose fill factor is below
    //     `target_page_fill_factor`, relocate every node on the page
    //     onto fresh tail pages. Old→new IDs are recorded in
    //     `reallocation_map`; parents have their child IDs remapped at
    //     the end of the pass.
    //
    // The caller (`commit`) writes the (pagesToCreate, pagesToDelete,
    // pagesToUpdate) triplet returned here through the committer.
    // -----------------------------------------------------------------------

    /// See module-level comment above. Mutates `root_id` if the root
    /// node itself was relocated. Updates `self.pages`,
    /// `self.next_node_id`, `self.pending_deletion_pages` as a side
    /// effect; the returned page sets reference the post-reallocation
    /// page IDs.
    fn reallocate_pending_pages(
        &mut self,
        root_id: &mut Option<u64>,
        stats: &mut CommitStats,
    ) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
        // newPageThreshold: pages with id >= this are "new" (created
        // since the last commit). Mirrors cache.go:430-433.
        let nodes_per_page = self.nodes_per_page;
        let mut new_page_threshold = self.last_committed_node_id / nodes_per_page;
        if self.last_committed_node_id % nodes_per_page > 0 {
            new_page_threshold += 1;
        }

        // Collect pages with at least one pending-created node.
        let mut created_pages: HashSet<u64> = HashSet::new();
        for &nid in &self.pending_created {
            created_pages.insert(nid / nodes_per_page);
        }
        let mut sorted_created: Vec<u64> = created_pages.iter().copied().collect();
        sorted_created.sort_unstable();

        // Advance next_node_id to the start of the next page so every
        // relocated node lands on a fresh tail page. Mirrors cache.go:452-453.
        self.next_node_id = self.next_node_id.div_ceil(nodes_per_page) * nodes_per_page;
        let reallocated_base_page = self.next_node_id / nodes_per_page;

        // Track pages created via relocation so the children-remap pass
        // touches them. Go uses `mtc.reallocatedPages` for this AND for
        // backing the page-map pointer; in Rust the page map lives in
        // `self.pages` and `reallocated_pages` is just the id set.
        let mut reallocated_pages: HashSet<u64> = HashSet::new();

        // Pass A — fanout-relocate-children on dirty internal nodes.
        // Mirrors `calculatePageHashes`'s fanout block (cache.go:550-564),
        // minus the hash computation (already done by the trie).
        for &page in &sorted_created {
            let is_new_page = page >= new_page_threshold;
            self.fanout_relocate_children_on_page(page, is_new_page, &mut reallocated_pages, stats);
        }

        // Pass B — per-page fill-factor repack.
        // Mirrors cache.go:469-484.
        let mut reallocation_map: HashMap<u64, u64> = HashMap::new();
        let mut pages_to_create: Vec<u64> = Vec::new();
        // Track which entries from `created_pages` survive the repack
        // (didn't get fully relocated away). Mirrors Go's
        // `createdPages` map mutation.
        let mut surviving_created: HashSet<u64> = sorted_created.iter().copied().collect();
        for &page in &sorted_created {
            if page < new_page_threshold {
                // Old page — fanout pass may have mutated it, but
                // repacking old pages is unnecessary (they were already
                // committed at their current layout).
                continue;
            }
            if self.get_page_fill_factor(page) >= self.target_page_fill_factor {
                if self.pages.get(&page).is_some_and(|m| !m.is_empty()) {
                    pages_to_create.push(page);
                }
                continue;
            }
            let count = self.reallocate_page(page, &mut reallocation_map, &mut reallocated_pages);
            stats.packing_reallocated_node_count += count;
            surviving_created.remove(&page);
        }

        // Remap child IDs across all surviving created pages AND
        // reallocated tail pages. Go folds this with `maps.Copy` then a
        // single iteration; we iterate the union directly.
        let pages_to_remap: HashSet<u64> = surviving_created
            .union(&reallocated_pages)
            .copied()
            .collect();
        for &p in &pages_to_remap {
            let node_ids: Vec<u64> = self
                .pages
                .get(&p)
                .map(|m| m.keys().copied().collect())
                .unwrap_or_default();
            for nid in node_ids {
                if let Some(node) = self.pages.get_mut(&p).and_then(|m| m.get_mut(&nid)) {
                    // Mirrors node.remapChildren (node.go:393-403): chase
                    // chains and delete-on-use so repeat lookups don't
                    // re-apply.
                    for child in node.children.iter_mut() {
                        while let Some(&new_id) = reallocation_map.get(&child.child_id) {
                            child.child_id = new_id;
                        }
                    }
                }
            }
        }

        // Root relocation. Mirrors cache.go:494-497.
        if let Some(rid) = *root_id {
            if let Some(&new_root) = reallocation_map.get(&rid) {
                *root_id = Some(new_root);
                reallocation_map.remove(&rid);
            }
        }

        // toRemovePages = pendingDeletionPages, plus mark the FIRST
        // created page as a removal candidate (it may have been emptied
        // by fanout / repack). Then walk and demote anything still
        // holding nodes back into the update set. Mirrors cache.go:500-527.
        let mut to_remove: HashSet<u64> = self.pending_deletion_pages.iter().copied().collect();
        if let Some(&first) = sorted_created.first() {
            if self.pages.contains_key(&first) {
                to_remove.insert(first);
            }
        }

        // Continue picking up reallocated tail pages into pages_to_create
        // (in ascending order from reallocated_base_page).
        let mut p = reallocated_base_page;
        loop {
            match self.pages.get(&p) {
                Some(m) if !m.is_empty() => {
                    if reallocated_pages.contains(&p) {
                        pages_to_create.push(p);
                    }
                    p += 1;
                }
                _ => break,
            }
        }

        // Partition to_remove into true deletes vs. updates (page still
        // has nodes → demote to update).
        let mut pages_to_delete: Vec<u64> = Vec::new();
        let mut pages_to_update: Vec<u64> = Vec::new();
        for &page in &to_remove {
            match self.pages.get(&page) {
                Some(m) if !m.is_empty() => pages_to_update.push(page),
                _ => pages_to_delete.push(page),
            }
        }

        // Catch mutations to previously-committed nodes (via
        // `get_mut`) that weren't already covered by the
        // pending_created path. Production add/delete always CoW so
        // this set is normally empty, but `get_node_mut` is a public
        // escape hatch (used by tests + the trie's
        // `recompute_all_hashes` for re-hashing internal nodes after
        // structural changes), so we must persist any page it touched.
        let handled: HashSet<u64> = pages_to_create
            .iter()
            .copied()
            .chain(pages_to_delete.iter().copied())
            .chain(pages_to_update.iter().copied())
            .chain(reallocated_pages.iter().copied())
            .chain(sorted_created.iter().copied())
            .collect();
        for &page in &self.pending_dirty_pages {
            if !handled.contains(&page) && self.pages.get(&page).is_some_and(|m| !m.is_empty()) {
                pages_to_update.push(page);
            }
        }

        // Stable ordering for deterministic commit output (helps the
        // page-count test be reproducible across runs).
        pages_to_create.sort_unstable();
        pages_to_create.dedup();
        pages_to_delete.sort_unstable();
        pages_to_delete.dedup();
        pages_to_update.sort_unstable();
        pages_to_update.dedup();

        (pages_to_create, pages_to_delete, pages_to_update)
    }

    /// Per-page fanout check + child relocation. Mirrors the fanout
    /// block of `calculatePageHashes` (cache.go:550-564). Walks nodes
    /// on `page` in id-ascending order; for any internal node whose
    /// unique child page count exceeds the threshold, relocate every
    /// child onto a single fresh tail page (possibly bumping
    /// `next_node_id` to a page boundary first).
    fn fanout_relocate_children_on_page(
        &mut self,
        page: u64,
        is_new_page: bool,
        reallocated_pages: &mut HashSet<u64>,
        stats: &mut CommitStats,
    ) {
        // Collect node ids on the page in ascending order.
        let mut node_ids: Vec<u64> = self
            .pages
            .get(&page)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        node_ids.sort_unstable();

        for nid in node_ids {
            if !is_new_page && !self.pending_created.contains(&nid) {
                continue;
            }
            // Read child count + unique-page count from a borrow that
            // ends before we mutate.
            let (child_count, unique_pages, child_ids) = {
                let Some(node) = self.pages.get(&page).and_then(|m| m.get(&nid)) else {
                    continue;
                };
                if node.is_leaf() {
                    continue;
                }
                let cc = node.children.len() as u64;
                let mut up: HashSet<u64> = HashSet::with_capacity(node.children.len());
                let mut cids = Vec::with_capacity(node.children.len());
                for c in &node.children {
                    up.insert(c.child_id / self.nodes_per_page);
                    cids.push(c.child_id);
                }
                (cc, up.len() as u64, cids)
            };

            if child_count <= self.max_children_pages_threshold
                || unique_pages <= self.max_children_pages_threshold
            {
                continue;
            }

            // Optionally bump next_node_id to a fresh page so all
            // relocated children land on the same page. Mirrors
            // cache.go:556-560: only bump if (a) the children fit on a
            // single page and (b) the current next page is at/over the
            // target fill factor.
            if child_count < self.nodes_per_page
                && self.get_page_fill_factor(self.next_node_id / self.nodes_per_page)
                    > self.target_page_fill_factor
            {
                self.next_node_id =
                    (1 + self.next_node_id / self.nodes_per_page) * self.nodes_per_page;
            }

            // Relocate every child via `reallocate_node`. Mirrors
            // node.reallocateChildren (node.go:383-387).
            let mut new_child_ids = Vec::with_capacity(child_ids.len());
            for cid in &child_ids {
                new_child_ids.push(self.reallocate_node(*cid, reallocated_pages));
            }

            // Write the new ids back into the parent node.
            if let Some(node) = self.pages.get_mut(&page).and_then(|m| m.get_mut(&nid)) {
                for (i, new_cid) in new_child_ids.into_iter().enumerate() {
                    node.children[i].child_id = new_cid;
                }
            }
            stats.fanout_reallocated_node_count += 1;
        }
    }

    /// Per-page fill factor: `live_nodes / nodes_per_page`. Returns 0.0
    /// when the page is not in memory. Mirrors `getPageFillFactor`
    /// (cache.go:570-575).
    fn get_page_fill_factor(&self, page: u64) -> f32 {
        match self.pages.get(&page) {
            Some(m) => (m.len() as f32) / (self.nodes_per_page as f32),
            None => 0.0,
        }
    }

    /// Bulk-relocate every node on `page` onto fresh tail pages
    /// starting at `next_node_id`. Records old→new IDs in
    /// `reallocation_map`. Returns the number of nodes moved. Mirrors
    /// `reallocatePage` (cache.go:577-622).
    fn reallocate_page(
        &mut self,
        page: u64,
        reallocation_map: &mut HashMap<u64, u64>,
        reallocated_pages: &mut HashSet<u64>,
    ) -> usize {
        let next_id_start = self.next_node_id;
        let count = self.pages.get(&page).map(|m| m.len()).unwrap_or(0);
        if count == 0 {
            self.pages.remove(&page);
            reallocated_pages.remove(&page);
            self.remove_from_priority(page);
            return 0;
        }

        // Decide whether the new id range will write into an already-
        // occupied page. Mirrors cache.go:589-598's nextPage-vs-lastPage
        // logic — if the leading page collides AND the trailing page
        // does not, jump to the trailing page; if both collide, use a
        // sentinel ("skip page allocation") and rely on per-id
        // insertion below.
        //
        // Implementation note: we ALWAYS insert nodes into
        // `self.pages.entry(cur_page).or_default()` per id (the loop
        // below), so the up-front page allocation is purely for the LRU
        // bookkeeping / reallocated_pages tracking. The skip-sentinel
        // ('SKIP') path means we'll just let the per-id loop allocate
        // pages lazily without an explicit empty entry.
        let mut next_page = next_id_start / self.nodes_per_page;
        let mut skip_explicit_alloc = false;
        if self.pages.contains_key(&next_page) {
            let last_id = next_id_start + count as u64 - 1;
            let last_page = last_id / self.nodes_per_page;
            if !self.pages.contains_key(&last_page) {
                next_page = last_page;
            } else {
                skip_explicit_alloc = true;
            }
        }
        if !skip_explicit_alloc {
            self.pages.entry(next_page).or_default();
            reallocated_pages.insert(next_page);
            self.prioritize_front(next_page);
        }

        // Drain nodes off the old page in id-ascending order so the
        // new id stream is deterministic.
        let mut old_nodes: Vec<(u64, TrieNode)> = self
            .pages
            .remove(&page)
            .map(|m| m.into_iter().collect())
            .unwrap_or_default();
        old_nodes.sort_by_key(|(id, _)| *id);
        self.next_node_id += count as u64;

        for (i, (old_id, node)) in old_nodes.into_iter().enumerate() {
            let cur_id = next_id_start + i as u64;
            reallocation_map.insert(old_id, cur_id);
            let cur_page = cur_id / self.nodes_per_page;
            // Note: cached_node_count is conserved across moves — we're
            // not adding or removing nodes, just changing their pages.
            self.pages.entry(cur_page).or_default().insert(cur_id, node);
            reallocated_pages.insert(cur_page);
            self.prioritize_front(cur_page);
        }

        // Old page is now empty; drop from LRU + reallocated set.
        self.remove_from_priority(page);
        reallocated_pages.remove(&page);
        count
    }

    /// Move a single node onto the latest tail page; bumps
    /// `next_node_id`. No-op when the node is already on the tail page.
    /// Mirrors `reallocateNode` (cache.go:624-658).
    fn reallocate_node(&mut self, nid: u64, reallocated_pages: &mut HashSet<u64>) -> u64 {
        let next_id = self.next_node_id;
        let next_page = next_id / self.nodes_per_page;
        let current_page = nid / self.nodes_per_page;
        if current_page == next_page {
            return nid;
        }

        // Extract the node from its current page. We don't go through
        // `delete()` because that touches `pending_created` /
        // `pending_deletion_pages` and would treat this as a logical
        // deletion. A relocation is a move; cached_node_count is
        // conserved.
        let Some(page_map) = self.pages.get_mut(&current_page) else {
            // Defensive: nothing to move. This shouldn't happen given
            // the caller iterates known children, but bail rather than
            // corrupt the cache.
            return nid;
        };
        let Some(node) = page_map.remove(&nid) else {
            return nid;
        };
        if page_map.is_empty() {
            self.pages.remove(&current_page);
            reallocated_pages.remove(&current_page);
            self.remove_from_priority(current_page);
        }
        self.pending_deletion_pages.insert(current_page);

        self.next_node_id += 1;
        self.pages
            .entry(next_page)
            .or_default()
            .insert(next_id, node);
        reallocated_pages.insert(next_page);
        self.prioritize_front(next_page);
        next_id
    }

    fn write_metadata_page<C: PageCommitter>(
        &self,
        root_id: Option<u64>,
        element_length: usize,
        committer: &C,
    ) -> Result<(), AlgoError> {
        // Format (matches Go `trie.go:251-258`):
        //   uvarint merkleTreeVersion
        //   uvarint root (0 = null)
        //   uvarint nextNodeID
        //   uvarint elementLength
        //   uvarint nodesPerPage
        let mut buf = Vec::with_capacity(64);
        write_uvarint(&mut buf, MERKLE_TREE_VERSION);
        write_uvarint(&mut buf, root_id.unwrap_or(0));
        write_uvarint(&mut buf, self.next_node_id);
        write_uvarint(&mut buf, element_length as u64);
        write_uvarint(&mut buf, self.nodes_per_page);
        committer.store_page(0, &buf)
    }

    /// Read the root-metadata page if present. Returns a [`TrieMetadata`]
    /// when page 0 exists, or `Ok(None)` when it doesn't (fresh DB).
    pub fn read_metadata_page<C: PageCommitter + ?Sized>(
        committer: &C,
    ) -> Result<Option<TrieMetadata>, AlgoError> {
        let Some(bytes) = committer.load_page(0)? else {
            return Ok(None);
        };
        if bytes.is_empty() {
            return Ok(None);
        }

        let mut cursor = 0usize;
        let (version, n) = read_uvarint(&bytes, cursor).ok_or_else(|| AlgoError::Ledger {
            message: "merkle trie metadata page: truncated version varint".into(),
        })?;
        cursor += n;
        if version != MERKLE_TREE_VERSION {
            return Err(AlgoError::Ledger {
                message: format!(
                    "merkle trie metadata page: unsupported version 0x{version:016x} (expected 0x{MERKLE_TREE_VERSION:016x})"
                ),
            });
        }
        let (root_raw, n) = read_uvarint(&bytes, cursor).ok_or_else(|| AlgoError::Ledger {
            message: "merkle trie metadata page: truncated root varint".into(),
        })?;
        cursor += n;
        let (next_node_id, n) = read_uvarint(&bytes, cursor).ok_or_else(|| AlgoError::Ledger {
            message: "merkle trie metadata page: truncated next-node-id varint".into(),
        })?;
        cursor += n;
        let (element_length, n) =
            read_uvarint(&bytes, cursor).ok_or_else(|| AlgoError::Ledger {
                message: "merkle trie metadata page: truncated element-length varint".into(),
            })?;
        cursor += n;
        let (nodes_per_page, _) =
            read_uvarint(&bytes, cursor).ok_or_else(|| AlgoError::Ledger {
                message: "merkle trie metadata page: truncated nodes-per-page varint".into(),
            })?;

        let root = if root_raw == 0 { None } else { Some(root_raw) };
        Ok(Some(TrieMetadata {
            root,
            next_node_id,
            element_length: element_length as usize,
            nodes_per_page,
        }))
    }

    /// **Metadata-only stub** (PLAN-144 TASK-146): record the post-load
    /// `next_node_id` and `last_committed_node_id` from the persisted
    /// metadata. No pages are read here — subsequent `get` / `get_mut`
    /// calls lazy-load pages through the installed
    /// [`MerkleTrieCache::lazy_loader`].
    ///
    /// This replaces the prior eager iteration over every page id from
    /// `FIRST_NODE_ID / nodes_per_page` up to `next_node_id /
    /// nodes_per_page`. The eager path was simpler but forced an O(N)
    /// read at every `MerkleTrie::load` (the cold-load phase of the
    /// PLAN-144 trie bench measured this as ~20× Go's `MakeTrie`).
    pub fn load_metadata_only(&mut self, next_node_id: u64) {
        self.next_node_id = next_node_id;
        self.last_committed_node_id = next_node_id;
    }
}

// ---------------------------------------------------------------------------
// TrieNode <-> PageNode conversion
// ---------------------------------------------------------------------------

fn trie_node_to_page_node(node: &TrieNode) -> PageNode {
    if node.is_leaf() {
        PageNode::leaf(node.hash.clone())
    } else {
        // Translate trie::ChildEntry -> page::ChildEntry. They have the
        // same fields but live in different modules (the page format is
        // a serialization concern, the trie ChildEntry is a runtime
        // concern), so the conversion is by-field.
        let children: Vec<PageChildEntry> = node
            .children
            .iter()
            .map(|c| PageChildEntry {
                hash_index: c.hash_index,
                child_id: c.child_id,
            })
            .collect();
        PageNode::internal(node.hash.clone(), children)
    }
}

fn page_node_to_trie_node(node: PageNode) -> TrieNode {
    if node.is_leaf {
        TrieNode {
            hash: node.hash,
            children: Vec::new(),
            children_mask: Bitset::ZERO,
        }
    } else {
        let children: Vec<ChildEntry> = node
            .children
            .into_iter()
            .map(|c| ChildEntry {
                hash_index: c.hash_index,
                child_id: c.child_id,
            })
            .collect();
        let mut children_mask = Bitset::ZERO;
        for c in &children {
            children_mask.set_bit(c.hash_index);
        }
        TrieNode {
            hash: node.hash,
            children,
            children_mask,
        }
    }
}

// ---------------------------------------------------------------------------
// Varint helpers (LEB128 / Go `encoding/binary.Uvarint`).
// Duplicated from merkle_page.rs intentionally — that module's
// varint helpers are pub(crate)-scoped and intentional dependency
// between merkle_cache and merkle_page is one-way (cache consumes
// merkle_page's Page type; we don't want merkle_page importing cache).
// ---------------------------------------------------------------------------

fn write_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn read_uvarint(buf: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf[start..].iter().enumerate() {
        if i >= 10 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some((x | ((b as u64) << s), i + 1));
        }
        x |= ((b as u64) & 0x7f) << s;
        s += 7;
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_allocated_node_lives_on_page_144() {
        // FIRST_NODE_ID = 0x4160 = 16736; 16736 / 116 = 144.
        // Reproduce Go's page-id base so Rust-written DBs are
        // byte-compatible with go-algorand's accounthashes schema.
        let mut cache = MerkleTrieCache::new();
        let id = cache.allocate(TrieNode::leaf(vec![0u8; 36]));
        assert_eq!(id, FIRST_NODE_ID);
        assert_eq!(cache.page_of(id), 144);
    }

    #[test]
    fn allocate_then_get_returns_same_node() {
        let mut cache = MerkleTrieCache::new();
        let node = TrieNode::leaf(vec![1, 2, 3]);
        let id = cache.allocate(node.clone());
        let got = cache.get(id).unwrap().expect("just allocated");
        assert_eq!(got.hash, node.hash);
        assert!(got.is_leaf());
    }

    #[test]
    fn delete_pending_node_drops_from_cache() {
        let mut cache = MerkleTrieCache::new();
        let id = cache.allocate(TrieNode::leaf(vec![1; 4]));
        assert!(cache.contains_in_memory(id));
        cache.delete(id);
        assert!(!cache.contains_in_memory(id));
        // Page was created+removed entirely → no pending deletion to flush.
        assert!(cache.pending_deletion_pages.is_empty());
    }

    #[test]
    fn delete_committed_node_records_pending_deletion_page() {
        let mut cache = MerkleTrieCache::new();
        let id = cache.allocate(TrieNode::leaf(vec![1; 4]));

        let committer = InMemoryPageCommitter::new();
        let mut root = Some(id);
        cache.commit(&mut root, 4, &committer).unwrap();
        // After commit, no pending-created records remain.
        assert!(cache.pending_created.is_empty());

        // Allocate a second node (so deleting the first doesn't empty the page).
        let _id2 = cache.allocate(TrieNode::leaf(vec![2; 4]));
        cache.delete(id);
        // First node was already committed → its page is now pending-delete-or-update.
        assert!(cache.pending_deletion_pages.contains(&cache.page_of(id)));
    }

    #[test]
    fn commit_then_load_round_trip_with_lazy_loader() {
        let committer = InMemoryPageCommitter::new();

        let mut cache = MerkleTrieCache::new();
        let id_a = cache.allocate(TrieNode::leaf(vec![0xaa; 36]));
        let id_b = cache.allocate(TrieNode::leaf(vec![0xbb; 36]));
        let mut root = Some(id_a);
        cache.commit(&mut root, 36, &committer).unwrap();

        // Read metadata only; don't preload pages.
        let meta = MerkleTrieCache::read_metadata_page(&committer)
            .unwrap()
            .unwrap();
        assert_eq!(meta.root, Some(id_a));
        assert_eq!(meta.element_length, 36);
        assert_eq!(meta.nodes_per_page, NODES_PER_PAGE);
        assert_eq!(meta.next_node_id, cache.next_node_id);

        let mut restored = MerkleTrieCache::new();
        restored.load_metadata_only(meta.next_node_id);
        restored.set_lazy_loader(Box::new(committer.clone()));

        // First get triggers a lazy load of the shared page (both leaves
        // share page 144 since they were allocated sequentially).
        committer.reset_load_page_hits();
        let got_a = restored.get(id_a).unwrap().expect("lazy loaded").clone();
        assert_eq!(got_a.hash, vec![0xaa; 36]);
        // After loading id_a's page, id_b is also resident — same page.
        let got_b = restored.get(id_b).unwrap().expect("same page").clone();
        assert_eq!(got_b.hash, vec![0xbb; 36]);
        // Exactly one page (144) should have been loaded.
        let hits = committer.load_page_hits();
        let page_144_hits = hits.get(&144).copied().unwrap_or(0);
        assert_eq!(
            page_144_hits, 1,
            "lazy load must touch page 144 exactly once for two nodes sharing it"
        );
    }

    #[test]
    fn empty_trie_metadata_round_trip() {
        let committer = InMemoryPageCommitter::new();

        let mut cache = MerkleTrieCache::new();
        let mut root: Option<u64> = None;
        cache.commit(&mut root, 36, &committer).unwrap();

        let meta = MerkleTrieCache::read_metadata_page(&committer)
            .unwrap()
            .unwrap();
        assert_eq!(meta.root, None);
        assert_eq!(meta.element_length, 36);
        assert_eq!(meta.nodes_per_page, NODES_PER_PAGE);
    }

    #[test]
    fn no_metadata_page_means_fresh_db() {
        let committer = InMemoryPageCommitter::new();
        let got = MerkleTrieCache::read_metadata_page(&committer).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn refurbish_pending_created_node_recycles_in_place() {
        // PLAN-144 TASK-149: when the old id was never committed,
        // refurbish drops the old slot silently (no
        // pending_deletion_pages record).
        let mut cache = MerkleTrieCache::new();
        let old_id = cache.allocate(TrieNode::leaf(vec![0xaa; 36]));
        assert!(cache.pending_created.contains(&old_id));
        assert_eq!(cache.cached_node_count(), 1);
        let pending_deletion_before = cache.pending_deletion_pages.len();

        let new_id = cache.refurbish(old_id);
        assert_ne!(old_id, new_id);
        // Old id is gone from the cache; new id is resident.
        assert!(!cache.contains_in_memory(old_id));
        assert!(cache.contains_in_memory(new_id));
        // Node count conserved (move, not add/delete).
        assert_eq!(cache.cached_node_count(), 1);
        // Old id was pending-only → no deletion record.
        assert_eq!(
            cache.pending_deletion_pages.len(),
            pending_deletion_before,
            "refurbish of a never-committed node must not record a pending deletion"
        );
        // New id is in pending_created.
        assert!(cache.pending_created.contains(&new_id));
        assert!(!cache.pending_created.contains(&old_id));
        // The value was moved (not cloned).
        let got = cache.get(new_id).unwrap().unwrap();
        assert_eq!(got.hash, vec![0xaa; 36]);
    }

    #[test]
    fn refurbish_committed_node_marks_old_page_for_deletion() {
        let committer = InMemoryPageCommitter::new();
        let mut cache = MerkleTrieCache::new();
        let old_id = cache.allocate(TrieNode::leaf(vec![0xbb; 36]));
        // Make the node committed.
        let mut root = Some(old_id);
        cache.commit(&mut root, 36, &committer).unwrap();
        let committed_id = root.expect("root survives commit");
        assert!(!cache.pending_created.contains(&committed_id));

        let pending_deletion_before = cache.pending_deletion_pages.len();
        let new_id = cache.refurbish(committed_id);
        assert_ne!(committed_id, new_id);
        // New id is resident.
        assert!(cache.contains_in_memory(new_id));
        // Cached count conserved.
        assert_eq!(cache.cached_node_count(), 1);
        // Old page (which had the committed node) is recorded for
        // deletion-or-update at the next commit.
        let old_page = cache.page_of(committed_id);
        assert!(
            cache.pending_deletion_pages.contains(&old_page),
            "refurbish of a committed node must mark its page in pending_deletion_pages"
        );
        assert!(cache.pending_deletion_pages.len() > pending_deletion_before);
        // New id is in pending_created.
        assert!(cache.pending_created.contains(&new_id));
        // Value preserved.
        let got = cache.get(new_id).unwrap().unwrap();
        assert_eq!(got.hash, vec![0xbb; 36]);
    }

    #[test]
    #[should_panic(expected = "not resident")]
    fn refurbish_nonexistent_id_panics() {
        // A logic bug surfaces loudly rather than corrupting state.
        let mut cache = MerkleTrieCache::new();
        let _ = cache.refurbish(FIRST_NODE_ID);
    }

    #[test]
    fn evict_drops_lru_pages_until_under_target() {
        // Verify the LRU eviction core directly (no commit involved —
        // commit's page-packing pass would repack the test's
        // manually-spaced pages, so we operate on the LRU+page maps
        // directly to exercise the eviction loop in isolation).
        let mut cache = MerkleTrieCache::with_target(1);
        // Allocate three nodes on three different pages by stepping
        // next_node_id forward between allocations.
        let a = cache.allocate(TrieNode::leaf(vec![1; 36]));
        cache.next_node_id += NODES_PER_PAGE;
        let b = cache.allocate(TrieNode::leaf(vec![2; 36]));
        cache.next_node_id += NODES_PER_PAGE;
        let c = cache.allocate(TrieNode::leaf(vec![3; 36]));
        assert_ne!(cache.page_of(a), cache.page_of(b));
        assert_ne!(cache.page_of(b), cache.page_of(c));
        assert_eq!(cache.cached_node_count(), 3);

        // Pin `c`'s page as the root; evict must drop at least one of
        // a/b's pages (cached_node_count > target=1, and pages_priority
        // has a → b → c → c-pinned front).
        cache.evict(Some(c));
        // `c`'s page is pinned. `a` and `b` are on independent pages,
        // both of which are eviction candidates. With target=1 and
        // root page holding 1 node, evict must leave us at exactly 1.
        assert_eq!(cache.cached_node_count(), 1);
        assert!(cache.contains_in_memory(c));
        // a and b were on un-pinned pages; eviction took them.
        assert!(!cache.contains_in_memory(a));
        assert!(!cache.contains_in_memory(b));
    }

    #[test]
    fn evict_does_not_drop_root_when_it_is_the_only_page() {
        // Regression for Codex round-2 finding: the previous loop popped
        // from the back unconditionally. With only the root page left
        // (one allocated node, root pointing at it) and a target of 0,
        // pop_back would remove the root.
        let mut cache = MerkleTrieCache::with_target(0);
        let root = cache.allocate(TrieNode::leaf(vec![1; 36]));

        let committer = InMemoryPageCommitter::new();
        let mut root_arg = Some(root);
        cache.commit(&mut root_arg, 36, &committer).unwrap();
        // Post-commit root id (relocation may have moved it).
        let new_root = root_arg.expect("root survives commit");
        cache.evict(Some(new_root));
        // Root must survive even when it's the only page and the target
        // is below the cached node count.
        assert!(
            cache.contains_in_memory(new_root),
            "root page must remain when it's the only page left in cache"
        );
    }

    #[test]
    fn evict_pins_root_page_even_if_lru() {
        let mut cache = MerkleTrieCache::with_target(1);
        let root = cache.allocate(TrieNode::leaf(vec![1; 36]));
        cache.next_node_id += NODES_PER_PAGE;
        let other = cache.allocate(TrieNode::leaf(vec![2; 36]));

        // After both allocations, `other` is at the front and `root` is
        // at the back (LRU). Without pinning, `root` would be evicted.
        let committer = InMemoryPageCommitter::new();
        let mut root_arg = Some(root);
        cache.commit(&mut root_arg, 36, &committer).unwrap();
        let new_root = root_arg.expect("root survives commit");
        cache.evict(Some(new_root));
        assert!(
            cache.contains_in_memory(new_root),
            "root page must be pinned even when LRU"
        );
        // The other page may or may not be evicted depending on how
        // much over-target we are; the contract is just "root never
        // evicted".
        let _ = other;
    }

    #[test]
    fn get_returns_none_when_no_loader_and_node_missing() {
        let mut cache = MerkleTrieCache::new();
        // Bumping next_node_id without an allocation simulates a node
        // that "should exist" per metadata but isn't in memory and has
        // no loader to fetch it.
        cache.next_node_id = FIRST_NODE_ID + 10;
        let got = cache.get(FIRST_NODE_ID).unwrap();
        assert!(got.is_none(), "no loader → miss should return Ok(None)");
    }

    #[test]
    fn lazy_load_propagates_committer_errors() {
        // A committer that fails after N load_page calls; verifies the
        // error flows up through cache.get().
        #[derive(Default)]
        struct FailingCommitter {
            inner: InMemoryPageCommitter,
            calls: std::sync::Mutex<u64>,
            fail_after: u64,
        }
        impl PageCommitter for FailingCommitter {
            fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                if *c > self.fail_after {
                    return Err(AlgoError::Ledger {
                        message: "synthetic load failure".into(),
                    });
                }
                self.inner.load_page(id)
            }
            fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
                self.inner.store_page(id, content)
            }
        }

        // Populate via the inner committer; then load via a failing wrapper.
        let inner = InMemoryPageCommitter::new();
        let mut src = MerkleTrieCache::new();
        let id = src.allocate(TrieNode::leaf(vec![0xaa; 36]));
        let mut root_arg = Some(id);
        src.commit(&mut root_arg, 36, &inner).unwrap();

        let failing = FailingCommitter {
            inner,
            calls: std::sync::Mutex::new(0),
            fail_after: 0, // fail on the very first load_page call
        };

        let mut restored = MerkleTrieCache::new();
        restored.load_metadata_only(src.next_node_id);
        restored.set_lazy_loader(Box::new(failing));

        let err = restored.get(id).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("synthetic load failure"),
            "expected committer error to propagate; got: {msg}"
        );
    }
}
