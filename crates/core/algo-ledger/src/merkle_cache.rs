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
//! Reference (go-algorand v4.5.1-stable):
//! - `crypto/merkletrie/cache.go:46-94`   — `merkleTrieCache` struct
//! - `crypto/merkletrie/cache.go:122-203` — `allocateNewNode`, `getNode`
//! - `crypto/merkletrie/cache.go:287-341` — transaction scopes
//! - `crypto/merkletrie/cache.go:356-423` — `commit`
//! - `crypto/merkletrie/cache.go:708-731` — `evict`
//! - `crypto/merkletrie/trie.go:251-291`  — root-metadata page (page 0)
//! - `crypto/merkletrie/trie.go:29,32`    — version constants
//!
//! Differences from Go (documented; preserved as follow-ups):
//!
//! - **Eager load.** `MerkleTrieCache::load_all` reads every page at
//!   load time, whereas Go's `loadPage` is on-demand. This is simpler
//!   and adequate for the small trie sizes algod-rust handles today;
//!   add lazy load once we hit large-N profiling.
//! - **No `reallocatePendingPages` packing heuristic.** Go reorganizes
//!   nodes across pages on commit to reduce fanout and improve fill
//!   factor (`cache.go:428-530`). We skip this — the resulting page
//!   layout is correct but may have lower fill factor and higher write
//!   amplification. Follow-up under TASK-137's perf-tuning scope.
//! - **No `refurbishNode` ID recycling.** Each `add`/`delete` allocates
//!   fresh IDs; old node slots are not reused. Mirrors Go's
//!   correctness contract; can be added once write amplification
//!   matters in practice.

use std::collections::{HashMap, HashSet, VecDeque};

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
#[derive(Debug, Default)]
pub struct InMemoryPageCommitter {
    pages: std::sync::Mutex<HashMap<u64, Vec<u8>>>,
}

impl InMemoryPageCommitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pages currently stored.
    pub fn page_count(&self) -> usize {
        self.pages.lock().unwrap().len()
    }
}

impl PageCommitter for InMemoryPageCommitter {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
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
/// or in-memory) can drive the persistence. The trie owns the cache; it
/// passes the committer in at `commit` / `load` time so the cache
/// doesn't need to hold a long-lived borrow.
#[derive(Debug)]
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
    /// from "the page is in-memory but unchanged".
    pending_created: HashSet<u64>,
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
    cached_node_count_target: usize,
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
            pending_deletion_pages: HashSet::new(),
            pages_priority: VecDeque::new(),
            pages_priority_set: HashSet::new(),
            cached_node_count: 0,
            cached_node_count_target: target,
        }
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
        self.prioritize_front(page);
        id
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

    /// Borrow node `id`. Returns `None` if the node is not in memory
    /// (lazy-load path is not implemented — the trie loads all pages
    /// eagerly in `load_all`).
    #[inline]
    pub fn get(&self, id: u64) -> Option<&TrieNode> {
        self.pages.get(&self.page_of(id))?.get(&id)
    }

    /// Borrow node `id` mutably. Marks the containing page as accessed
    /// (LRU bump) but does not implicitly dirty it — the caller dirties
    /// by mutating fields that affect the hash, and the trie-level
    /// `dirty` flag tracks recompute-needed.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut TrieNode> {
        let page = self.page_of(id);
        self.prioritize_front(page);
        self.pages.get_mut(&page)?.get_mut(&id)
    }

    /// True iff node `id` is in memory.
    pub fn contains(&self, id: u64) -> bool {
        self.pages
            .get(&self.page_of(id))
            .is_some_and(|p| p.contains_key(&id))
    }

    /// Total node count across all in-memory pages.
    pub fn cached_node_count(&self) -> usize {
        self.cached_node_count
    }

    /// Count of leaf nodes across the cache (used by `MerkleTrie::len`).
    pub fn leaf_count(&self) -> usize {
        self.pages
            .values()
            .flat_map(|p| p.values())
            .filter(|n| n.is_leaf())
            .count()
    }

    /// Borrow a node by id, panicking if absent. Mirrors the `self.nodes[&id]`
    /// indexed-access pattern used by the trie algorithms — keeps the
    /// algorithm-side code structurally identical to the pre-cache
    /// version. The trie eagerly loads all pages, so a missing node
    /// indicates an algorithm bug, not a cache miss.
    #[track_caller]
    pub fn get_or_panic(&self, id: u64) -> &TrieNode {
        self.get(id)
            .unwrap_or_else(|| panic!("MerkleTrieCache: node {id} not in memory"))
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
    /// Caller must guarantee no dirty pages remain (i.e. `commit` was
    /// called immediately before, or the cache is read-only) — evicting
    /// a dirty page would lose data. The wrapper [`MerkleTrie::evict`]
    /// enforces this.
    pub fn evict(&mut self, root_id: Option<u64>) -> usize {
        // Pin the root page at the front.
        if let Some(rid) = root_id {
            let root_page = self.page_of(rid);
            if self.pages_priority_set.contains(&root_page) {
                if let Some(pos) = self.pages_priority.iter().position(|&p| p == root_page) {
                    self.pages_priority.remove(pos);
                }
                self.pages_priority.push_front(root_page);
            }
        }

        let mut evicted = 0;
        while self.cached_node_count > self.cached_node_count_target {
            let Some(page) = self.pages_priority.pop_back() else {
                break;
            };
            self.pages_priority_set.remove(&page);
            if let Some(page_map) = self.pages.remove(&page) {
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
        root_id: Option<u64>,
        element_length: usize,
        committer: &C,
    ) -> Result<CommitStats, AlgoError> {
        let mut stats = CommitStats::default();

        // Partition pending pages into create / update / delete.
        // - Pages that contain any pending_created node need to be written.
        // - Pages in pending_deletion_pages either need DELETE (now empty)
        //   or UPDATE (still has nodes).
        let mut pages_to_write: HashSet<u64> = HashSet::new();
        for &nid in &self.pending_created {
            pages_to_write.insert(self.page_of(nid));
        }
        // Pages with deletions: write if they still have nodes, otherwise delete.
        let mut pages_to_delete: HashSet<u64> = HashSet::new();
        for &page in &self.pending_deletion_pages {
            match self.pages.get(&page) {
                Some(p) if !p.is_empty() => {
                    pages_to_write.insert(page);
                }
                _ => {
                    pages_to_delete.insert(page);
                }
            }
        }

        // Write pages.
        for &page in &pages_to_write {
            let Some(nodes) = self.pages.get(&page) else {
                continue;
            };
            let mut wire = Page::new();
            for (&nid, node) in nodes {
                wire.nodes.insert(nid, trie_node_to_page_node(node));
            }
            let bytes = wire.serialize();
            committer.store_page(page, &bytes)?;

            // Statistics: a page is "new" iff all of its nodes were
            // created since the last commit (i.e. their ids exceed
            // last_committed_node_id-derived threshold).
            let first_id_on_page = page * self.nodes_per_page;
            if first_id_on_page >= self.last_committed_node_id {
                stats.new_page_count += 1;
                stats.new_node_count += nodes.len();
            } else {
                stats.updated_page_count += 1;
                stats.updated_node_count += nodes.len();
            }
        }

        // Delete pages.
        for &page in &pages_to_delete {
            committer.store_page(page, &[])?;
            // Drop from in-memory state too — the page is gone.
            self.pages.remove(&page);
            self.remove_from_priority(page);
            stats.deleted_page_count += 1;
        }

        // Write root-metadata page (page 0).
        self.write_metadata_page(root_id, element_length, committer)?;

        // Reset dirty tracking.
        self.pending_created.clear();
        self.pending_deletion_pages.clear();
        self.last_committed_node_id = self.next_node_id;

        Ok(stats)
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
    pub fn read_metadata_page<C: PageCommitter>(
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

    /// Eagerly load every node page reachable from the metadata into
    /// memory. The simple approach: enumerate page ids starting at
    /// `FIRST_NODE_ID / nodes_per_page` and stop at the first missing
    /// page after `next_node_id / nodes_per_page`.
    ///
    /// This is the "load all" path mentioned in the module docs.
    /// Replace with lazy on-demand loading if profiling shows it
    /// matters; for the trie sizes algod-rust handles today it's
    /// adequate.
    pub fn load_all<C: PageCommitter>(
        &mut self,
        next_node_id: u64,
        committer: &C,
    ) -> Result<(), AlgoError> {
        self.next_node_id = next_node_id;
        self.last_committed_node_id = next_node_id;

        let first_page = FIRST_NODE_ID / self.nodes_per_page;
        let last_page = if next_node_id == 0 {
            // No nodes allocated yet (fresh trie); nothing to load.
            return Ok(());
        } else {
            (next_node_id - 1) / self.nodes_per_page
        };

        for page in first_page..=last_page {
            let Some(bytes) = committer.load_page(page)? else {
                // Sparse pages happen during reallocation; skip the
                // missing ones.
                continue;
            };
            if bytes.is_empty() {
                continue;
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
        }
        Ok(())
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
        let got = cache.get(id).expect("just allocated");
        assert_eq!(got.hash, node.hash);
        assert!(got.is_leaf());
    }

    #[test]
    fn delete_pending_node_drops_from_cache() {
        let mut cache = MerkleTrieCache::new();
        let id = cache.allocate(TrieNode::leaf(vec![1; 4]));
        assert!(cache.contains(id));
        cache.delete(id);
        assert!(!cache.contains(id));
        // Page was created+removed entirely → no pending deletion to flush.
        assert!(cache.pending_deletion_pages.is_empty());
    }

    #[test]
    fn delete_committed_node_records_pending_deletion_page() {
        let mut cache = MerkleTrieCache::new();
        let id = cache.allocate(TrieNode::leaf(vec![1; 4]));

        let committer = InMemoryPageCommitter::new();
        cache.commit(Some(id), 4, &committer).unwrap();
        // After commit, no pending-created records remain.
        assert!(cache.pending_created.is_empty());

        // Allocate a second node (so deleting the first doesn't empty the page).
        let _id2 = cache.allocate(TrieNode::leaf(vec![2; 4]));
        cache.delete(id);
        // First node was already committed → its page is now pending-delete-or-update.
        assert!(cache.pending_deletion_pages.contains(&cache.page_of(id)));
    }

    #[test]
    fn commit_then_load_round_trip() {
        let committer = InMemoryPageCommitter::new();

        let mut cache = MerkleTrieCache::new();
        let id_a = cache.allocate(TrieNode::leaf(vec![0xaa; 36]));
        let id_b = cache.allocate(TrieNode::leaf(vec![0xbb; 36]));
        cache.commit(Some(id_a), 36, &committer).unwrap();

        // Load metadata + all pages into a fresh cache.
        let meta = MerkleTrieCache::read_metadata_page(&committer)
            .unwrap()
            .unwrap();
        assert_eq!(meta.root, Some(id_a));
        assert_eq!(meta.element_length, 36);
        assert_eq!(meta.nodes_per_page, NODES_PER_PAGE);
        assert_eq!(meta.next_node_id, cache.next_node_id);

        let mut restored = MerkleTrieCache::new();
        restored.load_all(meta.next_node_id, &committer).unwrap();

        // Both leaves should be present in the restored cache.
        let got_a = restored.get(id_a).unwrap();
        let got_b = restored.get(id_b).unwrap();
        assert_eq!(got_a.hash, vec![0xaa; 36]);
        assert_eq!(got_b.hash, vec![0xbb; 36]);
    }

    #[test]
    fn empty_trie_metadata_round_trip() {
        let committer = InMemoryPageCommitter::new();

        let mut cache = MerkleTrieCache::new();
        cache.commit(None, 36, &committer).unwrap();

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
    fn evict_drops_lru_pages_until_under_target() {
        // Set the target very small so eviction kicks in deterministically.
        let mut cache = MerkleTrieCache::with_target(1);
        // Allocate three nodes on three different pages by stepping
        // next_node_id forward between allocations.
        let a = cache.allocate(TrieNode::leaf(vec![1; 36]));
        // Force the next allocation onto a different page.
        cache.next_node_id += NODES_PER_PAGE;
        let b = cache.allocate(TrieNode::leaf(vec![2; 36]));
        cache.next_node_id += NODES_PER_PAGE;
        let c = cache.allocate(TrieNode::leaf(vec![3; 36]));

        assert_ne!(cache.page_of(a), cache.page_of(b));
        assert_ne!(cache.page_of(b), cache.page_of(c));

        let committer = InMemoryPageCommitter::new();
        cache.commit(Some(c), 36, &committer).unwrap();
        // 3 pages, 3 nodes → over target=1.
        cache.evict(Some(c));
        assert!(cache.cached_node_count() <= 1);
        // Root page (the page containing c) is pinned and must still be present.
        assert!(cache.contains(c));
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
        cache.commit(Some(root), 36, &committer).unwrap();
        cache.evict(Some(root));
        assert!(
            cache.contains(root),
            "root page must be pinned even when LRU"
        );
        // The other page may or may not be evicted depending on how
        // much over-target we are; the contract is just "root never
        // evicted".
        let _ = other;
    }
}
