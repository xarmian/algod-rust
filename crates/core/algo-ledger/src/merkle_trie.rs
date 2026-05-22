//! Merkle trie matching go-algorand's `crypto/merkletrie/` byte-for-byte.
//!
//! Tree shape: **256-ary radix, exactly one byte per internal node.** Shared
//! prefixes are materialized as chains of single-child internal nodes
//! (mirroring Go's `node.add` ancestor-chain construction in
//! `../go-algorand/crypto/merkletrie/node.go:144-158`). There is no Patricia-
//! style path compression on internal nodes.
//!
//! Leaves carry the element-remainder bytes from the depth at which they were
//! branched off (mirroring Go's `node.add` leaf-case `pnode.hash = d[idiff+1:]`
//! at `node.go:112-113`). A single-leaf root carries the full element bytes
//! (set once by `trie.Add` when the trie is empty — `trie.go:144`).
//!
//! The `TrieNode.hash` field is overloaded to mirror Go's `node.hash`:
//! - **Leaf:** stores element remainder bytes (full element if root, else
//!   `element[depth+1..]`). Never recomputed; participates directly in the
//!   parent's hash accumulator.
//! - **Internal pre-computation:** stores the path-from-root bytes
//!   (`pnode.hash = path` in Go).
//! - **Internal post-computation:** stores the SHA512/256 hash, replacing the
//!   path bytes (`n.hash = hash[:]` at the end of `calculateHash`).
//!
//! Persistence: paged via [`crate::merkle_cache::MerkleTrieCache`] (each
//! page holds [`crate::merkle_page::NODES_PER_PAGE`] nodes), driven by a
//! [`crate::merkle_cache::PageCommitter`]. Page 0 carries the trie root
//! metadata; pages ≥ 1 carry node contents in the Go-compatible
//! `merkle_page::Page` format.
//!
//! ## Lazy on-demand page loading (PLAN-144 TASK-146)
//!
//! [`MerkleTrie::load`] now reads only the metadata page and installs the
//! supplied owned [`PageCommitter`] as the cache's `lazy_loader`. Every
//! algorithm helper (`node_find` / `node_add` / `node_remove` /
//! `recompute_all_hashes`) goes through the cache's fallible `get` /
//! `get_mut`, so a missing node triggers an on-demand page read instead
//! of panicking. As a result, every public read API ([`MerkleTrie::contains`],
//! [`MerkleTrie::root_hash`], [`MerkleTrie::get_node`],
//! [`MerkleTrie::get_node_mut`]) is now `&mut self -> Result<…, AlgoError>`
//! — the lazy load mutates the cache and may propagate committer I/O
//! errors.
//!
//! History:
//! - **PLAN-130 TASK-132/133/134** (PR #284): structural rewrite to
//!   256-ary, Go conformance gate.
//! - **PLAN-130 TASK-135** (PR #285): element-format fixture lock-in.
//! - **PLAN-130 TASK-136/137** (PR #286): paged `accounthashes` persistence
//!   via the [`crate::merkle_cache::MerkleTrieCache`] with LRU eviction.
//! - **PLAN-144 TASK-146** (this PR): lazy on-demand page loading;
//!   `load` no longer iterates every page; public read API becomes
//!   fallible.

use algo_error::AlgoError;
use sha2::{Digest, Sha512_256};

use crate::merkle_cache::{CommitStats, MerkleTrieCache, PageCommitter};

// ---------------------------------------------------------------------------
// Bitset — 256-bit child-presence mask. Mirrors go-algorand
// `crypto/merkletrie/bitset.go:21-44`.
// ---------------------------------------------------------------------------

/// 256-bit bitmask backed by four `u64`s. Mirrors Go's `bitset` struct exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bitset {
    d: [u64; 4],
}

impl Bitset {
    /// All bits clear.
    pub const ZERO: Bitset = Bitset { d: [0; 4] };

    /// Set bit `bit` (0..=255).
    #[inline]
    pub fn set_bit(&mut self, bit: u8) {
        self.d[(bit / 64) as usize] |= 1u64 << (bit & 63);
    }

    /// Clear bit `bit` (0..=255).
    #[inline]
    pub fn clear_bit(&mut self, bit: u8) {
        self.d[(bit / 64) as usize] &= !(1u64 << (bit & 63));
    }

    /// Test bit `bit` (0..=255).
    #[inline]
    pub fn bit(&self, bit: u8) -> bool {
        (self.d[(bit / 64) as usize] & (1u64 << (bit & 63))) != 0
    }

    /// True iff every bit is clear.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.d[0] == 0 && self.d[1] == 0 && self.d[2] == 0 && self.d[3] == 0
    }
}

// ---------------------------------------------------------------------------
// ChildEntry — child pointer in an internal node.
// Mirrors `crypto/merkletrie/node.go:29-32`.
// ---------------------------------------------------------------------------

/// A single child pointer in an internal trie node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildEntry {
    /// The byte value at which this child branches from its parent.
    pub hash_index: u8,
    /// Identifier of the child node in the node store.
    pub child_id: u64,
}

// ---------------------------------------------------------------------------
// TrieNode — a single node in the 256-ary trie.
// Mirrors `crypto/merkletrie/node.go:33-37`.
// ---------------------------------------------------------------------------

/// A node in the 256-ary radix Merkle trie.
///
/// See module documentation for the `hash` field's overloaded semantics.
#[derive(Debug, Clone)]
pub struct TrieNode {
    /// Multi-purpose field — see module docs.
    pub hash: Vec<u8>,
    /// Children sorted ascending by `hash_index`. Empty iff this is a leaf.
    pub children: Vec<ChildEntry>,
    /// 256-bit mask: bit `b` set iff `children` contains an entry with
    /// `hash_index == b`. Used for O(1) "does this byte branch from here?"
    /// lookups, mirroring Go's `childrenMask.Bit(d[0])` in `find`.
    pub children_mask: Bitset,
}

impl TrieNode {
    /// Construct a leaf node carrying the given remainder bytes (or the full
    /// element, in the single-leaf-root case).
    pub fn leaf(remainder: Vec<u8>) -> Self {
        Self {
            hash: remainder,
            children: Vec::new(),
            children_mask: Bitset::ZERO,
        }
    }

    /// Construct an internal node from a path-from-root and a children list.
    /// The `children_mask` is derived from `children`.
    ///
    /// Assumes `children` is non-empty and sorted ascending by `hash_index`.
    pub fn internal(path: Vec<u8>, children: Vec<ChildEntry>) -> Self {
        debug_assert!(!children.is_empty(), "internal node must have children");
        debug_assert!(
            children
                .windows(2)
                .all(|w| w[0].hash_index < w[1].hash_index),
            "children must be strictly ascending by hash_index"
        );
        let mut children_mask = Bitset::ZERO;
        for c in &children {
            children_mask.set_bit(c.hash_index);
        }
        Self {
            hash: path,
            children,
            children_mask,
        }
    }

    /// True iff this node is a leaf (i.e. has no children). Matches Go's
    /// `node.leaf()` at `node.go:40-42`.
    #[inline]
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Binary-search for the first child with `hash_index >= b` and return its
    /// index into `self.children`. Mirrors Go's `node.indexOf(b)` at
    /// `node.go:77-80`.
    #[inline]
    fn index_of(&self, b: u8) -> usize {
        self.children
            .binary_search_by_key(&b, |c| c.hash_index)
            .unwrap_or_else(|i| i)
    }

    /// Reset hash invalidation tracking. Kept for API compatibility with the
    /// previous design's `invalidate()`; under the cache-based design,
    /// dirty tracking lives at the trie level, not per-node.
    pub fn invalidate(&mut self) {}
}

/// Build a "missing node" `AlgoError` for an id the trie's algorithm
/// expected to find in cache (after `get`'s lazy-load returned `None`).
/// Centralised so the message format is consistent across call sites.
#[inline]
fn missing_node(id: u64) -> AlgoError {
    AlgoError::Ledger {
        message: format!(
            "merkle trie: node {id} not found in cache and no lazy loader produced it \
             (page {page})",
            page = id / crate::merkle_page::NODES_PER_PAGE
        ),
    }
}

// ---------------------------------------------------------------------------
// MerkleTrie — top-level trie wrapping the paged node store.
// Mirrors `crypto/merkletrie/trie.go:62-77` + the cache initialization at
// `crypto/merkletrie/cache.go:97-120`.
// ---------------------------------------------------------------------------

/// In-memory 256-ary Merkle trie matching go-algorand's algorithm, backed
/// by a paged [`MerkleTrieCache`].
///
/// Elements are fixed-length byte slices (typically 36 bytes for accounts —
/// see `trie_hash.rs::ELEMENT_SIZE`). The trie supports
/// `add` / `delete` / `contains` / `root_hash`, plus [`MerkleTrie::commit`]
/// and [`MerkleTrie::load`] for paged persistence via any
/// [`PageCommitter`].
#[derive(Debug)]
pub struct MerkleTrie {
    /// Root node ID (`None` when the trie is empty).
    root: Option<u64>,
    /// Paged node store. Replaces the prior `HashMap<u64, TrieNode>` +
    /// `next_id: u64` pair. Owns LRU eviction + dirty-page tracking.
    cache: MerkleTrieCache,
    /// Fixed element size in bytes (36 for V6 account hashing).
    element_length: usize,
    /// True iff any internal-node hash may be stale and must be recomputed
    /// on the next `root_hash` call. Set on every `add` / `delete`.
    dirty: bool,
}

impl MerkleTrie {
    // -----------------------------------------------------------------------
    // Construction + node-store accessors. The accessor methods are kept on
    // `MerkleTrie` (rather than exposing the cache directly) for backwards
    // compatibility with the original API surface — test code constructs
    // nodes via `TrieNode::leaf` / `TrieNode::internal`, allocates them
    // via `allocate_node`, and points the root at them via `set_root`.
    // -----------------------------------------------------------------------

    /// Create a new empty trie with the given fixed element length.
    pub fn new(element_length: usize) -> Self {
        Self {
            root: None,
            cache: MerkleTrieCache::new(),
            element_length,
            dirty: false,
        }
    }

    /// Create a new empty trie with a custom in-memory node-count target
    /// (LRU eviction kicks in when `commit` finishes and the cache holds
    /// more than this many nodes).
    pub fn with_cache_target(element_length: usize, target: usize) -> Self {
        Self {
            root: None,
            cache: MerkleTrieCache::with_target(target),
            element_length,
            dirty: false,
        }
    }

    /// Configured element length.
    pub fn element_length(&self) -> usize {
        self.element_length
    }

    /// Set the eviction target for the underlying [`MerkleTrieCache`].
    /// Pages are evicted by `evict` (called from
    /// `SqliteLedger::commit_block`) when the in-memory node count
    /// exceeds this value. Default is
    /// [`crate::merkle_cache::DEFAULT_CACHED_NODES_TARGET`] (9000,
    /// matching go-algorand's `TrieCachedNodesCount`).
    pub fn set_cache_target(&mut self, target: usize) {
        self.cache.set_cache_target(target);
    }

    /// Read-only view of the in-memory node-count target.
    pub fn cache_target(&self) -> usize {
        self.cache.cache_target()
    }

    /// In-memory node count across all resident pages. Used by tests +
    /// `SqliteLedger`'s eviction wiring to log post-evict cache size.
    pub fn cached_node_count(&self) -> usize {
        self.cache.cached_node_count()
    }

    /// True iff a lazy loader has been installed on the cache. Eviction
    /// is only safe when this returns `true`, because evicted pages
    /// must be re-fetchable. Used by [`SqliteLedger::commit_block`] to
    /// gate `evict` (and to decide whether to install a loader on first
    /// commit). PLAN-144 TASK-147.
    pub fn has_lazy_loader(&self) -> bool {
        self.cache.has_lazy_loader()
    }

    /// Install an owned page committer as the cache's lazy loader after
    /// construction. Production calls this from
    /// [`SqliteLedger::commit_block`] on disk-backed ledgers after the
    /// first successful commit so subsequent `evict` calls can re-load
    /// evicted pages on demand. Tests use it directly when they want to
    /// exercise the post-evict reload path against an
    /// [`crate::merkle_cache::InMemoryPageCommitter`] without going
    /// through [`MerkleTrie::load`].
    pub fn set_lazy_loader(&mut self, loader: Box<dyn PageCommitter + Send>) {
        self.cache.set_lazy_loader(loader);
    }

    /// True iff no elements have been added (or all have been deleted).
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Number of leaf elements currently **resident in memory**.
    ///
    /// For a freshly lazy-loaded trie this can be less than the persisted
    /// leaf count until pages are touched. Callers that need an
    /// authoritative count must walk the trie via `contains` (forcing
    /// lazy loads) or call this after a full traversal.
    pub fn len(&self) -> usize {
        self.cache.leaf_count()
    }

    /// Root node ID, if any.
    pub fn root_id(&self) -> Option<u64> {
        self.root
    }

    /// Set the root node ID (used by tests + persistence reload).
    pub fn set_root(&mut self, id: Option<u64>) {
        self.root = id;
        self.dirty = true;
    }

    /// Allocate a new node in the store and return its ID.
    pub fn allocate_node(&mut self, node: TrieNode) -> u64 {
        self.dirty = true;
        self.cache.allocate(node)
    }

    /// Recycle `old_id`'s storage to a freshly-allocated id. The
    /// in-memory `TrieNode` value (which the caller may have just
    /// mutated via `get_node_mut`) is moved to the new id without
    /// being cloned. PLAN-144 TASK-149.
    pub fn refurbish_node(&mut self, old_id: u64) -> u64 {
        self.dirty = true;
        self.cache.refurbish(old_id)
    }

    /// Borrow a node by ID. Lazy-loads its page on a cache miss; may
    /// return `Ok(None)` if no lazy loader is installed and the node was
    /// never resident.
    pub fn get_node(&mut self, id: u64) -> Result<Option<&TrieNode>, AlgoError> {
        self.cache.get(id)
    }

    /// Borrow a node by ID mutably. Marks the containing page as dirty.
    pub fn get_node_mut(&mut self, id: u64) -> Result<Option<&mut TrieNode>, AlgoError> {
        self.dirty = true;
        self.cache.get_mut(id)
    }

    // -----------------------------------------------------------------------
    // Public API — Add / Delete / Contains / RootHash.
    // -----------------------------------------------------------------------

    /// Add an element to the trie.
    ///
    /// Returns `Ok(true)` if the element was newly added, `Ok(false)` if it
    /// was already present (silent no-op, matching go-algorand
    /// `trie.go:137-170` Add returning `(false, nil)` on duplicate).
    /// Returns `Err` on element-length mismatch or lazy-load failure.
    pub fn add(&mut self, element: &[u8]) -> Result<bool, AlgoError> {
        // Length is checked on every add, including the first. Diverges from
        // go-algorand `trie.Add` at trie.go:144-145 (which infers element
        // length from the first add because `MakeTrie` has no length arg) —
        // Rust's `MerkleTrie::new(element_length)` is explicit, so silently
        // accepting a mismatched first element would defeat that contract.
        // Allow inference only when the caller opted in via `new(0)`.
        if self.element_length == 0 {
            self.element_length = element.len();
        }
        if element.len() != self.element_length {
            return Err(AlgoError::Ledger {
                message: format!(
                    "element length {} != expected {}",
                    element.len(),
                    self.element_length
                ),
            });
        }

        if self.root.is_none() {
            let leaf = TrieNode::leaf(element.to_vec());
            let id = self.allocate_node(leaf);
            self.root = Some(id);
            self.dirty = true;
            return Ok(true);
        }

        // Existence check: silent-no-op on duplicate (matches Go trie.go:155-158).
        let root_id = self.root.unwrap();
        if self.node_find(root_id, element)? {
            return Ok(false);
        }

        let new_root = self.node_add(root_id, element, &[])?;
        // PLAN-144 TASK-149: `node_add` now refurbishes the old root
        // internally (via `MerkleTrieCache::refurbish`), which both
        // recycles the id AND records the old slot as removed. No
        // additional `delete(root_id)` here — that would be a no-op at
        // best and a double-record at worst.
        self.root = Some(new_root);
        self.dirty = true;
        Ok(true)
    }

    /// Delete an element from the trie.
    ///
    /// Returns `Ok(true)` if the element was removed, `Ok(false)` if it was
    /// not present (silent no-op, matching go-algorand `trie.go:174-200`
    /// Delete returning `(false, nil)` on missing).
    /// Returns `Err` on element-length mismatch or lazy-load failure.
    pub fn delete(&mut self, element: &[u8]) -> Result<bool, AlgoError> {
        if self.root.is_none() {
            return Ok(false);
        }
        if element.len() != self.element_length {
            return Err(AlgoError::Ledger {
                message: format!(
                    "element length {} != expected {}",
                    element.len(),
                    self.element_length
                ),
            });
        }

        let root_id = self.root.unwrap();

        // Existence check (Go's trie.go:185-188 does `find` first).
        if !self.node_find(root_id, element)? {
            return Ok(false);
        }

        // Special case: the root itself is the leaf we're deleting.
        let root_is_leaf = self
            .cache
            .get(root_id)?
            .ok_or_else(|| missing_node(root_id))?
            .is_leaf();
        if root_is_leaf {
            self.cache.delete(root_id);
            self.root = None;
            self.dirty = true;
            return Ok(true);
        }

        let new_root = self.node_remove(root_id, element, &[])?;
        // PLAN-144 TASK-149: `node_remove` refurbishes the root in
        // place (or deletes it during the collapse branch). No
        // additional `delete(root_id)` here.
        self.root = new_root;
        self.dirty = true;
        Ok(true)
    }

    /// True iff `element` is present in the trie.
    ///
    /// Now `&mut self` and fallible because traversal may lazy-load
    /// pages from a stored committer (PLAN-144 TASK-146).
    pub fn contains(&mut self, element: &[u8]) -> Result<bool, AlgoError> {
        if element.len() != self.element_length {
            return Ok(false);
        }
        match self.root {
            None => Ok(false),
            Some(id) => self.node_find(id, element),
        }
    }

    /// Compute the root hash.
    ///
    /// - Empty trie: `[0u8; 32]` (matches Go `RootHash` at `trie.go:115-118`).
    /// - Single-leaf root: `SHA512/256(0x00 || leaf.hash)`.
    /// - Internal root: `SHA512/256(0x01 || root.hash)` after recomputation.
    ///
    /// Fallible because `recompute_all_hashes` traverses the entire trie
    /// and may lazy-load pages.
    pub fn root_hash(&mut self) -> Result<[u8; 32], AlgoError> {
        let root_id = match self.root {
            None => return Ok([0u8; 32]),
            Some(id) => id,
        };

        if self.dirty {
            self.recompute_all_hashes(root_id)?;
            self.dirty = false;
        }

        let node = self
            .cache
            .get(root_id)?
            .ok_or_else(|| missing_node(root_id))?;
        let mut hasher = Sha512_256::new();
        if node.is_leaf() {
            hasher.update([0x00]);
        } else {
            hasher.update([0x01]);
        }
        hasher.update(&node.hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Persistence — paged commit/load via PageCommitter.
    // Mirrors `crypto/merkletrie/trie.go:223-248` (Commit + Evict).
    // -----------------------------------------------------------------------

    /// Persist the trie to `committer`.
    ///
    /// Forces a hash recomputation when the trie is dirty (so the
    /// persisted node bytes carry final SHA hashes, not transient
    /// path-from-root bytes), then partitions the cache's pending pages
    /// into create/update/delete sets and writes them through the
    /// committer. Finally writes the root-metadata blob at page 0
    /// (matching Go's `Trie.Commit` at `trie.go:223-231`).
    ///
    /// Returns per-commit accounting from the cache.
    pub fn commit<C: PageCommitter>(&mut self, committer: &C) -> Result<CommitStats, AlgoError> {
        if self.dirty {
            if let Some(root_id) = self.root {
                self.recompute_all_hashes(root_id)?;
            }
            self.dirty = false;
        }
        // The cache's commit performs the page-packing repack
        // (PLAN-144 TASK-148), which may relocate the root node to a
        // fresh tail page. Pass `&mut self.root` so the cache can update
        // our root id in place.
        self.cache
            .commit(&mut self.root, self.element_length, committer)
    }

    /// Reconstruct a trie from a [`PageCommitter`].
    ///
    /// Reads page 0 for metadata via `loader` and installs `loader` as
    /// the cache's lazy loader. No node pages are read here — subsequent
    /// `get` / `get_mut` calls lazy-load through `loader` (PLAN-144 TASK-146).
    ///
    /// Returns `Ok(None)` if page 0 doesn't exist (fresh DB — caller
    /// should `rebuild_trie_from_db` or start empty).
    pub fn load(loader: Box<dyn PageCommitter + Send>) -> Result<Option<Self>, AlgoError> {
        let Some(meta) = MerkleTrieCache::read_metadata_page(loader.as_ref())? else {
            return Ok(None);
        };

        let mut cache = MerkleTrieCache::new();
        cache.load_metadata_only(meta.next_node_id);
        cache.set_lazy_loader(loader);

        Ok(Some(Self {
            root: meta.root,
            cache,
            element_length: meta.element_length,
            // After load every internal node's `hash` field carries the
            // SHA hash that was committed; root_hash returns without
            // recomputation.
            dirty: false,
        }))
    }

    /// Evict least-recently-used pages from memory back to the eviction
    /// target. The root page is pinned. Returns the number of pages
    /// evicted.
    ///
    /// Safe to call any time `self.dirty == false` (i.e. immediately
    /// after `commit`). Evicted pages are re-fetched on demand by the
    /// cache's lazy loader installed at [`MerkleTrie::load`] time
    /// (PLAN-144 TASK-146); a dirty trie would lose data on eviction,
    /// hence the check.
    ///
    /// Wired into `SqliteLedger::commit_block` (PLAN-144 TASK-147) so
    /// runtime cache memory is bounded across long block replays.
    pub fn evict(&mut self) -> Result<usize, AlgoError> {
        if self.dirty {
            return Err(AlgoError::Ledger {
                message: "MerkleTrie::evict called with dirty cache — commit first".into(),
            });
        }
        // Safety: never evict pages we can't recover. Without a lazy
        // loader, subsequent `get` for an evicted node returns
        // `Ok(None)` and the trie's algorithms surface that as a
        // `missing_node` error. The caller is responsible for
        // installing a loader (via `set_lazy_loader` or `MerkleTrie::load`)
        // before relying on eviction.
        if !self.cache.has_lazy_loader() {
            return Ok(0);
        }
        Ok(self.cache.evict(self.root))
    }

    // -----------------------------------------------------------------------
    // Hash computation — bottom-up, mirrors Go `node.calculateHash` at
    // `node.go:227-252`.
    // -----------------------------------------------------------------------

    fn recompute_all_hashes(&mut self, root_id: u64) -> Result<(), AlgoError> {
        let mut path: Vec<u8> = Vec::new();
        self.recompute_hash_at(root_id, &mut path)
    }

    fn recompute_hash_at(&mut self, node_id: u64, path: &mut Vec<u8>) -> Result<(), AlgoError> {
        let is_leaf = self
            .cache
            .get(node_id)?
            .ok_or_else(|| missing_node(node_id))?
            .is_leaf();
        if is_leaf {
            // Leaves never recompute — their `hash` is the element remainder
            // (or full element for a single-leaf root) and is set at
            // construction time.
            return Ok(());
        }

        // Snapshot child descriptors so we can release the cache borrow
        // before recursing (each recursive call needs `&mut self.cache`).
        let child_descriptors: Vec<(u8, u64)> = self
            .cache
            .get(node_id)?
            .ok_or_else(|| missing_node(node_id))?
            .children
            .iter()
            .map(|c| (c.hash_index, c.child_id))
            .collect();
        for (hi, cid) in &child_descriptors {
            path.push(*hi);
            self.recompute_hash_at(*cid, path)?;
            path.pop();
        }

        // Compose the accumulator. Format mirrors Go `node.calculateHash`:
        //   byte(len(path)) || path
        //   for each child in order:
        //     byte(0) if leaf else byte(1)
        //     byte(len(child.hash))
        //     child.hash_index
        //     child.hash bytes
        let mut acc: Vec<u8> = Vec::new();
        debug_assert!(path.len() <= 255);
        acc.push(path.len() as u8);
        acc.extend_from_slice(path);

        for (hi, cid) in &child_descriptors {
            // Re-borrow per iteration so the cache mutation from any
            // prior get's lazy-load is visible.
            let child = self.cache.get(*cid)?.ok_or_else(|| missing_node(*cid))?;
            if child.is_leaf() {
                acc.push(0x00);
            } else {
                acc.push(0x01);
            }
            debug_assert!(child.hash.len() <= 255);
            acc.push(child.hash.len() as u8);
            acc.push(*hi);
            acc.extend_from_slice(&child.hash);
        }

        let mut hasher = Sha512_256::new();
        hasher.update(&acc);
        let result = hasher.finalize();

        let node = self
            .cache
            .get_mut(node_id)?
            .ok_or_else(|| missing_node(node_id))?;
        node.hash = result.to_vec();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // node_find — mirror of Go `node.find` at `node.go:82-96`.
    // -----------------------------------------------------------------------

    fn node_find(&mut self, node_id: u64, d: &[u8]) -> Result<bool, AlgoError> {
        // Snapshot the data we need from the node, then release the
        // borrow before recursing — the recursive call also needs
        // `&mut self.cache`.
        let (is_leaf, leaf_hash, bit_set, child_id_opt) = {
            let node = self
                .cache
                .get(node_id)?
                .ok_or_else(|| missing_node(node_id))?;
            if node.is_leaf() {
                (true, Some(node.hash.clone()), false, None)
            } else if d.is_empty() {
                // Shouldn't happen with fixed-length elements; guard anyway.
                (false, None, false, None)
            } else if !node.children_mask.bit(d[0]) {
                (false, None, false, None)
            } else {
                let idx = node.index_of(d[0]);
                (false, None, true, Some(node.children[idx].child_id))
            }
        };

        if is_leaf {
            return Ok(d == leaf_hash.as_deref().unwrap_or(&[]));
        }
        if d.is_empty() || !bit_set {
            return Ok(false);
        }
        self.node_find(child_id_opt.unwrap(), &d[1..])
    }

    // -----------------------------------------------------------------------
    // node_add — mirror of Go `node.add` at `node.go:98-220`.
    //
    // Assumes the key is absent (the public `add` does a `find` first).
    // Returns the new node ID to use in the parent. Caller is responsible
    // for replacing the old node ID in its own children list (or in the trie
    // root pointer).
    // -----------------------------------------------------------------------

    fn node_add(&mut self, node_id: u64, d: &[u8], path: &[u8]) -> Result<u64, AlgoError> {
        let node = self
            .cache
            .get(node_id)?
            .ok_or_else(|| missing_node(node_id))?
            .clone();

        if node.is_leaf() {
            // Find the first byte where this leaf's remainder and the new
            // element's bytes-from-here diverge.
            let mut idiff = 0usize;
            // Both are guaranteed to differ somewhere (caller did a `find`),
            // so we won't run off the end.
            while node.hash[idiff] == d[idiff] {
                idiff += 1;
            }

            // Two new leaves, each carrying the remainder after the diff byte.
            let cur_child = TrieNode::leaf(node.hash[idiff + 1..].to_vec());
            let new_child = TrieNode::leaf(d[idiff + 1..].to_vec());
            let cur_child_id = self.allocate_node(cur_child);
            let new_child_id = self.allocate_node(new_child);

            // Bottom branch node: 2 children at the diverging bytes.
            let mut branch_children = Vec::with_capacity(2);
            let mut branch_mask = Bitset::ZERO;
            branch_mask.set_bit(node.hash[idiff]);
            branch_mask.set_bit(d[idiff]);
            if node.hash[idiff] < d[idiff] {
                branch_children.push(ChildEntry {
                    hash_index: node.hash[idiff],
                    child_id: cur_child_id,
                });
                branch_children.push(ChildEntry {
                    hash_index: d[idiff],
                    child_id: new_child_id,
                });
            } else {
                branch_children.push(ChildEntry {
                    hash_index: d[idiff],
                    child_id: new_child_id,
                });
                branch_children.push(ChildEntry {
                    hash_index: node.hash[idiff],
                    child_id: cur_child_id,
                });
            }

            // Path-from-root for the bottom branch = caller's path + d[0..idiff].
            let mut branch_path = Vec::with_capacity(path.len() + idiff);
            branch_path.extend_from_slice(path);
            branch_path.extend_from_slice(&d[..idiff]);
            let branch = TrieNode {
                hash: branch_path,
                children: branch_children,
                children_mask: branch_mask,
            };
            let mut top_id = self.allocate_node(branch);

            // Create `idiff` single-child ancestor internals, walking back up
            // from depth `caller_depth + idiff - 1` to `caller_depth`. Each
            // ancestor has its child branching on the next byte of d.
            for i in (0..idiff).rev() {
                let mut mask = Bitset::ZERO;
                mask.set_bit(d[i]);
                let mut ancestor_path = Vec::with_capacity(path.len() + i);
                ancestor_path.extend_from_slice(path);
                ancestor_path.extend_from_slice(&d[..i]);
                let ancestor = TrieNode {
                    hash: ancestor_path,
                    children: vec![ChildEntry {
                        hash_index: d[i],
                        child_id: top_id,
                    }],
                    children_mask: mask,
                };
                top_id = self.allocate_node(ancestor);
            }

            // Remove the old leaf (Go's add returns the new top; the caller
            // then calls cache.deleteNode on the old node it's replacing —
            // the top-level Trie.Add does this for the root; recursive
            // callers below "free" the old node implicitly by overwriting
            // their children entry).
            //
            // For correctness of subsequent operations and `len()`, remove
            // the old node here. The caller will plug `top_id` into its
            // children list (or the root pointer).
            self.cache.delete(node_id);
            return Ok(top_id);
        }

        // Non-leaf: branch on d[0].
        if !node.children_mask.bit(d[0]) {
            // No existing child at d[0]: insert a new leaf and refurbish
            // this internal node's id. Mirrors Go's no-existing-child
            // case at `node.go:162-181`: allocate the new leaf, then
            // mutate the parent's children list in place and recycle
            // its id via `refurbishNode`.
            let leaf = TrieNode::leaf(d[1..].to_vec());
            let leaf_id = self.allocate_node(leaf);

            // PLAN-144 TASK-149: mutate parent in place rather than
            // building a new TrieNode + allocate+delete pair. Avoids
            // cloning the children Vec.
            {
                let parent = self
                    .cache
                    .get_mut(node_id)?
                    .ok_or_else(|| missing_node(node_id))?;
                // Find insertion point (children are sorted by hash_index).
                let pos = parent
                    .children
                    .binary_search_by_key(&d[0], |c| c.hash_index)
                    .unwrap_or_else(|i| i);
                parent.children.insert(
                    pos,
                    ChildEntry {
                        hash_index: d[0],
                        child_id: leaf_id,
                    },
                );
                parent.children_mask.set_bit(d[0]);
                parent.hash = path.to_vec();
            }
            return Ok(self.refurbish_node(node_id));
        }

        // Existing child at d[0]: recurse, mutate this node's child
        // entry, then refurbish. Mirrors Go's existing-child branch at
        // `node.go:184-217`.
        let child_idx = node.index_of(d[0]);
        let cur_child_id = node.children[child_idx].child_id;
        let mut sub_path = Vec::with_capacity(path.len() + 1);
        sub_path.extend_from_slice(path);
        sub_path.push(d[0]);
        let updated_child_id = self.node_add(cur_child_id, &d[1..], &sub_path)?;

        // PLAN-144 TASK-149: in-place update + refurbish.
        {
            let parent = self
                .cache
                .get_mut(node_id)?
                .ok_or_else(|| missing_node(node_id))?;
            parent.children[child_idx].child_id = updated_child_id;
            parent.hash = path.to_vec();
        }
        Ok(self.refurbish_node(node_id))
    }

    // -----------------------------------------------------------------------
    // node_remove — mirror of Go `node.remove` at `node.go:254-309`.
    //
    // Called only on non-leaf nodes (the public `delete` handles the
    // root-is-leaf case directly).
    //
    // Returns:
    //   - `Some(new_id)` if this internal node survives (possibly with a
    //     reduced child set, or collapsed into a leaf carrying merged bytes).
    //   - `None` if this internal node should be removed entirely (the caller
    //     either replaces it in their parent's children list, or — at the
    //     trie root — sets `mt.root = None`).
    // -----------------------------------------------------------------------

    fn node_remove(
        &mut self,
        node_id: u64,
        key: &[u8],
        path: &[u8],
    ) -> Result<Option<u64>, AlgoError> {
        // Snapshot fields we need from the parent + child before we
        // start mutating the cache (each mutation may invalidate the
        // borrow). Mirrors Go `node.remove` at `node.go:254-309`.
        let (child_idx, child_id, child_is_leaf) = {
            let node = self
                .cache
                .get(node_id)?
                .ok_or_else(|| missing_node(node_id))?;
            debug_assert!(!node.is_leaf(), "node_remove must not be called on leaves");
            let ci = node.index_of(key[0]);
            let cid = node.children[ci].child_id;
            let cleaf = self
                .cache
                .get(cid)?
                .ok_or_else(|| missing_node(cid))?
                .is_leaf();
            (ci, cid, cleaf)
        };

        // PLAN-144 TASK-149: each branch mutates the parent in place
        // and refurbishes it, instead of cloning the children Vec into
        // a fresh TrieNode and allocate+delete-ing.
        if child_is_leaf {
            // Remove this leaf entirely from our children. Per Go's
            // comment at `node.go:269`, the tree forbids internal nodes
            // with exactly one leaf child and no other children, so
            // before this step we had ≥2 children — after removing one
            // leaf, ≥1 remains.
            self.cache.delete(child_id);
            {
                let parent = self
                    .cache
                    .get_mut(node_id)?
                    .ok_or_else(|| missing_node(node_id))?;
                parent.children.remove(child_idx);
                parent.children_mask.clear_bit(key[0]);
                parent.hash = path.to_vec();
            }
        } else {
            // Recurse. The child is non-leaf, so `remove` always
            // returns `Some` (the tree-invariant guarantees the child
            // has ≥2 children before, possibly collapsing to a leaf
            // after — still `Some`).
            let mut sub_path = Vec::with_capacity(path.len() + 1);
            sub_path.extend_from_slice(path);
            sub_path.push(key[0]);
            let updated = self
                .node_remove(child_id, &key[1..], &sub_path)?
                .expect("non-leaf remove always returns Some");
            {
                let parent = self
                    .cache
                    .get_mut(node_id)?
                    .ok_or_else(|| missing_node(node_id))?;
                parent.children[child_idx].child_id = updated;
                parent.hash = path.to_vec();
            }
        }

        // Collapse: if the (now-mutated) parent has exactly one child
        // and that child is a leaf, fold the parent itself into a leaf
        // carrying `[only_child.hash_index] || only_child.hash`.
        // Mirrors Go `node.go:291-304`.
        //
        // This branch builds a NEW TrieNode (leaf) with different
        // content than the parent — no refurbish opportunity here;
        // we delete the parent + only_child slots and allocate a fresh
        // leaf.
        let collapse = {
            let parent = self
                .cache
                .get(node_id)?
                .ok_or_else(|| missing_node(node_id))?;
            if parent.children.len() == 1 {
                let only_hi = parent.children[0].hash_index;
                let only_id = parent.children[0].child_id;
                let only_child = self
                    .cache
                    .get(only_id)?
                    .ok_or_else(|| missing_node(only_id))?;
                if only_child.is_leaf() {
                    let mut merged = Vec::with_capacity(1 + only_child.hash.len());
                    merged.push(only_hi);
                    merged.extend_from_slice(&only_child.hash);
                    Some((only_id, merged))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some((only_id, merged)) = collapse {
            self.cache.delete(only_id);
            self.cache.delete(node_id);
            return Ok(Some(self.allocate_node(TrieNode::leaf(merged))));
        }

        // No collapse — refurbish the (in-place-mutated) parent to
        // recycle its id. Mirrors Go `node.go:285` where `remove`
        // returns `mtc.cache.refurbishNode(nid)` for the non-collapse
        // case.
        Ok(Some(self.refurbish_node(node_id)))
    }

    // -----------------------------------------------------------------------
    // from_elements — build a trie from a full set of fixed-size elements.
    // -----------------------------------------------------------------------

    /// Build a trie by inserting every element in `iter` in iteration order.
    ///
    /// Returns `Err` only on element-length mismatch. Duplicates are silently
    /// ignored (matching Go's `Add` semantics).
    pub fn from_elements(
        iter: impl Iterator<Item = [u8; 36]>,
        element_length: usize,
    ) -> Result<Self, AlgoError> {
        let mut trie = Self::new(element_length);
        for elem in iter {
            trie.add(&elem)?;
        }
        Ok(trie)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_cache::InMemoryPageCommitter;

    fn sha512_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha512_256::new();
        hasher.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    // -----------------------------------------------------------------------
    // Bitset
    // -----------------------------------------------------------------------

    #[test]
    fn test_bitset_set_clear_test() {
        let mut b = Bitset::ZERO;
        assert!(b.is_zero());
        b.set_bit(0);
        b.set_bit(63);
        b.set_bit(64);
        b.set_bit(255);
        assert!(b.bit(0));
        assert!(b.bit(63));
        assert!(b.bit(64));
        assert!(b.bit(255));
        assert!(!b.bit(1));
        assert!(!b.bit(128));
        assert!(!b.is_zero());

        b.clear_bit(64);
        assert!(!b.bit(64));
        assert!(b.bit(0));
        assert!(b.bit(255));
    }

    #[test]
    fn test_bitset_layout_matches_go() {
        let mut b = Bitset::ZERO;
        b.set_bit(0);
        assert_eq!(b.d[0], 1);
        b.set_bit(63);
        assert_eq!(b.d[0], 1 | (1u64 << 63));
        b.set_bit(64);
        assert_eq!(b.d[1], 1);
        b.set_bit(255);
        assert_eq!(b.d[3], 1u64 << 63);
    }

    // -----------------------------------------------------------------------
    // Root hash basics
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_trie_root_hash() {
        let mut trie = MerkleTrie::new(36);
        assert_eq!(trie.root_hash().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf_root_hash() {
        let mut trie = MerkleTrie::new(36);
        let mut elem = vec![0u8; 36];
        elem[0] = 0xAB;
        elem[35] = 0xCD;

        trie.add(&elem).unwrap();
        let root = trie.root_hash().unwrap();

        let mut input = vec![0x00];
        input.extend_from_slice(&elem);
        assert_eq!(root, sha512_256(&input));
    }

    #[test]
    fn test_single_leaf_root_via_manual_construction() {
        let mut trie = MerkleTrie::new(36);
        let mut elem = vec![0u8; 36];
        elem[0] = 0xAB;
        elem[35] = 0xCD;

        let leaf_id = trie.allocate_node(TrieNode::leaf(elem.clone()));
        trie.set_root(Some(leaf_id));

        let mut input = vec![0x00];
        input.extend_from_slice(&elem);
        assert_eq!(trie.root_hash().unwrap(), sha512_256(&input));
    }

    // -----------------------------------------------------------------------
    // Two-element splits
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_two_elements_no_shared_prefix() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0xAA, 0xBB, 0xCC];
        let elem_b = vec![0x20, 0xDD, 0xEE, 0xFF];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        assert!(trie.contains(&elem_a).unwrap());
        assert!(trie.contains(&elem_b).unwrap());

        let root = trie.root_id().unwrap();
        let root_node = trie.get_node(root).unwrap().unwrap().clone();
        assert!(!root_node.is_leaf());
        assert_eq!(root_node.children.len(), 2);
        assert!(root_node.children_mask.bit(0x10));
        assert!(root_node.children_mask.bit(0x20));

        // Hand-computed expected root.
        let mut acc = vec![0x00];
        acc.extend_from_slice(&[0x00, 0x03, 0x10, 0xAA, 0xBB, 0xCC]);
        acc.extend_from_slice(&[0x00, 0x03, 0x20, 0xDD, 0xEE, 0xFF]);
        let internal_hash = sha512_256(&acc);

        let mut root_input = vec![0x01];
        root_input.extend_from_slice(&internal_hash);
        assert_eq!(trie.root_hash().unwrap(), sha512_256(&root_input));
    }

    #[test]
    fn test_add_two_elements_one_byte_shared_prefix() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x20, 0xAA, 0xBB];
        let elem_b = vec![0x10, 0x30, 0xCC, 0xDD];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        assert!(trie.contains(&elem_a).unwrap());
        assert!(trie.contains(&elem_b).unwrap());

        let root = trie.root_id().unwrap();
        let root_node = trie.get_node(root).unwrap().unwrap().clone();
        assert!(!root_node.is_leaf());
        assert_eq!(root_node.children.len(), 1);
        assert_eq!(root_node.children[0].hash_index, 0x10);

        let branch_id = root_node.children[0].child_id;
        let branch = trie.get_node(branch_id).unwrap().unwrap().clone();
        assert!(!branch.is_leaf());
        assert_eq!(branch.children.len(), 2);
        assert_eq!(branch.children[0].hash_index, 0x20);
        assert_eq!(branch.children[1].hash_index, 0x30);

        let mut branch_acc = vec![0x01, 0x10];
        branch_acc.extend_from_slice(&[0x00, 0x02, 0x20, 0xAA, 0xBB]);
        branch_acc.extend_from_slice(&[0x00, 0x02, 0x30, 0xCC, 0xDD]);
        let branch_hash = sha512_256(&branch_acc);

        let mut root_acc = vec![0x00];
        root_acc.push(0x01);
        root_acc.push(branch_hash.len() as u8);
        root_acc.push(0x10);
        root_acc.extend_from_slice(&branch_hash);
        let root_internal = sha512_256(&root_acc);

        let mut top = vec![0x01];
        top.extend_from_slice(&root_internal);
        assert_eq!(trie.root_hash().unwrap(), sha512_256(&top));
    }

    // -----------------------------------------------------------------------
    // Add / Delete / Contains
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_then_contains() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x10, 0x20, 0x30, 0x40];
        trie.add(&elem).unwrap();
        assert!(trie.contains(&elem).unwrap());
        assert!(!trie.contains(&[0x10, 0x20, 0x30, 0x41]).unwrap());
    }

    #[test]
    fn test_duplicate_add_returns_ok_false() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x01, 0x02, 0x03, 0x04];
        assert!(trie.add(&elem).unwrap());
        assert!(!trie.add(&elem).unwrap());
        assert_eq!(trie.len(), 1);
    }

    #[test]
    fn test_delete_nonexistent_returns_ok_false() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x01, 0x02, 0x03, 0x04];
        let elem_b = vec![0xFF, 0xFE, 0xFD, 0xFC];
        trie.add(&elem_a).unwrap();
        assert!(!trie.delete(&elem_b).unwrap());

        let mut empty = MerkleTrie::new(4);
        assert!(!empty.delete(&elem_a).unwrap());
    }

    #[test]
    fn test_delete_single_to_empty() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0xAA, 0xBB, 0xCC, 0xDD];
        trie.add(&elem).unwrap();
        assert!(trie.delete(&elem).unwrap());
        assert!(trie.is_empty());
        assert_eq!(trie.root_hash().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_add_three_delete_one_round_trip_hash() {
        let mut trie1 = MerkleTrie::new(4);
        let mut trie2 = MerkleTrie::new(4);
        let a = vec![0x10, 0x00, 0x00, 0x00];
        let b = vec![0x20, 0x00, 0x00, 0x00];
        let c = vec![0x30, 0x00, 0x00, 0x00];

        trie1.add(&a).unwrap();
        trie1.add(&b).unwrap();
        trie1.add(&c).unwrap();
        trie1.delete(&b).unwrap();

        trie2.add(&a).unwrap();
        trie2.add(&c).unwrap();

        assert_eq!(trie1.root_hash().unwrap(), trie2.root_hash().unwrap());
    }

    #[test]
    fn test_insertion_order_independence() {
        let elems: Vec<Vec<u8>> = (0u8..16)
            .map(|i| vec![i, i.wrapping_mul(3), i.wrapping_add(7), i ^ 0xAA])
            .collect();

        let mut t1 = MerkleTrie::new(4);
        for e in &elems {
            t1.add(e).unwrap();
        }

        let mut t2 = MerkleTrie::new(4);
        for e in elems.iter().rev() {
            t2.add(e).unwrap();
        }

        assert_eq!(t1.root_hash().unwrap(), t2.root_hash().unwrap());
        assert_eq!(t1.len(), t2.len());
    }

    #[test]
    fn test_add_many_delete_all() {
        let mut trie = MerkleTrie::new(4);
        let mut elements: Vec<Vec<u8>> = Vec::new();
        for i in 0u8..100 {
            elements.push(vec![
                i,
                i.wrapping_add(1),
                i.wrapping_add(2),
                i.wrapping_add(3),
            ]);
        }
        for e in &elements {
            trie.add(e).unwrap();
        }
        for e in &elements {
            assert!(trie.contains(e).unwrap());
        }
        for e in &elements {
            assert!(trie.delete(e).unwrap());
        }
        assert!(trie.is_empty());
        assert_eq!(trie.root_hash().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_add_delete_add_consistency() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x42, 0x43, 0x44, 0x45];
        trie.add(&elem).unwrap();
        let h1 = trie.root_hash().unwrap();
        trie.delete(&elem).unwrap();
        assert_eq!(trie.root_hash().unwrap(), [0u8; 32]);
        trie.add(&elem).unwrap();
        let h2 = trie.root_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_changes_on_add_and_delete() {
        let mut trie = MerkleTrie::new(4);
        let a = vec![0x10, 0x00, 0x00, 0x00];
        let b = vec![0x20, 0x00, 0x00, 0x00];

        trie.add(&a).unwrap();
        let h_a = trie.root_hash().unwrap();

        trie.add(&b).unwrap();
        let h_ab = trie.root_hash().unwrap();
        assert_ne!(h_a, h_ab);

        trie.delete(&b).unwrap();
        let h_back = trie.root_hash().unwrap();
        assert_eq!(h_a, h_back);
    }

    // -----------------------------------------------------------------------
    // Length-mismatch error paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_wrong_length_errors() {
        let mut trie = MerkleTrie::new(4);
        trie.add(&[1, 2, 3, 4]).unwrap();
        let err = trie.add(&[1, 2, 3]);
        assert!(err.is_err());
    }

    #[test]
    fn test_delete_wrong_length_errors() {
        let mut trie = MerkleTrie::new(4);
        trie.add(&[1, 2, 3, 4]).unwrap();
        let err = trie.delete(&[1, 2, 3]);
        assert!(err.is_err());
    }

    #[test]
    fn test_add_wrong_length_on_first_insert_errors() {
        let mut trie = MerkleTrie::new(36);
        let err = trie.add(&[1, 2, 3]);
        assert!(err.is_err());
        assert_eq!(trie.element_length(), 36);
        assert!(trie.is_empty());
    }

    #[test]
    fn test_add_length_inference_when_new_zero() {
        let mut trie = MerkleTrie::new(0);
        trie.add(&[1, 2, 3, 4]).unwrap();
        assert_eq!(trie.element_length(), 4);
        let err = trie.add(&[1, 2, 3]);
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------------
    // len / is_empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_len_and_is_empty() {
        let mut trie = MerkleTrie::new(4);
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);

        trie.add(&[1, 2, 3, 4]).unwrap();
        assert!(!trie.is_empty());
        assert_eq!(trie.len(), 1);

        trie.add(&[5, 6, 7, 8]).unwrap();
        assert_eq!(trie.len(), 2);

        trie.delete(&[1, 2, 3, 4]).unwrap();
        assert_eq!(trie.len(), 1);

        trie.delete(&[5, 6, 7, 8]).unwrap();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Paged persistence — commit / load via PageCommitter.
    // -----------------------------------------------------------------------

    #[test]
    fn test_commit_then_load_empty_trie() {
        let committer = InMemoryPageCommitter::new();

        let mut trie = MerkleTrie::new(36);
        trie.commit(&committer).unwrap();
        // Only the metadata page (page 0) should exist.
        assert_eq!(committer.page_count(), 1);

        let restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.element_length(), 36);
    }

    #[test]
    fn test_commit_then_load_round_trip_single_element() {
        let committer = InMemoryPageCommitter::new();
        let elem = [0x10, 0x20, 0x30, 0x40];

        let mut trie = MerkleTrie::new(4);
        trie.add(&elem).unwrap();
        let hash_before = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        assert!(restored.contains(&elem).unwrap());
        assert_eq!(restored.root_hash().unwrap(), hash_before);
    }

    #[test]
    fn test_commit_then_load_round_trip_multiple_elements() {
        let committer = InMemoryPageCommitter::new();
        let elems = [
            [0x10, 0x20, 0x30, 0x40],
            [0x50, 0x60, 0x70, 0x80],
            [0x10, 0x30, 0xAA, 0xBB],
            [0xCC, 0xDD, 0xEE, 0xFF],
        ];

        let mut trie = MerkleTrie::new(4);
        for e in &elems {
            trie.add(e).unwrap();
        }
        let hash_before = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        // Lazy: walk every element via contains, then root_hash forces
        // full traversal. After both, the leaf count matches.
        for e in &elems {
            assert!(restored.contains(e).unwrap());
        }
        assert_eq!(restored.root_hash().unwrap(), hash_before);
        assert_eq!(restored.len(), elems.len());
    }

    #[test]
    fn test_load_returns_none_on_fresh_committer() {
        let committer = InMemoryPageCommitter::new();
        let got = MerkleTrie::load(Box::new(committer)).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn test_commit_then_mutate_then_recommit_preserves_root() {
        let committer = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        trie.add(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        trie.commit(&committer).unwrap();

        // Add one more, then commit again.
        trie.add(&[0x50, 0x60, 0x70, 0x80]).unwrap();
        let expected = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(restored.root_hash().unwrap(), expected);
        assert!(restored.contains(&[0x10, 0x20, 0x30, 0x40]).unwrap());
        assert!(restored.contains(&[0x50, 0x60, 0x70, 0x80]).unwrap());
    }

    #[test]
    fn test_in_place_mutation_via_get_mut_survives_round_trip() {
        // Regression for the dirty-page-tracking fix (PR #286 Codex round 1):
        // get_node_mut on a previously-committed node must dirty the page
        // so commit includes it in the write set.
        //
        // Mutate a LEAF's hash (leaves are skipped by recompute_all_hashes).
        let committer = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        trie.add(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        trie.add(&[0x10, 0x21, 0x30, 0x40]).unwrap();
        let _ = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();

        let root_id = trie.root_id().unwrap();
        let leaf_id = find_a_leaf_descendant(&mut trie, root_id);
        let mutated_marker = vec![0xDE, 0xAD, 0xBE, 0xEF];
        trie.get_node_mut(leaf_id).unwrap().unwrap().hash = mutated_marker.clone();
        trie.commit(&committer).unwrap();

        // PLAN-144 TASK-148: the second commit's page-packing pass may
        // relocate the mutated leaf to a new id (the original leaf_id
        // was reported between commits, before the second relocation).
        // Reload and walk the tree by content — assert that SOMEWHERE
        // in the restored trie there is a leaf carrying the marker.
        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        let restored_root = restored.root_id().expect("non-empty trie");
        let found = leaf_with_hash_exists(&mut restored, restored_root, &mutated_marker);
        assert!(
            found,
            "in-place mutation via get_node_mut must persist through commit + load \
             (no leaf with the mutated marker found in the reloaded trie)"
        );
    }

    /// DFS: true iff any leaf in the subtree rooted at `node_id`
    /// carries `target_hash` as its `hash`.
    fn leaf_with_hash_exists(trie: &mut MerkleTrie, node_id: u64, target_hash: &[u8]) -> bool {
        let node = trie
            .get_node(node_id)
            .unwrap()
            .expect("node in cache")
            .clone();
        if node.is_leaf() {
            return node.hash == target_hash;
        }
        for c in &node.children {
            if leaf_with_hash_exists(trie, c.child_id, target_hash) {
                return true;
            }
        }
        false
    }

    /// Recursively find any leaf descendant of `node_id`. The trie's
    /// leaf-storage invariants guarantee at least one exists below any
    /// non-empty internal node. `&mut self` because lookups may lazy-load.
    fn find_a_leaf_descendant(trie: &mut MerkleTrie, node_id: u64) -> u64 {
        let node = trie
            .get_node(node_id)
            .unwrap()
            .expect("node in cache")
            .clone();
        if node.is_leaf() {
            return node_id;
        }
        find_a_leaf_descendant(trie, node.children[0].child_id)
    }

    #[test]
    fn test_commit_after_delete_persists_deletion() {
        let committer = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        trie.add(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        trie.add(&[0x50, 0x60, 0x70, 0x80]).unwrap();
        trie.commit(&committer).unwrap();

        trie.delete(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        let expected = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(restored.root_hash().unwrap(), expected);
        assert!(!restored.contains(&[0x10, 0x20, 0x30, 0x40]).unwrap());
        assert!(restored.contains(&[0x50, 0x60, 0x70, 0x80]).unwrap());
    }

    #[test]
    fn test_evict_rejects_dirty_trie() {
        let mut trie = MerkleTrie::new(4);
        trie.add(&[1, 2, 3, 4]).unwrap();
        // dirty=true, no commit; evict must refuse.
        let err = trie.evict();
        assert!(err.is_err());
    }

    #[test]
    fn test_evict_after_commit_then_load_back_via_lazy_loader() {
        let committer = InMemoryPageCommitter::new();
        // Tight cache target so eviction has work to do.
        let mut trie = MerkleTrie::with_cache_target(4, 1);
        for i in 0u8..20 {
            trie.add(&[i, i.wrapping_mul(3), 0, 0]).unwrap();
        }
        let expected = trie.root_hash().unwrap();
        trie.commit(&committer).unwrap();
        let _evicted = trie.evict().unwrap();

        // Reload via lazy-loader path, recompute root hash — every page
        // is fetched on demand.
        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(restored.root_hash().unwrap(), expected);
    }

    // -----------------------------------------------------------------------
    // Lazy-load specific coverage (PLAN-144 TASK-146).
    // -----------------------------------------------------------------------

    #[test]
    fn test_lazy_load_populates_only_touched_pages() {
        // Build a trie large enough to span multiple internal-node pages
        // when committed. 200 distinct 4-byte elements with mixed
        // prefixes is plenty.
        let committer = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        let elements: Vec<[u8; 4]> = (0u16..200)
            .map(|i| {
                [
                    (i & 0xff) as u8,
                    ((i >> 8) & 0xff) as u8,
                    i.wrapping_mul(7) as u8,
                    i.wrapping_add(13) as u8,
                ]
            })
            .collect();
        for e in &elements {
            trie.add(e).unwrap();
        }
        trie.commit(&committer).unwrap();

        // Reload lazily.
        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap()
            .unwrap();
        // Right after load the cache should hold NO node pages — only
        // the metadata was read.
        let touched_pages_initial = committer.load_page_hits();
        assert!(
            touched_pages_initial.keys().all(|&p| p == 0),
            "load() must touch only page 0 (metadata); touched: {touched_pages_initial:?}"
        );
        committer.reset_load_page_hits();

        // One contains for the first element should load only the pages
        // along its root-to-leaf path — NOT every node page.
        assert!(restored.contains(&elements[0]).unwrap());
        let hits_after_contains = committer.load_page_hits();
        assert!(
            !hits_after_contains.is_empty(),
            "contains must lazy-load at least one page"
        );
        // The element's path is at most ~4 hops deep for 200 elements,
        // so we should not have loaded all of them. The exact number
        // depends on layout; assert "fewer than total persisted pages".
        let total_persisted = committer.page_count();
        let loaded_distinct = hits_after_contains.len();
        assert!(
            loaded_distinct < total_persisted,
            "lazy contains must NOT load every page (loaded {loaded_distinct} / {total_persisted})"
        );
    }

    #[test]
    fn test_lazy_load_propagates_committer_errors_through_contains() {
        // A loader that fails on every load_page; contains() must
        // surface the error.
        struct AlwaysFail;
        impl PageCommitter for AlwaysFail {
            fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
                if id == 0 {
                    // Must succeed for the metadata page (so we get past
                    // load and into a real lazy_loader call).
                    Err(AlgoError::Ledger {
                        message: "load fail (metadata)".into(),
                    })
                } else {
                    Err(AlgoError::Ledger {
                        message: format!("load fail (node page {id})"),
                    })
                }
            }
            fn store_page(&self, _id: u64, _content: &[u8]) -> Result<(), AlgoError> {
                Ok(())
            }
        }

        // First commit to a real committer so metadata exists.
        let real = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        for i in 0u8..10 {
            trie.add(&[i, i.wrapping_mul(3), 0, 0]).unwrap();
        }
        trie.commit(&real).unwrap();

        // Now construct a "two-phase" committer: succeeds for the
        // metadata page (delegates to real), but fails for any node
        // page (returns Err).
        struct Probe {
            real: InMemoryPageCommitter,
            calls: std::sync::Mutex<u64>,
        }
        impl PageCommitter for Probe {
            fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
                if id == 0 {
                    return self.real.load_page(id);
                }
                *self.calls.lock().unwrap() += 1;
                Err(AlgoError::Ledger {
                    message: format!("synthetic node-page load fail (page {id})"),
                })
            }
            fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
                self.real.store_page(id, content)
            }
        }

        let probe = Probe {
            real: real.clone(),
            calls: std::sync::Mutex::new(0),
        };
        let mut restored = MerkleTrie::load(Box::new(probe)).unwrap().unwrap();
        let err = restored.contains(&[0u8; 4]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("synthetic node-page load fail"),
            "committer error must propagate up through contains; got: {msg}"
        );

        // Reference the AlwaysFail struct so it isn't dead code (it's
        // here as documentation of the simpler shape for readers).
        let _ = std::any::TypeId::of::<AlwaysFail>();
    }

    // -----------------------------------------------------------------------
    // from_elements
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_elements_matches_incremental_add() {
        let elems: Vec<[u8; 36]> = (0..10u8)
            .map(|i| {
                let mut e = [0u8; 36];
                e[0] = i;
                e[35] = i.wrapping_mul(7);
                e
            })
            .collect();

        let mut t1 = MerkleTrie::from_elements(elems.iter().copied(), 36).unwrap();

        let mut t2 = MerkleTrie::new(36);
        for e in &elems {
            t2.add(e).unwrap();
        }

        assert_eq!(t1.root_hash().unwrap(), t2.root_hash().unwrap());
        assert_eq!(t1.len(), t2.len());
    }
}
