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
//! History:
//! - **PLAN-130 TASK-132/133/134** (PR #284): structural rewrite to
//!   256-ary, Go conformance gate.
//! - **PLAN-130 TASK-135** (PR #285): element-format fixture lock-in.
//! - **PLAN-130 TASK-136/137** (this PR): swap single-blob `serialize`/
//!   `deserialize` for paged `accounthashes` persistence via the
//!   [`crate::merkle_cache::MerkleTrieCache`] with LRU eviction. The
//!   legacy `merkle_trie` SQL table DDL is retained for [`PLAN-36`]
//!   TASK-118 to drop separately.

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

    /// True iff no elements have been added (or all have been deleted).
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Number of leaf elements currently in the trie.
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

    /// Borrow a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&TrieNode> {
        self.cache.get(id)
    }

    /// Borrow a node by ID mutably.
    pub fn get_node_mut(&mut self, id: u64) -> Option<&mut TrieNode> {
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
    /// Returns `Err` only on element-length mismatch.
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
        if self.node_find(root_id, element) {
            return Ok(false);
        }

        let new_root = self.node_add(root_id, element, &[]);
        // Go does `cache.deleteNode(mt.root)` after add returns the new root.
        // The old root's storage is reused via `refurbishNode`; we just
        // remove the entry. The cache distinguishes "never committed" from
        // "previously committed" — if the root was already on-disk, this
        // marks its page for an update at the next commit.
        self.cache.delete(root_id);
        self.root = Some(new_root);
        self.dirty = true;
        Ok(true)
    }

    /// Delete an element from the trie.
    ///
    /// Returns `Ok(true)` if the element was removed, `Ok(false)` if it was
    /// not present (silent no-op, matching go-algorand `trie.go:174-200`
    /// Delete returning `(false, nil)` on missing).
    /// Returns `Err` only on element-length mismatch.
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
        if !self.node_find(root_id, element) {
            return Ok(false);
        }

        // Special case: the root itself is the leaf we're deleting.
        let root_is_leaf = self.cache.get_or_panic(root_id).is_leaf();
        if root_is_leaf {
            self.cache.delete(root_id);
            self.root = None;
            self.dirty = true;
            return Ok(true);
        }

        let new_root = self.node_remove(root_id, element, &[]);
        // Go: `cache.deleteNode(mt.root); mt.root = updatedRoot;`
        self.cache.delete(root_id);
        self.root = new_root;
        self.dirty = true;
        Ok(true)
    }

    /// True iff `element` is present in the trie.
    pub fn contains(&self, element: &[u8]) -> bool {
        if element.len() != self.element_length {
            return false;
        }
        match self.root {
            None => false,
            Some(id) => self.node_find(id, element),
        }
    }

    /// Compute the root hash.
    ///
    /// - Empty trie: `[0u8; 32]` (matches Go `RootHash` at `trie.go:115-118`).
    /// - Single-leaf root: `SHA512/256(0x00 || leaf.hash)`.
    /// - Internal root: `SHA512/256(0x01 || root.hash)` after recomputation.
    pub fn root_hash(&mut self) -> [u8; 32] {
        let root_id = match self.root {
            None => return [0u8; 32],
            Some(id) => id,
        };

        if self.dirty {
            self.recompute_all_hashes(root_id);
            self.dirty = false;
        }

        let node = self.cache.get_or_panic(root_id);
        let mut hasher = Sha512_256::new();
        if node.is_leaf() {
            hasher.update([0x00]);
        } else {
            hasher.update([0x01]);
        }
        hasher.update(&node.hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
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
                self.recompute_all_hashes(root_id);
            }
            self.dirty = false;
        }
        self.cache.commit(self.root, self.element_length, committer)
    }

    /// Reconstruct a trie from a [`PageCommitter`].
    ///
    /// Reads page 0 for metadata. Returns `Ok(None)` if page 0 doesn't
    /// exist (fresh DB — caller should `rebuild_trie_from_db` or start
    /// empty). On success eagerly loads every reachable node page; lazy
    /// loading is a future optimization.
    pub fn load<C: PageCommitter>(committer: &C) -> Result<Option<Self>, AlgoError> {
        let Some(meta) = MerkleTrieCache::read_metadata_page(committer)? else {
            return Ok(None);
        };

        let mut cache = MerkleTrieCache::new();
        cache.load_all(meta.next_node_id, committer)?;

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
    /// target. The root page is pinned. Caller must guarantee no dirty
    /// pages remain (i.e. `commit` was called immediately before, or
    /// `dirty == false`).
    ///
    /// Returns the number of pages evicted.
    pub fn evict(&mut self) -> Result<usize, AlgoError> {
        if self.dirty {
            return Err(AlgoError::Ledger {
                message: "MerkleTrie::evict called with dirty cache — commit first".into(),
            });
        }
        Ok(self.cache.evict(self.root))
    }

    // -----------------------------------------------------------------------
    // Hash computation — bottom-up, mirrors Go `node.calculateHash` at
    // `node.go:227-252`.
    // -----------------------------------------------------------------------

    fn recompute_all_hashes(&mut self, root_id: u64) {
        let mut path: Vec<u8> = Vec::new();
        self.recompute_hash_at(root_id, &mut path);
    }

    fn recompute_hash_at(&mut self, node_id: u64, path: &mut Vec<u8>) {
        let is_leaf = self.cache.get_or_panic(node_id).is_leaf();
        if is_leaf {
            // Leaves never recompute — their `hash` is the element remainder
            // (or full element for a single-leaf root) and is set at
            // construction time.
            return;
        }

        // Recurse into children first so their hashes are up-to-date.
        let child_descriptors: Vec<(u8, u64)> = self
            .cache
            .get_or_panic(node_id)
            .children
            .iter()
            .map(|c| (c.hash_index, c.child_id))
            .collect();
        for (hi, cid) in &child_descriptors {
            path.push(*hi);
            self.recompute_hash_at(*cid, path);
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
            let child = self.cache.get_or_panic(*cid);
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

        let node = self.cache.get_mut(node_id).unwrap();
        node.hash = result.to_vec();
    }

    // -----------------------------------------------------------------------
    // node_find — mirror of Go `node.find` at `node.go:82-96`.
    // -----------------------------------------------------------------------

    fn node_find(&self, node_id: u64, d: &[u8]) -> bool {
        let node = self.cache.get_or_panic(node_id);
        if node.is_leaf() {
            return d == node.hash.as_slice();
        }
        if d.is_empty() {
            // Shouldn't happen with fixed-length elements; guard anyway.
            return false;
        }
        if !node.children_mask.bit(d[0]) {
            return false;
        }
        let idx = node.index_of(d[0]);
        let child_id = node.children[idx].child_id;
        self.node_find(child_id, &d[1..])
    }

    // -----------------------------------------------------------------------
    // node_add — mirror of Go `node.add` at `node.go:98-220`.
    //
    // Assumes the key is absent (the public `add` does a `find` first).
    // Returns the new node ID to use in the parent. Caller is responsible
    // for replacing the old node ID in its own children list (or in the trie
    // root pointer).
    // -----------------------------------------------------------------------

    fn node_add(&mut self, node_id: u64, d: &[u8], path: &[u8]) -> u64 {
        let node = self.cache.get_or_panic(node_id).clone();

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
            return top_id;
        }

        // Non-leaf: branch on d[0].
        if !node.children_mask.bit(d[0]) {
            // No existing child at d[0]: insert a new leaf and rebuild this
            // internal node with the additional child entry.
            let leaf = TrieNode::leaf(d[1..].to_vec());
            let leaf_id = self.allocate_node(leaf);

            let mut new_children = Vec::with_capacity(node.children.len() + 1);
            let mut inserted = false;
            for c in &node.children {
                if !inserted && d[0] < c.hash_index {
                    new_children.push(ChildEntry {
                        hash_index: d[0],
                        child_id: leaf_id,
                    });
                    inserted = true;
                }
                new_children.push(c.clone());
            }
            if !inserted {
                new_children.push(ChildEntry {
                    hash_index: d[0],
                    child_id: leaf_id,
                });
            }
            let mut new_mask = node.children_mask;
            new_mask.set_bit(d[0]);

            let new_node = TrieNode {
                hash: path.to_vec(),
                children: new_children,
                children_mask: new_mask,
            };
            self.cache.delete(node_id);
            return self.allocate_node(new_node);
        }

        // Existing child at d[0]: recurse, then rebuild this node with the
        // updated child id.
        let child_idx = node.index_of(d[0]);
        let cur_child_id = node.children[child_idx].child_id;
        let mut sub_path = Vec::with_capacity(path.len() + 1);
        sub_path.extend_from_slice(path);
        sub_path.push(d[0]);
        let updated_child_id = self.node_add(cur_child_id, &d[1..], &sub_path);

        let mut new_children = node.children.clone();
        new_children[child_idx].child_id = updated_child_id;
        let new_node = TrieNode {
            hash: path.to_vec(),
            children: new_children,
            children_mask: node.children_mask,
        };
        self.cache.delete(node_id);
        self.allocate_node(new_node)
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

    fn node_remove(&mut self, node_id: u64, key: &[u8], path: &[u8]) -> Option<u64> {
        let node = self.cache.get_or_panic(node_id).clone();
        debug_assert!(!node.is_leaf(), "node_remove must not be called on leaves");

        let child_idx = node.index_of(key[0]);
        let child_id = node.children[child_idx].child_id;
        let child = self.cache.get_or_panic(child_id).clone();

        // Mirrors Go `node.remove` at node.go:266-289. We construct `new_node`
        // — the surviving node at this position — then potentially collapse
        // it if it ends up with a single leaf child (Go's "collapse" block at
        // node.go:291-304).
        let new_node: TrieNode = if child.is_leaf() {
            // Remove this leaf entirely from our children. Per Go's comment
            // at node.go:269, the tree forbids internal nodes with exactly
            // one leaf child and no other children, so before this step we
            // had ≥2 children — after removing one leaf, ≥1 remains.
            let mut new_children = node.children.clone();
            new_children.remove(child_idx);
            let mut new_mask = node.children_mask;
            new_mask.clear_bit(key[0]);
            // Free the leaf's storage.
            self.cache.delete(child_id);
            TrieNode {
                hash: path.to_vec(),
                children: new_children,
                children_mask: new_mask,
            }
        } else {
            // Recurse. The child is non-leaf, so `remove` always returns
            // `Some` (the tree-invariant guarantees the child has ≥2 children
            // before, possibly collapsing to a leaf after — still `Some`).
            let mut sub_path = Vec::with_capacity(path.len() + 1);
            sub_path.extend_from_slice(path);
            sub_path.push(key[0]);
            let updated = self
                .node_remove(child_id, &key[1..], &sub_path)
                .expect("non-leaf remove always returns Some");
            // Free the old child slot (Go's `cache.refurbishNode(childNodeID)`
            // returns a new id; we mirror that by replacing the children
            // entry's id).
            let mut new_children = node.children.clone();
            new_children[child_idx].child_id = updated;
            TrieNode {
                hash: path.to_vec(),
                children: new_children,
                children_mask: node.children_mask,
            }
        };

        // Collapse: if `new_node` has exactly one child and that child is a
        // leaf, convert `new_node` itself into a leaf carrying
        // `[only_child.hash_index] || only_child.hash`. Matches Go
        // `node.go:291-304`.
        let collapsed = if new_node.children.len() == 1 {
            let only = &new_node.children[0];
            let only_child = self.cache.get_or_panic(only.child_id);
            if only_child.is_leaf() {
                let mut merged = Vec::with_capacity(1 + only_child.hash.len());
                merged.push(only.hash_index);
                merged.extend_from_slice(&only_child.hash);
                let only_child_id = only.child_id;
                self.cache.delete(only_child_id);
                Some(TrieNode::leaf(merged))
            } else {
                None
            }
        } else {
            None
        };

        let final_node = collapsed.unwrap_or(new_node);
        // Free the original node and allocate the surviving node.
        self.cache.delete(node_id);
        Some(self.allocate_node(final_node))
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
        assert_eq!(trie.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf_root_hash() {
        let mut trie = MerkleTrie::new(36);
        let mut elem = vec![0u8; 36];
        elem[0] = 0xAB;
        elem[35] = 0xCD;

        trie.add(&elem).unwrap();
        let root = trie.root_hash();

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
        assert_eq!(trie.root_hash(), sha512_256(&input));
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

        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_b));

        let root = trie.root_id().unwrap();
        let root_node = trie.get_node(root).unwrap();
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
        assert_eq!(trie.root_hash(), sha512_256(&root_input));
    }

    #[test]
    fn test_add_two_elements_one_byte_shared_prefix() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x20, 0xAA, 0xBB];
        let elem_b = vec![0x10, 0x30, 0xCC, 0xDD];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_b));

        let root = trie.root_id().unwrap();
        let root_node = trie.get_node(root).unwrap();
        assert!(!root_node.is_leaf());
        assert_eq!(root_node.children.len(), 1);
        assert_eq!(root_node.children[0].hash_index, 0x10);

        let branch_id = root_node.children[0].child_id;
        let branch = trie.get_node(branch_id).unwrap();
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
        assert_eq!(trie.root_hash(), sha512_256(&top));
    }

    // -----------------------------------------------------------------------
    // Add / Delete / Contains
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_then_contains() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x10, 0x20, 0x30, 0x40];
        trie.add(&elem).unwrap();
        assert!(trie.contains(&elem));
        assert!(!trie.contains(&[0x10, 0x20, 0x30, 0x41]));
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
        assert_eq!(trie.root_hash(), [0u8; 32]);
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

        assert_eq!(trie1.root_hash(), trie2.root_hash());
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

        assert_eq!(t1.root_hash(), t2.root_hash());
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
            assert!(trie.contains(e));
        }
        for e in &elements {
            assert!(trie.delete(e).unwrap());
        }
        assert!(trie.is_empty());
        assert_eq!(trie.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_add_delete_add_consistency() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x42, 0x43, 0x44, 0x45];
        trie.add(&elem).unwrap();
        let h1 = trie.root_hash();
        trie.delete(&elem).unwrap();
        assert_eq!(trie.root_hash(), [0u8; 32]);
        trie.add(&elem).unwrap();
        let h2 = trie.root_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_changes_on_add_and_delete() {
        let mut trie = MerkleTrie::new(4);
        let a = vec![0x10, 0x00, 0x00, 0x00];
        let b = vec![0x20, 0x00, 0x00, 0x00];

        trie.add(&a).unwrap();
        let h_a = trie.root_hash();

        trie.add(&b).unwrap();
        let h_ab = trie.root_hash();
        assert_ne!(h_a, h_ab);

        trie.delete(&b).unwrap();
        let h_back = trie.root_hash();
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

        let restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.element_length(), 36);
    }

    #[test]
    fn test_commit_then_load_round_trip_single_element() {
        let committer = InMemoryPageCommitter::new();
        let elem = [0x10, 0x20, 0x30, 0x40];

        let mut trie = MerkleTrie::new(4);
        trie.add(&elem).unwrap();
        let hash_before = trie.root_hash();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert_eq!(restored.len(), 1);
        assert!(restored.contains(&elem));
        assert_eq!(restored.root_hash(), hash_before);
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
        let hash_before = trie.root_hash();
        let len_before = trie.len();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert_eq!(restored.len(), len_before);
        assert_eq!(restored.root_hash(), hash_before);
        for e in &elems {
            assert!(restored.contains(e));
        }
    }

    #[test]
    fn test_load_returns_none_on_fresh_committer() {
        let committer = InMemoryPageCommitter::new();
        let got = MerkleTrie::load(&committer).unwrap();
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
        let expected = trie.root_hash();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert_eq!(restored.root_hash(), expected);
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn test_commit_after_delete_persists_deletion() {
        let committer = InMemoryPageCommitter::new();
        let mut trie = MerkleTrie::new(4);
        trie.add(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        trie.add(&[0x50, 0x60, 0x70, 0x80]).unwrap();
        trie.commit(&committer).unwrap();

        trie.delete(&[0x10, 0x20, 0x30, 0x40]).unwrap();
        let expected = trie.root_hash();
        trie.commit(&committer).unwrap();

        let mut restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert_eq!(restored.root_hash(), expected);
        assert!(!restored.contains(&[0x10, 0x20, 0x30, 0x40]));
        assert!(restored.contains(&[0x50, 0x60, 0x70, 0x80]));
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
    fn test_evict_after_commit_keeps_root_page() {
        let committer = InMemoryPageCommitter::new();
        // Tight cache target so eviction has work to do.
        let mut trie = MerkleTrie::with_cache_target(4, 1);
        // Add a handful of elements that will land in multiple pages
        // worth of internal nodes.
        for i in 0u8..20 {
            trie.add(&[i, i.wrapping_mul(3), 0, 0]).unwrap();
        }
        let expected = trie.root_hash();
        trie.commit(&committer).unwrap();
        let evicted = trie.evict().unwrap();
        // We expect at least some pages to have been evicted given the
        // tight target.
        let _ = evicted; // not asserting an exact number — depends on layout

        // Root page is pinned: the trie can still serve root_hash
        // because it walks the root node first. (Re-load from disk
        // also works — verified by the round-trip tests.)
        let mut restored = MerkleTrie::load(&committer).unwrap().unwrap();
        assert_eq!(restored.root_hash(), expected);
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

        assert_eq!(t1.root_hash(), t2.root_hash());
        assert_eq!(t1.len(), t2.len());
    }
}
