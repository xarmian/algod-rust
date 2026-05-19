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
//! Persistence: single-blob msgpack via `serialize`/`deserialize`. The runtime
//! swap to paged `accounthashes` lands in PLAN-130 TASK-136; the legacy DDL
//! drop lands in PLAN-36 TASK-118.

use std::collections::HashMap;

use algo_error::AlgoError;
use sha2::{Digest, Sha512_256};

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
    /// previous design's `invalidate()`; under the new design, dirty tracking
    /// lives on the trie, not per-node. This is a no-op.
    pub fn invalidate(&mut self) {}
}

// ---------------------------------------------------------------------------
// MerkleTrie — top-level trie wrapping the node store.
// Mirrors `crypto/merkletrie/trie.go:62-77`.
// ---------------------------------------------------------------------------

/// In-memory 256-ary Merkle trie matching go-algorand's algorithm.
///
/// Elements are fixed-length byte slices (typically 36 bytes for accounts —
/// see `trie_hash.rs::ELEMENT_SIZE`). The trie supports `add` / `delete` /
/// `contains` / `root_hash`, plus single-blob `serialize` / `deserialize` for
/// the current (pre-TASK-136) persistence layer.
#[derive(Debug)]
pub struct MerkleTrie {
    /// Root node ID (`None` when the trie is empty).
    root: Option<u64>,
    /// In-memory node store. Node IDs are monotonically allocated; deleted
    /// nodes leave gaps (matching Go's `merkleTrieCache` pre-eviction model).
    nodes: HashMap<u64, TrieNode>,
    /// Next node ID to allocate.
    next_id: u64,
    /// Fixed element size in bytes (36 for V6 account hashing).
    element_length: usize,
    /// True iff any internal-node hash may be stale and must be recomputed
    /// on the next `root_hash` call. Set on every `add` / `delete`.
    dirty: bool,
}

impl MerkleTrie {
    // -----------------------------------------------------------------------
    // Construction + node-store accessors (public so tests can drive the
    // store directly — mirrors the original API surface).
    // -----------------------------------------------------------------------

    /// Create a new empty trie with the given fixed element length.
    pub fn new(element_length: usize) -> Self {
        Self {
            root: None,
            nodes: HashMap::new(),
            next_id: 1,
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
        self.nodes.values().filter(|n| n.is_leaf()).count()
    }

    /// Root node ID, if any.
    pub fn root_id(&self) -> Option<u64> {
        self.root
    }

    /// Set the root node ID (used by tests + deserialize).
    pub fn set_root(&mut self, id: Option<u64>) {
        self.root = id;
        self.dirty = true;
    }

    /// Allocate a new node in the store and return its ID.
    pub fn allocate_node(&mut self, node: TrieNode) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, node);
        self.dirty = true;
        id
    }

    /// Borrow a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&TrieNode> {
        self.nodes.get(&id)
    }

    /// Borrow a node by ID mutably.
    pub fn get_node_mut(&mut self, id: u64) -> Option<&mut TrieNode> {
        self.dirty = true;
        self.nodes.get_mut(&id)
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
        // First element bootstraps element_length (matches Go's behavior at
        // trie.go:144-145 where the first Add captures `len(d)`). The
        // public-API caller typically sets element_length via `new(...)`, so
        // length-mismatch is the only error path.
        if self.root.is_none() {
            let leaf = TrieNode::leaf(element.to_vec());
            let id = self.allocate_node(leaf);
            self.root = Some(id);
            self.element_length = element.len();
            self.dirty = true;
            return Ok(true);
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

        // Existence check: silent-no-op on duplicate (matches Go trie.go:155-158).
        let root_id = self.root.unwrap();
        if self.node_find(root_id, element) {
            return Ok(false);
        }

        let new_root = self.node_add(root_id, element, &[]);
        // Go does `cache.deleteNode(mt.root)` after add returns the new root.
        // The old root's storage is reused via `refurbishNode`; we just remove
        // the entry.
        self.nodes.remove(&root_id);
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
        let root_is_leaf = self.nodes[&root_id].is_leaf();
        if root_is_leaf {
            self.nodes.remove(&root_id);
            self.root = None;
            self.dirty = true;
            return Ok(true);
        }

        let new_root = self.node_remove(root_id, element, &[]);
        // Go: `cache.deleteNode(mt.root); mt.root = updatedRoot;`
        self.nodes.remove(&root_id);
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

        let node = &self.nodes[&root_id];
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
    // Hash computation — bottom-up, mirrors Go `node.calculateHash` at
    // `node.go:227-252`.
    // -----------------------------------------------------------------------

    /// Recompute hashes for every internal node reachable from `root_id`.
    ///
    /// The traversal order matters: when computing a parent's hash we need
    /// each child's *current* hash bytes (a leaf's element-remainder, or an
    /// internal's already-computed SHA hash). We post-order DFS so children
    /// are hashed before parents.
    ///
    /// Each internal node's `hash` field is overwritten in place: before the
    /// recomputation it holds the path-from-root bytes; afterward it holds
    /// the SHA512/256 output. To support recomputation across multiple
    /// `root_hash` calls (the trie may be mutated again), we reconstruct the
    /// path-from-root via the recursion's `path` parameter rather than
    /// relying on the (now-overwritten) field.
    fn recompute_all_hashes(&mut self, root_id: u64) {
        let mut path: Vec<u8> = Vec::new();
        self.recompute_hash_at(root_id, &mut path);
    }

    fn recompute_hash_at(&mut self, node_id: u64, path: &mut Vec<u8>) {
        let is_leaf = self.nodes[&node_id].is_leaf();
        if is_leaf {
            // Leaves never recompute — their `hash` is the element remainder
            // (or full element for a single-leaf root) and is set at
            // construction time.
            return;
        }

        // Recurse into children first so their hashes are up-to-date.
        let child_descriptors: Vec<(u8, u64)> = self.nodes[&node_id]
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
        // path length must fit in a byte — Go writes `byte(len(path))`. The
        // path length equals the depth of this node; depth is bounded by
        // `element_length` (= 36), so this fits comfortably.
        debug_assert!(path.len() <= 255);
        acc.push(path.len() as u8);
        acc.extend_from_slice(path);

        for (hi, cid) in &child_descriptors {
            let child = &self.nodes[cid];
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

        let node = self.nodes.get_mut(&node_id).unwrap();
        node.hash = result.to_vec();
    }

    // -----------------------------------------------------------------------
    // node_find — mirror of Go `node.find` at `node.go:82-96`.
    // -----------------------------------------------------------------------

    fn node_find(&self, node_id: u64, d: &[u8]) -> bool {
        let node = &self.nodes[&node_id];
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
        let node = self.nodes[&node_id].clone();

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
            self.nodes.remove(&node_id);
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
            self.nodes.remove(&node_id);
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
        self.nodes.remove(&node_id);
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
        let node = self.nodes[&node_id].clone();
        debug_assert!(!node.is_leaf(), "node_remove must not be called on leaves");

        let child_idx = node.index_of(key[0]);
        let child_id = node.children[child_idx].child_id;
        let child = self.nodes[&child_id].clone();

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
            self.nodes.remove(&child_id);
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
            let only_child = &self.nodes[&only.child_id];
            if only_child.is_leaf() {
                let mut merged = Vec::with_capacity(1 + only_child.hash.len());
                merged.push(only.hash_index);
                merged.extend_from_slice(&only_child.hash);
                let only_child_id = only.child_id;
                self.nodes.remove(&only_child_id);
                Some(TrieNode::leaf(merged))
            } else {
                None
            }
        } else {
            None
        };

        let final_node = collapsed.unwrap_or(new_node);
        // Free the original node and allocate the surviving node.
        self.nodes.remove(&node_id);
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

    // -----------------------------------------------------------------------
    // Serialize / Deserialize — single-blob msgpack. Format is Rust-internal
    // (NOT Go-compatible); used by the legacy `merkle_trie` SQL table. PLAN-
    // 130 TASK-136 deletes both methods when paged persistence lands.
    // -----------------------------------------------------------------------

    /// Serialize the trie to a compact msgpack representation for storage in
    /// the legacy single-blob `merkle_trie` SQL row.
    ///
    /// Layout: map with keys `r` (root_id, Nil if empty), `n` (next_id),
    /// `e` (element_length), `d` (nodes — map of `id -> node_map`).
    /// Each node_map: `h` (hash bytes), `m` (children_mask as 4×u64 array),
    /// `c` (children — array of `[hash_index, child_id]` pairs).
    pub fn serialize(&self) -> Vec<u8> {
        let mut nodes_vec: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
        for (&id, node) in &self.nodes {
            let mut node_map: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
            node_map.push((
                rmpv::Value::String("h".into()),
                rmpv::Value::Binary(node.hash.clone()),
            ));
            let mask_arr: Vec<rmpv::Value> = node
                .children_mask
                .d
                .iter()
                .map(|&w| rmpv::Value::from(w))
                .collect();
            node_map.push((
                rmpv::Value::String("m".into()),
                rmpv::Value::Array(mask_arr),
            ));
            if !node.children.is_empty() {
                let children: Vec<rmpv::Value> = node
                    .children
                    .iter()
                    .map(|c| {
                        rmpv::Value::Array(vec![
                            rmpv::Value::from(c.hash_index as u64),
                            rmpv::Value::from(c.child_id),
                        ])
                    })
                    .collect();
                node_map.push((
                    rmpv::Value::String("c".into()),
                    rmpv::Value::Array(children),
                ));
            }
            nodes_vec.push((rmpv::Value::from(id), rmpv::Value::Map(node_map)));
        }

        let root_val = match self.root {
            Some(id) => rmpv::Value::from(id),
            None => rmpv::Value::Nil,
        };

        let top = rmpv::Value::Map(vec![
            (rmpv::Value::String("r".into()), root_val),
            (
                rmpv::Value::String("n".into()),
                rmpv::Value::from(self.next_id),
            ),
            (
                rmpv::Value::String("e".into()),
                rmpv::Value::from(self.element_length as u64),
            ),
            (rmpv::Value::String("d".into()), rmpv::Value::Map(nodes_vec)),
        ]);

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &top).expect("msgpack encode trie");
        buf
    }

    /// Inverse of `serialize`.
    pub fn deserialize(data: &[u8], element_length: usize) -> Result<Self, AlgoError> {
        let val: rmpv::Value =
            rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
                message: format!("trie deserialize error: {e}"),
            })?;

        let map = match val {
            rmpv::Value::Map(m) => m,
            _ => {
                return Err(AlgoError::Ledger {
                    message: "expected msgpack map for trie".into(),
                })
            }
        };

        let mut root: Option<u64> = None;
        let mut next_id: u64 = 1;
        let mut stored_element_length: usize = element_length;
        let mut nodes = HashMap::new();

        for (k, v) in map {
            match k.as_str().unwrap_or("") {
                "r" => {
                    root = v.as_u64();
                }
                "n" => {
                    next_id = v.as_u64().unwrap_or(1);
                }
                "e" => {
                    stored_element_length = v.as_u64().unwrap_or(element_length as u64) as usize;
                }
                "d" => {
                    if let rmpv::Value::Map(node_pairs) = v {
                        for (nk, nv) in node_pairs {
                            let id = nk.as_u64().ok_or_else(|| AlgoError::Ledger {
                                message: "bad node id".into(),
                            })?;
                            let node = Self::deserialize_node(nv)?;
                            nodes.insert(id, node);
                        }
                    }
                }
                _ => {}
            }
        }

        if stored_element_length != element_length {
            return Err(AlgoError::Ledger {
                message: format!(
                    "element_length mismatch: stored={stored_element_length}, expected={element_length}"
                ),
            });
        }

        Ok(Self {
            root,
            nodes,
            next_id,
            element_length,
            // After deserialize, every internal node's `hash` field already
            // holds the SHA hash from before serialization, so `root_hash`
            // can return without recomputation.
            dirty: false,
        })
    }

    fn deserialize_node(val: rmpv::Value) -> Result<TrieNode, AlgoError> {
        let map = match val {
            rmpv::Value::Map(m) => m,
            _ => {
                return Err(AlgoError::Ledger {
                    message: "expected map for trie node".into(),
                })
            }
        };

        let mut hash = Vec::new();
        let mut children_mask = Bitset::ZERO;
        let mut children = Vec::new();

        for (k, v) in map {
            match k.as_str().unwrap_or("") {
                "h" => {
                    if let Some(b) = v.as_slice() {
                        hash = b.to_vec();
                    }
                }
                "m" => {
                    if let rmpv::Value::Array(arr) = v {
                        for (i, w) in arr.into_iter().take(4).enumerate() {
                            children_mask.d[i] = w.as_u64().unwrap_or(0);
                        }
                    }
                }
                "c" => {
                    if let rmpv::Value::Array(arr) = v {
                        for item in arr {
                            if let rmpv::Value::Array(pair) = item {
                                if pair.len() == 2 {
                                    let hash_index = pair[0].as_u64().unwrap_or(0) as u8;
                                    let child_id = pair[1].as_u64().unwrap_or(0);
                                    children.push(ChildEntry {
                                        hash_index,
                                        child_id,
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // If the persisted blob lacked the explicit mask (older format) or
        // had a mismatched one, rederive from children to keep the invariant.
        if children_mask == Bitset::ZERO && !children.is_empty() {
            for c in &children {
                children_mask.set_bit(c.hash_index);
            }
        }

        Ok(TrieNode {
            hash,
            children,
            children_mask,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        // Go: b.d[bit/64] |= 1 << (bit & 63). Bit 0 → d[0] low bit;
        // bit 63 → d[0] high bit; bit 64 → d[1] low bit; bit 255 → d[3] high bit.
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
        // A single-leaf root carries the FULL element. Root hash =
        // SHA512_256(0x00 || element). This is the Go invariant from
        // trie.go:144 (`pnode.hash = d` on first add) and trie.go:130.
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
        // Same test, but constructing the leaf node by hand. Verifies the
        // public TrieNode::leaf constructor and set_root paths.
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
    // Two-element splits (verifies leaf-remainder + chain-ancestor structure)
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_two_elements_no_shared_prefix() {
        // Two 4-byte elements with no shared prefix → root is a branch node
        // at depth 0 with two leaves, each carrying 3-byte remainders.
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

        // Path-from-root for the root branch is empty.
        // (Field is overwritten by root_hash; check via a fresh compute path.)
        // We verify the root hash matches the hand-computed value below.

        // Manually compute expected.
        //
        // leaf A: hash = elem_a[1..] = [0xAA, 0xBB, 0xCC]
        // leaf B: hash = elem_b[1..] = [0xDD, 0xEE, 0xFF]
        //
        // root_internal_hash = SHA512_256(
        //   0x00 (path length = 0)
        //   0x00 (leaf tag A) || 0x03 (len) || 0x10 (hash_index) || 0xAA 0xBB 0xCC
        //   0x00 (leaf tag B) || 0x03 (len) || 0x20 (hash_index) || 0xDD 0xEE 0xFF
        // )
        let mut acc = vec![0x00];
        acc.extend_from_slice(&[0x00, 0x03, 0x10, 0xAA, 0xBB, 0xCC]);
        acc.extend_from_slice(&[0x00, 0x03, 0x20, 0xDD, 0xEE, 0xFF]);
        let internal_hash = sha512_256(&acc);

        let mut root_input = vec![0x01];
        root_input.extend_from_slice(&internal_hash);
        let expected_root = sha512_256(&root_input);

        assert_eq!(trie.root_hash(), expected_root);
    }

    #[test]
    fn test_add_two_elements_one_byte_shared_prefix() {
        // [0x10, 0x20, 0xAA, 0xBB] and [0x10, 0x30, 0xCC, 0xDD]
        // Shared prefix = 1 byte (0x10).
        //
        // Go materializes this as:
        //   root: 1 ancestor with 1 child @ 0x10 → branch_at_depth_1
        //   branch_at_depth_1: 2 children @ 0x20 (leaf A) and @ 0x30 (leaf B)
        //   leaf A: hash = elem_a[2..] = [0xAA, 0xBB]
        //   leaf B: hash = [0xCC, 0xDD]
        //
        // Path-from-root values:
        //   root ancestor: path = []
        //   branch_at_depth_1: path = [0x10]
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x20, 0xAA, 0xBB];
        let elem_b = vec![0x10, 0x30, 0xCC, 0xDD];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_b));

        // Walk: root → child @ 0x10 → branch
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

        // Verify hash composition end-to-end.
        // branch_hash = SHA512_256(
        //   0x01 (path_len=1) || 0x10 (path)
        //   0x00 || 0x02 || 0x20 || 0xAA 0xBB
        //   0x00 || 0x02 || 0x30 || 0xCC 0xDD
        // )
        let mut branch_acc = vec![0x01, 0x10];
        branch_acc.extend_from_slice(&[0x00, 0x02, 0x20, 0xAA, 0xBB]);
        branch_acc.extend_from_slice(&[0x00, 0x02, 0x30, 0xCC, 0xDD]);
        let branch_hash = sha512_256(&branch_acc);

        // root_hash_internal = SHA512_256(
        //   0x00 (path_len=0)
        //   0x01 (internal tag) || 32 (len) || 0x10 (hash_index) || branch_hash
        // )
        let mut root_acc = vec![0x00];
        root_acc.push(0x01);
        root_acc.push(branch_hash.len() as u8);
        root_acc.push(0x10);
        root_acc.extend_from_slice(&branch_hash);
        let root_internal = sha512_256(&root_acc);

        let mut top = vec![0x01];
        top.extend_from_slice(&root_internal);
        let expected = sha512_256(&top);

        assert_eq!(trie.root_hash(), expected);
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
        // Go trie.go:155-158: silent no-op on duplicate.
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x01, 0x02, 0x03, 0x04];
        assert!(trie.add(&elem).unwrap());
        assert!(!trie.add(&elem).unwrap());
        assert_eq!(trie.len(), 1);
    }

    #[test]
    fn test_delete_nonexistent_returns_ok_false() {
        // Go trie.go:185-188: silent no-op on missing.
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x01, 0x02, 0x03, 0x04];
        let elem_b = vec![0xFF, 0xFE, 0xFD, 0xFC];
        trie.add(&elem_a).unwrap();
        assert!(!trie.delete(&elem_b).unwrap());

        // Same behavior from an empty trie.
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
        // Insertion-order independent: build (A, B, C) and (A, C, B), delete
        // both to (A, C), compare hashes.
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
        // Insert in reverse order.
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
    // Length-mismatch error path (kept from prior design)
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
    // Serialize / Deserialize
    // -----------------------------------------------------------------------

    #[test]
    fn test_serialize_deserialize_empty() {
        let trie = MerkleTrie::new(36);
        let data = trie.serialize();
        let restored = MerkleTrie::deserialize(&data, 36).unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.len(), 0);
        assert_eq!(restored.element_length(), 36);
    }

    #[test]
    fn test_serialize_deserialize_single_element() {
        let mut trie = MerkleTrie::new(4);
        let elem = [0x10, 0x20, 0x30, 0x40];
        trie.add(&elem).unwrap();
        let hash_before = trie.root_hash();

        let data = trie.serialize();
        let mut restored = MerkleTrie::deserialize(&data, 4).unwrap();

        assert_eq!(restored.len(), 1);
        assert!(restored.contains(&elem));
        assert_eq!(restored.root_hash(), hash_before);
    }

    #[test]
    fn test_serialize_deserialize_multiple_elements() {
        let mut trie = MerkleTrie::new(4);
        let elems: Vec<[u8; 4]> = vec![
            [0x10, 0x20, 0x30, 0x40],
            [0x50, 0x60, 0x70, 0x80],
            [0x10, 0x30, 0xAA, 0xBB],
            [0xCC, 0xDD, 0xEE, 0xFF],
        ];
        for e in &elems {
            trie.add(e).unwrap();
        }
        let hash_before = trie.root_hash();
        let len_before = trie.len();

        let data = trie.serialize();
        let mut restored = MerkleTrie::deserialize(&data, 4).unwrap();

        assert_eq!(restored.len(), len_before);
        assert_eq!(restored.root_hash(), hash_before);
        for e in &elems {
            assert!(restored.contains(e));
        }
    }

    #[test]
    fn test_serialize_deserialize_element_length_mismatch() {
        let trie = MerkleTrie::new(4);
        let data = trie.serialize();
        let err = MerkleTrie::deserialize(&data, 36);
        assert!(err.is_err());
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

    #[test]
    fn test_serialize_survives_mutations() {
        let mut trie = MerkleTrie::new(4);
        let elems = [
            [0x10, 0x20, 0x30, 0x40],
            [0x50, 0x60, 0x70, 0x80],
            [0xAA, 0xBB, 0xCC, 0xDD],
        ];
        for e in &elems {
            trie.add(e).unwrap();
        }
        trie.delete(&elems[1]).unwrap();
        let hash_before = trie.root_hash();

        let data = trie.serialize();
        let mut restored = MerkleTrie::deserialize(&data, 4).unwrap();
        assert_eq!(restored.root_hash(), hash_before);
        assert!(restored.contains(&elems[0]));
        assert!(!restored.contains(&elems[1]));
        assert!(restored.contains(&elems[2]));

        restored.add(&elems[1]).unwrap();
        assert!(restored.contains(&elems[1]));
    }
}
