//! Merkle trie implementation matching go-algorand's `crypto/merkletrie/`.
//!
//! This is a compressed trie over fixed-length elements (not key-value pairs).
//! Elements are self-contained and sorted by their byte content. The trie
//! supports incremental hash computation with caching.

use std::collections::HashMap;

use algo_error::AlgoError;
use sha2::{Digest, Sha512_256};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single child pointer in an internal trie node.
#[derive(Debug, Clone)]
pub struct ChildEntry {
    /// The byte value at the branch point (the discriminating byte).
    pub hash_index: u8,
    /// ID of the child node in the node store.
    pub child_id: u64,
}

/// A node in the compressed Merkle trie.
#[derive(Debug, Clone)]
pub struct TrieNode {
    /// Path compression: shared prefix bytes for this subtree.
    pub path: Vec<u8>,
    /// Children: sorted list of (byte_index, child_node_id) pairs.
    /// For leaf nodes this is empty.
    pub children: Vec<ChildEntry>,
    /// Cached hash. `None` means dirty (needs recomputation).
    /// For leaf nodes this holds the raw element data (no hashing applied).
    pub hash: Option<Vec<u8>>,
    /// Whether this node is a leaf.
    pub is_leaf: bool,
}

impl TrieNode {
    /// Create a new leaf node containing `element`.
    pub fn leaf(element: Vec<u8>) -> Self {
        Self {
            path: Vec::new(),
            children: Vec::new(),
            hash: Some(element),
            is_leaf: true,
        }
    }

    /// Create a new internal node with the given path prefix and children.
    pub fn internal(path: Vec<u8>, children: Vec<ChildEntry>) -> Self {
        Self {
            path,
            children,
            hash: None,
            is_leaf: false,
        }
    }

    /// Mark this node's cached hash as dirty so it will be recomputed.
    pub fn invalidate(&mut self) {
        if !self.is_leaf {
            self.hash = None;
        }
    }
}

/// In-memory compressed Merkle trie matching go-algorand's algorithm.
///
/// Elements are fixed-length byte slices. The trie structure compresses
/// shared prefixes and caches intermediate hashes for efficient root-hash
/// computation.
#[derive(Debug)]
pub struct MerkleTrie {
    /// Root node ID (`None` when the trie is empty).
    root: Option<u64>,
    /// In-memory node store.
    nodes: HashMap<u64, TrieNode>,
    /// Next node ID to allocate.
    next_id: u64,
    /// Fixed element size in bytes (36 for V6 account hashing).
    element_length: usize,
}

impl MerkleTrie {
    /// Create a new empty trie with the given fixed element length.
    pub fn new(element_length: usize) -> Self {
        Self {
            root: None,
            nodes: HashMap::new(),
            next_id: 1,
            element_length,
        }
    }

    /// Allocate a new node in the store and return its ID.
    pub fn allocate_node(&mut self, node: TrieNode) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, node);
        id
    }

    /// Return a reference to a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&TrieNode> {
        self.nodes.get(&id)
    }

    /// Return a mutable reference to a node by ID.
    pub fn get_node_mut(&mut self, id: u64) -> Option<&mut TrieNode> {
        self.nodes.get_mut(&id)
    }

    /// Return the root node ID, if any.
    pub fn root_id(&self) -> Option<u64> {
        self.root
    }

    /// Set the root node ID.
    pub fn set_root(&mut self, id: Option<u64>) {
        self.root = id;
    }

    /// Return the configured element length.
    pub fn element_length(&self) -> usize {
        self.element_length
    }

    /// Get the number of leaf elements in the trie.
    pub fn len(&self) -> usize {
        self.nodes.values().filter(|n| n.is_leaf).count()
    }

    /// Check if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Serialize the trie to a compact msgpack representation for storage.
    ///
    /// Format: msgpack map with keys "root", "next_id", "element_length", "nodes".
    /// The "nodes" value is a map of id -> serialized node.
    pub fn serialize(&self) -> Vec<u8> {
        let mut nodes_vec: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
        for (&id, node) in &self.nodes {
            let mut node_map: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
            node_map.push((
                rmpv::Value::String("p".into()),
                rmpv::Value::Binary(node.path.clone()),
            ));
            node_map.push((
                rmpv::Value::String("l".into()),
                rmpv::Value::Boolean(node.is_leaf),
            ));
            if let Some(ref h) = node.hash {
                node_map.push((
                    rmpv::Value::String("h".into()),
                    rmpv::Value::Binary(h.clone()),
                ));
            }
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

    /// Deserialize a trie from stored msgpack data.
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
        })
    }

    /// Deserialize a single TrieNode from an rmpv::Value.
    fn deserialize_node(val: rmpv::Value) -> Result<TrieNode, AlgoError> {
        let map = match val {
            rmpv::Value::Map(m) => m,
            _ => {
                return Err(AlgoError::Ledger {
                    message: "expected map for trie node".into(),
                })
            }
        };

        let mut path = Vec::new();
        let mut is_leaf = false;
        let mut hash: Option<Vec<u8>> = None;
        let mut children = Vec::new();

        for (k, v) in map {
            match k.as_str().unwrap_or("") {
                "p" => {
                    if let Some(b) = v.as_slice() {
                        path = b.to_vec();
                    }
                }
                "l" => {
                    is_leaf = v.as_bool().unwrap_or(false);
                }
                "h" => {
                    if let Some(b) = v.as_slice() {
                        hash = Some(b.to_vec());
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

        Ok(TrieNode {
            path,
            children,
            hash,
            is_leaf,
        })
    }

    /// Build a trie from a complete set of 36-byte elements.
    ///
    /// This is used when loading from a DB that has no persisted trie — all
    /// account and resource hashes are computed and inserted one by one.
    pub fn from_elements(
        elements: impl Iterator<Item = [u8; 36]>,
        element_length: usize,
    ) -> Result<Self, AlgoError> {
        let mut trie = Self::new(element_length);
        for elem in elements {
            trie.add(&elem)?;
        }
        Ok(trie)
    }

    // -----------------------------------------------------------------------
    // Hash computation
    // -----------------------------------------------------------------------

    /// Compute the root hash of the trie.
    ///
    /// - Empty trie: `[0u8; 32]`
    /// - Single leaf root: `SHA512/256(0x00 || leaf_element)`
    /// - Internal root: `SHA512/256(0x01 || internal_hash)`
    pub fn root_hash(&mut self) -> [u8; 32] {
        let root_id = match self.root {
            Some(id) => id,
            None => return [0u8; 32],
        };

        // Ensure all hashes are computed bottom-up.
        self.ensure_hashed(root_id);

        let node = &self.nodes[&root_id];
        let node_hash = node
            .hash
            .as_ref()
            .expect("hash must be computed after ensure_hashed");

        let mut hasher = Sha512_256::new();
        if node.is_leaf {
            hasher.update([0x00]);
        } else {
            hasher.update([0x01]);
        }
        hasher.update(node_hash);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Recursively ensure the hash is computed for `node_id` and all
    /// descendants. After this call, `node.hash` is `Some(...)`.
    fn ensure_hashed(&mut self, node_id: u64) {
        let node = &self.nodes[&node_id];

        // Already cached?
        if node.hash.is_some() {
            return;
        }

        // Must be an internal node (leaves always have hash set).
        assert!(!node.is_leaf, "leaf node must always have hash set");

        // Recursively hash all children first.
        let child_ids: Vec<u64> = node.children.iter().map(|c| c.child_id).collect();
        for child_id in child_ids {
            self.ensure_hashed(child_id);
        }

        // Now compute this node's hash.
        let hash = self.calculate_node_hash(node_id);
        self.nodes.get_mut(&node_id).unwrap().hash = Some(hash);
    }

    /// Calculate the hash for an internal node per go-algorand's algorithm.
    ///
    /// ```text
    /// SHA512/256(
    ///   path_length as u8 ||
    ///   path bytes ||
    ///   for each child in order:
    ///     child_type_tag (0x00 leaf, 0x01 internal) ||
    ///     child_hash_length as u8 ||
    ///     child.hash_index as u8 ||
    ///     child.hash bytes
    /// )
    /// ```
    fn calculate_node_hash(&self, node_id: u64) -> Vec<u8> {
        let node = &self.nodes[&node_id];

        let mut hasher = Sha512_256::new();

        // Path prefix.
        hasher.update([node.path.len() as u8]);
        hasher.update(&node.path);

        // Children (already in sorted order by hash_index).
        for child in &node.children {
            let child_node = &self.nodes[&child.child_id];
            let child_hash = child_node
                .hash
                .as_ref()
                .expect("child hash must be computed before parent");

            // Type tag.
            if child_node.is_leaf {
                hasher.update([0x00]);
            } else {
                hasher.update([0x01]);
            }

            // Hash length + hash_index + hash bytes.
            hasher.update([child_hash.len() as u8]);
            hasher.update([child.hash_index]);
            hasher.update(child_hash);
        }

        hasher.finalize().to_vec()
    }

    // -----------------------------------------------------------------------
    // Add / Delete / Contains
    // -----------------------------------------------------------------------

    /// Add a fixed-length element to the trie.
    ///
    /// Returns an error if the element already exists or has the wrong length.
    pub fn add(&mut self, element: &[u8]) -> Result<(), AlgoError> {
        if element.len() != self.element_length {
            return Err(AlgoError::Ledger {
                message: format!(
                    "element length {} != expected {}",
                    element.len(),
                    self.element_length
                ),
            });
        }

        match self.root {
            None => {
                // Empty trie: create a single leaf as root.
                let leaf = TrieNode::leaf(element.to_vec());
                let id = self.allocate_node(leaf);
                self.root = Some(id);
                Ok(())
            }
            Some(root_id) => {
                let new_root = self.node_add(root_id, element, 0)?;
                self.root = Some(new_root);
                Ok(())
            }
        }
    }

    /// Recursive add into the subtree rooted at `node_id`.
    /// `depth` is the current byte offset into the element.
    /// Returns the (possibly new) node ID for this position.
    fn node_add(&mut self, node_id: u64, element: &[u8], depth: usize) -> Result<u64, AlgoError> {
        let node = self.nodes.get(&node_id).unwrap().clone();

        if node.is_leaf {
            let existing = node.hash.as_ref().unwrap();
            if existing.as_slice() == element {
                return Err(AlgoError::Ledger {
                    message: "duplicate element".to_string(),
                });
            }
            // Split: find shared prefix between existing element and new element
            // starting from `depth`.
            return self.split_leaf(node_id, element, depth);
        }

        // Internal node: compare path.
        let path = &node.path;
        let path_len = path.len();

        // Find how much of the path matches element bytes at [depth..].
        let mut match_len = 0;
        while match_len < path_len {
            if depth + match_len >= element.len() {
                // Element is shorter than path — shouldn't happen with fixed-length elements.
                return Err(AlgoError::Ledger {
                    message: "element too short for trie path".to_string(),
                });
            }
            if element[depth + match_len] != path[match_len] {
                break;
            }
            match_len += 1;
        }

        if match_len < path_len {
            // Partial path match: split this internal node.
            return self.split_internal(node_id, element, depth, match_len);
        }

        // Full path matched. Branch on the next byte.
        let branch_depth = depth + path_len;
        if branch_depth >= element.len() {
            return Err(AlgoError::Ledger {
                message: "element too short after path".to_string(),
            });
        }
        let branch_byte = element[branch_depth];

        // Look for existing child with this branch byte.
        let child_idx = node
            .children
            .iter()
            .position(|c| c.hash_index == branch_byte);

        match child_idx {
            Some(idx) => {
                let child_id = node.children[idx].child_id;
                let new_child_id = self.node_add(child_id, element, branch_depth + 1)?;
                // Update child pointer if changed.
                let n = self.nodes.get_mut(&node_id).unwrap();
                n.children[idx].child_id = new_child_id;
                n.invalidate();
                Ok(node_id)
            }
            None => {
                // No child for this byte: create a new leaf.
                let leaf = TrieNode::leaf(element.to_vec());
                let leaf_id = self.allocate_node(leaf);
                let n = self.nodes.get_mut(&node_id).unwrap();
                let entry = ChildEntry {
                    hash_index: branch_byte,
                    child_id: leaf_id,
                };
                // Insert in sorted order by hash_index.
                let pos = n
                    .children
                    .iter()
                    .position(|c| c.hash_index > branch_byte)
                    .unwrap_or(n.children.len());
                n.children.insert(pos, entry);
                n.invalidate();
                Ok(node_id)
            }
        }
    }

    /// Split a leaf node when a new element collides at `depth`.
    /// Returns the new internal node ID that replaces the leaf.
    fn split_leaf(&mut self, leaf_id: u64, element: &[u8], depth: usize) -> Result<u64, AlgoError> {
        let existing = self.nodes.get(&leaf_id).unwrap().hash.clone().unwrap();

        // Find shared prefix length from `depth` onward.
        let mut shared = 0;
        while depth + shared < existing.len()
            && depth + shared < element.len()
            && existing[depth + shared] == element[depth + shared]
        {
            shared += 1;
        }

        let branch_depth = depth + shared;

        // Build the shared-prefix path.
        let shared_path = existing[depth..branch_depth].to_vec();

        // Branch bytes for the two elements.
        let old_byte = existing[branch_depth];
        let new_byte = element[branch_depth];

        // Create new leaf for the new element.
        let new_leaf_id = self.allocate_node(TrieNode::leaf(element.to_vec()));

        // Build children sorted by hash_index.
        let mut children = vec![
            ChildEntry {
                hash_index: old_byte,
                child_id: leaf_id,
            },
            ChildEntry {
                hash_index: new_byte,
                child_id: new_leaf_id,
            },
        ];
        children.sort_by_key(|c| c.hash_index);

        let internal = TrieNode::internal(shared_path, children);
        let internal_id = self.allocate_node(internal);
        Ok(internal_id)
    }

    /// Split an internal node when the path partially matches at `match_len`.
    /// Returns the new parent internal node ID.
    fn split_internal(
        &mut self,
        node_id: u64,
        element: &[u8],
        depth: usize,
        match_len: usize,
    ) -> Result<u64, AlgoError> {
        let node = self.nodes.get(&node_id).unwrap().clone();
        let branch_depth = depth + match_len;

        // The byte at the divergence point for the old node.
        let old_byte = node.path[match_len];
        // The byte at the divergence point for the new element.
        let new_byte = element[branch_depth];

        // Shorten the old node's path to the suffix after divergence.
        let suffix_path = node.path[match_len + 1..].to_vec();
        let n = self.nodes.get_mut(&node_id).unwrap();
        n.path = suffix_path;
        n.invalidate();

        // Create new leaf for the new element.
        let new_leaf_id = self.allocate_node(TrieNode::leaf(element.to_vec()));

        // Build children sorted by hash_index.
        let mut children = vec![
            ChildEntry {
                hash_index: old_byte,
                child_id: node_id,
            },
            ChildEntry {
                hash_index: new_byte,
                child_id: new_leaf_id,
            },
        ];
        children.sort_by_key(|c| c.hash_index);

        // New parent with shared prefix.
        let shared_path = element[depth..branch_depth].to_vec();
        let parent = TrieNode::internal(shared_path, children);
        let parent_id = self.allocate_node(parent);
        Ok(parent_id)
    }

    /// Delete an element from the trie.
    ///
    /// Returns an error if the element is not found.
    pub fn delete(&mut self, element: &[u8]) -> Result<(), AlgoError> {
        if element.len() != self.element_length {
            return Err(AlgoError::Ledger {
                message: format!(
                    "element length {} != expected {}",
                    element.len(),
                    self.element_length
                ),
            });
        }

        let root_id = match self.root {
            None => {
                return Err(AlgoError::Ledger {
                    message: "element not found in empty trie".to_string(),
                })
            }
            Some(id) => id,
        };

        let result = self.node_delete(root_id, element, 0)?;
        self.root = result;
        Ok(())
    }

    /// Recursive delete from the subtree rooted at `node_id`.
    /// Returns `Ok(Some(id))` with the (possibly new) node ID, or `Ok(None)`
    /// if the node was removed entirely (leaf deleted, subtree empty).
    fn node_delete(
        &mut self,
        node_id: u64,
        element: &[u8],
        depth: usize,
    ) -> Result<Option<u64>, AlgoError> {
        let node = self.nodes.get(&node_id).unwrap().clone();

        if node.is_leaf {
            let existing = node.hash.as_ref().unwrap();
            if existing.as_slice() == element {
                self.nodes.remove(&node_id);
                return Ok(None);
            }
            return Err(AlgoError::Ledger {
                message: "element not found".to_string(),
            });
        }

        // Internal node: verify path matches.
        let path_len = node.path.len();
        for i in 0..path_len {
            if depth + i >= element.len() || element[depth + i] != node.path[i] {
                return Err(AlgoError::Ledger {
                    message: "element not found".to_string(),
                });
            }
        }

        let branch_depth = depth + path_len;
        if branch_depth >= element.len() {
            return Err(AlgoError::Ledger {
                message: "element not found".to_string(),
            });
        }

        let branch_byte = element[branch_depth];

        let child_idx = node
            .children
            .iter()
            .position(|c| c.hash_index == branch_byte);

        let idx = match child_idx {
            Some(i) => i,
            None => {
                return Err(AlgoError::Ledger {
                    message: "element not found".to_string(),
                })
            }
        };

        let child_id = node.children[idx].child_id;
        let new_child = self.node_delete(child_id, element, branch_depth + 1)?;

        match new_child {
            Some(new_child_id) => {
                // Child still exists (possibly replaced).
                let n = self.nodes.get_mut(&node_id).unwrap();
                n.children[idx].child_id = new_child_id;
                n.invalidate();
                Ok(Some(node_id))
            }
            None => {
                // Child was removed. Remove entry from children.
                let n = self.nodes.get_mut(&node_id).unwrap();
                n.children.remove(idx);
                n.invalidate();

                if n.children.is_empty() {
                    // No children left — remove this node too.
                    self.nodes.remove(&node_id);
                    Ok(None)
                } else if n.children.len() == 1 {
                    // Single child: merge (collapse) to maintain path compression.
                    self.collapse_single_child(node_id)
                } else {
                    Ok(Some(node_id))
                }
            }
        }
    }

    /// Collapse an internal node with a single child into its child.
    /// Merges paths: `parent.path + child.hash_index + child.path`.
    /// Returns the surviving node ID.
    fn collapse_single_child(&mut self, node_id: u64) -> Result<Option<u64>, AlgoError> {
        let node = self.nodes.get(&node_id).unwrap().clone();
        assert_eq!(node.children.len(), 1);

        let child_entry = &node.children[0];
        let child_id = child_entry.child_id;
        let branch_byte = child_entry.hash_index;

        let child = self.nodes.get(&child_id).unwrap().clone();

        if child.is_leaf {
            // Parent becomes unnecessary; promote the leaf.
            // The leaf already stores the full element as its hash, no path merging needed.
            self.nodes.remove(&node_id);
            Ok(Some(child_id))
        } else {
            // Merge paths: parent.path + branch_byte + child.path.
            let mut merged_path = node.path.clone();
            merged_path.push(branch_byte);
            merged_path.extend_from_slice(&child.path);

            let c = self.nodes.get_mut(&child_id).unwrap();
            c.path = merged_path;
            c.invalidate();

            self.nodes.remove(&node_id);
            Ok(Some(child_id))
        }
    }

    /// Check whether an element exists in the trie.
    pub fn contains(&self, element: &[u8]) -> bool {
        if element.len() != self.element_length {
            return false;
        }

        let mut current_id = match self.root {
            None => return false,
            Some(id) => id,
        };

        let mut depth = 0;

        loop {
            let node = match self.nodes.get(&current_id) {
                Some(n) => n,
                None => return false,
            };

            if node.is_leaf {
                return node.hash.as_deref() == Some(element);
            }

            // Internal node: verify path matches.
            let path_len = node.path.len();
            for i in 0..path_len {
                if depth + i >= element.len() || element[depth + i] != node.path[i] {
                    return false;
                }
            }

            let branch_depth = depth + path_len;
            if branch_depth >= element.len() {
                return false;
            }

            let branch_byte = element[branch_depth];
            let child = node.children.iter().find(|c| c.hash_index == branch_byte);

            match child {
                Some(c) => {
                    current_id = c.child_id;
                    depth = branch_depth + 1;
                }
                None => return false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute SHA512/256 of the given data.
    fn sha512_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha512_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    #[test]
    fn test_empty_trie_root_hash() {
        let mut trie = MerkleTrie::new(36);
        assert_eq!(trie.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf_root_hash() {
        let mut trie = MerkleTrie::new(36);

        // Create a 36-byte element.
        let mut element = vec![0u8; 36];
        element[0] = 0xAB;
        element[35] = 0xCD;

        let leaf = TrieNode::leaf(element.clone());
        let leaf_id = trie.allocate_node(leaf);
        trie.set_root(Some(leaf_id));

        let root = trie.root_hash();

        // Expected: SHA512/256(0x00 || element)
        let mut input = vec![0x00];
        input.extend_from_slice(&element);
        let expected = sha512_256(&input);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_elements_shared_prefix() {
        // Two 4-byte elements sharing a 1-byte prefix, branching at byte 1.
        // Element A: [0x10, 0x20, 0xAA, 0xBB]
        // Element B: [0x10, 0x30, 0xCC, 0xDD]
        //
        // Trie structure:
        //   internal(path=[0x10], children=[
        //     ChildEntry { hash_index: 0x20, child_id: leaf_a },
        //     ChildEntry { hash_index: 0x30, child_id: leaf_b },
        //   ])
        let mut trie = MerkleTrie::new(4);

        let elem_a = vec![0x10, 0x20, 0xAA, 0xBB];
        let elem_b = vec![0x10, 0x30, 0xCC, 0xDD];

        let leaf_a_id = trie.allocate_node(TrieNode::leaf(elem_a.clone()));
        let leaf_b_id = trie.allocate_node(TrieNode::leaf(elem_b.clone()));

        let internal = TrieNode::internal(
            vec![0x10],
            vec![
                ChildEntry {
                    hash_index: 0x20,
                    child_id: leaf_a_id,
                },
                ChildEntry {
                    hash_index: 0x30,
                    child_id: leaf_b_id,
                },
            ],
        );
        let internal_id = trie.allocate_node(internal);
        trie.set_root(Some(internal_id));

        let root = trie.root_hash();

        // Manually compute the expected internal node hash.
        // internal_hash = SHA512/256(
        //   0x01          (path_length)
        //   0x10          (path byte)
        //   0x00          (leaf tag for child A)
        //   0x04          (hash_length = 4, the element itself)
        //   0x20          (hash_index for child A)
        //   elem_a bytes  (4 bytes)
        //   0x00          (leaf tag for child B)
        //   0x04          (hash_length = 4)
        //   0x30          (hash_index for child B)
        //   elem_b bytes  (4 bytes)
        // )
        let mut internal_input = vec![
            0x01,               // path length
            0x10,               // path
            0x00,               // leaf tag (child A)
            elem_a.len() as u8, // hash length
            0x20,               // hash_index
        ];
        internal_input.extend_from_slice(&elem_a);
        // Child B
        internal_input.extend_from_slice(&[
            0x00,               // leaf tag
            elem_b.len() as u8, // hash length
            0x30,               // hash_index
        ]);
        internal_input.extend_from_slice(&elem_b);

        let expected_internal_hash = sha512_256(&internal_input);

        // Root hash = SHA512/256(0x01 || internal_hash)
        let mut root_input = vec![0x01];
        root_input.extend_from_slice(&expected_internal_hash);
        let expected_root = sha512_256(&root_input);

        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_internal_node_hash_caching() {
        // After computing root_hash once, the internal node's hash should be cached.
        let mut trie = MerkleTrie::new(4);

        let elem_a = vec![0x01, 0x10, 0x00, 0x00];
        let elem_b = vec![0x01, 0x20, 0x00, 0x00];

        let leaf_a = trie.allocate_node(TrieNode::leaf(elem_a));
        let leaf_b = trie.allocate_node(TrieNode::leaf(elem_b));

        let internal = TrieNode::internal(
            vec![0x01],
            vec![
                ChildEntry {
                    hash_index: 0x10,
                    child_id: leaf_a,
                },
                ChildEntry {
                    hash_index: 0x20,
                    child_id: leaf_b,
                },
            ],
        );
        let internal_id = trie.allocate_node(internal);
        trie.set_root(Some(internal_id));

        let hash1 = trie.root_hash();
        // Internal node should now have cached hash.
        assert!(trie.get_node(internal_id).unwrap().hash.is_some());

        let hash2 = trie.root_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_invalidate_clears_cache() {
        let mut trie = MerkleTrie::new(4);

        let elem = vec![0x01, 0x02, 0x03, 0x04];
        let leaf_id = trie.allocate_node(TrieNode::leaf(elem));

        let internal = TrieNode::internal(
            vec![],
            vec![ChildEntry {
                hash_index: 0x01,
                child_id: leaf_id,
            }],
        );
        let internal_id = trie.allocate_node(internal);
        trie.set_root(Some(internal_id));

        // Compute hash so it gets cached.
        let _ = trie.root_hash();
        assert!(trie.get_node(internal_id).unwrap().hash.is_some());

        // Invalidate and verify cache is cleared.
        trie.get_node_mut(internal_id).unwrap().invalidate();
        assert!(trie.get_node(internal_id).unwrap().hash.is_none());

        // Leaf invalidate is a no-op (leaf hash is the element itself).
        trie.get_node_mut(leaf_id).unwrap().invalidate();
        assert!(trie.get_node(leaf_id).unwrap().hash.is_some());
    }

    // -----------------------------------------------------------------------
    // Add / Delete / Contains tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_single_element_root_hash() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x10, 0x20, 0x30, 0x40];
        trie.add(&elem).unwrap();

        let root = trie.root_hash();

        // Single leaf root hash = SHA512/256(0x00 || element)
        let mut input = vec![0x00];
        input.extend_from_slice(&elem);
        let expected = sha512_256(&input);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_add_two_elements_no_shared_prefix() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x00, 0x00, 0x00];
        let elem_b = vec![0x20, 0x00, 0x00, 0x00];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        // Root should be an internal node with empty path, two leaf children.
        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_b));

        let root_id = trie.root_id().unwrap();
        let root_node = trie.get_node(root_id).unwrap();
        assert!(!root_node.is_leaf);
        assert_eq!(root_node.path.len(), 0);
        assert_eq!(root_node.children.len(), 2);
    }

    #[test]
    fn test_add_two_elements_shared_prefix_splitting() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x20, 0xAA, 0xBB];
        let elem_b = vec![0x10, 0x30, 0xCC, 0xDD];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();

        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_b));

        // Root should be internal with path [0x10], two children at 0x20 and 0x30.
        let root_id = trie.root_id().unwrap();
        let root_node = trie.get_node(root_id).unwrap();
        assert!(!root_node.is_leaf);
        assert_eq!(root_node.path, vec![0x10]);
        assert_eq!(root_node.children.len(), 2);
        assert_eq!(root_node.children[0].hash_index, 0x20);
        assert_eq!(root_node.children[1].hash_index, 0x30);
    }

    #[test]
    fn test_add_three_delete_one_verify_hash() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x00, 0x00, 0x00];
        let elem_b = vec![0x20, 0x00, 0x00, 0x00];
        let elem_c = vec![0x30, 0x00, 0x00, 0x00];
        trie.add(&elem_a).unwrap();
        trie.add(&elem_b).unwrap();
        trie.add(&elem_c).unwrap();

        // Build a reference trie with just A and C.
        let mut ref_trie = MerkleTrie::new(4);
        ref_trie.add(&elem_a).unwrap();
        ref_trie.add(&elem_c).unwrap();

        // Delete B from original.
        trie.delete(&elem_b).unwrap();
        assert!(!trie.contains(&elem_b));
        assert!(trie.contains(&elem_a));
        assert!(trie.contains(&elem_c));

        assert_eq!(trie.root_hash(), ref_trie.root_hash());
    }

    #[test]
    fn test_delete_to_empty() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0xAA, 0xBB, 0xCC, 0xDD];
        trie.add(&elem).unwrap();
        trie.delete(&elem).unwrap();

        assert_eq!(trie.root_hash(), [0u8; 32]);
        assert!(trie.root_id().is_none());
    }

    #[test]
    fn test_duplicate_add_returns_error() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x01, 0x02, 0x03, 0x04];
        trie.add(&elem).unwrap();
        let result = trie.add(&elem);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("duplicate"),
            "error should mention duplicate"
        );
    }

    #[test]
    fn test_delete_nonexistent_returns_error() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x01, 0x02, 0x03, 0x04];
        let elem_b = vec![0xFF, 0xFE, 0xFD, 0xFC];
        trie.add(&elem_a).unwrap();
        let result = trie.delete(&elem_b);
        assert!(result.is_err());

        // Also test deleting from empty trie.
        let mut empty_trie = MerkleTrie::new(4);
        assert!(empty_trie.delete(&elem_a).is_err());
    }

    #[test]
    fn test_add_many_delete_all() {
        let mut trie = MerkleTrie::new(4);
        let mut elements: Vec<Vec<u8>> = Vec::new();
        for i in 0u8..100 {
            let elem = vec![i, i.wrapping_add(1), i.wrapping_add(2), i.wrapping_add(3)];
            elements.push(elem);
        }
        for elem in &elements {
            trie.add(elem).unwrap();
        }
        for elem in &elements {
            assert!(trie.contains(elem));
        }
        for elem in &elements {
            trie.delete(elem).unwrap();
        }
        assert_eq!(trie.root_hash(), [0u8; 32]);
        assert!(trie.root_id().is_none());
    }

    #[test]
    fn test_add_delete_add_consistency() {
        let mut trie = MerkleTrie::new(4);
        let elem = vec![0x42, 0x43, 0x44, 0x45];
        trie.add(&elem).unwrap();
        let hash1 = trie.root_hash();

        trie.delete(&elem).unwrap();
        assert_eq!(trie.root_hash(), [0u8; 32]);

        trie.add(&elem).unwrap();
        let hash2 = trie.root_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_invalidation_on_add_delete() {
        let mut trie = MerkleTrie::new(4);
        let elem_a = vec![0x10, 0x00, 0x00, 0x00];
        let elem_b = vec![0x20, 0x00, 0x00, 0x00];

        trie.add(&elem_a).unwrap();
        let hash_after_one = trie.root_hash();

        trie.add(&elem_b).unwrap();
        let hash_after_two = trie.root_hash();
        assert_ne!(
            hash_after_one, hash_after_two,
            "hash should change after add"
        );

        trie.delete(&elem_b).unwrap();
        let hash_after_delete = trie.root_hash();
        assert_ne!(
            hash_after_two, hash_after_delete,
            "hash should change after delete"
        );
        assert_eq!(
            hash_after_one, hash_after_delete,
            "hash should match single-element state"
        );
    }

    // -----------------------------------------------------------------------
    // Original Wave 1 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nested_internal_nodes() {
        // Three elements: [0x10, 0x20, ...], [0x10, 0x30, ...], [0x20, ...]
        // Structure:
        //   root_internal(path=[], children=[
        //     0x10 -> mid_internal(path=[], children=[
        //       0x20 -> leaf_a,
        //       0x30 -> leaf_b,
        //     ]),
        //     0x20 -> leaf_c,
        //   ])
        let mut trie = MerkleTrie::new(3);

        let elem_a = vec![0x10, 0x20, 0xAA];
        let elem_b = vec![0x10, 0x30, 0xBB];
        let elem_c = vec![0x20, 0x40, 0xCC];

        let leaf_a = trie.allocate_node(TrieNode::leaf(elem_a.clone()));
        let leaf_b = trie.allocate_node(TrieNode::leaf(elem_b.clone()));
        let leaf_c = trie.allocate_node(TrieNode::leaf(elem_c.clone()));

        let mid = TrieNode::internal(
            vec![],
            vec![
                ChildEntry {
                    hash_index: 0x20,
                    child_id: leaf_a,
                },
                ChildEntry {
                    hash_index: 0x30,
                    child_id: leaf_b,
                },
            ],
        );
        let mid_id = trie.allocate_node(mid);

        let root_node = TrieNode::internal(
            vec![],
            vec![
                ChildEntry {
                    hash_index: 0x10,
                    child_id: mid_id,
                },
                ChildEntry {
                    hash_index: 0x20,
                    child_id: leaf_c,
                },
            ],
        );
        let root_id = trie.allocate_node(root_node);
        trie.set_root(Some(root_id));

        let root = trie.root_hash();

        // Manually compute: mid_hash first, then root_internal_hash, then root_hash.
        // mid_hash = SHA512/256(0x00 || [children of mid])
        let mut mid_input = vec![
            0x00, // path length = 0
            0x00, // leaf tag (child A)
            elem_a.len() as u8,
            0x20, // hash_index
        ];
        mid_input.extend_from_slice(&elem_a);
        mid_input.extend_from_slice(&[
            0x00, // leaf tag (child B)
            elem_b.len() as u8,
            0x30, // hash_index
        ]);
        mid_input.extend_from_slice(&elem_b);
        let mid_hash = sha512_256(&mid_input);

        // root_internal_hash
        let mut root_internal_input = vec![
            0x00,                 // path length = 0
            0x01,                 // internal tag (child: mid)
            mid_hash.len() as u8, // 32
            0x10,                 // hash_index
        ];
        root_internal_input.extend_from_slice(&mid_hash);
        // child: leaf_c
        root_internal_input.push(0x00); // leaf tag
        root_internal_input.push(elem_c.len() as u8);
        root_internal_input.push(0x20); // hash_index
        root_internal_input.extend_from_slice(&elem_c);
        let root_internal_hash = sha512_256(&root_internal_input);

        // root_hash = SHA512/256(0x01 || root_internal_hash)
        let mut expected_input = vec![0x01];
        expected_input.extend_from_slice(&root_internal_hash);
        let expected = sha512_256(&expected_input);

        assert_eq!(root, expected);
    }

    // -----------------------------------------------------------------------
    // Serialization / Deserialization / from_elements / len / is_empty tests
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
        let elems = vec![
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
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("element_length mismatch"));
    }

    #[test]
    fn test_from_elements() {
        let elems: Vec<[u8; 36]> = (0..10u8)
            .map(|i| {
                let mut e = [0u8; 36];
                e[0] = i;
                e[35] = i.wrapping_mul(7);
                e
            })
            .collect();

        // Build via from_elements.
        let mut trie1 = MerkleTrie::from_elements(elems.iter().copied(), 36).unwrap();

        // Build via incremental add.
        let mut trie2 = MerkleTrie::new(36);
        for e in &elems {
            trie2.add(e).unwrap();
        }

        assert_eq!(trie1.root_hash(), trie2.root_hash());
        assert_eq!(trie1.len(), trie2.len());
    }

    #[test]
    fn test_serialize_survives_mutations() {
        // Serialize after some adds and deletes, then restore and verify.
        let mut trie = MerkleTrie::new(4);
        let elems = vec![
            [0x10, 0x20, 0x30, 0x40],
            [0x50, 0x60, 0x70, 0x80],
            [0xAA, 0xBB, 0xCC, 0xDD],
        ];
        for e in &elems {
            trie.add(e).unwrap();
        }
        trie.delete(&elems[1]).unwrap(); // remove middle element

        let hash_before = trie.root_hash();
        let data = trie.serialize();
        let mut restored = MerkleTrie::deserialize(&data, 4).unwrap();

        assert_eq!(restored.root_hash(), hash_before);
        assert!(restored.contains(&elems[0]));
        assert!(!restored.contains(&elems[1]));
        assert!(restored.contains(&elems[2]));

        // Can continue adding to the restored trie.
        restored.add(&elems[1]).unwrap();
        assert!(restored.contains(&elems[1]));
    }
}
