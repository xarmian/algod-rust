//! Paged on-disk serialization for Merkle trie nodes.
//!
//! Mirrors go-algorand's `crypto/merkletrie/cache.go::encodePage` /
//! `decodePage` (a "committed node page") plus
//! `crypto/merkletrie/node.go::node::serialize` / `deserializeNode`
//! byte-for-byte, so a Rust-written `accounthashes.data` row can be
//! decoded by Go and vice versa. The wider G2 schema wiring lives in
//! TASK-102; this module owns only the in-memory format.
//!
//! Reference (go-algorand v4.5.1-stable):
//! - `crypto/merkletrie/cache.go:660-704` — `decodePage` / `encodePage`
//! - `crypto/merkletrie/node.go:312-373` — node `serialize` / `deserializeNode`
//! - `crypto/merkletrie/trie.go:32`       — `nodePageVersion = 0x1000000010000000`
//! - `crypto/merkletrie/bitset.go`         — 256-bit children bitset
//! - `ledger/store/trackerdb/catchpoint.go:42` —
//!   `MerkleCommitterNodesPerPage = 116` (production page size)
//!
//! Format (network byte order, varint = LEB128 as defined by Go's
//! `encoding/binary.PutUvarint` / `PutVarint`):
//!
//! ```text
//! Page  := <Uvarint version=0x1000000010000000>
//!          <Varint nodeCount>          // signed (zigzag), but always >= 0
//!          <PerNode>{nodeCount}
//!
//! PerNode := <Uvarint nodeID>
//!            <SerializedNode>
//!
//! SerializedNode :=
//!   <Uvarint hashLen>
//!   <hashLen bytes : hash>
//!   <u8 leafFlag>            // 0 = leaf, 1 = non-leaf
//!   if leafFlag == 1:
//!     // children list, sorted ascending by hashIndex
//!     repeat:
//!       <u8 hashIndex>
//!       <Uvarint childID>
//!     until end of children
//!     <u8 sentinel = last child's hashIndex>
//!         // re-emitted so the deserializer breaks on a non-monotone byte
//! ```

use std::collections::BTreeMap;

use algo_error::AlgoError;

/// Version constant for the page-header / per-page format. Must match
/// go-algorand `crypto/merkletrie/trie.go:32`.
pub const NODE_PAGE_VERSION: u64 = 0x1000_0000_1000_0000;

/// Production page size used by go-algorand for the on-disk
/// `accounthashes` table. Mirrors
/// `ledger/store/trackerdb/catchpoint.go:42` (`MerkleCommitterNodesPerPage`).
pub const NODES_PER_PAGE: u64 = 116;

/// A single child pointer inside a non-leaf node.
///
/// `hash_index` is the discriminating byte at this depth in the trie;
/// `child_id` is the `storedNodeIdentifier` of the child node, exactly
/// as Go records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildEntry {
    pub hash_index: u8,
    pub child_id: u64,
}

/// In-memory shape of a go-compatible trie node, mirroring Go's
/// `crypto/merkletrie/node.go::node`. The 256-bit children bitset is
/// derivable from `children` and is not stored here — Go reconstructs
/// it on `deserializeNode` (`node.go:366`) and we do the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageNode {
    /// For non-leaf nodes this is the cached subtree hash. For leaf
    /// nodes it is the raw element bytes (matches Go's mixed usage of
    /// `node.hash`).
    pub hash: Vec<u8>,
    /// Children, sorted ascending by `hash_index`. Empty when the node
    /// is a leaf.
    pub children: Vec<ChildEntry>,
    /// `true` iff this is a leaf node (no children). Stored as the
    /// `leafFlag` byte; kept explicit so a non-leaf with zero children
    /// (which Go does not produce) still round-trips deterministically.
    pub is_leaf: bool,
}

impl PageNode {
    /// Construct a leaf node containing `element` bytes.
    pub fn leaf(element: Vec<u8>) -> Self {
        Self {
            hash: element,
            children: Vec::new(),
            is_leaf: true,
        }
    }

    /// Construct a non-leaf node with the given subtree hash and child
    /// list. Children are normalized to the invariant the on-disk
    /// format requires: sorted ascending by `hash_index` and unique
    /// (`node.go:355` breaks the decode loop on the first non-monotone
    /// byte, so duplicates / out-of-order entries would round-trip into
    /// a shorter child list and silently corrupt the trie).
    ///
    /// Panics if `children` is empty — go-algorand never produces a
    /// non-leaf node with zero children (the serializer would have no
    /// sentinel byte to emit). Callers that may have an empty list
    /// should construct a leaf instead, or use
    /// [`PageNode::try_internal`].
    pub fn internal(hash: Vec<u8>, children: Vec<ChildEntry>) -> Self {
        Self::try_internal(hash, children).expect("non-leaf must have at least one child")
    }

    /// Fallible variant of [`PageNode::internal`]. Returns the same
    /// normalized node on success, or `None` if `children` is empty.
    /// Duplicate `hash_index` entries are also rejected because they
    /// would collapse on deserialization (the sentinel terminator
    /// fires when the next index is `<=` the previous one).
    pub fn try_internal(hash: Vec<u8>, mut children: Vec<ChildEntry>) -> Option<Self> {
        if children.is_empty() {
            return None;
        }
        children.sort_by_key(|c| c.hash_index);
        // Reject duplicates: two children sharing the same `hash_index`
        // can never round-trip through the format (the deserializer
        // treats the second occurrence as a sentinel terminator).
        for win in children.windows(2) {
            if win[0].hash_index == win[1].hash_index {
                return None;
            }
        }
        Some(Self {
            hash,
            children,
            is_leaf: false,
        })
    }
}

/// A serialized page: an ordered map of `nodeID -> PageNode` plus the
/// version word. Ordering is deterministic (BTreeMap) so re-serializing
/// the same page produces byte-identical output regardless of how the
/// map was populated — go-algorand iterates over a Go map and is
/// therefore non-deterministic byte-wise, but the deserializer accepts
/// any node ordering. We use a `BTreeMap` so the Rust write path is
/// stable across runs without giving up Go-readability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub nodes: BTreeMap<u64, PageNode>,
}

impl Page {
    /// Create an empty page.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode the page into the on-disk byte format consumed by
    /// `crypto/merkletrie/cache.go::decodePage`. The version word and
    /// node count are written first, followed by `(nodeID, node)` pairs
    /// in ascending nodeID order.
    pub fn serialize(&self) -> Vec<u8> {
        // Rough size estimate: header + per-node (nodeID varint up to 10
        // bytes, hash varint+bytes, leaf byte, children up to 256 *
        // (1 byte hashIndex + 10 byte varint) + 1 sentinel byte).
        let mut out = Vec::with_capacity(self.estimate_size());
        write_uvarint(&mut out, NODE_PAGE_VERSION);
        write_varint(&mut out, self.nodes.len() as i64);
        for (&nid, node) in &self.nodes {
            write_uvarint(&mut out, nid);
            serialize_node(&mut out, node);
        }
        out
    }

    /// Decode a page produced by `Page::serialize` (or by Go's
    /// `encodePage`). Returns an `AlgoError::Ledger` with a stable
    /// message when the page header is malformed, the version does not
    /// match `NODE_PAGE_VERSION`, or a node body is truncated.
    pub fn deserialize(buf: &[u8]) -> Result<Self, AlgoError> {
        let mut cursor = 0usize;
        let (version, n) = read_uvarint(buf, cursor).ok_or_else(|| AlgoError::Ledger {
            message: "merkle page: truncated version varint".into(),
        })?;
        cursor += n;
        if version != NODE_PAGE_VERSION {
            return Err(AlgoError::Ledger {
                message: format!(
                    "merkle page: unsupported version 0x{version:016x} (expected 0x{NODE_PAGE_VERSION:016x})"
                ),
            });
        }
        let (count, n) = read_varint(buf, cursor).ok_or_else(|| AlgoError::Ledger {
            message: "merkle page: truncated node-count varint".into(),
        })?;
        cursor += n;
        if count < 0 {
            return Err(AlgoError::Ledger {
                message: format!("merkle page: negative node count {count}"),
            });
        }
        let mut nodes = BTreeMap::new();
        for i in 0..count {
            let (node_id, n) = read_uvarint(buf, cursor).ok_or_else(|| AlgoError::Ledger {
                message: format!("merkle page: truncated nodeID varint at entry {i}"),
            })?;
            cursor += n;
            let (node, consumed) =
                deserialize_node(buf, cursor).map_err(|e| AlgoError::Ledger {
                    message: format!("merkle page: bad node at entry {i} (id {node_id}): {e}"),
                })?;
            cursor += consumed;
            nodes.insert(node_id, node);
        }
        Ok(Self { nodes })
    }

    /// Rough byte-size estimate used to pre-size the serialization
    /// buffer. Intentionally conservative — overshooting saves
    /// re-allocations and undershooting costs us very little.
    fn estimate_size(&self) -> usize {
        // 10 bytes (max uvarint) for version + 10 for node count.
        let mut sz = 20usize;
        for node in self.nodes.values() {
            sz += 10 // nodeID
                + 10 // hash length
                + node.hash.len()
                + 1 // leaf flag
                + node.children.len() * (1 + 10) // hashIndex + childID
                + 1; // sentinel
        }
        sz
    }
}

// ---------------------------------------------------------------------------
// Node-level serialize / deserialize (Go: crypto/merkletrie/node.go)
// ---------------------------------------------------------------------------

fn serialize_node(out: &mut Vec<u8>, node: &PageNode) {
    write_uvarint(out, node.hash.len() as u64);
    out.extend_from_slice(&node.hash);
    if node.is_leaf {
        out.push(0);
        return;
    }
    out.push(1);
    // Children must already be sorted ascending by hash_index with no
    // duplicates — `PageNode::try_internal` enforces this on
    // construction, and `Page::deserialize` produces nodes that match
    // that invariant directly. The format relies on it: the loop below
    // emits each (hashIndex, childID) pair, then a single sentinel
    // byte equal to the LAST child's hashIndex so the deserializer
    // breaks on the first non-monotone byte (`node.go:355`
    // `childIndex <= prevChildIndex && !first`).
    assert!(
        !node.children.is_empty(),
        "non-leaf node must have at least one child to emit a sentinel terminator; \
         construct via PageNode::try_internal to surface this earlier",
    );
    // The fields of `PageNode` are public for inspection (TASK-102 will
    // need to walk node.hash / node.children from SQL-loaded pages), so
    // a caller can in principle bypass `try_internal` and hand us a
    // node with out-of-order or duplicate children. Validate at
    // serialize time — a `debug_assert!` would silently emit a
    // truncated/misaligned page in release builds.
    assert!(
        node.children
            .windows(2)
            .all(|w| w[0].hash_index < w[1].hash_index),
        "non-leaf children must be strictly ascending by hash_index with no duplicates; \
         construct via PageNode::try_internal to enforce, or sort+dedup before serialize",
    );
    for child in &node.children {
        out.push(child.hash_index);
        write_uvarint(out, child.child_id);
    }
    out.push(
        node.children
            .last()
            .expect("non-leaf with no children")
            .hash_index,
    );
}

fn deserialize_node(buf: &[u8], offset: usize) -> Result<(PageNode, usize), String> {
    let mut cursor = offset;
    let (hash_len, n) =
        read_uvarint(buf, cursor).ok_or_else(|| "truncated hash-length varint".to_string())?;
    cursor += n;
    let hash_len_usize: usize = hash_len
        .try_into()
        .map_err(|_| format!("hash length {hash_len} overflows usize"))?;
    // `cursor + hash_len_usize` would overflow on absurd (corrupt)
    // inputs, so use `checked_add` and treat overflow as truncation.
    // The trailing leaf-flag byte must also fit in the remaining slice;
    // requiring `< buf.len()` (rather than `<=`) reserves room for it.
    let hash_end = cursor.checked_add(hash_len_usize).ok_or_else(|| {
        format!("node body length overflow (hash_len={hash_len_usize}, cursor={cursor})",)
    })?;
    if hash_end >= buf.len() {
        return Err(format!(
            "truncated node body (need hash {hash_len_usize} + flag byte; have {} bytes left)",
            buf.len().saturating_sub(cursor),
        ));
    }
    let hash = buf[cursor..hash_end].to_vec();
    cursor = hash_end;
    let leaf_flag = buf[cursor];
    cursor += 1;
    if leaf_flag == 0 {
        return Ok((
            PageNode {
                hash,
                children: Vec::new(),
                is_leaf: true,
            },
            cursor - offset,
        ));
    }
    if leaf_flag != 1 {
        return Err(format!("unknown node leaf-flag byte 0x{leaf_flag:02x}"));
    }
    // Non-leaf: read (hashIndex, childID) pairs until we see a byte
    // that is <= the previous hashIndex (the sentinel terminator).
    let mut children: Vec<ChildEntry> = Vec::new();
    let mut prev_index: u8 = 0;
    let mut first = true;
    loop {
        if cursor >= buf.len() {
            return Err("truncated children list (no sentinel terminator)".into());
        }
        let hash_index = buf[cursor];
        cursor += 1;
        if !first && hash_index <= prev_index {
            // Sentinel — Go's deserializer breaks on this byte; the
            // matching encoder emits the last child's hashIndex as the
            // terminator. We consumed it above; the loop terminates here.
            break;
        }
        first = false;
        let (child_id, n) =
            read_uvarint(buf, cursor).ok_or_else(|| "truncated childID varint".to_string())?;
        cursor += n;
        children.push(ChildEntry {
            hash_index,
            child_id,
        });
        prev_index = hash_index;
    }
    Ok((
        PageNode {
            hash,
            children,
            is_leaf: false,
        },
        cursor - offset,
    ))
}

// ---------------------------------------------------------------------------
// Varint helpers — match Go's `encoding/binary.PutUvarint` /
// `PutVarint` byte-for-byte. Implemented inline (not pulled in from a
// crate) so the format stays grep-able next to the rest of the page
// code, and so the encoding is independent of any third-party varint
// implementation that might subtly diverge.
// ---------------------------------------------------------------------------

/// Encode `x` using Go's `binary.PutUvarint` (LEB128, low 7 bits first,
/// MSB set on every continuation byte). Appends to `out`.
fn write_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push((x as u8) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

/// Encode `x` using Go's `binary.PutVarint` (zigzag transform, then
/// `PutUvarint`). Appends to `out`.
fn write_varint(out: &mut Vec<u8>, x: i64) {
    // Zigzag: map signed -> unsigned so that small magnitudes (positive
    // or negative) encode to short varints.
    let ux = ((x as u64) << 1) ^ ((x >> 63) as u64);
    write_uvarint(out, ux);
}

/// Read a single LEB128 unsigned varint from `buf[offset..]`. Returns
/// `(value, bytes_consumed)` on success or `None` on truncation /
/// 10+ byte overflow (matching Go's `binary.Uvarint` failure modes).
fn read_uvarint(buf: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        let idx = offset.checked_add(i)?;
        let b = *buf.get(idx)?;
        i += 1;
        if b < 0x80 {
            // Detect overflow: Go's `Uvarint` returns failure for
            // varints longer than 10 bytes, or 10-byte varints whose
            // last byte is > 1. We mirror that bound.
            if i == 10 && b > 1 {
                return None;
            }
            value |= (b as u64) << shift;
            return Some((value, i));
        }
        if i == 10 {
            // 10 continuation bytes already; the next byte must be the
            // terminator (handled above) — anything else overflows.
            return None;
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
}

/// Read a single LEB128 signed varint (zigzag-decoded) from
/// `buf[offset..]`. Same return contract as `read_uvarint`.
fn read_varint(buf: &[u8], offset: usize) -> Option<(i64, usize)> {
    let (ux, n) = read_uvarint(buf, offset)?;
    // Zigzag decode: low bit is sign.
    let x = ((ux >> 1) as i64) ^ -((ux & 1) as i64);
    Some((x, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vectors derived directly from Go's
    /// `encoding/binary.PutUvarint` / `PutVarint`: small magnitudes
    /// produce 1-byte outputs; 0x80 needs the continuation byte; the
    /// max u64 needs 10 bytes.
    #[test]
    fn varint_roundtrip_matches_go_binary_encoding() {
        for &x in &[0u64, 1, 0x7f, 0x80, 0x3fff, 0x4000, u64::MAX] {
            let mut buf = Vec::new();
            write_uvarint(&mut buf, x);
            let (y, n) = read_uvarint(&buf, 0).expect("decode uvarint");
            assert_eq!(x, y, "uvarint round-trip mismatch for {x}");
            assert_eq!(n, buf.len(), "uvarint consumed unexpected bytes for {x}");
        }
        // Known Go vectors: x=1 → [0x01]; x=0x80 → [0x80, 0x01]; x=300 → [0xac, 0x02].
        let mut buf = Vec::new();
        write_uvarint(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);
        buf.clear();
        write_uvarint(&mut buf, 0x80);
        assert_eq!(buf, vec![0x80, 0x01]);
        buf.clear();
        write_uvarint(&mut buf, 300);
        assert_eq!(buf, vec![0xac, 0x02]);
    }

    #[test]
    fn signed_varint_zigzag_matches_go() {
        // Go vectors:  0 → 0; -1 → 1; 1 → 2; -2 → 3; 2 → 4; ... 63 → 0x7e; -64 → 0x7f; 64 → 0x8001.
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (-1, &[0x01]),
            (1, &[0x02]),
            (-2, &[0x03]),
            (2, &[0x04]),
            (63, &[0x7e]),
            (-64, &[0x7f]),
            (64, &[0x80, 0x01]),
            (
                i64::MIN,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
        ];
        for &(x, expected) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, x);
            assert_eq!(buf, expected, "varint encode mismatch for {x}");
            let (y, n) = read_varint(&buf, 0).expect("decode varint");
            assert_eq!(x, y, "varint round-trip mismatch for {x}");
            assert_eq!(
                n,
                expected.len(),
                "varint consumed unexpected bytes for {x}"
            );
        }
    }

    #[test]
    fn read_uvarint_rejects_overflow() {
        // 10 continuation bytes followed by 0x02 = overflow per Go.
        let bad = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(read_uvarint(&bad, 0), None);
        // 11+ continuation bytes is also overflow.
        let too_long = [
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ];
        assert_eq!(read_uvarint(&too_long, 0), None);
    }

    #[test]
    fn empty_page_round_trips() {
        let page = Page::new();
        let bytes = page.serialize();
        // Version uvarint (10 bytes for 0x10000000_10000000) + Varint(0) = 11 bytes.
        let (round, _) = read_uvarint(&bytes, 0).unwrap();
        assert_eq!(round, NODE_PAGE_VERSION);

        let decoded = Page::deserialize(&bytes).expect("decode empty page");
        assert_eq!(decoded, page);
    }

    #[test]
    fn leaf_node_round_trips() {
        let mut page = Page::new();
        page.nodes.insert(
            7,
            PageNode::leaf(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        );
        let bytes = page.serialize();
        let decoded = Page::deserialize(&bytes).expect("decode single leaf");
        assert_eq!(decoded, page);
    }

    #[test]
    fn non_leaf_with_children_round_trips() {
        let mut page = Page::new();
        let node = PageNode::internal(
            b"\xab\xcd\xef".to_vec(),
            vec![
                ChildEntry {
                    hash_index: 0x10,
                    child_id: 42,
                },
                ChildEntry {
                    hash_index: 0x55,
                    child_id: 1_000_000,
                },
                ChildEntry {
                    hash_index: 0xfe,
                    child_id: 17,
                },
            ],
        );
        page.nodes.insert(101, node.clone());
        let bytes = page.serialize();
        let decoded = Page::deserialize(&bytes).expect("decode internal");
        assert_eq!(decoded.nodes.len(), 1);
        assert_eq!(decoded.nodes.get(&101).unwrap(), &node);
    }

    #[test]
    fn multi_node_page_preserves_node_ids() {
        let mut page = Page::new();
        for nid in [1u64, 2, 5, 116, 116 * 2] {
            page.nodes.insert(nid, PageNode::leaf(vec![nid as u8; 4]));
        }
        let bytes = page.serialize();
        let decoded = Page::deserialize(&bytes).expect("decode multi-node");
        assert_eq!(decoded, page);
    }

    #[test]
    fn deserialize_rejects_wrong_version() {
        // Build a header with version 0 followed by an empty page body.
        let mut bytes = Vec::new();
        write_uvarint(&mut bytes, 0); // wrong version
        write_varint(&mut bytes, 0);
        let err = Page::deserialize(&bytes).expect_err("must reject wrong version");
        let msg = format!("{err}");
        assert!(
            msg.contains("unsupported version"),
            "expected version error, got: {msg}"
        );
    }

    #[test]
    fn deserialize_rejects_truncated_header() {
        // No bytes at all: truncated version.
        let err = Page::deserialize(&[]).expect_err("must reject empty input");
        assert!(format!("{err}").contains("truncated version"));

        // Only the version varint: truncated node count.
        let mut bytes = Vec::new();
        write_uvarint(&mut bytes, NODE_PAGE_VERSION);
        let err = Page::deserialize(&bytes).expect_err("must reject missing nodeCount");
        assert!(format!("{err}").contains("truncated node-count"));
    }

    #[test]
    fn deserialize_rejects_truncated_node_body() {
        // Build a header for 1 node, then provide only partial data.
        let mut bytes = Vec::new();
        write_uvarint(&mut bytes, NODE_PAGE_VERSION);
        write_varint(&mut bytes, 1);
        write_uvarint(&mut bytes, 9); // nodeID
                                      // Claim a hash of length 32 but only supply 4 bytes — the
                                      // leaf-flag byte will be missing.
        write_uvarint(&mut bytes, 32);
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let err = Page::deserialize(&bytes).expect_err("must reject truncated node body");
        assert!(format!("{err}").contains("truncated node body"));
    }

    #[test]
    fn deserialize_handles_node_ordering_independence() {
        // Two pages with the same nodes inserted in different orders
        // should decode to the same value (BTreeMap normalizes order).
        let mut a = Page::new();
        a.nodes.insert(1, PageNode::leaf(vec![1u8; 4]));
        a.nodes.insert(2, PageNode::leaf(vec![2u8; 4]));
        let mut b = Page::new();
        b.nodes.insert(2, PageNode::leaf(vec![2u8; 4]));
        b.nodes.insert(1, PageNode::leaf(vec![1u8; 4]));
        assert_eq!(a.serialize(), b.serialize());
    }

    /// Page-level round-trip exercising the production page size (116
    /// nodes per page) with a mix of leaves and internal nodes. Guards
    /// against off-by-one buffer-sizing mistakes when many entries land
    /// in a single serialization.
    #[test]
    fn full_production_size_page_round_trips() {
        let mut page = Page::new();
        for nid in 0..NODES_PER_PAGE {
            let node = if nid % 4 == 0 {
                PageNode::internal(
                    vec![(nid & 0xff) as u8; 32],
                    vec![
                        ChildEntry {
                            hash_index: 0x01,
                            child_id: nid * 2 + 1,
                        },
                        ChildEntry {
                            hash_index: 0x80,
                            child_id: nid * 2 + 2,
                        },
                    ],
                )
            } else {
                PageNode::leaf(vec![(nid & 0xff) as u8; 36])
            };
            page.nodes.insert(nid, node);
        }
        let bytes = page.serialize();
        let decoded = Page::deserialize(&bytes).expect("decode full page");
        assert_eq!(decoded, page);
    }

    #[test]
    fn try_internal_rejects_empty_children() {
        assert!(PageNode::try_internal(vec![0u8; 32], vec![]).is_none());
    }

    #[test]
    fn try_internal_sorts_unsorted_children() {
        // Construct with deliberately reversed children; try_internal
        // must normalize them to ascending hash_index order so the
        // serialize/deserialize round trip preserves the full list.
        let unsorted = vec![
            ChildEntry {
                hash_index: 0xff,
                child_id: 3,
            },
            ChildEntry {
                hash_index: 0x10,
                child_id: 1,
            },
            ChildEntry {
                hash_index: 0x55,
                child_id: 2,
            },
        ];
        let node = PageNode::try_internal(vec![0u8; 32], unsorted).expect("non-empty children");
        let expected_indices: Vec<u8> = node.children.iter().map(|c| c.hash_index).collect();
        assert_eq!(expected_indices, vec![0x10, 0x55, 0xff]);

        let mut page = Page::new();
        page.nodes.insert(1, node.clone());
        let bytes = page.serialize();
        let decoded = Page::deserialize(&bytes).expect("decode normalized");
        assert_eq!(decoded.nodes.get(&1).unwrap(), &node);
    }

    #[test]
    fn try_internal_rejects_duplicate_hash_indices() {
        // Two children with the same hash_index would round-trip as one
        // because the deserializer's sentinel fires on the second
        // occurrence (`<= prevChildIndex`). Reject up front.
        let dup = vec![
            ChildEntry {
                hash_index: 0x10,
                child_id: 1,
            },
            ChildEntry {
                hash_index: 0x10,
                child_id: 2,
            },
        ];
        assert!(PageNode::try_internal(vec![0u8; 32], dup).is_none());
    }

    #[test]
    #[should_panic(expected = "must be strictly ascending by hash_index")]
    fn serialize_panics_on_unsorted_children_constructed_via_public_fields() {
        // A caller that bypasses `try_internal` and assembles a node
        // via the public fields can violate the format invariant. The
        // serializer panics rather than emit a silently corrupt page
        // (the runtime assert is intentional — debug-only would let it
        // through in release builds).
        let bad = PageNode {
            hash: vec![0u8; 4],
            is_leaf: false,
            children: vec![
                ChildEntry {
                    hash_index: 0x55,
                    child_id: 1,
                },
                ChildEntry {
                    hash_index: 0x10, // out of order — assert fires here
                    child_id: 2,
                },
            ],
        };
        let mut page = Page::new();
        page.nodes.insert(1, bad);
        let _ = page.serialize();
    }

    #[test]
    #[should_panic(expected = "must be strictly ascending by hash_index")]
    fn serialize_panics_on_duplicate_children_constructed_via_public_fields() {
        let bad = PageNode {
            hash: vec![0u8; 4],
            is_leaf: false,
            children: vec![
                ChildEntry {
                    hash_index: 0x10,
                    child_id: 1,
                },
                ChildEntry {
                    hash_index: 0x10, // duplicate — assert fires here
                    child_id: 2,
                },
            ],
        };
        let mut page = Page::new();
        page.nodes.insert(1, bad);
        let _ = page.serialize();
    }

    #[test]
    fn deserialize_rejects_overflowing_hash_length() {
        // Craft a node whose declared hash length exceeds the buffer:
        // the addition `cursor + hash_len_usize` would have overflowed
        // on 32-bit targets, so we expect an `AlgoError`, not a panic.
        let mut bytes = Vec::new();
        write_uvarint(&mut bytes, NODE_PAGE_VERSION);
        write_varint(&mut bytes, 1); // 1 node
        write_uvarint(&mut bytes, 7); // nodeID
                                      // Declare a 1 GiB hash length, then provide nothing.
        write_uvarint(&mut bytes, 1u64 << 30);
        let err = Page::deserialize(&bytes).expect_err("must reject huge hash length");
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated node body") || msg.contains("length overflow"),
            "expected truncation / overflow error, got: {msg}",
        );

        // Now craft a length that overflows `usize` on every platform:
        // varint of u64::MAX. On 64-bit hosts this overflows on
        // `try_into`; on 32-bit hosts it overflows on `checked_add`.
        // Both paths must produce an error rather than panic.
        let mut bytes = Vec::new();
        write_uvarint(&mut bytes, NODE_PAGE_VERSION);
        write_varint(&mut bytes, 1);
        write_uvarint(&mut bytes, 9);
        write_uvarint(&mut bytes, u64::MAX);
        let err = Page::deserialize(&bytes).expect_err("must reject u64::MAX hash length");
        let msg = format!("{err}");
        assert!(
            msg.contains("overflow") || msg.contains("truncated"),
            "expected overflow / truncation error, got: {msg}",
        );
    }
}
