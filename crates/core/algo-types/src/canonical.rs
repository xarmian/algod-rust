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

//! go-algorand's canonical msgpack encoding of a transaction and everything
//! inside it (`SignedTxn`, `SignedTxnWithAD`, `SignedTxnInBlock`, `LogicSig`,
//! `MultisigSig`, the state-proof structs, ...).
//!
//! It lives here, not in `algo-codec` (which re-exports every function), so
//! that the decoder can re-encode an eval delta's inner transactions the way
//! go does (issue #2424: go re-encodes what it decoded, and a repeated key or
//! any other non-canonical form inside `dt` must not survive into the payset
//! commitment).
//!
//! Rules (go's generated `MarshalMsg`):
//! 1. Structs encoded as msgpack MAPs with string keys (codec tag names)
//! 2. Map keys sorted lexicographically by raw bytes
//! 3. Zero-value fields omitted (omitempty semantics)
//! 4. Integers use shortest msgpack representation, positive values as unsigned
//! 5. Byte arrays use msgpack Binary format (bin8/bin16/bin32)
//! 6. Strings use msgpack String format (fixstr/str8/str16)

use serde_bytes::ByteBuf;

use crate::{
    Address, AssetParams, BoxRef, FalconVerifier, HashFactory, HeartbeatProof, HeartbeatTxnFields,
    HoldingRef, LocalsRef, LogicSig, MerkleProof, MerkleSignature, MerkleSignatureVerifier,
    MultisigSig, MultisigSubsig, SaltedKeySig, Participant, ResourceRef, Reveal, SigSlotCommit,
    SignedTransaction, StateProofBody, StateProofMessage, StateSchema, Transaction,
};

/// A builder for canonical msgpack maps.
///
/// Collects non-zero fields, sorts them by key, and writes a msgpack map.
///
/// Every field value is appended to one shared `arena`; `fields` only records
/// the key and the value's byte range. go-algorand's msgp `MarshalMsg` appends
/// each field to one buffer as well, so encoding does not allocate per field
/// (issue #2314: one `Vec` per field made encoding 1.6x to 2x slower than go).
#[doc(hidden)]
pub struct CanonicalMap {
    arena: Vec<u8>,
    fields: Vec<(&'static str, usize, usize)>,
}

impl Default for CanonicalMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalMap {
    pub fn new() -> Self {
        Self {
            arena: Vec::with_capacity(256),
            fields: Vec::with_capacity(16),
        }
    }

    /// Add a field whose value is already encoded.
    pub fn push_encoded(&mut self, key: &'static str, val: &[u8]) {
        let start = self.arena.len();
        self.arena.extend_from_slice(val);
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_u64(&mut self, key: &'static str, val: u64) {
        if val != 0 {
            let start = self.arena.len();
            write_uint(&mut self.arena, val);
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_i64(&mut self, key: &'static str, val: i64) {
        if val != 0 {
            let start = self.arena.len();
            write_int(&mut self.arena, val);
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_bool(&mut self, key: &'static str, val: bool) {
        if val {
            let start = self.arena.len();
            rmp::encode::write_bool(&mut self.arena, true).unwrap();
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_string(&mut self, key: &'static str, val: &str) {
        if !val.is_empty() {
            let start = self.arena.len();
            rmp::encode::write_str(&mut self.arena, val).unwrap();
            self.fields.push((key, start, self.arena.len()));
        }
    }

    /// A go `string` field that may hold arbitrary bytes (`gen`, `proto`,
    /// `nextproto`, `upgradeprop`, `type`): `val` is in the lossless
    /// [`crate::raw_text`] form the decoder produced, written back as the
    /// original bytes (issue #2397).
    pub fn add_raw_string(&mut self, key: &'static str, val: &str) {
        if !val.is_empty() {
            let start = self.arena.len();
            let bytes = crate::raw_text::decode(val);
            rmp::encode::write_str_len(&mut self.arena, bytes.len() as u32).unwrap();
            self.arena.extend_from_slice(&bytes);
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_bytes(&mut self, key: &'static str, val: &[u8]) {
        // Go's omitempty for []byte: omit when len == 0 (nil or empty) OR
        // when all bytes are zero (for fixed-size [N]byte fields like digests).
        if !val.is_empty() && val.iter().any(|&b| b != 0) {
            let start = self.arena.len();
            rmp::encode::write_bin(&mut self.arena, val).unwrap();
            self.fields.push((key, start, self.arena.len()));
        }
    }

    /// Length-only omitempty for variable-length `[]byte` fields: the
    /// value is included as long as `len > 0`, even when every byte is
    /// zero. Used for things like `ResourcesData.ApprovalProgram` /
    /// `ClearStateProgram` where Go's `[]byte` omitempty checks `len`
    /// only — an all-zero non-empty program is still valid bytecode and
    /// must be preserved. PLAN-36 G8 (TASK-122).
    pub fn add_var_bytes(&mut self, key: &'static str, val: &[u8]) {
        if !val.is_empty() {
            let start = self.arena.len();
            rmp::encode::write_bin(&mut self.arena, val).unwrap();
            self.fields.push((key, start, self.arena.len()));
        }
    }

    /// Encode a byte slice using msgpack `str` format (not `bin`).
    ///
    /// In Go, fields typed as `string` are encoded by go-codec as msgpack str,
    /// even when the Rust model stores them as `Vec<u8>`. This is needed for
    /// `TealValue.Bytes` (`"tb"` field) which is `string` in Go, not `[]byte`.
    pub fn add_str_bytes(&mut self, key: &'static str, val: &[u8]) {
        if !val.is_empty() {
            let start = self.arena.len();
            rmp::encode::write_str_len(&mut self.arena, val.len() as u32).unwrap();
            self.arena.extend_from_slice(val);
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_address(&mut self, key: &'static str, val: &Address) {
        if !val.is_zero() {
            let start = self.arena.len();
            rmp::encode::write_bin(&mut self.arena, &val.0).unwrap();
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_map(&mut self, key: &'static str, val: Vec<u8>) {
        // Skip empty maps. Our encoder always produces fixmap(0) = 0x80 for
        // zero-entry maps, but we also handle map16/map32 representations.
        let is_empty = matches!(
            val.as_slice(),
            [0x80] | [0xDE, 0x00, 0x00] | [0xDF, 0x00, 0x00, 0x00, 0x00]
        );
        if !is_empty {
            self.push_encoded(key, &val);
        }
    }

    #[allow(dead_code)] // Will be used for payset encoding in Epic 5b
    pub fn add_array_of_maps(&mut self, key: &'static str, maps: &[Vec<u8>]) {
        if !maps.is_empty() {
            let start = self.arena.len();
            rmp::encode::write_array_len(&mut self.arena, maps.len() as u32).unwrap();
            for m in maps {
                self.arena.extend_from_slice(m);
            }
            self.fields.push((key, start, self.arena.len()));
        }
    }

    pub fn add_option_address(&mut self, key: &'static str, val: &Option<Address>) {
        if let Some(addr) = val {
            if !addr.is_zero() {
                self.add_address(key, addr);
            }
        }
    }

    /// WARNING: This passes through raw rmpv bytes WITHOUT recursive canonical
    /// sorting. It is only safe when the input was deserialized from Go output
    /// (which is already canonical). When msig/lsig are promoted to typed Rust
    /// structs, this method must be replaced with canonical_encode_* functions
    /// for those types — and this method should be deleted entirely.
    /// Tracking: the type change from Option<rmpv::Value> to a typed struct
    /// will cause a compile error here, forcing the update.
    pub fn add_option_rmpv(&mut self, key: &'static str, val: &Option<rmpv::Value>) {
        if let Some(v) = val {
            if !is_rmpv_empty(v) {
                let start = self.arena.len();
                write_value_str_preserving(&mut self.arena, v).unwrap();
                self.fields.push((key, start, self.arena.len()));
            }
        }
    }

    /// Variable-length `[]byte` (box names, programs): Go's omitempty is
    /// length-only, so a non-empty all-zero value must still be encoded
    /// (issue #1654: a box reference named with eight zero bytes was dropped,
    /// changing the txid and every block commitment of the enclosing block).
    pub fn add_option_bytes(&mut self, key: &'static str, val: &Option<ByteBuf>) {
        if let Some(b) = val {
            self.add_var_bytes(key, b);
        }
    }

    pub fn add_option_fixed_bytes<const N: usize>(
        &mut self,
        key: &'static str,
        val: &Option<[u8; N]>,
    ) {
        if let Some(b) = val {
            if b.iter().any(|&x| x != 0) {
                self.add_bytes(key, b);
            }
        }
    }

    pub fn add_option_map(&mut self, key: &'static str, val: Option<Vec<u8>>) {
        if let Some(encoded) = val {
            self.add_map(key, encoded);
        }
    }

    pub fn add_option_vec_bytes(&mut self, key: &'static str, val: &Option<Vec<Option<ByteBuf>>>) {
        if let Some(items) = val {
            if !items.is_empty() {
                let start = self.arena.len();
                rmp::encode::write_array_len(&mut self.arena, items.len() as u32).unwrap();
                for item in items {
                    match item {
                        Some(bytes) => rmp::encode::write_bin(&mut self.arena, bytes).unwrap(),
                        None => rmp::encode::write_nil(&mut self.arena).unwrap(),
                    }
                }
                self.fields.push((key, start, self.arena.len()));
            }
        }
    }

    pub fn add_option_vec_address(&mut self, key: &'static str, val: &Option<Vec<Address>>) {
        if let Some(addrs) = val {
            if !addrs.is_empty() {
                let start = self.arena.len();
                rmp::encode::write_array_len(&mut self.arena, addrs.len() as u32).unwrap();
                for addr in addrs {
                    rmp::encode::write_bin(&mut self.arena, &addr.0).unwrap();
                }
                self.fields.push((key, start, self.arena.len()));
            }
        }
    }

    pub fn add_option_vec_u64(&mut self, key: &'static str, val: &Option<Vec<u64>>) {
        if let Some(vals) = val {
            if !vals.is_empty() {
                let start = self.arena.len();
                rmp::encode::write_array_len(&mut self.arena, vals.len() as u32).unwrap();
                for &v in vals {
                    write_uint(&mut self.arena, v);
                }
                self.fields.push((key, start, self.arena.len()));
            }
        }
    }

    pub fn add_option_vec_box_refs(&mut self, key: &'static str, val: &Option<Vec<BoxRef>>) {
        if let Some(refs) = val {
            if !refs.is_empty() {
                let maps: Vec<Vec<u8>> = refs.iter().map(canonical_encode_box_ref).collect();
                let start = self.arena.len();
                rmp::encode::write_array_len(&mut self.arena, maps.len() as u32).unwrap();
                for m in &maps {
                    self.arena.extend_from_slice(m);
                }
                self.fields.push((key, start, self.arena.len()));
            }
        }
    }

    // ── "always" variants: write even when the value is zero ──────────
    // Used for structs whose Go definition does NOT have `_struct codec:",omitempty"`,
    // meaning all fields are always present in the encoded output.

    pub fn add_u64_always(&mut self, key: &'static str, val: u64) {
        let start = self.arena.len();
        write_uint(&mut self.arena, val);
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_u32_always(&mut self, key: &'static str, val: u32) {
        let start = self.arena.len();
        write_uint(&mut self.arena, val as u64);
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_bool_always(&mut self, key: &'static str, val: bool) {
        let start = self.arena.len();
        rmp::encode::write_bool(&mut self.arena, val).unwrap();
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_fixed_bytes_always<const N: usize>(&mut self, key: &'static str, val: &[u8; N]) {
        let start = self.arena.len();
        rmp::encode::write_bin(&mut self.arena, val).unwrap();
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_address_always(&mut self, key: &'static str, val: &Address) {
        let start = self.arena.len();
        rmp::encode::write_bin(&mut self.arena, &val.0).unwrap();
        self.fields.push((key, start, self.arena.len()));
    }

    pub fn add_option_fixed_bytes_always<const N: usize>(
        &mut self,
        key: &'static str,
        val: &Option<[u8; N]>,
    ) {
        let zero = [0u8; N];
        let bytes = val.as_ref().unwrap_or(&zero);
        self.add_fixed_bytes_always(key, bytes);
    }

    pub fn add_option_address_always(&mut self, key: &'static str, val: &Option<Address>) {
        let zero = Address([0u8; 32]);
        let addr = val.as_ref().unwrap_or(&zero);
        self.add_address_always(key, addr);
    }

    #[allow(dead_code)] // Part of the _always API; will be used when needed
    pub fn add_map_always(&mut self, key: &'static str, val: Vec<u8>) {
        self.push_encoded(key, &val);
    }

    /// Sort fields by key in lexicographic order (raw UTF-8 bytes).
    ///
    /// Go's go-codec sorts struct field codec tags alphabetically.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len_hint());
        self.encode_into(&mut buf);
        buf
    }

    /// Upper bound of the encoded length (map header, keys, values).
    pub fn encoded_len_hint(&self) -> usize {
        let keys: usize = self.fields.iter().map(|f| f.0.len() + 2).sum();
        5 + keys + self.arena.len()
    }

    /// Append the encoded map to `buf` (go: `MarshalMsg(b []byte)`).
    pub fn encode_into(mut self, buf: &mut Vec<u8>) {
        // Callers add the keys in ascending order almost everywhere, so the
        // sort is skipped unless a pair is out of order.
        let sorted = self
            .fields
            .windows(2)
            .all(|w| w[0].0.as_bytes() <= w[1].0.as_bytes());
        if !sorted {
            self.fields
                .sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        }

        buf.reserve(self.encoded_len_hint());
        rmp::encode::write_map_len(buf, self.fields.len() as u32).unwrap();

        for &(key, start, end) in &self.fields {
            rmp::encode::write_str(buf, key).unwrap();
            buf.extend_from_slice(&self.arena[start..end]);
        }
    }

    /// Add a nested map built by `inner`, written straight into this map's
    /// arena (no intermediate buffer); an empty map is omitted like
    /// [`CanonicalMap::add_map`] does.
    pub fn add_nested_map(&mut self, key: &'static str, inner: CanonicalMap) {
        if inner.fields.is_empty() {
            return;
        }
        let start = self.arena.len();
        inner.encode_into(&mut self.arena);
        self.fields.push((key, start, self.arena.len()));
    }
}

/// Write an unsigned integer in the most compact msgpack representation.
/// Algorand uses PositiveIntUnsigned=true, so positive values (even from
/// signed Go types) are encoded as unsigned msgpack integers.
#[doc(hidden)]
pub fn write_uint(buf: &mut Vec<u8>, val: u64) {
    if val <= 127 {
        // positive fixint: single byte 0x00-0x7f
        rmp::encode::write_pfix(buf, val as u8).unwrap();
    } else if val <= 0xFF {
        rmp::encode::write_u8(buf, val as u8).unwrap();
    } else if val <= 0xFFFF {
        rmp::encode::write_u16(buf, val as u16).unwrap();
    } else if val <= 0xFFFF_FFFF {
        rmp::encode::write_u32(buf, val as u32).unwrap();
    } else {
        rmp::encode::write_u64(buf, val).unwrap();
    }
}

/// Write a signed integer in compact msgpack representation.
/// Positive values are written as unsigned (PositiveIntUnsigned=true).
/// Negative values use the most compact signed representation.
#[doc(hidden)]
pub fn write_int(buf: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        write_uint(buf, val as u64);
    } else if val >= -32 {
        // negative fixint: single byte 0xe0-0xff
        rmp::encode::write_nfix(buf, val as i8).unwrap();
    } else if val >= i8::MIN as i64 {
        rmp::encode::write_i8(buf, val as i8).unwrap();
    } else if val >= i16::MIN as i64 {
        rmp::encode::write_i16(buf, val as i16).unwrap();
    } else if val >= i32::MIN as i64 {
        rmp::encode::write_i32(buf, val as i32).unwrap();
    } else {
        rmp::encode::write_i64(buf, val).unwrap();
    }
}

/// Write the msgpack `str` length-marker + raw bytes for a string field,
/// unconditionally (regardless of whether `bytes` happens to be valid
/// UTF-8) — matching go-algorand's own msgpack encoder, which never
/// validates a Go `string`'s bytes before writing it with a `str` type
/// marker. Implemented with `rmp::encode::write_str_len`.
pub fn write_str_marker_and_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    rmp::encode::write_str_len(buf, bytes.len() as u32).expect("Vec write is infallible");
    buf.extend_from_slice(bytes);
}

/// Re-encode an `rmpv::Value` to its msgpack bytes, recursing into
/// `Array`/`Map` (whose entries may themselves contain a `String`), but with
/// one deliberate deviation from `rmpv::encode::write_value`: a
/// [`rmpv::Value::String`] is **always** written using the `str` type
/// marker with its raw bytes (via [`write_str_marker_and_bytes`]), even when
/// those bytes aren't valid UTF-8.
///
/// `rmpv::encode::write_value` (see `rmpv-1.3.1/src/encode/value.rs`)
/// writes `Value::String(Utf8String { s: Err(err) })` — i.e. a decoded
/// `str` whose bytes failed UTF-8 validation — as a `bin` instead of a
/// `str`, changing the wire type-marker byte from what go-algorand's own
/// encoder actually wrote (go never validates a Go `string`'s bytes before
/// encoding, so it always emits `str`, valid UTF-8 or not). Every other
/// `rmpv::Value` variant delegates straight to `rmpv::encode::write_value`,
/// which has no equivalent hazard for them.
pub fn write_value_str_preserving(
    buf: &mut Vec<u8>,
    value: &rmpv::Value,
) -> Result<(), rmpv::encode::Error> {
    match value {
        rmpv::Value::String(s) => {
            write_str_marker_and_bytes(buf, s.as_bytes());
            Ok(())
        }
        rmpv::Value::Array(items) => {
            rmp::encode::write_array_len(buf, items.len() as u32)?;
            for item in items {
                write_value_str_preserving(buf, item)?;
            }
            Ok(())
        }
        rmpv::Value::Map(entries) => {
            rmp::encode::write_map_len(buf, entries.len() as u32)?;
            for (k, v) in entries {
                write_value_str_preserving(buf, k)?;
                write_value_str_preserving(buf, v)?;
            }
            Ok(())
        }
        other => rmpv::encode::write_value(buf, other),
    }
}

/// Check if an rmpv::Value is "empty" (nil, empty map, empty array, etc.)
#[doc(hidden)]
pub fn is_rmpv_empty(v: &rmpv::Value) -> bool {
    match v {
        rmpv::Value::Nil => true,
        rmpv::Value::Map(m) => m.is_empty(),
        rmpv::Value::Array(a) => a.is_empty(),
        rmpv::Value::Binary(b) => b.is_empty(),
        rmpv::Value::String(s) => s.as_str().is_none_or(|s| s.is_empty()),
        _ => false,
    }
}

// ── Transaction-level encoders ──────────────────────────────────

/// Canonically encode a Transaction (the inner txn body, not signed).
///
/// This produces bytes identical to go-algorand's `protocol.Encode(&tx)`
/// for payment transactions. The encoding uses sorted keys, omitempty,
/// and compact integer representation.
pub fn canonical_encode_transaction(tx: &Transaction) -> Vec<u8> {
    canonical_encode_transaction_with_genesis(tx, &tx.genesis_id, &tx.genesis_hash)
}

/// [`canonical_encode_transaction`] with the `gen` / `gh` fields taken from
/// the given values instead of `tx`'s own. Lets callers hash a stripped
/// transaction as if its genesis fields were restored WITHOUT cloning it
/// (issue #1707).
pub fn canonical_encode_transaction_with_genesis(
    tx: &Transaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
) -> Vec<u8> {
    canonical_encode_transaction_inner(tx, genesis_id, genesis_hash, &tx.group)
}

/// [`canonical_encode_transaction`] as if the transaction's group ID were
/// zero (go's `current.Group = crypto.Digest{}` before `current.ID()` in
/// `checkTxnGroupID`), WITHOUT cloning it (issue #2193).
pub fn canonical_encode_transaction_ungrouped(tx: &Transaction) -> Vec<u8> {
    canonical_encode_transaction_inner(tx, &tx.genesis_id, &tx.genesis_hash, &[0u8; 32])
}

fn canonical_encode_transaction_inner(
    tx: &Transaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    group: &[u8; 32],
) -> Vec<u8> {
    transaction_map(tx, genesis_id, genesis_hash, group).encode()
}

/// [`canonical_encode_transaction_with_genesis`] appended to `out`, for
/// callers that hash many transactions and reuse one buffer (issue #2318).
pub fn canonical_encode_transaction_with_genesis_into(
    tx: &Transaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    out: &mut Vec<u8>,
) {
    transaction_map(tx, genesis_id, genesis_hash, &tx.group).encode_into(out);
}

/// The canonical map of a transaction (see [`canonical_encode_transaction`]).
fn transaction_map(
    tx: &Transaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    group: &[u8; 32],
) -> CanonicalMap {
    let mut m = CanonicalMap::new();

    // All fields go into the SAME map so they sort correctly in a single
    // namespace (Go behavior). The keys are the serde rename values.

    // Asset transfer (axfer)
    m.add_u64("aamt", tx.asset_amount);

    // Access list (V41+)
    if let Some(ref access) = tx.access {
        if !access.is_empty() {
            let maps: Vec<Vec<u8>> = access.iter().map(canonical_encode_resource_ref).collect();
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
            for map in &maps {
                buf.extend_from_slice(map);
            }
            m.push_encoded("al", &buf);
        }
    }
    m.add_option_address("aclose", &tx.asset_close_to);

    // Asset freeze (afrz)
    m.add_bool("afrz", tx.asset_frozen);

    // Payment
    m.add_u64("amt", tx.amount);

    // Application call (appl)
    m.add_option_vec_bytes("apaa", &tx.app_arguments);
    m.add_u64("apan", tx.on_completion);
    m.add_option_bytes("apap", &tx.approval_program);
    m.add_option_vec_u64("apas", &tx.foreign_assets);
    m.add_option_vec_address("apat", &tx.accounts);
    m.add_option_vec_box_refs("apbx", &tx.boxes);
    m.add_u64("apep", tx.extra_program_pages as u64);
    m.add_option_vec_u64("apfa", &tx.foreign_apps);
    m.add_option_map(
        "apgs",
        tx.global_state_schema
            .as_ref()
            .map(canonical_encode_state_schema),
    );
    m.add_u64("apid", tx.application_id);
    m.add_option_map(
        "apls",
        tx.local_state_schema
            .as_ref()
            .map(canonical_encode_state_schema),
    );
    m.add_u64("aprv", tx.reject_version);
    m.add_option_bytes("apsu", &tx.clear_state_program);

    // Asset config (acfg)
    m.add_option_map(
        "apar",
        tx.asset_params.as_ref().map(canonical_encode_asset_params),
    );

    // Asset transfer (axfer)
    m.add_option_address("arcv", &tx.asset_receiver);
    m.add_option_address("asnd", &tx.asset_sender);

    // Asset config (acfg)
    m.add_u64("caid", tx.config_asset);

    // Payment
    m.add_address("close", &tx.close_remainder_to);

    // Asset freeze (afrz)
    m.add_option_address("fadd", &tx.freeze_account);
    m.add_u64("faid", tx.freeze_asset);

    // Header fields
    m.add_u64("fee", tx.fee);
    m.add_u64("fv", tx.first_valid.0);
    m.add_raw_string("gen", genesis_id);
    m.add_bytes("gh", genesis_hash);
    m.add_bytes("grp", group);
    // go's msgp writes `hb` whenever the pointer is set, even to an empty
    // struct (`HeartbeatTxnFields == nil` is its only omit check)
    if let Some(ref hb) = tx.heartbeat {
        m.add_map_always("hb", canonical_encode_heartbeat(hb));
    }
    m.add_u64("lv", tx.last_valid.0);
    m.add_bytes("lx", &tx.lease);

    // Key registration (keyreg)
    m.add_bool("nonpart", tx.non_participation);

    // `Note []byte` is Go's variable-length slice (`data/transactions/
    // transaction.go`), not a fixed-size `[N]byte` digest -- its omitempty
    // is length-only (`len(tx.Note) == 0`), so a genuinely non-empty but
    // all-zero note (a real, valid value -- e.g. zero-padding) must still
    // be signed/encoded, not treated as absent. `add_bytes`'s all-zero-omit
    // rule is only correct for fixed-size digest/key/signature fields;
    // using it here silently dropped the note from the canonical encoding
    // whenever it happened to be all zero bytes, producing a signature
    // that a real go-algorand node's own (correct, length-only) canonical
    // re-encoding would never match -- confirmed live via issue #703's
    // dual-node testing (an all-zero note of any nonzero length rejected
    // by a real go-algorand node with "At least one signature didn't pass
    // verification", while algod-rust's own signature check -- built on
    // this same wrong encoding on both the signing and verifying side --
    // self-consistently accepted it).
    m.add_var_bytes("note", &tx.note);
    m.add_address("rcv", &tx.receiver);
    m.add_option_address("rekey", &tx.rekey_to);

    // Key registration (keyreg)
    m.add_option_fixed_bytes("selkey", &tx.selection_pk);

    m.add_address("snd", &tx.sender);

    // State proof (stpf)
    if let Some(ref sp) = tx.state_proof {
        m.add_map("sp", canonical_encode_state_proof_body(sp));
    }
    if let Some(ref msg) = tx.state_proof_message {
        m.add_map("spmsg", canonical_encode_state_proof_message(msg));
    }
    m.add_u64("sptype", tx.state_proof_type);
    m.add_option_fixed_bytes("sprfkey", &tx.state_proof_pk);

    m.add_raw_string("type", tx.txn_type.as_str());

    // Key registration (keyreg)
    m.add_u64("votefst", tx.vote_first);
    m.add_option_fixed_bytes("votekey", &tx.vote_pk);
    m.add_u64("votekd", tx.vote_key_dilution);
    m.add_u64("votelst", tx.vote_last);

    // Asset transfer (axfer)
    m.add_u64("xaid", tx.xaid);

    m
}

/// Canonically encode a SignedTransaction (the core signed txn, excluding
/// block-level wrapper fields like hgi/hgh which belong to SignedTxnInBlock).
pub fn canonical_encode_signed_transaction(stx: &SignedTransaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // Note: hgi and hgh are NOT part of SignedTxn in go-algorand.
    // They belong to SignedTxnInBlock (the block payset wrapper).
    if let Some(ref lsig) = stx.lsig {
        // go omits a zero `LogicSig` (`Lsig.MsgIsZero()`): a decoded `lsig: {}`
        // is not re-encoded (issue #2424)
        m.add_map("lsig", canonical_encode_logicsig(lsig));
    }
    if let Some(ref msig) = stx.msig {
        m.push_encoded("msig", &canonical_encode_multisig(msig));
    }
    if let Some(ref pqsig) = stx.pqsig {
        m.add_map("pqsig", canonical_encode_pqsig(pqsig));
    }
    m.add_bytes("sig", &stx.sig);
    m.add_option_address("sgnr", &stx.auth_addr);
    m.add_map("txn", canonical_encode_transaction(&stx.txn));

    m.encode()
}

/// Canonically encode a SignedTxnInBlock (includes hgi/hgh wrapper fields
/// and ApplyData fields).
/// This is the encoding used in block payset arrays and for STIB hash computation.
pub fn canonical_encode_signed_txn_in_block(stx: &SignedTransaction) -> Vec<u8> {
    encode_signed_txn_apply_data(stx, true)
}

/// [`canonical_encode_signed_txn_in_block`] appended to `out`, for callers
/// that hash a whole payset and reuse one buffer (issue #2318).
pub fn canonical_encode_signed_txn_in_block_into(stx: &SignedTransaction, out: &mut Vec<u8>) {
    signed_txn_apply_data_map(stx, true).encode_into(out);
}

/// The encoded length of a `SignedTxnInBlock`, optionally also checking that
/// the encoding decodes back (go `SignedTxnInBlock.GetEncodedLength(decode)`,
/// `data/transactions/signedtxn.go`, v5.0.5-stable, issue #2309).
///
/// With `decode` set a transaction that encodes but cannot be read back (for
/// example one without its required `type`/`snd`, which the encoder omits as
/// zero) returns the decode error, so block assembly never emits a payset
/// entry its peers would reject. go sets it only while generating (pool
/// admission, block assembly), never for a received block.
pub fn signed_txn_in_block_encoded_len(
    stx: &SignedTransaction,
    decode: bool,
) -> Result<usize, algo_error::AlgoError> {
    let enc = canonical_encode_signed_txn_in_block(stx);
    if decode {
        SignedTransaction::decode_from_bytes(&enc)?;
    }
    Ok(enc.len())
}

/// Canonically encode a `SignedTxnWithAD` (go `data/transactions/signedtxn.go`:
/// `SignedTxn` + embedded `ApplyData`, `codec:",omitempty,omitemptyarray"`),
/// the element type of `EvalDelta.InnerTxns` (`itx`). Identical to
/// [`canonical_encode_signed_txn_in_block`] minus `hgi`/`hgh`, which belong to
/// `SignedTxnInBlock` only. An all-zero value is the empty map `0x80`.
pub fn canonical_encode_signed_txn_with_ad(stx: &SignedTransaction) -> Vec<u8> {
    encode_signed_txn_apply_data(stx, false)
}

fn encode_signed_txn_apply_data(stx: &SignedTransaction, block_wrapper: bool) -> Vec<u8> {
    signed_txn_apply_data_map(stx, block_wrapper).encode()
}

fn signed_txn_apply_data_map(stx: &SignedTransaction, block_wrapper: bool) -> CanonicalMap {
    let mut m = CanonicalMap::new();

    // ApplyData fields (flattened from SignedTxnWithAD -> ApplyData)
    m.add_u64("aca", stx.asset_closing_amount);
    m.add_u64("apid", stx.apply_data_application_id);
    m.add_u64("ca", stx.closing_amount);
    m.add_u64("caid", stx.apply_data_config_asset);
    m.add_option_rmpv("dt", &stx.eval_delta);

    // SignedTxnInBlock wrapper fields
    if block_wrapper {
        m.add_bool("hgh", stx.has_genesis_hash);
        m.add_bool("hgi", stx.has_genesis_id);
    }

    // SignedTxn fields
    if let Some(ref lsig) = stx.lsig {
        // go omits a zero `LogicSig` (`Lsig.MsgIsZero()`): a decoded `lsig: {}`
        // is not re-encoded (issue #2424)
        m.add_map("lsig", canonical_encode_logicsig(lsig));
    }
    if let Some(ref msig) = stx.msig {
        m.push_encoded("msig", &canonical_encode_multisig(msig));
    }
    if let Some(ref pqsig) = stx.pqsig {
        m.add_map("pqsig", canonical_encode_pqsig(pqsig));
    }

    // ApplyData rewards fields
    m.add_u64("rc", stx.close_rewards);
    m.add_u64("rr", stx.receiver_rewards);
    m.add_u64("rs", stx.sender_rewards);

    m.add_bytes("sig", &stx.sig);
    m.add_option_address("sgnr", &stx.auth_addr);
    m.add_nested_map(
        "txn",
        transaction_map(
            &stx.txn,
            &stx.txn.genesis_id,
            &stx.txn.genesis_hash,
            &stx.txn.group,
        ),
    );

    m
}

/// Canonically encode AssetParams as a nested msgpack map.
pub fn canonical_encode_asset_params(apar: &AssetParams) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_option_fixed_bytes("am", &apar.metadata_hash);
    // Issue #1608: unit_name/asset_name/url are raw bytes, not `String` --
    // go's `string`-typed fields are not UTF-8-validated, so encode via
    // `add_str_bytes` (msgpack "str" format, no validity requirement) rather
    // than `add_string` (which requires a Rust `&str`).
    m.add_str_bytes("an", &apar.asset_name);
    m.add_str_bytes("au", &apar.url);
    m.add_option_address("c", &apar.clawback);
    m.add_u64("dc", apar.decimals as u64);
    m.add_bool("df", apar.default_frozen);
    m.add_option_address("f", &apar.freeze);
    m.add_option_address("m", &apar.manager);
    m.add_option_address("r", &apar.reserve);
    m.add_u64("t", apar.total);
    m.add_str_bytes("un", &apar.unit_name);

    m.encode()
}

/// Canonically encode StateSchema as a nested msgpack map.
pub fn canonical_encode_state_schema(schema: &StateSchema) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("nbs", schema.num_byte_slice);
    m.add_u64("nui", schema.num_uint);

    m.encode()
}

/// Canonically encode BoxRef as a nested msgpack map.
pub fn canonical_encode_box_ref(bref: &BoxRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("i", bref.index);
    m.add_option_bytes("n", &bref.name);

    m.encode()
}

/// Canonically encode a MultisigSubsig as a nested msgpack map.
/// Sorted fields: "pk", "s" (alphabetical). "s" omitted if empty.
pub fn canonical_encode_multisig_subsig(subsig: &MultisigSubsig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_bytes("pk", &subsig.public_key);
    m.add_bytes("s", &subsig.signature);

    m.encode()
}

/// Canonically encode a MultisigSig as a nested msgpack map.
/// Sorted fields: "subsig", "thr", "v" (alphabetical).
pub fn canonical_encode_multisig(msig: &MultisigSig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // "subsig" — array of encoded subsigs
    if !msig.subsigs.is_empty() {
        let maps: Vec<Vec<u8>> = msig
            .subsigs
            .iter()
            .map(canonical_encode_multisig_subsig)
            .collect();
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
        for map in &maps {
            buf.extend_from_slice(map);
        }
        m.push_encoded("subsig", &buf);
    }

    m.add_u64("thr", msig.threshold as u64);
    m.add_u64("v", msig.version as u64);

    m.encode()
}

/// Canonically encode a LogicSig as a nested msgpack map.
/// Sorted fields: "arg", "l", "msig", "sig" (alphabetical).
/// Only includes non-empty/non-None fields.
pub fn canonical_encode_logicsig(lsig: &LogicSig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // "arg" — optional array of byte arrays
    if let Some(ref args) = lsig.args {
        if !args.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, args.len() as u32).unwrap();
            for arg in args {
                // go `msgp.AppendBytes`: a nil element is `nil` (issue #2430)
                match arg {
                    Some(arg) => rmp::encode::write_bin(&mut buf, arg).unwrap(),
                    None => rmp::encode::write_nil(&mut buf).unwrap(),
                }
            }
            m.push_encoded("arg", &buf);
        }
    }

    // go: `Logic []byte`: length-only omitempty (an all-zero program is
    // encoded, issue #2424)
    m.add_var_bytes("l", &lsig.logic);

    if let Some(ref lmsig) = lsig.lmsig {
        m.push_encoded("lmsig", &canonical_encode_multisig(lmsig));
    }

    if let Some(ref msig) = lsig.msig {
        m.push_encoded("msig", &canonical_encode_multisig(msig));
    }

    if let Some(ref pqsig) = lsig.pqsig {
        m.add_map("pqsig", canonical_encode_pqsig(pqsig));
    }

    m.add_bytes("sig", &lsig.sig);

    m.encode()
}

/// Canonically encode a SaltedKeySig as a nested msgpack map.
/// Sorted fields: "pk", "sch", "sig", "slt" (alphabetical).
/// Only includes non-empty/non-zero fields (Go: `SaltedKeySig`'s
/// `_struct codec:",omitempty,omitemptyarray"`).
pub fn canonical_encode_pqsig(pqsig: &SaltedKeySig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // go: `PublicKey` / `Signature` are `[]byte`: length-only omitempty
    // (issue #2424)
    m.add_var_bytes("pk", &pqsig.public_key);
    m.add_bytes("sch", &pqsig.scheme);
    m.add_var_bytes("sig", &pqsig.signature);
    m.add_u64("slt", pqsig.salt.0 as u64);

    m.encode()
}

/// Canonically encode a HeartbeatProof.
pub fn canonical_encode_heartbeat_proof(proof: &HeartbeatProof) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("p", &proof.pk);
    m.add_bytes("p1s", &proof.pk1_sig);
    m.add_bytes("p2", &proof.pk2);
    m.add_bytes("p2s", &proof.pk2_sig);
    m.add_bytes("s", &proof.sig);
    m.encode()
}

/// Canonically encode HeartbeatTxnFields.
pub fn canonical_encode_heartbeat(hb: &HeartbeatTxnFields) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_address("a", &hb.address);
    m.add_bool("c", hb.hb_challenge_discount);
    m.add_u64("kd", hb.key_dilution);
    if let Some(ref proof) = hb.proof {
        m.add_map("prf", canonical_encode_heartbeat_proof(proof));
    }
    m.add_bytes("sd", &hb.seed);
    m.add_bytes("vid", &hb.vote_id);
    m.encode()
}

/// Canonically encode a HashFactory.
pub fn canonical_encode_hash_factory(hf: &HashFactory) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("t", hf.hash_type as u64);
    m.encode()
}

/// Canonically encode a MerkleProof.
pub fn canonical_encode_merkle_proof(proof: &MerkleProof) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref hf) = proof.hash_factory {
        m.add_map("hsh", canonical_encode_hash_factory(hf));
    }
    if let Some(ref path) = proof.path {
        if !path.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, path.len() as u32).unwrap();
            for item in path {
                match item {
                    Some(b) => rmp::encode::write_bin(&mut buf, b).unwrap(),
                    None => rmp::encode::write_nil(&mut buf).unwrap(),
                }
            }
            m.push_encoded("pth", &buf);
        }
    }
    m.add_u64("td", proof.tree_depth as u64);
    m.encode()
}

/// Canonically encode a FalconVerifier.
pub fn canonical_encode_falcon_verifier(fv: &FalconVerifier) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("k", &fv.public_key);
    m.encode()
}

/// Canonically encode a MerkleSignature.
pub fn canonical_encode_merkle_signature(sig: &MerkleSignature) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("idx", sig.vector_commitment_index);
    if let Some(ref proof) = sig.proof {
        m.add_map("prf", canonical_encode_merkle_proof(proof));
    }
    // go: `FalconSignature` is a `[]byte`: length-only omitempty (issue #2196).
    m.add_var_bytes("sig", &sig.signature);
    if let Some(ref vkey) = sig.verifying_key {
        m.add_map("vkey", canonical_encode_falcon_verifier(vkey));
    }
    m.encode()
}

/// Canonically encode a SigSlotCommit.
pub fn canonical_encode_sig_slot_commit(slot: &SigSlotCommit) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("l", slot.l);
    if let Some(ref sig) = slot.sig {
        m.add_map("s", canonical_encode_merkle_signature(sig));
    }
    m.encode()
}

/// Canonically encode a MerkleSignatureVerifier.
pub fn canonical_encode_merkle_sig_verifier(v: &MerkleSignatureVerifier) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("cmt", &v.commitment);
    m.add_u64("lf", v.key_lifetime);
    m.encode()
}

/// Canonically encode a Participant.
pub fn canonical_encode_participant(p: &Participant) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref pk) = p.pk {
        m.add_map("p", canonical_encode_merkle_sig_verifier(pk));
    }
    m.add_u64("w", p.weight);
    m.encode()
}

/// Canonically encode a Reveal.
pub fn canonical_encode_reveal(r: &Reveal) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref part) = r.part {
        m.add_map("p", canonical_encode_participant(part));
    }
    if let Some(ref sig_slot) = r.sig_slot {
        m.add_map("s", canonical_encode_sig_slot_commit(sig_slot));
    }
    m.encode()
}

/// Canonically encode a StateProofBody.
pub fn canonical_encode_state_proof_body(sp: &StateProofBody) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref pp) = sp.part_proofs {
        m.add_map("P", canonical_encode_merkle_proof(pp));
    }
    if let Some(ref sp_proofs) = sp.sig_proofs {
        m.add_map("S", canonical_encode_merkle_proof(sp_proofs));
    }
    // go: `SigCommit` is a `[]byte` (GenericDigest): omitempty drops only a
    // zero-LENGTH slice, an all-zero 64-byte commitment is encoded (issue #2196).
    m.add_var_bytes("c", &sp.sig_commit);
    if let Some(ref positions) = sp.positions_to_reveal {
        if !positions.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, positions.len() as u32).unwrap();
            for pos in positions {
                write_uint(&mut buf, *pos);
            }
            m.push_encoded("pr", &buf);
        }
    }
    if let Some(ref reveals) = sp.reveals {
        if !reveals.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_map_len(&mut buf, reveals.len() as u32).unwrap();
            for (key, reveal) in reveals {
                write_uint(&mut buf, *key);
                let encoded = canonical_encode_reveal(reveal);
                buf.extend_from_slice(&encoded);
            }
            m.push_encoded("r", &buf);
        }
    }
    m.add_u64("v", sp.merkle_signature_salt_version as u64);
    m.add_u64("w", sp.signed_weight);
    m.encode()
}

/// Canonically encode a StateProofMessage.
pub fn canonical_encode_state_proof_message(msg: &StateProofMessage) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("P", msg.ln_proven_weight);
    m.add_var_bytes("b", &msg.block_headers_commitment);
    m.add_u64("f", msg.first_attested_round);
    m.add_u64("l", msg.last_attested_round);
    m.add_var_bytes("v", &msg.voters_commitment);
    m.encode()
}

/// Canonically encode a HoldingRef.
pub fn canonical_encode_holding_ref(hr: &HoldingRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("d", hr.address);
    m.add_u64("s", hr.asset);
    m.encode()
}

/// Canonically encode a LocalsRef.
pub fn canonical_encode_locals_ref(lr: &LocalsRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("d", lr.address);
    m.add_u64("p", lr.app);
    m.encode()
}

/// Canonically encode a ResourceRef.
pub fn canonical_encode_resource_ref(rr: &ResourceRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref br) = rr.box_ref {
        m.add_map("b", canonical_encode_box_ref(br));
    }
    m.add_address("d", &rr.address);
    if let Some(ref hr) = rr.holding {
        m.add_map("h", canonical_encode_holding_ref(hr));
    }
    if let Some(ref lr) = rr.locals {
        m.add_map("l", canonical_encode_locals_ref(lr));
    }
    m.add_u64("p", rr.app);
    m.add_u64("s", rr.asset);
    m.encode()
}
