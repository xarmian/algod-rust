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

//! Canonical block JSON encoding, byte-for-byte compatible with go-algorand's
//! `GET /v2/blocks/{round}?format=json` response.
//!
//! go encodes the block via `protocol.JSONStrictHandle` (`daemon/algod/api/
//! server/v2/handlers.go` `GetBlock` → `BlockResponseJSON`), a `codec.JsonHandle`
//! with `Canonical=true` (map keys sorted), `MapKeyAsString=true` (non-string map
//! keys rendered as strings), and `Indent=2`. Byte-valued fields are rendered
//! using each Go type's codec extension, not a uniform base64:
//!
//! - `basics.Address` (and `[]basics.Address`) → 58-char checksummed base32.
//! - `bookkeeping.BlockHash` → `blk-` + 52-char base32 (no checksum).
//! - everything else `[]byte` (digests, signatures, notes, programs, …) → base64 std.
//!
//! The block is stored as msgpack, where all of these are raw binary, so the
//! distinction is recovered here from the codec **key** the binary sits under.
//!
//! Output is rendered by a small printer that matches go-codec's JSON formatting
//! exactly: 2-space indent, empty collections inline (`{}`/`[]`), and Go's string
//! escaping — short escapes for `\b\f\n\r\t`, `\u00xx` for other control bytes,
//! raw output for valid UTF-8 (including non-ASCII and `<`/`>`/`&`/`/`), and
//! `�` for each invalid UTF-8 byte. serde_json cannot reproduce the
//! invalid-byte case, so the printer is hand-rolled.
//!
//! This is REST-JSON-only: the msgpack block response is a raw passthrough and
//! the consensus/canonical path uses `algo_codec`, neither of which is touched.

use base64::Engine;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha512_256};

/// Codec keys whose binary value is unambiguously a `basics.Address` (or
/// `[]basics.Address`) in any context, rendered as a checksummed base32 address.
/// Sourced from `basics.Address` codec tags across `data/transactions/*.go`,
/// `data/bookkeeping/*.go`, and `data/basics/*.go`. Short keys that *also* name a
/// binary non-address field elsewhere are handled by [`APAR_ADDRESS_KEYS`]
/// instead; the remaining short keys here (`a`, `d`) only collide with `uint64`
/// fields, which decode as integers, not binary, so they are unambiguous for a
/// binary leaf.
pub(crate) const ADDRESS_KEYS: &[&str] = &[
    "a",
    "aclose",
    "apat",
    "arcv",
    "asnd",
    "close",
    "d",
    "fadd",
    "fees",
    "partupdabs",
    "partupdrmv",
    "prp",
    "rcv",
    "rekey",
    "rwd",
    "sa",
    "sgnr",
    "snd",
];

/// Asset-params address keys (`AssetParams` manager/reserve/freeze/clawback).
/// These single letters collide with binary non-address fields elsewhere — most
/// notably `c` is also `StateProof.SigCommit` (a 32-byte digest → base64) — so
/// they are only treated as addresses when nested directly under `apar`.
pub(crate) const APAR_ADDRESS_KEYS: &[&str] = &["c", "f", "m", "r"];

/// Codec keys whose binary value is a `bookkeeping.BlockHash`, rendered as
/// `blk-` + base32 (no checksum).
const BLOCKHASH_KEYS: &[&str] = &["prev"];

/// Render 32 address bytes as a checksummed base32 Algorand address.
pub(crate) fn address_to_base32(addr: &[u8; 32]) -> String {
    let hash = Sha512_256::digest(addr);
    let mut payload = [0u8; 36];
    payload[..32].copy_from_slice(addr);
    payload[32..].copy_from_slice(&hash[28..32]);
    BASE32_NOPAD.encode(&payload)
}

/// Render a `BlockHash` as `blk-` + base32 (no checksum, no padding).
fn block_hash_to_string(bytes: &[u8]) -> String {
    format!("blk-{}", BASE32_NOPAD.encode(bytes))
}

fn base64_std(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Render a binary leaf as the JSON string go would, given the codec `key` it
/// sits under and the `parent` key of the map containing it (needed to
/// disambiguate the asset-params address letters from like-named binary fields).
fn binary_to_string(bytes: &[u8], key: &str, parent: Option<&str>) -> String {
    let is_address = (ADDRESS_KEYS.contains(&key)
        || (APAR_ADDRESS_KEYS.contains(&key) && parent == Some("apar")))
        && bytes.len() == 32;
    if BLOCKHASH_KEYS.contains(&key) {
        block_hash_to_string(bytes)
    } else if is_address {
        let mut a = [0u8; 32];
        a.copy_from_slice(bytes);
        address_to_base32(&a)
    } else {
        base64_std(bytes)
    }
}

/// Compare two msgpack map keys in go-codec's canonical order: integer keys
/// numerically, string keys lexically. Mixed/other key types fall back to their
/// string rendering (not expected in the block schema, where each map has a
/// single key type).
fn cmp_map_keys(a: &rmpv::Value, b: &rmpv::Value) -> std::cmp::Ordering {
    fn as_i128(v: &rmpv::Value) -> Option<i128> {
        match v {
            rmpv::Value::Integer(i) => i
                .as_u64()
                .map(|u| u as i128)
                .or_else(|| i.as_i64().map(|s| s as i128)),
            _ => None,
        }
    }
    match (as_i128(a), as_i128(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        // String keys are compared by their raw bytes (go sorts on the encoded
        // key, not a lossy rendering), so keys with invalid UTF-8 order the same.
        _ => match (a, b) {
            (rmpv::Value::String(x), rmpv::Value::String(y)) => x.as_bytes().cmp(y.as_bytes()),
            _ => map_key_to_string(a).cmp(&map_key_to_string(b)),
        },
    }
}

/// A map key's bytes as go-codec renders it: a string key keeps its raw bytes
/// (so invalid UTF-8 renders `�` per byte exactly as go does); integer /
/// binary / bool keys render to ASCII, so the string rendering is exact.
fn key_bytes(key: &rmpv::Value) -> Vec<u8> {
    match key {
        rmpv::Value::String(s) => s.as_bytes().to_vec(),
        other => map_key_to_string(other).into_bytes(),
    }
}

/// A scalar leaf, rendered once for both output paths (the text printer
/// [`write_value`] and the `Value` builder [`to_json_value`]), so the rendering
/// rules live in exactly one place: [`leaf`].
enum Leaf {
    Null,
    Bool(bool),
    /// An already-formatted JSON number literal.
    Num(String),
    /// A string as raw bytes (escaped / lossily decoded by each path).
    Str(Vec<u8>),
}

/// Render a non-container msgpack value, given the codec `key` it sits under and
/// the `parent` key (see [`binary_to_string`]). `None` for arrays and maps.
fn leaf(value: &rmpv::Value, key: Option<&str>, parent: Option<&str>) -> Option<Leaf> {
    Some(match value {
        rmpv::Value::Nil | rmpv::Value::Ext(_, _) => Leaf::Null,
        rmpv::Value::Boolean(b) => Leaf::Bool(*b),
        rmpv::Value::Integer(i) => Leaf::Num(i.to_string()),
        rmpv::Value::F32(f) => Leaf::Num(json_number(*f as f64)),
        rmpv::Value::F64(f) => Leaf::Num(json_number(*f)),
        rmpv::Value::String(s) => Leaf::Str(s.as_bytes().to_vec()),
        rmpv::Value::Binary(b) => {
            Leaf::Str(binary_to_string(b, key.unwrap_or_default(), parent).into_bytes())
        }
        rmpv::Value::Array(_) | rmpv::Value::Map(_) => return None,
    })
}

/// Render a non-string msgpack map key as a string (go's `MapKeyAsString`).
fn map_key_to_string(key: &rmpv::Value) -> String {
    match key {
        rmpv::Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
        rmpv::Value::Integer(i) => {
            if let Some(u) = i.as_u64() {
                u.to_string()
            } else if let Some(s) = i.as_i64() {
                s.to_string()
            } else {
                String::new()
            }
        }
        rmpv::Value::Binary(b) => base64_std(b),
        rmpv::Value::Boolean(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Append a JSON string literal (including quotes), escaping `bytes` exactly as
/// go-codec's JSON encoder does.
fn write_json_string(out: &mut String, bytes: &[u8]) {
    out.push('"');
    let mut i = 0;
    while i < bytes.len() {
        match std::str::from_utf8(&bytes[i..]) {
            Ok(valid) => {
                write_escaped_str(out, valid);
                break;
            }
            Err(e) => {
                let upto = e.valid_up_to();
                if let Ok(valid) = std::str::from_utf8(&bytes[i..i + upto]) {
                    write_escaped_str(out, valid);
                }
                i += upto;
                // Emit exactly one replacement escape per invalid byte and
                // re-decode from the next byte. Go's `utf8.DecodeRune` returns
                // size 1 for every invalid byte, so a multi-byte invalid or
                // truncated sequence becomes that many `�` (e.g. a trailing
                // `0xe2 0x82` → `��`), not one.
                out.push_str("\\ufffd");
                i += 1;
            }
        }
    }
    out.push('"');
}

/// Escape a valid UTF-8 string into `out` per go-codec's JSON rules.
fn write_escaped_str(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            // Valid non-ASCII and `<`/`>`/`&`/`/` are emitted raw (HTMLCharsAsIs).
            c => out.push(c),
        }
    }
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level * 2 {
        out.push(' ');
    }
}

/// Recursively render an msgpack value as canonical JSON into `out`. `key` is
/// the codec key this value sits under and `parent` is the key of the enclosing
/// map (both select the address/block-hash/base64 rendering for binary leaves).
/// Array elements inherit their parent key/context so a `[]basics.Address` (e.g.
/// `apat`) renders each element as an address.
fn write_value(
    out: &mut String,
    value: &rmpv::Value,
    key: Option<&str>,
    parent: Option<&str>,
    level: usize,
) {
    if let Some(l) = leaf(value, key, parent) {
        match l {
            Leaf::Null => out.push_str("null"),
            Leaf::Bool(b) => out.push_str(if b { "true" } else { "false" }),
            Leaf::Num(n) => out.push_str(&n),
            Leaf::Str(b) => write_json_string(out, &b),
        }
        return;
    }
    match value {
        rmpv::Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (idx, elem) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, level + 1);
                write_value(out, elem, key, parent, level + 1);
            }
            out.push('\n');
            push_indent(out, level);
            out.push(']');
        }
        rmpv::Value::Map(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            // Canonical: sort by the key in its natural order. go-codec sorts
            // integer keys numerically (`"2"` before `"10"`) and string keys
            // lexically (by raw bytes), so compare on the original msgpack key.
            let mut pairs: Vec<(&rmpv::Value, &rmpv::Value)> =
                entries.iter().map(|(k, v)| (k, v)).collect();
            pairs.sort_by(|a, b| cmp_map_keys(a.0, b.0));
            out.push('{');
            for (idx, (k, v)) in pairs.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, level + 1);
                write_json_string(out, &key_bytes(k));
                out.push_str(": ");
                // The entries of this map have it as their parent; `key` is the
                // key this map itself sits under. The string-rendered key drives
                // address-key detection (those keys are always ASCII).
                let key_ctx = map_key_to_string(k);
                write_value(out, v, Some(&key_ctx), key, level + 1);
            }
            out.push('\n');
            push_indent(out, level);
            out.push('}');
        }
        _ => {}
    }
}

/// Format a float the way go-codec would: integral values without a decimal
/// point or exponent (any magnitude, `-0` kept), others via Rust's shortest
/// round-trip form (never an exponent); non-finite values (which go's encoder
/// rejects) as `null`.
fn json_number(f: f64) -> String {
    if !f.is_finite() {
        "null".to_string()
    } else if f.fract() == 0.0 {
        format!("{f:.0}")
    } else {
        format!("{f}")
    }
}

/// Top-level keys of go's `transactions.SignedTxn` (`signedtxn.go`). The rust
/// `SignedTransaction` also carries the in-block-only flags (`hgi`, `hgh`) and
/// the `ApplyData` fields (`ca`, `aca`, `rs`, `rr`, `rc`, `dt`, `caid`, `apid`)
/// that go's `SignedTxnInBlock` has but `PreEncodedTxInfo.Txn` never does: go
/// reports apply data as separate top-level fields of the response.
const SIGNED_TXN_KEYS: &[&str] = &["sig", "msig", "lsig", "pqsig", "txn", "sgnr"];

/// A string leaf the way go-codec's JSON encoder writes it: one `U+FFFD` per
/// invalid UTF-8 byte (`utf8.DecodeRune` consumes a single byte each time).
fn go_lossy_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(e) => {
                let upto = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..upto]).unwrap_or_default());
                out.push('\u{fffd}');
                rest = &rest[upto + 1..];
            }
        }
    }
    out
}

/// Render an msgpack value straight into a `serde_json::Value` with the same
/// rules as [`write_value`] (shared through [`leaf`] and [`key_bytes`]; no
/// print-and-reparse).
fn to_json_value(
    value: &rmpv::Value,
    key: Option<&str>,
    parent: Option<&str>,
) -> serde_json::Value {
    use serde_json::Value as J;
    if let Some(l) = leaf(value, key, parent) {
        return match l {
            Leaf::Null => J::Null,
            Leaf::Bool(b) => J::Bool(b),
            Leaf::Num(n) => serde_json::from_str(&n).unwrap_or(J::Null),
            Leaf::Str(b) => J::String(go_lossy_string(&b)),
        };
    }
    match value {
        rmpv::Value::Array(items) => J::Array(
            items
                .iter()
                .map(|e| to_json_value(e, key, parent))
                .collect(),
        ),
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key_ctx = map_key_to_string(k);
                map.insert(
                    go_lossy_string(&key_bytes(k)),
                    to_json_value(v, Some(&key_ctx), key),
                );
            }
            J::Object(map)
        }
        _ => J::Null,
    }
}

/// Render a msgpack `SignedTxn` tree as go's JSON form of `transactions.SignedTxn`:
/// only `SignedTxn`'s own keys are kept, bytes are rendered by [`to_json_value`].
fn signed_txn_tree_to_json(tree: &rmpv::Value) -> serde_json::Value {
    match tree {
        rmpv::Value::Map(entries) => {
            let kept: Vec<(rmpv::Value, rmpv::Value)> = entries
                .iter()
                .filter(|(k, _)| k.as_str().is_some_and(|k| SIGNED_TXN_KEYS.contains(&k)))
                .cloned()
                .collect();
            to_json_value(&rmpv::Value::Map(kept), None, None)
        }
        other => to_json_value(other, None, None),
    }
}

/// The JSON value go's codec JSON handle produces for the `SignedTxn` embedded in
/// `PreEncodedTxInfo.Txn` (issue #2160). Total: go's encoder cannot fail on a
/// valid transaction, so a (never expected) msgpack round-trip failure is logged
/// and degrades to the plain serde form instead of failing the response.
pub(crate) fn signed_txn_go_json(txn: &algo_types::SignedTransaction) -> serde_json::Value {
    // go's codec omits every zero field (`omitempty`, a zero `fv` included): an
    // inner transaction pays no fee of its own, so `fee: 0` must not render
    // (issue #2178). The serde derive writes those three unless asked not to.
    let tree = algo_types::with_zero_header_fields_omitted(|| {
        algo_codec::to_vec_named_str_preserving(txn)
    })
    .map_err(|e| e.to_string())
    .and_then(|bytes| rmpv::decode::read_value(&mut &bytes[..]).map_err(|e| e.to_string()));
    match tree {
        Ok(tree) => signed_txn_tree_to_json(&tree),
        Err(e) => {
            tracing::error!(err = %e, "failed to render a transaction in go's JSON form");
            serde_json::to_value(txn).unwrap_or(serde_json::Value::Null)
        }
    }
}

/// Errors from canonical block JSON encoding.
#[derive(Debug)]
pub enum BlockJsonError {
    /// The raw block bytes were not valid msgpack.
    Decode(String),
    /// The decoded value was not a `{block, cert}` map with a `block` field.
    MissingBlock,
}

impl std::fmt::Display for BlockJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockJsonError::Decode(e) => write!(f, "block msgpack decode error: {e}"),
            BlockJsonError::MissingBlock => write!(f, "block response missing 'block' field"),
        }
    }
}

impl std::error::Error for BlockJsonError {}

/// Encode the raw `{block, cert}` msgpack block response as canonical block JSON,
/// matching go-algorand's `GET /v2/blocks/{round}?format=json` output. Only the
/// `block` field is embedded (the certificate is msgpack-only, as in go).
pub fn encode_block_json(raw_block_response: &[u8]) -> Result<Vec<u8>, BlockJsonError> {
    let tree = rmpv::decode::read_value(&mut &raw_block_response[..])
        .map_err(|e| BlockJsonError::Decode(e.to_string()))?;

    let block_val = match &tree {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_str() == Some("block"))
            .map(|(_, v)| v)
            .ok_or(BlockJsonError::MissingBlock)?,
        _ => return Err(BlockJsonError::MissingBlock),
    };

    // Render `{"block": <block>}`, matching go's `BlockResponseJSON`.
    let mut out = String::new();
    out.push_str("{\n");
    push_indent(&mut out, 1);
    out.push_str("\"block\": ");
    write_value(&mut out, block_val, Some("block"), None, 1);
    out.push('\n');
    out.push('}');
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #2178: an inner transaction with no fee renders without `fee`, as
    /// go's codec JSON omits zero fields; a nonzero fee is kept.
    #[test]
    fn signed_txn_go_json_omits_a_zero_fee() {
        let mut stx = algo_types::SignedTransaction::default();
        stx.txn.fee = 0;
        stx.txn.first_valid = algo_types::Round(5);
        let json = signed_txn_go_json(&stx);
        assert!(json["txn"].get("fee").is_none(), "{json}");
        assert!(json["txn"].get("lv").is_none(), "{json}");
        assert_eq!(json["txn"]["fv"], 5);
        stx.txn.fee = 1000;
        assert_eq!(signed_txn_go_json(&stx)["txn"]["fee"], 1000);
    }

    /// The single-letter asset-params address keys must only be treated as
    /// addresses under `apar`. In particular `c` is `AssetParams.Clawback`
    /// (address) under `apar` but `StateProof.SigCommit` (a 32-byte digest →
    /// base64) elsewhere.
    #[test]
    fn apar_address_keys_are_context_qualified() {
        let bytes = [0u8; 32];
        // Under `apar`: clawback → checksummed base32 address.
        let as_addr = binary_to_string(&bytes, "c", Some("apar"));
        assert_eq!(as_addr, address_to_base32(&bytes));
        assert!(!as_addr.contains('='), "address must not be base64");
        // Outside `apar` (e.g. state-proof sig-commit): base64 digest.
        let as_b64 = binary_to_string(&bytes, "c", Some("sp"));
        assert_eq!(as_b64, base64_std(&bytes));
        assert_ne!(as_addr, as_b64);
    }

    /// The direct `Value` builder renders exactly what the text printer does
    /// (issue #2160): same rules, no print-and-reparse.
    #[test]
    fn direct_value_rendering_equals_the_text_printer() {
        use rmpv::Value as M;
        let s = |x: &str| M::from(x);
        let tree = M::Map(vec![
            (s("snd"), M::Binary(vec![1; 32])),
            (s("gh"), M::Binary(vec![3; 32])),
            (s("n"), M::from(u64::MAX)),
            (s("neg"), M::from(-5i64)),
            (s("f"), M::F64(2.0)),
            (s("ok"), M::Boolean(true)),
            (s("nil"), M::Nil),
            (s("an"), s("h\u{e9}llo \"x\"")),
            (
                s("apar"),
                M::Map(vec![
                    (s("c"), M::Binary(vec![9; 32])),
                    (s("t"), M::from(1u64)),
                ]),
            ),
            (
                s("apat"),
                M::Array(vec![M::Binary(vec![2; 32]), M::Binary(vec![4; 32])]),
            ),
            (M::from(10u64), M::from(1u64)),
            (M::from(2u64), M::Array(vec![])),
        ]);
        let mut text = String::new();
        write_value(&mut text, &tree, None, None, 0);
        let old: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(to_json_value(&tree, None, None), old);
    }

    /// Both output paths share one rules table; sweep many shapes through the
    /// text printer and the `Value` builder and require identical results.
    #[test]
    fn sweep_text_printer_and_value_builder_agree() {
        use rmpv::Value as M;
        let s = |x: &str| M::from(x);
        let leaves = vec![
            M::Nil,
            M::Boolean(false),
            M::from(0u64),
            M::from(u64::MAX),
            M::from(i64::MIN),
            M::F64(1e19),
            M::F64(-0.0),
            M::F64(-1.5),
            M::F64(9223372036854775808.0),
            M::F32(0.25),
            M::F64(f64::NAN),
            M::String(rmpv::Utf8String::from(s("x").as_str().unwrap())),
            M::Binary(vec![]),
            M::Binary(vec![0xde, 0xad]),
            M::Ext(5, vec![1]),
        ];
        let keys = ["snd", "gh", "prev", "c", "f", "apat", "other", "r"];
        for key in keys {
            for leaf in &leaves {
                for wrapped in [
                    M::Map(vec![(s(key), leaf.clone())]),
                    M::Map(vec![(s("apar"), M::Map(vec![(s(key), leaf.clone())]))]),
                    M::Map(vec![(s(key), M::Array(vec![leaf.clone(), leaf.clone()]))]),
                ] {
                    let mut text = String::new();
                    write_value(&mut text, &wrapped, None, None, 0);
                    let old: serde_json::Value = serde_json::from_str(&text)
                        .unwrap_or_else(|e| panic!("printer output not JSON ({e}): {text}"));
                    assert_eq!(to_json_value(&wrapped, None, None), old, "{text}");
                }
            }
        }
        // 32-byte values under address / block-hash keys, and int / bin keys.
        let tree = M::Map(vec![
            (s("snd"), M::Binary(vec![1; 32])),
            (s("prev"), M::Binary(vec![2; 32])),
            (M::from(7u64), M::Binary(vec![3; 3])),
            (M::Binary(vec![9]), M::Boolean(true)),
        ]);
        let mut text = String::new();
        write_value(&mut text, &tree, None, None, 0);
        assert_eq!(
            to_json_value(&tree, None, None),
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        );
    }

    #[test]
    fn floats_render_like_go_at_every_magnitude() {
        assert_eq!(json_number(1e19), "10000000000000000000");
        assert_eq!(json_number(9223372036854775808.0), "9223372036854775808");
        assert_eq!(json_number(-0.0), "-0");
        assert_eq!(json_number(-1.5), "-1.5");
        assert_eq!(json_number(f64::INFINITY), "null");
    }

    #[test]
    fn invalid_utf8_renders_one_replacement_per_byte_like_go() {
        assert_eq!(go_lossy_string(&[0xe2, 0x82]), "\u{fffd}\u{fffd}");
        assert_eq!(go_lossy_string(b"ab"), "ab");
    }

    /// Unambiguous address keys render as addresses regardless of parent.
    #[test]
    fn unambiguous_address_keys_ignore_parent() {
        let bytes = [1u8; 32];
        assert_eq!(
            binary_to_string(&bytes, "snd", None),
            address_to_base32(&bytes)
        );
        assert_eq!(
            binary_to_string(&bytes, "rcv", Some("txn")),
            address_to_base32(&bytes)
        );
    }
}
