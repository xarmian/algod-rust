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
const ADDRESS_KEYS: &[&str] = &[
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
const APAR_ADDRESS_KEYS: &[&str] = &["c", "f", "m", "r"];

/// Codec keys whose binary value is a `bookkeeping.BlockHash`, rendered as
/// `blk-` + base32 (no checksum).
const BLOCKHASH_KEYS: &[&str] = &["prev"];

/// Render 32 address bytes as a checksummed base32 Algorand address.
fn address_to_base32(addr: &[u8; 32]) -> String {
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

/// Write a map key as a JSON string literal, escaping from the key's raw bytes
/// (so invalid-UTF-8 string keys render `�` exactly as go-codec does).
fn write_map_key(out: &mut String, key: &rmpv::Value) {
    match key {
        rmpv::Value::String(s) => write_json_string(out, s.as_bytes()),
        // Integer / binary / bool keys render to ASCII, so the lossy rendering
        // is already exact.
        other => write_json_string(out, map_key_to_string(other).as_bytes()),
    }
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
                // SAFETY: `from_utf8` reported the first `upto` bytes as valid.
                write_escaped_str(out, unsafe {
                    std::str::from_utf8_unchecked(&bytes[i..i + upto])
                });
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
    match value {
        rmpv::Value::Nil => out.push_str("null"),
        rmpv::Value::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        rmpv::Value::Integer(i) => out.push_str(&i.to_string()),
        rmpv::Value::F32(f) => out.push_str(&json_number(*f as f64)),
        rmpv::Value::F64(f) => out.push_str(&json_number(*f)),
        rmpv::Value::String(s) => write_json_string(out, s.as_bytes()),
        rmpv::Value::Binary(b) => write_json_string(
            out,
            binary_to_string(b, key.unwrap_or_default(), parent).as_bytes(),
        ),
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
                write_map_key(out, k);
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
        rmpv::Value::Ext(_, _) => out.push_str("null"),
    }
}

/// Format a float the way go-codec would (integers without a decimal point).
fn json_number(f: f64) -> String {
    if f.fract() == 0.0 && f.is_finite() {
        format!("{}", f as i64)
    } else {
        format!("{f}")
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
