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

/// Codec keys whose binary value is a `basics.Address` (or `[]basics.Address`),
/// rendered as a checksummed base32 address. Sourced from the `basics.Address`
/// codec tags across `data/transactions/*.go`, `data/bookkeeping/*.go`, and
/// `data/basics/*.go` (asset-params manager/reserve/freeze/clawback: `m`/`r`/
/// `f`/`c`).
const ADDRESS_KEYS: &[&str] = &[
    "a",
    "aclose",
    "apat",
    "arcv",
    "asnd",
    "c",
    "close",
    "d",
    "f",
    "fadd",
    "fees",
    "m",
    "partupdabs",
    "partupdrmv",
    "prp",
    "r",
    "rcv",
    "rekey",
    "rwd",
    "sa",
    "sgnr",
    "snd",
];

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

/// Render a binary leaf as the JSON string go would, given the codec key it
/// sits under.
fn binary_to_string(bytes: &[u8], key: &str) -> String {
    if BLOCKHASH_KEYS.contains(&key) {
        block_hash_to_string(bytes)
    } else if ADDRESS_KEYS.contains(&key) && bytes.len() == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(bytes);
        address_to_base32(&a)
    } else {
        base64_std(bytes)
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
                // Each invalid byte (or incomplete trailing sequence) becomes one
                // replacement-character escape, matching Go's `utf8.DecodeRune`.
                out.push_str("\\ufffd");
                i += e.error_len().unwrap_or(bytes.len() - i);
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
/// the codec key this value sits under (selecting the address/block-hash/base64
/// rendering for binary leaves); array elements inherit their parent key so a
/// `[]basics.Address` (e.g. `apat`) renders each element as an address.
fn write_value(out: &mut String, value: &rmpv::Value, key: Option<&str>, level: usize) {
    match value {
        rmpv::Value::Nil => out.push_str("null"),
        rmpv::Value::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        rmpv::Value::Integer(i) => out.push_str(&i.to_string()),
        rmpv::Value::F32(f) => out.push_str(&json_number(*f as f64)),
        rmpv::Value::F64(f) => out.push_str(&json_number(*f)),
        rmpv::Value::String(s) => write_json_string(out, s.as_bytes()),
        rmpv::Value::Binary(b) => {
            write_json_string(out, binary_to_string(b, key.unwrap_or_default()).as_bytes())
        }
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
                write_value(out, elem, key, level + 1);
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
            // Canonical: sort by the (string-rendered) key.
            let mut pairs: Vec<(String, &rmpv::Value)> = entries
                .iter()
                .map(|(k, v)| (map_key_to_string(k), v))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (idx, (k, v)) in pairs.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, level + 1);
                write_json_string(out, k.as_bytes());
                out.push_str(": ");
                write_value(out, v, Some(k), level + 1);
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
    write_value(&mut out, block_val, Some("block"), 1);
    out.push('\n');
    out.push('}');
    Ok(out.into_bytes())
}
