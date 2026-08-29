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

//! Catchpoint label parsing, verification, and construction.
//!
//! Implements `parse_catchpoint_label` which parses the `{round}#{base32_hash}`
//! format used by go-algorand's catchpoint labels, plus `make_catchpoint_label_v*`
//! for constructing labels for V6, V7, and V8 catchpoint file versions, and
//! `rebuild_trie_from_db` for rebuilding the account Merkle trie from the DB.
//!
//! Reference: `go-algorand/ledger/ledgercore/catchpointlabel.go` —
//! `ParseCatchpointLabel`, `MakeLabel`, `CatchpointLabelMakerV6/V7/Current`.

use data_encoding::BASE32_NOPAD;
use rusqlite::Connection;
use sha2::{Digest, Sha512_256};

use super::types::{
    AccountTotals, AlgoCount, CatchpointError, CatchpointLabel, CATCHPOINT_FILE_VERSION_V6,
    CATCHPOINT_FILE_VERSION_V7, CATCHPOINT_FILE_VERSION_V8,
};

/// Parse a catchpoint label string into its round and hash components.
///
/// The expected format is `{round}#{base32_hash}` where:
/// - `round` is a decimal u64
/// - `base32_hash` is base32 standard encoding (no padding) of up to 32 bytes
///
/// Matches Go's `ledgercore.ParseCatchpointLabel` semantics:
/// - Exactly one `#` separator
/// - Round is a valid u64
/// - Hash decodes from base32 to at most 32 bytes (padded with zeros if shorter)
///
/// # Errors
///
/// Returns `CatchpointError::LabelParsingFailed` if the label is malformed.
pub fn parse_catchpoint_label(label: &str) -> Result<CatchpointLabel, CatchpointError> {
    let parts: Vec<&str> = label.split('#').collect();
    if parts.len() != 2 {
        return Err(CatchpointError::LabelParsingFailed(format!(
            "expected exactly one '#' separator, got {} parts",
            parts.len()
        )));
    }

    let round: u64 = parts[0].parse().map_err(|e| {
        CatchpointError::LabelParsingFailed(format!("invalid round number '{}': {}", parts[0], e))
    })?;

    let hash_bytes = BASE32_NOPAD.decode(parts[1].as_bytes()).map_err(|e| {
        CatchpointError::LabelParsingFailed(format!("invalid base32 hash '{}': {}", parts[1], e))
    })?;

    if hash_bytes.len() > 32 {
        return Err(CatchpointError::LabelParsingFailed(format!(
            "hash too long: {} bytes (max 32)",
            hash_bytes.len()
        )));
    }

    // Go copies up to DigestSize (32) bytes, zero-filling the rest.
    let mut hash = [0u8; 32];
    hash[..hash_bytes.len()].copy_from_slice(&hash_bytes);

    Ok(CatchpointLabel { round, hash })
}

// ---------------------------------------------------------------------------
// AccountTotals canonical msgpack encoding (Go EncodeReflect compatible)
// ---------------------------------------------------------------------------

/// Encode an `AlgoCount` as a canonical msgpack map with sorted string keys
/// and omitempty semantics (matching Go's go-codec EncodeReflect).
///
/// Keys: `"mon"` (money), `"rwd"` (reward_units). Both omitted when zero.
fn encode_algo_count(ac: &AlgoCount) -> Vec<u8> {
    let mut entries: Vec<(&str, u64)> = Vec::new();
    if ac.money != 0 {
        entries.push(("mon", ac.money));
    }
    if ac.reward_units != 0 {
        entries.push(("rwd", ac.reward_units));
    }
    // Keys are already sorted: "mon" < "rwd"
    encode_string_uint_map(&entries)
}

/// Encode `AccountTotals` as canonical msgpack matching Go's `EncodeReflect`.
///
/// Top-level keys (sorted): `"notpart"`, `"offline"`, `"online"`, `"rwdlvl"`.
/// Struct-valued fields are omitted when all-zero; uint fields omitted when zero.
pub(crate) fn encode_account_totals(totals: &AccountTotals) -> Vec<u8> {
    // Build entries. For struct fields, encode them as sub-maps and only include
    // if non-zero. For u64 fields, only include if non-zero.
    // Sorted order: "notpart", "offline", "online", "rwdlvl"
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();

    let notpart_is_zero =
        totals.not_participating.money == 0 && totals.not_participating.reward_units == 0;
    if !notpart_is_zero {
        entries.push(("notpart", encode_algo_count(&totals.not_participating)));
    }

    let offline_is_zero = totals.offline.money == 0 && totals.offline.reward_units == 0;
    if !offline_is_zero {
        entries.push(("offline", encode_algo_count(&totals.offline)));
    }

    let online_is_zero = totals.online.money == 0 && totals.online.reward_units == 0;
    if !online_is_zero {
        entries.push(("online", encode_algo_count(&totals.online)));
    }

    if totals.rewards_level != 0 {
        entries.push(("rwdlvl", encode_msgpack_uint(totals.rewards_level)));
    }

    // entries are already in sorted order since: notpart < offline < online < rwdlvl
    encode_mixed_map(&entries)
}

/// Encode a msgpack map with string keys and u64 values.
fn encode_string_uint_map(entries: &[(&str, u64)]) -> Vec<u8> {
    let mixed: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(k, v)| (*k, encode_msgpack_uint(*v)))
        .collect();
    encode_mixed_map(&mixed)
}

/// Encode a msgpack map with string keys and pre-encoded msgpack values.
pub(crate) fn encode_mixed_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let len = entries.len();

    // Map header
    if len <= 15 {
        buf.push(0x80 | len as u8); // fixmap
    } else if len <= 0xFFFF {
        buf.push(0xDE);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xDF);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }

    for (key, value) in entries {
        // String key
        let key_bytes = key.as_bytes();
        let klen = key_bytes.len();
        if klen <= 31 {
            buf.push(0xA0 | klen as u8); // fixstr
        } else if klen <= 0xFF {
            buf.push(0xD9);
            buf.push(klen as u8);
        } else {
            buf.push(0xDA);
            buf.extend_from_slice(&(klen as u16).to_be_bytes());
        }
        buf.extend_from_slice(key_bytes);

        // Pre-encoded value
        buf.extend_from_slice(value);
    }

    buf
}

/// Encode a u64 as msgpack using the most compact representation.
pub(crate) fn encode_msgpack_uint(v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    if v <= 0x7F {
        buf.push(v as u8); // positive fixint
    } else if v <= 0xFF {
        buf.push(0xCC);
        buf.push(v as u8);
    } else if v <= 0xFFFF {
        buf.push(0xCD);
        buf.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        buf.push(0xCE);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push(0xCF);
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf
}

// ---------------------------------------------------------------------------
// Catchpoint label construction
// ---------------------------------------------------------------------------

/// Build the V6 buffer for catchpoint label hashing.
///
/// Layout: `block_hash(32) || balances_root(32) || EncodeReflect(totals)`
fn v6_buffer(block_hash: &[u8; 32], balances_root: &[u8; 32], totals: &AccountTotals) -> Vec<u8> {
    let encoded_totals = encode_account_totals(totals);
    let mut buf = Vec::with_capacity(64 + encoded_totals.len());
    buf.extend_from_slice(block_hash);
    buf.extend_from_slice(balances_root);
    buf.extend_from_slice(&encoded_totals);
    buf
}

/// Construct a catchpoint label for V6 (file version 129).
///
/// The label hash is `SHA512/256(block_hash || balances_root || EncodeReflect(totals))`.
/// NO domain separator prefix is used.
///
/// Returns `"{round}#{base32_nopad(hash)}"`.
pub fn make_catchpoint_label_v6(
    round: u64,
    block_hash: &[u8; 32],
    balances_root: &[u8; 32],
    totals: &AccountTotals,
) -> String {
    let buf = v6_buffer(block_hash, balances_root, totals);
    let hash = Sha512_256::digest(&buf);
    let encoded = BASE32_NOPAD.encode(&hash);
    format!("{round}#{encoded}")
}

/// Construct a catchpoint label for V7 (file version 130).
///
/// Buffer: `V6_buffer || sp_verification_hash(32)`.
pub fn make_catchpoint_label_v7(
    round: u64,
    block_hash: &[u8; 32],
    balances_root: &[u8; 32],
    totals: &AccountTotals,
    sp_hash: &[u8; 32],
) -> String {
    let mut buf = v6_buffer(block_hash, balances_root, totals);
    buf.extend_from_slice(sp_hash);
    let hash = Sha512_256::digest(&buf);
    let encoded = BASE32_NOPAD.encode(&hash);
    format!("{round}#{encoded}")
}

/// Construct a catchpoint label for V8/current (file version 131).
///
/// Buffer: `V7_buffer || online_accounts_hash(32) || online_round_params_hash(32)`.
pub fn make_catchpoint_label_v8(
    round: u64,
    block_hash: &[u8; 32],
    balances_root: &[u8; 32],
    totals: &AccountTotals,
    sp_hash: &[u8; 32],
    online_accts_hash: &[u8; 32],
    online_round_params_hash: &[u8; 32],
) -> String {
    let mut buf = v6_buffer(block_hash, balances_root, totals);
    buf.extend_from_slice(sp_hash);
    buf.extend_from_slice(online_accts_hash);
    buf.extend_from_slice(online_round_params_hash);
    let hash = Sha512_256::digest(&buf);
    let encoded = BASE32_NOPAD.encode(&hash);
    format!("{round}#{encoded}")
}

// ---------------------------------------------------------------------------
// Component hash computations for catchpoint label verification
// ---------------------------------------------------------------------------

/// Encode a string as msgpack string format.
///
/// Production callers in this module now route through
/// `algo_codec::canonical_encode_state_proof_verification_context`
/// (PLAN-36 TASK-125), but the unit tests below still construct
/// msgpack maps by hand and rely on this helper. Kept `#[cfg(test)]`
/// so the lib build doesn't fail the clippy `dead_code` lint.
#[cfg(test)]
fn encode_msgpack_str(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_str(&mut buf, s).expect("write_str to Vec never fails");
    buf
}

/// Encode a byte slice as msgpack binary format.
pub(crate) fn encode_msgpack_bin(b: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_bin(&mut buf, b).expect("write_bin to Vec never fails");
    buf
}

/// Encode a msgpack array header followed by pre-encoded element bytes.
fn encode_msgpack_array(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_array_len(&mut buf, elements.len() as u32)
        .expect("write_array_len to Vec never fails");
    for elem in elements {
        buf.extend_from_slice(elem);
    }
    buf
}

/// Local type for decoding `StateProofVerificationContext` from DB blobs,
/// including the `v` (version) field that the shared type in `types.rs` omits.
///
/// Fields match Go's `ledgercore.StateProofVerificationContext` codec tags.
/// Sorted key order: `"pw"`, `"spround"`, `"v"`, `"vc"`.
#[derive(serde::Deserialize)]
struct SpVerificationCtxFull {
    #[serde(rename = "spround", default)]
    last_attested_round: u64,
    #[serde(rename = "vc", default)]
    voters_commitment: serde_bytes::ByteBuf,
    #[serde(rename = "pw", default)]
    online_total_weight: u64,
    #[serde(rename = "v", default)]
    version: String,
}

/// Canonically encode a single `StateProofVerificationContext` as msgpack.
///
/// PLAN-36 G8 (TASK-125) promoted this to a public encoder in
/// `algo-codec`. This helper now adapts the decoder-side
/// [`SpVerificationCtxFull`] (which carries the `version` field
/// alongside the trio in the shared catchpoint types) into the public
/// [`algo_codec::StateProofVerificationContext`] and delegates. The
/// catchpoint label hash and the trackerdb BLOB write path now share
/// the same byte producer.
fn encode_sp_verification_context(ctx: &SpVerificationCtxFull) -> Vec<u8> {
    let public = algo_codec::StateProofVerificationContext {
        last_attested_round: ctx.last_attested_round,
        voters_commitment: ctx.voters_commitment.to_vec(),
        online_total_weight: ctx.online_total_weight,
        version: ctx.version.clone(),
    };
    algo_codec::canonical_encode_state_proof_verification_context(&public)
}

/// Canonically encode the SP verification wrapper struct.
///
/// Go type: `catchpointStateProofVerificationContext` with key `"spd"`.
/// The wrapper has a single field `"spd"` containing an array of SP contexts.
/// Uses omitempty: the `"spd"` field is omitted if the array is empty.
fn encode_sp_verification_wrapper(contexts: &[SpVerificationCtxFull]) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    if !contexts.is_empty() {
        let encoded_elements: Vec<Vec<u8>> = contexts
            .iter()
            .map(encode_sp_verification_context)
            .collect();
        entries.push(("spd", encode_msgpack_array(&encoded_elements)));
    }
    encode_mixed_map(&entries)
}

/// Compute the state proof verification hash.
///
/// Reads all rows from the `stateproofverification` table, decodes each
/// verification context blob, wraps them in the canonical wrapper struct,
/// and computes `SHA512_256("spv" || canonical_encode(wrapper))`.
///
/// Corresponds to Go's:
/// ```text
/// wrappedContext := catchpointStateProofVerificationContext{Data: rawContexts}
/// spverHash = crypto.HashObj(wrappedContext)
/// ```
///
/// Reference: `go-algorand/ledger/catchupaccessor.go` -- `GetVerifyData`
pub fn calculate_sp_verification_hash(conn: &Connection) -> Result<[u8; 32], CatchpointError> {
    let blob = build_sp_verification_blob(conn)?;
    Ok(hash_sp_verification_blob(&blob))
}

/// Hash an already-encoded SP verification wrapper blob.
///
/// `SHA512_256("spv" || blob)`, matching Go's `crypto.HashObj` over
/// `catchpointStateProofVerificationContext` (`protocol.StateProofVerCtx`
/// hash ID is the ASCII prefix `"spv"`).
pub fn hash_sp_verification_blob(blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(b"spv");
    hasher.update(blob);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Build the canonical msgpack blob written to the catchpoint file's
/// `stateProofVerificationContext.msgpack` entry.
///
/// This is the exact byte string Go hashes to obtain the SP verification
/// component of the catchpoint label (`catchpointTracker.getSPVerificationData`
/// in `../go-algorand/ledger/catchpointtracker.go`), so the writer and the
/// label computation are guaranteed to agree.
pub fn build_sp_verification_blob(conn: &Connection) -> Result<Vec<u8>, CatchpointError> {
    let contexts = read_sp_verification_contexts(conn)?;
    Ok(encode_sp_verification_wrapper(&contexts))
}

/// Read and decode every row of the `stateproofverification` table, ordered
/// by `lastattestedround` (matching Go's iteration order).
fn read_sp_verification_contexts(
    conn: &Connection,
) -> Result<Vec<SpVerificationCtxFull>, CatchpointError> {
    let mut stmt = conn
        .prepare(
            "SELECT verificationContext FROM stateproofverification \
             ORDER BY lastattestedround",
        )
        .map_err(|e| {
            CatchpointError::VerificationError(format!("prepare stateproofverification query: {e}"))
        })?;

    let rows = stmt
        .query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })
        .map_err(|e| {
            CatchpointError::VerificationError(format!("query stateproofverification: {e}"))
        })?;

    let mut contexts = Vec::new();
    for row in rows {
        let blob = row.map_err(|e| {
            CatchpointError::VerificationError(format!("read stateproofverification row: {e}"))
        })?;
        let ctx: SpVerificationCtxFull = rmp_serde::from_slice(&blob).map_err(|e| {
            CatchpointError::VerificationError(format!(
                "decode state proof verification context: {e}"
            ))
        })?;
        contexts.push(ctx);
    }

    Ok(contexts)
}

/// Canonically encode an `OnlineAccountRecordV6` as msgpack.
///
/// Keys (sorted): `"addr"`, `"data"`, `"nob"`, `"upd"`, `"vlv"`.
/// Uses omitempty: zero fields and empty bytes are omitted.
///
/// - `address`: Go `basics.Address` (`[32]byte`), omitted when all zeros.
/// - `data`: Go `msgp.Raw` -- raw msgpack bytes injected directly (not bin-wrapped).
/// - `update_round`, `vote_last_valid`: Go `basics.Round` (u64), omitted when zero.
/// - `normalized_balance`: u64, omitted when zero.
pub(crate) fn encode_online_account_record(
    address: &[u8],
    update_round: u64,
    normalized_balance: u64,
    vote_last_valid: u64,
    data: &[u8],
) -> Vec<u8> {
    // Sorted key order: addr < data < nob < upd < vlv
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    // Go's Digest.MsgIsZero() -> all-zero [32]byte is considered zero.
    let addr_is_zero = address.iter().all(|&b| b == 0);
    if !address.is_empty() && !addr_is_zero {
        entries.push(("addr", encode_msgpack_bin(address)));
    }
    if !data.is_empty() {
        // msgp.Raw: written directly as raw msgpack bytes (not bin-wrapped).
        entries.push(("data", data.to_vec()));
    }
    if normalized_balance != 0 {
        entries.push(("nob", encode_msgpack_uint(normalized_balance)));
    }
    if update_round != 0 {
        entries.push(("upd", encode_msgpack_uint(update_round)));
    }
    if vote_last_valid != 0 {
        entries.push(("vlv", encode_msgpack_uint(vote_last_valid)));
    }
    encode_mixed_map(&entries)
}

/// Compute the online accounts hash (aggregate).
///
/// Iterates over all rows in the `onlineaccounts` table ordered by
/// `(address, updround)`, computes per-row `SHA512_256("OA" || canonical_encode(record))`,
/// and feeds each 32-byte hash into a streaming SHA-512/256 hasher.
///
/// Corresponds to Go's:
/// ```text
/// calculateVerificationHash(ctx, tx.MakeOrderedOnlineAccountsIter, 0, true)
/// ```
///
/// Reference: `go-algorand/ledger/catchupaccessor.go` -- `calculateVerificationHash`
pub fn calculate_online_accounts_hash(conn: &Connection) -> Result<[u8; 32], CatchpointError> {
    let mut stmt = conn
        .prepare(
            "SELECT address, updround, normalizedonlinebalance, votelastvalid, data \
             FROM onlineaccounts ORDER BY address, updround",
        )
        .map_err(|e| {
            CatchpointError::VerificationError(format!("prepare onlineaccounts query: {e}"))
        })?;

    let rows = stmt
        .query_map([], |row| {
            let address: Vec<u8> = row.get(0)?;
            let updround: i64 = row.get(1)?;
            let norm_bal: i64 = row.get(2)?;
            let vlv: i64 = row.get(3)?;
            let data: Vec<u8> = row.get(4)?;
            Ok((address, updround as u64, norm_bal as u64, vlv as u64, data))
        })
        .map_err(|e| CatchpointError::VerificationError(format!("query onlineaccounts: {e}")))?;

    // Streaming hasher: feeds each per-row hash into an aggregate hash.
    let mut aggregate_hasher = Sha512_256::new();

    for row in rows {
        let (address, updround, norm_bal, vlv, data) = row.map_err(|e| {
            CatchpointError::VerificationError(format!("read onlineaccounts row: {e}"))
        })?;

        let encoded = encode_online_account_record(&address, updround, norm_bal, vlv, &data);

        // Per-row hash: SHA512_256("OA" || encoded)
        let mut row_hasher = Sha512_256::new();
        row_hasher.update(b"OA");
        row_hasher.update(&encoded);
        let row_hash = row_hasher.finalize();

        // Feed into aggregate
        aggregate_hasher.update(row_hash);
    }

    let result = aggregate_hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Canonically encode an `OnlineRoundParamsRecordV6` as msgpack.
///
/// Keys (sorted): `"data"`, `"rnd"`.
/// Uses omitempty: zero fields and empty bytes are omitted.
/// The `data` field is `msgp.Raw` in Go -- raw msgpack bytes injected directly.
pub(crate) fn encode_online_round_params_record(round: u64, data: &[u8]) -> Vec<u8> {
    // Sorted key order: data < rnd
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    if !data.is_empty() {
        // msgp.Raw: written directly as raw msgpack bytes (not bin-wrapped).
        entries.push(("data", data.to_vec()));
    }
    if round != 0 {
        entries.push(("rnd", encode_msgpack_uint(round)));
    }
    encode_mixed_map(&entries)
}

/// Compute the online round params hash (aggregate).
///
/// Iterates over all rows in the `onlineroundparamstail` table ordered by `rnd`,
/// computes per-row `SHA512_256("ORP" || canonical_encode(record))`,
/// and feeds each 32-byte hash into a streaming SHA-512/256 hasher.
///
/// Corresponds to Go's:
/// ```text
/// calculateVerificationHash(ctx, tx.MakeOnlineRoundParamsIter, 0, true)
/// ```
///
/// Reference: `go-algorand/ledger/catchupaccessor.go` -- `calculateVerificationHash`
pub fn calculate_online_round_params_hash(conn: &Connection) -> Result<[u8; 32], CatchpointError> {
    let mut stmt = conn
        .prepare("SELECT rnd, data FROM onlineroundparamstail ORDER BY rnd")
        .map_err(|e| {
            CatchpointError::VerificationError(format!("prepare onlineroundparamstail query: {e}"))
        })?;

    let rows = stmt
        .query_map([], |row| {
            let rnd: i64 = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            Ok((rnd as u64, data))
        })
        .map_err(|e| {
            CatchpointError::VerificationError(format!("query onlineroundparamstail: {e}"))
        })?;

    // Streaming hasher: feeds each per-row hash into an aggregate hash.
    let mut aggregate_hasher = Sha512_256::new();

    for row in rows {
        let (rnd, data) = row.map_err(|e| {
            CatchpointError::VerificationError(format!("read onlineroundparamstail row: {e}"))
        })?;

        let encoded = encode_online_round_params_record(rnd, &data);

        // Per-row hash: SHA512_256("ORP" || encoded)
        let mut row_hasher = Sha512_256::new();
        row_hasher.update(b"ORP");
        row_hasher.update(&encoded);
        let row_hash = row_hasher.finalize();

        // Feed into aggregate
        aggregate_hasher.update(row_hash);
    }

    let result = aggregate_hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Trie rebuild from DB
// ---------------------------------------------------------------------------

/// Compute a 36-byte trie element from raw encoded account data.
///
/// Matches Go's `AccountHashBuilderV6`: hashes the raw encoded blob directly
/// (no decode/re-encode round trip).
///
/// Prehash: `address(32) || encoded_data`
/// Element: `affinity(4 BE) || kind=0(1) || SHA512/256(prehash)[1..32]`
fn raw_account_element(addr: &[u8; 32], encoded_data: &[u8], affinity: u32) -> [u8; 36] {
    let mut hasher = Sha512_256::new();
    hasher.update(addr);
    hasher.update(encoded_data);
    let hash = hasher.finalize();

    let mut element = [0u8; 36];
    element[0..4].copy_from_slice(&affinity.to_be_bytes());
    element[4] = 0; // HashKind::Account
    element[5..36].copy_from_slice(&hash[1..32]);
    element
}

/// Compute a 36-byte trie element for a resource from raw encoded data.
///
/// Matches Go's `ResourcesHashBuilderV6`: hashes the raw encoded blob directly.
///
/// Prehash: `address(32) || creatable_index(8 LE) || resource_blob`
/// Element: `affinity(4 BE) || kind(1) || SHA512/256(prehash)[1..32]`
fn raw_resource_element(
    addr: &[u8; 32],
    creatable_index: u64,
    resource_data: &[u8],
    affinity: u32,
    kind: u8,
) -> [u8; 36] {
    let mut hasher = Sha512_256::new();
    hasher.update(addr);
    hasher.update(creatable_index.to_le_bytes());
    hasher.update(resource_data);
    let hash = hasher.finalize();

    let mut element = [0u8; 36];
    element[0..4].copy_from_slice(&affinity.to_be_bytes());
    element[4] = kind;
    element[5..36].copy_from_slice(&hash[1..32]);
    element
}

/// Rebuild the account Merkle trie from the database and return the root hash.
///
/// Iterates over all accounts in `accountbase`, all resources in `resources`,
/// and all key-value entries in `kvstore`, computing trie elements using the
/// V6 hash functions and inserting them into a new `MerkleTrie`.
///
/// Uses raw encoded blobs directly from the database for hashing (matching
/// Go's `AccountHashBuilderV6` which hashes the raw encoded data, not a
/// decoded-then-reencoded version). Affinity values are extracted from the
/// raw msgpack without full decode.
///
/// This is the standalone equivalent of `SqliteLedger::rebuild_trie_from_db`,
/// designed for use during catchpoint import where a full `SqliteLedger` is not
/// available.
pub fn rebuild_trie_from_db(conn: &Connection) -> Result<[u8; 32], CatchpointError> {
    use crate::merkle_trie::MerkleTrie;
    use crate::trie_hash::{extract_raw_affinity, kv_hash_v6, HashKind, ELEMENT_SIZE};

    const CTYPE_APP: i64 = 1;

    let mut trie = MerkleTrie::new(ELEMENT_SIZE);

    // 1. Process all accounts from accountbase.
    {
        let mut stmt = conn
            .prepare("SELECT address, data FROM accountbase")
            .map_err(|e| {
                CatchpointError::ImportError(format!("prepare accounts for trie rebuild: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                let addr_bytes: Vec<u8> = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((addr_bytes, data))
            })
            .map_err(|e| {
                CatchpointError::ImportError(format!("query accounts for trie rebuild: {e}"))
            })?;

        for row in rows {
            let (addr_bytes, data) =
                row.map_err(|e| CatchpointError::ImportError(format!("read account row: {e}")))?;
            if addr_bytes.len() != 32 {
                return Err(CatchpointError::ImportError(format!(
                    "bad address length {} (expected 32) in accountbase",
                    addr_bytes.len()
                )));
            }
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);
            let affinity = extract_raw_affinity(&data);
            let elem = raw_account_element(&addr, &data, affinity);
            trie.add(&elem)
                .map_err(|e| CatchpointError::ImportError(format!("trie add account: {e}")))?;
        }
    }

    // 2. Process all resources.
    {
        let mut stmt = conn
            .prepare(
                "SELECT r.addrid, r.aidx, r.ctype, r.data, a.address, a.data \
                 FROM resources r \
                 JOIN accountbase a ON a.rowid = r.addrid",
            )
            .map_err(|e| {
                CatchpointError::ImportError(format!("prepare resources for trie rebuild: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                let _addrid: i64 = row.get(0)?;
                let aidx: i64 = row.get(1)?;
                let ctype: i64 = row.get(2)?;
                let rdata: Vec<u8> = row.get(3)?;
                let addr_bytes: Vec<u8> = row.get(4)?;
                let acct_data: Vec<u8> = row.get(5)?;
                Ok((aidx, ctype, rdata, addr_bytes, acct_data))
            })
            .map_err(|e| {
                CatchpointError::ImportError(format!("query resources for trie rebuild: {e}"))
            })?;

        for row in rows {
            let (aidx, ctype, rdata, addr_bytes, _acct_data) =
                row.map_err(|e| CatchpointError::ImportError(format!("read resource row: {e}")))?;
            if addr_bytes.len() != 32 {
                return Err(CatchpointError::ImportError(format!(
                    "bad address length {} (expected 32) for resource aidx={aidx}",
                    addr_bytes.len()
                )));
            }
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);

            // Use the resource's own UpdateRound for affinity, matching Go's
            // ResourcesHashBuilderV6 which passes resData.UpdateRound.
            let affinity = extract_raw_affinity(&rdata);

            let kind = if ctype == CTYPE_APP {
                HashKind::App as u8
            } else {
                HashKind::Asset as u8
            };

            let elem = raw_resource_element(&addr, aidx as u64, &rdata, affinity, kind);
            trie.add(&elem)
                .map_err(|e| CatchpointError::ImportError(format!("trie add resource: {e}")))?;
        }
    }

    // 3. Process all KV (box) entries from kvstore.
    {
        let mut stmt = conn
            .prepare("SELECT key, value FROM kvstore")
            .map_err(|e| {
                CatchpointError::ImportError(format!("prepare kvstore for trie rebuild: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                let key: Vec<u8> = row.get(0)?;
                let value: Vec<u8> = row.get(1)?;
                Ok((key, value))
            })
            .map_err(|e| {
                CatchpointError::ImportError(format!("query kvstore for trie rebuild: {e}"))
            })?;

        for row in rows {
            let (key, value) =
                row.map_err(|e| CatchpointError::ImportError(format!("read kvstore row: {e}")))?;
            let elem = kv_hash_v6(&key, &value);
            trie.add(&elem)
                .map_err(|e| CatchpointError::ImportError(format!("trie add kv: {e}")))?;
        }
    }

    trie.root_hash()
        .map_err(|e| CatchpointError::ImportError(format!("trie root_hash: {e}")))
}

// ---------------------------------------------------------------------------
// Lookback block download orchestration
// ---------------------------------------------------------------------------

/// Maximum transaction lifetime in rounds (Go: `MaxTxnLife`).
///
/// The lookback window needs at least `MaxTxnLife + 1 = 1001` blocks
/// to cover all potentially active leases at the catchpoint round.
pub const MAX_TXN_LIFE: u64 = 1000;

/// Downloads lookback blocks from `round` backward for lease reconstruction.
///
/// After catchpoint import, we need block history to reconstruct the lease
/// table and provide block header lookback for transaction validation. This
/// function orchestrates downloading blocks from `round` backward to
/// `max(0, round - MAX_TXN_LIFE)`, storing each block's raw data via the
/// provided `store_block` callback.
///
/// # Arguments
///
/// * `round` - The catchpoint round (highest round to download).
/// * `fetch_block` - Callback that fetches raw block bytes and protocol version
///   for a given round. Returns `(proto, hdrdata, blkdata)`. The caller
///   (typically the CLI) bridges this to the async `BlockSource` trait.
/// * `store_block` - Callback that persists a block. Receives
///   `(round, proto, hdrdata, blkdata)`.
///
/// # Returns
///
/// The number of blocks successfully downloaded and stored.
///
/// # Errors
///
/// Returns `CatchpointError` if any fetch or store operation fails.
///
/// # Reference
///
/// go-algorand `ledger/ledger.go` lines 764-773: the txTail maintains
/// `[Latest - MaxTxnLife, Latest]` block headers (1001 rounds lookback).
/// After catchpoint restore, `loadFromDisk` reads txtail entries from the DB
/// to reconstruct leases and block header history.
pub fn download_lookback_blocks<F, S>(
    round: u64,
    mut fetch_block: F,
    mut store_block: S,
) -> Result<u64, CatchpointError>
where
    F: FnMut(u64) -> Result<(String, Vec<u8>, Vec<u8>), CatchpointError>,
    S: FnMut(u64, &str, &[u8], &[u8]) -> Result<(), CatchpointError>,
{
    let start_round = round.saturating_sub(MAX_TXN_LIFE);

    let mut count = 0u64;
    // Download from the catchpoint round backward (inclusive on both ends).
    // Going backward matches the typical catchpoint download pattern where
    // the catchpoint block is fetched first, then predecessors.
    let mut rnd = round;
    loop {
        if rnd < start_round {
            break;
        }

        let (proto, hdrdata, blkdata) = fetch_block(rnd).map_err(|e| {
            CatchpointError::VerificationError(format!(
                "failed to fetch lookback block at round {rnd}: {e}"
            ))
        })?;

        store_block(rnd, &proto, &hdrdata, &blkdata).map_err(|e| {
            CatchpointError::VerificationError(format!(
                "failed to store lookback block at round {rnd}: {e}"
            ))
        })?;

        count += 1;

        if rnd == 0 {
            break;
        }
        rnd -= 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Lease table reconstruction from txtail entries
// ---------------------------------------------------------------------------

/// Reconstruct the lease table from stored txtail entries in the database.
///
/// After lookback blocks are downloaded and their txtail entries stored,
/// this function reads them back and rebuilds the `LeaseTable` with all
/// leases that are still active at `current_round`.
///
/// # Arguments
///
/// * `conn` - SQLite connection containing the `txtail` table.
/// * `current_round` - The catchpoint round. Leases with `last_valid >= current_round`
///   are considered active.
///
/// # Returns
///
/// A populated `LeaseTable` containing all active leases found in the
/// lookback window.
///
/// # Reference
///
/// go-algorand `ledger/txtail.go` `loadFromDisk`:
/// ```text
/// for _, rlease := range txTailRound.Leases {
///     if rlease.Lease != [32]byte{} {
///         key := ledgercore.Txlease{Sender: rlease.Sender, Lease: rlease.Lease}
///         t.recent[old].txleases[key] = txTailRound.LastValid[rlease.TxnIdx]
///     }
/// }
/// ```
pub fn reconstruct_lease_table(
    conn: &Connection,
    current_round: u64,
) -> Result<crate::lease::LeaseTable, CatchpointError> {
    let mut lease_table = crate::lease::LeaseTable::new();

    let start_round = current_round.saturating_sub(MAX_TXN_LIFE);

    // Read all txtail entries in the lookback window.
    let mut stmt = conn
        .prepare("SELECT rnd, data FROM txtail WHERE rnd >= ?1 AND rnd <= ?2 ORDER BY rnd")
        .map_err(|e| CatchpointError::VerificationError(format!("prepare txtail query: {e}")))?;

    let rows = stmt
        .query_map(
            rusqlite::params![start_round as i64, current_round as i64],
            |row| {
                let rnd: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((rnd as u64, data))
            },
        )
        .map_err(|e| CatchpointError::VerificationError(format!("query txtail: {e}")))?;

    for row in rows {
        let (_rnd, data) =
            row.map_err(|e| CatchpointError::VerificationError(format!("read txtail row: {e}")))?;

        // Decode the TxTailRound from msgpack.
        let txtail: algo_types::TxTailRound = rmp_serde::from_slice(&data)
            .map_err(|e| CatchpointError::VerificationError(format!("decode txtail entry: {e}")))?;

        // Process each lease entry.
        for lease_entry in &txtail.leases {
            // Skip empty leases (all zeros).
            if lease_entry.lease.len() != 32 {
                continue;
            }
            let mut lease_bytes = [0u8; 32];
            lease_bytes.copy_from_slice(&lease_entry.lease);

            // All-zero lease is "no lease" — skip it.
            if lease_bytes == [0u8; 32] {
                continue;
            }

            // Look up the last_valid for this lease's transaction.
            let idx = lease_entry.txn_idx as usize;
            if idx >= txtail.last_valid.len() {
                continue; // malformed entry, skip
            }
            let last_valid = txtail.last_valid[idx];

            // Only record leases that are still active at current_round.
            if last_valid >= current_round {
                lease_table.record(&lease_entry.sender, &lease_bytes, last_valid);
            }
        }
    }

    Ok(lease_table)
}

// ---------------------------------------------------------------------------
// Catchpoint verification orchestrator
// ---------------------------------------------------------------------------

/// Result of a catchpoint verification.
#[derive(Debug, Clone)]
pub struct CatchpointVerifyResult {
    /// Whether the verification was successful (computed label matches stored label).
    pub success: bool,
    /// The label stored in the database (from `catchpointCatchupLabel`).
    pub expected_label: String,
    /// The label reconstructed from the database state.
    pub computed_label: String,
    /// The Merkle trie root hash computed by rebuilding the trie from the DB.
    pub trie_root: [u8; 32],
    /// Number of accounts found in the `accountbase` table.
    pub accounts_count: u64,
}

/// A non-critical warning found during post-import validation.
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    /// Short category label (e.g. "totals", "kvstore", "creators").
    pub category: String,
    /// Human-readable description.
    pub message: String,
}

/// Read a string value from the `catchpointstate` table.
fn read_catchpointstate_str(conn: &Connection, key: &str) -> Result<String, CatchpointError> {
    conn.query_row(
        "SELECT strval FROM catchpointstate WHERE id = ?1",
        rusqlite::params![key],
        |row| row.get(0),
    )
    .map_err(|e| {
        CatchpointError::VerificationError(format!(
            "failed to read catchpointstate key '{key}': {e}"
        ))
    })
}

/// Read an integer value from the `catchpointstate` table.
fn read_catchpointstate_int(conn: &Connection, key: &str) -> Result<i64, CatchpointError> {
    conn.query_row(
        "SELECT intval FROM catchpointstate WHERE id = ?1",
        rusqlite::params![key],
        |row| row.get(0),
    )
    .map_err(|e| {
        CatchpointError::VerificationError(format!(
            "failed to read catchpointstate key '{key}': {e}"
        ))
    })
}

/// Read the `acctrounds` value for a given key.
fn read_acctrounds(conn: &Connection, key: &str) -> Result<i64, CatchpointError> {
    conn.query_row(
        "SELECT rnd FROM acctrounds WHERE id = ?1",
        rusqlite::params![key],
        |row| row.get(0),
    )
    .map_err(|e| {
        CatchpointError::VerificationError(format!("failed to read acctrounds key '{key}': {e}"))
    })
}

/// Read the `accounttotals` row from the database.
pub(crate) fn read_account_totals(conn: &Connection) -> Result<AccountTotals, CatchpointError> {
    let (online, online_ru, offline, offline_ru, nopart, nopart_ru, rwdlvl): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            "SELECT online, onlinerewardunits, offline, offlinerewardunits, \
             notparticipating, notparticipatingrewardunits, rewardslevel \
             FROM accounttotals WHERE id = ''",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(|e| {
            CatchpointError::VerificationError(format!("failed to read accounttotals: {e}"))
        })?;

    Ok(AccountTotals {
        online: AlgoCount {
            money: online as u64,
            reward_units: online_ru as u64,
        },
        offline: AlgoCount {
            money: offline as u64,
            reward_units: offline_ru as u64,
        },
        not_participating: AlgoCount {
            money: nopart as u64,
            reward_units: nopart_ru as u64,
        },
        rewards_level: rwdlvl as u64,
    })
}

/// Count rows in the `accountbase` table.
pub(crate) fn count_accounts(conn: &Connection) -> Result<u64, CatchpointError> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM accountbase", [], |row| row.get(0))
        .map_err(|e| {
            CatchpointError::VerificationError(format!("failed to count accounts: {e}"))
        })?;
    Ok(count as u64)
}

/// Verify a catchpoint database after import.
///
/// This orchestrates the full verification pipeline:
/// 1. Reads catchpointstate keys (label, version, rounds) from the DB.
/// 2. Parses the stored catchpoint label.
/// 3. Rebuilds the Merkle trie from the DB to obtain the balances root hash.
/// 4. Computes component hashes (SP verification, online accounts, online round params).
/// 5. Reads account totals from the DB.
/// 6. Reconstructs the catchpoint label from the computed values.
/// 7. Compares the reconstructed label against the stored label.
///
/// The `block_header_digest` must be provided externally (from the catchpoint
/// file header) since it is not stored separately in the database.
///
/// # Arguments
///
/// * `conn` - Open SQLite connection to the catchpoint database (post-import).
/// * `block_header_digest` - The 32-byte block header digest from the catchpoint file header.
///
/// # Returns
///
/// A `CatchpointVerifyResult` indicating whether the verification passed.
pub fn verify_catchpoint(
    conn: &Connection,
    block_header_digest: &[u8; 32],
) -> Result<CatchpointVerifyResult, CatchpointError> {
    // Step 1: Read catchpointstate keys. Key names match Go's
    // `trackerdb.CatchpointState*` constants — see
    // `crate::catchpoint::state_keys` for the canonical list and the
    // mapping back to Go's `catchpoint.go`.
    use crate::catchpoint::state_keys;
    let stored_label = read_catchpointstate_str(conn, state_keys::CATCHUP_LABEL)?;
    let version = read_catchpointstate_int(conn, state_keys::CATCHUP_VERSION)? as u64;
    let _balances_round =
        read_catchpointstate_int(conn, state_keys::CATCHUP_BALANCES_ROUND)? as u64;

    // Step 2: Parse the stored label to extract round.
    let parsed_label = parse_catchpoint_label(&stored_label)?;
    let round = parsed_label.round;

    // Step 3: Read acctrounds to verify consistency.
    let db_balances_round = read_acctrounds(conn, "acctbase")? as u64;
    if db_balances_round != round {
        return Err(CatchpointError::VerificationError(format!(
            "acctrounds mismatch: acctrounds says round {db_balances_round}, \
             but catchpoint label says round {round}"
        )));
    }

    // Step 4: Rebuild Merkle trie.
    let trie_root = rebuild_trie_from_db(conn)?;

    // Step 5: Compute component hashes.
    let sp_hash = calculate_sp_verification_hash(conn)?;
    let online_accts_hash = calculate_online_accounts_hash(conn)?;
    let online_round_params_hash = calculate_online_round_params_hash(conn)?;

    // Step 6: Read account totals.
    let totals = read_account_totals(conn)?;

    // Step 7: Count accounts.
    let accounts_count = count_accounts(conn)?;

    // Step 8: Construct the label based on file version.
    let computed_label = match version {
        CATCHPOINT_FILE_VERSION_V6 => {
            make_catchpoint_label_v6(round, block_header_digest, &trie_root, &totals)
        }
        CATCHPOINT_FILE_VERSION_V7 => {
            make_catchpoint_label_v7(round, block_header_digest, &trie_root, &totals, &sp_hash)
        }
        CATCHPOINT_FILE_VERSION_V8 => make_catchpoint_label_v8(
            round,
            block_header_digest,
            &trie_root,
            &totals,
            &sp_hash,
            &online_accts_hash,
            &online_round_params_hash,
        ),
        other => {
            return Err(CatchpointError::VerificationError(format!(
                "unsupported catchpoint version {other} for label reconstruction"
            )));
        }
    };

    // Step 9: Compare.
    let success = computed_label == stored_label;

    Ok(CatchpointVerifyResult {
        success,
        expected_label: stored_label,
        computed_label,
        trie_root,
        accounts_count,
    })
}

/// Validate database consistency after catchpoint import.
///
/// Runs a series of non-critical checks against the post-import database
/// state and returns warnings for anything suspicious. Critical failures
/// are returned as errors.
///
/// # Arguments
///
/// * `conn` - Open SQLite connection to the catchpoint database.
/// * `expected_round` - The round the database should be at (from the catchpoint label).
///
/// # Returns
///
/// A list of `ValidationWarning` items for non-critical issues.
pub fn validate_post_import(
    conn: &Connection,
    expected_round: u64,
) -> Result<Vec<ValidationWarning>, CatchpointError> {
    let mut warnings = Vec::new();

    // Check 1: acctrounds matches expected round.
    let acctbase_round = read_acctrounds(conn, "acctbase")? as u64;
    if acctbase_round != expected_round {
        return Err(CatchpointError::VerificationError(format!(
            "acctrounds 'acctbase' is {acctbase_round}, expected {expected_round}"
        )));
    }

    // Check 2: accounttotals are non-negative and sensible.
    let totals = read_account_totals(conn)?;
    let total_money = totals
        .online
        .money
        .checked_add(totals.offline.money)
        .and_then(|s| s.checked_add(totals.not_participating.money))
        .ok_or_else(|| {
            CatchpointError::VerificationError(
                "total money overflow: sum of online + offline + not_participating exceeds u64"
                    .to_string(),
            )
        })?;
    if total_money == 0 {
        warnings.push(ValidationWarning {
            category: "totals".to_string(),
            message: "total money across all status classes is zero".to_string(),
        });
    }

    // Check 3: Box/KV consistency — count kvstore entries and compare to total_boxes
    // metadata in accounts if available.
    let kv_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM kvstore", [], |row| row.get(0))
        .unwrap_or(0);
    // Sum total_boxes from all accounts. The "m" field is total_boxes in the
    // raw blob, but we can't easily extract it from raw msgpack. Instead, just
    // report the kvstore count for informational purposes.
    if kv_count > 0 {
        // Just note how many KV entries exist — deeper validation would require
        // decoding every account blob.
        tracing::debug!("kvstore has {kv_count} entries");
    }

    // Check 4: Creator/resource index spot-check.
    // Verify that assetcreators entries reference addresses that exist in accountbase.
    let orphan_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM assetcreators ac \
             WHERE NOT EXISTS (SELECT 1 FROM accountbase ab WHERE ab.address = ac.creator)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if orphan_count > 0 {
        warnings.push(ValidationWarning {
            category: "creators".to_string(),
            message: format!(
                "{orphan_count} assetcreators entries reference addresses not in accountbase"
            ),
        });
    }

    // Check 5: Verify hashbase round matches acctbase round.
    match read_acctrounds(conn, "hashbase") {
        Ok(hashbase_round) => {
            if hashbase_round as u64 != expected_round {
                warnings.push(ValidationWarning {
                    category: "acctrounds".to_string(),
                    message: format!(
                        "hashbase round ({hashbase_round}) does not match expected round ({expected_round})"
                    ),
                });
            }
        }
        Err(_) => {
            warnings.push(ValidationWarning {
                category: "acctrounds".to_string(),
                message: "hashbase entry missing from acctrounds".to_string(),
            });
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a 32-byte digest as base32 no-padding.
    fn encode_hash(hash: &[u8; 32]) -> String {
        BASE32_NOPAD.encode(hash)
    }

    #[test]
    fn parse_valid_label() {
        let hash = [0xABu8; 32];
        let label = format!("47000000#{}", encode_hash(&hash));
        let parsed = parse_catchpoint_label(&label).unwrap();
        assert_eq!(parsed.round, 47_000_000);
        assert_eq!(parsed.hash, hash);
    }

    #[test]
    fn parse_round_zero() {
        let hash = [0x01u8; 32];
        let label = format!("0#{}", encode_hash(&hash));
        let parsed = parse_catchpoint_label(&label).unwrap();
        assert_eq!(parsed.round, 0);
        assert_eq!(parsed.hash, hash);
    }

    #[test]
    fn parse_max_round() {
        let hash = [0xFFu8; 32];
        let label = format!("{}#{}", u64::MAX, encode_hash(&hash));
        let parsed = parse_catchpoint_label(&label).unwrap();
        assert_eq!(parsed.round, u64::MAX);
        assert_eq!(parsed.hash, hash);
    }

    #[test]
    fn error_no_separator() {
        let result = parse_catchpoint_label("47000000ABCDEF");
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("'#' separator"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn error_multiple_separators() {
        let result = parse_catchpoint_label("47000000##ABCDEF");
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("3 parts"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn error_invalid_round() {
        let result = parse_catchpoint_label("5x893060#AAAA");
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("invalid round"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn error_negative_round() {
        let result = parse_catchpoint_label("-5893060#AAAA");
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("invalid round"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn error_invalid_base32() {
        // Lowercase is not valid standard base32
        let result =
            parse_catchpoint_label("5893060#aURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA");
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("invalid base32"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn error_hash_too_long() {
        // 33 bytes -> base32 encoded, longer than 32 bytes
        let long_bytes = [0xAB; 33];
        let encoded = BASE32_NOPAD.encode(&long_bytes);
        let label = format!("100#{encoded}");
        let result = parse_catchpoint_label(&label);
        assert!(result.is_err());
        match result.unwrap_err() {
            CatchpointError::LabelParsingFailed(msg) => {
                assert!(msg.contains("hash too long"), "msg: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn parse_shorter_hash_is_zero_padded() {
        // A hash that decodes to fewer than 32 bytes should be zero-padded.
        let short = [0xCC; 16];
        let encoded = BASE32_NOPAD.encode(&short);
        let label = format!("999#{encoded}");
        let parsed = parse_catchpoint_label(&label).unwrap();
        assert_eq!(parsed.round, 999);
        assert_eq!(&parsed.hash[..16], &short);
        assert_eq!(&parsed.hash[16..], &[0u8; 16]);
    }

    #[test]
    fn error_empty_label() {
        let result = parse_catchpoint_label("");
        assert!(result.is_err());
    }

    #[test]
    fn error_only_separator() {
        let result = parse_catchpoint_label("#");
        assert!(result.is_err());
    }

    /// Matches Go's TestCatchpointLabelParsing2 test case:
    /// `5893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJAB`
    /// This is one char too long (hash > 32 bytes), so it should fail.
    #[test]
    fn go_test_case_hash_too_long() {
        let result =
            parse_catchpoint_label("5893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJAB");
        assert!(result.is_err());
    }

    /// A valid 52-char base32 hash (encodes exactly 32 bytes) should parse
    /// successfully. 52 chars * 5 bits = 260 bits = 32 bytes + 4 padding bits.
    /// The trailing 'A' (0b00000) has zero padding bits, which is valid.
    #[test]
    fn go_test_case_valid_hash_length() {
        let result =
            parse_catchpoint_label("5893060#KURJLS6EWBEVXTMLC7NP3NABTUMQP32QUJOBBW2TT23376L6RWJA");
        assert!(result.is_ok(), "expected valid label, got: {result:?}");
        let label = result.unwrap();
        assert_eq!(label.round, 5_893_060);
        assert_eq!(label.hash.len(), 32);
    }

    // -----------------------------------------------------------------------
    // AccountTotals encoding tests (verified against Go EncodeReflect output)
    // -----------------------------------------------------------------------

    #[test]
    fn encode_account_totals_all_zero() {
        let totals = AccountTotals::default();
        let encoded = encode_account_totals(&totals);
        // Go EncodeReflect produces 0x80 (empty fixmap) for all-zero totals.
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn encode_account_totals_non_zero() {
        let totals = AccountTotals {
            online: AlgoCount {
                money: 1_000_000,
                reward_units: 500,
            },
            offline: AlgoCount {
                money: 2_000_000,
                reward_units: 1000,
            },
            not_participating: AlgoCount::default(),
            rewards_level: 42,
        };
        let encoded = encode_account_totals(&totals);
        // Verified against Go EncodeReflect output:
        // fixmap(3) | "offline" -> {mon:2000000, rwd:1000}
        //           | "online"  -> {mon:1000000, rwd:500}
        //           | "rwdlvl"  -> 42
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x83, // fixmap(3)
            // key "offline" (7 chars)
            0xA7, b'o', b'f', b'f', b'l', b'i', b'n', b'e',
            // value: fixmap(2)
            0x82,
              // key "mon"
              0xA3, b'm', b'o', b'n',
              // value: uint32 2_000_000 = 0x001E8480
              0xCE, 0x00, 0x1E, 0x84, 0x80,
              // key "rwd"
              0xA3, b'r', b'w', b'd',
              // value: uint16 1000 = 0x03E8
              0xCD, 0x03, 0xE8,
            // key "online" (6 chars)
            0xA6, b'o', b'n', b'l', b'i', b'n', b'e',
            // value: fixmap(2)
            0x82,
              // key "mon"
              0xA3, b'm', b'o', b'n',
              // value: uint32 1_000_000 = 0x000F4240
              0xCE, 0x00, 0x0F, 0x42, 0x40,
              // key "rwd"
              0xA3, b'r', b'w', b'd',
              // value: uint16 500 = 0x01F4
              0xCD, 0x01, 0xF4,
            // key "rwdlvl" (6 chars)
            0xA6, b'r', b'w', b'd', b'l', b'v', b'l',
            // value: fixint 42
            0x2A,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn encode_account_totals_online_only() {
        let totals = AccountTotals {
            online: AlgoCount {
                money: 5000,
                reward_units: 0,
            },
            ..Default::default()
        };
        let encoded = encode_account_totals(&totals);
        // Verified against Go EncodeReflect output:
        // fixmap(1) | "online" -> {mon:5000}
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x81, // fixmap(1)
            // key "online" (6 chars)
            0xA6, b'o', b'n', b'l', b'i', b'n', b'e',
            // value: fixmap(1)
            0x81,
              // key "mon"
              0xA3, b'm', b'o', b'n',
              // value: uint16 5000 = 0x1388
              0xCD, 0x13, 0x88,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn encode_msgpack_uint_compact() {
        // positive fixint (0-127)
        assert_eq!(encode_msgpack_uint(0), vec![0x00]);
        assert_eq!(encode_msgpack_uint(42), vec![42]);
        assert_eq!(encode_msgpack_uint(127), vec![127]);
        // uint8
        assert_eq!(encode_msgpack_uint(128), vec![0xCC, 128]);
        assert_eq!(encode_msgpack_uint(255), vec![0xCC, 255]);
        // uint16
        assert_eq!(encode_msgpack_uint(256), vec![0xCD, 0x01, 0x00]);
        assert_eq!(encode_msgpack_uint(0xFFFF), vec![0xCD, 0xFF, 0xFF]);
        // uint32
        assert_eq!(
            encode_msgpack_uint(0x10000),
            vec![0xCE, 0x00, 0x01, 0x00, 0x00]
        );
        // uint64
        assert_eq!(
            encode_msgpack_uint(0x1_0000_0000),
            vec![0xCF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    // -----------------------------------------------------------------------
    // Label maker tests
    // -----------------------------------------------------------------------

    #[test]
    fn make_label_v6_format() {
        let block_hash = [0xAA; 32];
        let balances_root = [0xBB; 32];
        let totals = AccountTotals::default();
        let label = make_catchpoint_label_v6(100, &block_hash, &balances_root, &totals);

        // Check format: "{round}#{base32}"
        assert!(label.starts_with("100#"), "label: {label}");
        let parsed = parse_catchpoint_label(&label).unwrap();
        assert_eq!(parsed.round, 100);
    }

    #[test]
    fn make_label_v6_deterministic() {
        let block_hash = [0xAA; 32];
        let balances_root = [0xBB; 32];
        let totals = AccountTotals {
            online: AlgoCount {
                money: 1_000_000,
                reward_units: 500,
            },
            offline: AlgoCount {
                money: 2_000_000,
                reward_units: 1000,
            },
            not_participating: AlgoCount::default(),
            rewards_level: 42,
        };

        let label1 = make_catchpoint_label_v6(100, &block_hash, &balances_root, &totals);
        let label2 = make_catchpoint_label_v6(100, &block_hash, &balances_root, &totals);
        assert_eq!(label1, label2, "labels should be deterministic");

        // Verify hash is SHA512/256 of the buffer
        let buf = v6_buffer(&block_hash, &balances_root, &totals);
        let hash = Sha512_256::digest(&buf);
        let expected_encoded = BASE32_NOPAD.encode(&hash);
        assert_eq!(label1, format!("100#{expected_encoded}"));
    }

    #[test]
    fn make_label_v7_extends_v6() {
        let block_hash = [0xAA; 32];
        let balances_root = [0xBB; 32];
        let totals = AccountTotals::default();
        let sp_hash = [0xCC; 32];

        let v6 = make_catchpoint_label_v6(200, &block_hash, &balances_root, &totals);
        let v7 = make_catchpoint_label_v7(200, &block_hash, &balances_root, &totals, &sp_hash);

        // V7 should differ from V6 because it includes sp_hash
        assert_ne!(v6, v7);

        // Parse both to confirm format
        let parsed = parse_catchpoint_label(&v7).unwrap();
        assert_eq!(parsed.round, 200);
    }

    #[test]
    fn make_label_v8_extends_v7() {
        let block_hash = [0xAA; 32];
        let balances_root = [0xBB; 32];
        let totals = AccountTotals::default();
        let sp_hash = [0xCC; 32];
        let online_hash = [0xDD; 32];
        let round_params_hash = [0xEE; 32];

        let v7 = make_catchpoint_label_v7(300, &block_hash, &balances_root, &totals, &sp_hash);
        let v8 = make_catchpoint_label_v8(
            300,
            &block_hash,
            &balances_root,
            &totals,
            &sp_hash,
            &online_hash,
            &round_params_hash,
        );

        // V8 should differ from V7
        assert_ne!(v7, v8);

        // Parse to confirm format
        let parsed = parse_catchpoint_label(&v8).unwrap();
        assert_eq!(parsed.round, 300);
    }

    #[test]
    fn make_label_v6_known_hash() {
        // Verify the V6 label buffer construction matches Go's layout:
        // buffer = blockHash(32) || balancesRoot(32) || EncodeReflect(totals)
        let block_hash = [0x01; 32];
        let balances_root = [0x02; 32];
        let totals = AccountTotals::default(); // encodes as 0x80

        let buf = v6_buffer(&block_hash, &balances_root, &totals);
        assert_eq!(buf.len(), 32 + 32 + 1); // 65 bytes
        assert_eq!(&buf[..32], &[0x01; 32]);
        assert_eq!(&buf[32..64], &[0x02; 32]);
        assert_eq!(&buf[64..], &[0x80]); // empty msgpack map
    }

    #[test]
    fn make_label_v7_buffer_layout() {
        // V7 = V6_buffer || sp_hash(32)
        let block_hash = [0x01; 32];
        let balances_root = [0x02; 32];
        let totals = AccountTotals::default();
        let sp_hash = [0x03; 32];

        let mut v6_buf = v6_buffer(&block_hash, &balances_root, &totals);
        let v6_len = v6_buf.len();
        v6_buf.extend_from_slice(&sp_hash);

        // Verify the hash matches what make_catchpoint_label_v7 would produce
        let hash = Sha512_256::digest(&v6_buf);
        let expected = format!("500#{}", BASE32_NOPAD.encode(&hash));
        let actual = make_catchpoint_label_v7(500, &block_hash, &balances_root, &totals, &sp_hash);
        assert_eq!(actual, expected);
        assert_eq!(v6_buf.len(), v6_len + 32);
    }

    #[test]
    fn make_label_v8_buffer_layout() {
        // V8 = V6_buffer || sp_hash(32) || online_accts(32) || online_round_params(32)
        let block_hash = [0x01; 32];
        let balances_root = [0x02; 32];
        let totals = AccountTotals::default();
        let sp_hash = [0x03; 32];
        let online_hash = [0x04; 32];
        let round_params_hash = [0x05; 32];

        let mut full_buf = v6_buffer(&block_hash, &balances_root, &totals);
        full_buf.extend_from_slice(&sp_hash);
        full_buf.extend_from_slice(&online_hash);
        full_buf.extend_from_slice(&round_params_hash);

        let hash = Sha512_256::digest(&full_buf);
        let expected = format!("600#{}", BASE32_NOPAD.encode(&hash));
        let actual = make_catchpoint_label_v8(
            600,
            &block_hash,
            &balances_root,
            &totals,
            &sp_hash,
            &online_hash,
            &round_params_hash,
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn make_label_different_rounds_different_labels() {
        let block_hash = [0xAA; 32];
        let balances_root = [0xBB; 32];
        let totals = AccountTotals::default();

        let l1 = make_catchpoint_label_v6(100, &block_hash, &balances_root, &totals);
        let l2 = make_catchpoint_label_v6(200, &block_hash, &balances_root, &totals);

        // Hash portion should be the same (same buffer), but round differs
        let p1 = parse_catchpoint_label(&l1).unwrap();
        let p2 = parse_catchpoint_label(&l2).unwrap();
        assert_eq!(p1.hash, p2.hash, "same inputs should produce same hash");
        assert_ne!(p1.round, p2.round);
    }

    #[test]
    fn make_label_parseable() {
        // Every label we produce must be parseable by parse_catchpoint_label
        let block_hash = [0xFF; 32];
        let balances_root = [0x00; 32];
        let totals = AccountTotals {
            online: AlgoCount {
                money: 999_999_999,
                reward_units: 123,
            },
            ..Default::default()
        };
        let sp_hash = [0x42; 32];
        let online_hash = [0x11; 32];
        let rp_hash = [0x22; 32];

        for label in [
            make_catchpoint_label_v6(1, &block_hash, &balances_root, &totals),
            make_catchpoint_label_v7(2, &block_hash, &balances_root, &totals, &sp_hash),
            make_catchpoint_label_v8(
                3,
                &block_hash,
                &balances_root,
                &totals,
                &sp_hash,
                &online_hash,
                &rp_hash,
            ),
        ] {
            let parsed = parse_catchpoint_label(&label);
            assert!(
                parsed.is_ok(),
                "label '{label}' should be parseable: {parsed:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Component hash computation tests
    // -----------------------------------------------------------------------

    /// Helper: create an in-memory SQLite DB with the required tables.
    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE stateproofverification (
                lastattestedround INTEGER PRIMARY KEY NOT NULL,
                verificationContext BLOB NOT NULL
            );
            CREATE TABLE onlineaccounts (
                address BLOB NOT NULL,
                updround INTEGER NOT NULL,
                normalizedonlinebalance INTEGER NOT NULL,
                votelastvalid INTEGER NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (address, updround)
            );
            CREATE TABLE onlineroundparamstail (
                rnd INTEGER NOT NULL PRIMARY KEY,
                data BLOB NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn sp_verification_hash_empty_table() {
        let conn = create_test_db();
        let hash = calculate_sp_verification_hash(&conn).unwrap();

        // Empty data -> wrapper encodes as empty map (0x80).
        // Hash = SHA512_256("spv" || 0x80)
        let mut hasher = Sha512_256::new();
        hasher.update(b"spv");
        hasher.update([0x80]); // empty fixmap
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn sp_verification_hash_single_context() {
        let conn = create_test_db();

        // Create a SP verification context with known values and encode it.
        // We use a context with all fields populated to test full encoding.
        let ctx_blob = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("pw", encode_msgpack_uint(1_000_000)),
                ("spround", encode_msgpack_uint(256)),
                ("v", encode_msgpack_str("v41")),
                ("vc", encode_msgpack_bin(&[0xAA; 32])),
            ];
            encode_mixed_map(&entries)
        };

        conn.execute(
            "INSERT INTO stateproofverification(lastattestedround, verificationContext) VALUES(?1, ?2)",
            rusqlite::params![256i64, &ctx_blob],
        )
        .unwrap();

        let hash = calculate_sp_verification_hash(&conn).unwrap();

        // Manually compute the expected hash:
        // wrapper = {"spd": [ctx_encoded]}
        // Hash = SHA512_256("spv" || encode(wrapper))
        let ctx_encoded = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("pw", encode_msgpack_uint(1_000_000)),
                ("spround", encode_msgpack_uint(256)),
                ("v", encode_msgpack_str("v41")),
                ("vc", encode_msgpack_bin(&[0xAA; 32])),
            ];
            encode_mixed_map(&entries)
        };
        let wrapper = {
            let array = encode_msgpack_array(&[ctx_encoded]);
            let entries: Vec<(&str, Vec<u8>)> = vec![("spd", array)];
            encode_mixed_map(&entries)
        };

        let mut hasher = Sha512_256::new();
        hasher.update(b"spv");
        hasher.update(&wrapper);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn online_accounts_hash_empty_table() {
        let conn = create_test_db();
        let hash = calculate_online_accounts_hash(&conn).unwrap();

        // Empty table -> streaming hasher with no data.
        // SHA512_256 of empty input.
        let hasher = Sha512_256::new();
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn online_accounts_hash_single_row() {
        let conn = create_test_db();

        let address = [0x01u8; 32];
        // BaseOnlineAccountData encoded as msgpack (minimal: all zeros -> empty map)
        let data = vec![0x80]; // empty fixmap

        conn.execute(
            "INSERT INTO onlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) \
             VALUES(?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&address[..], 100i64, 5000i64, 200i64, &data[..]],
        )
        .unwrap();

        let hash = calculate_online_accounts_hash(&conn).unwrap();

        // Manually compute expected:
        // record = canonical_encode({addr: address, data: data, nob: 5000, upd: 100, vlv: 200})
        let record = encode_online_account_record(&address, 100, 5000, 200, &data);

        // Per-row hash
        let mut row_hasher = Sha512_256::new();
        row_hasher.update(b"OA");
        row_hasher.update(&record);
        let row_hash: [u8; 32] = row_hasher.finalize().into();

        // Aggregate: streaming hash of single row hash
        let mut agg_hasher = Sha512_256::new();
        agg_hasher.update(row_hash);
        let expected: [u8; 32] = agg_hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn online_accounts_hash_multiple_rows_ordered() {
        let conn = create_test_db();

        // Insert two accounts with different addresses (sorted order)
        let addr_a = [0x01u8; 32];
        let addr_b = [0x02u8; 32];
        let data = vec![0x80]; // empty fixmap

        conn.execute(
            "INSERT INTO onlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) \
             VALUES(?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&addr_a[..], 10i64, 100i64, 50i64, &data[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO onlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) \
             VALUES(?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&addr_b[..], 20i64, 200i64, 100i64, &data[..]],
        )
        .unwrap();

        let hash = calculate_online_accounts_hash(&conn).unwrap();

        // Manually compute expected (rows ordered by address, updround)
        let rec_a = encode_online_account_record(&addr_a, 10, 100, 50, &data);
        let rec_b = encode_online_account_record(&addr_b, 20, 200, 100, &data);

        let hash_a = Sha512_256::digest([b"OA".as_slice(), &rec_a].concat());
        let hash_b = Sha512_256::digest([b"OA".as_slice(), &rec_b].concat());

        let mut agg = Sha512_256::new();
        agg.update(hash_a);
        agg.update(hash_b);
        let expected: [u8; 32] = agg.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn online_round_params_hash_empty_table() {
        let conn = create_test_db();
        let hash = calculate_online_round_params_hash(&conn).unwrap();

        // Empty table -> streaming hasher with no data.
        let hasher = Sha512_256::new();
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn online_round_params_hash_single_row() {
        let conn = create_test_db();

        // OnlineRoundParamsData encoded as canonical msgpack
        // {"online": 1000000, "proto": "v41", "rwdlvl": 0}
        // With omitempty: only "online" and "proto" are present
        let data = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("online", encode_msgpack_uint(1_000_000)),
                ("proto", encode_msgpack_str("v41")),
            ];
            encode_mixed_map(&entries)
        };

        conn.execute(
            "INSERT INTO onlineroundparamstail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![500i64, &data[..]],
        )
        .unwrap();

        let hash = calculate_online_round_params_hash(&conn).unwrap();

        // Manually compute expected
        let record = encode_online_round_params_record(500, &data);

        let mut row_hasher = Sha512_256::new();
        row_hasher.update(b"ORP");
        row_hasher.update(&record);
        let row_hash: [u8; 32] = row_hasher.finalize().into();

        let mut agg_hasher = Sha512_256::new();
        agg_hasher.update(row_hash);
        let expected: [u8; 32] = agg_hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn online_round_params_hash_multiple_rows_ordered() {
        let conn = create_test_db();

        let data1 = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("online", encode_msgpack_uint(500_000)),
                ("proto", encode_msgpack_str("v40")),
            ];
            encode_mixed_map(&entries)
        };
        let data2 = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("online", encode_msgpack_uint(600_000)),
                ("proto", encode_msgpack_str("v41")),
            ];
            encode_mixed_map(&entries)
        };

        conn.execute(
            "INSERT INTO onlineroundparamstail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![100i64, &data1[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO onlineroundparamstail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![200i64, &data2[..]],
        )
        .unwrap();

        let hash = calculate_online_round_params_hash(&conn).unwrap();

        let rec1 = encode_online_round_params_record(100, &data1);
        let rec2 = encode_online_round_params_record(200, &data2);

        let hash1 = Sha512_256::digest([b"ORP".as_slice(), &rec1].concat());
        let hash2 = Sha512_256::digest([b"ORP".as_slice(), &rec2].concat());

        let mut agg = Sha512_256::new();
        agg.update(hash1);
        agg.update(hash2);
        let expected: [u8; 32] = agg.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn encode_online_account_record_omits_zeros() {
        // All-zero fields should produce empty map
        let encoded = encode_online_account_record(&[], 0, 0, 0, &[]);
        assert_eq!(encoded, vec![0x80]); // empty fixmap
    }

    #[test]
    fn encode_online_account_record_omits_zero_address() {
        // A 32-byte all-zero address should be omitted (Go's Digest.MsgIsZero())
        let zero_addr = [0u8; 32];
        let encoded = encode_online_account_record(&zero_addr, 10, 100, 50, &[0x80]);

        let val: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = &val {
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str().unwrap()).collect();
            // addr should be omitted for all-zero address
            assert!(!keys.contains(&"addr"), "zero address should be omitted");
            assert_eq!(keys, vec!["data", "nob", "upd", "vlv"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn encode_online_account_record_key_order() {
        // Verify keys are in sorted order: addr < data < nob < upd < vlv
        let encoded = encode_online_account_record(
            &[0x01; 32],
            10,
            100,
            50,
            &[0x80], // minimal msgpack map
        );

        // Decode and verify key order
        let val: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = &val {
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str().unwrap()).collect();
            assert_eq!(keys, vec!["addr", "data", "nob", "upd", "vlv"]);
        } else {
            panic!("expected map, got {val:?}");
        }
    }

    #[test]
    fn encode_online_round_params_record_key_order() {
        let encoded = encode_online_round_params_record(100, &[0x80]);

        let val: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = &val {
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str().unwrap()).collect();
            assert_eq!(keys, vec!["data", "rnd"]);
        } else {
            panic!("expected map, got {val:?}");
        }
    }

    #[test]
    fn encode_sp_verification_context_key_order() {
        let ctx = SpVerificationCtxFull {
            last_attested_round: 256,
            voters_commitment: serde_bytes::ByteBuf::from(vec![0xAA; 32]),
            online_total_weight: 1_000_000,
            version: "v41".to_string(),
        };
        let encoded = encode_sp_verification_context(&ctx);

        let val: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = &val {
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str().unwrap()).collect();
            // pw < spround < v < vc
            assert_eq!(keys, vec!["pw", "spround", "v", "vc"]);
        } else {
            panic!("expected map, got {val:?}");
        }
    }

    #[test]
    fn encode_sp_verification_wrapper_empty() {
        let encoded = encode_sp_verification_wrapper(&[]);
        // Empty data -> omitted "spd" field -> empty map
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn encode_sp_verification_wrapper_with_data() {
        let ctx = SpVerificationCtxFull {
            last_attested_round: 100,
            voters_commitment: serde_bytes::ByteBuf::from(vec![0xBB; 16]),
            online_total_weight: 500,
            version: String::new(), // empty -> omitted
        };
        let encoded = encode_sp_verification_wrapper(&[ctx]);

        let val: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = &val {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0.as_str().unwrap(), "spd");
            // spd is an array with one element
            if let rmpv::Value::Array(arr) = &pairs[0].1 {
                assert_eq!(arr.len(), 1);
            } else {
                panic!("expected array for spd");
            }
        } else {
            panic!("expected map, got {val:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Lookback block download tests
    // -----------------------------------------------------------------------

    #[test]
    fn download_lookback_blocks_basic() {
        let mut stored: Vec<(u64, String, Vec<u8>, Vec<u8>)> = Vec::new();

        let count = download_lookback_blocks(
            5, // round
            |rnd| Ok((format!("v{rnd}"), vec![rnd as u8], vec![rnd as u8; 2])),
            |rnd, proto, hdr, blk| {
                stored.push((rnd, proto.to_string(), hdr.to_vec(), blk.to_vec()));
                Ok(())
            },
        )
        .unwrap();

        // Rounds 0..=5 inclusive = 6 blocks (since round < MAX_TXN_LIFE)
        assert_eq!(count, 6);
        assert_eq!(stored.len(), 6);

        // Should be stored in descending order (round down to 0)
        assert_eq!(stored[0].0, 5);
        assert_eq!(stored[5].0, 0);
    }

    #[test]
    fn download_lookback_blocks_large_round() {
        let mut stored_rounds: Vec<u64> = Vec::new();

        let count = download_lookback_blocks(
            2000, // round
            |_rnd| Ok(("v41".to_string(), vec![0], vec![0])),
            |rnd, _proto, _hdr, _blk| {
                stored_rounds.push(rnd);
                Ok(())
            },
        )
        .unwrap();

        // From 2000 down to 1000 inclusive = 1001 blocks
        assert_eq!(count, 1001);
        assert_eq!(*stored_rounds.first().unwrap(), 2000);
        assert_eq!(*stored_rounds.last().unwrap(), 1000);
    }

    #[test]
    fn download_lookback_blocks_round_zero() {
        let mut count_stored = 0u64;

        let count = download_lookback_blocks(
            0,
            |_rnd| Ok(("v41".to_string(), vec![], vec![])),
            |_rnd, _proto, _hdr, _blk| {
                count_stored += 1;
                Ok(())
            },
        )
        .unwrap();

        // Only round 0 itself
        assert_eq!(count, 1);
        assert_eq!(count_stored, 1);
    }

    #[test]
    fn download_lookback_blocks_fetch_error() {
        let result = download_lookback_blocks(
            10,
            |rnd| {
                if rnd == 7 {
                    Err(CatchpointError::VerificationError("network error".into()))
                } else {
                    Ok(("v41".to_string(), vec![], vec![]))
                }
            },
            |_rnd, _proto, _hdr, _blk| Ok(()),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            CatchpointError::VerificationError(msg) => {
                assert!(msg.contains("round 7"), "msg: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn download_lookback_blocks_store_error() {
        let result = download_lookback_blocks(
            10,
            |_rnd| Ok(("v41".to_string(), vec![], vec![])),
            |rnd, _proto, _hdr, _blk| {
                if rnd == 8 {
                    Err(CatchpointError::VerificationError("disk full".into()))
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Lease table reconstruction tests
    // -----------------------------------------------------------------------

    /// Create a test DB with the txtail table.
    fn create_txtail_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE txtail (
                rnd INTEGER PRIMARY KEY NOT NULL,
                data BLOB NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    /// Build a minimal BlockHeader for testing purposes.
    fn minimal_block_header() -> algo_types::BlockHeader {
        algo_types::BlockHeader {
            round: algo_types::Round(0),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 0,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: algo_types::Address([0u8; 32]),
            fee_sink: algo_types::Address([0u8; 32]),
            rewards_pool: algo_types::Address([0u8; 32]),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: algo_types::Round(0),
            current_protocol: String::new(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: algo_types::Round(0),
            next_protocol_vote_before: algo_types::Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            load: 0,
            congestion_tax: 0,
        }
    }

    /// Build a TxTailRound with given leases and serialize it to msgpack.
    fn make_txtail_data(
        last_valids: &[u64],
        leases: &[(algo_types::Address, [u8; 32], u64)], // (sender, lease, txn_idx)
    ) -> Vec<u8> {
        use serde_bytes::ByteBuf;

        let txn_ids: Vec<ByteBuf> = last_valids
            .iter()
            .enumerate()
            .map(|(i, _)| ByteBuf::from(vec![i as u8; 32]))
            .collect();

        let lease_entries: Vec<algo_types::TxTailRoundLease> = leases
            .iter()
            .map(|(sender, lease, idx)| algo_types::TxTailRoundLease {
                sender: *sender,
                lease: ByteBuf::from(lease.to_vec()),
                txn_idx: *idx,
            })
            .collect();

        let txtail = algo_types::TxTailRound {
            txn_ids,
            last_valid: last_valids.to_vec(),
            leases: lease_entries,
            hdr: minimal_block_header(),
        };

        rmp_serde::to_vec_named(&txtail).unwrap()
    }

    #[test]
    fn reconstruct_lease_table_empty_db() {
        let conn = create_txtail_test_db();
        let table = reconstruct_lease_table(&conn, 1000).unwrap();

        // No entries, should allow any lease check
        let sender = algo_types::Address([1u8; 32]);
        let lease = [0xAAu8; 32];
        assert!(table.check(&sender, &lease, 1000).is_ok());
    }

    #[test]
    fn reconstruct_lease_table_active_lease() {
        let conn = create_txtail_test_db();

        let sender = algo_types::Address([1u8; 32]);
        let lease = [0xBBu8; 32];
        let current_round = 1000u64;

        // Insert a txtail entry at round 990 with a lease whose last_valid = 1050
        // (still active at round 1000).
        let data = make_txtail_data(
            &[1050], // last_valid for txn 0
            &[(sender, lease, 0)],
        );
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![990i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // The lease should be active — check at current_round should fail (duplicate)
        assert!(table.check(&sender, &lease, current_round).is_err());
    }

    #[test]
    fn reconstruct_lease_table_expired_lease() {
        let conn = create_txtail_test_db();

        let sender = algo_types::Address([2u8; 32]);
        let lease = [0xCCu8; 32];
        let current_round = 1000u64;

        // Insert a txtail entry with a lease whose last_valid = 999
        // (expired before current_round).
        let data = make_txtail_data(
            &[999], // last_valid for txn 0
            &[(sender, lease, 0)],
        );
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![990i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // The lease expired before current_round, so it should NOT be in the table
        assert!(table.check(&sender, &lease, current_round).is_ok());
    }

    #[test]
    fn reconstruct_lease_table_skips_empty_lease() {
        let conn = create_txtail_test_db();

        let sender = algo_types::Address([3u8; 32]);
        let empty_lease = [0u8; 32]; // all zeros = "no lease"
        let current_round = 1000u64;

        let data = make_txtail_data(&[1050], &[(sender, empty_lease, 0)]);
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![990i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // Empty lease should always pass (not recorded)
        assert!(table.check(&sender, &empty_lease, current_round).is_ok());
    }

    #[test]
    fn reconstruct_lease_table_multiple_rounds() {
        let conn = create_txtail_test_db();

        let sender_a = algo_types::Address([4u8; 32]);
        let sender_b = algo_types::Address([5u8; 32]);
        let lease_a = [0xAAu8; 32];
        let lease_b = [0xBBu8; 32];
        let current_round = 1000u64;

        // Round 980: lease_a active (last_valid = 1100)
        let data1 = make_txtail_data(&[1100], &[(sender_a, lease_a, 0)]);
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![980i64, &data1[..]],
        )
        .unwrap();

        // Round 990: lease_b expired (last_valid = 995)
        let data2 = make_txtail_data(&[995], &[(sender_b, lease_b, 0)]);
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![990i64, &data2[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // lease_a is active
        assert!(table.check(&sender_a, &lease_a, current_round).is_err());
        // lease_b is expired
        assert!(table.check(&sender_b, &lease_b, current_round).is_ok());
    }

    #[test]
    fn reconstruct_lease_table_outside_lookback_window() {
        let conn = create_txtail_test_db();

        let sender = algo_types::Address([6u8; 32]);
        let lease = [0xDDu8; 32];
        let current_round = 2000u64;

        // Insert a txtail entry at round 500, which is outside the lookback
        // window [1000, 2000] for current_round=2000.
        let data = make_txtail_data(
            &[2500], // would be active if within window
            &[(sender, lease, 0)],
        );
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![500i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // Should not be in the table since the round is outside the lookback window
        assert!(table.check(&sender, &lease, current_round).is_ok());
    }

    #[test]
    fn reconstruct_lease_table_boundary_last_valid_equals_current() {
        let conn = create_txtail_test_db();

        let sender = algo_types::Address([7u8; 32]);
        let lease = [0xEEu8; 32];
        let current_round = 1000u64;

        // Lease with last_valid == current_round (boundary case: still active)
        let data = make_txtail_data(&[1000], &[(sender, lease, 0)]);
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![990i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // last_valid == current_round means still active
        assert!(table.check(&sender, &lease, current_round).is_err());
    }

    #[test]
    fn reconstruct_lease_table_multiple_leases_same_round() {
        let conn = create_txtail_test_db();

        let sender_a = algo_types::Address([8u8; 32]);
        let sender_b = algo_types::Address([9u8; 32]);
        let lease_a = [0x11u8; 32];
        let lease_b = [0x22u8; 32];
        let current_round = 500u64;

        // Two transactions in the same round, each with a lease
        let data = make_txtail_data(
            &[600, 700], // txn 0 -> last_valid 600, txn 1 -> last_valid 700
            &[
                (sender_a, lease_a, 0), // references txn 0
                (sender_b, lease_b, 1), // references txn 1
            ],
        );
        conn.execute(
            "INSERT INTO txtail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![490i64, &data[..]],
        )
        .unwrap();

        let table = reconstruct_lease_table(&conn, current_round).unwrap();

        // Both leases should be active
        assert!(table.check(&sender_a, &lease_a, current_round).is_err());
        assert!(table.check(&sender_b, &lease_b, current_round).is_err());
    }
}
