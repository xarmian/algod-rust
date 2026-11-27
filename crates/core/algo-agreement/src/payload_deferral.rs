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

//! Deferred proposal-payload decoding, a port of go-algorand's
//! `agreement/payloadDeferral.go` (v5.1.1-stable, commit 11f6cc2ea) and the
//! prefix-only `decodeProposal` of `agreement/message.go`.
//!
//! Agreement reads only the start of a proposal payload (a `PP` message) when
//! it arrives, up to the payset. It hashes and decodes the payload once the
//! proposalStore is waiting for a payload with that encoding
//! ([`crate::player::Player`]'s `decode_payload_if_wanted`).
//!
//! Every function here is checked against go's own on a corpus of valid,
//! truncated, reordered and hostile payloads
//! (`tests/fixtures/payload_deferral/cases.jsonl`, produced by
//! `tools/payload-deferral-oracle`), so the byte-level behaviour (which input
//! is accepted, what offsets and digest it yields) is go's, not a
//! reconstruction. Issue #2552.

use std::sync::Arc;

use algo_types::{Address, Digest, Round};
use sha2::{Digest as _, Sha512_256};

use crate::codec;
use crate::events::CompoundMessage;
use crate::proposal::UnauthenticatedProposal;
use crate::step::Period;
use crate::vote::UnauthenticatedVote;

/// go's `payloadPrefixLimit`: how much of a payload is read before agreement
/// decides whether it wants it. Every field that decision needs comes before
/// the payset in a canonical encoding, and together they take a few
/// kilobytes.
pub const PAYLOAD_PREFIX_LIMIT: usize = 64 * 1024;

/// go's `protocol.DefaultUnmarshalState.AllowableDepth` (`maxMsgpDecodeDepth`).
const MAX_DEPTH: u64 = 255;

/// Why a payload was not read or decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadError(pub String);

impl PayloadError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }

    /// go's `msgp.ErrShortBytes`.
    fn short() -> Self {
        Self::new("msgp: too few bytes left to read object")
    }
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PayloadError {}

type Result<T> = std::result::Result<T, PayloadError>;

/// The fields of a `transmittedPayload` that decide whether agreement wants
/// it (go's `payloadPrefix`).
#[derive(Debug, Clone, Default)]
pub struct PayloadPrefix {
    pub round: Round,
    pub original_period: Period,
    pub original_proposer: Address,
    pub prior_vote: UnauthenticatedVote,
    /// The number of entries the payload's map header declares.
    pub num_entries: u32,
    /// The offset of the first entry.
    pub entries_start_idx: usize,
    /// The offsets of the "pv" entry, key and value. Both are zero if the
    /// prefix has none.
    pub vote_start_idx: usize,
    pub vote_end_idx: usize,
}

// ---------------------------------------------------------------------------
// msgp primitives (algorand/msgp v1.1.66)
// ---------------------------------------------------------------------------

/// `msgp.ReadMapHeaderBytes`: the entry count and the rest.
fn read_map_header(b: &[u8]) -> Result<(u32, &[u8])> {
    let Some(&lead) = b.first() else {
        return Err(PayloadError::short());
    };
    match lead {
        0x80..=0x8f => Ok(((lead & 0x0f) as u32, &b[1..])),
        // go-codec compatibility: nil decodes as an empty map
        0xc0 => Ok((0, &b[1..])),
        0xde => {
            if b.len() < 3 {
                return Err(PayloadError::short());
            }
            Ok((u16::from_be_bytes([b[1], b[2]]) as u32, &b[3..]))
        }
        0xdf => {
            if b.len() < 5 {
                return Err(PayloadError::short());
            }
            Ok((u32::from_be_bytes([b[1], b[2], b[3], b[4]]), &b[5..]))
        }
        _ => Err(PayloadError::new(
            "msgp: attempted to decode type that is not a map with method for \"map\"",
        )),
    }
}

/// The element count of an array header, for `msgp.ReadArrayHeaderBytes`
/// (`flattenMap` false: a map is no array).
fn read_array_header(b: &[u8]) -> Result<(u64, &[u8])> {
    let Some(&lead) = b.first() else {
        return Err(PayloadError::short());
    };
    match lead {
        0x90..=0x9f => Ok(((lead & 0x0f) as u64, &b[1..])),
        0xc0 => Ok((0, &b[1..])),
        0xdc => {
            if b.len() < 3 {
                return Err(PayloadError::short());
            }
            Ok((u16::from_be_bytes([b[1], b[2]]) as u64, &b[3..]))
        }
        0xdd => {
            if b.len() < 5 {
                return Err(PayloadError::short());
            }
            Ok((u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as u64, &b[5..]))
        }
        _ => Err(PayloadError::new(
            "msgp: attempted to decode type that is not an array",
        )),
    }
}

/// A length-prefixed run of `str`/`bin` bytes after the header at `b[0]`,
/// for the str and bin markers; `None` when `lead` is neither.
fn read_sized_bytes(b: &[u8]) -> Option<Result<(&[u8], &[u8])>> {
    let lead = *b.first()?;
    let (hdr, len) = match lead {
        0xa0..=0xbf => (1usize, (lead & 0x1f) as usize),
        0xd9 | 0xc4 => {
            if b.len() < 2 {
                return Some(Err(PayloadError::short()));
            }
            (2, b[1] as usize)
        }
        0xda | 0xc5 => {
            if b.len() < 3 {
                return Some(Err(PayloadError::short()));
            }
            (3, u16::from_be_bytes([b[1], b[2]]) as usize)
        }
        0xdb | 0xc6 => {
            if b.len() < 5 {
                return Some(Err(PayloadError::short()));
            }
            (5, u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize)
        }
        _ => return None,
    };
    let rest = &b[hdr..];
    if rest.len() < len {
        return Some(Err(PayloadError::short()));
    }
    Some(Ok((&rest[..len], &rest[len..])))
}

/// `msgp.ReadUint8Bytes`-style element of a byte array used as a map key
/// (go-codec compatibility, `readBytesBytesSlow`).
fn read_key_byte(b: &[u8]) -> Result<(u8, &[u8])> {
    let mut rd = b;
    let v = algo_types::go_msgp::read_u64(&mut rd)
        .map_err(|e| PayloadError::new(format!("msgp: key byte: {e}")))?;
    if v > u8::MAX as u64 {
        return Err(PayloadError::new("msgp: value too large for uint8"));
    }
    Ok((v as u8, rd))
}

/// `msgp.ReadMapKeyZC`: a map key as bytes. go reads a `str`, a `bin`, nil
/// (the empty key) or, for compatibility with its other decoder, an array of
/// bytes.
fn read_map_key(b: &[u8]) -> Result<(std::borrow::Cow<'_, [u8]>, &[u8])> {
    let Some(&lead) = b.first() else {
        return Err(PayloadError::short());
    };
    if lead == 0xc0 {
        return Ok((std::borrow::Cow::Borrowed(&b[..0]), &b[1..]));
    }
    if let Some(r) = read_sized_bytes(b) {
        let (key, rest) = r?;
        return Ok((std::borrow::Cow::Borrowed(key), rest));
    }
    // an array of bytes
    let (count, mut o) = read_array_header(b).map_err(|_| {
        PayloadError::new("msgp: attempted to decode type for a map key that is not str or bin")
    })?;
    if (o.len() as u64) < count {
        return Err(PayloadError::short());
    }
    let mut key = Vec::new();
    for _ in 0..count {
        let (byte, rest) = read_key_byte(o)?;
        key.push(byte);
        o = rest;
    }
    Ok((std::borrow::Cow::Owned(key), o))
}

/// `msgp.Skip` for one object that is not a map or an array: the rest of `b`
/// without it.
fn skip_scalar(b: &[u8]) -> Result<&[u8]> {
    let Some(&lead) = b.first() else {
        return Err(PayloadError::short());
    };
    let l = b.len();
    // (prefix size, extra) for every non-container marker; `extra` is read
    // from the bytes after the marker
    enum Extra {
        None,
        U8,
        U16,
        U32,
    }
    let (size, extra) = match lead {
        0x00..=0x7f | 0xe0..=0xff => (1, Extra::None),
        0xa0..=0xbf => (1 + (lead & 0x1f) as usize, Extra::None),
        0xc0 | 0xc2 | 0xc3 => (1, Extra::None),
        0xc4 | 0xd9 => (2, Extra::U8),
        0xc5 | 0xda => (3, Extra::U16),
        0xc6 | 0xdb => (5, Extra::U32),
        0xc7 => (3, Extra::U8),
        0xc8 => (4, Extra::U16),
        0xc9 => (6, Extra::U32),
        0xca => (5, Extra::None),
        0xcb => (9, Extra::None),
        0xcc | 0xd0 => (2, Extra::None),
        0xcd | 0xd1 => (3, Extra::None),
        0xce | 0xd2 => (5, Extra::None),
        0xcf | 0xd3 => (9, Extra::None),
        0xd4 => (3, Extra::None),
        0xd5 => (4, Extra::None),
        0xd6 => (6, Extra::None),
        0xd7 => (10, Extra::None),
        0xd8 => (18, Extra::None),
        // 0xc1 and the containers, which `skip_with_depth` opens itself
        _ => return Err(PayloadError::new("msgp: unrecognized type prefix")),
    };
    let total = match extra {
        Extra::None => size,
        Extra::U8 => {
            if l < size {
                return Err(PayloadError::short());
            }
            size + b[1] as usize
        }
        Extra::U16 => {
            if l < size {
                return Err(PayloadError::short());
            }
            size + u16::from_be_bytes([b[1], b[2]]) as usize
        }
        Extra::U32 => {
            if l < size {
                return Err(PayloadError::short());
            }
            size + u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize
        }
    };
    if l < total {
        return Err(PayloadError::short());
    }
    Ok(&b[total..])
}

/// go's `skipWithDepth`: `b` without its first msgpack object. It accepts
/// exactly the input `msgp.Skip` accepts, except that it fails if maps and
/// arrays nest more than `max_depth` deep. It keeps the open maps and arrays
/// in a vector instead of recursing.
fn skip_with_depth(mut b: &[u8], max_depth: u64) -> Result<&[u8]> {
    // the number of objects still to skip in each open map or array,
    // innermost last; a map entry counts as two objects
    let mut open: Vec<u64> = Vec::with_capacity(16);
    loop {
        let lead = b.first().copied();
        match lead {
            Some(0x80..=0x8f | 0xde | 0xdf | 0x90..=0x9f | 0xdc | 0xdd) => {
                if open.len() as u64 >= max_depth {
                    return Err(PayloadError::new("Max depth exceeded"));
                }
                let lead = lead.unwrap_or(0);
                let items = if matches!(lead, 0x80..=0x8f | 0xde | 0xdf) {
                    let (n, rest) = read_map_header(b)?;
                    b = rest;
                    2 * n as u64
                } else {
                    let (n, rest) = read_array_header(b)?;
                    b = rest;
                    n
                };
                if items > 0 {
                    open.push(items);
                    continue;
                }
            }
            _ => b = skip_scalar(b)?,
        }
        // A whole object was skipped: count it against the innermost open
        // map or array, and close each one that it completes.
        while let Some(last) = open.last_mut() {
            *last -= 1;
            if *last > 0 {
                break;
            }
            open.pop();
        }
        if open.is_empty() {
            return Ok(b);
        }
    }
}

// ---------------------------------------------------------------------------
// parsePayloadPrefix and friends
// ---------------------------------------------------------------------------

/// go's `parsePayloadPrefix`: reads the fields of [`PayloadPrefix`] from the
/// first [`PAYLOAD_PREFIX_LIMIT`] bytes of `encoded`. It fails with a "too few
/// bytes" error if those bytes end before it is done.
///
/// It stops at the payset or at the first key that sorts after it. A canonical
/// encoding writes its keys in sorted order, and all of these fields sort
/// before the payset, so a field not read by then is zero in a canonical
/// encoding and is left zero here. [`decode_deferred_payload`] refuses a
/// payload whose decoded fields differ from the result.
pub fn parse_payload_prefix(encoded: &[u8]) -> Result<PayloadPrefix> {
    let prefix = &encoded[..encoded.len().min(PAYLOAD_PREFIX_LIMIT)];
    let mut pp = PayloadPrefix::default();
    let _session = algo_types::go_msgp::decode_session();

    let (n, mut b) = read_map_header(prefix)?;
    pp.num_entries = n;
    pp.entries_start_idx = prefix.len() - b.len();
    for _ in 0..n {
        let start = prefix.len() - b.len();
        let (key, rest) = read_map_key(b)?;
        b = rest;
        if key.as_ref() >= b"txns".as_slice() {
            break;
        }
        let field = |e: algo_error::AlgoError| {
            PayloadError::new(format!(
                "payload prefix: field {:?}: {e}",
                String::from_utf8_lossy(&key)
            ))
        };
        match key.as_ref() {
            b"rnd" => pp.round = Round(algo_types::go_msgp::read_u64(&mut b).map_err(field)?),
            b"oper" => {
                pp.original_period = Period(algo_types::go_msgp::read_u64(&mut b).map_err(field)?)
            }
            b"oprop" => algo_types::go_msgp::read_fixed_bytes_into_go_compat(
                &mut b,
                &mut pp.original_proposer.0,
            )
            .map_err(field)?,
            b"pv" => {
                if pp.vote_end_idx != 0 {
                    return Err(PayloadError::new("payload: repeated prior vote"));
                }
                codec::decode_vote_into(&mut b, &mut pp.prior_vote)
                    .map_err(|e| PayloadError::new(format!("payload prefix: field \"pv\": {e}")))?;
                pp.vote_start_idx = start;
                pp.vote_end_idx = prefix.len() - b.len();
            }
            _ => {
                b = skip_with_depth(b, MAX_DEPTH - 1).map_err(|e| {
                    PayloadError::new(format!(
                        "payload prefix: field {:?}: {e}",
                        String::from_utf8_lossy(&key)
                    ))
                })?;
            }
        }
    }
    Ok(pp)
}

/// `msgp.AppendMapHeader`.
fn append_map_header(out: &mut Vec<u8>, n: u32) {
    if n <= 15 {
        out.push(0x80 | n as u8);
    } else if n <= u16::MAX as u32 {
        out.push(0xde);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdf);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// go's `writeProposalEncoding`: the encoding of the `unauthenticatedProposal`
/// in `encoded`, a PP message, without decoding it.
///
/// An encoded transmittedPayload holds the proposal's fields and the prior
/// vote ("pv") in one map. The proposal's encoding is the same bytes without
/// the "pv" entry, with the map header counting one entry fewer.
///
/// The output is what the canonical encoding of the decoded proposal is when
/// `encoded` is itself canonical, as nodes send it. Otherwise it generally
/// differs.
fn write_proposal_encoding(encoded: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let pp = parse_payload_prefix(encoded)?;
    if pp.vote_end_idx == 0 {
        out.extend_from_slice(encoded);
        return Ok(());
    }
    append_map_header(out, pp.num_entries - 1);
    out.extend_from_slice(&encoded[pp.entries_start_idx..pp.vote_start_idx]);
    out.extend_from_slice(&encoded[pp.vote_end_idx..]);
    Ok(())
}

/// The bytes go's `writeProposalEncoding` produces (see there).
pub fn proposal_encoding(encoded: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(encoded.len());
    write_proposal_encoding(encoded, &mut out)?;
    Ok(out)
}

/// go's `payloadEncodingDigest`: `proposalValue.EncodingDigest` computed from
/// a PP message without decoding it: the hash that `crypto.HashObj` gives for
/// the decoded `unauthenticatedProposal`. A payload that is not canonically
/// encoded generally gets another digest, and then matches no proposal-value.
pub fn payload_encoding_digest(encoded: &[u8]) -> Result<Digest> {
    let mut h = Sha512_256::new();
    h.update(b"PL");
    let mut body = Vec::with_capacity(encoded.len());
    write_proposal_encoding(encoded, &mut body)?;
    h.update(&body);
    let mut d = [0u8; 32];
    d.copy_from_slice(&h.finalize());
    Ok(Digest(d))
}

// ---------------------------------------------------------------------------
// decodeProposal / decodeDeferredPayload
// ---------------------------------------------------------------------------

/// go's `decodeProposal`: reads a proposal from a PP message.
///
/// It reads only the fields before the payset, and keeps `data` in the
/// proposal (`deferred_payload`) for `Player::decode_payload_if_wanted` to
/// decode if agreement wants the payload.
pub fn decode_proposal(data: Arc<[u8]>) -> Result<CompoundMessage> {
    let mut pp = parse_payload_prefix(&data)?;
    pp.prior_vote
        .well_formed()
        .map_err(|e| PayloadError::new(e.to_string()))?;
    // No verifier reads PKSigOld, and the vote stays valid without it.
    pp.prior_vote.sig.pk_sig_old = [0u8; 64];

    let mut proposal = UnauthenticatedProposal::default();
    proposal.block.round = pp.round;
    proposal.original_period = pp.original_period;
    proposal.original_proposer = pp.original_proposer;
    proposal.deferred_payload = Some(data);
    Ok(CompoundMessage {
        vote: pp.prior_vote,
        proposal,
    })
}

/// go v5.1.1's `checkTxnGroup` (`data/transactions/checks.go`) for one run of
/// the payset: the state proof payload rule, the rule that keeps a heartbeat
/// out of a resource group (unless the protocol allows it), and the group-ID
/// rules (go's `checkTxnGroupID`: size, consistency, duplicates, commitment).
///
/// It is not `algo_validate::check_txn_group`, which also rejects a missing
/// heartbeat body, an unknown transaction type and a box index go v5.1 no
/// longer screens for here (`WellFormed` does, later): a proposal carrying one
/// is not dropped by go at this stage.
fn check_txn_group(
    group: &[algo_types::SignedTransaction],
    allow_grouped_heartbeats: bool,
) -> std::result::Result<(), algo_error::AlgoError> {
    let (mut heartbeat, mut avail_trigger) = (false, false);
    for stx in group {
        let txn = &stx.txn;
        match txn.txn_type.as_str() {
            "hb" => heartbeat = true,
            "stpf" => algo_validate::checks::check_state_proof_payload(txn)?,
            "appl" => avail_trigger = true,
            "acfg" if txn.config_asset == 0 => avail_trigger = true,
            _ => {}
        }
    }
    if !allow_grouped_heartbeats && heartbeat && avail_trigger {
        return Err(algo_error::AlgoError::Validation {
            message: "heartbeat transaction may not be grouped with an application call or asset creation"
                .into(),
        });
    }
    algo_validate::rules::validate_transaction_group_strict(group)
}

/// go's `proposalCarriesInvalidTxn`: whether the payset of `up` fails the
/// structural screen of a proposal. A group is malformed if it is longer than
/// a group may be, if a nonzero group ID does not commit to its transactions
/// in order, or if it breaks the heartbeat rule of the block's protocol.
pub(crate) fn proposal_carries_invalid_txn(up: &UnauthenticatedProposal) -> Result<()> {
    // Each group's claimed `Group` digest must commit to its transactions
    // (go v4.7.4 `checks: recompute group IDs`, part of `CheckPaysetGroup`).
    // The payset strips genesis ID/hash; the group ID commits to the full
    // transaction, so restore them from the block header first (issue #1686).
    // An unknown protocol is go's `consensus protocol %s not found` failure
    // of `DecodeSignedTxn` (issue #1728).
    if up.block.payset.is_empty() {
        // nothing to decode, so go never looks the protocol up
        return Ok(());
    }
    let restored = match algo_validate::restore_payset_genesis_fields(&up.block) {
        Ok(r) => r,
        Err(e) => {
            // This runs on a peer-controlled string before any
            // authentication, so the drop is counted and its log rate-limited.
            crate::demux::note_unknown_protocol_drop(&e.protocol);
            return Err(PayloadError::new(
                "proposal payload carries a malformed transaction: unknown consensus protocol",
            ));
        }
    };
    // go's `CheckPaysetGroup` runs on every run of consecutive transactions
    // with the same group ID (`Block.PaysetGroups`), a lone transaction with a
    // nonzero group ID included: its ID must commit to the group as it is.
    let allow_grouped_heartbeats =
        algo_types::consensus::allow_grouped_heartbeats_for_protocol(&up.block.current_protocol);
    let mut start = 0;
    while start < restored.len() {
        let group = restored[start].txn.group;
        let mut end = start + 1;
        if group != [0u8; 32] {
            while end < restored.len() && restored[end].txn.group == group {
                end += 1;
            }
        }
        check_txn_group(&restored[start..end], allow_grouped_heartbeats).map_err(|e| {
            PayloadError::new(format!(
                "proposal payload carries a malformed transaction: {e}"
            ))
        })?;
        start = end;
    }
    Ok(())
}

/// go's `decodeDeferredPayload`: decodes the payload `deferred` holds, if its
/// encoding digest is one of `wanted`, and fails otherwise without decoding
/// its payset.
///
/// The digest it matched is of the bytes received, so it is not kept for
/// `UnauthenticatedProposal::value`, which hashes the canonical encoding.
pub fn decode_deferred_payload(
    deferred: &UnauthenticatedProposal,
    wanted: &[Digest],
) -> Result<UnauthenticatedProposal> {
    let data: &[u8] = deferred.deferred_payload.as_deref().unwrap_or(&[]);
    let digest = payload_encoding_digest(data)?;
    if !wanted.contains(&digest) {
        return Err(PayloadError::new(
            "proposalStore: payload encoding matches no proposal-value waiting for a payload",
        ));
    }

    let mut up = codec::decode_compound_message(data)
        .map_err(|e| PayloadError::new(e.to_string()))?
        .proposal;
    // The decoded fields must be the ones agreement read from the prefix.
    if up.round() != deferred.round()
        || up.original_period != deferred.original_period
        || up.original_proposer != deferred.original_proposer
    {
        return Err(PayloadError::new("payload fields differ from its prefix"));
    }
    proposal_carries_invalid_txn(&up)?;
    up.received_at = deferred.received_at;
    Ok(up)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashable::hash_obj;

    /// One row of `cases.jsonl`, as go's real functions answered it.
    struct GoRow(serde_json::Value);

    impl GoRow {
        fn s(&self, path: &[&str]) -> String {
            let mut v = &self.0;
            for p in path {
                v = &v[*p];
            }
            v.as_str().unwrap_or_default().to_string()
        }
        fn ok(&self, path: &[&str]) -> bool {
            let mut v = &self.0;
            for p in path {
                v = &v[*p];
            }
            v["ok"].as_bool().unwrap()
        }
        fn u(&self, path: &[&str]) -> u64 {
            let mut v = &self.0;
            for p in path {
                v = &v[*p];
            }
            v.as_u64().unwrap()
        }
    }

    fn rows() -> Vec<GoRow> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/payload_deferral/cases.jsonl");
        let text = std::fs::read_to_string(path).expect("fixture");
        text.lines()
            .map(|l| GoRow(serde_json::from_str(l).expect("row")))
            .collect()
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha512_256::digest(b))
    }

    fn vote_hash(v: &UnauthenticatedVote) -> String {
        sha(&codec::encode_vote(v))
    }

    #[test]
    fn corpus_is_go_answer_for_answer() {
        let rows = rows();
        assert!(rows.len() > 1000, "fixture truncated: {} rows", rows.len());
        let mut checked_ok = 0;
        for row in &rows {
            let name = row.s(&["name"]);
            let data: Vec<u8> = hex::decode(row.s(&["hex"])).unwrap();

            // parsePayloadPrefix
            let parsed = parse_payload_prefix(&data);
            assert_eq!(
                parsed.is_ok(),
                row.ok(&["parse"]),
                "{name}: parse ok ({parsed:?})"
            );
            if let Ok(pp) = &parsed {
                assert_eq!(pp.round.0, row.u(&["parse", "round"]), "{name}: round");
                assert_eq!(
                    pp.original_period.0,
                    row.u(&["parse", "oper"]),
                    "{name}: oper"
                );
                assert_eq!(
                    hex::encode(pp.original_proposer.0),
                    row.s(&["parse", "oprop"]),
                    "{name}: oprop"
                );
                assert_eq!(
                    pp.num_entries as u64,
                    row.u(&["parse", "num_entries"]),
                    "{name}: n"
                );
                assert_eq!(
                    pp.entries_start_idx as u64,
                    row.u(&["parse", "entries_start"]),
                    "{name}: start"
                );
                assert_eq!(
                    pp.vote_start_idx as u64,
                    row.u(&["parse", "vote_start"]),
                    "{name}: vote start"
                );
                assert_eq!(
                    pp.vote_end_idx as u64,
                    row.u(&["parse", "vote_end"]),
                    "{name}: vote end"
                );
                assert_eq!(
                    vote_hash(&pp.prior_vote),
                    row.s(&["parse", "vote"]),
                    "{name}: prior vote"
                );
            }

            // writeProposalEncoding
            let enc = proposal_encoding(&data);
            assert_eq!(enc.is_ok(), row.ok(&["enc"]), "{name}: enc ok");
            if let Ok(enc) = &enc {
                assert_eq!(sha(enc), row.s(&["enc", "hash"]), "{name}: enc hash");
            }

            // payloadEncodingDigest
            let digest = payload_encoding_digest(&data);
            assert_eq!(digest.is_ok(), row.ok(&["digest"]), "{name}: digest ok");
            if let Ok(d) = &digest {
                assert_eq!(
                    hex::encode(d.0),
                    row.s(&["digest", "hash"]),
                    "{name}: digest"
                );
            }

            // decodeProposal
            let proposal = decode_proposal(Arc::from(data.as_slice()));
            assert_eq!(
                proposal.is_ok(),
                row.ok(&["proposal"]),
                "{name}: decodeProposal ok ({proposal:?})"
            );
            let Ok(cm) = proposal else { continue };
            assert_eq!(
                cm.proposal.round().0,
                row.u(&["proposal", "round"]),
                "{name}"
            );
            assert_eq!(
                cm.proposal.original_period.0,
                row.u(&["proposal", "oper"]),
                "{name}"
            );
            assert_eq!(
                hex::encode(cm.proposal.original_proposer.0),
                row.s(&["proposal", "oprop"]),
                "{name}"
            );
            assert_eq!(
                vote_hash(&cm.vote),
                row.s(&["proposal", "vote"]),
                "{name}: vote after clearPKSigOld"
            );

            // decodeDeferredPayload, with each wanted set go was asked
            let mut other = Digest([0u8; 32]);
            other.0[0] = 0xee;
            let mut wanted: Vec<(&str, Vec<Digest>)> =
                vec![("none", vec![]), ("other", vec![other])];
            if let Ok(d) = &digest {
                wanted.push(("own", vec![*d]));
                wanted.push(("own_and_other", vec![other, *d]));
            }
            for (label, w) in wanted {
                let got = decode_deferred_payload(&cm.proposal, &w);
                assert_eq!(
                    got.is_ok(),
                    row.ok(&["deferred", label]),
                    "{name}: decodeDeferredPayload({label}) ok ({got:?})"
                );
                if let Ok(up) = got {
                    checked_ok += 1;
                    assert_eq!(
                        hex::encode(up.block_digest().0),
                        row.s(&["deferred", label, "block_digest"]),
                        "{name}: block digest"
                    );
                    assert_eq!(
                        hex::encode(hash_obj(&up).0),
                        row.s(&["deferred", label, "enc_digest"]),
                        "{name}: encoding digest"
                    );
                }
            }
        }
        assert!(
            checked_ok > 100,
            "only {checked_ok} successful deferred decodes were compared"
        );
    }

    /// A proposal this node encodes is one go's payloadEncodingDigest
    /// recognises: if this failed, go v5.1.1 peers would refuse every
    /// proposal this node sends.
    #[test]
    fn encoding_digest_of_own_encoding_is_the_proposal_value_digest() {
        for with_vote in [true, false] {
            let mut up = UnauthenticatedProposal::default();
            up.block.round = Round(7);
            up.original_period = Period(2);
            up.original_proposer = Address([2u8; 32]);
            let mut vote = UnauthenticatedVote::default();
            if with_vote {
                vote.raw_vote.round = Round(7);
                vote.raw_vote.sender = Address([3u8; 32]);
                vote.sig.pk = [8u8; 32];
            }
            let wire = codec::encode_compound_message(&CompoundMessage {
                vote,
                proposal: up.clone(),
            });
            let digest = payload_encoding_digest(&wire).unwrap();
            assert_eq!(digest, up.value().encoding_digest, "with_vote={with_vote}");
        }
    }
}
