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

// Agreement message wire codec for encoding/decoding agreement messages
// in Go-compatible msgpack format.
//
// Wire types and their Go codec tags:
//
// unauthenticatedVote (omitempty):
//   "r"    -> rawVote (sub-map)
//   "cred" -> UnauthenticatedCredential (sub-map)
//   "sig"  -> OneTimeSignature (sub-map, omitemptycheckstruct)
//
// rawVote (omitempty):
//   "per"  -> Period (uint64)
//   "prop" -> proposalValue (sub-map)
//   "rnd"  -> Round (uint64)
//   "snd"  -> Sender (bin32)
//   "step" -> Step (uint64)
//
// proposalValue (omitempty):
//   "dig"    -> BlockDigest (bin32)
//   "encdig" -> EncodingDigest (bin32)
//   "oper"   -> OriginalPeriod (uint64)
//   "oprop"  -> OriginalProposer (bin32)
//
// UnauthenticatedCredential (omitempty):
//   "pf" -> Proof (bin, 80 bytes)
//
// OneTimeSignature (NOT omitempty — all fields always present):
//   "p"   -> PK (bin32)
//   "p1s" -> PK1Sig (bin64)
//   "p2"  -> PK2 (bin32)
//   "p2s" -> PK2Sig (bin64)
//   "ps"  -> PKSigOld (bin64)
//   "s"   -> Sig (bin64)
//
// unauthenticatedBundle (omitempty):
//   "eqv"  -> EquivocationVotes (array)
//   "per"  -> Period (uint64)
//   "prop" -> Proposal (sub-map)
//   "rnd"  -> Round (uint64)
//   "step" -> Step (uint64)
//   "vote" -> Votes (array)
//
// voteAuthenticator (NOT omitempty):
//   "cred" -> Cred (sub-map)
//   "sig"  -> Sig (sub-map, omitemptycheckstruct)
//   "snd"  -> Sender (bin32)
//
// equivocationVoteAuthenticator (NOT omitempty):
//   "cred"  -> Cred (sub-map)
//   "props" -> Proposals ([2]proposalValue, array)
//   "sig"   -> Sigs ([2]OneTimeSignature, array, omitemptycheckstruct)
//   "snd"   -> Sender (bin32)

use std::io::Cursor;

use algo_codec::canonical_encode_unauthenticated_proposal;
use algo_consensus_crypto::OneTimeSignature;
use algo_types::{go_msgp, Address, Block, Round};

use crate::bundle::{EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator};
use crate::credential::UnauthenticatedCredential;
use crate::events::CompoundMessage;
use crate::proposal::UnauthenticatedProposal;
use crate::step::{Period, Step};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, BOTTOM};
use crate::VRF_PROOF_SIZE;

/// Errors that can occur during agreement message decoding.
#[derive(Debug)]
pub enum CodecError {
    /// Msgpack decoding error.
    Decode(String),
    /// Unexpected data format.
    Format(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
            Self::Format(msg) => write!(f, "format error: {msg}"),
        }
    }
}

impl std::error::Error for CodecError {}

// ── Encoding helpers ─────────────────────────────────────────────────────

/// Write a msgpack fixstr key.
fn write_str_key(buf: &mut Vec<u8>, key: &str) {
    rmp::encode::write_str(buf, key).unwrap();
}

/// Encode a ProposalValue in canonical msgpack format (omitempty, sorted by tag).
/// Fields: "dig", "encdig", "oper", "oprop"
fn encode_proposal_value(pv: &ProposalValue) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    let dig_empty = pv.block_digest.0 == [0u8; 32];
    let encdig_empty = pv.encoding_digest.0 == [0u8; 32];
    let oper_empty = pv.original_period.0 == 0;
    let oprop_empty = pv.original_proposer.0 == [0u8; 32];

    let mut count: u8 = 0;
    if !dig_empty {
        count += 1;
    }
    if !encdig_empty {
        count += 1;
    }
    if !oper_empty {
        count += 1;
    }
    if !oprop_empty {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    if !dig_empty {
        write_str_key(&mut buf, "dig");
        rmp::encode::write_bin(&mut buf, &pv.block_digest.0).unwrap();
    }
    if !encdig_empty {
        write_str_key(&mut buf, "encdig");
        rmp::encode::write_bin(&mut buf, &pv.encoding_digest.0).unwrap();
    }
    if !oper_empty {
        write_str_key(&mut buf, "oper");
        rmp::encode::write_uint(&mut buf, pv.original_period.0).unwrap();
    }
    if !oprop_empty {
        write_str_key(&mut buf, "oprop");
        rmp::encode::write_bin(&mut buf, &pv.original_proposer.0).unwrap();
    }

    buf
}

/// Encode a RawVote in canonical msgpack format (omitempty, sorted by tag).
/// Fields: "per", "prop", "rnd", "snd", "step"
fn encode_raw_vote(rv: &RawVote) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    let per_empty = rv.period.0 == 0;
    let prop_empty = rv.proposal.is_bottom();
    let rnd_empty = rv.round.0 == 0;
    let snd_empty = rv.sender.0 == [0u8; 32];
    let step_empty = rv.step.0 == 0;

    let mut count: u8 = 0;
    if !per_empty {
        count += 1;
    }
    if !prop_empty {
        count += 1;
    }
    if !rnd_empty {
        count += 1;
    }
    if !snd_empty {
        count += 1;
    }
    if !step_empty {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    if !per_empty {
        write_str_key(&mut buf, "per");
        rmp::encode::write_uint(&mut buf, rv.period.0).unwrap();
    }
    if !prop_empty {
        write_str_key(&mut buf, "prop");
        buf.extend_from_slice(&encode_proposal_value(&rv.proposal));
    }
    if !rnd_empty {
        write_str_key(&mut buf, "rnd");
        rmp::encode::write_uint(&mut buf, rv.round.0).unwrap();
    }
    if !snd_empty {
        write_str_key(&mut buf, "snd");
        rmp::encode::write_bin(&mut buf, &rv.sender.0).unwrap();
    }
    if !step_empty {
        write_str_key(&mut buf, "step");
        rmp::encode::write_uint(&mut buf, rv.step.0).unwrap();
    }

    buf
}

/// Encode an UnauthenticatedCredential in canonical msgpack format (omitempty).
/// Fields: "pf"
fn encode_unauthenticated_credential(cred: &UnauthenticatedCredential) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);

    let pf_empty = cred.proof == [0u8; VRF_PROOF_SIZE];

    if pf_empty {
        buf.push(0x80); // fixmap(0)
    } else {
        buf.push(0x81); // fixmap(1)
        write_str_key(&mut buf, "pf");
        rmp::encode::write_bin(&mut buf, &cred.proof).unwrap();
    }

    buf
}

/// Check if a OneTimeSignature is all-zero.
fn ots_is_zero(sig: &OneTimeSignature) -> bool {
    sig.sig == [0u8; 64]
        && sig.pk == [0u8; 32]
        && sig.pk_sig_old == [0u8; 64]
        && sig.pk2 == [0u8; 32]
        && sig.pk1_sig == [0u8; 64]
        && sig.pk2_sig == [0u8; 64]
}

/// Encode a OneTimeSignature in canonical msgpack format.
///
/// IMPORTANT: Go's OneTimeSignature uses `codec:""` (NOT omitempty),
/// so ALL 6 fields are always serialized even when zero.
/// Fields sorted by codec tag: "p", "p1s", "p2", "p2s", "ps", "s"
fn encode_one_time_signature(sig: &OneTimeSignature) -> Vec<u8> {
    let mut buf = Vec::with_capacity(384);

    // Always 6 fields (non-omitempty struct)
    buf.push(0x86); // fixmap(6)

    // "p" -> PK (32 bytes)
    write_str_key(&mut buf, "p");
    rmp::encode::write_bin(&mut buf, &sig.pk).unwrap();

    // "p1s" -> PK1Sig (64 bytes)
    write_str_key(&mut buf, "p1s");
    rmp::encode::write_bin(&mut buf, &sig.pk1_sig).unwrap();

    // "p2" -> PK2 (32 bytes)
    write_str_key(&mut buf, "p2");
    rmp::encode::write_bin(&mut buf, &sig.pk2).unwrap();

    // "p2s" -> PK2Sig (64 bytes)
    write_str_key(&mut buf, "p2s");
    rmp::encode::write_bin(&mut buf, &sig.pk2_sig).unwrap();

    // "ps" -> PKSigOld (64 bytes)
    write_str_key(&mut buf, "ps");
    rmp::encode::write_bin(&mut buf, &sig.pk_sig_old).unwrap();

    // "s" -> Sig (64 bytes)
    write_str_key(&mut buf, "s");
    rmp::encode::write_bin(&mut buf, &sig.sig).unwrap();

    buf
}

/// Encode an UnauthenticatedVote to wire-format msgpack bytes.
///
/// Matches Go's `unauthenticatedVote.MarshalMsg` (omitempty).
/// Fields sorted by codec tag: "cred", "r", "sig"
pub fn encode_vote(vote: &UnauthenticatedVote) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    let r_encoded = encode_raw_vote(&vote.raw_vote);
    let cred_encoded = encode_unauthenticated_credential(&vote.cred);
    let sig_zero = ots_is_zero(&vote.sig);

    // raw vote is "empty" if it encodes to fixmap(0)
    let r_empty = r_encoded == [0x80];
    let cred_empty = cred_encoded == [0x80];

    let mut count: u8 = 0;
    if !cred_empty {
        count += 1;
    }
    if !r_empty {
        count += 1;
    }
    // sig uses omitemptycheckstruct: omit only if all fields are zero
    if !sig_zero {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Fields sorted alphabetically by codec tag: "cred", "r", "sig"
    if !cred_empty {
        write_str_key(&mut buf, "cred");
        buf.extend_from_slice(&cred_encoded);
    }
    if !r_empty {
        write_str_key(&mut buf, "r");
        buf.extend_from_slice(&r_encoded);
    }
    if !sig_zero {
        write_str_key(&mut buf, "sig");
        buf.extend_from_slice(&encode_one_time_signature(&vote.sig));
    }

    buf
}

/// Encode a VoteAuthenticator in canonical msgpack format.
///
/// Go's voteAuthenticator uses `codec:""` (NOT omitempty at struct level),
/// but individual fields have their own omitempty behavior:
///   "cred" -> always present (non-omitempty field)
///   "sig"  -> omitemptycheckstruct (omit if all zero)
///   "snd"  -> always present (non-omitempty field)
///
/// Note: The struct-level `codec:""` means the struct ITSELF is never omitted,
/// but individual fields still have their own omitempty annotations.
/// Specifically: `cred` and `snd` are always present (no omitempty),
/// while `sig` is omitted when all fields are zero (Go `omitemptycheckstruct`).
fn encode_vote_authenticator(auth: &VoteAuthenticator) -> Vec<u8> {
    let mut buf = Vec::with_capacity(384);

    // Non-omitempty struct: always 3 fields
    // But sig has omitemptycheckstruct at the field level
    let sig_zero = ots_is_zero(&auth.sig);

    let mut count: u8 = 2; // cred and snd always present
    if !sig_zero {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Fields sorted: "cred", "sig", "snd"
    write_str_key(&mut buf, "cred");
    buf.extend_from_slice(&encode_unauthenticated_credential(&auth.cred));

    if !sig_zero {
        write_str_key(&mut buf, "sig");
        buf.extend_from_slice(&encode_one_time_signature(&auth.sig));
    }

    write_str_key(&mut buf, "snd");
    rmp::encode::write_bin(&mut buf, &auth.sender.0).unwrap();

    buf
}

/// Encode an EquivocationVoteAuthenticator in canonical msgpack format.
///
/// Non-omitempty struct with fields:
///   "cred"  -> UnauthenticatedCredential
///   "props" -> [2]proposalValue (always 2-element array)
///   "sig"   -> [2]OneTimeSignature (omitemptycheckstruct)
///   "snd"   -> Address
fn encode_equivocation_vote_authenticator(auth: &EquivocationVoteAuthenticator) -> Vec<u8> {
    let mut buf = Vec::with_capacity(768);

    // go's generated `equivocationVoteAuthenticator.MarshalMsg` writes all
    // four fields: the struct is not omitempty and `omitemptycheckstruct`
    // has no effect on an array field (`zb0003Len := uint32(4)`, no mask).
    // Omitting an all-zero `sig` pair (as this encoder did before issue
    // #2424) changed the bundle bytes go would have produced.
    rmp::encode::write_map_len(&mut buf, 4).unwrap();

    // Fields sorted: "cred", "props", "sig", "snd"
    write_str_key(&mut buf, "cred");
    buf.extend_from_slice(&encode_unauthenticated_credential(&auth.cred));

    write_str_key(&mut buf, "props");
    // [2]proposalValue -> fixarray(2)
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    buf.extend_from_slice(&encode_proposal_value(&auth.proposals[0]));
    buf.extend_from_slice(&encode_proposal_value(&auth.proposals[1]));

    write_str_key(&mut buf, "sig");
    // [2]OneTimeSignature -> fixarray(2)
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    buf.extend_from_slice(&encode_one_time_signature(&auth.sigs[0]));
    buf.extend_from_slice(&encode_one_time_signature(&auth.sigs[1]));

    write_str_key(&mut buf, "snd");
    rmp::encode::write_bin(&mut buf, &auth.sender.0).unwrap();

    buf
}

/// Encode an UnauthenticatedBundle to wire-format msgpack bytes.
///
/// Matches Go's `unauthenticatedBundle.MarshalMsg` (omitempty).
/// Fields sorted by codec tag: "eqv", "per", "prop", "rnd", "step", "vote"
pub fn encode_bundle(bundle: &UnauthenticatedBundle) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    let eqv_empty = bundle.equivocation_votes.is_empty();
    let per_empty = bundle.period.0 == 0;
    let prop_empty = bundle.proposal.is_bottom();
    let rnd_empty = bundle.round.0 == 0;
    let step_empty = bundle.step.0 == 0;
    let vote_empty = bundle.votes.is_empty();

    let mut count: u8 = 0;
    if !eqv_empty {
        count += 1;
    }
    if !per_empty {
        count += 1;
    }
    if !prop_empty {
        count += 1;
    }
    if !rnd_empty {
        count += 1;
    }
    if !step_empty {
        count += 1;
    }
    if !vote_empty {
        count += 1;
    }

    // Use map_len for counts > 15 (though unlikely for 6 fields)
    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Fields sorted: "eqv", "per", "prop", "rnd", "step", "vote"
    if !eqv_empty {
        write_str_key(&mut buf, "eqv");
        rmp::encode::write_array_len(&mut buf, bundle.equivocation_votes.len() as u32).unwrap();
        for ev in &bundle.equivocation_votes {
            buf.extend_from_slice(&encode_equivocation_vote_authenticator(ev));
        }
    }

    if !per_empty {
        write_str_key(&mut buf, "per");
        rmp::encode::write_uint(&mut buf, bundle.period.0).unwrap();
    }

    if !prop_empty {
        write_str_key(&mut buf, "prop");
        buf.extend_from_slice(&encode_proposal_value(&bundle.proposal));
    }

    if !rnd_empty {
        write_str_key(&mut buf, "rnd");
        rmp::encode::write_uint(&mut buf, bundle.round.0).unwrap();
    }

    if !step_empty {
        write_str_key(&mut buf, "step");
        rmp::encode::write_uint(&mut buf, bundle.step.0).unwrap();
    }

    if !vote_empty {
        write_str_key(&mut buf, "vote");
        rmp::encode::write_array_len(&mut buf, bundle.votes.len() as u32).unwrap();
        for v in &bundle.votes {
            buf.extend_from_slice(&encode_vote_authenticator(v));
        }
    }

    buf
}

/// Encode a `CompoundMessage` as a `transmittedPayload` in Go-compatible
/// wire format.
///
/// In Go, `transmittedPayload` embeds `unauthenticatedProposal` (fields
/// flattened into the map) and adds `PriorVote` with codec tag `"pv"`.
/// All fields are sorted lexicographically.
///
/// This function takes the canonical encoding of the unauthenticated
/// proposal (a sorted msgpack map) and inserts the `"pv"` field at the
/// correct sorted position.
pub fn encode_compound_message(cm: &CompoundMessage) -> Vec<u8> {
    let vote_encoded = encode_vote(&cm.vote);
    // A vote is "empty" if it encodes to fixmap(0)
    let vote_empty = vote_encoded == [0x80];

    // Get the canonical encoding of the unauthenticated proposal.
    let proposal_bytes = canonical_encode_unauthenticated_proposal(
        &cm.proposal.block,
        &cm.proposal.seed_proof,
        cm.proposal.original_period.0,
        &cm.proposal.original_proposer,
    );

    if vote_empty {
        // No prior vote — the transmittedPayload is identical to the
        // unauthenticatedProposal encoding.
        return proposal_bytes;
    }

    // We need to insert a "pv" key-value pair into the sorted map.
    // The proposal_bytes start with a map header (fixmap, map16, or map32)
    // followed by sorted key-value pairs. We parse the header, increment
    // the count, then scan through key-value pairs to find where "pv" belongs.
    let mut cursor = Cursor::new(proposal_bytes.as_slice());
    let map_len = rmp::decode::read_map_len(&mut cursor).unwrap_or(0);
    let header_end = cursor.position() as usize;

    // The key-value pairs start at header_end.
    let kv_bytes = &proposal_bytes[header_end..];

    // Scan through keys to find insertion point for "pv".
    let mut scan = Cursor::new(kv_bytes);
    let mut insert_offset = kv_bytes.len(); // default: append at end
    for _ in 0..map_len {
        let key_start = scan.position() as usize;
        // Read the key
        let key_val =
            rmpv::decode::read_value(&mut scan).expect("valid msgpack key in proposal encoding");
        if let rmpv::Value::String(ref s) = key_val {
            if let Some(k) = s.as_str() {
                if k > "pv" {
                    insert_offset = key_start;
                    break;
                }
            }
        }
        // Skip the value
        let _val =
            rmpv::decode::read_value(&mut scan).expect("valid msgpack value in proposal encoding");
    }

    // Build the result: new map header + kv pairs with "pv" inserted.
    let new_map_len = map_len + 1;
    let mut buf = Vec::with_capacity(proposal_bytes.len() + vote_encoded.len() + 8);
    rmp::encode::write_map_len(&mut buf, new_map_len).unwrap();

    // Copy key-value pairs before insertion point.
    buf.extend_from_slice(&kv_bytes[..insert_offset]);

    // Insert "pv" -> encoded vote.
    write_str_key(&mut buf, "pv");
    buf.extend_from_slice(&vote_encoded);

    // Copy remaining key-value pairs after insertion point.
    buf.extend_from_slice(&kv_bytes[insert_offset..]);

    buf
}

/// Decode a `CompoundMessage` from wire-format msgpack bytes.
///
/// This is the inverse of `encode_compound_message`. The wire format is a
/// Go `transmittedPayload`: a flat msgpack map containing all
/// `unauthenticatedProposal` fields (which embeds `bookkeeping.Block` fields
/// plus `sdpf`, `oper`, `oprop`) and optionally a `"pv"` key holding the
/// prior vote (`unauthenticatedVote`).
///
/// Decoding strategy:
/// 1. Decode the bytes as a `Block` via `Block::decode_from_bytes` (which skips only
///    the proposal's own top-level keys `oper`, `oprop`, `sdpf`, `pv`).
/// 2. Scan the map a second time to extract the proposal-specific fields
///    (`oper`, `oprop`, `sdpf`) and the optional prior vote (`pv`).
pub fn decode_compound_message(bytes: &[u8]) -> Result<CompoundMessage, CodecError> {
    let _session = go_msgp::decode_session();
    // Step 1: Decode block fields (skips unknown keys). Use the
    // rnd-tolerant wrapper so transmittedPayload fixtures with
    // round=0 (which omit the `rnd` key via omitempty) still parse.
    let block = decode_block_allowing_missing_rnd(
        bytes,
        "agreement.transmittedPayload",
        &[b"oper", b"oprop", b"sdpf", b"pv"],
    )?;

    // Step 2: Scan the map to extract proposal-specific fields and prior vote.
    let mut proposal = UnauthenticatedProposal {
        block,
        ..UnauthenticatedProposal::default()
    };
    let mut prior_vote = UnauthenticatedVote::default();
    proposal_fields_into(&mut &bytes[..], &mut proposal, Some(&mut prior_vote)).map_err(go_err)?;
    Ok(CompoundMessage {
        vote: prior_vote,
        proposal,
    })
}

/// The second pass over an `unauthenticatedProposal` / `transmittedPayload`
/// map: its own fields (`oper`, `oprop`, `sdpf` and, for a payload, `pv`),
/// each decoded into the current value like go's (a repeated key merges);
/// the block fields were read by the block decoder, which also rejected
/// every key the message lacks.
fn proposal_fields_into(
    rd: &mut &[u8],
    p: &mut UnauthenticatedProposal,
    mut prior_vote: Option<&mut UnauthenticatedVote>,
) -> GoResult<()> {
    // go's type of the message: the array form reads the block's fields, then
    // these, at go's positions (issue #2426)
    let go_type = if prior_vote.is_some() {
        "agreement.transmittedPayload"
    } else {
        "agreement.unauthenticatedProposal"
    };
    let mut keys = go_msgp::struct_keys(rd, &mut (), go_type)?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"oper" => p.original_period = Period(go_msgp::read_u64(rd)?),
            b"oprop" => fixed_into(rd, &mut p.original_proposer.0)?,
            b"sdpf" => fixed_into(rd, &mut p.seed_proof)?,
            b"pv" if prior_vote.is_some() => {
                vote_into(rd, prior_vote.as_deref_mut().expect("checked"))?
            }
            // A block field: the strict block decode already rejected every
            // key go's message lacks.
            _ => match fast_skip_len(rd) {
                Some(len) => *rd = &rd[len..],
                None => go_msgp::skip_value(rd)?,
            },
        }
    }
    Ok(())
}

// ── Decoding helpers ─────────────────────────────────────────────────────

/// Containers nested deeper than this are left to `rmpv` (which has its own,
/// much larger, depth limit and error).
const FAST_SKIP_MAX_DEPTH: usize = 32;

/// Encoded length of the msgpack value at the start of `buf`, or `None` when
/// it is not complete and well formed within [`FAST_SKIP_MAX_DEPTH`] (the
/// caller then falls back to the general skipper). Skips a proposal's block
/// fields without building them (go: `msgp.Skip`, issue #2317).
fn fast_skip_len(buf: &[u8]) -> Option<usize> {
    fn be16(buf: &[u8], pos: usize) -> Option<usize> {
        Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize)
    }
    fn be32(buf: &[u8], pos: usize) -> Option<usize> {
        let b = buf.get(pos..pos.checked_add(4)?)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    // Values still to read at each enclosing level.
    let mut stack = [0usize; FAST_SKIP_MAX_DEPTH];
    let mut depth = 0usize;
    let mut pending = 1usize;
    let mut pos = 0usize;
    loop {
        while pending == 0 {
            if depth == 0 {
                return Some(pos);
            }
            depth -= 1;
            pending = stack[depth];
        }
        pending -= 1;
        let marker = *buf.get(pos)?;
        pos += 1;
        // (payload bytes to skip, child values that follow)
        let (payload, children) = match marker {
            // positive fixint, negative fixint, nil, false, true
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => (0, 0),
            0x80..=0x8f => (0, 2 * (marker & 0x0f) as usize),
            0x90..=0x9f => (0, (marker & 0x0f) as usize),
            0xa0..=0xbf => ((marker & 0x1f) as usize, 0),
            // reserved
            0xc1 => return None,
            // bin8 / str8
            0xc4 | 0xd9 => {
                let n = *buf.get(pos)? as usize;
                pos += 1;
                (n, 0)
            }
            // bin16 / str16
            0xc5 | 0xda => {
                let n = be16(buf, pos)?;
                pos += 2;
                (n, 0)
            }
            // bin32 / str32
            0xc6 | 0xdb => {
                let n = be32(buf, pos)?;
                pos += 4;
                (n, 0)
            }
            // ext8 / ext16 / ext32: length, then a type byte and the data
            0xc7 => {
                let n = *buf.get(pos)? as usize;
                pos += 1;
                (n.checked_add(1)?, 0)
            }
            0xc8 => {
                let n = be16(buf, pos)?;
                pos += 2;
                (n.checked_add(1)?, 0)
            }
            0xc9 => {
                let n = be32(buf, pos)?;
                pos += 4;
                (n.checked_add(1)?, 0)
            }
            // float32, uint32, int32
            0xca | 0xce | 0xd2 => (4, 0),
            // float64, uint64, int64
            0xcb | 0xcf | 0xd3 => (8, 0),
            // uint8, int8
            0xcc | 0xd0 => (1, 0),
            // uint16, int16
            0xcd | 0xd1 => (2, 0),
            // fixext1/2/4/8/16: a type byte and the data
            0xd4 => (2, 0),
            0xd5 => (3, 0),
            0xd6 => (5, 0),
            0xd7 => (9, 0),
            0xd8 => (17, 0),
            // array16 / array32
            0xdc => {
                let n = be16(buf, pos)?;
                pos += 2;
                (0, n)
            }
            0xdd => {
                let n = be32(buf, pos)?;
                pos += 4;
                (0, n)
            }
            // map16 / map32
            0xde => {
                let n = be16(buf, pos)?;
                pos += 2;
                (0, n.checked_mul(2)?)
            }
            0xdf => {
                let n = be32(buf, pos)?;
                pos += 4;
                (0, n.checked_mul(2)?)
            }
        };
        pos = pos.checked_add(payload)?;
        if pos > buf.len() {
            return None;
        }
        if children > 0 {
            if depth == FAST_SKIP_MAX_DEPTH {
                return None;
            }
            stack[depth] = pending;
            depth += 1;
            pending = children;
        }
    }
}

// ── Decoding INTO the populated value (issue #2424) ─────────────────────
//
// go's generated `UnmarshalMsg` decodes a repeated map key again INTO the
// field it already filled: a nested struct is merged (a `nil` resets it), a
// `[N]byte` keeps the bytes past a shorter value, a slice is re-sliced
// within its capacity (each element decoded into the element already
// there), a fixed array `[2]T` takes at most two elements into the leading
// ones. The readers below work on the remaining input slice with the
// `algo_types::go_msgp` primitives that implement exactly that.

type GoResult<T> = algo_error::Result<T>;

/// go's `bounds.MaxVoteThreshold` (7750 for the built-in protocols, issue
/// #2427; raised by a loaded `consensus.json`, #2439): the `allocbound` of a
/// bundle's votes / equivocation votes.
fn max_bundle_array_len() -> usize {
    go_msgp::bounds::MAX_VOTE_THRESHOLD.get()
}

fn go_err(e: algo_error::AlgoError) -> CodecError {
    CodecError::Decode(e.to_string())
}

/// Run a slice reader at the cursor position and advance the cursor past
/// what it consumed.
#[inline]
fn at_cursor<T>(
    cursor: &mut Cursor<&[u8]>,
    f: impl FnOnce(&mut &[u8]) -> GoResult<T>,
) -> Result<T, CodecError> {
    let buf: &[u8] = cursor.get_ref();
    let pos = (cursor.position() as usize).min(buf.len());
    let mut rd = &buf[pos..];
    let before = rd.len();
    let v = f(&mut rd).map_err(go_err)?;
    cursor.set_position((pos + before - rd.len()) as u64);
    Ok(v)
}

/// A `[N]byte` field decoded into its current value (`msgp.ReadExactBytes`),
/// with a fast path for the `bin8` of exactly N bytes go's encoder writes.
#[inline]
fn fixed_into(rd: &mut &[u8], into: &mut [u8]) -> GoResult<()> {
    let n = into.len();
    if n <= u8::MAX as usize && rd.len() >= n + 2 && rd[0] == 0xc4 && rd[1] as usize == n {
        into.copy_from_slice(&rd[2..2 + n]);
        *rd = &rd[2 + n..];
        return Ok(());
    }
    go_msgp::read_fixed_bytes_into_go_compat(rd, into)
}

fn zero_ots() -> OneTimeSignature {
    OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    }
}

fn zero_raw_vote() -> RawVote {
    RawVote {
        sender: Address([0u8; 32]),
        round: Round(0),
        period: Period(0),
        step: Step(0),
        proposal: BOTTOM,
    }
}

fn zero_vote_authenticator() -> VoteAuthenticator {
    VoteAuthenticator {
        sender: Address([0u8; 32]),
        cred: UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
        sig: zero_ots(),
    }
}

fn zero_equivocation_vote_authenticator() -> EquivocationVoteAuthenticator {
    EquivocationVoteAuthenticator {
        sender: Address([0u8; 32]),
        cred: UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
        sigs: [zero_ots(), zero_ots()],
        proposals: [BOTTOM, BOTTOM],
    }
}

/// `proposalValue` decoded into `pv`.
fn proposal_value_into(rd: &mut &[u8], pv: &mut ProposalValue) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(rd, pv, || BOTTOM, "agreement.proposalValue")?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"dig" => fixed_into(rd, &mut pv.block_digest.0)?,
            b"encdig" => fixed_into(rd, &mut pv.encoding_digest.0)?,
            b"oper" => pv.original_period = Period(go_msgp::read_u64(rd)?),
            b"oprop" => fixed_into(rd, &mut pv.original_proposer.0)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `rawVote` decoded into `rv`.
fn raw_vote_into(rd: &mut &[u8], rv: &mut RawVote) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(rd, rv, zero_raw_vote, "agreement.rawVote")?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"per" => rv.period = Period(go_msgp::read_u64(rd)?),
            b"prop" => proposal_value_into(rd, &mut rv.proposal)?,
            b"rnd" => rv.round = Round(go_msgp::read_u64(rd)?),
            b"snd" => fixed_into(rd, &mut rv.sender.0)?,
            b"step" => rv.step = Step(go_msgp::read_u64(rd)?),
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `committee.UnauthenticatedCredential` decoded into `c`.
fn credential_into(rd: &mut &[u8], c: &mut UnauthenticatedCredential) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(
        rd,
        c,
        || UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
        "committee.UnauthenticatedCredential",
    )?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"pf" => fixed_into(rd, &mut c.proof)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `crypto.OneTimeSignature` decoded into `sig`.
fn one_time_signature_into(rd: &mut &[u8], sig: &mut OneTimeSignature) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(rd, sig, zero_ots, "crypto.OneTimeSignature")?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"p" => fixed_into(rd, &mut sig.pk)?,
            b"p1s" => fixed_into(rd, &mut sig.pk1_sig)?,
            b"p2" => fixed_into(rd, &mut sig.pk2)?,
            b"p2s" => fixed_into(rd, &mut sig.pk2_sig)?,
            b"ps" => fixed_into(rd, &mut sig.pk_sig_old)?,
            b"s" => fixed_into(rd, &mut sig.sig)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `unauthenticatedVote` decoded into `vote`.
fn vote_into(rd: &mut &[u8], vote: &mut UnauthenticatedVote) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(
        rd,
        vote,
        UnauthenticatedVote::default,
        "agreement.unauthenticatedVote",
    )?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"cred" => credential_into(rd, &mut vote.cred)?,
            b"r" => raw_vote_into(rd, &mut vote.raw_vote)?,
            b"sig" => one_time_signature_into(rd, &mut vote.sig)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `unauthenticatedVote.UnmarshalMsg` at the start of `rd`, decoded into
/// `vote`: the `pv` entry of a proposal payload prefix
/// (`payload_deferral::parse_payload_prefix`).
pub(crate) fn decode_vote_into(
    rd: &mut &[u8],
    vote: &mut UnauthenticatedVote,
) -> Result<(), CodecError> {
    vote_into(rd, vote).map_err(go_err)
}

/// `voteAuthenticator` decoded into `auth`.
fn vote_authenticator_into(rd: &mut &[u8], auth: &mut VoteAuthenticator) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(
        rd,
        auth,
        zero_vote_authenticator,
        "agreement.voteAuthenticator",
    )?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"cred" => credential_into(rd, &mut auth.cred)?,
            b"sig" => one_time_signature_into(rd, &mut auth.sig)?,
            b"snd" => fixed_into(rd, &mut auth.sender.0)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `equivocationVoteAuthenticator` decoded into `auth`; `sig` / `props`
/// are go `[2]T` arrays (at most two elements, decoded into the leading
/// ones).
fn equivocation_vote_authenticator_into(
    rd: &mut &[u8],
    auth: &mut EquivocationVoteAuthenticator,
) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(
        rd,
        auth,
        zero_equivocation_vote_authenticator,
        "agreement.equivocationVoteAuthenticator",
    )?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"cred" => credential_into(rd, &mut auth.cred)?,
            b"props" => {
                go_msgp::read_fixed_array_into(rd, &mut auth.proposals, proposal_value_into)?
            }
            b"sig" => go_msgp::read_fixed_array_into(rd, &mut auth.sigs, one_time_signature_into)?,
            b"snd" => fixed_into(rd, &mut auth.sender.0)?,
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// `unauthenticatedBundle` decoded into `bundle`.
fn bundle_into(rd: &mut &[u8], bundle: &mut UnauthenticatedBundle) -> GoResult<()> {
    let mut keys = go_msgp::struct_keys_with(
        rd,
        bundle,
        UnauthenticatedBundle::default,
        "agreement.unauthenticatedBundle",
    )?;
    while let Some(key) = keys.next(rd)? {
        match key {
            b"eqv" => {
                go_msgp::read_slice_into(
                    rd,
                    &mut bundle.equivocation_votes,
                    max_bundle_array_len(),
                    zero_equivocation_vote_authenticator,
                    equivocation_vote_authenticator_into,
                )?;
            }
            b"per" => bundle.period = Period(go_msgp::read_u64(rd)?),
            b"prop" => proposal_value_into(rd, &mut bundle.proposal)?,
            b"rnd" => bundle.round = Round(go_msgp::read_u64(rd)?),
            b"step" => bundle.step = Step(go_msgp::read_u64(rd)?),
            b"vote" => {
                go_msgp::read_slice_into(
                    rd,
                    &mut bundle.votes,
                    max_bundle_array_len(),
                    zero_vote_authenticator,
                    vote_authenticator_into,
                )?;
            }
            key => return Err(go_msgp::no_matching_field_error(key)),
        }
    }
    Ok(())
}

/// Decode a ProposalValue from cursor position.
fn decode_proposal_value(cursor: &mut Cursor<&[u8]>) -> Result<ProposalValue, CodecError> {
    at_cursor(cursor, |rd| {
        let mut pv = BOTTOM;
        proposal_value_into(rd, &mut pv)?;
        Ok(pv)
    })
}

/// Decode a RawVote from cursor position.
fn decode_raw_vote(cursor: &mut Cursor<&[u8]>) -> Result<RawVote, CodecError> {
    at_cursor(cursor, |rd| {
        let mut rv = zero_raw_vote();
        raw_vote_into(rd, &mut rv)?;
        Ok(rv)
    })
}

#[cfg(test)]
fn decode_unauthenticated_credential(
    cursor: &mut Cursor<&[u8]>,
) -> Result<UnauthenticatedCredential, CodecError> {
    at_cursor(cursor, |rd| {
        let mut c = UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]);
        credential_into(rd, &mut c)?;
        Ok(c)
    })
}

#[cfg(test)]
fn decode_equivocation_vote_authenticator(
    cursor: &mut Cursor<&[u8]>,
) -> Result<EquivocationVoteAuthenticator, CodecError> {
    at_cursor(cursor, |rd| {
        let mut a = zero_equivocation_vote_authenticator();
        equivocation_vote_authenticator_into(rd, &mut a)?;
        Ok(a)
    })
}

/// Decode an UnauthenticatedVote from wire-format msgpack bytes.
pub fn decode_vote(bytes: &[u8]) -> Result<UnauthenticatedVote, CodecError> {
    let _session = go_msgp::decode_session();
    let mut vote = UnauthenticatedVote::default();
    vote_into(&mut &bytes[..], &mut vote).map_err(go_err)?;
    Ok(vote)
}

/// Decode an UnauthenticatedBundle from wire-format msgpack bytes.
pub fn decode_bundle(bytes: &[u8]) -> Result<UnauthenticatedBundle, CodecError> {
    let _session = go_msgp::decode_session();
    let mut bundle = UnauthenticatedBundle::default();
    bundle_into(&mut &bytes[..], &mut bundle).map_err(go_err)?;
    Ok(bundle)
}

// ── Pub wrappers for inner types (TASK-60) ───────────────────────────────
//
// TASK-55 shipped only the outer-envelope encoders/decoders
// (UnauthenticatedVote, UnauthenticatedBundle, Certificate,
// CompoundMessage). TASK-60 extends public coverage to every inner
// wire type captured under tests/fixtures/wire/ so that the roundtrip
// parity harness can assert byte-identical equality against
// go-algorand/agreement/msgp_gen.go for the full corpus.

/// Encode a `ProposalValue` to canonical wire-format msgpack bytes.
///
/// Mirrors `agreement.proposalValue.MarshalMsg` in
/// `../go-algorand/agreement/msgp_gen.go`. Fields sorted by codec tag,
/// all `omitempty`: `"dig"`, `"encdig"`, `"oper"`, `"oprop"`.
pub fn encode_proposalvalue(pv: &ProposalValue) -> Vec<u8> {
    encode_proposal_value(pv)
}

/// Decode a `ProposalValue` from canonical wire-format msgpack bytes.
pub fn decode_proposalvalue(bytes: &[u8]) -> Result<ProposalValue, CodecError> {
    let mut cursor = Cursor::new(bytes);
    decode_proposal_value(&mut cursor)
}

/// Encode a `RawVote` to canonical wire-format msgpack bytes.
///
/// Mirrors `agreement.rawVote.MarshalMsg`. Fields sorted by codec tag,
/// all `omitempty`: `"per"`, `"prop"`, `"rnd"`, `"snd"`, `"step"`.
pub fn encode_rawvote(rv: &RawVote) -> Vec<u8> {
    encode_raw_vote(rv)
}

/// Decode a `RawVote` from canonical wire-format msgpack bytes.
pub fn decode_rawvote(bytes: &[u8]) -> Result<RawVote, CodecError> {
    let mut cursor = Cursor::new(bytes);
    decode_raw_vote(&mut cursor)
}

// ── UnauthenticatedProposal wire codec ───────────────────────────────────
//
// `unauthenticatedProposal` embeds `bookkeeping.Block` (flattened into
// the outer map) and adds `"sdpf"` (VRF seed proof), `"oper"`
// (OriginalPeriod), `"oprop"` (OriginalProposer). `proposal` embeds
// `unauthenticatedProposal` without adding any new serialized fields,
// so its wire bytes are byte-identical.
//
// The encode side reuses `algo_codec::canonical_encode_unauthenticated_proposal`,
// which already produces the canonical sorted-map representation.
//
// The decode side delegates block-field handling to
// `Block::decode_from_bytes` (which skips unknown keys) and then scans
// the same map for the three uproposal-specific fields.

/// Encode an `UnauthenticatedProposal` to canonical wire-format msgpack bytes.
///
/// Produces the same bytes as Go's
/// `unauthenticatedProposal.MarshalMsg` and (by construction) Go's
/// `proposal.MarshalMsg`.
pub fn encode_unauthenticated_proposal(p: &UnauthenticatedProposal) -> Vec<u8> {
    canonical_encode_unauthenticated_proposal(
        &p.block,
        &p.seed_proof,
        p.original_period.0,
        &p.original_proposer,
    )
}

/// Decode an `UnauthenticatedProposal` from canonical wire-format
/// msgpack bytes. Accepts both `unauthenticatedProposal` and
/// `proposal` fixtures (they share the same wire representation).
pub fn decode_unauthenticated_proposal(
    bytes: &[u8],
) -> Result<UnauthenticatedProposal, CodecError> {
    let _session = go_msgp::decode_session();
    // Step 1: decode block fields (skips unknown keys).
    //
    // `Block::decode_from_bytes` requires `rnd` to be present, but
    // uproposal fixtures where round=0 omit that key via Go's
    // `omitempty`. Synthesize `rnd: 0` when the key is absent so the
    // block decoder can complete — round stays Round(0) either way.
    let block = decode_block_allowing_missing_rnd(
        bytes,
        "agreement.unauthenticatedProposal",
        &[b"oper", b"oprop", b"sdpf"],
    )?;

    // Step 2: the proposal's own fields.
    let mut proposal = UnauthenticatedProposal {
        block,
        ..UnauthenticatedProposal::default()
    };
    proposal_fields_into(&mut &bytes[..], &mut proposal, None).map_err(go_err)?;
    Ok(proposal)
}

/// Run `Block::decode_from_bytes`, with a fallback that synthesizes
/// `rnd: 0` into the top-level map if the block decoder rejects the
/// input for the specific reason that `rnd` is missing. Needed because
/// that decoder hard-requires `rnd`, whereas Go msgp omits zero rounds
/// via `omitempty` — a legitimate shape for uproposal / transmitted
/// payload fixtures where round=0.
///
/// The fast path (round ≠ 0) is a single call to
/// `Block::decode_from_bytes` with no extra map traversal — this
/// matters because `decode_compound_message` is on the network ingest
/// path (`demux::handle_raw_proposal`) and pre-scanning every proposal
/// map would add per-packet CPU and amplify proposal-spam.
fn decode_block_allowing_missing_rnd(
    bytes: &[u8],
    go_type: &'static str,
    extra_keys: &[&[u8]],
) -> Result<Block, CodecError> {
    let decode = |b: &[u8]| Block::decode_as(&mut &b[..], go_type, extra_keys);
    match decode(bytes) {
        Ok(block) => Ok(block),
        Err(first_err) => {
            // Only attempt the synthesized-`rnd` fallback if the
            // decoder rejected the input specifically for a missing
            // `rnd` key. Other failures (malformed bytes, other
            // missing required fields) propagate unchanged.
            if !is_missing_rnd_error(&first_err) {
                return Err(CodecError::Decode(format!(
                    "block decode: {}",
                    format_error_chain(&first_err)
                )));
            }
            let patched = inject_rnd_zero(bytes).map_err(|_| {
                CodecError::Decode(format!("block decode: {}", format_error_chain(&first_err)))
            })?;
            decode(&patched).map_err(|retry_err| {
                CodecError::Decode(format!(
                    "block decode (rnd synthesized): {}",
                    format_error_chain(&retry_err)
                ))
            })
        }
    }
}

/// Render an error together with its full `source()` chain.
///
/// `algo_error::AlgoError::Codec`'s `Display` prints only its `context`
/// string (literally `"codec error: rmp_decode"`), which hides the actual
/// diagnostic. Every decode failure on the agreement ingest path would
/// otherwise be reported identically, making wire-format mismatches with
/// go-algorand effectively undebuggable from logs (see issue #478).
fn format_error_chain<E: std::error::Error + 'static>(err: &E) -> String {
    let mut out = err.to_string();
    let mut cur: &(dyn std::error::Error + 'static) = err;
    while let Some(next) = cur.source() {
        out.push_str(": ");
        out.push_str(&next.to_string());
        cur = next;
    }
    out
}

/// Returns `true` if `err` is the specific error emitted by
/// `Block::decode_from_bytes` when the top-level msgpack map omits
/// the required `rnd` key (i.e., Go's `omitempty` dropped it because
/// round=0). `algo-agreement` doesn't depend on `algo-error` directly
/// — inspect via the `std::error::Error` trait so we don't need to
/// add a dep just for pattern-matching.
fn is_missing_rnd_error<E: std::error::Error + 'static>(err: &E) -> bool {
    // `Block::decode_from_reader` wraps the diagnostic as
    // `AlgoError::Codec { source: "Block: missing required 'rnd' field", .. }`.
    // The Display impl for `AlgoError::Codec` shows only the context
    // ("rmp_decode"), so walk the chained `source` to detect the
    // specific case.
    let mut cur: &(dyn std::error::Error + 'static) = err;
    loop {
        if cur.to_string().contains("missing required 'rnd'") {
            return true;
        }
        match cur.source() {
            Some(next) => cur = next,
            None => return false,
        }
    }
}

/// Insert a `"rnd" -> 0` entry at the sorted position in a top-level
/// msgpack map and return the patched bytes.
fn inject_rnd_zero(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut cursor = Cursor::new(bytes);
    let map_len = rmp::decode::read_map_len(&mut cursor)
        .map_err(|e| CodecError::Decode(format!("map header: {e}")))?;
    let header_end = cursor.position() as usize;
    let kv_bytes = &bytes[header_end..];

    let mut scan = Cursor::new(kv_bytes);
    let mut insert_offset = kv_bytes.len();
    for _ in 0..map_len {
        let key_start = scan.position() as usize;
        let key_val = rmpv::decode::read_value(&mut scan)
            .map_err(|e| CodecError::Decode(format!("key: {e}")))?;
        if let rmpv::Value::String(ref s) = key_val {
            if let Some(k) = s.as_str() {
                if k > "rnd" {
                    insert_offset = key_start;
                    break;
                }
            }
        }
        rmpv::decode::read_value(&mut scan)
            .map_err(|e| CodecError::Decode(format!("value: {e}")))?;
    }

    let new_map_len = map_len + 1;
    let mut buf = Vec::with_capacity(bytes.len() + 8);
    rmp::encode::write_map_len(&mut buf, new_map_len).unwrap();
    buf.extend_from_slice(&kv_bytes[..insert_offset]);
    write_str_key(&mut buf, "rnd");
    rmp::encode::write_uint(&mut buf, 0).unwrap();
    buf.extend_from_slice(&kv_bytes[insert_offset..]);

    Ok(buf)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Digest;

    /// The key of the map entry at the cursor, as an owned string.
    fn read_str_key(cursor: &mut Cursor<&[u8]>) -> Result<String, CodecError> {
        match rmpv::decode::read_value(cursor)
            .map_err(|e| CodecError::Decode(format!("key: {e}")))?
        {
            rmpv::Value::String(s) => s
                .into_str()
                .ok_or_else(|| CodecError::Format("key is not valid UTF-8".into())),
            v => Err(CodecError::Format(format!(
                "expected string key, got {v:?}"
            ))),
        }
    }

    fn make_zero_sig() -> OneTimeSignature {
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        }
    }

    fn make_nonzero_sig() -> OneTimeSignature {
        OneTimeSignature {
            sig: [0x11; 64],
            pk: [0x22; 32],
            pk_sig_old: [0x33; 64],
            pk2: [0x44; 32],
            pk1_sig: [0x55; 64],
            pk2_sig: [0x66; 64],
        }
    }

    // ── Vote round-trip tests ────────────────────────────────────────────

    #[test]
    fn vote_roundtrip_default() {
        let vote = UnauthenticatedVote::default();
        let encoded = encode_vote(&vote);
        let decoded = decode_vote(&encoded).expect("decode should succeed");
        assert_eq!(decoded.raw_vote.round.0, 0);
        assert_eq!(decoded.raw_vote.period.0, 0);
        assert_eq!(decoded.raw_vote.step.0, 0);
        assert!(decoded.raw_vote.proposal.is_bottom());
        assert_eq!(decoded.cred.proof, [0u8; VRF_PROOF_SIZE]);
        assert!(ots_is_zero(&decoded.sig));
    }

    #[test]
    fn vote_roundtrip_with_data() {
        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x42; 32]),
                round: Round(100),
                period: Period(1),
                step: Step(2),
                proposal: ProposalValue {
                    original_period: Period(1),
                    original_proposer: Address([0x42; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0xcc; VRF_PROOF_SIZE]),
            sig: make_nonzero_sig(),
        };

        let encoded = encode_vote(&vote);
        let decoded = decode_vote(&encoded).expect("decode should succeed");

        assert_eq!(decoded.raw_vote.sender, Address([0x42; 32]));
        assert_eq!(decoded.raw_vote.round, Round(100));
        assert_eq!(decoded.raw_vote.period, Period(1));
        assert_eq!(decoded.raw_vote.step, Step(2));
        assert_eq!(decoded.raw_vote.proposal.block_digest, Digest([0xaa; 32]));
        assert_eq!(
            decoded.raw_vote.proposal.encoding_digest,
            Digest([0xbb; 32])
        );
        assert_eq!(decoded.raw_vote.proposal.original_period, Period(1));
        assert_eq!(
            decoded.raw_vote.proposal.original_proposer,
            Address([0x42; 32])
        );
        assert_eq!(decoded.cred.proof, [0xcc; VRF_PROOF_SIZE]);
        assert_eq!(decoded.sig.sig, [0x11; 64]);
        assert_eq!(decoded.sig.pk, [0x22; 32]);
        assert_eq!(decoded.sig.pk_sig_old, [0x33; 64]);
        assert_eq!(decoded.sig.pk2, [0x44; 32]);
        assert_eq!(decoded.sig.pk1_sig, [0x55; 64]);
        assert_eq!(decoded.sig.pk2_sig, [0x66; 64]);
    }

    #[test]
    fn vote_roundtrip_zero_sig_omitted() {
        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(42),
                period: Period(0),
                step: Step(1),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xff; 32]),
                    encoding_digest: Digest([0xee; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0xdd; VRF_PROOF_SIZE]),
            sig: make_zero_sig(),
        };

        let encoded = encode_vote(&vote);
        let decoded = decode_vote(&encoded).expect("decode should succeed");

        assert_eq!(decoded.raw_vote.sender, Address([0x01; 32]));
        assert_eq!(decoded.raw_vote.round, Round(42));
        assert!(ots_is_zero(&decoded.sig));
    }

    // ── Bundle round-trip tests ──────────────────────────────────────────

    #[test]
    fn bundle_roundtrip_default() {
        let bundle = UnauthenticatedBundle::default();
        let encoded = encode_bundle(&bundle);
        let decoded = decode_bundle(&encoded).expect("decode should succeed");
        assert_eq!(decoded.round.0, 0);
        assert_eq!(decoded.period.0, 0);
        assert_eq!(decoded.step.0, 0);
        assert!(decoded.proposal.is_bottom());
        assert!(decoded.votes.is_empty());
        assert!(decoded.equivocation_votes.is_empty());
    }

    #[test]
    fn bundle_roundtrip_with_votes() {
        let bundle = UnauthenticatedBundle {
            round: Round(200),
            period: Period(1),
            step: Step(3),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![
                VoteAuthenticator {
                    sender: Address([0x01; 32]),
                    cred: UnauthenticatedCredential::new([0x11; VRF_PROOF_SIZE]),
                    sig: make_nonzero_sig(),
                },
                VoteAuthenticator {
                    sender: Address([0x02; 32]),
                    cred: UnauthenticatedCredential::new([0x22; VRF_PROOF_SIZE]),
                    sig: make_nonzero_sig(),
                },
            ],
            equivocation_votes: vec![],
        };

        let encoded = encode_bundle(&bundle);
        let decoded = decode_bundle(&encoded).expect("decode should succeed");

        assert_eq!(decoded.round, Round(200));
        assert_eq!(decoded.period, Period(1));
        assert_eq!(decoded.step, Step(3));
        assert_eq!(decoded.proposal.block_digest, Digest([0xaa; 32]));
        assert_eq!(decoded.votes.len(), 2);
        assert_eq!(decoded.votes[0].sender, Address([0x01; 32]));
        assert_eq!(decoded.votes[0].cred.proof, [0x11; VRF_PROOF_SIZE]);
        assert_eq!(decoded.votes[1].sender, Address([0x02; 32]));
        assert_eq!(decoded.votes[1].cred.proof, [0x22; VRF_PROOF_SIZE]);
    }

    #[test]
    fn bundle_roundtrip_with_equivocation_votes() {
        let bundle = UnauthenticatedBundle {
            round: Round(300),
            period: Period(0),
            step: Step(4),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![VoteAuthenticator {
                sender: Address([0x03; 32]),
                cred: UnauthenticatedCredential::new([0x33; VRF_PROOF_SIZE]),
                sig: make_nonzero_sig(),
            }],
            equivocation_votes: vec![EquivocationVoteAuthenticator {
                sender: Address([0x04; 32]),
                cred: UnauthenticatedCredential::new([0x44; VRF_PROOF_SIZE]),
                sigs: [make_nonzero_sig(), make_nonzero_sig()],
                proposals: [
                    ProposalValue {
                        original_period: Period(0),
                        original_proposer: Address([0x04; 32]),
                        block_digest: Digest([0xcc; 32]),
                        encoding_digest: Digest([0xdd; 32]),
                    },
                    ProposalValue {
                        original_period: Period(0),
                        original_proposer: Address([0x04; 32]),
                        block_digest: Digest([0xee; 32]),
                        encoding_digest: Digest([0xff; 32]),
                    },
                ],
            }],
        };

        let encoded = encode_bundle(&bundle);
        let decoded = decode_bundle(&encoded).expect("decode should succeed");

        assert_eq!(decoded.round, Round(300));
        assert_eq!(decoded.step, Step(4));
        assert_eq!(decoded.votes.len(), 1);
        assert_eq!(decoded.equivocation_votes.len(), 1);

        let ev = &decoded.equivocation_votes[0];
        assert_eq!(ev.sender, Address([0x04; 32]));
        assert_eq!(ev.cred.proof, [0x44; VRF_PROOF_SIZE]);
        assert_eq!(ev.proposals[0].block_digest, Digest([0xcc; 32]));
        assert_eq!(ev.proposals[1].block_digest, Digest([0xee; 32]));
    }

    // ── OTS encoding tests ──────────────────────────────────────────────

    #[test]
    fn ots_encoding_always_has_six_fields() {
        let sig = make_zero_sig();
        let encoded = encode_one_time_signature(&sig);
        // fixmap(6) = 0x86
        assert_eq!(encoded[0], 0x86);
    }

    #[test]
    fn ots_encoding_field_order() {
        let sig = make_nonzero_sig();
        let encoded = encode_one_time_signature(&sig);
        assert_eq!(encoded[0], 0x86);

        // Verify field ordering by finding key positions
        // Verify field ordering by parsing the keys back out.
        let mut cursor = Cursor::new(encoded.as_slice());
        let map_len = rmp::decode::read_map_len(&mut cursor).unwrap();
        assert_eq!(map_len, 6);

        let mut keys = Vec::new();
        for _ in 0..map_len {
            let key = read_str_key(&mut cursor).unwrap();
            // Skip value
            rmpv::decode::read_value(&mut cursor).unwrap();
            keys.push(key);
        }
        assert_eq!(keys, vec!["p", "p1s", "p2", "p2s", "ps", "s"]);
    }

    // ── Credential encoding tests ────────────────────────────────────────

    #[test]
    fn credential_encoding_empty() {
        let cred = UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]);
        let encoded = encode_unauthenticated_credential(&cred);
        assert_eq!(encoded, vec![0x80]); // fixmap(0)
    }

    #[test]
    fn credential_encoding_with_proof() {
        let cred = UnauthenticatedCredential::new([0xaa; VRF_PROOF_SIZE]);
        let encoded = encode_unauthenticated_credential(&cred);
        assert_eq!(encoded[0], 0x81); // fixmap(1)
    }

    #[test]
    fn credential_roundtrip() {
        let cred = UnauthenticatedCredential::new([0xbb; VRF_PROOF_SIZE]);
        let encoded = encode_unauthenticated_credential(&cred);
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = decode_unauthenticated_credential(&mut cursor).unwrap();
        assert_eq!(decoded.proof, [0xbb; VRF_PROOF_SIZE]);
    }

    /// Issue #2063: `[N]byte` fields decode like go's `ReadExactBytes`
    /// (bin/str/nil/uint8-array, `min(len, N)` copy, no length check). The
    /// old strict `bin`-of-exact-length reader rejected all of these.
    #[test]
    fn fixed_byte_fields_decode_like_go_read_exact_bytes() {
        let decode = |pf: &[u8]| {
            let mut enc = vec![0x81, 0xa2, b'p', b'f'];
            enc.extend_from_slice(pf);
            let mut cursor = Cursor::new(enc.as_slice());
            decode_unauthenticated_credential(&mut cursor).map(|c| c.proof)
        };
        let mut want = [0u8; VRF_PROOF_SIZE];
        want[0] = 1;
        want[1] = 2;
        // short bin, short str, short array: tail stays zero
        assert_eq!(decode(&[0xc4, 2, 1, 2]).unwrap(), want);
        assert_eq!(decode(&[0xa2, 1, 2]).unwrap(), want);
        assert_eq!(decode(&[0x92, 1, 2]).unwrap(), want);
        // nil -> zeroed
        assert_eq!(decode(&[0xc0]).unwrap(), [0u8; VRF_PROOF_SIZE]);
        // long bin is truncated
        let mut long = vec![0xc4, (VRF_PROOF_SIZE + 3) as u8];
        long.extend((0..VRF_PROOF_SIZE + 3).map(|i| i as u8));
        let got = decode(&long).unwrap();
        assert_eq!(got[VRF_PROOF_SIZE - 1], (VRF_PROOF_SIZE - 1) as u8);
        // go still rejects a non-container
        assert!(decode(&[0x05]).is_err());
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn vote_empty_encodes_to_empty_map() {
        let vote = UnauthenticatedVote::default();
        let encoded = encode_vote(&vote);
        // All fields are zero, so the outer map should be empty
        assert_eq!(encoded, vec![0x80]); // fixmap(0)
    }

    #[test]
    fn bundle_empty_encodes_to_empty_map() {
        let bundle = UnauthenticatedBundle::default();
        let encoded = encode_bundle(&bundle);
        assert_eq!(encoded, vec![0x80]); // fixmap(0)
    }

    #[test]
    fn proposal_value_max_period() {
        let pv = ProposalValue {
            original_period: Period(u64::MAX),
            original_proposer: Address([0u8; 32]),
            block_digest: Digest([0u8; 32]),
            encoding_digest: Digest([0u8; 32]),
        };
        let encoded = encode_proposal_value(&pv);
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = decode_proposal_value(&mut cursor).unwrap();
        assert_eq!(decoded.original_period, Period(u64::MAX));
    }

    #[test]
    fn vote_field_order_matches_go() {
        // Go's unauthenticatedVote codec tags sorted: "cred", "r", "sig"
        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(1),
                period: Period(0),
                step: Step(1),
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0xff; VRF_PROOF_SIZE]),
            sig: make_nonzero_sig(),
        };

        let encoded = encode_vote(&vote);
        let mut cursor = Cursor::new(encoded.as_slice());
        let map_len = rmp::decode::read_map_len(&mut cursor).unwrap();

        let mut keys = Vec::new();
        for _ in 0..map_len {
            let key = read_str_key(&mut cursor).unwrap();
            rmpv::decode::read_value(&mut cursor).unwrap();
            keys.push(key);
        }
        assert_eq!(keys, vec!["cred", "r", "sig"]);
    }

    #[test]
    fn bundle_field_order_matches_go() {
        // Go's unauthenticatedBundle codec tags sorted: "eqv", "per", "prop", "rnd", "step", "vote"
        let bundle = UnauthenticatedBundle {
            round: Round(1),
            period: Period(1),
            step: Step(1),
            proposal: ProposalValue {
                original_period: Period(1),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![VoteAuthenticator {
                sender: Address([0x01; 32]),
                cred: UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
                sig: make_zero_sig(),
            }],
            equivocation_votes: vec![EquivocationVoteAuthenticator {
                sender: Address([0x01; 32]),
                cred: UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
                sigs: [make_zero_sig(), make_zero_sig()],
                proposals: [BOTTOM, BOTTOM],
            }],
        };

        let encoded = encode_bundle(&bundle);
        let mut cursor = Cursor::new(encoded.as_slice());
        let map_len = rmp::decode::read_map_len(&mut cursor).unwrap();

        let mut keys = Vec::new();
        for _ in 0..map_len {
            let key = read_str_key(&mut cursor).unwrap();
            rmpv::decode::read_value(&mut cursor).unwrap();
            keys.push(key);
        }
        assert_eq!(keys, vec!["eqv", "per", "prop", "rnd", "step", "vote"]);
    }

    #[test]
    fn vote_authenticator_field_order() {
        let auth = VoteAuthenticator {
            sender: Address([0x01; 32]),
            cred: UnauthenticatedCredential::new([0xff; VRF_PROOF_SIZE]),
            sig: make_nonzero_sig(),
        };

        let encoded = encode_vote_authenticator(&auth);
        let mut cursor = Cursor::new(encoded.as_slice());
        let map_len = rmp::decode::read_map_len(&mut cursor).unwrap();

        let mut keys = Vec::new();
        for _ in 0..map_len {
            let key = read_str_key(&mut cursor).unwrap();
            rmpv::decode::read_value(&mut cursor).unwrap();
            keys.push(key);
        }
        assert_eq!(keys, vec!["cred", "sig", "snd"]);
    }

    #[test]
    fn vote_authenticator_zero_sig_omitted() {
        let auth = VoteAuthenticator {
            sender: Address([0x01; 32]),
            cred: UnauthenticatedCredential::new([0xff; VRF_PROOF_SIZE]),
            sig: make_zero_sig(),
        };

        let encoded = encode_vote_authenticator(&auth);
        let mut cursor = Cursor::new(encoded.as_slice());
        let map_len = rmp::decode::read_map_len(&mut cursor).unwrap();

        let mut keys = Vec::new();
        for _ in 0..map_len {
            let key = read_str_key(&mut cursor).unwrap();
            rmpv::decode::read_value(&mut cursor).unwrap();
            keys.push(key);
        }
        // sig omitted when zero (omitemptycheckstruct)
        assert_eq!(keys, vec!["cred", "snd"]);
    }

    #[test]
    fn equivocation_vote_authenticator_roundtrip() {
        let auth = EquivocationVoteAuthenticator {
            sender: Address([0x05; 32]),
            cred: UnauthenticatedCredential::new([0x55; VRF_PROOF_SIZE]),
            sigs: [make_nonzero_sig(), make_nonzero_sig()],
            proposals: [
                ProposalValue {
                    original_period: Period(1),
                    original_proposer: Address([0x05; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
                ProposalValue {
                    original_period: Period(2),
                    original_proposer: Address([0x05; 32]),
                    block_digest: Digest([0xcc; 32]),
                    encoding_digest: Digest([0xdd; 32]),
                },
            ],
        };

        let encoded = encode_equivocation_vote_authenticator(&auth);
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = decode_equivocation_vote_authenticator(&mut cursor).unwrap();

        assert_eq!(decoded.sender, Address([0x05; 32]));
        assert_eq!(decoded.cred.proof, [0x55; VRF_PROOF_SIZE]);
        assert_eq!(decoded.proposals[0].original_period, Period(1));
        assert_eq!(decoded.proposals[1].original_period, Period(2));
        assert_eq!(decoded.proposals[0].block_digest, Digest([0xaa; 32]));
        assert_eq!(decoded.proposals[1].block_digest, Digest([0xcc; 32]));
    }

    #[test]
    fn decode_vote_unknown_fields_rejected() {
        // Build a valid vote encoding with an extra unknown field
        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(42),
                period: Period(0),
                step: Step(1),
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]),
            sig: make_zero_sig(),
        };

        // Encode normally, then manually inject an extra field
        // We'll do this by encoding a vote with extra keys
        let mut buf = Vec::new();
        // fixmap(2): "r" + "zzz" (unknown field)
        buf.push(0x82);
        write_str_key(&mut buf, "r");
        buf.extend_from_slice(&encode_raw_vote(&vote.raw_vote));
        write_str_key(&mut buf, "zzz");
        rmp::encode::write_uint(&mut buf, 999).unwrap();

        // go's msgp decoder: msgp.ErrNoField (issue #2394)
        let err = decode_vote(&buf).expect_err("unknown fields are rejected");
        assert!(err.to_string().contains("zzz"), "{err}");
    }

    // ── Compound message round-trip tests ────────────────────────────────

    #[test]
    fn compound_message_roundtrip_no_prior_vote() {
        // A compound message with only a proposal (no prior vote).
        let cm = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(42),
                    genesis_id: "test-v1".to_string(),
                    ..algo_types::Block::default()
                },
                seed_proof: [0xab; VRF_PROOF_SIZE],
                original_period: Period(1),
                original_proposer: Address([0x01; 32]),
                ..UnauthenticatedProposal::default()
            },
        };

        let encoded = encode_compound_message(&cm);
        let decoded = decode_compound_message(&encoded).expect("decode should succeed");

        assert_eq!(decoded.proposal.block.round, Round(42));
        assert_eq!(decoded.proposal.block.genesis_id, "test-v1");
        assert_eq!(decoded.proposal.seed_proof, [0xab; VRF_PROOF_SIZE]);
        assert_eq!(decoded.proposal.original_period, Period(1));
        assert_eq!(decoded.proposal.original_proposer, Address([0x01; 32]));
        // Prior vote should be default (empty)
        assert_eq!(decoded.vote.raw_vote.round, Round(0));
    }

    #[test]
    fn compound_message_roundtrip_with_prior_vote() {
        // A compound message with both a proposal and a prior vote.
        let cm = CompoundMessage {
            vote: UnauthenticatedVote {
                raw_vote: RawVote {
                    sender: Address([0x42; 32]),
                    round: Round(100),
                    period: Period(1),
                    step: Step(2),
                    proposal: ProposalValue {
                        original_period: Period(1),
                        original_proposer: Address([0x42; 32]),
                        block_digest: Digest([0xaa; 32]),
                        encoding_digest: Digest([0xbb; 32]),
                    },
                },
                cred: UnauthenticatedCredential::new([0xcc; VRF_PROOF_SIZE]),
                sig: make_nonzero_sig(),
            },
            proposal: UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(100),
                    genesis_id: "roundtrip-test".to_string(),
                    timestamp: 12345,
                    ..algo_types::Block::default()
                },
                seed_proof: [0xdd; VRF_PROOF_SIZE],
                original_period: Period(0),
                original_proposer: Address([0x99; 32]),
                ..UnauthenticatedProposal::default()
            },
        };

        let encoded = encode_compound_message(&cm);
        let decoded = decode_compound_message(&encoded).expect("decode should succeed");

        // Verify proposal
        assert_eq!(decoded.proposal.block.round, Round(100));
        assert_eq!(decoded.proposal.block.genesis_id, "roundtrip-test");
        assert_eq!(decoded.proposal.block.timestamp, 12345);
        assert_eq!(decoded.proposal.seed_proof, [0xdd; VRF_PROOF_SIZE]);
        assert_eq!(decoded.proposal.original_period, Period(0));
        assert_eq!(decoded.proposal.original_proposer, Address([0x99; 32]));

        // Verify prior vote
        assert_eq!(decoded.vote.raw_vote.sender, Address([0x42; 32]));
        assert_eq!(decoded.vote.raw_vote.round, Round(100));
        assert_eq!(decoded.vote.raw_vote.period, Period(1));
        assert_eq!(decoded.vote.raw_vote.step, Step(2));
        assert_eq!(
            decoded.vote.raw_vote.proposal.block_digest,
            Digest([0xaa; 32])
        );
        assert_eq!(decoded.vote.cred.proof, [0xcc; VRF_PROOF_SIZE]);
        assert_eq!(decoded.vote.sig.sig, [0x11; 64]);
    }

    #[test]
    fn compound_message_roundtrip_minimal() {
        // A compound message with a minimal block (round 0 must still be
        // encoded because Block::decode_from_bytes requires the "rnd" field).
        let cm = CompoundMessage {
            vote: UnauthenticatedVote::default(),
            proposal: UnauthenticatedProposal {
                block: algo_types::Block {
                    round: Round(1), // Ensure "rnd" is emitted.
                    ..algo_types::Block::default()
                },
                seed_proof: [0u8; VRF_PROOF_SIZE],
                original_period: Period(0),
                original_proposer: Address([0u8; 32]),
                ..UnauthenticatedProposal::default()
            },
        };
        let encoded = encode_compound_message(&cm);
        let decoded = decode_compound_message(&encoded).expect("decode should succeed");

        assert_eq!(decoded.proposal.block.round, Round(1));
        assert_eq!(decoded.proposal.original_period, Period(0));
        assert_eq!(decoded.proposal.original_proposer, Address([0u8; 32]));
        assert_eq!(decoded.proposal.seed_proof, [0u8; VRF_PROOF_SIZE]);
        assert_eq!(decoded.vote.raw_vote.round, Round(0));
    }
}

/// The allocation-free key reader and skipper against the `rmpv` reference
/// they replaced (issue #2317): same accepted inputs, same bytes consumed.
#[cfg(test)]
mod skip_tests {
    use super::*;

    /// xorshift64*: deterministic, no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random bytes biased towards msgpack markers with small lengths, so
    /// that a good share of the buffers are complete values.
    fn random_buf(rng: &mut Rng) -> Vec<u8> {
        const MARKERS: &[u8] = &[
            0x00, 0x7f, 0x80, 0x81, 0x82, 0x90, 0x91, 0x93, 0xa0, 0xa1, 0xa3, 0xc0, 0xc1, 0xc2,
            0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
            0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
            0xdf, 0xe0, 0xff,
        ];
        let len = rng.below(48) as usize;
        (0..len)
            .map(|_| match rng.below(4) {
                0 => MARKERS[rng.below(MARKERS.len() as u64) as usize],
                1 => rng.below(4) as u8,
                2 => b'a' + rng.below(26) as u8,
                _ => rng.next() as u8,
            })
            .collect()
    }

    fn container_depth(v: &rmpv::Value) -> usize {
        match v {
            rmpv::Value::Array(a) => 1 + a.iter().map(container_depth).max().unwrap_or(0),
            rmpv::Value::Map(m) => {
                1 + m
                    .iter()
                    .map(|(k, v)| container_depth(k).max(container_depth(v)))
                    .max()
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// `rmpv`'s verdict on the value at the start of `buf`.
    fn reference(buf: &[u8]) -> Option<(rmpv::Value, usize)> {
        let mut c = Cursor::new(buf);
        let v = rmpv::decode::read_value(&mut c).ok()?;
        Some((v, c.position() as usize))
    }

    fn check_skip(buf: &[u8]) {
        let fast = fast_skip_len(buf);
        match (fast, reference(buf)) {
            (Some(n), Some((_, consumed))) => assert_eq!(n, consumed, "length of {buf:02x?}"),
            (Some(n), None) => panic!("fast skip took {n} bytes of {buf:02x?}, rmpv rejects it"),
            // The fast path only declines a value rmpv accepts when it is
            // nested too deep or holds the reserved marker 0xc1 (which rmpv
            // reads as nil): both are left to rmpv. A 0xc1 in marker position
            // is told from one inside a payload by turning every 0xc1 into
            // nil: only the former makes the fast path take the value.
            (None, Some((v, consumed))) => {
                let as_nil: Vec<u8> = buf
                    .iter()
                    .map(|&b| if b == 0xc1 { 0xc0 } else { b })
                    .collect();
                assert!(
                    container_depth(&v) > FAST_SKIP_MAX_DEPTH
                        || fast_skip_len(&as_nil) == Some(consumed),
                    "fast skip refused {buf:02x?}, which rmpv accepts"
                );
            }
            (None, None) => {}
        }
    }

    #[test]
    fn fast_skip_agrees_with_rmpv_on_random_input() {
        let mut rng = Rng(0x2317_2317_2317_2317);
        let mut complete = 0;
        for _ in 0..200_000 {
            let buf = random_buf(&mut rng);
            if fast_skip_len(&buf).is_some() {
                complete += 1;
            }
            check_skip(&buf);
        }
        assert!(complete > 10_000, "only {complete} complete values tried");
    }

    #[test]
    fn deep_nesting_is_left_to_rmpv() {
        // One level past the fast limit: still accepted (rmpv's limit is far
        // higher), through the fallback.
        let mut buf = vec![0x91u8; FAST_SKIP_MAX_DEPTH + 1];
        buf.push(0x01);
        assert_eq!(fast_skip_len(&buf), None);
        check_skip(&buf);
        // Exactly at the limit: fast path.
        let mut buf = vec![0x91u8; FAST_SKIP_MAX_DEPTH];
        buf.push(0x01);
        assert_eq!(fast_skip_len(&buf), Some(buf.len()));
        check_skip(&buf);
    }

    #[test]
    fn skip_stops_at_the_end_of_the_value() {
        // {"a": [1, "xy"], "b": bin(2)} followed by a trailing byte.
        let buf = [
            0x82, 0xa1, b'a', 0x92, 0x01, 0xa2, b'x', b'y', 0xa1, b'b', 0xc4, 2, 9, 9, 0x7f,
        ];
        assert_eq!(fast_skip_len(&buf), Some(buf.len() - 1));
        check_skip(&buf);
    }
}
