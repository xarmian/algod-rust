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
use algo_types::{Address, Block, Digest, Round};

use crate::bundle::{EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator};
use crate::credential::{Credential, HashableCredential, UnauthenticatedCredential};
use crate::events::CompoundMessage;
use crate::proposal::UnauthenticatedProposal;
use crate::step::{Period, Step};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, Vote, BOTTOM};
use crate::vote_tracker::EquivocationVote;
use crate::VRF_PROOF_SIZE;

/// Size of the VRF output (vrf_out `raw_out` inside hashableCredential) in bytes.
const VRF_OUTPUT_SIZE: usize = 64;

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

    // sig has omitemptycheckstruct; check if both sigs are zero
    let sigs_zero = ots_is_zero(&auth.sigs[0]) && ots_is_zero(&auth.sigs[1]);

    let mut count: u8 = 3; // cred, props, snd always present
    if !sigs_zero {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Fields sorted: "cred", "props", "sig", "snd"
    write_str_key(&mut buf, "cred");
    buf.extend_from_slice(&encode_unauthenticated_credential(&auth.cred));

    write_str_key(&mut buf, "props");
    // [2]proposalValue -> fixarray(2)
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    buf.extend_from_slice(&encode_proposal_value(&auth.proposals[0]));
    buf.extend_from_slice(&encode_proposal_value(&auth.proposals[1]));

    if !sigs_zero {
        write_str_key(&mut buf, "sig");
        // [2]OneTimeSignature -> fixarray(2)
        rmp::encode::write_array_len(&mut buf, 2).unwrap();
        buf.extend_from_slice(&encode_one_time_signature(&auth.sigs[0]));
        buf.extend_from_slice(&encode_one_time_signature(&auth.sigs[1]));
    }

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
/// 1. Decode the bytes as a `Block` via `Block::decode_from_bytes` (which
///    skips unknown keys like `oper`, `oprop`, `sdpf`, `pv`).
/// 2. Scan the map a second time to extract the proposal-specific fields
///    (`oper`, `oprop`, `sdpf`) and the optional prior vote (`pv`).
pub fn decode_compound_message(bytes: &[u8]) -> Result<CompoundMessage, CodecError> {
    // Step 1: Decode block fields (skips unknown keys). Use the
    // rnd-tolerant wrapper so transmittedPayload fixtures with
    // round=0 (which omit the `rnd` key via omitempty) still parse.
    let block = decode_block_allowing_missing_rnd(bytes)?;

    // Step 2: Scan the map to extract proposal-specific fields and prior vote.
    let mut cursor = Cursor::new(bytes);
    let map_len = rmp::decode::read_map_len(&mut cursor)
        .map_err(|e| CodecError::Decode(format!("compound message map: {e}")))?;

    let mut original_period = Period(0);
    let mut original_proposer = Address([0u8; 32]);
    let mut seed_proof = [0u8; VRF_PROOF_SIZE];
    let mut prior_vote = UnauthenticatedVote::default();

    for _ in 0..map_len {
        let key = read_str_key(&mut cursor)?;
        match key.as_str() {
            "oper" => original_period = Period(read_uint64(&mut cursor)?),
            "oprop" => original_proposer = Address(read_bin_fixed::<32>(&mut cursor)?),
            "sdpf" => seed_proof = read_bin_fixed::<VRF_PROOF_SIZE>(&mut cursor)?,
            "pv" => prior_vote = decode_vote_from_cursor(&mut cursor)?,
            _ => {
                // Skip all block fields and any other unknown fields.
                rmpv::decode::read_value(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(CompoundMessage {
        vote: prior_vote,
        proposal: UnauthenticatedProposal {
            block,
            seed_proof,
            original_period,
            original_proposer,
        },
    })
}

// ── Decoding helpers ─────────────────────────────────────────────────────

/// Read a msgpack string key from cursor.
fn read_str_key(cursor: &mut Cursor<&[u8]>) -> Result<String, CodecError> {
    let val =
        rmpv::decode::read_value(cursor).map_err(|e| CodecError::Decode(format!("key: {e}")))?;
    match val {
        rmpv::Value::String(s) => s
            .into_str()
            .ok_or_else(|| CodecError::Format("key is not valid UTF-8".into())),
        _ => Err(CodecError::Format(format!(
            "expected string key, got {val:?}"
        ))),
    }
}

/// Read a uint64 value from cursor.
fn read_uint64(cursor: &mut Cursor<&[u8]>) -> Result<u64, CodecError> {
    let val =
        rmpv::decode::read_value(cursor).map_err(|e| CodecError::Decode(format!("uint: {e}")))?;
    match val {
        rmpv::Value::Integer(i) => i
            .as_u64()
            .ok_or_else(|| CodecError::Format("integer is not u64".into())),
        _ => Err(CodecError::Format(format!("expected uint, got {val:?}"))),
    }
}

/// Read a binary value and copy into a fixed-size array.
fn read_bin_fixed<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], CodecError> {
    let val =
        rmpv::decode::read_value(cursor).map_err(|e| CodecError::Decode(format!("bin: {e}")))?;
    match val {
        rmpv::Value::Binary(b) => {
            if b.len() != N {
                return Err(CodecError::Format(format!(
                    "expected {N} bytes, got {}",
                    b.len()
                )));
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(&b);
            Ok(arr)
        }
        _ => Err(CodecError::Format(format!("expected binary, got {val:?}"))),
    }
}

/// Read a msgpack bool value.
fn read_bool(cursor: &mut Cursor<&[u8]>) -> Result<bool, CodecError> {
    let val =
        rmpv::decode::read_value(cursor).map_err(|e| CodecError::Decode(format!("bool: {e}")))?;
    match val {
        rmpv::Value::Boolean(b) => Ok(b),
        _ => Err(CodecError::Format(format!("expected bool, got {val:?}"))),
    }
}

/// Decode a ProposalValue from cursor position.
fn decode_proposal_value(cursor: &mut Cursor<&[u8]>) -> Result<ProposalValue, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("proposal value map: {e}")))?;

    let mut pv = BOTTOM;
    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "dig" => pv.block_digest = Digest(read_bin_fixed::<32>(cursor)?),
            "encdig" => pv.encoding_digest = Digest(read_bin_fixed::<32>(cursor)?),
            "oper" => pv.original_period = Period(read_uint64(cursor)?),
            "oprop" => pv.original_proposer = Address(read_bin_fixed::<32>(cursor)?),
            _ => {
                // Skip unknown field
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(pv)
}

/// Decode a RawVote from cursor position.
fn decode_raw_vote(cursor: &mut Cursor<&[u8]>) -> Result<RawVote, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("raw vote map: {e}")))?;

    let mut rv = RawVote {
        sender: Address([0u8; 32]),
        round: Round(0),
        period: Period(0),
        step: Step(0),
        proposal: BOTTOM,
    };

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "per" => rv.period = Period(read_uint64(cursor)?),
            "prop" => rv.proposal = decode_proposal_value(cursor)?,
            "rnd" => rv.round = Round(read_uint64(cursor)?),
            "snd" => rv.sender = Address(read_bin_fixed::<32>(cursor)?),
            "step" => rv.step = Step(read_uint64(cursor)?),
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(rv)
}

/// Decode an UnauthenticatedCredential from cursor position.
fn decode_unauthenticated_credential(
    cursor: &mut Cursor<&[u8]>,
) -> Result<UnauthenticatedCredential, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("credential map: {e}")))?;

    let mut proof = [0u8; VRF_PROOF_SIZE];

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "pf" => proof = read_bin_fixed::<VRF_PROOF_SIZE>(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(UnauthenticatedCredential::new(proof))
}

/// Decode a OneTimeSignature from cursor position.
fn decode_one_time_signature(cursor: &mut Cursor<&[u8]>) -> Result<OneTimeSignature, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("OTS map: {e}")))?;

    let mut sig = OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    };

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "p" => sig.pk = read_bin_fixed::<32>(cursor)?,
            "p1s" => sig.pk1_sig = read_bin_fixed::<64>(cursor)?,
            "p2" => sig.pk2 = read_bin_fixed::<32>(cursor)?,
            "p2s" => sig.pk2_sig = read_bin_fixed::<64>(cursor)?,
            "ps" => sig.pk_sig_old = read_bin_fixed::<64>(cursor)?,
            "s" => sig.sig = read_bin_fixed::<64>(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(sig)
}

/// Decode an UnauthenticatedVote from wire-format msgpack bytes.
pub fn decode_vote(bytes: &[u8]) -> Result<UnauthenticatedVote, CodecError> {
    let mut cursor = Cursor::new(bytes);
    decode_vote_from_cursor(&mut cursor)
}

/// Decode an UnauthenticatedVote from cursor position.
fn decode_vote_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<UnauthenticatedVote, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("vote map: {e}")))?;

    let mut vote = UnauthenticatedVote::default();

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "cred" => vote.cred = decode_unauthenticated_credential(cursor)?,
            "r" => vote.raw_vote = decode_raw_vote(cursor)?,
            "sig" => vote.sig = decode_one_time_signature(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(vote)
}

/// Decode a VoteAuthenticator from cursor position.
fn decode_vote_authenticator(cursor: &mut Cursor<&[u8]>) -> Result<VoteAuthenticator, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("vote auth map: {e}")))?;

    let mut sender = Address([0u8; 32]);
    let mut cred = UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]);
    let mut sig = OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    };

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "cred" => cred = decode_unauthenticated_credential(cursor)?,
            "sig" => sig = decode_one_time_signature(cursor)?,
            "snd" => sender = Address(read_bin_fixed::<32>(cursor)?),
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(VoteAuthenticator { sender, cred, sig })
}

/// Decode an EquivocationVoteAuthenticator from cursor position.
fn decode_equivocation_vote_authenticator(
    cursor: &mut Cursor<&[u8]>,
) -> Result<EquivocationVoteAuthenticator, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("equivocation auth map: {e}")))?;

    let mut sender = Address([0u8; 32]);
    let mut cred = UnauthenticatedCredential::new([0u8; VRF_PROOF_SIZE]);
    let mut sigs = [
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        },
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        },
    ];
    let mut proposals = [BOTTOM, BOTTOM];

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "cred" => cred = decode_unauthenticated_credential(cursor)?,
            "props" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("props array: {e}")))?;
                if arr_len != 2 {
                    return Err(CodecError::Format(format!(
                        "expected 2 proposals, got {arr_len}"
                    )));
                }
                proposals[0] = decode_proposal_value(cursor)?;
                proposals[1] = decode_proposal_value(cursor)?;
            }
            "sig" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("sig array: {e}")))?;
                if arr_len != 2 {
                    return Err(CodecError::Format(format!(
                        "expected 2 signatures, got {arr_len}"
                    )));
                }
                sigs[0] = decode_one_time_signature(cursor)?;
                sigs[1] = decode_one_time_signature(cursor)?;
            }
            "snd" => sender = Address(read_bin_fixed::<32>(cursor)?),
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(EquivocationVoteAuthenticator {
        sender,
        cred,
        sigs,
        proposals,
    })
}

/// Decode an UnauthenticatedBundle from wire-format msgpack bytes.
pub fn decode_bundle(bytes: &[u8]) -> Result<UnauthenticatedBundle, CodecError> {
    // Go uses allocbound=bounds.MaxVoteThreshold which is typically 10_000.
    const MAX_BUNDLE_ARRAY_LEN: u32 = 10_000;

    let mut cursor = Cursor::new(bytes);
    let map_len = rmp::decode::read_map_len(&mut cursor)
        .map_err(|e| CodecError::Decode(format!("bundle map: {e}")))?;

    let mut bundle = UnauthenticatedBundle::default();

    for _ in 0..map_len {
        let key = read_str_key(&mut cursor)?;
        match key.as_str() {
            "eqv" => {
                let arr_len = rmp::decode::read_array_len(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("eqv array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "eqv array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut evs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    evs.push(decode_equivocation_vote_authenticator(&mut cursor)?);
                }
                bundle.equivocation_votes = evs;
            }
            "per" => bundle.period = Period(read_uint64(&mut cursor)?),
            "prop" => bundle.proposal = decode_proposal_value(&mut cursor)?,
            "rnd" => bundle.round = Round(read_uint64(&mut cursor)?),
            "step" => bundle.step = Step(read_uint64(&mut cursor)?),
            "vote" => {
                let arr_len = rmp::decode::read_array_len(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("vote array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "vote array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut vs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    vs.push(decode_vote_authenticator(&mut cursor)?);
                }
                bundle.votes = vs;
            }
            _ => {
                rmpv::decode::read_value(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

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

// ── committee.Credential / hashableCredential wire codec ────────────────
//
// `committee.Credential` wraps `UnauthenticatedCredential` (providing `pf`)
// with verified fields `wt`, `h`, `ds`, and `hc`. The embedded
// `UnauthenticatedCredential` is flattened into the outer map by Go's
// msgpack generator, so the wire shape is a single map with fields
// sorted alphabetically by codec tag:
//
//   "ds" -> DomainSeparationEnabled (bool)
//   "h"  -> VrfOut (crypto.Digest, bin32)
//   "hc" -> Hashable (hashableCredential sub-map)
//   "pf" -> Proof (crypto.VrfProof, bin80)  — from embedded UnauthenticatedCredential
//   "wt" -> Weight (uint64)
//
// All fields are `omitempty` (`codec:",omitempty,omitemptyarray"` at the
// struct level). Reference: `../go-algorand/data/committee/credential.go`.

/// Encode a `hashableCredential` sub-map.
///
/// Fields (sorted, `omitempty`):
///   "i" -> Iter (uint64)
///   "m" -> Member (Address, bin32)
///   "v" -> RawOut (VrfOutput, bin64)
fn encode_hashable_credential_wire(hc: &HashableCredential) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    let iter_empty = hc.iter == 0;
    let m_empty = hc.member.0 == [0u8; 32];
    let v_empty = hc.raw_out == [0u8; VRF_OUTPUT_SIZE];

    let mut count: u8 = 0;
    if !iter_empty {
        count += 1;
    }
    if !m_empty {
        count += 1;
    }
    if !v_empty {
        count += 1;
    }

    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    if !iter_empty {
        write_str_key(&mut buf, "i");
        rmp::encode::write_uint(&mut buf, hc.iter).unwrap();
    }
    if !m_empty {
        write_str_key(&mut buf, "m");
        rmp::encode::write_bin(&mut buf, &hc.member.0).unwrap();
    }
    if !v_empty {
        write_str_key(&mut buf, "v");
        rmp::encode::write_bin(&mut buf, &hc.raw_out).unwrap();
    }

    buf
}

/// Decode a `hashableCredential` sub-map from cursor.
fn decode_hashable_credential_from_cursor(
    cursor: &mut Cursor<&[u8]>,
) -> Result<HashableCredential, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("hashable cred map: {e}")))?;

    let mut hc = HashableCredential::default();

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "i" => hc.iter = read_uint64(cursor)?,
            "m" => hc.member = Address(read_bin_fixed::<32>(cursor)?),
            "v" => hc.raw_out = read_bin_fixed::<VRF_OUTPUT_SIZE>(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(hc)
}

/// Encode a `committee.Credential` to canonical wire-format msgpack bytes.
pub fn encode_credential(cred: &Credential) -> Vec<u8> {
    let hc_encoded = encode_hashable_credential_wire(&cred.hashable);

    let ds_empty = !cred.domain_separation_enabled;
    let h_empty = cred.vrf_out.0 == [0u8; 32];
    let hc_empty = hc_encoded == [0x80];
    let pf_empty = cred.proof == [0u8; VRF_PROOF_SIZE];
    let wt_empty = cred.weight == 0;

    let mut count: u8 = 0;
    if !ds_empty {
        count += 1;
    }
    if !h_empty {
        count += 1;
    }
    if !hc_empty {
        count += 1;
    }
    if !pf_empty {
        count += 1;
    }
    if !wt_empty {
        count += 1;
    }

    let mut buf = Vec::with_capacity(192);
    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Fields sorted: "ds", "h", "hc", "pf", "wt"
    if !ds_empty {
        write_str_key(&mut buf, "ds");
        rmp::encode::write_bool(&mut buf, cred.domain_separation_enabled).unwrap();
    }
    if !h_empty {
        write_str_key(&mut buf, "h");
        rmp::encode::write_bin(&mut buf, &cred.vrf_out.0).unwrap();
    }
    if !hc_empty {
        write_str_key(&mut buf, "hc");
        buf.extend_from_slice(&hc_encoded);
    }
    if !pf_empty {
        write_str_key(&mut buf, "pf");
        rmp::encode::write_bin(&mut buf, &cred.proof).unwrap();
    }
    if !wt_empty {
        write_str_key(&mut buf, "wt");
        rmp::encode::write_uint(&mut buf, cred.weight).unwrap();
    }

    buf
}

/// Decode a `committee.Credential` from canonical wire-format msgpack bytes.
pub fn decode_credential(bytes: &[u8]) -> Result<Credential, CodecError> {
    let mut cursor = Cursor::new(bytes);
    decode_credential_from_cursor(&mut cursor)
}

fn decode_credential_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Credential, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("credential map: {e}")))?;

    let mut cred = Credential {
        weight: 0,
        vrf_out: Digest([0u8; 32]),
        domain_separation_enabled: false,
        hashable: HashableCredential::default(),
        proof: [0u8; VRF_PROOF_SIZE],
    };

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "ds" => cred.domain_separation_enabled = read_bool(cursor)?,
            "h" => cred.vrf_out = Digest(read_bin_fixed::<32>(cursor)?),
            "hc" => cred.hashable = decode_hashable_credential_from_cursor(cursor)?,
            "pf" => cred.proof = read_bin_fixed::<VRF_PROOF_SIZE>(cursor)?,
            "wt" => cred.weight = read_uint64(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(cred)
}

// ── authenticated Vote wire codec ────────────────────────────────────────
//
// Go's `agreement.vote` has the same top-level shape as
// `unauthenticatedVote` — fields sorted `"cred"`, `"r"`, `"sig"` —
// except `cred` is a full `committee.Credential` (not
// `UnauthenticatedCredential`). The struct carries an unserialized
// `validatedAt` field which is skipped by msgp.

/// Encode an authenticated `Vote` (with verified `committee.Credential`)
/// to canonical wire-format msgpack bytes. Matches Go's
/// `vote.MarshalMsg`.
pub fn encode_authenticated_vote(v: &Vote) -> Vec<u8> {
    let cred_encoded = encode_credential(&v.cred);
    let r_encoded = encode_raw_vote(&v.raw_vote);
    let sig_zero = ots_is_zero(&v.sig);

    let cred_empty = cred_encoded == [0x80];
    let r_empty = r_encoded == [0x80];

    let mut count: u8 = 0;
    if !cred_empty {
        count += 1;
    }
    if !r_empty {
        count += 1;
    }
    if !sig_zero {
        count += 1;
    }

    let mut buf = Vec::with_capacity(768);
    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

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
        buf.extend_from_slice(&encode_one_time_signature(&v.sig));
    }

    buf
}

/// Decode an authenticated `Vote` from canonical wire-format msgpack bytes.
pub fn decode_authenticated_vote(bytes: &[u8]) -> Result<Vote, CodecError> {
    let mut cursor = Cursor::new(bytes);
    decode_authenticated_vote_from_cursor(&mut cursor)
}

fn decode_authenticated_vote_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Vote, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("auth vote map: {e}")))?;

    let mut vote = Vote::default();

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "cred" => vote.cred = decode_credential_from_cursor(cursor)?,
            "r" => vote.raw_vote = decode_raw_vote(cursor)?,
            "sig" => vote.sig = decode_one_time_signature(cursor)?,
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(vote)
}

// ── authenticated equivocationVote wire codec ────────────────────────────
//
// Go's `agreement.equivocationVote` (full struct, not the bundle-level
// `equivocationVoteAuthenticator`) has fields sorted alphabetically:
//
//   "cred"  -> committee.Credential       (omitempty)
//   "per"   -> period                     (omitempty)
//   "props" -> [2]proposalValue           (always fixarray(2); entries are proposalValue sub-maps)
//   "rnd"   -> basics.Round               (omitempty)
//   "sigs"  -> [2]crypto.OneTimeSignature (always fixarray(2); entries are OTS sub-maps)
//   "snd"   -> basics.Address             (omitempty)
//   "step"  -> step                       (omitempty)
//
// Struct-level `codec:",omitempty,omitemptyarray"` only affects
// variable-length fields; `[2]T` arrays always emit a fixarray(2).

fn encode_equivocation_vote(ev: &EquivocationVote) -> Vec<u8> {
    let cred_encoded = encode_credential(&ev.cred);
    let cred_empty = cred_encoded == [0x80];
    let per_empty = ev.period.0 == 0;
    let rnd_empty = ev.round.0 == 0;
    let snd_empty = ev.sender.0 == [0u8; 32];
    let step_empty = ev.step.0 == 0;

    // props + sigs are always present (fixed-size arrays)
    let mut count: u8 = 2;
    if !cred_empty {
        count += 1;
    }
    if !per_empty {
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

    let mut buf = Vec::with_capacity(1024);
    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Sorted: "cred", "per", "props", "rnd", "sigs", "snd", "step"
    if !cred_empty {
        write_str_key(&mut buf, "cred");
        buf.extend_from_slice(&cred_encoded);
    }
    if !per_empty {
        write_str_key(&mut buf, "per");
        rmp::encode::write_uint(&mut buf, ev.period.0).unwrap();
    }

    write_str_key(&mut buf, "props");
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    buf.extend_from_slice(&encode_proposal_value(&ev.proposals[0]));
    buf.extend_from_slice(&encode_proposal_value(&ev.proposals[1]));

    if !rnd_empty {
        write_str_key(&mut buf, "rnd");
        rmp::encode::write_uint(&mut buf, ev.round.0).unwrap();
    }

    write_str_key(&mut buf, "sigs");
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    buf.extend_from_slice(&encode_one_time_signature(&ev.sigs[0]));
    buf.extend_from_slice(&encode_one_time_signature(&ev.sigs[1]));

    if !snd_empty {
        write_str_key(&mut buf, "snd");
        rmp::encode::write_bin(&mut buf, &ev.sender.0).unwrap();
    }
    if !step_empty {
        write_str_key(&mut buf, "step");
        rmp::encode::write_uint(&mut buf, ev.step.0).unwrap();
    }

    buf
}

fn decode_equivocation_vote_from_cursor(
    cursor: &mut Cursor<&[u8]>,
) -> Result<EquivocationVote, CodecError> {
    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("equivocation vote map: {e}")))?;

    let zero_sig = OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    };

    let mut ev = EquivocationVote {
        sender: Address([0u8; 32]),
        round: Round(0),
        period: Period(0),
        step: Step(0),
        cred: Credential {
            weight: 0,
            vrf_out: Digest([0u8; 32]),
            domain_separation_enabled: false,
            hashable: HashableCredential::default(),
            proof: [0u8; VRF_PROOF_SIZE],
        },
        proposals: [BOTTOM, BOTTOM],
        sigs: [zero_sig.clone(), zero_sig],
    };

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "cred" => ev.cred = decode_credential_from_cursor(cursor)?,
            "per" => ev.period = Period(read_uint64(cursor)?),
            "props" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("props array: {e}")))?;
                if arr_len != 2 {
                    return Err(CodecError::Format(format!(
                        "expected 2 proposals, got {arr_len}"
                    )));
                }
                ev.proposals[0] = decode_proposal_value(cursor)?;
                ev.proposals[1] = decode_proposal_value(cursor)?;
            }
            "rnd" => ev.round = Round(read_uint64(cursor)?),
            "sigs" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("sigs array: {e}")))?;
                if arr_len != 2 {
                    return Err(CodecError::Format(format!(
                        "expected 2 signatures, got {arr_len}"
                    )));
                }
                ev.sigs[0] = decode_one_time_signature(cursor)?;
                ev.sigs[1] = decode_one_time_signature(cursor)?;
            }
            "snd" => ev.sender = Address(read_bin_fixed::<32>(cursor)?),
            "step" => ev.step = Step(read_uint64(cursor)?),
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(ev)
}

// ── authenticated Bundle wire codec ──────────────────────────────────────
//
// Go's `agreement.bundle` (vs `unauthenticatedBundle`) wraps the
// unauthenticated form and attaches full `[]vote` / `[]equivocationVote`
// arrays (each carrying its own verified credential/signature) rather
// than the compressed `[]voteAuthenticator` /
// `[]equivocationVoteAuthenticator` that the unauthenticated form uses.
//
// Wire shape (all `omitempty`, sorted):
//   "eqv"  -> []equivocationVote
//   "u"    -> unauthenticatedBundle sub-map
//   "vote" -> []vote

/// Wire-level authenticated bundle mirroring Go's `agreement.bundle`.
///
/// This is a pure msgpack container for roundtrip parity — it does NOT
/// perform signature/credential verification. For verified-bundle
/// semantics (threshold checks, duplicate voter detection, etc.), see
/// [`crate::Bundle`] and [`UnauthenticatedBundle::verify`].
#[derive(Debug, Clone, Default)]
pub struct AuthenticatedBundle {
    /// The underlying unauthenticated bundle (round, period, step, proposal,
    /// plus the compressed authenticator arrays).
    pub u: UnauthenticatedBundle,
    /// Full authenticated votes (each carrying its own `RawVote`,
    /// `Credential`, and signature).
    pub votes: Vec<Vote>,
    /// Full authenticated equivocation votes (each with round/period/step,
    /// credential, pair of proposals, pair of signatures).
    pub equivocation_votes: Vec<EquivocationVote>,
}

/// Encode an authenticated bundle to canonical wire-format msgpack bytes.
pub fn encode_authenticated_bundle(b: &AuthenticatedBundle) -> Vec<u8> {
    let u_encoded = encode_bundle(&b.u);
    let u_empty = u_encoded == [0x80];
    let eqv_empty = b.equivocation_votes.is_empty();
    let vote_empty = b.votes.is_empty();

    let mut count: u8 = 0;
    if !eqv_empty {
        count += 1;
    }
    if !u_empty {
        count += 1;
    }
    if !vote_empty {
        count += 1;
    }

    let mut buf = Vec::with_capacity(2048);
    rmp::encode::write_map_len(&mut buf, count as u32).unwrap();

    // Sorted: "eqv", "u", "vote"
    if !eqv_empty {
        write_str_key(&mut buf, "eqv");
        rmp::encode::write_array_len(&mut buf, b.equivocation_votes.len() as u32).unwrap();
        for ev in &b.equivocation_votes {
            buf.extend_from_slice(&encode_equivocation_vote(ev));
        }
    }
    if !u_empty {
        write_str_key(&mut buf, "u");
        buf.extend_from_slice(&u_encoded);
    }
    if !vote_empty {
        write_str_key(&mut buf, "vote");
        rmp::encode::write_array_len(&mut buf, b.votes.len() as u32).unwrap();
        for v in &b.votes {
            buf.extend_from_slice(&encode_authenticated_vote(v));
        }
    }

    buf
}

/// Decode an authenticated bundle from canonical wire-format msgpack bytes.
pub fn decode_authenticated_bundle(bytes: &[u8]) -> Result<AuthenticatedBundle, CodecError> {
    // Same alloc bound as `decode_bundle`.
    const MAX_BUNDLE_ARRAY_LEN: u32 = 10_000;

    let mut cursor = Cursor::new(bytes);
    let map_len = rmp::decode::read_map_len(&mut cursor)
        .map_err(|e| CodecError::Decode(format!("auth bundle map: {e}")))?;

    let mut ab = AuthenticatedBundle::default();

    for _ in 0..map_len {
        let key = read_str_key(&mut cursor)?;
        match key.as_str() {
            "eqv" => {
                let arr_len = rmp::decode::read_array_len(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("eqv array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "eqv array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut evs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    evs.push(decode_equivocation_vote_from_cursor(&mut cursor)?);
                }
                ab.equivocation_votes = evs;
            }
            "u" => {
                // The unauthenticated bundle is an inline sub-map; decode
                // it by delegating to the existing cursor-aware logic.
                ab.u = decode_unauthenticated_bundle_from_cursor(&mut cursor)?;
            }
            "vote" => {
                let arr_len = rmp::decode::read_array_len(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("vote array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "vote array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut vs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    vs.push(decode_authenticated_vote_from_cursor(&mut cursor)?);
                }
                ab.votes = vs;
            }
            _ => {
                rmpv::decode::read_value(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(ab)
}

/// Decode an `UnauthenticatedBundle` from the current cursor position
/// (as opposed to a standalone byte slice). Used when a bundle appears
/// as a nested sub-map (e.g., the `"u"` field of `AuthenticatedBundle`).
fn decode_unauthenticated_bundle_from_cursor(
    cursor: &mut Cursor<&[u8]>,
) -> Result<UnauthenticatedBundle, CodecError> {
    const MAX_BUNDLE_ARRAY_LEN: u32 = 10_000;

    let map_len = rmp::decode::read_map_len(cursor)
        .map_err(|e| CodecError::Decode(format!("unauth bundle map: {e}")))?;

    let mut bundle = UnauthenticatedBundle::default();

    for _ in 0..map_len {
        let key = read_str_key(cursor)?;
        match key.as_str() {
            "eqv" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("eqv array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "eqv array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut evs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    evs.push(decode_equivocation_vote_authenticator(cursor)?);
                }
                bundle.equivocation_votes = evs;
            }
            "per" => bundle.period = Period(read_uint64(cursor)?),
            "prop" => bundle.proposal = decode_proposal_value(cursor)?,
            "rnd" => bundle.round = Round(read_uint64(cursor)?),
            "step" => bundle.step = Step(read_uint64(cursor)?),
            "vote" => {
                let arr_len = rmp::decode::read_array_len(cursor)
                    .map_err(|e| CodecError::Decode(format!("vote array: {e}")))?;
                if arr_len > MAX_BUNDLE_ARRAY_LEN {
                    return Err(CodecError::Format(format!(
                        "vote array length {} exceeds maximum {}",
                        arr_len, MAX_BUNDLE_ARRAY_LEN
                    )));
                }
                let mut vs = Vec::with_capacity(arr_len as usize);
                for _ in 0..arr_len {
                    vs.push(decode_vote_authenticator(cursor)?);
                }
                bundle.votes = vs;
            }
            _ => {
                rmpv::decode::read_value(cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(bundle)
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
    // Step 1: decode block fields (skips unknown keys).
    //
    // `Block::decode_from_bytes` requires `rnd` to be present, but
    // uproposal fixtures where round=0 omit that key via Go's
    // `omitempty`. Synthesize `rnd: 0` when the key is absent so the
    // block decoder can complete — round stays Round(0) either way.
    let block = decode_block_allowing_missing_rnd(bytes)?;

    // Step 2: scan the map to extract proposal-specific fields.
    let mut cursor = Cursor::new(bytes);
    let map_len = rmp::decode::read_map_len(&mut cursor)
        .map_err(|e| CodecError::Decode(format!("uproposal map: {e}")))?;

    let mut original_period = Period(0);
    let mut original_proposer = Address([0u8; 32]);
    let mut seed_proof = [0u8; VRF_PROOF_SIZE];

    for _ in 0..map_len {
        let key = read_str_key(&mut cursor)?;
        match key.as_str() {
            "oper" => original_period = Period(read_uint64(&mut cursor)?),
            "oprop" => original_proposer = Address(read_bin_fixed::<32>(&mut cursor)?),
            "sdpf" => seed_proof = read_bin_fixed::<VRF_PROOF_SIZE>(&mut cursor)?,
            _ => {
                // Skip all block fields (already consumed via the
                // block decoder above) and any unknown fields.
                rmpv::decode::read_value(&mut cursor)
                    .map_err(|e| CodecError::Decode(format!("skip field: {e}")))?;
            }
        }
    }

    Ok(UnauthenticatedProposal {
        block,
        seed_proof,
        original_period,
        original_proposer,
    })
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
fn decode_block_allowing_missing_rnd(bytes: &[u8]) -> Result<Block, CodecError> {
    match Block::decode_from_bytes(bytes) {
        Ok(block) => Ok(block),
        Err(first_err) => {
            // Only attempt the synthesized-`rnd` fallback if the
            // decoder rejected the input specifically for a missing
            // `rnd` key. Other failures (malformed bytes, other
            // missing required fields) propagate unchanged.
            if !is_missing_rnd_error(&first_err) {
                return Err(CodecError::Decode(format!("block decode: {first_err}")));
            }
            let patched = inject_rnd_zero(bytes)
                .map_err(|_| CodecError::Decode(format!("block decode: {first_err}")))?;
            Block::decode_from_bytes(&patched).map_err(|retry_err| {
                CodecError::Decode(format!("block decode (rnd synthesized): {retry_err}"))
            })
        }
    }
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

    #[test]
    fn ots_roundtrip() {
        let sig = make_nonzero_sig();
        let encoded = encode_one_time_signature(&sig);
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = decode_one_time_signature(&mut cursor).unwrap();
        assert_eq!(decoded.sig, sig.sig);
        assert_eq!(decoded.pk, sig.pk);
        assert_eq!(decoded.pk_sig_old, sig.pk_sig_old);
        assert_eq!(decoded.pk2, sig.pk2);
        assert_eq!(decoded.pk1_sig, sig.pk1_sig);
        assert_eq!(decoded.pk2_sig, sig.pk2_sig);
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
    fn decode_vote_unknown_fields_skipped() {
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

        let decoded = decode_vote(&buf).expect("should skip unknown fields");
        assert_eq!(decoded.raw_vote.round, Round(42));
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
