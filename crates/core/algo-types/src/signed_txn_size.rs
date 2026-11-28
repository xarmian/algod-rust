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

//! `signedTxnSize` of go-algorand v5.1.1-stable (`data/txHandler.go`, issue
//! #2621): the estimate of the memory a decoded, canonically encoded
//! transaction holds, which the transaction handler charges to its backlog
//! byte bound (`txBacklogMaxBytes`).
//!
//! go's estimate is the generated `SignedTxn.Msgsize()` (an upper bound of the
//! encoded size: every field counted whether or not `omitempty` drops it, each
//! `[N]byte` array as `ArrayHeaderSize + N * ByteSize` -- `ByteSize` is 2 -- and
//! each variable-length field by its length) plus one 24-byte slice header for
//! every element of the slices whose elements hold a slice themselves. The
//! functions below port the generated `Msgsize` methods one by one; each names
//! the go type. A field that is `None` here is the zero value in go and counts
//! as such (zero length). `algo-network`'s `tests/fixtures/signed_txn_size_go.jsonl`
//! holds go-generated sizes that this port must match.

use crate::transaction::{
    AssetParams, HeartbeatProof, HeartbeatTxnFields, LogicSig, MerkleProof, MerkleSignature,
    MultisigSig, Participant, ResourceRef, Reveal, SigSlotCommit, StateProofBody,
    StateProofMessage,
};
use crate::{pq::SaltedKeySig, SignedTransaction, Transaction};

// msgp/size.go
const ARRAY_HEADER: i64 = 5;
const BYTE: i64 = 2;
const U8: i64 = 2;
const U16: i64 = 3;
const U32: i64 = 5;
const U64: i64 = 9;
const BOOL: i64 = 1;
const BYTES_PREFIX: i64 = 5;
const STRING_PREFIX: i64 = 5;
const MAP_HEADER: i64 = 5;
const NIL: i64 = 1;

/// A `[n]byte` array, e.g. `crypto.Digest` (`n == 32`).
const fn arr(n: i64) -> i64 {
    ARRAY_HEADER + n * BYTE
}

const ADDRESS: i64 = arr(32);
const SIGNATURE: i64 = arr(64);
/// `merklesignature.MerkleSignatureSchemeRootSize` (`crypto.SumhashDigestSize`).
const MERKLE_ROOT: i64 = arr(64);
/// `crypto.Falcon1024PublicKeySize` (`FALCON_DET1024_PUBKEY_SIZE`).
const FALCON_1024_PUBLIC_KEY_SIZE: i64 = 1793;
/// The size of a `[]byte` slice header in memory (`txBacklogSliceHeaderSize`).
pub const TX_BACKLOG_SLICE_HEADER_SIZE: i64 = 24;

fn bytes_len(len: usize) -> i64 {
    BYTES_PREFIX + len as i64
}

fn opt_bytes(b: Option<&serde_bytes::ByteBuf>) -> i64 {
    bytes_len(b.map_or(0, |b| b.len()))
}

/// `[][]byte`: the array header is counted by the caller.
fn byte_slices(v: &Option<Vec<Option<serde_bytes::ByteBuf>>>) -> i64 {
    v.iter()
        .flatten()
        .map(|e| opt_bytes(e.as_ref()))
        .sum::<i64>()
}

/// `crypto.MultisigSig.Msgsize`.
fn multisig(m: &Option<MultisigSig>) -> i64 {
    let n = m.as_ref().map_or(0, |m| m.subsigs.len()) as i64;
    // 1 + 2 + Uint8Size + 4 + Uint8Size + 7 + ArrayHeaderSize, then per
    // `MultisigSubsig`: 1 + 3 + [32]byte + 2 + [64]byte
    1 + 2 + U8 + 4 + U8 + 7 + ARRAY_HEADER + n * (1 + 3 + arr(32) + 2 + SIGNATURE)
}

/// `transactions.SaltedKeySig.Msgsize`.
fn salted_key_sig(s: &Option<SaltedKeySig>) -> i64 {
    let (pk, sig) = s
        .as_ref()
        .map_or((0, 0), |s| (s.public_key.len(), s.signature.len()));
    // 1 + 4 + SigScheme[2]byte + 4 + AddressSalt(uint8) + 3 + bytes + 4 + bytes
    1 + 4 + arr(2) + 4 + U8 + 3 + bytes_len(pk) + 4 + bytes_len(sig)
}

/// `transactions.LogicSig.Msgsize`.
fn logic_sig(l: &Option<LogicSig>) -> i64 {
    let empty = LogicSig::default();
    let l = l.as_ref().unwrap_or(&empty);
    1 + 2
        + bytes_len(l.logic.len())
        + 4
        + SIGNATURE
        + 5
        + multisig(&l.msig)
        + 6
        + multisig(&l.lmsig)
        + 6
        + salted_key_sig(&l.pqsig)
        + 4
        + ARRAY_HEADER
        + byte_slices(&l.args)
}

/// `basics.AssetParams.Msgsize`.
fn asset_params(p: &Option<AssetParams>) -> i64 {
    let empty = AssetParams::default();
    let p = p.as_ref().unwrap_or(&empty);
    1 + 2
        + U64
        + 3
        + U32
        + 3
        + BOOL
        + 3
        + STRING_PREFIX
        + p.unit_name.len() as i64
        + 3
        + STRING_PREFIX
        + p.asset_name.len() as i64
        + 3
        + STRING_PREFIX
        + p.url.len() as i64
        + 3
        + arr(32)
        + 2
        + ADDRESS
        + 2
        + ADDRESS
        + 2
        + ADDRESS
        + 2
        + ADDRESS
}

/// `basics.StateSchema.Msgsize`.
const STATE_SCHEMA: i64 = 1 + 4 + U64 + 4 + U64;

/// `transactions.ResourceRef.Msgsize`.
fn resource_ref(r: &ResourceRef) -> i64 {
    let name = r
        .box_ref
        .as_ref()
        .and_then(|b| b.name.as_ref())
        .map_or(0, |n| n.len());
    1 + 2
        + ADDRESS
        + 2
        + U64
        + 2
        + U64
        + 2
        + 1
        + 2
        + U64
        + 2
        + U64
        + 2
        + 1
        + 2
        + U64
        + 2
        + U64
        + 2
        + 1
        + 2
        + U64
        + 2
        + bytes_len(name)
}

/// `merklearray.Proof.Msgsize` (and `SingleLeafProof`, which embeds it).
fn merkle_proof(p: Option<&MerkleProof>) -> i64 {
    let path: i64 = p
        .and_then(|p| p.path.as_ref())
        .into_iter()
        .flatten()
        .map(|d| opt_bytes(d.as_ref()))
        .sum();
    // 1 + 4 + ArrayHeaderSize, the path, 4 + HashFactory{1 + 2 + Uint16Size} + 3 + Uint8Size
    1 + 4 + ARRAY_HEADER + path + 4 + (1 + 2 + U16) + 3 + U8
}

/// `merklesignature.Signature.Msgsize`.
fn merkle_signature(s: Option<&MerkleSignature>) -> i64 {
    let empty = MerkleSignature::default();
    let s = s.unwrap_or(&empty);
    1 + 4
        + bytes_len(s.signature.len())
        + 4
        + U64
        + 4
        + merkle_proof(s.proof.as_ref())
        + 5
        // `crypto.Falcon1024Verifier`: 1 + 2 + [FALCON_DET1024_PUBKEY_SIZE]byte
        + (1 + 2 + arr(FALCON_1024_PUBLIC_KEY_SIZE))
}

/// `stateproof.sigslotCommit.Msgsize`.
fn sig_slot_commit(s: &Option<SigSlotCommit>) -> i64 {
    let sig = s.as_ref().and_then(|s| s.sig.as_ref());
    1 + 2 + merkle_signature(sig) + 2 + U64
}

/// `basics.Participant.Msgsize` (its `merklesignature.Verifier`: 1 + 4 +
/// [64]byte + 3 + Uint64Size).
fn participant(_: &Option<Participant>) -> i64 {
    1 + 2 + (1 + 4 + MERKLE_ROOT + 3 + U64) + 2 + U64
}

/// `stateproof.Reveal.Msgsize`.
fn reveal(r: &Reveal) -> i64 {
    1 + 2 + sig_slot_commit(&r.sig_slot) + 2 + participant(&r.part)
}

/// `stateproof.StateProof.Msgsize`.
fn state_proof(s: &Option<StateProofBody>) -> i64 {
    let empty = StateProofBody::default();
    let s = s.as_ref().unwrap_or(&empty);
    let reveals: i64 = s
        .reveals
        .iter()
        .flatten()
        .map(|(_, r)| U64 + reveal(r))
        .sum();
    let positions = s.positions_to_reveal.as_ref().map_or(0, |p| p.len()) as i64;
    1 + 2
        + bytes_len(s.sig_commit.len())
        + 2
        + U64
        + 2
        + merkle_proof(s.sig_proofs.as_ref())
        + 2
        + merkle_proof(s.part_proofs.as_ref())
        + 2
        + BYTE
        + 2
        + MAP_HEADER
        + reveals
        + 3
        + ARRAY_HEADER
        + positions * U64
}

/// `stateproofmsg.Message.Msgsize`.
fn state_proof_message(m: &Option<StateProofMessage>) -> i64 {
    let empty = StateProofMessage::default();
    let m = m.as_ref().unwrap_or(&empty);
    1 + 2
        + bytes_len(m.block_headers_commitment.len())
        + 2
        + bytes_len(m.voters_commitment.len())
        + 2
        + U64
        + 2
        + U64
        + 2
        + U64
}

/// `crypto.HeartbeatProof.Msgsize`.
fn heartbeat_proof(_: &Option<HeartbeatProof>) -> i64 {
    1 + 2 + SIGNATURE + 2 + arr(32) + 3 + arr(32) + 4 + SIGNATURE + 4 + SIGNATURE
}

/// `transactions.HeartbeatTxnFields.Msgsize`; a nil pointer is `NilSize`.
fn heartbeat(h: &Option<HeartbeatTxnFields>) -> i64 {
    match h {
        None => NIL,
        Some(h) => {
            1 + 2
                + ADDRESS
                + 4
                + heartbeat_proof(&h.proof)
                + 3
                + arr(32)
                + 4
                + arr(32)
                + 3
                + U64
                + 2
                + BOOL
        }
    }
}

/// `transactions.Transaction.Msgsize`.
fn transaction(t: &Transaction) -> i64 {
    let args = byte_slices(&t.app_arguments);
    let accounts = t.accounts.as_ref().map_or(0, |a| a.len()) as i64 * ADDRESS;
    let assets = t.foreign_assets.as_ref().map_or(0, |a| a.len()) as i64 * U64;
    let apps = t.foreign_apps.as_ref().map_or(0, |a| a.len()) as i64 * U64;
    let access: i64 = t.access.iter().flatten().map(resource_ref).sum();
    let boxes: i64 = t
        .boxes
        .iter()
        .flatten()
        .map(|b| 1 + 2 + U64 + 2 + opt_bytes(b.name.as_ref()))
        .sum();
    let schema = STATE_SCHEMA;
    3 + 5
        + (STRING_PREFIX + t.txn_type.as_str().len() as i64)
        + 4
        + ADDRESS
        + 4
        + U64
        + 3
        + U64
        + 3
        + U64
        + 5
        + bytes_len(t.note.len())
        + 4
        + (STRING_PREFIX + t.genesis_id.len() as i64)
        + 3
        + arr(32)
        + 4
        + arr(32)
        + 3
        + arr(32)
        + 6
        + ADDRESS
        + 8
        + arr(32)
        + 7
        + arr(32)
        + 8
        + MERKLE_ROOT
        + 8
        + U64
        + 8
        + U64
        + 7
        + U64
        + 8
        + BOOL
        + 4
        + ADDRESS
        + 4
        + U64
        + 6
        + ADDRESS
        + 5
        + U64
        + 5
        + asset_params(&t.asset_params)
        + 5
        + U64
        + 5
        + U64
        + 5
        + ADDRESS
        + 5
        + ADDRESS
        + 7
        + ADDRESS
        + 5
        + ADDRESS
        + 5
        + U64
        + 5
        + BOOL
        + 5
        + U64
        + 5
        + U64
        + 5
        + ARRAY_HEADER
        + args
        + 5
        + ARRAY_HEADER
        + accounts
        + 5
        + ARRAY_HEADER
        + assets
        + 5
        + ARRAY_HEADER
        + apps
        + 3
        + ARRAY_HEADER
        + access
        + 5
        + ARRAY_HEADER
        + boxes
        + 5
        + schema
        + 5
        + schema
        + 5
        + opt_bytes(t.approval_program.as_ref())
        + 5
        + opt_bytes(t.clear_state_program.as_ref())
        + 5
        + U32
        + 5
        + U64
        + 7
        + U64
        + 3
        + state_proof(&t.state_proof)
        + 6
        + state_proof_message(&t.state_proof_message)
        + 3
        + heartbeat(&t.heartbeat)
}

/// `SignedTxn.Msgsize()` of go.
#[must_use]
pub fn signed_txn_msgsize(s: &SignedTransaction) -> i64 {
    1 + 4
        + SIGNATURE
        + 5
        + multisig(&s.msig)
        + 5
        + logic_sig(&s.lsig)
        + 6
        + salted_key_sig(&s.pqsig)
        + 4
        + transaction(&s.txn)
        + 5
        + ADDRESS
}

/// go's `signedTxnSize`: `Msgsize()` plus a slice header for each element of
/// `Lsig.Args`, `ApplicationArgs`, `Boxes` and the merkle proof paths of a state
/// proof (`Msgsize` undercounts an element that holds a slice itself).
#[must_use]
pub fn signed_txn_size(s: &SignedTransaction) -> i64 {
    let t = &s.txn;
    let len = |v: Option<usize>| v.unwrap_or(0) as i64;
    let proof_path = |p: Option<&MerkleProof>| len(p.and_then(|p| p.path.as_ref()).map(Vec::len));
    let mut n = len(s.lsig.as_ref().and_then(|l| l.args.as_ref()).map(Vec::len))
        + len(t.app_arguments.as_ref().map(Vec::len))
        + len(t.boxes.as_ref().map(Vec::len));
    if let Some(sp) = &t.state_proof {
        n += proof_path(sp.sig_proofs.as_ref()) + proof_path(sp.part_proofs.as_ref());
        for r in sp.reveals.iter().flat_map(|m| m.values()) {
            n += proof_path(
                r.sig_slot
                    .as_ref()
                    .and_then(|s| s.sig.as_ref())
                    .and_then(|s| s.proof.as_ref()),
            );
        }
    }
    signed_txn_msgsize(s) + TX_BACKLOG_SLICE_HEADER_SIZE * n
}
