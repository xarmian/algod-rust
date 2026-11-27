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

//! Group-level transaction screen (go-algorand v4.7.2-stable `data/transactions/checks.go`).
//!
//! `check_txn_group`/`check_payset` mirror go-algorand's `CheckTxnGroup`/
//! `CheckPayset`: a screen run over a signed-txn group (or a whole payset,
//! walked in contiguous same-group runs) *before* per-txn signature
//! verification, rejecting a group that is structurally malformed in ways
//! signature verification alone wouldn't catch.

use algo_consensus_crypto::merklearray::{HashType, MAX_ENCODED_TREE_DEPTH};
use algo_consensus_crypto::merklesig::MERKLE_SIGNATURE_SCHEME_ROOT_SIZE;
use algo_error::AlgoError;
use algo_types::{MerkleProof, MerkleSignature, SignedTransaction, StateProofBody, Transaction};

/// `protocol.StateProofBasic` -- the only currently-supported state-proof
/// type. Matches `algo_ledger::apply_stateproof::STATE_PROOF_BASIC`
/// (duplicated here rather than shared, since `algo-validate` doesn't
/// depend on `algo-ledger`).
const STATE_PROOF_BASIC: u64 = 0;

fn err(message: impl Into<String>) -> AlgoError {
    AlgoError::Validation {
        message: message.into(),
    }
}

/// Returns `true` for a txn type that "triggers resource availability"
/// computation: an application call, or an asset-config txn creating a new
/// asset. Mirrors Go's `triggersResourceAvailability`.
fn triggers_resource_availability(txn: &Transaction) -> bool {
    txn.txn_type == "appl" || (txn.txn_type == "acfg" && txn.config_asset == 0)
}

/// Mirrors Go's `checkBasicStateProofPath` (`data/transactions/checks.go`,
/// `v5.0.1-stable`): a Merkle proof's `HashFactory.HashType` must equal
/// `expected_hash`, and every non-empty path element must be exactly
/// `digest_size` bytes (an empty element represents a missing sibling and is
/// always allowed).
fn check_basic_state_proof_path(
    proof: Option<&MerkleProof>,
    expected_hash: HashType,
    digest_size: usize,
) -> Result<(), AlgoError> {
    let raw_hash_type = proof
        .and_then(|p| p.hash_factory.as_ref())
        .map_or(0, |hf| hf.hash_type);
    if HashType::from_u16(raw_hash_type) != Some(expected_hash) {
        return Err(err(format!(
            "state proof uses an unexpected hash algorithm: uses {raw_hash_type}, expected {}",
            expected_hash as u16
        )));
    }

    let Some(path) = proof.and_then(|p| p.path.as_ref()) else {
        return Ok(());
    };
    for (i, elem) in path.iter().enumerate() {
        let len = elem.as_ref().map_or(0, |b| b.len());
        if len != 0 && len != digest_size {
            return Err(err(format!(
                "state proof has a Merkle path element with an unexpected size: element {i} has length {len}, expected {digest_size}"
            )));
        }
    }
    Ok(())
}

/// Mirrors Go's `checkBasicStateProof` (`data/transactions/checks.go`,
/// `v5.0.1-stable`): `SigCommit` must be exactly `HashSize` bytes,
/// `SigProofs`/`PartProofs` must both use the protocol-fixed Sumhash
/// algorithm (with correctly-sized path elements), and every reveal whose
/// signature isn't the zero value must have a signature of at least 2
/// bytes, a proof `TreeDepth` that is both within `MAX_ENCODED_TREE_DEPTH`
/// and consistent with the proof's own path length, and a nested Merkle
/// signature proof that itself uses the Merkle-signature-scheme's fixed
/// Sumhash algorithm with correctly-sized path elements.
fn check_basic_state_proof(sp: &StateProofBody) -> Result<(), AlgoError> {
    // `stateproof.HashType` / `stateproof.HashSize`: StateProofBasic pins
    // every hash factory in the proof to Sumhash (64-byte digest).
    const HASH_TYPE: HashType = HashType::Sumhash;
    let hash_size = HASH_TYPE.digest_size();

    if sp.sig_commit.len() != hash_size {
        return Err(err(format!(
            "state proof has an unexpected signature commitment size: has length {}, expected {hash_size}",
            sp.sig_commit.len()
        )));
    }

    check_basic_state_proof_path(sp.sig_proofs.as_ref(), HASH_TYPE, hash_size)?;
    check_basic_state_proof_path(sp.part_proofs.as_ref(), HASH_TYPE, hash_size)?;

    let reveals = sp.reveals.as_ref();
    for reveal in reveals.into_iter().flat_map(|r| r.values()) {
        let Some(ref sig_slot) = reveal.sig_slot else {
            continue;
        };
        let Some(ref sig) = sig_slot.sig else {
            continue;
        };
        // Go: `sig.MsgIsZero()` — an entirely-default signature carries no
        // reveal and is skipped, regardless of whether the "s" key was
        // present on the wire.
        if *sig == MerkleSignature::default() {
            continue;
        }
        if sig.signature.len() < 2 {
            return Err(err(
                "state proof reveal has an empty or too-short signature",
            ));
        }
        let proof = sig.proof.as_ref();
        let tree_depth = proof.map_or(0, |p| p.tree_depth);
        let path_len = proof
            .and_then(|p| p.path.as_ref())
            .map_or(0, |path| path.len());
        if (tree_depth as usize) > path_len || tree_depth as usize > MAX_ENCODED_TREE_DEPTH {
            return Err(err("state proof reveal has an invalid Merkle proof depth"));
        }
        // `merklesignature.MerkleSignatureSchemeHashFunction` is also
        // Sumhash, but with the Merkle-signature-scheme's own (equal, in
        // this repo) root size constant, matching go's use of a separate
        // named constant rather than reusing `stateproof.HashSize`.
        check_basic_state_proof_path(proof, HashType::Sumhash, MERKLE_SIGNATURE_SCHEME_ROOT_SIZE)?;
    }
    check_merkle_path_lengths(sp)
}

/// `unexpected number of Merkle path elements` (`stateproof.ErrUnexpectedPathLength`).
const UNEXPECTED_PATH_LENGTH: &str = "unexpected number of Merkle path elements";

/// Mirrors Go's `StateProof.CheckMerklePathLengths`
/// (`crypto/stateproof/proofPathLength.go`, v5.1.0-beta, run at the end of
/// `checkBasicStateProof`): a multi-leaf proof (`SigProofs`, `PartProofs`) may
/// not carry more path elements than `reveals * TreeDepth`, and the Merkle
/// signature proof of every reveal (zero or not) is bounded by
/// `MaxEncodedTreeDepth` on both its depth and its path length, with a path no
/// shorter than its depth.
fn check_merkle_path_lengths(sp: &StateProofBody) -> Result<(), AlgoError> {
    let num_leaves = sp.reveals.as_ref().map_or(0, |r| r.len()) as u64;
    for (name, proof) in [
        ("SigProofs", &sp.sig_proofs),
        ("PartProofs", &sp.part_proofs),
    ] {
        let path_len = proof
            .as_ref()
            .and_then(|p| p.path.as_ref())
            .map_or(0, |p| p.len()) as u64;
        let depth = proof.as_ref().map_or(0, |p| p.tree_depth) as u64;
        if path_len > num_leaves * depth {
            return Err(err(format!(
                "{name}: {UNEXPECTED_PATH_LENGTH}: {path_len} path elements for {num_leaves} leaves at TreeDepth {depth}"
            )));
        }
    }
    for (pos, reveal) in sp.reveals.iter().flatten() {
        let proof = reveal
            .sig_slot
            .as_ref()
            .and_then(|s| s.sig.as_ref())
            .and_then(|s| s.proof.as_ref());
        let depth = proof.map_or(0, |p| p.tree_depth) as usize;
        let path_len = proof.and_then(|p| p.path.as_ref()).map_or(0, |p| p.len());
        if depth > MAX_ENCODED_TREE_DEPTH {
            return Err(err(format!(
                "reveal {pos}: tree depth is too large: signature proof TreeDepth {depth}, maximum {MAX_ENCODED_TREE_DEPTH}"
            )));
        }
        if path_len > MAX_ENCODED_TREE_DEPTH {
            return Err(err(format!(
                "reveal {pos}: {UNEXPECTED_PATH_LENGTH}: signature proof has {path_len} path elements, maximum {MAX_ENCODED_TREE_DEPTH}"
            )));
        }
        if depth > path_len {
            return Err(err(format!(
                "reveal {pos}: {UNEXPECTED_PATH_LENGTH}: signature proof has {path_len} path elements for TreeDepth {depth}"
            )));
        }
    }
    Ok(())
}

/// Mirrors Go's `checkStateProof` (`data/transactions/checks.go`,
/// `v5.0.1-stable`): dispatches on `StateProofType`, rejecting any type
/// other than `StateProofBasic`.
fn check_state_proof(state_proof_type: u64, sp: &StateProofBody) -> Result<(), AlgoError> {
    match state_proof_type {
        STATE_PROOF_BASIC => check_basic_state_proof(sp),
        other => Err(err(format!("state proof has an unsupported type: {other}"))),
    }
}

/// Mirrors Go's `StateProofTxnFields.wellFormed` calling `checkStateProof`
/// (`data/transactions/stateproof.go`, `v5.0.1-stable`): every state-proof
/// txn is checked, including one whose `StateProof` field was entirely
/// absent on the wire -- go's `StateProof` is a plain (non-pointer) struct
/// field, so an absent wire value still decodes to (and must pass checks
/// as) its zero value, not be skipped.
///
/// go runs this check in TWO places and so does this port, through this one
/// helper (issue #2196): per member in `WellFormed` (so the gossip test stage
/// and the REST path report the first malformed member in go's order, called
/// from `rules::validate_transaction_wellformed_in_mode`) and at group level in
/// `checkTxnGroup` ([`check_txn_group`], which block validation, the agreement
/// demux's `proposalCarriesInvalidTxn` screen, simulation and the REST path run).
/// Block validation checks the payload there, in `check_txn_group`, even for an
/// `stpf` whose per-transaction rules `block.rs` skips.
pub fn check_state_proof_payload(txn: &Transaction) -> Result<(), AlgoError> {
    let default_sp = StateProofBody::default();
    let sp = txn.state_proof.as_ref().unwrap_or(&default_sp);
    check_state_proof(txn.state_proof_type, sp)
}

/// Screen a signed-transaction group for invalid transactions, mirroring
/// go-algorand's `CheckTxnGroup`. Run this *before* per-txn signature
/// verification/prep, over the same contiguous group signature
/// verification operates on (a "group" of one is still a group here).
pub fn check_txn_group(
    group: &[SignedTransaction],
    allow_grouped_heartbeats: bool,
) -> Result<(), AlgoError> {
    let mut heartbeat = false;
    let mut avail_trigger = false;

    // go v5.1 (#6728): only the state proof payload rule and the heartbeat /
    // resource-availability rule remain. The missing-heartbeat-body,
    // unknown-type and box-index group checks were removed upstream:
    // `Transaction.WellFormed` rejects those, per transaction.
    for stx in group {
        let txn = &stx.txn;
        match txn.txn_type.as_str() {
            "hb" => heartbeat = true,
            "stpf" => check_state_proof_payload(txn)?,
            "appl" => avail_trigger = true,
            "pay" | "keyreg" | "acfg" | "axfer" | "afrz" if triggers_resource_availability(txn) => {
                avail_trigger = true;
            }
            _ => {}
        }
    }

    if !allow_grouped_heartbeats && heartbeat && avail_trigger {
        return Err(err(
            "heartbeat transaction may not be grouped with an application call or asset creation",
        ));
    }

    Ok(())
}

/// Screen a full payset for invalid transactions, mirroring go-algorand's
/// `CheckPayset`: walks the payset in contiguous runs of the same non-zero
/// group (a zero-group txn is its own singleton run) and runs
/// [`check_txn_group`] over each run.
pub fn check_payset(
    payset: &[SignedTransaction],
    allow_grouped_heartbeats: bool,
) -> Result<(), AlgoError> {
    let groups = crate::block::detect_validation_groups(payset).map_err(err)?;
    for group in groups {
        let members: Vec<SignedTransaction> = group.iter().map(|&(_, stx)| stx.clone()).collect();
        check_txn_group(&members, allow_grouped_heartbeats)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{
        Address, HeartbeatTxnFields, MerkleProof, Reveal, SigSlotCommit, StateProofBody, TxnType,
    };
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap;

    fn base_txn(txn_type: &str) -> Transaction {
        Transaction {
            txn_type: TxnType::from(txn_type),
            sender: Address([1u8; 32]),
            ..Default::default()
        }
    }

    fn signed(txn: Transaction) -> SignedTransaction {
        SignedTransaction {
            txn,
            ..Default::default()
        }
    }

    // ── Issue #2553: go v5.1's `CheckMerklePathLengths` ──────────

    use algo_types::MerkleSignature;

    fn proof(path_len: usize, tree_depth: u8) -> Option<MerkleProof> {
        Some(MerkleProof {
            path: Some(vec![Some(ByteBuf::from(vec![0u8; 32])); path_len]),
            hash_factory: None,
            tree_depth,
        })
    }

    fn reveal_with_proof(path_len: usize, tree_depth: u8) -> Reveal {
        Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    proof: proof(path_len, tree_depth),
                    ..Default::default()
                }),
                l: 0,
            }),
            part: None,
        }
    }

    fn sp_with(
        sig_proofs: Option<MerkleProof>,
        part_proofs: Option<MerkleProof>,
        reveals: Vec<Reveal>,
    ) -> StateProofBody {
        StateProofBody {
            sig_proofs,
            part_proofs,
            reveals: Some(
                reveals
                    .into_iter()
                    .enumerate()
                    .map(|(i, r)| (i as u64, r))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn multi_leaf_proof_paths_are_bounded_by_leaves_times_depth() {
        // 3 reveals at TreeDepth 4: up to 12 path elements
        let reveals = || (0..3).map(|_| reveal_with_proof(2, 2)).collect::<Vec<_>>();
        check_merkle_path_lengths(&sp_with(proof(12, 4), proof(12, 4), reveals())).unwrap();
        let e = check_merkle_path_lengths(&sp_with(proof(13, 4), proof(0, 0), reveals()))
            .unwrap_err()
            .to_string();
        assert!(
            e.ends_with(
                "SigProofs: unexpected number of Merkle path elements: 13 path elements for 3 leaves at TreeDepth 4"
            ),
            "{e}"
        );
        let e = check_merkle_path_lengths(&sp_with(proof(0, 0), proof(13, 4), reveals()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("PartProofs: unexpected number of Merkle path elements: 13 path elements for 3 leaves at TreeDepth 4"), "{e}");
        // TreeDepth 0 admits no path at all
        let e = check_merkle_path_lengths(&sp_with(proof(1, 0), None, reveals())).unwrap_err();
        assert!(e.to_string().contains("SigProofs:"), "{e}");
        // an absent proof is empty
        check_merkle_path_lengths(&sp_with(None, None, reveals())).unwrap();
    }

    #[test]
    fn revealed_signature_proof_paths_are_bounded_by_the_max_encoded_depth() {
        let one = |r| sp_with(None, None, vec![r]);
        // depth 16 with 16 elements (and depth 3 with 5: longer than depth is fine)
        check_merkle_path_lengths(&one(reveal_with_proof(16, 16))).unwrap();
        check_merkle_path_lengths(&one(reveal_with_proof(5, 3))).unwrap();
        // the checked reveal is named by its position
        let e = check_merkle_path_lengths(&one(reveal_with_proof(17, 16)))
            .unwrap_err()
            .to_string();
        assert!(e.ends_with("reveal 0: unexpected number of Merkle path elements: signature proof has 17 path elements, maximum 16"), "{e}");
        let e = check_merkle_path_lengths(&one(reveal_with_proof(20, 17)))
            .unwrap_err()
            .to_string();
        assert!(
            e.ends_with(
                "reveal 0: tree depth is too large: signature proof TreeDepth 17, maximum 16"
            ),
            "{e}"
        );
        // a path shorter than TreeDepth
        let e = check_merkle_path_lengths(&one(reveal_with_proof(2, 3)))
            .unwrap_err()
            .to_string();
        assert!(e.ends_with("reveal 0: unexpected number of Merkle path elements: signature proof has 2 path elements for TreeDepth 3"), "{e}");
        // an all-default signature (no reveal) is checked the same way: depth 0, path 0
        check_merkle_path_lengths(&one(Reveal::default())).unwrap();
    }

    // ── Heartbeat missing fields ─────────────────────────────────

    /// go v5.1 (#6728) dropped `errMissingHeartbeatFields` from
    /// `checkTxnGroup`: `Transaction.WellFormed` ("heartbeat transaction has
    /// no heartbeat fields") is what rejects it, later.
    #[test]
    fn heartbeat_missing_fields_is_not_a_group_check() {
        let mut txn = base_txn("hb");
        txn.heartbeat = None;
        check_txn_group(&[signed(txn)], false).unwrap();
    }

    #[test]
    fn heartbeat_with_fields_is_accepted() {
        let mut txn = base_txn("hb");
        txn.heartbeat = Some(HeartbeatTxnFields::default());
        check_txn_group(&[signed(txn)], false).unwrap();
    }

    // ── Heartbeat grouped with resource-availability trigger ─────

    #[test]
    fn heartbeat_grouped_with_appl_is_rejected() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let appl = base_txn("appl");
        let err = check_txn_group(&[signed(hb), signed(appl)], false).unwrap_err();
        assert!(err.to_string().contains("heartbeat"), "got: {err}");
    }

    #[test]
    fn heartbeat_grouped_with_asset_create_is_rejected() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let mut acfg = base_txn("acfg");
        acfg.config_asset = 0; // creation
        let err = check_txn_group(&[signed(hb), signed(acfg)], false).unwrap_err();
        assert!(err.to_string().contains("heartbeat"), "got: {err}");
    }

    #[test]
    fn heartbeat_grouped_with_asset_reconfig_is_accepted() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let mut acfg = base_txn("acfg");
        acfg.config_asset = 42; // reconfigure, not create
        check_txn_group(&[signed(hb), signed(acfg)], false).unwrap();
    }

    // go v5.1 `AllowGroupedHeartbeats` (#2544): where consensus allows it a
    // heartbeat may share a group with an application call or asset creation.
    #[test]
    fn allow_grouped_heartbeats_lifts_the_resource_group_rule() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let appl = base_txn("appl");
        let mut acfg = base_txn("acfg");
        acfg.config_asset = 0; // creation
        for other in [appl, acfg] {
            let group = [signed(hb.clone()), signed(other)];
            let e = check_txn_group(&group, false).unwrap_err().to_string();
            assert!(
                e.contains("heartbeat transaction may not be grouped with an application call or asset creation"),
                "{e}"
            );
            check_txn_group(&group, true).expect("allowed under AllowGroupedHeartbeats");
        }
        // check_payset passes the flag per run
        let mut hb2 = hb.clone();
        let mut appl2 = base_txn("appl");
        let ids: Vec<algo_types::Digest> = [&hb2, &appl2]
            .iter()
            .map(|t| algo_codec::compute_txn_id(t))
            .collect();
        let gid = algo_codec::compute_group_id_from_hashes(&ids);
        hb2.group = gid.0;
        appl2.group = gid.0;
        let payset = [signed(hb2), signed(appl2)];
        assert!(check_payset(&payset, false).is_err());
        check_payset(&payset, true).unwrap();
    }

    #[test]
    fn heartbeat_grouped_with_payment_is_accepted() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let pay = base_txn("pay");
        check_txn_group(&[signed(hb), signed(pay)], false).unwrap();
    }

    // ── StateProof reveal bounds ──────────────────────────────────

    fn sumhash_wire_factory() -> algo_types::HashFactory {
        algo_types::HashFactory {
            hash_type: HashType::Sumhash as u16,
        }
    }

    /// A reveal's nested Merkle signature proof, correctly Sumhash-typed
    /// with `path_len` correctly-sized (`MERKLE_SIGNATURE_SCHEME_ROOT_SIZE`)
    /// elements -- so tests below exercise only the signature-length/
    /// tree-depth bound they're named for, not the hash-algorithm/
    /// path-element-size checks added in `v5.0.1-stable`.
    fn reveal_with(sig_len: usize, tree_depth: u8, path_len: usize) -> Reveal {
        Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    signature: ByteBuf::from(vec![7u8; sig_len]),
                    vector_commitment_index: 0,
                    proof: Some(MerkleProof {
                        path: Some(vec![
                            Some(ByteBuf::from(vec![
                                0u8;
                                MERKLE_SIGNATURE_SCHEME_ROOT_SIZE
                            ]));
                            path_len
                        ]),
                        hash_factory: Some(sumhash_wire_factory()),
                        tree_depth,
                    }),
                    verifying_key: None,
                }),
                l: 0,
            }),
            part: None,
        }
    }

    /// A well-formed base `StateProofBody`: correctly-sized `SigCommit` and
    /// Sumhash-typed, empty-path `SigProofs`/`PartProofs` -- everything
    /// `check_basic_state_proof` requires outside of the per-reveal checks.
    /// Matches go's `stateProofTxnForCheck` (`checks_test.go`,
    /// `v5.0.1-stable`).
    fn well_formed_state_proof_body() -> StateProofBody {
        StateProofBody {
            sig_commit: ByteBuf::from(vec![0u8; HashType::Sumhash.digest_size()]),
            sig_proofs: Some(MerkleProof {
                path: None,
                hash_factory: Some(sumhash_wire_factory()),
                tree_depth: 0,
            }),
            part_proofs: Some(MerkleProof {
                path: None,
                hash_factory: Some(sumhash_wire_factory()),
                tree_depth: 0,
            }),
            ..Default::default()
        }
    }

    fn stpf_txn_with_reveal(reveal: Reveal) -> Transaction {
        let mut txn = base_txn("stpf");
        let mut reveals = BTreeMap::new();
        reveals.insert(0u64, reveal);
        txn.state_proof = Some(StateProofBody {
            reveals: Some(reveals),
            ..well_formed_state_proof_body()
        });
        txn
    }

    #[test]
    fn state_proof_reveal_short_signature_is_rejected() {
        let txn = stpf_txn_with_reveal(reveal_with(1, 1, 1));
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn state_proof_reveal_tree_depth_exceeds_max_is_rejected() {
        let txn = stpf_txn_with_reveal(reveal_with(
            2,
            (MAX_ENCODED_TREE_DEPTH + 1) as u8,
            MAX_ENCODED_TREE_DEPTH + 1,
        ));
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("proof"), "got: {err}");
    }

    #[test]
    fn state_proof_reveal_tree_depth_exceeds_path_len_is_rejected() {
        let txn = stpf_txn_with_reveal(reveal_with(2, 5, 3));
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("proof"), "got: {err}");
    }

    #[test]
    fn a_multi_leaf_proof_longer_than_reveals_times_depth_is_rejected_like_go() {
        // go v5.1 `CheckMerklePathLengths`: `SigProofs` with 2 path elements,
        // no reveals (0 leaves) at TreeDepth 0.
        let mut body = well_formed_state_proof_body();
        body.sig_proofs.as_mut().unwrap().path = Some(vec![
            Some(ByteBuf::from(vec![
                0u8;
                HashType::Sumhash.digest_size()
            ]));
            2
        ]);
        let mut txn = base_txn("stpf");
        txn.state_proof = Some(body.clone());
        assert_eq!(
            check_state_proof_payload(&txn).unwrap_err().to_string(),
            "validation error: SigProofs: unexpected number of Merkle path elements: 2 path elements for 0 leaves at TreeDepth 0"
        );
        // One reveal at TreeDepth 2 allows up to two elements, not three.
        let mut reveals = BTreeMap::new();
        reveals.insert(5u64, reveal_with(2, 0, 0));
        body.reveals = Some(reveals);
        let elem = || Some(ByteBuf::from(vec![0u8; HashType::Sumhash.digest_size()]));
        body.part_proofs.as_mut().unwrap().tree_depth = 2;
        body.part_proofs.as_mut().unwrap().path = Some(vec![elem(), elem()]);
        body.sig_proofs.as_mut().unwrap().path = None;
        txn.state_proof = Some(body.clone());
        check_state_proof_payload(&txn).unwrap();
        body.part_proofs.as_mut().unwrap().path = Some(vec![elem(), elem(), elem()]);
        txn.state_proof = Some(body);
        assert_eq!(
            check_state_proof_payload(&txn).unwrap_err().to_string(),
            "validation error: PartProofs: unexpected number of Merkle path elements: 3 path elements for 1 leaves at TreeDepth 2"
        );
    }

    #[test]
    fn state_proof_reveal_within_bounds_is_accepted() {
        let txn = stpf_txn_with_reveal(reveal_with(2, 4, 4));
        check_state_proof_payload(&txn).unwrap();
    }

    #[test]
    fn state_proof_reveal_zero_signature_is_skipped() {
        // An all-default MerkleSignature (MsgIsZero) carries no reveal and
        // must not be checked against the bounds above.
        let txn = stpf_txn_with_reveal(Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature::default()),
                l: 0,
            }),
            part: None,
        });
        check_state_proof_payload(&txn).unwrap();
    }

    // ── Application box index (go v5.1: no longer a group check) ───

    /// go v5.1 removed `errMalformedApplicationBoxIndex` from `checkTxnGroup`
    /// (`TestCheckTxnGroupApplicationBoxIndex` and
    /// `TestCheckPaysetGroupApplicationBoxIndex` are deleted): a box index
    /// past `ForeignApps` is the business of `WellFormed`, not of the group.
    #[test]
    fn box_index_is_not_a_group_check() {
        use algo_types::BoxRef;
        let mut txn = base_txn("appl");
        txn.foreign_apps = Some(vec![100, 200]); // len 2
        txn.boxes = Some(vec![BoxRef {
            index: 3,
            name: None,
        }]);
        check_txn_group(&[signed(txn)], false).unwrap();
    }

    // ── Unknown transaction type (go v5.1: no longer a group check) ─

    /// go v5.1: "checkTxnGroup used to reject an unknown type on behalf of
    /// nodes whose resources.fill could not cope with one. WellFormed is what
    /// rejects it" (`TestCheckTxnGroupUnknownType`).
    #[test]
    fn unknown_txn_type_is_not_a_group_check() {
        let bogus = base_txn("bogus");
        check_txn_group(&[signed(bogus.clone())], false).unwrap();
        check_txn_group(&[signed(base_txn("appl")), signed(bogus)], false).unwrap();
    }

    #[test]
    fn every_known_type_is_accepted() {
        // "stpf" is checked separately: an all-default `StateProofBody` is
        // itself malformed (its zero-value `SigCommit`/hash factories fail
        // `check_basic_state_proof`), matching go's own test split
        // (`TestCheckTxnGroupUnknownType`/`TestCheckTxnGroupStateProofBasicSuite`).
        for t in ["pay", "keyreg", "acfg", "axfer", "afrz", "appl"] {
            let txn = base_txn(t);
            check_txn_group(&[signed(txn)], false)
                .unwrap_or_else(|e| panic!("type {t:?} should be accepted, got: {e}"));
        }
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        check_txn_group(&[signed(hb)], false).unwrap();

        let mut stpf = base_txn("stpf");
        stpf.state_proof = Some(well_formed_state_proof_body());
        check_txn_group(&[signed(stpf)], false).unwrap();
    }

    // ── check_basic_state_proof / check_state_proof (go:
    //    TestCheckTxnGroupStateProofBasicSuite, checks_test.go,
    //    v5.0.1-stable) ─────────────────────────────────────────────

    fn well_formed_stpf_txn() -> Transaction {
        let mut txn = base_txn("stpf");
        txn.state_proof = Some(well_formed_state_proof_body());
        txn
    }

    #[test]
    fn state_proof_basic_suite_accepts_a_well_formed_proof() {
        check_state_proof_payload(&well_formed_stpf_txn()).unwrap();
    }

    #[test]
    fn state_proof_basic_suite_rejects_unsupported_state_proof_type() {
        let mut txn = well_formed_stpf_txn();
        txn.state_proof_type = 1;
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("unsupported"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_sig_proofs_hash_type() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.sig_proofs.as_mut().unwrap().hash_factory = Some(algo_types::HashFactory {
                hash_type: HashType::Sha256 as u16,
            });
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("hash algorithm"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_part_proofs_hash_type() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.part_proofs.as_mut().unwrap().hash_factory = Some(algo_types::HashFactory {
                hash_type: HashType::Sha256 as u16,
            });
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("hash algorithm"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_sized_path_element() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.part_proofs.as_mut().unwrap().path = Some(vec![Some(ByteBuf::from(vec![0u8; 32]))]);
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("unexpected size"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_sig_commit_size() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.sig_commit = ByteBuf::from(vec![0u8; 32]);
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(
            err.to_string().contains("signature commitment size"),
            "got: {err}"
        );
    }

    #[test]
    fn state_proof_basic_suite_rejects_nested_merkle_signature_proof_hash_type() {
        let mut txn = well_formed_stpf_txn();
        let reveal = Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    signature: ByteBuf::from(vec![1u8, 2]),
                    vector_commitment_index: 0,
                    proof: Some(MerkleProof {
                        path: None,
                        hash_factory: Some(algo_types::HashFactory {
                            hash_type: HashType::Sha256 as u16,
                        }),
                        tree_depth: 0,
                    }),
                    verifying_key: None,
                }),
                l: 0,
            }),
            part: None,
        };
        let mut reveals = BTreeMap::new();
        reveals.insert(0u64, reveal);
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.reveals = Some(reveals);
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("hash algorithm"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_nested_merkle_signature_proof_path_size() {
        let mut txn = well_formed_stpf_txn();
        let reveal = Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    signature: ByteBuf::from(vec![1u8, 2]),
                    vector_commitment_index: 0,
                    proof: Some(MerkleProof {
                        path: Some(vec![Some(ByteBuf::from(vec![0u8; 32]))]),
                        hash_factory: Some(sumhash_wire_factory()),
                        tree_depth: 0,
                    }),
                    verifying_key: None,
                }),
                l: 0,
            }),
            part: None,
        };
        let mut reveals = BTreeMap::new();
        reveals.insert(0u64, reveal);
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.reveals = Some(reveals);
        }
        let err = check_state_proof_payload(&txn).unwrap_err();
        assert!(err.to_string().contains("unexpected size"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_accepts_well_formed_nested_merkle_signature_proof() {
        let mut txn = well_formed_stpf_txn();
        let reveal = Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    signature: ByteBuf::from(vec![1u8, 2]),
                    vector_commitment_index: 0,
                    proof: Some(MerkleProof {
                        path: None,
                        hash_factory: Some(sumhash_wire_factory()),
                        tree_depth: 0,
                    }),
                    verifying_key: None,
                }),
                l: 0,
            }),
            part: None,
        };
        let mut reveals = BTreeMap::new();
        reveals.insert(0u64, reveal);
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.reveals = Some(reveals);
        }
        check_state_proof_payload(&txn).unwrap();
    }

    // ── check_payset: contiguous-group walking ─────────────────────

    #[test]
    fn check_payset_rejects_a_malformed_group_anywhere_in_the_payset() {
        let good = signed(base_txn("pay"));
        // a state proof with an all-default body is malformed
        let mut bad = base_txn("stpf");
        bad.state_proof = Some(StateProofBody::default());
        let err = check_payset(&[good, signed(bad)], false).unwrap_err();
        assert!(
            err.to_string().contains("signature commitment"),
            "got: {err}"
        );
    }

    #[test]
    fn check_payset_rejects_a_group_larger_than_the_max_group_size() {
        // TestProposalCarriesOversizedTxnGroup (go: agreement/message_test.go),
        // via go's Block.PaysetGroups: a run of MAX_GROUP_SIZE+1 consecutive
        // same-group transactions must be rejected, not silently grouped and
        // passed on to check_txn_group.
        let group_hash = [0x42u8; 32];
        let mut txns = Vec::new();
        for _ in 0..=crate::rules::MAX_GROUP_SIZE {
            let mut txn = base_txn("pay");
            txn.group = group_hash;
            txns.push(signed(txn));
        }
        let err = check_payset(&txns, false).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn check_payset_accepts_a_group_at_exactly_the_max_group_size() {
        let group_hash = [0x42u8; 32];
        let mut txns = Vec::new();
        for _ in 0..crate::rules::MAX_GROUP_SIZE {
            let mut txn = base_txn("pay");
            txn.group = group_hash;
            txns.push(signed(txn));
        }
        check_payset(&txns, false).unwrap();
    }

    #[test]
    fn check_payset_accepts_a_normal_payset() {
        let txns = vec![
            signed(base_txn("pay")),
            signed(base_txn("axfer")),
            signed(base_txn("afrz")),
        ];
        check_payset(&txns, false).unwrap();
    }
}
