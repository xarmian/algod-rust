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
            "state proof SigCommit has an unexpected size: SigCommit is {} bytes, expected {hash_size}",
            sp.sig_commit.len()
        )));
    }

    check_basic_state_proof_path(sp.sig_proofs.as_ref(), HASH_TYPE, hash_size)?;
    check_basic_state_proof_path(sp.part_proofs.as_ref(), HASH_TYPE, hash_size)?;

    let Some(ref reveals) = sp.reveals else {
        return Ok(());
    };
    for reveal in reveals.values() {
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
fn check_state_proof_reveals(txn: &Transaction) -> Result<(), AlgoError> {
    let default_sp = StateProofBody::default();
    let sp = txn.state_proof.as_ref().unwrap_or(&default_sp);
    check_state_proof(txn.state_proof_type, sp)
}

/// Mirrors Go's `checkApplicationCallBoxes`: when a txn doesn't use the
/// `Access`-based resource list, every box ref's `Index` must be within
/// `ForeignApps`'s bounds (0 always refers to the called app itself).
///
/// This is a group-level check (run once per txn in `check_txn_group`,
/// independent of consensus params). `rules::validate_application_call_wellformed`
/// (issue #701) separately ports the same bound — plus the
/// `EnableBoxRefNameError` box-name-length check this function doesn't
/// cover — directly from upstream's `wellFormed`, so a box-index violation
/// is now caught by both; that's intentional redundancy, not a bug.
fn check_application_call_boxes(txn: &Transaction) -> Result<(), AlgoError> {
    if txn.access.is_some() {
        return Ok(());
    }
    let foreign_apps_len = txn.foreign_apps.as_ref().map_or(0, |v| v.len()) as u64;
    let Some(ref boxes) = txn.boxes else {
        return Ok(());
    };
    for b in boxes {
        if b.index > foreign_apps_len {
            return Err(err(
                "application transaction box index exceeds foreign apps",
            ));
        }
    }
    Ok(())
}

/// Screen a signed-transaction group for invalid transactions, mirroring
/// go-algorand's `CheckTxnGroup`. Run this *before* per-txn signature
/// verification/prep, over the same contiguous group signature
/// verification operates on (a "group" of one is still a group here).
pub fn check_txn_group(group: &[SignedTransaction]) -> Result<(), AlgoError> {
    let mut heartbeat = false;
    let mut avail_trigger = false;

    for stx in group {
        let txn = &stx.txn;
        match txn.txn_type.as_str() {
            "hb" => {
                heartbeat = true;
                if txn.heartbeat.is_none() {
                    return Err(err("heartbeat transaction is missing its heartbeat fields"));
                }
            }
            "stpf" => {
                check_state_proof_reveals(txn)?;
            }
            "appl" => {
                avail_trigger = true;
                check_application_call_boxes(txn)?;
            }
            "pay" | "keyreg" | "acfg" | "axfer" | "afrz" => {
                if triggers_resource_availability(txn) {
                    avail_trigger = true;
                }
            }
            other => {
                return Err(err(format!("transaction has an unknown type: {other}")));
            }
        }
    }

    if heartbeat && avail_trigger {
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
pub fn check_payset(payset: &[SignedTransaction]) -> Result<(), AlgoError> {
    let groups = crate::block::detect_validation_groups(payset).map_err(err)?;
    for group in groups {
        let members: Vec<SignedTransaction> = group.iter().map(|&(_, stx)| stx.clone()).collect();
        check_txn_group(&members)?;
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

    // ── Heartbeat missing fields ─────────────────────────────────

    #[test]
    fn heartbeat_missing_fields_is_rejected() {
        let mut txn = base_txn("hb");
        txn.heartbeat = None;
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("heartbeat"), "got: {err}");
    }

    #[test]
    fn heartbeat_with_fields_is_accepted() {
        let mut txn = base_txn("hb");
        txn.heartbeat = Some(HeartbeatTxnFields::default());
        check_txn_group(&[signed(txn)]).unwrap();
    }

    // ── Heartbeat grouped with resource-availability trigger ─────

    #[test]
    fn heartbeat_grouped_with_appl_is_rejected() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let appl = base_txn("appl");
        let err = check_txn_group(&[signed(hb), signed(appl)]).unwrap_err();
        assert!(err.to_string().contains("heartbeat"), "got: {err}");
    }

    #[test]
    fn heartbeat_grouped_with_asset_create_is_rejected() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let mut acfg = base_txn("acfg");
        acfg.config_asset = 0; // creation
        let err = check_txn_group(&[signed(hb), signed(acfg)]).unwrap_err();
        assert!(err.to_string().contains("heartbeat"), "got: {err}");
    }

    #[test]
    fn heartbeat_grouped_with_asset_reconfig_is_accepted() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let mut acfg = base_txn("acfg");
        acfg.config_asset = 42; // reconfigure, not create
        check_txn_group(&[signed(hb), signed(acfg)]).unwrap();
    }

    #[test]
    fn heartbeat_grouped_with_payment_is_accepted() {
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        let pay = base_txn("pay");
        check_txn_group(&[signed(hb), signed(pay)]).unwrap();
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
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn state_proof_reveal_tree_depth_exceeds_max_is_rejected() {
        let txn = stpf_txn_with_reveal(reveal_with(
            2,
            (MAX_ENCODED_TREE_DEPTH + 1) as u8,
            MAX_ENCODED_TREE_DEPTH + 1,
        ));
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("proof"), "got: {err}");
    }

    #[test]
    fn state_proof_reveal_tree_depth_exceeds_path_len_is_rejected() {
        let txn = stpf_txn_with_reveal(reveal_with(2, 5, 3));
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("proof"), "got: {err}");
    }

    #[test]
    fn state_proof_reveal_within_bounds_is_accepted() {
        let txn = stpf_txn_with_reveal(reveal_with(2, 4, 4));
        check_txn_group(&[signed(txn)]).unwrap();
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
        check_txn_group(&[signed(txn)]).unwrap();
    }

    // ── Application box index bound ────────────────────────────────

    #[test]
    fn box_index_exceeding_foreign_apps_is_rejected() {
        use algo_types::BoxRef;
        let mut txn = base_txn("appl");
        txn.foreign_apps = Some(vec![100, 200]); // len 2
        txn.boxes = Some(vec![BoxRef {
            index: 3,
            name: None,
        }]);
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("box"), "got: {err}");
    }

    #[test]
    fn box_index_within_foreign_apps_is_accepted() {
        use algo_types::BoxRef;
        let mut txn = base_txn("appl");
        txn.foreign_apps = Some(vec![100, 200]);
        txn.boxes = Some(vec![BoxRef {
            index: 2,
            name: None,
        }]);
        check_txn_group(&[signed(txn)]).unwrap();
    }

    #[test]
    fn box_index_bound_skipped_when_access_is_used() {
        use algo_types::{BoxRef, ResourceRef};
        let mut txn = base_txn("appl");
        txn.access = Some(vec![ResourceRef::default()]);
        txn.foreign_apps = None;
        txn.boxes = Some(vec![BoxRef {
            index: 99,
            name: None,
        }]);
        check_txn_group(&[signed(txn)]).unwrap();
    }

    // ── Unknown transaction type ───────────────────────────────────

    #[test]
    fn unknown_txn_type_alone_is_rejected() {
        let txn = base_txn("bogus");
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("unknown"), "got: {err}");
    }

    #[test]
    fn unknown_txn_type_grouped_after_appl_is_rejected() {
        // The crash case upstream (go-algorand's pre-fix panic): the
        // group-wide availability computation used to walk every member,
        // including an unknown type appearing after the app call that
        // triggers it.
        let appl = base_txn("appl");
        let bogus = base_txn("bogus");
        let err = check_txn_group(&[signed(appl), signed(bogus)]).unwrap_err();
        assert!(err.to_string().contains("unknown"), "got: {err}");
    }

    #[test]
    fn every_known_type_is_accepted() {
        // "stpf" is checked separately below: since `v5.0.1-stable`, an
        // all-default `StateProofBody` is itself malformed (its zero-value
        // `SigCommit`/hash factories fail `check_basic_state_proof`), so it
        // no longer belongs in a loop of types accepted with zero fields
        // set. Matches go's own test split
        // (`TestCheckTxnGroupUnknownType`/`TestCheckTxnGroupStateProofBasicSuite`,
        // `checks_test.go`, `v5.0.1-stable`).
        for t in ["pay", "keyreg", "acfg", "axfer", "afrz", "appl"] {
            let txn = base_txn(t);
            check_txn_group(&[signed(txn)])
                .unwrap_or_else(|e| panic!("type {t:?} should be accepted, got: {e}"));
        }
        // Heartbeat needs its fields populated to be accepted on its own.
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        check_txn_group(&[signed(hb)]).unwrap();

        let mut stpf = base_txn("stpf");
        stpf.state_proof = Some(well_formed_state_proof_body());
        check_txn_group(&[signed(stpf)]).unwrap();
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
        check_txn_group(&[signed(well_formed_stpf_txn())]).unwrap();
    }

    #[test]
    fn state_proof_basic_suite_rejects_unsupported_state_proof_type() {
        let mut txn = well_formed_stpf_txn();
        txn.state_proof_type = 1;
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
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
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
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
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("hash algorithm"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_sized_path_element() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.part_proofs.as_mut().unwrap().path = Some(vec![Some(ByteBuf::from(vec![0u8; 32]))]);
        }
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("unexpected size"), "got: {err}");
    }

    #[test]
    fn state_proof_basic_suite_rejects_wrong_sig_commit_size() {
        let mut txn = well_formed_stpf_txn();
        if let Some(sp) = txn.state_proof.as_mut() {
            sp.sig_commit = ByteBuf::from(vec![0u8; 32]);
        }
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
        assert!(err.to_string().contains("SigCommit"), "got: {err}");
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
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
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
        let err = check_txn_group(&[signed(txn)]).unwrap_err();
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
        check_txn_group(&[signed(txn)]).unwrap();
    }

    // ── check_payset: contiguous-group walking ─────────────────────

    #[test]
    fn check_payset_rejects_a_malformed_group_anywhere_in_the_payset() {
        let good = signed(base_txn("pay"));
        let bad = signed(base_txn("bogus"));
        let err = check_payset(&[good, bad]).unwrap_err();
        assert!(err.to_string().contains("unknown"), "got: {err}");
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
        let err = check_payset(&txns).unwrap_err();
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
        check_payset(&txns).unwrap();
    }

    #[test]
    fn check_payset_accepts_a_normal_payset() {
        let txns = vec![
            signed(base_txn("pay")),
            signed(base_txn("axfer")),
            signed(base_txn("afrz")),
        ];
        check_payset(&txns).unwrap();
    }
}
