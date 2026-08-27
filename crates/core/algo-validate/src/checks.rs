//! Group-level transaction screen (go-algorand v4.7.2-stable `data/transactions/checks.go`).
//!
//! `check_txn_group`/`check_payset` mirror go-algorand's `CheckTxnGroup`/
//! `CheckPayset`: a screen run over a signed-txn group (or a whole payset,
//! walked in contiguous same-group runs) *before* per-txn signature
//! verification, rejecting a group that is structurally malformed in ways
//! signature verification alone wouldn't catch.

use algo_consensus_crypto::merklearray::MAX_ENCODED_TREE_DEPTH;
use algo_error::AlgoError;
use algo_types::{MerkleSignature, SignedTransaction, Transaction};

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

/// Mirrors Go's `checkStateProofReveals`: for a state-proof txn, every
/// reveal whose signature isn't the zero value must have a signature of at
/// least 2 bytes and a proof `TreeDepth` that is both within
/// `MAX_ENCODED_TREE_DEPTH` and consistent with the proof's own path length.
fn check_state_proof_reveals(txn: &Transaction) -> Result<(), AlgoError> {
    let Some(ref sp) = txn.state_proof else {
        return Ok(());
    };
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
    }
    Ok(())
}

/// Mirrors Go's `checkApplicationCallBoxes`: when a txn doesn't use the
/// `Access`-based resource list, every box ref's `Index` must be within
/// `ForeignApps`'s bounds (0 always refers to the called app itself).
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
    for group in crate::block::detect_validation_groups(payset) {
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

    fn reveal_with(sig_len: usize, tree_depth: u8, path_len: usize) -> Reveal {
        Reveal {
            sig_slot: Some(SigSlotCommit {
                sig: Some(MerkleSignature {
                    signature: ByteBuf::from(vec![7u8; sig_len]),
                    vector_commitment_index: 0,
                    proof: Some(MerkleProof {
                        path: Some(vec![Some(ByteBuf::from(vec![0u8; 32])); path_len]),
                        hash_factory: None,
                        tree_depth,
                    }),
                    verifying_key: None,
                }),
                l: 0,
            }),
            part: None,
        }
    }

    fn stpf_txn_with_reveal(reveal: Reveal) -> Transaction {
        let mut txn = base_txn("stpf");
        let mut reveals = BTreeMap::new();
        reveals.insert(0u64, reveal);
        txn.state_proof = Some(StateProofBody {
            reveals: Some(reveals),
            ..Default::default()
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
        for t in ["pay", "keyreg", "acfg", "axfer", "afrz", "appl", "stpf"] {
            let txn = base_txn(t);
            check_txn_group(&[signed(txn)])
                .unwrap_or_else(|e| panic!("type {t:?} should be accepted, got: {e}"));
        }
        // Heartbeat needs its fields populated to be accepted on its own.
        let mut hb = base_txn("hb");
        hb.heartbeat = Some(HeartbeatTxnFields::default());
        check_txn_group(&[signed(hb)]).unwrap();
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
    fn check_payset_accepts_a_normal_payset() {
        let txns = vec![
            signed(base_txn("pay")),
            signed(base_txn("axfer")),
            signed(base_txn("afrz")),
        ];
        check_payset(&txns).unwrap();
    }
}
