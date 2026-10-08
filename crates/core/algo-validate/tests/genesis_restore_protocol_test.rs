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

//! Issue #1704: payset genesis-field restoration is protocol-aware (go
//! `BlockHeader.DecodeSignedTxn`, data/bookkeeping/block.go:983-1020), for
//! both `restore_payset_genesis_fields` and the payset merkle leaf txid.

use algo_types::consensus::{CONSENSUS_V15, CONSENSUS_V41};
use algo_types::{Block, SignedTransaction};
use algo_validate::merkle::{compute_payset_merkle_root, compute_payset_merkle_root_raw, HashAlgo};
use algo_validate::restore_payset_genesis_fields;

fn block(proto: &str, hgh: bool, header_gh: [u8; 32]) -> Block {
    let txn = algo_types::Transaction {
        txn_type: "pay".into(),
        fee: 1000,
        ..Default::default()
    };
    let stx = SignedTransaction {
        txn,
        has_genesis_id: true,
        has_genesis_hash: hgh,
        ..SignedTransaction::default()
    };
    Block {
        genesis_id: "gid".into(),
        genesis_hash: header_gh,
        current_protocol: proto.into(),
        payset: vec![stx],
        ..Block::default()
    }
}

#[test]
fn hash_optional_protocol_without_hgh_keeps_gh_omitted() {
    let b = block(CONSENSUS_V15, false, [9u8; 32]);
    let r = restore_payset_genesis_fields(&b).unwrap();
    assert_eq!(r[0].txn.genesis_hash, [0u8; 32]);
    assert_eq!(r[0].txn.genesis_id, "gid");
    // Merkle leaf txid is computed over the same (gh-less) txn: identical to
    // the root of a block with nothing to restore.
    let mut no_hash_header = b.clone();
    no_hash_header.genesis_hash = [0u8; 32];
    assert_eq!(
        compute_payset_merkle_root(&b),
        compute_payset_merkle_root(&no_hash_header)
    );
}

#[test]
fn hash_optional_protocol_with_hgh_restores_gh() {
    let b = block(CONSENSUS_V15, true, [9u8; 32]);
    assert_eq!(
        restore_payset_genesis_fields(&b).unwrap()[0]
            .txn
            .genesis_hash,
        [9u8; 32]
    );
    let mut no_hash_header = b.clone();
    no_hash_header.genesis_hash = [0u8; 32];
    assert_ne!(
        compute_payset_merkle_root(&b),
        compute_payset_merkle_root(&no_hash_header)
    );
}

#[test]
fn hash_required_protocol_restores_gh_without_hgh() {
    let b = block(CONSENSUS_V41, false, [9u8; 32]);
    assert_eq!(
        restore_payset_genesis_fields(&b).unwrap()[0]
            .txn
            .genesis_hash,
        [9u8; 32]
    );
}

/// Unknown protocol: `validate_block` reports it explicitly (go: "consensus
/// protocol not found") and so does restoration -- an error, never a silent
/// guess (issue #1728).
#[test]
fn unknown_protocol_is_rejected_by_validate_and_restore() {
    let b = block("no-such-protocol", false, [9u8; 32]);
    let err = restore_payset_genesis_fields(&b).unwrap_err();
    assert_eq!(
        err.to_string(),
        "consensus protocol no-such-protocol not found"
    );
    let res = algo_validate::validate_block(&b, None, "gid", &[9u8; 32], None);
    assert!(res.errors.iter().any(|e| matches!(
        e,
        algo_validate::BlockValidationError::UnknownProtocolVersion { .. }
    )));
}

/// Issue #1728: the merkle / vector-commitment leaf builders resolve the
/// genesis rule per block; none of them may rebuild and clone a whole
/// `ConsensusParams` to do it.
#[test]
fn commitment_builders_do_no_consensus_params_lookup() {
    use algo_types::consensus::{consensus_params_lookup_count, genesis_flags_for_version};
    let _ = genesis_flags_for_version(CONSENSUS_V41); // warm the one-time table
    for proto in [CONSENSUS_V15, CONSENSUS_V41] {
        let b = block(proto, true, [9u8; 32]);
        let blobs = vec![vec![0x80u8]];
        let before = consensus_params_lookup_count();
        let _ = compute_payset_merkle_root(&b);
        let _ = compute_payset_merkle_root_raw(&b, &blobs);
        let _ = algo_validate::merkle::compute_vector_commitment(&b, HashAlgo::Sha256);
        let _ = algo_validate::merkle::compute_vector_commitment_raw(&b, HashAlgo::Sha512, &blobs);
        let _ = restore_payset_genesis_fields(&b).unwrap();
        assert_eq!(consensus_params_lookup_count(), before, "{proto}");
    }
}
