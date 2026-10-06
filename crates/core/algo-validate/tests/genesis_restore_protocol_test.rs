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

//! Issue #1704: payset genesis-field restoration is protocol-aware (go
//! `BlockHeader.DecodeSignedTxn`, data/bookkeeping/block.go:983-1020), for
//! both `restore_payset_genesis_fields` and the payset merkle leaf txid.

use algo_types::consensus::{CONSENSUS_V15, CONSENSUS_V41};
use algo_types::{Block, SignedTransaction};
use algo_validate::merkle::compute_payset_merkle_root;
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
    let r = restore_payset_genesis_fields(&b);
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
        restore_payset_genesis_fields(&b)[0].txn.genesis_hash,
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
        restore_payset_genesis_fields(&b)[0].txn.genesis_hash,
        [9u8; 32]
    );
}

/// Unknown protocol: validate_block reports it explicitly (go: "consensus
/// protocol not found") and restoration agrees by treating it as
/// hash-requiring (never silently hash-optional).
#[test]
fn unknown_protocol_is_rejected_and_restored_as_hash_requiring() {
    let b = block("no-such-protocol", false, [9u8; 32]);
    assert_eq!(
        restore_payset_genesis_fields(&b)[0].txn.genesis_hash,
        [9u8; 32]
    );
    let res = algo_validate::validate_block(&b, None, "gid", &[9u8; 32], None);
    assert!(res.errors.iter().any(|e| matches!(
        e,
        algo_validate::BlockValidationError::UnknownProtocolVersion { .. }
    )));
}
