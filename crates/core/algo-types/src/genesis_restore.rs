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

//! The single, protocol-aware implementation of go-algorand's payset
//! genesis-field restoration (issue #1704).
//!
//! A block stores each transaction as a `SignedTxnInBlock`: the header
//! carries the genesis id/hash once and the per-transaction copies are
//! stripped. go re-adds them in `BlockHeader.DecodeSignedTxn`
//! (`data/bookkeeping/block.go:983-1020`, go-algorand v5.0.2-stable):
//!
//! * `GenesisID` is restored from the header **only** when the txn's
//!   `HasGenesisID` (`hgi`) flag is set (an empty `gen` is otherwise a
//!   legitimate, distinct state).
//! * `GenesisHash` is restored from the header when the block's protocol has
//!   `RequireGenesisHash` (then `hgh` must be unset -- the flag is obviated),
//!   and otherwise **only** when `HasGenesisHash` (`hgh`) is set. On a
//!   hash-optional (legacy, pre-V16) protocol a txn that genuinely omitted
//!   `gh` therefore keeps it omitted, which keeps its TxID / group id / payset
//!   merkle leaf identical to what the submitter signed.
//!
//! (go also returns the txn untouched when the protocol lacks
//! `SupportSignedTxnInBlock`; that is pre-V5 and not modelled here. go
//! rejects a stripped txn that still carries a non-empty `gen`/`gh`; this
//! helper is tolerant and only fills fields that are empty/zero, which makes
//! it idempotent.)
//!
//! A block whose `current_protocol` is not in the consensus table cannot
//! occur on a supported network; it is treated as hash-requiring (modern),
//! the behaviour every pre-#1704 caller but one already had.

use crate::consensus::consensus_params_for_version;
use crate::{Block, SignedTransaction, Transaction};

/// Whether `proto` has go's `RequireGenesisHash` set (unknown protocol:
/// `true`, see the module docs).
pub fn protocol_requires_genesis_hash(proto: &str) -> bool {
    consensus_params_for_version(proto).is_none_or(|p| p.require_genesis_hash)
}

/// Fill the genesis fields `stx` had stripped, from the header's
/// `genesis_id` / `genesis_hash`. `require_genesis_hash` is the block
/// protocol's `RequireGenesisHash`. This is the one place the rule lives.
pub fn restore_genesis_fields_with(
    stx: &mut SignedTransaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    require_genesis_hash: bool,
) {
    if stx.has_genesis_id && stx.txn.genesis_id.is_empty() {
        stx.txn.genesis_id = genesis_id.to_string();
    }
    if stx.txn.genesis_hash == [0u8; 32] && (require_genesis_hash || stx.has_genesis_hash) {
        stx.txn.genesis_hash = *genesis_hash;
    }
}

/// [`restore_genesis_fields_with`] using `block`'s header and protocol.
pub fn restore_genesis_fields(stx: &mut SignedTransaction, block: &Block) {
    restore_genesis_fields_with(
        stx,
        &block.genesis_id,
        &block.genesis_hash,
        protocol_requires_genesis_hash(&block.current_protocol),
    );
}

/// Copy of the payset with every transaction's genesis fields restored
/// (go: `Block.DecodePaysetFlat`).
pub fn restore_payset_genesis_fields(block: &Block) -> Vec<SignedTransaction> {
    let req = protocol_requires_genesis_hash(&block.current_protocol);
    let mut out = block.payset.clone();
    for stx in &mut out {
        restore_genesis_fields_with(stx, &block.genesis_id, &block.genesis_hash, req);
    }
    out
}

/// The restored inner [`Transaction`] of one payset entry (what TxID, group
/// id and the payset merkle leaf are computed over).
pub fn restored_block_txn(stx: &SignedTransaction, block: &Block) -> Transaction {
    let mut t = stx.txn.clone();
    if stx.has_genesis_id && t.genesis_id.is_empty() {
        t.genesis_id.clone_from(&block.genesis_id);
    }
    if t.genesis_hash == [0u8; 32]
        && (stx.has_genesis_hash || protocol_requires_genesis_hash(&block.current_protocol))
    {
        t.genesis_hash = block.genesis_hash;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{CONSENSUS_V15, CONSENSUS_V16, CONSENSUS_V41};

    const GID: &str = "gid";
    const GH: [u8; 32] = [9u8; 32];

    fn block(proto: &str, hgi: bool, hgh: bool) -> Block {
        let stx = SignedTransaction {
            has_genesis_id: hgi,
            has_genesis_hash: hgh,
            ..SignedTransaction::default()
        };
        Block {
            genesis_id: GID.into(),
            genesis_hash: GH,
            current_protocol: proto.into(),
            payset: vec![stx],
            ..Block::default()
        }
    }

    #[test]
    fn legacy_optional_hash_without_hgh_stays_omitted() {
        assert!(!protocol_requires_genesis_hash(CONSENSUS_V15));
        for hgi in [false, true] {
            let b = block(CONSENSUS_V15, hgi, false);
            let r = restore_payset_genesis_fields(&b);
            assert_eq!(r[0].txn.genesis_hash, [0u8; 32]);
            assert_eq!(restored_block_txn(&b.payset[0], &b), r[0].txn);
            assert_eq!(r[0].txn.genesis_id, if hgi { GID } else { "" });
        }
    }

    #[test]
    fn legacy_optional_hash_with_hgh_restores() {
        let b = block(CONSENSUS_V15, false, true);
        let r = restore_payset_genesis_fields(&b);
        assert_eq!(r[0].txn.genesis_hash, GH);
        assert_eq!(r[0].txn.genesis_id, "", "gen is gated on hgi only");
        assert_eq!(restored_block_txn(&b.payset[0], &b), r[0].txn);
    }

    #[test]
    fn hash_required_protocols_restore_without_hgh() {
        for proto in [CONSENSUS_V16, CONSENSUS_V41] {
            assert!(protocol_requires_genesis_hash(proto));
            let b = block(proto, true, false);
            let r = restore_payset_genesis_fields(&b);
            assert_eq!(r[0].txn.genesis_hash, GH);
            assert_eq!(r[0].txn.genesis_id, GID);
            assert_eq!(restored_block_txn(&b.payset[0], &b), r[0].txn);
        }
    }

    #[test]
    fn unknown_protocol_is_treated_as_hash_requiring() {
        assert!(protocol_requires_genesis_hash(""));
    }

    #[test]
    fn restoration_is_idempotent() {
        let b = block(CONSENSUS_V15, true, true);
        let once = restore_payset_genesis_fields(&b);
        let mut twice = once.clone();
        restore_genesis_fields(&mut twice[0], &b);
        assert_eq!(once, twice);
    }
}
