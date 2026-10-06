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

use std::borrow::Cow;

use crate::consensus::consensus_params_for_version;
use crate::{Block, SignedTransaction, Transaction};

/// Whether `proto` has go's `RequireGenesisHash` set (unknown protocol:
/// `true`, see the module docs).
pub fn protocol_requires_genesis_hash(proto: &str) -> bool {
    consensus_params_for_version(proto).is_none_or(|p| p.require_genesis_hash)
}

/// The pure per-transaction decision: which stripped fields must be
/// restored. This is the one place the go rule lives; every other helper in
/// this module is built on it so they cannot drift.
#[inline]
fn decide(stx: &SignedTransaction, require_genesis_hash: bool) -> (bool, bool) {
    let restore_id = stx.has_genesis_id && stx.txn.genesis_id.is_empty();
    let restore_hash =
        stx.txn.genesis_hash == [0u8; 32] && (require_genesis_hash || stx.has_genesis_hash);
    (restore_id, restore_hash)
}

/// A block header's genesis-restoration rule, resolved ONCE per payset (the
/// protocol lookup rebuilds `ConsensusParams`, so it must not run per
/// transaction).
#[derive(Clone, Copy, Debug)]
pub struct GenesisRestoreRule<'a> {
    genesis_id: &'a str,
    genesis_hash: &'a [u8; 32],
    require_genesis_hash: bool,
}

impl<'a> GenesisRestoreRule<'a> {
    /// Rule from explicit header fields and the protocol's
    /// `RequireGenesisHash`.
    pub fn new(
        genesis_id: &'a str,
        genesis_hash: &'a [u8; 32],
        require_genesis_hash: bool,
    ) -> Self {
        Self {
            genesis_id,
            genesis_hash,
            require_genesis_hash,
        }
    }

    /// Rule for `block`'s header and `current_protocol` (one protocol lookup).
    pub fn for_block(block: &'a Block) -> Self {
        Self::new(
            &block.genesis_id,
            &block.genesis_hash,
            protocol_requires_genesis_hash(&block.current_protocol),
        )
    }

    /// Whether `stx` has any stripped field this rule would fill in. Pure
    /// compares only: no allocation, no protocol lookup.
    #[inline]
    pub fn needs_restore(&self, stx: &SignedTransaction) -> bool {
        let (id, hash) = decide(stx, self.require_genesis_hash);
        id || hash
    }

    /// Fill the stripped genesis fields of `stx` in place.
    pub fn restore(&self, stx: &mut SignedTransaction) {
        let (id, hash) = decide(stx, self.require_genesis_hash);
        if id {
            stx.txn.genesis_id = self.genesis_id.to_string();
        }
        if hash {
            stx.txn.genesis_hash = *self.genesis_hash;
        }
    }

    /// The restored inner [`Transaction`] (what TxID, group id and the
    /// payset merkle leaf are computed over). Borrowed (no clone) when
    /// nothing needs restoring.
    pub fn restored_txn<'t>(&self, stx: &'t SignedTransaction) -> Cow<'t, Transaction> {
        let (id, hash) = decide(stx, self.require_genesis_hash);
        if !id && !hash {
            return Cow::Borrowed(&stx.txn);
        }
        let mut t = stx.txn.clone();
        if id {
            t.genesis_id = self.genesis_id.to_string();
        }
        if hash {
            t.genesis_hash = *self.genesis_hash;
        }
        Cow::Owned(t)
    }
}

/// Fill the genesis fields `stx` had stripped, from the header's
/// `genesis_id` / `genesis_hash`. `require_genesis_hash` is the block
/// protocol's `RequireGenesisHash`.
pub fn restore_genesis_fields_with(
    stx: &mut SignedTransaction,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    require_genesis_hash: bool,
) {
    GenesisRestoreRule::new(genesis_id, genesis_hash, require_genesis_hash).restore(stx);
}

/// [`restore_genesis_fields_with`] using `block`'s header and protocol.
pub fn restore_genesis_fields(stx: &mut SignedTransaction, block: &Block) {
    GenesisRestoreRule::for_block(block).restore(stx);
}

/// Copy of the payset with every transaction's genesis fields restored
/// (go: `Block.DecodePaysetFlat`).
pub fn restore_payset_genesis_fields(block: &Block) -> Vec<SignedTransaction> {
    let rule = GenesisRestoreRule::for_block(block);
    let mut out = block.payset.clone();
    for stx in &mut out {
        rule.restore(stx);
    }
    out
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
            assert_eq!(
                *GenesisRestoreRule::for_block(&b).restored_txn(&b.payset[0]),
                r[0].txn
            );
            assert_eq!(r[0].txn.genesis_id, if hgi { GID } else { "" });
        }
    }

    #[test]
    fn legacy_optional_hash_with_hgh_restores() {
        let b = block(CONSENSUS_V15, false, true);
        let r = restore_payset_genesis_fields(&b);
        assert_eq!(r[0].txn.genesis_hash, GH);
        assert_eq!(r[0].txn.genesis_id, "", "gen is gated on hgi only");
        assert_eq!(
            *GenesisRestoreRule::for_block(&b).restored_txn(&b.payset[0]),
            r[0].txn
        );
    }

    #[test]
    fn hash_required_protocols_restore_without_hgh() {
        for proto in [CONSENSUS_V16, CONSENSUS_V41] {
            assert!(protocol_requires_genesis_hash(proto));
            let b = block(proto, true, false);
            let r = restore_payset_genesis_fields(&b);
            assert_eq!(r[0].txn.genesis_hash, GH);
            assert_eq!(r[0].txn.genesis_id, GID);
            assert_eq!(
                *GenesisRestoreRule::for_block(&b).restored_txn(&b.payset[0]),
                r[0].txn
            );
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

    #[test]
    fn restored_txn_and_restore_agree_over_the_full_matrix() {
        let gh = [9u8; 32];
        for hgi in [false, true] {
            for hgh in [false, true] {
                for gen in ["", "own"] {
                    for stx_gh in [[0u8; 32], [5u8; 32]] {
                        for req in [false, true] {
                            let mut stx = SignedTransaction {
                                has_genesis_id: hgi,
                                has_genesis_hash: hgh,
                                ..SignedTransaction::default()
                            };
                            stx.txn.genesis_id = gen.into();
                            stx.txn.genesis_hash = stx_gh;
                            let rule = GenesisRestoreRule::new(GID, &gh, req);
                            let mut inplace = stx.clone();
                            rule.restore(&mut inplace);
                            let cow = rule.restored_txn(&stx);
                            assert_eq!(*cow, inplace.txn);
                            assert_eq!(rule.needs_restore(&stx), inplace != stx);
                            assert_eq!(
                                matches!(cow, Cow::Borrowed(_)),
                                !rule.needs_restore(&stx),
                                "borrowed iff nothing to restore"
                            );
                            // go matrix.
                            let want_id = if hgi && gen.is_empty() { GID } else { gen };
                            let want_gh = if stx_gh == [0u8; 32] && (req || hgh) {
                                gh
                            } else {
                                stx_gh
                            };
                            assert_eq!(inplace.txn.genesis_id, want_id);
                            assert_eq!(inplace.txn.genesis_hash, want_gh);
                        }
                    }
                }
            }
        }
    }
}
