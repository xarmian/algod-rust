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

//! Inner transaction types and helpers.
//!
//! Provides `InnerTxnId` computation matching go-algorand's `Transaction.InnerID`
//! and shared constants used across inner transaction handling.

use algo_types::{Digest, Transaction};
use sha2::{Digest as Sha2Digest, Sha512_256};

/// Domain separation prefix for transaction hashing (same as outer txn IDs).
const TX_HASH_PREFIX: &[u8] = b"TX";

/// Compute an inner transaction ID.
///
/// Matches go-algorand's `Transaction.InnerID(parent, index)`:
///   `SHA512/256("TX" || parent_txid || big_endian_u64(index) || canonical_encode(inner_txn))`
///
/// The inner txn ID incorporates the parent transaction's ID and the offset
/// (position within the parent's inner txn list) to ensure uniqueness even when
/// the inner transaction fields are identical.
pub fn compute_inner_txn_id(
    parent_txid: &Digest,
    offset: usize,
    inner_txn: &Transaction,
) -> Digest {
    let canonical = algo_codec::canonical_encode_transaction(inner_txn);
    let mut hasher = Sha512_256::new();
    hasher.update(TX_HASH_PREFIX);
    hasher.update(parent_txid.0);
    hasher.update((offset as u64).to_be_bytes());
    hasher.update(&canonical);
    Digest(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Transaction};

    #[test]
    fn inner_txn_id_deterministic() {
        let parent = Digest([0xAB; 32]);
        let txn = Transaction {
            txn_type: algo_types::TxnType::Pay,
            sender: Address([1u8; 32]),
            fee: 1000,
            ..Default::default()
        };

        let id1 = compute_inner_txn_id(&parent, 0, &txn);
        let id2 = compute_inner_txn_id(&parent, 0, &txn);
        assert_eq!(id1.0, id2.0, "same inputs should produce same ID");
    }

    #[test]
    fn inner_txn_id_varies_with_offset() {
        let parent = Digest([0xAB; 32]);
        let txn = Transaction {
            txn_type: algo_types::TxnType::Pay,
            sender: Address([1u8; 32]),
            fee: 1000,
            ..Default::default()
        };

        let id0 = compute_inner_txn_id(&parent, 0, &txn);
        let id1 = compute_inner_txn_id(&parent, 1, &txn);
        assert_ne!(
            id0.0, id1.0,
            "different offsets should produce different IDs"
        );
    }

    #[test]
    fn inner_txn_id_varies_with_parent() {
        let parent_a = Digest([0xAA; 32]);
        let parent_b = Digest([0xBB; 32]);
        let txn = Transaction {
            txn_type: algo_types::TxnType::Pay,
            sender: Address([1u8; 32]),
            fee: 1000,
            ..Default::default()
        };

        let id_a = compute_inner_txn_id(&parent_a, 0, &txn);
        let id_b = compute_inner_txn_id(&parent_b, 0, &txn);
        assert_ne!(
            id_a.0, id_b.0,
            "different parents should produce different IDs"
        );
    }
}
