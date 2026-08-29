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

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::Address;

/// Tracks active transaction leases to prevent duplicate transactions
/// within a validity window.
///
/// A lease is a (sender, lease_value) pair that locks out duplicate
/// transactions from the same sender with the same lease until the
/// original transaction's last_valid round has passed.
#[derive(Debug, Default, Clone)]
pub struct LeaseTable {
    /// Maps (sender, lease) to the last_valid round of the recorded transaction.
    entries: HashMap<(Address, [u8; 32]), u64>,
}

/// A lease value of all zeros is treated as "no lease" and is always allowed.
const EMPTY_LEASE: [u8; 32] = [0u8; 32];

impl LeaseTable {
    /// Create an empty lease table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a transaction with the given sender and lease is allowed
    /// at `current_round`.
    ///
    /// - An all-zero lease (empty) is always allowed.
    /// - Otherwise, if an entry exists for (sender, lease) with
    ///   `stored_last_valid >= current_round`, the lease is still active
    ///   and the transaction is rejected as a duplicate.
    pub fn check(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError> {
        if *lease == EMPTY_LEASE {
            return Ok(());
        }

        if let Some(&stored_last_valid) = self.entries.get(&(*sender, *lease)) {
            if stored_last_valid >= current_round {
                return Err(AlgoError::Ledger {
                    message: "duplicate lease".into(),
                });
            }
        }

        Ok(())
    }

    /// Record a lease for the given sender. If the lease is all zeros,
    /// this is a no-op. Otherwise, the (sender, lease) entry is set to
    /// `last_valid`.
    pub fn record(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        if *lease == EMPTY_LEASE {
            return;
        }
        self.entries.insert((*sender, *lease), last_valid);
    }

    /// Remove all entries whose `last_valid` is strictly less than
    /// `current_round`. These leases have expired and no longer need
    /// to block new transactions.
    pub fn purge_expired(&mut self, current_round: u64) {
        self.entries
            .retain(|_, &mut last_valid| last_valid >= current_round);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn test_lease(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn test_empty_lease_allowed() {
        let mut table = LeaseTable::new();
        let sender = test_address(1);
        let empty = [0u8; 32];

        // Empty lease always passes, even after recording
        assert!(table.check(&sender, &empty, 100).is_ok());
        table.record(&sender, &empty, 200);
        assert!(table.check(&sender, &empty, 100).is_ok());
    }

    #[test]
    fn test_lease_check_and_record() {
        let mut table = LeaseTable::new();
        let sender = test_address(1);
        let lease = test_lease(0xAA);

        // Before recording, check passes
        assert!(table.check(&sender, &lease, 100).is_ok());

        // Record with last_valid = 150
        table.record(&sender, &lease, 150);

        // Now check at round 100 (within window) should fail
        let err = table.check(&sender, &lease, 100).unwrap_err();
        assert!(err.to_string().contains("duplicate lease"));
    }

    #[test]
    fn test_duplicate_lease_rejected() {
        let mut table = LeaseTable::new();
        let sender = test_address(2);
        let lease = test_lease(0xBB);

        table.record(&sender, &lease, 200);

        // Same sender, same lease, round within validity window
        assert!(table.check(&sender, &lease, 150).is_err());
        assert!(table.check(&sender, &lease, 200).is_err()); // at exact last_valid
    }

    #[test]
    fn test_lease_expired_allowed() {
        let mut table = LeaseTable::new();
        let sender = test_address(3);
        let lease = test_lease(0xCC);

        // Record with last_valid = 100
        table.record(&sender, &lease, 100);

        // Check at round 101 (past last_valid) should succeed
        assert!(table.check(&sender, &lease, 101).is_ok());
    }

    #[test]
    fn test_purge_expired() {
        let mut table = LeaseTable::new();
        let sender = test_address(4);
        let lease_a = test_lease(0xDD);
        let lease_b = test_lease(0xEE);

        table.record(&sender, &lease_a, 100);
        table.record(&sender, &lease_b, 200);

        // Purge at round 150: lease_a (last_valid=100) removed, lease_b kept
        table.purge_expired(150);

        assert!(table.check(&sender, &lease_a, 100).is_ok()); // purged
        assert!(table.check(&sender, &lease_b, 150).is_err()); // still active
    }

    #[test]
    fn test_different_sender_same_lease_ok() {
        let mut table = LeaseTable::new();
        let sender_a = test_address(5);
        let sender_b = test_address(6);
        let lease = test_lease(0xFF);

        table.record(&sender_a, &lease, 200);

        // Different sender with same lease value is allowed
        assert!(table.check(&sender_b, &lease, 100).is_ok());
    }
}
