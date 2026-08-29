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

//! Broadcast callback and drain iterator for block assembly.
//!
//! The pool itself does **not** broadcast transactions.  Instead, the caller
//! (e.g. a `TxHandler`) registers a [`TransactionBroadcaster`] callback that
//! is invoked after a transaction group has been successfully added to the
//! pool.  This mirrors the pattern in go-algorand where `txHandler` calls
//! `handler.net.Relay(...)` after `pool.Remember(...)` succeeds.
//!
//! [`DrainIterator`] yields transaction groups from the pool for block
//! assembly, consumed one group at a time.

use algo_types::SignedTransaction;

// ── Broadcast trait ─────────────────────────────────────────────

/// Callback invoked after a transaction group is added to the pool.
///
/// The implementation should relay the group to the network.  The pool
/// itself never calls this — it is meant for the caller (like a
/// `TxHandler`) to use after a successful `Remember`.
pub trait TransactionBroadcaster: Send + Sync {
    /// Called after a transaction group has been successfully added to the
    /// pool.  The implementation should relay the group to the network.
    fn broadcast_transaction_group(&self, group: &[SignedTransaction]);
}

// ── NoOpBroadcaster ─────────────────────────────────────────────

/// A [`TransactionBroadcaster`] that does nothing.
///
/// Useful for testing and standalone (non-networked) use.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpBroadcaster;

impl TransactionBroadcaster for NoOpBroadcaster {
    fn broadcast_transaction_group(&self, _group: &[SignedTransaction]) {
        // intentionally empty
    }
}

// ── DrainIterator ───────────────────────────────────────────────

/// An iterator that yields transaction groups for block assembly.
///
/// Each call to `next()` returns one group (`Vec<SignedTransaction>`).
/// This is used by the block-assembly path to iterate over the pending
/// groups extracted from the pool.
pub struct DrainIterator {
    groups: Vec<Vec<SignedTransaction>>,
    index: usize,
}

impl DrainIterator {
    /// Create a new drain iterator over the given transaction groups.
    pub fn new(groups: Vec<Vec<SignedTransaction>>) -> Self {
        Self { groups, index: 0 }
    }

    /// Returns the number of remaining groups that have not yet been yielded.
    pub fn remaining(&self) -> usize {
        self.groups.len().saturating_sub(self.index)
    }
}

impl Iterator for DrainIterator {
    type Item = Vec<SignedTransaction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.groups.len() {
            let group = std::mem::take(&mut self.groups[self.index]);
            self.index += 1;
            Some(group)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DrainIterator {}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::SignedTransaction;

    /// Helper: create a minimal signed transaction for testing.
    fn dummy_signed_txn() -> SignedTransaction {
        SignedTransaction::default()
    }

    #[test]
    fn noop_broadcaster_does_not_panic() {
        let broadcaster = NoOpBroadcaster;
        // Single transaction group.
        broadcaster.broadcast_transaction_group(&[dummy_signed_txn()]);
        // Empty group.
        broadcaster.broadcast_transaction_group(&[]);
        // Multiple transactions.
        broadcaster.broadcast_transaction_group(&[dummy_signed_txn(), dummy_signed_txn()]);
    }

    #[test]
    fn drain_iterator_yields_all_groups_in_order() {
        let groups = vec![
            vec![dummy_signed_txn()],
            vec![dummy_signed_txn(), dummy_signed_txn()],
            vec![dummy_signed_txn()],
        ];
        let mut iter = DrainIterator::new(groups.clone());

        assert_eq!(iter.remaining(), 3);
        assert_eq!(iter.len(), 3);

        let first = iter.next().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(iter.remaining(), 2);

        let second = iter.next().unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(iter.remaining(), 1);

        let third = iter.next().unwrap();
        assert_eq!(third.len(), 1);
        assert_eq!(iter.remaining(), 0);

        assert!(iter.next().is_none());
    }

    #[test]
    fn drain_iterator_empty_input() {
        let mut iter = DrainIterator::new(vec![]);
        assert_eq!(iter.remaining(), 0);
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn drain_iterator_size_hint_is_exact() {
        let groups = vec![vec![dummy_signed_txn()]; 5];
        let mut iter = DrainIterator::new(groups);

        for expected in (0..=5).rev() {
            assert_eq!(iter.size_hint(), (expected, Some(expected)));
            if expected > 0 {
                iter.next();
            }
        }
    }
}
