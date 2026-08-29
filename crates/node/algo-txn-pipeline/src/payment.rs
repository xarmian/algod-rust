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

//! Pure (I/O-free) builder for payment transactions.
//!
//! Mirrors go-algorand's `libgoal.Client.ConstructPayment`
//! (`libgoal/libgoal.go:571`): a payment transaction carrying sender,
//! receiver, amount, optional close-remainder-to and rekey-to, plus the common
//! header fields (validity window, fee, genesis, lease, note).
//!
//! Like [`KeyregBuilder`](crate::KeyregBuilder), the builder is free of network
//! access: callers fetch suggested params via the
//! [`TxnPipeline`](crate::TxnPipeline) and feed the resolved validity window,
//! genesis hash, etc. in, so construction stays unit-testable against fixtures.

use algo_types::{Address, Round, Transaction, TxnType};

use crate::error::{PipelineError, Result};

/// Builder for a payment [`Transaction`].
///
/// Construct via [`PaymentBuilder::new`], set the header fields (validity
/// window, fee, genesis, lease, note, close-to, rekey-to), then
/// [`build`](PaymentBuilder::build).
#[derive(Debug, Clone)]
pub struct PaymentBuilder {
    sender: Address,
    receiver: Address,
    amount: u64,
    close_remainder_to: Option<Address>,
    rekey_to: Option<Address>,
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: String,
    lease: [u8; 32],
    note: Vec<u8>,
}

impl PaymentBuilder {
    /// Start a payment of `amount` microAlgos from `sender` to `receiver`.
    pub fn new(sender: Address, receiver: Address, amount: u64) -> Self {
        PaymentBuilder {
            sender,
            receiver,
            amount,
            close_remainder_to: None,
            rekey_to: None,
            fee: 0,
            first_valid: 0,
            last_valid: 0,
            genesis_hash: [0u8; 32],
            genesis_id: String::new(),
            lease: [0u8; 32],
            note: Vec::new(),
        }
    }

    /// Close the sender account, sending its remaining balance to this address.
    /// Mirrors Go's `--close-to` (`ConstructPayment`'s `closeTo`).
    pub fn close_remainder_to(mut self, addr: Address) -> Self {
        self.close_remainder_to = Some(addr);
        self
    }

    /// Rekey the sender account to this spending key/address. Mirrors Go's
    /// `--rekey-to` (`clerk.go` sets `payment.RekeyTo`).
    pub fn rekey_to(mut self, addr: Address) -> Self {
        self.rekey_to = Some(addr);
        self
    }

    /// Set the transaction fee (microAlgos).
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Set the validity window `[first_valid, last_valid]`.
    pub fn validity(mut self, first_valid: u64, last_valid: u64) -> Self {
        self.first_valid = first_valid;
        self.last_valid = last_valid;
        self
    }

    /// Set the genesis hash (required for the transaction to be accepted on a
    /// network that supports genesis hashes, i.e. every current network).
    pub fn genesis_hash(mut self, genesis_hash: [u8; 32]) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Set the genesis id (informational; not committed to the txid).
    pub fn genesis_id(mut self, genesis_id: impl Into<String>) -> Self {
        self.genesis_id = genesis_id.into();
        self
    }

    /// Set the 32-byte lease.
    pub fn lease(mut self, lease: [u8; 32]) -> Self {
        self.lease = lease;
        self
    }

    /// Set the note field.
    pub fn note(mut self, note: Vec<u8>) -> Self {
        self.note = note;
        self
    }

    /// Finalize the builder into a [`Transaction`].
    pub fn build(self) -> Result<Transaction> {
        if self.last_valid < self.first_valid {
            return Err(PipelineError::InvalidValidity(format!(
                "last_valid ({}) < first_valid ({})",
                self.last_valid, self.first_valid
            )));
        }

        let mut txn = Transaction {
            txn_type: TxnType::Pay,
            sender: self.sender,
            fee: self.fee,
            first_valid: Round(self.first_valid),
            last_valid: Round(self.last_valid),
            genesis_id: self.genesis_id,
            genesis_hash: self.genesis_hash,
            lease: self.lease,
            note: self.note.into(),
            amount: self.amount,
            receiver: self.receiver,
            rekey_to: self.rekey_to,
            ..Transaction::default()
        };
        if let Some(close) = self.close_remainder_to {
            txn.close_remainder_to = close;
        }

        Ok(txn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_go_compatible_payment_fields() {
        let sender = Address([0xAA; 32]);
        let receiver = Address([0xBB; 32]);
        let txn = PaymentBuilder::new(sender, receiver, 1_000_000)
            .fee(1000)
            .validity(500, 1500)
            .genesis_hash([0x9; 32])
            .build()
            .unwrap();

        assert_eq!(txn.txn_type, TxnType::Pay);
        assert_eq!(txn.sender, sender);
        assert_eq!(txn.receiver, receiver);
        assert_eq!(txn.amount, 1_000_000);
        assert_eq!(txn.fee, 1000);
        assert_eq!(txn.first_valid, Round(500));
        assert_eq!(txn.last_valid, Round(1500));
        assert_eq!(txn.genesis_hash, [0x9; 32]);
        assert!(txn.close_remainder_to.is_zero());
        assert_eq!(txn.rekey_to, None);
    }

    #[test]
    fn close_and_rekey_are_optional() {
        let close = Address([0xCC; 32]);
        let rekey = Address([0xDD; 32]);
        let txn = PaymentBuilder::new(Address([0xAA; 32]), Address([0xBB; 32]), 0)
            .validity(10, 1010)
            .close_remainder_to(close)
            .rekey_to(rekey)
            .build()
            .unwrap();

        assert_eq!(txn.close_remainder_to, close);
        assert_eq!(txn.rekey_to, Some(rekey));
    }

    #[test]
    fn note_and_lease_round_trip() {
        let txn = PaymentBuilder::new(Address([0xAA; 32]), Address([0xBB; 32]), 42)
            .validity(10, 1010)
            .note(vec![1, 2, 3, 4])
            .lease([0x7; 32])
            .build()
            .unwrap();

        assert_eq!(txn.note.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(txn.lease, [0x7; 32]);
    }

    #[test]
    fn build_rejects_inverted_validity_window() {
        let err = PaymentBuilder::new(Address([0xAA; 32]), Address([0xBB; 32]), 1)
            .validity(1000, 500)
            .build()
            .unwrap_err();
        assert!(matches!(err, PipelineError::InvalidValidity(_)));
    }
}
