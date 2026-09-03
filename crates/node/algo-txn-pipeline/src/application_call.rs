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

//! Pure (I/O-free) builder for application-call transactions.
//!
//! Mirrors go-algorand's `libgoal.Client.MakeUnsignedApplicationCallTx`
//! (`libgoal/libgoal.go`): an application-call transaction carrying the
//! app id, on-completion action, application args, optional
//! approval/clear-state programs + state schemas (create/update), extra
//! program pages, reject-version, plus the common header fields (validity
//! window, fee, genesis, lease, note, rekey-to).
//!
//! Like [`PaymentBuilder`](crate::PaymentBuilder), this builder does not
//! attach the foreign-resource arrays / access list itself — go's
//! `MakeUnsignedApplicationCallTx` takes a `libgoal.RefBundle` and lowers it
//! internally, but `goal-rust` already has that lowering as a standalone,
//! independently tested module
//! ([`resource_resolution::attach_references`](../../../tools/goal-rust/src/resource_resolution.rs)
//! in the `goal-rust` crate, since `algo-txn-pipeline` is a lower crate that
//! cannot depend on a `crates/tools/*` binary crate). Callers build the
//! transaction here, then call `attach_references` themselves.

use algo_types::{Address, Round, StateSchema, Transaction, TxnType};
use serde_bytes::ByteBuf;

use crate::error::{PipelineError, Result};

/// Builder for an application-call [`Transaction`].
///
/// Construct via [`ApplicationCallBuilder::new`], set the app-specific
/// fields (arguments, programs, schemas) and the common header fields, then
/// [`build`](ApplicationCallBuilder::build).
#[derive(Debug, Clone)]
pub struct ApplicationCallBuilder {
    sender: Address,
    application_id: u64,
    on_completion: u64,
    app_arguments: Vec<Vec<u8>>,
    approval_program: Option<Vec<u8>>,
    clear_state_program: Option<Vec<u8>>,
    global_state_schema: Option<StateSchema>,
    local_state_schema: Option<StateSchema>,
    extra_program_pages: u32,
    reject_version: u64,
    rekey_to: Option<Address>,
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: String,
    lease: [u8; 32],
    note: Vec<u8>,
}

impl ApplicationCallBuilder {
    /// Start an application call from `sender` against `application_id`
    /// (`0` for `app create`) with the given `on_completion` action (the
    /// numeric `OnCompletion` value: `0` NoOp, `1` OptIn, `2` CloseOut, `3`
    /// ClearState, `4` UpdateApplication, `5` DeleteApplication).
    pub fn new(sender: Address, application_id: u64, on_completion: u64) -> Self {
        ApplicationCallBuilder {
            sender,
            application_id,
            on_completion,
            app_arguments: Vec::new(),
            approval_program: None,
            clear_state_program: None,
            global_state_schema: None,
            local_state_schema: None,
            extra_program_pages: 0,
            reject_version: 0,
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

    /// Set the ABI-encoded application arguments (`appArgs[0]` is
    /// conventionally the ARC-4 method selector when calling a method).
    pub fn app_arguments(mut self, args: Vec<Vec<u8>>) -> Self {
        self.app_arguments = args;
        self
    }

    /// Set the (compiled) approval program. Required for `app create` /
    /// `app update`.
    pub fn approval_program(mut self, program: Vec<u8>) -> Self {
        self.approval_program = Some(program);
        self
    }

    /// Set the (compiled) clear-state program. Required for `app create` /
    /// `app update`.
    pub fn clear_state_program(mut self, program: Vec<u8>) -> Self {
        self.clear_state_program = Some(program);
        self
    }

    /// Set the global state schema (only meaningful on `app create`).
    pub fn global_state_schema(mut self, schema: StateSchema) -> Self {
        self.global_state_schema = Some(schema);
        self
    }

    /// Set the local state schema (only meaningful on `app create`).
    pub fn local_state_schema(mut self, schema: StateSchema) -> Self {
        self.local_state_schema = Some(schema);
        self
    }

    /// Set the extra program pages (create/update only).
    pub fn extra_program_pages(mut self, pages: u32) -> Self {
        self.extra_program_pages = pages;
        self
    }

    /// Set the reject-version.
    pub fn reject_version(mut self, version: u64) -> Self {
        self.reject_version = version;
        self
    }

    /// Rekey the sender account to this spending key/address.
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

    /// Set the genesis hash.
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

    /// Finalize the builder into a [`Transaction`]. The caller is
    /// responsible for attaching foreign-resource arrays / the access list
    /// (see the module docs).
    pub fn build(self) -> Result<Transaction> {
        if self.last_valid < self.first_valid {
            return Err(PipelineError::InvalidValidity(format!(
                "last_valid ({}) < first_valid ({})",
                self.last_valid, self.first_valid
            )));
        }

        let app_arguments = if self.app_arguments.is_empty() {
            None
        } else {
            Some(
                self.app_arguments
                    .into_iter()
                    .map(|a| Some(ByteBuf::from(a)))
                    .collect(),
            )
        };

        Ok(Transaction {
            txn_type: TxnType::Appl,
            sender: self.sender,
            fee: self.fee,
            first_valid: Round(self.first_valid),
            last_valid: Round(self.last_valid),
            genesis_id: self.genesis_id,
            genesis_hash: self.genesis_hash,
            lease: self.lease,
            note: self.note.into(),
            rekey_to: self.rekey_to,
            application_id: self.application_id,
            on_completion: self.on_completion,
            approval_program: self.approval_program.map(ByteBuf::from),
            clear_state_program: self.clear_state_program.map(ByteBuf::from),
            app_arguments,
            global_state_schema: self.global_state_schema,
            local_state_schema: self.local_state_schema,
            extra_program_pages: self.extra_program_pages,
            reject_version: self.reject_version,
            ..Transaction::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_go_compatible_app_call_fields() {
        let sender = Address([0xAA; 32]);
        let txn = ApplicationCallBuilder::new(sender, 111, 0)
            .fee(1000)
            .validity(500, 1500)
            .genesis_hash([0x9; 32])
            .app_arguments(vec![vec![1, 2, 3, 4], vec![0xAB]])
            .build()
            .unwrap();

        assert_eq!(txn.txn_type, TxnType::Appl);
        assert_eq!(txn.sender, sender);
        assert_eq!(txn.application_id, 111);
        assert_eq!(txn.on_completion, 0);
        assert_eq!(txn.fee, 1000);
        assert_eq!(txn.first_valid, Round(500));
        assert_eq!(txn.last_valid, Round(1500));
        assert_eq!(txn.genesis_hash, [0x9; 32]);
        let args = txn.app_arguments.unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].as_ref().unwrap().as_ref(), &[1, 2, 3, 4]);
        assert_eq!(args[1].as_ref().unwrap().as_ref(), &[0xAB]);
    }

    #[test]
    fn empty_app_arguments_stays_none() {
        let txn = ApplicationCallBuilder::new(Address([0xAA; 32]), 111, 0)
            .validity(10, 1010)
            .build()
            .unwrap();
        assert!(txn.app_arguments.is_none());
    }

    #[test]
    fn create_txn_carries_programs_and_schemas() {
        let txn = ApplicationCallBuilder::new(Address([0xAA; 32]), 0, 0)
            .validity(10, 1010)
            .approval_program(vec![0x06, 0x81, 0x01])
            .clear_state_program(vec![0x06, 0x81, 0x01])
            .global_state_schema(StateSchema {
                num_uint: 1,
                num_byte_slice: 2,
            })
            .local_state_schema(StateSchema {
                num_uint: 3,
                num_byte_slice: 4,
            })
            .extra_program_pages(1)
            .build()
            .unwrap();

        assert_eq!(txn.application_id, 0);
        assert_eq!(
            txn.approval_program.as_ref().unwrap().as_ref(),
            &[0x06, 0x81, 0x01]
        );
        assert_eq!(
            txn.clear_state_program.as_ref().unwrap().as_ref(),
            &[0x06, 0x81, 0x01]
        );
        assert_eq!(txn.global_state_schema.unwrap().num_uint, 1);
        assert_eq!(txn.local_state_schema.unwrap().num_byte_slice, 4);
        assert_eq!(txn.extra_program_pages, 1);
    }

    #[test]
    fn reject_version_and_rekey_round_trip() {
        let rekey = Address([0xDD; 32]);
        let txn = ApplicationCallBuilder::new(Address([0xAA; 32]), 5, 4)
            .validity(10, 1010)
            .reject_version(3)
            .rekey_to(rekey)
            .build()
            .unwrap();
        assert_eq!(txn.reject_version, 3);
        assert_eq!(txn.rekey_to, Some(rekey));
        assert_eq!(txn.on_completion, 4);
    }

    #[test]
    fn build_rejects_inverted_validity_window() {
        let err = ApplicationCallBuilder::new(Address([0xAA; 32]), 1, 0)
            .validity(1000, 500)
            .build()
            .unwrap_err();
        assert!(matches!(err, PipelineError::InvalidValidity(_)));
    }
}
