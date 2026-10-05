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

//! Issue #1703: a block applied in `ApplyMode::Execute` evaluates a copy with
//! the genesis id/hash restored (for `txn TxID`), but the block that is
//! *stored* must stay in go's stripped `SignedTxnInBlock` form: `hgi` set,
//! empty `gen`, zero `gh`, `hgh` unset (the protocol requires the hash).

use algo_ledger::apply::apply_block_executing_app_calls;
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{Address, Block, Round, SignedTransaction};

const GENESIS_ID: &str = "test-net-v1";
const GENESIS_HASH: [u8; 32] = [7u8; 32];

fn stripped_block(payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(1),
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        fee_sink: Address([0xFE; 32]),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        txn_counter: 1001,
        payset,
        ..Block::default()
    }
}

fn stripped_stx(txn_type: &str, sender: Address) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = txn_type.into();
    stx.txn.sender = sender;
    stx.txn.fee = 1000;
    stx.has_genesis_id = true; // stripped: genesis_id empty, genesis_hash zero
    stx
}

fn funded_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = Address([0xFE; 32]);
    state.get_or_default_account_mut(&sender).micro_algos = 100_000_000;
    state
}

fn assert_stored_block_stripped(state: &LedgerState, expected_txns: usize) {
    let raw = state
        .get_block_data(1)
        .unwrap()
        .expect("block 1 must be stored");
    let stored = algo_codec::decode_block(&raw).expect("stored block decodes");
    assert_eq!(stored.payset.len(), expected_txns);
    for stx in &stored.payset {
        assert!(stx.has_genesis_id, "hgi must stay set");
        assert!(
            stx.txn.genesis_id.is_empty(),
            "stored txn must not carry gen, got {:?}",
            stx.txn.genesis_id
        );
        assert_eq!(
            stx.txn.genesis_hash, [0u8; 32],
            "stored txn must not carry gh"
        );
        assert!(!stx.has_genesis_hash, "hgh must stay unset");
    }
}

#[test]
fn pay_only_block_is_stored_stripped() {
    let sender = Address([1u8; 32]);
    let mut state = funded_state(sender);
    let mut stx = stripped_stx("pay", sender);
    stx.txn.receiver = Address([2u8; 32]);
    stx.txn.amount = 1_000_000;
    apply_block_executing_app_calls(&mut state, &stripped_block(vec![stx])).unwrap();
    assert_stored_block_stripped(&state, 1);
}

#[test]
fn app_call_block_executed_is_stored_stripped() {
    let sender = Address([1u8; 32]);
    let mut state = funded_state(sender);
    let mut stx = stripped_stx("appl", sender);
    let program = algo_avm::assembler::assemble_string("#pragma version 8\nint 1\n")
        .expect("assemble")
        .program;
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(program));
    stx.apply_data_application_id = 1001;
    apply_block_executing_app_calls(&mut state, &stripped_block(vec![stx])).unwrap();
    assert_stored_block_stripped(&state, 1);
}
