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
//! empty `gen`, zero `gh`, `hgh` unset when the protocol requires the hash
//! (and set when it is optional and the submitter included it).
//! The pay-only Execute tests and the app-call test cover the Execute path
//! (where the restored copy exists); one test covers the real dispatch.
//! The app-call test pins both halves: evaluation sees the full transaction
//! (`txn TxID`), the stored bytes stay stripped.

use algo_ledger::apply::{apply_block_executing_app_calls, apply_block_with_mode, ApplyMode};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V15, CONSENSUS_V41};
use algo_types::{Address, Block, BoxRef, Round, SignedTransaction};

const GENESIS_ID: &str = "test-net-v1";
const GENESIS_HASH: [u8; 32] = [7u8; 32];

fn stripped_block(proto: &str, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(1),
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        fee_sink: Address([0xFE; 32]),
        current_protocol: proto.to_string(),
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
    stx.txn.first_valid = Round(1);
    stx.txn.last_valid = Round(1000);
    stx.has_genesis_id = true; // stripped: genesis_id empty, genesis_hash zero
    stx
}

fn funded_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = Address([0xFE; 32]);
    state.get_or_default_account_mut(&sender).micro_algos = 100_000_000;
    state
}

fn stored_block(state: &LedgerState, expected_txns: usize) -> Block {
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
    }
    stored
}

fn pay_block(proto: &str, hgh: bool) -> (LedgerState, Block) {
    let sender = Address([1u8; 32]);
    let state = funded_state(sender);
    let mut stx = stripped_stx("pay", sender);
    stx.txn.receiver = Address([2u8; 32]);
    stx.txn.amount = 1_000_000;
    stx.has_genesis_hash = hgh;
    (state, stripped_block(proto, vec![stx]))
}

fn assert_requires_hash(proto: &str, required: bool) {
    assert_eq!(
        consensus_params_for_version(proto)
            .unwrap()
            .require_genesis_hash,
        required,
        "unexpected require_genesis_hash for {proto}"
    );
}

/// Execute is the mode where the evaluation copy has its genesis fields
/// restored, i.e. where the #1703 regression lived: call it explicitly.
#[test]
fn execute_pay_block_is_stored_stripped_on_hash_requiring_protocol() {
    assert_requires_hash(CONSENSUS_V41, true);
    let (mut state, block) = pay_block(CONSENSUS_V41, false);
    apply_block_with_mode(&mut state, &block, ApplyMode::Execute).unwrap();
    let stored = stored_block(&state, 1);
    assert!(
        !stored.payset[0].has_genesis_hash,
        "hgh stays unset when the protocol requires the genesis hash"
    );
}

#[test]
fn execute_pay_block_keeps_hgh_on_hash_optional_protocol() {
    assert_requires_hash(CONSENSUS_V15, false);
    // The submitter included gh; it is stripped on store and hgh records it.
    let (mut state, block) = pay_block(CONSENSUS_V15, true);
    apply_block_with_mode(&mut state, &block, ApplyMode::Execute).unwrap();
    let stored = stored_block(&state, 1);
    assert!(stored.payset[0].has_genesis_hash, "hgh must be preserved");
}

/// The real follow-path dispatch: a pay-only block takes the Replay path
/// there (no Execute), and must be stored stripped as well.
#[test]
fn dispatch_pay_only_block_is_stored_stripped() {
    assert_requires_hash(CONSENSUS_V41, true);
    let (mut state, block) = pay_block(CONSENSUS_V41, false);
    apply_block_executing_app_calls(&mut state, &block).unwrap();
    let stored = stored_block(&state, 1);
    assert!(!stored.payset[0].has_genesis_hash);
}

/// Both halves of the invariant in one test: the AVM sees the id of the FULL
/// transaction (issue #1664), while the stored block stays stripped (#1703).
#[test]
fn app_call_block_evaluates_full_txid_and_is_stored_stripped() {
    let sender = Address([1u8; 32]);
    let app_id = 1001u64;
    let mut state = funded_state(sender);
    let program = algo_avm::assembler::assemble_string(concat!(
        "#pragma version 8
",
        "byte \"id\"
",
        "txn TxID
",
        "box_put
",
        "int 1
",
    ))
    .expect("assemble")
    .program;
    state
        .get_or_default_account_mut(&Address(algo_ledger::avm_context::app_address(app_id)))
        .micro_algos = 10_000_000;
    state.set_app_params(
        app_id,
        algo_types::AppParams {
            creator: sender,
            approval_program: program,
            clear_state_program: vec![0x08, 0x81, 0x01],
            ..Default::default()
        },
    );
    let mut stx = stripped_stx("appl", sender);
    stx.txn.application_id = app_id;
    stx.txn.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(serde_bytes::ByteBuf::from(b"id".to_vec())),
    }]);
    let mut full = stx.txn.clone();
    full.genesis_id = GENESIS_ID.to_string();
    full.genesis_hash = GENESIS_HASH;

    apply_block_executing_app_calls(&mut state, &stripped_block(CONSENSUS_V41, vec![stx])).unwrap();

    assert_eq!(
        state.get_box(app_id, b"id"),
        Some(algo_codec::compute_txn_id(&full).0.to_vec()),
        "txn TxID must be the id of the full (restored) transaction"
    );
    let stored = stored_block(&state, 1);
    assert!(!stored.payset[0].has_genesis_hash);
}
