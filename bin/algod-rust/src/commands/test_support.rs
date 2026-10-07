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

//! Shared `cfg(test)` fixtures for the `relay` and `replay` command tests
//! (issue #1709): an in-memory ledger with a funded sender and a deployed
//! box-writing app, plus app-call and pay blocks. The box-writing block's
//! recorded `dt` carries no box field, so a block applied purely from
//! recorded deltas (`ApplyMode::Replay`) can never create the box; only AVM
//! execution does.

use algo_ledger::{LedgerStore, SqliteLedger};
use algo_types::consensus::CONSENSUS_V41;
use algo_types::{AccountData, Address, Block, BoxRef, Round, SignedTransaction};

pub const APP_ID: u64 = 1001;
pub const BOX_NAME: &[u8] = b"bx";

pub fn sender() -> Address {
    Address([1u8; 32])
}

pub fn receiver() -> Address {
    Address([2u8; 32])
}

fn deploy(l: &mut SqliteLedger, source: &str) {
    let program = algo_avm::assembler::assemble_string(source)
        .expect("assemble")
        .program;
    l.set_app_params(
        APP_ID,
        algo_types::AppParams {
            creator: sender(),
            approval_program: program,
            clear_state_program: vec![0x08, 0x81, 0x01],
            ..Default::default()
        },
    );
}

/// In-memory ledger with a funded sender and a deployed box-writing app.
pub fn ledger() -> SqliteLedger {
    let mut l = SqliteLedger::open_in_memory().expect("in-memory ledger");
    l.set_fee_sink(Address([0xFE; 32]));
    l.set_account(
        &sender(),
        AccountData {
            micro_algos: 100_000_000,
            ..Default::default()
        },
    );
    l.set_account(
        &Address(algo_ledger::avm_context::app_address(APP_ID)),
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    deploy(
        &mut l,
        "#pragma version 8\nbyte \"bx\"\nbyte \"hello\"\nbox_put\nint 1\n",
    );
    l
}

fn base_block(stx: SignedTransaction) -> Block {
    Block {
        round: Round(1),
        genesis_id: "test-net-v1".to_string(),
        genesis_hash: [7u8; 32],
        fee_sink: Address([0xFE; 32]),
        current_protocol: CONSENSUS_V41.to_string(),
        txn_counter: 1001,
        payset: vec![stx],
        ..Block::default()
    }
}

fn base_stx(txn_type: &str) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = txn_type.into();
    stx.txn.sender = sender();
    stx.txn.fee = 1000;
    stx.txn.first_valid = Round(1);
    stx.txn.last_valid = Round(1000);
    stx.has_genesis_id = true;
    stx
}

/// Round-1 block with one app call that writes box `bx` = `hello`.
pub fn block() -> Block {
    let mut stx = base_stx("appl");
    stx.txn.application_id = APP_ID;
    stx.txn.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(serde_bytes::ByteBuf::from(BOX_NAME.to_vec())),
    }]);
    base_block(stx)
}

/// Like [`ledger`] but the app's approval program rejects (`int 0`), so
/// executing [`block`] fails the whole block.
pub fn rejecting_ledger() -> SqliteLedger {
    let mut l = ledger();
    deploy(
        &mut l,
        "#pragma version 8
int 0
",
    );
    l
}

/// Round-1 block with a single 1 000 000 microalgo payment to [`receiver`].
pub fn pay_block() -> Block {
    let mut stx = base_stx("pay");
    stx.txn.receiver = receiver();
    stx.txn.amount = 1_000_000;
    base_block(stx)
}
