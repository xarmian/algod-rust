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

//! Integration tests for inner transactions (Epic 22).
//!
//! Tests cover: inner txn groups, nested inner txns, budget/depth limits,
//! fee credit pooling, rollback semantics, field access, sender authorization,
//! and edge cases (axfer opt-in, clawback, afrz, keyreg).

use std::collections::BTreeMap;

use algo_avm::{parse, AvmMachine, ExecMode};
use algo_ledger::{LedgerAvmContext, LedgerState};
use algo_types::{
    Address, AppParams, AssetHolding, AssetParams, AssetParamsRecord, SignedTransaction,
    StateSchema, Transaction,
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Check if a result indicates failure (either error or Ok(false)).
fn is_failure(result: &Result<bool, algo_error::AlgoError>) -> bool {
    match result {
        Err(_) => true,
        Ok(false) => true,
        Ok(true) => false,
    }
}

/// Build a raw AVM program: version byte + opcode stream.
fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = vec![version];
    p.extend_from_slice(code);
    p
}

/// Compute app address = SHA512/256("appID" || app_id.to_be_bytes()).
fn app_address(app_id: u64) -> [u8; 32] {
    algo_ledger::avm_context::app_address(app_id)
}

/// Create a minimal appl SignedTransaction.
fn make_appl_txn(sender: [u8; 32], app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender: Address(sender),
            fee: 1000,
            first_valid: 100.into(),
            last_valid: 200.into(),
            application_id: app_id,
            on_completion: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Build a LedgerAvmContext in app mode.
fn make_context<'a>(
    store: &'a mut LedgerState,
    group: Vec<SignedTransaction>,
    app_id: u64,
) -> LedgerAvmContext<'a, LedgerState> {
    let creator = [1u8; 32];
    LedgerAvmContext::new(
        store,
        group,
        0,         // group_index
        100,       // round
        50000,     // latest_timestamp
        app_id,    // app_id
        creator,   // creator
        true,      // app_mode
        [0u8; 32], // program_hash
        [0u8; 32], // genesis_hash
        algo_types::ConsensusParams::default(),
    )
}

/// Run a program through the AVM with given context. Returns pass/reject.
fn run_with_context(
    version: u8,
    code: &[u8],
    ctx: &mut dyn algo_avm::AvmContext,
) -> Result<bool, algo_error::AlgoError> {
    let raw = prog(version, code);
    let program = parse(&raw)?;
    let mut machine = AvmMachine::new(program, ExecMode::Application, 20_000);
    machine.run(ctx)
}

/// Seed an app with approval + clear programs.
fn seed_app_with_programs(
    store: &mut LedgerState,
    app_id: u64,
    creator: Address,
    approval: Vec<u8>,
    clear: Vec<u8>,
) {
    store.app_params.insert(
        app_id,
        AppParams {
            creator,
            approval_program: approval,
            clear_state_program: clear,
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            extra_program_pages: 0,
            ..Default::default()
        },
    );
    let acct = store.get_or_default_account_mut(&creator);
    acct.total_created_apps += 1;
}

/// Seed an app with simple approval program (pushint 1; return).
fn seed_app_approve(store: &mut LedgerState, app_id: u64, creator: Address) {
    seed_app_with_programs(
        store,
        app_id,
        creator,
        prog(6, &[0x81, 0x01]),
        prog(6, &[0x81, 0x01]),
    );
}

/// Fund an account with the given microAlgos balance.
fn fund_account(store: &mut LedgerState, addr: Address, micro_algos: u64) {
    let acct = store.get_or_default_account_mut(&addr);
    acct.micro_algos = micro_algos;
}

/// Helper to encode a varuint for pushint. Handles values up to ~2M.
fn varuint(val: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut v = val;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
    buf
}

/// Build pushint bytecode: 0x81 + varuint encoding.
fn pushint(val: u64) -> Vec<u8> {
    let mut bytes = vec![0x81];
    bytes.extend(varuint(val));
    bytes
}

/// Build pushbytes bytecode: 0x80 + length + data.
fn pushbytes(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80];
    bytes.extend(varuint(data.len() as u64));
    bytes.extend_from_slice(data);
    bytes
}

/// Build an inner pay transaction program fragment.
/// itxn_begin; TypeEnum=pay; Receiver=addr; Amount=amt; itxn_submit
fn build_inner_pay(receiver: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1)); // TypeEnum = 1 (pay)
    code.extend([0xb2, 16]); // itxn_field TypeEnum
    code.extend(pushbytes(receiver)); // receiver address
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(amount)); // amount
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code
}

/// Build an inner pay with fee=0 program fragment.
fn build_inner_pay_fee0(receiver: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1)); // TypeEnum = 1 (pay)
    code.extend([0xb2, 16]); // itxn_field TypeEnum
    code.extend(pushbytes(receiver)); // receiver address
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(amount)); // amount
    code.extend([0xb2, 8]); // itxn_field Amount
    code.extend(pushint(0)); // fee = 0
    code.extend([0xb2, 1]); // itxn_field Fee
    code.push(0xb3); // itxn_submit
    code
}

// ===========================================================================
// 1. Inner Transaction Groups
// ===========================================================================

/// itxn_next chaining: begin -> field -> next -> field -> submit (2 inner txns)
#[test]
fn inner_group_two_pays_via_itxn_next() {
    let sender = [0xAA; 32];
    let receiver1 = [0xBB; 32];
    let receiver2 = [0xCC; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    // Give fee credit for inner txns
    ctx.fee_credit = 10_000;

    let mut code = Vec::new();
    // First inner txn: pay receiver1 1000
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // itxn_field TypeEnum (pay)
    code.extend(pushbytes(&receiver1));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(1000));
    code.extend([0xb2, 8]); // itxn_field Amount
                            // Chain second inner txn
    code.push(0xb6); // itxn_next
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // itxn_field TypeEnum (pay)
    code.extend(pushbytes(&receiver2));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(2000));
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "program should approve");

    let inner = ctx.inner_txns();
    assert_eq!(inner.len(), 1, "one inner group submitted");
    assert_eq!(inner[0].len(), 2, "group has 2 txns");
    assert_eq!(inner[0][0].txn.receiver, Address(receiver1));
    assert_eq!(inner[0][0].txn.amount, 1000);
    assert_eq!(inner[0][1].txn.receiver, Address(receiver2));
    assert_eq!(inner[0][1].txn.amount, 2000);

    // Verify balances changed
    let r1_bal = ctx
        .store
        .get_account(&Address(receiver1))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    let r2_bal = ctx
        .store
        .get_account(&Address(receiver2))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(r1_bal, 1000);
    assert_eq!(r2_bal, 2000);
}

/// Group of 3 inner txns.
#[test]
fn inner_group_three_pays() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    let receivers: [[u8; 32]; 3] = [[0xB1; 32], [0xB2; 32], [0xB3; 32]];
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    for (i, recv) in receivers.iter().enumerate() {
        if i > 0 {
            code.push(0xb6); // itxn_next
        }
        code.extend(pushint(1));
        code.extend([0xb2, 16]); // TypeEnum = pay
        code.extend(pushbytes(recv));
        code.extend([0xb2, 7]); // Receiver
        code.extend(pushint((i as u64 + 1) * 100));
        code.extend([0xb2, 8]); // Amount
    }
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result);

    let inner = ctx.inner_txns();
    assert_eq!(inner[0].len(), 3, "group has 3 txns");
    for (i, recv) in receivers.iter().enumerate() {
        assert_eq!(inner[0][i].txn.receiver, Address(*recv));
        assert_eq!(inner[0][i].txn.amount, (i as u64 + 1) * 100);
    }
}

/// Max group size enforcement: 17 inner txns should fail at itxn_next.
#[test]
fn inner_group_max_size_exceeded() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 100_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 100_000;

    // Build 16 inner txns (the max), then try itxn_next for #17
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    for i in 0..16u64 {
        if i > 0 {
            code.push(0xb6); // itxn_next
        }
        code.extend(pushint(1));
        code.extend([0xb2, 16]); // TypeEnum = pay
        code.extend(pushint(1000));
        code.extend([0xb2, 8]); // Amount
    }
    // This 17th itxn_next should fail
    code.push(0xb6); // itxn_next — exceeds MAX_TX_GROUP_SIZE
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result), "17th inner txn should fail");
}

// ===========================================================================
// 2. Nested Inner Transactions
// ===========================================================================

/// App A calls App B via inner appl. B does inner pay. Verify state changes.
#[test]
fn nested_inner_app_b_does_pay() {
    let sender = [0xAA; 32];
    let receiver = [0xDD; 32];
    let app_a = 100u64;
    let app_b = 200u64;

    let mut store = LedgerState::new();

    // App B: does an inner pay to receiver for 5000, then approves.
    let mut b_code = Vec::new();
    b_code.extend(build_inner_pay(&receiver, 5000));
    b_code.extend(pushint(1));
    b_code.push(0x43); // return
    let b_prog = prog(6, &b_code);

    seed_app_with_programs(
        &mut store,
        app_b,
        Address([2u8; 32]),
        b_prog,
        prog(6, &[0x81, 0x01]),
    );

    // App A: does inner appl call to App B, then approves.
    // We need to seed App A and have the outer txn call App A.
    let mut a_code = Vec::new();
    a_code.push(0xb1); // itxn_begin
    a_code.extend(pushint(6)); // TypeEnum = appl
    a_code.extend([0xb2, 16]);
    a_code.extend(pushint(app_b)); // ApplicationID
    a_code.extend([0xb2, 24]);
    a_code.push(0xb3); // itxn_submit
    a_code.extend(pushint(1));
    a_code.push(0x43);
    let a_prog = prog(6, &a_code);

    seed_app_with_programs(
        &mut store,
        app_a,
        Address([1u8; 32]),
        a_prog,
        prog(6, &[0x81, 0x01]),
    );

    // Fund App B's address (B is the one doing the inner pay)
    let app_b_addr = Address(app_address(app_b));
    fund_account(&mut store, app_b_addr, 10_000_000);

    // Fund App A's address (for fees)
    let app_a_addr = Address(app_address(app_a));
    fund_account(&mut store, app_a_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_a);
    let mut ctx = make_context(&mut store, vec![txn], app_a);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 300;

    let result = run_with_context(6, &a_code, &mut ctx).unwrap();
    assert!(result, "App A should approve after calling App B");

    // Verify receiver got paid
    let r_bal = ctx
        .store
        .get_account(&Address(receiver))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(
        r_bal, 5000,
        "receiver should have 5000 from App B's inner pay"
    );
}

/// CallerApplicationID at depth 1 should be the outer app's ID.
#[test]
fn nested_caller_app_id() {
    let sender = [0xAA; 32];
    let app_a = 100u64;
    let app_b = 200u64;

    let mut store = LedgerState::new();

    // App B: checks CallerApplicationID == 100, approves if so.
    // global CallerApplicationID; pushint 100; ==; return
    let mut b_code = Vec::new();
    b_code.extend([0x32, 13]); // global CallerApplicationID (field 13)
    b_code.extend(pushint(app_a));
    b_code.push(0x12); // ==
    b_code.push(0x43); // return
    let b_prog = prog(6, &b_code);

    seed_app_with_programs(
        &mut store,
        app_b,
        Address([2u8; 32]),
        b_prog,
        prog(6, &[0x81, 0x01]),
    );

    // App A: inner appl call to App B
    let mut a_code = Vec::new();
    a_code.push(0xb1); // itxn_begin
    a_code.extend(pushint(6)); // TypeEnum = appl
    a_code.extend([0xb2, 16]);
    a_code.extend(pushint(app_b));
    a_code.extend([0xb2, 24]); // ApplicationID
    a_code.push(0xb3); // itxn_submit
    a_code.extend(pushint(1));
    a_code.push(0x43);
    let a_prog = prog(6, &a_code);

    seed_app_with_programs(
        &mut store,
        app_a,
        Address([1u8; 32]),
        a_prog,
        prog(6, &[0x81, 0x01]),
    );

    let app_a_addr = Address(app_address(app_a));
    fund_account(&mut store, app_a_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_a);
    let mut ctx = make_context(&mut store, vec![txn], app_a);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 300;

    let result = run_with_context(6, &a_code, &mut ctx).unwrap();
    assert!(result, "App B should see CallerApplicationID == 100");
}

// ===========================================================================
// 3. Budget and Depth
// ===========================================================================

/// Budget pooling: inner app call adds 700 to pool.
#[test]
fn budget_pooling_inner_app_call_adds_budget() {
    let sender = [0xAA; 32];
    let app_a = 100u64;
    let app_b = 200u64;

    let mut store = LedgerState::new();

    // App B: simple approve
    seed_app_approve(&mut store, app_b, Address([2u8; 32]));

    // App A: inner appl call to App B, then approve.
    let mut a_code = Vec::new();
    a_code.push(0xb1); // itxn_begin
    a_code.extend(pushint(6)); // TypeEnum = appl
    a_code.extend([0xb2, 16]);
    a_code.extend(pushint(app_b));
    a_code.extend([0xb2, 24]);
    a_code.push(0xb3); // itxn_submit
    a_code.extend(pushint(1));
    a_code.push(0x43);
    let a_prog = prog(6, &a_code);

    seed_app_with_programs(
        &mut store,
        app_a,
        Address([1u8; 32]),
        a_prog,
        prog(6, &[0x81, 0x01]),
    );

    let app_a_addr = Address(app_address(app_a));
    fund_account(&mut store, app_a_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_a);
    let mut ctx = make_context(&mut store, vec![txn], app_a);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 300;

    // Run with limited budget to verify pooling works
    let raw = prog(6, &a_code);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::Application, 700);
    let result = machine.run(&mut ctx).unwrap();
    assert!(result, "should succeed: inner app call adds 700 to budget");
}

/// Depth limit: chain of 8 inner app calls succeeds.
#[test]
fn depth_limit_chain_of_8_succeeds() {
    let sender = [0xAA; 32];

    let mut store = LedgerState::new();

    // Create a chain: app[i] calls app[i+1].
    // App 8 (leaf): just approves.
    let base_id = 100u64;
    let depth = 8u64;

    // Leaf app (at depth 8): approve
    let leaf_id = base_id + depth;
    seed_app_approve(&mut store, leaf_id, Address([1u8; 32]));
    fund_account(&mut store, Address(app_address(leaf_id)), 10_000_000);

    // Chain apps from depth-1 down to 0: each calls the next
    for d in (0..depth).rev() {
        let this_id = base_id + d;
        let next_id = base_id + d + 1;

        let mut code = Vec::new();
        code.push(0xb1); // itxn_begin
        code.extend(pushint(6)); // TypeEnum = appl
        code.extend([0xb2, 16]);
        code.extend(pushint(next_id));
        code.extend([0xb2, 24]); // ApplicationID
        code.push(0xb3); // itxn_submit
        code.extend(pushint(1));
        code.push(0x43);
        let p = prog(6, &code);

        seed_app_with_programs(
            &mut store,
            this_id,
            Address([1u8; 32]),
            p,
            prog(6, &[0x81, 0x01]),
        );
        fund_account(&mut store, Address(app_address(this_id)), 10_000_000);
    }

    let top_id = base_id;
    let txn = make_appl_txn(sender, top_id);
    let mut ctx = make_context(&mut store, vec![txn], top_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 500_000;
    ctx.txn_counter = 1000;

    // Build the top-level code
    let mut top_code = Vec::new();
    top_code.push(0xb1);
    top_code.extend(pushint(6));
    top_code.extend([0xb2, 16]);
    top_code.extend(pushint(base_id + 1));
    top_code.extend([0xb2, 24]);
    top_code.push(0xb3);
    top_code.extend(pushint(1));
    top_code.push(0x43);

    let raw = prog(6, &top_code);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::Application, 20_000);
    let result = machine.run(&mut ctx).unwrap();
    assert!(result, "chain of 8 depth should succeed");
}

/// Depth limit exceeded: 9th level should fail.
#[test]
fn depth_limit_9_fails() {
    let sender = [0xAA; 32];

    let mut store = LedgerState::new();

    // Create chain of 9 inner app calls.
    let base_id = 100u64;
    let depth = 9u64;

    let leaf_id = base_id + depth;
    seed_app_approve(&mut store, leaf_id, Address([1u8; 32]));
    fund_account(&mut store, Address(app_address(leaf_id)), 10_000_000);

    for d in (0..depth).rev() {
        let this_id = base_id + d;
        let next_id = base_id + d + 1;

        let mut code = Vec::new();
        code.push(0xb1);
        code.extend(pushint(6));
        code.extend([0xb2, 16]);
        code.extend(pushint(next_id));
        code.extend([0xb2, 24]);
        code.push(0xb3);
        code.extend(pushint(1));
        code.push(0x43);
        let p = prog(6, &code);

        seed_app_with_programs(
            &mut store,
            this_id,
            Address([1u8; 32]),
            p,
            prog(6, &[0x81, 0x01]),
        );
        fund_account(&mut store, Address(app_address(this_id)), 10_000_000);
    }

    let top_id = base_id;
    let txn = make_appl_txn(sender, top_id);
    let mut ctx = make_context(&mut store, vec![txn], top_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 500_000;
    ctx.txn_counter = 1000;

    let mut top_code = Vec::new();
    top_code.push(0xb1);
    top_code.extend(pushint(6));
    top_code.extend([0xb2, 16]);
    top_code.extend(pushint(base_id + 1));
    top_code.extend([0xb2, 24]);
    top_code.push(0xb3);
    top_code.extend(pushint(1));
    top_code.push(0x43);

    let result = run_with_context(6, &top_code, &mut ctx);
    assert!(is_failure(&result), "depth 9 should fail");
}

// ===========================================================================
// 4. Fee Credit Pooling
// ===========================================================================

/// Single inner txn with fee=0 and outer provides enough credit.
#[test]
fn fee_credit_zero_fee_inner_with_overpay() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    // Outer overpays: give 2000 credit (covers 1000 min fee for inner)
    ctx.fee_credit = 2000;

    let code = build_inner_pay_fee0(&receiver, 3000);
    let mut full_code = code.clone();
    full_code.extend(pushint(1));
    full_code.push(0x43);

    let result = run_with_context(6, &full_code, &mut ctx).unwrap();
    assert!(
        result,
        "should succeed with fee credit covering the inner txn fee"
    );

    let r_bal = ctx
        .store
        .get_account(&Address(receiver))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(r_bal, 3000);
}

/// Fee credit insufficient should fail.
/// Two inner txns both with fee=0 (defaulted to 1000 each). Group needs 2000.
/// fee_credit is only 1000, which is insufficient because the inner txns'
/// fees (2*1000=2000) already cover the group_fee (2*1000=2000) by default.
/// Instead, test with fee=500 explicitly + fee_credit=400 (shortfall=500,
/// credit=400 < 500).
#[test]
fn fee_credit_insufficient_fails() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    // Only 400 credit — not enough to cover 500 shortfall
    ctx.fee_credit = 400;

    // Inner pay with explicit fee=500 (shortfall = 1000-500 = 500, credit=400 < 500)
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(3000));
    code.extend([0xb2, 8]); // Amount
    code.extend(pushint(500)); // Fee = 500
    code.extend([0xb2, 1]); // itxn_field Fee
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result), "should fail: insufficient fee credit");
}

// ===========================================================================
// Fee residue (FeeForUsage) — issue #677
//
// Mirrors go-algorand's `EvalParams.feeResidue` (`data/transactions/logic/
// eval.go`, PR #6650 "Fees: Handle rounding of fees with non-integral usage
// better"): an inner group's required fee is usage-weighted (an oversized
// `Note` field contributes a fractional-of-a-MinTxnFee surcharge, in
// `Micros`, via `SummarizeFees`/`Transaction.feeFactor`) and rounded up
// against a running residue, so a whole tree of inner-txn groups rounds up
// its aggregate fee only once rather than once per group.
//
// Consensus V42 charges `per_byte_txn_surcharge = 100` Micros per Note byte
// beyond the free `max_txn_note_bytes = 1024` cap, at `min_txn_fee = 1000`.
// So a Note of `1024 + over` bytes contributes `over * 100` Micros of usage
// beyond the baseline `1_000_000` (`ONE_MICROS`):
//   - over=7  -> usage = 1_000_700 -> true fee = 1000.7  -> rounds up to 1001,
//                overpaying by 0.3 microAlgo (residue = 0.3 * FEE_RESIDUE_SCALE).
//   - over=2  -> usage = 1_000_200 -> true fee = 1000.2  -> needs to round up
//                to 1001 *unless* a carried-in residue of >= 0.2 already
//                covers the fraction, in which case 1000 suffices exactly.
// ===========================================================================

/// Build an inner pay program fragment with an oversized `Note` (contributing
/// a `SummarizeFees` surcharge) and an explicit `Fee`.
fn build_inner_pay_with_note_and_fee(receiver: &[u8; 32], note_len: usize, fee: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1)); // TypeEnum = 1 (pay)
    code.extend([0xb2, 16]); // itxn_field TypeEnum
    code.extend(pushbytes(receiver));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(0)); // Amount = 0
    code.extend([0xb2, 8]); // itxn_field Amount
    code.extend(pushbytes(&vec![0xABu8; note_len]));
    code.extend([0xb2, 5]); // itxn_field Note
    code.extend(pushint(fee));
    code.extend([0xb2, 1]); // itxn_field Fee
    code.push(0xb3); // itxn_submit
    code
}

/// A single inner group with an oversized Note (usage = 1_000_700, true fee =
/// 1000.7, rounds up to 1001) that pays only 1000 must fail — and the error
/// must report the actual net shortfall (1, not the flat requirement),
/// matching go-algorand's corrected message (PR #6693 "AVM: report actual
/// inner group fee shortfall": `"group fee %s too small (needs %s more)"`).
#[test]
fn inner_group_usage_based_fee_shortfall_reports_net_amount() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 0;
    ctx.fee_residue = 0;

    let mut code = build_inner_pay_with_note_and_fee(&receiver, 1024 + 7, 1000);
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(
        is_failure(&result),
        "usage-based fee (1001) exceeds flat paid (1000): should fail"
    );
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("group fee 1000 too small (needs 1 more)"),
        "expected the actual net shortfall (1), got: {}",
        msg
    );
}

/// In isolation (fresh residue=0, no fee_credit), a group with usage=1_000_200
/// (true fee 1000.2, independently rounds up to 1001) that pays only 1000
/// must fail. This is the control for
/// `inner_group_fee_residue_carries_to_sibling_group` below: it shows 1000 is
/// *not* independently sufficient for this usage, so that test's success can
/// only be explained by the carried-in residue.
#[test]
fn inner_group_usage_based_fee_shortfall_without_residue_control() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 0;
    ctx.fee_residue = 0;

    let mut code = build_inner_pay_with_note_and_fee(&receiver, 1024 + 2, 1000);
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(
        is_failure(&result),
        "usage=1_000_200 with no carried residue independently needs 1001, not 1000"
    );
}

/// The core regression this issue fixes: fee_residue left over from one
/// inner group's round-up carries forward and is consumed by the next
/// sibling inner group's charge, so the pair rounds up only once in
/// aggregate rather than once per group.
///
/// Group 1: usage=1_000_700 (Note over=7), pays exactly the rounded-up fee
/// 1001 -- overpaying the *true* fee (1000.7) by 0.3 microAlgo, which is
/// retained as residue (not fee_credit -- no whole-microAlgo overpayment).
/// Group 2: usage=1_000_200 (Note over=2, true fee 1000.2) pays only 1000.
/// Without the carried-in 0.3 residue this would fail (see the control test
/// above); with it, the 0.2 fraction is absorbed and 1000 exactly suffices.
#[test]
fn inner_group_fee_residue_carries_to_sibling_group() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 0;
    ctx.fee_residue = 0;

    let mut code = build_inner_pay_with_note_and_fee(&receiver, 1024 + 7, 1001);
    code.extend(build_inner_pay_with_note_and_fee(&receiver, 1024 + 2, 1000));
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(
        result.as_ref().is_ok_and(|approved| *approved),
        "second group's 1000 should be exactly covered by the 0.3 residue \
         left over from the first group's round-up: {:?}",
        result
    );
    // The leftover residue after both groups: 0.3 - 0.2 = 0.1 microAlgo,
    // scaled by FEE_RESIDUE_SCALE (1e12).
    assert_eq!(
        ctx.fee_residue, 100_000_000_000,
        "residue should reflect 0.1 microAlgo left after both round-ups"
    );
    // No whole-microAlgo fee_credit was ever available or needed.
    assert_eq!(ctx.fee_credit, 0);
}

/// Fee deducted from app address balance.
#[test]
fn fee_deducted_from_app_address() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner pay with default fee (gets set to 1000)
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(1000));
    code.extend([0xb2, 8]); // Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let balance_before = ctx
        .store
        .get_account(&app_addr)
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result);

    let balance_after = ctx
        .store
        .get_account(&app_addr)
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    // App paid 1000 (amount) + 1000 (fee) = 2000 total
    assert_eq!(
        balance_before - balance_after,
        2000,
        "app should have paid amount + fee"
    );
}

// ===========================================================================
// 5. Rollback Semantics
// ===========================================================================

/// Inner pay fails (insufficient balance) -> state rolled back.
#[test]
fn rollback_on_inner_pay_insufficient_balance() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    // Only 500 microAlgos — not enough for 1000 fee + 5000 amount
    fund_account(&mut store, app_addr, 500);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    let mut code = build_inner_pay(&receiver, 5000);
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    // Should fail due to insufficient balance
    assert!(is_failure(&result));

    // App address balance should be unchanged (rolled back)
    let app_bal = ctx
        .store
        .get_account(&app_addr)
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(app_bal, 500, "app balance should be rolled back to 500");

    // Receiver should have 0
    let r_bal = ctx
        .store
        .get_account(&Address(receiver))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(r_bal, 0, "receiver should still have 0 after rollback");
}

/// Inner group partial execution: first txn succeeds, second fails -> all rolled back.
#[test]
fn rollback_inner_group_partial_failure() {
    let sender = [0xAA; 32];
    let receiver1 = [0xBB; 32];
    let receiver2 = [0xCC; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    // Enough for first pay + fee, but not second pay
    fund_account(&mut store, app_addr, 3000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Group of 2: pay 1000 to r1, then pay 50000 to r2 (will fail)
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver1));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(1000));
    code.extend([0xb2, 8]); // Amount
    code.push(0xb6); // itxn_next
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver2));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(50_000)); // Will fail - insufficient balance
    code.extend([0xb2, 8]); // Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result));

    // Both receivers should have 0 (everything rolled back)
    let r1_bal = ctx
        .store
        .get_account(&Address(receiver1))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    let r2_bal = ctx
        .store
        .get_account(&Address(receiver2))
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(r1_bal, 0, "receiver1 should be 0 after rollback");
    assert_eq!(r2_bal, 0, "receiver2 should be 0 after rollback");

    // App balance should be unchanged
    let app_bal = ctx
        .store
        .get_account(&app_addr)
        .map(|a| a.micro_algos)
        .unwrap_or(0);
    assert_eq!(app_bal, 3000, "app balance should be rolled back");
}

// ===========================================================================
// 6. Inner Txn Field Access
// ===========================================================================

/// Multiple itxn_submit calls: field access reads from LAST submitted group only.
#[test]
fn field_access_reads_last_submitted_group() {
    let sender = [0xAA; 32];
    let receiver1 = [0xBB; 32];
    let receiver2 = [0xCC; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;

    // First submit: pay 1000 to receiver1
    let mut code = Vec::new();
    code.push(0xb1);
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver1));
    code.extend([0xb2, 7]);
    code.extend(pushint(1000));
    code.extend([0xb2, 8]);
    code.push(0xb3); // itxn_submit

    // Second submit: pay 2000 to receiver2
    code.push(0xb1);
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver2));
    code.extend([0xb2, 7]);
    code.extend(pushint(2000));
    code.extend([0xb2, 8]);
    code.push(0xb3); // itxn_submit

    // itxn Amount should be 2000 (from second/last submit)
    code.extend([0xb4, 8]); // itxn Amount (field 8)
    code.extend(pushint(2000));
    code.push(0x12); // ==
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "itxn Amount should read from last submitted group");
}

/// gitxn with group of 2: read fields from each by index.
#[test]
fn gitxn_reads_from_group_by_index() {
    let sender = [0xAA; 32];
    let receiver1 = [0xBB; 32];
    let receiver2 = [0xCC; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;

    // Submit group of 2: pay 1000 to r1, pay 2000 to r2
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver1));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(1000));
    code.extend([0xb2, 8]); // Amount
    code.push(0xb6); // itxn_next
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver2));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(2000));
    code.extend([0xb2, 8]); // Amount
    code.push(0xb3); // itxn_submit

    // gitxn 0 Amount => 1000
    code.extend([0xb7, 0, 8]); // gitxn group_index=0, field=8 (Amount)
    code.extend(pushint(1000));
    code.push(0x12); // ==

    // gitxn 1 Amount => 2000
    code.extend([0xb7, 1, 8]); // gitxn group_index=1, field=8 (Amount)
    code.extend(pushint(2000));
    code.push(0x12); // ==

    code.push(0x10); // &&
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "gitxn should read correct amounts from inner group");
}

/// CreatedAssetID from inner acfg create.
#[test]
fn created_asset_id_from_inner_acfg() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 500;

    // Create an asset via inner acfg
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(3)); // TypeEnum = acfg
    code.extend([0xb2, 16]); // itxn_field TypeEnum
    code.extend(pushint(1_000_000)); // ConfigAssetTotal
    code.extend([0xb2, 34]); // itxn_field ConfigAssetTotal
    code.extend(pushint(0)); // ConfigAssetDecimals
    code.extend([0xb2, 35]); // itxn_field ConfigAssetDecimals
    code.push(0xb3); // itxn_submit

    // Read CreatedAssetID (field 60)
    code.extend([0xb4, 60]); // itxn CreatedAssetID
                             // txn_counter starts at 500, incremented to 501 before execution,
                             // then apply_acfg uses txn_counter + 1 = 502
    code.extend(pushint(502));
    code.push(0x12); // ==
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "CreatedAssetID should equal txn_counter");
}

/// Logs from inner appl are accessible via itxn field.
#[test]
fn inner_app_logs_accessible() {
    let sender = [0xAA; 32];
    let app_a = 100u64;
    let app_b = 200u64;

    let mut store = LedgerState::new();

    // App B: logs "hello", then approves
    let mut b_code = Vec::new();
    b_code.extend(pushbytes(b"hello"));
    b_code.push(0xb0); // log
    b_code.extend(pushint(1));
    b_code.push(0x43);
    let b_prog = prog(6, &b_code);

    seed_app_with_programs(
        &mut store,
        app_b,
        Address([2u8; 32]),
        b_prog,
        prog(6, &[0x81, 0x01]),
    );

    // App A: inner appl call to B, then read B's logs
    let mut a_code = Vec::new();
    a_code.push(0xb1); // itxn_begin
    a_code.extend(pushint(6)); // TypeEnum = appl
    a_code.extend([0xb2, 16]);
    a_code.extend(pushint(app_b));
    a_code.extend([0xb2, 24]);
    a_code.push(0xb3); // itxn_submit

    // itxn NumLogs (field 59) should be 1
    a_code.extend([0xb4, 59]); // itxn NumLogs
    a_code.extend(pushint(1));
    a_code.push(0x12); // ==
    a_code.push(0x43); // return

    let a_prog = prog(6, &a_code);
    seed_app_with_programs(
        &mut store,
        app_a,
        Address([1u8; 32]),
        a_prog,
        prog(6, &[0x81, 0x01]),
    );

    let app_a_addr = Address(app_address(app_a));
    fund_account(&mut store, app_a_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_a);
    let mut ctx = make_context(&mut store, vec![txn], app_a);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 300;

    let result = run_with_context(6, &a_code, &mut ctx).unwrap();
    assert!(result, "should see 1 log from inner app call");
}

// ===========================================================================
// 7. Sender Authorization
// ===========================================================================

/// Inner txn with sender = app address succeeds.
#[test]
fn sender_auth_app_address_succeeds() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Explicitly set sender to app address
    let app_addr_bytes = app_address(app_id);
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&app_addr_bytes));
    code.extend([0xb2, 0]); // itxn_field Sender
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(100));
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "app address as sender should succeed");
}

/// Inner txn with sender rekeyed to app address succeeds.
#[test]
fn sender_auth_rekeyed_account_succeeds() {
    let sender = [0xAA; 32];
    let rekeyed_account = [0xDD; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    // Create the rekeyed account with auth_addr = app address
    let rekeyed_acct = store.get_or_default_account_mut(&Address(rekeyed_account));
    rekeyed_acct.micro_algos = 5_000_000;
    rekeyed_acct.auth_addr = Some(app_addr);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner pay from rekeyed account
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&rekeyed_account));
    code.extend([0xb2, 0]); // itxn_field Sender
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(100));
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "rekeyed account as sender should succeed");
}

/// Inner txn with unauthorized sender fails.
#[test]
fn sender_auth_unauthorized_fails() {
    let sender = [0xAA; 32];
    let unauthorized = [0xDD; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    // Create unauthorized account (no rekey to app)
    let unauth_acct = store.get_or_default_account_mut(&Address(unauthorized));
    unauth_acct.micro_algos = 5_000_000;
    // auth_addr is None (defaults to self, not app address)

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&unauthorized));
    code.extend([0xb2, 0]); // itxn_field Sender
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(100));
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result), "unauthorized sender should fail");
}

// ===========================================================================
// 8. Edge Cases
// ===========================================================================

/// Inner axfer opt-in (self-transfer of 0).
#[test]
fn inner_axfer_opt_in() {
    let sender = [0xAA; 32];
    let app_id = 42u64;
    let asset_id = 999u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    // Create an asset
    store.asset_params.insert(
        asset_id,
        AssetParamsRecord {
            creator: Address([1u8; 32]),
            params: AssetParams {
                total: 1_000_000,
                decimals: 0,
                default_frozen: false,
                ..Default::default()
            },
        },
    );

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner axfer: app opts itself in by sending 0 of the asset to itself
    let app_addr_bytes = app_address(app_id);
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(4)); // TypeEnum = axfer
    code.extend([0xb2, 16]);
    code.extend(pushint(asset_id)); // XferAsset
    code.extend([0xb2, 17]);
    code.extend(pushbytes(&app_addr_bytes)); // AssetReceiver = app itself
    code.extend([0xb2, 20]);
    code.extend(pushint(0)); // AssetAmount = 0
    code.extend([0xb2, 18]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "inner axfer opt-in should succeed");

    // Verify the app address now holds the asset
    let holding = ctx.store.asset_holdings.get(&(app_addr, asset_id));
    assert!(holding.is_some(), "app should be opted into the asset");
    assert_eq!(holding.unwrap().amount, 0);
}

/// Inner axfer clawback.
#[test]
fn inner_axfer_clawback() {
    let sender = [0xAA; 32];
    let holder = [0xDD; 32];
    let clawback_receiver = [0xEE; 32];
    let app_id = 42u64;
    let asset_id = 999u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    // Create asset with app as clawback address
    store.asset_params.insert(
        asset_id,
        AssetParamsRecord {
            creator: Address([1u8; 32]),
            params: AssetParams {
                total: 1_000_000,
                decimals: 0,
                default_frozen: false,
                clawback: Some(app_addr),
                ..Default::default()
            },
        },
    );

    // Holder has 5000 units
    store.asset_holdings.insert(
        (Address(holder), asset_id),
        AssetHolding {
            amount: 5000,
            frozen: false,
        },
    );

    // Receiver is opted in
    store.asset_holdings.insert(
        (Address(clawback_receiver), asset_id),
        AssetHolding {
            amount: 0,
            frozen: false,
        },
    );

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner axfer clawback: from holder to clawback_receiver, 3000 units
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(4)); // TypeEnum = axfer
    code.extend([0xb2, 16]);
    code.extend(pushint(asset_id)); // XferAsset
    code.extend([0xb2, 17]);
    code.extend(pushint(3000)); // AssetAmount = 3000
    code.extend([0xb2, 18]);
    // AssetSender (field 19) = holder (the account being clawed back from)
    code.extend(pushbytes(&holder));
    code.extend([0xb2, 19]); // itxn_field AssetSender
    code.extend(pushbytes(&clawback_receiver)); // AssetReceiver
    code.extend([0xb2, 20]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "clawback should succeed");

    let holder_amt = ctx
        .store
        .asset_holdings
        .get(&(Address(holder), asset_id))
        .map(|h| h.amount)
        .unwrap_or(0);
    let recv_amt = ctx
        .store
        .asset_holdings
        .get(&(Address(clawback_receiver), asset_id))
        .map(|h| h.amount)
        .unwrap_or(0);
    assert_eq!(holder_amt, 2000, "holder should have 5000 - 3000 = 2000");
    assert_eq!(recv_amt, 3000, "receiver should have 3000");
}

/// Inner afrz: freeze an asset holding.
#[test]
fn inner_afrz() {
    let sender = [0xAA; 32];
    let target = [0xDD; 32];
    let app_id = 42u64;
    let asset_id = 999u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    // Create asset with app as freeze address
    store.asset_params.insert(
        asset_id,
        AssetParamsRecord {
            creator: Address([1u8; 32]),
            params: AssetParams {
                total: 1_000_000,
                decimals: 0,
                default_frozen: false,
                freeze: Some(app_addr),
                ..Default::default()
            },
        },
    );

    // Target holds the asset, not frozen
    store.asset_holdings.insert(
        (Address(target), asset_id),
        AssetHolding {
            amount: 100,
            frozen: false,
        },
    );

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner afrz: freeze the target's holding
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(5)); // TypeEnum = afrz
    code.extend([0xb2, 16]);
    code.extend(pushint(asset_id)); // FreezeAsset (field 45)
    code.extend([0xb2, 45]);
    code.extend(pushbytes(&target)); // FreezeAssetAccount (field 46)
    code.extend([0xb2, 46]);
    code.extend(pushint(1)); // FreezeAssetFrozen (field 47) = true
    code.extend([0xb2, 47]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "inner afrz should succeed");

    let holding = ctx
        .store
        .asset_holdings
        .get(&(Address(target), asset_id))
        .unwrap();
    assert!(holding.frozen, "target's holding should now be frozen");
}

/// Inner keyreg (non-participation).
#[test]
fn inner_keyreg_nonparticipation() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Inner keyreg: non-participation
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(2)); // TypeEnum = keyreg
    code.extend([0xb2, 16]);
    code.extend(pushint(1)); // Nonparticipation (field 57)
    code.extend([0xb2, 57]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "inner keyreg non-participation should succeed");

    let inner = ctx.inner_txns();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0][0].txn.txn_type, "keyreg");
}

/// Self-call (reentrancy) is disallowed.
#[test]
fn self_call_disallowed() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Try to call self
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(6)); // TypeEnum = appl
    code.extend([0xb2, 16]);
    code.extend(pushint(app_id)); // ApplicationID = self
    code.extend([0xb2, 24]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result), "self-call should be disallowed");
}

/// itxn_begin without itxn_submit then another itxn_begin should fail.
#[test]
fn double_itxn_begin_fails() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);

    // itxn_begin; itxn_begin (should fail)
    let code: &[u8] = &[0xb1, 0xb1];
    let result = run_with_context(6, code, &mut ctx);
    assert!(
        is_failure(&result),
        "double itxn_begin without submit should fail"
    );
}

/// Unsupported inner txn type (stpf) fails.
#[test]
fn unsupported_inner_type_fails() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Try to create an stpf inner txn (TypeEnum = 7)
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(7)); // TypeEnum = stpf
    code.extend([0xb2, 16]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx);
    assert!(is_failure(&result), "stpf inner txn should be unsupported");
}

/// Inner acfg create followed by successful read of CreatedAssetID.
#[test]
fn inner_acfg_create_and_read_asset_id() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 1000;

    // Create asset, then check CreatedAssetID > 0
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(3)); // TypeEnum = acfg
    code.extend([0xb2, 16]);
    code.extend(pushint(100)); // ConfigAssetTotal
    code.extend([0xb2, 34]);
    code.push(0xb3); // itxn_submit

    // itxn CreatedAssetID (field 60) should be > 0
    code.extend([0xb4, 60]);
    code.extend(pushint(0));
    code.push(0x13); // !=
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(
        result,
        "CreatedAssetID should be non-zero after inner acfg create"
    );
}

/// Two sequential itxn_submit calls produce separate groups.
#[test]
fn two_sequential_submits_produce_separate_groups() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;

    // First submit
    let mut code = Vec::new();
    code.push(0xb1);
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]);
    code.extend(pushint(100));
    code.extend([0xb2, 8]);
    code.push(0xb3);

    // Second submit
    code.push(0xb1);
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]);
    code.extend(pushint(200));
    code.extend([0xb2, 8]);
    code.push(0xb3);

    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result);

    let inner = ctx.inner_txns();
    assert_eq!(inner.len(), 2, "should have 2 separate inner groups");
    assert_eq!(inner[0].len(), 1);
    assert_eq!(inner[1].len(), 1);
    assert_eq!(inner[0][0].txn.amount, 100);
    assert_eq!(inner[1][0].txn.amount, 200);
}

/// Clear state programs cannot issue inner transactions.
#[test]
fn clear_state_cannot_issue_inner_txns() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));

    // Create a ClearState on_completion txn
    let txn = SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender: Address(sender),
            fee: 1000,
            first_valid: 100.into(),
            last_valid: 200.into(),
            application_id: app_id,
            on_completion: 3, // ClearStateOC
            ..Default::default()
        },
        ..Default::default()
    };

    let mut ctx = make_context(&mut store, vec![txn], app_id);

    let code: &[u8] = &[0xb1]; // itxn_begin
    let result = run_with_context(6, code, &mut ctx);
    assert!(
        is_failure(&result),
        "clear state should not issue inner txns"
    );
}

/// itxn_next without itxn_begin fails.
#[test]
fn itxn_next_without_begin_fails() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);

    let code: &[u8] = &[0xb6]; // itxn_next
    let result = run_with_context(6, code, &mut ctx);
    assert!(
        is_failure(&result),
        "itxn_next without itxn_begin should fail"
    );
}

/// itxn_submit without itxn_begin fails.
#[test]
fn itxn_submit_without_begin_fails() {
    let sender = [0xAA; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);

    let code: &[u8] = &[0xb3]; // itxn_submit
    let result = run_with_context(6, code, &mut ctx);
    assert!(
        is_failure(&result),
        "itxn_submit without itxn_begin should fail"
    );
}

/// Default sender is the application address.
#[test]
fn default_sender_is_app_address() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Don't set Sender explicitly
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]); // Receiver
    code.extend(pushint(100));
    code.extend([0xb2, 8]); // Amount
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result);

    let inner = ctx.inner_txns();
    assert_eq!(
        inner[0][0].txn.sender, app_addr,
        "default sender should be app address"
    );
}

/// Inner txn IDs are computed and accessible.
#[test]
fn inner_txn_ids_computed() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 10_000;

    // Submit an inner pay, then read its TxID via itxn TxID (field 23)
    let mut code = Vec::new();
    code.push(0xb1);
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver));
    code.extend([0xb2, 7]);
    code.extend(pushint(100));
    code.extend([0xb2, 8]);
    code.push(0xb3);

    // itxn TxID should be 32 bytes long
    code.extend([0xb4, 23]); // itxn TxID
    code.push(0x15); // len
    code.extend(pushint(32));
    code.push(0x12); // ==
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "itxn TxID should be 32 bytes");

    // Also verify via the context
    let ids = ctx.inner_txn_ids();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].len(), 1);
    assert!(!ids[0][0].is_zero(), "inner txn ID should be non-zero");
}

/// Inner app creation (application_id == 0) creates new app.
#[test]
fn inner_app_creation() {
    let sender = [0xAA; 32];
    let app_a = 100u64;

    let mut store = LedgerState::new();

    // App A: creates a new app via inner txn
    let new_app_approval = prog(6, &[0x81, 0x01]); // pushint 1
    let new_app_clear = prog(6, &[0x81, 0x01]);

    let mut a_code = Vec::new();
    a_code.push(0xb1); // itxn_begin
    a_code.extend(pushint(6)); // TypeEnum = appl
    a_code.extend([0xb2, 16]);
    a_code.extend(pushint(0)); // ApplicationID = 0 (create)
    a_code.extend([0xb2, 24]);
    // ApprovalProgram (field 30)
    a_code.extend(pushbytes(&new_app_approval));
    a_code.extend([0xb2, 30]);
    // ClearStateProgram (field 31)
    a_code.extend(pushbytes(&new_app_clear));
    a_code.extend([0xb2, 31]);
    a_code.push(0xb3); // itxn_submit

    // Check CreatedApplicationID (field 61) > 0
    a_code.extend([0xb4, 61]); // itxn CreatedApplicationID
    a_code.extend(pushint(0));
    a_code.push(0x13); // !=
    a_code.push(0x43); // return

    let a_prog = prog(6, &a_code);
    seed_app_with_programs(
        &mut store,
        app_a,
        Address([1u8; 32]),
        a_prog,
        prog(6, &[0x81, 0x01]),
    );

    let app_a_addr = Address(app_address(app_a));
    fund_account(&mut store, app_a_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_a);
    let mut ctx = make_context(&mut store, vec![txn], app_a);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    ctx.fee_credit = 50_000;
    ctx.txn_counter = 500;

    let result = run_with_context(6, &a_code, &mut ctx).unwrap();
    assert!(
        result,
        "inner app creation should succeed and return non-zero ID"
    );

    // Verify the new app exists in the store
    let inner = ctx.inner_txns();
    let created_app_id = inner[0][0].apply_data_application_id;
    assert!(created_app_id > 0, "should have a created app ID");
    let new_app = ctx.store.app_params.get(&created_app_id);
    assert!(new_app.is_some(), "new app should exist in store");
}

/// Fee credit with group: one pays extra, another pays 0.
#[test]
fn fee_credit_mixed_fees_in_group() {
    let sender = [0xAA; 32];
    let receiver1 = [0xBB; 32];
    let receiver2 = [0xCC; 32];
    let app_id = 42u64;

    let mut store = LedgerState::new();
    seed_app_approve(&mut store, app_id, Address([1u8; 32]));
    let app_addr = Address(app_address(app_id));
    fund_account(&mut store, app_addr, 10_000_000);

    let txn = make_appl_txn(sender, app_id);
    let mut ctx = make_context(&mut store, vec![txn], app_id);
    ctx.fee_sink = Address([0xFE; 32]);
    fund_account(ctx.store, Address([0xFE; 32]), 0);
    // Give enough credit for the group minimum (2 * 1000 = 2000)
    ctx.fee_credit = 10_000;

    // Group of 2: first pays 2000 (overpays by 1000), second pays 0
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1));
    code.extend([0xb2, 16]); // TypeEnum = pay
    code.extend(pushbytes(&receiver1));
    code.extend([0xb2, 7]);
    code.extend(pushint(100));
    code.extend([0xb2, 8]);
    code.extend(pushint(2000)); // Fee = 2000 (overpays by 1000)
    code.extend([0xb2, 1]); // itxn_field Fee
    code.push(0xb6); // itxn_next
    code.extend(pushint(1));
    code.extend([0xb2, 16]);
    code.extend(pushbytes(&receiver2));
    code.extend([0xb2, 7]);
    code.extend(pushint(200));
    code.extend([0xb2, 8]);
    code.extend(pushint(0)); // Fee = 0 (covered by overpayment)
    code.extend([0xb2, 1]);
    code.push(0xb3); // itxn_submit
    code.extend(pushint(1));
    code.push(0x43);

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "mixed fee group should succeed with credit pooling");
}
