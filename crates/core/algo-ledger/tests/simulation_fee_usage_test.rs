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

//! Integration test for simulate fee-usage reporting (issue #671).
//!
//! Runs a real two-level nested inner-transaction group through the
//! `Simulator` end to end (top-level appl -> inner appl -> inner pay) and
//! checks that `TxnResult::fees_paid` and `TxnGroupResult::group_usage` /
//! `group_fees_paid` are populated by recursively summing over the whole
//! inner-transaction tree, matching go-algorand's `populateFeeUsage`
//! (`ledger/simulation/trace.go`).

use std::collections::BTreeMap;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};

const FEE_SINK: Address = Address([0xFE; 32]);
const MIN_TXN_FEE: u64 = 1000;

/// Compute app address = SHA512/256("appID" || app_id.to_be_bytes()).
fn app_address(app_id: u64) -> Address {
    Address(algo_ledger::avm_context::app_address(app_id))
}

fn setup_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

fn register_app(state: &mut LedgerState, creator: Address, app_id: u64, approval: Vec<u8>) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: vec![0x06, 0x81, 0x01, 0x43], // v6: pushint 1; return
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    };
    state.set_app_params(app_id, app_params);
    let mut acct = state.get_account(&creator).cloned().unwrap_or_default();
    acct.total_created_apps += 1;
    state.set_account(&creator, acct);
}

fn fund(state: &mut LedgerState, addr: Address, micro_algos: u64) {
    let mut acct = state.get_account(&addr).cloned().unwrap_or_default();
    acct.micro_algos = micro_algos;
    state.set_account(&addr, acct);
}

fn make_appl_txn(sender: Address, app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee: MIN_TXN_FEE,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            application_id: app_id,
            on_completion: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

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

fn pushint(val: u64) -> Vec<u8> {
    let mut bytes = vec![0x81];
    bytes.extend(varuint(val));
    bytes
}

fn pushbytes(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80];
    bytes.extend(varuint(data.len() as u64));
    bytes.extend_from_slice(data);
    bytes
}

/// itxn_begin; TypeEnum=pay; Receiver=addr; Amount=amt; itxn_submit (fee left
/// unset, so the AVM defaults it to `consensus.min_txn_fee`).
fn build_inner_pay(receiver: &Address, amount: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(1)); // TypeEnum = pay
    code.extend([0xb2, 16]); // itxn_field TypeEnum
    code.extend(pushbytes(&receiver.0)); // Receiver
    code.extend([0xb2, 7]); // itxn_field Receiver
    code.extend(pushint(amount));
    code.extend([0xb2, 8]); // itxn_field Amount
    code.push(0xb3); // itxn_submit
    code
}

/// itxn_begin; TypeEnum=appl; ApplicationID=id; itxn_submit (fee unset).
fn build_inner_appl_call(app_id: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.push(0xb1); // itxn_begin
    code.extend(pushint(6)); // TypeEnum = appl
    code.extend([0xb2, 16]);
    code.extend(pushint(app_id)); // ApplicationID
    code.extend([0xb2, 24]);
    code.push(0xb3); // itxn_submit
    code
}

/// Two-level nested inner transactions through `Simulator::simulate`:
/// top-level appl call to App A -> App A's inner appl call to App B -> App
/// B's inner pay to `receiver`. Every hop pays exactly `MIN_TXN_FEE` with no
/// size surcharges, so both the recursive fees-paid sum and the recursive
/// usage sum are exact multiples of one min-fee unit.
#[test]
fn simulate_reports_fee_usage_recursively_over_nested_inner_txns() {
    let sender = Address([0xAA; 32]);
    let receiver = Address([0xDD; 32]);
    let app_a = 100u64;
    let app_b = 200u64;

    let mut state = setup_state(sender);

    // App B: inner pay to receiver, then approve.
    let mut b_code = vec![0x06]; // version 6
    b_code.extend(build_inner_pay(&receiver, 5000));
    b_code.extend(pushint(1));
    b_code.push(0x43); // return
    register_app(&mut state, Address([2u8; 32]), app_b, b_code);

    // App A: inner appl call to App B, then approve.
    let mut a_code = vec![0x06];
    a_code.extend(build_inner_appl_call(app_b));
    a_code.extend(pushint(1));
    a_code.push(0x43);
    register_app(&mut state, Address([1u8; 32]), app_a, a_code);

    // Fund both app accounts for their inner-txn fees/payment, and both
    // creator accounts (min-balance requires `app_flat_params_min_balance`
    // per created app).
    fund(&mut state, app_address(app_a), 10_000_000);
    fund(&mut state, app_address(app_b), 10_000_000);
    fund(&mut state, Address([1u8; 32]), 10_000_000);
    fund(&mut state, Address([2u8; 32]), 10_000_000);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, app_a)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "unexpected failure: {:?}",
        group.failure_message
    );

    // Per-txn FeesPaid: own fee (MIN_TXN_FEE) + inner appl's fee
    // (MIN_TXN_FEE) + inner pay's fee (MIN_TXN_FEE), recursively summed.
    let txn_result = &group.txn_results[0];
    assert_eq!(txn_result.fees_paid, MIN_TXN_FEE * 3);

    // No per-transaction `usage` field exists on TxnResult at all -- usage is
    // only reported at the group level (see below). This is a compile-time
    // guarantee (the field doesn't exist), documented here for the reader.

    // Group-level usage: three ordinary transactions, each with feeFactor ==
    // ONE_MICROS (1_000_000, no size surcharges), pooled recursively across
    // the whole inner-txn tree exactly like GroupFeesPaid.
    assert_eq!(group.group_usage, 3_000_000);
    assert_eq!(group.group_fees_paid, MIN_TXN_FEE * 3);
}

/// A group whose transaction spawns no inner transactions reports FeesPaid
/// equal to its own fee, and GroupUsage/GroupFeesPaid equal to the ordinary
/// (non-recursive) `SummarizeFees` result -- the recursive machinery must be
/// a no-op when there is nothing to recurse into.
#[test]
fn simulate_reports_fee_usage_for_flat_group_without_inner_txns() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, vec![0x06, 0x81, 0x01, 0x43]);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());
    assert_eq!(group.txn_results[0].fees_paid, MIN_TXN_FEE);
    assert_eq!(group.group_usage, 1_000_000); // one ordinary txn's feeFactor
    assert_eq!(group.group_fees_paid, MIN_TXN_FEE);
}
