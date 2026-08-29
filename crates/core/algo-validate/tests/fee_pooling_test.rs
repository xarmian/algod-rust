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

//! Integration tests for fee pooling validation (Epic 12).
//!
//! Tests validate_group_fees and validate_transaction_rules with allow_fee_pooling.

use algo_types::{Address, Round, SignedTransaction, Transaction};
use algo_validate::{
    compute_group_id, validate_group_fees, validate_transaction_rules, MIN_TXN_FEE,
};

/// A non-zero sender address for tests.
const TEST_SENDER: Address = Address([1u8; 32]);

/// Build a minimal valid transaction for testing.
fn make_txn(fee: u64, amount: u64) -> Transaction {
    Transaction {
        txn_type: "pay".into(),
        sender: TEST_SENDER,
        fee,
        first_valid: Round(1000),
        last_valid: Round(1100),
        amount,
        receiver: Address([2u8; 32]),
        ..Default::default()
    }
}

/// Wrap a Transaction into a SignedTransaction with a dummy signature.
fn wrap_signed(txn: Transaction) -> SignedTransaction {
    SignedTransaction {
        txn,
        sig: [0u8; 64],
        ..Default::default()
    }
}

/// Assign group IDs to a slice of transactions: compute the group ID and
/// set the `group` field on each transaction.
fn assign_group(txns: &mut [Transaction]) {
    let gid = compute_group_id(txns);
    for txn in txns.iter_mut() {
        txn.group = gid.0;
    }
}

// ── Test 1: Valid pooling ─────────────────────────────────────────────
// 2 txns in a group: fees 0 + 2000 => total 2000 >= 2*1000 => passes.

#[test]
fn fee_pooling_valid_group_passes() {
    let mut txn1 = make_txn(0, 100);
    let mut txn2 = make_txn(2000, 200);
    assign_group(&mut [txn1.clone(), txn2.clone()]);

    // Re-read the group field after assignment (assign_group computed on unmodified txns).
    let gid = compute_group_id(&[make_txn(0, 100), make_txn(2000, 200)]);
    txn1.group = gid.0;
    txn2.group = gid.0;

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    // Group fee check should pass: 0 + 2000 = 2000 >= 2 * 1000.
    validate_group_fees(&txn_refs).expect("group fees should be valid");

    // Per-txn rules with allow_fee_pooling=true should also pass for the zero-fee txn.
    validate_transaction_rules(&stx1.txn, true)
        .expect("zero-fee txn with fee pooling should pass per-txn rules");
    validate_transaction_rules(&stx2.txn, true)
        .expect("2000-fee txn with fee pooling should pass per-txn rules");
}

// ── Test 2: Invalid pooling ───────────────────────────────────────────
// 2 txns in a group: fees 400 + 400 => total 800 < 2*1000 => fails.

#[test]
fn fee_pooling_insufficient_group_fees_fails() {
    let mut txn1 = make_txn(400, 100);
    let mut txn2 = make_txn(400, 200);

    let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
    txn1.group = gid.0;
    txn2.group = gid.0;

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    let err = validate_group_fees(&txn_refs).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("800"),
        "expected total_fee=800 in error, got: {msg}"
    );
    assert!(
        msg.contains("2000"),
        "expected required_fee=2000 in error, got: {msg}"
    );
}

// ── Test 3: Ungrouped zero fee fails ──────────────────────────────────
// Single txn with fee=0, no group => fails per-txn check.

#[test]
fn ungrouped_zero_fee_fails_per_txn_check() {
    let txn = make_txn(0, 100);
    let err = validate_transaction_rules(&txn, false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("below minimum"),
        "expected 'below minimum' error, got: {msg}"
    );
}

#[test]
fn ungrouped_zero_fee_with_pooling_flag_passes() {
    // When allow_fee_pooling=true, per-txn minimum fee check is skipped.
    let txn = make_txn(0, 100);
    validate_transaction_rules(&txn, true)
        .expect("zero-fee txn should pass when fee pooling is allowed");
}

// ── Test 4: Mixed block ──────────────────────────────────────────────
// Grouped txns with pooling + ungrouped txns with normal fees => all pass.

#[test]
fn mixed_block_grouped_and_ungrouped_passes() {
    // Grouped pair: fees 0 + 2000 (pooled total 2000 >= 2*1000).
    let mut gtxn1 = make_txn(0, 100);
    let mut gtxn2 = make_txn(2000, 200);

    let gid = compute_group_id(&[gtxn1.clone(), gtxn2.clone()]);
    gtxn1.group = gid.0;
    gtxn2.group = gid.0;

    // Ungrouped txn with standard fee.
    let utxn = make_txn(MIN_TXN_FEE, 500);

    let sg1 = wrap_signed(gtxn1);
    let sg2 = wrap_signed(gtxn2);
    let su = wrap_signed(utxn);

    // validate_group_fees should pass for the whole payset: the grouped
    // pair is checked pooled (usage summed across the group), and the
    // ungrouped txn is checked as its own singleton group -- it pays
    // MIN_TXN_FEE, which covers an ordinary transaction on its own.
    let txn_refs: Vec<&SignedTransaction> = vec![&sg1, &sg2, &su];
    validate_group_fees(&txn_refs).expect("mixed block group fees should be valid");

    // Per-txn rules: grouped txns use allow_fee_pooling=true.
    validate_transaction_rules(&sg1.txn, true)
        .expect("grouped zero-fee txn should pass with fee pooling");
    validate_transaction_rules(&sg2.txn, true)
        .expect("grouped 2000-fee txn should pass with fee pooling");

    // Ungrouped txn uses allow_fee_pooling=false.
    validate_transaction_rules(&su.txn, false)
        .expect("ungrouped txn with standard fee should pass");
}

// ── Test 5: Edge case — exactly at minimum ────────────────────────────

#[test]
fn fee_pooling_exact_minimum_passes() {
    // 2 txns: fees 500 + 1500 => total 2000 == 2*1000 => passes exactly.
    let mut txn1 = make_txn(500, 100);
    let mut txn2 = make_txn(1500, 200);

    let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
    txn1.group = gid.0;
    txn2.group = gid.0;

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    validate_group_fees(&txn_refs).expect("exact minimum group fees should pass");
}

// ── Test 6: Edge case — one below minimum ─────────────────────────────

#[test]
fn fee_pooling_one_below_minimum_fails() {
    // 2 txns: fees 999 + 1000 => total 1999 < 2*1000 => fails.
    let mut txn1 = make_txn(999, 100);
    let mut txn2 = make_txn(1000, 200);

    let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
    txn1.group = gid.0;
    txn2.group = gid.0;

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    let err = validate_group_fees(&txn_refs).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("1999"),
        "expected total_fee=1999 in error, got: {msg}"
    );
}

// ── Test 7: Ungrouped txns are each checked as their own singleton group ──
//
// Go's `ledger/eval.go` `CheckGroupFees`/`SummarizeFees` run unconditionally
// on every top-level txgroup, size-1 (ungrouped) submissions included --
// there is no "skip when `Group` is zero" carve-out upstream. This
// function previously treated `group == 0` as "not part of a group, skip
// the pooled-usage check entirely", which correctly matched the flat
// per-txn minimum-fee rule for *ordinary* transactions (redundant with
// `validate_transaction_rules`'s own check) but silently never enforced
// the size-pricing surcharges that are *only* computed at the group level
// -- most notably `logic_sig_program_fee_contribution`'s pooled LogicSig
// program-byte surcharge, which has no other enforcement point for a
// standalone submission. Confirmed live via issue #703's dual-node
// testing: a real go-algorand node correctly rejected an ungrouped,
// underpaid, oversized-LogicSig transaction that algod-rust wrongly
// accepted because of this exact gap.
#[test]
fn validate_group_fees_rejects_underpaid_ungrouped_txns() {
    // All ungrouped txns, each individually underpaid — each is now its
    // own size-1 "group" and must independently satisfy its required fee.
    let txn1 = make_txn(0, 100); // no group, zero fee
    let txn2 = make_txn(500, 200); // no group, sub-minimum fee

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    let err = validate_group_fees(&txn_refs).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("ungrouped:"),
        "expected the singleton group's label to identify it as ungrouped, got: {msg}"
    );
}

#[test]
fn validate_group_fees_accepts_adequately_paid_ungrouped_txns() {
    // Each ungrouped txn independently pays at least MIN_TXN_FEE: the
    // singleton-group check must pass for every one of them.
    let txn1 = make_txn(MIN_TXN_FEE, 100);
    let txn2 = make_txn(MIN_TXN_FEE, 200);

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    validate_group_fees(&txn_refs)
        .expect("adequately-paid ungrouped txns should each pass their own singleton check");
}
