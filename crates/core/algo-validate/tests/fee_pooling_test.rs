//! Integration tests for fee pooling validation (Epic 12).
//!
//! Tests validate_group_fees and validate_transaction_rules with allow_fee_pooling.

use algo_types::{Address, Round, SignedTransaction, Transaction};
use algo_validate::{
    compute_group_id, validate_group_fees, validate_transaction_rules, MIN_TXN_FEE,
};
use serde_bytes::ByteBuf;

/// A non-zero sender address for tests.
const TEST_SENDER: Address = Address([1u8; 32]);

/// Build a minimal valid transaction for testing.
fn make_txn(fee: u64, amount: u64) -> Transaction {
    Transaction {
        txn_type: "pay".to_string(),
        sender: TEST_SENDER,
        fee,
        first_valid: Round(1000),
        last_valid: Round(1100),
        amount,
        receiver: Address([2u8; 32]),
        note: ByteBuf::new(),
        genesis_id: String::new(),
        genesis_hash: ByteBuf::new(),
        group: ByteBuf::new(),
        lease: ByteBuf::new(),
        ..Default::default()
    }
}

/// Wrap a Transaction into a SignedTransaction with a dummy signature.
fn wrap_signed(txn: Transaction) -> SignedTransaction {
    SignedTransaction {
        txn,
        sig: ByteBuf::from(vec![0u8; 64]),
        msig: None,
        lsig: None,
        auth_addr: None,
        has_genesis_id: false,
        has_genesis_hash: false,
        ..Default::default()
    }
}

/// Assign group IDs to a slice of transactions: compute the group ID and
/// set the `group` field on each transaction.
fn assign_group(txns: &mut [Transaction]) {
    let gid = compute_group_id(txns);
    for txn in txns.iter_mut() {
        txn.group = ByteBuf::from(gid.as_bytes().to_vec());
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
    txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
    txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

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
    txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
    txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

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
    gtxn1.group = ByteBuf::from(gid.as_bytes().to_vec());
    gtxn2.group = ByteBuf::from(gid.as_bytes().to_vec());

    // Ungrouped txn with standard fee.
    let utxn = make_txn(MIN_TXN_FEE, 500);

    let sg1 = wrap_signed(gtxn1);
    let sg2 = wrap_signed(gtxn2);
    let su = wrap_signed(utxn);

    // validate_group_fees should pass for the whole payset
    // (it only checks grouped txns, skips ungrouped ones).
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
    txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
    txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

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
    txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
    txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

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

// ── Test 7: Ungrouped txns skipped by validate_group_fees ─────────────

#[test]
fn validate_group_fees_skips_ungrouped_txns() {
    // All ungrouped txns — validate_group_fees should return Ok regardless of fee.
    let txn1 = make_txn(0, 100); // no group, zero fee
    let txn2 = make_txn(500, 200); // no group, sub-minimum fee

    let stx1 = wrap_signed(txn1);
    let stx2 = wrap_signed(txn2);
    let txn_refs: Vec<&SignedTransaction> = vec![&stx1, &stx2];

    validate_group_fees(&txn_refs)
        .expect("ungrouped txns should be skipped by validate_group_fees");
}
