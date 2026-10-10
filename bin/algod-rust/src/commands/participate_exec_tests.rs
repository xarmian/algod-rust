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

//! Issues #1773 / #1774 / #1776: pool admission and block assembly run the
//! real apply (go `pendingBlockEvaluator.TransactionGroup` / `GenerateBlock`),
//! so nothing go refuses is admitted or proposed.

use super::*;
use algo_pool::traits::BlockEvaluator;
use algo_types::{AppParams, AssetHolding, SignedTransaction, Transaction};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{Duration, Instant};

const GENESIS_ID: &str = "net-x";
const GENESIS_HASH: [u8; 32] = [0xAA; 32];
const FEE_SINK: Address = Address([0xF1; 32]);
const REWARDS_POOL: Address = Address([0xF2; 32]);

type Key = (Address, SigningKey);

fn key(seed: u8) -> Key {
    let k = SigningKey::from_bytes(&[seed; 32]);
    (Address(k.verifying_key().to_bytes()), k)
}

fn funded(micro: u64) -> AccountData {
    AccountData {
        micro_algos: micro,
        ..Default::default()
    }
}

/// An account that still holds one asset.
fn holder(micro: u64) -> AccountData {
    AccountData {
        micro_algos: micro,
        total_assets_opted_in: 1,
        ..Default::default()
    }
}

fn genesis_header() -> BlockHeader {
    BlockHeader {
        round: Round(0),
        current_protocol: CONSENSUS_V41.to_string(),
        fee_sink: FEE_SINK,
        rewards_pool: REWARDS_POOL,
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        timestamp: 1_000,
        ..BlockHeader::default()
    }
}

/// A ledger committed through genesis (round 0) with the chain fields the
/// apply reads and the given funded accounts, plus a primed pool on top.
fn fixture(
    accounts: &[(Address, AccountData)],
    holdings: &[(Address, u64)],
) -> (Arc<Mutex<SqliteLedger>>, Arc<TransactionPool>) {
    fixture_with_tracking(accounts, holdings, None)
}

/// [`fixture`] whose round-0 header carries `state_proof_tracking`.
fn fixture_with_tracking(
    accounts: &[(Address, AccountData)],
    holdings: &[(Address, u64)],
    state_proof_tracking: Option<rmpv::Value>,
) -> (Arc<Mutex<SqliteLedger>>, Arc<TransactionPool>) {
    let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().expect("ledger")));
    let hdr = genesis_header();
    let block = algo_types::Block {
        round: hdr.round,
        current_protocol: hdr.current_protocol.clone(),
        fee_sink: hdr.fee_sink,
        rewards_pool: hdr.rewards_pool,
        genesis_id: hdr.genesis_id.clone(),
        genesis_hash: hdr.genesis_hash,
        timestamp: hdr.timestamp,
        state_proof_tracking,
        ..algo_types::Block::default()
    };
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().unwrap();
        l.put_block(
            0,
            &block.current_protocol,
            &canonical_encode_block_header_from_block(&block),
            &canonical_encode_block(&block),
        )
        .unwrap();
        l.set_current_round(Round(0));
        l.set_fee_sink(FEE_SINK);
        l.set_rewards_pool(REWARDS_POOL);
        l.set_genesis_id(GENESIS_ID.to_string());
        l.set_genesis_hash(GENESIS_HASH);
        l.set_protocol(CONSENSUS_V41.to_string());
        l.set_account(&FEE_SINK, funded(10_000_000));
        l.set_account(&REWARDS_POOL, funded(10_000_000));
        for (a, d) in accounts {
            l.set_account(a, d.clone());
        }
        for (a, id) in holdings {
            l.set_asset_holding(a, *id, AssetHolding::default());
        }
        l.commit_block().unwrap();
    }
    let adapter = Arc::new(PoolLedgerAdapter::new(ledger.clone()));
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        adapter as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    pool.ensure_evaluator_primed();
    (ledger, pool)
}

fn sign(txn: Transaction, k: &SigningKey) -> SignedTransaction {
    let canonical = algo_codec::canonical_encode_transaction(&txn);
    let mut msg = b"TX".to_vec();
    msg.extend_from_slice(&canonical);
    SignedTransaction {
        sig: k.sign(&msg).to_bytes(),
        txn,
        ..Default::default()
    }
}

fn base_txn(sender: Address, txn_type: TxnType) -> Transaction {
    Transaction {
        txn_type,
        sender,
        fee: 1_000,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        ..Default::default()
    }
}

fn pay(k: &Key, to: Address, amount: u64, close: Option<Address>) -> SignedTransaction {
    let mut t = base_txn(k.0, TxnType::Pay);
    t.receiver = to;
    t.amount = amount;
    if let Some(c) = close {
        t.close_remainder_to = c;
    }
    sign(t, &k.1)
}

fn txid(stx: &SignedTransaction) -> String {
    algo_codec::compute_txn_id(&stx.txn).to_string()
}

fn app_call(k: &Key, app_id: u64, accounts: Vec<Address>, fee: u64) -> SignedTransaction {
    let mut t = base_txn(k.0, TxnType::Appl);
    t.application_id = app_id;
    t.fee = fee;
    if !accounts.is_empty() {
        t.accounts = Some(accounts);
    }
    sign(t, &k.1)
}

fn put_app(ledger: &Arc<Mutex<SqliteLedger>>, app_id: u64, creator: Address, teal: &str) {
    let program = algo_avm::assembler::assemble_string(teal)
        .expect("program must assemble")
        .program;
    ledger.lock().unwrap().set_app_params(
        app_id,
        AppParams {
            creator,
            approval_program: program,
            clear_state_program: vec![0x08, 0x81, 0x01],
            ..Default::default()
        },
    );
}

// ---- #1773: close-to with outstanding assets ----

#[test]
fn pool_rejects_close_to_with_outstanding_assets_with_go_text() {
    let a = key(1);
    let d = key(2);
    let (_ledger, pool) = fixture(
        &[(a.0, holder(5_000_000)), (d.0, funded(1_000_000))],
        &[(a.0, 77)],
    );
    let stx = pay(&a, d.0, 0, Some(d.0));
    let err = pool.remember_one(stx.clone()).expect_err("go rejects this");
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction {}: cannot close: 1 outstanding assets",
            txid(&stx)
        )
    );
    assert!(
        pool.pending_tx_groups().is_empty(),
        "a rejected group must not be pending"
    );
}

#[test]
fn pool_still_admits_a_valid_close_to() {
    let a = key(1);
    let d = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(5_000_000)), (d.0, funded(1_000_000))], &[]);
    pool.remember_one(pay(&a, d.0, 0, Some(d.0)))
        .expect("closing an empty account is valid");
    assert_eq!(pool.pending_tx_groups().len(), 1);
}

// ---- #1774: app calls ----

#[test]
fn pool_rejects_a_call_to_a_deleted_app() {
    let s = key(3);
    let (_ledger, pool) = fixture(&[(s.0, funded(5_000_000))], &[]);
    let stx = app_call(&s, 4242, vec![], 1_000);
    let err = pool.remember_one(stx.clone()).expect_err("no such app");
    // go ledger/apply/application.go ApplicationCall + eval.go
    // `fmt.Errorf("transaction %v: %w", txid, err)` + Remember's wrap.
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction {}: only ClearState is supported for an application (4242) that does not exist",
            txid(&stx)
        )
    );
    assert!(pool.pending_tx_groups().is_empty());
}

#[test]
fn pool_rejects_an_app_call_whose_inner_close_fails() {
    let s = key(3);
    let d = key(4);
    let app_id = 900u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let (ledger, pool) = fixture(
        &[
            (s.0, funded(5_000_000)),
            (d.0, funded(1_000_000)),
            (app_addr, holder(10_000_000)),
        ],
        &[(app_addr, 77)],
    );
    put_app(
        &ledger,
        app_id,
        s.0,
        concat!(
            "#pragma version 8\n",
            "itxn_begin\n",
            "int pay\n",
            "itxn_field TypeEnum\n",
            "txn Accounts 1\n",
            "itxn_field Receiver\n",
            "txn Accounts 1\n",
            "itxn_field CloseRemainderTo\n",
            "int 0\n",
            "itxn_field Fee\n",
            "itxn_submit\n",
            "int 1\n",
        ),
    );
    let stx = app_call(&s, app_id, vec![d.0], 2_000);
    let err = pool
        .remember_one(stx.clone())
        .expect_err("inner close fails");
    let text = err.to_string();
    assert!(
        text.starts_with(&format!(
            "TransactionPool.Remember: transaction {}: ",
            txid(&stx)
        )),
        "{text}"
    );
    // go: logic.EvalError => "logic eval error: <err>. Details: app=<id>, pc=<pc>".
    let want = format!(
        "TransactionPool.Remember: transaction {}: logic eval error: inner tx 0 failed: cannot close: 1 outstanding assets. Details: app=900, pc=",
        txid(&stx)
    );
    assert!(text.starts_with(&want), "{text}");
    assert!(
        text[want.len()..].chars().all(|c| c.is_ascii_digit()),
        "{text}"
    );
    assert!(pool.pending_tx_groups().is_empty());
}

#[test]
fn pool_rejects_a_rejecting_approval_program() {
    let s = key(3);
    let app_id = 901u64;
    let (ledger, pool) = fixture(&[(s.0, funded(5_000_000))], &[]);
    put_app(
        &ledger,
        app_id,
        s.0,
        "#pragma version 8
int 0
",
    );
    let stx = app_call(&s, app_id, vec![], 1_000);
    let err = pool.remember_one(stx.clone()).expect_err("program rejects");
    // go ledgercore.ApprovalProgramRejectedError.
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction {}: transaction rejected by ApprovalProgram",
            txid(&stx)
        )
    );
}

// ---- pending state visibility (go pendingBlockEvaluator) ----

#[test]
fn pool_admits_a_spend_from_an_account_funded_by_a_pending_group() {
    let a = key(1);
    let fresh = key(5);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    pool.remember_one(pay(&a, fresh.0, 10_000_000, None))
        .expect("fund");
    pool.remember_one(pay(&fresh, b.0, 1_000_000, None))
        .expect("spends what the pending group gave it");
    assert_eq!(pool.pending_tx_groups().len(), 2);
}

// ---- #1776: the proposer never emits an un-applyable group ----

#[test]
fn assembled_block_drops_an_injected_unapplyable_group_and_carries_apply_data() {
    use algo_ledger::apply::{apply_block_capturing_apply_data, ApplyMode};

    let a = key(1);
    let b = key(2);
    let c = key(6);
    let d = key(7);
    let accounts = vec![
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (c.0, holder(5_000_000)),
        (d.0, funded(5_000_000)),
    ];
    let holdings = [(c.0, 77u64)];
    let (ledger, _pool) = fixture(&accounts, &holdings);

    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");

    // A good group, then a close that closes d with a real closing amount.
    eval.transaction_group(&[pay(&a, b.0, 2_000_000, None)])
        .expect("good group");
    eval.transaction_group(&[pay(&d, a.0, 0, Some(a.0))])
        .expect("valid close");
    assert!(
        eval.transaction_group(&[pay(&c, a.0, 0, Some(a.0))])
            .is_err(),
        "admission refuses the close with an outstanding asset"
    );

    // Smuggle the same group in past admission, as a stale or buggy
    // admission path could: assembly must still not propose it.
    let bad = pay(&c, a.0, 0, Some(a.0));
    let mut stib = bad.clone();
    eval.genesis_rule().strip(&mut stib);
    let start = eval.included_txns.len();
    eval.included_txns.push(stib);
    eval.exec.as_mut().unwrap().groups.push(ExecGroup {
        start,
        len: 1,
        fees: 1_000,
    });
    eval.fees_collected += 1_000;
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(
        eval.exec.as_ref().unwrap().last_passes,
        2,
        "one failing pass, one clean pass"
    );
    // The agreement layer sets the proposer after assembly: the epilogue of
    // the final apply must accept the proposed block with it set.
    block.proposer = b.0;

    assert_eq!(block.payset.len(), 2, "the un-applyable group is dropped");
    assert_eq!(
        block.fees_collected, 2_000,
        "dropped group fees are removed"
    );
    assert_eq!(block.payset[1].closing_amount, 5_000_000 - 1_000);

    // The proposal applies cleanly on a fresh copy of the same chain and its
    // recorded ApplyData is exactly what apply computes (go compares the
    // two: "applyData mismatch").
    let (replica, _p) = fixture(&accounts, &holdings);
    let computed = {
        let mut l = replica.lock().unwrap();
        apply_block_capturing_apply_data(&mut *l, &block, ApplyMode::Execute)
            .expect("proposal must apply")
    };
    let diffs = algo_ledger::shadow_execute::compare_recorded_apply_data(&block, &computed);
    assert!(diffs.is_empty(), "applyData mismatch: {diffs:?}");

    let result =
        algo_validate::block::validate_block(&block, Some(1_000), GENESIS_ID, &GENESIS_HASH, None);
    assert!(
        result.errors.is_empty(),
        "validate_block: {:?}",
        result.errors
    );
}

// ---- review findings: overlay and admitted set stay consistent ----

/// A concrete evaluator on a fresh fixture ledger (round 0 committed).
fn evaluator(
    accounts: &[(Address, AccountData)],
) -> (Arc<Mutex<SqliteLedger>>, SimpleBlockEvaluator) {
    let (ledger, _pool) = fixture(accounts, &[]);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    (ledger, eval)
}

#[test]
fn stale_base_marks_exec_incomplete_and_later_groups_are_not_wrongly_rejected() {
    let a = key(1);
    let fresh = key(5);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    // The chain advanced under the evaluator: the group cannot be evaluated.
    eval.exec.as_mut().unwrap().template.round = Round(9);
    eval.transaction_group(&[pay(&a, fresh.0, 10_000_000, None)])
        .expect("admitted on the cheap checks");
    assert!(eval.exec.as_ref().unwrap().incomplete);
    // Its effects are not in the overlay; without the incomplete flag this
    // spend would be rejected as an overspend.
    eval.transaction_group(&[pay(&fresh, b.0, 1_000_000, None)])
        .expect("must not be rejected for a missing overlay entry");
}

#[test]
fn spent_admission_budget_marks_exec_incomplete() {
    let a = key(1);
    let fresh = key(5);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.exec.as_mut().unwrap().spent = EXEC_ADMISSION_BUDGET;
    eval.transaction_group(&[pay(&a, fresh.0, 10_000_000, None)])
        .expect("admitted without evaluation");
    assert!(eval.exec.as_ref().unwrap().incomplete);
    eval.transaction_group(&[pay(&fresh, b.0, 1_000_000, None)])
        .expect("later group is not checked against a stale overlay");
}

#[test]
fn an_evaluation_failure_no_transaction_owns_rejects_the_group() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.exec.as_mut().unwrap().template.current_protocol = "no-such-protocol".to_string();
    let stx = pay(&a, b.0, 1, None);
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("rejected");
    assert!(
        err.to_string()
            .starts_with(&format!("transaction {}: ", txid(&stx))),
        "{err}"
    );
    assert!(eval.included_txns.is_empty(), "nothing was admitted");
}

// ---- review findings: go wording of the common reasons ----

#[test]
fn pool_reason_maps_typed_apply_errors_to_go_wording() {
    use algo_error::{AlgoError, RejectClass};
    assert_eq!(
        pool_reason(&AlgoError::AppDoesNotExist { app_id: 7 }),
        (
            "only ClearState is supported for an application (7) that does not exist".to_string(),
            RejectClass::Other
        )
    );
    assert_eq!(
        pool_reason(&AlgoError::ApprovalRejected {
            app_id: 7,
            reason: None
        }),
        (
            "transaction rejected by ApprovalProgram".to_string(),
            RejectClass::TealReject
        )
    );
    assert_eq!(
        pool_reason(&AlgoError::ApprovalRejected {
            app_id: 7,
            reason: Some("AVM: assert failed".into())
        }),
        (
            "logic eval error: assert failed. Details: app=7, pc=0".to_string(),
            RejectClass::TealErr
        )
    );
    // Text that merely LOOKS like a typed verdict is not one.
    assert_eq!(
        pool_reason(&AlgoError::Ledger {
            message: "appl: app 7 does not exist".into()
        })
        .1,
        RejectClass::Other
    );
    assert_eq!(
        pool_reason(&AlgoError::Ledger {
            message: "sender X has insufficient balance 1 for fee 2".into()
        })
        .0,
        "sender X has insufficient balance 1 for fee 2",
        "no 'ledger error: ' prefix"
    );
    assert_eq!(
        pool_reason(&AlgoError::Avm {
            message: "boom".into()
        })
        .0,
        "boom",
        "no 'AVM: ' prefix"
    );
}

// ---- review findings: block size is checked WITH ApplyData ----

#[test]
fn proposal_is_trimmed_to_the_byte_limit_measured_with_apply_data() {
    let a = key(1);
    let b = key(2);
    let d = key(7);
    let (_ledger, mut eval) = evaluator(&[
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (d.0, funded(5_000_000)),
    ]);
    let plain = pay(&a, b.0, 2_000_000, None);
    let closing = pay(&d, a.0, 0, Some(a.0));
    // Admission sizes the stripped transactions; pick a limit that admits
    // both but that the closing payment outgrows once its closing amount
    // (`ca`) is recorded.
    let mut sizes = 0usize;
    for stx in [&plain, &closing] {
        let mut stib = stx.clone();
        eval.genesis_rule().strip(&mut stib);
        sizes += canonical_encode_signed_txn_in_block(&stib).len();
    }
    eval.max_txn_bytes = sizes;
    eval.transaction_group(&[plain]).expect("first group fits");
    eval.transaction_group(&[closing])
        .expect("second group fits when stripped");
    let block = eval.generate_block(&[]).expect("generate_block");
    let encoded: usize = block
        .payset
        .iter()
        .map(|s| canonical_encode_signed_txn_in_block(s).len())
        .sum();
    assert!(
        encoded <= sizes,
        "payset {encoded} exceeds the limit {sizes}"
    );
    assert_eq!(
        block.payset.len(),
        1,
        "the group that no longer fits is dropped"
    );
    assert_eq!(block.fees_collected, 1_000, "its fees are removed");
}

// ---- review findings: transient / unattributable scratch failures ----

use algo_ledger::shadow_execute::test_hooks;

#[test]
fn transient_scratch_failure_is_retried_once() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 1_000, None)])
        .unwrap();
    test_hooks::reset_scratch_calls();
    test_hooks::inject_scratch_failures(1);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1, "the retry succeeded");
    assert_eq!(
        test_hooks::scratch_calls(),
        2,
        "one failed pass + one retry"
    );
}

#[test]
fn unattributable_failure_keeps_the_longest_prefix_that_evaluates() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    for i in 0..3u64 {
        eval.transaction_group(&[pay(&a, b.0, 1_000 + i, None)])
            .unwrap();
    }
    test_hooks::reset_scratch_calls();
    // Any evaluation of more than one transaction fails with a failure no
    // transaction owns: pass 1 and its retry fail, bisection finds the
    // prefix of one group (mid=2 fails, mid=1 succeeds), one pass verifies.
    test_hooks::inject_failure_over_payset_len(Some(1));
    let block = eval.generate_block(&[]).expect("generate_block");
    test_hooks::inject_failure_over_payset_len(None);
    assert_eq!(block.payset.len(), 1, "the clean prefix is proposed");
    assert_eq!(block.fees_collected, 1_000);
    assert_eq!(test_hooks::scratch_calls(), 5);
    assert_eq!(eval.exec.as_ref().unwrap().last_passes, 5);
}

#[test]
fn persistent_failure_of_even_the_first_group_proposes_an_empty_payset_and_is_counted() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 1_000, None)])
        .unwrap();
    let before = algo_ledger::proposal_eval::scratch_failures();
    test_hooks::inject_failure_over_payset_len(Some(0));
    let block = eval.generate_block(&[]).expect("generate_block");
    test_hooks::inject_failure_over_payset_len(None);
    assert!(block.payset.is_empty());
    assert_eq!(block.fees_collected, 0);
    // The counter is process-global: other tests may add to it concurrently.
    assert!(algo_ledger::proposal_eval::scratch_failures() > before);
    assert!(
        algo_ledger::proposal_eval::proposal_metrics_prometheus_text()
            .contains("algod_rust_proposal_scratch_failures_total")
    );
}

// ---- review findings: oversize is trimmed in one step ----

#[test]
fn oversize_payset_is_trimmed_to_the_fitting_prefix_in_one_step() {
    let a = key(1);
    let closers: Vec<Key> = (10..14).map(key).collect();
    let mut accounts = vec![(a.0, funded(50_000_000))];
    accounts.extend(closers.iter().map(|k| (k.0, funded(5_000_000))));
    let (_ledger, mut eval) = evaluator(&accounts);
    let txns: Vec<SignedTransaction> = closers.iter().map(|k| pay(k, a.0, 0, Some(a.0))).collect();
    let mut stripped = 0usize;
    for stx in &txns {
        let mut stib = stx.clone();
        eval.genesis_rule().strip(&mut stib);
        stripped += canonical_encode_signed_txn_in_block(&stib).len();
    }
    // Each closing payment grows by its `ca`; leave room for only one.
    eval.max_txn_bytes = stripped + 8;
    for stx in &txns {
        eval.transaction_group(std::slice::from_ref(stx))
            .expect("fits when stripped");
    }
    test_hooks::reset_scratch_calls();
    let block = eval.generate_block(&[]).expect("generate_block");
    assert!(block.payset.len() < 4 && !block.payset.is_empty());
    let encoded: usize = block
        .payset
        .iter()
        .map(|s| canonical_encode_signed_txn_in_block(s).len())
        .sum();
    assert!(encoded <= stripped + 8);
    assert_eq!(
        test_hooks::scratch_calls(),
        2,
        "one pass measures the ApplyData sizes, one verifies the prefix (not one pass per dropped group)"
    );
}

// ---- review findings: lock wait is not charged to the admission budget ----

#[test]
fn waiting_for_the_ledger_lock_does_not_consume_the_admission_budget() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let held = ledger.clone();
    let holder = std::thread::spawn(move || {
        let _g = held.lock().unwrap();
        std::thread::sleep(Duration::from_millis(400));
    });
    std::thread::sleep(Duration::from_millis(50));
    eval.transaction_group(&[pay(&a, b.0, 1_000, None)])
        .expect("admitted once the lock frees");
    holder.join().unwrap();
    let spent = eval.exec.as_ref().unwrap().spent;
    assert!(
        spent < Duration::from_millis(200),
        "the 350 ms lock wait must not be charged to the budget, spent {spent:?}"
    );
    assert!(
        algo_ledger::proposal_eval::proposal_metrics_prometheus_text()
            .contains("algod_rust_pool_eval_ledger_lock_wait_microseconds_total")
    );
}

// ---- review findings: inner-rollback path of the overlay ----

#[test]
fn a_call_that_creates_an_asset_and_then_rejects_leaves_the_overlay_untouched() {
    let s = key(3);
    let app_id = 902u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let (ledger, _pool) = fixture(
        &[(s.0, funded(5_000_000)), (app_addr, funded(10_000_000))],
        &[],
    );
    put_app(
        &ledger,
        app_id,
        s.0,
        concat!(
            "#pragma version 8\n",
            "itxn_begin\n",
            "int acfg\n",
            "itxn_field TypeEnum\n",
            "int 1\n",
            "itxn_field ConfigAssetTotal\n",
            "int 0\n",
            "itxn_field Fee\n",
            "itxn_submit\n",
            "int 0\n",
        ),
    );
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    let err = eval
        .transaction_group(&[app_call(&s, app_id, vec![], 2_000)])
        .expect_err("program rejects after creating an asset");
    assert!(
        err.to_string()
            .contains("transaction rejected by ApprovalProgram"),
        "{err}"
    );
    assert!(
        eval.exec.as_ref().unwrap().overlay.is_empty(),
        "nothing of the failed group (including the inner asset) may remain"
    );
}

// ---- review findings: lock hold, measured ----

#[test]
fn ledger_lock_hold_for_a_full_scratch_pass_is_recorded() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(5_000_000_000)), (b.0, funded(1_000_000))]);
    let n = 500u64;
    for i in 0..n {
        let mut t = base_txn(a.0, TxnType::Pay);
        t.receiver = b.0;
        t.amount = 1 + i;
        eval.transaction_group(&[sign(t, &a.1)]).unwrap();
    }
    let started = Instant::now();
    let block = eval.generate_block(&[]).expect("generate_block");
    let took = started.elapsed();
    assert_eq!(block.payset.len(), n as usize);
    eprintln!(
        "lock-hold measurement: {n} payments, assembly scratch pass + block build took {took:?}"
    );
    assert!(
        algo_ledger::proposal_eval::proposal_metrics_prometheus_text()
            .contains("algod_rust_pool_eval_ledger_lock_hold_max_microseconds")
    );
}

// ---- #1791: header fields derived from the payset's apply effects ----

/// A tracking map `{0: {"n": next}}`.
fn spt(next: u64) -> Option<rmpv::Value> {
    Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(0u64),
        rmpv::Value::Map(vec![(rmpv::Value::from("n"), rmpv::Value::from(next))]),
    )]))
}

fn state_proof_txn(last_attested_round: u64) -> SignedTransaction {
    let mut t = base_txn(Address::STATE_PROOF_SENDER, TxnType::Stpf);
    t.fee = 0;
    t.state_proof_type = 0;
    t.state_proof_message = Some(algo_types::StateProofMessage {
        last_attested_round,
        ..Default::default()
    });
    t.state_proof = Some(algo_types::StateProofBody::default());
    SignedTransaction {
        txn: t,
        ..Default::default()
    }
}

/// The header of a proposal whose payset carries a state proof transaction
/// holds the `StateProofNextRound` that transaction leaves behind
/// (`lastAttestedRound + StateProofInterval`), exactly what a replica's real
/// apply computes. Before #1791 the template's previous-round value was
/// proposed, so go rejected it: `StateProofNextRound wrong: 1024 != 1280`.
#[test]
fn proposal_with_a_state_proof_txn_carries_the_advanced_next_round() {
    use algo_ledger::shadow_execute::scratch_execute_payset;

    let a = key(1);
    let b = key(2);
    let accounts = vec![(a.0, funded(50_000_000)), (b.0, funded(1_000_000))];
    let (ledger, _pool) = fixture_with_tracking(&accounts, &[], spt(1024));

    let mut prev = genesis_header();
    prev.state_proof_tracking = spt(1024);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(prev, 0, 0)
        .expect("start_evaluator");
    assert_eq!(
        algo_ledger::block_header::state_proof_next_round(&eval.hdr.state_proof_tracking),
        1024,
        "the template inherits the previous round value"
    );

    eval.transaction_group(&[pay(&a, b.0, 2_000_000, None)])
        .expect("payment");
    eval.transaction_group(&[state_proof_txn(1024)])
        .expect("state proof for the expected round");
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 2, "both groups proposed");

    let proposed = algo_ledger::block_header::state_proof_next_round(&block.state_proof_tracking);
    assert_eq!(
        proposed, 1280,
        "go: lastRoundInInterval + StateProofInterval (1024 + 256)"
    );

    // A replica's real apply of the same payset agrees with the header.
    let (replica, _p) = fixture_with_tracking(&accounts, &[], spt(1024));
    let mut l = replica.lock().unwrap();
    let scratch = scratch_execute_payset(&mut *l, &block).expect("replica apply");
    assert_eq!(scratch.final_state_proof_next, Some(proposed));
    // Everything else the apply derives matches too.
    assert_eq!(scratch.final_txn_counter, block.txn_counter);
}

/// Without a state proof in the payset the header keeps the inherited value.
#[test]
fn proposal_without_a_state_proof_txn_keeps_the_inherited_next_round() {
    let a = key(1);
    let b = key(2);
    let accounts = vec![(a.0, funded(50_000_000)), (b.0, funded(1_000_000))];
    let (ledger, _pool) = fixture_with_tracking(&accounts, &[], spt(1024));
    let mut prev = genesis_header();
    prev.state_proof_tracking = spt(1024);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(prev, 0, 0)
        .expect("start_evaluator");
    eval.transaction_group(&[pay(&a, b.0, 2_000_000, None)])
        .expect("payment");
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(
        algo_ledger::block_header::state_proof_next_round(&block.state_proof_tracking),
        1024
    );
}

/// An evaluator on a ledger whose round-0 header tracks NextRound 1024.
fn tracked_evaluator(
    accounts: &[(Address, AccountData)],
) -> (Arc<Mutex<SqliteLedger>>, SimpleBlockEvaluator) {
    let (ledger, _pool) = fixture_with_tracking(accounts, &[], spt(1024));
    let mut prev = genesis_header();
    prev.state_proof_tracking = spt(1024);
    let eval = PoolLedgerAdapter::new(ledger.clone())
        .start_simple_evaluator(prev, 0, 0)
        .expect("start_evaluator");
    (ledger, eval)
}

/// `finalize_payset` resets the remembered NextRound before its empty-payset
/// early return: a second call (nothing left to propose) must not leave the
/// first call's value for `generate_block` to read.
#[test]
fn finalize_payset_twice_does_not_keep_a_stale_next_round() {
    let a = key(1);
    let (_ledger, mut eval) = tracked_evaluator(&[(a.0, funded(50_000_000))]);
    eval.transaction_group(&[state_proof_txn(1024)])
        .expect("state proof");
    let (payset, _) = eval.finalize_payset().expect("first finalize");
    assert_eq!(payset.len(), 1);
    assert_eq!(
        eval.exec.as_ref().unwrap().final_state_proof_next,
        Some(1280)
    );

    let (payset, _) = eval.finalize_payset().expect("second finalize");
    assert!(payset.is_empty());
    assert_eq!(
        eval.exec.as_ref().unwrap().final_state_proof_next,
        None,
        "an empty second finalize must not report the first call's value"
    );
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(
        algo_ledger::block_header::state_proof_next_round(&block.state_proof_tracking),
        1024,
        "an empty payset keeps the template's value"
    );
}

/// An evaluator without exec state never proposes a state proof (fail
/// closed: nothing evaluated it), and keeps the template's value otherwise.
#[test]
fn evaluator_without_exec_state_refuses_a_state_proof_payset() {
    let a = key(1);
    let (_ledger, mut eval) = tracked_evaluator(&[(a.0, funded(50_000_000))]);
    eval.exec = None;
    let mut stpf = state_proof_txn(1024);
    eval.genesis_rule().strip(&mut stpf);
    eval.included_txns.push(stpf);
    let err = eval.generate_block(&[]).expect_err("must fail closed");
    assert!(err.to_string().contains("without evaluator state"), "{err}");

    // No state proof in the payset: the template value is kept.
    let (_ledger, mut eval) = tracked_evaluator(&[(key(1).0, funded(50_000_000))]);
    eval.exec = None;
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(
        algo_ledger::block_header::state_proof_next_round(&block.state_proof_tracking),
        1024
    );
}
