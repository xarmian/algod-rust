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
use algo_agreement::BlockValidator;
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
    fixture_at(accounts, holdings, state_proof_tracking, genesis_header())
}

/// [`fixture_with_tracking`] committed at `hdr.round` instead of round 0.
fn fixture_at(
    accounts: &[(Address, AccountData)],
    holdings: &[(Address, u64)],
    state_proof_tracking: Option<rmpv::Value>,
    hdr: BlockHeader,
) -> (Arc<Mutex<SqliteLedger>>, Arc<TransactionPool>) {
    let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().expect("ledger")));
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
            hdr.round.0,
            &block.current_protocol,
            &canonical_encode_block_header_from_block(&block),
            &canonical_encode_block(&block),
        )
        .unwrap();
        l.set_current_round(hdr.round);
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
    let scratch = scratch_execute_payset(&mut *l, &block, None).expect("replica apply");
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

// ---- #1794: the proposal header carries the ProposerPayout ----

/// go `proposerPayout` with the sink read from the ledger: the fee sink's
/// balance after the proposal's fees are paid in, minus its minimum balance.
fn expected_payout(
    ledger: &Arc<Mutex<SqliteLedger>>,
    eval: &SimpleBlockEvaluator,
    block: &algo_types::Block,
) -> u64 {
    let l = ledger.lock().unwrap();
    let sink = l.get_account(&FEE_SINK).unwrap_or_default();
    let balance = sink.micro_algos + block.fees_collected;
    let available = balance.saturating_sub(l.min_balance_with_state(&FEE_SINK, &sink));
    let p = &eval.consensus_params;
    (block.fees_collected * p.payouts_percent / 100 + block.bonus).min(available)
}

/// A proposal built while payouts are enabled carries the payout go's
/// `endOfBlock` would set (`ledger/eval/eval.go`: `eval.block.BlockHeader
/// .ProposerPayout, err = eval.proposerPayout()`): the payouts percent of the
/// fees the payset collected plus the header bonus, bounded by the fee sink's
/// available balance after the payset. Before #1794 the header kept the
/// template's 0, so Rust proposers never applied their payout.
#[test]
fn proposal_header_carries_the_proposer_payout() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    for amount in [1_000_000u64, 2_000_000, 3_000_000] {
        eval.transaction_group(&[pay(&a, b.0, amount, None)])
            .expect("payment");
    }
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.fees_collected, 3_000);
    assert!(eval.consensus_params.payouts_enabled && eval.consensus_params.payouts_percent > 0);
    let want = expected_payout(&ledger, &eval, &block);
    assert!(want > 0, "test must exercise a non-zero payout");
    assert_eq!(block.proposer_payout, want);
}

/// Generation and validation cannot drift (issue #1798): the block a proposer
/// builds (fees, bonus and capped payout from #1794) passes the validating
/// apply once agreement has set the proposer, and the same block with the
/// payout raised by one microAlgo is rejected as over the allowance.
#[test]
fn proposer_built_block_passes_the_validating_apply() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    for amount in [1_000_000u64, 2_000_000] {
        eval.transaction_group(&[pay(&a, b.0, amount, None)])
            .expect("payment");
    }
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert!(block.proposer_payout > 0, "must exercise a real payout");
    // agreement sets the proposer after generation (go `WithProposer`).
    block.proposer = a.0;
    let mut l = ledger.lock().unwrap();
    algo_ledger::apply_block_validating(&mut *l, &block)
        .expect("a proposer-built block must validate");
    drop(l);

    // ...and one microAlgo more than it chose is over the allowance.
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 1_000_000, None)])
        .expect("payment");
    let mut block = eval.generate_block(&[]).expect("generate_block");
    block.proposer = a.0;
    block.proposer_payout += 1;
    let mut l = ledger.lock().unwrap();
    let err = algo_ledger::apply_block_validating(&mut *l, &block).unwrap_err();
    assert!(err.to_string().contains("is allowed"), "{err}");
}

/// The node's real proposal-validation entry point (issue #1798): the
/// stateless validator wrapped with go's `validateForPayouts` over the ledger.
fn payout_validator(
    ledger: &Arc<Mutex<SqliteLedger>>,
) -> algo_ledger::PayoutCheckingValidator<algo_agreement::StubBlockValidator> {
    algo_ledger::PayoutCheckingValidator::new(
        algo_agreement::StubBlockValidator::accepting(),
        ledger.clone(),
    )
}

/// A proposer-built block (single fees, a pooled group fee and a transaction
/// sent by the fee sink) is accepted by the validation entry point once
/// agreement has set the proposer; an inflated payout, a forged
/// `FeesCollected` and a missing proposer are each rejected.
#[test]
fn proposal_validation_entry_point_enforces_validate_for_payouts() {
    let a = key(1);
    let b = key(2);
    let build = || {
        let (ledger, mut eval) = evaluator(&[
            (a.0, funded(50_000_000)),
            (b.0, funded(1_000_000)),
            (
                FEE_SINK,
                AccountData {
                    auth_addr: Some(a.0),
                    ..funded(50_000_000)
                },
            ),
        ]);
        eval.transaction_group(&[pay(&a, b.0, 1_000_000, None)])
            .expect("single payment");
        // Pooled group: the first member pays the whole 2_000 group fee.
        let mut members = [(1_000u64, 2_000u64), (2_000, 0)].map(|(amount, fee)| {
            let mut t = base_txn(a.0, TxnType::Pay);
            t.receiver = b.0;
            t.amount = amount;
            t.fee = fee;
            t
        });
        let gid = algo_codec::compute_group_id(&members);
        for t in members.iter_mut() {
            t.group = gid.0;
        }
        let group: Vec<_> = members.into_iter().map(|t| sign(t, &a.1)).collect();
        eval.transaction_group(&group).expect("pooled group");
        // A transaction paid FOR by the fee sink collects no fee (go
        // `takeFee`): generation and validation must agree on that.
        let mut from_sink = base_txn(FEE_SINK, TxnType::Pay);
        from_sink.receiver = b.0;
        from_sink.amount = 1_000;
        // The sink is rekeyed to `a` so the test can sign for it.
        let mut from_sink = sign(from_sink, &a.1);
        from_sink.auth_addr = Some(a.0);
        eval.transaction_group(&[from_sink])
            .expect("fee sink sender");
        let mut block = eval.generate_block(&[]).expect("generate_block");
        assert_eq!(block.fees_collected, 3_000);
        assert!(block.proposer_payout > 0, "must exercise a real payout");
        // agreement sets the proposer after generation (go `WithProposer`).
        block.proposer = a.0;
        (ledger, block)
    };

    let (ledger, block) = build();
    payout_validator(&ledger)
        .validate(&block)
        .map(|_| ())
        .expect("a proposer-built block must validate");

    let (ledger, mut inflated) = build();
    inflated.proposer_payout += 1;
    let err = payout_validator(&ledger).validate(&inflated).err().unwrap();
    assert!(err.to_string().contains("is allowed"), "{err}");

    let (ledger, mut forged) = build();
    forged.fees_collected += 1;
    let err = payout_validator(&ledger).validate(&forged).err().unwrap();
    assert!(err.to_string().contains("fees collected wrong"), "{err}");

    let (ledger, mut orphan) = build();
    orphan.proposer = Address::ZERO;
    let err = payout_validator(&ledger).validate(&orphan).err().unwrap();
    assert!(err.to_string().contains("proposer missing"), "{err}");
}

/// go fails block generation outright when `incentive + Bonus` overflows;
/// the node must not propose that round (a payout of 0 would instead be
/// rejected by its own `validateForPayouts`).
#[test]
fn generate_block_fails_when_the_bonus_overflows_the_payout() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 1_000_000, None)])
        .expect("payment");
    eval.hdr.bonus = u64::MAX;
    let err = eval.generate_block(&[]).expect_err("must not propose");
    assert!(
        err.to_string().contains("payout overflowed adding bonus"),
        "{err}"
    );
}

/// An empty block still pays the bonus (go computes it from `Bonus` alone),
/// read through the ledger fallback because nothing was evaluated.
#[test]
fn empty_proposal_pays_the_bonus_only() {
    let a = key(1);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000))]);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.fees_collected, 0);
    assert!(block.bonus > 0);
    assert_eq!(
        block.proposer_payout,
        expected_payout(&ledger, &eval, &block)
    );
    assert!(block.proposer_payout > 0);
}

/// The payout never exceeds what the fee sink can spend without closing
/// (go `sink.AvailableBalance(&proto)`): with the sink 1 microAlgo above its
/// minimum, only that plus the collected fees is available.
#[test]
fn proposer_payout_is_capped_by_the_fee_sink_available_balance() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let min = {
        let mut l = ledger.lock().unwrap();
        let min = l.min_balance_with_state(&FEE_SINK, &AccountData::default());
        l.set_account(&FEE_SINK, funded(min + 1));
        min
    };
    eval.transaction_group(&[pay(&a, b.0, 1_000_000, None)])
        .expect("payment");
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.fees_collected, 1_000);
    assert!(min + 1 < 10_000_000, "min balance read from the ledger");
    assert_eq!(block.proposer_payout, 1_001, "sink surplus 1 + fees 1000");
    assert_eq!(
        block.proposer_payout,
        expected_payout(&ledger, &eval, &block)
    );
    assert!(
        block.fees_collected * eval.consensus_params.payouts_percent / 100 + block.bonus
            > block.proposer_payout,
        "the cap, not the formula, bounds the payout"
    );
}

/// A sink below its minimum balance has nothing available: payout 0.
#[test]
fn proposer_payout_is_zero_when_the_sink_is_below_its_minimum_balance() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    ledger.lock().unwrap().set_account(&FEE_SINK, funded(1));
    // Fees (1000) do not lift a 1 microAlgo sink above its minimum either.
    eval.transaction_group(&[pay(&a, b.0, 1_000_000, None)])
        .expect("payment");
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.proposer_payout, 0);
    // Same through the empty-payset ledger fallback.
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000))]);
    ledger.lock().unwrap().set_account(&FEE_SINK, funded(1));
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.proposer_payout, 0);
}

/// A payset trimmed to the byte limit before the header is built pays out on
/// the fees of the groups that were kept, with the sink balance after them.
#[test]
fn trimmed_payset_pays_out_on_the_kept_fees_only() {
    let a = key(1);
    let b = key(2);
    let d = key(7);
    let (ledger, mut eval) = evaluator(&[
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (d.0, funded(5_000_000)),
    ]);
    let plain = pay(&a, b.0, 2_000_000, None);
    let closing = pay(&d, a.0, 0, Some(a.0));
    let mut sizes = 0usize;
    for stx in [&plain, &closing] {
        let mut stib = stx.clone();
        eval.genesis_rule().strip(&mut stib);
        sizes += canonical_encode_signed_txn_in_block(&stib).len();
    }
    eval.max_txn_bytes = sizes;
    eval.transaction_group(&[plain]).unwrap();
    eval.transaction_group(&[closing]).unwrap();
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1, "the closing group was trimmed");
    assert_eq!(block.fees_collected, 1_000);
    assert_eq!(
        block.proposer_payout,
        expected_payout(&ledger, &eval, &block)
    );
    assert!(block.proposer_payout > 0);
}

/// The per-group overlay evaluation never asks for the sink balance.
#[test]
fn per_group_probe_does_not_read_the_fee_sink() {
    let p = algo_ledger::apply::ExecProbe::default();
    assert!(!p.want_fee_sink_available && p.final_fee_sink_available.is_none());
}

/// Hand-computed from go's `proposerPayout` (independent of any helper).
/// V41: Payouts.Percent = 50, genesis fee sink = 10_000_000, min balance =
/// 100_000. Three payments at the 1_000 min fee collect 3_000.
///   * bonus 1_234:  floor(3_000 * 50 / 100) + 1_234 = 1_500 + 1_234 = 2_734
///     (sink available 10_000_000 + 3_000 - 100_000 = 9_903_000, not binding)
///   * bonus 20_000_000: 1_500 + 20_000_000 = 20_001_500 > 9_903_000, so the
///     sink cap wins: 9_903_000.
#[test]
fn proposer_payout_golden_values() {
    for (bonus, want) in [(1_234u64, 2_734u64), (20_000_000, 9_903_000)] {
        let a = key(1);
        let b = key(2);
        let (_l, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
        eval.hdr.bonus = bonus;
        for amount in [1_000_000u64, 2_000_000, 3_000_000] {
            eval.transaction_group(&[pay(&a, b.0, amount, None)])
                .unwrap();
        }
        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(block.fees_collected, 3_000);
        assert_eq!(block.proposer_payout, want, "bonus {bonus}");
    }
}

/// Fallback path (no exec state): the sink's deficit must not turn positive
/// when fees are added. Min balance 100_000, sink balance 1, fees 5_000:
/// (1 + 5_000) - 100_000 saturates to 0, so the payout is 0.
#[test]
fn fallback_sink_deficit_is_not_cured_by_fees() {
    let a = key(1);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000))]);
    ledger.lock().unwrap().set_account(&FEE_SINK, funded(1));
    eval.exec = None;
    eval.fees_collected = 5_000;
    let block = eval.generate_block(&[]).unwrap();
    assert_eq!(block.proposer_payout, 0);
}

/// Fallback path: a payset transaction that touches the fee sink (here the
/// sink as sender) has effects beyond `fees_collected` that the fallback
/// cannot see, so it proposes payout 0 (go accepts any lower payout).
#[test]
fn fallback_payout_is_zero_when_the_payset_touches_the_fee_sink() {
    let a = key(1);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000))]);
    eval.exec = None;
    let mut t = base_txn(FEE_SINK, TxnType::Pay);
    t.receiver = a.0;
    t.amount = 1;
    let mut stx = SignedTransaction {
        txn: t,
        ..Default::default()
    };
    eval.genesis_rule().strip(&mut stx);
    eval.included_txns.push(stx);
    let block = eval.generate_block(&[]).unwrap();
    assert_eq!(block.proposer_payout, 0);
    // Control: the same evaluator without that transaction pays the bonus.
    let (_l, mut eval) = evaluator(&[(a.0, funded(50_000_000))]);
    eval.exec = None;
    assert!(eval.generate_block(&[]).unwrap().proposer_payout > 0);
}

// ---- #1795: knock-offline lists come from the post-payset state ----

/// An evaluator whose ledger tip is round 99, so the proposal is round 100.
fn evaluator_at_99(
    accounts: &[(Address, AccountData)],
) -> (Arc<Mutex<SqliteLedger>>, SimpleBlockEvaluator) {
    let mut prev = genesis_header();
    prev.round = Round(99);
    let (ledger, _pool) = fixture_at(accounts, &[], None, prev.clone());
    let eval = PoolLedgerAdapter::new(ledger.clone())
        .start_simple_evaluator(prev, 0, 0)
        .expect("start_evaluator");
    (ledger, eval)
}

fn online_with_key(micro: u64, last_valid: u64) -> AccountData {
    AccountData {
        micro_algos: micro,
        status: algo_types::AccountStatus::Online,
        vote_id: Some([7u8; 32]),
        vote_last_valid: last_valid,
        ..Default::default()
    }
}

/// go computes `ExpiredParticipationAccounts` in `endOfBlock`, over the state
/// the payset left behind (`generateKnockOfflineAccountsList`). An expired
/// account the payset closes out is therefore not listed (go skips zero
/// balances), while an untouched expired account still is; and the validating
/// apply, which judges the lists against the post-payset state, accepts the
/// block. Before #1795 the list was read from the pre-block ledger, so the
/// closed account was listed and the block failed `had no vote key`.
#[test]
fn expired_list_is_computed_from_the_post_payset_state() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (ledger, mut eval) = evaluator_at_99(&[
        (a.0, online_with_key(5_000_000, 50)),
        (b.0, funded(1_000_000)),
        (c.0, online_with_key(5_000_000, 60)),
    ]);
    eval.transaction_group(&[pay(&a, b.0, 0, Some(b.0))])
        .expect("close the expired account out");
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[c.0][..]),
        "only the untouched expired account may be listed"
    );
    block.proposer = b.0;
    let mut l = ledger.lock().unwrap();
    algo_ledger::apply_block_validating(&mut *l, &block)
        .expect("a proposer-built block must pass the validating apply");
}

/// Same for `AbsentParticipationAccounts`: an absent account closed by the
/// payset has a zero balance in go's post-payset state and is skipped.
#[test]
fn absent_list_is_computed_from_the_post_payset_state() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let absent = |micro| AccountData {
        micro_algos: micro,
        status: algo_types::AccountStatus::Online,
        incentive_eligible: true,
        last_heartbeat: 1,
        ..Default::default()
    };
    let (ledger, mut eval) = evaluator_at_99(&[
        (a.0, absent(5_000_000)),
        (b.0, funded(1_000_000)),
        (c.0, absent(5_000_000)),
    ]);
    eval.transaction_group(&[pay(&a, b.0, 0, Some(b.0))])
        .expect("close the absent account out");
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.absent_participation_accounts.as_deref(),
        Some(&[c.0][..]),
        "only the untouched absent account may be listed"
    );
    block.proposer = b.0;
    let mut l = ledger.lock().unwrap();
    algo_ledger::apply_block_validating(&mut *l, &block)
        .expect("a proposer-built block must pass the validating apply");
}

/// go skips the proposer's own participating addresses for BOTH lists
/// (`partAddrs.Contains` precedes the expiry check): a node never proposes
/// expiring itself. The payset here is non-empty, so the final scratch apply
/// (not the ledger fallback) must honor the exclusion.
#[test]
fn own_participating_address_is_never_listed_expired() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (b.0, online_with_key(5_000_000, 50)),
        (c.0, online_with_key(5_000_000, 60)),
    ]);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    let block = eval.generate_block(&[b.0]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[c.0][..])
    );
}

/// The absent list also skips the proposer's own addresses (go `partAddrs`).
#[test]
fn own_participating_address_is_never_listed_absent() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let absent = |micro| AccountData {
        micro_algos: micro,
        status: algo_types::AccountStatus::Online,
        incentive_eligible: true,
        last_heartbeat: 1,
        ..Default::default()
    };
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (b.0, absent(5_000_000)),
        (c.0, absent(5_000_000)),
    ]);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    let block = eval.generate_block(&[b.0]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.absent_participation_accounts.as_deref(),
        Some(&[c.0][..])
    );
}

/// With nothing in the payset the post-payset state IS the ledger tip, so
/// the lists come straight from it.
#[test]
fn empty_payset_lists_come_from_the_ledger_tip() {
    let c = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[(c.0, online_with_key(5_000_000, 60))]);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert!(block.payset.is_empty());
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[c.0][..])
    );
}

/// A non-empty payset that no scratch apply evaluated (legacy path without
/// exec state) must not borrow the pre-payset tip's lists: they are empty,
/// which is always valid.
#[test]
fn non_empty_payset_without_a_scratch_result_gets_empty_lists() {
    let a = key(1);
    let c = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (c.0, online_with_key(5_000_000, 60)),
    ]);
    eval.exec = None;
    let mut stx = pay(&a, a.0, 1, None);
    eval.genesis_rule().strip(&mut stx);
    eval.included_txns.push(stx);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert!(block.expired_participation_accounts.is_none());
    assert!(block.absent_participation_accounts.is_none());
}

/// The same when the scratch apply cannot run for a non-empty payset: the
/// proposal is retried/bisected down to an empty payset (tip lists) or keeps
/// the evaluated prefix (its own lists), never a stale mix.
#[test]
fn lists_always_describe_the_payset_that_was_kept() {
    let a = key(1);
    let c = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (c.0, online_with_key(5_000_000, 60)),
    ]);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[c.0][..])
    );
}

/// go judges absence against the balance-round lookback stake, so a payset
/// that moves online stake in this very block does not change who is listed
/// (go TestWhaleJoin). The lookback total (100M, seeded at the balance round)
/// keeps a 5M account at lag 400 > 99 quiet rounds, although the online sum
/// after the payset (about 6M) would make it absent; the replica's validating
/// apply, which uses the same lookback, accepts the block.
#[test]
fn absent_list_uses_the_lookback_stake_not_the_post_payset_sum() {
    let x = key(1);
    let z = key(2);
    let b = key(3);
    let (ledger, mut eval) = evaluator_at_99(&[
        (
            x.0,
            AccountData {
                micro_algos: 5_000_000,
                status: algo_types::AccountStatus::Online,
                incentive_eligible: true,
                last_heartbeat: 1,
                ..Default::default()
            },
        ),
        (
            z.0,
            AccountData {
                micro_algos: 5_000_000,
                status: algo_types::AccountStatus::Online,
                ..Default::default()
            },
        ),
        (b.0, funded(1_000_000)),
    ]);
    ledger
        .lock()
        .unwrap()
        .put_online_supply_at_round(0, 100_000_000)
        .unwrap();
    // Z moves most of its online stake to an offline account.
    eval.transaction_group(&[pay(&z, b.0, 4_000_000, None)])
        .expect("payment");
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert!(
        block.absent_participation_accounts.is_none(),
        "lookback lag 400 > 99: not absent, whatever the post-payset online sum says"
    );
    block.proposer = b.0;
    let mut l = ledger.lock().unwrap();
    algo_ledger::apply_block_validating(&mut *l, &block)
        .expect("a proposer-built block must pass the validating apply");
}
