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

/// Issue #1919 (the real cause of the ~47k authorizer rejections in the
/// mainnet soaks): a hot bot sends `appl` calls from S with `rekey_to =
/// <app account>`; the app, now S's authorizer, rekeys S back to itself with an
/// INNER transaction during the same call. go's pending state therefore shows S
/// as its own authorizer afterwards and S's next call (signed by S, no
/// auth-addr) is valid. The pool tracked only the top-level `rekey_to`, so
/// after the first admitted call it believed S was still rekeyed to the app and
/// rejected every following call ("should have been authorized by <app> but
/// was actually authorized by <S>").
#[test]
fn inner_rekey_back_to_self_is_seen_by_the_next_group() {
    let s = key(5);
    let app_id = 910u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let (ledger, pool) = fixture(
        &[(s.0, funded(5_000_000)), (app_addr, holder(1_000_000))],
        &[],
    );
    put_app(
        &ledger,
        app_id,
        s.0,
        concat!(
            "#pragma version 8\n",
            // An inner payment FROM the caller (authorized by the app, S's new
            // auth-addr) that rekeys the caller back to itself.
            "itxn_begin\n",
            "int pay\n",
            "itxn_field TypeEnum\n",
            "txn Sender\n",
            "itxn_field Sender\n",
            "txn Sender\n",
            "itxn_field Receiver\n",
            "txn Sender\n",
            "itxn_field RekeyTo\n",
            "int 0\n",
            "itxn_field Fee\n",
            "itxn_submit\n",
            "int 1\n",
        ),
    );
    let call = |fee: u64, rekey: Option<Address>| {
        let mut t = base_txn(s.0, TxnType::Appl);
        t.application_id = app_id;
        t.fee = fee;
        t.rekey_to = rekey;
        sign(t, &s.1)
    };
    // Call 1: S rekeys itself to the app; the app rekeys it back inside the call.
    pool.remember_one(call(3_000, Some(app_addr)))
        .expect("first call (rekey to the app, app rekeys back)");
    // Call 2: signed by S alone - valid, S is its own authorizer again.
    pool.remember_one(call(3_001, Some(app_addr)))
        .expect("second call must be admitted: the inner rekey-back is part of the pending state");
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
    let txids = Some(carried_txids(&eval, start, 1));
    eval.exec.as_mut().unwrap().groups.push(ExecGroup {
        start,
        len: 1,
        fees: 1_000,
        txids,
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

/// A payload that passes go's `checkStateProof` (issue #2196: admission refuses
/// a malformed one): a 64-byte commitment and Sumhash-typed proofs.
fn well_formed_state_proof_body() -> algo_types::StateProofBody {
    let sumhash = algo_types::MerkleProof {
        path: None,
        hash_factory: Some(algo_types::HashFactory { hash_type: 1 }),
        tree_depth: 0,
    };
    algo_types::StateProofBody {
        sig_commit: serde_bytes::ByteBuf::from(vec![7u8; 64]),
        sig_proofs: Some(sumhash.clone()),
        part_proofs: Some(sumhash),
        ..Default::default()
    }
}

fn state_proof_txn(last_attested_round: u64) -> SignedTransaction {
    let mut t = base_txn(Address::STATE_PROOF_SENDER, TxnType::Stpf);
    t.fee = 0;
    t.state_proof_type = 0;
    t.state_proof_message = Some(algo_types::StateProofMessage {
        last_attested_round,
        ..Default::default()
    });
    t.state_proof = Some(well_formed_state_proof_body());
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
    let (payset, _) = eval
        .finalize_payset(&Default::default())
        .expect("first finalize");
    assert_eq!(payset.len(), 1);
    assert_eq!(
        eval.exec.as_ref().unwrap().final_state_proof_next,
        Some(1280)
    );

    let (payset, _) = eval
        .finalize_payset(&Default::default())
        .expect("second finalize");
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
        // go's admission refuses a fee-sink sender (WellFormed with the special
        // addresses, issue #2198), but its block evaluator has no WellFormed:
        // the transaction enters the proposal through the apply path only.
        eval.admit_group_apply_path_only_for_test(&[from_sink]);
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

/// `takeFee` accounting for a fee-sink sender on the CURRENT protocol (v41,
/// payouts enabled; the v39 variant is `sender_is_fee_sink_no_fees_collected_increment`).
/// Admission refuses the sender under go's special-address rules (issue #2198),
/// so it enters through the apply path only: the generated block must collect
/// no fee for it, and the validation entry point must agree.
#[test]
fn a_fee_sink_sender_collects_no_fee_in_a_generated_block() {
    let a = key(1);
    let b = key(2);
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
    let mut from_sink = base_txn(FEE_SINK, TxnType::Pay);
    from_sink.receiver = b.0;
    from_sink.amount = 1_000;
    from_sink.fee = 1_000;
    let mut from_sink = sign(from_sink, &a.1);
    from_sink.auth_addr = Some(a.0);

    let err = eval
        .transaction_group(std::slice::from_ref(&from_sink))
        .expect_err("admission refuses a fee-sink sender");
    assert!(
        err.to_string()
            .contains("cannot spend from fee sink address"),
        "{err}"
    );

    eval.admit_group_apply_path_only_for_test(&[from_sink]);
    assert_eq!(
        eval.fees_collected, 0,
        "the sink's own fee is not collected"
    );
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1, "the real apply accepts it");
    assert_eq!(block.fees_collected, 0, "the block collects no fee for it");
    block.proposer = a.0;
    payout_validator(&ledger)
        .validate(&block)
        .map(|_| ())
        .expect("validation agrees on the fee");
}

/// Issue #1908: go's `FeesCollected` also counts every paid INNER transaction
/// fee (`takeFee` in `ledger/eval/applications.go`). The proposer must emit
/// top-level + inner fees (and derive the payout from that), the overlay
/// proposal validator and the validating apply must accept it, and the
/// top-level-only sum must be rejected.
#[test]
fn proposal_fees_collected_includes_inner_transaction_fees() {
    let s = key(3);
    let d = key(4);
    let app_id = 902u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let build = || {
        let (ledger, mut eval) = evaluator(&[
            (s.0, funded(50_000_000)),
            (d.0, funded(1_000_000)),
            (app_addr, funded(10_000_000)),
        ]);
        put_app(
            &ledger,
            app_id,
            s.0,
            concat!(
                "#pragma version 8
",
                "itxn_begin
",
                "int pay
",
                "itxn_field TypeEnum
",
                "txn Accounts 1
",
                "itxn_field Receiver
",
                "int 1
",
                "itxn_field Amount
",
                "int 1000
",
                "itxn_field Fee
",
                "itxn_submit
",
                "int 1
",
            ),
        );
        eval.transaction_group(&[app_call(&s, app_id, vec![d.0], 1_000)])
            .expect("app call with a paid inner fee");
        let mut block = eval.generate_block(&[]).expect("generate_block");
        // agreement sets the proposer after generation (go `WithProposer`).
        block.proposer = s.0;
        (ledger, eval, block)
    };

    let (ledger, eval, block) = build();
    assert_eq!(
        block.fees_collected, 2_000,
        "top-level 1_000 + inner 1_000, not the top-level sum"
    );
    assert_eq!(
        block.proposer_payout,
        expected_payout(&ledger, &eval, &block),
        "the payout is derived from the full FeesCollected"
    );
    assert!(block.proposer_payout > 0);
    payout_validator(&ledger)
        .validate(&block)
        .map(|_| ())
        .expect("the overlay proposal validation must accept the proposer's own block");
    {
        let mut l = ledger.lock().unwrap();
        algo_ledger::apply_block_validating(&mut *l, &block)
            .expect("the validating apply must accept it");
    }

    let (ledger, _eval, mut top_level_only) = build();
    top_level_only.fees_collected = 1_000;
    let err = payout_validator(&ledger)
        .validate(&top_level_only)
        .err()
        .expect("the top-level-only sum is wrong");
    assert!(
        err.to_string()
            .contains("fees collected wrong: 1000 != 2000"),
        "{err}"
    );
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
        vote_id: Some([7u8; 32]),
        vote_last_valid: 1_000_000,
        ..Default::default()
    };
    let (ledger, mut eval) = evaluator_at_99(&[
        (a.0, absent(5_000_000)),
        (b.0, funded(1_000_000)),
        (c.0, absent(5_000_000)),
    ]);
    seed_online_history(
        &ledger,
        &[(a.0, absent(5_000_000)), (c.0, absent(5_000_000))],
    );
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
        vote_id: Some([7u8; 32]),
        vote_last_valid: 1_000_000,
        ..Default::default()
    };
    let (ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (b.0, absent(5_000_000)),
        (c.0, absent(5_000_000)),
    ]);
    seed_online_history(
        &ledger,
        &[(b.0, absent(5_000_000)), (c.0, absent(5_000_000))],
    );
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
/// exec state): the ledger-tip lists are filtered to accounts the payset does
/// not touch and that are not the proposer's own, which the payset cannot have
/// changed, so the lists are valid. `d` (paid by the payset) and `own` are
/// dropped; `c` is kept.
#[test]
fn non_empty_payset_without_a_scratch_result_lists_only_untouched_accounts() {
    let a = key(1);
    let c = key(3);
    let d = key(4);
    let own = key(5);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (c.0, online_with_key(5_000_000, 60)),
        (d.0, online_with_key(5_000_000, 60)),
        (own.0, online_with_key(5_000_000, 60)),
    ]);
    eval.exec = None;
    let mut stx = pay(&a, d.0, 1, None);
    eval.genesis_rule().strip(&mut stx);
    eval.included_txns.push(stx);
    let block = eval.generate_block(&[own.0]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[c.0][..]),
        "tip lists minus the payset's touched accounts and the proposer's own"
    );
    assert!(block.absent_participation_accounts.is_none());
}

/// An application call can modify any account through inner transactions, so
/// the touched set is unbounded and the fallback proposes empty lists.
#[test]
fn unevaluated_payset_with_an_app_call_gets_empty_lists() {
    let a = key(1);
    let c = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (c.0, online_with_key(5_000_000, 60)),
    ]);
    eval.exec = None;
    let mut stx = app_call(&a, 1, vec![], 1_000);
    eval.genesis_rule().strip(&mut stx);
    eval.included_txns.push(stx);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1);
    assert!(block.expired_participation_accounts.is_none());
    assert!(block.absent_participation_accounts.is_none());
}

/// Seed the history rows go would hold for accounts that were online at the
/// balance round (round 0 for the round-100 proposals of these tests).
fn seed_online_history(ledger: &Arc<Mutex<SqliteLedger>>, accounts: &[(Address, AccountData)]) {
    let l = ledger.lock().unwrap();
    let mut total = 0u64;
    for (addr, acct) in accounts {
        l.put_online_account_at_round(addr, 0, acct).unwrap();
        total += acct.micro_algos;
    }
    // The lookback total, from the same time basis as the history rows, and
    // the balance-round header the stake lookups read the rewards level from.
    l.put_online_supply_at_round(0, total).unwrap();
    l.put_block_header_fixture(0, 0).unwrap();
}

fn evaluator_at_99_limited(
    accounts: &[(Address, AccountData)],
    max_txn_bytes: usize,
) -> (Arc<Mutex<SqliteLedger>>, SimpleBlockEvaluator) {
    let mut prev = genesis_header();
    prev.round = Round(99);
    let (ledger, _pool) = fixture_at(accounts, &[], None, prev.clone());
    let eval = PoolLedgerAdapter::new(ledger.clone())
        .start_simple_evaluator(prev, 0, max_txn_bytes)
        .expect("start_evaluator");
    (ledger, eval)
}

/// Two groups: an unrelated payment and a close-out of the expired account
/// `x`. The lists must describe the payset that is KEPT. Here a failure no
/// transaction owns forces bisection (probes run without lists) down to the
/// first group; `x` is then still online and expired, so it is listed. A list
/// taken from the two-group state (where `x` is closed) would omit it.
#[test]
fn lists_describe_the_prefix_kept_after_bisection() {
    let a = key(1);
    let b = key(2);
    let x = key(3);
    let (_ledger, mut eval) = evaluator_at_99(&[
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (x.0, online_with_key(5_000_000, 60)),
    ]);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    eval.transaction_group(&[pay(&x, b.0, 0, Some(b.0))])
        .expect("close-out");
    test_hooks::inject_failure_over_payset_len(Some(1));
    let block = eval.generate_block(&[]).expect("generate_block");
    test_hooks::inject_failure_over_payset_len(None);
    assert_eq!(block.payset.len(), 1, "only the first group is kept");
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[x.0][..]),
        "x is not closed by the kept payset"
    );
}

/// The oversize path: the first pass evaluates both groups (its lists omit
/// the closed `x`), then the byte limit truncates to the first group and a
/// rerun produces the lists the proposal carries. The stale first-pass lists
/// must not survive into the kept payset.
#[test]
fn stale_first_pass_lists_do_not_survive_a_truncating_rerun() {
    let a = key(1);
    let b = key(2);
    let x = key(3);
    let accounts = [
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (x.0, online_with_key(5_000_000, 60)),
    ];
    // Measure the two groups as they will be encoded with their ApplyData.
    let (_l, mut probe) = evaluator_at_99(&accounts);
    probe
        .transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    probe
        .transaction_group(&[pay(&x, b.0, 0, Some(b.0))])
        .expect("close-out");
    let full = probe.generate_block(&[]).expect("generate_block");
    assert_eq!(full.payset.len(), 2);
    assert_eq!(
        full.expired_participation_accounts, None,
        "both groups kept: x is closed, nothing to expire"
    );
    let sizes: Vec<usize> = full
        .payset
        .iter()
        .map(SimpleBlockEvaluator::encoded_len)
        .collect();

    let (_ledger, mut eval) = evaluator_at_99_limited(&accounts, sizes[0] + sizes[1] - 1);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    eval.transaction_group(&[pay(&x, b.0, 0, Some(b.0))])
        .expect("close-out admitted on its pre-ApplyData size");
    test_hooks::reset_knock_offline_calls();
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 1, "the close-out no longer fits");
    assert_eq!(
        test_hooks::knock_offline_calls(),
        1,
        "the discarded oversize pass must not pay for the scan"
    );
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[x.0][..]),
        "lists come from the rerun over the kept payset"
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
    let x_acct = AccountData {
        micro_algos: 5_000_000,
        status: algo_types::AccountStatus::Online,
        incentive_eligible: true,
        last_heartbeat: 1,
        vote_id: Some([7u8; 32]),
        vote_last_valid: 1_000_000,
        ..Default::default()
    };
    let z_acct = AccountData {
        micro_algos: 5_000_000,
        status: algo_types::AccountStatus::Online,
        vote_id: Some([8u8; 32]),
        vote_last_valid: 1_000_000,
        ..Default::default()
    };
    let (ledger, mut eval) = evaluator_at_99(&[
        (x.0, x_acct.clone()),
        (z.0, z_acct.clone()),
        (b.0, funded(1_000_000)),
    ]);
    seed_online_history(&ledger, &[(x.0, x_acct), (z.0, z_acct)]);
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

/// go reads the account's stake at the balance round and gets an empty
/// `OnlineAccountData` (stake 0, so never absent) for an account with no
/// online history at or before it. An account that went online AFTER the
/// balance round and has been quiet since must not be listed absent: go's
/// validator would reject the block ("is not absent").
#[test]
fn account_that_went_online_after_the_balance_round_is_not_listed_absent() {
    let a = key(1);
    let x = key(2);
    let x_acct = AccountData {
        micro_algos: 5_000_000,
        status: algo_types::AccountStatus::Online,
        incentive_eligible: true,
        last_heartbeat: 1,
        vote_id: Some([7u8; 32]),
        vote_last_valid: 1_000_000,
        ..Default::default()
    };
    let (ledger, mut eval) = evaluator_at_99(&[(a.0, funded(50_000_000)), (x.0, x_acct.clone())]);
    // x's only history row is at round 50, after round 100's balance round 0.
    ledger
        .lock()
        .unwrap()
        .put_online_account_at_round(&x.0, 50, &x_acct)
        .unwrap();
    ledger
        .lock()
        .unwrap()
        .put_online_supply_at_round(0, 5_000_000)
        .unwrap();
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    let mut block = eval.generate_block(&[]).expect("generate_block");
    assert!(
        block.absent_participation_accounts.is_none(),
        "no online row at the balance round: stake 0, not absent"
    );

    // The validating apply agrees with go: listing x anyway is rejected.
    block.proposer = a.0;
    block.absent_participation_accounts = Some(vec![x.0]);
    let mut l = ledger.lock().unwrap();
    let err = algo_ledger::apply_block_validating(&mut *l, &block).unwrap_err();
    assert!(err.to_string().contains("is not absent"), "{err}");
}

/// The tip-vs-parent check also guards the empty payset: when the ledger tip
/// is not the block's parent (the chain moved under the evaluator) the tip's
/// state says nothing about this block, so the lists are empty.
#[test]
fn empty_payset_with_a_stale_tip_gets_empty_lists() {
    let c = key(3);
    let (ledger, mut eval) = evaluator_at_99(&[(c.0, online_with_key(5_000_000, 60))]);
    ledger.lock().unwrap().set_current_round(Round(120));
    let block = eval.generate_block(&[]).expect("generate_block");
    assert!(block.payset.is_empty());
    assert!(block.expired_participation_accounts.is_none());
    assert!(block.absent_participation_accounts.is_none());
}

/// The lists are computed once, after the exact size check, from the kept
/// pass's modified accounts (issue #1885): with the limit exactly the encoded
/// size the proposal is complete and the scan ran exactly once, with no extra
/// payset execution to produce it.
#[test]
fn lists_are_computed_once_after_the_exact_size_check_at_the_limit() {
    let a = key(1);
    let b = key(2);
    let x = key(3);
    let accounts = [
        (a.0, funded(50_000_000)),
        (b.0, funded(1_000_000)),
        (x.0, online_with_key(5_000_000, 60)),
        (key(4).0, online_with_key(5_000_000, 60)),
    ];
    let (_l, mut probe) = evaluator_at_99(&accounts);
    probe
        .transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    probe
        .transaction_group(&[pay(&x, b.0, 0, Some(b.0))])
        .expect("close-out");
    let full = probe.generate_block(&[]).expect("generate_block");
    assert_eq!(full.payset.len(), 2);
    let exact: usize = full
        .payset
        .iter()
        .map(SimpleBlockEvaluator::encoded_len)
        .sum();

    let (_ledger, mut eval) = evaluator_at_99_limited(&accounts, exact);
    eval.transaction_group(&[pay(&a, a.0, 1, None)])
        .expect("payment");
    eval.transaction_group(&[pay(&x, b.0, 0, Some(b.0))])
        .expect("close-out");
    test_hooks::reset_knock_offline_calls();
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 2, "the exact size fits the limit");
    assert_eq!(
        block.expired_participation_accounts.as_deref(),
        Some(&[key(4).0][..]),
        "x is closed by the payset; the other expired account is listed"
    );
    assert_eq!(
        test_hooks::knock_offline_calls(),
        1,
        "one scan, after the exact size check"
    );
    assert_eq!(
        eval.exec.as_ref().unwrap().last_passes,
        1,
        "no second payset execution to produce the lists"
    );
}

// ---- #1781: the ledger mutex is not held across evaluation ----

/// A background thread that repeatedly takes the ledger mutex the way the
/// commit path / REST handlers do and records the longest wait it saw.
struct LockProber {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: std::thread::JoinHandle<Duration>,
}

impl LockProber {
    fn start(ledger: &Arc<Mutex<SqliteLedger>>) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (l, s) = (ledger.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            let mut worst = Duration::ZERO;
            while !s.load(std::sync::atomic::Ordering::Relaxed) {
                let t = Instant::now();
                let g = l.lock().unwrap();
                worst = worst.max(t.elapsed());
                drop(g);
                std::thread::sleep(Duration::from_micros(200));
            }
            worst
        });
        Self { stop, handle }
    }

    fn finish(self) -> Duration {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle.join().unwrap()
    }
}

/// A ledger with four rich senders, a loop-heavy app (id 1000) and a primed
/// evaluator.
fn rich_fixture() -> (Arc<Mutex<SqliteLedger>>, SimpleBlockEvaluator, Vec<Key>) {
    let senders: Vec<Key> = (1..=4).map(key).collect();
    let b = key(9);
    let mut accounts: Vec<(Address, AccountData)> = senders
        .iter()
        .map(|k| (k.0, funded(5_000_000_000_000)))
        .collect();
    accounts.push((b.0, funded(1_000_000)));
    let (ledger, _pool) = fixture(&accounts, &[]);
    put_app(
        &ledger,
        1_000,
        senders[0].0,
        concat!(
            "#pragma version 8
",
            "int 0
",
            "loop:
",
            "int 1
",
            "+
",
            "dup
",
            "int 80
",
            "<
",
            "bnz loop
",
            "pop
",
            "int 1
",
        ),
    );
    let eval = PoolLedgerAdapter::new(ledger.clone())
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    (ledger, eval, senders)
}

/// Admit `payments` payments and `calls` loop-heavy app calls.
fn admit_rich(eval: &mut SimpleBlockEvaluator, senders: &[Key], payments: u64, calls: u64) {
    let b = key(9);
    for i in 0..payments {
        let s = &senders[(i % 4) as usize];
        let mut t = base_txn(s.0, TxnType::Pay);
        t.receiver = b.0;
        t.amount = 1 + i;
        eval.transaction_group(&[sign(t, &s.1)]).unwrap();
    }
    for i in 0..calls {
        let s = &senders[(i % 4) as usize];
        let mut t = base_txn(s.0, TxnType::Appl);
        t.application_id = 1_000;
        t.note = serde_bytes::ByteBuf::from(i.to_be_bytes().to_vec());
        eval.transaction_group(&[sign(t, &s.1)]).unwrap();
    }
}

#[test]
fn assembly_does_not_block_other_ledger_users_across_evaluation() {
    let (ledger, mut eval, senders) = rich_fixture();
    let prober = LockProber::start(&ledger);
    let started = Instant::now();
    admit_rich(&mut eval, &senders, 500, 60);
    let admitted = started.elapsed();
    let started = Instant::now();
    let block = eval.generate_block(&[]).expect("generate_block");
    let assembled = started.elapsed();
    let worst = prober.finish();
    eprintln!(
        "rich workload: {} txns; admission {admitted:?}, generate_block {assembled:?};          worst wait of a concurrent ledger user {worst:?}
{}",
        block.payset.len(),
        algo_ledger::proposal_eval::proposal_metrics_prometheus_text()
    );
    assert_eq!(block.payset.len(), 560);
    // Debug build: the old whole-pass hold of the mutex was ~75 ms here; one
    // read is microseconds.
    assert!(
        worst < Duration::from_millis(40),
        "a concurrent ledger user waited {worst:?} behind pool evaluation"
    );
    let exec = eval.exec.as_ref().unwrap();
    assert!(
        exec.lock_hold_max.get() < Duration::from_millis(20),
        "longest single hold of the ledger mutex: {:?}",
        exec.lock_hold_max.get()
    );
    assert!(
        exec.lock_acquisitions.get() > 560,
        "reads take the mutex one by one"
    );
}

/// Issue #1781: a concurrent block commit while the proposal is being
/// evaluated drops the proposal instead of building it on the old parent.
#[test]
fn proposal_is_dropped_when_the_ledger_advances_during_assembly() {
    let (ledger, mut eval, senders) = rich_fixture();
    admit_rich(&mut eval, &senders, 400, 40);
    let stale_before = algo_ledger::proposal_eval::stale_base_total();
    // The assembly pass starts while a block commit is in progress: it blocks
    // on its first read, the commit completes (the round moves), and the pass
    // then reads the new state. The mid-evaluation case is covered by
    // `payset_evaluated_while_the_ledger_advances_is_stale_and_returns_nothing`.
    let guard = ledger.lock().unwrap();
    let assembler = std::thread::spawn(move || {
        let res = eval.generate_block(&[]);
        (res, eval)
    });
    std::thread::sleep(Duration::from_millis(100));
    // What a block commit does to the base: the round moves.
    let mut guard = guard;
    guard.set_current_round(Round(1));
    drop(guard);
    let (res, _eval) = assembler.join().unwrap();
    let err = res.expect_err("a proposal evaluated across a commit must be dropped");
    assert!(err.to_string().contains("ledger advanced"), "{err}");
    assert!(algo_ledger::proposal_eval::stale_base_total() > stale_before);
}

/// Issue #1781 / #1895: the overlay assembly pass and a direct locked
/// `scratch_execute_payset` SAVEPOINT pass over the proposed block produce
/// identical ApplyData / counter / sink balance over random payment / close /
/// app call mixes, including a smuggled un-applyable group and byte-limit
/// trimming.
#[test]
fn overlay_assembly_equals_the_locked_scratch_pass_over_random_mixes() {
    fn mix(seed: u64, limit_num: usize) -> (algo_types::Block, usize, usize) {
        let senders: Vec<Key> = (1..=4).map(key).collect();
        let closers: Vec<Key> = (20..30).map(key).collect();
        let c = key(6);
        let b = key(9);
        let mut accounts: Vec<(Address, AccountData)> = senders
            .iter()
            .map(|k| (k.0, funded(5_000_000_000_000)))
            .collect();
        accounts.push((b.0, funded(1_000_000)));
        accounts.push((c.0, holder(5_000_000)));
        accounts.extend(closers.iter().map(|k| (k.0, funded(5_000_000))));
        let (ledger, _pool) = fixture(&accounts, &[(c.0, 77)]);
        put_app(
            &ledger,
            1_000,
            senders[0].0,
            "#pragma version 8\nint 0\nloop:\nint 1\n+\ndup\nint 20\n<\nbnz loop\npop\nint 1\n",
        );
        let mut eval = PoolLedgerAdapter::new(ledger.clone())
            .start_simple_evaluator(genesis_header(), 0, 0)
            .expect("start_evaluator");
        let mut state = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        let mut closed = 0usize;
        for i in 0..60u64 {
            let s = &senders[next() % 4];
            let admitted = match next() % 6 {
                0..=2 => {
                    let mut t = base_txn(s.0, TxnType::Pay);
                    t.receiver = b.0;
                    t.amount = 1 + i;
                    eval.transaction_group(&[sign(t, &s.1)])
                }
                3 if closed < closers.len() => {
                    closed += 1;
                    eval.transaction_group(&[pay(&closers[closed - 1], s.0, 0, Some(s.0))])
                }
                4 => {
                    let mut t = base_txn(s.0, TxnType::Appl);
                    t.application_id = 1_000;
                    t.note = serde_bytes::ByteBuf::from(i.to_be_bytes().to_vec());
                    eval.transaction_group(&[sign(t, &s.1)])
                }
                _ => {
                    // A group go refuses: admission rejects it.
                    let _ = eval.transaction_group(&[pay(&c, s.0, 0, Some(s.0))]);
                    continue;
                }
            };
            admitted.expect("valid group admitted");
        }
        // Smuggle an un-applyable group past admission at a random position.
        let bad = {
            let mut stib = pay(&c, senders[0].0, 0, Some(senders[0].0));
            eval.genesis_rule().strip(&mut stib);
            stib
        };
        let pos = next() % (eval.exec.as_ref().unwrap().groups.len() + 1);
        let at = eval
            .exec
            .as_ref()
            .unwrap()
            .groups
            .get(pos)
            .map(|g| g.start)
            .unwrap_or(eval.included_txns.len());
        eval.included_txns.insert(at, bad);
        for g in eval.exec.as_mut().unwrap().groups.iter_mut().skip(pos) {
            g.start += 1;
        }
        let txids = Some(carried_txids(&eval, at, 1));
        eval.exec.as_mut().unwrap().groups.insert(
            pos,
            ExecGroup {
                start: at,
                len: 1,
                fees: 1_000,
                txids,
            },
        );
        eval.fees_collected += 1_000;
        if limit_num > 0 {
            let total: usize = eval
                .included_txns
                .iter()
                .map(SimpleBlockEvaluator::encoded_len)
                .sum();
            eval.max_txn_bytes = total * limit_num / 10;
        }
        let block = eval.generate_block(&[]).expect("generate_block");
        let passes = eval.exec.as_ref().unwrap().last_passes;
        // The locked reference: the proposed block run through the SAVEPOINT
        // scratch apply directly (the old ALGOD_RUST_LOCKED_SCRATCH pass).
        let reference = {
            let mut l = ledger.lock().unwrap();
            algo_ledger::shadow_execute::scratch_execute_payset(&mut *l, &block, None)
                .unwrap_or_else(|e| panic!("seed {seed}: locked reference failed: {e:?}"))
        };
        assert_eq!(
            format!(
                "{:?}",
                SimpleBlockEvaluator::with_apply_data(&block.payset, &reference.apply_data)
            ),
            format!("{:?}", block.payset),
            "seed {seed} limit {limit_num}: ApplyData (overlay vs locked)"
        );
        assert_eq!(
            reference.final_txn_counter, block.txn_counter,
            "seed {seed}: txn counter"
        );
        (block, passes, closed)
    }

    let mut trimmed = 0usize;
    for seed in 0..8u64 {
        for limit in [0usize, 6] {
            let (ov, _passes, _) = mix(seed, limit);
            assert!(!ov.payset.is_empty());
            if limit > 0 {
                trimmed += 1;
            }
        }
    }
    assert!(trimmed > 0);
}

/// Release-build measurement for issue #1781:
/// `cargo test --release -p algod-rust --bin algod-rust lock_hold_report -- --ignored --nocapture`
#[test]
#[ignore = "measurement, run explicitly in a release build"]
fn lock_hold_report_large_workload() {
    let (ledger, mut eval, senders) = rich_fixture();
    let prober = LockProber::start(&ledger);
    let started = Instant::now();
    admit_rich(&mut eval, &senders, 3_000, 600);
    let admitted = started.elapsed();
    let started = Instant::now();
    let block = eval.generate_block(&[]).expect("generate_block");
    let assembled = started.elapsed();
    let worst = prober.finish();
    eprintln!(
        "LOCK-HOLD-REPORT {} txns: admission {admitted:?}, generate_block {assembled:?}, \
         worst wait of a concurrent ledger user {worst:?}",
        block.payset.len()
    );
    for line in algo_ledger::proposal_eval::proposal_metrics_prometheus_text().lines() {
        if !line.starts_with('#') {
            eprintln!("LOCK-HOLD-REPORT {line}");
        }
    }
}

// ---- #2127: go generates with Generate + Validate (checkDup) ----

/// `a`'s payment to `b` carrying `lease`.
fn leased_pay(k: &Key, to: Address, lease: [u8; 32], note: u8) -> SignedTransaction {
    let mut t = base_txn(k.0, TxnType::Pay);
    t.receiver = to;
    t.amount = 1_000;
    t.lease = lease;
    t.note = serde_bytes::ByteBuf::from(vec![note]);
    sign(t, &k.1)
}

/// A lease the ledger holds but the evaluator's snapshot does not (it was
/// recorded after the snapshot was taken) is still rejected at admission:
/// `exec_group` evaluates the group through `evaluate_group`, whose
/// `checkDup` reads the live ledger (issue #2127, go `StartEvaluator` with
/// Generate + Validate).
#[test]
fn exec_group_rejects_a_lease_recorded_after_the_snapshot() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let lease = [0x5A; 32];
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let stx = leased_pay(&a, b.0, lease, 1);
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("the live lease must reject the group");
    // go returns the bare, typed `LeaseInLedgerError` (no second
    // "transaction <txid>:" frame), which its pool tags `lease`.
    let expected = algo_ledger::check_dup::lease_in_ledger_error(
        algo_codec::compute_txn_id(&stx.txn),
        &a.0,
        &lease,
        false,
    );
    assert_eq!(err.to_string(), expected.to_string());
    assert!(
        matches!(
            err,
            algo_error::AlgoError::Rejected {
                class: algo_error::RejectClass::LeaseInLedger { in_block: false },
                ..
            }
        ),
        "{err:?}"
    );
}

/// The same rejection through the pool: `Remember` reports go's text and
/// the pool tags it `lease`, as go's `ClassifyTxPoolError` does (#2127).
#[test]
fn pool_tags_a_live_lease_rejection_lease_like_go() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let lease = [0x5C; 32];
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let stx = leased_pay(&a, b.0, lease, 3);
    let err = pool.remember_one(stx.clone()).expect_err("rejected");
    assert_eq!(
        algo_pool::error::classify_pool_error(&err),
        algo_pool::error::PoolErrorTag::Lease
    );
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: {}",
            algo_ledger::check_dup::lease_in_ledger_error(
                algo_codec::compute_txn_id(&stx.txn),
                &a.0,
                &lease,
                false
            )
        )
    );
}

/// The same at assembly: a group admitted before the lease was recorded is
/// dropped from the proposal, because the final scratch apply runs
/// `checkDup` against the live ledger (issue #2127).
#[test]
fn assembly_drops_a_group_whose_lease_was_recorded_after_admission() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let lease = [0x5B; 32];
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 2_000_000, None)])
        .expect("good group");
    eval.transaction_group(&[leased_pay(&a, b.0, lease, 2)])
        .expect("admitted while the lease is free");
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(
        block.payset.len(),
        1,
        "the group reusing the live lease is not proposed"
    );
    assert_eq!(block.payset[0].txn.lease, [0u8; 32]);
}

/// When the dev-mode commit rejects a group (go `AssembleDevModeBlock`
/// drops a group its evaluator rejects), the producer evicts that group
/// from the pool, so the next dev block carries the rest and the chain
/// keeps advancing (issue #2127).
#[test]
fn dev_mode_evicts_a_rejected_group_and_the_chain_advances() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (ledger, pool) = fixture(
        &[
            (a.0, funded(50_000_000)),
            (b.0, funded(1_000_000)),
            (c.0, funded(50_000_000)),
        ],
        &[],
    );
    pool.remember_one(pay(&a, b.0, 1_000_000, None)).expect("a");
    pool.remember_one(pay(&c, b.0, 2_000_000, None)).expect("c");
    let candidate = pool.assemble_dev_mode_block().expect("assemble");
    assert_eq!(candidate.payset.len(), 2);
    let rejected_sender = candidate.payset[0].txn.sender;

    let rejected_txid = algo_codec::block_txids_with_rule(
        &candidate,
        &algo_types::genesis_restore::GenesisRestoreRule::for_block(&candidate),
    )[0];
    let reason = algo_ledger::check_dup::lease_in_ledger_error(
        rejected_txid,
        &rejected_sender,
        &[0x5D; 32],
        false,
    );
    let lease_tag = algo_pool::error::PoolErrorTag::Lease;
    let reevals_before = pool.reeval_counter().count(lease_tag);
    assert_eq!(
        crate::dev_producer::evict_failed_group(&pool, &candidate, 0, &reason),
        1,
        "the failing transaction's group is dropped"
    );
    assert_eq!(pool.pending_count(), 1);
    // `pending/{txid}` reports the rejection, and the re-evaluation counter
    // counts it under the `lease` tag, as for any re-evaluation eviction.
    let (_, status, found) = pool.lookup(&rejected_txid);
    assert!(found);
    assert_eq!(status, reason.to_string());
    assert_eq!(pool.reeval_counter().count(lease_tag), reevals_before + 1);

    let (block, _) =
        crate::dev_producer::produce_dev_block(&pool, &ledger, None).expect("dev block");
    assert_eq!(block.round, Round(1), "the chain advanced");
    assert_eq!(block.payset.len(), 1);
    assert_ne!(block.payset[0].txn.sender, rejected_sender);
}

/// An eviction also rolls the pending-block evaluator back: it no longer
/// holds the evicted group's txid, lease or balance changes, so the same
/// transaction resubmitted afterwards is admitted again (issue #2127).
#[test]
fn a_group_evicted_in_dev_mode_can_be_resubmitted() {
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let stx = leased_pay(&a, b.0, [0x5F; 32], 7);
    pool.remember_one(stx.clone()).expect("admitted");
    let candidate = pool.assemble_dev_mode_block().expect("assemble");
    assert_eq!(candidate.payset.len(), 1);
    let reason = algo_error::AlgoError::Ledger {
        message: "dev-mode commit rejected the group".into(),
    };
    assert_eq!(
        crate::dev_producer::evict_failed_group(&pool, &candidate, 0, &reason),
        1
    );
    assert_eq!(pool.pending_count(), 0);
    pool.remember_one(stx)
        .expect("the evicted transaction is admitted again");
    assert_eq!(pool.pending_count(), 1);
}

/// An eviction that matches no pending group changes nothing: no index
/// entry, status-cache entry or re-evaluation count (issue #2127).
#[test]
fn evicting_an_unknown_group_changes_nothing() {
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let kept = leased_pay(&a, b.0, [0x60; 32], 8);
    pool.remember_one(kept.clone()).expect("admitted");
    let unknown = algo_codec::compute_txn_id(&leased_pay(&a, b.0, [0x61; 32], 9).txn);
    let reason = algo_error::AlgoError::Ledger {
        message: "dev-mode commit rejected the group".into(),
    };
    let tag =
        algo_pool::error::classify_pool_error(&algo_pool::PoolError::Evaluator(reason.to_string()));
    let reevals_before = pool.reeval_counter().count(tag);
    assert_eq!(
        pool.evict_groups(&std::collections::HashSet::from([unknown]), &reason),
        0
    );
    assert_eq!(pool.pending_count(), 1);
    let (_, status, found) = pool.lookup(&unknown);
    assert!(
        !found && status.is_empty(),
        "no status for {unknown}: {status}"
    );
    assert_eq!(pool.reeval_counter().count(tag), reevals_before);
    let (_, _, found) = pool.lookup(&algo_codec::compute_txn_id(&kept.txn));
    assert!(found, "the pending transaction is still indexed");
}

/// The pool's own `checkDup` copy always runs, so a lease the snapshot holds
/// is rejected even when the real apply cannot run (stale base): go's typed
/// `LeaseInLedgerError`, tagged `lease` (issue #2127).
#[test]
fn snapshot_lease_is_rejected_when_exec_is_stale() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let lease = [0x5E; 32];
    let (ledger, _pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    // The chain advanced under the evaluator: exec cannot evaluate.
    eval.exec.as_mut().unwrap().template.round = Round(9);
    let stx = leased_pay(&a, b.0, lease, 4);
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("the snapshot lease rejects the group");
    let expected = algo_ledger::check_dup::lease_in_ledger_error(
        algo_codec::compute_txn_id(&stx.txn),
        &a.0,
        &lease,
        false,
    );
    assert_eq!(err.to_string(), expected.to_string());
    assert!(matches!(
        err,
        algo_error::AlgoError::Rejected {
            class: algo_error::RejectClass::LeaseInLedger { in_block: false },
            ..
        }
    ));
}

/// go runs `checkDup` before the balance checks: a leased payment that is
/// also an overspend reports the lease conflict (issue #2127).
#[test]
fn leased_overspend_reports_the_lease_conflict_first() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let lease = [0x5F; 32];
    let (ledger, _pool) = fixture(&[(a.0, funded(5_000_000)), (b.0, funded(1_000_000))], &[]);
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    let mut t = base_txn(a.0, TxnType::Pay);
    t.receiver = b.0;
    t.amount = 900_000_000; // far more than a holds
    t.lease = lease;
    let stx = sign(t, &a.1);
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("rejected");
    assert!(
        err.to_string().contains("using an overlapping lease"),
        "expected the lease conflict, got: {err}"
    );
}

/// Port of go's `TestPoolLeaseReevalClassification`
/// (`data/pools/transactionPool_test.go`): a leased transaction is
/// remembered, then committed in a block; the pool re-evaluates its pending
/// group without the block's txids (go nils `delta.Txids`), and the group is
/// dropped as a conflict with the ledger's lease, counted under go's
/// `TxPoolErrTagLease` (the typed `LeaseInLedgerError` with
/// `InBlockEvaluator` false), not `lease_eval` (issue #2127).
#[test]
fn pool_lease_reeval_classification() {
    use algo_pool::error::PoolErrorTag;
    let a = key(1);
    let b = key(2);
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let mut lease = [0u8; 32];
    lease[0] = 0x01;
    pool.remember_one(leased_pay(&a, b.0, lease, 10))
        .expect("remembered");

    // Commit the transaction in a block, behind the pool's back.
    let block = pool.assemble_dev_mode_block().expect("assemble");
    assert_eq!(block.payset.len(), 1);
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().expect("begin_block");
        algo_ledger::apply::apply_generated_block_capturing_apply_data_with_delta(
            &mut *l,
            &block,
            algo_ledger::ApplyMode::Execute,
        )
        .expect("commit the leased transaction");
        l.commit_block().expect("commit_block");
    }

    let counter = pool.reeval_counter();
    let (lease_before, lease_eval_before) = (
        counter.count(PoolErrorTag::Lease),
        counter.count(PoolErrorTag::LeaseEval),
    );
    // No committed txids: the pool re-evaluates instead of filtering.
    pool.on_new_block(&block, &std::collections::HashSet::new());
    let counter = pool.reeval_counter();
    assert_eq!(counter.count(PoolErrorTag::Lease), lease_before + 1);
    assert_eq!(counter.count(PoolErrorTag::LeaseEval), lease_eval_before);
    assert_eq!(pool.pending_count(), 0);
}

/// go returns `Transaction.Alive`'s rejection from the validating
/// evaluator's prologue bare (`bookkeeping.TxnDeadError`), with no
/// `transaction <txid>:` frame; its pool tags it `txn_early` / `txn_dead`
/// from the error (issue #2127).
#[test]
fn exec_prologue_alive_rejection_is_bare_like_go() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let mut t = base_txn(a.0, TxnType::Pay);
    t.receiver = b.0;
    t.amount = 1_000;
    t.first_valid = Round(500);
    let early = sign(t, &a.1);
    let err = eval
        .transaction_group(std::slice::from_ref(&early))
        .expect_err("not yet alive");
    let round = eval.round().0;
    assert_eq!(
        err.to_string(),
        format!("txn dead: round {round} outside of 500--1000")
    );
    assert!(
        matches!(
            err,
            algo_error::AlgoError::Rejected {
                class: algo_error::RejectClass::Alive,
                ..
            }
        ),
        "{err:?}"
    );

    // The exec prologue's own `Alive` rejection (reached when the payset is
    // evaluated against the live ledger) is passed through unframed too.
    let txid = algo_codec::compute_txn_id(&early.txn).to_string();
    let alive = algo_error::AlgoError::Rejected {
        source: None,
        message: format!("txn dead: round {round} outside of 500--1000"),
        class: algo_error::RejectClass::Alive,
    };
    let passed = super::go_rejection(&txid, alive);
    assert_eq!(
        passed.to_string(),
        format!("txn dead: round {round} outside of 500--1000")
    );
}

/// An eviction counts one re-evaluation drop per dropped group, as go's
/// `recomputeBlockEvaluator` does (issue #2127).
#[test]
fn eviction_counts_one_reeval_drop_per_group() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (_ledger, pool) = fixture(
        &[
            (a.0, funded(50_000_000)),
            (b.0, funded(1_000_000)),
            (c.0, funded(50_000_000)),
        ],
        &[],
    );
    let first = leased_pay(&a, b.0, [0x62; 32], 11);
    let second = leased_pay(&c, b.0, [0x63; 32], 12);
    pool.remember_one(first.clone()).expect("first");
    pool.remember_one(second.clone()).expect("second");
    let reason = algo_error::AlgoError::Ledger {
        message: "dev-mode commit rejected the group".into(),
    };
    let tag =
        algo_pool::error::classify_pool_error(&algo_pool::PoolError::Evaluator(reason.to_string()));
    let before = pool.reeval_counter().count(tag);
    let ids = std::collections::HashSet::from([
        algo_codec::compute_txn_id(&first.txn),
        algo_codec::compute_txn_id(&second.txn),
    ]);
    assert_eq!(pool.evict_groups(&ids, &reason), 2);
    assert_eq!(pool.reeval_counter().count(tag), before + 2);
    assert_eq!(pool.pending_count(), 0);
}

// ---- #2129: in-group lease conflicts, pool test stage vs apply stage ----

/// go's pool runs `TestTransactionGroup` (each member against the
/// unmodified state, so it cannot see a sibling's lease) and then
/// `TransactionGroup` (members applied in order, the second one hitting
/// `LeaseInLedgerError` from `checkDup`). The oracle pins both outcomes
/// (`block_checkdup/oracle.json` `pool`, checked in algo-ledger's
/// `block_checkdup_oracle_test`). Here the same two stages of the Rust pool
/// evaluator: its test stage judges each member against the unmodified
/// state (per-transaction `Alive` and `checkDup`, issue #2130), so it accepts
/// the conflicting group as go's does, and the apply stage rejects the second
/// member with go's text and pool tag.
#[test]
fn in_group_lease_conflict_passes_the_test_stage_and_fails_the_apply_stage() {
    let a = key(1);
    let b = key(2);
    let lease = [0x5D; 32];
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let mut members = [1u8, 2].map(|note| {
        let mut t = base_txn(a.0, TxnType::Pay);
        t.receiver = b.0;
        t.amount = 1_000;
        t.lease = lease;
        t.note = serde_bytes::ByteBuf::from(vec![note]);
        t
    });
    let gid = algo_codec::compute_group_id(&members);
    for t in members.iter_mut() {
        t.group = gid.0;
    }
    let group: Vec<_> = members.into_iter().map(|t| sign(t, &a.1)).collect();

    eval.test_transaction_group(&group)
        .expect("the test stage does not see a sibling's lease");
    let err = eval
        .transaction_group(&group)
        .expect_err("the apply stage rejects the second member");
    let expected = algo_ledger::check_dup::lease_in_ledger_error(
        algo_codec::compute_txn_id(&group[1].txn),
        &a.0,
        &lease,
        true,
    );
    assert_eq!(err.to_string(), expected.to_string());
    // The typed class the pool maps to its `lease_eval` tag.
    assert!(
        matches!(
            err,
            algo_error::AlgoError::Rejected {
                class: algo_error::RejectClass::LeaseInLedger { in_block: true },
                ..
            }
        ),
        "{err:?}"
    );
}

// ---- #2130: go's per-transaction order, against the go oracle ----

/// go's pool admission for one scenario of
/// `block_checkdup/oracle.json` `pool_order` (`tools/simulate-rewards-oracle`,
/// `blockdup.go`): a fresh Generate + Validate evaluator, `Pre` groups
/// applied first, then `TestTransactionGroup` and `TransactionGroup`.
struct OrderScenario {
    name: String,
    pre: Vec<Vec<SignedTransaction>>,
    group: Vec<SignedTransaction>,
    test_error: String,
    add_error: String,
    /// Issue #2184: go's apply verdict is not that of any admission path the
    /// evaluator's apply stage models (go's gossip handler runs the test
    /// stage before any signature check, its REST path verifies first), so
    /// only the test stage is compared.
    skip_apply: bool,
}

fn oracle_b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("fixture base64")
}

fn oracle_addr(s: &str) -> Address {
    Address(oracle_b64(s).try_into().expect("32-byte address"))
}

/// The go oracle's ledger (genesis plus go's block 1) and its scenarios.
fn order_oracle() -> (Arc<Mutex<SqliteLedger>>, Vec<OrderScenario>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/core/algo-ledger/tests/fixtures/block_checkdup/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read the go oracle fixture");
    let o: serde_json::Value = serde_json::from_str(&raw).expect("parse the go oracle fixture");
    let text = |v: &serde_json::Value| v.as_str().expect("string").to_string();
    let mut l = SqliteLedger::open_in_memory().expect("ledger");
    l.set_protocol(text(&o["protocol"]));
    l.set_genesis_id(text(&o["genesis_id"]));
    l.set_genesis_hash(oracle_b64(&text(&o["genesis_hash"])).try_into().unwrap());
    l.set_fee_sink(oracle_addr(&text(&o["fee_sink"])));
    l.set_rewards_pool(oracle_addr(&text(&o["rewards_pool"])));
    for a in o["genesis_accounts"].as_array().expect("accounts") {
        let status = match a["status"].as_str().unwrap() {
            "Offline" => algo_types::AccountStatus::Offline,
            "Not Participating" => algo_types::AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        l.set_account(
            &oracle_addr(&text(&a["addr"])),
            AccountData {
                status,
                micro_algos: a["micro_algos"].as_u64().unwrap(),
                ..Default::default()
            },
        );
    }
    let block1 = algo_codec::decode_block(&oracle_b64(&text(&o["block1"]))).expect("go block 1");
    l.begin_block().expect("begin block");
    algo_ledger::apply::apply_block(&mut l, &block1).expect("apply go block 1");
    l.commit_block().expect("commit block");
    let txns = |v: &serde_json::Value| -> Vec<SignedTransaction> {
        v.as_array()
            .expect("txns")
            .iter()
            .map(|t| {
                let mut one = algo_codec::decode_signed_txn_stream(&oracle_b64(&text(t)))
                    .expect("decode go txn");
                assert_eq!(one.len(), 1);
                one.remove(0)
            })
            .collect()
    };
    let scenarios = o["pool_order"]
        .as_array()
        .expect("pool_order")
        .iter()
        .map(|s| OrderScenario {
            name: text(&s["name"]),
            pre: s["pre"]
                .as_array()
                .map(|p| p.iter().map(txns).collect())
                .unwrap_or_default(),
            group: txns(&s["group"]),
            test_error: text(&s["test_error"]),
            add_error: text(&s["add_error"]),
            skip_apply: s["skip_apply"].as_bool().unwrap_or(false),
        })
        .collect();
    (Arc::new(Mutex::new(l)), scenarios)
}

/// A fresh pool evaluator on go's ledger, one per scenario.
fn order_evaluator(ledger: &Arc<Mutex<SqliteLedger>>) -> SimpleBlockEvaluator {
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let hdr1 = algo_pool::traits::PoolLedger::block_hdr(&adapter, Round(1)).expect("block 1");
    adapter
        .start_simple_evaluator(hdr1, 0, 0)
        .expect("start_evaluator")
}

/// Every scenario go's `BlockEvaluator` decides: the Rust evaluator's
/// `transaction_group` (apply stage) gives go's `TransactionGroup` text, and
/// its `test_transaction_group` gives go's `TestTransactionGroup` text. The
/// order is per transaction, `Alive` -> `checkDup` -> authorizer -> apply
/// (`BlockEvaluator.transaction`), so the FIRST failing member decides.
#[test]
fn pool_evaluator_matches_go_per_transaction_order() {
    let (ledger, scenarios) = order_oracle();
    assert!(!scenarios.is_empty(), "the oracle has pool_order rows");
    let mut mismatches = Vec::new();
    for sc in &scenarios {
        let mut eval = order_evaluator(&ledger);
        for pre in &sc.pre {
            eval.transaction_group(pre)
                .unwrap_or_else(|e| panic!("{}: pre group: {e}", sc.name));
        }
        let test = eval
            .test_transaction_group(&sc.group)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        let add = eval
            .transaction_group(&sc.group)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        if test != sc.test_error {
            mismatches.push(format!(
                "{} (test stage)\n  go:   {:?}\n  rust: {:?}",
                sc.name, sc.test_error, test
            ));
        }
        if add != sc.add_error && !sc.skip_apply {
            mismatches.push(format!(
                "{} (apply stage)\n  go:   {:?}\n  rust: {:?}",
                sc.name, sc.add_error, add
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} verdict(s) differ from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

// ---- #2193: WellFormed and verify.TxnGroup texts, against the go oracle ----

/// One `wellformed` row of `block_checkdup/oracle.json` (`wellformed.go`,
/// `blockdup.go` in `tools/simulate-rewards-oracle`): a group and go's two
/// verdicts on it, `TestTransactionGroup` (gossip test stage) and
/// `verify.TxnGroup` (REST path).
struct WellFormedRow {
    name: String,
    /// `Err` when the Rust decoder refuses go's encoding of the group.
    group: Result<Vec<SignedTransaction>, String>,
    test_error: String,
    /// go's `verify.TxnGroup` error, its `transaction <dump> invalid : `
    /// frame (if any) reduced to the reason.
    verify_error: String,
    /// go's error carried that frame.
    verify_framed: bool,
}

fn wellformed_rows() -> Vec<WellFormedRow> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/core/algo-ledger/tests/fixtures/block_checkdup/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read the go oracle fixture");
    let o: serde_json::Value = serde_json::from_str(&raw).expect("parse the go oracle fixture");
    let text = |v: &serde_json::Value| v.as_str().expect("string").to_string();
    o["wellformed"]
        .as_array()
        .expect("wellformed rows")
        .iter()
        .map(|r| WellFormedRow {
            name: text(&r["name"]),
            group: r["group"]
                .as_array()
                .expect("group")
                .iter()
                .map(|t| {
                    let mut one = algo_codec::decode_signed_txn_stream(&oracle_b64(&text(t)))
                        .map_err(|e| e.to_string())?;
                    assert_eq!(one.len(), 1);
                    Ok(one.remove(0))
                })
                .collect(),
            test_error: text(&r["test_error"]),
            verify_error: text(&r["verify_error"]),
            verify_framed: r["verify_framed"].as_bool().unwrap_or(false),
        })
        .collect()
}

/// A REST-path error as a client sees it: the evaluator's typed, bare
/// verify-class rejection (with the pool tag its failure gets), the batch
/// signature failure, or an error that is neither (never what go sends).
fn rest_error_text(e: &algo_error::AlgoError) -> (String, Option<algo_error::VerifyKind>) {
    match e {
        algo_error::AlgoError::Rejected {
            message,
            class: algo_error::RejectClass::Verify(kind),
            ..
        } => (message.clone(), Some(*kind)),
        e if e.is_batch_sig_failure() => (algo_error::BATCH_HAS_FAILED_SIGS.to_string(), None),
        e => (format!("not a verify-class rejection: {e}"), None),
    }
}

/// Splits go's `transaction <dump> invalid : <reason>` into (framed, reason).
/// go's dump is its own `%+v` struct formatting (the Rust frame prints an
/// abbreviated one with the same `transaction {` prefix and ` invalid : `
/// infix), so the SHAPE of the frame is compared and then the reason.
fn split_frame(text: &str) -> (bool, &str) {
    match (text.starts_with("transaction {"), text.find("} invalid : ")) {
        (true, Some(at)) => (true, &text[at + "} invalid : ".len()..]),
        _ => (false, text),
    }
}

/// Every `Transaction.WellFormed` rule, and the order the rules run in, as go
/// words and orders them: the gossip test stage's error is go's in full
/// (`transaction <txid>: malformed: <reason>`), and the REST path's error is
/// go's `verify.TxnGroup` text (group errors and signature errors in full, a
/// not-well-formed transaction by its reason).
#[test]
fn wellformed_and_group_error_texts_match_go() {
    let (ledger, _) = order_oracle();
    let rows = wellformed_rows();
    assert!(rows.len() > 100, "the oracle has the WellFormed table");
    let mut mismatches = Vec::new();
    let mut undecodable = Vec::new();
    for row in &rows {
        let Ok(group) = &row.group else {
            undecodable.push(row.name.as_str());
            continue;
        };
        let eval = order_evaluator(&ledger);
        let test = eval
            .test_transaction_group(group)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        if test != row.test_error {
            mismatches.push(format!(
                "{} (test stage)\n  go:   {:?}\n  rust: {:?}",
                row.name, row.test_error, test
            ));
        }
        // The REST path's stateless half (`validate_group_stateless_inner`:
        // go's `verify.TxnGroup`) is compared for EVERY row: where go
        // rejects, Rust must reject with go's reason, the same frame shape and
        // the pool tag the same failure gets on the gossip test stage; where go
        // accepts, Rust must accept (the window, duplicates and fees are not
        // `verify.TxnGroup`'s). The rules that need the special addresses
        // (rewards-pool sender, fee-sink payment and keyreg) are compared too:
        // go's `verify.TxnGroup` hands `WellFormed` the header's addresses and
        // so does this path (issue #2198).
        let eval = order_evaluator(&ledger);
        match (
            eval.validate_group_stateless_inner(group),
            row.verify_error.as_str(),
        ) {
            (Ok(_), "") => {}
            (Ok(_), want) => mismatches.push(format!(
                "{} (REST path)\n  go rejects: {:?}\n  rust accepts",
                row.name, want
            )),
            (Err(e), "") => mismatches.push(format!(
                "{} (REST path)\n  go accepts\n  rust rejects: {:?}",
                row.name,
                e.to_string()
            )),
            (Err(e), want) => {
                let (text, kind) = rest_error_text(&e);
                let (rust_framed, rust_reason) = split_frame(&text);
                // A LogicSig that ERRORS (`verify_logicsig_err_*`, one row per AVM error
                // kind, and `verify_logicsig_errors`): go prints the AVM's own error
                // and the byte offset `pc` of its `EvalError` (`err=/ 0. Details:
                // pc=5`), compared in full (issue #2200).
                let (rust_reason, want) = (rust_reason.to_string(), want.to_string());
                if rust_reason != want || rust_framed != row.verify_framed {
                    mismatches.push(format!(
                        "{} (REST path)\n  go:   {:?} (framed: {})\n  rust: {:?} (framed: {})",
                        row.name, want, row.verify_framed, rust_reason, rust_framed
                    ));
                }
                // The pool tag follows the failure's kind, as on gossip.
                let want_kind = if row.name.starts_with("wf_") {
                    Some(algo_error::VerifyKind::NotWell)
                } else if row.name.starts_with("group_") {
                    Some(algo_error::VerifyKind::GroupId)
                } else if row.name.starts_with("verify_") {
                    Some(algo_error::VerifyKind::Other)
                } else {
                    None
                };
                if want_kind.is_some() && kind != want_kind && kind.is_some() {
                    mismatches.push(format!(
                        "{} (REST path) tag kind {:?}, want {:?}",
                        row.name, kind, want_kind
                    ));
                }
                if let (Some(kind), algo_error::AlgoError::Rejected { class, message, .. }) =
                    (kind, &e)
                {
                    let tag =
                        algo_pool::error::classify_pool_error(&algo_pool::PoolError::TxnRejected {
                            message: message.clone(),
                            class: *class,
                            detail: None,
                        });
                    let want_tag = match kind {
                        algo_error::VerifyKind::NotWell => algo_pool::error::PoolErrorTag::NotWell,
                        algo_error::VerifyKind::GroupId => algo_pool::error::PoolErrorTag::GroupId,
                        algo_error::VerifyKind::TooLarge => {
                            algo_pool::error::PoolErrorTag::TooLarge
                        }
                        algo_error::VerifyKind::Other => {
                            algo_pool::error::PoolErrorTag::EvalGeneric
                        }
                    };
                    assert_eq!(tag, want_tag, "{}", row.name);
                    assert!(!text.contains("TransactionPool"), "{}: {text}", row.name);
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} verdict(s) differ from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    // Rows the Rust decoder refuses are not judged by the evaluator at all;
    // none may be skipped silently. go encodes a zero sender as an absent
    // `snd` key, and since v4.7.2 `snd` is `codec:",required"`: go's own
    // decoder refuses these rows too (`missing required field: snd`), so they
    // cannot reach `WellFormed` over the wire in go either. Both decoders
    // reject, which `go_and_rust_both_refuse_a_zero_sender_at_decode` proves
    // against the oracle's `decode_required` rows (issue #2197); the rule
    // itself is pinned by `rules::tests::test_zero_sender_rejected` and the
    // order rows that do not need an absent sender.
    assert_eq!(
        undecodable,
        [
            "wf_zero_sender_payment",
            "wf_zero_sender_axfer",
            "wf_order_note_before_zero_sender"
        ],
        "rows go encodes and the Rust decoder refuses"
    );
}

/// Issue #2197: a transaction whose sender is the zero address is encoded by
/// go with no `snd` key, and go's own decoder refuses it (`snd` is a required
/// field since v4.7.2: `missing required field: snd`). The Rust decoder
/// refuses it at the same stage, so no accept/reject verdict differs, and the
/// zero-sender `wellformed` rows are undecodable on both sides. (go's third
/// row fails an earlier bound of the same decode, the note length.)
#[test]
fn go_and_rust_both_refuse_a_zero_sender_at_decode() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/core/algo-ledger/tests/fixtures/block_checkdup/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read the go oracle fixture");
    let o: serde_json::Value = serde_json::from_str(&raw).expect("parse the go oracle fixture");
    let rows = o["decode_required"].as_array().expect("decode rows");
    let names: Vec<&str> = rows
        .iter()
        .map(|r| r["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        [
            "wf_zero_sender_payment",
            "wf_zero_sender_axfer",
            "wf_order_note_before_zero_sender"
        ],
        "the same rows `wellformed_and_group_error_texts_match_go` cannot decode"
    );
    for r in rows {
        let name = r["name"].as_str().expect("name");
        let go_error = r["decode_error"].as_str().expect("decode_error");
        assert!(!go_error.is_empty(), "{name}: go decodes it");
        let bytes = oracle_b64(r["txn"].as_str().expect("txn"));
        let rust_error = algo_codec::decode_signed_txn_stream(&bytes)
            .expect_err(&format!("{name}: the Rust decoder accepts it"));
        // The stream decoder wraps the field error; its source names the field.
        let rust_error = format!("{rust_error:?}");
        if go_error.contains("missing required field: snd") {
            assert!(rust_error.contains("snd"), "{name}: {rust_error}");
        }
    }
}

/// One signed group of `members` (the group ID computed over them).
fn signed_group(members: Vec<Transaction>, k: &Key) -> Vec<SignedTransaction> {
    let gid = algo_codec::compute_group_id(&members);
    members
        .into_iter()
        .map(|mut t| {
            t.group = gid.0;
            sign(t, &k.1)
        })
        .collect()
}

fn pay_txn(k: &Key, to: Address, amount: u64, note: u8) -> Transaction {
    let mut t = base_txn(k.0, TxnType::Pay);
    t.receiver = to;
    t.amount = amount;
    t.note = serde_bytes::ByteBuf::from(vec![note]);
    t
}

/// go's `BlockEvaluator.transaction` is per member, so the FIRST failing member
/// of a group decides the error and the pool's tag: member 0's overspend is
/// reported even though member 1 repeats it (a duplicate). The same through
/// `Remember`, with go's frame and tag (issue #2130; the go oracle pins the
/// texts in `pool_evaluator_matches_go_per_transaction_order`).
#[test]
fn pool_reports_the_first_failing_member_with_its_own_tag() {
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(5_000_000)), (b.0, funded(1_000_000))], &[]);
    let over = pay_txn(&a, b.0, 900_000_000, 7);
    let group = signed_group(vec![over.clone(), over], &a);
    let err = pool.remember(group.clone()).expect_err("overspend");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::Overspend, "{err}");
    assert!(
        err.to_string().starts_with(&format!(
            "TransactionPool.Remember: transaction {}: overspend",
            txid(&group[0])
        )),
        "{err}"
    );
}

/// Issue #2193: the REST path's `verify.TxnGroup` verdicts reach the client
/// bare (no `TransactionPool.Remember` / `ingest` frame) and carry the pool
/// tag the same failure gets on the gossip test stage: too large, group ID,
/// not well formed. A not-well-formed member is framed as go frames it
/// (`transaction {..} invalid : <reason>`).
#[test]
fn rest_verify_failures_are_bare_and_tagged_like_gossip() {
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);

    // One more member than MaxTxGroupSize.
    let members: Vec<Transaction> = (0..17).map(|i| pay_txn(&a, b.0, 1, i)).collect();
    let err = pool
        .remember(signed_group(members, &a))
        .expect_err("too large");
    assert_eq!(err.to_string(), "group size 17 exceeds maximum 16");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TooLarge);

    // A group ID the members do not hash to.
    let mut members = vec![pay_txn(&a, b.0, 1, 1), pay_txn(&a, b.0, 1, 2)];
    for m in &mut members {
        m.group = [7u8; 32];
    }
    let group: Vec<SignedTransaction> = members.into_iter().map(|t| sign(t, &a.1)).collect();
    let err = pool.remember(group).expect_err("bogus group id");
    assert!(
        err.to_string()
            .starts_with("transactionGroup: incomplete group: "),
        "{err}"
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::GroupId);

    // A member that is not well formed: framed, bare, tagged not_well.
    let mut long = pay_txn(&a, b.0, 1, 3);
    long.last_valid = Round(100_000);
    let err = pool
        .remember(vec![sign(long, &a.1)])
        .expect_err("not well formed");
    let text = err.to_string();
    assert!(text.starts_with("transaction {"), "{text}");
    assert!(
        text.ends_with("} invalid : transaction window size excessive (1--100000)")
            || text.contains(" invalid : transaction window size excessive ("),
        "{text}"
    );
    assert!(!text.contains("TransactionPool"), "{text}");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::NotWell);
}

/// An application call that go's apply rejects on member 0 beats a precheck
/// failure (here an overspend) of member 1: the cheap prechecks do not model
/// the AVM, so the real apply runs the group in go's order to find it.
#[test]
fn an_earlier_apply_failure_beats_a_later_precheck_failure() {
    let a = key(1);
    let b = key(2);
    let app_id = 902u64;
    let (ledger, pool) = fixture(&[(a.0, funded(5_000_000)), (b.0, funded(1_000_000))], &[]);
    put_app(
        &ledger,
        app_id,
        a.0,
        "#pragma version 8
int 0
",
    );
    let mut call = base_txn(a.0, TxnType::Appl);
    call.application_id = app_id;
    call.fee = 1_000;
    let over = pay_txn(&a, b.0, 900_000_000, 8);
    let group = signed_group(vec![call, over], &a);
    let err = pool.remember(group.clone()).expect_err("rejected");
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction {}: transaction rejected by ApprovalProgram",
            txid(&group[0])
        )
    );
    // The rejected group left nothing behind: an ordinary payment is admitted.
    pool.remember_one(pay(&a, b.0, 1_000, None))
        .expect("the pool is unchanged");
}

/// go's pool has no duplicate pass of its own: a transaction the pending
/// block already holds is the evaluator's `checkDup` error, go's
/// `TransactionInLedgerError` with `InBlockEvaluator` (text
/// `transaction already in ledger: <txid>`, tag `txid_eval`), not a
/// pool-level "already in the pool" (issue #2130).
#[test]
fn pool_reports_a_pending_duplicate_like_go() {
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let stx = pay(&a, b.0, 1_000_000, None);
    pool.remember_one(stx.clone()).expect("first");
    let err = pool.remember_one(stx.clone()).expect_err("duplicate");
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction already in ledger: {}",
            txid(&stx)
        )
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TxIdEval);
}

/// go's `Test` stage runs `Alive` and `checkDup` per member against the
/// unmodified state (the pending block included) and returns the typed error,
/// which the pool tags `txid_eval` / `lease`.
#[test]
fn pool_test_stage_keeps_the_typed_checkdup_class() {
    use algo_ledger::store_trait::LedgerStore;
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let lease = [0x6B; 32];
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let pending = pay(&a, b.0, 1_000_000, None);
    pool.remember_one(pending.clone()).expect("pending");
    let err = pool.test(std::slice::from_ref(&pending)).expect_err("dup");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TxIdEval, "{err}");
    assert_eq!(
        err.to_string(),
        format!("transaction already in ledger: {}", txid(&pending))
    );

    // A lease committed after the evaluator's snapshot: the live ledger has it.
    ledger.lock().unwrap().record_lease(&a.0, &lease, 500);
    let stx = leased_pay(&a, b.0, lease, 9);
    let err = pool.test(std::slice::from_ref(&stx)).expect_err("lease");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::Lease, "{err}");
}

/// Issue #2184: the pool's `Test` (go's gossip pre-check) reports a group with
/// several problems for the FIRST one in `TestTransactionGroup`'s order, with
/// go's pool tag: a duplicate beats a bad signature, an incomplete group is
/// `groupid`, an oversized one `too_large`, an ill-formed member `not_well`
/// (the texts are pinned against go in
/// `pool_evaluator_matches_go_per_transaction_order`).
#[test]
fn pool_test_stage_reports_the_first_problem_in_go_order_with_its_tag() {
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let pending = pay(&a, b.0, 1_000_000, None);
    pool.remember_one(pending.clone()).expect("pending");

    // A pending duplicate whose signature is corrupted: the duplicate.
    let mut bad = pending.clone();
    bad.sig[0] ^= 0xFF;
    let err = pool.test(std::slice::from_ref(&bad)).expect_err("dup");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TxIdEval, "{err}");

    // A group of three submitted as its first member only: incomplete.
    let group = signed_group(
        vec![
            pay_txn(&a, b.0, 1_000, 21),
            pay_txn(&a, b.0, 1_000, 22),
            pay_txn(&a, b.0, 1_000, 23),
        ],
        &a,
    );
    let err = pool.test(&group[..1]).expect_err("incomplete");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::GroupId, "{err}");
    assert!(
        err.to_string()
            .starts_with("transactionGroup: incomplete group: "),
        "{err}"
    );
    // The whole group passes the test stage.
    pool.test(&group).expect("complete group");

    // Member 0 a duplicate, member 1 ungrouped inside a group: the duplicate.
    let mut mixed = group.clone();
    mixed[0] = pending.clone();
    let err = pool.test(&mixed).expect_err("dup first");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TxIdEval, "{err}");

    // Seventeen members: too large (MaxTxGroupSize is 16).
    let big: Vec<Transaction> = (0..17u8).map(|n| pay_txn(&a, b.0, 1_000, 50 + n)).collect();
    let err = pool.test(&signed_group(big, &a)).expect_err("too large");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TooLarge, "{err}");
    assert_eq!(err.to_string(), "group size 17 exceeds maximum 16");

    // A member that is not well formed (window longer than MaxTxnLife).
    let mut long = pay_txn(&a, b.0, 1_000, 99);
    long.last_valid = Round(100_000);
    let err = pool.test(&[sign(long, &a.1)]).expect_err("not well formed");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::NotWell, "{err}");
}

/// Port of go's `TestTxPoolReevalMetricsRecordLedgerDuplicate`
/// (`data/pools/transactionPool_test.go`): a transaction is remembered, then
/// committed in a block; the pool re-evaluates its pending group without the
/// block's txids (go nils `delta.Txids`, so the fast committed-txid filter
/// misses), and the re-fed evaluator itself finds the transaction in the
/// ledger: `TransactionInLedgerError`, counted under `TxPoolErrTagTxID`
/// (issue #2130: the evaluator runs `checkDup` per transaction, as go's does).
#[test]
fn pool_txid_reeval_classification() {
    use algo_pool::error::PoolErrorTag;
    let a = key(1);
    let b = key(2);
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    pool.remember_one(pay(&a, b.0, 1_000_000, None))
        .expect("remembered");

    let block = pool.assemble_dev_mode_block().expect("assemble");
    assert_eq!(block.payset.len(), 1);
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().expect("begin_block");
        algo_ledger::apply::apply_generated_block_capturing_apply_data_with_delta(
            &mut *l,
            &block,
            algo_ledger::ApplyMode::Execute,
        )
        .expect("commit the transaction");
        l.commit_block().expect("commit_block");
    }

    let counter = pool.reeval_counter();
    let (txid_before, txid_eval_before) = (
        counter.count(PoolErrorTag::TxId),
        counter.count(PoolErrorTag::TxIdEval),
    );
    pool.on_new_block(&block, &std::collections::HashSet::new());
    let counter = pool.reeval_counter();
    assert_eq!(counter.count(PoolErrorTag::TxId), txid_before + 1);
    assert_eq!(counter.count(PoolErrorTag::TxIdEval), txid_eval_before);
    assert_eq!(pool.pending_count(), 0);
}

// ---- #2130 review: the reconciliation of a rejected group is side-effect free ----

/// `[valid payment, not-yet-valid payment]`: member 1 fails `Alive`, so the
/// cheap prechecks reject at a LATER member and the reconciliation dry run
/// asks the real apply about member 0.
fn rejected_late_group(a: &Key, b: &Key, note: u8) -> Vec<SignedTransaction> {
    let ok = pay_txn(a, b.0, 1_000, note);
    let mut early = pay_txn(a, b.0, 1_000, note.wrapping_add(100));
    early.first_valid = Round(5_000);
    early.last_valid = Round(6_000);
    signed_group(vec![ok, early], a)
}

/// A stream of rejected groups leaves the shared evaluator as it was: not
/// incomplete, the overlay and admitted set unchanged, the main admission
/// budget untouched, and the next valid group still takes the real apply.
#[test]
fn a_stream_of_rejected_groups_does_not_poison_or_change_the_evaluator() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.transaction_group(&[pay(&a, b.0, 2_000_000, None)])
        .expect("a valid group");
    let (overlay_len, groups, spent) = {
        let exec = eval.exec.as_ref().expect("exec");
        (exec.overlay.len(), exec.groups.len(), exec.spent)
    };
    let paysize = eval.pay_set_size();
    for n in 0..100u8 {
        let group = rejected_late_group(&a, &b, n);
        let err = eval
            .transaction_group(&group)
            .expect_err("member 1 is early");
        assert!(err.to_string().starts_with("txn dead: round"), "{err}");
    }
    let exec = eval.exec.as_ref().expect("exec");
    assert!(!exec.incomplete, "rejections never poison the evaluator");
    assert_eq!(exec.overlay.len(), overlay_len, "the overlay is unchanged");
    assert_eq!(exec.groups.len(), groups);
    assert_eq!(exec.spent, spent, "the admission budget is untouched");
    assert_eq!(eval.pay_set_size(), paysize);
    eval.transaction_group(&[pay(&a, b.0, 3_000_000, None)])
        .expect("a following valid group");
    let exec = eval.exec.as_ref().expect("exec");
    assert!(!exec.incomplete);
    assert_eq!(exec.groups.len(), groups + 1, "it took the real-apply path");
}

/// The reconciliation has a budget of its own: once it is spent a precheck
/// rejection stands as it is, and the main admission budget is never used.
#[test]
fn reconciliation_is_bounded_by_its_own_budget() {
    let a = key(1);
    let b = key(2);
    let app_id = 903u64;
    let (ledger, mut eval) = evaluator(&[(a.0, funded(5_000_000)), (b.0, funded(1_000_000))]);
    put_app(
        &ledger,
        app_id,
        a.0,
        "#pragma version 8
int 0
",
    );
    let mut call = base_txn(a.0, TxnType::Appl);
    call.application_id = app_id;
    call.fee = 1_000;
    let group = signed_group(vec![call, pay_txn(&a, b.0, 900_000_000, 9)], &a);
    // With budget left, member 0's apply failure outranks member 1's overspend.
    let err = eval.transaction_group(&group).expect_err("rejected");
    assert!(
        err.to_string()
            .ends_with("transaction rejected by ApprovalProgram"),
        "{err}"
    );
    assert!(eval.exec.as_ref().unwrap().reconcile_spent > Duration::ZERO);
    assert_eq!(
        eval.exec.as_ref().unwrap().spent,
        Duration::ZERO,
        "charged to the reconciliation budget"
    );
    // Spent: the precheck's own verdict stands.
    eval.exec.as_mut().unwrap().reconcile_spent = RECONCILE_BUDGET;
    let err = eval.transaction_group(&group).expect_err("rejected");
    assert!(err.to_string().contains("overspend"), "{err}");
    assert_eq!(eval.exec.as_ref().unwrap().spent, Duration::ZERO);
    assert!(!eval.exec.as_ref().unwrap().incomplete);
}

/// A poisoned ledger lock cannot be read: `checkDup` rejects the group
/// instead of admitting it unchecked, at both stages.
#[test]
fn a_poisoned_ledger_lock_rejects_instead_of_skipping_checkdup() {
    let a = key(1);
    let b = key(2);
    let (ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let l2 = ledger.clone();
    let _ = std::thread::spawn(move || {
        let _guard = l2.lock().unwrap();
        panic!("poison the ledger lock");
    })
    .join();
    let stx = pay(&a, b.0, 1_000, None);
    let err = eval
        .test_transaction_group(std::slice::from_ref(&stx))
        .expect_err("test stage");
    assert!(err.to_string().contains("poisoned"), "{err}");
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("apply stage");
    assert!(err.to_string().contains("poisoned"), "{err}");
}

/// A member that fails does not leave its rekey in the group state: member 0
/// overspends and rekeys, member 1 is authorized by the new key; the verdict
/// is member 0's overspend.
#[test]
fn a_failed_member_does_not_rekey_the_group_state() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(5_000_000)), (b.0, funded(1_000_000))]);
    let mut m0 = pay_txn(&a, b.0, 900_000_000, 1);
    m0.rekey_to = Some(c.0);
    let m1 = pay_txn(&a, b.0, 1_000, 2);
    let gid = algo_codec::compute_group_id(&[m0.clone(), m1.clone()]);
    let mut members = [m0, m1];
    for t in members.iter_mut() {
        t.group = gid.0;
    }
    let s0 = sign(members[0].clone(), &a.1);
    let mut s1 = sign(members[1].clone(), &c.1);
    s1.auth_addr = Some(c.0);
    let err = eval
        .transaction_group(&[s0, s1])
        .expect_err("member 0 overspends");
    assert!(err.to_string().contains("overspend"), "{err}");
}

/// A transaction confirmed after the evaluator's snapshot is still found (the
/// evaluator reads the ledger's txtail live), with go's typed error and tag
/// `txid`.
#[test]
fn a_transaction_confirmed_outside_the_snapshot_is_a_ledger_duplicate() {
    use algo_pool::error::{classify_pool_error, PoolError, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let stx = pay(&a, b.0, 1_000_000, None);
    pool.remember_one(stx.clone()).expect("remembered");
    let block = pool.assemble_dev_mode_block().expect("assemble");
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().expect("begin_block");
        algo_ledger::apply::apply_generated_block_capturing_apply_data_with_delta(
            &mut *l,
            &block,
            algo_ledger::ApplyMode::Execute,
        )
        .expect("commit");
        l.commit_block().expect("commit_block");
    }
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let hdr1 = algo_pool::traits::PoolLedger::block_hdr(&adapter, Round(1)).expect("block 1");
    let mut eval = adapter
        .start_simple_evaluator(hdr1, 0, 0)
        .expect("start_evaluator");
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("already confirmed");
    assert_eq!(
        err.to_string(),
        format!("transaction already in ledger: {}", txid(&stx))
    );
    let pool_err = PoolError::TxnRejected {
        message: err.to_string(),
        class: algo_error::RejectClass::TxidInLedger { in_block: false },
        detail: None,
    };
    assert_eq!(classify_pool_error(&pool_err), PoolErrorTag::TxId);
    assert!(matches!(
        err,
        algo_error::AlgoError::Rejected {
            class: algo_error::RejectClass::TxidInLedger { in_block: false },
            ..
        }
    ));
}

/// A rekey-authorizer failure submitted through the pool: go's bare text
/// behind only `Remember`'s frame (no algod-rust `validation error:`), the
/// same pool tag the text-classified error had.
#[test]
fn rekey_authorizer_failure_through_the_pool_is_go_text_and_tag() {
    use algo_ledger::store_trait::LedgerStore;
    use algo_pool::error::{classify_pool_error, PoolError};
    let a = key(1);
    let b = key(2);
    let new_auth = Address([0x4C; 32]);
    let (ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    {
        let mut l = ledger.lock().unwrap();
        let mut acct = l.get_account(&a.0).expect("a");
        acct.auth_addr = Some(new_auth);
        l.set_account(&a.0, acct);
    }
    let stx = pay(&a, b.0, 1_000, None);
    let err = pool
        .remember_one(stx.clone())
        .expect_err("wrong authorizer");
    let text = format!(
        "transaction {}: should have been authorized by {new_auth} but was actually authorized by {}",
        txid(&stx),
        a.0
    );
    assert_eq!(err.to_string(), format!("TransactionPool.Remember: {text}"));
    // The tag is what classifying the same text gave before (a generic
    // evaluator rejection).
    assert_eq!(
        classify_pool_error(&err),
        classify_pool_error(&PoolError::Evaluator(text))
    );
}

// ---- #2130 final review round ----

/// `[app call funds F, F pays R]`: the balance precheck does not model the
/// inner payment that funds F, so it refuses the group at member 1; go runs
/// the real apply per member and accepts it. The reconciliation's dry run
/// accepts, so the group is admitted as go would admit it, without poisoning
/// the evaluator.
#[test]
fn an_inner_transaction_funding_a_later_member_is_admitted_like_go() {
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let app_id = 904u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let (ledger, pool) = fixture(
        &[
            (s.0, funded(5_000_000)),
            (r.0, funded(1_000_000)),
            (app_addr, funded(10_000_000)),
        ],
        &[],
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
            "int 3000000\n",
            "itxn_field Amount\n",
            "int 0\n",
            "itxn_field Fee\n",
            "itxn_submit\n",
            "int 1\n",
        ),
    );
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.fee = 2_000;
    call.accounts = Some(vec![f.0]);
    let mut pay_r = pay_txn(&f, r.0, 1_000, 5);
    pay_r.fee = 1_000;
    let gid = algo_codec::compute_group_id(&[call.clone(), pay_r.clone()]);
    let (mut call, mut pay_r) = (call, pay_r);
    call.group = gid.0;
    pay_r.group = gid.0;
    let group = vec![sign(call, &s.1), sign(pay_r, &f.1)];
    let before = PRECHECK_OVER_REJECTS.load(std::sync::atomic::Ordering::Relaxed);
    pool.remember(group.clone())
        .expect("go accepts it: the inner payment funds F");
    assert_eq!(pool.pending_tx_groups().len(), 1);
    assert!(PRECHECK_OVER_REJECTS.load(std::sync::atomic::Ordering::Relaxed) > before);
}

/// Issue #2187: `[app call by S, F pays R]` over an evaluator whose ledger
/// holds the application. The program (AVM `version`) funds `Accounts 1`
/// (F) with 3 Algo by an inner payment when `funds`, else does nothing; the
/// call names F in its accounts array when `reference_f`. F pays `amount`.
fn app_then_pay_group(
    version: u8,
    funds: bool,
    reference_f: bool,
    amount: u64,
) -> (SimpleBlockEvaluator, Vec<SignedTransaction>) {
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let app_id = 904u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let (ledger, eval) = evaluator(&[
        (s.0, funded(5_000_000)),
        (r.0, funded(1_000_000)),
        (app_addr, funded(10_000_000)),
    ]);
    let program = if funds {
        format!(
            "#pragma version {version}\nitxn_begin\nint pay\nitxn_field TypeEnum\n\
             txn Accounts 1\nitxn_field Receiver\nint 3000000\nitxn_field Amount\n\
             int 0\nitxn_field Fee\nitxn_submit\nint 1\n"
        )
    } else {
        format!("#pragma version {version}\nint 1\n")
    };
    put_app(&ledger, app_id, s.0, &program);
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.fee = 2_000;
    if reference_f {
        call.accounts = Some(vec![f.0]);
    }
    let mut pay_r = pay_txn(&f, r.0, amount, 5);
    pay_r.fee = 1_000;
    let gid = algo_codec::compute_group_id(&[call.clone(), pay_r.clone()]);
    call.group = gid.0;
    pay_r.group = gid.0;
    (eval, vec![sign(call, &s.1), sign(pay_r, &f.1)])
}

/// Issue #2187: an evaluator whose real apply gave up cannot run the dry run,
/// yet go accepts `[app call funds F, F pays R]`: the shortfall of F, which
/// the call references, is not provably an overspend, so it is admitted.
#[test]
fn an_incomplete_evaluator_admits_a_shortfall_the_app_call_may_credit() {
    let (mut eval, group) = app_then_pay_group(8, true, true, 1_000);
    eval.exec.as_mut().unwrap().incomplete = true;
    eval.transaction_group(&group)
        .expect("admitted on the cheap checks, like go");
}

/// Issue #2187: the shortfall is judged only after an application call. With
/// the call AFTER the short member (or none) there is no unmodelled credit,
/// so the overspend is go's, complete or incomplete evaluator alike.
#[test]
fn a_shortfall_before_any_app_call_stays_rejected_in_degraded_mode() {
    let a = key(1);
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let app_id = 904u64;
    for incomplete in [true, false] {
        let (ledger, mut eval) = evaluator(&[
            (a.0, funded(50_000_000)),
            (s.0, funded(5_000_000)),
            (r.0, funded(1_000_000)),
        ]);
        put_app(&ledger, app_id, s.0, "#pragma version 9\nint 1\n");
        let mut call = base_txn(s.0, TxnType::Appl);
        call.application_id = app_id;
        let mut members = [
            pay_txn(&a, f.0, 1_000_000, 1),
            pay_txn(&f, r.0, 900_000_000, 2),
            call,
        ];
        let gid = algo_codec::compute_group_id(&members);
        for m in members.iter_mut() {
            m.group = gid.0;
        }
        let [m0, m1, m2] = members;
        let group = vec![sign(m0, &a.1), sign(m1, &f.1), sign(m2, &s.1)];
        eval.exec.as_mut().unwrap().incomplete = incomplete;
        let err = eval.transaction_group(&group).expect_err("overspend");
        assert!(err.to_string().contains("overspend"), "{err}");
        let exec = eval.exec.as_ref().unwrap();
        assert_eq!(exec.incomplete, incomplete);
        assert_eq!(exec.spent, Duration::ZERO, "no admission time charged");
    }
}

/// What is wrong with the third member of [`degraded_group`].
#[derive(Clone, Copy, PartialEq)]
enum Defect {
    None,
    Expired,
    GroupFees,
    WrongAuthorizer,
}

/// `[app call by S (names F), F pays R (short), T pays R]`: the later members'
/// checks must still run when the evaluator admits F's shortfall without a
/// real apply (issue #2187). T is rekeyed in the ledger under `WrongAuthorizer`
/// while its member is validly signed by T itself.
fn degraded_group(defect: Defect) -> (SimpleBlockEvaluator, Vec<SignedTransaction>) {
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let t = key(9);
    let app_id = 904u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let mut t_account = funded(5_000_000);
    if defect == Defect::WrongAuthorizer {
        t_account.auth_addr = Some(key(10).0);
    }
    let (ledger, mut eval) = evaluator(&[
        (s.0, funded(5_000_000)),
        (r.0, funded(1_000_000)),
        (t.0, t_account),
        (app_addr, funded(10_000_000)),
    ]);
    put_app(&ledger, app_id, s.0, "#pragma version 9\nint 1\n");
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.accounts = Some(vec![f.0]);
    let mut members = [call, pay_txn(&f, r.0, 1_000, 5), pay_txn(&t, r.0, 1_000, 6)];
    match defect {
        Defect::Expired => {
            members[2].first_valid = Round(5_000);
            members[2].last_valid = Round(6_000);
        }
        Defect::GroupFees => members.iter_mut().for_each(|m| m.fee = 0),
        Defect::None | Defect::WrongAuthorizer => {}
    }
    let gid = algo_codec::compute_group_id(&members);
    members.iter_mut().for_each(|m| m.group = gid.0);
    let [m0, m1, m2] = members;
    eval.exec.as_mut().unwrap().incomplete = true;
    (eval, vec![sign(m0, &s.1), sign(m1, &f.1), sign(m2, &t.1)])
}

/// Control for the three cases below: the unmodified group is admitted on the
/// incomplete evaluator (F's shortfall is creditable by the call).
#[test]
fn a_degraded_admission_admits_the_unmodified_group() {
    let (mut eval, group) = degraded_group(Defect::None);
    eval.transaction_group(&group).expect("admitted");
}

/// Issue #2187: admitting a creditable shortfall on an incomplete evaluator
/// does not skip the other checks of the later members. The reported error is
/// the later member's outright failure (a certain one), not F's deferred
/// shortfall that go would name first if the credit did not cover it:
/// verdict-only parity, documented on `validate_group`.
#[test]
fn a_degraded_admission_still_refuses_an_expired_later_member() {
    let (mut eval, group) = degraded_group(Defect::Expired);
    let err = eval.transaction_group(&group).expect_err("expired");
    assert!(err.to_string().starts_with("txn dead: round"), "{err}");
    assert!(!err.to_string().contains("overspend"), "{err}");
    assert!(eval.exec.as_ref().unwrap().groups.is_empty());
}

#[test]
fn a_degraded_admission_still_checks_the_group_fees() {
    let (mut eval, group) = degraded_group(Defect::GroupFees);
    let err = eval.transaction_group(&group).expect_err("fees");
    assert!(err.to_string().contains("fees is less than"), "{err}");
    assert!(eval.exec.as_ref().unwrap().groups.is_empty());
}

/// T's member is validly signed by T, but the ledger says T is rekeyed: the
/// authorizer check of a member AFTER the skipped shortfall still runs.
#[test]
fn a_degraded_admission_still_checks_a_later_authorizer() {
    let (mut eval, group) = degraded_group(Defect::WrongAuthorizer);
    let err = eval.transaction_group(&group).expect_err("authorizer");
    assert!(
        err.to_string().contains("should have been authorized by"),
        "{err}"
    );
    assert!(eval.exec.as_ref().unwrap().groups.is_empty());
}

/// `[create (AVM `version`, `names` in its accounts), one pay per sender
/// (each empty)]` on an incomplete evaluator.
fn creation_group(
    version: u8,
    names: &[Address],
    senders: &[&Key],
) -> (SimpleBlockEvaluator, Vec<SignedTransaction>) {
    let s = key(3);
    let r = key(4);
    let (_ledger, mut eval) = evaluator(&[(s.0, funded(5_000_000)), (r.0, funded(1_000_000))]);
    let program =
        algo_avm::assembler::assemble_string(&format!("#pragma version {version}\nint 1\n"))
            .expect("assembles")
            .program;
    let mut create = base_txn(s.0, TxnType::Appl);
    create.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
    create.clear_state_program = Some(serde_bytes::ByteBuf::from(program));
    if !names.is_empty() {
        create.accounts = Some(names.to_vec());
    }
    let mut members = vec![create];
    for (i, k) in senders.iter().enumerate() {
        members.push(pay_txn(k, r.0, 1_000, 20 + i as u8));
    }
    let gid = algo_codec::compute_group_id(&members);
    members.iter_mut().for_each(|m| m.group = gid.0);
    let mut signed = vec![sign(members[0].clone(), &s.1)];
    for (m, k) in members[1..].iter().zip(senders) {
        signed.push(sign(m.clone(), &k.1));
    }
    eval.exec.as_mut().unwrap().incomplete = true;
    (eval, signed)
}

/// Issue #2187: the bound that needs no ledger access. An app CREATION carries
/// its program in the group: version 4 cannot make inner transactions, so a
/// later shortfall is go's overspend; version 5 and up may credit.
#[test]
fn a_creation_below_version_5_cannot_credit_a_later_shortfall() {
    let g = key(7);
    let (mut eval, group) = creation_group(4, &[g.0], &[&g]);
    let err = eval.transaction_group(&group).expect_err("overspend");
    assert!(err.to_string().contains("overspend"), "{err}");
    let (mut eval, group) = creation_group(6, &[g.0], &[&g]);
    eval.transaction_group(&group)
        .expect("a version 6 creation may pay G");
}

/// `[pay, app call, short pay]` on an incomplete evaluator: the call stands
/// between the payment and the short member, so F's shortfall is creditable.
#[test]
fn a_shortfall_after_a_payment_and_an_app_call_is_creditable() {
    let a = key(1);
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let app_id = 904u64;
    let (ledger, mut eval) = evaluator(&[
        (a.0, funded(50_000_000)),
        (s.0, funded(5_000_000)),
        (r.0, funded(1_000_000)),
    ]);
    put_app(&ledger, app_id, s.0, "#pragma version 8\nint 1\n");
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.accounts = Some(vec![f.0]);
    let mut members = [pay_txn(&a, r.0, 1_000, 1), call, pay_txn(&f, r.0, 1_000, 2)];
    let gid = algo_codec::compute_group_id(&members);
    members.iter_mut().for_each(|m| m.group = gid.0);
    let [m0, m1, m2] = members;
    let group = vec![sign(m0, &a.1), sign(m1, &s.1), sign(m2, &f.1)];
    eval.exec.as_mut().unwrap().incomplete = true;
    eval.transaction_group(&group).expect("creditable");
}

/// A plain payment alone never makes a later shortfall creditable.
#[test]
fn a_plain_payment_alone_never_makes_a_shortfall_creditable() {
    let a = key(1);
    let f = key(7);
    let r = key(4);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (r.0, funded(1_000_000))]);
    let mut members = [pay_txn(&a, f.0, 1_000, 1), pay_txn(&f, r.0, 900_000_000, 2)];
    let gid = algo_codec::compute_group_id(&members);
    members.iter_mut().for_each(|m| m.group = gid.0);
    let [m0, m1] = members;
    let group = vec![sign(m0, &a.1), sign(m1, &f.1)];
    eval.exec.as_mut().unwrap().incomplete = true;
    let err = eval.transaction_group(&group).expect_err("overspend");
    assert!(err.to_string().contains("overspend"), "{err}");
}

/// Two applications on one evaluator: 905 is version 2, 906 is version 9.
/// (The degraded rule does not read them: every call to an existing
/// application may credit.)
fn two_app_evaluator() -> SimpleBlockEvaluator {
    let s = key(3);
    let r = key(4);
    let (ledger, eval) = evaluator(&[(s.0, funded(5_000_000)), (r.0, funded(1_000_000))]);
    put_app(&ledger, 905, s.0, "#pragma version 2\nint 1\n");
    put_app(&ledger, 906, s.0, "#pragma version 9\nint 1\n");
    eval
}

/// `[call to `app_id` by S, key(seed) pays R (short)]`; `note` keeps the txids
/// of repeated groups apart.
fn call_then_short_pay(app_id: u64, seed: u8, note: u8) -> Vec<SignedTransaction> {
    let s = key(3);
    let f = key(seed);
    let r = key(4);
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.note = serde_bytes::ByteBuf::from(vec![note]);
    let mut members = [call, pay_txn(&f, r.0, 1_000, note)];
    let gid = algo_codec::compute_group_id(&members);
    members.iter_mut().for_each(|m| m.group = gid.0);
    let [m0, m1] = members;
    vec![sign(m0, &s.1), sign(m1, &f.1)]
}

/// Issue #2187: the per-sender cap. Repeated groups of ONE short sender share
/// one slot (an honest sender is not starved by its own retries).
#[test]
fn one_short_sender_takes_one_cap_slot_however_many_groups() {
    let mut eval = two_app_evaluator();
    eval.exec.as_mut().unwrap().incomplete = true;
    for n in 0..(DEGRADED_SENDER_CAP as u8 + 8) {
        eval.transaction_group(&call_then_short_pay(906, 7, n))
            .expect("the same sender, one slot");
    }
    assert_eq!(eval.exec.as_ref().unwrap().degraded_senders.len(), 1);
}

/// Distinct short senders each take a slot until the cap is spent; then a NEW
/// sender is refused with go's overspend text while an admitted sender still
/// gets through.
#[test]
fn distinct_short_senders_are_capped() {
    let mut eval = two_app_evaluator();
    eval.exec.as_mut().unwrap().incomplete = true;
    for n in 0..DEGRADED_SENDER_CAP as u8 {
        eval.transaction_group(&call_then_short_pay(906, 100 + n, n))
            .expect("within the cap");
    }
    let err = eval
        .transaction_group(&call_then_short_pay(906, 200, 250))
        .expect_err("cap spent for a new sender");
    assert!(err.to_string().contains("overspend"), "{err}");
    assert_eq!(
        eval.exec.as_ref().unwrap().degraded_senders.len(),
        DEGRADED_SENDER_CAP
    );
    eval.transaction_group(&call_then_short_pay(906, 100, 251))
        .expect("an admitted sender keeps its slot");
}

/// A slot is taken only when the group is really admitted: a group refused for
/// another reason (here an expired later member) leaves the cap untouched.
#[test]
fn a_refused_degraded_group_takes_no_slot() {
    let (mut eval, group) = degraded_group(Defect::Expired);
    eval.transaction_group(&group).expect_err("expired");
    assert!(eval.exec.as_ref().unwrap().degraded_senders.is_empty());
}

/// An evaluator with no exec state admits a creditable shortfall as it did
/// before the cap existed (nothing to cap, nothing to panic), and still
/// refuses what the group itself proves harmless (a version 4 creation).
#[test]
fn an_evaluator_without_exec_state_admits_a_creditable_shortfall() {
    let mut eval = two_app_evaluator();
    eval.exec = None;
    for n in 0..(DEGRADED_SENDER_CAP as u8 + 4) {
        eval.transaction_group(&call_then_short_pay(906, 7, n))
            .expect("no exec state, no cap");
    }
    let g = key(7);
    let (mut eval, group) = creation_group(4, &[g.0], &[&g]);
    eval.exec = None;
    let err = eval.transaction_group(&group).expect_err("version 4");
    assert!(err.to_string().contains("overspend"), "{err}");
}

/// The group-local rule, exactly: only a creation of version 4 or older proves
/// a call harmless; an existing application, a version 5 creation and a
/// creation with no readable program may credit.
#[test]
fn the_group_local_rule_is_exact() {
    let mut create = base_txn(key(3).0, TxnType::Appl);
    let program = |v: u8| {
        algo_avm::assembler::assemble_string(&format!("#pragma version {v}\nint 1\n"))
            .expect("assembles")
            .program
    };
    create.approval_program = Some(serde_bytes::ByteBuf::from(program(4)));
    assert!(!SimpleBlockEvaluator::app_call_may_credit(&create));
    create.approval_program = Some(serde_bytes::ByteBuf::from(program(5)));
    assert!(SimpleBlockEvaluator::app_call_may_credit(&create));
    create.approval_program = Some(serde_bytes::ByteBuf::from(Vec::new()));
    assert!(SimpleBlockEvaluator::app_call_may_credit(&create));
    create.approval_program = None;
    assert!(SimpleBlockEvaluator::app_call_may_credit(&create));
    create.application_id = 906;
    create.approval_program = Some(serde_bytes::ByteBuf::from(program(2)));
    assert!(SimpleBlockEvaluator::app_call_may_credit(&create));
}

/// Signs `parts` (transaction, its signer) as one group.
fn signed_parts(parts: Vec<(Transaction, &Key)>) -> Vec<SignedTransaction> {
    let mut txns: Vec<Transaction> = parts.iter().map(|(t, _)| t.clone()).collect();
    let gid = algo_codec::compute_group_id(&txns);
    txns.iter_mut().for_each(|t| t.group = gid.0);
    txns.into_iter()
        .zip(parts)
        .map(|(t, (_, k))| sign(t, &k.1))
        .collect()
}

/// `[call to 906 by S, then `members` (each a payment by a short sender)]`.
fn call_then(members: Vec<(Transaction, &Key)>, call_note: u8) -> Vec<SignedTransaction> {
    let s = key(3);
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = 906;
    call.note = serde_bytes::ByteBuf::from(vec![call_note]);
    let mut parts = vec![(call, &s)];
    parts.extend(members);
    signed_parts(parts)
}

fn degraded_evaluator() -> SimpleBlockEvaluator {
    let mut eval = two_app_evaluator();
    eval.exec.as_mut().unwrap().incomplete = true;
    eval
}

fn unknown_of(eval: &SimpleBlockEvaluator) -> HashSet<Address> {
    (*eval.exec.as_ref().unwrap().unknown_balances).clone()
}

fn balance(eval: &mut SimpleBlockEvaluator, who: &Address) -> u64 {
    eval.try_effective_balance(who).expect("balance")
}

/// Issue #2217: the cheap overlay of an incomplete evaluator does not know the
/// inner credit that justified a degraded admission, so it must not keep the
/// unmodelled member's balance moves (the short sender saturated to 0 and the
/// receiver credited as if the sender could pay were phantom balances). The
/// touched balances are UNKNOWN instead: later checks do not judge them (the
/// block assembly re-runs the real apply and drops what fails), while an
/// address the admission never touched is still judged.
#[test]
fn a_degraded_admission_does_not_leave_phantom_balances() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let r = key(4);
    let f_before = balance(&mut eval, &f.0);
    let r_before = balance(&mut eval, &r.0);
    eval.transaction_group(&call_then_short_pay(906, 7, 1))
        .expect("admitted");
    assert_eq!(
        balance(&mut eval, &f.0),
        f_before,
        "F was not saturated to 0"
    );
    assert_eq!(balance(&mut eval, &r.0), r_before, "R was not credited");
    let unknown = unknown_of(&eval);
    assert!(unknown.contains(&f.0) && unknown.contains(&r.0));
    // F's own later group: the inner credit may well fund it, so a balance
    // the evaluator cannot know does not refuse it.
    eval.transaction_group(&[pay(&f, key(5).0, 1_000, None)])
        .expect("F's later group is not refused on an unknown balance");
    // Negative control: an address the admission never touched is judged.
    eval.transaction_group(&[pay(&key(201), key(5).0, 1_000, None)])
        .expect_err("an untouched short sender is still refused");
}

/// Issue #2217 review: EVERY short member of a group is unmodelled, not only
/// the first one `deferred` keeps: `[call, F pays R1 (short), F pays R2
/// (short)]` credits neither receiver.
#[test]
fn a_degraded_admission_with_two_short_members_credits_neither_receiver() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let (r1, r2) = (key(4), key(5));
    let r2_before = balance(&mut eval, &r2.0);
    let group = call_then(
        vec![
            (pay_txn(&f, r1.0, 1_000, 1), &f),
            (pay_txn(&f, r2.0, 2_000, 2), &f),
        ],
        1,
    );
    eval.transaction_group(&group).expect("admitted");
    assert_eq!(balance(&mut eval, &r2.0), r2_before, "the second receiver");
    assert!(unknown_of(&eval).contains(&r2.0));
}

/// Issue #2217 review: the unknown set propagates inside the group: `[call, F
/// pays R (short), R pays X]` applies R's payment against no balance at all,
/// X gets no phantom credit and is unknown too.
#[test]
fn a_degraded_admission_propagates_unknown_balances_through_the_group() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let (r, x) = (key(4), key(5));
    let x_before = balance(&mut eval, &x.0);
    let r_before = balance(&mut eval, &r.0);
    let group = call_then(
        vec![
            (pay_txn(&f, r.0, 1_000, 1), &f),
            (pay_txn(&r, x.0, 500, 2), &r),
        ],
        2,
    );
    eval.transaction_group(&group).expect("admitted");
    assert_eq!(balance(&mut eval, &x.0), x_before, "X got a phantom credit");
    assert_eq!(balance(&mut eval, &r.0), r_before, "R was debited");
    assert!(unknown_of(&eval).contains(&x.0));
    // Across groups: a later payment BY the now-unknown R credits nobody.
    let y = key(6);
    let y_before = balance(&mut eval, &y.0);
    eval.transaction_group(&[pay(&r, y.0, 300, None)])
        .expect("R is unknown");
    assert_eq!(balance(&mut eval, &y.0), y_before);
    assert!(unknown_of(&eval).contains(&y.0));
}

/// Issue #2217 review: the close target of an unmodelled payment is unknown
/// and receives nothing.
#[test]
fn a_degraded_admission_with_a_close_target_credits_nothing() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let (r, c) = (key(4), key(8));
    let c_before = balance(&mut eval, &c.0);
    let mut close = pay_txn(&f, r.0, 1_000, 3);
    close.close_remainder_to = c.0;
    eval.transaction_group(&call_then(vec![(close, &f)], 3))
        .expect("admitted");
    assert_eq!(balance(&mut eval, &c.0), c_before, "the close target");
    assert!(unknown_of(&eval).contains(&c.0));
}

/// Issue #2217 review: the short member can be an application call (only the
/// fee is short). Its sender, the fee sink and what it references (the
/// application's account, foreign accounts, foreign applications) are unknown;
/// the fee is neither debited nor credited to the sink. Inner-transaction
/// targets beyond the references are not knowable: as for every application
/// call before this change, the overlay never modelled inner effects, and the
/// group-local creditable rule (`app_call_may_credit`) is what admits their
/// consequences.
#[test]
fn a_degraded_admission_with_a_short_app_call_marks_what_the_call_references() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let named = key(9);
    let sink = eval.hdr.fee_sink;
    let sink_before = balance(&mut eval, &sink);
    let mut call = base_txn(f.0, TxnType::Appl);
    call.application_id = 905;
    call.accounts = Some(vec![named.0]);
    call.foreign_apps = Some(vec![906]);
    eval.transaction_group(&call_then(vec![(call, &f)], 4))
        .expect("admitted");
    // S's call is modelled (one 1_000 fee reaches the sink); F's is not.
    assert_eq!(
        balance(&mut eval, &sink),
        sink_before + 1_000,
        "F's fee credit was skipped"
    );
    let unknown = unknown_of(&eval);
    for who in [
        f.0,
        sink,
        named.0,
        Address(algo_ledger::avm_context::app_address(905)),
        Address(algo_ledger::avm_context::app_address(906)),
    ] {
        assert!(unknown.contains(&who), "{who} should be unknown");
    }
}

/// Issue #2217 review: the V41 access list references accounts and
/// applications too (`app_call_may_credit` counts it); a short application call
/// that references them through `access` marks them unknown like the legacy
/// `accounts` / `foreign_apps` fields.
#[test]
fn a_degraded_admission_with_a_short_app_call_marks_its_access_list() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let named = key(9);
    let mut call = base_txn(f.0, TxnType::Appl);
    call.application_id = 905;
    call.access = Some(vec![
        algo_types::ResourceRef {
            address: named.0,
            ..Default::default()
        },
        algo_types::ResourceRef {
            app: 906,
            ..Default::default()
        },
    ]);
    eval.transaction_group(&call_then(vec![(call, &f)], 5))
        .expect("admitted");
    let unknown = unknown_of(&eval);
    for who in [named.0, Address(algo_ledger::avm_context::app_address(906))] {
        assert!(unknown.contains(&who), "{who} should be unknown");
    }
}

/// Issue #2246 (a): only a call that was ITSELF admitted on a shortfall marks
/// what it references. A call sent from an address that is merely unknown (and
/// can pay) is an ordinary degraded-mode call: its references keep their
/// known balances, so a later honest group of a referenced account is judged
/// on them (its shortfall is refused, not taken for a creditable one).
#[test]
fn an_unknown_sender_app_call_without_a_shortfall_does_not_mark_its_references() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    let r = key(4);
    let named = key(9);
    // R (funded with 1_000_000) is made unknown by F's short payment to it,
    // and keeps a real balance it can pay from.
    let group = call_then(vec![(pay_txn(&f, r.0, 1_000, 1), &f)], 2);
    eval.transaction_group(&group).expect("admitted");
    assert!(unknown_of(&eval).contains(&r.0));
    assert!(!unknown_of(&eval).contains(&named.0));
    let mut call = base_txn(r.0, TxnType::Appl);
    call.application_id = 905;
    call.accounts = Some(vec![named.0]);
    call.foreign_apps = Some(vec![906]);
    eval.transaction_group(&[sign(call, &r.1)])
        .expect("R can pay the fee");
    let unknown = unknown_of(&eval);
    for who in [
        named.0,
        Address(algo_ledger::avm_context::app_address(905)),
        Address(algo_ledger::avm_context::app_address(906)),
    ] {
        assert!(!unknown.contains(&who), "{who} must stay known");
    }
    // The verdict that follows: a referenced account's overspend is refused.
    let err = eval
        .transaction_group(&[pay(&named, r.0, 1 << 60, None)])
        .expect_err("named is known, its overspend is refused");
    assert!(err.to_string().contains("overspend"), "{err}");
}

/// Issue #2246 (b): when the evaluator turns incomplete WHILE a group is being
/// admitted (here the admission budget is spent, so `exec_group` gives up on
/// that group), the group's application call was admitted without the real
/// apply: what it references may have been credited by inner transactions, and
/// is marked unknown like the references of any other unmodelled call.
#[test]
fn an_evaluator_that_turns_incomplete_mid_group_marks_the_calls_references() {
    let mut eval = two_app_evaluator();
    eval.exec.as_mut().unwrap().spent = EXEC_ADMISSION_BUDGET;
    assert!(!eval.exec.as_ref().unwrap().incomplete);
    let f = key(3);
    let named = key(9);
    let mut call = base_txn(f.0, TxnType::Appl);
    call.application_id = 905;
    call.accounts = Some(vec![named.0]);
    call.foreign_apps = Some(vec![906]);
    eval.transaction_group(&[sign(call, &f.1)])
        .expect("admitted on the cheap checks");
    assert!(
        eval.exec.as_ref().unwrap().incomplete,
        "the spent budget turned the evaluator incomplete"
    );
    let unknown = unknown_of(&eval);
    for who in [
        named.0,
        Address(algo_ledger::avm_context::app_address(905)),
        Address(algo_ledger::avm_context::app_address(906)),
    ] {
        assert!(unknown.contains(&who), "{who} should be unknown");
    }
    // A group of a complete evaluator that stays complete marks nothing.
    let mut eval = two_app_evaluator();
    let mut call = base_txn(f.0, TxnType::Appl);
    call.application_id = 905;
    call.accounts = Some(vec![named.0]);
    eval.transaction_group(&[sign(call, &f.1)])
        .expect("admitted");
    assert!(unknown_of(&eval).is_empty());
}

/// Issue #2217 review: an evaluator with no exec state (a unit-test fake: the
/// only production constructor, `make_evaluator`, always builds `exec:
/// Some(..)`) cannot carry unknown marks, so it keeps the behaviour from before
/// #2217 entirely: the moves are applied (consistently, not restored with
/// nothing marked), so the receiver holds what the sender paid it.
#[test]
fn an_evaluator_without_exec_state_keeps_the_pre_2217_behaviour() {
    let mut eval = degraded_evaluator();
    eval.exec = None;
    let r = key(4);
    let r_before = balance(&mut eval, &r.0);
    eval.transaction_group(&call_then_short_pay(906, 7, 1))
        .expect("admitted");
    assert_eq!(balance(&mut eval, &r.0), r_before + 1_000);
}

/// Issue #2217 review: EVERY creditable sender of a group takes a cap slot,
/// not only the first one `deferred` keeps: with one slot left, `[call, F1 pays
/// (short), F2 pays (short)]` is refused (it needs two), while a group with one
/// new short sender is admitted and takes the last slot.
#[test]
fn every_creditable_sender_of_a_group_counts_against_the_cap() {
    let mut eval = degraded_evaluator();
    {
        let exec = eval.exec.as_mut().unwrap();
        for n in 0..DEGRADED_SENDER_CAP as u8 - 1 {
            exec.degraded_senders.insert(key(150 + n).0);
        }
    }
    let (f1, f2, r) = (key(7), key(8), key(4));
    let two = call_then(
        vec![
            (pay_txn(&f1, r.0, 1_000, 1), &f1),
            (pay_txn(&f2, r.0, 1_000, 2), &f2),
        ],
        6,
    );
    let err = eval.transaction_group(&two).expect_err("needs two slots");
    assert!(err.to_string().contains("overspend"), "{err}");
    assert_eq!(
        eval.exec.as_ref().unwrap().degraded_senders.len(),
        DEGRADED_SENDER_CAP - 1,
        "a refused group takes no slot"
    );
    let one = call_then(vec![(pay_txn(&f1, r.0, 1_000, 3), &f1)], 7);
    eval.transaction_group(&one).expect("one slot is left");
    assert_eq!(
        eval.exec.as_ref().unwrap().degraded_senders.len(),
        DEGRADED_SENDER_CAP
    );
}

/// Issue #2217 review: the balance read of the restore snapshot can fail; the
/// group is then rolled back like every other failure (overlay and fees as
/// before), not left half applied for the next group. R's pending-rewards
/// arithmetic overflows at a huge rewards level, S's does not.
#[test]
fn a_failing_restore_snapshot_rolls_the_group_back() {
    let s = key(3);
    let r = key(4);
    let (ledger, mut eval) = evaluator(&[
        (s.0, funded(5_000_000)),
        (r.0, funded(20_000_000_000_000_000)),
    ]);
    put_app(&ledger, 906, s.0, "#pragma version 9\nint 1\n");
    eval.exec.as_mut().unwrap().incomplete = true;
    eval.hdr.rewards_level = 1_000_000_000;
    let s_before = balance(&mut eval, &s.0);
    let fees_before = eval.fees_collected;
    eval.transaction_group(&call_then_short_pay(906, 7, 1))
        .expect_err("R's balance cannot be read");
    assert_eq!(
        eval.fees_collected, fees_before,
        "fees were not rolled back"
    );
    assert_eq!(
        balance(&mut eval, &s.0),
        s_before,
        "the modelled member's moves were not rolled back"
    );
    assert!(eval.included_txns.is_empty());
}

/// Issue #2217 review: the minimum balance of an address whose moves were
/// restored is not judged against its stale overlay balance: `[call S, F opts
/// in to an asset]` with F below the minimum and short for the fee (the call's
/// inner payment may fund it) is admitted.
#[test]
fn a_degraded_admission_does_not_judge_the_minimum_of_an_unknown_balance() {
    let mut eval = degraded_evaluator();
    let f = key(7);
    eval.snapshot.accounts.insert(f.0, Some(funded(500)));
    let mut optin = base_txn(f.0, TxnType::Axfer);
    optin.xaid = 7;
    optin.asset_receiver = Some(f.0);
    eval.transaction_group(&call_then(vec![(optin, &f)], 9))
        .expect("admitted: F's minimum is unknown, not judged");
    assert!(unknown_of(&eval).contains(&f.0));
}

/// Issue #2217 review: an admitted group with two short senders takes a slot
/// for EACH of them, so a retry by either does not take a new one.
#[test]
fn a_group_with_two_short_senders_takes_two_cap_slots() {
    let mut eval = degraded_evaluator();
    let (f1, f2, r) = (key(7), key(8), key(4));
    let group = call_then(
        vec![
            (pay_txn(&f1, r.0, 1_000, 1), &f1),
            (pay_txn(&f2, r.0, 1_000, 2), &f2),
        ],
        8,
    );
    eval.transaction_group(&group).expect("admitted");
    let slots = &eval.exec.as_ref().unwrap().degraded_senders;
    assert!(slots.contains(&f1.0) && slots.contains(&f2.0), "{slots:?}");
}

/// Issue #2217 review (item 8): an unknown-balance shortfall is admitted even
/// as a group's first member, so the per-sender cap must bound it: the same
/// cap as for the creditable senders, shared. Cheap admissions are re-verified
/// at block assembly, so what this costs is evaluation budget only.
#[test]
fn unknown_balance_admissions_are_capped_per_sender() {
    let mut eval = degraded_evaluator();
    let senders: Vec<Key> = (0..DEGRADED_SENDER_CAP as u8 + 1)
        .map(|n| key(150 + n))
        .collect();
    for k in &senders {
        let exec = eval.exec.as_mut().unwrap();
        Arc::make_mut(&mut exec.unknown_balances).insert(k.0);
    }
    for (n, k) in senders.iter().take(DEGRADED_SENDER_CAP).enumerate() {
        eval.transaction_group(&[pay(k, key(5).0, 1_000, None)])
            .unwrap_or_else(|e| panic!("sender {n} is within the cap: {e}"));
    }
    let err = eval
        .transaction_group(&[pay(&senders[DEGRADED_SENDER_CAP], key(5).0, 1_000, None)])
        .expect_err("the cap is spent for a new sender");
    assert!(err.to_string().contains("overspend"), "{err}");
    assert_eq!(
        eval.exec.as_ref().unwrap().degraded_senders.len(),
        DEGRADED_SENDER_CAP
    );
}

/// Issue #2187: a stream of creditable overspends against a COMPLETE
/// evaluator never poisons it. The dry runs are charged to the
/// reconciliation budget only; once that is spent the precheck's verdict
/// stands (admitting there would leave the group unevaluated and turn the
/// evaluator incomplete), the admission budget stays untouched, and an
/// honest group still takes the real apply afterwards.
#[test]
fn a_stream_of_creditable_overspends_neither_poisons_nor_exhausts_the_evaluator() {
    let (mut eval, _) = app_then_pay_group(9, false, true, 1_000);
    eval.exec.as_mut().unwrap().reconcile_runs = RECONCILE_MAX_RUNS - 5;
    for n in 0..20u64 {
        let (_, group) = app_then_pay_group(9, false, true, 900_000_000 + n);
        let err = eval.transaction_group(&group).expect_err("overspend");
        assert!(err.to_string().contains("overspend"), "{err}");
        let exec = eval.exec.as_ref().unwrap();
        assert!(!exec.incomplete, "group {n} poisoned the evaluator");
        assert_eq!(exec.spent, Duration::ZERO, "main budget charged");
        assert!(exec.reconcile_runs <= RECONCILE_MAX_RUNS);
    }
    assert_eq!(
        eval.exec.as_ref().unwrap().reconcile_runs,
        RECONCILE_MAX_RUNS,
        "the dry runs stopped at the bound"
    );
    eval.transaction_group(&[pay(&key(3), key(4).0, 1_000, None)])
        .expect("an honest group");
    let exec = eval.exec.as_ref().unwrap();
    assert!(!exec.incomplete);
    assert_eq!(exec.groups.len(), 1, "it took the real-apply path");
}

/// Issue #2187: a complete evaluator with its reconciliation budget spent
/// keeps the precheck's verdict for a creditable shortfall (it must not turn
/// incomplete just to admit a group without evaluating it).
#[test]
fn a_spent_reconciliation_budget_does_not_turn_a_complete_evaluator_incomplete() {
    let (mut eval, group) = app_then_pay_group(8, true, true, 1_000);
    eval.exec.as_mut().unwrap().reconcile_runs = RECONCILE_MAX_RUNS;
    eval.transaction_group(&group)
        .expect_err("the precheck's verdict stands");
    let exec = eval.exec.as_ref().unwrap();
    assert!(!exec.incomplete);
    assert_eq!(exec.spent, Duration::ZERO);
}

/// Issue #2187: the other over-reject shape of the precheck. An inner
/// payment rekeys F back to itself, so a later member authorized by F is
/// valid in go although the ledger says F is rekeyed to the application; the
/// precheck refuses the authorizer, the dry run accepts, the group is
/// admitted and counted.
#[test]
fn an_inner_rekey_before_a_later_member_is_reconciled() {
    let s = key(3);
    let f = key(7);
    let r = key(4);
    let app_id = 904u64;
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));
    let mut f_account = funded(5_000_000);
    f_account.auth_addr = Some(app_addr);
    let (ledger, mut eval) = evaluator(&[
        (s.0, funded(5_000_000)),
        (f.0, f_account),
        (r.0, funded(1_000_000)),
        (app_addr, funded(10_000_000)),
    ]);
    put_app(
        &ledger,
        app_id,
        s.0,
        concat!(
            "#pragma version 8\n",
            "itxn_begin\nint pay\nitxn_field TypeEnum\n",
            "txn Accounts 1\nitxn_field Sender\n",
            "txn Accounts 1\nitxn_field Receiver\n",
            "txn Accounts 1\nitxn_field RekeyTo\n",
            "int 0\nitxn_field Amount\nint 0\nitxn_field Fee\n",
            "itxn_submit\nint 1\n",
        ),
    );
    let mut call = base_txn(s.0, TxnType::Appl);
    call.application_id = app_id;
    call.fee = 2_000;
    call.accounts = Some(vec![f.0]);
    let mut pay_r = pay_txn(&f, r.0, 1_000, 5);
    pay_r.fee = 1_000;
    let gid = algo_codec::compute_group_id(&[call.clone(), pay_r.clone()]);
    call.group = gid.0;
    pay_r.group = gid.0;
    let group = vec![sign(call, &s.1), sign(pay_r, &f.1)];
    let before = PRECHECK_OVER_REJECTS.load(std::sync::atomic::Ordering::Relaxed);
    eval.transaction_group(&group)
        .expect("go accepts it: the inner rekey clears F's authorizer");
    assert!(PRECHECK_OVER_REJECTS.load(std::sync::atomic::Ordering::Relaxed) > before);
}

/// The count-based bound: with the run count spent the precheck's verdict
/// stands, deterministically.
#[test]
fn reconciliation_is_bounded_by_a_run_count() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    eval.exec.as_mut().unwrap().reconcile_runs = RECONCILE_MAX_RUNS;
    let group = rejected_late_group(&a, &b, 1);
    eval.transaction_group(&group)
        .expect_err("member 1 is early");
    assert_eq!(
        eval.exec.as_ref().unwrap().reconcile_runs,
        RECONCILE_MAX_RUNS
    );
    let group = rejected_late_group(&a, &b, 2);
    eval.exec.as_mut().unwrap().reconcile_runs = 0;
    eval.transaction_group(&group)
        .expect_err("member 1 is early");
    assert_eq!(eval.exec.as_ref().unwrap().reconcile_runs, 1);
}

/// The evaluator holds every pending txid, so a pending transaction is a
/// duplicate after the pool rebuilt its evaluator (go's
/// `recomputeBlockEvaluator` re-ingests the pending groups).
#[test]
fn a_pending_txid_is_still_a_duplicate_after_the_pool_recomputes() {
    use algo_pool::error::{classify_pool_error, PoolErrorTag};
    let a = key(1);
    let b = key(2);
    let (_ledger, pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let stx = pay(&a, b.0, 1_000_000, None);
    pool.remember_one(stx.clone()).expect("remembered");
    let block = algo_types::Block {
        round: Round(0),
        ..algo_types::Block::default()
    };
    pool.on_new_block(&block, &std::collections::HashSet::new());
    assert_eq!(pool.pending_count(), 1, "re-fed into the new evaluator");
    let err = pool.remember_one(stx.clone()).expect_err("duplicate");
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TxIdEval, "{err}");
    assert_eq!(
        err.to_string(),
        format!(
            "TransactionPool.Remember: transaction already in ledger: {}",
            txid(&stx)
        )
    );
    // go's Reset forgets everything: the same transaction is new again.
    pool.reset();
    pool.ensure_evaluator_primed();
    pool.remember_one(stx).expect("a reset pool forgot it");
}

/// An incomplete evaluator (its real apply gave up) still runs `checkDup`
/// against the overlay it keeps for every admitted group, so the evaluator
/// path alone rejects a pending duplicate.
#[test]
fn an_incomplete_evaluator_still_rejects_a_pending_duplicate() {
    let a = key(1);
    let b = key(2);
    let (_ledger, mut eval) = evaluator(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))]);
    let stx = pay(&a, b.0, 1_000_000, None);
    eval.transaction_group(std::slice::from_ref(&stx))
        .expect("admitted");
    eval.exec.as_mut().unwrap().incomplete = true;
    let err = eval
        .transaction_group(std::slice::from_ref(&stx))
        .expect_err("duplicate");
    assert_eq!(
        err.to_string(),
        format!("transaction already in ledger: {}", txid(&stx))
    );
    assert!(matches!(
        err,
        algo_error::AlgoError::Rejected {
            class: algo_error::RejectClass::TxidInLedger { in_block: true },
            ..
        }
    ));
}

/// The live ledger lease table subsumes the evaluator's creation-time
/// snapshot: a lease known at creation and one committed later are both
/// rejected, with the same verdict.
#[test]
fn the_live_lease_table_gives_the_snapshot_verdict() {
    use algo_ledger::store_trait::LedgerStore;
    let a = key(1);
    let b = key(2);
    let early = [0x61; 32];
    let late = [0x62; 32];
    let (ledger, _pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    ledger.lock().unwrap().record_lease(&a.0, &early, 500);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    ledger.lock().unwrap().record_lease(&a.0, &late, 500);
    for lease in [early, late] {
        let stx = leased_pay(&a, b.0, lease, 6);
        let err = eval
            .test_transaction_group(std::slice::from_ref(&stx))
            .expect_err("live lease");
        assert_eq!(
            err.to_string(),
            algo_ledger::check_dup::lease_in_ledger_error(
                algo_codec::compute_txn_id(&stx.txn),
                &a.0,
                &lease,
                false
            )
            .to_string()
        );
    }
}

/// The txids of `len` payset transactions of `eval` from `start`, hashed as
/// the txtail records them (what a smuggled-in group carries).
fn carried_txids(eval: &SimpleBlockEvaluator, start: usize, len: usize) -> Vec<algo_types::Digest> {
    algo_codec::payset_txids_with_rule(&eval.included_txns[start..start + len], &eval.genesis_rule())
}

/// Admission hands every group's txids (hashed once for `checkDup`) to the
/// scratch passes of block assembly (issue #2132): they are exactly what
/// hashing the assembled payset again would give, and the proposed block is
/// built from them.
#[test]
fn admitted_groups_carry_the_txids_the_scratch_passes_reuse() {
    let a = key(1);
    let b = key(2);
    let (ledger, _pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    eval.transaction_group(&[leased_pay(&a, b.0, [0x71; 32], 7)])
        .expect("first group");
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
    eval.transaction_group(&group)
        .expect("a second, two-member group");
    let supplied = ExecGroup::flatten_txids(&eval.exec.as_ref().unwrap().groups)
        .expect("every admitted group carries its txids");
    assert_eq!(supplied.len(), 3);
    let block = algo_types::Block {
        payset: eval.included_txns.clone(),
        ..Default::default()
    };
    let rehashed = algo_codec::block_txids_with_rule(&block, &eval.genesis_rule());
    assert_eq!(supplied, rehashed);
    // And the assembly (which feeds them to every scratch pass) still
    // produces the whole payset.
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 3);
}

/// The carried txids are the ones the txtail rebuilds through the block's
/// genesis rule, whichever of the transaction's genesis id / hash is present
/// (issue #2132): a transaction without a genesis id, one without a genesis
/// hash, and one with neither are admitted (or refused) by admission as it
/// decides, and every ADMITTED group's carried txids equal a rehash of the
/// assembled payset (debug builds also assert this in every scratch pass).
#[test]
fn carried_txids_equal_the_rehash_for_transactions_without_genesis_fields() {
    let a = key(1);
    let b = key(2);
    let (ledger, _pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    let variant = |amount: u64, with_id: bool, with_hash: bool| {
        let mut t = base_txn(a.0, TxnType::Pay);
        t.receiver = b.0;
        t.amount = amount;
        if !with_id {
            t.genesis_id = String::new();
        }
        if !with_hash {
            t.genesis_hash = [0u8; 32];
        }
        sign(t, &a.1)
    };
    let mut admitted = 0;
    for (amount, with_id, with_hash) in [
        (1_000u64, true, true),
        (2_000, false, true),
        (3_000, true, false),
        (4_000, false, false),
    ] {
        if eval
            .transaction_group(&[variant(amount, with_id, with_hash)])
            .is_ok()
        {
            admitted += 1;
        }
    }
    assert!(admitted >= 2, "the id-less variant must be admitted too");
    let supplied = ExecGroup::flatten_txids(&eval.exec.as_ref().unwrap().groups)
        .expect("every admitted group carries its txids");
    assert_eq!(supplied.len(), admitted);
    let block = algo_types::Block {
        payset: eval.included_txns.clone(),
        ..Default::default()
    };
    assert_eq!(
        supplied,
        algo_codec::block_txids_with_rule(&block, &eval.genesis_rule())
    );
    assert_eq!(
        eval.generate_block(&[]).expect("generate_block").payset.len(),
        admitted
    );
}

/// Dropping or truncating groups, and the failure / bisection passes of
/// assembly, keep every group's txids aligned with the payset (issue #2132):
/// the table still flattens (no fallback to hashing) and equals a rehash.
#[test]
fn removing_and_truncating_groups_keeps_the_txids_aligned() {
    let a = key(1);
    let b = key(2);
    let (ledger, _pool) = fixture(&[(a.0, funded(50_000_000)), (b.0, funded(1_000_000))], &[]);
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    for note in 1..=4u8 {
        eval.transaction_group(&[leased_pay(&a, b.0, [0x80 + note; 32], note)])
            .expect("admitted");
    }
    let mut groups = std::mem::take(&mut eval.exec.as_mut().unwrap().groups);
    let mut payset = eval.included_txns.clone();
    let rehash = |payset: &[SignedTransaction]| {
        algo_codec::payset_txids_with_rule(payset, &eval.genesis_rule())
    };
    let all = ExecGroup::flatten_txids(&groups).expect("all carried");
    assert_eq!(all, rehash(&payset));

    // Drop a MIDDLE group: the later group's txids shift with it.
    SimpleBlockEvaluator::remove_group(&mut groups, &mut payset, 1);
    let after_remove = ExecGroup::flatten_txids(&groups).expect("still carried");
    assert_eq!(after_remove.len(), 3);
    assert_eq!(after_remove, rehash(&payset));
    assert!(!after_remove.contains(&all[1]), "the dropped txid is gone");

    // Truncate to a prefix, as the oversize and failure passes do.
    SimpleBlockEvaluator::truncate_groups(&mut groups, &mut payset, 2);
    let after_truncate = ExecGroup::flatten_txids(&groups).expect("still carried");
    assert_eq!(after_truncate, vec![all[0], all[2]]);
    assert_eq!(after_truncate, rehash(&payset));

    // A bisection probe evaluates a prefix of the groups.
    assert_eq!(
        ExecGroup::flatten_txids(&groups[..1]).expect("prefix"),
        vec![all[0]]
    );
    // A group added without its txids makes the pass hash instead.
    groups[1].txids = None;
    assert!(ExecGroup::flatten_txids(&groups).is_none());
}

/// A bad group smuggled into the MIDDLE of the admitted groups is dropped by
/// the failure pass and the retry still gets aligned txids: every pass (debug
/// builds assert it) is handed what a rehash of ITS payset gives.
#[test]
fn a_failing_middle_group_keeps_the_retry_pass_txids_aligned() {
    let a = key(1);
    let b = key(2);
    let c = key(3);
    let (ledger, _pool) = fixture(
        &[
            (a.0, funded(50_000_000)),
            (b.0, funded(1_000_000)),
            (c.0, funded(5_000_000)),
        ],
        &[],
    );
    let adapter = PoolLedgerAdapter::new(ledger.clone());
    let mut eval = adapter
        .start_simple_evaluator(genesis_header(), 0, 0)
        .expect("start_evaluator");
    eval.transaction_group(&[leased_pay(&a, b.0, [0x91; 32], 1)])
        .expect("first");
    eval.transaction_group(&[leased_pay(&a, b.0, [0x92; 32], 2)])
        .expect("second");
    // A pay from an account that does not exist cannot apply.
    let ghost = key(9);
    let bad = {
        let mut t = base_txn(ghost.0, TxnType::Pay);
        t.receiver = b.0;
        t.amount = 1;
        sign(t, &ghost.1)
    };
    let mut stib = bad;
    eval.genesis_rule().strip(&mut stib);
    let at = 1usize;
    eval.included_txns.insert(at, stib);
    let txids = Some(carried_txids(&eval, at, 1));
    {
        let exec = eval.exec.as_mut().unwrap();
        for g in exec.groups.iter_mut().skip(1) {
            g.start += 1;
        }
        exec.groups.insert(
            1,
            ExecGroup {
                start: at,
                len: 1,
                fees: 1_000,
                txids,
            },
        );
    }
    eval.fees_collected += 1_000;
    let block = eval.generate_block(&[]).expect("generate_block");
    assert_eq!(block.payset.len(), 2, "the bad middle group was dropped");
    assert!(
        eval.exec.as_ref().unwrap().last_passes >= 2,
        "a failing pass and a clean retry ran"
    );
}

/// `go_rejection` decides from the error's TYPE whether an evaluator error is
/// already in go's framed form, not from its text (issue #2133): an error
/// whose text merely starts like a framed one is still framed (once), and each
/// typed pre-framed rejection passes through unchanged with its pool tag.
#[test]
fn go_rejection_decides_framing_from_the_type_not_the_text() {
    use algo_error::{AlgoError, RejectClass};
    let txid = "TXID".to_string();

    // Looks framed, is not: an untyped error whose text starts like go's frame.
    for lookalike in [
        AlgoError::Rejected {
            source: None,
            message: format!("transaction {txid}: not really framed"),
            class: RejectClass::Other,
        },
        AlgoError::Ledger {
            message: format!("transaction {txid}: not really framed"),
        },
    ] {
        let out = super::go_rejection(&txid, lookalike);
        assert_eq!(
            out.to_string(),
            format!("transaction {txid}: transaction {txid}: not really framed"),
            "framed once more, by type"
        );
    }

    // Typed pre-framed rejections pass through untouched.
    let authorizer = algo_error::authorizer_rejection(&txid, "ADDR1", "ADDR2");
    let text = authorizer.to_string();
    assert_eq!(
        text,
        "transaction TXID: should have been authorized by ADDR1 but was actually authorized by ADDR2"
    );
    assert_eq!(super::go_rejection(&txid, authorizer).to_string(), text);

    let framed_min = algo_error::frame_min_balance(
        algo_error::min_balance_rejected("ADDR", 50, 100_000, 0),
        || txid.clone(),
    );
    let text = framed_min.to_string();
    let out = super::go_rejection(&txid, framed_min);
    assert_eq!(out.to_string(), text);
    assert!(matches!(
        out,
        AlgoError::Rejected {
            class: RejectClass::Framed(algo_error::FramedKind::MinBalance),
            ..
        }
    ));

    // A `Framed(Other)` rejection (the max-minimum-balance one) passes through.
    let framed_other = algo_error::framed_rejection(&txid, "account A would use too much space");
    let text = framed_other.to_string();
    assert_eq!(text, "transaction TXID: account A would use too much space");
    let out = super::go_rejection(&txid, framed_other);
    assert_eq!(out.to_string(), text);
    assert!(matches!(
        out,
        AlgoError::Rejected {
            class: RejectClass::Framed(algo_error::FramedKind::Other),
            ..
        }
    ));

    // A framed rejection reached through an `AvmLogicSig` wrapper (which
    // `reason_of` looks through) keeps its single frame and its framed class.
    let nested = AlgoError::AvmLogicSig {
        source: Box::new(algo_error::authorizer_rejection(&txid, "ADDR1", "ADDR2")),
        message: "logic sig failure".into(),
        pc: 0,
        group_index: 0,
        app_index: None,
        eval_states: Vec::new(),
    };
    let out = super::go_rejection(&txid, nested);
    assert_eq!(
        out.to_string(),
        "transaction TXID: should have been authorized by ADDR1 but was actually authorized by ADDR2",
        "no second frame"
    );
    assert!(matches!(
        out,
        AlgoError::Rejected {
            class: RejectClass::Framed(_),
            ..
        }
    ));

    // An UNframed typed min-balance rejection is framed once, tag kept.
    let out = super::go_rejection(&txid, algo_error::min_balance_rejected("ADDR", 50, 100_000, 0));
    assert_eq!(
        out.to_string(),
        "transaction TXID: account ADDR balance 50 below min 100000 (0 assets)"
    );
}
