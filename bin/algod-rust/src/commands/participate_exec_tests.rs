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
    let text = err.to_string();
    assert!(
        text.starts_with(&format!(
            "TransactionPool.Remember: transaction {}: ",
            txid(&stx)
        )),
        "{text}"
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
    assert!(
        text.contains("cannot close: 1 outstanding assets"),
        "{text}"
    );
    assert!(pool.pending_tx_groups().is_empty());
}

#[test]
fn pool_rejects_a_rejecting_approval_program() {
    let s = key(3);
    let app_id = 901u64;
    let (ledger, pool) = fixture(&[(s.0, funded(5_000_000))], &[]);
    put_app(&ledger, app_id, s.0, "#pragma version 8\nint 0\n");
    let err = pool
        .remember_one(app_call(&s, app_id, vec![], 1_000))
        .expect_err("program rejects");
    assert!(err
        .to_string()
        .starts_with("TransactionPool.Remember: transaction "));
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
        bytes: 100,
        fees: 1_000,
    });
    eval.fees_collected += 1_000;
    let block = eval.generate_block(&[]).expect("generate_block");

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
