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

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use algo_ledger::{apply_pay, LedgerStore, SqliteLedger};
use algo_types::{AccountData, Address, SignedTransaction};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a fresh SqliteLedger backed by a temporary file.
/// Returns (ledger, temp_dir) — the temp_dir must be kept alive to avoid cleanup.
fn fresh_sqlite_ledger() -> (SqliteLedger, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("ledger.sqlite");
    let ledger = SqliteLedger::open(&path).expect("open sqlite ledger");
    (ledger, dir)
}

fn make_address(byte: u8) -> Address {
    Address([byte; 32])
}

fn make_account(balance: u64) -> AccountData {
    AccountData {
        micro_algos: balance,
        ..AccountData::default()
    }
}

fn pay_txn(sender: Address, receiver: Address, amount: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = sender;
    stx.txn.receiver = receiver;
    stx.txn.amount = amount;
    stx.txn.fee = 1_000;
    stx
}

// ---------------------------------------------------------------------------
// Benchmark: SQLite ledger open
// ---------------------------------------------------------------------------
fn bench_sqlite_open(c: &mut Criterion) {
    c.bench_function("sqlite_ledger_open", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("create temp dir");
            let path = dir.path().join("ledger.sqlite");
            let _ledger = SqliteLedger::open(black_box(&path)).expect("open");
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: account write then read
// ---------------------------------------------------------------------------
fn bench_account_read_write(c: &mut Criterion) {
    let addr = make_address(1);
    let account = make_account(1_000_000);

    c.bench_function("sqlite_account_write", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        b.iter(|| {
            ledger.set_account(black_box(&addr), black_box(account.clone()));
        });
    });

    c.bench_function("sqlite_account_read", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        ledger.set_account(&addr, account.clone());
        b.iter(|| {
            let _ = ledger.get_account(black_box(&addr));
        });
    });

    c.bench_function("sqlite_account_write_then_read", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        b.iter(|| {
            ledger.set_account(black_box(&addr), black_box(account.clone()));
            let _ = ledger.get_account(black_box(&addr));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: block storage (put_block + get_block_data)
// ---------------------------------------------------------------------------
fn bench_block_storage(c: &mut Criterion) {
    let proto =
        "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb4";
    let hdr_data = vec![0xAAu8; 256];
    let blk_data = vec![0xBBu8; 4096];

    c.bench_function("sqlite_put_block", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        let mut round = 0u64;
        b.iter(|| {
            ledger
                .put_block(
                    black_box(round),
                    black_box(proto),
                    black_box(&hdr_data),
                    black_box(&blk_data),
                )
                .expect("put_block");
            round += 1;
        });
    });

    c.bench_function("sqlite_get_block_data", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        // Pre-populate a block at round 1.
        ledger
            .put_block(1, proto, &hdr_data, &blk_data)
            .expect("put_block");
        b.iter(|| {
            let _ = ledger.get_block_data(black_box(1)).expect("get_block_data");
        });
    });

    c.bench_function("sqlite_put_then_get_block", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        let mut round = 0u64;
        b.iter(|| {
            ledger
                .put_block(
                    black_box(round),
                    black_box(proto),
                    black_box(&hdr_data),
                    black_box(&blk_data),
                )
                .expect("put_block");
            let _ = ledger
                .get_block_data(black_box(round))
                .expect("get_block_data");
            round += 1;
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: apply_pay (payment transaction against SQLite-backed ledger)
// ---------------------------------------------------------------------------
fn bench_apply_pay(c: &mut Criterion) {
    let sender = make_address(1);
    let receiver = make_address(2);
    let fee_sink = make_address(3);

    c.bench_function("sqlite_apply_pay", |b| {
        let (mut ledger, _dir) = fresh_sqlite_ledger();
        // Seed accounts: sender with enough balance, receiver and fee_sink.
        ledger.set_account(&sender, make_account(1_000_000_000));
        ledger.set_account(&receiver, make_account(0));
        ledger.set_account(&fee_sink, make_account(0));

        let stx = pay_txn(sender, receiver, 1_000);

        b.iter(|| {
            // Reset sender balance each iteration to avoid exhaustion.
            ledger.set_account(&sender, make_account(1_000_000_000));
            let _ = apply_pay(black_box(&mut ledger), black_box(&stx.txn)).expect("apply_pay");
        });
    });

    // Also benchmark apply_pay on in-memory LedgerState for comparison.
    c.bench_function("inmemory_apply_pay", |b| {
        let mut state = algo_ledger::LedgerState::new();
        state.set_fee_sink(fee_sink);
        state.set_account(&sender, make_account(1_000_000_000));
        state.set_account(&receiver, make_account(0));
        state.set_account(&fee_sink, make_account(0));

        let stx = pay_txn(sender, receiver, 1_000);

        b.iter(|| {
            state.set_account(&sender, make_account(1_000_000_000));
            let _ = apply_pay(black_box(&mut state), black_box(&stx.txn)).expect("apply_pay");
        });
    });
}

criterion_group!(
    benches,
    bench_sqlite_open,
    bench_account_read_write,
    bench_block_storage,
    bench_apply_pay,
);
criterion_main!(benches);
