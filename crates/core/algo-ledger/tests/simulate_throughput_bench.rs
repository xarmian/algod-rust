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

//! Issue #2162 -- per-request cost of `POST /v2/transactions/simulate` below
//! the HTTP layer: one unsigned 1-microalgo payment (`allow-empty-signatures`,
//! the `rest` bench tier's request) simulated against a file-backed
//! `SqliteLedger` under the same mutex the node interface holds.
//!
//! `#[ignore]`d micro benchmark (run it in release):
//! `cargo test --release -p algo-ledger --test simulate_throughput_bench -- --ignored --nocapture`.
//! `SIM_BENCH_CALLS` (default 20000) and `SIM_BENCH_THREADS` (default 16).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerStore as _, SqliteLedger};
use algo_types::{AccountData, Address, Block, Round, SignedTransaction, TxnType};

const SENDER: Address = Address([0x11; 32]);
const RECEIVER: Address = Address([0x22; 32]);
const FEE_SINK: Address = Address([3; 32]);

fn chain_block(round: u64) -> Block {
    Block {
        round: Round(round),
        fee_sink: FEE_SINK,
        proposer: Address([9; 32]),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        genesis_hash: [0x6E; 32],
        ..Block::default()
    }
}

fn ledger(dir: &std::path::Path) -> SqliteLedger {
    let mut l = SqliteLedger::open_with_prefix(&dir.join("ledger")).unwrap();
    l.set_genesis_hash([0x6E; 32]);
    l.begin_block().unwrap();
    algo_ledger::apply::pool_fixtures::fund_test_rewards_pool(&mut l);
    for who in [SENDER, RECEIVER, FEE_SINK] {
        l.set_account(
            &who,
            AccountData {
                micro_algos: 1_000_000_000,
                ..Default::default()
            },
        );
    }
    l.commit_block().unwrap();
    for round in 1..=5 {
        let block = chain_block(round);
        let hdr = algo_codec::canonical_encode_block_header_from_block(&block);
        let blk = algo_codec::encode_block(&block).unwrap();
        l.begin_block().unwrap();
        l.put_block(round, &block.current_protocol, &hdr, &blk)
            .unwrap();
        l.put_block_cert(round, b"cert").unwrap();
        algo_ledger::apply::apply_block_executing_app_calls_for(&mut l, &block, true).unwrap();
        l.commit_block().unwrap();
    }
    l
}

fn request(round: u64) -> SimulationRequest {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = TxnType::Pay;
    stx.txn.sender = SENDER;
    stx.txn.receiver = RECEIVER;
    stx.txn.amount = 1;
    stx.txn.fee = 1000;
    stx.txn.first_valid = Round(round);
    stx.txn.last_valid = Round(round + 1000);
    stx.txn.genesis_hash = [0x6E; 32];
    SimulationRequest {
        round: None,
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        allow_more_logging: false,
        allow_unnamed_resources: false,
        extra_opcode_budget: 0,
        trace_config: Default::default(),
        fix_signers: false,
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn simulate_one_payment_per_request_cost() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(ledger(dir.path())));
    let round = ledger.lock().unwrap().current_round().0;
    let calls = env_usize("SIM_BENCH_CALLS", 20_000);
    let threads = env_usize("SIM_BENCH_THREADS", 16);

    // Sanity: the request simulates cleanly.
    {
        let mut l = ledger.lock().unwrap();
        let r = Simulator::new(&mut *l).simulate(request(round)).unwrap();
        assert!(
            r.txn_groups[0].failure_message.is_none(),
            "{:?}",
            r.txn_groups[0].failure_message
        );
    }
    // Warm up, then single-threaded cost.
    for _ in 0..500 {
        let mut l = ledger.lock().unwrap();
        Simulator::new(&mut *l).simulate(request(round)).unwrap();
    }
    let t = Instant::now();
    for _ in 0..calls {
        let mut l = ledger.lock().unwrap();
        Simulator::new(&mut *l).simulate(request(round)).unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "SIMBENCH single-thread: {calls} calls in {secs:.3}s = {:.0} req/s, {:.1} us/call",
        calls as f64 / secs,
        secs * 1e6 / calls as f64
    );

    // Where the per-call time goes: the store pieces the simulator uses.
    {
        let mut l = ledger.lock().unwrap();
        let t = Instant::now();
        for _ in 0..calls {
            let snap = l.snapshot(&[SENDER, RECEIVER, FEE_SINK]);
            l.restore_snapshot(snap);
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / calls as f64;
        println!("SIMBENCH piece snapshot+restore (no writes): {us:.1} us");
        let t = Instant::now();
        for _ in 0..calls {
            let snap = l.snapshot(&[SENDER, RECEIVER, FEE_SINK]);
            let mut a = l.get_account(&SENDER).unwrap();
            a.micro_algos -= 1;
            l.set_account(&SENDER, a);
            let mut f = l.get_account(&FEE_SINK).unwrap();
            f.micro_algos += 1;
            l.set_account(&FEE_SINK, f);
            l.restore_snapshot(snap);
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / calls as f64;
        println!("SIMBENCH piece snapshot+2 account writes+restore: {us:.1} us");
        let t = Instant::now();
        for _ in 0..calls {
            let _ = l.get_block_header(round).unwrap();
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / calls as f64;
        println!("SIMBENCH piece get_block_header: {us:.1} us");
        let t = Instant::now();
        for _ in 0..calls {
            let _ = l.get_account(&SENDER);
            let _ = l.get_account(&RECEIVER);
            let _ = l.total_reward_units();
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / calls as f64;
        println!("SIMBENCH piece 2 get_account + total_reward_units: {us:.1} us");
    }

    // The server's shape: many requests contending for the one ledger mutex.
    let per = calls / threads;
    let t = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let ledger = Arc::clone(&ledger);
            std::thread::spawn(move || {
                for _ in 0..per {
                    let mut l = ledger.lock().unwrap();
                    Simulator::new(&mut *l).simulate(request(round)).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "SIMBENCH {threads} threads on one ledger mutex: {} calls in {secs:.3}s = {:.0} req/s",
        per * threads,
        (per * threads) as f64 / secs
    );
}
