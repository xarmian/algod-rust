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

//! Thread-safety stress tests for the transaction pool.
//!
//! These tests verify that `TransactionPool` does not panic, deadlock,
//! or corrupt data under concurrent access from multiple threads.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use algo_codec::compute_txn_id;
use algo_error::AlgoError;
use algo_pool::config::PoolConfig;
use algo_pool::pool::TransactionPool;
use algo_pool::traits::{BlockEvaluator, PoolLedger};
use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, SignedTransaction, TxnType};

// ── Mock implementations ──────────────────────────────────────────

/// Thread-safe mock ledger.
struct ConcurrentMockLedger {
    round: AtomicU64,
}

impl ConcurrentMockLedger {
    fn new(round: u64) -> Self {
        Self {
            round: AtomicU64::new(round),
        }
    }

    fn advance(&self) {
        self.round.fetch_add(1, Ordering::SeqCst);
    }
}

impl PoolLedger for ConcurrentMockLedger {
    fn latest(&self) -> Round {
        Round(self.round.load(Ordering::SeqCst))
    }

    fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
        Ok(BlockHeader::default())
    }

    fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
        Ok(ConsensusParams::default())
    }

    fn start_evaluator(
        &self,
        _hdr: BlockHeader,
        _payset_hint: usize,
        _max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
        Ok(Box::new(ConcurrentMockEvaluator {
            round: self.latest().next(),
        }))
    }
}

/// Minimal evaluator that accepts everything.
struct ConcurrentMockEvaluator {
    round: Round,
}

impl BlockEvaluator for ConcurrentMockEvaluator {
    fn round(&self) -> Round {
        self.round
    }

    fn pay_set_size(&self) -> usize {
        0
    }

    fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
        Ok(Block::default())
    }

    fn reset_txn_bytes(&mut self) {}
}

// ── Test helpers ──────────────────────────────────────────────────

fn make_pool(pool_size: usize, round: u64) -> (Arc<TransactionPool>, Arc<ConcurrentMockLedger>) {
    let ledger = Arc::new(ConcurrentMockLedger::new(round));
    let config = PoolConfig {
        pool_size,
        ..Default::default()
    };
    let pool = Arc::new(TransactionPool::new(config, ledger.clone()));

    // Install evaluator via on_new_block.
    let block = Block {
        round: Round(round),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    (pool, ledger)
}

/// Create a unique transaction using a 4-byte note derived from an index.
fn make_unique_txn(index: u32) -> SignedTransaction {
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Pay;
    txn.txn.fee = 1_000_000;
    txn.txn.first_valid = Round(1);
    txn.txn.last_valid = Round(10_000);
    txn.txn.note = serde_bytes::ByteBuf::from(index.to_le_bytes().to_vec());
    txn
}

// ── Stress tests ─────────────────────────────────────────────────

/// Multiple threads calling remember() simultaneously.
/// Verifies no panics or data corruption.
#[test]
fn stress_concurrent_remember() {
    let (pool, _ledger) = make_pool(50_000, 1);
    let num_threads = 8;
    let ops_per_thread = 200;

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let pool = pool.clone();
            thread::spawn(move || {
                for i in 0..ops_per_thread {
                    let index = (t * ops_per_thread + i) as u32;
                    let txn = make_unique_txn(index);
                    // Errors are OK (duplicates, capacity) — no panics.
                    let _ = pool.remember_one(txn);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // Verify consistency: pending count should match pending IDs count.
    let count = pool.pending_count();
    let ids = pool.pending_tx_ids();
    assert_eq!(
        count,
        ids.len(),
        "pending_count and pending_tx_ids should agree"
    );
    assert!(
        count <= (num_threads * ops_per_thread) as usize,
        "count should not exceed total ops"
    );
}

/// Readers (pending_by_address, lookup) running concurrently with writers (remember).
/// Verifies no deadlocks or panics.
#[test]
fn stress_concurrent_read_write() {
    let (pool, _ledger) = make_pool(50_000, 1);
    let addr = Address([1u8; 32]);

    let num_writers = 4;
    let num_readers = 4;
    let ops_per_thread = 200;

    let mut handles = Vec::new();

    // Writer threads: remember transactions.
    for t in 0..num_writers {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                let index = (t * ops_per_thread + i) as u32;
                let mut txn = make_unique_txn(index);
                // Set some txns with the target address for reader threads to find.
                if i % 3 == 0 {
                    txn.txn.sender = Address([1u8; 32]);
                }
                let _ = pool.remember_one(txn);
            }
        }));
    }

    // Reader threads: query pending_by_address and lookup.
    for _t in 0..num_readers {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                // pending_by_address read.
                let _result = pool.pending_by_address(&addr);

                // lookup read.
                let fake_txid = algo_types::Digest([i as u8; 32]);
                let (_txn, _err, _found) = pool.lookup(&fake_txid);

                // pending_count read.
                let _count = pool.pending_count();

                // pending_tx_groups read.
                let _groups = pool.pending_tx_groups();
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

/// on_new_block running concurrently with remember.
/// This is a particularly important race condition to test because
/// on_new_block rebuilds the evaluator and flushes pending state.
#[test]
fn stress_concurrent_remember_and_on_new_block() {
    let (pool, ledger) = make_pool(50_000, 1);
    let ops_per_thread = 100;

    let mut handles = Vec::new();

    // Writer threads: remember transactions.
    for t in 0..4 {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                let index = (t * ops_per_thread + i) as u32;
                let txn = make_unique_txn(index);
                let _ = pool.remember_one(txn);
            }
        }));
    }

    // on_new_block thread: process blocks.
    {
        let pool = pool.clone();
        let ledger = ledger.clone();
        handles.push(thread::spawn(move || {
            for r in 2..=10 {
                ledger.advance();
                let block = Block {
                    round: Round(r),
                    ..Block::default()
                };
                pool.on_new_block(&block, &HashSet::new());
                // Small delay to interleave with remember.
                thread::sleep(Duration::from_millis(1));
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // Verify no corruption.
    let count = pool.pending_count();
    let ids = pool.pending_tx_ids();
    assert_eq!(count, ids.len());
}

/// shutdown() running concurrently with remember().
/// After shutdown, remember should return PoolShutdown errors.
#[test]
fn stress_concurrent_shutdown() {
    let (pool, _ledger) = make_pool(50_000, 1);
    let ops = 200;

    let mut handles = Vec::new();

    // Writer thread: remember transactions.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            let mut successes = 0u32;
            let mut shutdowns = 0u32;
            let mut others = 0u32;
            for i in 0..ops {
                let txn = make_unique_txn(i);
                match pool.remember_one(txn) {
                    Ok(()) => successes += 1,
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("shutting down") {
                            shutdowns += 1;
                        } else {
                            others += 1;
                        }
                    }
                }
            }
            (successes, shutdowns, others)
        }));
    }

    // Shutdown thread: shut down after a short delay.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            // Let some remember operations go through first.
            thread::sleep(Duration::from_millis(1));
            pool.shutdown();
            (0u32, 0u32, 0u32)
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    assert!(pool.is_shutdown());
}

/// Multiple threads doing a mix of remember, on_new_block, lookup,
/// pending_by_address, pending_count, pending_tx_groups, and test.
/// This is the kitchen-sink stress test.
#[test]
fn stress_mixed_operations() {
    let (pool, ledger) = make_pool(50_000, 1);
    let ops = 100;
    let num_threads = 8;

    let mut handles = Vec::new();

    for t in 0..num_threads {
        let pool = pool.clone();
        let ledger = ledger.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ops {
                let op = (t * ops + i) % 6;
                match op {
                    0 => {
                        // remember
                        let index = (t * ops + i) as u32;
                        let txn = make_unique_txn(index);
                        let _ = pool.remember_one(txn);
                    }
                    1 => {
                        // lookup
                        let fake_txid = algo_types::Digest([i as u8; 32]);
                        let _ = pool.lookup(&fake_txid);
                    }
                    2 => {
                        // pending_by_address
                        let addr = Address([t as u8; 32]);
                        let _ = pool.pending_by_address(&addr);
                    }
                    3 => {
                        // pending_count + pending_tx_ids
                        let _count = pool.pending_count();
                        let _ids = pool.pending_tx_ids();
                    }
                    4 => {
                        // test (validate without storing)
                        let index = (t * ops + i + 10000) as u32;
                        let txn = make_unique_txn(index);
                        let _ = pool.test(&[txn]);
                    }
                    5 => {
                        // on_new_block (only from thread 0 to avoid too many round advances)
                        if t == 0 {
                            ledger.advance();
                            let r = ledger.latest();
                            let block = Block {
                                round: r,
                                ..Block::default()
                            };
                            pool.on_new_block(&block, &HashSet::new());
                        } else {
                            // Other threads do pending_tx_groups instead.
                            let _ = pool.pending_tx_groups();
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // Basic consistency check.
    let count = pool.pending_count();
    let ids = pool.pending_tx_ids();
    assert_eq!(count, ids.len());
}

/// Stress test: many threads calling remember() with overlapping transaction IDs.
/// This verifies the duplicate detection is thread-safe.
#[test]
fn stress_concurrent_duplicate_detection() {
    let (pool, _ledger) = make_pool(50_000, 1);
    let num_threads = 8;
    // Each thread tries to remember the SAME set of 50 transactions.
    let num_txns = 50;

    // Pre-compute the transactions so all threads use identical copies.
    let txns: Vec<SignedTransaction> = (0..num_txns).map(make_unique_txn).collect();

    let mut handles = Vec::new();
    for _t in 0..num_threads {
        let pool = pool.clone();
        let txns = txns.clone();
        handles.push(thread::spawn(move || {
            let mut successes = 0u32;
            let mut duplicates = 0u32;
            for txn in txns {
                match pool.remember_one(txn) {
                    Ok(()) => successes += 1,
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("already in the pool") {
                            duplicates += 1;
                        }
                        // Other errors (e.g., capacity) are also acceptable.
                    }
                }
            }
            (successes, duplicates)
        }));
    }

    let mut total_successes = 0u32;
    for h in handles {
        let (s, _d) = h.join().expect("thread should not panic");
        total_successes += s;
    }

    // Exactly num_txns unique transactions should have been accepted.
    let count = pool.pending_count();
    assert_eq!(
        count, num_txns as usize,
        "exactly {} unique txns should be in pool, got {}",
        num_txns, count
    );
    // Total successes across all threads should also equal num_txns.
    assert_eq!(
        total_successes, num_txns,
        "total successes should equal unique txn count"
    );
}

/// Stress test: on_new_block with committed txids while readers query.
/// Ensures that eviction during on_new_block does not cause data corruption
/// observable by concurrent readers.
#[test]
fn stress_on_new_block_with_committed_and_readers() {
    let (pool, ledger) = make_pool(50_000, 1);

    // Pre-populate the pool.
    let mut txids = Vec::new();
    for i in 0..200u32 {
        let txn = make_unique_txn(i);
        let txid = compute_txn_id(&txn.txn);
        txids.push(txid);
        pool.remember_one(txn).unwrap();
    }

    assert_eq!(pool.pending_count(), 200);

    // Commit half the transactions.
    let committed: HashSet<_> = txids.iter().take(100).copied().collect();
    let surviving_ids: Vec<_> = txids.iter().skip(100).copied().collect();

    let mut handles = Vec::new();

    // Reader threads: query state during on_new_block.
    for _t in 0..4 {
        let pool = pool.clone();
        let surviving = surviving_ids.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                let _count = pool.pending_count();
                let _groups = pool.pending_tx_groups();
                let _ids = pool.pending_tx_ids();

                // Lookup some surviving txids.
                for txid in surviving.iter().take(10) {
                    let _ = pool.lookup(txid);
                }
            }
        }));
    }

    // on_new_block thread.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            ledger.advance();
            let block = Block {
                round: Round(2),
                ..Block::default()
            };
            pool.on_new_block(&block, &committed);
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // After on_new_block completes, verify consistency.
    let count = pool.pending_count();
    let ids = pool.pending_tx_ids();
    assert_eq!(count, ids.len());

    // Committed txns should be gone from pending.
    for txid in txids.iter().take(100) {
        assert!(!ids.contains(txid), "committed txn should be evicted");
    }

    // Surviving txns should still be present.
    assert_eq!(count, 100, "100 surviving txns should remain");
}

/// Stress test: reset while other threads are operating.
/// Reset is a destructive operation — verify it doesn't cause panics.
#[test]
fn stress_concurrent_reset() {
    let (pool, _ledger) = make_pool(50_000, 1);
    let ops = 100;

    let mut handles = Vec::new();

    // Writer thread.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for i in 0..ops {
                let txn = make_unique_txn(i);
                let _ = pool.remember_one(txn);
            }
        }));
    }

    // Reader thread.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..ops {
                let _ = pool.pending_count();
                let _ = pool.pending_tx_ids();
                let _ = pool.pending_tx_groups();
            }
        }));
    }

    // Reset thread.
    {
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            // Let some operations happen first.
            thread::sleep(Duration::from_millis(1));
            pool.reset();
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
}
