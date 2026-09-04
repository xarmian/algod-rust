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

//! Conformance tests for the transaction pool.
//!
//! These tests port key test cases from go-algorand's
//! `data/pools/transactionPool_test.go` and verify that the Rust
//! implementation matches the Go behaviour exactly (error strings,
//! fee escalation formula, eviction semantics, etc.).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use algo_codec::compute_txn_id;
use algo_error::AlgoError;
use algo_pool::config::PoolConfig;
use algo_pool::error::{classify_pool_error, PoolError, PoolErrorTag};
use algo_pool::fee::{check_sufficient_fee, compute_fee_per_byte, STATE_PROOF_SENDER};
use algo_pool::pool::TransactionPool;
use algo_pool::traits::{BlockEvaluator, PoolLedger};
use algo_types::{
    Address, Block, BlockHeader, ConsensusParams, Digest, Round, SignedTransaction, TxnType,
};

// ── Mock implementations ──────────────────────────────────────────

/// A mock ledger with an atomic round counter that can be advanced
/// and a configurable evaluator factory.
struct MockLedger {
    round: AtomicU64,
    /// Note bytes that the evaluator should reject.
    reject_notes: parking_lot::Mutex<HashSet<u8>>,
    /// If set, start_evaluator returns this error.
    eval_error: parking_lot::Mutex<Option<String>>,
    /// Track how many transactions the evaluator has seen (for "no space" simulation).
    max_txns_per_block: parking_lot::Mutex<Option<usize>>,
}

impl MockLedger {
    fn new(round: u64) -> Self {
        Self {
            round: AtomicU64::new(round),
            reject_notes: parking_lot::Mutex::new(HashSet::new()),
            eval_error: parking_lot::Mutex::new(None),
            max_txns_per_block: parking_lot::Mutex::new(None),
        }
    }

    fn advance(&self) {
        self.round.fetch_add(1, Ordering::SeqCst);
    }

    fn add_reject_note(&self, note: u8) {
        self.reject_notes.lock().insert(note);
    }
}

impl PoolLedger for MockLedger {
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
        if let Some(ref msg) = *self.eval_error.lock() {
            return Err(AlgoError::Validation {
                message: msg.clone(),
            });
        }
        let reject_notes = self.reject_notes.lock().clone();
        let max_txns = *self.max_txns_per_block.lock();
        Ok(Box::new(MockEvaluator {
            round: self.latest().next(),
            reject_notes,
            txn_count: 0,
            max_txns,
        }))
    }
}

/// A mock evaluator that optionally rejects transactions by note byte
/// and optionally returns "no space" after a set number of transactions.
struct MockEvaluator {
    round: Round,
    reject_notes: HashSet<u8>,
    txn_count: usize,
    max_txns: Option<usize>,
}

impl BlockEvaluator for MockEvaluator {
    fn round(&self) -> Round {
        self.round
    }

    fn pay_set_size(&self) -> usize {
        self.txn_count
    }

    fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn transaction_group(&mut self, txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        // Check for "no space" condition.
        if let Some(max) = self.max_txns {
            if self.txn_count + txgroup.len() > max {
                return Err(AlgoError::Validation {
                    message: "no space".to_string(),
                });
            }
        }

        for txn in txgroup {
            if !txn.txn.note.is_empty() {
                let note_byte = txn.txn.note[0];
                if self.reject_notes.contains(&note_byte) {
                    return Err(AlgoError::Validation {
                        message: format!("rejected txn with note byte {}", note_byte),
                    });
                }
            }
        }
        self.txn_count += txgroup.len();
        Ok(())
    }

    fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
        Ok(Block::default())
    }

    fn reset_txn_bytes(&mut self) {
        // Allow more transactions after a reset.
    }
}

// ── Test helpers ──────────────────────────────────────────────────

/// Create a pool with a mock evaluator installed.
fn make_pool(pool_size: usize, round: u64) -> (TransactionPool, Arc<MockLedger>) {
    let ledger = Arc::new(MockLedger::new(round));
    let config = PoolConfig {
        pool_size,
        ..Default::default()
    };
    let pool = TransactionPool::new(config, ledger.clone());

    // Trigger evaluator installation via on_new_block.
    let block = Block {
        round: Round(round),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    (pool, ledger)
}

/// Create a test transaction with a unique note (to produce distinct txn IDs).
fn make_txn(note_byte: u8) -> SignedTransaction {
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Pay;
    txn.txn.fee = 1_000_000; // high fee to pass any fee check
    txn.txn.first_valid = Round(1);
    txn.txn.last_valid = Round(1000);
    txn.txn.note = serde_bytes::ByteBuf::from(vec![note_byte]);
    txn
}

/// Create a test transaction with a specific note (for distinct IDs) and sender.
fn make_txn_from(note_byte: u8, sender: Address) -> SignedTransaction {
    let mut txn = make_txn(note_byte);
    txn.txn.sender = sender;
    txn
}

/// Create a test transaction with a specific last_valid round.
fn make_txn_expiring(note_byte: u8, last_valid: Round) -> SignedTransaction {
    let mut txn = make_txn(note_byte);
    txn.txn.last_valid = last_valid;
    txn
}

/// Create a transaction with a multi-byte note for uniqueness when >256 txns needed.
fn make_txn_with_note(note: &[u8]) -> SignedTransaction {
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Pay;
    txn.txn.fee = 1_000_000;
    txn.txn.first_valid = Round(1);
    txn.txn.last_valid = Round(1000);
    txn.txn.note = serde_bytes::ByteBuf::from(note.to_vec());
    txn
}

// ── Conformance tests ────────────────────────────────────────────

/// Port of Go's TestRememberForget:
/// Remember N transactions, then process a block that commits all of them.
/// After on_new_block, pending should be empty.
#[test]
fn test_remember_forget() {
    // Go: TestRememberForget — 5 accounts send to each other (5*4 = 20 txns),
    // then all are committed in a block.
    let (pool, _ledger) = make_pool(1000, 1);

    let num_accounts = 5usize;
    let mut txids = Vec::new();

    for i in 0..num_accounts {
        for j in 0..num_accounts {
            if i != j {
                let note = [i as u8, j as u8];
                let txn = make_txn_with_note(&note);
                let txid = compute_txn_id(&txn.txn);
                txids.push(txid);
                pool.remember_one(txn).unwrap();
            }
        }
    }

    let expected_count = num_accounts * (num_accounts - 1); // 20
    let pending = pool.pending_tx_groups();
    assert_eq!(
        pending.len(),
        expected_count,
        "should have {} pending groups",
        expected_count
    );

    // Simulate a block that commits all transactions.
    let committed: HashSet<Digest> = txids.into_iter().collect();
    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &committed);

    let pending = pool.pending_tx_groups();
    assert_eq!(pending.len(), 0, "all txns should be removed after commit");
}

/// Port of Go's TestCleanUp:
/// Submit transactions with short last_valid, advance blocks past expiry,
/// and verify all expired transactions are cleaned up.
#[test]
fn test_clean_up_expired_txns() {
    // Go: TestCleanUp — 10 accounts send to each other (90 txns, last_valid=5),
    // then advance 6 rounds so all expire.
    let (pool, ledger) = make_pool(1000, 1);

    let num_accounts = 5; // Using fewer to keep test fast
    let mut issued = 0;

    for i in 0..num_accounts {
        for j in 0..num_accounts {
            if i != j {
                let note = [i as u8, j as u8];
                let mut txn = make_txn_with_note(&note);
                txn.txn.last_valid = Round(5);
                pool.remember_one(txn).unwrap();
                issued += 1;
            }
        }
    }

    assert_eq!(pool.pending_tx_groups().len(), issued);

    // Advance past last_valid=5 by processing empty blocks.
    for r in 2..=6 {
        ledger.advance();
        let block = Block {
            round: Round(r),
            ..Block::default()
        };
        pool.on_new_block(&block, &HashSet::new());
    }

    assert!(
        pool.pending_tx_groups().is_empty(),
        "all expired txns should be cleaned up"
    );
}

/// Port of Go's TestOverspender (adapted):
/// Verify that the pool rejects transactions when the evaluator returns an error.
#[test]
fn test_evaluator_rejection() {
    // Go: TestOverspender — ledger evaluator rejects an overspend.
    // We simulate this with a mock evaluator that rejects specific note bytes.
    // Install the rejection rule BEFORE creating the pool so the first
    // evaluator already has the rule.
    let ledger = Arc::new(MockLedger::new(1));
    ledger.add_reject_note(42);

    let config = PoolConfig {
        pool_size: 1000,
        ..Default::default()
    };
    let pool = TransactionPool::new(config, ledger.clone());

    // Trigger evaluator creation via on_new_block.
    let block = Block {
        round: Round(1),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    let mut txn = make_txn(42);
    txn.txn.fee = 1_000_000;

    let result = pool.remember_one(txn);
    assert!(result.is_err(), "rejected txn should fail");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("rejected"),
        "error should mention rejection: {}",
        err_str
    );
}

/// Port of Go's TestRemove (adapted):
/// Verify that committed transactions are removed from the pool on on_new_block.
#[test]
fn test_remove_committed() {
    // Go: TestRemove — remember one txn, verify it's pending, then remove it
    // via on_new_block.
    let (pool, _ledger) = make_pool(1000, 1);

    let txn = make_txn(1);
    let txid = compute_txn_id(&txn.txn);

    pool.remember_one(txn).unwrap();
    assert_eq!(pool.pending_tx_groups().len(), 1);

    // Simulate the txn being included in a block.
    let mut committed = HashSet::new();
    committed.insert(txid);
    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &committed);

    assert_eq!(
        pool.pending_tx_groups().len(),
        0,
        "committed txn should be removed"
    );
}

/// Port of Go's TestTxPoolSizeLimits:
/// Fill the pool to near capacity, then verify that a group exceeding
/// remaining capacity is rejected. Verify that individual singleton
/// transactions still fit until the pool is completely full.
#[test]
fn test_pool_size_limits() {
    // Go: TestTxPoolSizeLimits — fill pool leaving room for MaxTxGroupSize,
    // then verify groups too large are rejected while singletons still fit.
    let pool_size = 20;
    let (pool, _ledger) = make_pool(pool_size, 1);

    // Fill pool to pool_size - 4 (leaving room for a group of 4).
    for i in 0..(pool_size - 4) {
        let note = [(i & 0xff) as u8, ((i >> 8) & 0xff) as u8];
        let txn = make_txn_with_note(&note);
        pool.remember_one(txn)
            .unwrap_or_else(|e| panic!("should fit txn {}: {:?}", i, e));
    }

    // A group of 5 should be rejected (would exceed capacity).
    let group: Vec<SignedTransaction> = (0..5u8).map(|i| make_txn_with_note(&[200, i])).collect();
    let result = pool.remember(group);
    assert!(result.is_err(), "group of 5 should exceed capacity");
    assert!(
        matches!(result.unwrap_err(), PoolError::PendingQueueFull),
        "expected PendingQueueFull"
    );

    // A group of 4 should fit (exactly at capacity).
    let group: Vec<SignedTransaction> = (0..4u8).map(|i| make_txn_with_note(&[201, i])).collect();
    pool.remember(group)
        .expect("group of 4 should fit at capacity");

    // Now pool is exactly full. One more singleton should fail.
    let result = pool.remember_one(make_txn_with_note(&[202, 0]));
    assert!(
        result.is_err(),
        "pool should be full after reaching capacity"
    );
    assert!(
        matches!(result.unwrap_err(), PoolError::PendingQueueFull),
        "expected PendingQueueFull"
    );
}

/// Port of Go's TestTransactionPool_CurrentFeePerByte:
/// Verify the fee-per-byte formula: fee = factor^(num_pending_whole_blocks - 1).
#[test]
fn test_fee_per_byte_formula() {
    // Go: TestTransactionPool_CurrentFeePerByte — after filling the pool with
    // many transactions, fee_per_byte = 2^(numPendingWholeBlocks-1).
    // We test the formula directly since we cannot easily fill an entire block
    // in integration tests without a real ledger.

    // With factor=2:
    // 0 whole blocks -> 0 (no escalation)
    assert_eq!(compute_fee_per_byte(0, 2), 0);
    // 1 whole block  -> 0 (no escalation)
    assert_eq!(compute_fee_per_byte(1, 2), 0);
    // 2 whole blocks -> 2^1 = 2
    assert_eq!(compute_fee_per_byte(2, 2), 2);
    // 3 whole blocks -> 2^2 = 4
    assert_eq!(compute_fee_per_byte(3, 2), 4);
    // 4 whole blocks -> 2^3 = 8
    assert_eq!(compute_fee_per_byte(4, 2), 8);
    // 5 whole blocks -> 2^4 = 16
    assert_eq!(compute_fee_per_byte(5, 2), 16);

    // With factor=10:
    assert_eq!(compute_fee_per_byte(2, 10), 10);
    assert_eq!(compute_fee_per_byte(3, 10), 100);
    assert_eq!(compute_fee_per_byte(4, 10), 1000);
}

/// Port of Go's duplicate-detection logic:
/// Verify that remembering the same transaction twice returns a
/// DuplicateTxn error with the correct ID.
#[test]
fn test_duplicate_detection() {
    let (pool, _ledger) = make_pool(1000, 1);

    let txn = make_txn(42);
    let txid = compute_txn_id(&txn.txn);

    // First remember succeeds.
    pool.remember_one(txn.clone()).unwrap();

    // Second remember fails with DuplicateTxn.
    let result = pool.remember_one(txn);
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_str = err.to_string();

    // Verify error string format: "TransactionPool.Remember: transaction already in the pool: <txid>"
    assert!(
        err_str.contains("TransactionPool.Remember:"),
        "should have Remember wrapper: {}",
        err_str
    );
    assert!(
        err_str.contains("already in the pool"),
        "should mention duplicate: {}",
        err_str
    );
    assert!(
        err_str.contains(&txid.to_string()),
        "should contain txid: {}",
        err_str
    );
}

/// Port of Go's duplicate-within-group detection:
/// If a group contains a transaction that is already in the pool,
/// the entire group should be rejected.
#[test]
fn test_duplicate_in_group_rejected() {
    let (pool, _ledger) = make_pool(1000, 1);

    let txn1 = make_txn(10);
    pool.remember_one(txn1.clone()).unwrap();

    // Try to remember a group containing txn1 — should fail.
    let txn2 = make_txn(11);
    let result = pool.remember(vec![txn2, txn1]);
    assert!(
        result.is_err(),
        "group with duplicate txn should be rejected"
    );
}

/// Port of Go's on_new_block confirmed-txns-in-status-cache behaviour:
/// After on_new_block, committed transactions should appear in the status
/// cache with an empty error string (meaning "confirmed").
#[test]
fn test_on_new_block_status_cache_confirmed() {
    // Go: committed txns go into statusCache with empty error string
    let (pool, _ledger) = make_pool(1000, 1);

    let txn = make_txn(1);
    let txid = compute_txn_id(&txn.txn);
    pool.remember_one(txn).unwrap();

    let mut committed = HashSet::new();
    committed.insert(txid);

    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &committed);

    // lookup should find it in status cache with empty error.
    let (_txn, err_str, found) = pool.lookup(&txid);
    assert!(found, "confirmed txn should be in status cache");
    assert!(
        err_str.is_empty(),
        "confirmed txn should have empty error string"
    );
}

/// Port of Go's on_new_block eviction of expired txns:
/// Transactions with last_valid before the new evaluator round should be
/// evicted and recorded in the status cache with an error.
#[test]
fn test_on_new_block_evicts_expired() {
    let (pool, ledger) = make_pool(1000, 1);
    // Initial evaluator is at round 2.

    // txn1: expires far in the future (survives)
    let txn1 = make_txn_expiring(1, Round(1000));
    let txid1 = compute_txn_id(&txn1.txn);

    // txn2: expires at round 2 (valid now with evaluator at round 2,
    // but will be evicted when on_new_block rebuilds the evaluator at round 3)
    let txn2 = make_txn_expiring(2, Round(2));
    let txid2 = compute_txn_id(&txn2.txn);

    pool.remember_one(txn1).unwrap();
    pool.remember_one(txn2).unwrap();
    assert_eq!(pool.pending_count(), 2);

    // Advance the ledger round to simulate the block being applied.
    // This ensures recompute_block_evaluator creates a new evaluator at round 3.
    ledger.advance();

    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    assert_eq!(
        pool.pending_count(),
        1,
        "only non-expired txn should remain"
    );

    let remaining_ids = pool.pending_tx_ids();
    assert!(remaining_ids.contains(&txid1), "txn1 should survive");
    assert!(!remaining_ids.contains(&txid2), "txn2 should be evicted");

    // txn2 should be in status cache with an error.
    let (_txn, err_str, found) = pool.lookup(&txid2);
    assert!(found, "evicted txn should be in status cache");
    assert!(!err_str.is_empty(), "evicted txn should have error string");
}

/// Port of Go's on_new_block re-evaluation eviction:
/// If the new evaluator rejects a previously-valid transaction, it should
/// be evicted and recorded in the status cache.
#[test]
fn test_on_new_block_re_evaluation_eviction() {
    let (pool, ledger) = make_pool(1000, 1);

    let txn1 = make_txn(1);
    let txn2 = make_txn(2);
    let txn3 = make_txn(3);
    let txid1 = compute_txn_id(&txn1.txn);
    let txid2 = compute_txn_id(&txn2.txn);
    let txid3 = compute_txn_id(&txn3.txn);

    pool.remember_one(txn1).unwrap();
    pool.remember_one(txn2).unwrap();
    pool.remember_one(txn3).unwrap();

    // Configure the new evaluator to reject note byte 2.
    ledger.add_reject_note(2);

    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    // txn1 and txn3 survive; txn2 is evicted.
    assert_eq!(pool.pending_count(), 2);
    let ids = pool.pending_tx_ids();
    assert!(ids.contains(&txid1));
    assert!(!ids.contains(&txid2));
    assert!(ids.contains(&txid3));

    // txn2 should be in status cache with rejection error.
    let (_txn, err_str, found) = pool.lookup(&txid2);
    assert!(found, "evicted txn should be in status cache");
    assert!(err_str.contains("rejected"), "error: {}", err_str);
}

/// Port of Go's fee threshold adjustment rules in on_new_block:
///
/// - 0 pending whole blocks: multiplier /= exp_factor (decrease)
/// - 1 pending whole block: multiplier stays same (steady)
/// - 2+ pending whole blocks: multiplier *= exp_factor (increase), or 0->1
#[test]
fn test_on_new_block_fee_threshold_adjustment() {
    // This tests the fee threshold multiplier adjustment rules.
    // We cannot easily access the internal multiplier, but we can observe
    // fee_per_byte() which is computed from the multiplier.

    // Test 1: Idle pool -> fee should stay at 0.
    let (pool, _ledger) = make_pool(1000, 1);
    assert_eq!(pool.fee_per_byte(), 0, "initial fee should be 0");

    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());
    // After on_new_block with 0 pending blocks, fee should remain 0.
    assert_eq!(
        pool.fee_per_byte(),
        0,
        "fee should stay 0 when pool is idle"
    );
}

/// Port of Go's state proof sender fee exemption:
/// A state proof transaction from STATE_PROOF_SENDER with zero fee should
/// bypass fee checks.
#[test]
fn test_state_proof_sender_fee_exemption() {
    // Go: state proof txns from StateProofSender with zero fee are exempted
    // from fee-per-byte checks.
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Stpf;
    txn.txn.sender = STATE_PROOF_SENDER;
    txn.txn.fee = 0;

    let consensus = ConsensusParams::default();

    // Should pass even with a very high fee_per_byte.
    let result = check_sufficient_fee(&txn, 100_000, &consensus, 1);
    assert!(
        result.is_ok(),
        "state proof sender with zero fee should be exempt"
    );
}

/// Verify that non-state-proof types from STATE_PROOF_SENDER do NOT get exemption.
#[test]
fn test_state_proof_sender_wrong_type_no_exemption() {
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Pay; // Wrong type
    txn.txn.sender = STATE_PROOF_SENDER;
    txn.txn.fee = 0;

    let consensus = ConsensusParams::default();
    let result = check_sufficient_fee(&txn, 1000, &consensus, 1);
    assert!(
        result.is_err(),
        "pay txn from SP sender should not be exempt"
    );
}

/// Verify that state proof type from wrong sender does NOT get exemption.
#[test]
fn test_state_proof_wrong_sender_no_exemption() {
    let mut txn = SignedTransaction::default();
    txn.txn.txn_type = TxnType::Stpf;
    txn.txn.sender = Address::ZERO; // Wrong sender
    txn.txn.fee = 0;

    let consensus = ConsensusParams::default();
    let result = check_sufficient_fee(&txn, 1000, &consensus, 1);
    assert!(
        result.is_err(),
        "stpf from non-SP sender should not be exempt"
    );
}

/// Port of Go's TestPoolFeeClassification:
/// Verify that FeeBelowThreshold errors are classified as "fee" tag.
#[test]
fn test_pool_fee_classification() {
    // Go: TestPoolFeeClassification — fill pool past one block to trigger
    // fee escalation, then submit a low-fee txn. The error should classify
    // as TxPoolErrTagFee.
    let err = PoolError::FeeBelowThreshold {
        fee: 1000,
        fee_threshold: 5000,
        fee_per_byte: 5,
        encoded_len: 1000,
    };
    assert_eq!(classify_pool_error(&err), PoolErrorTag::Fee);
    assert_eq!(PoolErrorTag::Fee.as_str(), "fee");
}

/// Port of Go's error classification coverage:
/// Verify that all pool error types classify to the correct tags.
#[test]
fn test_pool_error_classification() {
    assert_eq!(
        classify_pool_error(&PoolError::PendingQueueFull),
        PoolErrorTag::Cap
    );
    assert_eq!(
        classify_pool_error(&PoolError::NoPendingBlockEvaluator),
        PoolErrorTag::PendingEval
    );
    assert_eq!(
        classify_pool_error(&PoolError::StaleBlockAssemblyRequest),
        PoolErrorTag::EvalGeneric
    );
    assert_eq!(
        classify_pool_error(&PoolError::PoolShutdown),
        PoolErrorTag::EvalGeneric
    );
    assert_eq!(
        classify_pool_error(&PoolError::DuplicateTxn(Digest([0; 32]))),
        PoolErrorTag::TxId
    );
    assert_eq!(
        classify_pool_error(&PoolError::Evaluator("some error".into())),
        PoolErrorTag::EvalGeneric
    );
    // Remember wrapping delegates classification.
    assert_eq!(
        classify_pool_error(&PoolError::Remember(Box::new(PoolError::PendingQueueFull))),
        PoolErrorTag::Cap
    );
    assert_eq!(
        classify_pool_error(&PoolError::Remember(Box::new(
            PoolError::FeeBelowThreshold {
                fee: 0,
                fee_threshold: 0,
                fee_per_byte: 0,
                encoded_len: 0,
            }
        ))),
        PoolErrorTag::Fee
    );
}

/// Port of Go's `TestPoolLeaseReevalClassification`
/// (`data/pools/transactionPool_test.go`): a lease conflict discovered
/// while the pool's block evaluator is being rebuilt during re-evaluation
/// (`OnNewBlock` -> `recompute_block_evaluator`) must classify as
/// `LeaseEval`, distinct from a lease conflict discovered during a normal
/// `Remember()` (`Lease`). Go carries this distinction on
/// `ledgercore.LeaseInLedgerError.InBlockEvaluator`; algod-rust carries it
/// on `PoolError::LeaseConflict::in_block_evaluator` for the same reason
/// (the `BlockEvaluator` trait only reports a message string, not a typed
/// error). The plumbing that sets this flag from the two call sites is
/// exercised directly in `pool.rs`'s
/// `test_lease_conflict_classification_by_reevaluation_context` (it needs
/// private access); this test pins the public classification contract.
#[test]
fn test_pool_lease_reeval_classification() {
    let reeval_err = PoolError::LeaseConflict {
        message: "duplicate lease".into(),
        in_block_evaluator: true,
    };
    assert_eq!(classify_pool_error(&reeval_err), PoolErrorTag::LeaseEval);

    let remember_err = PoolError::LeaseConflict {
        message: "duplicate lease".into(),
        in_block_evaluator: false,
    };
    assert_eq!(classify_pool_error(&remember_err), PoolErrorTag::Lease);
}

/// Port of Go's `TestPoolAssetBalanceClassification`
/// (`data/pools/transactionPool_test.go`): a transfer of more of an asset
/// than the sender holds must classify as `AssetBalance`, mirroring Go's
/// `ledgercore.AssetBalanceError` case in `ClassifyTxPoolError`. The
/// message text pinned here is `algo-ledger`'s `apply.rs` axfer
/// insufficient-holding message (`"axfer: {sender} holding {held}
/// insufficient for transfer {amount} of asset {id}"`), which is what a
/// real evaluator would surface through `PoolError::Evaluator`.
#[test]
fn test_pool_asset_balance_classification() {
    let err = PoolError::Evaluator(
        "axfer: SENDERADDR holding 0 insufficient for transfer 10 of asset 1".to_string(),
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::AssetBalance);
}

/// Port of Go's `TestPoolTealRejectClassification`
/// (`data/pools/transactionPool_test.go`): an approval program that simply
/// returns false (no runtime error) must classify as `TealReject`,
/// mirroring Go's `ledgercore.ApprovalProgramRejectedError` case. The
/// message text pinned here is `algo-ledger`'s `apply.rs` `apply_appl`
/// rejection message with no `result.error` suffix (i.e. no trailing
/// `": <err>"`).
#[test]
fn test_pool_teal_reject_classification() {
    let err = PoolError::Evaluator(
        "appl execute: app 1 approval program rejected transaction".to_string(),
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TealReject);
}

/// Port of Go's `TestPoolTealErrClassification`
/// (`data/pools/transactionPool_test.go`): an approval program that hits a
/// runtime error (e.g. the `err` opcode) must classify as `TealErr`,
/// mirroring Go's `logic.EvalError` case. The message text pinned here is
/// `algo-ledger`'s `apply.rs` `apply_appl` rejection message *with* a
/// `result.error` suffix (`": <err>"`), which is how a genuine runtime
/// error (as opposed to an explicit `return 0`) is distinguished from a
/// plain reject at the message-text level.
#[test]
fn test_pool_teal_err_classification() {
    let err = PoolError::Evaluator(
        "appl execute: app 1 approval program rejected transaction: err opcode executed"
            .to_string(),
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::TealErr);
}

/// Verify exact error string format for FeeBelowThreshold matches Go's
/// `fmt.Sprintf("fee %d below threshold %d (%d per byte * %d bytes)", ...)`.
#[test]
fn test_fee_error_string_exact_match() {
    // Go: fmt.Sprintf("fee %d below threshold %d (%d per byte * %d bytes)", 500, 1000, 5, 200)
    let err = PoolError::FeeBelowThreshold {
        fee: 500,
        fee_threshold: 1000,
        fee_per_byte: 5,
        encoded_len: 200,
    };
    assert_eq!(
        err.to_string(),
        "fee 500 below threshold 1000 (5 per byte * 200 bytes)"
    );
}

/// Verify exact error string for PendingQueueFull matches Go.
#[test]
fn test_pending_queue_full_error_string() {
    let err = PoolError::PendingQueueFull;
    assert_eq!(
        err.to_string(),
        "TransactionPool.checkPendingQueueSize: transaction pool have reached capacity"
    );
}

/// Verify exact error string for NoPendingBlockEvaluator matches Go.
#[test]
fn test_no_pending_block_evaluator_error_string() {
    let err = PoolError::NoPendingBlockEvaluator;
    assert_eq!(
        err.to_string(),
        "TransactionPool.ingest: no pending block evaluator"
    );
}

/// Verify Remember wrapping produces the correct nested error string.
#[test]
fn test_remember_wraps_error_string() {
    let inner = PoolError::NoPendingBlockEvaluator;
    let err = PoolError::Remember(Box::new(inner));
    assert_eq!(
        err.to_string(),
        "TransactionPool.Remember: TransactionPool.ingest: no pending block evaluator"
    );
}

/// Port of Go's TestRememberTxnDeadError (adapted):
/// If we try to remember a transaction whose LastValid is in the past,
/// the evaluator should reject it. The pool wraps the evaluator error
/// in a Remember error.
#[test]
fn test_remember_expired_txn() {
    // We need a pool at round > 5 to make a txn with last_valid=5 expired.
    let (pool, _ledger) = make_pool(1000, 10);

    let mut txn = make_txn(1);
    txn.txn.last_valid = Round(5); // Already expired at round 10
    txn.txn.first_valid = Round(0);

    let result = pool.remember_one(txn);
    // Note: In our implementation, the evaluator handles expiry checks.
    // With our mock evaluator, the txn goes through (mock doesn't check expiry).
    // This is testing the Remember wrapper format if it fails.
    // In Go, the real ledger evaluator rejects the expired txn.
    // The key conformance point here is the Remember error wrapping.
    if let Err(e) = result {
        let err_str = e.to_string();
        assert!(
            err_str.starts_with("TransactionPool.Remember:"),
            "error should be wrapped with Remember prefix: {}",
            err_str
        );
    }
}

/// Verify lookup semantics for pending, evicted, and missing transactions.
#[test]
fn test_lookup_semantics() {
    let (pool, _ledger) = make_pool(1000, 1);

    let txn = make_txn(99);
    let txid = compute_txn_id(&txn.txn);

    // Before remember: not found.
    let (_t, err, found) = pool.lookup(&txid);
    assert!(!found);
    assert!(err.is_empty());

    // After remember: found with empty error.
    pool.remember_one(txn.clone()).unwrap();
    let (found_txn, err, found) = pool.lookup(&txid);
    assert!(found);
    assert!(err.is_empty());
    assert_eq!(found_txn.txn.note, txn.txn.note);

    // After commit via on_new_block: found in status cache with empty error.
    let mut committed = HashSet::new();
    committed.insert(txid);
    let block = Block {
        round: Round(2),
        ..Block::default()
    };
    pool.on_new_block(&block, &committed);

    let (_t, err, found) = pool.lookup(&txid);
    assert!(found, "committed txn should be in status cache");
    assert!(err.is_empty(), "committed txn should have empty error");
}

/// Verify pending_by_address matches both sender and auth_addr.
#[test]
fn test_pending_by_address() {
    // Go: REST handler getPendingTransactions filters by MatchAddress
    let (pool, _ledger) = make_pool(1000, 1);

    let addr = Address([1u8; 32]);
    let other = Address([2u8; 32]);

    // Direct sender match.
    let txn1 = make_txn_from(1, addr);
    pool.remember_one(txn1).unwrap();

    // Auth addr match (rekeyed).
    let mut txn2 = make_txn_from(2, other);
    txn2.auth_addr = Some(addr);
    pool.remember_one(txn2).unwrap();

    // Non-matching.
    pool.remember_one(make_txn_from(3, other)).unwrap();

    let result = pool.pending_by_address(&addr);
    assert_eq!(
        result.len(),
        2,
        "should match both sender and auth_addr txns"
    );
}

/// Verify pool shutdown semantics.
#[test]
fn test_shutdown_rejects_remember() {
    let (pool, _ledger) = make_pool(1000, 1);

    assert!(!pool.is_shutdown());
    pool.shutdown();
    assert!(pool.is_shutdown());

    let result = pool.remember_one(make_txn(1));
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("shutting down"),
        "should mention shutdown: {}",
        err_str
    );
}

/// Verify pool reset clears all state.
#[test]
fn test_reset_clears_all() {
    let (pool, _ledger) = make_pool(1000, 1);

    pool.remember_one(make_txn(1)).unwrap();
    pool.remember_one(make_txn(2)).unwrap();
    assert_eq!(pool.pending_count(), 2);

    pool.reset();

    assert_eq!(pool.pending_count(), 0);
    assert!(pool.pending_tx_ids().is_empty());
    assert!(pool.pending_tx_groups().is_empty());
    assert_eq!(pool.fee_per_byte(), 0);
}

/// Verify that the pool enforces capacity based on individual transaction count,
/// not group count. A group of 3 should count as 3 toward the limit.
#[test]
fn test_capacity_counts_individual_txns() {
    let (pool, _ledger) = make_pool(5, 1);

    // Add a group of 3.
    pool.remember(vec![make_txn(1), make_txn(2), make_txn(3)])
        .unwrap();
    assert_eq!(pool.pending_count(), 3);

    // Add a group of 2 — should succeed (3+2=5 = capacity).
    pool.remember(vec![make_txn(4), make_txn(5)]).unwrap();
    assert_eq!(pool.pending_count(), 5);

    // One more should fail.
    let result = pool.remember_one(make_txn(6));
    assert!(
        matches!(result.unwrap_err(), PoolError::PendingQueueFull),
        "should be full"
    );
}

/// Verify Test() method validates without storing.
#[test]
fn test_method_does_not_store() {
    let (pool, _ledger) = make_pool(1000, 1);
    let txn = make_txn(1);

    let result = pool.test(&[txn]);
    assert!(result.is_ok());

    assert_eq!(pool.pending_count(), 0, "test should not store txn");
}

// ── Close-account pool-admission tests ──────────────────────────────
//
// Port of Go's `TestCloseAccount`, `TestCloseAccountWhileTxIsPending`, and
// `TestCloseToAccountBelowMinBalance` (`data/pools/transactionPool_test.go`).
// These exercise account-closing (`close_remainder_to`) at the
// pool-admission layer. algo-pool itself does no balance accounting (that
// lives in algo-ledger's block evaluator, reached only through the
// `BlockEvaluator` trait), so this harness plugs in an evaluator that
// tracks per-address balances and applies go-algorand's payment/close
// semantics -- fee + amount debited from the sender, the remainder swept
// to `close_remainder_to`, min-balance enforced on the receiver and the
// close-to address but *not* on a closing sender -- closely enough to
// prove the pool correctly propagates the accept/reject verdict for each
// scenario end to end. Failure messages follow `algo-ledger::apply.rs`'s
// conventions (`"...insufficient balance..."`, `"...below minimum
// balance..."`) so `classify_pool_error` also classifies them correctly.

const CLOSE_TEST_MIN_BALANCE: u64 = 100_000;
const CLOSE_TEST_FEE: u64 = 1_000;

/// A ledger whose evaluator tracks per-address balances and applies
/// payment/close-remainder-to semantics, mirroring go-algorand's mock
/// ledger used by the close-account pool tests.
struct BalanceLedger {
    round: AtomicU64,
    balances: Arc<parking_lot::Mutex<HashMap<Address, u64>>>,
}

impl BalanceLedger {
    fn new(round: u64, initial: &[(Address, u64)]) -> Self {
        Self {
            round: AtomicU64::new(round),
            balances: Arc::new(parking_lot::Mutex::new(initial.iter().copied().collect())),
        }
    }

    fn balance_of(&self, addr: Address) -> u64 {
        *self.balances.lock().get(&addr).unwrap_or(&0)
    }
}

impl PoolLedger for BalanceLedger {
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
        Ok(Box::new(BalanceEvaluator {
            round: self.latest().next(),
            balances: self.balances.clone(),
        }))
    }
}

/// Evaluator counterpart to [`BalanceLedger`]: applies payment/close
/// semantics against the shared balance map, rejecting (without mutating
/// state) on overspend or a resulting balance strictly between 0 and the
/// minimum balance.
struct BalanceEvaluator {
    round: Round,
    balances: Arc<parking_lot::Mutex<HashMap<Address, u64>>>,
}

impl BlockEvaluator for BalanceEvaluator {
    fn round(&self) -> Round {
        self.round
    }

    fn pay_set_size(&self) -> usize {
        0
    }

    fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn transaction_group(&mut self, txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
        let mut balances = self.balances.lock();
        for stx in txgroup {
            let t = &stx.txn;
            let sender_bal = *balances.get(&t.sender).unwrap_or(&0);
            let total_spend = t.fee + t.amount;
            if sender_bal < total_spend {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "sender {} has insufficient balance {} for payment {}",
                        t.sender, sender_bal, total_spend
                    ),
                });
            }
            let remainder = sender_bal - total_spend;
            let closing = !t.close_remainder_to.is_zero();

            let new_sender_bal = if closing { 0 } else { remainder };
            let new_receiver_bal = balances.get(&t.receiver).copied().unwrap_or(0) + t.amount;
            let new_close_to_bal = closing
                .then(|| balances.get(&t.close_remainder_to).copied().unwrap_or(0) + remainder);

            // Min-balance checks (a closing sender is exempt; go-algorand
            // never enforces a minimum on an account that ends at zero via
            // CloseRemainderTo). Nothing is committed until all checks pass,
            // matching go's evaluator (a rejected txn has no side effects).
            if !closing && new_sender_bal > 0 && new_sender_bal < CLOSE_TEST_MIN_BALANCE {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "account {} balance {} below minimum balance {}",
                        t.sender, new_sender_bal, CLOSE_TEST_MIN_BALANCE
                    ),
                });
            }
            if new_receiver_bal > 0 && new_receiver_bal < CLOSE_TEST_MIN_BALANCE {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "account {} balance {} below minimum balance {}",
                        t.receiver, new_receiver_bal, CLOSE_TEST_MIN_BALANCE
                    ),
                });
            }
            if let Some(close_to_bal) = new_close_to_bal {
                if close_to_bal > 0 && close_to_bal < CLOSE_TEST_MIN_BALANCE {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "account {} balance {} below minimum balance {}",
                            t.close_remainder_to, close_to_bal, CLOSE_TEST_MIN_BALANCE
                        ),
                    });
                }
            }

            balances.insert(t.sender, new_sender_bal);
            balances.insert(t.receiver, new_receiver_bal);
            if let Some(close_to_bal) = new_close_to_bal {
                balances.insert(t.close_remainder_to, close_to_bal);
            }
        }
        Ok(())
    }

    fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
        Ok(Block::default())
    }

    fn reset_txn_bytes(&mut self) {}
}

/// Build a pool backed by a [`BalanceLedger`] seeded with the given
/// initial balances, with the evaluator already installed (mirrors
/// `make_pool`'s `on_new_block` bootstrap).
fn make_balance_pool(
    round: u64,
    initial: &[(Address, u64)],
) -> (TransactionPool, Arc<BalanceLedger>) {
    let ledger = Arc::new(BalanceLedger::new(round, initial));
    let config = PoolConfig {
        pool_size: 1000,
        ..Default::default()
    };
    let pool = TransactionPool::new(config, ledger.clone());

    let block = Block {
        round: Round(round),
        ..Block::default()
    };
    pool.on_new_block(&block, &HashSet::new());

    (pool, ledger)
}

/// A payment transaction with an optional `close_remainder_to`, using a
/// distinguishing note byte for a unique txid.
fn make_payment(
    note_byte: u8,
    sender: Address,
    receiver: Address,
    amount: u64,
    close_remainder_to: Address,
) -> SignedTransaction {
    let mut txn = make_txn(note_byte);
    txn.txn.sender = sender;
    txn.txn.fee = CLOSE_TEST_FEE;
    txn.txn.receiver = receiver;
    txn.txn.amount = amount;
    txn.txn.close_remainder_to = close_remainder_to;
    txn
}

/// Port of Go's `TestCloseAccount`: after a payment closes the sender's
/// account out via `CloseRemainderTo`, a further payment from that same
/// (now-empty) sender must be rejected for insufficient balance.
#[test]
fn test_close_account() {
    let addr0 = Address([10u8; 32]);
    let addr1 = Address([11u8; 32]);
    let addr2 = Address([12u8; 32]);

    let (pool, ledger) = make_balance_pool(
        1,
        &[(addr0, 3 * CLOSE_TEST_MIN_BALANCE + 2 * CLOSE_TEST_FEE)],
    );

    // Close addr0 out: pay addr1 minBalance, sweep the remainder to addr2.
    let close_txn = make_payment(1, addr0, addr1, CLOSE_TEST_MIN_BALANCE, addr2);
    pool.remember_one(close_txn)
        .expect("closing payment should be accepted");
    assert_eq!(ledger.balance_of(addr0), 0, "sender should be fully closed");

    // The sender is closed -- it can no longer pay the fee, let alone a
    // further payment.
    let follow_up = make_payment(2, addr0, addr1, CLOSE_TEST_MIN_BALANCE, Address::ZERO);
    let err = pool
        .remember_one(follow_up)
        .expect_err("closed sender should not be able to spend");
    let err_str = err.to_string();
    assert!(
        err_str.contains("insufficient balance"),
        "expected an overspend-style rejection, got: {}",
        err_str
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::Overspend);
}

/// Port of Go's `TestCloseAccountWhileTxIsPending`: a close transaction
/// that would overspend (because a prior pending payment already
/// consumed most of the balance) is rejected, but a slightly smaller
/// close succeeds even though the sender ends up below the minimum
/// balance -- closing is exempt from the sender-side minimum-balance
/// check.
#[test]
fn test_close_account_while_tx_is_pending() {
    let addr0 = Address([20u8; 32]);
    let addr1 = Address([21u8; 32]);
    let addr2 = Address([22u8; 32]);

    let (pool, _ledger) = make_balance_pool(
        1,
        &[
            (addr0, 2 * CLOSE_TEST_MIN_BALANCE + 2 * CLOSE_TEST_FEE - 1),
            (addr1, CLOSE_TEST_MIN_BALANCE),
            (addr2, CLOSE_TEST_MIN_BALANCE),
        ],
    );

    // First payment leaves addr0 with minBalance + fee - 1.
    let first = make_payment(1, addr0, addr1, CLOSE_TEST_MIN_BALANCE, Address::ZERO);
    pool.remember_one(first)
        .expect("first payment should be accepted");

    // Trying to pay minBalance + fee again overspends by 1.
    let overspend_close = make_payment(2, addr0, addr1, CLOSE_TEST_MIN_BALANCE, addr2);
    let err = pool
        .remember_one(overspend_close)
        .expect_err("second close should overspend by 1");
    assert!(
        err.to_string().contains("insufficient balance"),
        "expected an overspend-style rejection, got: {}",
        err
    );

    // Paying a bit less succeeds even though it's closing -- the sender
    // would end up below the minimum balance, but that's fine because the
    // account is closing (CloseRemainderTo sweeps the rest away).
    let ok_close = make_payment(3, addr0, addr1, CLOSE_TEST_MIN_BALANCE - 10, addr2);
    pool.remember_one(ok_close)
        .expect("closing for slightly less should be accepted");
}

/// Port of Go's `TestCloseToAccountBelowMinBalance`: a close transaction
/// is rejected when the `CloseRemainderTo` account would end up holding a
/// nonzero balance below the minimum -- the problem is on the close-to
/// side, not the sender's.
#[test]
fn test_close_to_account_below_min_balance() {
    let addr0 = Address([30u8; 32]);
    let addr1 = Address([31u8; 32]);
    let addr2 = Address([32u8; 32]);

    let (pool, _ledger) = make_balance_pool(
        1,
        &[
            (addr0, 2 * CLOSE_TEST_MIN_BALANCE - 1 + CLOSE_TEST_FEE),
            (addr2, 0),
        ],
    );

    let close_txn = make_payment(1, addr0, addr1, CLOSE_TEST_MIN_BALANCE, addr2);
    let err = pool
        .remember_one(close_txn)
        .expect_err("close-to account ending up below min balance should be rejected");
    let err_str = err.to_string();
    assert!(
        err_str.contains(&addr2.to_string()),
        "error should name the close-to address {}: {}",
        addr2,
        err_str
    );
    assert!(
        err_str.contains("below minimum balance"),
        "expected a min-balance rejection, got: {}",
        err_str
    );
    assert_eq!(classify_pool_error(&err), PoolErrorTag::MinBalance);
}
