//! Transaction pool — caches validated transaction groups and assembles blocks.
//!
//! Mirrors `go-algorand/data/pools/transactionPool.go`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex, RwLock};

use algo_codec::compute_txn_id;
use algo_error::AlgoError;
use algo_types::{Address, Block, Digest, Round, SignedTransaction, TxnType};

use crate::config::PoolConfig;
use crate::error::PoolError;
use crate::fee::check_sufficient_fee;
use crate::status_cache::StatusCache;
use crate::traits::{BlockEvaluator, PoolLedger};

// ── Helper types ─────────────────────────────────────────────────

/// Location of a single transaction within the pool's group storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxnLocation {
    /// Index into the `Vec<Vec<SignedTransaction>>` of groups.
    pub group_index: usize,
    /// Index within the group.
    pub intra_index: usize,
}

/// Results of an asynchronous block-assembly attempt.
#[derive(Default)]
struct AssemblyResults {
    /// Whether assembly completed (or was abandoned).
    ok: bool,
    /// The generated block, if successful.
    block: Option<Block>,
    /// Error from assembly, if any.
    err: Option<AlgoError>,
    /// The round we started evaluating.
    round_started_evaluating: Round,
    /// Mirror of `ok` for lock-free inspection from the `on_new_block` path.
    assembly_completed_or_abandoned: bool,
}

// ── Inner state (behind `mu`) ────────────────────────────────────

/// State protected by the main mutex (`mu`).
///
/// Matches the fields that live behind `pool.mu` in go-algorand.
struct PoolInner {
    /// Transaction groups staged for the next block via `remember()`.
    /// Committed to `pending` via `remember_commit()`.
    remembered_tx_groups: Vec<Vec<SignedTransaction>>,

    /// Quick lookup of remembered transactions by ID.
    remembered_txids: HashMap<Digest, SignedTransaction>,

    /// The evaluator building the current pending block.
    evaluator: Option<Box<dyn BlockEvaluator>>,

    /// Number of "whole blocks" worth of transactions that have accumulated.
    /// Drives the exponential fee ramp.
    num_pending_whole_blocks: u64,

    /// Fee threshold multiplier — grows exponentially under load.
    fee_threshold_multiplier: u64,

    /// Whether a state-proof txn already overflowed the pool capacity.
    stateproof_overflowed: bool,

    /// Status cache for recently evicted/committed transactions.
    status_cache: StatusCache,
}

// ── Pending state (behind `pending_mu`) ──────────────────────────

/// State protected by the pending read-write lock (`pending_mu`).
///
/// Readers can snapshot pending transaction groups and IDs without
/// blocking `remember()`.
struct PendingState {
    /// Transaction groups ready for proposal, in order.
    tx_groups: Vec<Vec<SignedTransaction>>,

    /// All pending transaction IDs mapped to their signed txn.
    txids: HashMap<Digest, SignedTransaction>,
}

// ── Assembly state (behind `assembly_mu`) ────────────────────────

/// State related to the block-assembly handshake between
/// `on_new_block()` / `recompute_block_evaluator()` and `assemble_block()`.
struct AssemblyState {
    deadline: Option<Instant>,
    round: Round,
    results: AssemblyResults,
}

// ── TransactionPool ──────────────────────────────────────────────

/// A pool of validated transaction groups, mirroring go-algorand's
/// `TransactionPool`.
///
/// The pool prepares valid blocks for proposal and caches validated
/// transaction groups.  It enforces fee-priority ordering under load
/// using an exponential fee ramp.
pub struct TransactionPool {
    // ── immutable after construction ──
    config: PoolConfig,
    ledger: Arc<dyn PoolLedger>,

    // ── concurrency primitives ──
    /// Main lock protecting evaluator, remembered groups, fee state.
    mu: Mutex<PoolInner>,

    /// Read-write lock for pending groups/IDs — readers do not block
    /// `remember()` except during `remember_commit()`.
    pending_mu: RwLock<PendingState>,

    /// Lock for the assembly handshake.
    assembly_mu: Mutex<AssemblyState>,

    /// Condvar signalled when assembly results become available.
    assembly_cond: Condvar,

    /// Condvar associated with `mu`, signalled by `on_new_block()` after
    /// rebuilding the evaluator. Mirrors Go's `pool.cond`.
    cond: Condvar,

    /// Atomic fee-per-byte for fast lock-free reads via `fee_per_byte()`.
    fee_per_byte: AtomicU64,

    /// Whether the pool is shutting down.
    shutdown: AtomicBool,
}

impl TransactionPool {
    /// Create a new transaction pool.
    ///
    /// Mirrors `MakeTransactionPool` in go-algorand.
    pub fn new(config: PoolConfig, ledger: Arc<dyn PoolLedger>) -> Self {
        let config = PoolConfig {
            exponential_increase_factor: config.exponential_increase_factor.max(1),
            ..config
        };

        let inner = PoolInner {
            remembered_tx_groups: Vec::new(),
            remembered_txids: HashMap::new(),
            evaluator: None,
            num_pending_whole_blocks: 0,
            fee_threshold_multiplier: 0,
            stateproof_overflowed: false,
            status_cache: StatusCache::new(config.pool_size),
        };

        let pending = PendingState {
            tx_groups: Vec::new(),
            txids: HashMap::new(),
        };

        let assembly = AssemblyState {
            deadline: None,
            round: Round(0),
            results: AssemblyResults::default(),
        };

        TransactionPool {
            config,
            ledger,
            mu: Mutex::new(inner),
            pending_mu: RwLock::new(pending),
            assembly_mu: Mutex::new(assembly),
            assembly_cond: Condvar::new(),
            cond: Condvar::new(),
            fee_per_byte: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        }
    }

    // ── Public query methods ─────────────────────────────────────

    /// Return the current minimum fee-per-byte required to enter the pool.
    pub fn fee_per_byte(&self) -> u64 {
        self.fee_per_byte.load(Ordering::Relaxed)
    }

    /// Number of individual pending transactions (not groups).
    pub fn pending_count(&self) -> usize {
        let pending = self.pending_mu.read();
        pending.tx_groups.iter().map(|g| g.len()).sum()
    }

    /// Return the number of pending transaction IDs.
    ///
    /// Mirrors `pendingTxIDsCount()` in go-algorand. Uses the txids map
    /// which counts individual transactions (including all members of groups).
    fn pending_txids_count(&self) -> usize {
        let pending = self.pending_mu.read();
        pending.txids.len()
    }

    /// Return the IDs of all pending transactions.
    pub fn pending_tx_ids(&self) -> Vec<Digest> {
        let pending = self.pending_mu.read();
        pending.txids.keys().copied().collect()
    }

    /// Return a snapshot of the pending transaction groups, in proposal order.
    pub fn pending_tx_groups(&self) -> Vec<Vec<SignedTransaction>> {
        let pending = self.pending_mu.read();
        pending.tx_groups.clone()
    }

    /// Return all pending transactions sent by (or authorized by) `addr`.
    ///
    /// Matches transactions where `txn.sender == addr` or where
    /// `auth_addr == Some(addr)` (rekeyed accounts).
    ///
    /// Mirrors the address filter in Go's REST handler
    /// `getPendingTransactions` which calls `txn.Txn.MatchAddress`.
    pub fn pending_by_address(&self, addr: &Address) -> Vec<SignedTransaction> {
        let pending = self.pending_mu.read();
        let mut result = Vec::new();
        for group in &pending.tx_groups {
            for txn in group {
                if txn.txn.sender == *addr || txn.auth_addr.as_ref() == Some(addr) {
                    result.push(txn.clone());
                }
            }
        }
        result
    }

    // ── Capacity check ──────────────────────────────────────────

    /// Check whether the pool has room for `tx_group`.
    ///
    /// Mirrors `checkPendingQueueSize()` in go-algorand.
    /// The pool counts individual transactions, not groups.
    /// A state proof singleton group is allowed to overflow once.
    fn check_pending_queue_size(&self, tx_group: &[SignedTransaction]) -> Result<(), PoolError> {
        let pending_size = self.pending_txids_count();
        let tx_count = tx_group.len();

        if pending_size + tx_count > self.config.pool_size {
            // Allow a single state proof transaction to overflow once.
            if tx_group.len() == 1 && tx_group[0].txn.txn_type == TxnType::Stpf {
                // In Go, stateproofOverflowed is checked/set under pendingMu.Lock().
                // We check the flag on PoolInner (behind mu). The capacity check
                // runs BEFORE mu is acquired in Remember(), matching Go's flow.
                let mut inner = self.mu.lock();
                if !inner.stateproof_overflowed {
                    inner.stateproof_overflowed = true;
                    return Ok(());
                }
            }
            return Err(PoolError::PendingQueueFull);
        }
        Ok(())
    }

    // ── Fee computation ─────────────────────────────────────────

    /// Recompute the fee-per-byte threshold and update the atomic counter.
    ///
    /// Mirrors `computeFeePerByte()` in go-algorand. Must be called
    /// with `mu` held.
    fn recompute_fee_per_byte(&self, inner: &PoolInner) -> u64 {
        // Baseline threshold fee per byte is 1.
        let mut fee = 1u64;

        // Scale by the fee threshold multiplier.
        fee = fee.saturating_mul(inner.fee_threshold_multiplier);

        // If multiplier is 0 but there's load, bump to 1 to make
        // the exponential growth valid.
        if fee == 0 && inner.num_pending_whole_blocks > 1 {
            fee = 1;
        }

        // Exponential growth for multiple pending blocks.
        for _ in 0..inner.num_pending_whole_blocks.saturating_sub(1) {
            fee = fee.saturating_mul(self.config.exponential_increase_factor);
        }

        self.fee_per_byte.store(fee, Ordering::Relaxed);
        fee
    }

    // ── Duplicate detection ─────────────────────────────────────

    /// Check if any transaction in the group is already known
    /// (in pending or remembered txid maps).
    ///
    /// This provides early rejection before hitting the evaluator.
    fn check_duplicate(
        &self,
        tx_group: &[SignedTransaction],
        inner: &PoolInner,
    ) -> Result<(), PoolError> {
        let pending = self.pending_mu.read();
        for txn in tx_group {
            let txid = compute_txn_id(&txn.txn);
            if pending.txids.contains_key(&txid) || inner.remembered_txids.contains_key(&txid) {
                return Err(PoolError::DuplicateTxn(txid));
            }
        }
        Ok(())
    }

    // ── Ingest ──────────────────────────────────────────────────

    /// Internal ingestion: validate and store a transaction group.
    ///
    /// The caller must pass in the `MutexGuard` for `mu` (not just the inner
    /// data) because the wait-for-`OnNewBlock` loop needs to temporarily
    /// release the lock via a condvar wait.
    ///
    /// Mirrors `ingest()` in go-algorand (non-recomputing path).
    fn ingest(
        &self,
        tx_group: &[SignedTransaction],
        guard: &mut parking_lot::MutexGuard<'_, PoolInner>,
    ) -> Result<(), PoolError> {
        if guard.evaluator.is_none() {
            return Err(PoolError::NoPendingBlockEvaluator);
        }

        // Wait for OnNewBlock to catch up to the ledger.
        //
        // Mirrors Go lines 435-450: if the evaluator's round is behind
        // ledger.Latest(), wait on pool.cond (which temporarily releases mu)
        // until OnNewBlock rebuilds the evaluator or the timeout expires.
        {
            let latest = self.ledger.latest();
            let wait_expires = Instant::now() + self.config.timeout_on_new_block;

            while guard
                .evaluator
                .as_ref()
                .is_some_and(|e| e.round() <= latest)
                && Instant::now() < wait_expires
            {
                let timeout = wait_expires.saturating_duration_since(Instant::now());
                self.cond.wait_for(guard, timeout);

                if guard.evaluator.is_none() {
                    return Err(PoolError::NoPendingBlockEvaluator);
                }
                if self.is_shutdown() {
                    return Err(PoolError::PoolShutdown);
                }
            }
        }

        // Fee check: use the current fee-per-byte.
        let fee_per_byte = self.recompute_fee_per_byte(guard);
        let consensus = self
            .ledger
            .consensus_params(self.ledger.latest())
            .unwrap_or_default();

        let group_size = tx_group.len();
        for txn in tx_group {
            check_sufficient_fee(txn, fee_per_byte, &consensus, group_size)?;
        }

        // Duplicate check.
        self.check_duplicate(tx_group, guard)?;

        // Feed to the evaluator (with "no space" handling).
        // Mirrors Go's ingest() which calls addToPendingBlockEvaluator().
        self.add_to_pending_block_evaluator(tx_group, guard)?;

        // Store in remembered collections.
        let group_clone: Vec<SignedTransaction> = tx_group.to_vec();
        guard.remembered_tx_groups.push(group_clone);
        for txn in tx_group {
            let txid = compute_txn_id(&txn.txn);
            guard.remembered_txids.insert(txid, txn.clone());
        }

        Ok(())
    }

    // ── Remember commit ─────────────────────────────────────────

    /// Flush remembered transactions to the pending collections.
    ///
    /// When `flush` is true, pending is replaced entirely by remembered
    /// (used during `recompute_block_evaluator`). When false, remembered
    /// is appended to pending (used after `Remember()`).
    ///
    /// Assumes `mu` is held. Acquires `pending_mu` for writing.
    fn remember_commit(&self, inner: &mut PoolInner, flush: bool) {
        let mut pending = self.pending_mu.write();

        if flush {
            pending.tx_groups = std::mem::take(&mut inner.remembered_tx_groups);
            pending.txids = std::mem::take(&mut inner.remembered_txids);
            inner.stateproof_overflowed = false;
        } else {
            pending.tx_groups.append(&mut inner.remembered_tx_groups);
            for (txid, txn) in inner.remembered_txids.drain() {
                pending.txids.insert(txid, txn);
            }
        }

        inner.remembered_tx_groups = Vec::new();
        inner.remembered_txids = HashMap::new();
    }

    // ── Block evaluator recomputation ────────────────────────────

    /// Rebuild the block evaluator from scratch and re-feed surviving
    /// pending transactions.
    ///
    /// Mirrors `recomputeBlockEvaluator()` in go-algorand:
    /// 1. Clear the current evaluator
    /// 2. Get the latest block header from the ledger
    /// 3. Create a new evaluator via `start_evaluator()`
    /// 4. Snapshot the current pending transaction groups
    /// 5. For each group:
    ///    - Skip if already committed (in `committed_txids`)
    ///    - Feed through the new evaluator via `add_to_block_evaluator()`
    ///    - If re-evaluation fails, record the error in the status cache
    /// 6. Flush the surviving groups into pending (replacing old pending state)
    ///
    /// Assumes `mu` is held by the caller.
    fn recompute_block_evaluator(&self, inner: &mut PoolInner, committed_txids: &HashSet<Digest>) {
        inner.evaluator = None;

        let latest = self.ledger.latest();
        let prev_hdr = match self.ledger.block_hdr(latest) {
            Ok(hdr) => hdr,
            Err(_) => return, // Cannot proceed without the header
        };

        // Snapshot the current pending transaction groups (read lock).
        let txgroups: Vec<Vec<SignedTransaction>> = {
            let pending = self.pending_mu.read();
            pending.tx_groups.clone()
        };

        let eval_round = Round(latest.0 + 1);

        // Reset assembly results for this new round.
        {
            let mut asm = self.assembly_mu.lock();
            asm.results = AssemblyResults {
                round_started_evaluating: eval_round,
                ..Default::default()
            };
        }

        // Reset pending whole blocks count for the new evaluator.
        inner.num_pending_whole_blocks = 0;

        // Create a new evaluator for the next round.
        let pending_count = txgroups.iter().map(|g| g.len()).sum::<usize>();
        let hint = pending_count.saturating_sub(committed_txids.len());
        let new_eval = match self.ledger.start_evaluator(prev_hdr, hint, 0) {
            Ok(eval) => eval,
            Err(_) => return, // Cannot start evaluator; leave pool without one
        };
        inner.evaluator = Some(new_eval);

        // Clear remembered state -- we are rebuilding from scratch.
        inner.remembered_tx_groups = Vec::new();
        inner.remembered_txids = HashMap::new();

        // Re-feed surviving transactions through the new evaluator.
        for txgroup in &txgroups {
            if txgroup.is_empty() {
                continue;
            }

            // Skip groups where the first transaction was already committed.
            // In Go, committed txids are checked by the first txn in the group.
            let first_txid = compute_txn_id(&txgroup[0].txn);
            if committed_txids.contains(&first_txid) {
                // Record committed transactions in the status cache
                // with an empty error string (meaning "confirmed").
                for txn in txgroup {
                    let txid = compute_txn_id(&txn.txn);
                    inner.status_cache.put(txid, String::new());
                }
                continue;
            }

            // Try to re-evaluate the group through the new evaluator.
            let result = self.add_to_block_evaluator(txgroup, inner);
            if let Err(e) = result {
                // Record evicted transactions in the status cache.
                let err_str = e.to_string();
                for txn in txgroup {
                    let txid = compute_txn_id(&txn.txn);
                    inner.status_cache.put(txid, err_str.clone());
                }
            }
        }

        // After re-feeding all txns, generate the block if assembly is
        // waiting for this round.  Mirrors Go lines 797-819.
        {
            let mut asm = self.assembly_mu.lock();
            if let Some(ref mut evaluator) = inner.evaluator {
                let eval_rnd = evaluator.round();
                if !asm.results.ok && asm.round <= eval_rnd {
                    asm.results.ok = true;
                    asm.results.assembly_completed_or_abandoned = true;
                    match evaluator.generate_block(&[]) {
                        Ok(block) => {
                            asm.results.block = Some(block);
                        }
                        Err(e) => {
                            asm.results.err = Some(e);
                        }
                    }
                    self.assembly_cond.notify_all();
                }
            }
        }

        // Update fee per byte based on the new state.
        self.recompute_fee_per_byte(inner);

        // Flush remembered (surviving) groups into pending, replacing old state.
        self.remember_commit(inner, true);
    }

    /// Feed a transaction group to the pending block evaluator, handling
    /// "no space" by rolling into the next pending block.
    ///
    /// Mirrors go-algorand's `addToPendingBlockEvaluator()`:
    /// - Calls `add_to_pending_block_evaluator_once()` (expiry check + evaluator call)
    /// - If the evaluator returns "no space", increments `num_pending_whole_blocks`,
    ///   resets txn bytes, and retries once
    ///
    /// This is used by both `ingest()` (normal Remember path) and
    /// `add_to_block_evaluator()` (recompute path). It does NOT store in
    /// remembered collections — the caller is responsible for that.
    fn add_to_pending_block_evaluator(
        &self,
        txgroup: &[SignedTransaction],
        inner: &mut PoolInner,
    ) -> Result<(), PoolError> {
        match self.add_to_pending_block_evaluator_once(txgroup, inner) {
            Ok(()) => Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("no space") || err_str.contains("NoSpace") {
                    inner.num_pending_whole_blocks += 1;
                    if let Some(ref mut evaluator) = inner.evaluator {
                        evaluator.reset_txn_bytes();
                    }
                    self.add_to_pending_block_evaluator_once(txgroup, inner)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Try to feed a transaction group to the evaluator once.
    ///
    /// Mirrors go-algorand's `addToPendingBlockEvaluatorOnce()`:
    /// - Checks if any transaction in the group has expired
    ///   (last_valid < evaluator_round + pending_blocks)
    /// - Feeds the group to the evaluator
    fn add_to_pending_block_evaluator_once(
        &self,
        txgroup: &[SignedTransaction],
        inner: &mut PoolInner,
    ) -> Result<(), PoolError> {
        // Check for expired transactions.
        let effective_round = match &inner.evaluator {
            Some(eval) => Round(eval.round().0 + inner.num_pending_whole_blocks),
            None => return Err(PoolError::NoPendingBlockEvaluator),
        };
        for txn in txgroup {
            if txn.txn.last_valid < effective_round {
                let txid = compute_txn_id(&txn.txn);
                return Err(PoolError::Evaluator(format!(
                    "{} expired, LastValid {} before effective round {}",
                    txid, txn.txn.last_valid, effective_round
                )));
            }
        }

        // Feed to the evaluator.
        if let Some(ref mut evaluator) = inner.evaluator {
            evaluator
                .transaction_group(txgroup)
                .map_err(|e| PoolError::Evaluator(e.to_string()))?;
            Ok(())
        } else {
            Err(PoolError::NoPendingBlockEvaluator)
        }
    }

    /// Feed a transaction group to the block evaluator during re-evaluation.
    ///
    /// Mirrors go-algorand's `add()` which calls `ingest()` with `recomputing: true`.
    /// Calls `add_to_pending_block_evaluator()` for the "no space" handling, then
    /// stores in remembered collections on success.
    ///
    /// This bypasses fee checks (matching Go's `add()` which uses `recomputing: true`).
    fn add_to_block_evaluator(
        &self,
        txgroup: &[SignedTransaction],
        inner: &mut PoolInner,
    ) -> Result<(), PoolError> {
        self.add_to_pending_block_evaluator(txgroup, inner)?;

        // Store in remembered collections (these get flushed to pending later).
        inner.remembered_tx_groups.push(txgroup.to_vec());
        for txn in txgroup {
            let txid = compute_txn_id(&txn.txn);
            inner.remembered_txids.insert(txid, txn.clone());
        }

        Ok(())
    }

    // ── Mutation methods ─────────────────────────────────────────

    /// Validate and remember a transaction group.
    ///
    /// The group must already be properly signed and well-formed.
    ///
    /// Mirrors `Remember()` in go-algorand:
    /// 1. Check pending queue capacity
    /// 2. Acquire mu
    /// 3. Check shutdown
    /// 4. Check fees
    /// 5. Check duplicates
    /// 6. Feed to evaluator
    /// 7. Store in remembered
    /// 8. Flush remembered to pending
    pub fn remember(&self, tx_group: Vec<SignedTransaction>) -> Result<(), PoolError> {
        // Capacity check (before acquiring mu, matching Go).
        self.check_pending_queue_size(&tx_group)?;

        let mut guard = self.mu.lock();

        // Shutdown check.
        if self.is_shutdown() {
            return Err(PoolError::PoolShutdown);
        }

        // Ingest: wait-for-OnNewBlock, fee check, duplicate check,
        // evaluator validation, store.
        let result = self.ingest(&tx_group, &mut guard);
        if let Err(e) = result {
            return Err(PoolError::Remember(Box::new(e)));
        }

        // Flush remembered to pending (non-flush mode).
        self.remember_commit(&mut guard, false);
        Ok(())
    }

    /// Validate and remember a single transaction.
    ///
    /// Convenience wrapper around `remember()` that wraps the transaction
    /// in a singleton group.
    ///
    /// Mirrors `RememberOne()` in go-algorand.
    pub fn remember_one(&self, txn: SignedTransaction) -> Result<(), PoolError> {
        self.remember(vec![txn])
    }

    /// Validate a transaction group without storing it.
    ///
    /// Mirrors `Test()` in go-algorand: checks capacity, then uses the
    /// evaluator's `test_transaction_group` for validation.
    pub fn test(&self, tx_group: &[SignedTransaction]) -> Result<(), PoolError> {
        self.check_pending_queue_size(tx_group)?;

        let inner = self.mu.lock();

        if let Some(ref evaluator) = inner.evaluator {
            evaluator
                .test_transaction_group(tx_group)
                .map_err(|e| PoolError::Evaluator(e.to_string()))?;
            Ok(())
        } else {
            Err(PoolError::NoPendingBlockEvaluator)
        }
    }

    /// Look up a transaction that is (or was) in the pool.
    ///
    /// Returns `(signed_txn, error_string, found)`.
    /// - If the transaction is still pending: `(txn, "", true)`
    /// - If it was evicted with an error: `(default, err, true)`
    /// - If no record exists: `(default, "", false)`
    pub fn lookup(&self, txid: &Digest) -> (SignedTransaction, String, bool) {
        let inner = self.mu.lock();
        let pending = self.pending_mu.read();

        // Check if it's still in pending.
        if let Some(txn) = pending.txids.get(txid) {
            return (txn.clone(), String::new(), true);
        }

        // Check the status cache for recently evicted transactions.
        if let Some(status) = inner.status_cache.check(txid) {
            return (SignedTransaction::default(), status.txn_err.clone(), true);
        }

        (SignedTransaction::default(), String::new(), false)
    }

    /// Process a newly committed block: evict included/expired transactions,
    /// adjust fee thresholds, and rebuild the block evaluator.
    ///
    /// Mirrors `OnNewBlock()` in go-algorand:
    /// 1. Compute the set of committed transaction IDs from the block's payset
    /// 2. Adjust the fee threshold multiplier based on pool load
    /// 3. Call `recompute_block_evaluator` to rebuild the evaluator and re-feed
    ///    surviving transactions
    ///
    /// The `committed_txids` parameter provides the set of transaction IDs that
    /// were included in the block. In go-algorand this comes from `delta.Txids`;
    /// here we accept it directly to avoid needing the full `StateDelta` type.
    pub fn on_new_block(&self, block: &Block, committed_txids: &HashSet<Digest>) {
        let mut inner = self.mu.lock();

        if self.is_shutdown() {
            return;
        }

        // Only process if the block is at or ahead of our evaluator's round.
        let should_process = match &inner.evaluator {
            None => true,
            Some(eval) => block.round >= eval.round(),
        };

        if should_process {
            // Adjust the pool fee threshold. The rules are:
            // - If there was less than one full block in the pool, reduce
            //   the multiplier by 2x. It will eventually go to 0, so that
            //   only the flat MinTxnFee matters if the pool is idle.
            // - If there were less than two full blocks in the pool, keep
            //   the multiplier as-is.
            // - If there were two or more full blocks in the pool, grow
            //   the multiplier by 2x (or increment by 1, if 0).
            match inner.num_pending_whole_blocks {
                0 => {
                    inner.fee_threshold_multiplier /= self.config.exponential_increase_factor;
                }
                1 => {
                    // Keep the fee multiplier the same.
                }
                _ => {
                    if inner.fee_threshold_multiplier == 0 {
                        inner.fee_threshold_multiplier = 1;
                    } else {
                        inner.fee_threshold_multiplier = inner
                            .fee_threshold_multiplier
                            .saturating_mul(self.config.exponential_increase_factor);
                    }
                }
            }

            // Recompute the pool by starting from the new latest block.
            // This has the side-effect of discarding transactions that
            // have been committed (or that are otherwise no longer valid).
            self.recompute_block_evaluator(&mut inner, committed_txids);
        }

        // Wake any threads waiting in ingest() for the evaluator to catch up.
        // Mirrors Go's `defer pool.cond.Broadcast()` in OnNewBlock().
        self.cond.notify_all();
    }

    /// Assemble a block for `round`, spending at most until `deadline`.
    ///
    /// Mirrors `AssembleBlock()` in go-algorand:
    /// 1. If the pool is more than two rounds behind, assemble an empty block
    /// 2. If the requested round is behind the pool's evaluator, return stale error
    /// 3. Set the assembly deadline and round, then wait for results
    /// 4. If the deadline expires, try assembling an empty block as fallback
    /// 5. Wait an additional `assembly_wait_eps` for the full block
    /// 6. Return whichever block is available
    pub fn assemble_block(&self, round: Round, deadline: Instant) -> Result<Block, PoolError> {
        {
            let mut asm = self.assembly_mu.lock();

            // If the pool is more than two rounds behind, assemble an empty block.
            if asm.results.round_started_evaluating <= round.sub_saturate(2) {
                drop(asm);
                return self.assemble_empty_block(round);
            }

            // If the requested round is behind the pool's evaluator round,
            // we've already moved past it — return a stale error.
            if asm.results.round_started_evaluating > round {
                return Err(PoolError::StaleBlockAssemblyRequest);
            }

            // Set the assembly deadline and round so that
            // `recompute_block_evaluator` (called from `on_new_block`) knows
            // what we are waiting for.
            asm.deadline = Some(deadline);
            asm.round = round;

            // Wait until results are ready or deadline passes.
            while Instant::now() < deadline
                && (!asm.results.ok || asm.results.round_started_evaluating != round)
            {
                let timeout = deadline.saturating_duration_since(Instant::now());
                self.assembly_cond.wait_for(&mut asm, timeout);
            }

            if !asm.results.ok {
                // Deadline expired. Prepare an empty block as fallback while
                // we wait the extra epsilon.
                drop(asm);
                let empty_result = self.assemble_empty_block(round);
                let mut asm = self.assembly_mu.lock();

                // Check if the pool advanced past our round while we were
                // assembling the empty block.
                if asm.results.round_started_evaluating > round {
                    return Err(PoolError::StaleBlockAssemblyRequest);
                }

                // Wait an additional assembly_wait_eps for the full block.
                let extended_deadline = deadline + self.config.assembly_wait_eps;
                while Instant::now() < extended_deadline
                    && (!asm.results.ok || asm.results.round_started_evaluating != round)
                {
                    let timeout = extended_deadline.saturating_duration_since(Instant::now());
                    self.assembly_cond.wait_for(&mut asm, timeout);
                }

                if !asm.results.ok {
                    // Still no full block — return the empty block.
                    asm.deadline = None;
                    return empty_result;
                }
                // Fall through — re-acquire the lock below to extract results.
            }
        }

        // Re-acquire the lock to extract results.
        let mut asm = self.assembly_mu.lock();

        // Clear the assembly deadline.
        asm.deadline = None;

        if let Some(ref e) = asm.results.err {
            return Err(PoolError::Evaluator(format!(
                "AssembleBlock: encountered error for round {}: {}",
                round, e
            )));
        }

        if asm.results.round_started_evaluating > round {
            return Err(PoolError::StaleBlockAssemblyRequest);
        } else if asm.results.round_started_evaluating == round.sub_saturate(1) {
            // Assembled block didn't catch up to requested round.
            drop(asm);
            return self.assemble_empty_block(round);
        } else if asm.results.round_started_evaluating < round {
            return Err(PoolError::Evaluator(format!(
                "AssembleBlock: assembled block round much behind requested round: {} != {}",
                asm.results.round_started_evaluating, round
            )));
        }

        // Success — return the assembled block.
        asm.results
            .block
            .clone()
            .ok_or_else(|| PoolError::Evaluator("AssembleBlock: no block produced".into()))
    }

    /// Assemble an empty block for `round` without feeding any transactions.
    ///
    /// Mirrors `assembleEmptyBlock()` in go-algorand:
    /// creates a fresh evaluator for the round and immediately calls
    /// `generate_block()`.
    pub fn assemble_empty_block(&self, round: Round) -> Result<Block, PoolError> {
        let prev_round = Round(round.0.saturating_sub(1));
        let prev_hdr = self.ledger.block_hdr(prev_round).map_err(|e| {
            PoolError::Evaluator(format!(
                "TransactionPool.assembleEmptyBlock: cannot get prev header for {}: {}",
                prev_round, e
            ))
        })?;

        let mut evaluator = self.ledger.start_evaluator(prev_hdr, 0, 0).map_err(|e| {
            PoolError::Evaluator(format!(
                "TransactionPool.assembleEmptyBlock: cannot start evaluator for {}: {}",
                round, e
            ))
        })?;

        evaluator.generate_block(&[]).map_err(|e| {
            PoolError::Evaluator(format!(
                "TransactionPool.assembleEmptyBlock: cannot generate block for {}: {}",
                round, e
            ))
        })
    }

    /// Check whether block assembly has timed out given projected durations.
    ///
    /// Mirrors `isAssemblyTimedOut()` in go-algorand. Returns `true` if the
    /// projected time to finish (base + per_txn * pending_count) would exceed
    /// the deadline.
    ///
    /// This is a pure function (no `&self`) so it can be used as a static helper.
    pub fn is_assembly_timed_out(
        started: Instant,
        deadline: Instant,
        base_duration: Duration,
        per_txn_duration: Duration,
        pending_count: usize,
    ) -> bool {
        let generate_block_duration =
            base_duration + per_txn_duration * (pending_count.min(u32::MAX as usize) as u32);
        // Check: now > deadline - generate_block_duration
        // Equivalent: deadline < now + generate_block_duration
        Instant::now()
            > deadline
                .checked_sub(generate_block_duration)
                .unwrap_or(started)
    }

    /// Assemble a block in dev mode: recompute the evaluator and immediately
    /// assemble a block from current pending transactions.
    ///
    /// Mirrors `AssembleDevModeBlock()` in go-algorand.
    pub fn assemble_dev_mode_block(&self) -> Result<Block, PoolError> {
        let mut inner = self.mu.lock();

        // Drop the current evaluator and rebuild from scratch.
        self.recompute_block_evaluator(&mut inner, &HashSet::new());

        // Read the evaluator round while we still have the lock.
        let eval_round = inner
            .evaluator
            .as_ref()
            .map(|e| e.round())
            .ok_or(PoolError::NoPendingBlockEvaluator)?;

        drop(inner);

        // The recompute above already pre-generated the block, so
        // assemble_block should return immediately.
        let deadline = Instant::now() + self.config.proposal_assembly_time;
        self.assemble_block(eval_round, deadline)
    }

    /// Signal the pool to stop accepting new transactions.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Return `true` if the pool has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Reset the pool — discard all pending and remembered transactions
    /// and rebuild the block evaluator from scratch.
    pub fn reset(&self) {
        let mut inner = self.mu.lock();
        let mut pending = self.pending_mu.write();

        pending.txids.clear();
        pending.tx_groups.clear();
        inner.remembered_txids.clear();
        inner.remembered_tx_groups.clear();
        inner.num_pending_whole_blocks = 0;
        inner.fee_threshold_multiplier = 0;
        inner.evaluator = None;
        inner.stateproof_overflowed = false;
        inner.status_cache.reset();

        self.fee_per_byte.store(0, Ordering::Relaxed);
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{BlockEvaluator, PoolLedger};
    use algo_types::{Block, BlockHeader, ConsensusParams, TxnType};

    /// Minimal stub ledger for unit tests.
    struct StubLedger {
        round: Round,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
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
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
            }))
        }
    }

    /// Minimal stub evaluator for unit tests.
    struct StubEvaluator {
        round: Round,
    }

    impl BlockEvaluator for StubEvaluator {
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

    /// Create a pool with an evaluator already installed.
    fn make_pool_with_evaluator(pool_size: usize) -> TransactionPool {
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let config = PoolConfig {
            pool_size,
            ..Default::default()
        };
        let pool = TransactionPool::new(config, ledger.clone());

        // Install a stub evaluator so remember() can proceed.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(StubEvaluator { round: Round(2) }));
        }

        pool
    }

    /// Create a test transaction with a unique note (to produce distinct txn IDs).
    fn make_test_txn(note_byte: u8) -> SignedTransaction {
        let mut txn = SignedTransaction::default();
        txn.txn.txn_type = TxnType::Pay;
        txn.txn.fee = 1_000_000; // high fee to pass any fee check
        txn.txn.first_valid = Round(1);
        txn.txn.last_valid = Round(1000);
        txn.txn.note = serde_bytes::ByteBuf::from(vec![note_byte]);
        txn
    }

    // ── Construction tests ───────────────────────────────────────

    #[test]
    fn test_pool_construction() {
        let ledger = Arc::new(StubLedger { round: Round(42) });
        let pool = TransactionPool::new(PoolConfig::default(), ledger);

        assert_eq!(pool.pending_count(), 0);
        assert!(pool.pending_tx_ids().is_empty());
        assert!(pool.pending_tx_groups().is_empty());
        assert_eq!(pool.fee_per_byte(), 0);
        assert!(!pool.is_shutdown());
    }

    #[test]
    fn test_pool_shutdown() {
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let pool = TransactionPool::new(PoolConfig::default(), ledger);

        assert!(!pool.is_shutdown());
        pool.shutdown();
        assert!(pool.is_shutdown());
    }

    #[test]
    fn test_pool_config_clamps_exp_fee_factor() {
        let config = PoolConfig {
            exponential_increase_factor: 0,
            ..Default::default()
        };
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let pool = TransactionPool::new(config, ledger);

        // The pool should have clamped exp_fee_factor to 1 internally.
        // We verify indirectly: fee_per_byte starts at 0 (no load).
        assert_eq!(pool.fee_per_byte(), 0);
    }

    // ── Remember tests ──────────────────────────────────────────

    #[test]
    fn test_remember_single_txn() {
        let pool = make_pool_with_evaluator(1000);
        let txn = make_test_txn(1);

        let result = pool.remember_one(txn.clone());
        assert!(
            result.is_ok(),
            "remember_one should succeed: {:?}",
            result.err()
        );

        // After remember (which calls remember_commit), the txn should be in pending.
        assert_eq!(pool.pending_count(), 1);
        assert_eq!(pool.pending_tx_ids().len(), 1);
        assert_eq!(pool.pending_tx_groups().len(), 1);
    }

    #[test]
    fn test_remember_group() {
        let pool = make_pool_with_evaluator(1000);
        let txn1 = make_test_txn(1);
        let txn2 = make_test_txn(2);
        let txn3 = make_test_txn(3);

        let result = pool.remember(vec![txn1, txn2, txn3]);
        assert!(
            result.is_ok(),
            "remember group should succeed: {:?}",
            result.err()
        );

        // All 3 txn IDs should be tracked.
        assert_eq!(pool.pending_count(), 3);
        assert_eq!(pool.pending_tx_ids().len(), 3);
        // But only 1 group.
        assert_eq!(pool.pending_tx_groups().len(), 1);
    }

    #[test]
    fn test_remember_multiple_groups() {
        let pool = make_pool_with_evaluator(1000);

        pool.remember_one(make_test_txn(1)).unwrap();
        pool.remember_one(make_test_txn(2)).unwrap();
        pool.remember(vec![make_test_txn(3), make_test_txn(4)])
            .unwrap();

        assert_eq!(pool.pending_count(), 4);
        assert_eq!(pool.pending_tx_ids().len(), 4);
        assert_eq!(pool.pending_tx_groups().len(), 3);
    }

    // ── Duplicate detection ─────────────────────────────────────

    #[test]
    fn test_duplicate_detection() {
        let pool = make_pool_with_evaluator(1000);
        let txn = make_test_txn(42);

        // First remember should succeed.
        pool.remember_one(txn.clone()).unwrap();

        // Second remember of the same txn should fail.
        let result = pool.remember_one(txn);
        assert!(result.is_err(), "duplicate txn should be rejected");

        // Verify it's a Remember-wrapped DuplicateTxn error.
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("already in the pool"),
            "error should mention duplicate: {}",
            err_str
        );
    }

    #[test]
    fn test_duplicate_in_group_rejected() {
        let pool = make_pool_with_evaluator(1000);
        let txn1 = make_test_txn(10);

        // Remember txn1.
        pool.remember_one(txn1.clone()).unwrap();

        // Try to remember a group containing txn1 — should fail.
        let txn2 = make_test_txn(11);
        let result = pool.remember(vec![txn2, txn1]);
        assert!(
            result.is_err(),
            "group with duplicate txn should be rejected"
        );
    }

    // ── Capacity tests ──────────────────────────────────────────

    #[test]
    fn test_capacity_limit() {
        let pool = make_pool_with_evaluator(3);

        pool.remember_one(make_test_txn(1)).unwrap();
        pool.remember_one(make_test_txn(2)).unwrap();
        pool.remember_one(make_test_txn(3)).unwrap();

        // Pool is now full (3 txns, capacity 3).
        let result = pool.remember_one(make_test_txn(4));
        assert!(result.is_err(), "should reject when pool is full");

        let err = result.unwrap_err();
        assert!(
            matches!(err, PoolError::PendingQueueFull),
            "expected PendingQueueFull, got: {:?}",
            err
        );
    }

    #[test]
    fn test_capacity_group_counts_individual_txns() {
        // Pool capacity is 2, but we try to add a group of 3 txns.
        let pool = make_pool_with_evaluator(2);

        let result = pool.remember(vec![make_test_txn(1), make_test_txn(2), make_test_txn(3)]);
        assert!(
            result.is_err(),
            "group exceeding capacity should be rejected"
        );
        assert!(
            matches!(result.unwrap_err(), PoolError::PendingQueueFull),
            "expected PendingQueueFull"
        );
    }

    // ── Shutdown tests ──────────────────────────────────────────

    #[test]
    fn test_remember_after_shutdown() {
        let pool = make_pool_with_evaluator(1000);
        pool.shutdown();

        let result = pool.remember_one(make_test_txn(1));
        assert!(result.is_err(), "should reject after shutdown");

        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("shutting down"),
            "error should mention shutdown: {}",
            err_str
        );
    }

    // ── No evaluator tests ──────────────────────────────────────

    #[test]
    fn test_remember_without_evaluator() {
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let pool = TransactionPool::new(PoolConfig::default(), ledger);
        // No evaluator installed.

        let result = pool.remember_one(make_test_txn(1));
        assert!(result.is_err(), "should fail without evaluator");

        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("no pending block evaluator"),
            "error should mention no evaluator: {}",
            err_str
        );
    }

    // ── Test method ─────────────────────────────────────────────

    #[test]
    fn test_test_method() {
        let pool = make_pool_with_evaluator(1000);
        let txn = make_test_txn(1);

        // Test should succeed without storing.
        let result = pool.test(&[txn]);
        assert!(result.is_ok(), "test should succeed: {:?}", result.err());

        // Nothing should be in pending.
        assert_eq!(pool.pending_count(), 0);
    }

    #[test]
    fn test_test_without_evaluator() {
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let pool = TransactionPool::new(PoolConfig::default(), ledger);

        let result = pool.test(&[make_test_txn(1)]);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), PoolError::NoPendingBlockEvaluator),
            "expected NoPendingBlockEvaluator"
        );
    }

    // ── Lookup tests ────────────────────────────────────────────

    #[test]
    fn test_lookup_pending_txn() {
        let pool = make_pool_with_evaluator(1000);
        let txn = make_test_txn(99);
        let txid = compute_txn_id(&txn.txn);

        pool.remember_one(txn.clone()).unwrap();

        let (found_txn, err_str, found) = pool.lookup(&txid);
        assert!(found, "should find pending txn");
        assert!(err_str.is_empty(), "pending txn should have no error");
        assert_eq!(found_txn.txn.note, txn.txn.note);
    }

    #[test]
    fn test_lookup_missing_txn() {
        let pool = make_pool_with_evaluator(1000);
        let txid = Digest([0u8; 32]);

        let (_txn, err_str, found) = pool.lookup(&txid);
        assert!(!found, "should not find unknown txn");
        assert!(err_str.is_empty());
    }

    // ── Reset test ──────────────────────────────────────────────

    #[test]
    fn test_reset_clears_pool() {
        let pool = make_pool_with_evaluator(1000);

        pool.remember_one(make_test_txn(1)).unwrap();
        pool.remember_one(make_test_txn(2)).unwrap();
        assert_eq!(pool.pending_count(), 2);

        pool.reset();

        assert_eq!(pool.pending_count(), 0);
        assert!(pool.pending_tx_ids().is_empty());
        assert!(pool.pending_tx_groups().is_empty());
    }

    // ── Fee check integration ───────────────────────────────────

    #[test]
    fn test_fee_threshold_under_load() {
        let pool = make_pool_with_evaluator(1000);

        // Simulate load by setting fee_threshold_multiplier and num_pending_whole_blocks.
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 1;
            inner.num_pending_whole_blocks = 3;
        }

        // A transaction with very low fee should be rejected.
        let mut txn = make_test_txn(1);
        txn.txn.fee = 1; // very low fee

        let result = pool.remember_one(txn);
        assert!(result.is_err(), "low-fee txn should be rejected under load");

        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("fee") && err_str.contains("below threshold"),
            "error should mention fee threshold: {}",
            err_str
        );
    }

    // ── pending_by_address tests ─────────────────────────────────

    /// Helper: create a test txn with a specific sender address.
    fn make_test_txn_from(note_byte: u8, sender: Address) -> SignedTransaction {
        let mut txn = make_test_txn(note_byte);
        txn.txn.sender = sender;
        txn
    }

    #[test]
    fn test_pending_by_address_single_match_by_sender() {
        let pool = make_pool_with_evaluator(1000);
        let addr = Address([1u8; 32]);
        let other = Address([2u8; 32]);

        let txn_match = make_test_txn_from(1, addr);
        let txn_other = make_test_txn_from(2, other);

        pool.remember_one(txn_match.clone()).unwrap();
        pool.remember_one(txn_other).unwrap();

        let result = pool.pending_by_address(&addr);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].txn.sender, addr);
        assert_eq!(result[0].txn.note, txn_match.txn.note);
    }

    #[test]
    fn test_pending_by_address_match_by_auth_addr() {
        let pool = make_pool_with_evaluator(1000);
        let addr = Address([3u8; 32]);
        let actual_sender = Address([4u8; 32]);

        // Rekeyed account: sender is different but auth_addr matches.
        let mut txn = make_test_txn_from(10, actual_sender);
        txn.auth_addr = Some(addr);

        pool.remember_one(txn.clone()).unwrap();

        let result = pool.pending_by_address(&addr);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].auth_addr, Some(addr));
        assert_eq!(result[0].txn.note, txn.txn.note);
    }

    #[test]
    fn test_pending_by_address_no_matches() {
        let pool = make_pool_with_evaluator(1000);
        let addr_a = Address([5u8; 32]);
        let addr_b = Address([6u8; 32]);
        let query_addr = Address([99u8; 32]);

        pool.remember_one(make_test_txn_from(1, addr_a)).unwrap();
        pool.remember_one(make_test_txn_from(2, addr_b)).unwrap();

        let result = pool.pending_by_address(&query_addr);
        assert!(
            result.is_empty(),
            "expected no matches for unrelated address"
        );
    }

    #[test]
    fn test_pending_by_address_multiple_matches_across_groups() {
        let pool = make_pool_with_evaluator(1000);
        let addr = Address([7u8; 32]);
        let other = Address([8u8; 32]);

        // Group 1: two txns from addr.
        let txn1 = make_test_txn_from(20, addr);
        let txn2 = make_test_txn_from(21, addr);
        pool.remember(vec![txn1, txn2]).unwrap();

        // Group 2: singleton from another address.
        pool.remember_one(make_test_txn_from(22, other)).unwrap();

        // Group 3: one from addr, one from other.
        let txn3 = make_test_txn_from(23, addr);
        let txn4 = make_test_txn_from(24, other);
        pool.remember(vec![txn3, txn4]).unwrap();

        let result = pool.pending_by_address(&addr);
        assert_eq!(
            result.len(),
            3,
            "should find 3 txns from addr across groups"
        );

        // Verify they are the right txns.
        for txn in &result {
            assert_eq!(txn.txn.sender, addr);
        }
    }

    #[test]
    fn test_pending_by_address_matches_sender_and_auth_addr() {
        let pool = make_pool_with_evaluator(1000);
        let addr = Address([9u8; 32]);
        let other_sender = Address([10u8; 32]);

        // Direct sender match.
        let txn_sender = make_test_txn_from(30, addr);
        pool.remember_one(txn_sender).unwrap();

        // Auth addr match (rekeyed).
        let mut txn_rekeyed = make_test_txn_from(31, other_sender);
        txn_rekeyed.auth_addr = Some(addr);
        pool.remember_one(txn_rekeyed).unwrap();

        let result = pool.pending_by_address(&addr);
        assert_eq!(result.len(), 2, "should match both sender and auth_addr");
    }

    // ── Query method correctness tests ───────────────────────────

    #[test]
    fn test_pending_tx_ids_returns_correct_ids() {
        let pool = make_pool_with_evaluator(1000);
        let txn1 = make_test_txn(50);
        let txn2 = make_test_txn(51);
        let id1 = compute_txn_id(&txn1.txn);
        let id2 = compute_txn_id(&txn2.txn);

        pool.remember_one(txn1).unwrap();
        pool.remember_one(txn2).unwrap();

        let ids = pool.pending_tx_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_pending_tx_groups_returns_correct_groups() {
        let pool = make_pool_with_evaluator(1000);

        // Add a singleton group.
        pool.remember_one(make_test_txn(60)).unwrap();
        // Add a two-txn group.
        pool.remember(vec![make_test_txn(61), make_test_txn(62)])
            .unwrap();

        let groups = pool.pending_tx_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 2);
    }

    #[test]
    fn test_fee_per_byte_reflects_state() {
        let pool = make_pool_with_evaluator(1000);

        // Initially 0.
        assert_eq!(pool.fee_per_byte(), 0);

        // Manually set load state and recompute.
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 5;
            inner.num_pending_whole_blocks = 1;
            pool.recompute_fee_per_byte(&inner);
        }

        assert_eq!(pool.fee_per_byte(), 5);
    }

    // ── on_new_block tests ───────────────────────────────────────

    /// A ledger stub with an atomic round counter so on_new_block can
    /// see advancing rounds, and a configurable evaluator factory.
    struct AdvancingLedger {
        round: std::sync::atomic::AtomicU64,
        /// If set, the evaluator factory will produce evaluators that
        /// reject transactions matching these note bytes.
        reject_notes: parking_lot::Mutex<HashSet<u8>>,
    }

    impl AdvancingLedger {
        fn new(round: u64) -> Self {
            Self {
                round: std::sync::atomic::AtomicU64::new(round),
                reject_notes: parking_lot::Mutex::new(HashSet::new()),
            }
        }

        fn add_reject_note(&self, note: u8) {
            self.reject_notes.lock().insert(note);
        }
    }

    impl PoolLedger for AdvancingLedger {
        fn latest(&self) -> Round {
            Round(self.round.load(std::sync::atomic::Ordering::SeqCst))
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
            let reject_notes = self.reject_notes.lock().clone();
            Ok(Box::new(FilteringEvaluator {
                round: self.latest().next(),
                reject_notes,
            }))
        }
    }

    /// An evaluator that rejects transactions whose note byte is in
    /// the `reject_notes` set. Useful for testing re-evaluation eviction.
    struct FilteringEvaluator {
        round: Round,
        reject_notes: HashSet<u8>,
    }

    impl BlockEvaluator for FilteringEvaluator {
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
            Ok(())
        }

        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }

        fn reset_txn_bytes(&mut self) {}
    }

    /// Create a test transaction with specific `last_valid`.
    fn make_test_txn_with_last_valid(note_byte: u8, last_valid: Round) -> SignedTransaction {
        let mut txn = make_test_txn(note_byte);
        txn.txn.last_valid = last_valid;
        txn
    }

    /// Create a pool backed by an `AdvancingLedger` with an evaluator installed.
    fn make_pool_with_advancing_ledger(
        pool_size: usize,
        round: u64,
    ) -> (TransactionPool, Arc<AdvancingLedger>) {
        let ledger = Arc::new(AdvancingLedger::new(round));
        let config = PoolConfig {
            pool_size,
            ..Default::default()
        };
        let pool = TransactionPool::new(config, ledger.clone());

        // Install a filtering evaluator so remember() can proceed.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(FilteringEvaluator {
                round: Round(round + 1),
                reject_notes: HashSet::new(),
            }));
        }

        (pool, ledger)
    }

    #[test]
    fn test_on_new_block_removes_confirmed_txns() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        let txn2 = make_test_txn(2);
        let txn3 = make_test_txn(3);
        let txid1 = compute_txn_id(&txn1.txn);
        let txid2 = compute_txn_id(&txn2.txn);
        let txid3 = compute_txn_id(&txn3.txn);

        pool.remember_one(txn1).unwrap();
        pool.remember_one(txn2).unwrap();
        pool.remember_one(txn3).unwrap();
        assert_eq!(pool.pending_count(), 3);

        // Simulate a block that includes txn1 and txn2.
        let mut committed = HashSet::new();
        committed.insert(txid1);
        committed.insert(txid2);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &committed);

        // Only txn3 should remain.
        assert_eq!(pool.pending_count(), 1);
        let remaining_ids = pool.pending_tx_ids();
        assert!(!remaining_ids.contains(&txid1), "txn1 should be removed");
        assert!(!remaining_ids.contains(&txid2), "txn2 should be removed");
        assert!(remaining_ids.contains(&txid3), "txn3 should survive");
    }

    #[test]
    fn test_on_new_block_confirmed_txns_in_status_cache() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        let txid1 = compute_txn_id(&txn1.txn);

        pool.remember_one(txn1).unwrap();

        let mut committed = HashSet::new();
        committed.insert(txid1);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &committed);

        // txn1 should be in the status cache as confirmed (empty error).
        let (_txn, err_str, found) = pool.lookup(&txid1);
        assert!(found, "confirmed txn should be in status cache");
        assert!(
            err_str.is_empty(),
            "confirmed txn should have empty error string"
        );
    }

    #[test]
    fn test_on_new_block_evicts_expired_txns() {
        let (pool, ledger) = make_pool_with_advancing_ledger(1000, 1);
        // Initial evaluator is at round 2.

        // txn1: expires at round 1000 (will survive)
        let txn1 = make_test_txn_with_last_valid(1, Round(1000));
        let txid1 = compute_txn_id(&txn1.txn);

        // txn2: expires at round 2 (valid now with evaluator at round 2,
        // but will be evicted when on_new_block rebuilds the evaluator at round 3)
        let txn2 = make_test_txn_with_last_valid(2, Round(2));
        let txid2 = compute_txn_id(&txn2.txn);

        pool.remember_one(txn1).unwrap();
        pool.remember_one(txn2).unwrap();
        assert_eq!(pool.pending_count(), 2);

        // Advance the ledger round to simulate the block being applied.
        // This ensures recompute_block_evaluator creates a new evaluator at round 3.
        ledger.round.store(2, std::sync::atomic::Ordering::SeqCst);

        // Process a new block -- the new evaluator will be at round 3,
        // so txn2 (last_valid=2) should be evicted.
        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // Only txn1 should remain.
        assert_eq!(pool.pending_count(), 1);
        let remaining_ids = pool.pending_tx_ids();
        assert!(remaining_ids.contains(&txid1), "txn1 should survive");
        assert!(!remaining_ids.contains(&txid2), "txn2 should be evicted");

        // txn2 should be in the status cache with an error.
        let (_txn, err_str, found) = pool.lookup(&txid2);
        assert!(found, "evicted txn should be in status cache");
        assert!(
            !err_str.is_empty(),
            "evicted txn should have an error string"
        );
    }

    #[test]
    fn test_on_new_block_adjusts_fee_threshold_decrease() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Simulate load: set multiplier to 4 and pending blocks to 0.
        // On new block with 0 pending blocks, multiplier should be divided by exp_factor (2).
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 4;
            inner.num_pending_whole_blocks = 0;
        }

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // The fee threshold multiplier should have been halved (4 / 2 = 2).
        let inner = pool.mu.lock();
        assert_eq!(
            inner.fee_threshold_multiplier, 2,
            "multiplier should be halved when no pending blocks"
        );
    }

    #[test]
    fn test_on_new_block_adjusts_fee_threshold_steady() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // With exactly 1 pending whole block, multiplier stays the same.
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 4;
            inner.num_pending_whole_blocks = 1;
        }

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        let inner = pool.mu.lock();
        assert_eq!(
            inner.fee_threshold_multiplier, 4,
            "multiplier should stay the same with 1 pending block"
        );
    }

    #[test]
    fn test_on_new_block_adjusts_fee_threshold_increase() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // With 2+ pending whole blocks, multiplier should grow.
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 4;
            inner.num_pending_whole_blocks = 3;
        }

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        let inner = pool.mu.lock();
        assert_eq!(
            inner.fee_threshold_multiplier, 8,
            "multiplier should double (4 * 2) with 3 pending blocks"
        );
    }

    #[test]
    fn test_on_new_block_adjusts_fee_threshold_increase_from_zero() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // With 2+ pending whole blocks and multiplier at 0, it should become 1.
        {
            let mut inner = pool.mu.lock();
            inner.fee_threshold_multiplier = 0;
            inner.num_pending_whole_blocks = 2;
        }

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        let inner = pool.mu.lock();
        assert_eq!(
            inner.fee_threshold_multiplier, 1,
            "multiplier should become 1 from 0 with 2+ pending blocks"
        );
    }

    #[test]
    fn test_on_new_block_surviving_txns_re_evaluated_and_kept() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        let txn2 = make_test_txn(2);
        let txid1 = compute_txn_id(&txn1.txn);
        let txid2 = compute_txn_id(&txn2.txn);

        pool.remember_one(txn1).unwrap();
        pool.remember_one(txn2).unwrap();
        assert_eq!(pool.pending_count(), 2);

        // No transactions committed.
        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // Both transactions should survive re-evaluation.
        assert_eq!(pool.pending_count(), 2);
        let ids = pool.pending_tx_ids();
        assert!(ids.contains(&txid1));
        assert!(ids.contains(&txid2));
    }

    #[test]
    fn test_on_new_block_txns_failing_re_evaluation_are_evicted() {
        let (pool, ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        let txn2 = make_test_txn(2);
        let txn3 = make_test_txn(3);
        let txid1 = compute_txn_id(&txn1.txn);
        let txid2 = compute_txn_id(&txn2.txn);
        let txid3 = compute_txn_id(&txn3.txn);

        pool.remember_one(txn1).unwrap();
        pool.remember_one(txn2).unwrap();
        pool.remember_one(txn3).unwrap();
        assert_eq!(pool.pending_count(), 3);

        // Configure the ledger so the new evaluator rejects note byte 2.
        ledger.add_reject_note(2);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // txn1 and txn3 should survive; txn2 should be evicted.
        assert_eq!(pool.pending_count(), 2);
        let ids = pool.pending_tx_ids();
        assert!(ids.contains(&txid1), "txn1 should survive");
        assert!(!ids.contains(&txid2), "txn2 should be evicted");
        assert!(ids.contains(&txid3), "txn3 should survive");

        // txn2 should be in the status cache with an error.
        let (_txn, err_str, found) = pool.lookup(&txid2);
        assert!(found, "evicted txn2 should be in status cache");
        assert!(
            err_str.contains("rejected"),
            "error should mention rejection: {}",
            err_str
        );
    }

    #[test]
    fn test_on_new_block_shutdown_is_noop() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        pool.remember_one(txn1).unwrap();
        assert_eq!(pool.pending_count(), 1);

        pool.shutdown();

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // Pool should be unchanged (shutdown skips processing).
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_on_new_block_group_eviction() {
        // Test that when a group has its first txn committed, the whole
        // group is removed.
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let txn1 = make_test_txn(1);
        let txn2 = make_test_txn(2);
        let txid1 = compute_txn_id(&txn1.txn);
        let txid2 = compute_txn_id(&txn2.txn);

        // Add as a group.
        pool.remember(vec![txn1, txn2]).unwrap();
        assert_eq!(pool.pending_count(), 2);

        // Commit only the first txn of the group.
        let mut committed = HashSet::new();
        committed.insert(txid1);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &committed);

        // The entire group should be removed (committed check uses first txn ID).
        assert_eq!(pool.pending_count(), 0);
        let ids = pool.pending_tx_ids();
        assert!(!ids.contains(&txid1));
        assert!(!ids.contains(&txid2));
    }

    #[test]
    fn test_on_new_block_evaluator_rebuilt() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        // After on_new_block, the evaluator should be rebuilt.
        // We can verify by successfully remembering a new transaction.
        let txn = make_test_txn(100);
        let result = pool.remember_one(txn);
        assert!(
            result.is_ok(),
            "should be able to remember after on_new_block: {:?}",
            result.err()
        );
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_on_new_block_empty_pool() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Empty pool should handle on_new_block gracefully.
        assert_eq!(pool.pending_count(), 0);

        let block = Block {
            round: Round(2),
            ..Block::default()
        };

        pool.on_new_block(&block, &HashSet::new());

        assert_eq!(pool.pending_count(), 0);
    }

    // ── Block assembly tests ────────────────────────────────────────

    #[test]
    fn test_assemble_empty_block_produces_block() {
        let ledger = Arc::new(StubLedger { round: Round(1) });
        let pool = TransactionPool::new(PoolConfig::default(), ledger);

        // Assemble an empty block for round 2 (previous round is 1).
        let result = pool.assemble_empty_block(Round(2));
        assert!(
            result.is_ok(),
            "assemble_empty_block should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_assemble_block_with_pending_txns() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Add some transactions.
        pool.remember_one(make_test_txn(1)).unwrap();
        pool.remember_one(make_test_txn(2)).unwrap();
        assert_eq!(pool.pending_count(), 2);

        // Process on_new_block so the evaluator rebuilds and generates
        // assembly results for round 2.
        let block = Block {
            round: Round(2),
            ..Block::default()
        };
        pool.on_new_block(&block, &HashSet::new());

        // Now assemble_block for the evaluator's round should succeed.
        let eval_round = {
            let inner = pool.mu.lock();
            inner.evaluator.as_ref().unwrap().round()
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = pool.assemble_block(eval_round, deadline);
        assert!(
            result.is_ok(),
            "assemble_block should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_assemble_block_stale_round_returns_error() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Process on_new_block so the pool is at round 2.
        let block = Block {
            round: Round(2),
            ..Block::default()
        };
        pool.on_new_block(&block, &HashSet::new());

        // Requesting assembly for round 1 (which is behind the pool)
        // should return StaleBlockAssemblyRequest.
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = pool.assemble_block(Round(1), deadline);
        assert!(result.is_err(), "stale round should fail");
        assert!(
            matches!(result.unwrap_err(), PoolError::StaleBlockAssemblyRequest),
            "expected StaleBlockAssemblyRequest"
        );
    }

    #[test]
    fn test_assemble_block_pool_far_behind_returns_empty_block() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // The assembly results start at round_started_evaluating = 0.
        // Request round 10 which is far ahead — pool is more than 2 rounds behind.
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = pool.assemble_block(Round(10), deadline);
        // Should fall back to assembling an empty block.
        assert!(
            result.is_ok(),
            "pool far behind should produce empty block: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_is_assembly_timed_out_not_timed_out() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let base = Duration::from_millis(2);
        let per_txn = Duration::from_nanos(2155);

        // With 100 txns, projected time is ~2.2ms. Deadline is 10s away.
        assert!(
            !TransactionPool::is_assembly_timed_out(now, deadline, base, per_txn, 100),
            "should not be timed out with plenty of time"
        );
    }

    #[test]
    fn test_is_assembly_timed_out_timed_out() {
        let now = Instant::now();
        // Deadline is already in the past.
        let deadline = now.checked_sub(Duration::from_millis(1)).unwrap_or(now);
        let base = Duration::from_millis(2);
        let per_txn = Duration::from_nanos(2155);

        assert!(
            TransactionPool::is_assembly_timed_out(now, deadline, base, per_txn, 100),
            "should be timed out when deadline is in the past"
        );
    }

    #[test]
    fn test_is_assembly_timed_out_tight_deadline() {
        let now = Instant::now();
        // Deadline is 1ms away but base duration alone is 2ms.
        let deadline = now + Duration::from_millis(1);
        let base = Duration::from_millis(2);
        let per_txn = Duration::from_nanos(2155);

        assert!(
            TransactionPool::is_assembly_timed_out(now, deadline, base, per_txn, 0),
            "should be timed out when base duration exceeds remaining time"
        );
    }

    #[test]
    fn test_assemble_block_after_on_new_block() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Add a transaction and process a block.
        pool.remember_one(make_test_txn(1)).unwrap();

        let block = Block {
            round: Round(2),
            ..Block::default()
        };
        pool.on_new_block(&block, &HashSet::new());

        // The evaluator should have been rebuilt for round 2.
        // Assemble block should work.
        let eval_round = {
            let inner = pool.mu.lock();
            inner.evaluator.as_ref().unwrap().round()
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = pool.assemble_block(eval_round, deadline);
        assert!(
            result.is_ok(),
            "assemble_block after on_new_block should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_assemble_dev_mode_block() {
        let (pool, _ledger) = make_pool_with_advancing_ledger(1000, 1);

        // Add some transactions.
        pool.remember_one(make_test_txn(1)).unwrap();
        pool.remember_one(make_test_txn(2)).unwrap();
        assert_eq!(pool.pending_count(), 2);

        // Dev mode assembly should work immediately.
        let result = pool.assemble_dev_mode_block();
        assert!(
            result.is_ok(),
            "assemble_dev_mode_block should succeed: {:?}",
            result.err()
        );
    }

    // ── Wait-for-OnNewBlock tests ──────────────────────────────────

    #[test]
    fn test_ingest_waits_for_on_new_block() {
        // Setup: evaluator round == ledger.latest(), so ingest() should
        // block until on_new_block() rebuilds the evaluator.
        let ledger = Arc::new(AdvancingLedger::new(2));
        let config = PoolConfig {
            pool_size: 1000,
            ..Default::default()
        };
        let pool = Arc::new(TransactionPool::new(config, ledger.clone()));

        // Install an evaluator at round 2 (same as ledger.latest()).
        // Condition: evaluator.round() <= latest() => 2 <= 2 => true => waits.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(FilteringEvaluator {
                round: Round(2),
                reject_notes: HashSet::new(),
            }));
        }

        let pool_clone = Arc::clone(&pool);
        let handle = std::thread::spawn(move || {
            // This should block in ingest()'s wait loop until on_new_block
            // rebuilds the evaluator past ledger.latest().
            pool_clone.remember_one(make_test_txn(1))
        });

        // Give the remember thread time to enter the wait loop.
        std::thread::sleep(Duration::from_millis(50));

        // Call on_new_block, which rebuilds the evaluator (round 3)
        // and notifies the condvar.
        let block = Block {
            round: Round(2),
            ..Block::default()
        };
        pool.on_new_block(&block, &HashSet::new());

        // The remember thread should unblock and succeed.
        let result = handle.join().expect("remember thread panicked");
        assert!(
            result.is_ok(),
            "remember should succeed after on_new_block: {:?}",
            result.err()
        );
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_ingest_wait_times_out_gracefully() {
        // Setup: evaluator round == ledger.latest(), and nobody calls
        // on_new_block. The wait loop should time out (1 second default)
        // and proceed anyway.
        let ledger = Arc::new(AdvancingLedger::new(2));
        let config = PoolConfig {
            pool_size: 1000,
            // Use a short timeout so the test doesn't take too long.
            timeout_on_new_block: Duration::from_millis(50),
            ..Default::default()
        };
        let pool = TransactionPool::new(config, ledger);

        // Evaluator at round 2, ledger at round 2: condition is true,
        // but timeout will expire and ingest will proceed.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(FilteringEvaluator {
                round: Round(2),
                reject_notes: HashSet::new(),
            }));
        }

        let start = Instant::now();
        let result = pool.remember_one(make_test_txn(1));
        let elapsed = start.elapsed();

        // Should succeed (proceeds after timeout).
        assert!(
            result.is_ok(),
            "remember should succeed after timeout: {:?}",
            result.err()
        );

        // Should have waited at least close to the timeout.
        assert!(
            elapsed >= Duration::from_millis(40),
            "should have waited near timeout_on_new_block, elapsed: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_ingest_no_wait_when_evaluator_ahead() {
        // When evaluator.round() > ledger.latest(), there is no wait.
        let ledger = Arc::new(AdvancingLedger::new(1));
        let config = PoolConfig {
            pool_size: 1000,
            timeout_on_new_block: Duration::from_millis(500),
            ..Default::default()
        };
        let pool = TransactionPool::new(config, ledger);

        // Evaluator at round 2, ledger at round 1: 2 <= 1 is false => no wait.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(FilteringEvaluator {
                round: Round(2),
                reject_notes: HashSet::new(),
            }));
        }

        let start = Instant::now();
        let result = pool.remember_one(make_test_txn(1));
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "remember should succeed immediately: {:?}",
            result.err()
        );
        // Should not have waited at all (well under timeout).
        assert!(
            elapsed < Duration::from_millis(100),
            "should not wait when evaluator is ahead, elapsed: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_ingest_wait_returns_shutdown_error() {
        // If the pool shuts down while waiting, ingest should return PoolShutdown.
        let ledger = Arc::new(AdvancingLedger::new(2));
        let config = PoolConfig {
            pool_size: 1000,
            timeout_on_new_block: Duration::from_secs(5),
            ..Default::default()
        };
        let pool = Arc::new(TransactionPool::new(config, ledger));

        // Evaluator at round 2, ledger at round 2: will wait.
        {
            let mut inner = pool.mu.lock();
            inner.evaluator = Some(Box::new(FilteringEvaluator {
                round: Round(2),
                reject_notes: HashSet::new(),
            }));
        }

        let pool_clone = Arc::clone(&pool);
        let handle = std::thread::spawn(move || pool_clone.remember_one(make_test_txn(1)));

        // Give the remember thread time to enter the wait loop.
        std::thread::sleep(Duration::from_millis(50));

        // Shutdown and wake the waiter.
        pool.shutdown.store(true, Ordering::SeqCst);
        pool.cond.notify_all();

        let result = handle.join().expect("remember thread panicked");
        assert!(result.is_err(), "should fail after shutdown");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("shutting down"),
            "should mention shutdown: {}",
            err_str
        );
    }
}
