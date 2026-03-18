use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::{
    AsyncCryptoVerifier, BlockFactoryBridge, BlockValidatorBridge, EventsProcessingMonitor,
    NetworkAdvancer, Parameters, RandomSource, Service,
};
use algo_avm::group::GroupBudget;
use algo_codec::{canonical_encode_signed_txn_in_block, canonical_encode_transaction};
use algo_ledger::participation::ParticipationStore;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{
    AgreementKeyManagerBridge, AgreementLedgerBridge, BlockFetcher, CatchupService, SqliteLedger,
};
use algo_network::{
    AgreementNetworkBridge, GossipNode, Phonebook, WebsocketNetwork, WebsocketNetworkConfig,
    RELAY_ROLE,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_rest_client::GossipBlockSource;
use algo_types::{AccountData, Address, Block, BlockHeader, Round};
use algo_validate::merkle::{compute_payset_merkle_root, compute_vector_commitment, HashAlgo};
use algo_validate::rules::{has_txn256, has_txn512};
use algo_validate::signature::verify_transaction_signature;
use rand::Rng;
use sha2::{Digest as _, Sha512_256};
use tracing::{info, warn};

use crate::commands::network_common::genesis_id_for;

/// A no-op `EventsProcessingMonitor` for production use.
///
/// Unlike `StubEventsProcessingMonitor` which stores all events in a Vec
/// (leaking memory), this implementation does nothing.
struct NoOpMonitor;

impl EventsProcessingMonitor for NoOpMonitor {
    fn update_events_queue(&self, _queue_name: &str, _queue_length: usize) {}
}

/// A `RandomSource` backed by the OS/thread-local CSPRNG.
///
/// Replaces `StubRandomSource::constant(42)` for production use.
struct RealRandomSource;

impl RandomSource for RealRandomSource {
    fn uint64(&self) -> u64 {
        rand::thread_rng().gen()
    }
}

/// A concrete [`NetworkAdvancer`] that wraps the gossip node.
///
/// When the agreement service makes progress (e.g. a certificate arrives or a
/// block is committed), it calls `on_network_advance()`. This adapter
/// delegates to the `GossipNode::on_network_advance()` method, which triggers
/// mesh maintenance (e.g. clique-resolution peer cycling).
///
/// Mirrors Go's `agreementLedger.n.OnNetworkAdvance()` in `node/impls.go`.
struct GossipNetworkAdvancer {
    node: Arc<dyn GossipNode>,
}

impl NetworkAdvancer for GossipNetworkAdvancer {
    fn on_network_advance(&self) {
        self.node.on_network_advance();
    }
}

/// A concrete [`BlockFetcher`] that fetches blocks from peers via the gossip
/// network's WebSocket unicast protocol.
///
/// The catchup service runs on a dedicated background thread and calls
/// `fetch_block` synchronously. This adapter bridges the async
/// `GossipBlockSource` to the sync trait by using `tokio::runtime::Handle::block_on`.
///
/// Mirrors Go's `universalFetcher` used in `catchup/service.go`.
struct GossipBlockFetcher {
    ws_network: Arc<WebsocketNetwork>,
    rt_handle: tokio::runtime::Handle,
}

impl BlockFetcher for GossipBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<Block, String> {
        // SAFETY: This is called from the CatchupService's background std::thread,
        // NOT from a tokio worker thread. Calling block_on from within the tokio
        // runtime would panic.
        self.rt_handle.block_on(async {
            let peers = self.ws_network.get_unicast_peers().await;
            if peers.is_empty() {
                return Err(format!(
                    "no unicast peers available to fetch block for round {}",
                    round
                ));
            }
            let source = GossipBlockSource::new(peers);
            use algo_rest_client::BlockSource;
            let response = source
                .get_block(round)
                .await
                .map_err(|e| format!("block fetch failed for round {}: {}", round, e))?;
            Ok(response.block)
        })
    }
}

/// Domain separation prefix for transaction ID hashing (matches go-algorand).
const TX_PREFIX: &[u8] = b"TX";

/// Compute the transaction ID: SHA512/256("TX" || canonical_encode(txn)).
///
/// The transaction should have genesis fields restored before calling this,
/// since Go's `txn.ID()` is computed over the full transaction including
/// genesis_id and genesis_hash.
fn compute_txid(txn: &algo_types::Transaction) -> [u8; 32] {
    let canonical = canonical_encode_transaction(txn);
    let mut hasher = Sha512_256::new();
    hasher.update(TX_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Read-only snapshot of ledger state captured at evaluator creation.
///
/// Mirrors Go's `roundCowBase` pattern: snapshot the relevant state once at
/// the start of block evaluation, then release the ledger lock so agreement
/// and catchup can proceed concurrently.
struct LedgerSnapshot {
    /// Cached account balances (sender address -> AccountData).
    /// Populated lazily on first access and cached for the block.
    accounts: HashMap<Address, Option<AccountData>>,
    /// Lease table snapshot from the ledger at evaluator creation time.
    lease_table: algo_ledger::LeaseTable,
    /// The round being evaluated.
    round: u64,
}

impl LedgerSnapshot {
    /// Create a new snapshot by briefly locking the ledger to capture lease
    /// state for the current round.
    fn from_ledger(ledger: &Arc<Mutex<SqliteLedger>>, round: u64) -> Self {
        let l = ledger.lock().expect("ledger lock for snapshot");
        // Clone the lease table while holding the lock so the snapshot
        // reflects the actual lease state from prior committed blocks.
        let lease_table = l.lease_table().clone();
        drop(l);
        LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table,
            round,
        }
    }

    /// Look up an account balance, checking the cache first, then the ledger.
    fn get_account(
        &mut self,
        addr: &Address,
        ledger: &Arc<Mutex<SqliteLedger>>,
    ) -> Option<AccountData> {
        if let Some(cached) = self.accounts.get(addr) {
            return cached.clone();
        }
        let result = {
            let l = ledger.lock().expect("ledger lock for account lookup");
            l.get_account(addr)
        };
        self.accounts.insert(*addr, result.clone());
        result
    }

    /// Check whether a lease is active in the ledger snapshot.
    ///
    /// The snapshot's lease table was cloned from the ledger at evaluator
    /// creation time, so this is a pure read with no lock acquisition.
    fn check_lease(&self, sender: &Address, lease: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        self.lease_table.check(sender, lease, self.round)
    }
}

/// Copy-on-write overlay that accumulates mutations during block evaluation.
///
/// Mirrors Go's `roundCowState` pattern: reads check the overlay first, then
/// fall back to the snapshot/ledger. Writes go only to the overlay. The
/// overlay is discarded if the block is abandoned.
struct CowOverlay {
    /// Balance adjustments: maps address to remaining microAlgos.
    /// When a transaction is accepted, the sender's fee (and amount for
    /// payment txns) is deducted and the receiver's balance is credited.
    balance_deltas: HashMap<Address, u64>,
    /// Leases recorded within this block. Maps (sender, lease) to last_valid.
    leases: HashMap<(Address, [u8; 32]), u64>,
    /// Transaction IDs seen within this block, for duplicate detection.
    seen_txids: HashSet<[u8; 32]>,
}

/// A checkpoint of `CowOverlay` state for tentative-apply rollback.
///
/// Before applying a group, we capture the current overlay state. If any
/// check fails after tentative apply (e.g. min-balance violation), we
/// restore the overlay to this checkpoint so the rejected group leaves
/// no trace.
struct CowCheckpoint {
    balance_deltas: HashMap<Address, u64>,
    leases: HashMap<(Address, [u8; 32]), u64>,
    seen_txids: HashSet<[u8; 32]>,
}

impl CowOverlay {
    fn new() -> Self {
        CowOverlay {
            balance_deltas: HashMap::new(),
            leases: HashMap::new(),
            seen_txids: HashSet::new(),
        }
    }

    /// Create a checkpoint of the current overlay state for rollback.
    fn checkpoint(&self) -> CowCheckpoint {
        CowCheckpoint {
            balance_deltas: self.balance_deltas.clone(),
            leases: self.leases.clone(),
            seen_txids: self.seen_txids.clone(),
        }
    }

    /// Restore the overlay to a previous checkpoint, discarding all
    /// mutations made since the checkpoint was taken.
    fn restore(&mut self, cp: CowCheckpoint) {
        self.balance_deltas = cp.balance_deltas;
        self.leases = cp.leases;
        self.seen_txids = cp.seen_txids;
    }

    /// Check whether a lease conflicts with an already-included transaction
    /// in this block's overlay.
    fn check_lease_in_overlay(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        round: u64,
    ) -> Result<(), algo_error::AlgoError> {
        // All-zero lease is always allowed.
        if *lease == [0u8; 32] {
            return Ok(());
        }
        if let Some(&last_valid) = self.leases.get(&(*sender, *lease)) {
            if last_valid >= round {
                return Err(algo_error::AlgoError::Ledger {
                    message: "duplicate lease in block".into(),
                });
            }
        }
        Ok(())
    }

    /// Record a lease in the overlay. No-op for zero leases.
    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        if *lease == [0u8; 32] {
            return;
        }
        self.leases.insert((*sender, *lease), last_valid);
    }

    /// Check whether a transaction ID has already been seen in this block.
    fn check_txid(&self, txid: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        if self.seen_txids.contains(txid) {
            return Err(algo_error::AlgoError::Ledger {
                message: "duplicate transaction ID in block".into(),
            });
        }
        Ok(())
    }

    /// Record a transaction ID in the overlay.
    fn record_txid(&mut self, txid: [u8; 32]) {
        self.seen_txids.insert(txid);
    }

    /// Get the effective balance for an address from the overlay.
    /// Returns `None` if the overlay has no entry for this address (caller
    /// should fall back to the snapshot/ledger).
    fn get_balance(&self, addr: &Address) -> Option<u64> {
        self.balance_deltas.get(addr).copied()
    }

    /// Set the effective balance for an address in the overlay.
    fn set_balance(&mut self, addr: &Address, balance: u64) {
        self.balance_deltas.insert(*addr, balance);
    }
}

/// A `BlockEvaluator` that validates transactions using stateless rules and
/// stateful checks (balance, lease, txid dedup) via a COW overlay.
///
/// Stateless validation covers: well-formedness (fees, round window, note/
/// lease/group size), group ID consistency, group fee pooling, and signature
/// verification. Stateful validation includes balance pre-checks, lease
/// uniqueness, and transaction ID duplicate detection using the COW overlay
/// on top of a ledger snapshot.
struct SimpleBlockEvaluator {
    hdr: algo_types::BlockHeader,
    /// Consensus parameters for the protocol version of this block.
    consensus_params: algo_types::ConsensusParams,
    /// Transactions included in the block so far.
    included_txns: Vec<algo_types::SignedTransaction>,
    /// Running total of serialized transaction bytes (for the per-block cap).
    txn_bytes: usize,
    /// Maximum transaction bytes allowed in this block. This is the minimum
    /// of the caller-provided limit and the consensus protocol limit.
    max_txn_bytes: usize,
    /// Handle to the shared ledger for snapshot reads.
    ledger: Arc<Mutex<SqliteLedger>>,
    /// Read-only snapshot of ledger state captured at evaluator creation.
    snapshot: LedgerSnapshot,
    /// COW overlay accumulating mutations from accepted transaction groups.
    overlay: CowOverlay,
}

impl SimpleBlockEvaluator {
    /// Restore genesis fields on a signed transaction that may have had them
    /// stripped (STIB format). If `has_genesis_id` is set and genesis_id is
    /// empty, fill it from the block header. If genesis_hash is zero, fill
    /// it from the block header. This is needed for signature verification
    /// and txid computation.
    fn restore_genesis_fields(&self, stx: &mut algo_types::SignedTransaction) {
        if stx.has_genesis_id && stx.txn.genesis_id.is_empty() {
            stx.txn.genesis_id.clone_from(&self.hdr.genesis_id);
        }
        // Restore genesis_hash when the protocol requires it (modern protocols)
        // or when the STIB flag indicates the hash was stripped. On old protocols
        // where genesis_hash is optional, only restore if has_genesis_hash is set
        // to avoid mutating transactions that were legitimately signed without a
        // genesis hash. Mirrors Go's DecodeSignedTxn logic.
        if stx.txn.genesis_hash == [0u8; 32]
            && (self.consensus_params.require_genesis_hash || stx.has_genesis_hash)
        {
            stx.txn.genesis_hash.clone_from(&self.hdr.genesis_hash);
        }
    }

    /// Perform stateless validation only (well-formedness, group ID, fees,
    /// signatures). Used by `test_transaction_group` which takes `&self`.
    fn validate_group_stateless(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        if txgroup.is_empty() {
            return Err(algo_error::AlgoError::Validation {
                message: "empty transaction group".into(),
            });
        }

        let params = &self.consensus_params;
        let round = self.hdr.round;

        // 1. Reject consensus-injected transaction types.
        // State proof (stpf) and heartbeat (hb) transactions are injected by
        // the consensus layer, not submitted by users through the pool.
        for stx in txgroup {
            if stx.txn.txn_type == "stpf" {
                return Err(algo_error::AlgoError::Validation {
                    message: "state proof transactions (stpf) cannot be submitted via the pool"
                        .into(),
                });
            }
            if stx.txn.txn_type == "hb" {
                return Err(algo_error::AlgoError::Validation {
                    message: "heartbeat transactions (hb) cannot be submitted via the pool".into(),
                });
            }
        }

        // 2. Per-transaction well-formedness.
        let in_group = txgroup.len() > 1;
        for stx in txgroup {
            algo_validate::validate_transaction_wellformed(
                &stx.txn,
                in_group && params.enable_fee_pooling,
                params,
                None, // SpecialAddresses not available without ledger lookup
            )?;

            // Check that the transaction's round window covers this block's round.
            if round < stx.txn.first_valid || round > stx.txn.last_valid {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction round window [{}, {}] does not cover block round {}",
                        stx.txn.first_valid.0, stx.txn.last_valid.0, round.0,
                    ),
                });
            }
        }

        // 3. Group ID consistency.
        algo_validate::validate_transaction_group(txgroup)?;

        // 4. Group fee pooling (for multi-txn groups with fee pooling enabled).
        if in_group && params.enable_fee_pooling {
            let refs: Vec<&algo_types::SignedTransaction> = txgroup.iter().collect();
            algo_validate::validate_group_fees_with_params(&refs, params).map_err(|e| {
                algo_error::AlgoError::Validation {
                    message: format!("group fee validation failed: {e}"),
                }
            })?;
        }

        // 5. Signature verification.
        // Restore genesis fields before verification — signatures are computed
        // over the ORIGINAL transaction (with genesis_id and genesis_hash), but
        // the pool receives transactions with these fields present. For pool
        // transactions the genesis fields should already be populated, but we
        // ensure they're set matching the block header, mirroring the pattern
        // from block.rs.
        let mut restored: Vec<algo_types::SignedTransaction> = txgroup.to_vec();
        for stx in &mut restored {
            self.restore_genesis_fields(stx);
        }

        // Create a per-group LogicSig budget for logicsig evaluation.
        let mut lsig_budget = GroupBudget::for_logicsig(restored.len());

        for (intra_group_idx, stx) in restored.iter().enumerate() {
            verify_transaction_signature(
                stx,
                &restored,
                intra_group_idx,
                &mut lsig_budget,
                params,
            )?;
        }

        Ok(())
    }

    /// Validate a transaction group using both stateless and stateful checks.
    ///
    /// Stateful checks (txid dedup, lease uniqueness, balance precheck) require
    /// `&mut self` because the snapshot cache is populated lazily.
    ///
    /// Checks performed (in addition to stateless):
    /// 6. Transaction ID duplicate detection (in-block overlay + ledger)
    /// 7. Lease uniqueness check (in-block overlay + ledger snapshot)
    /// 8. Sender balance precheck (fee + amount against overlay/snapshot)
    fn validate_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // Run all stateless checks first.
        self.validate_group_stateless(txgroup)?;

        let round = self.hdr.round;

        // Build restored copies with genesis fields for txid computation.
        let restored: Vec<algo_types::SignedTransaction> = txgroup
            .iter()
            .map(|stx| {
                let mut r = stx.clone();
                self.restore_genesis_fields(&mut r);
                r
            })
            .collect();

        // 6. Transaction ID duplicate detection.
        // Compute txid for each transaction (with genesis fields restored)
        // and check for duplicates WITHIN the current group first, then
        // against the in-block overlay. Mirrors Go's cow.checkDup(txid)
        // which checks mods.Txids first.
        {
            let mut group_txids = HashSet::new();
            for stx in &restored {
                let txid = compute_txid(&stx.txn);
                if !group_txids.insert(txid) {
                    return Err(algo_error::AlgoError::Ledger {
                        message: "duplicate transaction ID within group".into(),
                    });
                }
                self.overlay.check_txid(&txid)?;
            }
        }

        // 7. Lease uniqueness check.
        // For each transaction with a non-zero lease, check:
        //   a. Duplicates WITHIN the current group (same sender + lease)
        //   b. The in-block overlay (already-included txns in this block)
        //   c. The ledger snapshot (existing leases from prior blocks)
        // Mirrors Go's cow.checkDup() which checks mods.Txleases then
        // delegates to roundCowBase.checkDup -> ledger.CheckDup.
        {
            let mut group_leases: HashSet<(Address, [u8; 32])> = HashSet::new();
            for stx in &restored {
                if stx.txn.lease != [0u8; 32] {
                    // Check within current group first
                    if !group_leases.insert((stx.txn.sender, stx.txn.lease)) {
                        return Err(algo_error::AlgoError::Ledger {
                            message: "duplicate lease within group".into(),
                        });
                    }
                    // Check overlay (leases from earlier groups in this block)
                    self.overlay.check_lease_in_overlay(
                        &stx.txn.sender,
                        &stx.txn.lease,
                        round.0,
                    )?;
                    // Check ledger snapshot (leases from prior committed blocks)
                    self.snapshot.check_lease(&stx.txn.sender, &stx.txn.lease)?;
                }
            }
        }

        // 8. Sender balance precheck.
        // Verify each sender has sufficient balance for fee + amount (for
        // payment transactions). This is a read-only precheck — actual
        // balance mutation is deferred to transaction_group() on acceptance.
        // Mirrors Go's approach of checking balances via cow.lookup() which
        // first checks the overlay, then falls back to the parent/ledger.
        //
        // We accumulate per-sender costs within this group to handle groups
        // where the same sender appears multiple times.
        let mut group_costs: HashMap<Address, u64> = HashMap::new();
        for stx in txgroup {
            let sender = &stx.txn.sender;
            let cost = stx.txn.fee.saturating_add(stx.txn.amount);
            let entry = group_costs.entry(*sender).or_insert(0);
            *entry = entry.saturating_add(cost);
        }

        for (sender, required) in &group_costs {
            // Check overlay first for cumulative effects of earlier groups,
            // then fall back to the ledger snapshot.
            let bal = self.effective_balance(sender);

            if bal < *required {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "sender {} has insufficient balance: need {} microAlgos, have {}",
                        sender, required, bal,
                    ),
                });
            }
        }

        Ok(())
    }
}

impl SimpleBlockEvaluator {
    /// Get the effective balance for an address, checking the overlay first
    /// then falling back to the snapshot/ledger.
    ///
    /// This is the single source of truth for balance lookups during
    /// evaluation, ensuring cross-group visibility of balance changes.
    fn effective_balance(&mut self, addr: &Address) -> u64 {
        match self.overlay.get_balance(addr) {
            Some(bal) => bal,
            None => self
                .snapshot
                .get_account(addr, &self.ledger)
                .map(|acct| acct.micro_algos)
                .unwrap_or(0),
        }
    }
}

impl algo_pool::traits::BlockEvaluator for SimpleBlockEvaluator {
    fn round(&self) -> Round {
        self.hdr.round
    }

    fn pay_set_size(&self) -> usize {
        self.included_txns.len()
    }

    fn test_transaction_group(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // test_transaction_group performs stateless checks only (matching
        // Go's TestTransactionGroup which does well-formedness + group
        // consistency but doesn't mutate evaluator state). The full
        // stateful checks (txid dedup, lease, balance) run in
        // transaction_group() when the group is actually committed.
        self.validate_group_stateless(txgroup)
    }

    fn transaction_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group(txgroup)?;

        // Convert each transaction to STIB (SignedTxnInBlock) format:
        // strip genesis fields and set has_genesis_id / has_genesis_hash flags.
        // This mirrors go-algorand's BlockHeader.EncodeSignedTxn().
        //
        // Before stripping, validate that genesis fields match the block
        // header. Go returns an error on mismatch — we do the same.
        let mut stibs: Vec<algo_types::SignedTransaction> = Vec::with_capacity(txgroup.len());
        for stx in txgroup {
            let mut stib = stx.clone();

            // Reject transactions whose genesis_id doesn't match the block.
            if !stib.txn.genesis_id.is_empty() && stib.txn.genesis_id != self.hdr.genesis_id {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction genesis_id '{}' does not match block header '{}'",
                        stib.txn.genesis_id, self.hdr.genesis_id,
                    ),
                });
            }

            // Reject transactions whose genesis_hash doesn't match the block.
            if stib.txn.genesis_hash != [0u8; 32] && stib.txn.genesis_hash != self.hdr.genesis_hash
            {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash does not match block header".into(),
                });
            }

            // If the protocol requires genesis_hash, reject transactions with a zero hash.
            if self.consensus_params.require_genesis_hash && stib.txn.genesis_hash == [0u8; 32] {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash is required but missing".into(),
                });
            }

            // Strip genesis_id if present (it matched above).
            if !stib.txn.genesis_id.is_empty() {
                stib.txn.genesis_id = String::new();
                stib.has_genesis_id = true;
            }

            // Strip genesis_hash if present (it matched above).
            if stib.txn.genesis_hash != [0u8; 32] {
                stib.txn.genesis_hash = [0u8; 32];
                // Only set has_genesis_hash if the protocol doesn't
                // require it (matching go-algorand behavior).
                if !self.consensus_params.require_genesis_hash {
                    stib.has_genesis_hash = true;
                }
            }

            stibs.push(stib);
        }

        // Use exact byte counting via canonical STIB encoding.
        let max_bytes = self.max_txn_bytes;
        let exact_bytes: usize = stibs
            .iter()
            .map(|stib| canonical_encode_signed_txn_in_block(stib).len())
            .sum();

        if self.txn_bytes + exact_bytes > max_bytes {
            return Err(algo_error::AlgoError::Ledger {
                message: format!(
                    "transaction group would exceed block byte limit ({} + {} > {})",
                    self.txn_bytes, exact_bytes, max_bytes,
                ),
            });
        }

        // ── Tentative apply with rollback ────────────────────────────
        // Checkpoint the overlay before making any mutations. If the
        // min-balance check (or any later check) fails, we restore the
        // overlay to this checkpoint so the rejected group leaves no
        // trace. This mirrors Go's child-cow pattern where
        // `cow.commitToParent()` is only called after all checks pass.
        let checkpoint = self.overlay.checkpoint();

        // Record txids, leases, and balance deltas in the COW overlay.
        // This mirrors Go's cow.addTx() which records txids and leases,
        // and the balance mutations from applyTransaction().
        for stx in txgroup {
            // Restore genesis fields for txid computation.
            let mut restored = stx.clone();
            self.restore_genesis_fields(&mut restored);

            // Record transaction ID.
            let txid = compute_txid(&restored.txn);
            self.overlay.record_txid(txid);

            // Record lease if non-zero.
            if stx.txn.lease != [0u8; 32] {
                self.overlay
                    .record_lease(&stx.txn.sender, &stx.txn.lease, stx.txn.last_valid.0);
            }

            // Update balances in overlay following Go's apply.Payment() order:
            // 1. Debit fee from sender
            // 2. Move amount from sender to receiver (cow.Move)
            // 3. If close_remainder_to is set, move remaining balance
            //    to close address and zero the sender (cow.CloseAccount)
            let sender = &stx.txn.sender;
            let sender_balance = self.effective_balance(sender);
            let sender_after_fee = sender_balance.saturating_sub(stx.txn.fee);

            // Credit receiver for payment transactions.
            // This must happen BEFORE close-out so that when receiver == sender,
            // the balance is correctly computed before zeroing. Mirrors Go's
            // cow.Move(sender, receiver, amount).
            if stx.txn.amount > 0 && !stx.txn.receiver.is_zero() {
                let receiver = &stx.txn.receiver;
                if receiver == sender {
                    // Self-payment: fee is debited but amount is a no-op
                    // (debit and credit cancel out). Just debit fee.
                    self.overlay.set_balance(sender, sender_after_fee);
                } else {
                    let recv_balance = self.effective_balance(receiver);
                    self.overlay
                        .set_balance(receiver, recv_balance.saturating_add(stx.txn.amount));
                    self.overlay
                        .set_balance(sender, sender_after_fee.saturating_sub(stx.txn.amount));
                }
            } else {
                self.overlay
                    .set_balance(sender, sender_after_fee.saturating_sub(stx.txn.amount));
            }

            // Handle close_remainder_to: the sender's entire remaining
            // balance (after fee + amount + receiver credit) goes to the
            // close address and the sender's balance becomes 0. Closing
            // an account to zero is valid (the account is deleted).
            // Mirrors Go's apply.Payment() -> cow.CloseAccount().
            if !stx.txn.close_remainder_to.is_zero() {
                let close_addr = &stx.txn.close_remainder_to;
                let remaining = self.effective_balance(sender);
                if remaining > 0 && close_addr != sender {
                    let close_balance = self.effective_balance(close_addr);
                    self.overlay
                        .set_balance(close_addr, close_balance.saturating_add(remaining));
                }
                // Sender balance goes to zero after close.
                self.overlay.set_balance(sender, 0);
            }
        }

        // ── Min-balance check after apply ────────────────────────────
        // After tentatively applying all balance mutations for this
        // group, verify that no affected account has dropped below the
        // minimum balance. Mirrors Go's `checkMinBalance(cow)` which
        // iterates over `cow.modifiedAccounts()`.
        //
        // Accounts at exactly zero are allowed — this represents a
        // closed/deleted account, matching Go's `data.IsZero()` check.
        let min_balance = self.consensus_params.min_balance;

        // Collect addresses modified in this group for the check.
        let mut modified_addrs: HashSet<Address> = HashSet::new();
        for stx in txgroup {
            modified_addrs.insert(stx.txn.sender);
            if !stx.txn.receiver.is_zero() {
                modified_addrs.insert(stx.txn.receiver);
            }
            if !stx.txn.close_remainder_to.is_zero() {
                modified_addrs.insert(stx.txn.close_remainder_to);
            }
        }

        for addr in &modified_addrs {
            let balance = self.effective_balance(addr);
            // A zero balance is valid (account closed/deleted), matching
            // Go's `if data.IsZero() { continue }` in checkMinBalance.
            if balance > 0 && balance < min_balance {
                // Min-balance violation — rollback overlay and reject.
                self.overlay.restore(checkpoint);
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "account {} balance {} below minimum {} after transaction group",
                        addr, balance, min_balance,
                    ),
                });
            }
        }

        // All checks passed — commit the STIB data and byte counts.
        self.txn_bytes += exact_bytes;
        self.included_txns.extend(stibs);

        Ok(())
    }

    fn generate_block(
        &mut self,
        _voting_accounts: &[algo_types::Address],
    ) -> Result<algo_types::Block, algo_error::AlgoError> {
        let txn_count = self.included_txns.len() as u64;

        // Take ownership of included transactions for payset assembly.
        let payset = std::mem::take(&mut self.included_txns);

        // Build the block by propagating ALL header fields from self.hdr,
        // then overriding the computed fields (txn_counter, commitments,
        // payset). This ensures fee_sink, rewards_pool, rewards_level,
        // rewards_rate, rewards_residue, rewards_recalculation_round,
        // proposer, and all other header fields are preserved.
        let hdr = &self.hdr;
        let mut block = algo_types::Block {
            round: hdr.round,
            branch: hdr.branch,
            seed: hdr.seed,
            timestamp: hdr.timestamp,
            genesis_id: hdr.genesis_id.clone(),
            genesis_hash: hdr.genesis_hash,
            proposer: hdr.proposer,
            fee_sink: hdr.fee_sink,
            rewards_pool: hdr.rewards_pool,
            rewards_level: hdr.rewards_level,
            rewards_rate: hdr.rewards_rate,
            rewards_residue: hdr.rewards_residue,
            rewards_recalculation_round: hdr.rewards_recalculation_round,
            current_protocol: hdr.current_protocol.clone(),
            next_protocol: hdr.next_protocol.clone(),
            next_protocol_approvals: hdr.next_protocol_approvals,
            next_protocol_switch_on: hdr.next_protocol_switch_on,
            next_protocol_vote_before: hdr.next_protocol_vote_before,
            txn_counter: hdr.txn_counter + txn_count,
            fees_collected: hdr.fees_collected,
            bonus: hdr.bonus,
            proposer_payout: hdr.proposer_payout,
            prev512: hdr.prev512,
            state_proof_tracking: hdr.state_proof_tracking.clone(),
            upgrade_propose: hdr.upgrade_propose.clone(),
            upgrade_delay: hdr.upgrade_delay,
            upgrade_approve: hdr.upgrade_approve,
            expired_participation_accounts: hdr.expired_participation_accounts.clone(),
            absent_participation_accounts: hdr.absent_participation_accounts.clone(),
            payset,
            // Commitment fields are computed below.
            txn_commitment: [0u8; 32],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
        };

        // Compute the SHA-512/256 Merkle root (the primary `txn` commitment).
        // This matches go-algorand's PaysetCommit() → paysetCommit(PaysetCommitMerkle).
        block.txn_commitment = compute_payset_merkle_root(&block);

        // Protocol-gated vector commitments.
        let proto = &self.hdr.current_protocol;

        // SHA-256 vector commitment (txn256 field, v34+).
        if has_txn256(proto) {
            let vc256 = compute_vector_commitment(&block, HashAlgo::Sha256);
            block.txn256.copy_from_slice(&vc256);
        }

        // SHA-512 vector commitment (txn512 field, v41+).
        if has_txn512(proto) {
            let vc512 = compute_vector_commitment(&block, HashAlgo::Sha512);
            block.txn512.copy_from_slice(&vc512);
        }

        Ok(block)
    }

    fn reset_txn_bytes(&mut self) {
        self.txn_bytes = 0;
    }
}

/// A minimal `PoolLedger` that wraps `SqliteLedger` behind a `Mutex`.
///
/// The `TransactionPool` requires an `Arc<dyn PoolLedger>`, so we provide
/// this thin adapter that delegates to the same SQLite ledger used by the
/// agreement bridges.
struct PoolLedgerAdapter {
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl algo_pool::traits::PoolLedger for PoolLedgerAdapter {
    fn latest(&self) -> Round {
        self.ledger
            .lock()
            .map(|l| l.current_round())
            .unwrap_or(Round(0))
    }

    fn block_hdr(&self, round: Round) -> Result<algo_types::BlockHeader, algo_error::AlgoError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("ledger lock poisoned: {e}"),
            })?;
        let hdr_data = ledger
            .get_block_header_data(round.0)
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("block_hdr({}) read error: {e}", round.0),
            })?
            .ok_or_else(|| algo_error::AlgoError::Ledger {
                message: format!("no block header data for round {}", round.0),
            })?;
        BlockHeader::decode_from_bytes(&hdr_data).map_err(|e| algo_error::AlgoError::Ledger {
            message: format!("block_hdr({}) decode error: {e}", round.0),
        })
    }

    fn consensus_params(
        &self,
        _round: Round,
    ) -> Result<algo_types::ConsensusParams, algo_error::AlgoError> {
        // Return V41 params as a reasonable default.
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41).ok_or_else(
            || algo_error::AlgoError::Ledger {
                message: "could not look up v41 consensus params".into(),
            },
        )
    }

    fn start_evaluator(
        &self,
        hdr: algo_types::BlockHeader,
        _payset_hint: usize,
        max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn algo_pool::traits::BlockEvaluator>, algo_error::AlgoError> {
        let consensus_params =
            algo_types::consensus::consensus_params_for_version(&hdr.current_protocol)
                .or_else(|| {
                    algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
                })
                .ok_or_else(|| algo_error::AlgoError::Ledger {
                    message: "could not look up consensus params for block evaluator".into(),
                })?;

        // Snapshot the ledger state at evaluator creation time.
        // This briefly acquires the mutex, captures lease state, then releases.
        let snapshot = LedgerSnapshot::from_ledger(&self.ledger, hdr.round.0);

        // Use the caller-provided byte limit, or the consensus protocol
        // default if the caller passed 0. Take the minimum of the two when
        // both are non-zero, matching Go's behavior.
        let consensus_max = consensus_params.max_txn_bytes_per_block as usize;
        let max_txn_bytes = if max_txn_bytes_per_block == 0 {
            consensus_max
        } else {
            max_txn_bytes_per_block.min(consensus_max)
        };

        Ok(Box::new(SimpleBlockEvaluator {
            hdr,
            consensus_params,
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes,
            ledger: self.ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
        }))
    }
}

/// Parse a hex-encoded genesis hash into a 32-byte array.
fn parse_genesis_hash(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        anyhow::bail!(
            "genesis hash must be 64 hex characters (32 bytes), got {} chars",
            hex_str.len()
        );
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in genesis hash at byte {}: {}", i, e))?;
    }
    Ok(arr)
}

/// Run the participate command: start the agreement protocol and participate
/// in consensus using the provided participation keys.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ledger_path: &Path,
    genesis_id: Option<&str>,
    network: &str,
    peers: &[String],
    partkey_path: &Path,
    listen_address: Option<&str>,
    genesis_hash_hex: Option<&str>,
) -> anyhow::Result<()> {
    // Resolve genesis ID: use the provided value, or look it up by network name.
    let resolved_genesis_id = match genesis_id {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => genesis_id_for(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network '{}': use --genesis-id to specify the genesis ID",
                    network
                )
            })?
            .to_string(),
    };

    // Parse genesis hash (default to zeros if not provided).
    let genesis_hash = match genesis_hash_hex {
        Some(hex_str) => parse_genesis_hash(hex_str)?,
        None => [0u8; 32],
    };

    info!(
        ledger = %ledger_path.display(),
        genesis_id = %resolved_genesis_id,
        network = network,
        peers = peers.len(),
        partkey = %partkey_path.display(),
        listen = listen_address.unwrap_or("none"),
        "starting consensus participation"
    );

    // -----------------------------------------------------------------------
    // 1. Open the SQLite ledger (shared between agreement and pool bridges).
    // -----------------------------------------------------------------------
    let sqlite_ledger = SqliteLedger::open(ledger_path).map_err(|e| {
        anyhow::anyhow!("failed to open ledger at {}: {}", ledger_path.display(), e)
    })?;
    let latest = sqlite_ledger.current_round().0;
    info!(path = %ledger_path.display(), latest_round = latest, "opened ledger database");

    let ledger = Arc::new(Mutex::new(sqlite_ledger));

    // -----------------------------------------------------------------------
    // 2. Open the participation key store.
    // -----------------------------------------------------------------------
    let part_store = ParticipationStore::open(partkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open participation key store at {}: {}",
            partkey_path.display(),
            e
        )
    })?;
    let key_count = part_store.get_all().map(|v| v.len()).unwrap_or(0);
    info!(
        path = %partkey_path.display(),
        keys = key_count,
        "opened participation key store"
    );

    if key_count == 0 {
        warn!("No participation keys found — node will not produce valid proposals or votes");
    } else {
        // Check whether loaded keys have the required VRF/vote secrets.
        // Records missing vote_id or vrf_public_key will be filtered out by
        // the key manager and won't contribute to consensus.
        if let Ok(records) = part_store.get_all() {
            let missing: Vec<_> = records
                .iter()
                .filter(|r| r.vote_id.is_none() || r.vrf_public_key.is_none())
                .collect();
            for rec in &missing {
                warn!(
                    account = %rec.account,
                    participation_id = %rec.participation_id,
                    vote_id_present = rec.vote_id.is_some(),
                    vrf_key_present = rec.vrf_public_key.is_some(),
                    "participation key is missing vote_id or VRF key — it will not produce valid consensus messages"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Build the gossip network node.
    // -----------------------------------------------------------------------
    let phonebook = Arc::new(Phonebook::new(60, Duration::from_secs(60)));
    if !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    }

    let net_config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: listen_address.map(|s| s.to_string()),
        relay_messages: false, // participation node, not a relay
        gossip_fanout: peers.len().max(algo_network::DEFAULT_GOSSIP_FANOUT),
        ..Default::default()
    };

    let gossip_node = Arc::new(WebsocketNetwork::new(net_config, phonebook));

    // Start the network (listener + mesh).
    gossip_node
        .start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start gossip network: {}", e))?;

    let (addr, listening) = gossip_node.address();
    if listening {
        info!(address = %addr, "gossip network listening");
    } else {
        info!("gossip network started (no listener)");
    }

    // -----------------------------------------------------------------------
    // 4. Build agreement bridges.
    // -----------------------------------------------------------------------

    // Network bridge: wraps GossipNode for agreement message passing.
    let rt_handle = tokio::runtime::Handle::current();
    let agreement_network = AgreementNetworkBridge::with_defaults(
        gossip_node.clone() as Arc<dyn GossipNode>,
        rt_handle.clone(),
    );

    // Network advancer: wraps the gossip node so the ledger bridge can
    // signal network progress when certificates arrive.
    let network_advancer: Arc<dyn NetworkAdvancer> = Arc::new(GossipNetworkAdvancer {
        node: gossip_node.clone() as Arc<dyn GossipNode>,
    });

    // Ledger bridge: wraps SqliteLedger for agreement read/write access.
    // Uses `new_with_catchup` to enable the certificate-driven catchup path.
    // The returned `cert_rx` is consumed by the CatchupService below.
    let (agreement_ledger, cert_rx) =
        AgreementLedgerBridge::new_with_catchup(ledger.clone(), network_advancer.clone());

    // Key manager bridge: wraps ParticipationStore for voting key lookups.
    let key_manager = AgreementKeyManagerBridge::new(part_store);

    // Block factory bridge: wraps TransactionPool for block assembly.
    let pool_ledger_adapter = Arc::new(PoolLedgerAdapter {
        ledger: ledger.clone(),
    });
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    let block_factory = BlockFactoryBridge::new(pool);

    // Block validator bridge: wraps algo-validate for incoming block checks.
    // Extract the timestamp from the latest committed block header so the
    // validator can enforce the MaxTimestampIncrement constraint.
    let prev_timestamp: Option<i64> = {
        let l = ledger.lock().expect("ledger lock");
        let current = l.current_round().0;
        if current > 0 {
            match l.get_block_header_data(current) {
                Ok(Some(hdr_bytes)) => match BlockHeader::decode_from_bytes(&hdr_bytes) {
                    Ok(hdr) => {
                        info!(
                            round = current,
                            timestamp = hdr.timestamp,
                            "extracted previous block timestamp"
                        );
                        Some(hdr.timestamp)
                    }
                    Err(e) => {
                        warn!(round = current, error = %e, "failed to decode block header for timestamp; skipping timestamp validation");
                        None
                    }
                },
                Ok(None) => {
                    warn!(
                        round = current,
                        "no block header data found; skipping timestamp validation"
                    );
                    None
                }
                Err(e) => {
                    warn!(round = current, error = %e, "failed to read block header data; skipping timestamp validation");
                    None
                }
            }
        } else {
            // Round 0 (genesis) — no previous timestamp needed.
            None
        }
    };
    // A single shared BlockValidatorBridge is used by both the Parameters
    // (demux loop / ensure action) and the AsyncCryptoVerifier (proposal
    // verification). This mirrors Go where the same BlockValidator is passed
    // to both. Sharing ensures that `set_prev_timestamp` updates made in
    // `do_ensure_action` are visible to the crypto verifier's proposal
    // validation, keeping timestamp validation accurate.
    let block_validator: Arc<BlockValidatorBridge> = Arc::new(BlockValidatorBridge::new(
        resolved_genesis_id.clone(),
        genesis_hash,
        prev_timestamp,
    ));

    // Real random source backed by the OS CSPRNG; no-op monitor.
    let random_source = RealRandomSource;
    let monitor = NoOpMonitor;

    // Real crypto verifier backed by the agreement ledger bridge.
    // This verifies VRF credentials and OTS signatures on incoming votes
    // and bundles, rather than blindly accepting them.
    //
    // The block validator is also threaded into the crypto verifier so that
    // proposal verification validates the block eagerly and caches the
    // `ValidatedBlock` — mirroring Go's `makeCryptoVerifier(l, v, ...)`.
    let crypto_ledger = Arc::new(AgreementLedgerBridge::new(ledger.clone()));
    let crypto = AsyncCryptoVerifier::new_with_validator(crypto_ledger, Arc::clone(&block_validator));

    // -----------------------------------------------------------------------
    // 5. Build and start the catchup service.
    // -----------------------------------------------------------------------
    // The catchup service runs a background thread that receives certificates
    // from the agreement service (via `cert_rx`) and fetches the corresponding
    // blocks from peers when the ledger doesn't have them yet.
    //
    // The catchup bridge is a separate `AgreementLedgerBridge` wrapping the
    // same underlying `SqliteLedger`. It only needs `ensure_block` to commit
    // fetched blocks, and shares the same ledger mutex so commits are visible
    // to the agreement service immediately.
    let catchup_bridge = Arc::new(AgreementLedgerBridge::new_with_advancer_and_condvar(
        ledger.clone(),
        network_advancer,
        agreement_ledger.round_advanced_condvar(),
    ));

    let block_fetcher: Arc<dyn BlockFetcher> = Arc::new(GossipBlockFetcher {
        ws_network: gossip_node.clone(),
        rt_handle,
    });

    let mut catchup_service =
        CatchupService::start(cert_rx, ledger.clone(), catchup_bridge, block_fetcher);
    info!("catchup service started");

    // -----------------------------------------------------------------------
    // 6. Build and start the agreement Service.
    // -----------------------------------------------------------------------
    let params = Parameters {
        network: agreement_network,
        ledger: agreement_ledger,
        key_manager,
        block_factory,
        block_validator,
        random_source,
        monitor,
        crypto,
        crash_db: None, // TODO: wire up crash recovery database
    };

    let service = Service::new(params);
    let handle = service.start();

    info!(
        genesis_id = %resolved_genesis_id,
        latest_round = latest,
        "consensus participation active -- press Ctrl+C to stop"
    );

    // -----------------------------------------------------------------------
    // 7. Wait for shutdown signal (Ctrl+C).
    // -----------------------------------------------------------------------
    tokio::signal::ctrl_c().await?;

    info!("shutting down consensus participation...");

    // Stop the agreement service first, then the catchup service (mirrors
    // Go's shutdown order where the agreement service is stopped before the
    // catchup service, ensuring no new certificates are sent after the
    // catchup service shuts down).
    handle.shutdown();
    catchup_service.stop();
    gossip_node.stop().await;
    info!("consensus participation stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_pool::traits::BlockEvaluator;
    use algo_types::{
        consensus::consensus_params_for_version, Address, ConsensusParams, Round,
        SignedTransaction, Transaction, TxnType, CONSENSUS_V41,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;
    use std::sync::{Arc, Mutex};

    // ── Helper: create an in-memory ledger ──────────────────────────
    fn test_ledger() -> Arc<Mutex<SqliteLedger>> {
        Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ))
    }

    // ── Helper: V41 consensus params ────────────────────────────────
    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V41).unwrap()
    }

    // ── Helper: build an evaluator with pre-seeded account balances ─
    fn make_evaluator(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        accounts: &[(Address, u64)],
    ) -> SimpleBlockEvaluator {
        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round,
        };
        // Pre-populate the snapshot cache so tests don't need the ledger
        // to actually contain accounts.
        for (addr, balance) in accounts {
            snapshot.accounts.insert(
                *addr,
                Some(algo_types::AccountData {
                    micro_algos: *balance,
                    ..Default::default()
                }),
            );
        }
        SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(round),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
        }
    }

    // ── Helper: ed25519 keypair → (Address, SigningKey) ─────────────
    fn test_keypair(seed: u8) -> (Address, SigningKey) {
        let secret = [seed; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let pk = signing_key.verifying_key().to_bytes();
        (Address(pk), signing_key)
    }

    // ── Helper: sign a transaction with ed25519 ─────────────────────
    fn sign_txn(txn: &Transaction, key: &SigningKey) -> [u8; 64] {
        let canonical = algo_codec::canonical_encode_transaction(txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        sig.to_bytes()
    }

    // ── Helper: build a signed payment txn for a given round ────────
    fn make_signed_pay(
        sender_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, sender_key);
        SignedTransaction {
            txn,
            sig,
            ..Default::default()
        }
    }

    // ====================================================================
    // 1. CowOverlay unit tests
    // ====================================================================

    #[test]
    fn cow_overlay_txid_dedup() {
        let mut overlay = CowOverlay::new();
        let txid = [0x42; 32];
        assert!(overlay.check_txid(&txid).is_ok());
        overlay.record_txid(txid);
        let err = overlay.check_txid(&txid).unwrap_err();
        assert!(err.to_string().contains("duplicate transaction ID"));
    }

    #[test]
    fn cow_overlay_lease_dedup() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let lease = [0xBB; 32];
        let round = 100;
        assert!(overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .is_ok());
        overlay.record_lease(&sender, &lease, round + 500);
        let err = overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .unwrap_err();
        assert!(err.to_string().contains("duplicate lease"));
    }

    #[test]
    fn cow_overlay_zero_lease_always_allowed() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let zero_lease = [0u8; 32];
        overlay.record_lease(&sender, &zero_lease, 999);
        assert!(overlay
            .check_lease_in_overlay(&sender, &zero_lease, 100)
            .is_ok());
    }

    #[test]
    fn cow_overlay_balance_tracking() {
        let mut overlay = CowOverlay::new();
        let addr = Address([5; 32]);
        assert!(overlay.get_balance(&addr).is_none());
        overlay.set_balance(&addr, 1_000_000);
        assert_eq!(overlay.get_balance(&addr), Some(1_000_000));
    }

    #[test]
    fn cow_checkpoint_and_rollback() {
        let mut overlay = CowOverlay::new();
        let addr = Address([7; 32]);
        overlay.set_balance(&addr, 500_000);
        let txid1 = [0x01; 32];
        overlay.record_txid(txid1);

        // Checkpoint
        let cp = overlay.checkpoint();

        // Mutate
        overlay.set_balance(&addr, 100);
        let txid2 = [0x02; 32];
        overlay.record_txid(txid2);
        assert_eq!(overlay.get_balance(&addr), Some(100));
        assert!(overlay.check_txid(&txid2).is_err());

        // Rollback
        overlay.restore(cp);
        assert_eq!(overlay.get_balance(&addr), Some(500_000));
        // txid2 should no longer be seen
        assert!(overlay.check_txid(&txid2).is_ok());
        // txid1 should still be seen
        assert!(overlay.check_txid(&txid1).is_err());
    }

    // ====================================================================
    // 2. stpf / heartbeat rejection tests
    // ====================================================================

    #[test]
    fn reject_stpf_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &Address([2; 32]), 0, 1000, 100);
        stx.txn.txn_type = TxnType::Stpf;
        // Re-sign after mutation
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("stpf"),
            "expected stpf rejection, got: {err}"
        );
    }

    #[test]
    fn reject_heartbeat_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &Address([2; 32]), 0, 1000, 100);
        stx.txn.txn_type = TxnType::Hb;
        // Re-sign after mutation
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("hb") || err.to_string().contains("heartbeat"),
            "expected heartbeat rejection, got: {err}"
        );
    }

    // ====================================================================
    // 3. Signature verification tests
    // ====================================================================

    #[test]
    fn valid_single_sig_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(10);
        let (receiver, _) = test_keypair(11);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 10_000_000), (receiver, 100_000)],
        );

        let stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        assert!(eval.transaction_group(&[stx]).is_ok());
    }

    #[test]
    fn invalid_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(20);
        let (receiver, _) = test_keypair(21);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        // Corrupt signature
        stx.sig[0] ^= 0xFF;

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "expected signature error, got: {err}"
        );
    }

    #[test]
    fn missing_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(30);
        let (receiver, _) = test_keypair(31);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender,
                receiver,
                amount: 1000,
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(1100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                ..Default::default()
            },
            sig: [0u8; 64], // no signature
            ..Default::default()
        };

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("no signature"),
            "expected no-signature error, got: {err}"
        );
    }

    // ====================================================================
    // 4. Lease uniqueness tests
    // ====================================================================

    #[test]
    fn duplicate_lease_in_block_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(40);
        let (receiver, _) = test_keypair(41);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xCC; 32];

        // First txn with lease (amount=0 to avoid receiver min-balance issues)
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second txn with same lease but different note (so txid differs) — should be rejected
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            lease,
            note: ByteBuf::from(vec![0x01]), // different note -> different txid
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("lease"),
            "expected lease error, got: {err}"
        );
    }

    #[test]
    fn different_leases_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(42);
        let (receiver, _) = test_keypair(43);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = [0xDD; 32];
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = [0xEE; 32];
        stx2.sig = sign_txn(&stx2.txn, &key);
        assert!(eval.transaction_group(&[stx2]).is_ok());
    }

    // ====================================================================
    // 5. TxID dedup tests
    // ====================================================================

    #[test]
    fn duplicate_txid_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(50);
        let (receiver, _) = test_keypair(51);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);

        // First submission succeeds
        assert!(eval.transaction_group(std::slice::from_ref(&stx)).is_ok());

        // Same exact transaction again — should be rejected as duplicate txid
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate transaction ID"),
            "expected duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_txid_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(52);
        let (receiver, _) = test_keypair(53);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Build a single transaction and submit it twice in the same group.
        // Both copies are identical so they have the same txid.
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx.clone(), stx]).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate transaction ID within group"),
            "expected intra-group duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_lease_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(54);
        let (receiver, _) = test_keypair(55);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xFF; 32];

        // Two transactions from the same sender with the same lease but
        // different notes (so they have different txids).
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.txn.note = ByteBuf::from(vec![0x01]);
        stx1.sig = sign_txn(&stx1.txn, &key);

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = lease;
        stx2.txn.note = ByteBuf::from(vec![0x02]);
        stx2.sig = sign_txn(&stx2.txn, &key);

        let err = eval.transaction_group(&[stx1, stx2]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate lease within group"),
            "expected intra-group duplicate lease error, got: {err}"
        );
    }

    // ====================================================================
    // 6. Balance / min-balance tests
    // ====================================================================

    #[test]
    fn insufficient_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(60);
        let (receiver, _) = test_keypair(61);
        // Sender only has 500 microAlgos — not enough for fee(1000) + amount(100)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 500)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance"),
            "expected insufficient balance, got: {err}"
        );
    }

    #[test]
    fn sender_below_min_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(62);
        let (receiver, _) = test_keypair(63);
        // Sender has exactly min_balance + fee + amount — after deduction they'd
        // have amount=0 left. Let's set them up so they'd have a few uAlgos left
        // but below min_balance.
        // fee=1000, amount=0 -> sender_after = balance - 1000
        // We want: 0 < sender_after < min_balance
        // So balance = 1000 + 50_000 = 51_000, sender_after = 50_000 < 100_000
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 51_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum") || err.to_string().contains("min"),
            "expected min-balance error, got: {err}"
        );
    }

    #[test]
    fn close_remainder_zeros_sender_and_credits_close_addr() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(64);
        let (receiver, _) = test_keypair(65);
        let (close_addr, _) = test_keypair(66);
        // Sender: 1_000_000, fee=1000, amount=200_000
        // After cost: 1_000_000 - 1000 - 200_000 = 799_000
        // Close: sender -> 0, close_addr gets 799_000
        let initial_close_balance = 500_000u64;
        let initial_receiver_balance = 100_000u64;
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, 1_000_000),
                (receiver, initial_receiver_balance),
                (close_addr, initial_close_balance),
            ],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 200_000, 1000, 100);
        stx.txn.close_remainder_to = close_addr;
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(eval.transaction_group(&[stx]).is_ok());

        // Verify sender is zero (closed)
        assert_eq!(eval.effective_balance(&sender), 0);
        // Verify close_addr got the remainder
        // sender_after_cost = 1_000_000 - 1000 - 200_000 = 799_000
        // close_addr = 500_000 + 799_000 = 1_299_000
        assert_eq!(
            eval.effective_balance(&close_addr),
            initial_close_balance + (1_000_000 - 1000 - 200_000)
        );
        // Verify receiver got the amount
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + 200_000
        );
    }

    #[test]
    fn cross_group_receiver_can_spend() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(70);
        let (sender_b, key_b) = test_keypair(71);
        let (receiver, _) = test_keypair(72);
        // sender_a has 1M, sender_b has 0
        // Group 1: A sends 500_000 to B
        // Group 2: B sends 100_000 to receiver (needs balance from group 1)
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 1_000_000),
                (sender_b, 200_000), // needs min balance + fee
            ],
        );

        // Group 1: A -> B for 500_000
        let stx1 = make_signed_pay(&key_a, &sender_a, &sender_b, 500_000, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Group 2: B -> receiver for 100_000 (B should have 200_000 + 500_000 = 700_000 now)
        let stx2 = make_signed_pay(&key_b, &sender_b, &receiver, 100_000, 1000, 100);
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "receiver from group 1 should be able to spend in group 2"
        );

        // B's balance: 700_000 - 100_000 - 1000 = 599_000
        assert_eq!(eval.effective_balance(&sender_b), 599_000);
    }

    // ====================================================================
    // 7. COW rollback test (rejected group doesn't corrupt overlay)
    // ====================================================================

    #[test]
    fn rejected_group_does_not_corrupt_overlay() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(80);
        let (receiver, _) = test_keypair(81);
        // Give sender enough for one group but the second would drop below min balance
        // after the first. The second group should fail min-balance check and
        // the overlay should be rolled back.
        //
        // Balance: 200_000. min_balance = 100_000.
        // Group 1: fee=1000, amount=0 -> sender=199_000 (ok, above min_balance)
        // Group 2 (will fail): fee=1000, amount=99_000 -> sender=99_000 (below min_balance!)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 200_000)]);

        // Group 1 succeeds
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 199_000);

        // Group 2 should fail (would put sender at 99_000 < 100_000)
        // Use a different note to avoid duplicate txid
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 99_000,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "expected min-balance error, got: {err}"
        );

        // After rollback, sender balance should still be 199_000 (from group 1)
        assert_eq!(
            eval.effective_balance(&sender),
            199_000,
            "overlay should be rolled back after rejected group"
        );

        // And we should be able to do a valid group 3
        let stx3_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x02]),
            ..Default::default()
        };
        let sig3 = sign_txn(&stx3_txn, &key);
        let stx3 = SignedTransaction {
            txn: stx3_txn,
            sig: sig3,
            ..Default::default()
        };
        assert!(eval.transaction_group(&[stx3]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 198_000);
    }

    // ====================================================================
    // 8. Exact byte counting / block size limit tests
    // ====================================================================

    #[test]
    fn block_byte_limit_enforced() {
        let ledger = test_ledger();
        let mut params = v41_params();
        // Set a very small block byte limit to force rejection
        params.max_txn_bytes_per_block = 50;
        let (sender, key) = test_keypair(90);
        let (receiver, _) = test_keypair(91);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // A normal pay txn will be >50 bytes in STIB encoding
        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("block byte limit") || err.to_string().contains("exceed"),
            "expected block byte limit error, got: {err}"
        );
    }

    #[test]
    fn second_group_exceeds_byte_limit() {
        let ledger = test_ledger();
        let mut params = v41_params();
        let (sender, key) = test_keypair(92);
        let (receiver, _) = test_keypair(93);

        // First, figure out how big a single STIB is (amount=0 avoids receiver min-balance)
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let stib_size = algo_codec::canonical_encode_signed_txn_in_block(&stx).len();

        // Set limit so first txn fits but second doesn't
        params.max_txn_bytes_per_block = (stib_size + 10) as u64;
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // First group fits
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second group should exceed
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("exceed") || err.to_string().contains("block byte limit"),
            "expected byte limit error, got: {err}"
        );
    }

    // ====================================================================
    // 9. Merkle commitment tests
    // ====================================================================

    #[test]
    fn generate_block_with_payset_computes_txn_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(100);
        let (receiver, _) = test_keypair(101);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // Payset should be non-empty
        assert_eq!(block.payset.len(), 1);

        // txn_commitment should be non-zero (Merkle root of non-empty payset)
        assert_ne!(
            block.txn_commitment, [0u8; 32],
            "txn_commitment should be non-zero for non-empty payset"
        );

        // Verify it matches the independently computed Merkle root
        let expected = algo_validate::merkle::compute_payset_merkle_root(&block);
        assert_eq!(block.txn_commitment, expected);
    }

    #[test]
    fn generate_block_empty_payset_has_zero_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let eval = make_evaluator(&ledger, &params, 100, &[]);

        // Cast to mutable for generate_block
        let mut eval = eval;
        let block = eval.generate_block(&[]).unwrap();

        assert!(block.payset.is_empty());
        assert_eq!(
            block.txn_commitment, [0u8; 32],
            "empty payset should have zero txn_commitment"
        );
    }

    #[test]
    fn generate_block_v41_computes_vector_commitments() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(102);
        let (receiver, _) = test_keypair(103);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // V41 has both txn256 (v34+) and txn512 (v41+)
        assert!(
            algo_validate::rules::has_txn256(CONSENSUS_V41),
            "V41 should support txn256"
        );
        assert!(
            algo_validate::rules::has_txn512(CONSENSUS_V41),
            "V41 should support txn512"
        );

        assert_ne!(
            block.txn256, [0u8; 32],
            "txn256 should be non-zero for V41 with non-empty payset"
        );
        assert_ne!(
            block.txn512, [0u8; 64],
            "txn512 should be non-zero for V41 with non-empty payset"
        );

        // Verify they match independently computed values
        let expected_256 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha256,
        );
        assert_eq!(block.txn256.as_slice(), expected_256.as_slice());

        let expected_512 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha512,
        );
        assert_eq!(block.txn512.as_slice(), expected_512.as_slice());
    }

    #[test]
    fn generate_block_old_protocol_skips_vector_commitments() {
        let ledger = test_ledger();
        // Use v30 params — no vector commitments
        let v30_proto = algo_types::consensus::CONSENSUS_V30;
        let params = consensus_params_for_version(v30_proto).unwrap();
        let (sender, key) = test_keypair(104);
        let (receiver, _) = test_keypair(105);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: v30_proto.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: {
                    let mut m = HashMap::new();
                    m.insert(
                        sender,
                        Some(algo_types::AccountData {
                            micro_algos: 10_000_000,
                            ..Default::default()
                        }),
                    );
                    m
                },
                lease_table: algo_ledger::LeaseTable::new(),
                round: 100,
            },
            overlay: CowOverlay::new(),
        };

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        assert!(!algo_validate::rules::has_txn256(v30_proto));
        assert!(!algo_validate::rules::has_txn512(v30_proto));
        assert_eq!(block.txn256, [0u8; 32], "v30 should not compute txn256");
        assert_eq!(block.txn512, [0u8; 64], "v30 should not compute txn512");
    }

    // ====================================================================
    // 10. Evaluator round and pay_set_size
    // ====================================================================

    #[test]
    fn evaluator_round_and_pay_set_size() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(110);
        let (receiver, _) = test_keypair(111);
        let mut eval = make_evaluator(&ledger, &params, 42, &[(sender, 10_000_000)]);

        assert_eq!(eval.round(), Round(42));
        assert_eq!(eval.pay_set_size(), 0);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 42);
        eval.transaction_group(&[stx]).unwrap();

        assert_eq!(eval.pay_set_size(), 1);
    }

    // ====================================================================
    // 11. STIB genesis field stripping
    // ====================================================================

    #[test]
    fn transaction_group_strips_genesis_fields() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(120);
        let (receiver, _) = test_keypair(121);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        // Pre-check: the txn has genesis fields set
        assert_eq!(stx.txn.genesis_id, "test-v1");
        assert_eq!(stx.txn.genesis_hash, [0xAA; 32]);

        eval.transaction_group(&[stx]).unwrap();

        // After inclusion, the included_txns should have genesis fields stripped
        // (STIB format). Generate the block to access them.
        let block = eval.generate_block(&[]).unwrap();
        let stib = &block.payset[0];
        assert!(
            stib.txn.genesis_id.is_empty(),
            "STIB should have genesis_id stripped"
        );
        assert_eq!(
            stib.txn.genesis_hash, [0u8; 32],
            "STIB should have genesis_hash zeroed"
        );
        assert!(stib.has_genesis_id, "STIB should set has_genesis_id flag");
    }

    // ====================================================================
    // 12. Multi-transaction group test (T1)
    // ====================================================================

    #[test]
    fn multi_txn_group_accepted_and_included() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(130);
        let (sender_b, key_b) = test_keypair(131);
        let (receiver, _) = test_keypair(132);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 10_000_000),
                (sender_b, 10_000_000),
                (receiver, 100_000),
            ],
        );

        // Build two transactions that will form a group.
        let mut txn_a = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_a,
            receiver,
            amount: 1_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let mut txn_b = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_b,
            receiver,
            amount: 2_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };

        // Compute group ID (compute_group_id zeroes the group field internally).
        let group_id = algo_validate::rules::compute_group_id(&[txn_a.clone(), txn_b.clone()]);
        txn_a.group = *group_id.as_bytes();
        txn_b.group = *group_id.as_bytes();

        // Sign both transactions (with group field set).
        let sig_a = sign_txn(&txn_a, &key_a);
        let sig_b = sign_txn(&txn_b, &key_b);
        let stx_a = SignedTransaction {
            txn: txn_a,
            sig: sig_a,
            ..Default::default()
        };
        let stx_b = SignedTransaction {
            txn: txn_b,
            sig: sig_b,
            ..Default::default()
        };

        // Submit as a single group of 2 transactions.
        assert!(
            eval.transaction_group(&[stx_a, stx_b]).is_ok(),
            "multi-txn group should be accepted"
        );

        // Both should appear in the block payset.
        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(
            block.payset.len(),
            2,
            "block should contain both transactions from the group"
        );
    }

    // ====================================================================
    // 13. Header field propagation test (T3)
    // ====================================================================

    #[test]
    fn generate_block_propagates_all_header_fields() {
        let ledger = test_ledger();
        let params = v41_params();

        // Set distinctive values on the header fields that H2 was dropping.
        let fee_sink = Address([0x11; 32]);
        let rewards_pool = Address([0x22; 32]);
        let proposer = Address([0x33; 32]);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(500),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                rewards_pool,
                proposer,
                rewards_level: 42,
                rewards_rate: 100,
                rewards_residue: 7,
                rewards_recalculation_round: Round(1000),
                bonus: 99,
                fees_collected: 12345,
                proposer_payout: 6789,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: HashMap::new(),
                lease_table: algo_ledger::LeaseTable::new(),
                round: 500,
            },
            overlay: CowOverlay::new(),
        };

        let block = eval.generate_block(&[]).unwrap();

        // Verify all header fields were propagated to the generated block.
        assert_eq!(block.fee_sink, fee_sink, "fee_sink should be propagated");
        assert_eq!(
            block.rewards_pool, rewards_pool,
            "rewards_pool should be propagated"
        );
        assert_eq!(block.proposer, proposer, "proposer should be propagated");
        assert_eq!(
            block.rewards_level, 42,
            "rewards_level should be propagated"
        );
        assert_eq!(block.rewards_rate, 100, "rewards_rate should be propagated");
        assert_eq!(
            block.rewards_residue, 7,
            "rewards_residue should be propagated"
        );
        assert_eq!(
            block.rewards_recalculation_round,
            Round(1000),
            "rewards_recalculation_round should be propagated"
        );
        assert_eq!(block.bonus, 99, "bonus should be propagated");
        assert_eq!(
            block.fees_collected, 12345,
            "fees_collected should be propagated"
        );
        assert_eq!(
            block.proposer_payout, 6789,
            "proposer_payout should be propagated"
        );
    }
}
