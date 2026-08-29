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

//! Traits defining what the transaction pool needs from the ledger and block evaluator.
//!
//! These correspond to the `BlockEvaluator` and ledger interfaces in
//! `go-algorand/data/pools/transactionPool.go`.  We keep them minimal:
//! only the methods the pool actually calls are included.

use algo_error::AlgoError;
use algo_types::{Address, Block, BlockHeader, ConsensusParams, Digest, Round, SignedTransaction};

// ── BlockEvaluator ───────────────────────────────────────────────

/// What the pool needs from a block evaluator.
///
/// Mirrors the Go `BlockEvaluator` interface declared next to
/// `TransactionPool`:
///
/// ```text
/// TestTransactionGroup(txgroup []SignedTxn) error
/// Round() basics.Round
/// PaySetSize() int
/// TransactionGroup(txads ...SignedTxnWithAD) error
/// GenerateBlock(addrs []Address) (*UnfinishedBlock, error)
/// ResetTxnBytes()
/// ```
pub trait BlockEvaluator: Send {
    /// The round this evaluator is building a block for.
    fn round(&self) -> Round;

    /// Number of transactions already added to this evaluator's block.
    fn pay_set_size(&self) -> usize;

    /// Validate a transaction group without committing it.
    fn test_transaction_group(&self, txgroup: &[SignedTransaction]) -> Result<(), AlgoError>;

    /// Add a transaction group to the block under construction.
    fn transaction_group(&mut self, txgroup: &[SignedTransaction]) -> Result<(), AlgoError>;

    /// Finalize and return the assembled block.
    ///
    /// `voting_accounts` are the addresses eligible to vote in this round
    /// (used for proposer payout eligibility in consensus v39+).
    fn generate_block(&mut self, voting_accounts: &[Address]) -> Result<Block, AlgoError>;

    /// Reset the running transaction byte count, allowing more transactions
    /// to be added after hitting the per-block byte limit.
    fn reset_txn_bytes(&mut self);
}

// ── PoolLedger ───────────────────────────────────────────────────

/// What the pool needs from the ledger.
///
/// This is *not* the full ledger interface -- only the subset that
/// `TransactionPool` actually calls:
///
/// - `Latest()` / `BlockHdr(round)` -- track the chain tip.
/// - `StartEvaluator(...)` -- build new block proposals.
/// - `ConsensusParams(round)` -- fee / size checks.
pub trait PoolLedger: Send + Sync {
    /// The latest round committed to the ledger.
    fn latest(&self) -> Round;

    /// Return the block header for a given round.
    fn block_hdr(&self, round: Round) -> Result<BlockHeader, AlgoError>;

    /// Consensus parameters for the protocol version at `round`.
    fn consensus_params(&self, round: Round) -> Result<ConsensusParams, AlgoError>;

    /// Create a new `BlockEvaluator` for building a block on top of `hdr`.
    ///
    /// * `hdr` -- header of the block to build (its round = latest + 1).
    /// * `payset_hint` -- expected number of transactions (sizing hint).
    /// * `max_txn_bytes_per_block` -- 0 means "use the protocol default".
    fn start_evaluator(
        &self,
        hdr: BlockHeader,
        payset_hint: usize,
        max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn BlockEvaluator>, AlgoError>;

    /// Whether `txid` is already confirmed in a recently-committed block.
    ///
    /// Mirrors go's block evaluator rejecting a resubmission of an
    /// already-confirmed transaction via `ledgercore.TransactionInLedgerError`
    /// (`ledger/txtail.go`'s `checkDup`, called from `eval.go`'s
    /// `TestTransactionGroup`). The pool itself only tracks *pending*-pool
    /// duplicates (see `TransactionPool::check_duplicate`), so without this
    /// check a transaction that already confirmed and cleared the pool could
    /// be silently resubmitted and re-applied.
    ///
    /// Default implementation returns `false` (no ledger-confirmed dedup) —
    /// test doubles that don't model committed history can ignore this.
    fn contains_confirmed_txid(&self, _txid: Digest) -> bool {
        false
    }
}
