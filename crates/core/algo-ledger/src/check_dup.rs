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

//! go-algorand's `checkDup`: the duplicate-transaction and lease checks
//! `BlockEvaluator.transaction` runs under `Validate: true`
//! (`ledger/eval/eval.go`), between `BlockHeader.Alive` and the authorizer
//! check.
//!
//! go asks the block being evaluated first (`roundCowState.checkDup`,
//! `ledger/eval/cow.go`: the txid, then the lease), then the ledger's txtail
//! (`txTail.checkDup`, `ledger/txtail.go`: the lease, then the txid).
//! [`check_dup`] keeps that order. Simulate uses it today (issue #2125); it
//! takes the block's own state as a [`BlockDups`] so validate-mode block
//! evaluation can reuse it (issue #2127).

use std::collections::{HashMap, HashSet};

use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, Digest, Transaction};

use crate::store_trait::LedgerStore;

/// go `ledgercore.TransactionInLedgerError`, whose text go's simulate and
/// evaluator report bare.
pub fn transaction_in_ledger_error(txid: Digest) -> AlgoError {
    rejected(format!("transaction already in ledger: {txid}"))
}

/// go `ledgercore.LeaseInLedgerError`, which prints the lease as an address.
pub fn lease_in_ledger_error(txid: Digest, sender: &Address, lease: &[u8; 32]) -> AlgoError {
    rejected(format!(
        "transaction {txid} using an overlapping lease (sender, lease):({sender}, {})",
        Address(*lease)
    ))
}

fn rejected(message: String) -> AlgoError {
    AlgoError::Rejected {
        source: None,
        message,
        class: algo_error::RejectClass::Other,
    }
}

/// The transactions already evaluated in the block (go `roundCowState`'s
/// `mods.Txids` / `mods.Txleases`).
#[derive(Debug, Default)]
pub struct BlockDups {
    txids: HashSet<Digest>,
    leases: HashMap<(Address, [u8; 32]), u64>,
}

impl BlockDups {
    /// An empty block.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transaction that was evaluated successfully (go `addTx`).
    pub fn record(&mut self, txn: &Transaction, txid: Digest) {
        self.txids.insert(txid);
        if txn.lease != [0u8; 32] {
            self.leases
                .insert((txn.sender, txn.lease), txn.last_valid.0);
        }
    }
}

/// go `checkDup` for `txn` (id `txid`) evaluated in block `round`, after the
/// transactions in `block`.
pub fn check_dup<L: LedgerStore + ?Sized>(
    store: &L,
    consensus: &ConsensusParams,
    round: u64,
    txn: &Transaction,
    txid: Digest,
    block: &BlockDups,
) -> Result<(), AlgoError> {
    if block.txids.contains(&txid) {
        return Err(transaction_in_ledger_error(txid));
    }
    if consensus.support_transaction_leases && txn.lease != [0u8; 32] {
        let in_block = block
            .leases
            .get(&(txn.sender, txn.lease))
            .is_some_and(|&expires| round <= expires);
        if in_block || ledger_lease_live(store, consensus, round, txn) {
            return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease));
        }
    }
    if store.txtail_contains_txid(&txid) {
        return Err(transaction_in_ledger_error(txid));
    }
    Ok(())
}

/// go `txTail.checkDup`'s lease half: a committed transaction with this
/// (sender, lease) is still in force at `round`.
///
/// go scans the rounds `[round - MaxTxnLife, round]` (`FixTransactionLeases`;
/// `[FirstValid, LastValid]` before it) for a lease that expires at or after
/// `round`. When `round` is the next block, every committed round is in that
/// window, so the store's lease table (the latest expiry per pair) answers
/// it. For a past round (simulate's `round` parameter) the table also holds
/// leases committed after `round`, so the txtail rows of the window are
/// scanned instead. A missing or undecodable row adds no leases, as in
/// [`crate::txtail_cache::TxTailDupCache::sync`].
fn ledger_lease_live<L: LedgerStore + ?Sized>(
    store: &L,
    consensus: &ConsensusParams,
    round: u64,
    txn: &Transaction,
) -> bool {
    let latest = store.current_round().0;
    if round > latest {
        return store.check_lease(&txn.sender, &txn.lease, round).is_err();
    }
    let (first, last) = if consensus.fix_transaction_leases {
        (round.saturating_sub(consensus.max_txn_life), round)
    } else {
        (txn.first_valid.0, txn.last_valid.0)
    };
    for r in first.max(1)..=last.min(latest) {
        let Some(bytes) = store.get_txtail(r).ok().flatten() else {
            continue;
        };
        let Ok(tail) = rmp_serde::from_slice::<algo_types::TxTailRound>(&bytes) else {
            continue;
        };
        let live = tail.leases.iter().any(|l| {
            l.sender == txn.sender
                && l.lease.as_ref() == txn.lease.as_slice()
                && usize::try_from(l.txn_idx)
                    .ok()
                    .and_then(|i| tail.last_valid.get(i))
                    .is_some_and(|&expires| round <= expires)
        });
        if live {
            return true;
        }
    }
    false
}
