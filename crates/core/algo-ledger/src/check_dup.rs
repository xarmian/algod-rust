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
//! takes the block's own state as a [`BlockDups`] and the ledger's as a
//! [`LedgerDups`] so validate-mode block evaluation can reuse it (issue
//! #2127).

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

/// The ledger half of go `checkDup` for one group or block evaluated in
/// `round`, loaded lazily and at most once (issue #2125): which of its
/// `txids` the txtail already holds, and, for a past `round`, the leases in
/// force in go's window.
#[derive(Debug)]
pub struct LedgerDups {
    round: u64,
    txids: Vec<Digest>,
    confirmed: Option<HashSet<Digest>>,
    past_leases: Option<crate::lease::LeaseTable>,
}

impl LedgerDups {
    /// The ledger state for evaluating the transactions `txids` in `round`.
    #[must_use]
    pub fn new(round: u64, txids: Vec<Digest>) -> Self {
        Self {
            round,
            txids,
            confirmed: None,
            past_leases: None,
        }
    }

    /// The txids this was built for.
    #[must_use]
    pub fn txids(&self) -> &[Digest] {
        &self.txids
    }

    fn txid_in_ledger<L: LedgerStore + ?Sized>(
        &mut self,
        store: &L,
        consensus: &ConsensusParams,
        txid: &Digest,
    ) -> bool {
        self.confirmed
            .get_or_insert_with(|| {
                store.txtail_confirmed_txids(&self.txids, consensus.max_txn_life)
            })
            .contains(txid)
    }

    /// go `txTail.checkDup`'s lease half: a committed transaction with this
    /// (sender, lease) is still in force at `round`.
    ///
    /// go scans `recent[r]` for the rounds `[round - MaxTxnLife, round]`
    /// (with `FixTransactionLeases`, set on every protocol since v18) for a
    /// lease that expires at or after `round`; `recent` itself only keeps
    /// the rounds `[latest - MaxTxnLife, latest]` (`txTail.committedUpTo`).
    /// When `round` is the next block that is every committed round, so the
    /// store's lease table (the latest expiry per pair) answers it. For a
    /// past round (simulate's `round` parameter) the table also holds leases
    /// committed after `round`, so the window's txtail rows are read once
    /// into a table of their own
    /// ([`crate::lease::LeaseTable::record_txtail_round`]). A missing,
    /// unreadable or undecodable row adds no leases.
    fn lease_in_ledger<L: LedgerStore + ?Sized>(
        &mut self,
        store: &L,
        consensus: &ConsensusParams,
        txn: &Transaction,
    ) -> bool {
        let round = self.round;
        let latest = store.current_round().0;
        if round > latest {
            return store.check_lease(&txn.sender, &txn.lease, round).is_err();
        }
        self.past_leases
            .get_or_insert_with(|| {
                let mut table = crate::lease::LeaseTable::new();
                let life = consensus.max_txn_life;
                let first = round
                    .saturating_sub(life)
                    .max(latest.saturating_sub(life))
                    .max(1);
                for r in first..=round {
                    let Some(bytes) = store.get_txtail(r).ok().flatten() else {
                        continue;
                    };
                    if let Ok(tail) = rmp_serde::from_slice::<algo_types::TxTailRound>(&bytes) {
                        table.record_txtail_round(&tail, round);
                    }
                }
                table
            })
            .check(&txn.sender, &txn.lease, round)
            .is_err()
    }
}

/// go `checkDup` for `txn` (id `txid`) evaluated after the transactions in
/// `block`, with `ledger` the ledger half for its round.
///
/// Order, as in go: the block's own txid, then its leases
/// (`roundCowState.checkDup`); then the ledger's (`txTail.checkDup`): a
/// `LastValid` below its low-water mark, the lease, the txid.
pub fn check_dup<L: LedgerStore + ?Sized>(
    store: &L,
    consensus: &ConsensusParams,
    txn: &Transaction,
    txid: Digest,
    block: &BlockDups,
    ledger: &mut LedgerDups,
) -> Result<(), AlgoError> {
    if block.txids.contains(&txid) {
        return Err(transaction_in_ledger_error(txid));
    }
    let leased = consensus.support_transaction_leases && txn.lease != [0u8; 32];
    if leased
        && block
            .leases
            .get(&(txn.sender, txn.lease))
            .is_some_and(|&expires| ledger.round <= expires)
    {
        return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease));
    }
    // go `txTail.checkDup`: `lastValid < t.lowWaterMark`. The low-water mark
    // is the last round flushed to the block store; algod-rust commits each
    // block synchronously, so it is the latest round. Only a past simulate
    // round can reach this (`Alive` keeps `LastValid >= round` otherwise).
    if txn.last_valid.0 < store.current_round().0 {
        return Err(rejected(format!(
            "txTail: tried to check for dup in missing round {}",
            txn.last_valid.0
        )));
    }
    if leased && ledger.lease_in_ledger(store, consensus, txn) {
        return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease));
    }
    if ledger.txid_in_ledger(store, consensus, &txid) {
        return Err(transaction_in_ledger_error(txid));
    }
    Ok(())
}
