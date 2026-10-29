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
//! [`check_dup`] keeps that order. It takes the block's own state as a
//! [`BlockDups`] and the ledger's as a [`LedgerDups`]: simulate uses it per
//! group (issue #2125), and validate-mode block evaluation per block through
//! [`BlockCheckDup`] (issue #2127).

use std::collections::{HashMap, HashSet};

use algo_error::{AlgoError, RejectClass};
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, Digest, Transaction};

use crate::store_trait::LedgerStore;

/// go `ledgercore.TransactionInLedgerError`, whose text go's simulate and
/// evaluator report bare. `in_block`: go `InBlockEvaluator`, the txid was
/// found among the block's own transactions; it only changes the pool tag.
pub fn transaction_in_ledger_error(txid: Digest, in_block: bool) -> AlgoError {
    typed(
        format!("transaction already in ledger: {txid}"),
        RejectClass::TxidInLedger { in_block },
    )
}

/// go `ledgercore.LeaseInLedgerError`, which prints the lease as an address
/// (`in_block` as in [`transaction_in_ledger_error`]).
pub fn lease_in_ledger_error(
    txid: Digest,
    sender: &Address,
    lease: &[u8; 32],
    in_block: bool,
) -> AlgoError {
    typed(
        format!(
            "transaction {txid} using an overlapping lease (sender, lease):({sender}, {})",
            Address(*lease)
        ),
        RejectClass::LeaseInLedger { in_block },
    )
}

fn rejected(message: String) -> AlgoError {
    typed(message, RejectClass::Other)
}

fn typed(message: String, class: RejectClass) -> AlgoError {
    AlgoError::Rejected {
        source: None,
        message,
        class,
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
    /// The caller already checked the txids against the ledger (the pool's
    /// `contains_confirmed_txid`): the txtail lookup is skipped.
    txids_checked: bool,
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
            txids_checked: false,
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
        if self.txids_checked {
            return false;
        }
        self.confirmed
            .get_or_insert_with(|| {
                store.txtail_confirmed_txids(&self.txids, consensus.max_txn_life)
            })
            .contains(txid)
    }

    /// go `txTail.checkDup`'s lease half: a committed transaction with this
    /// (sender, lease) is still in force at `round`.
    ///
    /// go scans `recent[r]` for a lease that expires at or after `round`,
    /// over `[round - MaxTxnLife, round]` with `FixTransactionLeases` (v23
    /// on) and over the transaction's own `[FirstValid, LastValid]` before
    /// it; `recent` itself only keeps the rounds `[latest - MaxTxnLife,
    /// latest]` (`txTail.committedUpTo`).
    ///
    /// With the fix, at the next block that window is every committed
    /// round, so the store's lease table (the latest expiry per pair)
    /// answers it. For a past round (simulate's `round` parameter) the
    /// table also holds leases committed after `round`, so the window's
    /// txtail rows are read once per group into a table of their own.
    /// Without the fix the window depends on the transaction, so its rows
    /// are read for each leased transaction (protocols before v23 only).
    fn lease_in_ledger<L: LedgerStore + ?Sized>(
        &mut self,
        store: &L,
        consensus: &ConsensusParams,
        txn: &Transaction,
    ) -> bool {
        let round = self.round;
        let latest = store.current_round().0;
        let recent_lo = latest.saturating_sub(consensus.max_txn_life);
        if !consensus.fix_transaction_leases {
            let first = txn.first_valid.0.max(recent_lo);
            let last = txn.last_valid.0.min(latest);
            return window_leases(store, first, last, round)
                .check(&txn.sender, &txn.lease, round)
                .is_err();
        }
        if round > latest {
            return store.check_lease(&txn.sender, &txn.lease, round).is_err();
        }
        let first = round.saturating_sub(consensus.max_txn_life).max(recent_lo);
        self.past_leases
            .get_or_insert_with(|| window_leases(store, first, round, round))
            .check(&txn.sender, &txn.lease, round)
            .is_err()
    }
}

/// The leases in force at `active_at` that the txtail rows `[first, last]`
/// record, with `first` floored at round one
/// ([`crate::lease::LeaseTable::record_txtail_round`]). A missing,
/// unreadable or undecodable row adds no leases.
fn window_leases<L: LedgerStore + ?Sized>(
    store: &L,
    first: u64,
    last: u64,
    active_at: u64,
) -> crate::lease::LeaseTable {
    let mut table = crate::lease::LeaseTable::new();
    for r in first.max(1)..=last {
        let Some(bytes) = store.get_txtail(r).ok().flatten() else {
            continue;
        };
        if let Ok(tail) = rmp_serde::from_slice::<algo_types::TxTailRound>(&bytes) {
            table.record_txtail_round(&tail, active_at);
        }
    }
    table
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
        return Err(transaction_in_ledger_error(txid, true));
    }
    let leased = consensus.support_transaction_leases && txn.lease != [0u8; 32];
    if leased
        && block
            .leases
            .get(&(txn.sender, txn.lease))
            .is_some_and(|&expires| ledger.round <= expires)
    {
        return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease, true));
    }
    // go's block cow: a lease an earlier group of the same pending block
    // holds (the pool's overlay) is an in-block conflict.
    if leased && store.pending_block_lease(&txn.sender, &txn.lease, ledger.round) {
        return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease, true));
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
        return Err(lease_in_ledger_error(txid, &txn.sender, &txn.lease, false));
    }
    if ledger.txid_in_ledger(store, consensus, &txid) {
        return Err(transaction_in_ledger_error(txid, false));
    }
    Ok(())
}

/// go `BlockEvaluator.transaction`'s checks under `Validate` across one
/// block (issue #2127): `BlockHeader.Alive`, then `checkDup` against the
/// block's own txids and leases so far ([`BlockDups`]) and the ledger
/// ([`LedgerDups`]), indexed by payset position. The authorizer check that
/// follows them in go needs the store mutably and stays with the caller.
///
/// The first failure is kept in [`Self::violation`], so a caller that
/// evaluates a block only for a verdict (the agreement proposal validator)
/// can tell such a rejection apart from any other evaluation error.
#[derive(Debug)]
pub struct BlockCheckDup {
    block: BlockDups,
    ledger: LedgerDups,
    /// The block header's genesis id and hash, for `Alive`.
    genesis_id: String,
    genesis_hash: [u8; 32],
    /// Per payset transaction, which stripped genesis fields go's
    /// `DecodeSignedTxn` restores from the header (the block's
    /// `GenesisRestoreRule`, resolved once by the caller).
    restores: Vec<(bool, bool)>,
    violation: Option<String>,
}

impl BlockCheckDup {
    /// The checks for a block of round `round` with header genesis
    /// `genesis_id` / `genesis_hash`, whose payset has the ids `txids` (as
    /// the txtail records them) and the genesis-restore decisions
    /// `restores` (`GenesisRestoreRule::restores`), one per transaction.
    #[must_use]
    pub fn new(
        round: u64,
        txids: Vec<Digest>,
        genesis_id: String,
        genesis_hash: [u8; 32],
        restores: Vec<(bool, bool)>,
    ) -> Self {
        Self {
            block: BlockDups::new(),
            ledger: LedgerDups::new(round, txids),
            genesis_id,
            genesis_hash,
            restores,
            violation: None,
        }
    }

    /// Skip the ledger txid lookup: the caller already rejected txids the
    /// ledger holds (pool admission, whose `contains_confirmed_txid` ran on
    /// the same cache under its own lock).
    #[must_use]
    pub fn with_ledger_txids_checked(mut self) -> Self {
        self.ledger.txids_checked = true;
        self
    }

    /// Record a rejection that follows `checkDup` in go's prologue (the
    /// authorizer), so the proposal check renders it as a verdict too.
    pub fn record_violation(&mut self, message: &str) {
        self.violation.get_or_insert_with(|| message.to_owned());
    }

    /// The payset's txids, as the txtail records them.
    #[must_use]
    pub fn txids(&self) -> &[Digest] {
        self.ledger.txids()
    }

    /// go's `Alive` then `checkDup` for payset transaction `index`
    /// (`stx` in payset form: its stripped genesis fields are restored the
    /// way go's `DecodeSignedTxn` restores them), recording it in the block
    /// when it passes (go `addTx`: a block that fails is discarded whole, so
    /// recording before the transaction applies is equivalent).
    pub fn check<L: LedgerStore + ?Sized>(
        &mut self,
        store: &L,
        consensus: &ConsensusParams,
        stx: &algo_types::SignedTransaction,
        index: usize,
    ) -> Result<(), AlgoError> {
        let Some(&txid) = self.ledger.txids().get(index) else {
            return Err(AlgoError::Ledger {
                message: format!("checkDup: no txid for payset index {index}"),
            });
        };
        let (restore_id, restore_hash) = self.restores.get(index).copied().unwrap_or_default();
        let txn_genesis_id = if restore_id {
            self.genesis_id.as_str()
        } else {
            stx.txn.genesis_id.as_str()
        };
        let txn_genesis_hash = if restore_hash {
            &self.genesis_hash
        } else {
            &stx.txn.genesis_hash
        };
        if let Err(message) = algo_validate::block_alive_with_genesis(
            self.ledger.round,
            &self.genesis_id,
            &self.genesis_hash,
            consensus,
            &stx.txn,
            txn_genesis_id,
            txn_genesis_hash,
        ) {
            self.violation.get_or_insert_with(|| message.clone());
            return Err(rejected(message));
        }
        if let Err(e) = check_dup(
            store,
            consensus,
            &stx.txn,
            txid,
            &self.block,
            &mut self.ledger,
        ) {
            self.violation.get_or_insert_with(|| e.to_string());
            return Err(e);
        }
        self.block.record(&stx.txn, txid);
        Ok(())
    }

    /// The first `Alive` / `checkDup` rejection, if any (go's text).
    #[must_use]
    pub fn violation(&self) -> Option<&str> {
        self.violation.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V22, CONSENSUS_V23};
    use algo_types::{BlockHeader, Round, TxTailRound, TxTailRoundLease};

    const SENDER: Address = Address([7; 32]);
    const LEASE: [u8; 32] = [0x11; 32];

    /// A ledger at round 10 whose round-5 block holds a payment from
    /// `SENDER` with `LEASE`, valid until round 50.
    fn ledger_with_lease_in_round_5() -> crate::state::LedgerState {
        let mut state = crate::state::LedgerState::new();
        let tail = TxTailRound {
            txn_ids: vec![serde_bytes::ByteBuf::from(vec![0xAB; 32])],
            last_valid: vec![50],
            leases: vec![TxTailRoundLease {
                sender: SENDER,
                lease: serde_bytes::ByteBuf::from(LEASE.to_vec()),
                txn_idx: 0,
            }],
            hdr: BlockHeader {
                round: Round(5),
                ..Default::default()
            },
        };
        state
            .put_txtail(5, &algo_codec::canonical_encode_txtail_round(&tail))
            .expect("put txtail");
        state.record_lease(&SENDER, &LEASE, 50);
        state.set_current_round(Round(10));
        state
    }

    fn leased_txn(first_valid: u64, last_valid: u64) -> Transaction {
        Transaction {
            sender: SENDER,
            lease: LEASE,
            first_valid: Round(first_valid),
            last_valid: Round(last_valid),
            ..Default::default()
        }
    }

    fn check(protocol: &str, txn: &Transaction) -> Result<(), AlgoError> {
        let state = ledger_with_lease_in_round_5();
        let consensus = consensus_params_for_version(protocol).expect("known protocol");
        let txid = Digest([0xCD; 32]);
        let mut ledger = LedgerDups::new(11, vec![txid]);
        check_dup(
            &state,
            &consensus,
            txn,
            txid,
            &BlockDups::new(),
            &mut ledger,
        )
    }

    /// Before `FixTransactionLeases` (v18 to v22) go scans the
    /// transaction's own `[FirstValid, LastValid]`, so a lease committed
    /// before `FirstValid` is not seen; from v23 the window is
    /// `[round - MaxTxnLife, round]` (issue #2125).
    #[test]
    fn pre_v23_lease_window_is_the_transactions_validity_range() {
        let v22 = consensus_params_for_version(CONSENSUS_V22).expect("v22");
        assert!(v22.support_transaction_leases && !v22.fix_transaction_leases);
        // FirstValid 6: round 5 is outside the window.
        assert!(check(CONSENSUS_V22, &leased_txn(6, 20)).is_ok());
        // FirstValid 5: round 5 is inside it.
        let err = check(CONSENSUS_V22, &leased_txn(5, 20)).expect_err("lease in force");
        assert!(err.to_string().contains("overlapping lease"), "{err}");
        // v23 sees the lease either way.
        assert!(check(CONSENSUS_V23, &leased_txn(6, 20)).is_err());
        assert!(check(CONSENSUS_V23, &leased_txn(5, 20)).is_err());
    }
}
