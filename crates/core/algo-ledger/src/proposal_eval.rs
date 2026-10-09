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

//! Group-at-a-time evaluation for the transaction pool and block proposer
//! (issue #1776).
//!
//! [`evaluate_group`] is the Rust form of go's
//! `BlockEvaluator.TransactionGroup` as the pool calls it from `ingest`
//! (`data/pools/transactionPool.go`): run the group through the real apply
//! (AVM included) on top of the state the already-pending groups left, and
//! either keep the result or report the first failing transaction without
//! leaving anything behind.

use std::sync::atomic::{AtomicU64, Ordering};

use algo_error::AlgoError;
use algo_types::{Block, SignedTransaction};

use crate::apply::{apply_block_impl_probe, ApplyData, ApplyMode, ExecProbe};
use crate::pending_overlay::{OverlayStore, PendingOverlay};
use crate::sqlite::SqliteLedger;

/// Successful evaluation of one group.
#[derive(Debug)]
pub struct GroupEval {
    /// Apply data of each transaction of the group, in order.
    pub apply_data: Vec<ApplyData>,
    /// The transaction counter after the group (top-level and inner).
    pub final_txn_counter: u64,
}

/// Why [`evaluate_group`] did not produce a [`GroupEval`].
#[derive(Debug)]
pub enum GroupEvalError {
    /// The transaction at `index` (position within the group) cannot be
    /// applied. The overlay is exactly as before the call.
    Txn { index: usize, error: AlgoError },
    /// The overlay or `template` does not match the committed ledger (the
    /// chain advanced since the overlay was created): the group was not
    /// evaluated and the overlay is untouched.
    Stale,
    /// Evaluation failed for a reason no transaction owns.
    Other(AlgoError),
}

/// Evaluate `group` (payset form: genesis fields stripped, `hgi`/`hgh` set
/// per the protocol rule) as the next group of the block described by
/// `template` (next-round header fields; its payset is ignored) on top of
/// `base` + `overlay`.
///
/// On success the group effects stay in `overlay` and later groups see them.
/// On failure the overlay is rolled back.
pub fn evaluate_group(
    base: &SqliteLedger,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
) -> Result<GroupEval, GroupEvalError> {
    use crate::store_trait::LedgerStore;

    if overlay.base_round() != base.current_round()
        || template.round.0 != base.current_round().0 + 1
    {
        return Err(GroupEvalError::Stale);
    }
    let mut block = template.clone();
    block.payset = group.to_vec();

    overlay.begin_group();
    let mut ad: Vec<ApplyData> = Vec::with_capacity(group.len());
    let mut probe = ExecProbe {
        skip_epilogue: true,
        ..ExecProbe::default()
    };
    let res = {
        let mut store = OverlayStore::new(base, overlay);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            apply_block_impl_probe(
                &mut store,
                &block,
                ApplyMode::Execute,
                false,
                None,
                None,
                Some(&mut ad),
                None,
                true,
                Some(&mut probe),
            )
        }))
    };
    match res {
        Ok(Ok(())) => {
            overlay.commit_group(probe.final_txn_counter);
            Ok(GroupEval {
                apply_data: ad,
                final_txn_counter: probe.final_txn_counter,
            })
        }
        Ok(Err(error)) => {
            overlay.rollback_group();
            match probe.failed_txn_index {
                Some(index) if index < group.len() => Err(GroupEvalError::Txn { index, error }),
                _ => Err(GroupEvalError::Other(error)),
            }
        }
        Err(_) => {
            overlay.rollback_group();
            Err(GroupEvalError::Other(AlgoError::Ledger {
                message: "group evaluation panicked".into(),
            }))
        }
    }
}

// ---- metrics (issue #1776) ----

static SCRATCH_FAILURES: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_MAX_US: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_COUNT: AtomicU64 = AtomicU64::new(0);
static LOCK_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);

/// Count a block assembly that had to propose an empty payset because the
/// scratch evaluation could not run (or could not be attributed).
pub fn count_scratch_failure() {
    SCRATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Scratch failures counted so far.
pub fn scratch_failures() -> u64 {
    SCRATCH_FAILURES.load(Ordering::Relaxed)
}

/// Record how long the ledger mutex was held for one pool/proposer
/// evaluation (admission of one group, or the assembly scratch pass).
pub fn record_ledger_lock_hold(held: std::time::Duration) {
    let us = held.as_micros().min(u128::from(u64::MAX)) as u64;
    LOCK_HOLD_MAX_US.fetch_max(us, Ordering::Relaxed);
    LOCK_HOLD_TOTAL_US.fetch_add(us, Ordering::Relaxed);
    LOCK_HOLD_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record how long a pool/proposer evaluation waited to acquire the ledger
/// mutex (not charged to the admission budget or to the hold metrics).
pub fn record_ledger_lock_wait(waited: std::time::Duration) {
    let us = waited.as_micros().min(u128::from(u64::MAX)) as u64;
    LOCK_WAIT_TOTAL_US.fetch_add(us, Ordering::Relaxed);
}

/// Prometheus text for the pool/proposer evaluation counters.
pub fn proposal_metrics_prometheus_text() -> String {
    let rows: [(&str, &str, &str, u64); 5] = [
        (
            "algod_rust_proposal_scratch_failures_total",
            "counter",
            "Block assemblies that proposed an empty payset because the scratch evaluation failed.",
            SCRATCH_FAILURES.load(Ordering::Relaxed),
        ),
        (
            "algod_rust_pool_eval_ledger_lock_hold_max_microseconds",
            "gauge",
            "Longest single hold of the ledger mutex by a pool/proposer evaluation.",
            LOCK_HOLD_MAX_US.load(Ordering::Relaxed),
        ),
        (
            "algod_rust_pool_eval_ledger_lock_hold_microseconds_total",
            "counter",
            "Total ledger mutex hold time of pool/proposer evaluations.",
            LOCK_HOLD_TOTAL_US.load(Ordering::Relaxed),
        ),
        (
            "algod_rust_pool_eval_ledger_lock_wait_microseconds_total",
            "counter",
            "Total time pool/proposer evaluations waited to acquire the ledger mutex.",
            LOCK_WAIT_TOTAL_US.load(Ordering::Relaxed),
        ),
        (
            "algod_rust_pool_eval_ledger_lock_holds_total",
            "counter",
            "Number of pool/proposer evaluations that held the ledger mutex.",
            LOCK_HOLD_COUNT.load(Ordering::Relaxed),
        ),
    ];
    let mut out = String::new();
    for (name, kind, help, value) in rows {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_trait::LedgerStore;
    use algo_types::{AccountData, Address, AssetHolding, Round, TxnType, CONSENSUS_V41};

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn ledger(accounts: &[(Address, AccountData)]) -> SqliteLedger {
        let mut l = SqliteLedger::open_in_memory().expect("ledger");
        l.set_fee_sink(addr(0xF1));
        l.set_rewards_pool(addr(0xF2));
        l.set_protocol(CONSENSUS_V41.to_string());
        l.set_account(
            &addr(0xF1),
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        for (a, d) in accounts {
            l.set_account(a, d.clone());
        }
        l
    }

    fn template(l: &SqliteLedger) -> Block {
        Block {
            round: Round(l.current_round().0 + 1),
            current_protocol: CONSENSUS_V41.to_string(),
            fee_sink: addr(0xF1),
            rewards_pool: addr(0xF2),
            ..Block::default()
        }
    }

    fn pay(from: Address, to: Address, amount: u64, close: Option<Address>) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = from;
        stx.txn.receiver = to;
        stx.txn.amount = amount;
        stx.txn.fee = 1_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1000);
        if let Some(c) = close {
            stx.txn.close_remainder_to = c;
        }
        stx
    }

    fn funded(micro: u64) -> AccountData {
        AccountData {
            micro_algos: micro,
            ..Default::default()
        }
    }

    #[test]
    fn close_to_with_outstanding_assets_is_rejected_with_go_text() {
        let a = addr(1);
        let mut acct = funded(5_000_000);
        acct.total_assets_opted_in = 1;
        let mut l = ledger(&[(a, acct), (addr(2), funded(1_000_000))]);
        l.set_asset_holding(
            &a,
            77,
            AssetHolding {
                amount: 0,
                ..Default::default()
            },
        );
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let err = evaluate_group(&l, &mut ov, &t, &[pay(a, addr(2), 0, Some(addr(2)))])
            .expect_err("must be rejected");
        match err {
            GroupEvalError::Txn { index, error } => {
                assert_eq!(index, 0);
                assert_eq!(error.to_string(), "cannot close: 1 outstanding assets");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            ov.is_empty(),
            "a rejected group leaves the overlay untouched"
        );
    }

    #[test]
    fn later_group_sees_the_effects_of_an_earlier_pending_group() {
        let a = addr(1);
        let b = addr(2);
        let fresh = addr(3);
        let l = ledger(&[(a, funded(50_000_000)), (b, funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        // The fresh account does not exist on the ledger: it can only pay
        // once the pending funding payment is visible (go pending state).
        evaluate_group(&l, &mut ov, &t, &[pay(a, fresh, 10_000_000, None)]).expect("fund");
        evaluate_group(&l, &mut ov, &t, &[pay(fresh, b, 1_000_000, None)]).expect("spend");
        // And it cannot overspend what the first group gave it.
        assert!(matches!(
            evaluate_group(&l, &mut ov, &t, &[pay(fresh, b, 50_000_000, None)]),
            Err(GroupEvalError::Txn { .. })
        ));
    }

    #[test]
    fn failing_second_member_rolls_back_the_whole_group() {
        let a = addr(1);
        let b = addr(2);
        let l = ledger(&[(a, funded(50_000_000)), (b, funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let group = [pay(a, b, 1_000_000, None), pay(b, a, 900_000_000, None)];
        let err = evaluate_group(&l, &mut ov, &t, &group).expect_err("second overspends");
        assert!(matches!(err, GroupEvalError::Txn { index: 1, .. }));
        assert!(ov.is_empty(), "first member effects must be undone");
    }

    #[test]
    fn evaluating_against_an_advanced_ledger_is_stale_not_an_error_verdict() {
        let a = addr(1);
        let mut l = ledger(&[(a, funded(50_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        l.set_current_round(Round(5));
        assert!(matches!(
            evaluate_group(&l, &mut ov, &t, &[pay(a, addr(2), 1, None)]),
            Err(GroupEvalError::Stale)
        ));
    }

    #[test]
    fn per_group_evaluation_skips_the_block_epilogue() {
        let a = addr(1);
        let proposer = addr(0xAB);
        let l = ledger(&[(a, funded(50_000_000)), (proposer, funded(1_000_000))]);
        let mut t = template(&l);
        // A proposer with a payout configured: the block epilogue would pay
        // it out (once, in the final scratch apply), never per group.
        t.proposer = proposer;
        t.proposer_payout = 777_000;
        let mut ov = PendingOverlay::new(&l);
        evaluate_group(&l, &mut ov, &t, &[pay(a, addr(2), 200_000, None)]).expect("first");
        evaluate_group(&l, &mut ov, &t, &[pay(a, addr(2), 300_000, None)]).expect("second");
        let store = OverlayStore::new(&l, &mut ov);
        assert_eq!(
            store.get_account(&proposer).map(|p| p.micro_algos),
            Some(1_000_000),
            "the proposer payout is epilogue, not per-group evaluation"
        );
        assert_eq!(
            store.current_round(),
            Round(0),
            "round bookkeeping is epilogue"
        );
    }

    #[test]
    fn failed_member_index_is_reported_for_a_transaction_apply_failure() {
        let a = addr(1);
        let l = ledger(&[(a, funded(5_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let group = [
            pay(a, addr(2), 200_000, None),
            pay(addr(9), addr(2), 200_000, None),
        ];
        match evaluate_group(&l, &mut ov, &t, &group) {
            Err(GroupEvalError::Txn { index, .. }) => assert_eq!(index, 1),
            other => panic!("unexpected {other:?}"),
        }
    }
}
