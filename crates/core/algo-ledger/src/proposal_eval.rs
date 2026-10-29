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

use crate::apply::{
    apply_block_impl_probe, ApplyData, ApplyMode, ExecProbe, ListsRequest, ProbeRequest,
};
use crate::pending_overlay::{OverlayBase, OverlayStore, PendingOverlay};
use crate::shadow_execute::{ProposalCheck, ScratchFailure, ScratchPayset};

/// Successful evaluation of one group.
#[derive(Debug)]
pub struct GroupEval {
    /// Apply data of each transaction of the group, in order.
    pub apply_data: Vec<ApplyData>,
    /// The transaction counter after the group (top-level and inner).
    pub final_txn_counter: u64,
    /// The fees the group paid, top-level and inner transactions, excluding
    /// fee-sink senders (go `takeFee`, issue #1908).
    pub fees_collected: u64,
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
///
/// `base` may take the ledger mutex per read (`LockedBase`, issue #1781): a
/// ledger that moved while the group was evaluated is reported as
/// [`GroupEvalError::Stale`] and the overlay is rolled back, whatever the
/// apply itself concluded.
pub fn evaluate_group<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
) -> Result<GroupEval, GroupEvalError> {
    evaluate_group_with_txids(base, overlay, template, group, None)
}

/// [`evaluate_group`] with the group's txids (as the txtail records them)
/// already computed by the caller, so `checkDup` does not hash the group
/// again. `None` hashes them here.
pub fn evaluate_group_with_txids<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
    txids: Option<Vec<algo_types::Digest>>,
) -> Result<GroupEval, GroupEvalError> {
    let tip = base.base_current_round();
    if base.base_is_stale() || overlay.base_round() != tip || template.round.0 != tip.0 + 1 {
        return Err(GroupEvalError::Stale);
    }
    let mut block = template.clone();
    block.payset = group.to_vec();

    overlay.begin_group();
    let mut ad: Vec<ApplyData> = Vec::with_capacity(group.len());
    let mut probe = ExecProbe {
        request: ProbeRequest {
            skip_epilogue: true,
            generate: true,
            pool_withdrawn: overlay.pool_withdrawn(),
            // go's generating evaluator validates too (`StartEvaluator`
            // with Generate + Validate), so `Alive` and `checkDup` run
            // against the live ledger, not the pool's snapshot (issue #2127).
            check_dup: true,
            txids,
            ..ProbeRequest::default()
        },
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
    if base.base_is_stale() {
        // A read saw another committed state: nothing this evaluation
        // concluded (accept or reject) says anything about the pending block.
        overlay.rollback_group();
        return Err(GroupEvalError::Stale);
    }
    match res {
        Ok(Ok(())) => {
            overlay.commit_group(probe.out.final_txn_counter);
            Ok(GroupEval {
                apply_data: ad,
                final_txn_counter: probe.out.final_txn_counter,
                fees_collected: probe.out.final_fees_collected,
            })
        }
        Ok(Err(error)) => {
            overlay.rollback_group();
            match probe.out.failed_txn_index {
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

/// Evaluate the whole candidate `block` payset (next-round header + stripped
/// payset) on a **fresh** overlay over `base` and return exactly what the
/// proposer's locked scratch apply returns
/// ([`crate::shadow_execute::scratch_execute_payset`]), without a SAVEPOINT on
/// the live connection (issue #1781).
///
/// The block epilogue is skipped: every output the proposer consumes (apply
/// data, transaction counter, `StateProofNextRound`, the fee sink's available
/// balance, the modified accounts for the expired / absent lists) is produced
/// before it, and the epilogue itself cannot fail for the candidate (empty
/// participation lists, no payout in the template).
///
/// [`ScratchFailure::Stale`] when the base is not at `block.round - 1`, or
/// moved while evaluating: the result is dropped, never returned.
pub fn evaluate_payset<B: OverlayBase + ?Sized>(
    base: &B,
    block: &Block,
    lists: Option<ListsRequest>,
) -> Result<ScratchPayset, ScratchFailure> {
    #[cfg(any(test, feature = "test-hooks"))]
    if crate::shadow_execute::test_hooks::should_fail(block.payset.len()) {
        return Err(ScratchFailure::Other(AlgoError::Ledger {
            message: "injected transient scratch failure".into(),
        }));
    }
    let mut probe = ExecProbe {
        request: ProbeRequest {
            skip_epilogue: true,
            generate: true,
            want_fee_sink_available: true,
            knock_offline_exclude: lists.as_ref().map(|l| l.own_addresses.clone()),
            // go generates with Generate + Validate: `checkDup` (#2127).
            check_dup: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let ad = evaluate_block_on_overlay(base, block, &mut probe)?;
    Ok(ScratchPayset {
        apply_data: ad,
        final_txn_counter: probe.out.final_txn_counter,
        final_fees_collected: probe.out.final_fees_collected,
        final_state_proof_next: probe.out.final_state_proof_next,
        final_fee_sink_available: probe.out.final_fee_sink_available,
        knock_offline_lists: probe.out.knock_offline_lists.take(),
        knock_offline_modified: probe.out.knock_offline_modified.take(),
    })
}

/// Judge a peer proposal's payout header fields (go `validateForPayouts`,
/// issue #1798) on a **fresh** overlay over `base`, without a SAVEPOINT on the
/// live connection and without holding the ledger mutex across the
/// evaluation (issue #1895). Identical verdicts to
/// [`crate::shadow_execute::scratch_proposal_check`]: the whole block is
/// evaluated in [`ApplyMode::Execute`] *including* the epilogue (participation
/// lists, payout validation, payout application) with only the payout
/// validation and go's `checkDup` (issue #2127) switched on; a `checkDup`
/// rejection is a verdict too. A base that is not at `block.round - 1`, or that
/// advanced while evaluating, is a transient
/// [`ProposalCheck::NoVerdict`] (the caller retries), never a verdict.
pub fn evaluate_proposal_check<B: OverlayBase + ?Sized>(base: &B, block: &Block) -> ProposalCheck {
    #[cfg(any(test, feature = "test-hooks"))]
    if crate::shadow_execute::test_hooks::should_fail(block.payset.len()) {
        return crate::shadow_execute::payout_check_from::<()>(Err(ScratchFailure::Other(
            AlgoError::Ledger {
                message: "injected transient scratch failure".into(),
            },
        )));
    }
    let mut probe = crate::shadow_execute::proposal_check_probe();
    let result = evaluate_block_on_overlay(base, block, &mut probe);
    crate::shadow_execute::proposal_check_from(result, &probe)
}

/// Evaluate `block` in [`ApplyMode::Execute`] on a fresh overlay over `base`
/// with `probe`, returning the per-transaction apply data. Shared by
/// [`evaluate_payset`] and [`evaluate_proposal_check`].
fn evaluate_block_on_overlay<B: OverlayBase + ?Sized>(
    base: &B,
    block: &Block,
    probe: &mut ExecProbe,
) -> Result<Vec<ApplyData>, ScratchFailure> {
    let mut overlay = PendingOverlay::new(base);
    if base.base_is_stale() || block.round.0 != overlay.base_round().0 + 1 {
        return Err(ScratchFailure::Stale);
    }
    let mut ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    overlay.begin_group();
    let res = {
        let mut store = OverlayStore::new(base, &mut overlay);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            apply_block_impl_probe(
                &mut store,
                block,
                ApplyMode::Execute,
                false,
                None,
                None,
                Some(&mut ad),
                None,
                true,
                Some(&mut *probe),
            )
        }))
    };
    if base.base_is_stale() {
        return Err(ScratchFailure::Stale);
    }
    match res {
        Err(_) => Err(ScratchFailure::Other(AlgoError::Ledger {
            message: "scratch Execute evaluation panicked".into(),
        })),
        Ok(Err(error)) => match probe.out.failed_txn_index {
            Some(index) if index < block.payset.len() => Err(ScratchFailure::Txn { index, error }),
            _ => Err(ScratchFailure::Other(error)),
        },
        Ok(Ok(())) => Ok(ad),
    }
}

// ---- metrics (issue #1776) ----

static SCRATCH_FAILURES: AtomicU64 = AtomicU64::new(0);
static STALE_BASE: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_MAX_US: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static LOCK_HOLD_COUNT: AtomicU64 = AtomicU64::new(0);
static LOCK_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);

/// Count a block assembly that had to propose an empty payset because the
/// scratch evaluation could not run (or could not be attributed).
pub fn count_scratch_failure() {
    SCRATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Count an evaluation (admission of a group or block assembly) that was
/// dropped because the ledger advanced while it ran (issue #1781).
pub fn count_stale_base() {
    STALE_BASE.fetch_add(1, Ordering::Relaxed);
}

/// Stale-base evaluations counted so far.
pub fn stale_base_total() -> u64 {
    STALE_BASE.load(Ordering::Relaxed)
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

/// Record the mutex usage of one evaluation that took the ledger mutex once
/// per read (`LockedBase`, issue #1781): `holds` acquisitions, `total` time
/// held across them and the longest `max` single hold.
pub fn record_ledger_lock_holds(holds: u64, total: std::time::Duration, max: std::time::Duration) {
    if holds == 0 {
        return;
    }
    LOCK_HOLD_MAX_US.fetch_max(
        max.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    LOCK_HOLD_TOTAL_US.fetch_add(
        total.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    LOCK_HOLD_COUNT.fetch_add(holds, Ordering::Relaxed);
}

/// Record how long a pool/proposer evaluation waited to acquire the ledger
/// mutex (not charged to the admission budget or to the hold metrics).
pub fn record_ledger_lock_wait(waited: std::time::Duration) {
    let us = waited.as_micros().min(u128::from(u64::MAX)) as u64;
    LOCK_WAIT_TOTAL_US.fetch_add(us, Ordering::Relaxed);
}

/// Prometheus text for the pool/proposer evaluation counters.
pub fn proposal_metrics_prometheus_text() -> String {
    let rows: [(&str, &str, &str, u64); 6] = [
        (
            "algod_rust_pool_eval_stale_base_total",
            "counter",
            "Pool/proposer evaluations dropped because the ledger advanced while they ran.",
            STALE_BASE.load(Ordering::Relaxed),
        ),
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
    use crate::sqlite::SqliteLedger;
    use crate::store_trait::LedgerStore;
    use algo_types::{AccountData, Address, AssetHolding, Round, TxnType, CONSENSUS_V41};

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn ledger(accounts: &[(Address, AccountData)]) -> SqliteLedger {
        let mut l = SqliteLedger::open_in_memory().unwrap();
        l.set_fee_sink(addr(0xF1));
        l.set_rewards_pool(addr(0xF2));
        // Issue #2116: the block-start withdrawal needs a pool at MinBalance.
        crate::apply::pool_fixtures::fund_test_rewards_pool(&mut l);
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
            // V41 requires a genesis hash: block generation runs go's
            // `Alive` (#2127) on the payset with it restored.
            genesis_hash: crate::apply::pool_fixtures::TEST_GENESIS_HASH,
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

    /// Issue #2116: go's pool evaluates a pending block with one
    /// `BlockEvaluator`, so `StartEvaluator` withdraws the block's accrued
    /// rewards from the pool once, however many groups follow.
    #[test]
    fn pending_block_withdraws_accrued_rewards_from_the_pool_once() {
        let a = addr(1);
        let b = addr(2);
        let pool = addr(0xF2);
        let mut l = ledger(&[
            (a, funded(50_000_000)),
            (b, funded(1_000_000)),
            (
                pool,
                AccountData {
                    micro_algos: 10_000_000,
                    status: algo_types::AccountStatus::NotParticipating,
                    ..Default::default()
                },
            ),
        ]);
        l.put_account_totals_seed(0, 0, 61_000_000, 51, 10_000_000, 10)
            .unwrap();
        // go `prevTotals.RewardUnits()`: online + offline.
        let units = {
            let t = l.account_totals();
            t.online.reward_units + t.offline.reward_units
        };
        assert!(units > 0);
        let mut t = template(&l);
        t.rewards_level = 2;
        let mut ov = PendingOverlay::new(&l);
        evaluate_group(&l, &mut ov, &t, &[pay(a, b, 1_000, None)]).expect("first");
        evaluate_group(&l, &mut ov, &t, &[pay(b, a, 1_000, None)]).expect("second");
        let store = OverlayStore::new(&l, &mut ov);
        assert_eq!(
            crate::store_trait::LedgerStore::get_account(&store, &pool)
                .unwrap()
                .micro_algos,
            10_000_000 - units * 2,
            "one withdrawal of {units} units * 2 levels, not one per group"
        );
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

    // ---- issue #1781: per-read locked base ----

    #[test]
    fn payset_evaluated_while_the_ledger_advances_is_stale_and_returns_nothing() {
        use crate::locked_base::LockedBase;
        use std::sync::{Arc, Mutex};

        let a = addr(1);
        let shared = Arc::new(Mutex::new(ledger(&[(a, funded(5_000_000_000_000))])));
        let (t,) = {
            let l = shared.lock().unwrap();
            (template(&l),)
        };
        let mut block = t;
        // Each payment funds a fresh receiver, so every transaction reads
        // the base at least once (apply no longer reads the lease table per
        // transaction, issue #2127).
        block.payset = (0..600u64)
            .map(|i| {
                let mut to = [0u8; 32];
                to[..8].copy_from_slice(&(1_000 + i).to_be_bytes());
                let mut p = pay(a, Address(to), 200_000 + i, None);
                p.txn.note = serde_bytes::ByteBuf::from(i.to_be_bytes().to_vec());
                p
            })
            .collect();
        let base = LockedBase::new(&shared, Round(0));
        // A block commit lands after 200 reads, in the middle of the evaluation.
        let m = shared.clone();
        base.before_acquisition(200, move || {
            m.lock().unwrap().set_current_round(Round(1));
        });
        let res = evaluate_payset(&base, &block, None);
        assert!(
            base.stats().acquisitions > 200,
            "the commit must land mid-evaluation"
        );
        assert!(
            matches!(res, Err(crate::shadow_execute::ScratchFailure::Stale)),
            "a result computed across a commit must be dropped, got {res:?}"
        );
        assert!(base.is_stale());
    }

    #[test]
    fn group_evaluated_against_an_advanced_ledger_is_stale_and_rolled_back() {
        use crate::locked_base::LockedBase;
        use std::sync::Mutex;

        let a = addr(1);
        let shared = Mutex::new(ledger(&[(a, funded(50_000_000))]));
        let (t, mut ov) = {
            let l = shared.lock().unwrap();
            (template(&l), PendingOverlay::new(&*l))
        };
        shared.lock().unwrap().set_current_round(Round(1));
        let base = LockedBase::new(&shared, Round(0));
        assert!(matches!(
            evaluate_group(&base, &mut ov, &t, &[pay(a, addr(2), 1, None)]),
            Err(GroupEvalError::Stale)
        ));
        assert!(ov.is_empty());
    }

    #[test]
    fn evaluation_does_not_hold_the_mutex_between_reads() {
        use crate::locked_base::LockedBase;
        use std::sync::Mutex;

        let a = addr(1);
        let shared = Mutex::new(ledger(&[(a, funded(5_000_000_000))]));
        let (t, mut ov) = {
            let l = shared.lock().unwrap();
            (template(&l), PendingOverlay::new(&*l))
        };
        let base = LockedBase::new(&shared, Round(0));
        evaluate_group(&base, &mut ov, &t, &[pay(a, addr(2), 5_000_000, None)]).expect("group");
        // Free after the evaluation, and it was taken once per read.
        assert!(shared.try_lock().is_ok());
        assert!(base.stats().acquisitions > 1);
        assert!(!base.is_stale());
    }
}
