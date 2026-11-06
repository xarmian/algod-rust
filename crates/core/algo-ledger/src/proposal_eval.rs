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

/// [`evaluate_group`] for pool admission, with the group's txids (as the
/// txtail records them) already computed by the pool, so `checkDup` does not
/// hash the group again (`None` hashes them here). `checkDup` still looks
/// them up in the ledger's txtail: a re-evaluated pending transaction may
/// have been committed meanwhile.
pub fn evaluate_group_with_txids<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
    txids: Option<Vec<algo_types::Digest>>,
) -> Result<GroupEval, GroupEvalError> {
    evaluate_group_impl(base, overlay, template, group, txids, true)
}

/// [`evaluate_group_with_txids`] that never keeps the group's effects: the
/// overlay is rolled back whether the group is accepted or rejected, so the
/// verdict can be asked of a group that is not going to be admitted (the
/// pool's reconciliation of a precheck rejection, issue #2130) without
/// changing the pending state.
pub fn evaluate_group_discarding<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
    txids: Option<Vec<algo_types::Digest>>,
) -> Result<GroupEval, GroupEvalError> {
    evaluate_group_impl(base, overlay, template, group, txids, false)
}

/// Rolls the pending block's `checkDup` record back to where it was when the
/// guard was made, when dropped, unless [`Self::commit`] kept the group: a
/// rejected, stale, panicked or discarded evaluation (every exit of
/// `evaluate_group_impl` but the kept one) records nothing, however it ends.
struct DupsGuard {
    dups: crate::check_dup::SharedBlockDups,
    mark: crate::check_dup::DupMark,
    kept: bool,
}

impl DupsGuard {
    fn new(dups: crate::check_dup::SharedBlockDups) -> Self {
        let mark = crate::check_dup::lock_dups(&dups).mark();
        Self {
            dups,
            mark,
            kept: false,
        }
    }

    /// Keep the group's records for good (also drops the undo log).
    fn commit(&mut self) {
        crate::check_dup::lock_dups(&self.dups).commit();
        self.kept = true;
    }
}

impl Drop for DupsGuard {
    fn drop(&mut self) {
        if !self.kept {
            crate::check_dup::lock_dups(&self.dups).rollback_to(self.mark);
        }
    }
}

fn evaluate_group_impl<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    template: &Block,
    group: &[SignedTransaction],
    txids: Option<Vec<algo_types::Digest>>,
    keep: bool,
) -> Result<GroupEval, GroupEvalError> {
    let tip = base.base_current_round();
    if base.base_is_stale() || overlay.base_round() != tip || template.round.0 != tip.0 + 1 {
        return Err(GroupEvalError::Stale);
    }
    let mut block = template.clone();
    block.payset = group.to_vec();

    overlay.begin_group();
    // go's one block cow per pending block: `checkDup` starts from the txids
    // and leases of the groups already admitted (issue #2131), and the
    // group's own records are kept only when it is (below).
    let block_dups = overlay.block_dups();
    let mut dups_guard = DupsGuard::new(block_dups.clone());
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
            block_dups: Some(block_dups.clone()),
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
            if keep {
                dups_guard.commit();
                overlay.commit_group(probe.out.final_txn_counter);
            } else {
                overlay.rollback_group();
            }
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
    evaluate_payset_with_txids(base, block, lists, None)
}

/// [`evaluate_payset`] with the payset's txids (as the txtail records them,
/// in payset order) already known by the caller, as the pool knows every
/// pending transaction's: `checkDup` then does not hash the whole payset on
/// every scratch pass (issue #2132). `None` hashes it here; a count that does
/// not match the payset is refused (`checkDup: N txids for a payset of M`).
pub fn evaluate_payset_with_txids<B: OverlayBase + ?Sized>(
    base: &B,
    block: &Block,
    lists: Option<ListsRequest>,
    txids: Option<Vec<algo_types::Digest>>,
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
            txids,
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
    // One overlay for the evaluation and, rolled back, the pre-pass after it
    // (issue #2134): `PendingOverlay::new` reads the chain scalars.
    let mut overlay = PendingOverlay::new(base);
    let result = evaluate_block_on_overlay_with(base, &mut overlay, block, &mut probe);
    // Only a clean apply failure leaves the overlay in a state `rollback_group`
    // is known to restore completely (its undo journal covers every write the
    // apply made). A panic in the middle of a write, a stale base or any other
    // failure gets a fresh overlay for the pre-pass instead.
    let clean_failure = matches!(result, Err(ScratchFailure::Txn { .. }));
    let check = crate::shadow_execute::proposal_check_from(result, &probe);
    if !matches!(check, ProposalCheck::NoVerdict { .. }) {
        return check;
    }
    let reuse = probe.out.ledger_dups.take();
    let prepass = if clean_failure {
        prepass_after_clean_failure(base, &mut overlay, block, reuse)
    } else {
        prologue_prepass_with(base, &mut PendingOverlay::new(base), block, reuse)
    };
    crate::shadow_execute::with_prologue_prepass(check, prepass)
}

/// [`crate::check_dup::prologue_prepass`] on a fresh overlay over `base`:
/// go's `Alive` and `checkDup` over the whole payset, nothing executed. `None`
/// (no verdict) when it passes, or when `base` is not at `block.round - 1` or
/// advanced while it ran.
pub fn prologue_prepass<B: OverlayBase + ?Sized>(base: &B, block: &Block) -> Option<String> {
    let mut overlay = PendingOverlay::new(base);
    prologue_prepass_with(base, &mut overlay, block, None)
}

/// The pre-pass on the overlay a CLEAN apply failure left behind: the group in
/// progress is rolled back first (the undo journal and the lease table), then
/// the pre-pass runs on it with the failed evaluation's ledger half.
fn prepass_after_clean_failure<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    block: &Block,
    reuse: Option<crate::check_dup::LedgerDups>,
) -> Option<String> {
    overlay.rollback_group();
    prologue_prepass_with(base, overlay, block, reuse)
}

/// [`prologue_prepass`] over an overlay the caller already has (empty or
/// rolled back) and the ledger half of the evaluation that just ran on it
/// (`reuse`, [`crate::check_dup::prologue_prepass_reusing`]).
fn prologue_prepass_with<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    block: &Block,
    reuse: Option<crate::check_dup::LedgerDups>,
) -> Option<String> {
    if base.base_is_stale() || block.round.0 != overlay.base_round().0 + 1 {
        return None;
    }
    let verdict =
        crate::check_dup::prologue_prepass_reusing(&OverlayStore::new(base, overlay), block, reuse)
            .violation();
    (!base.base_is_stale()).then_some(verdict).flatten()
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
    evaluate_block_on_overlay_with(base, &mut overlay, block, probe)
}

/// [`evaluate_block_on_overlay`] on an overlay the caller made (and may reuse
/// afterwards: a failed evaluation leaves its group open, to be rolled back).
fn evaluate_block_on_overlay_with<B: OverlayBase + ?Sized>(
    base: &B,
    overlay: &mut PendingOverlay,
    block: &Block,
    probe: &mut ExecProbe,
) -> Result<Vec<ApplyData>, ScratchFailure> {
    if base.base_is_stale() || block.round.0 != overlay.base_round().0 + 1 {
        return Err(ScratchFailure::Stale);
    }
    let mut ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    overlay.begin_group();
    let res = {
        let mut store = OverlayStore::new(base, &mut *overlay);
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

    /// go keeps ONE block cow per pending-block evaluator, so a later group is
    /// checked against every earlier group of the block: a repeated txid is an
    /// in-block `transaction already in ledger` (issue #2131).
    #[test]
    fn a_later_group_repeating_an_earlier_txid_is_an_in_block_duplicate() {
        let a = addr(1);
        let l = ledger(&[(a, funded(50_000_000)), (addr(2), funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let group = [pay(a, addr(2), 1_000, None)];
        evaluate_group(&l, &mut ov, &t, &group).expect("first");
        let err = evaluate_group(&l, &mut ov, &t, &group).expect_err("repeat");
        let GroupEvalError::Txn { index: 0, error } = err else {
            panic!("expected a txn rejection, got {err:?}");
        };
        assert!(
            matches!(
                &error,
                algo_error::AlgoError::Rejected {
                    class: algo_error::RejectClass::TxidInLedger { in_block: true },
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(error
            .to_string()
            .starts_with("transaction already in ledger: "));
    }

    /// The same for a lease an earlier group of the pending block holds.
    #[test]
    fn a_later_group_reusing_an_earlier_lease_is_an_in_block_lease_conflict() {
        let a = addr(1);
        let l = ledger(&[(a, funded(50_000_000)), (addr(2), funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let mut first = pay(a, addr(2), 1_000, None);
        first.txn.lease = [7; 32];
        let mut second = pay(a, addr(2), 2_000, None);
        second.txn.lease = [7; 32];
        evaluate_group(&l, &mut ov, &t, &[first]).expect("first");
        let err = evaluate_group(&l, &mut ov, &t, &[second]).expect_err("same lease");
        let GroupEvalError::Txn { index: 0, error } = err else {
            panic!("expected a txn rejection, got {err:?}");
        };
        assert!(
            matches!(
                &error,
                algo_error::AlgoError::Rejected {
                    class: algo_error::RejectClass::LeaseInLedger { in_block: true },
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// A rejected or discarded evaluation records nothing: the same group is
    /// admitted afterwards.
    #[test]
    fn a_discarded_group_leaves_no_in_block_record() {
        let a = addr(1);
        let l = ledger(&[(a, funded(50_000_000)), (addr(2), funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let group = [pay(a, addr(2), 1_000, None)];
        evaluate_group_discarding(&l, &mut ov, &t, &group, None).expect("asked, not admitted");
        evaluate_group(&l, &mut ov, &t, &group).expect("then admitted");
    }

    /// The pending block's recorded txid count.
    fn recorded(ov: &PendingOverlay) -> usize {
        crate::check_dup::lock_dups(&ov.block_dups()).txid_count()
    }

    /// A member that fails AFTER an earlier member of its group was recorded
    /// leaves no record of the group: the earlier member is admitted when
    /// resubmitted (issue #2131).
    #[test]
    fn a_group_failing_at_its_second_member_leaves_no_in_block_record() {
        let a = addr(1);
        let b = addr(2);
        let l = ledger(&[(a, funded(50_000_000)), (b, funded(1_000_000))]);
        let t = template(&l);
        let mut ov = PendingOverlay::new(&l);
        let first = pay(a, b, 1_000_000, None);
        let group = [first.clone(), pay(b, a, 900_000_000, None)];
        let err = evaluate_group(&l, &mut ov, &t, &group).expect_err("second overspends");
        assert!(matches!(err, GroupEvalError::Txn { index: 1, .. }));
        assert_eq!(recorded(&ov), 0, "the rejected group is not recorded");
        evaluate_group(&l, &mut ov, &t, &[first]).expect("the first member is admitted alone");
        assert_eq!(recorded(&ov), 1);
    }

    /// A panic in the middle of the evaluation (the last read panics, long
    /// after the group was recorded by `checkDup`) leaves no record either.
    #[test]
    fn a_panicking_evaluation_leaves_no_in_block_record() {
        use crate::locked_base::LockedBase;
        use std::sync::Mutex;

        let a = addr(1);
        let group = [pay(a, addr(2), 5_000_000, None)];
        // An uninterrupted run counts the reads and shows the group is
        // recorded by the time the evaluation ends.
        let total = {
            let shared = Mutex::new(ledger(&[(a, funded(50_000_000))]));
            let (t, mut ov) = {
                let l = shared.lock().unwrap();
                (template(&l), PendingOverlay::new(&*l))
            };
            let base = LockedBase::new(&shared, Round(0));
            evaluate_group(&base, &mut ov, &t, &group).expect("group");
            assert_eq!(recorded(&ov), 1);
            base.stats().acquisitions
        };
        let shared = Mutex::new(ledger(&[(a, funded(50_000_000))]));
        let (t, mut ov) = {
            let l = shared.lock().unwrap();
            (template(&l), PendingOverlay::new(&*l))
        };
        let base = LockedBase::new(&shared, Round(0));
        base.before_acquisition(total - 1, || panic!("injected read panic"));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = evaluate_group(&base, &mut ov, &t, &group);
        std::panic::set_hook(prev);
        match res {
            Err(GroupEvalError::Other(e)) => assert!(e.to_string().contains("panicked"), "{e}"),
            other => panic!("expected the panic verdict, got {other:?}"),
        }
        assert_eq!(recorded(&ov), 0, "a panicked group is not recorded");
        assert!(ov.is_empty());
    }

    /// A base that moved while the group was evaluated (Stale: the apply
    /// itself succeeded and recorded the group) leaves no record.
    #[test]
    fn a_stale_evaluation_leaves_no_in_block_record() {
        use crate::locked_base::LockedBase;
        use std::sync::{Arc, Mutex};

        let a = addr(1);
        let group = [pay(a, addr(2), 5_000_000, None)];
        let total = {
            let shared = Mutex::new(ledger(&[(a, funded(50_000_000))]));
            let (t, mut ov) = {
                let l = shared.lock().unwrap();
                (template(&l), PendingOverlay::new(&*l))
            };
            let base = LockedBase::new(&shared, Round(0));
            evaluate_group(&base, &mut ov, &t, &group).expect("group");
            base.stats().acquisitions
        };
        let shared = Arc::new(Mutex::new(ledger(&[(a, funded(50_000_000))])));
        let (t, mut ov) = {
            let l = shared.lock().unwrap();
            (template(&l), PendingOverlay::new(&*l))
        };
        let base = LockedBase::new(&shared, Round(0));
        // A commit lands before the last read, after `checkDup` recorded.
        let m = shared.clone();
        base.before_acquisition(total - 1, move || {
            m.lock().unwrap().set_current_round(Round(1));
        });
        let res = evaluate_group(&base, &mut ov, &t, &group);
        assert!(matches!(res, Err(GroupEvalError::Stale)), "{res:?}");
        assert_eq!(recorded(&ov), 0, "a stale group is not recorded");
    }

    /// The overlay a failed evaluation leaves behind, after `rollback_group`,
    /// gives the pre-pass exactly the verdict a fresh overlay does, with the
    /// execution's ledger half reused or not, across random mixes of plain,
    /// leased, repeated and unevaluable (overspending) transactions (issue
    /// #2134).
    #[test]
    fn reused_overlay_prepass_verdict_equals_a_fresh_overlay_one() {
        let a = addr(1);
        let b = addr(2);
        let l = ledger(&[(a, funded(500_000_000)), (b, funded(1_000_000))]);
        let t = template(&l);
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let (mut violations, mut clean) = (0, 0);
        for _ in 0..60 {
            let mut payset: Vec<SignedTransaction> = Vec::new();
            for i in 0..(2 + next(5)) {
                let mut stx = match next(4) {
                    0 => pay(a, b, 1_000_000_000_000, None), // unevaluable here
                    _ => pay(a, b, 1_000 + next(3), None),
                };
                if next(3) == 0 {
                    stx.txn.lease = [1 + next(2) as u8; 32];
                }
                stx.txn.note = serde_bytes::ByteBuf::from(vec![next(3) as u8, i as u8 % 2]);
                // A repeat of an earlier member (a txid duplicate).
                if !payset.is_empty() && next(5) == 0 {
                    stx = payset[next(payset.len() as u64) as usize].clone();
                }
                payset.push(stx);
            }
            let mut block = t.clone();
            block.payset = payset;

            let fresh = prologue_prepass(&l, &block);

            let mut probe = crate::shadow_execute::proposal_check_probe();
            let mut overlay = PendingOverlay::new(&l);
            let result = evaluate_block_on_overlay_with(&l, &mut overlay, &block, &mut probe);
            if !matches!(result, Err(ScratchFailure::Txn { .. })) {
                continue; // evaluated fully, or no clean failure: not this path
            }
            let reuse = probe.out.ledger_dups.take();
            let reused_overlay_with_reuse =
                prepass_after_clean_failure(&l, &mut overlay, &block, reuse);
            let reused_overlay_without =
                prepass_after_clean_failure(&l, &mut overlay, &block, None);
            assert_eq!(
                reused_overlay_with_reuse,
                fresh,
                "payset {:?}",
                block.payset.len()
            );
            assert_eq!(reused_overlay_without, fresh);
            if fresh.is_some() {
                violations += 1;
            } else {
                clean += 1;
            }
        }
        assert!(
            violations > 0 && clean > 0,
            "{violations} violations, {clean} clean"
        );
    }
}
