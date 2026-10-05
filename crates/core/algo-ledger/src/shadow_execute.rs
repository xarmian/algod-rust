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

//! Shadow-execute diagnostic: Replay-vs-Execute differential check (issue #1673).
//!
//! The follow/catch-up paths apply a block that contains no `appl`
//! transaction in [`ApplyMode::Replay`], which trusts the block's recorded
//! `ApplyData`; go-algorand's evaluator re-evaluates every transaction of every
//! block (`ledger/eval/eval.go`, `BlockEvaluator.transaction`). Every Replay
//! parity bug so far (#1655, #1665, #1670, ...) was found only when a live block
//! happened to trip it.
//!
//! With `ALGOD_SHADOW_EXECUTE=1`, [`apply_replay_block_with_shadow`] first
//! evaluates the block in [`ApplyMode::Execute`] inside a scratch SAVEPOINT
//! against the same pre-state and records the post-state of everything the
//! evaluation touched; the savepoint (and the in-memory chain fields) are then
//! rolled back and the block is applied for real in Replay mode, also
//! recording its touches. Both views are compared and any difference is logged
//! as one structured `shadow_execute_mismatch` WARN per block. The committed
//! result is always the plain Replay result; the check never fails a block.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use algo_error::AlgoError;
use algo_types::{AccountData, Address, Block};

use crate::apply::{apply_block_impl_ex, ApplyData, ApplyMode, KvModsMap};
use crate::recording_store::{RecordingStore, ResourceTouches};
use crate::store_trait::LedgerStore;

/// Environment variable that turns the diagnostic on (`1`/`true`).
pub const SHADOW_EXECUTE_ENV: &str = "ALGOD_SHADOW_EXECUTE";

/// Log token the soak log scan counts under the hard tier.
pub const MISMATCH_LOG_TOKEN: &str = "shadow_execute_mismatch";

/// Longest value rendering kept in a [`ShadowDiff`].
const MAX_VALUE_CHARS: usize = 160;
/// How many diffs one WARN line spells out.
const MAX_DIFFS_LOGGED: usize = 8;
/// Emit a `shadow_execute_progress` INFO line every this many checked blocks
/// (and every 5x this many app-call blocks that bypass the check).
const PROGRESS_EVERY: u64 = 100;

static CHECKED: AtomicU64 = AtomicU64::new(0);
static MISMATCHED: AtomicU64 = AtomicU64::new(0);
static SKIPPED: AtomicU64 = AtomicU64::new(0);
static APP_CALL_BLOCKS: AtomicU64 = AtomicU64::new(0);
static CHECK_US: AtomicU64 = AtomicU64::new(0);

fn log_progress(last_round: u64) {
    let (c, m, k) = shadow_execute_counters();
    let app = APP_CALL_BLOCKS.load(Ordering::Relaxed);
    let avg_us = CHECK_US.load(Ordering::Relaxed).checked_div(c).unwrap_or(0);
    tracing::info!(
        "shadow_execute_progress checked={c} mismatched_blocks={m} skipped_unsupported_store={k} app_call_blocks_not_checked={app} avg_check_us={avg_us} last_round={last_round}"
    );
}

/// Record that a block with app calls (applied in Execute mode already, so
/// not shadow-checked) went by; keeps the progress line meaningful on a chain
/// where almost every block carries an `appl` transaction.
pub fn note_app_call_block(round: u64) {
    let n = APP_CALL_BLOCKS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n % (PROGRESS_EVERY * 5) == 0 {
        log_progress(round);
    }
}

/// Whether `ALGOD_SHADOW_EXECUTE` is set to a truthy value (read once).
pub fn shadow_execute_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(SHADOW_EXECUTE_ENV)
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

/// `(checked, mismatched, skipped)` block counters since process start.
pub fn shadow_execute_counters() -> (u64, u64, u64) {
    (
        CHECKED.load(Ordering::Relaxed),
        MISMATCHED.load(Ordering::Relaxed),
        SKIPPED.load(Ordering::Relaxed),
    )
}

/// One Replay-vs-Execute difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowDiff {
    pub round: u64,
    /// Index of the (first) payset transaction naming `account`, or the
    /// transaction an `ApplyData` field belongs to.
    pub txn_index: Option<usize>,
    /// `account`, `asset_holding`, `asset_params`, `app_params`,
    /// `app_local_state`, `box`, `apply_data`, `execute_error`.
    pub kind: &'static str,
    pub account: Option<Address>,
    /// Asset/app id for resource kinds.
    pub id: Option<u64>,
    pub field: String,
    pub replay: String,
    pub execute: String,
}

impl std::fmt::Display for ShadowDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(i) = self.txn_index {
            write!(f, " txn={i}")?;
        }
        if let Some(a) = &self.account {
            write!(f, " account={a}")?;
        }
        if let Some(id) = self.id {
            write!(f, " id={id}")?;
        }
        write!(
            f,
            " field={} replay={} execute={}",
            self.field, self.replay, self.execute
        )
    }
}

/// Outcome of one shadow check.
#[derive(Debug, Default)]
pub struct ShadowReport {
    /// `false` when the store cannot roll back a scratch apply.
    pub checked: bool,
    pub diffs: Vec<ShadowDiff>,
}

fn clip(s: String) -> String {
    if s.chars().count() <= MAX_VALUE_CHARS {
        s
    } else {
        let mut t: String = s.chars().take(MAX_VALUE_CHARS).collect();
        t.push_str("...");
        t
    }
}

/// Chain-level in-memory fields a block apply rewrites and
/// `restore_snapshot` does not cover.
struct ChainFields {
    round: algo_types::Round,
    level: u64,
    rate: u64,
    residue: u64,
    recalc: u64,
    fee_sink: Address,
    pool: Address,
    protocol: String,
    txn_counter: u64,
}

impl ChainFields {
    fn capture<L: LedgerStore>(s: &L) -> Self {
        Self {
            round: s.current_round(),
            level: s.rewards_level(),
            rate: s.rewards_rate(),
            residue: s.rewards_residue(),
            recalc: s.rewards_recalculation_round(),
            fee_sink: s.fee_sink(),
            pool: s.rewards_pool(),
            protocol: s.protocol().to_string(),
            txn_counter: s.txn_counter(),
        }
    }

    fn restore<L: LedgerStore>(self, s: &mut L) {
        s.set_current_round(self.round);
        s.set_rewards_level(self.level);
        s.set_rewards_rate(self.rate);
        s.set_rewards_residue(self.residue);
        s.set_rewards_recalculation_round(self.recalc);
        s.set_fee_sink(self.fee_sink);
        s.set_rewards_pool(self.pool);
        s.set_protocol(self.protocol);
        s.set_txn_counter(self.txn_counter);
    }
}

/// Post-state of every key a scratch Execute apply touched.
#[derive(Default)]
struct ExecView {
    accounts: HashMap<Address, Option<AccountData>>,
    holdings: HashMap<(Address, u64), Option<algo_types::AssetHolding>>,
    asset_params: HashMap<u64, Option<algo_types::AssetParamsRecord>>,
    app_params: HashMap<u64, Option<algo_types::AppParams>>,
    locals: HashMap<(Address, u64), Option<algo_types::AppLocalState>>,
}

fn read_exec_view<L: LedgerStore>(store: &L, t: &ResourceTouches) -> ExecView {
    ExecView {
        accounts: t
            .accounts
            .keys()
            .map(|a| (*a, store.get_account(a)))
            .collect(),
        holdings: t
            .asset_holdings
            .keys()
            .map(|k| (*k, store.get_asset_holding(&k.0, k.1)))
            .collect(),
        asset_params: t
            .asset_params
            .keys()
            .map(|id| (*id, store.get_asset_params(*id)))
            .collect(),
        app_params: t
            .app_params
            .keys()
            .map(|id| (*id, store.get_app_params(*id)))
            .collect(),
        locals: t
            .app_local_states
            .keys()
            .map(|k| (*k, store.get_app_local_state(&k.0, k.1)))
            .collect(),
    }
}

/// First payset index whose transaction names `addr` (best effort).
fn txn_index_for(block: &Block, addr: &Address) -> Option<usize> {
    block.payset.iter().position(|stx| {
        let mut set = std::collections::HashSet::new();
        crate::apply::collect_txn_addresses(&stx.txn, &mut set);
        set.contains(addr)
    })
}

macro_rules! field_diffs {
    ($out:expr, $mk:expr, $r:expr, $e:expr, [$($f:ident),* $(,)?]) => {
        $(
            if $r.$f != $e.$f {
                $out.push($mk(
                    stringify!($f).to_string(),
                    clip(format!("{:?}", $r.$f)),
                    clip(format!("{:?}", $e.$f)),
                ));
            }
        )*
    };
}

fn diff_accounts(
    block: &Block,
    addr: &Address,
    replay: Option<AccountData>,
    exec: Option<AccountData>,
    out: &mut Vec<ShadowDiff>,
) {
    // go treats an absent account and an all-zero one identically.
    let r = replay.unwrap_or_default();
    let e = exec.unwrap_or_default();
    if r == e {
        return;
    }
    let idx = txn_index_for(block, addr);
    let mk = |field: String, replay: String, execute: String| ShadowDiff {
        round: block.round.0,
        txn_index: idx,
        kind: "account",
        account: Some(*addr),
        id: None,
        field,
        replay,
        execute,
    };
    let before = out.len();
    field_diffs!(
        out,
        mk,
        r,
        e,
        [
            micro_algos,
            rewards_base,
            rewarded_micro_algos,
            status,
            vote_id,
            selection_id,
            state_proof_id,
            vote_first_valid,
            vote_last_valid,
            vote_key_dilution,
            auth_addr,
            total_assets_opted_in,
            total_created_assets,
            total_apps_opted_in,
            total_created_apps,
            total_extra_app_pages,
            total_box_bytes,
            total_boxes,
            total_app_schema,
            incentive_eligible,
            last_proposed,
            last_heartbeat,
            update_round,
            asset_params,
            assets,
            app_local_states,
            app_params,
        ]
    );
    if out.len() == before {
        out.push(mk(
            "<other>".into(),
            clip(format!("{r:?}")),
            clip(format!("{e:?}")),
        ));
    }
}

fn diff_opt<T: PartialEq + std::fmt::Debug>(
    block: &Block,
    kind: &'static str,
    account: Option<Address>,
    id: u64,
    replay: Option<T>,
    exec: Option<T>,
    out: &mut Vec<ShadowDiff>,
) {
    if replay == exec {
        return;
    }
    let show = |v: &Option<T>| match v {
        Some(v) => clip(format!("{v:?}")),
        None => "<absent>".to_string(),
    };
    out.push(ShadowDiff {
        round: block.round.0,
        txn_index: account.as_ref().and_then(|a| txn_index_for(block, a)),
        kind,
        account,
        id: Some(id),
        field: if replay.is_none() || exec.is_none() {
            "presence".into()
        } else {
            "value".into()
        },
        replay: show(&replay),
        execute: show(&exec),
    });
}

fn diff_apply_data(
    block: &Block,
    replay: &[ApplyData],
    exec: &[ApplyData],
    out: &mut Vec<ShadowDiff>,
) {
    let mk = |idx: Option<usize>, field: &str, r: String, e: String| ShadowDiff {
        round: block.round.0,
        txn_index: idx,
        kind: "apply_data",
        account: None,
        id: None,
        field: field.to_string(),
        replay: r,
        execute: e,
    };
    if replay.len() != exec.len() {
        out.push(mk(
            None,
            "len",
            replay.len().to_string(),
            exec.len().to_string(),
        ));
        return;
    }
    for (i, (r, e)) in replay.iter().zip(exec).enumerate() {
        macro_rules! cmp {
            ($($f:ident),*) => {$(
                if r.$f != e.$f {
                    out.push(mk(Some(i), stringify!($f), r.$f.to_string(), e.$f.to_string()));
                }
            )*};
        }
        cmp!(
            closing_amount,
            asset_closing_amount,
            sender_rewards,
            receiver_rewards,
            close_rewards,
            config_asset,
            application_id
        );
    }
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(24).map(|x| format!("{x:02x}")).collect()
}

/// Compare the Execute view against the state Replay left in `store`.
#[allow(clippy::too_many_arguments)]
fn compare<L: LedgerStore>(
    store: &L,
    block: &Block,
    exec: &ExecView,
    exec_touches: &ResourceTouches,
    replay_touches: &ResourceTouches,
    replay_ad: &[ApplyData],
    exec_ad: &[ApplyData],
    exec_kv: &KvModsMap,
) -> Vec<ShadowDiff> {
    let mut out = Vec::new();
    diff_apply_data(block, replay_ad, exec_ad, &mut out);

    let addrs: BTreeSet<Address> = exec_touches
        .accounts
        .keys()
        .chain(replay_touches.accounts.keys())
        .copied()
        .collect();
    for a in &addrs {
        let replay = store.get_account(a);
        let exec_v = match exec.accounts.get(a) {
            Some(v) => v.clone(),
            // Execute never touched it: its value is the pre-image.
            None => replay_touches.accounts.get(a).cloned().flatten(),
        };
        diff_accounts(block, a, replay, exec_v, &mut out);
    }

    let keys: BTreeSet<(Address, u64)> = exec_touches
        .asset_holdings
        .keys()
        .chain(replay_touches.asset_holdings.keys())
        .copied()
        .collect();
    for k in keys {
        let exec_v = match exec.holdings.get(&k) {
            Some(v) => v.clone(),
            None => replay_touches.asset_holdings.get(&k).cloned().flatten(),
        };
        diff_opt(
            block,
            "asset_holding",
            Some(k.0),
            k.1,
            store.get_asset_holding(&k.0, k.1),
            exec_v,
            &mut out,
        );
    }

    let ids: BTreeSet<u64> = exec_touches
        .asset_params
        .keys()
        .chain(replay_touches.asset_params.keys())
        .copied()
        .collect();
    for id in ids {
        let exec_v = match exec.asset_params.get(&id) {
            Some(v) => v.clone(),
            None => replay_touches.asset_params.get(&id).cloned().flatten(),
        };
        let replay_v = store.get_asset_params(id);
        let acct = replay_v
            .as_ref()
            .map(|r| r.creator)
            .or_else(|| exec_v.as_ref().map(|r| r.creator));
        diff_opt(block, "asset_params", acct, id, replay_v, exec_v, &mut out);
    }

    let ids: BTreeSet<u64> = exec_touches
        .app_params
        .keys()
        .chain(replay_touches.app_params.keys())
        .copied()
        .collect();
    for id in ids {
        let exec_v = match exec.app_params.get(&id) {
            Some(v) => v.clone(),
            None => replay_touches.app_params.get(&id).cloned().flatten(),
        };
        diff_opt(
            block,
            "app_params",
            None,
            id,
            store.get_app_params(id),
            exec_v,
            &mut out,
        );
    }

    let keys: BTreeSet<(Address, u64)> = exec_touches
        .app_local_states
        .keys()
        .chain(replay_touches.app_local_states.keys())
        .copied()
        .collect();
    for k in keys {
        let exec_v = match exec.locals.get(&k) {
            Some(v) => v.clone(),
            None => replay_touches.app_local_states.get(&k).cloned().flatten(),
        };
        diff_opt(
            block,
            "app_local_state",
            Some(k.0),
            k.1,
            store.get_app_local_state(&k.0, k.1),
            exec_v,
            &mut out,
        );
    }

    // A block without `appl` transactions cannot change box storage in go, so
    // any box delta from the Execute evaluation is a divergence.
    for (key, delta) in exec_kv {
        out.push(ShadowDiff {
            round: block.round.0,
            txn_index: None,
            kind: "box",
            account: None,
            id: None,
            field: format!("kv_key={}", hex_prefix(key)),
            replay: "<unchanged>".into(),
            execute: clip(format!("{delta:?}")),
        });
    }
    out
}

/// Apply `block` for real in [`ApplyMode::Replay`] (exactly what the follow
/// path does for a block without app calls) after shadow-evaluating it in
/// [`ApplyMode::Execute`] on a rolled-back scratch apply, and return the
/// differences. An error is only ever the real Replay apply's own.
pub fn shadow_check_replay_block<L: LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<ShadowReport, AlgoError> {
    let Some(aux) = store.save_scratch_state() else {
        apply_block_impl_ex(
            store,
            block,
            ApplyMode::Replay,
            false,
            None,
            None,
            None,
            None,
            false,
        )?;
        return Ok(ShadowReport::default());
    };

    // ---- scratch Execute evaluation, rolled back ----
    let chain = ChainFields::capture(store);
    let sp = store.snapshot(&[]);
    let mut exec_ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    let mut exec_kv = KvModsMap::new();
    let (exec_res, exec_view, exec_touches) = {
        let mut rec = RecordingStore::new(store);
        let res = apply_block_impl_ex(
            &mut rec,
            block,
            ApplyMode::Execute,
            false,
            None,
            None,
            Some(&mut exec_ad),
            Some(&mut exec_kv),
            true,
        );
        let view = read_exec_view(&rec, &rec.touches);
        (res, view, std::mem::take(&mut rec.touches))
    };
    store.restore_snapshot(sp);
    chain.restore(store);
    store.restore_scratch_state(aux);

    // ---- the real Replay apply ----
    let mut replay_ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    let replay_touches = {
        let mut rec = RecordingStore::new(store);
        apply_block_impl_ex(
            &mut rec,
            block,
            ApplyMode::Replay,
            false,
            None,
            None,
            Some(&mut replay_ad),
            None,
            false,
        )?;
        std::mem::take(&mut rec.touches)
    };

    let diffs = match exec_res {
        Ok(()) => compare(
            store,
            block,
            &exec_view,
            &exec_touches,
            &replay_touches,
            &replay_ad,
            &exec_ad,
            &exec_kv,
        ),
        Err(e) => vec![ShadowDiff {
            round: block.round.0,
            txn_index: None,
            kind: "execute_error",
            account: None,
            id: None,
            field: "error".into(),
            replay: "ok".into(),
            execute: clip(e.to_string()),
        }],
    };
    Ok(ShadowReport {
        checked: true,
        diffs,
    })
}

/// Follow-path entry point when [`shadow_execute_enabled`]: apply `block` in
/// Replay mode, shadow-check it, and log a `shadow_execute_mismatch` WARN when
/// the two evaluations disagree. Never alters what is committed and never
/// fails on a mismatch.
pub fn apply_replay_block_with_shadow<L: LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    let started = std::time::Instant::now();
    let report = shadow_check_replay_block(store, block)?;
    let elapsed_us = started.elapsed().as_micros() as u64;
    if !report.checked {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    let checked = CHECKED.fetch_add(1, Ordering::Relaxed) + 1;
    CHECK_US.fetch_add(elapsed_us, Ordering::Relaxed);
    if !report.diffs.is_empty() {
        MISMATCHED.fetch_add(1, Ordering::Relaxed);
        let first: Vec<String> = report
            .diffs
            .iter()
            .take(MAX_DIFFS_LOGGED)
            .map(|d| d.to_string())
            .collect();
        tracing::warn!(
            round = block.round.0,
            diffs = report.diffs.len(),
            elapsed_us,
            "{MISMATCH_LOG_TOKEN} round={} diffs={} [{}]",
            block.round.0,
            report.diffs.len(),
            first.join("; ")
        );
    }
    if checked == 1 || checked % PROGRESS_EVERY == 0 {
        log_progress(block.round.0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::SqliteLedger;
    use algo_types::{AssetParams, Round, SignedTransaction};

    const SENDER: Address = Address([1u8; 32]);
    const RECEIVER: Address = Address([2u8; 32]);
    const FEE_SINK: Address = Address([3u8; 32]);
    const POOL: Address = Address([9u8; 32]);

    fn ledger() -> SqliteLedger {
        let mut l = SqliteLedger::open_in_memory().unwrap();
        l.begin_block().unwrap();
        for (a, v) in [(SENDER, 10_000_000), (FEE_SINK, 1_000_000), (POOL, 0)] {
            l.set_account(
                &a,
                AccountData {
                    micro_algos: v,
                    ..Default::default()
                },
            );
        }
        l.set_fee_sink(FEE_SINK);
        l.set_rewards_pool(POOL);
        l
    }

    fn block(payset: Vec<SignedTransaction>) -> Block {
        Block {
            round: Round(1),
            fee_sink: FEE_SINK,
            rewards_pool: POOL,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            txn_counter: payset.len() as u64,
            payset,
            ..Block::default()
        }
    }

    fn pay() -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "pay".into();
        stx.txn.sender = SENDER;
        stx.txn.receiver = RECEIVER;
        stx.txn.amount = 500_000;
        stx.txn.fee = 1_000;
        stx.txn.last_valid = Round(1_000_000);
        stx
    }

    fn acfg_create(recorded_asset_id: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = SENDER;
        stx.txn.fee = 1_000;
        stx.txn.last_valid = Round(1_000_000);
        stx.txn.asset_params = Some(AssetParams {
            total: 100,
            ..Default::default()
        });
        stx.apply_data_config_asset = recorded_asset_id;
        stx
    }

    #[test]
    fn clean_block_reports_no_diff_and_matches_plain_replay() {
        let b = block(vec![pay()]);
        let mut shadowed = ledger();
        let report = shadow_check_replay_block(&mut shadowed, &b).unwrap();
        assert!(report.checked);
        assert!(report.diffs.is_empty(), "{:#?}", report.diffs);

        // The committed result is exactly what plain Replay produces.
        let mut plain = ledger();
        apply_block_impl_ex(
            &mut plain,
            &b,
            ApplyMode::Replay,
            false,
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();
        for a in [SENDER, RECEIVER, FEE_SINK, POOL] {
            assert_eq!(shadowed.get_account(&a), plain.get_account(&a), "{a}");
        }
        assert_eq!(shadowed.current_round(), plain.current_round());
        assert_eq!(shadowed.txn_counter(), plain.txn_counter());
        assert_eq!(
            shadowed.get_account(&RECEIVER).unwrap().micro_algos,
            500_000
        );
    }

    #[test]
    fn clean_asset_create_block_reports_no_diff() {
        // Recorded `caid` equals what the evaluator derives from the counter.
        let b = block(vec![acfg_create(1)]);
        let mut l = ledger();
        let report = shadow_check_replay_block(&mut l, &b).unwrap();
        assert!(report.checked);
        assert!(report.diffs.is_empty(), "{:#?}", report.diffs);
        assert!(l.get_asset_params(1).is_some());
    }

    #[test]
    fn tampered_recorded_asset_id_is_reported_and_replay_result_is_committed() {
        let b = block(vec![acfg_create(9)]);
        let mut l = ledger();
        let report = shadow_check_replay_block(&mut l, &b).unwrap();
        assert!(report.checked);
        let kinds: Vec<_> = report
            .diffs
            .iter()
            .map(|d| (d.kind, d.id, d.field.as_str()))
            .collect();
        assert!(
            kinds.contains(&("apply_data", None, "config_asset")),
            "{kinds:?}"
        );
        // Replay trusts the recorded id (9); Execute derives 1.
        assert!(
            kinds.contains(&("asset_params", Some(9), "presence")),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&("asset_params", Some(1), "presence")),
            "{kinds:?}"
        );
        let d = report
            .diffs
            .iter()
            .find(|d| d.kind == "apply_data")
            .unwrap();
        assert_eq!(d.txn_index, Some(0));
        assert_eq!(d.replay, "9");
        assert_eq!(d.execute, "1");
        // The scratch Execute apply left nothing behind; Replay's result stands.
        assert!(l.get_asset_params(9).is_some());
        assert!(l.get_asset_params(1).is_none());
        assert_eq!(l.current_round(), Round(1));
    }

    #[test]
    fn tampered_account_state_is_reported_with_field() {
        // Drive the comparison directly: an account whose Replay value differs.
        let b = block(vec![pay()]);
        let mut out = Vec::new();
        diff_accounts(
            &b,
            &SENDER,
            Some(AccountData {
                micro_algos: 5,
                ..Default::default()
            }),
            Some(AccountData {
                micro_algos: 6,
                rewards_base: 1,
                ..Default::default()
            }),
            &mut out,
        );
        let fields: Vec<_> = out.iter().map(|d| d.field.as_str()).collect();
        assert_eq!(fields, ["micro_algos", "rewards_base"]);
        assert_eq!(out[0].txn_index, Some(0));
        assert_eq!(out[0].account, Some(SENDER));
    }

    #[test]
    fn real_replay_error_is_never_masked_by_the_shadow_check() {
        let mut stx = pay();
        stx.txn.sender = Address([7u8; 32]); // unfunded sender
        let b = block(vec![stx]);
        let mut l = ledger();
        assert!(shadow_check_replay_block(&mut l, &b).is_err());
    }

    #[test]
    fn scratch_apply_leaves_exactly_one_round_applied() {
        let mut l = ledger();
        let before = (
            l.rewards_level(),
            l.fee_sink(),
            l.txn_counter(),
            l.current_round(),
        );
        let b = block(vec![pay()]);
        let _ = shadow_check_replay_block(&mut l, &b).unwrap();
        // Applying the same round again must be refused (round advanced once).
        assert_eq!(l.current_round(), Round(before.3 .0 + 1));
        assert_eq!(l.txn_counter(), 1);
    }
}
