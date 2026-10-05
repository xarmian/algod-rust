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
use crate::eval_delta::{parse_eval_delta, EvalDelta, ValueDelta};
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
/// Cap on per-field WARNs for one block's ApplyData mismatches.
const MAX_APPLY_DATA_WARNS_PER_BLOCK: usize = 16;
/// Emit a `shadow_execute_progress` INFO line every this many checked blocks
/// (and every 5x this many app-call blocks that bypass the check).
const PROGRESS_EVERY: u64 = 100;

static CHECKED: AtomicU64 = AtomicU64::new(0);
static MISMATCHED: AtomicU64 = AtomicU64::new(0);
static SKIPPED: AtomicU64 = AtomicU64::new(0);
static CHECK_US: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_BLOCKS: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_TXNS: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_MISMATCH_BLOCKS: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_MISMATCH_TXNS: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_US: AtomicU64 = AtomicU64::new(0);

fn log_progress(last_round: u64) {
    let (c, m, k) = shadow_execute_counters();
    let avg_us = CHECK_US.load(Ordering::Relaxed).checked_div(c).unwrap_or(0);
    let ab = APPLY_DATA_BLOCKS.load(Ordering::Relaxed);
    let ad_avg_us = APPLY_DATA_US
        .load(Ordering::Relaxed)
        .checked_div(ab)
        .unwrap_or(0);
    tracing::info!(
        "shadow_execute_progress state_checked_blocks={c} state_mismatched_blocks={m} state_skipped_unsupported_store={k} state_avg_check_us={avg_us} apply_data_compared_blocks={ab} apply_data_compared_txns={} apply_data_mismatched_blocks={} apply_data_mismatched_txns={} apply_data_avg_compare_us={ad_avg_us} last_round={last_round}",
        APPLY_DATA_TXNS.load(Ordering::Relaxed),
        APPLY_DATA_MISMATCH_BLOCKS.load(Ordering::Relaxed),
        APPLY_DATA_MISMATCH_TXNS.load(Ordering::Relaxed),
    );
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
        let (l, r) = if self.kind == "apply_data" {
            ("recorded", "computed")
        } else {
            ("replay", "execute")
        };
        write!(
            f,
            " field={} {l}={} {r}={}",
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

// ---------------------------------------------------------------------------
// Recorded-vs-computed ApplyData check (go: BlockEvaluator.transaction's
// `ad.Equal(applyData)`, ledger/eval/eval.go).
// ---------------------------------------------------------------------------

type FieldDiff = (String, String, String);

fn show_value_delta(v: Option<&ValueDelta>) -> String {
    match v {
        None => "<absent>".to_string(),
        Some(v) => clip(format!("{v:?}")),
    }
}

/// `basics.StateDelta.Equal`: same keys, same `ValueDelta`s.
fn diff_state_delta(
    path: &str,
    rec: &HashMap<Vec<u8>, ValueDelta>,
    comp: &HashMap<Vec<u8>, ValueDelta>,
    out: &mut Vec<FieldDiff>,
) {
    let keys: BTreeSet<&Vec<u8>> = rec.keys().chain(comp.keys()).collect();
    for k in keys {
        let (r, c) = (rec.get(k), comp.get(k));
        if r != c {
            out.push((
                format!("{path}[{}]", hex_prefix(k)),
                show_value_delta(r),
                show_value_delta(c),
            ));
        }
    }
}

/// First few pretty-`Debug` lines present on one side only; pinpoints the
/// differing field of a large struct without a hand-written field list.
fn debug_line_diff(rec: &str, comp: &str) -> (String, String) {
    let r: Vec<&str> = rec.lines().collect();
    let c: Vec<&str> = comp.lines().collect();
    let pick = |a: &[&str], b: &[&str]| {
        let only: Vec<&str> = a
            .iter()
            .filter(|l| !b.contains(l))
            .take(3)
            .map(|l| l.trim())
            .collect();
        if only.is_empty() {
            "<none>".to_string()
        } else {
            clip(only.join(" | "))
        }
    };
    (pick(&r, &c), pick(&c, &r))
}

/// Compare one pair of recorded/computed `dt` values with `EvalDelta.Equal`
/// semantics: nil and empty deltas are equal, local deltas are keyed by wire
/// index, logs and shared accounts compare element-wise, inner transactions
/// compare their `txn` and (recursively) their own ApplyData.
fn diff_eval_delta(
    path: &str,
    rec: Option<&rmpv::Value>,
    comp: Option<&rmpv::Value>,
    out: &mut Vec<FieldDiff>,
) {
    let parse = |v: Option<&rmpv::Value>| match v {
        None => Ok(EvalDelta::default()),
        Some(v) => parse_eval_delta(v),
    };
    let (r, c) = match (parse(rec), parse(comp)) {
        (Ok(r), Ok(c)) => (r, c),
        (r, c) => {
            out.push((
                format!("{path}.parse"),
                r.err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "ok".into()),
                c.err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "ok".into()),
            ));
            return;
        }
    };

    let empty_sd: HashMap<Vec<u8>, ValueDelta> = HashMap::new();
    diff_state_delta(
        &format!("{path}.global_delta"),
        r.global_delta.as_ref().unwrap_or(&empty_sd),
        c.global_delta.as_ref().unwrap_or(&empty_sd),
        out,
    );

    let empty_ld: HashMap<u64, HashMap<Vec<u8>, ValueDelta>> = HashMap::new();
    let (rl, cl) = (
        r.local_deltas.as_ref().unwrap_or(&empty_ld),
        c.local_deltas.as_ref().unwrap_or(&empty_ld),
    );
    let idxs: BTreeSet<&u64> = rl.keys().chain(cl.keys()).collect();
    for i in idxs {
        match (rl.get(i), cl.get(i)) {
            (Some(a), Some(b)) => diff_state_delta(&format!("{path}.local_delta[{i}]"), a, b, out),
            (a, b) => out.push((
                format!("{path}.local_delta[{i}]"),
                a.map(|m| format!("{} keys", m.len()))
                    .unwrap_or_else(|| "<absent>".into()),
                b.map(|m| format!("{} keys", m.len()))
                    .unwrap_or_else(|| "<absent>".into()),
            )),
        }
    }

    let (rs, cs) = (
        r.shared_accts.clone().unwrap_or_default(),
        c.shared_accts.clone().unwrap_or_default(),
    );
    if rs != cs {
        out.push((
            format!("{path}.shared_accts"),
            clip(format!("{rs:?}")),
            clip(format!("{cs:?}")),
        ));
    }

    let (rg, cg) = (
        r.logs.clone().unwrap_or_default(),
        c.logs.clone().unwrap_or_default(),
    );
    if rg != cg {
        let first = rg
            .iter()
            .zip(&cg)
            .position(|(a, b)| a != b)
            .unwrap_or(rg.len().min(cg.len()));
        out.push((
            format!("{path}.logs[{first}] (counts {}/{})", rg.len(), cg.len()),
            rg.get(first)
                .map(|l| hex_prefix(l))
                .unwrap_or_else(|| "<absent>".into()),
            cg.get(first)
                .map(|l| hex_prefix(l))
                .unwrap_or_else(|| "<absent>".into()),
        ));
    }

    let (ri, ci) = (
        r.inner_txns.as_deref().unwrap_or(&[]),
        c.inner_txns.as_deref().unwrap_or(&[]),
    );
    if ri.len() != ci.len() {
        out.push((
            format!("{path}.inner_txns.len"),
            ri.len().to_string(),
            ci.len().to_string(),
        ));
        return;
    }
    for (i, (a, b)) in ri.iter().zip(ci).enumerate() {
        let p = format!("{path}.inner_txns[{i}]");
        let (ea, eb) = (
            algo_codec::canonical_encode_transaction(&a.txn),
            algo_codec::canonical_encode_transaction(&b.txn),
        );
        if ea != eb {
            let (x, y) = debug_line_diff(&format!("{:#?}", a.txn), &format!("{:#?}", b.txn));
            out.push((format!("{p}.txn"), x, y));
        }
        macro_rules! scalar {
            ($($f:ident),*) => {$(
                if a.$f != b.$f {
                    out.push((format!("{p}.{}", stringify!($f)), a.$f.to_string(), b.$f.to_string()));
                }
            )*};
        }
        scalar!(
            closing_amount,
            asset_closing_amount,
            sender_rewards,
            receiver_rewards,
            close_rewards,
            apply_data_config_asset,
            apply_data_application_id
        );
        diff_eval_delta(
            &format!("{p}.eval_delta"),
            a.eval_delta.as_ref(),
            b.eval_delta.as_ref(),
            out,
        );
    }
}

/// Compare the ApplyData `Execute` computed for each payset transaction with
/// the ApplyData recorded in the block (`SignedTxnInBlock` fields), using
/// go's `ApplyData.Equal` semantics.
pub fn compare_recorded_apply_data(block: &Block, computed: &[ApplyData]) -> Vec<ShadowDiff> {
    let mut out = Vec::new();
    if computed.len() != block.payset.len() {
        out.push(ShadowDiff {
            round: block.round.0,
            txn_index: None,
            kind: "apply_data",
            account: None,
            id: None,
            field: "len".into(),
            replay: block.payset.len().to_string(),
            execute: computed.len().to_string(),
        });
        return out;
    }
    for (i, (stx, c)) in block.payset.iter().zip(computed).enumerate() {
        let mut fields: Vec<FieldDiff> = Vec::new();
        macro_rules! scalar {
            ($($rec:expr, $comp:expr, $name:literal);* $(;)?) => {$(
                if $rec != $comp {
                    fields.push(($name.to_string(), $rec.to_string(), $comp.to_string()));
                }
            )*};
        }
        scalar!(
            stx.closing_amount, c.closing_amount, "closing_amount";
            stx.asset_closing_amount, c.asset_closing_amount, "asset_closing_amount";
            stx.sender_rewards, c.sender_rewards, "sender_rewards";
            stx.receiver_rewards, c.receiver_rewards, "receiver_rewards";
            stx.close_rewards, c.close_rewards, "close_rewards";
            stx.apply_data_config_asset, c.config_asset, "config_asset";
        );
        // `application_id` prefers the recorded apid when replaying; the
        // counter-derived value is what go's evaluator would produce.
        if stx.txn.txn_type == "appl" && stx.txn.application_id == 0 {
            scalar!(
                stx.apply_data_application_id,
                c.derived_application_id,
                "application_id"
            );
        } else {
            scalar!(
                stx.apply_data_application_id,
                c.application_id,
                "application_id"
            );
        }
        diff_eval_delta(
            "eval_delta",
            stx.eval_delta.as_ref(),
            c.eval_delta.as_ref(),
            &mut fields,
        );
        for (field, rec, comp) in fields {
            out.push(ShadowDiff {
                round: block.round.0,
                txn_index: Some(i),
                kind: "apply_data",
                account: None,
                id: None,
                field,
                replay: clip(rec),
                execute: clip(comp),
            });
        }
    }
    out
}

/// Follow-path entry point for blocks that contain app calls when
/// [`shadow_execute_enabled`]: apply the block in [`ApplyMode::Execute`] (as
/// the plain path does), then compare the ApplyData it computed per
/// transaction with the block's recorded ApplyData and log one
/// `shadow_execute_mismatch kind=apply_data` WARN per differing field.
/// Reads only what Execute already computed; never changes what is committed
/// and never fails on a mismatch.
pub fn apply_execute_block_with_apply_data_check<L: LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    let mut computed: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    apply_block_impl_ex(
        store,
        block,
        ApplyMode::Execute,
        false,
        None,
        None,
        Some(&mut computed),
        None,
        false,
    )?;
    let started = std::time::Instant::now();
    let diffs = compare_recorded_apply_data(block, &computed);
    let elapsed_us = started.elapsed().as_micros() as u64;
    let n = APPLY_DATA_BLOCKS.fetch_add(1, Ordering::Relaxed) + 1;
    APPLY_DATA_TXNS.fetch_add(block.payset.len() as u64, Ordering::Relaxed);
    APPLY_DATA_US.fetch_add(elapsed_us, Ordering::Relaxed);
    if !diffs.is_empty() {
        APPLY_DATA_MISMATCH_BLOCKS.fetch_add(1, Ordering::Relaxed);
        let txns: BTreeSet<Option<usize>> = diffs.iter().map(|d| d.txn_index).collect();
        APPLY_DATA_MISMATCH_TXNS.fetch_add(txns.len() as u64, Ordering::Relaxed);
        for d in diffs.iter().take(MAX_APPLY_DATA_WARNS_PER_BLOCK) {
            tracing::warn!(
                "{MISMATCH_LOG_TOKEN} kind=apply_data round={} txn={} field={} recorded={} computed={}",
                d.round,
                d.txn_index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into()),
                d.field,
                d.replay,
                d.execute
            );
        }
        if diffs.len() > MAX_APPLY_DATA_WARNS_PER_BLOCK {
            tracing::warn!(
                "{MISMATCH_LOG_TOKEN} kind=apply_data round={} field=<truncated> total_diffs={}",
                block.round.0,
                diffs.len()
            );
        }
    }
    if n == 1 || n % PROGRESS_EVERY == 0 {
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

    // ---- recorded-vs-computed ApplyData (go: ApplyData.Equal) ----

    use rmpv::Value;

    fn vd_uint(u: u64) -> Value {
        Value::Map(vec![
            (Value::from("at"), Value::from(1u64)),
            (Value::from("ui"), Value::from(u)),
        ])
    }

    fn gd(key: &[u8], v: Value) -> (Value, Value) {
        (
            Value::from("gd"),
            Value::Map(vec![(Value::Binary(key.to_vec()), v)]),
        )
    }

    fn dt(entries: Vec<(Value, Value)>) -> Option<Value> {
        Some(Value::Map(entries))
    }

    /// Block with one transaction carrying `recorded` ApplyData-ish fields,
    /// compared against `computed`.
    fn cmp_one(
        recorded: impl FnOnce(&mut SignedTransaction),
        computed: ApplyData,
    ) -> Vec<ShadowDiff> {
        let mut stx = pay();
        recorded(&mut stx);
        let b = block(vec![stx]);
        compare_recorded_apply_data(&b, &[computed])
    }

    #[test]
    fn identical_apply_data_has_no_diff() {
        assert!(cmp_one(|_| {}, ApplyData::default()).is_empty());
    }

    #[test]
    fn nil_and_empty_eval_deltas_are_equal() {
        // Recorded carries an explicit-but-empty dt; computed has none.
        let d = cmp_one(
            |s| s.eval_delta = dt(vec![(Value::from("gd"), Value::Map(vec![]))]),
            ApplyData::default(),
        );
        assert!(d.is_empty(), "{d:#?}");
        // And the reverse: computed carries an empty dt.
        let d = cmp_one(
            |_| {},
            ApplyData {
                eval_delta: dt(vec![]),
                ..Default::default()
            },
        );
        assert!(d.is_empty(), "{d:#?}");
    }

    #[test]
    fn local_delta_entry_order_is_irrelevant() {
        let ld = |order: &[u64]| {
            Value::Map(
                order
                    .iter()
                    .map(|i| {
                        (
                            Value::from(*i),
                            Value::Map(vec![(Value::Binary(b"k".to_vec()), vd_uint(*i))]),
                        )
                    })
                    .collect(),
            )
        };
        let d = cmp_one(
            |s| s.eval_delta = dt(vec![(Value::from("ld"), ld(&[2, 1]))]),
            ApplyData {
                eval_delta: dt(vec![(Value::from("ld"), ld(&[1, 2]))]),
                ..Default::default()
            },
        );
        assert!(d.is_empty(), "{d:#?}");
    }

    #[test]
    fn rewards_fields_compare_equal_when_both_sides_omit_them() {
        // Protocols without RewardsInApplyData record (and compute) zero.
        let d = cmp_one(
            |s| s.sender_rewards = 0,
            ApplyData {
                sender_rewards: 0,
                ..Default::default()
            },
        );
        assert!(d.is_empty());
        // When present on only one side it is a real mismatch.
        let d = cmp_one(|s| s.sender_rewards = 7, ApplyData::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "sender_rewards");
        assert_eq!((d[0].replay.as_str(), d[0].execute.as_str()), ("7", "0"));
    }

    #[test]
    fn global_delta_value_mismatch_is_reported_per_key() {
        let d = cmp_one(
            |s| s.eval_delta = dt(vec![gd(b"cnt", vd_uint(5))]),
            ApplyData {
                eval_delta: dt(vec![gd(b"cnt", vd_uint(6))]),
                ..Default::default()
            },
        );
        assert_eq!(d.len(), 1, "{d:#?}");
        assert_eq!(d[0].kind, "apply_data");
        assert_eq!(d[0].txn_index, Some(0));
        assert_eq!(d[0].field, "eval_delta.global_delta[636e74]");
        assert!(d[0].replay.contains("uint: 5") && d[0].execute.contains("uint: 6"));
        let line = d[0].to_string();
        assert!(
            line.contains("recorded=") && line.contains("computed="),
            "{line}"
        );
    }

    #[test]
    fn logs_and_missing_local_delta_entry_are_reported() {
        let d = cmp_one(
            |s| {
                s.eval_delta = dt(vec![
                    (
                        Value::from("lg"),
                        Value::Array(vec![Value::Binary(vec![1, 2])]),
                    ),
                    (
                        Value::from("ld"),
                        Value::Map(vec![(Value::from(1u64), Value::Map(vec![]))]),
                    ),
                ])
            },
            ApplyData {
                eval_delta: dt(vec![(
                    Value::from("lg"),
                    Value::Array(vec![Value::Binary(vec![1, 3])]),
                )]),
                ..Default::default()
            },
        );
        let fields: Vec<&str> = d.iter().map(|x| x.field.as_str()).collect();
        assert!(
            fields.iter().any(|f| f.starts_with("eval_delta.logs[0]")),
            "{fields:?}"
        );
        assert!(fields.contains(&"eval_delta.local_delta[1]"), "{fields:?}");
    }

    #[test]
    fn created_app_id_uses_the_counter_derived_value_not_the_recorded_one() {
        let mk = |derived: u64| {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = "appl".into();
            stx.txn.sender = SENDER;
            stx.apply_data_application_id = 42;
            let b = block(vec![stx]);
            compare_recorded_apply_data(
                &b,
                &[ApplyData {
                    application_id: 42,
                    derived_application_id: derived,
                    ..Default::default()
                }],
            )
        };
        assert!(mk(42).is_empty());
        let d = mk(43);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "application_id");
    }

    #[test]
    fn inner_transaction_difference_is_reported_with_path() {
        let inner = |amount: u64| {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = "pay".into();
            stx.txn.sender = SENDER;
            stx.txn.receiver = RECEIVER;
            stx.txn.amount = amount;
            let bytes = rmp_serde::to_vec_named(&stx).unwrap();
            rmpv::decode::read_value(&mut &bytes[..]).unwrap()
        };
        let itx = |amount: u64| {
            dt(vec![(
                Value::from("itx"),
                Value::Array(vec![inner(amount)]),
            )])
        };
        let d = cmp_one(
            |s| s.eval_delta = itx(10),
            ApplyData {
                eval_delta: itx(11),
                ..Default::default()
            },
        );
        assert_eq!(d.len(), 1, "{d:#?}");
        assert_eq!(d[0].field, "eval_delta.inner_txns[0].txn");
        assert!(
            d[0].replay.contains("10") && d[0].execute.contains("11"),
            "{:?}",
            d[0]
        );
        assert!(cmp_one(
            |s| s.eval_delta = itx(10),
            ApplyData {
                eval_delta: itx(10),
                ..Default::default()
            }
        )
        .is_empty());
    }

    #[test]
    fn executed_app_create_round_trips_against_its_own_recorded_apply_data() {
        let approval = algo_avm::assembler::assemble_string(
            "#pragma version 8\nbyte \"k\"\nint 7\napp_global_put\nbyte \"hi\"\nlog\nint 1\nreturn\n",
        )
        .unwrap()
        .program;
        let clear = algo_avm::assembler::assemble_string("#pragma version 8\nint 1\nreturn\n")
            .unwrap()
            .program;
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = SENDER;
        create.txn.fee = 1_000;
        create.txn.last_valid = Round(1_000_000);
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        create.txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        let b = block(vec![create]);

        // Execute once to obtain the computed ApplyData.
        let mut l = ledger();
        let ads =
            crate::apply::apply_block_capturing_apply_data(&mut l, &b, ApplyMode::Execute).unwrap();
        assert_eq!(ads.len(), 1);
        assert_eq!(ads[0].derived_application_id, 1);
        assert!(ads[0].eval_delta.is_some());

        // Record those values the way a committed block carries them.
        let mut recorded = b.clone();
        recorded.payset[0].apply_data_application_id = 1;
        recorded.payset[0].eval_delta = ads[0].eval_delta.clone();
        assert!(compare_recorded_apply_data(&recorded, &ads).is_empty());

        // The follow-path wrapper applies it and agrees.
        let mut l2 = ledger();
        apply_execute_block_with_apply_data_check(&mut l2, &recorded).unwrap();
        assert!(l2.get_app_params(1).is_some());

        // A recorded apid that disagrees with the counter is reported.
        recorded.payset[0].apply_data_application_id = 9;
        let d = compare_recorded_apply_data(&recorded, &ads);
        assert_eq!(d.len(), 1, "{d:#?}");
        assert_eq!(d[0].field, "application_id");
    }
}
