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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

use algo_error::AlgoError;
use algo_types::{AccountData, Address, Block, Transaction};

use crate::apply::{apply_block_impl_ex, ApplyData, ApplyMode, KvModsMap};
use crate::eval_delta::{parse_eval_delta, EvalDelta, ValueDelta};
use crate::recording_store::{RecordingStore, ResourceTouches};
use crate::store_trait::LedgerStore;

/// Environment variable that turns the diagnostic on (`1`/`true`).
pub const SHADOW_EXECUTE_ENV: &str = "ALGOD_SHADOW_EXECUTE";

/// Optional sampling knob: shadow-check only every Nth Replay-applied block
/// (default 1 = every block). Bounds the extra CPU of the scratch Execute pass.
pub const SHADOW_SAMPLE_ENV: &str = "ALGOD_SHADOW_EXECUTE_SAMPLE_EVERY";

/// Log token the soak log scan counts under the hard tier.
pub const MISMATCH_LOG_TOKEN: &str = "shadow_execute_mismatch";

/// Longest value rendering kept in a [`ShadowDiff`].
const MAX_VALUE_CHARS: usize = 160;
/// How many diffs one WARN line spells out.
const MAX_DIFFS_LOGGED: usize = 8;
/// Per-window budget of repeated (already-seen pattern) mismatch lines.
const MAX_MISMATCH_LINES_PER_WINDOW: u32 = 60;
/// Length of that window in seconds.
const MISMATCH_WINDOW_SECS: u64 = 60;
/// Distinct field patterns tracked (first occurrence of each is never dropped).
const MAX_TRACKED_PATTERNS: usize = 512;
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
static APPLY_DATA_MISMATCH_LINES: AtomicU64 = AtomicU64::new(0);
static APPLY_DATA_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
/// State-mismatch WARN lines dropped by the limiter (distinct from the
/// ApplyData flavour's [`APPLY_DATA_SUPPRESSED`]).
static STATE_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
/// Limiter-suppressed lines already reported by a progress/rollover summary.
static SUPPRESSED_REPORTED: AtomicU64 = AtomicU64::new(0);
static SKIP_WARNED: AtomicBool = AtomicBool::new(false);

// Test-only fault injection into the scratch pass.
#[cfg(test)]
thread_local! {
    /// 0 = none, 1 = pretend the store cannot roll back, 2 = scratch Execute
    /// returns an error, 3 = scratch Execute panics, 4/5 = leaky scratch
    /// (see `inject_leak`).
    static TEST_HOOK: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn test_hook() -> u8 {
    TEST_HOOK.with(|h| h.get())
}

/// `save_scratch_state` with the test-only "unsupported store" injection
/// compiled out of production builds.
fn scratch_state<L: LedgerStore>(store: &mut L) -> Option<Box<dyn std::any::Any>> {
    #[cfg(test)]
    if test_hook() == 1 {
        return None;
    }
    store.save_scratch_state()
}

/// The scratch Execute evaluation; test builds can inject an error/panic.
fn run_scratch_execute<L: LedgerStore>(
    rec: &mut RecordingStore<'_, L>,
    block: &Block,
    exec_ad: &mut Vec<ApplyData>,
    exec_kv: &mut KvModsMap,
) -> Result<(), AlgoError> {
    #[cfg(test)]
    match test_hook() {
        2 => {
            return Err(AlgoError::Ledger {
                message: "injected scratch error".into(),
            })
        }
        3 => panic!("injected scratch panic"),
        _ => {}
    }
    apply_block_impl_ex(
        rec,
        block,
        ApplyMode::Execute,
        false,
        None,
        None,
        Some(exec_ad),
        Some(exec_kv),
        true,
    )
}

fn log_progress(last_round: u64) {
    let (c, m, k) = shadow_execute_counters();
    let avg_us = CHECK_US.load(Ordering::Relaxed).checked_div(c).unwrap_or(0);
    let ab = APPLY_DATA_BLOCKS.load(Ordering::Relaxed);
    let ad_avg_us = APPLY_DATA_US
        .load(Ordering::Relaxed)
        .checked_div(ab)
        .unwrap_or(0);
    // Report limiter-suppressed lines even when mismatches have stopped.
    let pending = limiter()
        .lock()
        .map(|mut l| l.take_suppressed())
        .unwrap_or(0);
    if pending > 0 {
        SUPPRESSED_REPORTED.fetch_add(pending, Ordering::Relaxed);
        tracing::warn!(
            "{MISMATCH_LOG_TOKEN} kind=rate_limited suppressed_lines={pending} (pending at progress tick)"
        );
    }
    tracing::info!(
        "shadow_execute_progress state_checked_blocks={c} state_mismatched_blocks={m} state_skipped_unsupported_store={k} state_avg_check_us={avg_us} apply_data_compared_blocks={ab} apply_data_compared_txns={} apply_data_mismatched_blocks={} apply_data_mismatched_txns={} apply_data_avg_compare_us={ad_avg_us} apply_data_mismatch_diffs={} apply_data_mismatch_lines_suppressed={} state_mismatch_lines_suppressed={} limiter_suppressed_reported={} last_round={last_round}",
        APPLY_DATA_TXNS.load(Ordering::Relaxed),
        APPLY_DATA_MISMATCH_BLOCKS.load(Ordering::Relaxed),
        APPLY_DATA_MISMATCH_TXNS.load(Ordering::Relaxed),
        APPLY_DATA_MISMATCH_LINES.load(Ordering::Relaxed),
        APPLY_DATA_SUPPRESSED.load(Ordering::Relaxed),
        STATE_SUPPRESSED.load(Ordering::Relaxed),
        SUPPRESSED_REPORTED.load(Ordering::Relaxed),
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

/// Sampling period from [`SHADOW_SAMPLE_ENV`] (read once; invalid/zero -> 1).
fn sample_every() -> u64 {
    static N: OnceLock<u64> = OnceLock::new();
    *N.get_or_init(|| {
        std::env::var(SHADOW_SAMPLE_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n >= 1)
            .unwrap_or(1)
    })
}

/// Whether the `seen`-th (0-based) eligible block is sampled for period `every`.
fn sample_hit(seen: u64, every: u64) -> bool {
    every <= 1 || seen.is_multiple_of(every)
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Scratch-invariant violations seen since process start (debug builds only
/// evaluate the checks; always 0 in release).
static INVARIANT_VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// Number of scratch-invariant violations logged since process start.
pub fn shadow_execute_invariant_violations() -> u64 {
    INVARIANT_VIOLATIONS.load(Ordering::Relaxed)
}

#[cfg(test)]
thread_local! {
    /// Test strict mode (default on): a violation panics so leaky-stub tests
    /// can assert it. Non-test builds never panic.
    static TEST_STRICT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Record an invariant violation: error log + counter, never a panic outside
/// test strict mode (the diagnostic must not take block sync down).
fn invariant_violation(msg: &str) {
    INVARIANT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    tracing::error!("shadow_execute_invariant_violation: {msg}");
    #[cfg(test)]
    if TEST_STRICT.with(|s| s.get()) {
        panic!("{msg}");
    }
}

/// Debug-only guard (issue #1721) that a scratch Execute pass is fully
/// invisible: it leaves the persistent tracker rows alone (the "KEEP IN SYNC"
/// early return in `apply_block_impl_ex`) and, once rolled back, leaves the
/// tracker/lease/chain-field/trie-log state exactly as it found it. Compiled
/// to a no-op capture in release builds (`cfg!(debug_assertions)`).
struct ScratchInvariant {
    tracker: Option<u64>,
    full: Option<u64>,
    chain: Option<ChainFields>,
}

impl ScratchInvariant {
    fn capture<L: LedgerStore>(store: &L, chain: &ChainFields) -> Self {
        if !cfg!(debug_assertions) {
            return Self {
                tracker: None,
                full: None,
                chain: None,
            };
        }
        Self {
            tracker: store.tracker_rows_fingerprint(),
            full: store.scratch_invariant_fingerprint(),
            chain: Some(chain.clone()),
        }
    }

    /// After the scratch Execute pass, before any rollback: the pass must not
    /// have written a persistent tracker row.
    fn check_scratch_pass<L: LedgerStore>(&self, store: &L) {
        if self.tracker.is_some() && self.tracker != store.tracker_rows_fingerprint() {
            invariant_violation(
                "shadow-execute: scratch pass changed the newest per-round tracker rows (block store/txtail/online-params/voters; accounthashes not covered); the real apply may have gained a tracker write above the scratch early return in apply_block_impl_ex",
            );
        }
    }

    /// After every rollback step: nothing of the scratch pass may remain.
    fn check_rolled_back<L: LedgerStore>(&self, store: &L) {
        if (self.full.is_some() && self.full != store.scratch_invariant_fingerprint())
            || (self.tracker.is_some() && self.tracker != store.tracker_rows_fingerprint())
        {
            invariant_violation(
                "shadow-execute: scratch rollback left lease/trie-log/totals state or the newest tracker rows changed",
            );
        }
        if let Some(chain) = &self.chain {
            if *chain != ChainFields::capture(store) {
                invariant_violation("shadow-execute: scratch rollback left chain fields changed");
            }
        }
    }
}

/// Test-only leaks injected between the scratch pass and the invariant
/// checks: 4 = persistent tracker row written by the scratch pass, 5 = state
/// left behind after the rollback.
#[cfg(test)]
fn inject_leak<L: LedgerStore>(store: &mut L, phase: u8) {
    if test_hook() != phase {
        return;
    }
    match phase {
        4 => {
            let _ = store.put_txtail(9_999, b"leak");
        }
        _ => store.record_lease(&Address([0xEE; 32]), &[0xEE; 32], 9),
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

/// Fault injection for the proposer assembly tests. Compiled only into test
/// builds and into builds that enable the `test-hooks` feature (the
/// `algod-rust` dev-dependency does); never into a production binary.
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT: Cell<u64> = const { Cell::new(0) };
        static FAIL_OVER: Cell<Option<usize>> = const { Cell::new(None) };
        static CALLS: Cell<u64> = const { Cell::new(0) };
    }

    /// The next `n` [`super::scratch_execute_payset`] calls on this thread
    /// fail with a transient, unattributable error.
    pub fn inject_scratch_failures(n: u64) {
        FAIL_NEXT.with(|c| c.set(n));
    }

    /// Every call on this thread whose payset has more than `n` transactions
    /// fails with an unattributable error (`None` clears it).
    pub fn inject_failure_over_payset_len(n: Option<usize>) {
        FAIL_OVER.with(|c| c.set(n));
    }

    /// Number of scratch passes run on this thread since the last reset.
    pub fn scratch_calls() -> u64 {
        CALLS.with(|c| c.get())
    }

    /// Reset the per-thread pass counter.
    pub fn reset_scratch_calls() {
        CALLS.with(|c| c.set(0));
    }

    pub(super) fn should_fail(payset_len: usize) -> bool {
        CALLS.with(|c| c.set(c.get() + 1));
        let next = FAIL_NEXT.with(|c| {
            let n = c.get();
            c.set(n.saturating_sub(1));
            n > 0
        });
        next || FAIL_OVER.with(|c| c.get()).is_some_and(|n| payset_len > n)
    }
}

/// Result of [`scratch_execute_payset`].
#[derive(Debug)]
pub struct ScratchPayset {
    /// Per-transaction apply data in payset order.
    pub apply_data: Vec<ApplyData>,
    /// The transaction counter after every top-level and inner transaction
    /// (go `block.TxnCounter`).
    pub final_txn_counter: u64,
    /// The `StateProofNextRound` after the payset's state proof transactions
    /// (go `cow.GetStateProofNextRound()`; `0` without state proofs). The
    /// proposed header must carry this value (issue #1791).
    pub final_state_proof_next: u64,
}

/// Why [`scratch_execute_payset`] did not produce a result.
#[derive(Debug)]
pub enum ScratchFailure {
    /// The payset transaction at `index` cannot be applied.
    Txn { index: usize, error: AlgoError },
    /// The evaluation failed for a reason no transaction owns (stale round,
    /// end-of-block failure, panic).
    Other(AlgoError),
    /// The store cannot roll a scratch apply back (a lease journal is
    /// already open): nothing was evaluated.
    Unsupported,
}

/// Evaluate `block` (the proposer's candidate: next-round header + payset,
/// stripped form) in [`ApplyMode::Execute`] on a rolled-back scratch apply of
/// `store` and return every transaction's `ApplyData` and the final
/// transaction counter, or the payset index that failed (issue #1776).
///
/// This is the authoritative check the block proposer runs on its assembled
/// payset (go's `BlockEvaluator.GenerateBlock` only ever emits what its
/// `TransactionGroup` applied). Nothing is persisted: the SAVEPOINT, the
/// lease journal and the chain fields are restored before returning.
pub fn scratch_execute_payset<L: LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<ScratchPayset, ScratchFailure> {
    #[cfg(any(test, feature = "test-hooks"))]
    if test_hooks::should_fail(block.payset.len()) {
        return Err(ScratchFailure::Other(AlgoError::Ledger {
            message: "injected transient scratch failure".into(),
        }));
    }
    let Some(aux) = scratch_state(store) else {
        return Err(ScratchFailure::Unsupported);
    };
    let chain = ChainFields::capture(store);
    let invariant = ScratchInvariant::capture(store, &chain);
    let sp = store.snapshot(&[]);
    let mut ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    let mut probe = crate::apply::ExecProbe::default();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::apply::apply_block_impl_probe(
            store,
            block,
            ApplyMode::Execute,
            false,
            None,
            None,
            Some(&mut ad),
            None,
            true,
            Some(&mut probe),
        )
    }));
    invariant.check_scratch_pass(store);
    store.restore_snapshot(sp);
    chain.restore(store);
    store.restore_scratch_state(aux);
    invariant.check_rolled_back(store);
    match res {
        Err(_) => Err(ScratchFailure::Other(AlgoError::Ledger {
            message: "scratch Execute evaluation panicked".into(),
        })),
        Ok(Err(error)) => match probe.failed_txn_index {
            Some(index) if index < block.payset.len() => Err(ScratchFailure::Txn { index, error }),
            _ => Err(ScratchFailure::Other(error)),
        },
        Ok(Ok(())) => Ok(ScratchPayset {
            apply_data: ad,
            final_txn_counter: probe.final_txn_counter,
            final_state_proof_next: probe.final_state_proof_next,
        }),
    }
}

/// Apply `block` for real in [`ApplyMode::Replay`] (exactly what the follow
/// path does for a block without app calls) after shadow-evaluating it in
/// [`ApplyMode::Execute`] on a rolled-back scratch apply, and return the
/// differences. An error is only ever the real Replay apply's own.
pub fn shadow_check_replay_block<L: LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<ShadowReport, AlgoError> {
    let Some(aux) = scratch_state(store) else {
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
    let invariant = ScratchInvariant::capture(store, &chain);
    let sp = store.snapshot(&[]);
    let mut exec_ad: Vec<ApplyData> = Vec::with_capacity(block.payset.len());
    let mut exec_kv = KvModsMap::new();
    let scratch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut rec = RecordingStore::new(store);
        let res = run_scratch_execute(&mut rec, block, &mut exec_ad, &mut exec_kv);
        let view = read_exec_view(&rec, &rec.touches);
        (res, view, std::mem::take(&mut rec.touches))
    }));
    // A panic inside the diagnostic evaluation must not take the node down
    // (or leave scratch state behind): report it as an execute error.
    let (exec_res, exec_view, exec_touches) = scratch.unwrap_or_else(|_| {
        (
            Err(AlgoError::Ledger {
                message: "shadow Execute evaluation panicked".into(),
            }),
            ExecView::default(),
            ResourceTouches::default(),
        )
    });
    #[cfg(test)]
    inject_leak(store, 4);
    invariant.check_scratch_pass(store);
    store.restore_snapshot(sp);
    chain.restore(store);
    store.restore_scratch_state(aux);
    #[cfg(test)]
    inject_leak(store, 5);
    invariant.check_rolled_back(store);

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
    static SEEN: AtomicU64 = AtomicU64::new(0);
    if !sample_hit(SEEN.fetch_add(1, Ordering::Relaxed), sample_every()) {
        return apply_block_impl_ex(
            store,
            block,
            ApplyMode::Replay,
            false,
            None,
            None,
            None,
            None,
            false,
        );
    }
    let started = std::time::Instant::now();
    let report = shadow_check_replay_block(store, block)?;
    let elapsed_us = started.elapsed().as_micros() as u64;
    if !report.checked {
        let skipped = SKIPPED.fetch_add(1, Ordering::Relaxed) + 1;
        // Never stay silent: a soak with the flag on must not look clean
        // while verifying nothing.
        if !SKIP_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "shadow_execute_unsupported_store: this store cannot roll back a scratch apply; blocks are applied without shadow verification (counted as skipped_unsupported)"
            );
        }
        if skipped == 1 || skipped.is_multiple_of(PROGRESS_EVERY) {
            log_progress(block.round.0);
        }
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
        // A systematic mismatch repeats on every block: dedupe by the first
        // diff's (kind, field pattern) with the shared per-window budget.
        let pat = format!(
            "state:{}:{}",
            report.diffs[0].kind,
            field_pattern(&report.diffs[0].field)
        );
        if admit_line(&pat) {
            tracing::warn!(
                round = block.round.0,
                diffs = report.diffs.len(),
                elapsed_us,
                "{MISMATCH_LOG_TOKEN} round={} diffs={} [{}]",
                block.round.0,
                report.diffs.len(),
                first.join("; ")
            );
        } else {
            STATE_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if checked == 1 || checked.is_multiple_of(PROGRESS_EVERY) {
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

/// One diff per `Transaction` field whose typed value differs, named
/// `<path>.txn.<field>` (struct declaration order). The field list is checked
/// exhaustively at compile time: the destructuring pattern below names every
/// `Transaction` field with no `..`, so adding a field to the struct fails to
/// compile here until it is added to the list.
fn txn_field_diffs(path: &str, rec: &Transaction, comp: &Transaction, out: &mut Vec<FieldDiff>) {
    macro_rules! typed_txn_diffs {
        ([$($f:ident),* $(,)?]) => {
            let Transaction { $($f: _),* } = rec;
            $(
                if rec.$f != comp.$f {
                    out.push((
                        format!("{path}.txn.{}", stringify!($f)),
                        clip(format!("{:?}", rec.$f)),
                        clip(format!("{:?}", comp.$f)),
                    ));
                }
            )*
        };
    }
    typed_txn_diffs!([
        txn_type,
        sender,
        fee,
        first_valid,
        last_valid,
        note,
        genesis_id,
        genesis_hash,
        group,
        lease,
        rekey_to,
        amount,
        receiver,
        close_remainder_to,
        xaid,
        asset_amount,
        asset_sender,
        asset_receiver,
        asset_close_to,
        config_asset,
        asset_params,
        freeze_asset,
        freeze_account,
        asset_frozen,
        application_id,
        on_completion,
        approval_program,
        clear_state_program,
        app_arguments,
        accounts,
        foreign_apps,
        foreign_assets,
        boxes,
        global_state_schema,
        local_state_schema,
        extra_program_pages,
        vote_pk,
        selection_pk,
        state_proof_pk,
        vote_first,
        vote_last,
        vote_key_dilution,
        non_participation,
        state_proof_type,
        state_proof,
        state_proof_message,
        heartbeat,
        access,
        reject_version
    ]);
}

/// Fallback entry `<path>.txn` for inner transactions whose canonical
/// encodings differ while every typed field compares equal: encoded lengths
/// and the first differing byte offset.
fn encoding_only_diff(path: &str, enc_rec: &[u8], enc_comp: &[u8], out: &mut Vec<FieldDiff>) {
    let first = enc_rec
        .iter()
        .zip(enc_comp)
        .position(|(a, b)| a != b)
        .unwrap_or(enc_rec.len().min(enc_comp.len()));
    out.push((
        format!("{path}.txn"),
        format!(
            "encoded {} bytes, first difference at byte {first}",
            enc_rec.len()
        ),
        format!(
            "encoded {} bytes, first difference at byte {first}",
            enc_comp.len()
        ),
    ));
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
            let before = out.len();
            txn_field_diffs(&p, &a.txn, &b.txn, out);
            if out.len() == before {
                // Canonical encodings differ yet no typed field does: never
                // record the mismatch with zero entries.
                encoding_only_diff(&p, &ea, &eb, out);
            }
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

/// Collapse the variable parts of a mismatch field path (state keys, wire
/// indices, inner-txn positions, log counts) so occurrences of the same root
/// cause share one pattern, e.g. `eval_delta.inner_txns[N].eval_delta.global_delta[K]`.
pub fn field_pattern(field: &str) -> String {
    // Box diffs name the key as `kv_key=<hex>`: unique per key, so collapse it
    // or every box would bypass the limiter as a "new pattern".
    if let Some(i) = field.find("kv_key=") {
        return format!("{}kv_key=[K]", &field[..i]);
    }
    let mut out = String::new();
    let mut rest = field;
    while let Some(i) = rest.find('[') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let Some(j) = after.find(']') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let inner = &after[..j];
        out.push_str(if inner.is_empty() {
            "[]"
        } else if inner.len() <= 3 && inner.chars().all(|c| c.is_ascii_digit()) {
            "[N]"
        } else {
            "[K]"
        });
        rest = &after[j + 1..];
        if rest.starts_with(" (") {
            if let Some(k) = rest.find(')') {
                rest = &rest[k + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Keeps a systematic mismatch from flooding the log: the first occurrence of
/// every distinct [`field_pattern`] is always emitted (so every kind stays
/// visible); repeats share a per-window line budget.
#[derive(Debug)]
pub struct MismatchLimiter {
    max_per_window: u32,
    window_secs: u64,
    window_start: u64,
    emitted: u32,
    suppressed: u64,
    seen: std::collections::HashSet<String>,
    counts: HashMap<String, u64>,
}

impl MismatchLimiter {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            window_start: 0,
            emitted: 0,
            suppressed: 0,
            seen: Default::default(),
            counts: Default::default(),
        }
    }

    /// Returns `(emit, suppressed_in_previous_window)`; the second value is
    /// non-zero once, when a window rolls over, so the caller can log it.
    pub fn admit(&mut self, pattern: &str, now_secs: u64) -> (bool, u64) {
        let mut flushed = 0;
        if now_secs >= self.window_start + self.window_secs {
            flushed = self.suppressed;
            self.suppressed = 0;
            self.emitted = 0;
            self.window_start = now_secs;
        }
        if self.counts.len() < MAX_TRACKED_PATTERNS || self.counts.contains_key(pattern) {
            *self.counts.entry(pattern.to_string()).or_insert(0) += 1;
        }
        let new = !self.seen.contains(pattern) && self.seen.len() < MAX_TRACKED_PATTERNS;
        if new {
            self.seen.insert(pattern.to_string());
        }
        if new || self.emitted < self.max_per_window {
            self.emitted += 1;
            (true, flushed)
        } else {
            self.suppressed += 1;
            (false, flushed)
        }
    }

    /// Drain the suppressed-line count of the current window (for a summary
    /// emitted outside a window rollover).
    pub fn take_suppressed(&mut self) -> u64 {
        std::mem::take(&mut self.suppressed)
    }

    /// Most frequent patterns, for the periodic summary line.
    pub fn top_patterns(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

fn limiter() -> &'static std::sync::Mutex<MismatchLimiter> {
    static L: OnceLock<std::sync::Mutex<MismatchLimiter>> = OnceLock::new();
    L.get_or_init(|| {
        std::sync::Mutex::new(MismatchLimiter::new(
            MAX_MISMATCH_LINES_PER_WINDOW,
            MISMATCH_WINDOW_SECS,
        ))
    })
}

/// Admit one mismatch line through the shared limiter, logging a rollover
/// summary of previously suppressed lines.
fn admit_line(pattern: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (emit, flushed) = match limiter().lock() {
        Ok(mut l) => l.admit(pattern, now),
        Err(_) => (true, 0),
    };
    if flushed > 0 {
        SUPPRESSED_REPORTED.fetch_add(flushed, Ordering::Relaxed);
        tracing::warn!("{MISMATCH_LOG_TOKEN} kind=rate_limited suppressed_lines={flushed}");
    }
    emit
}

fn log_apply_data_diffs(round: u64, diffs: &[ShadowDiff]) {
    // One line per (transaction, field pattern) with an occurrence count.
    let mut groups: Vec<(Option<usize>, String, usize, usize)> = Vec::new();
    for (i, d) in diffs.iter().enumerate() {
        let pat = field_pattern(&d.field);
        match groups.iter_mut().find(|g| g.0 == d.txn_index && g.1 == pat) {
            Some(g) => g.2 += 1,
            None => groups.push((d.txn_index, pat, 1, i)),
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for (txn, pat, count, idx) in groups {
        let (emit, flushed) = match limiter().lock() {
            Ok(mut l) => l.admit(&pat, now),
            Err(_) => (true, 0),
        };
        if flushed > 0 {
            tracing::warn!(
                "{MISMATCH_LOG_TOKEN} kind=apply_data field=<rate-limited> suppressed_lines={flushed}"
            );
        }
        if !emit {
            APPLY_DATA_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let d = &diffs[idx];
        tracing::warn!(
            "{MISMATCH_LOG_TOKEN} kind=apply_data round={round} txn={} field={} recorded={} computed={} pattern={pat} count={count}",
            txn.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            d.field,
            d.replay,
            d.execute
        );
    }
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
        APPLY_DATA_MISMATCH_LINES.fetch_add(diffs.len() as u64, Ordering::Relaxed);
        log_apply_data_diffs(block.round.0, &diffs);
    }
    if n == 1 || n.is_multiple_of(PROGRESS_EVERY) {
        log_progress(block.round.0);
    }
    if n.is_multiple_of(PROGRESS_EVERY * 10) {
        if let Ok(l) = limiter().lock() {
            let top: Vec<String> = l
                .top_patterns(12)
                .into_iter()
                .map(|(p, c)| format!("{p}={c}"))
                .collect();
            tracing::info!("shadow_execute_patterns top=[{}]", top.join("; "));
        }
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
        assert_eq!(d[0].field, "eval_delta.inner_txns[0].txn.amount");
        assert!(d[0].replay == "10" && d[0].execute == "11", "{:?}", d[0]);
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

    /// Synthetic inner transaction differing in several typed fields, used by
    /// the golden mismatch-output test.
    fn golden_inner(variant: bool) -> Value {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "pay".into();
        stx.txn.sender = SENDER;
        stx.txn.receiver = RECEIVER;
        stx.txn.amount = if variant { 11 } else { 10 };
        stx.txn.fee = if variant { 0 } else { 1_000 };
        stx.txn.group = if variant { [0u8; 32] } else { [7u8; 32] };
        stx.txn.rekey_to = if variant { Some(FEE_SINK) } else { None };
        stx.txn.genesis_id = if variant {
            "b-v1".into()
        } else {
            String::new()
        };
        let bytes = rmp_serde::to_vec_named(&stx).unwrap();
        rmpv::decode::read_value(&mut &bytes[..]).unwrap()
    }

    #[test]
    fn inner_txn_mismatch_output_golden() {
        let itx = |v: bool| {
            dt(vec![(
                Value::from("itx"),
                Value::Array(vec![golden_inner(v)]),
            )])
        };
        let d = cmp_one(
            |s| s.eval_delta = itx(false),
            ApplyData {
                eval_delta: itx(true),
                ..Default::default()
            },
        );
        let got: Vec<(String, String, String)> = d
            .iter()
            .map(|x| (x.field.clone(), x.replay.clone(), x.execute.clone()))
            .collect();
        let s = |x: &str| x.to_string();
        let want: Vec<(String, String, String)> = vec![
            (s("eval_delta.inner_txns[0].txn.fee"), s("1000"), s("0")),
            (
                s("eval_delta.inner_txns[0].txn.genesis_id"),
                s("\"\""),
                s("\"b-v1\""),
            ),
            (
                s("eval_delta.inner_txns[0].txn.group"),
                clip(format!("{:?}", [7u8; 32])),
                clip(format!("{:?}", [0u8; 32])),
            ),
            (
                s("eval_delta.inner_txns[0].txn.rekey_to"),
                s("None"),
                clip(format!("{:?}", Some(FEE_SINK))),
            ),
            (s("eval_delta.inner_txns[0].txn.amount"), s("10"), s("11")),
        ];
        assert_eq!(got, want);
        // Every field name still buckets to a stable limiter pattern.
        for (f, _, _) in &got {
            assert!(
                field_pattern(f).starts_with("eval_delta.inner_txns[N].txn."),
                "{f}"
            );
        }
    }

    #[test]
    fn inner_group_id_difference_names_the_txn_field() {
        let inner = |group: [u8; 32]| {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = "pay".into();
            stx.txn.sender = SENDER;
            stx.txn.group = group;
            let bytes = rmp_serde::to_vec_named(&stx).unwrap();
            rmpv::decode::read_value(&mut &bytes[..]).unwrap()
        };
        let itx = |g: [u8; 32]| dt(vec![(Value::from("itx"), Value::Array(vec![inner(g)]))]);
        let d = cmp_one(
            |s| s.eval_delta = itx([7u8; 32]),
            ApplyData {
                eval_delta: itx([0u8; 32]),
                ..Default::default()
            },
        );
        assert_eq!(d.len(), 1, "{d:#?}");
        assert_eq!(d[0].field, "eval_delta.inner_txns[0].txn.group");
    }

    #[test]
    fn field_patterns_collapse_keys_indices_and_counts() {
        assert_eq!(
            field_pattern("eval_delta.inner_txns[3].eval_delta.global_delta[6b6579]"),
            "eval_delta.inner_txns[N].eval_delta.global_delta[K]"
        );
        assert_eq!(
            field_pattern("eval_delta.global_delta[]"),
            "eval_delta.global_delta[]"
        );
        assert_eq!(
            field_pattern("eval_delta.local_delta[1][6362]"),
            "eval_delta.local_delta[N][K]"
        );
        assert_eq!(
            field_pattern("eval_delta.logs[2] (counts 3/4)"),
            "eval_delta.logs[N]"
        );
        assert_eq!(field_pattern("closing_amount"), "closing_amount");
        assert_eq!(
            field_pattern("kv_key=0102ab..."),
            field_pattern("kv_key=ffee")
        );
        assert_eq!(field_pattern("kv_key=0102ab"), "kv_key=[K]");
    }

    #[test]
    fn limiter_always_emits_a_new_pattern_and_rate_limits_repeats() {
        let mut l = MismatchLimiter::new(2, 60);
        assert_eq!(l.admit("a", 100), (true, 0));
        assert_eq!(l.admit("a", 101), (true, 0));
        assert_eq!(l.admit("a", 102), (false, 0));
        // A different, never-seen pattern is emitted even over budget.
        assert_eq!(l.admit("b", 103), (true, 0));
        assert_eq!(l.admit("a", 104), (false, 0));
        // Window rollover reports what was suppressed and refills the budget.
        assert_eq!(l.admit("a", 170), (true, 2));
        assert_eq!(l.top_patterns(1)[0], ("a".to_string(), 5));
    }

    #[test]
    fn sampling_period_selects_every_nth() {
        assert!((0..5).all(|i| sample_hit(i, 1)));
        assert!((0..5).all(|i| sample_hit(i, 0)));
        let hits: Vec<u64> = (0..10).filter(|i| sample_hit(*i, 4)).collect();
        assert_eq!(hits, vec![0, 4, 8]);
    }

    #[test]
    fn limiter_dedupes_state_pattern_repeats() {
        let mut l = MismatchLimiter::new(2, 60);
        assert!(l.admit("state:account:micro_algos", 100).0); // new
        assert!(l.admit("state:account:micro_algos", 100).0); // budget (new line counts)
        assert!(!l.admit("state:account:micro_algos", 100).0); // suppressed
        assert!(l.admit("state:box:kv_key=[K]", 100).0); // new pattern always passes
        let (emit, flushed) = l.admit("state:account:micro_algos", 161);
        assert!(emit);
        assert_eq!(flushed, 1);
    }

    fn with_hook<R>(h: u8, f: impl FnOnce() -> R) -> R {
        TEST_HOOK.with(|c| c.set(h));
        let r = f();
        TEST_HOOK.with(|c| c.set(0));
        r
    }

    fn leased_pay(lease: u8) -> SignedTransaction {
        let mut stx = pay();
        stx.txn.lease = [lease; 32];
        stx
    }

    #[test]
    fn scratch_leases_do_not_make_the_real_apply_reject_duplicates() {
        let mut l = ledger();
        let b = block(vec![leased_pay(5)]);
        let r = shadow_check_replay_block(&mut l, &b).unwrap();
        assert!(r.checked && r.diffs.is_empty(), "{:?}", r.diffs);
        // The lease is recorded by the real apply: it must now be active.
        assert!(l.check_lease(&SENDER, &[5u8; 32], 1).is_err());
    }

    #[test]
    fn failed_scratch_execute_is_reported_and_real_apply_still_commits() {
        let mut l = ledger();
        let b = block(vec![leased_pay(6)]);
        let r = with_hook(2, || shadow_check_replay_block(&mut l, &b)).unwrap();
        assert_eq!(r.diffs.len(), 1);
        assert_eq!(r.diffs[0].kind, "execute_error");
        assert_eq!(l.current_round(), Round(1));
        assert_eq!(l.txn_counter(), 1);
        assert!(l.get_account(&RECEIVER).is_some());
    }

    #[test]
    fn panicking_scratch_is_contained_and_node_continues() {
        let mut l = ledger();
        let b = block(vec![leased_pay(7)]);
        let r = with_hook(3, || shadow_check_replay_block(&mut l, &b)).unwrap();
        assert_eq!(r.diffs.len(), 1);
        assert_eq!(r.diffs[0].kind, "execute_error");
        assert!(r.diffs[0].execute.contains("panicked"));
        assert_eq!(l.current_round(), Round(1));
        // A following block applies normally on the same store.
        let mut b2 = block(vec![pay()]);
        b2.round = Round(2);
        b2.txn_counter = 2;
        let r2 = shadow_check_replay_block(&mut l, &b2).unwrap();
        assert!(r2.checked && r2.diffs.is_empty());
        assert_eq!(l.current_round(), Round(2));
    }

    #[test]
    fn unsupported_store_is_applied_counted_and_not_silent() {
        let mut l = ledger();
        let before = shadow_execute_counters().2;
        let b = block(vec![pay()]);
        with_hook(1, || apply_replay_block_with_shadow(&mut l, &b)).unwrap();
        assert_eq!(l.current_round(), Round(1));
        assert!(shadow_execute_counters().2 > before);
        assert!(SKIP_WARNED.load(Ordering::Relaxed));
        let r = with_hook(1, || {
            shadow_check_replay_block(&mut ledger(), &block(vec![pay()]))
        })
        .unwrap();
        assert!(!r.checked);
    }

    // ---- scratch rollback invariants (issue #1721) ----

    fn app_create_stx() -> SignedTransaction {
        let approval = algo_avm::assembler::assemble_string(
            "#pragma version 8
byte \"k\"
int 7
app_global_put
int 1
return
",
        )
        .unwrap()
        .program;
        let clear = algo_avm::assembler::assemble_string(
            "#pragma version 8
int 1
return
",
        )
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
        create.apply_data_application_id = 1;
        create
    }

    /// Everything observable about a ledger after a block, for exact
    /// scratch+real vs real-only comparison.
    fn ledger_state(l: &SqliteLedger) -> String {
        let accts: Vec<_> = [SENDER, RECEIVER, FEE_SINK, POOL]
            .iter()
            .map(|a| l.get_account(a))
            .collect();
        format!(
            "{accts:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            ChainFields::capture(l),
            l.get_app_params(1),
            l.get_asset_params(1),
            l.scratch_invariant_fingerprint(),
            l.tracker_rows_fingerprint(),
            l.lease_table().clone() == crate::lease::LeaseTable::new(),
            l.check_lease(&SENDER, &[5u8; 32], 1).is_err(),
            l.check_lease(&SENDER, &[6u8; 32], 1).is_err(),
            l.txn_counter(),
        )
    }

    fn plain_replay(l: &mut SqliteLedger, b: &Block) {
        apply_block_impl_ex(
            l,
            b,
            ApplyMode::Replay,
            false,
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();
    }

    #[test]
    fn scratch_plus_real_apply_equals_real_apply_alone() {
        let mut rewards = block(vec![pay()]);
        rewards.rewards_level = 77;
        rewards.rewards_rate = 1_000;
        rewards.rewards_residue = 5;
        rewards.rewards_recalculation_round = Round(5);
        let blocks = [
            ("pay-only", block(vec![pay()])),
            ("app-call", block(vec![app_create_stx()])),
            ("lease-bearing", block(vec![leased_pay(5)])),
            ("rewards", rewards),
            ("asset-create", block(vec![acfg_create(1)])),
        ];
        for (name, b) in blocks {
            let mut shadowed = ledger();
            let mut plain = ledger();
            for l in [&mut shadowed, &mut plain] {
                // The rewards case withdraws from the pool.
                l.set_account(
                    &POOL,
                    AccountData {
                        micro_algos: 1_000_000_000,
                        ..Default::default()
                    },
                );
            }
            let report = shadow_check_replay_block(&mut shadowed, &b).unwrap();
            assert!(report.checked, "{name}");
            plain_replay(&mut plain, &b);
            assert_eq!(ledger_state(&shadowed), ledger_state(&plain), "{name}");
            assert_eq!(
                shadowed.lease_table(),
                plain.lease_table(),
                "{name}: lease table"
            );
        }
    }

    #[test]
    fn real_apply_changes_tracker_rows_but_scratch_pass_does_not() {
        // Non-vacuity: the fingerprint really moves when the real apply runs,
        // so "unchanged across the scratch pass" is a meaningful assertion.
        let mut l = ledger();
        let b = block(vec![pay()]);
        let before = l.tracker_rows_fingerprint();
        assert!(before.is_some(), "sqlite must support the fingerprint");
        plain_replay(&mut l, &b);
        assert_ne!(before, l.tracker_rows_fingerprint());
        // A scratch-checked block runs both checks (debug asserts are on in
        // test builds) without tripping them.
        shadow_check_replay_block(&mut ledger(), &b).unwrap();
    }

    #[test]
    #[should_panic(expected = "scratch pass changed the newest per-round tracker rows")]
    fn tracker_write_in_scratch_pass_trips_the_invariant() {
        let b = block(vec![pay()]);
        let _ = with_hook(4, || shadow_check_replay_block(&mut ledger(), &b));
    }

    #[test]
    fn invariant_violation_is_counted_and_not_fatal_outside_strict_mode() {
        let before = shadow_execute_invariant_violations();
        TEST_STRICT.with(|s| s.set(false));
        let b = block(vec![pay()]);
        let mut l = ledger();
        let r = with_hook(5, || shadow_check_replay_block(&mut l, &b));
        TEST_STRICT.with(|s| s.set(true));
        let r = r.expect("a violation must not fail block application");
        assert!(r.checked);
        assert!(shadow_execute_invariant_violations() > before);
        assert_eq!(l.current_round(), Round(1), "real apply still ran");
    }

    #[test]
    fn encoding_only_difference_still_yields_an_entry() {
        let mut out: Vec<FieldDiff> = Vec::new();
        encoding_only_diff(
            "eval_delta.inner_txns[0]",
            &[1, 2, 3, 4],
            &[1, 2, 9],
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "eval_delta.inner_txns[0].txn");
        assert_eq!(out[0].1, "encoded 4 bytes, first difference at byte 2");
        assert_eq!(out[0].2, "encoded 3 bytes, first difference at byte 2");
        assert_eq!(field_pattern(&out[0].0), "eval_delta.inner_txns[N].txn");
        // Prefix-only difference: first differing offset is the shorter length.
        let mut out = Vec::new();
        encoding_only_diff("p", &[1, 2], &[1, 2, 3], &mut out);
        assert_eq!(out[0].1, "encoded 2 bytes, first difference at byte 2");
    }

    #[test]
    #[should_panic(
        expected = "scratch rollback left lease/trie-log/totals state or the newest tracker rows changed"
    )]
    fn leak_surviving_rollback_trips_the_invariant() {
        let b = block(vec![pay()]);
        let _ = with_hook(5, || shadow_check_replay_block(&mut ledger(), &b));
    }

    #[test]
    fn limiter_take_suppressed_reports_pending_after_mismatches_stop() {
        let mut l = MismatchLimiter::new(1, 60);
        assert!(l.admit("p", 10).0);
        assert!(!l.admit("p", 10).0);
        assert!(!l.admit("p", 10).0);
        assert_eq!(l.take_suppressed(), 2);
        assert_eq!(l.take_suppressed(), 0);
    }
}
