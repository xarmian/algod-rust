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

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use algo_avm::eval::{
    run_approval_program, run_approval_program_with_tracer, run_clear_state_program,
    run_clear_state_program_with_tracer,
};
use algo_avm::group::GroupBudget;
use algo_avm::tracer::EvalTracer;
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};
use algo_types::{
    AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord,
    Block, Round, SignedTransaction, TealValue,
};
use sha2::{Digest, Sha512_256};

use crate::avm_context::LedgerAvmContext;
use crate::eval_compare::{
    compare_eval_delta, EvalDeltaMismatchDetail, EvalDeltaStats, MismatchCategory,
};
use crate::eval_delta::{apply_eval_delta, parse_eval_delta};
use crate::rewards::apply_rewards;

/// Box-modification deltas accumulated during a block apply, keyed by the
/// raw KV-store key bytes (`make_box_key`). See [`apply_block_with_delta_mode`]
/// and [`crate::state_delta::StateDelta::kv_mods`] (issue #570).
pub type KvModsMap = std::collections::HashMap<Vec<u8>, crate::state_delta::KvValueDelta>;

/// Results of applying a transaction, capturing all side-effect data.
///
/// Mirrors go-algorand's `transactions.ApplyData`. Returned from
/// `apply_transaction_inner` so callers (especially the simulation engine)
/// can capture execution results without re-reading state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplyData {
    /// Closing amount for payment transactions.
    pub closing_amount: u64,
    /// Closing amount for asset transfer transactions.
    pub asset_closing_amount: u64,
    /// Rewards applied to sender.
    pub sender_rewards: u64,
    /// Rewards applied to receiver.
    pub receiver_rewards: u64,
    /// Rewards applied to close-to address.
    pub close_rewards: u64,
    /// Created/configured asset ID (from acfg creates).
    pub config_asset: u64,
    /// Created application ID (from appl creates).
    pub application_id: u64,
    /// Eval delta (opaque msgpack, contains state changes, logs, inner txns).
    pub eval_delta: Option<rmpv::Value>,
}

/// Determines whether the ledger replays recorded block data or actively
/// executes AVM programs to produce results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Use recorded EvalDelta from block data (backward compatible).
    Replay,
    /// Run AVM programs to produce results.
    Execute,
}

/// Context derived from the block header, passed to transaction application.
pub struct ApplyContext {
    pub rewards_level: u64,
    pub fee_sink: Address,
    pub round: u64,
    /// Controls whether EvalDeltas come from block data or AVM execution.
    pub mode: ApplyMode,
    /// Whether to run end-of-block participation validation checks.
    ///
    /// Mirrors go-algorand's `eval.validate`. When true, validates that
    /// expired/absent accounts in the block header are correct (duplicate
    /// checks, vote key checks, etc.). When false (replay/catchup), only
    /// the apply-side state transitions run.
    pub validate: bool,
    /// Latest confirmed timestamp (for AVM context).
    pub latest_timestamp: u64,
    /// Genesis hash (for AVM context).
    pub genesis_hash: [u8; 32],
    /// Running transaction counter for creatable ID generation.
    ///
    /// Mirrors go-algorand's `roundCowState.Counter()`. Starts at the
    /// previous block's `TxnCounter` and is incremented for each top-level
    /// and inner transaction. Used to seed `LedgerAvmContext::txn_counter`
    /// so that inner `acfg`/`appl` creates derive globally unique IDs.
    ///
    /// Uses `Cell` for interior mutability — the context is shared via `&`
    /// across all transactions in a block.
    pub txn_counter: Cell<u64>,
    /// Fee credit available to inner transactions from outer group overpayment.
    ///
    /// Mirrors go-algorand's `EvalParams.FeeCredit`. Computed per group as
    /// `total_fees_paid - (MinTxnFee * num_non_stpf_txns)`. Inner transactions
    /// that set fee=0 draw from this credit; overpayment by inner txns adds
    /// back to it. Shared across all app calls in a group.
    pub fee_credit: Cell<u64>,
    /// Fractional microAlgo residue (1e-12 precision) left over from the
    /// group's fee round-ups so far but not yet consumed.
    ///
    /// Mirrors go-algorand's `EvalParams.feeResidue` (`data/transactions/
    /// logic/eval.go`, PR #6650): seeded per top-level group by
    /// `compute_group_fee_credit_and_residue` alongside `fee_credit`, then
    /// threaded into `LedgerAvmContext::fee_residue` for the group's app
    /// calls so nested inner-txn groups round their aggregate fee up only
    /// once, not once per group. Shared across all app calls in a group,
    /// same as `fee_credit`.
    pub fee_residue: Cell<u64>,
    /// Current transaction index within the block (for mismatch reporting).
    pub txn_index: Cell<usize>,
    /// Consensus parameters for the current protocol version.
    pub consensus: ConsensusParams,
    /// Simulation-only AVM evaluation overrides (log limits,
    /// unnamed-resource tracking). Defaults leave consensus behaviour
    /// unchanged.
    pub avm_overrides: AvmEvalOverrides,
    /// Side channel for the partial EvalDelta of a top-level `appl` call that
    /// was rejected or errored during execution.
    ///
    /// `apply_appl` sets this immediately before returning `Err` for a
    /// rejected/erroring approval program, carrying whatever global/local
    /// state, logs, and inner transactions the AVM had already accumulated
    /// (see `algo_avm::eval::run_approval_program`'s error-preservation, and
    /// go-algorand's `evalTracer.saveEvalDelta` — `tracer.go:263`). The
    /// transaction still fails and its state changes are rolled back
    /// (nothing here is ever applied to the ledger); this exists purely so
    /// callers that need failure visibility (the simulation engine) can
    /// surface the partial delta in `TxnResult.apply_data` instead of `None`.
    ///
    /// Uses `Cell` for the same reason as `fee_credit`/`txn_counter`: the
    /// context is shared via `&` across the call chain. Consumed with
    /// `.take()` by the caller so a stale value never leaks into an
    /// unrelated later transaction.
    pub failed_eval_delta: Cell<Option<rmpv::Value>>,
    /// Shared per-round box-modification recorder for `StateDelta.kv_mods`
    /// (issue #570). Only set (by [`apply_block_with_delta_mode`]) when the
    /// caller runs in [`ApplyMode::Execute`] and wants box deltas back —
    /// `Replay` mode never mutates box storage (box mutations only happen
    /// inside AVM execution), so there is nothing to record there.
    pub kv_mods_recorder: Option<crate::avm_context::KvModsRecorder>,
}

/// AVM evaluation overrides applied by the simulation engine.
///
/// Mirrors the effect of go-algorand's `ResultEvalOverrides.LogicEvalConstants()`
/// and the `UnnamedResources` policy on `logic.EvalParams`.
#[derive(Debug, Clone, Default)]
pub struct AvmEvalOverrides {
    /// Raised `log` call limit (simulation `allow_more_logging`).
    pub max_log_calls: Option<u64>,
    /// Raised total log size limit (simulation `allow_more_logging`).
    pub max_log_size: Option<u64>,
    /// Enable unnamed-resource tracking (simulation `allow_unnamed_resources`).
    /// Holds the group's named resources, shared across all transactions.
    pub unnamed_tracking: Option<std::sync::Arc<crate::avm_context::NamedGroupResources>>,
}

impl ApplyContext {
    /// Create a Replay-mode context with zero timestamp and genesis hash.
    /// Primarily for tests and backward compatibility.
    pub fn new_replay(rewards_level: u64, fee_sink: Address, round: u64) -> Self {
        Self {
            rewards_level,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus: ConsensusParams::default(),
            avm_overrides: AvmEvalOverrides::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        }
    }

    /// Apply this context's simulation AVM overrides to a freshly created
    /// `LedgerAvmContext`. A no-op for the default (consensus) overrides.
    pub(crate) fn configure_avm_ctx<L: crate::store_trait::LedgerStore>(
        &self,
        avm_ctx: &mut crate::avm_context::LedgerAvmContext<'_, L>,
    ) {
        if self.avm_overrides.max_log_calls.is_some() || self.avm_overrides.max_log_size.is_some() {
            avm_ctx.set_log_limits(
                self.avm_overrides
                    .max_log_calls
                    .unwrap_or(crate::avm_context::MAX_LOG_CALLS),
                self.avm_overrides
                    .max_log_size
                    .unwrap_or(crate::avm_context::MAX_LOG_SIZE),
            );
        }
        if let Some(named) = &self.avm_overrides.unnamed_tracking {
            avm_ctx.enable_unnamed_resource_tracking(named.clone());
        }
        if let Some(recorder) = &self.kv_mods_recorder {
            avm_ctx.kv_mods_recorder = Some(recorder.clone());
        }
    }
}

/// Apply a full block to the ledger state using the default Replay mode.
///
/// This is a convenience wrapper around [`apply_block_impl`] that uses
/// `ApplyMode::Replay` with `validate=false` for backward compatibility.
pub fn apply_block<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    apply_block_impl(
        store,
        block,
        ApplyMode::Replay,
        false,
        None,
        None,
        None,
        None,
    )
}

/// Apply a full block to the ledger state with the specified mode.
///
/// Convenience wrapper with `validate=false` (replay/catchup behavior).
pub fn apply_block_with_mode<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
) -> Result<(), AlgoError> {
    apply_block_impl(store, block, mode, false, None, None, None, None)
}

/// Apply a full block to the ledger state with validation enabled.
///
/// Like [`apply_block`] but also runs end-of-block participation validation
/// (duplicate checks, vote key checks, online status checks) matching
/// Go's `eval.validate = true` code path.
pub fn apply_block_validating<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    apply_block_impl(
        store,
        block,
        ApplyMode::Replay,
        true,
        None,
        None,
        None,
        None,
    )
}

/// Apply a full block (Execute mode) while capturing per-transaction-group
/// state deltas into `group_deltas`, for the `GET /v2/deltas/txn/group/...`
/// endpoints. The tracer records each group's delta indexed by every txn ID and
/// the group ID, within its rolling lookback window. Behaves like
/// [`apply_block_with_mode`] with [`ApplyMode::Execute`] otherwise.
pub fn apply_block_capturing_group_deltas<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    group_deltas: &mut crate::txn_group_delta_tracer::TxnGroupDeltaTracer,
) -> Result<(), AlgoError> {
    apply_block_impl(
        store,
        block,
        ApplyMode::Execute,
        false,
        None,
        Some(group_deltas),
        None,
        None,
    )
}

/// Apply `block` in `mode`, returning the per-transaction [`ApplyData`] in
/// payset order (created asset/app ids, eval delta, rewards, closing amounts).
///
/// Used by the dev-mode producer to backfill the committed block's
/// `SignedTxnInBlock` apply-data fields so `/v2/transactions/pending/{txid}` can
/// report created ids and eval deltas. `Execute` mode runs the AVM (the deltas
/// reflect real execution); `Replay` mode returns the trusted-block apply data.
pub fn apply_block_capturing_apply_data<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
) -> Result<Vec<ApplyData>, AlgoError> {
    let mut out = Vec::with_capacity(block.payset.len());
    apply_block_impl(store, block, mode, false, None, None, Some(&mut out), None)?;
    Ok(out)
}

/// Build a `StateDelta` balance record from an account's post-state, matching
/// the field mapping in [`apply_block_with_delta`] and the per-group capture in
/// [`apply_block_impl`].
fn balance_record_for(
    addr: &Address,
    ad: &algo_types::AccountData,
) -> crate::state_delta::BalanceRecord {
    use crate::state_delta::{AccountBaseData, BalanceRecord, LedgercoreAccountData, VotingData};
    let voting = VotingData {
        vote_id: ad.vote_id.unwrap_or([0u8; 32]),
        selection_id: ad.selection_id.unwrap_or([0u8; 32]),
        state_proof_id: ad.state_proof_id.unwrap_or([0u8; 64]),
        vote_first_valid: Round(ad.vote_first_valid),
        vote_last_valid: Round(ad.vote_last_valid),
        vote_key_dilution: ad.vote_key_dilution,
    };
    let base = AccountBaseData {
        status: ad.status as u64,
        micro_algos: ad.micro_algos,
        rewards_base: ad.rewards_base,
        rewarded_micro_algos: ad.rewarded_micro_algos,
        auth_addr: ad.auth_addr.unwrap_or(Address::ZERO),
        incentive_eligible: ad.incentive_eligible,
        total_app_schema: ad.total_app_schema.clone(),
        total_extra_app_pages: ad.total_extra_app_pages,
        total_app_params: ad.total_created_apps,
        total_app_local_states: ad.total_apps_opted_in,
        total_asset_params: ad.total_created_assets,
        total_assets: ad.total_assets_opted_in,
        total_boxes: ad.total_boxes,
        total_box_bytes: ad.total_box_bytes,
        last_proposed: Round(ad.last_proposed),
        last_heartbeat: Round(ad.last_heartbeat),
    };
    BalanceRecord {
        addr: *addr,
        account_data: LedgercoreAccountData { base, voting },
    }
}

/// Convert the ledger's `AssetParams` (asset-config transaction payload
/// shape) into the `StateDelta` wire record (`crate::state_delta::
/// AssetParamsRecord`, go's `basics.AssetParams`). Field-for-field copy;
/// the two types differ only in that the ledger type uses `Option<Address>`
/// for role addresses (matching itxn-field semantics, see `apply_acfg`)
/// while the wire record uses the plain zero-address per go's own
/// `basics.AssetParams` (issue #579).
fn asset_params_record(p: &AssetParams) -> crate::state_delta::AssetParamsRecord {
    crate::state_delta::AssetParamsRecord {
        total: p.total,
        decimals: p.decimals,
        default_frozen: p.default_frozen,
        unit_name: p.unit_name.clone(),
        asset_name: p.asset_name.clone(),
        url: p.url.clone(),
        metadata_hash: p.metadata_hash,
        manager: p.manager.unwrap_or(Address::ZERO),
        reserve: p.reserve.unwrap_or(Address::ZERO),
        freeze: p.freeze.unwrap_or(Address::ZERO),
        clawback: p.clawback.unwrap_or(Address::ZERO),
    }
}

/// Convert the ledger's `AssetHolding` into the `StateDelta` wire record.
fn asset_holding_record(h: &AssetHolding) -> crate::state_delta::AssetHoldingRecord {
    crate::state_delta::AssetHoldingRecord {
        amount: h.amount,
        frozen: h.frozen,
    }
}

/// Convert the ledger's `AppParams` into the `StateDelta` wire record
/// (`crate::state_delta::AppParamsRecord`, go's `basics.AppParams`).
///
/// Issue #602: `algo_types::AppParams` now tracks real `version`/
/// `size_sponsor` values (set at app-create/update apply time in
/// `create_application`/`apply_appl_on_completion`), so both are threaded
/// through here instead of being hard-coded to zero.
fn app_params_record(p: &AppParams) -> crate::state_delta::AppParamsRecord {
    crate::state_delta::AppParamsRecord {
        approval_program: p.approval_program.clone(),
        clear_state_program: p.clear_state_program.clone(),
        global_state: teal_kv_to_record_map(&p.global_state),
        local_state_schema: p.local_state_schema.clone(),
        global_state_schema: p.global_state_schema.clone(),
        extra_program_pages: p.extra_program_pages,
        version: p.version,
        size_sponsor: p.size_sponsor,
        foreign_box_reads: p.foreign_box_reads,
        family_box_access: p.family_box_access,
    }
}

/// Convert the ledger's `AppLocalState` into the `StateDelta` wire record.
fn app_local_state_record(s: &AppLocalState) -> crate::state_delta::AppLocalStateRecord {
    crate::state_delta::AppLocalStateRecord {
        schema: s.schema.clone(),
        key_value: teal_kv_to_record_map(&s.key_value),
    }
}

/// Convert a `TealValue` key-value map (global or local state) into the
/// `StateDelta` wire shape (`HashMap<String, TealValueRecord>`, `None` when
/// empty — go leaves an untouched `TealKeyValue` map nil).
///
/// Key encoding: go's `basics.TealKeyValue` is `map[string]TealValue` where
/// the "string" is a raw-byte state key reinterpreted as a Go string (Go
/// strings are byte sequences with no UTF-8 validity requirement). This
/// repo's msgpack encoder already tunnels genuinely non-UTF-8 keys through
/// safely for `KvMods` (see `state_delta::serialize_kv_mods`'s `unsafe`
/// `from_utf8_unchecked` for the non-human-readable path); app/local state
/// keys go through ordinary (lossy) `String` conversion here instead,
/// matching this function's `HashMap<String, _>` value type and this PR's
/// scope (real state keys are overwhelmingly ASCII in practice) — a
/// byte-exact non-UTF-8 key round-trip for `AppResourceRecord`/
/// `AppParamsRecord` is a narrower gap than the one #586 set out to close
/// and is left for a follow-up if it proves to matter in practice.
fn teal_kv_to_record_map(
    kv: &std::collections::BTreeMap<Vec<u8>, algo_types::TealValue>,
) -> Option<std::collections::HashMap<String, crate::state_delta::TealValueRecord>> {
    if kv.is_empty() {
        return None;
    }
    Some(
        kv.iter()
            .map(|(k, v)| {
                let record = match v {
                    algo_types::TealValue::Bytes(b) => crate::state_delta::TealValueRecord {
                        value_type: 1,
                        bytes: String::from_utf8_lossy(b).into_owned(),
                        uint: 0,
                    },
                    algo_types::TealValue::Uint(u) => crate::state_delta::TealValueRecord {
                        value_type: 2,
                        bytes: String::new(),
                        uint: *u,
                    },
                };
                (String::from_utf8_lossy(k).into_owned(), record)
            })
            .collect(),
    )
}

/// Compute a transaction's ID: `SHA-512/256("TX" || canonical(txn))`.
fn transaction_id(txn: &algo_types::Transaction) -> algo_types::Digest {
    let canonical = algo_codec::canonical_encode_transaction(txn);
    let mut hasher = Sha512_256::new();
    hasher.update(b"TX");
    hasher.update(&canonical);
    let hash: [u8; 32] = hasher.finalize().into();
    algo_types::Digest(hash)
}

/// Apply a full block and return the resulting [`StateDelta`], using
/// `ApplyMode::Replay`. See [`apply_block_with_delta_mode`] for the
/// `Execute`-mode variant that can populate `kv_mods` with real box deltas
/// (issue #570).
pub fn apply_block_with_delta<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<crate::state_delta::StateDelta, AlgoError> {
    apply_block_with_delta_mode(store, block, ApplyMode::Replay)
}

/// Apply a full block and return the resulting [`StateDelta`].
///
/// Wraps [`apply_block_impl`]: snapshots pre-state for all addresses
/// referenced in the payset (and end-of-block participation lists), applies
/// the block, then diffs pre vs post state to build the delta.
///
/// `mode` controls how the block is applied. `Replay` (the historical
/// default, still what [`apply_block_with_delta`] uses) never runs the AVM,
/// so it can never observe box mutations — box create/put/replace/resize/
/// splice/delete only happen inside AVM execution
/// (`avm_context.rs`), and go-algorand's own `ApplyData`/`EvalDelta` (which
/// `Replay` mode replays from) carries no box-content field either, so a
/// block replayed from recorded `EvalDelta` alone genuinely cannot know
/// what changed in box storage — this is a go-algorand-shared limitation,
/// not something `Replay` mode is missing relative to the reference node.
/// `Execute` mode runs the AVM for real, so it *can* populate `kv_mods`
/// with real box deltas (issue #570); callers that want historical box-list
/// reconstruction (`SqliteLedger`'s `DeltaCache`) need an `Execute`-mode
/// apply path (e.g. dev-mode block production) to get non-empty `kv_mods`.
pub fn apply_block_with_delta_mode<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
) -> Result<crate::state_delta::StateDelta, AlgoError> {
    let (delta, _apply_data) =
        apply_block_with_delta_mode_and_apply_data(store, block, mode, false)?;
    Ok(delta)
}

/// Like [`apply_block_with_delta_mode`], but also returns the per-transaction
/// [`ApplyData`] captured during the same apply pass (payset order), so a
/// caller that already needs `ApplyData` (e.g. the dev-mode block producer,
/// issue #581) doesn't have to apply the block a second time to also get a
/// fully-populated `StateDelta`.
///
/// The returned `StateDelta` has the same field coverage as
/// [`apply_block_with_delta_mode`]: `Accts` (base account data only, no
/// per-resource deltas), `Txids`, `Txleases`, `Hdr`, and `KvMods` (real box
/// deltas under `Execute` mode) are populated; `Accts.AppResources`/
/// `AssetResources`, `Creatables`, `Totals`, and `StateProofNext` stay at
/// their zero values — computing those is tracked separately in #586, not
/// something this function (or issue #581's dev-mode caching fix) is
/// responsible for.
pub fn apply_block_capturing_apply_data_with_delta<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
) -> Result<(Vec<ApplyData>, crate::state_delta::StateDelta), AlgoError> {
    let (delta, apply_data) = apply_block_with_delta_mode_and_apply_data(store, block, mode, true)?;
    Ok((apply_data, delta))
}

fn apply_block_with_delta_mode_and_apply_data<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
    capture_apply_data: bool,
) -> Result<(crate::state_delta::StateDelta, Vec<ApplyData>), AlgoError> {
    use std::collections::{HashMap, HashSet};

    use crate::state_delta::{
        AccountBaseData, AccountDeltas, BalanceRecord, IncludedTransactions, LedgercoreAccountData,
        StateDelta, Txlease, VotingData,
    };

    // ── 1. Collect all addresses referenced in the payset ──────────
    let mut addrs = HashSet::new();
    for stx in &block.payset {
        collect_txn_addresses(&stx.txn, &mut addrs);
    }
    // End-of-block participation accounts.
    if let Some(ref expired) = block.expired_participation_accounts {
        for a in expired {
            addrs.insert(*a);
        }
    }
    if let Some(ref absent) = block.absent_participation_accounts {
        for a in absent {
            addrs.insert(*a);
        }
    }
    // Always include fee sink and rewards pool.
    addrs.insert(block.fee_sink);
    addrs.insert(block.rewards_pool);

    // ── 2. Snapshot pre-state for all collected addresses ──────────
    let mut addr_list: Vec<Address> = addrs.iter().copied().collect();
    let mut pre_accounts: HashMap<Address, Option<algo_types::AccountData>> = HashMap::new();
    for addr in &addr_list {
        pre_accounts.insert(*addr, store.get_account(addr));
    }
    // TODO(#190): prev_timestamp should be the previous block's timestamp.
    // We don't have easy access to it here; callers can fill it in if needed.
    let prev_timestamp = 0i64;

    // ── 2b. Collect app/asset resource keys touched by top-level txns and
    // snapshot their pre-state (issue #586) ────────────────────────────
    //
    // Mirrors go-algorand's `roundCowState` resource tracking
    // (`ledger/eval/cow.go`'s `Put`/`putAsset`), but scoped to what the
    // payset's *top-level* transaction fields name directly. This pass
    // alone does not recurse into inner transactions (an app call's inner
    // `acfg`/`axfer`/`afrz`/`appl` can touch resources it never names) --
    // step 3c below closes that gap (and `collect_txn_addresses`'s
    // matching account-address gap) using a different mechanism, since
    // the resource keys an inner transaction touches aren't knowable
    // until after the block has actually been applied (issue #604; see
    // `recording_store`'s module doc comment for why).
    //
    // - Acfg (update/destroy, `config_asset != 0`): the asset's params
    //   delta is attributed to the *creator* address (go keys
    //   `AssetParamsDelta` by creator, not by whoever signed the reconfig/
    //   destroy as manager) — resolved from the pre-image below, since
    //   `apply_acfg`'s own destroy path removes the params record entirely.
    // - Acfg (create, `config_asset == 0`): the new asset id doesn't exist
    //   pre-apply, so it's resolved post-apply from `ApplyData::config_asset`
    //   instead (below, after applying the block).
    // - Axfer: holding changes for every address the transfer can touch
    //   (sender, receiver, close-to, clawback source).
    // - Afrz: the holding (frozen flag) change for the target account.
    // - Appl: local-state changes are always attributed to the *sender*
    //   (go-algorand only ever lets a call mutate its own sender's local
    //   state via `AppLocalPut`/`AppLocalDel`, regardless of on-completion —
    //   not just at OptIn/CloseOut/ClearState) plus any `accounts` array
    //   entries (an app can also write another opted-in account's local
    //   state when that account is named in the call's `Accounts` array).
    //   Params changes are attributed to the creator, resolved from the
    //   pre-image (Update/Delete) or, for a create, from `ApplyData::
    //   application_id` post-apply.
    let mut asset_holding_keys: HashSet<(Address, u64)> = HashSet::new();
    // Issue #603 (live-verification against a real go-algorand
    // v4.7.0-stable node found this): go-algorand's `AccountDeltas` entries
    // are "was this resource `Put` during the round"-tracked
    // (`ledger/eval/cow.go`), not before/after diffed the way this
    // function's own `pre != post` gating works elsewhere. Concretely, a
    // *reconfigure* Acfg that re-affirms identical manager/reserve/freeze/
    // clawback values (a legal, real no-op reconfigure) still produces a
    // full `AssetResourceRecord` on go's wire response -- both `Params` and
    // (unexpectedly) `Holding`, even though neither value actually changed.
    // Every key in this set is force-emitted below regardless of the
    // pre/post diff. Originally scoped to just the (creator, asset) key an
    // existing-asset Acfg (reconfigure/destroy) resolves in the loop below
    // (that key never itself goes through `set_asset_holding`/
    // `remove_asset_holding` for a reconfigure, so it can't be discovered
    // via `touches` -- go's own combined `UpsertAssetResource` call from
    // `putAssetParams` is what forces the creator's holding onto the wire
    // even though the holding itself wasn't `Put`). Issue #608 widened this
    // to *also* be populated from `touches.asset_holdings` below (every key
    // an actual `set_asset_holding`/`remove_asset_holding` call touched,
    // top-level or inner, any txn type) -- live-verification confirmed
    // go's `AssetFreeze`/`AssetTransfer` (`ledger/apply/asset.go`) call
    // `PutAssetHolding` unconditionally too, so Axfer/Afrz-touched holdings
    // need the same force-emit treatment as the Acfg case.
    let mut asset_holding_force_emit: HashSet<(Address, u64)> = HashSet::new();
    let mut asset_creators: HashMap<u64, Address> = HashMap::new();
    let mut asset_params_pre: HashMap<u64, Option<AssetParams>> = HashMap::new();
    let mut asset_ids_resolved: HashSet<u64> = HashSet::new();
    let mut app_state_keys: HashSet<(Address, u64)> = HashSet::new();
    let mut app_creators: HashMap<u64, Address> = HashMap::new();
    let mut app_params_pre: HashMap<u64, Option<AppParams>> = HashMap::new();
    let mut app_ids_resolved: HashSet<u64> = HashSet::new();

    for stx in &block.payset {
        let txn = &stx.txn;
        match txn.txn_type {
            algo_types::TxnType::Acfg => {
                if txn.config_asset != 0 && asset_ids_resolved.insert(txn.config_asset) {
                    if let Some(rec) = store.get_asset_params(txn.config_asset) {
                        asset_creators.insert(txn.config_asset, rec.creator);
                        asset_params_pre.insert(txn.config_asset, Some(rec.params));
                        // A destroy Acfg removes the creator's holding too
                        // (`apply_acfg`'s destroy branch calls
                        // `remove_asset_holding`); a reconfigure never
                        // changes it. Either way, track it as force-emit
                        // (see `asset_holding_force_emit`'s doc comment) so
                        // it always appears in the resulting
                        // `AssetResourceRecord`, matching go.
                        asset_holding_keys.insert((rec.creator, txn.config_asset));
                        asset_holding_force_emit.insert((rec.creator, txn.config_asset));
                    } else {
                        asset_params_pre.insert(txn.config_asset, None);
                    }
                }
            }
            algo_types::TxnType::Axfer => {
                if txn.xaid != 0 {
                    asset_holding_keys.insert((txn.sender, txn.xaid));
                    if let Some(r) = txn.asset_receiver {
                        if !r.is_zero() {
                            asset_holding_keys.insert((r, txn.xaid));
                        }
                    }
                    if let Some(c) = txn.asset_close_to {
                        if !c.is_zero() {
                            asset_holding_keys.insert((c, txn.xaid));
                        }
                    }
                    if let Some(s) = txn.asset_sender {
                        if !s.is_zero() {
                            asset_holding_keys.insert((s, txn.xaid));
                        }
                    }
                }
            }
            algo_types::TxnType::Afrz => {
                if txn.freeze_asset != 0 {
                    if let Some(a) = txn.freeze_account {
                        if !a.is_zero() {
                            asset_holding_keys.insert((a, txn.freeze_asset));
                        }
                    }
                }
            }
            algo_types::TxnType::Appl if txn.application_id != 0 => {
                app_state_keys.insert((txn.sender, txn.application_id));
                if let Some(ref accts) = txn.accounts {
                    for a in accts {
                        if !a.is_zero() {
                            app_state_keys.insert((*a, txn.application_id));
                        }
                    }
                }
                if app_ids_resolved.insert(txn.application_id) {
                    if let Some(params) = store.get_app_params(txn.application_id) {
                        app_creators.insert(txn.application_id, params.creator);
                        app_params_pre.insert(txn.application_id, Some(params));
                    } else {
                        app_params_pre.insert(txn.application_id, None);
                    }
                }
            }
            _ => {}
        }
    }

    let mut asset_holding_pre: HashMap<(Address, u64), Option<AssetHolding>> = HashMap::new();
    for &(addr, aid) in &asset_holding_keys {
        asset_holding_pre.insert((addr, aid), store.get_asset_holding(&addr, aid));
    }
    let mut app_state_pre: HashMap<(Address, u64), Option<AppLocalState>> = HashMap::new();
    for &(addr, aid) in &app_state_keys {
        app_state_pre.insert((addr, aid), store.get_app_local_state(&addr, aid));
    }

    // ── 3. Apply the block ────────────────────────────────────────
    let mut kv_mods: HashMap<Vec<u8>, crate::state_delta::KvValueDelta> = HashMap::new();
    // Always capture ApplyData internally -- resource-delta attribution for
    // Acfg/Appl *creates* needs the created id regardless of whether the
    // caller itself wants ApplyData back (`capture_apply_data`); the return
    // value below still honors that flag.
    let mut apply_data: Vec<ApplyData> = Vec::new();
    // Issue #604: wrap `store` for the duration of the real apply so that
    // every account/resource mutation -- top-level *or* inner-transaction,
    // at any nesting depth -- has its pre-mutation value recorded as it
    // happens. This is what lets step 3c below attribute resource deltas
    // for resources only ever touched by an `itxn_submit`-driven inner
    // transaction, which the top-level-only scan in step 2b can't see and
    // which (for a freshly-executed, not-yet-recorded block) can't be
    // discovered before the apply either. See `recording_store`'s module
    // doc comment for why a pre-apply snapshot alone doesn't work here.
    let mut recording_store = crate::recording_store::RecordingStore::new(store);
    apply_block_impl(
        &mut recording_store,
        block,
        mode,
        false,
        None,
        None,
        Some(&mut apply_data),
        Some(&mut kv_mods),
    )?;
    let touches = recording_store.touches;

    // ── 3b. Resolve create-time resource keys now that new ids exist ───
    for (stx, ad) in block.payset.iter().zip(apply_data.iter()) {
        let txn = &stx.txn;
        if txn.txn_type == algo_types::TxnType::Acfg
            && txn.config_asset == 0
            && ad.config_asset != 0
        {
            asset_holding_keys.insert((txn.sender, ad.config_asset));
            asset_creators.insert(ad.config_asset, txn.sender);
            asset_params_pre.entry(ad.config_asset).or_insert(None);
        }
        if txn.txn_type == algo_types::TxnType::Appl
            && txn.application_id == 0
            && ad.application_id != 0
        {
            app_state_keys.insert((txn.sender, ad.application_id));
            app_creators.insert(ad.application_id, txn.sender);
            app_params_pre.entry(ad.application_id).or_insert(None);
        }
    }
    // Newly-created ids have no pre-image holding/local-state to look up
    // (the account couldn't hold/opt into a resource that didn't exist yet).
    for &(addr, aid) in &asset_holding_keys {
        asset_holding_pre.entry((addr, aid)).or_insert(None);
    }
    for &(addr, aid) in &app_state_keys {
        app_state_pre.entry((addr, aid)).or_insert(None);
    }

    // ── 3c. Merge in resources/accounts only ever touched by an inner
    // transaction (issue #604) ──────────────────────────────────────────
    //
    // `touches` (populated by the `RecordingStore` wrapper around step 3)
    // captured the pre-mutation value of every account/asset/app resource
    // actually written this round, including ones only reachable via
    // `itxn_submit` at any nesting depth -- something the top-level-only
    // scan in step 2b (and `collect_txn_addresses`'s own long-standing
    // TODO(#190) gap, in step 1) can't see. Keys step 1/2b/3b already
    // resolved are left untouched here (their pre-image was captured
    // correctly, before the block applied, which is strictly more
    // reliable than a post-apply store read for a key that step 2b/3b
    // themselves mutated); this only *adds* newly-discovered
    // inner-transaction-only keys, using each one's actual first-touch
    // pre-mutation value (not a post-apply read, which would silently
    // read the *post* value for a key mutated earlier in the same round).
    for (&aid, pre) in &touches.asset_params {
        if asset_params_pre.contains_key(&aid) {
            continue;
        }
        let creator = match pre {
            Some(rec) => rec.creator,
            None => match store.get_asset_params(aid) {
                Some(rec) => rec.creator,
                // Created and destroyed within the same round, leaving no
                // surviving params record to resolve a creator from --
                // nothing stable to attribute a delta to.
                None => continue,
            },
        };
        asset_creators.insert(aid, creator);
        asset_params_pre.insert(aid, pre.as_ref().map(|rec| rec.params.clone()));
        if let Some(pre_rec) = pre {
            // Existing asset touched (reconfigure/destroy semantics) --
            // mirror issue #603's force-emit of the creator's holding
            // record for a top-level Acfg on an existing asset (go's
            // `AccountDeltas` are "was this resource `Put`"-tracked, not
            // value-diffed).
            asset_holding_keys.insert((pre_rec.creator, aid));
            asset_holding_force_emit.insert((pre_rec.creator, aid));
        }
    }
    for (&app_id, pre) in &touches.app_params {
        if app_params_pre.contains_key(&app_id) {
            continue;
        }
        let creator = match pre {
            Some(p) => p.creator,
            None => match store.get_app_params(app_id) {
                Some(p) => p.creator,
                None => continue,
            },
        };
        app_creators.insert(app_id, creator);
        app_params_pre.insert(app_id, pre.clone());
    }
    for (&(addr, aid), pre) in &touches.asset_holdings {
        asset_holding_keys.insert((addr, aid));
        asset_holding_pre
            .entry((addr, aid))
            .or_insert_with(|| pre.clone());
        // Issue #608 (widening #603's Acfg-only fix): `touches.asset_holdings`
        // is populated by `RecordingStore` on every `set_asset_holding`/
        // `remove_asset_holding` call made *anywhere* during this block's
        // apply -- top-level or inner, and for every txn type (Acfg's own
        // creator-holding writes, Axfer's opt-in/transfer/close-out, Afrz's
        // freeze/unfreeze), not just Acfg. That's the exact same "was this
        // resource `Put`" signal go-algorand's `roundCowState.putAssetHolding`
        // (`ledger/eval/cow_creatables.go`) uses to force an entry into
        // `AccountDeltas` -- go calls `PutAssetHolding` unconditionally
        // whenever `takeOut`/`putIn`/`AssetFreeze` run (`ledger/apply/
        // asset.go`), even when the resulting value is byte-identical to the
        // value already there (e.g. a non-zero-amount self-transfer, or a
        // re-freeze to the already-current flag). Force-emitting every
        // touched key, not just the Acfg-derived ones, makes algod-rust
        // match that unconditional-Put semantics for Axfer/Afrz too.
        asset_holding_force_emit.insert((addr, aid));
    }
    // Issue #608 (the other half of go's combined-record semantics): go's
    // `putAssetHolding` (`ledger/eval/cow_creatables.go`) doesn't just
    // upsert the touched `Holding` -- it calls `lookupAssetParams(addr,
    // aidx, cacheOnly=true)` first and bundles *that* onto the very same
    // `AssetResourceRecord`. When the touched address is the asset's own
    // creator (e.g. the creator self-transfers or freezes their own asset,
    // live-verified: a value-identical self-transfer's wire record from a
    // real go-algorand v4.7.0-stable node carries a full `Params` object,
    // not null), go's response shows the asset's actual (round-unchanged)
    // `Params` on that record too. Resolve and attach it here if no Acfg
    // already did so above -- since nothing touched the params this round,
    // the post-apply store read *is* the correct pre-image too (nothing to
    // diff against a stale value).
    for &(addr, aid) in touches.asset_holdings.keys() {
        if asset_creators.contains_key(&aid) {
            continue;
        }
        if let Some(rec) = store.get_asset_params(aid) {
            if rec.creator == addr {
                asset_creators.insert(aid, addr);
                asset_params_pre.insert(aid, Some(rec.params));
            }
        }
    }
    for (&(addr, app_id), pre) in &touches.app_local_states {
        app_state_keys.insert((addr, app_id));
        app_state_pre
            .entry((addr, app_id))
            .or_insert_with(|| pre.clone());
    }
    // Same first-touch-wins merge for accounts (issue #190's gap, folded
    // into #604's fix since it needs the identical mechanism): an account
    // only ever referenced by an inner transaction (e.g. an inner `axfer`
    // receiver never named in the outer txn's own fields or `Accounts`
    // array) was never added to `addr_list`/`pre_accounts` in step 1/2.
    for (&addr, pre) in &touches.accounts {
        if let std::collections::hash_map::Entry::Vacant(e) = pre_accounts.entry(addr) {
            e.insert(pre.clone());
            addr_list.push(addr);
        }
    }

    // ── 4. Build the StateDelta by diffing pre vs post state ──────
    let mut accts = Vec::new();
    for addr in &addr_list {
        let post = store.get_account(addr);
        let pre = pre_accounts.get(addr).cloned().flatten();
        // Only include in delta if something actually changed.
        if pre != post {
            let ad = post.unwrap_or_default();
            let voting = VotingData {
                vote_id: ad.vote_id.unwrap_or([0u8; 32]),
                selection_id: ad.selection_id.unwrap_or([0u8; 32]),
                state_proof_id: ad.state_proof_id.unwrap_or([0u8; 64]),
                vote_first_valid: Round(ad.vote_first_valid),
                vote_last_valid: Round(ad.vote_last_valid),
                vote_key_dilution: ad.vote_key_dilution,
            };
            let base = AccountBaseData {
                status: ad.status as u64,
                micro_algos: ad.micro_algos,
                rewards_base: ad.rewards_base,
                rewarded_micro_algos: ad.rewarded_micro_algos,
                auth_addr: ad.auth_addr.unwrap_or(Address::ZERO),
                incentive_eligible: ad.incentive_eligible,
                total_app_schema: ad.total_app_schema.clone(),
                total_extra_app_pages: ad.total_extra_app_pages,
                total_app_params: ad.total_created_apps,
                total_app_local_states: ad.total_apps_opted_in,
                total_asset_params: ad.total_created_assets,
                total_assets: ad.total_assets_opted_in,
                total_boxes: ad.total_boxes,
                total_box_bytes: ad.total_box_bytes,
                last_proposed: Round(ad.last_proposed),
                last_heartbeat: Round(ad.last_heartbeat),
            };
            accts.push(BalanceRecord {
                addr: *addr,
                account_data: LedgercoreAccountData { base, voting },
            });
        }
    }

    // ── 4b. Build app_resources/asset_resources/creatables by diffing the
    // resource keys collected in step 2b/3b against their post-apply state
    // (issue #586) ───────────────────────────────────────────────────────
    use crate::state_delta::{
        AppLocalStateDelta, AppParamsDelta, AppResourceRecord, AssetHoldingDelta, AssetParamsDelta,
        AssetResourceRecord, ModifiedCreatable,
    };

    let mut asset_records: HashMap<(Address, u64), AssetResourceRecord> = HashMap::new();
    let mut creatables: HashMap<u64, ModifiedCreatable> = HashMap::new();

    for (&aid, &creator) in &asset_creators {
        let pre = asset_params_pre.get(&aid).cloned().flatten();
        let post_rec = store.get_asset_params(aid);
        let post = post_rec.as_ref().map(|r| r.params.clone());
        // `asset_creators` is populated solely by processing an Acfg (see
        // step 2b/3b above) -- create, reconfigure, or destroy. Emit
        // unconditionally, not gated on `pre != post`: go-algorand's own
        // `/v2/deltas` response always carries an `AssetResourceRecord.Params`
        // entry for any Acfg that touches an existing asset, even a
        // no-op reconfigure that re-affirms identical values (issue #603,
        // live-verified against a real go-algorand v4.7.0-stable node).
        let delta = match &post {
            Some(p) => AssetParamsDelta {
                params: Some(asset_params_record(p)),
                deleted: false,
            },
            None => AssetParamsDelta {
                params: None,
                deleted: true,
            },
        };
        asset_records
            .entry((creator, aid))
            .or_insert_with(|| AssetResourceRecord {
                aidx: aid,
                addr: creator,
                params: AssetParamsDelta::default(),
                holding: AssetHoldingDelta::default(),
            })
            .params = delta;
        match (pre.is_some(), post.is_some()) {
            (false, true) => {
                creatables.insert(
                    aid,
                    ModifiedCreatable {
                        ctype: 0,
                        created: true,
                        creator,
                        ndeltas: 1,
                    },
                );
            }
            (true, false) => {
                creatables.insert(
                    aid,
                    ModifiedCreatable {
                        ctype: 0,
                        created: false,
                        creator,
                        ndeltas: 1,
                    },
                );
            }
            _ => {}
        }
    }
    for &(addr, aid) in &asset_holding_keys {
        let pre = asset_holding_pre.get(&(addr, aid)).cloned().flatten();
        let post = store.get_asset_holding(&addr, aid);
        // See `asset_holding_force_emit`'s doc comment: an existing-asset
        // Acfg (reconfigure/destroy) always emits the creator's holding on
        // go's wire response too, even when its value is unchanged.
        if pre != post || asset_holding_force_emit.contains(&(addr, aid)) {
            let delta = match &post {
                Some(h) => AssetHoldingDelta {
                    holding: Some(asset_holding_record(h)),
                    deleted: false,
                },
                None => AssetHoldingDelta {
                    holding: None,
                    deleted: true,
                },
            };
            asset_records
                .entry((addr, aid))
                .or_insert_with(|| AssetResourceRecord {
                    aidx: aid,
                    addr,
                    params: AssetParamsDelta::default(),
                    holding: AssetHoldingDelta::default(),
                })
                .holding = delta;
        }
    }
    let asset_resources: Vec<AssetResourceRecord> = asset_records.into_values().collect();

    let mut app_records: HashMap<(Address, u64), AppResourceRecord> = HashMap::new();
    for (&aid, &creator) in &app_creators {
        let pre = app_params_pre.get(&aid).cloned().flatten();
        let post = store.get_app_params(aid);
        if pre != post {
            let delta = match &post {
                Some(p) => AppParamsDelta {
                    params: Some(app_params_record(p)),
                    deleted: false,
                },
                None => AppParamsDelta {
                    params: None,
                    deleted: true,
                },
            };
            app_records
                .entry((creator, aid))
                .or_insert_with(|| AppResourceRecord {
                    aidx: aid,
                    addr: creator,
                    params: AppParamsDelta::default(),
                    state: AppLocalStateDelta::default(),
                })
                .params = delta;
            match (pre.is_some(), post.is_some()) {
                (false, true) => {
                    creatables.insert(
                        aid,
                        ModifiedCreatable {
                            ctype: 1,
                            created: true,
                            creator,
                            ndeltas: 1,
                        },
                    );
                }
                (true, false) => {
                    creatables.insert(
                        aid,
                        ModifiedCreatable {
                            ctype: 1,
                            created: false,
                            creator,
                            ndeltas: 1,
                        },
                    );
                }
                _ => {}
            }
        }
    }
    for &(addr, aid) in &app_state_keys {
        let pre = app_state_pre.get(&(addr, aid)).cloned().flatten();
        let post = store.get_app_local_state(&addr, aid);
        if pre != post {
            let delta = match &post {
                Some(s) => AppLocalStateDelta {
                    local_state: Some(app_local_state_record(s)),
                    deleted: false,
                },
                None => AppLocalStateDelta {
                    local_state: None,
                    deleted: true,
                },
            };
            app_records
                .entry((addr, aid))
                .or_insert_with(|| AppResourceRecord {
                    aidx: aid,
                    addr,
                    params: AppParamsDelta::default(),
                    state: AppLocalStateDelta::default(),
                })
                .state = delta;
        }
    }
    let app_resources: Vec<AppResourceRecord> = app_records.into_values().collect();

    // ── 5. Build Txids from the payset ────────────────────────────
    let mut txids: HashMap<algo_types::Digest, IncludedTransactions> = HashMap::new();
    for (i, stx) in block.payset.iter().enumerate() {
        let canonical = algo_codec::canonical_encode_transaction(&stx.txn);
        let mut hasher = Sha512_256::new();
        hasher.update(b"TX");
        hasher.update(&canonical);
        let hash: [u8; 32] = hasher.finalize().into();
        txids.insert(
            algo_types::Digest(hash),
            IncludedTransactions {
                last_valid: stx.txn.last_valid,
                intra: i as u64,
            },
        );
    }

    // ── 6. Build Txleases from the payset ─────────────────────────
    let mut txleases: Vec<(Txlease, Round)> = Vec::new();
    for stx in &block.payset {
        if stx.txn.lease != [0u8; 32] {
            txleases.push((
                Txlease {
                    sender: stx.txn.sender,
                    lease: stx.txn.lease,
                },
                stx.txn.last_valid,
            ));
        }
    }

    // ── 7. Build block header ─────────────────────────────────────
    let hdr = algo_types::BlockHeader {
        round: block.round,
        branch: block.branch,
        seed: block.seed,
        txn_commitment: block.txn_commitment,
        timestamp: block.timestamp,
        genesis_id: block.genesis_id.clone(),
        genesis_hash: block.genesis_hash,
        proposer: block.proposer,
        fee_sink: block.fee_sink,
        rewards_pool: block.rewards_pool,
        fees_collected: block.fees_collected,
        bonus: block.bonus,
        proposer_payout: block.proposer_payout,
        rewards_level: block.rewards_level,
        rewards_rate: block.rewards_rate,
        rewards_residue: block.rewards_residue,
        rewards_recalculation_round: block.rewards_recalculation_round,
        current_protocol: block.current_protocol.clone(),
        next_protocol: block.next_protocol.clone(),
        next_protocol_approvals: block.next_protocol_approvals,
        next_protocol_vote_before: block.next_protocol_vote_before,
        next_protocol_switch_on: block.next_protocol_switch_on,
        txn_counter: block.txn_counter,
        state_proof_tracking: block.state_proof_tracking.clone(),
        prev512: block.prev512,
        txn256: block.txn256,
        txn512: block.txn512,
        upgrade_propose: block.upgrade_propose.clone(),
        upgrade_delay: block.upgrade_delay,
        upgrade_approve: block.upgrade_approve,
        expired_participation_accounts: block.expired_participation_accounts.clone(),
        absent_participation_accounts: block.absent_participation_accounts.clone(),
        load: block.load,
        congestion_tax: block.congestion_tax,
    };

    let delta = StateDelta {
        accts: AccountDeltas {
            accts,
            app_resources,
            asset_resources,
        },
        kv_mods,
        txids,
        txleases: if txleases.is_empty() {
            None
        } else {
            Some(txleases)
        },
        creatables,
        hdr: Some(hdr),
        // Closes #586: mirrors go's `endOfBlock` (`ledger/eval/eval.go:1391-1400`),
        // which reads the cow's (post-`apply.StateProof`) `StateProofNextRound`
        // back into the header's `StateProofTracking[StateProofBasic].NextRound`.
        // For any block received from the wire (the state proof security-relevant
        // path this issue is about), `block.state_proof_tracking` already carries
        // that real value from go-algorand's own block production -- so reading
        // it back out of the header we just built is exactly the cow readback,
        // without needing a separate per-round mutable tracking field threaded
        // through `apply_transaction_inner`.
        state_proof_next: Round(crate::block_header::state_proof_next_round(
            &block.state_proof_tracking,
        )),
        prev_timestamp,
        totals: store.account_totals(),
    };

    // Preserve the pre-#586 contract: ApplyData is only actually returned
    // (non-empty) when the caller opted in via `capture_apply_data`, even
    // though it's now always populated internally above (needed to attribute
    // Acfg/Appl *create* resource deltas to the right id -- see step 3b).
    let apply_data = if capture_apply_data {
        apply_data
    } else {
        Vec::new()
    };

    Ok((delta, apply_data))
}

/// Collect all addresses referenced by a transaction (sender, receiver, etc.).
///
/// Deliberately does not recurse into inner transactions -- an address only
/// referenced by an inner app call isn't knowable from the top-level
/// transaction fields alone (issue #190/#604). For
/// [`apply_block_with_delta_mode_and_apply_data`], that gap is closed by a
/// different mechanism (step 3c's `RecordingStore`-captured `touches`,
/// which sees every address actually mutated regardless of nesting depth)
/// rather than by extending this function -- see that function's step 2b
/// doc comment. The other caller (this function's use inside `Execute`
/// mode's per-group delta capture, gated by
/// `sqlite::block_state_delta_is_complete`) had the same gap until issue
/// #609, which closed it the same way: a group-scoped
/// [`crate::recording_store::RecordingStore`] wraps `store` for the
/// duration of each group's apply (see the `capture_group_deltas` branch
/// below), and any address only ever touched by that group's inner
/// transactions is merged into the group's pre-image map from the
/// wrapper's `touches.accounts`, using each address's actual first-touch
/// pre-mutation value.
fn collect_txn_addresses(
    txn: &algo_types::Transaction,
    addrs: &mut std::collections::HashSet<Address>,
) {
    addrs.insert(txn.sender);
    if !txn.receiver.is_zero() {
        addrs.insert(txn.receiver);
    }
    if !txn.close_remainder_to.is_zero() {
        addrs.insert(txn.close_remainder_to);
    }
    if let Some(ar) = txn.asset_receiver {
        if !ar.is_zero() {
            addrs.insert(ar);
        }
    }
    if let Some(asnd) = txn.asset_sender {
        if !asnd.is_zero() {
            addrs.insert(asnd);
        }
    }
    if let Some(ac) = txn.asset_close_to {
        if !ac.is_zero() {
            addrs.insert(ac);
        }
    }
    if let Some(fa) = txn.freeze_account {
        if !fa.is_zero() {
            addrs.insert(fa);
        }
    }
    // App call accounts array.
    if let Some(ref accts) = txn.accounts {
        for a in accts {
            addrs.insert(*a);
        }
    }
}

/// Apply one atomic transaction group's transactions against `store`, in
/// payset order, threading a shared [`GroupBudget`] for pooled Execute-mode
/// AVM budget accounting (matches go-algorand's per-group `feeCredit`
/// pooling).
///
/// Factored out of `apply_block_impl`'s `Execute` arm (issue #609) so the
/// exact same per-transaction dispatch logic can run against either the
/// real ledger store or a group-scoped [`crate::recording_store::RecordingStore`]
/// wrapper, without duplicating it -- the caller picks which by choosing
/// what `S` is instantiated with at the call site.
#[allow(clippy::too_many_arguments)]
fn apply_group_transactions<S: crate::store_trait::LedgerStore>(
    store: &mut S,
    group: &[&SignedTransaction],
    ctx: &ApplyContext,
    group_budget: &mut GroupBudget,
    group_box_budget: &mut BoxBudgetState,
    mut tracer: Option<&mut dyn EvalTracer>,
    mut apply_data_out: Option<&mut Vec<ApplyData>>,
    global_txn_idx: &mut usize,
) -> Result<(), AlgoError> {
    // Shared across every member of this atomic group so `gload`/`gloads`/
    // `gloadss` in a later transaction can see whether an earlier sibling
    // actually ran a program (see `GroupInfo::ran_program`) and read back
    // the real values it wrote (see `GroupInfo::scratch`).
    let ran_program = RefCell::new(vec![false; group.len()]);
    let scratch = RefCell::new(vec![None; group.len()]);
    for (gi_idx, stx) in group.iter().enumerate() {
        ctx.txn_index.set(*global_txn_idx);
        let gi = GroupInfo {
            txns: group,
            index: gi_idx,
            ran_program: &ran_program,
            scratch: &scratch,
        };
        if stx.txn.txn_type == "appl" {
            // Fresh per-call re-borrow via explicit `match`-bound reborrow.
            // The inner `&mut dyn EvalTracer` lives only for the duration
            // of this synchronous call; matching binds a fresh borrow with
            // a local lifetime that the borrow checker can prove doesn't
            // outlive the call.
            let tracer_ref: Option<&mut dyn EvalTracer> = match tracer {
                Some(ref mut t) => Some(&mut **t),
                None => None,
            };
            let ad = apply_transaction_with_budget(
                store,
                stx,
                ctx,
                0,
                Some(&mut *group_budget),
                Some(&mut *group_box_budget),
                Some(&gi),
                tracer_ref,
            )?;
            if let Some(out) = apply_data_out.as_deref_mut() {
                out.push(ad);
            }
        } else {
            let ad = apply_transaction(store, stx, ctx, 0)?;
            if let Some(out) = apply_data_out.as_deref_mut() {
                out.push(ad);
            }
        }
        *global_txn_idx += 1;
    }
    Ok(())
}

/// Apply a full block to the ledger state (internal implementation).
///
/// Updates rewards parameters from the block header, then applies each
/// transaction in payset order. Finally updates `current_round`.
///
/// In `Replay` mode, recorded EvalDeltas from block data are used directly.
/// In `Execute` mode, AVM programs are run to produce results.
///
/// When `validate` is true, end-of-block participation validation checks
/// are run (matching Go's `eval.validate`). When false (replay/catchup),
/// only the apply-side state transitions run.
///
/// On error, rewards state is restored to its pre-block values. Note that
/// account mutations from earlier successful transactions in the payset are
/// NOT rolled back — the caller should treat the state as corrupted on error.
/// In practice, committed blocks are already validated and should never
/// produce errors — the checks here are defensive safety nets.
#[allow(clippy::too_many_arguments)]
fn apply_block_impl<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    mode: ApplyMode,
    validate: bool,
    mut tracer: Option<&mut dyn EvalTracer>,
    mut group_deltas: Option<&mut crate::txn_group_delta_tracer::TxnGroupDeltaTracer>,
    mut apply_data_out: Option<&mut Vec<ApplyData>>,
    kv_mods_out: Option<&mut KvModsMap>,
) -> Result<(), AlgoError> {
    // Issue #570: only allocate the shared box-delta recorder when a caller
    // actually wants `kv_mods` back (Execute mode, via
    // `apply_block_with_delta_mode`) — this keeps the hot Replay-mode sync
    // path free of the extra `Rc<RefCell<_>>` bookkeeping.
    let kv_mods_recorder = kv_mods_out
        .is_some()
        .then(|| std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new())));
    // Validate round monotonicity.
    let expected = Round(store.current_round().0 + 1);
    if block.round != expected {
        return Err(AlgoError::Ledger {
            message: format!("expected round {}, got {}", expected, block.round),
        });
    }

    // Save rewards state and addresses for rollback on error.
    let prev_rewards_level = store.rewards_level();
    let prev_rewards_rate = store.rewards_rate();
    let prev_rewards_residue = store.rewards_residue();
    let prev_rewards_recalc = store.rewards_recalculation_round();
    let prev_fee_sink = store.fee_sink();
    let prev_rewards_pool = store.rewards_pool();

    // Update rewards state and reward addresses from block header.
    store.set_rewards_level(block.rewards_level);
    store.set_rewards_rate(block.rewards_rate);
    store.set_rewards_residue(block.rewards_residue);
    store.set_rewards_recalculation_round(block.rewards_recalculation_round.0);
    store.set_fee_sink(block.fee_sink);
    store.set_rewards_pool(block.rewards_pool);

    let mut gh = [0u8; 32];
    if block.genesis_hash.len() == 32 {
        gh.copy_from_slice(&block.genesis_hash);
    }

    // Look up consensus parameters from the block's protocol version.
    let consensus =
        consensus_params_for_version(&block.current_protocol).ok_or_else(|| AlgoError::Ledger {
            message: format!("unknown protocol version: {}", block.current_protocol),
        })?;

    // Initialize txn_counter from the store's current value (= previous block's
    // TxnCounter). This is the base for creatable ID generation.
    let base_txn_counter = store.txn_counter();

    let ctx = ApplyContext {
        rewards_level: block.rewards_level,
        fee_sink: block.fee_sink,
        round: block.round.0,
        mode,
        validate,
        latest_timestamp: block.timestamp as u64,
        genesis_hash: gh,
        txn_counter: Cell::new(base_txn_counter),
        fee_credit: Cell::new(0),
        fee_residue: Cell::new(0),
        txn_index: Cell::new(0),
        consensus: consensus.clone(),
        avm_overrides: Default::default(),
        failed_eval_delta: Cell::new(None),
        kv_mods_recorder: kv_mods_recorder.clone(),
    };

    // Re-borrow the tracer per iteration with `Option::as_deref_mut` so
    // each `apply_transaction_with_budget` call gets its own short-lived
    // `Option<&mut dyn EvalTracer>` without aliasing. A labeled block
    // (rather than the previous IIFE) lets us early-exit on error without
    // pulling `tracer` into a closure capture — the closure form would
    // reborrow `tracer` for the lifetime of the captured `&mut`, which
    // conflicts with the per-iteration `as_deref_mut` borrows. Resolves
    // GH #209 — replaces the previous `*mut dyn EvalTracer` round-trip
    // with a fully-checked borrow chain.
    let result: Result<(), AlgoError> = 'block: {
        match ctx.mode {
            ApplyMode::Replay => {
                // Replay mode: process transactions individually (no AVM execution).
                for stx in &block.payset {
                    match apply_transaction(store, stx, &ctx, 0) {
                        Ok(ad) => {
                            if let Some(out) = apply_data_out.as_deref_mut() {
                                out.push(ad);
                            }
                        }
                        Err(e) => break 'block Err(e),
                    }
                }
            }
            ApplyMode::Execute => {
                // Execute mode: detect transaction groups, create group budgets,
                // and pass them through to apply_appl for AVM execution.
                let groups = detect_transaction_groups(&block.payset);
                let mut global_txn_idx: usize = 0;

                // Per-group state-delta capture (opt-in via `group_deltas`),
                // gated on the same completeness check as the per-round delta
                // cache. The diff-based capture only reconstructs full deltas for
                // pay/keyreg blocks, because `collect_txn_addresses` does not
                // enumerate every account touched by app calls, asset ops, or
                // heartbeats. For incomplete blocks the round is left unretained,
                // so the endpoints report the delta as unavailable rather than
                // returning a partial one.
                let capture_group_deltas =
                    group_deltas.is_some() && crate::sqlite::block_state_delta_is_complete(block);
                if let Some(t) = group_deltas.as_deref_mut() {
                    if capture_group_deltas {
                        // Advance the window and retain this round for recording.
                        t.before_block(block.round.0);
                    } else {
                        // Still advance/evict the window so a run of incomplete
                        // blocks can't leave stale deltas past the lookback, but
                        // leave this round unretained (delta unavailable).
                        t.advance(block.round.0);
                    }
                }

                for group in &groups {
                    let num_app_calls = group
                        .iter()
                        .filter(|stx| stx.txn.txn_type == "appl")
                        .count();
                    let mut group_budget = GroupBudget::new(num_app_calls);
                    // Group-scoped box I/O budget state (issue #727): mirrors
                    // go-algorand's shared `EvalParams.ioBudget`/
                    // `readBudgetChecked`/`available` (boxes, dirtyBytes,
                    // updateBytes), which persist across every top-level
                    // app-call transaction in this atomic group via one
                    // shared `EvalParams` pointer -- not just within a
                    // single top-level call's own inner-txn tree (which the
                    // existing `BoxBudgetState` propagation already
                    // handled).
                    let mut group_box_budget = BoxBudgetState::default();

                    // Compute per-group fee credit and residue (matches go-algorand feeCredit).
                    let (group_fee_credit, group_fee_residue) =
                        compute_group_fee_credit_and_residue(group, &ctx.consensus);
                    ctx.fee_credit.set(group_fee_credit);
                    ctx.fee_residue.set(group_fee_residue);

                    // Snapshot the group's touched accounts before applying it, so
                    // the per-group state delta can be built by diffing afterwards
                    // (the diff-based equivalent of go's per-group cow delta).
                    let group_start_idx = global_txn_idx;
                    let group_pre: Option<
                        std::collections::HashMap<Address, Option<algo_types::AccountData>>,
                    > = if capture_group_deltas {
                        let mut addrs = std::collections::HashSet::new();
                        for stx in group.iter() {
                            collect_txn_addresses(&stx.txn, &mut addrs);
                        }
                        addrs.insert(ctx.fee_sink);
                        addrs.insert(block.rewards_pool);
                        Some(
                            addrs
                                .into_iter()
                                .map(|a| (a, store.get_account(&a)))
                                .collect(),
                        )
                    } else {
                        None
                    };

                    // Issue #609: run this group's transactions through a
                    // group-scoped `RecordingStore` whenever the group's
                    // delta is actually being captured, so that an account
                    // only ever touched by one of this group's *inner*
                    // transactions (an `appl` call's `itxn_submit`, at any
                    // nesting depth) is still picked up by the diff below --
                    // `collect_txn_addresses` above only sees each
                    // top-level transaction's own fields, the same
                    // long-standing gap issue #604 fixed for the per-round
                    // delta cache's own resource-key collection. Scoped
                    // fresh per group (not once for the whole block) so
                    // that an address touched again in a later group still
                    // gets that later group's own correct first-touch
                    // pre-value, not an earlier group's.
                    let mut inner_touched_accounts: Option<
                        std::collections::HashMap<Address, Option<algo_types::AccountData>>,
                    > = None;
                    // Fresh per-iteration reborrow via explicit `match`, same
                    // rationale as `apply_group_transactions`'s own per-call
                    // reborrow: a plain `.as_deref_mut()` here makes rustc
                    // unify the reborrow's lifetime with `tracer`'s own `'1`
                    // input lifetime across loop iterations (E0499), since
                    // it's threaded through a second, generic function call
                    // boundary. The explicit reborrow binds a lifetime local
                    // to this `match`, which the borrow checker can prove
                    // ends when the call returns.
                    let tracer_reborrow: Option<&mut dyn EvalTracer> = match tracer {
                        Some(ref mut t) => Some(&mut **t),
                        None => None,
                    };
                    if capture_group_deltas {
                        let mut recording_store =
                            crate::recording_store::RecordingStore::new(store);
                        if let Err(e) = apply_group_transactions(
                            &mut recording_store,
                            group,
                            &ctx,
                            &mut group_budget,
                            &mut group_box_budget,
                            tracer_reborrow,
                            apply_data_out.as_deref_mut(),
                            &mut global_txn_idx,
                        ) {
                            break 'block Err(e);
                        }
                        inner_touched_accounts = Some(recording_store.touches.accounts);
                    } else if let Err(e) = apply_group_transactions(
                        store,
                        group,
                        &ctx,
                        &mut group_budget,
                        &mut group_box_budget,
                        tracer_reborrow,
                        apply_data_out.as_deref_mut(),
                        &mut global_txn_idx,
                    ) {
                        break 'block Err(e);
                    }

                    // Build and record this group's state delta (account diff +
                    // txids + txleases, matching the per-round delta's scope).
                    if let (Some(t), Some(mut pre)) = (group_deltas.as_deref_mut(), group_pre) {
                        use crate::state_delta::{IncludedTransactions, StateDelta, Txlease};
                        if let Some(extra) = inner_touched_accounts {
                            for (addr, pre_val) in extra {
                                pre.entry(addr).or_insert(pre_val);
                            }
                        }
                        let mut delta = StateDelta::default();
                        for (addr, pre_ad) in &pre {
                            let post = store.get_account(addr);
                            if *pre_ad != post {
                                delta
                                    .accts
                                    .accts
                                    .push(balance_record_for(addr, &post.unwrap_or_default()));
                            }
                        }
                        let mut ids = Vec::new();
                        let mut group_id_added = false;
                        for (j, stx) in group.iter().enumerate() {
                            let tid = transaction_id(&stx.txn);
                            delta.txids.insert(
                                tid,
                                IncludedTransactions {
                                    last_valid: stx.txn.last_valid,
                                    intra: (group_start_idx + j) as u64,
                                },
                            );
                            ids.push(tid);
                            // The shared group ID resolves to the same delta.
                            if stx.txn.group != [0u8; 32] && !group_id_added {
                                ids.push(algo_types::Digest(stx.txn.group));
                                group_id_added = true;
                            }
                            if stx.txn.lease != [0u8; 32] {
                                delta.txleases.get_or_insert_with(Vec::new).push((
                                    Txlease {
                                        sender: stx.txn.sender,
                                        lease: stx.txn.lease,
                                    },
                                    stx.txn.last_valid,
                                ));
                            }
                        }
                        t.record_group(ids, delta);
                    }
                }
            }
        }
        Ok(())
    };

    if result.is_err() {
        // Restore rewards state and addresses on failure.
        store.set_rewards_level(prev_rewards_level);
        store.set_rewards_rate(prev_rewards_rate);
        store.set_rewards_residue(prev_rewards_residue);
        store.set_rewards_recalculation_round(prev_rewards_recalc);
        store.set_fee_sink(prev_fee_sink);
        store.set_rewards_pool(prev_rewards_pool);
        return result;
    }

    // ── End-of-block participation updates ──────────────────────────
    // Mirrors go-algorand endOfBlock: for each category, first validate
    // (gated on ctx.validate, matching Go's `eval.validate`), then apply.
    //
    // Go order:
    //   1. validateExpiredOnlineAccounts()   — gated on eval.validate
    //   2. resetExpiredOnlineAccountsParticipationKeys()  — always runs
    //   3. validateAbsentOnlineAccounts()    — gated on eval.validate
    //   4. suspendAbsentAccounts()           — always runs
    //
    // Wrap in a snapshot/rollback guard so that if any function fails,
    // partial mutations from end-of-block processing are reverted.
    {
        // Collect all addresses that will be mutated by end-of-block processing
        // so we can snapshot them for rollback.
        let mut eob_addrs: Vec<Address> = Vec::new();
        if let Some(ref expired) = block.expired_participation_accounts {
            for addr in expired {
                if !eob_addrs.contains(addr) {
                    eob_addrs.push(*addr);
                }
            }
        }
        if let Some(ref absent) = block.absent_participation_accounts {
            for addr in absent {
                if !eob_addrs.contains(addr) {
                    eob_addrs.push(*addr);
                }
            }
        }
        // The proposer-payout step below (issue #523) mutates the fee sink
        // and proposer accounts, so they need the same rollback coverage.
        if !eob_addrs.contains(&block.fee_sink) {
            eob_addrs.push(block.fee_sink);
        }
        if !block.proposer.is_zero() && !eob_addrs.contains(&block.proposer) {
            eob_addrs.push(block.proposer);
        }
        let eob_snapshot = store.snapshot(&eob_addrs);
        let eob_result = (|| {
            validate_expired_online_accounts(store, block, &consensus, ctx.validate)?;
            reset_expired_online_accounts(store, block, &consensus)?;
            validate_absent_online_accounts(store, block, &consensus, ctx.validate)?;
            suspend_absent_accounts(store, block, &consensus)?;
            apply_proposer_payout(store, block)?;
            record_proposal(store, block)
        })();
        if eob_result.is_err() {
            store.restore_snapshot(eob_snapshot);
            return eob_result;
        }
    }

    store.set_current_round(block.round);
    store.purge_expired_leases(block.round.0);

    // Persist the block's txn_counter so the next block's ID generation
    // starts from the right base (matches go-algorand endOfBlock).
    store.set_txn_counter(block.txn_counter);

    // Store block header data, full block data, and txtail for history.
    // These are auxiliary tracker writes — failures are logged but do not
    // fail block application (matches go-algorand's tracker persistence pattern).
    // TODO(Epic 25b): Wire up `forget_before` to prune old blocks/txtail entries.
    let hdrdata = algo_codec::canonical_encode_block_header_from_block(block);
    let blkdata = algo_codec::canonical_encode_block(block);
    let proto = &block.current_protocol;
    if let Err(e) = store.put_block(block.round.0, proto, &hdrdata, &blkdata) {
        tracing::warn!("put_block failed for round {}: {e}", block.round.0);
    }

    let txtail = algo_codec::build_txtail_from_block(block);
    let txtail_data = algo_codec::canonical_encode_txtail_round(&txtail);
    if let Err(e) = store.put_txtail(block.round.0, &txtail_data) {
        tracing::warn!("put_txtail failed for round {}: {e}", block.round.0);
    }

    // State-proof verification-context tracker (issue #632): mirrors go's
    // `spVerificationTracker.newBlock` — record this block's own voters
    // data if it's a "voters round", and prune contexts a proof already
    // covered. Auxiliary tracker writes, same failure policy as above.
    if let Err(e) = crate::apply_stateproof::record_state_proof_verification_context(
        store,
        block.round.0,
        &block.current_protocol,
        &block.state_proof_tracking,
        consensus.state_proof_interval,
    ) {
        tracing::warn!(
            "record_state_proof_verification_context failed for round {}: {e}",
            block.round.0
        );
    }
    let state_proof_next = crate::block_header::state_proof_next_round(&block.state_proof_tracking);
    if let Err(e) =
        crate::apply_stateproof::prune_state_proof_verification_contexts(store, state_proof_next)
    {
        tracing::warn!(
            "prune_state_proof_verification_contexts failed for round {}: {e}",
            block.round.0
        );
    }

    // Issue #570: hand the accumulated box deltas back to the caller.
    if let (Some(out), Some(recorder)) = (kv_mods_out, kv_mods_recorder) {
        *out = Rc::try_unwrap(recorder)
            .map(RefCell::into_inner)
            .unwrap_or_else(|rc| rc.borrow().clone());
    }

    Ok(())
}

/// Validate expired participation accounts at end of block.
///
/// Mirrors go-algorand's `validateExpiredOnlineAccounts`. Gated on the
/// `validate` flag (matching Go's `if !eval.validate { return nil }`).
///
/// Checks: count <= max, no duplicate addresses, each account has a vote
/// key and its vote_last_valid < current round.
fn validate_expired_online_accounts<L: crate::store_trait::LedgerStore>(
    store: &L,
    block: &Block,
    consensus: &ConsensusParams,
    validate: bool,
) -> Result<(), AlgoError> {
    if !validate {
        return Ok(());
    }

    let max_expired = consensus.max_proposed_expired_online_accounts;
    let expired = block
        .expired_participation_accounts
        .as_deref()
        .unwrap_or(&[]);

    // If the length exceeds the max, it is an error (also handles max==0 disabling the feature).
    if expired.len() > max_expired {
        return Err(AlgoError::Ledger {
            message: format!(
                "length of expired accounts ({}) was greater than expected ({})",
                expired.len(),
                max_expired
            ),
        });
    }

    // Check for duplicates and that each account truly has expired keys.
    let round = block.round.0;
    let mut seen = std::collections::HashSet::with_capacity(expired.len());
    for addr in expired {
        if !seen.insert(*addr) {
            return Err(AlgoError::Ledger {
                message: format!("duplicate address found: {}", addr),
            });
        }

        let acct = store.get_or_default_account(addr);

        // Go: if acctData.VoteID.IsEmpty() -> error
        if acct.vote_id.is_none() || acct.vote_id.as_ref().is_some_and(|v| v == &[0u8; 32]) {
            return Err(AlgoError::Ledger {
                message: format!(
                    "endOfBlock found expiration candidate {} had no vote key",
                    addr
                ),
            });
        }
        // Go: if acctData.VoteLastValid >= currentRound -> error
        if acct.vote_last_valid >= round {
            return Err(AlgoError::Ledger {
                message: format!(
                    "endOfBlock found {} round ({}) was not less than current round ({})",
                    addr, acct.vote_last_valid, round
                ),
            });
        }
    }

    Ok(())
}

/// Apply expired participation accounts at end of block.
///
/// Mirrors go-algorand's `resetExpiredOnlineAccountsParticipationKeys`.
/// Always runs (not gated on validate). For each address in
/// `block.expired_participation_accounts`, looks up the account (returning
/// default for missing), calls ClearOnlineState, and persists.
///
/// Keeps the count check (Go has this in the apply function too).
fn reset_expired_online_accounts<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let max_expired = consensus.max_proposed_expired_online_accounts;
    let expired = block
        .expired_participation_accounts
        .as_deref()
        .unwrap_or(&[]);

    // If the length exceeds the max, it is an error (also handles max==0 disabling the feature).
    if expired.len() > max_expired {
        return Err(AlgoError::Ledger {
            message: format!(
                "length of expired accounts ({}) was greater than expected ({})",
                expired.len(),
                max_expired
            ),
        });
    }

    // ClearOnlineState on each expired account.
    for addr in expired {
        let mut acct = store.get_or_default_account(addr);
        // ClearOnlineState: set Offline and clear all voting keys.
        acct.status = AccountStatus::Offline;
        acct.vote_id = None;
        acct.selection_id = None;
        acct.state_proof_id = None;
        acct.vote_first_valid = 0;
        acct.vote_last_valid = 0;
        acct.vote_key_dilution = 0;
        store.set_account(addr, acct);
    }

    Ok(())
}

/// Validate absent participation accounts at end of block.
///
/// Mirrors go-algorand's `validateAbsentOnlineAccounts`. Gated on the
/// `validate` flag (matching Go's `if !eval.validate { return nil }`).
///
/// Checks: count <= max, no duplicate addresses, each account is Online
/// with non-zero balance and IncentiveEligible.
///
/// Note: Go also checks isAbsent (via online stake / voting stake) and
/// challenge failure (via FindChallenge + ch.Failed). Those require
/// agreement-level data not yet available here — deferred to Phase 6.
fn validate_absent_online_accounts<L: crate::store_trait::LedgerStore>(
    store: &L,
    block: &Block,
    consensus: &ConsensusParams,
    validate: bool,
) -> Result<(), AlgoError> {
    if !validate {
        return Ok(());
    }

    let max_suspensions = consensus.payouts_max_mark_absent;
    let absent = block
        .absent_participation_accounts
        .as_deref()
        .unwrap_or(&[]);

    // If the length exceeds the max, it is an error (also handles max==0 disabling the feature).
    if absent.len() > max_suspensions {
        return Err(AlgoError::Ledger {
            message: format!(
                "length of absent accounts ({}) was greater than expected ({})",
                absent.len(),
                max_suspensions
            ),
        });
    }

    // Check for duplicates and basic account eligibility for suspension.
    let mut seen = std::collections::HashSet::with_capacity(absent.len());
    for addr in absent {
        if !seen.insert(*addr) {
            return Err(AlgoError::Ledger {
                message: format!("duplicate address found: {}", addr),
            });
        }

        let acct = store.get_or_default_account(addr);

        if acct.status != AccountStatus::Online {
            return Err(AlgoError::Ledger {
                message: format!(
                    "proposed absent account {} was {:?}, not Online",
                    addr, acct.status
                ),
            });
        }
        if acct.micro_algos == 0 {
            return Err(AlgoError::Ledger {
                message: format!("proposed absent account {} with zero algos", addr),
            });
        }
        if !acct.incentive_eligible {
            return Err(AlgoError::Ledger {
                message: format!("proposed absent account {} not IncentiveEligible", addr),
            });
        }
    }

    Ok(())
}

/// Apply absent participation accounts at end of block.
///
/// Mirrors go-algorand's `suspendAbsentAccounts`. Always runs (not gated
/// on validate). For each address in `block.absent_participation_accounts`,
/// looks up the account (returning default for missing), suspends it
/// (Offline + clear IncentiveEligible), and persists.
///
/// Go's `suspendAbsentAccounts` has NO count check — the count check is
/// only in `validateAbsentOnlineAccounts`.
fn suspend_absent_accounts<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
    _consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let absent = block
        .absent_participation_accounts
        .as_deref()
        .unwrap_or(&[]);

    // Suspend each absent account.
    for addr in absent {
        let mut acct = store.get_or_default_account(addr);
        // Suspend: set Offline and clear incentive eligibility, but keep voting keys.
        acct.status = AccountStatus::Offline;
        acct.incentive_eligible = false;
        store.set_account(addr, acct);
    }

    Ok(())
}

/// Credit the block's proposer with its incentive payout.
///
/// Mirrors go-algorand's `BlockEvaluator.performPayout`
/// (`ledger/eval/eval.go`): moves `block.proposer_payout` microAlgos from
/// `block.fee_sink` to `block.proposer`. Runs unconditionally from
/// `endOfBlock` in go — not gated on `eval.generate` or `eval.validate` —
/// because by the time a block reaches apply/replay, its `Proposer` and
/// `ProposerPayout` header fields already encode whatever agreement
/// decided (a proposer found ineligible has its payout zeroed by
/// `WithProposer()` before the block is finalized); a replaying node just
/// applies what's in the header, exactly like a normal `Pay`-shaped
/// transfer.
///
/// Before this function existed, algod-rust's apply path only threaded
/// `block.proposer_payout` into the stored header/hash — it never actually
/// moved the money, so the proposer's balance and the ledger's
/// online/total money supply (`accounttotals`, `GET /v2/ledger/supply`)
/// silently diverged from go-algorand by the cumulative sum of every
/// block's payout. See issue #523.
///
/// No-op when there is no proposer (payouts not enabled for this block, or
/// a zero header) or the payout is zero, matching go's early return in
/// `performPayout`.
fn apply_proposer_payout<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    if block.proposer.is_zero() || block.proposer_payout == 0 {
        return Ok(());
    }

    let mut sink = store.get_or_default_account(&block.fee_sink);
    // Go's `proposerPayout()` clamps the payout to the fee sink's
    // available balance before it ever reaches a block header
    // (`ledger/eval/eval.go`), so this should never trip on a
    // well-formed block. `block.proposer_payout` is still
    // replay-path/untrusted-peer-reachable data, though, so surface a
    // `Result` here rather than underflowing or panicking.
    if sink.micro_algos < block.proposer_payout {
        return Err(AlgoError::Ledger {
            message: format!(
                "fee sink {} balance {} insufficient for proposer payout {} (round {})",
                block.fee_sink, sink.micro_algos, block.proposer_payout, block.round.0
            ),
        });
    }
    sink.micro_algos -= block.proposer_payout;
    store.set_account(&block.fee_sink, sink);

    let mut proposer = store.get_or_default_account(&block.proposer);
    proposer.micro_algos += block.proposer_payout;
    store.set_account(&block.proposer, proposer);

    Ok(())
}

/// Record the block's proposer bookkeeping: `LastProposed` and suspension
/// recovery.
///
/// Mirrors go-algorand's `BlockEvaluator.recordProposal`
/// (`ledger/eval/eval.go`), called immediately after `performPayout` in
/// `endOfBlock`:
///
/// ```go
/// func (eval *BlockEvaluator) recordProposal() error {
///     proposer := eval.block.Proposer()
///     if proposer.IsZero() {
///         return nil
///     }
///     prp, err := eval.state.Get(proposer, false)
///     if err != nil {
///         return err
///     }
///     if !prp.IsZero() {
///         prp.LastProposed = eval.Round()
///     }
///     if prp.Suspended() {
///         prp.Status = basics.Online
///     }
///     return eval.state.Put(proposer, prp)
/// }
/// ```
///
/// No-op when there is no proposer, matching go's early return. The
/// `!prp.IsZero()` guard on `LastProposed` (skip recording for a wholly
/// absent/default account) is mirrored by comparing against
/// `AccountData::default()` — go's comment explains the intent: a proposer
/// that has since closed its account, but is still voting (it takes 320
/// rounds for a keyreg to take effect), should not have `LastProposed`
/// recorded, since that would prevent the account from being GC'd.
///
/// Un-suspension mirrors go's `ledgercore.AccountData.Suspended()`
/// (`ledger/ledgercore/accountdata.go`): `Status == Offline && !VoteID
/// empty`. An account could propose while suspended because of the
/// 320-round key-registration lookback; doing so is evidence the account is
/// actually operational, so it is unsuspended. It remains not
/// `IncentiveEligible` until it keyregs again with the extra fee (go
/// intentionally leaves that field alone here).
fn record_proposal<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    if block.proposer.is_zero() {
        return Ok(());
    }

    let mut prp = store.get_or_default_account(&block.proposer);
    if prp != algo_types::AccountData::default() {
        prp.last_proposed = block.round.0;
    }
    // Go: `!VoteID.IsEmpty()` -- an unset or all-zero vote key means "no
    // voting keys", matching the check already used by
    // `validate_expired_online_accounts` above.
    let has_vote_key = prp.vote_id.is_some_and(|v| v != [0u8; 32]);
    if prp.status == AccountStatus::Offline && has_vote_key {
        prp.status = AccountStatus::Online;
    }
    store.set_account(&block.proposer, prp);

    Ok(())
}

/// Apply a block in Execute mode with EvalDelta comparison enabled.
///
/// Returns the collected comparison statistics alongside the apply result.
/// This is a convenience wrapper that enables stats collection, calls
/// `apply_block_with_mode(Execute)`, and extracts the stats afterward.
pub fn apply_block_with_comparison<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> (Result<(), AlgoError>, EvalDeltaStats) {
    // We need to set up stats before apply_block_with_mode runs, but that
    // function creates its own ApplyContext internally. To avoid duplicating
    // the entire function, we use a thread-local to pass stats through.
    EVAL_DELTA_STATS_SLOT.with(|slot| {
        *slot.borrow_mut() = Some(EvalDeltaStats::default());
    });

    let result = apply_block_with_mode(store, block, ApplyMode::Execute);

    let stats = EVAL_DELTA_STATS_SLOT.with(|slot| slot.borrow_mut().take().unwrap_or_default());

    (result, stats)
}

thread_local! {
    /// Thread-local slot for passing EvalDelta stats into the apply path.
    ///
    /// When `Some`, the AVM Execute path records comparison results here.
    /// Set by `apply_block_with_comparison`, consumed after apply completes.
    static EVAL_DELTA_STATS_SLOT: RefCell<Option<EvalDeltaStats>> = const { RefCell::new(None) };
}

/// Record an EvalDelta comparison result into the thread-local stats slot.
///
/// Called from the AVM Execute path in `apply_appl`. No-op if stats
/// collection is not active (i.e., called via `apply_block_with_mode`
/// directly rather than `apply_block_with_comparison`).
fn record_eval_delta_comparison(
    stx: &SignedTransaction,
    avm_result: &algo_avm::eval::AvmResult,
    round: u64,
    txn_index: usize,
    app_id: u64,
) {
    EVAL_DELTA_STATS_SLOT.with(|slot| {
        let mut guard = slot.borrow_mut();
        if let Some(ref mut stats) = *guard {
            // Parse the recorded EvalDelta from block data.
            let recorded = stx
                .eval_delta
                .as_ref()
                .and_then(|dt| parse_eval_delta(dt).ok());

            let cmp = compare_eval_delta(avm_result, recorded.as_ref(), stx);
            if cmp.matches {
                stats.record_match_with_coverage(&avm_result.coverage);
            } else {
                stats.record_mismatch_with_coverage(
                    EvalDeltaMismatchDetail {
                        round,
                        txn_index,
                        app_id,
                        mismatches: cmp.mismatches,
                    },
                    &avm_result.coverage,
                    MismatchCategory::SemanticMismatch,
                );
            }
        }
    });
}

/// Build the AVM group and group_index from optional `GroupInfo`.
///
/// When `group_info` is available (Execute mode with detected groups), the
/// full atomic group is cloned so that `gtxn`/`global GroupSize` opcodes
/// see the real group. When absent (Replay mode or standalone calls), falls
/// back to a single-element group with index 0.
fn build_avm_group(
    stx: &SignedTransaction,
    group_info: Option<&GroupInfo<'_>>,
) -> (Vec<SignedTransaction>, usize) {
    match group_info {
        Some(gi) => {
            let group: Vec<SignedTransaction> = gi.txns.iter().map(|s| (*s).clone()).collect();
            (group, gi.index)
        }
        None => (vec![stx.clone()], 0),
    }
}

/// Seed a freshly-built `LedgerAvmContext`'s scratch view from the group's
/// shared `ran_program`/`scratch` record, so `gload`/`gloads`/`gloadss` can
/// see which earlier siblings already ran a program and read back the real
/// per-slot values those siblings' `store`/`stores` wrote (issue #686;
/// mirrors go-algorand's `cx.pastScratch[cx.groupIndex] = &cx.Scratch`,
/// `data/transactions/logic/eval.go`, which is a live pointer into the
/// sibling's actual scratch space, not a placeholder). A sibling that never
/// ran (or hasn't executed yet) is left `None`, which `gload` reports as an
/// explicit error rather than a default/garbage value.
///
/// Gated on `ran_program` rather than `scratch` alone: `ran_program[idx]` is
/// set the instant that sibling's evaluation *starts* (matching
/// go-algorand's ordering), while `scratch[idx]` is only populated once
/// that evaluation *returns* a result. A sibling that started but hit a
/// hard pre-execution error (e.g. failed the program-version-ceiling
/// check) before producing an `AvmResult` -- practically unreachable in a
/// valid block, since such a transaction would fail validation before
/// reaching group apply -- still falls back to an all-zero row rather than
/// an erroring `None`, matching `cx.Scratch`'s zero-initialized state at
/// the point go-algorand sets the `pastScratch` pointer.
fn seed_avm_scratch_from_group<L: crate::store_trait::LedgerStore>(
    avm_ctx: &mut LedgerAvmContext<'_, L>,
    group_info: Option<&GroupInfo<'_>>,
) {
    if let Some(gi) = group_info {
        let ran = gi.ran_program.borrow();
        let recorded = gi.scratch.borrow();
        for idx in 0..avm_ctx.scratch.len().min(ran.len()) {
            if ran[idx] {
                avm_ctx.scratch[idx] = Some(
                    recorded[idx]
                        .clone()
                        .unwrap_or_else(crate::avm_context::default_scratch_row),
                );
            }
        }
    }
}

/// Mark the current group member as having started running its program, per
/// the shared `ran_program` record. Mirrors go-algorand's
/// `cx.pastScratch[cx.groupIndex] = &cx.Scratch` in `EvalContract`
/// (`data/transactions/logic/eval.go`), which is set the instant evaluation
/// begins -- before the program runs -- so a rejected or erroring program
/// still counts as "ran" for `gload` purposes; only a group member whose
/// program never actually starts (e.g. a ClearState call against an
/// already-deleted app, which has no clear-state program to run) stays
/// unmarked.
fn mark_group_member_ran(group_info: Option<&GroupInfo<'_>>) {
    if let Some(gi) = group_info {
        gi.ran_program.borrow_mut()[gi.index] = true;
    }
}

/// Record this group member's *real* final scratch space, once its program
/// has actually run (approved, rejected, or errored -- see `AvmResult::
/// scratch`'s doc for why all three cases still carry real data), so a
/// later sibling's `gload`/`gloads`/`gloadss` reads what this transaction
/// actually wrote via `store`/`stores` rather than a zero-filled
/// placeholder (issue #686). Call this immediately after the program run
/// that produced `result`, alongside `mark_group_member_ran` (which is
/// called *before* the run to match go-algorand's ordering).
fn record_group_member_scratch(group_info: Option<&GroupInfo<'_>>, scratch: &[TealValue; 256]) {
    if let Some(gi) = group_info {
        gi.scratch.borrow_mut()[gi.index] = Some(scratch.clone());
    }
}

/// Compute the fee credit and fee residue for a transaction group.
///
/// Mirrors go-algorand's `feeCredit(txgroup, proto) (credit MicroAlgos, residue
/// uint64)` (`data/transactions/logic/eval.go`, PR #6650 "Fees: Handle rounding
/// of fees with non-integral usage better"): usage-weights each group member
/// via `SummarizeFees` (`Transaction.feeFactor`, which is 0 for `stpf` and can
/// exceed one `MinTxnFee` for oversized notes/programs, unlike a flat per-txn
/// count) and rounds the required fee up via `FeeForUsage` with no incoming
/// residue (a top-level group always starts a fresh rounding sequence). The
/// returned residue seeds the group's inner-txn evaluation
/// (`ApplyContext::fee_residue` / `LedgerAvmContext::fee_residue`) so that
/// inner-txn groups round their aggregate fee up only once in concert with
/// the top-level group, rather than once per group.
pub(crate) fn compute_group_fee_credit_and_residue(
    group: &[&SignedTransaction],
    params: &ConsensusParams,
) -> (u64, u64) {
    let (usage, fees_paid) = algo_validate::summarize_fees(group, params);
    let (fee_needed, residue, _overflow) =
        algo_validate::fee_for_usage(params.min_txn_fee, usage, algo_validate::ONE_MICROS, 0);
    (fees_paid.saturating_sub(fee_needed), residue)
}

/// Detect transaction groups within a block's payset.
///
/// Consecutive transactions sharing the same non-empty `group` hash form an
/// atomic group. Transactions with an empty group hash are treated as their
/// own single-transaction group.
///
/// Safety: two distinct atomic groups cannot share the same group hash in a
/// valid block. The group ID is `SHA512/256("TG" || encode(TxGroup))` where
/// `TxGroup` contains the individual transaction hashes (each unique), so a
/// collision would require breaking SHA-512/256. Merging adjacent runs with
/// the same hash is therefore correct.
fn detect_transaction_groups(payset: &[SignedTransaction]) -> Vec<Vec<&SignedTransaction>> {
    let mut groups: Vec<Vec<&SignedTransaction>> = Vec::new();
    let mut i = 0;
    while i < payset.len() {
        let stx = &payset[i];
        if stx.txn.group == [0u8; 32] {
            // Standalone transaction.
            groups.push(vec![stx]);
            i += 1;
        } else {
            // Atomic group: collect consecutive transactions with the same group hash.
            let group_hash = &stx.txn.group;
            let mut group = vec![stx];
            i += 1;
            while i < payset.len() && payset[i].txn.group == *group_hash {
                group.push(&payset[i]);
                i += 1;
            }
            groups.push(group);
        }
    }
    groups
}

/// Information about the current transaction's group, used to provide correct
/// group context to AVM execution (gtxn opcodes, global GroupSize, etc.).
pub struct GroupInfo<'a> {
    /// All transactions in the atomic group.
    pub txns: &'a [&'a SignedTransaction],
    /// Index of the current transaction within the group.
    pub index: usize,
    /// Shared, group-wide record of which group members have actually
    /// invoked their approval/clear-state program so far (`ran_program[gi]`),
    /// mirroring go-algorand's per-group `pastScratch` population in
    /// `EvalContract` (`data/transactions/logic/eval.go`) -- set the instant
    /// a program starts running, even if it later rejects or errors, and
    /// left `false` for a group member whose program never actually ran
    /// (e.g. a ClearState call against an already-deleted app). Read by
    /// `apply_appl` to seed each subsequent sibling's `LedgerAvmContext`
    /// scratch view so `gload`/`gloads`/`gloadss` can distinguish "ran" from
    /// "never ran" instead of nil-dereferencing or returning a default value.
    pub ran_program: &'a RefCell<Vec<bool>>,
    /// Shared, group-wide record of each group member's *real* final
    /// scratch-space contents, once that member's program has run
    /// (`scratch[gi]`). Populated by `record_group_member_scratch`
    /// immediately after a group member's `run_approval_program`/
    /// `run_clear_state_program` call returns, and read by
    /// `seed_avm_scratch_from_group` to seed each subsequent sibling's
    /// `LedgerAvmContext::scratch` with the actual values earlier siblings
    /// wrote via `store`/`stores` -- not a zero-filled placeholder (issue
    /// #686). `None` until that index's program has run, matching
    /// `ran_program`.
    pub scratch: &'a RefCell<Vec<Option<[TealValue; 256]>>>,
}

/// Apply a single signed transaction with a group budget for AVM execution.
///
/// Same as `apply_transaction` but threads the group budget, group-scoped
/// box I/O budget (issue #727), and group info through to `apply_appl` for
/// Execute-mode pooled budget accounting.
#[allow(clippy::too_many_arguments)]
pub fn apply_transaction_with_budget<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
    group_box_budget: Option<&mut BoxBudgetState>,
    group_info: Option<&GroupInfo<'_>>,
    tracer: Option<&mut dyn EvalTracer>,
) -> Result<ApplyData, AlgoError> {
    apply_transaction_inner(
        store,
        stx,
        ctx,
        depth,
        group_budget,
        group_box_budget,
        group_info,
        tracer,
    )
}

/// Apply a single signed transaction to the ledger state.
///
/// Matches go-algorand's `applyTransaction` ordering:
/// 1. Snapshot touched accounts, then apply rewards.
/// 2. Handle rekey_to (before type-specific dispatch).
/// 3. Dispatch by transaction type (fee + type-specific logic).
/// 4. Debit rewards pool for any rewards distributed.
/// 5. Check min balance for all touched accounts.
///
/// On error, touched account data is restored to pre-reward state.
///
/// **Note:** This per-transaction API passes `None` for the group budget,
/// so each app call in Execute mode gets an isolated `GroupBudget(1)` (700
/// opcodes). For correct pooled-budget semantics across atomic groups, use
/// `apply_block()` which detects groups and threads a shared `GroupBudget`.
/// A public group-aware API (`apply_group()`) is planned for Epic 23 (#27).
pub fn apply_transaction<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
) -> Result<ApplyData, AlgoError> {
    apply_transaction_inner(store, stx, ctx, depth, None, None, None, None)
}

/// Apply a single signed transaction with an optional execution tracer.
///
/// Like [`apply_transaction`] but accepts an [`EvalTracer`] for capturing
/// opcode-level execution details (used by the simulation engine).
pub fn apply_transaction_with_tracer<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    tracer: &mut dyn EvalTracer,
) -> Result<ApplyData, AlgoError> {
    apply_transaction_inner(store, stx, ctx, depth, None, None, None, Some(tracer))
}

/// Core transaction application logic, shared by `apply_transaction`,
/// `apply_transaction_with_tracer`, and `apply_transaction_with_budget`.
#[allow(clippy::too_many_arguments)]
fn apply_transaction_inner<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
    group_box_budget: Option<&mut BoxBudgetState>,
    group_info: Option<&GroupInfo<'_>>,
    tracer: Option<&mut dyn EvalTracer>,
) -> Result<ApplyData, AlgoError> {
    let txn = &stx.txn;

    // State proof transactions are protocol-injected: no rewards, no fees,
    // no ledger state changes beyond the round-matching/crypto checks in
    // `apply_stateproof::apply_state_proof` (go's `apply.StateProof`,
    // `ledger/apply/stateproof.go:38`). See issue #626 -- this used to be an
    // unconditional no-op that accepted any state proof with zero
    // cryptographic verification.
    if txn.txn_type == "stpf" {
        return crate::apply_stateproof::apply_state_proof(store, ctx, txn);
    }

    // Convert lease bytes to [u8; 32] for lease table operations.
    let lease_arr: [u8; 32] = if txn.lease == [0u8; 32] {
        [0u8; 32]
    } else {
        <[u8; 32]>::try_from(txn.lease.as_ref()).map_err(|_| AlgoError::Ledger {
            message: format!("invalid lease length {}, expected 32", txn.lease.len()),
        })?
    };

    // Check lease before any state changes.
    store.check_lease(&txn.sender, &lease_arr, ctx.round)?;

    // Collect addresses for reward application (only actual transaction participants
    // per go-algorand: sender, receiver, close-to, asset participants, freeze target).
    let mut reward_addrs = Vec::with_capacity(6);
    reward_addrs.push(txn.sender);
    if !txn.receiver.is_zero() && txn.receiver != txn.sender {
        reward_addrs.push(txn.receiver);
    }
    if !txn.close_remainder_to.is_zero()
        && txn.close_remainder_to != txn.sender
        && txn.close_remainder_to != txn.receiver
    {
        reward_addrs.push(txn.close_remainder_to);
    }
    // Asset transfer: receiver, sender (clawback source), close-to.
    if let Some(ar) = txn.asset_receiver {
        if !ar.is_zero() && !reward_addrs.contains(&ar) {
            reward_addrs.push(ar);
        }
    }
    if let Some(asnd) = txn.asset_sender {
        if !asnd.is_zero() && !reward_addrs.contains(&asnd) {
            reward_addrs.push(asnd);
        }
    }
    if let Some(ac) = txn.asset_close_to {
        if !ac.is_zero() && !reward_addrs.contains(&ac) {
            reward_addrs.push(ac);
        }
    }
    // Asset freeze: target account.
    if let Some(fa) = txn.freeze_account {
        if !fa.is_zero() && !reward_addrs.contains(&fa) {
            reward_addrs.push(fa);
        }
    }

    // Extend with additional addresses needed for snapshot/rollback only
    // (these do NOT receive rewards — only transaction participants do).
    let mut touched = reward_addrs.clone();
    // Application accounts array: EvalDelta local deltas can mutate these.
    if let Some(ref accounts) = txn.accounts {
        for acct in accounts {
            if !acct.is_zero() && !touched.contains(acct) {
                touched.push(*acct);
            }
        }
    }
    // Heartbeat target address: heartbeat mutates the target account.
    if let Some(ref hb) = txn.heartbeat {
        if !hb.address.is_zero() && !touched.contains(&hb.address) {
            touched.push(hb.address);
        }
    }

    // Determine asset/app IDs to snapshot for rollback, and include
    // creator addresses that may differ from the transaction sender.
    let mut asset_ids_to_snap = Vec::new();
    let mut app_ids_to_snap = Vec::new();
    match txn.txn_type.as_str() {
        "acfg" => {
            if txn.config_asset != 0 {
                asset_ids_to_snap.push(txn.config_asset);
                // Snapshot the asset creator for destroy/reconfig rollback.
                if let Some(params) = store.get_asset_params(txn.config_asset) {
                    if !touched.contains(&params.creator) {
                        touched.push(params.creator);
                    }
                }
            }
            // For creates (config_asset == 0), snapshot the ID that apply_acfg
            // will derive (txn_counter + 1) so rollback can clean it up on failure.
            // Also snapshot apply_data_config_asset from block data if present.
            let derived_id = ctx.txn_counter.get() + 1;
            if txn.config_asset == 0 && derived_id != 0 {
                asset_ids_to_snap.push(derived_id);
            }
            if stx.apply_data_config_asset != 0
                && !asset_ids_to_snap.contains(&stx.apply_data_config_asset)
            {
                asset_ids_to_snap.push(stx.apply_data_config_asset);
            }
        }
        "axfer" => {
            if txn.xaid != 0 {
                asset_ids_to_snap.push(txn.xaid);
            }
        }
        "afrz" => {
            if txn.freeze_asset != 0 {
                asset_ids_to_snap.push(txn.freeze_asset);
            }
        }
        "appl" => {
            if txn.application_id != 0 {
                app_ids_to_snap.push(txn.application_id);
                // Snapshot the app creator for delete rollback.
                if let Some(params) = store.get_app_params(txn.application_id) {
                    if !touched.contains(&params.creator) {
                        touched.push(params.creator);
                    }
                }
            }
            if stx.apply_data_application_id != 0 {
                app_ids_to_snap.push(stx.apply_data_application_id);
            }
        }
        _ => {}
    }

    // Snapshot all accounts that may be mutated (touched + fee_sink + rewards_pool)
    // for rollback. The rewards pool must be included because it is debited for
    // distributed rewards, and a later min-balance check failure must restore it.
    let mut snapshot_addrs = touched.clone();
    if !snapshot_addrs.contains(&ctx.fee_sink) {
        snapshot_addrs.push(ctx.fee_sink);
    }
    {
        let rp = store.rewards_pool();
        if !snapshot_addrs.contains(&rp) {
            snapshot_addrs.push(rp);
        }
    }

    let snapshot = if asset_ids_to_snap.is_empty() && app_ids_to_snap.is_empty() {
        store.snapshot(&snapshot_addrs)
    } else {
        store.snapshot_with_ids(&snapshot_addrs, &asset_ids_to_snap, &app_ids_to_snap)
    };

    // The `appl` branch below re-borrows `tracer` per call via
    // `Option::as_deref_mut`, giving each `apply_appl` invocation its
    // own short-lived `Option<&mut dyn EvalTracer>` without aliasing.
    // The IIFE pattern remains so an early-return via `?` still triggers
    // the post-closure snapshot rollback. Resolves GH #209 — replaces
    // the previous `*mut dyn EvalTracer` round-trip with a fully-checked
    // borrow chain.

    // Execute all transaction logic in a helper so that ANY error
    // (fee, type-specific, EvalDelta, rewards-pool debit, rekey) returns
    // through `?` and we trigger a full rollback via `restore_snapshot`.
    // Pulling the body out of an IIFE (which it used to be) lets the
    // borrow checker see `tracer` as a normal function parameter, so the
    // appl branch can do a fresh `tracer.as_deref_mut()` per call without
    // the lifetime tangles a closure capture would create. Resolves
    // GH #209 — replaces the previous `*mut dyn EvalTracer` round-trip.
    let result = apply_transaction_inner_body(
        store,
        stx,
        ctx,
        depth,
        group_budget,
        group_box_budget,
        group_info,
        tracer,
        &reward_addrs,
        &snapshot_addrs,
        &lease_arr,
    );

    if result.is_err() {
        store.restore_snapshot(snapshot);
    }

    result
}

/// Body of `apply_transaction_inner` extracted into a helper so the
/// `?`-based control flow doesn't have to live inside an IIFE that
/// captured `tracer` and `store` simultaneously. The outer
/// `apply_transaction_inner` still owns the snapshot rollback path; this
/// helper is purely the work that needs rollback on error.
#[allow(clippy::too_many_arguments)]
fn apply_transaction_inner_body<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
    group_box_budget: Option<&mut BoxBudgetState>,
    group_info: Option<&GroupInfo<'_>>,
    mut tracer: Option<&mut dyn EvalTracer>,
    reward_addrs: &[Address],
    snapshot_addrs: &[Address],
    lease_arr: &[u8; 32],
) -> Result<ApplyData, AlgoError> {
    let txn = &stx.txn;
    {
        let mut apply_data = ApplyData::default();

        // Apply rewards to transaction participants only (not snapshot-only addresses).
        let mut total_rewards: u64 = 0;
        for addr in reward_addrs {
            let account_before = store.get_or_default_account(addr);
            let mut account = account_before.clone();
            let reward = apply_rewards(&mut account, ctx.rewards_level);
            total_rewards += reward;

            // UnfundedSenders (go-algorand v34+, `config/consensus.go`):
            // don't force a zero-balance account into on-disk existence
            // merely by bumping its RewardsBase, when this transaction
            // doesn't otherwise move algos through it. Mirrors go's
            // `roundCowState.Move` (`ledger/eval/eval.go`), whose
            // fee-payment call site (`cs.Move(tx.Sender, ep.Specials.FeeSink,
            // tx.Fee, ...)`, `ledger/eval/eval.go`) writes the sender's
            // updated account only if
            // `!amt.IsZero() || fromBal.RewardUnits(...) > 0 ||
            // !proto.UnfundedSenders`. Scoped here to the sender/fee case,
            // the one universally-applicable across every txn type (every
            // transaction's sender pays `txn.fee`, possibly zero under fee
            // pooling); other reward_addrs roles keep the unconditional
            // write.
            let skip_write = ctx.consensus.unfunded_senders
                && *addr == txn.sender
                && txn.fee == 0
                && account_before.micro_algos == 0
                && reward == 0;
            if !skip_write {
                store.set_account(addr, account);
            }

            // Track per-address rewards.
            if *addr == txn.sender {
                apply_data.sender_rewards += reward;
            } else if *addr == txn.receiver {
                apply_data.receiver_rewards += reward;
            } else if *addr == txn.close_remainder_to {
                apply_data.close_rewards += reward;
            }
        }

        // Handle rekey_to BEFORE type-specific apply (matching Go's ordering:
        // rewards -> rekey -> type-specific dispatch).
        if let Some(rekey_addr) = txn.rekey_to {
            let mut account = store.get_or_default_account(&txn.sender);
            if rekey_addr == txn.sender || rekey_addr.is_zero() {
                account.auth_addr = None;
            } else {
                account.auth_addr = Some(rekey_addr);
            }
            store.set_account(&txn.sender, account);
        }

        // Dispatch by transaction type and capture InnerApplyData.
        match txn.txn_type.as_str() {
            "pay" => {
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                let ad = apply_pay(store, &stx.txn)?;
                apply_data.closing_amount = ad.closing_amount;
            }
            "acfg" => {
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                let ad = apply_acfg(store, &stx.txn, ctx.txn_counter.get())?;
                apply_data.config_asset = ad.config_asset;
            }
            "axfer" => {
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                let ad = apply_axfer(store, &stx.txn)?;
                apply_data.asset_closing_amount = ad.asset_closing_amount;
            }
            "afrz" => {
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                apply_afrz(store, &stx.txn)?;
            }
            "appl" => {
                // Fresh re-borrow via explicit `match`-bound reborrow so
                // the inner `&mut dyn EvalTracer` has a local lifetime
                // the borrow checker accepts across `apply_appl`'s
                // elided lifetime.
                let tracer_ref: Option<&mut dyn EvalTracer> = match tracer {
                    Some(ref mut t) => Some(&mut **t),
                    None => None,
                };
                // Capture the app ID that will be created (txn_counter + 1)
                // before apply_appl runs, in case we need it for ApplyData.
                let pre_apply_counter = ctx.txn_counter.get();
                let executed_eval_delta = apply_appl(
                    store,
                    stx,
                    ctx,
                    depth,
                    group_budget,
                    group_box_budget,
                    group_info,
                    tracer_ref,
                )?;
                // For appl creates, capture the created application ID.
                if txn.application_id == 0 {
                    apply_data.application_id = if stx.apply_data_application_id != 0 {
                        stx.apply_data_application_id // Replay: from block data
                    } else {
                        pre_apply_counter + 1 // Execute: derived from txn_counter
                    };
                }
                // In Execute mode, record the AVM-produced eval delta (state
                // changes / logs / inner txns). Replay mode records the block's
                // recorded delta below.
                if ctx.mode == ApplyMode::Execute {
                    apply_data.eval_delta = executed_eval_delta;
                }
            }
            "keyreg" => {
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                apply_keyreg(store, &stx.txn, ctx.round, &ctx.consensus)?;
            }
            "hb" => {
                if !ctx.consensus.enable_heartbeat {
                    return Err(AlgoError::Ledger {
                        message: "heartbeat transaction not supported".to_string(),
                    });
                }
                apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;
                apply_heartbeat(store, &stx.txn, ctx.round, &ctx.consensus)?;
            }
            other => {
                return Err(AlgoError::Ledger {
                    message: format!("unknown transaction type: {}", other),
                });
            }
        }

        // Apply EvalDelta if present. For "appl" transactions, EvalDelta is
        // already applied inside apply_appl() before on_completion structural
        // changes, so we skip it here to avoid double-application.
        if txn.txn_type != "appl" {
            if let Some(ref dt) = stx.eval_delta {
                let delta = parse_eval_delta(dt)?;
                apply_eval_delta(stx, &delta, store, ctx, depth)?;
            }
        }

        // Capture EvalDelta in Replay mode (from block data).
        if ctx.mode == ApplyMode::Replay {
            apply_data.eval_delta = stx.eval_delta.clone();
        }

        // Debit rewards pool for distributed rewards.
        if total_rewards > 0 {
            let rewards_pool_addr = store.rewards_pool();
            let mut pool = store.get_or_default_account(&rewards_pool_addr);
            if pool.micro_algos < total_rewards {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "rewards pool balance {} insufficient for {} in rewards",
                        pool.micro_algos, total_rewards,
                    ),
                });
            }
            pool.micro_algos -= total_rewards;
            store.set_account(&rewards_pool_addr, pool);
        }

        // Check min balance for all touched accounts after the transaction.
        // Go checks all modified accounts per-transaction (skipping FeeSink,
        // RewardsPool, StateProofSender, and zeroed-out accounts).
        {
            let rewards_pool_addr = store.rewards_pool();
            for addr in snapshot_addrs {
                // Skip special accounts that are exempt from min balance checks.
                if *addr == ctx.fee_sink || *addr == rewards_pool_addr {
                    continue;
                }
                if let Some(account) = store.get_account(addr) {
                    // Zeroed-out accounts (will be deleted) are OK.
                    if account == algo_types::AccountData::default() {
                        continue;
                    }
                    let min_bal = store.min_balance_with_state(addr, &account);
                    if account.micro_algos < min_bal {
                        return Err(AlgoError::Ledger {
                            message: format!(
                                "account {} balance {} below minimum balance {}",
                                addr, account.micro_algos, min_bal,
                            ),
                        });
                    }
                }
            }
        }

        // Record lease on success (no-op for empty/zero leases).
        store.record_lease(&txn.sender, lease_arr, txn.last_valid.0);

        // Increment the running transaction counter for this top-level txn.
        // Mirrors go-algorand's `addTx` -> `incTxnCount()`. This ensures
        // creatable IDs from subsequent app calls use fresh counter values.
        ctx.txn_counter.set(ctx.txn_counter.get() + 1);

        // Set update_round on all touched accounts (including fee_sink).
        // This tracks which round last modified each account, used by the
        // Merkle trie V6 hash builder as affinity bytes.
        for addr in snapshot_addrs {
            // UnfundedSenders (v34+): the sender-specific skip-write above
            // (rewards loop, `apply_fee`) is only meaningful if this
            // bookkeeping pass doesn't independently force the same
            // zero-balance sender into existence just to record
            // `update_round`. Mirrors go's real update-round tracking,
            // which only ever touches an account that some other write
            // path actually persisted (`putAccount`) this round.
            if ctx.consensus.unfunded_senders
                && *addr == txn.sender
                && store.get_account(addr).is_none()
            {
                continue;
            }
            let mut account = store.get_or_default_account(addr);
            if account.update_round < ctx.round {
                account.update_round = ctx.round;
                store.set_account(addr, account);
            }
        }

        Ok(apply_data)
    }
}

/// Debit fee from sender and credit to fee_sink.
fn apply_fee<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    sender: &Address,
    fee: u64,
    fee_sink: &Address,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let sender_account_before = store.get_or_default_account(sender);
    if sender_account_before.micro_algos < fee {
        return Err(AlgoError::Ledger {
            message: format!(
                "sender {} has insufficient balance {} for fee {}",
                sender, sender_account_before.micro_algos, fee,
            ),
        });
    }
    let mut sender_account = sender_account_before.clone();
    sender_account.micro_algos -= fee;
    // UnfundedSenders (go-algorand v34+, `config/consensus.go`): mirrors
    // go's `roundCowState.Move` (`ledger/eval/eval.go`) fee-payment call
    // site (`cs.Move(tx.Sender, ep.Specials.FeeSink, tx.Fee, ...)`,
    // `ledger/eval/eval.go`), which writes the sender's updated account only
    // if `!amt.IsZero() || fromBal.RewardUnits(...) > 0 || !proto.
    // UnfundedSenders`. A zero-fee transaction from a genuinely
    // zero-balance sender must not be forced into on-disk existence by
    // this fee no-op write. Before v34, the write always happens.
    let skip_write =
        consensus.unfunded_senders && fee == 0 && sender_account_before.micro_algos == 0;
    if !skip_write {
        store.set_account(sender, sender_account);
    }

    let mut fee_sink_account = store.get_or_default_account(fee_sink);
    fee_sink_account.micro_algos += fee;
    store.set_account(fee_sink, fee_sink_account);

    Ok(())
}

/// Apply a payment transaction (core state mutation only).
///
/// Debits `amount` from sender, credits `amount` to receiver.
/// If `close_remainder_to` is set, moves the sender's remaining balance
/// to that address and zeros the account.
///
/// Does NOT debit fees — the caller handles fee application separately.
/// Returns `InnerApplyData` with `closing_amount` populated when applicable.
///
/// Used by both outer dispatch (after `apply_fee`) and inner transaction dispatch.
pub fn apply_pay<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
) -> Result<InnerApplyData, AlgoError> {
    let mut ad = InnerApplyData::default();

    // Transfer amount from sender to receiver.
    if txn.amount > 0 || !txn.receiver.is_zero() {
        let mut sender = store.get_or_default_account(&txn.sender);
        if sender.micro_algos < txn.amount {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} has insufficient balance {} for payment {}",
                    txn.sender, sender.micro_algos, txn.amount,
                ),
            });
        }
        sender.micro_algos -= txn.amount;
        store.set_account(&txn.sender, sender);

        if txn.amount > 0 {
            let mut receiver = store.get_or_default_account(&txn.receiver);
            receiver.micro_algos += txn.amount;
            store.set_account(&txn.receiver, receiver);
        }
    }

    // Handle close_remainder_to.
    if !txn.close_remainder_to.is_zero() {
        let sender = store.get_or_default_account(&txn.sender);

        let close_amount = sender.micro_algos;
        ad.closing_amount = close_amount;

        // Cannot close account with opted-in or created assets/apps.
        if sender.total_assets_opted_in > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} opted-in assets",
                    txn.sender, sender.total_assets_opted_in,
                ),
            });
        }
        if sender.total_created_assets > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} created assets",
                    txn.sender, sender.total_created_assets,
                ),
            });
        }
        if sender.total_apps_opted_in > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} opted-in apps",
                    txn.sender, sender.total_apps_opted_in,
                ),
            });
        }
        if sender.total_created_apps > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} created apps",
                    txn.sender, sender.total_created_apps,
                ),
            });
        }
        if sender.total_boxes > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} outstanding boxes",
                    txn.sender, sender.total_boxes,
                ),
            });
        }
        if sender.total_box_bytes > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} outstanding box bytes",
                    txn.sender, sender.total_box_bytes,
                ),
            });
        }

        // Go calls CloseAccount() which zeros the entire account record.
        // Reset to default to match that behavior.
        store.set_account(&txn.sender, algo_types::AccountData::default());

        // Credit close-to address.
        if close_amount > 0 {
            let mut close_to = store.get_or_default_account(&txn.close_remainder_to);
            close_to.micro_algos += close_amount;
            store.set_account(&txn.close_remainder_to, close_to);
        }
    }

    Ok(ad)
}

/// Apply an asset config transaction (core state mutation only).
///
/// Handles asset creation (config_asset == 0), reconfiguration, and destruction.
/// For creation, `txn_counter` is used to derive the new asset ID (txn_counter + 1),
/// matching go-algorand's `AssetConfig` function.
/// Does NOT debit fees — the outer dispatch handles fee application.
/// Callable by both outer and inner transaction paths.
///
/// Returns `InnerApplyData` with `config_asset` populated on create.
pub fn apply_acfg<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
    txn_counter: u64,
) -> Result<InnerApplyData, AlgoError> {
    let mut ad = InnerApplyData::default();

    if txn.config_asset == 0 {
        // ── Create ──
        let new_asset_id = txn_counter + 1;

        let txn_params = txn.asset_params.as_ref().cloned().unwrap_or_default();
        let total = txn_params.total;

        let record = AssetParamsRecord {
            params: txn_params,
            creator: txn.sender,
        };
        store.set_asset_params(new_asset_id, record);

        // Creator gets the full supply and an opt-in holding.
        store.set_asset_holding(
            &txn.sender,
            new_asset_id,
            AssetHolding {
                amount: total,
                frozen: false,
            },
        );

        let mut sender_account = store.get_or_default_account(&txn.sender);
        sender_account.total_created_assets += 1;
        sender_account.total_assets_opted_in += 1;
        store.set_account(&txn.sender, sender_account);

        ad.config_asset = new_asset_id;
    } else {
        // ── Reconfigure or Destroy ──
        let asset_id = txn.config_asset;
        let existing = store
            .get_asset_params(asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("acfg: asset {} does not exist", asset_id),
            })?;

        // Sender must be the manager.
        let existing_manager = existing.params.manager.unwrap_or(Address::ZERO);
        if existing_manager.is_zero() || txn.sender != existing_manager {
            return Err(AlgoError::Ledger {
                message: format!(
                    "acfg: sender {} is not the manager of asset {}",
                    txn.sender, asset_id,
                ),
            });
        }

        let creator = existing.creator;
        let txn_params = txn.asset_params.as_ref().cloned().unwrap_or_default();

        if txn_params == AssetParams::default() {
            // ── Destroy ──
            // Verify creator holds full supply.
            let holding =
                store
                    .get_asset_holding(&creator, asset_id)
                    .ok_or_else(|| AlgoError::Ledger {
                        message: format!(
                            "acfg destroy: creator {} has no holding for asset {}",
                            creator, asset_id,
                        ),
                    })?;
            let params_total = existing.params.total;
            if holding.amount != params_total {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "acfg destroy: creator holds {} but total supply is {} for asset {}",
                        holding.amount, params_total, asset_id,
                    ),
                });
            }

            // Remove asset params and creator holding.
            // NOTE: This intentionally does NOT remove other accounts' zero-balance
            // holdings for this asset. In go-algorand, asset destruction only removes
            // the creator's holding and the asset params. Other opted-in accounts with
            // zero balance keep their stale holdings — they must explicitly close-out
            // via an axfer with asset_close_to to reclaim their min-balance.
            store.remove_asset_params(asset_id);
            store.remove_asset_holding(&creator, asset_id);

            let mut creator_account = store.get_or_default_account(&creator);
            creator_account.total_created_assets =
                creator_account.total_created_assets.saturating_sub(1);
            creator_account.total_assets_opted_in =
                creator_account.total_assets_opted_in.saturating_sub(1);
            store.set_account(&creator, creator_account);
        } else {
            // ── Reconfigure ──
            let mut updated_params = existing.params.clone();

            // Only update a role when the existing on-chain role is non-zero
            // AND the transaction explicitly set the field (is_some()).
            // In go-algorand, unset inner txn fields are zero-valued Address{},
            // but Rust uses Option<Address> where None = "not set via itxn_field".
            // The is_some() guard prevents None from clearing existing roles.
            // For outer transactions, all fields are always Some(...), so the
            // guard is transparent.
            if updated_params.manager.is_some_and(|a| !a.is_zero()) && txn_params.manager.is_some()
            {
                updated_params.manager = txn_params.manager;
            }
            if updated_params.reserve.is_some_and(|a| !a.is_zero()) && txn_params.reserve.is_some()
            {
                updated_params.reserve = txn_params.reserve;
            }
            if updated_params.freeze.is_some_and(|a| !a.is_zero()) && txn_params.freeze.is_some() {
                updated_params.freeze = txn_params.freeze;
            }
            if updated_params.clawback.is_some_and(|a| !a.is_zero())
                && txn_params.clawback.is_some()
            {
                updated_params.clawback = txn_params.clawback;
            }

            let mut record = existing;
            record.params = updated_params;
            store.set_asset_params(asset_id, record);
        }
    }

    Ok(ad)
}

/// Apply an asset transfer transaction (core state mutation only).
///
/// Handles opt-in, transfer (including clawback), and close-to paths.
/// Does NOT debit fees — the outer dispatch handles fee application.
/// Callable by both outer and inner transaction paths.
///
/// Returns `InnerApplyData` with `asset_closing_amount` populated when
/// a close-to address is present.
pub fn apply_axfer<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
) -> Result<InnerApplyData, AlgoError> {
    let mut ad = InnerApplyData::default();

    let asset_id = txn.xaid;
    if asset_id == 0 {
        return Err(AlgoError::Ledger {
            message: "axfer: asset ID (xaid) is zero".to_string(),
        });
    }

    let asset_receiver = txn.asset_receiver.ok_or_else(|| AlgoError::Ledger {
        message: "axfer: asset_receiver (arcv) is missing".to_string(),
    })?;

    let clawback_source = txn.asset_sender.filter(|a| !a.is_zero());
    let from_addr = clawback_source.unwrap_or(txn.sender);
    let is_clawback = clawback_source.is_some();

    // ── Clawback authorization ──
    // go-algorand checks clawback auth before anything else when AssetSender is set.
    if is_clawback {
        let params = store
            .get_asset_params(asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("axfer: asset {} does not exist", asset_id),
            })?;
        let clawback = params.params.clawback.unwrap_or(Address::ZERO);
        if txn.sender != clawback {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer clawback: sender {} is not the clawback address for asset {}",
                    txn.sender, asset_id,
                ),
            });
        }
    }

    // ── Opt-in detection ──
    // Matches go-algorand: `ct.AssetReceiver == source && ct.AssetAmount == 0 && !clawback`
    // where `source` is `from_addr` (clawback_source or txn.sender). Since opt-in
    // requires `!is_clawback`, `from_addr == txn.sender` in the opt-in path.
    // go-algorand does NOT check AssetCloseTo here — close-to is handled independently.
    let is_optin = asset_receiver == from_addr && txn.asset_amount == 0 && !is_clawback;

    // If already opted in, this is a no-op (matching go-algorand).
    if is_optin && !store.has_asset_holding(&from_addr, asset_id) {
        let params = store
            .get_asset_params(asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("axfer opt-in: asset {} does not exist", asset_id),
            })?;
        let default_frozen = params.params.default_frozen;
        store.set_asset_holding(
            &from_addr,
            asset_id,
            AssetHolding {
                amount: 0,
                frozen: default_frozen,
            },
        );
        let mut account = store.get_or_default_account(&from_addr);
        account.total_assets_opted_in += 1;
        store.set_account(&from_addr, account);
    }

    // ── Transfer ──
    // go-algorand always runs takeOut/putIn after opt-in (they short-circuit on amount==0).
    // Frozen checks and balance checks happen inside takeOut/putIn when amount > 0.
    if txn.asset_amount > 0 {
        // takeOut: debit from source
        let mut from_holding = store
            .get_asset_holding(&from_addr, asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("axfer: {} has no holding for asset {}", from_addr, asset_id),
            })?;
        if from_holding.frozen && !is_clawback {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer: {} holding for asset {} is frozen",
                    from_addr, asset_id,
                ),
            });
        }
        if from_holding.amount < txn.asset_amount {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer: {} holding {} insufficient for transfer {} of asset {}",
                    from_addr, from_holding.amount, txn.asset_amount, asset_id,
                ),
            });
        }
        from_holding.amount -= txn.asset_amount;
        store.set_asset_holding(&from_addr, asset_id, from_holding);

        // putIn: credit receiver
        let mut recv_holding = store
            .get_asset_holding(&asset_receiver, asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!(
                    "axfer: receiver {} has no holding for asset {} (not opted in)",
                    asset_receiver, asset_id,
                ),
            })?;
        if recv_holding.frozen && !is_clawback {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer: receiver {} holding for asset {} is frozen",
                    asset_receiver, asset_id,
                ),
            });
        }
        recv_holding.amount += txn.asset_amount;
        store.set_asset_holding(&asset_receiver, asset_id, recv_holding);
    }

    // ── Close-to ──
    if let Some(close_to) = txn.asset_close_to {
        if !close_to.is_zero() {
            // Cannot close by clawback (go-algorand: "cannot close asset by clawback").
            if is_clawback {
                return Err(AlgoError::Ledger {
                    message: format!("axfer: cannot close asset by clawback (asset {})", asset_id,),
                });
            }

            let close_from = from_addr;

            // The creator of the asset cannot close their holding.
            // go-algorand: HasAssetParams(source, ct.XferAsset) -> "cannot close asset ID in allocating account"
            // Also determine bypass_freeze: allowed when closing to the asset creator.
            let bypass_freeze = if let Some(params_record) = store.get_asset_params(asset_id) {
                if params_record.creator == close_from {
                    return Err(AlgoError::Ledger {
                        message: "cannot close asset ID in allocating account".to_string(),
                    });
                }
                params_record.creator == close_to
            } else {
                false
            };

            let from_holding = store
                .get_asset_holding(&close_from, asset_id)
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!(
                        "axfer close: {} has no holding for asset {}",
                        close_from, asset_id,
                    ),
                })?;
            let remaining = from_holding.amount;
            ad.asset_closing_amount = remaining;

            // Check frozen on the sender's holding (unless bypassed).
            if from_holding.frozen && !bypass_freeze {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "axfer close: {} holding for asset {} is frozen",
                        close_from, asset_id,
                    ),
                });
            }

            if remaining > 0 {
                // Check frozen on close-to's holding (unless bypassed).
                let mut close_holding =
                    store
                        .get_asset_holding(&close_to, asset_id)
                        .ok_or_else(|| AlgoError::Ledger {
                            message: format!(
                                "axfer close: {} has no holding for asset {} (not opted in)",
                                close_to, asset_id,
                            ),
                        })?;
                if close_holding.frozen && !bypass_freeze {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "axfer close: receiver {} holding for asset {} is frozen",
                            close_to, asset_id,
                        ),
                    });
                }
                close_holding.amount += remaining;
                store.set_asset_holding(&close_to, asset_id, close_holding);
            }

            // Remove sender holding.
            store.remove_asset_holding(&close_from, asset_id);

            let mut account = store.get_or_default_account(&close_from);
            account.total_assets_opted_in = account.total_assets_opted_in.saturating_sub(1);
            store.set_account(&close_from, account);
        }
    }

    Ok(ad)
}

/// Apply an asset freeze transaction (core state mutation only).
///
/// Freezes or unfreezes an asset holding for the target account.
/// Does NOT debit fees — the outer dispatch handles fee application.
/// Callable by both outer and inner transaction paths.
pub fn apply_afrz<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
) -> Result<InnerApplyData, AlgoError> {
    let asset_id = txn.freeze_asset;
    if asset_id == 0 {
        return Err(AlgoError::Ledger {
            message: "afrz: freeze asset ID (faid) is zero".to_string(),
        });
    }

    // Look up asset params to verify sender is the freeze address.
    let params = store
        .get_asset_params(asset_id)
        .ok_or_else(|| AlgoError::Ledger {
            message: format!("afrz: asset {} does not exist", asset_id),
        })?;
    let freeze_addr = params.params.freeze.unwrap_or(Address::ZERO);
    if freeze_addr.is_zero() || txn.sender != freeze_addr {
        return Err(AlgoError::Ledger {
            message: format!(
                "afrz: sender {} is not the freeze address for asset {}",
                txn.sender, asset_id,
            ),
        });
    }

    let target = txn.freeze_account.ok_or_else(|| AlgoError::Ledger {
        message: "afrz: freeze_account (fadd) is missing".to_string(),
    })?;

    let mut holding =
        store
            .get_asset_holding(&target, asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("afrz: {} has no holding for asset {}", target, asset_id,),
            })?;
    holding.frozen = txn.asset_frozen;
    store.set_asset_holding(&target, asset_id, holding);

    Ok(InnerApplyData::default())
}

/// On-completion action constants for application calls.
pub(crate) const ON_COMPLETION_NOOP: u64 = 0;
pub(crate) const ON_COMPLETION_OPT_IN: u64 = 1;
pub(crate) const ON_COMPLETION_CLOSE_OUT: u64 = 2;
pub(crate) const ON_COMPLETION_CLEAR_STATE: u64 = 3;
pub(crate) const ON_COMPLETION_UPDATE: u64 = 4;
pub(crate) const ON_COMPLETION_DELETE: u64 = 5;

/// Compute SHA-512/256 hash of program bytes for AVM context.
pub(crate) fn program_hash(program: &[u8]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update(program);
    h.finalize().into()
}

/// Discriminates the error context for shared application call helpers.
///
/// Used by shared helpers to produce `AlgoError::Ledger` (outer transactions)
/// or `AlgoError::Avm` (inner transactions) as appropriate.
#[derive(Clone, Copy)]
pub(crate) enum ApplErrorContext {
    Outer,
    Inner,
}

impl ApplErrorContext {
    /// Create an `AlgoError` with the appropriate variant for this context.
    #[inline]
    fn error(&self, message: String) -> AlgoError {
        match self {
            ApplErrorContext::Outer => AlgoError::Ledger { message },
            ApplErrorContext::Inner => AlgoError::Avm { message },
        }
    }

    /// Prefix for error messages.
    #[inline]
    fn prefix(&self) -> &'static str {
        match self {
            ApplErrorContext::Outer => "appl",
            ApplErrorContext::Inner => "inner appl",
        }
    }
}

/// Create a new application in the store.
///
/// Writes `AppParams`, increments the creator's counters, and returns the
/// created `app_id`. The caller provides `app_id` directly — outer callers
/// pass `stx.apply_data_application_id`, inner callers pass `txn_counter + 1`.
pub(crate) fn create_application<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
    app_id: u64,
    err_ctx: ApplErrorContext,
) -> Result<(), AlgoError> {
    if app_id == 0 {
        return Err(err_ctx.error(format!(
            "{} create: application id is zero",
            err_ctx.prefix()
        )));
    }

    let approval = txn
        .approval_program
        .as_ref()
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let clear = txn
        .clear_state_program
        .as_ref()
        .map(|b| b.to_vec())
        .unwrap_or_default();

    let global_schema = txn.global_state_schema.clone().unwrap_or_default();
    let local_schema = txn.local_state_schema.clone().unwrap_or_default();
    let extra_pages = txn.extra_program_pages;

    store.set_app_params(
        app_id,
        AppParams {
            creator: txn.sender,
            approval_program: approval,
            clear_state_program: clear,
            global_state: std::collections::BTreeMap::new(),
            local_state_schema: local_schema,
            global_state_schema: global_schema.clone(),
            extra_program_pages: extra_pages,

            ..Default::default()
        },
    );

    let mut sender_account = store.get_or_default_account(&txn.sender);
    sender_account.total_created_apps += 1;
    sender_account.total_extra_app_pages += extra_pages;
    // Update aggregate schema: creator stores global state.
    sender_account.total_app_schema = sender_account.total_app_schema.add_schema(&global_schema);
    store.set_account(&txn.sender, sender_account);

    Ok(())
}

/// Pre-program opt-in: create local state before running the called app's program.
///
/// Used by the inner transaction path where opt-in happens before program execution
/// (matching go-algorand's `optInApplication` called before `StatefulEval`).
/// Rejects duplicate opt-in.
pub(crate) fn apply_appl_opt_in_pre_program<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    sender: &Address,
    app_id: u64,
    err_ctx: ApplErrorContext,
) -> Result<(), AlgoError> {
    if store.has_app_local_state(sender, app_id) {
        return Err(err_ctx.error(format!(
            "{} opt-in: {} is already opted into app {}",
            err_ctx.prefix(),
            sender,
            app_id,
        )));
    }
    let app = store.get_app_params(app_id).ok_or_else(|| {
        err_ctx.error(format!(
            "{} opt-in: app {} not found",
            err_ctx.prefix(),
            app_id
        ))
    })?;
    let local = AppLocalState {
        schema: app.local_state_schema.clone(),
        key_value: std::collections::BTreeMap::new(),
    };
    store.set_app_local_state(sender, app_id, local);

    // Update account counters.
    let mut acct = store.get_or_default_account(sender);
    acct.total_apps_opted_in += 1;
    acct.total_app_schema = acct.total_app_schema.add_schema(&app.local_state_schema);
    store.set_account(sender, acct);

    Ok(())
}

/// Apply on-completion side effects after program execution.
///
/// Handles NoOp, OptIn (post-program, outer path only — `had_local_state` + `is_create`
/// semantics), CloseOut, ClearState, Delete, and Update.
///
/// For ClearState, local state is required (the caller must have already
/// verified the sender is opted in). This matches go-algorand's
/// `closeOutApplication`, which errors if local state is absent.
pub(crate) fn apply_appl_on_completion<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
    app_id: u64,
    err_ctx: ApplErrorContext,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    match txn.on_completion {
        ON_COMPLETION_NOOP => {
            // NoOp — no structural state changes.
        }
        ON_COMPLETION_OPT_IN => {
            // OptIn — already handled before program execution (inner path)
            // or handled separately by outer path's `had_local_state` logic.
            // Nothing to do here.
        }
        ON_COMPLETION_CLOSE_OUT => {
            let local_state = store
                .get_app_local_state(&txn.sender, app_id)
                .ok_or_else(|| {
                    err_ctx.error(format!(
                        "{} close-out: {} is not opted into app {}",
                        err_ctx.prefix(),
                        txn.sender,
                        app_id,
                    ))
                })?;
            let local_schema = local_state.schema.clone();
            store.remove_app_local_state(&txn.sender, app_id);
            let mut sender_account = store.get_or_default_account(&txn.sender);
            sender_account.total_apps_opted_in =
                sender_account.total_apps_opted_in.saturating_sub(1);
            sender_account.total_app_schema =
                sender_account.total_app_schema.sub_schema(&local_schema);
            store.set_account(&txn.sender, sender_account);
        }
        ON_COMPLETION_CLEAR_STATE => {
            // ClearState removes local state. The caller must have already
            // verified that the sender is opted in (has local state) before
            // reaching this point, matching go-algorand's closeOutApplication.
            let local_state = store
                .get_app_local_state(&txn.sender, app_id)
                .ok_or_else(|| {
                    err_ctx.error(format!(
                        "{} clear-state: {} is not opted into app {}",
                        err_ctx.prefix(),
                        txn.sender,
                        app_id,
                    ))
                })?;
            let local_schema = local_state.schema.clone();
            store.remove_app_local_state(&txn.sender, app_id);
            let mut sender_account = store.get_or_default_account(&txn.sender);
            sender_account.total_apps_opted_in =
                sender_account.total_apps_opted_in.saturating_sub(1);
            sender_account.total_app_schema =
                sender_account.total_app_schema.sub_schema(&local_schema);
            store.set_account(&txn.sender, sender_account);
        }
        ON_COMPLETION_DELETE => {
            if let Some(existing) = store.get_app_params(app_id) {
                if txn.sender != existing.creator {
                    return Err(err_ctx.error(format!(
                        "{} delete: sender {} is not the creator of app {}",
                        err_ctx.prefix(),
                        txn.sender,
                        app_id,
                    )));
                }
                let creator = existing.creator;
                let global_schema = existing.global_state_schema.clone();
                store.remove_app_params(app_id);
                let mut creator_account = store.get_or_default_account(&creator);
                creator_account.total_created_apps =
                    creator_account.total_created_apps.saturating_sub(1);
                creator_account.total_extra_app_pages = creator_account
                    .total_extra_app_pages
                    .saturating_sub(existing.extra_program_pages);
                creator_account.total_app_schema =
                    creator_account.total_app_schema.sub_schema(&global_schema);
                store.set_account(&creator, creator_account);
            }
        }
        ON_COMPLETION_UPDATE => {
            if let Some(mut app) = store.get_app_params(app_id) {
                if txn.sender != app.creator {
                    return Err(err_ctx.error(format!(
                        "{} update: sender {} is not the creator of app {}",
                        err_ctx.prefix(),
                        txn.sender,
                        app_id,
                    )));
                }
                if let Some(ref approval) = txn.approval_program {
                    app.approval_program = approval.to_vec();
                }
                if let Some(ref clear) = txn.clear_state_program {
                    app.clear_state_program = clear.to_vec();
                }
                // go-algorand `ledger/apply/application.go`'s `updateApplication`:
                // `if proto.EnableAppVersioning { params.Version++ }`.
                if consensus.enable_app_versioning {
                    app.version += 1;
                }
                store.set_app_params(app_id, app);
            }
        }
        other => {
            return Err(err_ctx.error(format!(
                "{}: unknown on_completion value {}",
                err_ctx.prefix(),
                other,
            )));
        }
    }

    Ok(())
}

/// Apply an application call transaction.
///
/// Handles creation, opt-in, close-out, clear-state, update, delete, and no-op.
/// EvalDelta is applied BEFORE the on_completion structural changes (matching
/// go-algorand ordering): TEAL executes first (writing state via EvalDelta),
/// then the runtime performs close-out/delete cleanup. This prevents EvalDelta's
/// `or_insert_with` calls from recreating entries that close-out/delete removed.
///
/// In `Execute` mode, the AVM programs are run to produce state changes
/// directly. In `Replay` mode, the recorded EvalDelta from the block is used.
/// The optional `group_budget` and `group_box_budget` are consumed only in
/// `Execute` mode. `group_box_budget` (issue #727) carries the box I/O
/// budget state (`io_budget`/`dirty_bytes`/`update_bytes`/
/// `read_budget_checked`/`available_boxes`/`boxes_initialized`) across every
/// top-level `appl` call in the same atomic group, mirroring go-algorand's
/// single shared `EvalParams` pointer (`ledger/eval/eval.go:1090`) -- the
/// same role `group_budget` already plays for pooled opcode-cost budget.
#[allow(clippy::too_many_arguments)]
fn apply_appl<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
    mut group_box_budget: Option<&mut BoxBudgetState>,
    group_info: Option<&GroupInfo<'_>>,
    mut tracer: Option<&mut dyn EvalTracer>,
) -> Result<Option<rmpv::Value>, AlgoError> {
    let txn = &stx.txn;

    // EvalDelta (state changes / logs / inner txns) encoded from the AVM result
    // in Execute mode, for the caller to record in ApplyData. `None` in Replay
    // mode (the caller uses the block's recorded delta instead).
    let mut captured_eval_delta: Option<rmpv::Value> = None;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink, &ctx.consensus)?;

    let is_create = txn.application_id == 0;
    let app_id = if is_create {
        // In Replay mode, use the recorded ID from block data.
        // In Execute mode (simulation), derive from txn_counter
        // (matching inner transaction create behavior).
        if stx.apply_data_application_id != 0 {
            stx.apply_data_application_id
        } else {
            ctx.txn_counter.get() + 1
        }
    } else {
        txn.application_id
    };

    // For non-create calls, verify the app exists in state.
    // Exception: ClearState always succeeds even if app is deleted (lets users reclaim local state).
    if !is_create && txn.on_completion != ON_COMPLETION_CLEAR_STATE && !store.has_app_params(app_id)
    {
        return Err(AlgoError::Ledger {
            message: format!("appl: app {} does not exist", app_id),
        });
    }

    if is_create {
        create_application(store, txn, app_id, ApplErrorContext::Outer)?;
        // During simulation with state-change tracing, apps created
        // mid-simulation are excluded from initial-state capture (they have no
        // pre-existing on-chain state). No-op when no tracer is attached, so the
        // consensus apply path is unaffected. Mirrors go-algorand's
        // `tracer.go` `CreatedApp` population on app-create calls.
        if let Some(ref mut t) = tracer {
            t.record_created_app(app_id);
        }
    }

    // ClearState requires the sender to be opted in (have local state).
    // go-algorand checks this BEFORE running the clear-state program.
    if txn.on_completion == ON_COMPLETION_CLEAR_STATE
        && !store.has_app_local_state(&txn.sender, app_id)
    {
        return Err(AlgoError::Ledger {
            message: format!(
                "cannot clear state: {} is not currently opted in to app {}",
                txn.sender, app_id,
            ),
        });
    }

    // Record whether local state exists BEFORE EvalDelta, so the OptIn branch
    // can correctly detect a new opt-in even if EvalDelta creates a placeholder entry.
    // Only needed in Replay mode; Execute mode handles opt-in pre-program.
    let had_local_state = if ctx.mode == ApplyMode::Replay {
        store.has_app_local_state(&txn.sender, app_id)
    } else {
        false
    };

    // EvalDelta sourcing: Replay uses recorded block data, Execute runs AVM.
    match ctx.mode {
        ApplyMode::Replay => {
            // Apply EvalDelta BEFORE on_completion structural changes (matching go-algorand).
            // TEAL executes first (writing global/local state), then the runtime performs
            // structural close-out/delete. This ordering prevents EvalDelta from recreating
            // entries that close-out or delete would remove.
            if let Some(ref dt) = stx.eval_delta {
                let delta = parse_eval_delta(dt)?;
                apply_eval_delta(stx, &delta, store, ctx, depth)?;
            }
        }
        ApplyMode::Execute => {
            // Look up app params to get the program bytes.
            let app_params = store.get_app_params(app_id);
            let creator = app_params
                .as_ref()
                .map(|p| p.creator.0)
                .unwrap_or([0u8; 32]);

            if txn.on_completion == ON_COMPLETION_CLEAR_STATE {
                // ClearState: run clear-state program with isolated budget.
                // If program rejects or errors, roll back any store mutations
                // made during AVM execution (IsolateClearState semantics), then
                // proceed to the on-completion branch which clears local state.
                let clear_program = app_params
                    .map(|p| p.clear_state_program.clone())
                    .unwrap_or_default();

                if !clear_program.is_empty() {
                    let ph = program_hash(&clear_program);

                    // Snapshot store BEFORE AVM execution so we can roll back
                    // any state mutations if the program rejects/errors.
                    // We snapshot the sender, any accounts in the txn's accounts
                    // array, and the app's global state (via app_ids).
                    let mut cs_addrs = vec![txn.sender];
                    if let Some(ref accounts) = txn.accounts {
                        for acct in accounts {
                            if !acct.is_zero() && !cs_addrs.contains(acct) {
                                cs_addrs.push(*acct);
                            }
                        }
                    }
                    let cs_snapshot = store.snapshot_with_ids(&cs_addrs, &[], &[app_id]);

                    let (avm_group, avm_group_index) = build_avm_group(stx, group_info);
                    let mut avm_ctx = LedgerAvmContext::new(
                        store,
                        avm_group,
                        avm_group_index,
                        ctx.round,
                        ctx.latest_timestamp,
                        app_id,
                        creator,
                        true, // app_mode
                        ph,
                        ctx.genesis_hash,
                        ctx.consensus.clone(),
                    );
                    avm_ctx.fee_sink = ctx.fee_sink;
                    avm_ctx.txn_counter = ctx.txn_counter.get();
                    avm_ctx.fee_credit = ctx.fee_credit.get();
                    avm_ctx.fee_residue = ctx.fee_residue.get();
                    ctx.configure_avm_ctx(&mut avm_ctx);
                    seed_avm_scratch_from_group(&mut avm_ctx, group_info);
                    if let Some(ref mut t) = tracer {
                        avm_ctx.tracer_ptr = Some(*t as *mut dyn EvalTracer);
                    }
                    // Seed box I/O budget state from the group-scoped carrier
                    // (issue #727): a prior sibling top-level app call in
                    // this same atomic group may already have computed
                    // `io_budget`/checked the read budget/accumulated
                    // `dirty_bytes` -- go-algorand shares this state by
                    // pointer across the whole group's `EvalParams`
                    // (`ledger/eval/eval.go:1090`), not just within one
                    // call's own inner-txn tree.
                    if let Some(ref gbb) = group_box_budget {
                        avm_ctx.load_box_budget_state(gbb);
                    }
                    // Mark this group member as having started running its
                    // program *before* invoking it (matching go-algorand's
                    // `EvalContract` ordering), so a sibling that reads
                    // `gload` on us sees "ran" even if we go on to
                    // reject/error.
                    mark_group_member_ran(group_info);
                    // Eager box read-I/O-budget check (issue #725): matches
                    // go-algorand's `EvalContract`'s
                    // `if cx.caller == nil && !cx.readBudgetChecked { ... }`
                    // gate (`data/transactions/logic/eval.go:1275-1344`),
                    // which runs unconditionally before a single opcode
                    // executes -- regardless of whether the clear-state
                    // program ever touches a box.
                    //
                    // Whether an overrun here fails the outer transaction is
                    // gated on `EnableBareBudgetError` (v38+, issue #752),
                    // not unconditional: when true, this is a bare error, not
                    // a `logic.EvalError` -- so unlike an ordinary
                    // ClearState-program rejection/error, it is NOT swallowed
                    // by `ledger/apply/application.go`'s
                    // `if _, ok := evalErr.(logic.EvalError); !ok { return
                    // evalErr }` and must fail the outer transaction. Before
                    // v38, this same overrun *was* an `EvalError`, so
                    // go's `EvalContract` returns it before a single opcode
                    // runs (`eval.go:1334`, i.e. the ClearState program never
                    // actually executes) and `application.go` swallows it
                    // like any other ClearState failure -- mirrored below by
                    // building an empty `AvmResult` instead of running the
                    // program, exactly as `run_clear_state_program`'s own
                    // `Err(e)` branch already does for in-program errors.
                    avm_ctx.ensure_boxes_initialized();
                    let result = match avm_ctx.check_read_budget() {
                        Err(e) if ctx.consensus.enable_bare_budget_error => return Err(e),
                        Err(e) => {
                            let mut empty = algo_avm::eval::AvmResult::empty();
                            empty.error = Some(e.to_string());
                            empty
                        }
                        Ok(()) => {
                            if let Some(ref mut t) = tracer {
                                run_clear_state_program_with_tracer(
                                    &clear_program,
                                    &mut avm_ctx,
                                    &ctx.consensus,
                                    *t,
                                )
                            } else {
                                run_clear_state_program(
                                    &clear_program,
                                    &mut avm_ctx,
                                    &ctx.consensus,
                                )
                            }
                        }
                    };
                    // Export box I/O budget state back to the group-scoped
                    // carrier (issue #727) so the next top-level app call in
                    // this group sees the accumulated state. Matches
                    // go-algorand's shared `EvalParams` pointer, which keeps
                    // this state regardless of whether ClearState ultimately
                    // rejects (a ClearState rejection is swallowed at the
                    // ledger/apply layer, never rolling back the
                    // already-shared `EvalParams` fields).
                    if let Some(ref mut gbb) = group_box_budget {
                        avm_ctx.save_box_budget_state(gbb);
                    }
                    // Record this clear-state program's real final scratch
                    // space so a sibling's `gload` sees the actual values
                    // written, not a zero-filled placeholder (issue #686).
                    record_group_member_scratch(group_info, &result.scratch);
                    // Propagate updated counters back to context.
                    ctx.txn_counter.set(avm_ctx.txn_counter);
                    ctx.fee_credit.set(avm_ctx.fee_credit);
                    ctx.fee_residue.set(avm_ctx.fee_residue);
                    // Record EvalDelta comparison (clear-state).
                    record_eval_delta_comparison(
                        stx,
                        &result,
                        ctx.round,
                        ctx.txn_index.get(),
                        app_id,
                    );
                    if !result.approved {
                        // ClearState rejection: roll back any state changes the
                        // program made during execution. The on-completion branch
                        // below will still clear local state regardless.
                        store.restore_snapshot(cs_snapshot);
                    } else {
                        // Report the clear-state program's state changes / logs.
                        captured_eval_delta = crate::eval_delta::encode_eval_delta(&result, txn);
                    }
                }
            } else {
                // Non-ClearState: run approval program.
                //
                // No separate snapshot is needed here: if the program rejects,
                // apply_appl returns Err, which propagates to apply_transaction_inner's
                // closure. That outer closure's error path restores the snapshot
                // taken at the top of apply_transaction_inner, reverting all state
                // changes (including any AVM writes) for the entire transaction.

                // OptIn: create local state BEFORE program execution (matching
                // go-algorand's `optInApplication()` before `StatefulEval()`).
                // This lets the approval program read/write the sender's local
                // state in the same transaction that opts them in.
                if txn.on_completion == ON_COMPLETION_OPT_IN {
                    apply_appl_opt_in_pre_program(
                        store,
                        &txn.sender,
                        app_id,
                        ApplErrorContext::Outer,
                    )?;
                }

                let approval_program = app_params
                    .map(|p| p.approval_program.clone())
                    .unwrap_or_default();

                if approval_program.is_empty() {
                    return Err(AlgoError::Ledger {
                        message: format!("appl execute: app {} has empty approval program", app_id),
                    });
                }

                let ph = program_hash(&approval_program);
                let (avm_group, avm_group_index) = build_avm_group(stx, group_info);
                let mut avm_ctx = LedgerAvmContext::new(
                    store,
                    avm_group,
                    avm_group_index,
                    ctx.round,
                    ctx.latest_timestamp,
                    app_id,
                    creator,
                    true, // app_mode
                    ph,
                    ctx.genesis_hash,
                    ctx.consensus.clone(),
                );
                avm_ctx.fee_sink = ctx.fee_sink;
                avm_ctx.txn_counter = ctx.txn_counter.get();
                avm_ctx.fee_credit = ctx.fee_credit.get();
                avm_ctx.fee_residue = ctx.fee_residue.get();
                ctx.configure_avm_ctx(&mut avm_ctx);
                seed_avm_scratch_from_group(&mut avm_ctx, group_info);
                if let Some(ref mut t) = tracer {
                    avm_ctx.tracer_ptr = Some(*t as *mut dyn EvalTracer);
                }
                // Seed box I/O budget state from the group-scoped carrier
                // (issue #727): a prior sibling top-level app call in this
                // same atomic group may already have computed
                // `io_budget`/checked the read budget/accumulated
                // `dirty_bytes` -- go-algorand shares this state by pointer
                // across the whole group's `EvalParams`
                // (`ledger/eval/eval.go:1090`), not just within one call's
                // own inner-txn tree.
                if let Some(ref gbb) = group_box_budget {
                    avm_ctx.load_box_budget_state(gbb);
                }

                // Use the group budget if provided, otherwise create a single-call budget.
                let mut fallback_budget = GroupBudget::new(1);
                let budget = group_budget.unwrap_or(&mut fallback_budget);
                // Mark this group member as having started running its
                // program *before* invoking it (matching go-algorand's
                // `EvalContract` ordering), so a sibling that reads `gload`
                // on us sees "ran" even if we go on to reject/error.
                mark_group_member_ran(group_info);
                // Eager box read-I/O-budget check (issue #725): matches
                // go-algorand's `EvalContract`'s
                // `if cx.caller == nil && !cx.readBudgetChecked { ... }` gate
                // (`data/transactions/logic/eval.go:1275-1344`), which sums
                // the sizes of all boxes referenced by the group's box refs
                // against the I/O budget those refs grant -- unconditionally,
                // before a single opcode executes, regardless of whether the
                // approval program ever touches a box. Preserves the
                // existing lazy call sites (`available_app_box`,
                // `itxn_submit`'s inner-`appl` dispatch): `read_budget_checked`
                // makes every call after this one a no-op.
                avm_ctx.ensure_boxes_initialized();
                avm_ctx.check_read_budget()?;
                let mut result = if let Some(ref mut t) = tracer {
                    run_approval_program_with_tracer(&approval_program, &mut avm_ctx, budget, *t)?
                } else {
                    run_approval_program(&approval_program, &mut avm_ctx, budget)?
                };
                // Mirrors go-algorand's `EvalContract`
                // (`data/transactions/logic/eval.go:1353-1358`): `err == nil
                // && pass` gates `considerBudgetProgramWrites`, and a
                // failure there flips `pass` to false the same as any other
                // post-execution rejection (issue #723).
                if result.approved {
                    if let Err(e) = avm_ctx.consider_budget_program_writes() {
                        result.approved = false;
                        result.error = Some(e.to_string());
                    }
                }
                // Export box I/O budget state back to the group-scoped
                // carrier (issue #727) so the next top-level app call in
                // this group sees the accumulated state -- regardless of
                // whether this call's own program approved, since
                // go-algorand's shared `EvalParams` pointer accumulates
                // this state unconditionally as each top-level call runs.
                if let Some(ref mut gbb) = group_box_budget {
                    avm_ctx.save_box_budget_state(gbb);
                }
                // Record this approval program's real final scratch space
                // so a sibling's `gload` sees the actual values written,
                // not a zero-filled placeholder (issue #686) -- regardless
                // of whether this program approved, rejected, or errored
                // (see `AvmResult::scratch`'s doc).
                record_group_member_scratch(group_info, &result.scratch);

                // Propagate updated counters back to context.
                ctx.txn_counter.set(avm_ctx.txn_counter);
                ctx.fee_credit.set(avm_ctx.fee_credit);
                ctx.fee_residue.set(avm_ctx.fee_residue);

                // Record EvalDelta comparison (approval program).
                record_eval_delta_comparison(stx, &result, ctx.round, ctx.txn_index.get(), app_id);

                if !result.approved {
                    // Surface whatever global/local state, logs, and inner
                    // transactions accumulated before the program rejected or
                    // errored (algo_avm::eval preserves these rather than
                    // discarding them — see the error-preservation comments
                    // there). The transaction still fails and none of this is
                    // applied to the ledger; it exists purely so callers that
                    // need failure visibility (the simulation engine) can
                    // report the partial delta instead of `None`. Mirrors
                    // go-algorand's `evalTracer.saveEvalDelta`.
                    ctx.failed_eval_delta
                        .set(crate::eval_delta::encode_eval_delta(&result, txn));
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "appl execute: app {} approval program rejected transaction{}",
                            app_id,
                            result
                                .error
                                .as_ref()
                                .map(|e| format!(": {}", e))
                                .unwrap_or_default()
                        ),
                    });
                }
                // Report the approval program's state changes / logs / inner txns.
                captured_eval_delta = crate::eval_delta::encode_eval_delta(&result, txn);
            }
        }
    }

    // Handle OptIn for Replay mode — uses `had_local_state` and `is_create`
    // to support EvalDelta placeholder merging. In Execute mode, opt-in is
    // handled pre-program via `apply_appl_opt_in_pre_program` (matching
    // go-algorand's `optInApplication()` before `StatefulEval()`).
    if txn.on_completion == ON_COMPLETION_OPT_IN && ctx.mode == ApplyMode::Replay {
        if had_local_state {
            return Err(AlgoError::Ledger {
                message: format!(
                    "appl opt-in: {} is already opted into app {}",
                    txn.sender, app_id,
                ),
            });
        }
        let local_schema = if is_create {
            txn.local_state_schema.clone().unwrap_or_default()
        } else {
            store
                .get_app_params(app_id)
                .map(|p| p.local_state_schema.clone())
                .unwrap_or_default()
        };

        // Insert or update with the correct schema (EvalDelta may have
        // already created a placeholder with default schema).
        let mut local = store
            .get_app_local_state(&txn.sender, app_id)
            .unwrap_or_else(|| AppLocalState {
                schema: local_schema.clone(),
                key_value: std::collections::BTreeMap::new(),
            });
        local.schema = local_schema.clone();
        store.set_app_local_state(&txn.sender, app_id, local);

        let mut sender_account = store.get_or_default_account(&txn.sender);
        sender_account.total_apps_opted_in += 1;
        // Update aggregate schema: sender stores local state.
        sender_account.total_app_schema = sender_account.total_app_schema.add_schema(&local_schema);
        store.set_account(&txn.sender, sender_account);
    }

    // Apply remaining on-completion side effects via the shared helper.
    // ON_COMPLETION_OPT_IN is a no-op in the shared helper (handled above).
    apply_appl_on_completion(store, txn, app_id, ApplErrorContext::Outer, &ctx.consensus)?;

    Ok(captured_eval_delta)
}

/// Apply a key registration transaction (core state mutation only).
///
/// Transitions account participation status:
/// - `non_participation == true`: set NotParticipating (irreversible), clear all keys
/// - `vote_pk` present with non-empty bytes: go Online, copy key material
/// - Otherwise (offline keyreg): go Offline, clear all keys
///
/// Does NOT debit fees — the caller is responsible for calling `apply_fee()`
/// before dispatching here. This allows the same function to be used for both
/// outer transactions (where `apply_fee` is called in the dispatch layer) and
/// inner transactions (where fee pooling is handled by `itxn_submit`).
pub fn apply_keyreg<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
    round: u64,
    consensus: &ConsensusParams,
) -> Result<InnerApplyData, AlgoError> {
    // Guard: NotParticipating is irreversible.
    {
        let account = store.get_or_default_account(&txn.sender);
        if account.status == AccountStatus::NotParticipating {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg: account {} has status NotParticipating (irreversible)",
                    txn.sender,
                ),
            });
        }
    }

    // Go checks: if VotePK.IsEmpty() || SelectionPK.IsEmpty() -> offline/nonpart,
    // else -> online.  We must check BOTH keys to determine online vs offline.
    let vote_pk_empty = !txn.vote_pk.as_ref().is_some_and(|pk| !pk.is_empty());
    let selection_pk_empty = !txn.selection_pk.as_ref().is_some_and(|pk| !pk.is_empty());

    if vote_pk_empty || selection_pk_empty {
        // ── Offline or non-participating ──
        let mut account = store.get_or_default_account(&txn.sender);
        if txn.non_participation {
            account.status = AccountStatus::NotParticipating;
        } else {
            account.status = AccountStatus::Offline;
        }
        account.vote_id = None;
        account.selection_id = None;
        account.state_proof_id = None;
        account.vote_first_valid = 0;
        account.vote_last_valid = 0;
        account.vote_key_dilution = 0;
        store.set_account(&txn.sender, account);
    } else if txn.vote_pk.as_ref().is_some_and(|pk| !pk.is_empty()) {
        // ── Online keyreg ──
        let vote_bytes = txn.vote_pk.as_ref().unwrap();
        if vote_bytes.len() != 32 {
            return Err(AlgoError::Ledger {
                message: format!("keyreg: vote_pk length {} != 32", vote_bytes.len(),),
            });
        }
        let mut vote_id = [0u8; 32];
        vote_id.copy_from_slice(vote_bytes);

        let sel_bytes = txn.selection_pk.as_ref().ok_or_else(|| AlgoError::Ledger {
            message: "keyreg online: selection_pk is missing".to_string(),
        })?;
        if sel_bytes.len() != 32 {
            return Err(AlgoError::Ledger {
                message: format!("keyreg: selection_pk length {} != 32", sel_bytes.len(),),
            });
        }
        let mut selection_id = [0u8; 32];
        selection_id.copy_from_slice(sel_bytes);

        let state_proof_id = if let Some(ref sp_bytes) = txn.state_proof_pk {
            if !sp_bytes.is_empty() {
                if sp_bytes.len() != 64 {
                    return Err(AlgoError::Ledger {
                        message: format!("keyreg: state_proof_pk length {} != 64", sp_bytes.len(),),
                    });
                }
                let mut sp_id = [0u8; 64];
                sp_id.copy_from_slice(sp_bytes);
                Some(sp_id)
            } else {
                None
            }
        } else {
            None
        };

        // Validate participation parameters.
        if txn.vote_key_dilution == 0 {
            return Err(AlgoError::Ledger {
                message: "keyreg online: vote_key_dilution must be > 0".to_string(),
            });
        }
        if txn.vote_last < txn.vote_first {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_last {} < vote_first {}",
                    txn.vote_last, txn.vote_first
                ),
            });
        }

        // D14: Round-based keyreg coherency check (Go: EnableKeyregCoherencyCheck, enabled since v28).
        // VoteLast must be beyond the current round, and VoteFirst must start by next round.
        if txn.vote_last <= round {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_last {} <= current round {} (expired participation key)",
                    txn.vote_last, round,
                ),
            });
        }
        if txn.vote_first > round + 1 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_first {} > round+1 {} (first voting round too far in future)",
                    txn.vote_first, round + 1,
                ),
            });
        }

        let mut account = store.get_or_default_account(&txn.sender);
        account.status = AccountStatus::Online;
        account.vote_id = Some(vote_id);
        account.selection_id = Some(selection_id);
        account.state_proof_id = state_proof_id;
        account.vote_first_valid = txn.vote_first;
        account.vote_last_valid = txn.vote_last;
        account.vote_key_dilution = txn.vote_key_dilution;

        // D15: Incentive eligibility and last heartbeat (Go: Payouts.Enabled, since v40).
        // Go sets LastHeartbeat = round + lookback when Payouts.Enabled.
        // Go sets IncentiveEligible = true when fee >= Payouts.GoOnlineFee && Payouts.Enabled.
        // lookback = 2 * SeedRefreshInterval * SeedLookback = 2 * 80 * 2 = 320.
        const BALANCE_LOOKBACK: u64 = 320; // 2 * SeedRefreshInterval(80) * SeedLookback(2)

        if consensus.payouts_enabled {
            account.last_heartbeat = round + BALANCE_LOOKBACK;

            if txn.fee >= consensus.payouts_go_online_fee {
                account.incentive_eligible = true;
            }
        }

        store.set_account(&txn.sender, account);
    }

    Ok(InnerApplyData::default())
}

/// Apply a heartbeat transaction.
///
/// Matches go-algorand's `Heartbeat()` in `ledger/apply/heartbeat.go`.
/// A heartbeat proves that the target account (hb_address) is online by
/// demonstrating possession of the account's participation keys.
///
/// This implementation covers:
/// - Challenge-based fee validation: if the fee is below MinTxnFee and the txn
///   is a singleton (no group), the heartbeat is only allowed if the target
///   account is online, incentive-eligible, and currently challenged.
/// - Validates the target account exists and has matching voting keys
/// - Sets `last_heartbeat = round` on the target account
pub fn apply_heartbeat<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    txn: &algo_types::Transaction,
    round: u64,
    consensus: &ConsensusParams,
) -> Result<InnerApplyData, AlgoError> {
    let hb = txn.heartbeat.as_ref().ok_or_else(|| AlgoError::Ledger {
        message: "heartbeat transaction missing heartbeat fields".to_string(),
    })?;

    let hb_address = &hb.address;

    // Look up the target account.
    let account = store.get_account(hb_address);
    if account.is_none() {
        return Err(AlgoError::Ledger {
            message: format!("heartbeat: target account {} does not exist", hb_address),
        });
    }
    let account = account.unwrap();

    // Cheap/free/discounted heartbeat validation.
    //
    // `kind` mirrors go's `Heartbeat()` local variable (`ledger/apply/heartbeat.go`):
    // how (if at all) this heartbeat is claiming the challenge fee discount.
    // `None` means no discount is being claimed, so no eligibility
    // verification is needed here (well-formedness/fee checks upstream
    // already require the full, undiscounted fee in that case).
    //
    // Post-v42 (`TxnSizePricingEnabled`): the discount is claimed explicitly
    // via `hb_challenge_discount`, regardless of grouping. Pre-v42: it is
    // inferred from an underpaying singleton heartbeat (Go:
    // `header.Fee.Raw < proto.MinTxnFee && header.Group.IsZero()`).
    //
    // Either way, claiming the discount (via either convention) is only a
    // *request* -- it is granted only if the target account is actually
    // online, incentive-eligible, and currently challenged (the "risky"
    // challenge period).
    let is_singleton = txn.group == [0u8; 32];
    let kind: Option<&'static str> = if consensus.txn_size_pricing_enabled() {
        if hb.hb_challenge_discount {
            Some("discounted")
        } else {
            None
        }
    } else if txn.fee < consensus.min_txn_fee && is_singleton {
        Some(if txn.fee > 0 { "cheap" } else { "free" })
    } else {
        None
    };
    if let Some(kind) = kind {
        if account.status != AccountStatus::Online {
            return Err(AlgoError::Ledger {
                message: format!(
                    "{} heartbeat is not allowed for {} {}",
                    kind, account.status, hb_address
                ),
            });
        }
        if !account.incentive_eligible {
            return Err(AlgoError::Ledger {
                message: format!(
                    "{} heartbeat is not allowed when not IncentiveEligible {}",
                    kind, hb_address
                ),
            });
        }

        let provider = crate::heartbeat::StoreHeaderProvider { store: &*store };
        let ch = crate::heartbeat::find_challenge(
            consensus,
            round,
            &provider,
            crate::heartbeat::ChallengePeriod::Risky,
        );
        if ch.is_zero() {
            return Err(AlgoError::Ledger {
                message: format!(
                    "{} heartbeat for {} is not allowed with no challenge",
                    kind, hb_address
                ),
            });
        }
        let acct_last_seen =
            crate::heartbeat::last_seen(account.last_proposed, account.last_heartbeat);
        if !ch.failed(&hb_address.0, acct_last_seen) {
            return Err(AlgoError::Ledger {
                message: format!("{} heartbeat for {} is not challenged", kind, hb_address),
            });
        }
    }

    // Validate HbSeed matches the block seed at FirstValid.
    // Go (heartbeat.go:76-83): fetches the block header at header.FirstValid,
    // checks hdr.Seed != hb.HbSeed. This discourages pre-signing heartbeats.
    {
        let first_valid = txn.first_valid.0;
        let hdr_data = store
            .get_block_header_data(first_valid)
            .map_err(|e| AlgoError::Ledger {
                message: format!(
                    "heartbeat: failed to get block header at round {}: {}",
                    first_valid, e
                ),
            })?;
        let hdr_data = hdr_data.ok_or_else(|| AlgoError::Ledger {
            message: format!("heartbeat: block header not found at round {}", first_valid),
        })?;
        // decode_block works on header-only data because Block is a flat struct;
        // the payset fields simply default to empty.
        let hdr_block = algo_codec::decode_block(&hdr_data).map_err(|e| AlgoError::Ledger {
            message: format!(
                "heartbeat: failed to decode block header at round {}: {}",
                first_valid, e
            ),
        })?;
        let hdr_seed: [u8; 32] = hdr_block.seed;
        let hb_seed: [u8; 32] = hb.seed;
        if hdr_seed != hb_seed {
            return Err(AlgoError::Ledger {
                message: format!(
                    "heartbeat: provided seed does not match round {}'s seed",
                    first_valid
                ),
            });
        }
    }

    // Validate vote_id matches.
    // Go: account.VotingData.VoteID != hb.HbVoteID
    let account_vote_id = account.vote_id.unwrap_or([0u8; 32]);
    let hb_vote_id: [u8; 32] = hb.vote_id;
    if account_vote_id != hb_vote_id {
        return Err(AlgoError::Ledger {
            message: format!(
                "heartbeat: provided vote ID does not match {}'s vote ID",
                hb_address
            ),
        });
    }

    // Validate key_dilution matches.
    // Go: account.VotingData.VoteKeyDilution != hb.HbKeyDilution
    if account.vote_key_dilution != hb.key_dilution {
        return Err(AlgoError::Ledger {
            message: format!(
                "heartbeat: provided key dilution {} does not match {}'s key dilution {}",
                hb.key_dilution, hb_address, account.vote_key_dilution
            ),
        });
    }

    // Update last_heartbeat on the target account.
    // Go: account.LastHeartbeat = round
    let mut account = store.get_or_default_account(hb_address);
    account.last_heartbeat = round;
    store.set_account(hb_address, account);

    Ok(InnerApplyData::default())
}

// ── Inner transaction apply functions ────────────────────────────────
//
// These functions perform ONLY the core state mutation for inner transactions
// dispatched by `itxn_submit`. They skip:
// - Fee debit (fee pooling is handled by the itxn_submit coordinator)
// - Lease checks (not applicable to inner transactions)
// - Reward distribution (not applicable to inner transactions)
// - Snapshot/rollback (managed by the itxn_submit coordinator)
// - Min-balance checks (deferred to the end of the outer transaction)
//
// Corresponds to go-algorand's `roundCowState.Perform()` dispatch
// (ledger/eval/applications.go), which calls the same `apply.*` functions
// but without the outer-transaction ceremony.

/// Data returned from inner transaction application.
///
/// Contains created asset/app IDs and closing amounts that the
/// `itxn_submit` coordinator records in the inner transaction's ApplyData.
#[derive(Debug, Default, Clone)]
pub struct InnerApplyData {
    /// Created asset ID (for acfg create transactions).
    pub config_asset: u64,
    /// Created app ID (for appl create transactions).
    pub application_id: u64,
    /// Closing amount for payment close-remainder-to.
    pub closing_amount: u64,
    /// Closing amount for asset transfer close-to.
    pub asset_closing_amount: u64,
    /// Remaining fee credit after inner app call execution.
    /// Propagated back so the parent can sync its fee_credit.
    pub fee_credit: u64,
    /// Remaining fee residue after inner app call execution.
    /// Propagated back so the parent can sync its fee_residue (see
    /// `LedgerAvmContext::fee_residue`).
    pub fee_residue: u64,
    /// Final transaction counter after inner app call execution.
    /// Propagated back so the parent can sync its txn_counter.
    pub txn_counter: u64,
    /// All asset IDs created by this inner app call and any nested inner txns.
    /// Used by the parent to track resources for snapshot rollback (P1-3).
    pub nested_created_assets: Vec<u64>,
    /// All app IDs created by this inner app call and any nested inner txns.
    /// Used by the parent to track resources for snapshot rollback (P1-3).
    pub nested_created_apps: Vec<u64>,
    /// Box state propagated back from inner app call to parent.
    /// In go-algorand, box state is shared by pointer; in Rust we pass it
    /// through and propagate back.
    pub box_state: Option<BoxBudgetState>,
}

/// Shared box budget state that is passed between parent and inner app calls.
/// Mirrors go-algorand's shared `resources` + `EvalParams` box fields.
#[derive(Debug, Clone, Default)]
pub struct BoxBudgetState {
    /// Available box references: `(app_id, box_name) -> is_dirty`.
    pub available_boxes: std::collections::HashMap<(u64, Vec<u8>), bool>,
    /// Total dirty bytes written to boxes.
    pub dirty_bytes: u64,
    /// I/O budget: `num_box_refs * BYTES_PER_BOX_REFERENCE`.
    pub io_budget: u64,
    /// Whether the read budget check has already been performed.
    pub read_budget_checked: bool,
    /// Whether boxes have been initialized.
    pub boxes_initialized: bool,
    /// Number of unnamed box ref slots available for newly created apps.
    pub unnamed_access: i64,
    /// Per-app-ID oversized-program-bytes contribution currently folded
    /// into `dirty_bytes` (issue #723). Mirrors go-algorand's
    /// `resources.updateBytes`; see
    /// `LedgerAvmContext::consider_budget_program_writes`.
    pub update_bytes: std::collections::HashMap<u64, u64>,
    /// Whether the caller should fold this inner call's family-shared-box
    /// touch mark into its own (issue #662). Already resolved to the
    /// caller-should-touch condition (child touched family-shared state
    /// *and* shares the caller's creator) by the point it's set, matching
    /// go-algorand's merge-back condition
    /// (`data/transactions/logic/eval.go:1373-1384`).
    pub touched_family_shared: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;

    fn make_state_with_accounts(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
        let mut state = LedgerState::new();
        state.fee_sink = fee_sink;
        for (addr, balance) in balances {
            let account = state.get_or_default_account_mut(addr);
            account.micro_algos = *balance;
        }
        state
    }

    fn pay_txn(sender: Address, receiver: Address, amount: u64, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "pay".into();
        stx.txn.sender = sender;
        stx.txn.receiver = receiver;
        stx.txn.amount = amount;
        stx.txn.fee = fee;
        stx
    }

    /// Issue #602: `app_params_record` must thread real `version`/
    /// `size_sponsor` values through instead of hard-coding zero.
    #[test]
    fn test_app_params_record_threads_version_and_size_sponsor() {
        let p = AppParams {
            creator: Address([1u8; 32]),
            version: 4,
            size_sponsor: Address([9u8; 32]),
            ..Default::default()
        };
        let record = app_params_record(&p);
        assert_eq!(record.version, 4);
        assert_eq!(record.size_sponsor, Address([9u8; 32]));
    }

    #[test]
    fn test_simple_payment() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (receiver, 500_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 200_000, 1_000);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 799_000);
        assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 700_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
    }

    #[test]
    fn test_insufficient_balance() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 100), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 200, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Verify state was not mutated (rollback).
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 100);
    }

    #[test]
    fn test_close_remainder_to() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 1_000_000),
                (receiver, 0),
                (close_to, 0),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 100_000, 1_000);
        stx.txn.close_remainder_to = close_to;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 0);
        assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 100_000);
        // close_to gets remainder: 1_000_000 - 100_000 - 1_000 = 899_000
        assert_eq!(state.get_account(&close_to).unwrap().micro_algos, 899_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
    }

    #[test]
    fn test_close_with_assets_fails() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        state
            .get_or_default_account_mut(&sender)
            .total_assets_opted_in = 1;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 0, 1_000);
        stx.txn.close_remainder_to = close_to;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_balance_check() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 200_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        // Try to send 100_000 + 1_000 fee, leaving 99_000 < min_balance (100_000)
        let stx = pay_txn(sender, receiver, 100_000, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_to() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let auth = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (receiver, 100_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 1_000, 1_000);
        stx.txn.rekey_to = Some(auth);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().auth_addr, Some(auth),);

        // Rekey back to self clears auth_addr.
        let mut stx2 = pay_txn(sender, receiver, 1_000, 1_000);
        stx2.txn.rekey_to = Some(sender);

        apply_transaction(&mut state, &stx2, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().auth_addr, None);
    }

    #[test]
    fn test_stpf_no_longer_unconditionally_accepted() {
        // Issue #626: a `stpf` transaction used to be an unconditional no-op
        // that accepted *any* state proof (forged or otherwise) with zero
        // cryptographic verification. It now goes through
        // `apply_stateproof::apply_state_proof`, which requires the ledger
        // to have a tracked `StateProofNext` round to check against -- a
        // bare `stpf` txn with no such context (no previous block header at
        // all) is correctly rejected, not silently accepted. See
        // `apply_stateproof::tests` for full round-matching/crypto coverage.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "stpf".into();
        stx.txn.sender = sender;
        stx.txn.fee = 0;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(
            result.is_err(),
            "a state proof txn with no ledger context must not be silently accepted"
        );
        // Balance unchanged: state proof txns carry no fee/reward regardless.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_unknown_type_returns_error() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "bogus".into();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Balance unchanged — unknown type is rejected.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_keyreg_offline_debits_fee() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 998_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 2_000);
        assert_eq!(
            state.get_account(&sender).unwrap().status,
            AccountStatus::Offline,
        );
    }

    #[test]
    fn test_non_pay_min_balance_check() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        // Sender at exactly min_balance (100_000). Fee of 1_000 drops below.
        let mut state = make_state_with_accounts(&[(sender, 100_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Verify rollback — sender balance unchanged.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 100_000);
    }

    #[test]
    fn test_rewards_pool_debited() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (receiver, 100_000),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 1_000, 1_000);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Sender had 5 Algos = 5 reward units. Pending = (10 - 0) * 5 = 50.
        // Rewards pool should be debited by 50.
        assert_eq!(
            state.get_account(&rewards_pool).unwrap().micro_algos,
            10_000_000 - 50
        );
    }

    #[test]
    fn test_error_rollback_with_rewards() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (receiver, 0),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        // Sender has 5M but tries to send 10M — will fail.
        // Rewards would have been applied (50) bumping to 5_000_050, still < 10M.
        let stx = pay_txn(sender, receiver, 10_000_000, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());

        // Verify full rollback — sender balance and rewards_base unchanged.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.micro_algos, 5_000_000);
        assert_eq!(acct.rewards_base, 0);
        assert_eq!(acct.rewarded_micro_algos, 0);

        // Rewards pool should NOT have been debited.
        assert_eq!(
            state.get_account(&rewards_pool).unwrap().micro_algos,
            10_000_000
        );
    }

    #[test]
    fn test_fee_sink_rolled_back_on_close_failure() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 100)], fee_sink);
        state
            .get_or_default_account_mut(&sender)
            .total_assets_opted_in = 1;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 0, 1_000);
        stx.txn.close_remainder_to = close_to;

        // This fails because sender has opted-in assets.
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());

        // Fee sink should be rolled back — fee was credited by apply_fee
        // but the close check failed in apply_pay, so the whole transaction is reverted.
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 100);
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Asset Config (acfg) tests
    // -----------------------------------------------------------------------

    /// Helper: build an acfg create transaction.
    fn acfg_create_txn(sender: Address, fee: u64, params: AssetParams) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.config_asset = 0; // 0 = create
        stx.txn.asset_params = Some(params);
        stx
    }

    /// Helper: create an asset in state and return the asset_id.
    ///
    /// Sets `ctx.txn_counter` to `asset_id - 1` so that `apply_acfg` computes
    /// `txn_counter + 1 == asset_id`. After `apply_transaction` the counter
    /// will be incremented by the dispatch epilogue.
    fn create_asset_in_state(
        state: &mut LedgerState,
        ctx: &ApplyContext,
        creator: Address,
        asset_id: u64,
        params: AssetParams,
    ) {
        // Set counter so txn_counter + 1 == asset_id inside apply_acfg.
        ctx.txn_counter.set(asset_id - 1);
        let stx = acfg_create_txn(creator, 1_000, params);
        apply_transaction(state, &stx, ctx, 0).unwrap();
    }

    #[test]
    fn test_acfg_create() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000_000,
            decimals: 6,
            default_frozen: false,
            unit_name: "TST".to_string(),
            asset_name: "Test Asset".to_string(),
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        // Set txn_counter so txn_counter + 1 == 42.
        ctx.txn_counter.set(41);
        let stx = acfg_create_txn(sender, 1_000, params.clone());
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify asset params record.
        let record = state.get_asset_params(42).unwrap();
        assert_eq!(record.creator, sender);
        assert_eq!(record.params.total, 1_000_000);
        assert_eq!(record.params.decimals, 6);
        assert_eq!(record.params.unit_name, "TST");

        // Creator holds full supply.
        let holding = state.get_asset_holding(&sender, 42).unwrap();
        assert_eq!(holding.amount, 1_000_000);
        assert!(!holding.frozen);

        // Account counters incremented.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.total_created_assets, 1);
        assert_eq!(acct.total_assets_opted_in, 1);

        // Fee deducted.
        assert_eq!(acct.micro_algos, 10_000_000 - 1_000);
    }

    #[test]
    fn test_acfg_create_default_frozen() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 500,
            default_frozen: true,
            manager: Some(sender),
            ..Default::default()
        };
        // Set txn_counter so txn_counter + 1 == 50.
        ctx.txn_counter.set(49);
        let stx = acfg_create_txn(sender, 1_000, params);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Per Go semantics, creator holding is always unfrozen on create
        // (the implementation sets frozen: false for the creator).
        let holding = state.get_asset_holding(&sender, 50).unwrap();
        assert_eq!(holding.amount, 500);
        assert!(!holding.frozen);
    }

    #[test]
    fn test_acfg_destroy() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset first.
        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Destroy: config_asset = existing ID, asset_params = default (empty).
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        // No asset_params means destroy.

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Params and holding removed.
        assert!(state.get_asset_params(42).is_none());
        assert!(state.get_asset_holding(&sender, 42).is_none());

        // Counters decremented.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.total_created_assets, 0);
        assert_eq!(acct.total_assets_opted_in, 0);
    }

    #[test]
    fn test_acfg_destroy_not_full_supply_fails() {
        let sender = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (other, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset with total=1000.
        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Opt-in other and transfer some supply.
        state.asset_holdings.insert(
            (other, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&other)
            .total_assets_opted_in += 1;

        // Manually move 100 units from creator to other.
        state.asset_holdings.get_mut(&(sender, 42)).unwrap().amount = 900;
        state.asset_holdings.get_mut(&(other, 42)).unwrap().amount = 100;

        // Attempt destroy — should fail because creator doesn't hold full supply.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("total supply"));
    }

    #[test]
    fn test_acfg_reconfig() {
        let sender = Address([1u8; 32]);
        let new_manager = Address([5u8; 32]);
        let new_reserve = Address([6u8; 32]);
        let new_freeze = Address([7u8; 32]);
        let new_clawback = Address([8u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Reconfigure: change all role addresses.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(new_manager),
            reserve: Some(new_reserve),
            freeze: Some(new_freeze),
            clawback: Some(new_clawback),
            ..Default::default()
        });

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let record = state.get_asset_params(42).unwrap();
        assert_eq!(record.params.manager, Some(new_manager));
        assert_eq!(record.params.reserve, Some(new_reserve));
        assert_eq!(record.params.freeze, Some(new_freeze));
        assert_eq!(record.params.clawback, Some(new_clawback));
        // Total should be unchanged.
        assert_eq!(record.params.total, 1_000);
    }

    #[test]
    fn test_acfg_reconfig_unauthorized() {
        let creator = Address([1u8; 32]);
        let attacker = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (attacker, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Attacker tries to reconfigure.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(attacker),
            ..Default::default()
        });

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the manager"));
    }

    #[test]
    fn test_acfg_reconfig_cleared_role_locked() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Clear the manager (set to zero address).
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(Address::ZERO),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        });

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Now manager is zero — any further reconfig should fail.
        let mut stx2 = SignedTransaction::default();
        stx2.txn.txn_type = "acfg".into();
        stx2.txn.sender = sender;
        stx2.txn.fee = 1_000;
        stx2.txn.config_asset = 42;
        stx2.txn.asset_params = Some(AssetParams {
            manager: Some(sender),
            ..Default::default()
        });

        let result = apply_transaction(&mut state, &stx2, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the manager"));
    }

    // -----------------------------------------------------------------------
    // Inner acfg reconfig: P1-2 — unset fields must not clear existing roles
    // -----------------------------------------------------------------------

    #[test]
    fn p1_2_inner_acfg_reconfig_preserves_unset_roles() {
        // Create an asset with all four role addresses set.
        // Then do an inner acfg reconfig that only sets the manager field.
        // The reserve, freeze, and clawback should remain unchanged.
        let creator = Address([1u8; 32]);
        let new_manager = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(creator, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let original_params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            reserve: Some(Address([10u8; 32])),
            freeze: Some(Address([11u8; 32])),
            clawback: Some(Address([12u8; 32])),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, original_params.clone());

        // Build an inner acfg transaction that ONLY sets the manager field.
        // Other role fields are None (not set via itxn_field).
        let inner_txn = algo_types::Transaction {
            txn_type: "acfg".into(),
            sender: creator,
            config_asset: 42,
            asset_params: Some(AssetParams {
                manager: Some(new_manager),
                // reserve, freeze, clawback are None (not set by itxn_field)
                ..Default::default()
            }),
            ..Default::default()
        };

        let _ad = apply_acfg(&mut state, &inner_txn, 100).unwrap();

        let record = state.get_asset_params(42).unwrap();
        // Manager should be updated.
        assert_eq!(record.params.manager, Some(new_manager));
        // Reserve, freeze, clawback should be PRESERVED (not cleared to None).
        assert_eq!(
            record.params.reserve,
            Some(Address([10u8; 32])),
            "reserve should be preserved when not set in inner txn"
        );
        assert_eq!(
            record.params.freeze,
            Some(Address([11u8; 32])),
            "freeze should be preserved when not set in inner txn"
        );
        assert_eq!(
            record.params.clawback,
            Some(Address([12u8; 32])),
            "clawback should be preserved when not set in inner txn"
        );
    }

    #[test]
    fn p1_2_inner_acfg_reconfig_explicit_zero_clears_role() {
        // When an inner acfg explicitly sets a role to the zero address
        // (via itxn_field), it should clear that role.
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(creator, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let original_params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            reserve: Some(Address([10u8; 32])),
            freeze: Some(Address([11u8; 32])),
            clawback: Some(Address([12u8; 32])),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, original_params);

        // Inner txn sets reserve to zero address (explicitly clearing it)
        // and also sets manager to keep it valid.
        let inner_txn = algo_types::Transaction {
            txn_type: "acfg".into(),
            sender: creator,
            config_asset: 42,
            asset_params: Some(AssetParams {
                manager: Some(creator),
                reserve: Some(Address::ZERO), // explicit clear
                // freeze, clawback are None (not set)
                ..Default::default()
            }),
            ..Default::default()
        };

        let _ad = apply_acfg(&mut state, &inner_txn, 100).unwrap();

        let record = state.get_asset_params(42).unwrap();
        assert_eq!(record.params.manager, Some(creator));
        // Reserve should be cleared to zero address.
        assert_eq!(
            record.params.reserve,
            Some(Address::ZERO),
            "reserve should be cleared when explicitly set to zero"
        );
        // Freeze and clawback should be preserved.
        assert_eq!(
            record.params.freeze,
            Some(Address([11u8; 32])),
            "freeze should be preserved when not set in inner txn"
        );
        assert_eq!(
            record.params.clawback,
            Some(Address([12u8; 32])),
            "clawback should be preserved when not set in inner txn"
        );
    }

    // -----------------------------------------------------------------------
    // Asset Transfer (axfer) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_axfer_optin() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset with default_frozen = true.
        let params = AssetParams {
            total: 1_000,
            default_frozen: true,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in: axfer to self, amount 0.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 0;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Holding created with default_frozen.
        let holding = state.get_asset_holding(&user, 42).unwrap();
        assert_eq!(holding.amount, 0);
        assert!(holding.frozen); // default_frozen = true

        // Counter incremented.
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 1);
    }

    #[test]
    fn test_axfer_optin_duplicate_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // First opt-in succeeds.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 0;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Second opt-in is a no-op (matches Go behavior — no error).
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        // Holding unchanged, count unchanged.
        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 0);
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 1);
    }

    #[test]
    fn test_axfer_transfer() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Transfer 300 from creator to user.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 300;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 700);
        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 300);
    }

    #[test]
    fn test_axfer_transfer_insufficient_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Try to transfer more than creator holds.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 2_000; // > 1_000 total supply
        stx.txn.asset_receiver = Some(user);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn test_axfer_transfer_not_opted_in_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Transfer to user who hasn't opted in.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(user);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not opted in"));
    }

    #[test]
    fn test_axfer_clawback() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let clawback_addr = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (clawback_addr, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            clawback: Some(clawback_addr),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user and give them some tokens.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;
        // Adjust creator holding.
        state.asset_holdings.get_mut(&(creator, 42)).unwrap().amount = 500;

        // Clawback: sender=clawback_addr, asset_sender=user (source), receiver=creator.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = clawback_addr;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 200;
        stx.txn.asset_sender = Some(user);
        stx.txn.asset_receiver = Some(creator);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 300);
        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 700);
    }

    #[test]
    fn test_axfer_clawback_unauthorized_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let attacker = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (attacker, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            clawback: Some(creator), // creator is clawback, not attacker
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Attacker tries clawback.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_sender = Some(user);
        stx.txn.asset_receiver = Some(attacker);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the clawback"));
    }

    #[test]
    fn test_axfer_close_to() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let close_target = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (close_target, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user and give them 300 tokens.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 300,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Opt-in close_target.
        state.asset_holdings.insert(
            (close_target, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&close_target)
            .total_assets_opted_in += 1;

        // Close asset holding: transfer 100 to creator, close remainder to close_target.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(creator);
        stx.txn.asset_close_to = Some(close_target);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Creator gets the 100 transferred (had 1000 from create).
        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 1100);
        // close_target gets the remaining 200.
        assert_eq!(
            state.get_asset_holding(&close_target, 42).unwrap().amount,
            200
        );
        // User holding removed.
        assert!(state.get_asset_holding(&user, 42).is_none());
        // Counter decremented.
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 0);
    }

    #[test]
    fn test_axfer_transfer_frozen_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user with frozen holding.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: true,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // User tries to transfer from frozen holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".into();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(creator);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("frozen"));
    }

    // -----------------------------------------------------------------------
    // Asset Freeze (afrz) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_afrz_freeze() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Freeze user's holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert!(state.get_asset_holding(&user, 42).unwrap().frozen);
    }

    #[test]
    fn test_afrz_unfreeze() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user with frozen holding.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: true,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Unfreeze.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = false;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert!(!state.get_asset_holding(&user, 42).unwrap().frozen);
    }

    #[test]
    fn test_afrz_unauthorized_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let attacker = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (attacker, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: false,
            },
        );
        state
            .get_or_default_account_mut(&user)
            .total_assets_opted_in += 1;

        // Attacker tries to freeze.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".into();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not the freeze address"));
    }

    #[test]
    fn test_afrz_no_holding_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // User has NOT opted in — no holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no holding"));
    }

    // -----------------------------------------------------------------------
    // Key Registration (keyreg) tests
    // -----------------------------------------------------------------------

    fn keyreg_online_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".into();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.vote_pk = Some([1u8; 32]);
        stx.txn.selection_pk = Some([2u8; 32]);
        stx.txn.state_proof_pk = Some([3u8; 64]);
        // vote_first <= round+1 and vote_last > round to pass coherency checks.
        // Tests use round=1, so vote_first=1, vote_last=200.
        stx.txn.vote_first = 1;
        stx.txn.vote_last = 200;
        stx.txn.vote_key_dilution = 10;
        stx
    }

    fn keyreg_offline_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".into();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        // No keys, non_participation=false => offline
        stx
    }

    fn keyreg_nonpart_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".into();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.non_participation = true;
        stx
    }

    #[test]
    fn test_keyreg_online() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_online_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Online);
        assert_eq!(acct.vote_id, Some([1u8; 32]));
        assert_eq!(acct.selection_id, Some([2u8; 32]));
        assert_eq!(acct.state_proof_id, Some([3u8; 64]));
        assert_eq!(acct.vote_first_valid, 1);
        assert_eq!(acct.vote_last_valid, 200);
        assert_eq!(acct.vote_key_dilution, 10);
        // Fee deducted.
        assert_eq!(acct.micro_algos, 999_000);
        // D15: last_heartbeat = round(1) + lookback(320) = 321.
        assert_eq!(acct.last_heartbeat, 321);
        // Fee < 2_000_000, so incentive_eligible remains false.
        assert!(!acct.incentive_eligible);
    }

    #[test]
    fn test_keyreg_offline() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        // Set account to Online with keys first.
        {
            let acct = state.get_or_default_account_mut(&sender);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.state_proof_id = Some([3u8; 64]);
            acct.vote_first_valid = 100;
            acct.vote_last_valid = 200;
            acct.vote_key_dilution = 10;
        }
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_offline_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
        assert_eq!(acct.vote_first_valid, 0);
        assert_eq!(acct.vote_last_valid, 0);
        assert_eq!(acct.vote_key_dilution, 0);
    }

    #[test]
    fn test_keyreg_nonpart() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_nonpart_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
    }

    #[test]
    fn test_keyreg_nonpart_irreversible() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        // Set account to NotParticipating.
        state.get_or_default_account_mut(&sender).status = AccountStatus::NotParticipating;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Attempt online keyreg — should fail.
        let stx = keyreg_online_txn(sender, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("NotParticipating"),
            "expected NotParticipating error, got: {}",
            err_msg,
        );

        // Account should be unchanged (rollback).
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);
        assert_eq!(acct.micro_algos, 1_000_000); // fee rolled back
    }

    #[test]
    fn test_keyreg_online_then_offline() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Go online.
        let stx_on = keyreg_online_txn(sender, 1_000);
        apply_transaction(&mut state, &stx_on, &ctx, 0).unwrap();
        assert_eq!(
            state.get_account(&sender).unwrap().status,
            AccountStatus::Online
        );
        assert!(state.get_account(&sender).unwrap().vote_id.is_some());

        // Go offline.
        let stx_off = keyreg_offline_txn(sender, 1_000);
        apply_transaction(&mut state, &stx_off, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
        assert_eq!(acct.vote_first_valid, 0);
        assert_eq!(acct.vote_last_valid, 0);
        assert_eq!(acct.vote_key_dilution, 0);
        // Two fees deducted.
        assert_eq!(acct.micro_algos, 998_000);
    }

    #[test]
    fn test_keyreg_rewards_stop_for_nonpart() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        // Set account Online with rewards_base=0.
        {
            let acct = state.get_or_default_account_mut(&sender);
            acct.status = AccountStatus::Online;
            acct.rewards_base = 0;
        }

        // Verify pending rewards are > 0 at rewards_level=10.
        use crate::rewards::compute_pending_rewards;
        let pending = compute_pending_rewards(state.get_account(&sender).unwrap(), 10);
        assert!(pending > 0, "expected pending rewards > 0, got {}", pending);

        // Apply nonpart keyreg.
        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        let stx = keyreg_nonpart_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);

        // After becoming NotParticipating, compute_pending_rewards returns 0.
        let pending_after = compute_pending_rewards(acct, 20);
        assert_eq!(pending_after, 0);
    }

    #[test]
    fn test_keyreg_online_zero_dilution_rejected() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let mut stx = keyreg_online_txn(sender, 1_000);
        stx.txn.vote_key_dilution = 0;
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("vote_key_dilution"),
            "error should mention vote_key_dilution"
        );
        // Balance unchanged (rollback).
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_keyreg_online_vote_last_before_first_rejected() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let mut stx = keyreg_online_txn(sender, 1_000);
        stx.txn.vote_first = 200;
        stx.txn.vote_last = 100;
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("vote_last"),
            "error should mention vote_last"
        );
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_detect_transaction_groups() {
        // Build a payset with mixed standalone and grouped transactions:
        // [standalone_A, group_B1, group_B2, group_B3, standalone_C]

        let mut standalone_a = SignedTransaction::default();
        standalone_a.txn.txn_type = "pay".into();
        standalone_a.txn.sender = Address([1u8; 32]);
        // Empty group hash => standalone.

        let group_hash = [42u8; 32];

        let mut group_b1 = SignedTransaction::default();
        group_b1.txn.txn_type = "appl".into();
        group_b1.txn.sender = Address([2u8; 32]);
        group_b1.txn.group = group_hash;

        let mut group_b2 = SignedTransaction::default();
        group_b2.txn.txn_type = "pay".into();
        group_b2.txn.sender = Address([3u8; 32]);
        group_b2.txn.group = group_hash;

        let mut group_b3 = SignedTransaction::default();
        group_b3.txn.txn_type = "axfer".into();
        group_b3.txn.sender = Address([4u8; 32]);
        group_b3.txn.group = group_hash;

        let mut standalone_c = SignedTransaction::default();
        standalone_c.txn.txn_type = "pay".into();
        standalone_c.txn.sender = Address([5u8; 32]);

        let payset = vec![standalone_a, group_b1, group_b2, group_b3, standalone_c];
        let groups = detect_transaction_groups(&payset);

        // Should produce 3 groups: [standalone_A], [B1, B2, B3], [standalone_C].
        assert_eq!(groups.len(), 3, "expected 3 groups, got {}", groups.len());

        // First group: standalone A.
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[0][0].txn.sender, Address([1u8; 32]));

        // Second group: atomic group of 3.
        assert_eq!(groups[1].len(), 3);
        assert_eq!(groups[1][0].txn.sender, Address([2u8; 32]));
        assert_eq!(groups[1][1].txn.sender, Address([3u8; 32]));
        assert_eq!(groups[1][2].txn.sender, Address([4u8; 32]));

        // Third group: standalone C.
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[2][0].txn.sender, Address([5u8; 32]));
    }

    #[test]
    fn test_detect_transaction_groups_empty() {
        let groups = detect_transaction_groups(&[]);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_detect_transaction_groups_all_standalone() {
        let mut stx1 = SignedTransaction::default();
        stx1.txn.sender = Address([1u8; 32]);
        let mut stx2 = SignedTransaction::default();
        stx2.txn.sender = Address([2u8; 32]);

        let payset = vec![stx1, stx2];
        let groups = detect_transaction_groups(&payset);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 1);
    }

    #[test]
    fn test_detect_transaction_groups_two_different_groups() {
        let group_a = [10u8; 32];
        let group_b = [20u8; 32];

        let mut a1 = SignedTransaction::default();
        a1.txn.sender = Address([1u8; 32]);
        a1.txn.group = group_a;

        let mut a2 = SignedTransaction::default();
        a2.txn.sender = Address([2u8; 32]);
        a2.txn.group = group_a;

        let mut b1 = SignedTransaction::default();
        b1.txn.sender = Address([3u8; 32]);
        b1.txn.group = group_b;

        let mut b2 = SignedTransaction::default();
        b2.txn.sender = Address([4u8; 32]);
        b2.txn.group = group_b;

        let payset = vec![a1, a2, b1, b2];
        let groups = detect_transaction_groups(&payset);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[0][0].txn.sender, Address([1u8; 32]));
        assert_eq!(groups[0][1].txn.sender, Address([2u8; 32]));
        assert_eq!(groups[1].len(), 2);
        assert_eq!(groups[1][0].txn.sender, Address([3u8; 32]));
        assert_eq!(groups[1][1].txn.sender, Address([4u8; 32]));
    }

    /// Create a minimal Block for round 1 with a single payment transaction.
    fn make_test_block(fee_sink: Address) -> Block {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let stx = pay_txn(sender, receiver, 100, 1_000);

        Block {
            round: Round(1),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 1000,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: Address::ZERO,
            fee_sink,
            rewards_pool: Address::ZERO,
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 1,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            load: 0,
            congestion_tax: 0,
            payset: vec![stx],
        }
    }

    #[test]
    fn test_apply_stores_block() {
        use crate::store_trait::LedgerStore;

        let fee_sink = Address([3u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (receiver, 1_000_000), (fee_sink, 0)],
            fee_sink,
        );

        let block = make_test_block(fee_sink);
        apply_block(&mut state, &block).unwrap();

        let blkdata = state.get_block_data(1).unwrap();
        assert!(blkdata.is_some(), "block data should be stored after apply");
        assert!(!blkdata.unwrap().is_empty());

        let hdrdata = state.get_block_header_data(1).unwrap();
        assert!(
            hdrdata.is_some(),
            "header data should be stored after apply"
        );
        assert!(!hdrdata.unwrap().is_empty());
    }

    #[test]
    fn test_apply_stores_txtail() {
        use crate::store_trait::LedgerStore;

        let fee_sink = Address([3u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (receiver, 1_000_000), (fee_sink, 0)],
            fee_sink,
        );

        let block = make_test_block(fee_sink);
        apply_block(&mut state, &block).unwrap();

        let txtail = state.get_txtail(1).unwrap();
        assert!(txtail.is_some(), "txtail should be stored after apply");
        assert!(!txtail.unwrap().is_empty());
    }

    // ---------------------------------------------------------------------
    // Proposer payout (issue #523)
    // ---------------------------------------------------------------------

    /// Issue #523: `apply_block` must move `block.proposer_payout`
    /// microAlgos from the fee sink to `block.proposer`, mirroring
    /// go-algorand's `BlockEvaluator.performPayout` (`ledger/eval/eval.go`).
    /// Before this fix, `apply_block_impl` only threaded `proposer_payout`
    /// through into the stored header — it never actually credited the
    /// proposer or debited the fee sink, so a live mixed-cluster run
    /// diverged from go-algorand's `GET /v2/ledger/supply` by the
    /// cumulative sum of every block's payout (observed: 30,000,000,000,000
    /// microAlgos over 150 rounds).
    #[test]
    fn apply_block_credits_proposer_payout_from_fee_sink() {
        let fee_sink = Address([3u8; 32]);
        let proposer = Address([9u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[
                (sender, 10_000_000),
                (receiver, 1_000_000),
                (fee_sink, 5_000_000),
                (proposer, 1_000_000),
            ],
            fee_sink,
        );

        let mut block = make_test_block(fee_sink);
        block.proposer = proposer;
        block.proposer_payout = 200_000;

        apply_block(&mut state, &block).unwrap();

        assert_eq!(
            state.get_account(&proposer).unwrap().micro_algos,
            1_200_000,
            "proposer must be credited with the block's proposer_payout"
        );
        assert_eq!(
            state.get_account(&fee_sink).unwrap().micro_algos,
            // fee_sink starts at 5_000_000; make_test_block's payment sends
            // its 1_000 fee to fee_sink too (pay_txn(..., 1_000)).
            5_000_000 + 1_000 - 200_000,
            "fee sink must be debited by the block's proposer_payout"
        );
    }

    /// A zero `proposer_payout` (or no proposer — payouts not enabled for
    /// this block) must not move any money, matching go's early return in
    /// `performPayout`.
    #[test]
    fn apply_block_zero_proposer_payout_is_a_no_op() {
        let fee_sink = Address([3u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (receiver, 1_000_000), (fee_sink, 0)],
            fee_sink,
        );

        // make_test_block leaves proposer = Address::ZERO, proposer_payout = 0.
        let block = make_test_block(fee_sink);
        apply_block(&mut state, &block).unwrap();

        assert_eq!(
            state.get_account(&fee_sink).unwrap().micro_algos,
            1_000,
            "only the payment's fee should have reached the fee sink"
        );
    }

    // ---------------------------------------------------------------------
    // Record proposal: LastProposed + un-suspend (issue #528)
    // ---------------------------------------------------------------------

    /// Issue #528: `apply_block` must mirror go-algorand's
    /// `BlockEvaluator.recordProposal` (`ledger/eval/eval.go`), called
    /// immediately after `performPayout` in `endOfBlock`. A proposer that
    /// was suspended (Offline with voting keys intact) proves it is
    /// actually online by proposing — even though it takes 320 rounds for
    /// a keyreg to take effect — so `recordProposal` unsuspends it
    /// (`Status = Online`) and records `LastProposed = eval.Round()`.
    #[test]
    fn apply_block_unsuspends_proposer_and_records_last_proposed() {
        let fee_sink = Address([3u8; 32]);
        let proposer = Address([9u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[
                (sender, 10_000_000),
                (receiver, 1_000_000),
                (fee_sink, 0),
                (proposer, 1_000_000),
            ],
            fee_sink,
        );

        // Set the proposer as suspended: Offline but with voting keys intact
        // and IncentiveEligible cleared (mirrors `suspend_absent_accounts`'s
        // effect from a prior round).
        {
            let acct = state.get_or_default_account_mut(&proposer);
            acct.status = AccountStatus::Offline;
            acct.vote_id = Some([7u8; 32]);
            acct.selection_id = Some([8u8; 32]);
            acct.vote_key_dilution = 10;
            acct.vote_first_valid = 0;
            acct.vote_last_valid = 999_999;
            acct.incentive_eligible = false;
            acct.last_proposed = 0;
        }

        let mut block = make_test_block(fee_sink);
        block.proposer = proposer;
        block.proposer_payout = 0;

        apply_block(&mut state, &block).unwrap();

        let acct = state.get_account(&proposer).unwrap();
        assert_eq!(
            acct.last_proposed, 1,
            "last_proposed must be set to the block's round"
        );
        assert_eq!(
            acct.status,
            AccountStatus::Online,
            "a suspended proposer must be un-suspended by proposing"
        );
        // Un-suspension does not restore incentive eligibility -- that
        // requires a fresh keyreg with the extra fee (matches go's comment
        // in recordProposal).
        assert!(!acct.incentive_eligible);
        // Voting keys must be preserved untouched.
        assert_eq!(acct.vote_id, Some([7u8; 32]));
    }

    /// A proposer that was already `Online` (not suspended) must still get
    /// `LastProposed` updated, but `recordProposal` must not touch any
    /// other field (no accidental clearing of voting keys, incentive
    /// eligibility, etc.).
    #[test]
    fn apply_block_records_last_proposed_for_already_online_proposer() {
        let fee_sink = Address([3u8; 32]);
        let proposer = Address([9u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[
                (sender, 10_000_000),
                (receiver, 1_000_000),
                (fee_sink, 0),
                (proposer, 1_000_000),
            ],
            fee_sink,
        );

        let before = {
            let acct = state.get_or_default_account_mut(&proposer);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([7u8; 32]);
            acct.selection_id = Some([8u8; 32]);
            acct.vote_key_dilution = 10;
            acct.vote_first_valid = 0;
            acct.vote_last_valid = 999_999;
            acct.incentive_eligible = true;
            acct.last_proposed = 0;
            acct.clone()
        };

        let mut block = make_test_block(fee_sink);
        block.proposer = proposer;
        block.proposer_payout = 0;

        apply_block(&mut state, &block).unwrap();

        let acct = state.get_account(&proposer).unwrap();
        assert_eq!(
            acct.last_proposed, 1,
            "last_proposed must be updated to the new block's round"
        );
        assert_eq!(acct.status, AccountStatus::Online);
        assert_eq!(acct.vote_id, before.vote_id);
        assert_eq!(acct.selection_id, before.selection_id);
        assert_eq!(acct.incentive_eligible, before.incentive_eligible);
        assert_eq!(
            acct.micro_algos, before.micro_algos,
            "recordProposal must not touch the balance"
        );
    }

    /// A zero proposer (no proposer for this block) must leave every
    /// account's `last_proposed`/`status` untouched, matching go's early
    /// return `if proposer.IsZero() { return nil }`.
    #[test]
    fn apply_block_no_proposer_is_a_no_op_for_record_proposal() {
        let fee_sink = Address([3u8; 32]);
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (receiver, 1_000_000), (fee_sink, 0)],
            fee_sink,
        );

        // make_test_block leaves proposer = Address::ZERO.
        let block = make_test_block(fee_sink);
        apply_block(&mut state, &block).unwrap();

        // No panic, and the (untouched) sender/receiver accounts are
        // unaffected -- record_proposal must not have run against anything.
        assert_eq!(state.get_account(&sender).unwrap().last_proposed, 0);
        assert_eq!(state.get_account(&receiver).unwrap().last_proposed, 0);
    }

    #[test]
    fn test_forget_before_in_memory() {
        use crate::store_trait::LedgerStore;

        let mut state = LedgerState::new();

        // Insert block and txtail entries for rounds 1-5.
        for r in 1..=5u64 {
            state
                .put_block(r, "test-v1", &[r as u8], &[r as u8, 0])
                .unwrap();
            state.put_txtail(r, &[r as u8, 1]).unwrap();
        }

        // Verify all 5 rounds are present.
        for r in 1..=5u64 {
            assert!(state.get_block_data(r).unwrap().is_some());
            assert!(state.get_txtail(r).unwrap().is_some());
        }

        // Forget rounds before 3.
        state.forget_before(3).unwrap();

        // Rounds 1, 2 should be gone.
        assert!(state.get_block_data(1).unwrap().is_none());
        assert!(state.get_block_data(2).unwrap().is_none());
        assert!(state.get_txtail(1).unwrap().is_none());
        assert!(state.get_txtail(2).unwrap().is_none());

        // Rounds 3, 4, 5 should still be present.
        for r in 3..=5u64 {
            assert!(state.get_block_data(r).unwrap().is_some());
            assert!(state.get_txtail(r).unwrap().is_some());
        }
    }

    // ── Heartbeat tests ──────────────────────────────────────────────

    /// Default seed used for heartbeat tests.
    const HB_TEST_SEED: [u8; 32] = [0xABu8; 32];

    fn heartbeat_txn(
        sender: Address,
        hb_address: Address,
        vote_id: [u8; 32],
        key_dilution: u64,
        fee: u64,
    ) -> SignedTransaction {
        heartbeat_txn_with_seed(
            sender,
            hb_address,
            vote_id,
            key_dilution,
            fee,
            &HB_TEST_SEED,
        )
    }

    fn heartbeat_txn_with_seed(
        sender: Address,
        hb_address: Address,
        vote_id: [u8; 32],
        key_dilution: u64,
        fee: u64,
        seed: &[u8; 32],
    ) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "hb".into();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        // first_valid = 1 (matching the round of the stored block header).
        stx.txn.first_valid = Round(1);
        stx.txn.heartbeat = Some(algo_types::HeartbeatTxnFields {
            address: hb_address,
            proof: None,
            seed: *seed,
            vote_id,
            key_dilution,
            hb_challenge_discount: false,
        });
        stx
    }

    /// Store a minimal block header at the given round with the given seed.
    /// Used by heartbeat tests so that HbSeed validation can find the header.
    fn store_block_header_with_seed(state: &mut LedgerState, round: u64, seed: &[u8; 32]) {
        use crate::store_trait::LedgerStore;

        // Build a minimal block with the seed for header encoding.
        let block = Block {
            round: Round(round),
            branch: [0u8; 32],
            seed: *seed,
            txn_commitment: [0u8; 32],
            timestamp: 0,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: Address::ZERO,
            fee_sink: Address::ZERO,
            rewards_pool: Address::ZERO,
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            load: 0,
            congestion_tax: 0,
            payset: vec![],
        };
        let hdrdata = algo_codec::canonical_encode_block_header_from_block(&block);
        let blkdata = algo_codec::encode_block(&block).unwrap();
        state
            .put_block(
                round,
                algo_types::consensus::CONSENSUS_V41,
                &hdrdata,
                &blkdata,
            )
            .unwrap();
    }

    /// Create an ApplyContext with heartbeat-compatible consensus params (V41).
    fn heartbeat_ctx(fee_sink: Address, round: u64) -> ApplyContext {
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .unwrap();
        ApplyContext {
            rewards_level: 0,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        }
    }

    #[test]
    fn test_heartbeat_updates_last_heartbeat() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );

        // Store block header at round 1 (first_valid) with matching seed.
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        // Set target account to Online with matching voting keys.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.last_heartbeat = 0;
        }

        let ctx = heartbeat_ctx(fee_sink, 100);
        let stx = heartbeat_txn(sender, target, vote_id, 10, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify last_heartbeat is updated to the current round.
        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, 100);

        // Verify fee was deducted from sender.
        let sender_acct = state.get_account(&sender).unwrap();
        assert_eq!(sender_acct.micro_algos, 999_000);
    }

    #[test]
    fn test_heartbeat_nonexistent_account_errors() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        // Only create sender and fee_sink -- target does NOT exist.
        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        let ctx = heartbeat_ctx(fee_sink, 100);
        let stx = heartbeat_txn(sender, target, vote_id, 10, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not exist"),
            "expected 'does not exist' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_heartbeat_vote_id_mismatch_errors() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let account_vote_id = [42u8; 32];
        let wrong_vote_id = [99u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        // Set target account with one vote_id.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(account_vote_id);
            acct.vote_key_dilution = 10;
        }

        let ctx = heartbeat_ctx(fee_sink, 100);
        // Heartbeat with a different vote_id.
        let stx = heartbeat_txn(sender, target, wrong_vote_id, 10, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("vote ID"),
            "expected 'vote ID' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_heartbeat_key_dilution_mismatch_errors() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        // Set target account with key_dilution=10.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
        }

        let ctx = heartbeat_ctx(fee_sink, 100);
        // Heartbeat with wrong key_dilution=99.
        let stx = heartbeat_txn(sender, target, vote_id, 99, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("key dilution"),
            "expected 'key dilution' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_heartbeat_missing_fields_errors() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);

        let ctx = heartbeat_ctx(fee_sink, 100);
        // Heartbeat with no heartbeat fields (None).
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "hb".into();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        // heartbeat field is None

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing heartbeat fields"),
            "expected 'missing heartbeat fields' in error: {}",
            err_msg
        );
    }

    // ── Expired / absent participation account tests ──────────────────

    /// Helper: create a minimal block for round 1 with the given protocol version,
    /// no transactions, and optional expired/absent lists.
    fn make_empty_block_with_protocol(
        fee_sink: Address,
        protocol: &str,
        expired: Option<Vec<Address>>,
        absent: Option<Vec<Address>>,
    ) -> Block {
        Block {
            round: Round(1),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 1000,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: Address::ZERO,
            fee_sink,
            rewards_pool: Address::ZERO,
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: protocol.to_string(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: expired,
            absent_participation_accounts: absent,
            load: 0,
            congestion_tax: 0,
            payset: vec![],
        }
    }

    #[test]
    fn test_expired_accounts_clear_online_state() {
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        // Set up the expired account as Online with voting keys.
        // vote_last_valid = 0 so it is less than block round (1), i.e. truly expired.
        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.state_proof_id = Some([3u8; 64]);
            acct.vote_first_valid = 0;
            acct.vote_last_valid = 0;
            acct.vote_key_dilution = 50;
            acct.incentive_eligible = true;
        }

        // V41 has max_proposed_expired_online_accounts = 32.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            None,
        );

        apply_block(&mut state, &block).unwrap();

        // Verify the account is now Offline with all voting keys cleared.
        let acct = state.get_account(&expired_addr).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert!(acct.vote_id.is_none());
        assert!(acct.selection_id.is_none());
        assert!(acct.state_proof_id.is_none());
        assert_eq!(acct.vote_first_valid, 0);
        assert_eq!(acct.vote_last_valid, 0);
        assert_eq!(acct.vote_key_dilution, 0);
        // Balance should be unchanged (no fee deducted for end-of-block processing).
        assert_eq!(acct.micro_algos, 5_000_000);
    }

    #[test]
    fn test_absent_accounts_suspend_preserves_keys() {
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        // Set up the absent account as Online with voting keys and incentive eligible.
        let vote_id = [42u8; 32];
        let selection_id = [43u8; 32];
        let state_proof_id = [44u8; 64];
        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.selection_id = Some(selection_id);
            acct.state_proof_id = Some(state_proof_id);
            acct.vote_first_valid = 100;
            acct.vote_last_valid = 999_999;
            acct.vote_key_dilution = 50;
            acct.incentive_eligible = true;
        }

        // V41 has payouts_enabled = true.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr]),
        );

        apply_block(&mut state, &block).unwrap();

        // Verify the account is now Offline with incentive_eligible = false.
        let acct = state.get_account(&absent_addr).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert!(!acct.incentive_eligible);

        // Voting keys should be PRESERVED (unlike expired which clears them).
        assert_eq!(acct.vote_id, Some(vote_id));
        assert_eq!(acct.selection_id, Some(selection_id));
        assert_eq!(acct.state_proof_id, Some(state_proof_id));
        assert_eq!(acct.vote_first_valid, 100);
        assert_eq!(acct.vote_last_valid, 999_999);
        assert_eq!(acct.vote_key_dilution, 50);
    }

    #[test]
    fn test_expired_gating_pre_v31_skips_processing() {
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
        }

        // V30 has max_proposed_expired_online_accounts = 0.
        // Any non-empty list should be rejected.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V30,
            Some(vec![expired_addr]),
            None,
        );

        let result = apply_block(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("greater than expected"),
            "expected gating error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_expired_empty_list_pre_v31_succeeds() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // V30 has max_proposed_expired_online_accounts = 0.
        // An empty list (or None) should succeed.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V30,
            None,
            None,
        );

        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_absent_gating_payouts_not_enabled_validate() {
        // V39 does not have payouts_enabled (payouts_max_mark_absent = 0).
        // In validate mode, a non-empty absent list should be rejected by
        // the count check (absent.len() > 0 = max).
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V39,
            None,
            Some(vec![absent_addr]),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("greater than expected"),
            "expected count overflow error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_gating_payouts_not_enabled_replay_succeeds() {
        // V39 does not have payouts_enabled. In replay mode, no validation
        // runs, so the suspend just applies (matching Go's replay behavior).
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V39,
            None,
            Some(vec![absent_addr]),
        );

        // Replay mode: no validation, apply succeeds.
        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_absent_empty_list_payouts_not_enabled_succeeds() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // V39 does not have payouts_enabled.
        // An empty list (or None) should succeed.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V39,
            None,
            None,
        );

        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_empty_expired_and_absent_lists_noop() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // V41 with empty lists — should be a no-op.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![]),
            Some(vec![]),
        );

        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_integration_block_with_expired_and_absent() {
        let expired_addr = Address([10u8; 32]);
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (expired_addr, 5_000_000),
                (absent_addr, 5_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );

        // Set up expired account as Online with voting keys.
        // vote_last_valid = 0 so it is less than block round (1), i.e. truly expired.
        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.state_proof_id = Some([3u8; 64]);
            acct.vote_first_valid = 0;
            acct.vote_last_valid = 0;
            acct.vote_key_dilution = 50;
            acct.incentive_eligible = true;
        }

        // Set up absent account as Online with voting keys.
        let absent_vote_id = [42u8; 32];
        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(absent_vote_id);
            acct.selection_id = Some([43u8; 32]);
            acct.state_proof_id = Some([44u8; 64]);
            acct.vote_first_valid = 100;
            acct.vote_last_valid = 999_999;
            acct.vote_key_dilution = 50;
            acct.incentive_eligible = true;
        }

        // Build block with both expired and absent lists.
        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            Some(vec![absent_addr]),
        );

        apply_block(&mut state, &block).unwrap();

        // Verify expired: Offline, keys cleared.
        let expired_acct = state.get_account(&expired_addr).unwrap();
        assert_eq!(expired_acct.status, AccountStatus::Offline);
        assert!(expired_acct.vote_id.is_none());
        assert!(expired_acct.selection_id.is_none());
        assert!(expired_acct.state_proof_id.is_none());
        assert_eq!(expired_acct.vote_first_valid, 0);
        assert_eq!(expired_acct.vote_last_valid, 0);
        assert_eq!(expired_acct.vote_key_dilution, 0);

        // Verify absent: Offline, incentive_eligible = false, keys preserved.
        let absent_acct = state.get_account(&absent_addr).unwrap();
        assert_eq!(absent_acct.status, AccountStatus::Offline);
        assert!(!absent_acct.incentive_eligible);
        assert_eq!(absent_acct.vote_id, Some(absent_vote_id));
        assert_eq!(absent_acct.selection_id, Some([43u8; 32]));
        assert_eq!(absent_acct.state_proof_id, Some([44u8; 64]));
        assert_eq!(absent_acct.vote_first_valid, 100);
        assert_eq!(absent_acct.vote_last_valid, 999_999);
        assert_eq!(absent_acct.vote_key_dilution, 50);
    }

    #[test]
    fn test_expired_exceeds_max_errors() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // Create 33 expired addresses (max is 32 for V41).
        let expired: Vec<Address> = (0..33u8).map(|i| Address([100 + i; 32])).collect();
        for addr in &expired {
            let acct = state.get_or_default_account_mut(addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(expired),
            None,
        );

        let result = apply_block(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("greater than expected"),
            "expected overflow error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_expired_at_max_succeeds() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // Create exactly 32 expired addresses (max is 32 for V41).
        let expired: Vec<Address> = (0..32u8).map(|i| Address([100 + i; 32])).collect();
        for addr in &expired {
            let acct = state.get_or_default_account_mut(addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.micro_algos = 1_000_000;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(expired.clone()),
            None,
        );

        apply_block(&mut state, &block).unwrap();

        // All 32 accounts should be set Offline with cleared keys.
        for addr in &expired {
            let acct = state.get_account(addr).unwrap();
            assert_eq!(acct.status, AccountStatus::Offline);
            assert!(acct.vote_id.is_none());
        }
    }

    // ── New tests for issue #62 fixes ──────────────────────────────────

    #[test]
    fn test_heartbeat_seed_mismatch_errors() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );

        // Store block header at round 1 with one seed.
        let block_seed = [0xBBu8; 32];
        store_block_header_with_seed(&mut state, 1, &block_seed);

        // Set target account to Online with matching voting keys.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
        }

        let ctx = heartbeat_ctx(fee_sink, 100);
        // Heartbeat with a different seed than the block.
        let wrong_seed = [0xCCu8; 32];
        let stx = heartbeat_txn_with_seed(sender, target, vote_id, 10, 1_000, &wrong_seed);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("provided seed does not match"),
            "expected seed mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_heartbeat_seed_match_succeeds() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );

        // Store block header at round 1 with a specific seed.
        let seed = [0xDDu8; 32];
        store_block_header_with_seed(&mut state, 1, &seed);

        // Set target account to Online with matching voting keys.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
        }

        let ctx = heartbeat_ctx(fee_sink, 100);
        // Heartbeat with the same seed as the block.
        let stx = heartbeat_txn_with_seed(sender, target, vote_id, 10, 1_000, &seed);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify heartbeat was applied.
        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, 100);
    }

    #[test]
    fn test_heartbeat_rejected_pre_v40() {
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 500_000), (fee_sink, 0)],
            fee_sink,
        );

        // Set target account to Online.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
        }

        // V39 does not support heartbeats (enable_heartbeat = false).
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V39,
        )
        .unwrap();
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
            round: 100,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        };
        let stx = heartbeat_txn(sender, target, vote_id, 10, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("heartbeat transaction not supported"),
            "expected heartbeat not supported error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_exceeds_max_errors() {
        // The count check for absent accounts is in the validate path
        // (matching Go's validateAbsentOnlineAccounts), not the apply path.
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // Create 33 absent addresses (max is 32 for V41).
        let absent: Vec<Address> = (0..33u8).map(|i| Address([100 + i; 32])).collect();
        for addr in &absent {
            let acct = state.get_or_default_account_mut(addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.incentive_eligible = true;
            acct.micro_algos = 1_000_000;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(absent),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("greater than expected"),
            "expected absent overflow error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_at_max_succeeds() {
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        // Create exactly 32 absent addresses (max is 32 for V41).
        let absent: Vec<Address> = (0..32u8).map(|i| Address([100 + i; 32])).collect();
        for addr in &absent {
            let acct = state.get_or_default_account_mut(addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.incentive_eligible = true;
            acct.micro_algos = 1_000_000;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(absent.clone()),
        );

        apply_block(&mut state, &block).unwrap();

        // All 32 accounts should be suspended (Offline, not incentive eligible).
        for addr in &absent {
            let acct = state.get_account(addr).unwrap();
            assert_eq!(acct.status, AccountStatus::Offline);
            assert!(!acct.incentive_eligible);
        }
    }

    #[test]
    fn test_eob_error_rolls_back_partial_mutations() {
        // In validate mode: expired is valid (1 addr, max=32), but absent
        // exceeds max (33 addresses). The expired validate+apply will succeed,
        // then absent validate will fail. The rollback guard should revert
        // all end-of-block mutations.
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        // Set up expired account as Online with expired keys.
        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.vote_key_dilution = 50;
            acct.incentive_eligible = true;
            acct.vote_last_valid = 0; // Expired (< round 1)
        }

        let absent: Vec<Address> = (0..33u8).map(|i| Address([200 + i; 32])).collect();
        for addr in &absent {
            let acct = state.get_or_default_account_mut(addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.incentive_eligible = true;
            acct.micro_algos = 1_000_000;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            Some(absent),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());

        // The expired account should be ROLLED BACK to Online with keys intact.
        let acct = state.get_account(&expired_addr).unwrap();
        assert_eq!(
            acct.status,
            AccountStatus::Online,
            "expired account should be rolled back to Online"
        );
        assert!(
            acct.vote_id.is_some(),
            "expired account vote_id should be rolled back"
        );
    }

    // ── Cheap/free heartbeat path tests ─────────────────────────────────

    /// Helper: build a minimal msgpack-encoded block header for challenge lookup.
    /// The header contains the seed and protocol version needed by `find_challenge`.
    fn make_challenge_header_data(seed: &[u8; 32], proto: &str) -> Vec<u8> {
        use serde::Serialize;
        use serde_bytes::ByteBuf;

        #[derive(Serialize)]
        struct MinHeader {
            #[serde(rename = "seed")]
            seed: ByteBuf,
            #[serde(rename = "proto")]
            proto: String,
            #[serde(rename = "rnd")]
            rnd: u64,
        }

        let hdr = MinHeader {
            seed: ByteBuf::from(seed.to_vec()),
            proto: proto.to_string(),
            rnd: 0,
        };
        rmp_serde::to_vec_named(&hdr).expect("encode block header")
    }

    /// Helper: create an ApplyContext with V41 consensus parameters.
    fn make_v41_apply_context(fee_sink: Address, round: u64) -> ApplyContext {
        use algo_types::consensus::consensus_params_for_version;
        let consensus =
            consensus_params_for_version(algo_types::consensus::CONSENSUS_V41).expect("V41 params");
        ApplyContext {
            rewards_level: 0,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        }
    }

    fn apply_context_for_version(fee_sink: Address, round: u64, version: &str) -> ApplyContext {
        use algo_types::consensus::consensus_params_for_version;
        let consensus = consensus_params_for_version(version).expect("known version");
        ApplyContext {
            rewards_level: 100,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        }
    }

    /// UnfundedSenders (go-algorand v34+, `config/consensus.go`) activation
    /// boundary: a zero-balance, zero-fee sender (e.g. a fee-pooled group
    /// member) must not be forced into on-disk existence merely by a
    /// rewards-bookkeeping write when the transaction doesn't otherwise move
    /// algos through it.
    ///
    /// Before v34, the write always happens (a bumped `RewardsBase` makes the
    /// account no longer equal to `AccountData::default()`), which then trips
    /// the post-transaction min-balance check for a genuinely zero-balance
    /// account -- this is the actual historical bug `UnfundedSenders` fixes:
    /// pre-v34, a truly zero-balance account could not act as a transaction
    /// sender at all, even paying zero fee.
    #[test]
    fn unfunded_senders_skips_write_for_zero_balance_zero_fee_sender() {
        let sender = Address([7u8; 32]);
        let fee_sink = Address([3u8; 32]);

        // ── Pre-v34: the rewards-bookkeeping write happens unconditionally,
        // touching the zero-balance sender into existence and tripping the
        // min-balance check. ──
        let mut store_pre = LedgerState::new();
        store_pre.fee_sink = fee_sink;
        let ctx_pre = apply_context_for_version(fee_sink, 1, algo_types::consensus::CONSENSUS_V33);
        assert!(!ctx_pre.consensus.unfunded_senders);
        let txn_pre = pay_txn(sender, Address::default(), 0, 0);
        let err = apply_transaction(&mut store_pre, &txn_pre, &ctx_pre, 0)
            .expect_err("pre-v34 must reject a zero-balance sender (min balance violation)");
        assert!(
            format!("{err}").contains("below minimum balance"),
            "unexpected error: {err}"
        );

        // ── v34+: the write is skipped -- the sender stays fully
        // non-existent, so the min-balance check never sees it. ──
        let mut store_post = LedgerState::new();
        store_post.fee_sink = fee_sink;
        let ctx_post = apply_context_for_version(fee_sink, 1, algo_types::consensus::CONSENSUS_V34);
        assert!(ctx_post.consensus.unfunded_senders);
        let txn_post = pay_txn(sender, Address::default(), 0, 0);
        apply_transaction(&mut store_post, &txn_post, &ctx_post, 0).expect("apply v34+");
        assert!(
            store_post.get_account(&sender).is_none(),
            "v34+ must leave a zero-balance, zero-fee sender fully unwritten"
        );
    }

    #[test]
    fn test_cheap_heartbeat_challenged_account_succeeds() {
        // Test gap #1: Cheap heartbeat for a challenged account should succeed.
        // Challenge seed first 5 bits: 1111_1 (0xF8). Account address first 5 bits
        // must match: 1111_1xxx (e.g., 0xFF).
        let seed = [0xF8; 32];
        let target = Address([0xFF; 32]); // First 5 bits match seed.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        // Set target account as Online, IncentiveEligible, with voting keys.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = true;
            acct.last_heartbeat = 0; // Not heartbeated since before challenge.
            acct.last_proposed = 0;
        }

        // V41 params: interval=1000, grace=200, bits=5.
        // Challenge round = 2000 for rounds in [2000..3000).
        // Risky window: (2000 + 100, 2000 + 200] = (2100, 2200].
        // Use round 2150, which is in the risky window.
        let round = 2150;

        // Store block header data at challenge round 2000 with matching seed.
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
                .unwrap();
        }

        // Store block header at first_valid round (1) with matching HbSeed.
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        let ctx = make_v41_apply_context(fee_sink, round);
        // Fee = 0 (free heartbeat), singleton (no group).
        let stx = heartbeat_txn(sender, target, vote_id, 10, 0);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify last_heartbeat is updated.
        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, round);
    }

    #[test]
    fn test_cheap_heartbeat_non_matching_address_rejected() {
        // Test gap #2: Cheap heartbeat for account whose address does NOT match
        // challenge bits should fail.
        let seed = [0xF8; 32]; // First 5 bits: 1111_1
        let target = Address([0x00; 32]); // First bit differs — no match.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = true;
            acct.last_heartbeat = 0;
            acct.last_proposed = 0;
        }

        let round = 2150;
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
                .unwrap();
        }

        let ctx = make_v41_apply_context(fee_sink, round);
        let stx = heartbeat_txn(sender, target, vote_id, 10, 0);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not challenged"),
            "expected 'not challenged' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_cheap_heartbeat_non_incentive_eligible_rejected() {
        // Test gap #3: Cheap heartbeat for account that matches challenge but
        // is not IncentiveEligible should fail.
        let seed = [0xF8; 32];
        let target = Address([0xFF; 32]); // Matches seed.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = false; // NOT incentive eligible.
            acct.last_heartbeat = 0;
        }

        let round = 2150;
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
                .unwrap();
        }

        let ctx = make_v41_apply_context(fee_sink, round);
        let stx = heartbeat_txn(sender, target, vote_id, 10, 0);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not IncentiveEligible"),
            "expected 'not IncentiveEligible' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_cheap_heartbeat_offline_account_rejected() {
        // Test gap #4: Cheap heartbeat for Offline account should fail,
        // even if address matches challenge.
        let seed = [0xF8; 32];
        let target = Address([0xFF; 32]); // Matches seed bits.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Offline; // Offline.
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = true;
            acct.last_heartbeat = 0;
        }

        let round = 2150;
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
                .unwrap();
        }

        let ctx = make_v41_apply_context(fee_sink, round);
        let stx = heartbeat_txn(sender, target, vote_id, 10, 0);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not allowed for Offline"),
            "expected 'not allowed for Offline' in error: {}",
            err_msg
        );
    }

    /// Helper: create an ApplyContext with V42 consensus parameters (size
    /// pricing / explicit `HbChallengeDiscount` enabled). V42 inherits V41's
    /// payout-challenge parameters unchanged, so the same round/window math
    /// used by the V41 challenge tests above applies here too.
    fn make_v42_apply_context(fee_sink: Address, round: u64) -> ApplyContext {
        use algo_types::consensus::consensus_params_for_version;
        let consensus =
            consensus_params_for_version(algo_types::consensus::CONSENSUS_V42).expect("V42 params");
        assert!(consensus.txn_size_pricing_enabled());
        ApplyContext {
            rewards_level: 0,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        }
    }

    #[test]
    fn test_discounted_heartbeat_post_v42_challenged_account_succeeds() {
        // Post-v42 mirror of test_cheap_heartbeat_challenged_account_succeeds:
        // the explicit `hb_challenge_discount` flag (not fee underpayment)
        // claims the discount, and a genuinely challenged/eligible account is
        // still granted it.
        let seed = [0xF8; 32];
        let target = Address([0xFF; 32]); // First 5 bits match seed.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = true;
            acct.last_heartbeat = 0;
            acct.last_proposed = 0;
        }

        let round = 2150; // within the V41/V42-shared risky window.
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V42);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V42, &hdr, &[])
                .unwrap();
        }
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        let ctx = make_v42_apply_context(fee_sink, round);
        // Full fee paid (not underpaying) -- the flag alone claims the discount.
        let mut stx = heartbeat_txn(sender, target, vote_id, 10, ctx.consensus.min_txn_fee);
        stx.txn.heartbeat.as_mut().unwrap().hb_challenge_discount = true;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, round);
    }

    #[test]
    fn test_discounted_heartbeat_post_v42_not_incentive_eligible_rejected() {
        // Post-v42 mirror of test_cheap_heartbeat_non_incentive_eligible_rejected:
        // the explicit flag is a request, not an assertion -- apply must
        // still independently verify eligibility.
        let seed = [0xF8; 32];
        let target = Address([0xFF; 32]); // Matches seed.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = false; // NOT incentive eligible.
            acct.last_heartbeat = 0;
        }

        let round = 2150;
        {
            use crate::store_trait::LedgerStore;
            let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V42);
            state
                .put_block(2000, algo_types::consensus::CONSENSUS_V42, &hdr, &[])
                .unwrap();
        }

        let ctx = make_v42_apply_context(fee_sink, round);
        let mut stx = heartbeat_txn(sender, target, vote_id, 10, ctx.consensus.min_txn_fee);
        stx.txn.heartbeat.as_mut().unwrap().hb_challenge_discount = true;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not IncentiveEligible"),
            "expected 'not IncentiveEligible' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_heartbeat_post_v42_without_discount_flag_skips_eligibility_gate() {
        // Post-v42, a heartbeat that does NOT set hb_challenge_discount makes
        // no discount claim, so apply_heartbeat must not require online/
        // eligible/challenged status for it -- even though (pre-v42) an
        // underpaying singleton heartbeat would have implied exactly that.
        // (In a full pipeline this txn would be rejected upstream by the fee
        // check for underpaying without the flag; this test isolates
        // apply_heartbeat's own eligibility gate.)
        let target = Address([0x00; 32]); // Would NOT match any challenge seed.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );

        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Offline; // Would fail the eligibility gate.
            acct.vote_id = Some(vote_id);
            acct.vote_key_dilution = 10;
            acct.incentive_eligible = false;
            acct.last_heartbeat = 0;
        }

        let round = 2150;
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        let ctx = make_v42_apply_context(fee_sink, round);
        // No discount flag set, full fee paid -- kind is None, so the
        // online/eligible/challenged gate must not run at all.
        let stx = heartbeat_txn(sender, target, vote_id, 10, ctx.consensus.min_txn_fee);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, round);
    }

    #[test]
    fn test_store_header_provider_retrieves_correct_seed() {
        // Test gap #5: StoreHeaderProvider integration -- store a block header,
        // then look it up via StoreHeaderProvider and verify the seed.
        use crate::heartbeat::{HeaderProvider, StoreHeaderProvider};
        use crate::store_trait::LedgerStore;

        let fee_sink = Address([3u8; 32]);
        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let seed = [0xAB; 32];
        let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
        state
            .put_block(1000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
            .unwrap();

        let provider = StoreHeaderProvider { store: &state };
        let data = provider.block_header_data(1000).unwrap();
        assert!(data.is_some(), "block header should be retrievable");

        // Decode and verify the seed.
        let block = algo_codec::decode_block(&data.unwrap()).unwrap();
        let mut got_seed = [0u8; 32];
        got_seed.copy_from_slice(&block.seed[..32]);
        assert_eq!(got_seed, seed);

        // Non-existent round returns None.
        let missing = provider.block_header_data(9999).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_find_challenge_with_store_header_provider() {
        // Test gap #6: find_challenge with a real StoreHeaderProvider.
        use crate::heartbeat::{find_challenge, ChallengePeriod, StoreHeaderProvider};
        use crate::store_trait::LedgerStore;
        use algo_types::consensus::consensus_params_for_version;

        let fee_sink = Address([3u8; 32]);
        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let seed = [0xCD; 32];
        let hdr = make_challenge_header_data(&seed, algo_types::consensus::CONSENSUS_V41);
        state
            .put_block(2000, algo_types::consensus::CONSENSUS_V41, &hdr, &[])
            .unwrap();

        let params =
            consensus_params_for_version(algo_types::consensus::CONSENSUS_V41).expect("V41 params");
        let provider = StoreHeaderProvider { store: &state };

        // Round 2150 is in the risky window (2100, 2200].
        let ch = find_challenge(&params, 2150, &provider, ChallengePeriod::Risky);
        assert!(!ch.is_zero());
        assert_eq!(ch.round, 2000);
        assert_eq!(ch.seed, seed);
        assert_eq!(ch.bits, 5);

        // Round outside risky window should return zero challenge.
        let ch = find_challenge(&params, 2050, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    #[test]
    fn test_heartbeat_on_suspended_account_updates_last_heartbeat() {
        // Test gap #7: A suspended account (Offline with voting keys) receives
        // a normal-fee heartbeat. The heartbeat should succeed and update
        // last_heartbeat. (A cheap heartbeat would be rejected because the
        // cheap path requires status == Online.)
        let sender = Address([1u8; 32]);
        let target = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (target, 5_000_000), (fee_sink, 0)],
            fee_sink,
        );
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        // Set target as suspended: Offline but with voting keys intact.
        {
            let acct = state.get_or_default_account_mut(&target);
            acct.status = AccountStatus::Offline;
            acct.vote_id = Some(vote_id);
            acct.selection_id = Some([2u8; 32]);
            acct.vote_key_dilution = 10;
            acct.vote_first_valid = 100;
            acct.vote_last_valid = 999_999;
            acct.incentive_eligible = false; // Cleared by suspension.
            acct.last_heartbeat = 0;
        }

        let ctx = heartbeat_ctx(fee_sink, 500);
        // Normal fee (>= MinTxnFee of 1000), so it bypasses the cheap heartbeat check.
        let stx = heartbeat_txn(sender, target, vote_id, 10, 1_000);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify last_heartbeat is updated.
        let acct = state.get_account(&target).unwrap();
        assert_eq!(acct.last_heartbeat, 500);

        // Account remains Offline -- heartbeat only updates last_heartbeat,
        // it does NOT restore Online status (that requires a keyreg).
        assert_eq!(acct.status, AccountStatus::Offline);

        // Voting keys are preserved.
        assert_eq!(acct.vote_id, Some(vote_id));
    }

    #[test]
    fn test_multiple_heartbeats_in_same_block() {
        // Test gap #8: Two heartbeat transactions for different accounts
        // in the same block should both succeed.
        let sender = Address([1u8; 32]);
        let target1 = Address([10u8; 32]);
        let target2 = Address([20u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let vote_id1 = [41u8; 32];
        let vote_id2 = [42u8; 32];

        let mut state = make_state_with_accounts(
            &[
                (sender, 10_000_000),
                (target1, 5_000_000),
                (target2, 5_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        store_block_header_with_seed(&mut state, 1, &HB_TEST_SEED);

        // Set up both accounts as Online with voting keys.
        {
            let acct = state.get_or_default_account_mut(&target1);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id1);
            acct.vote_key_dilution = 10;
            acct.last_heartbeat = 0;
        }
        {
            let acct = state.get_or_default_account_mut(&target2);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some(vote_id2);
            acct.vote_key_dilution = 20;
            acct.last_heartbeat = 0;
        }

        let round = 500;
        let ctx = heartbeat_ctx(fee_sink, round);

        // Apply first heartbeat.
        let stx1 = heartbeat_txn(sender, target1, vote_id1, 10, 1_000);
        apply_transaction(&mut state, &stx1, &ctx, 0).unwrap();

        // Apply second heartbeat.
        let stx2 = heartbeat_txn(sender, target2, vote_id2, 20, 1_000);
        apply_transaction(&mut state, &stx2, &ctx, 0).unwrap();

        // Verify both accounts have updated last_heartbeat.
        let acct1 = state.get_account(&target1).unwrap();
        assert_eq!(acct1.last_heartbeat, round);

        let acct2 = state.get_account(&target2).unwrap();
        assert_eq!(acct2.last_heartbeat, round);

        // Verify fee deducted from sender for both heartbeats.
        let sender_acct = state.get_account(&sender).unwrap();
        assert_eq!(sender_acct.micro_algos, 10_000_000 - 2_000);
    }

    // ── Tests for non-existent accounts in expired/absent lists (issue #62) ──
    // In replay mode (validate=false), nonexistent accounts are treated as
    // defaults (matching Go's lookup). In validate mode, they fail validation.

    #[test]
    fn test_expired_nonexistent_account_replay_applies_default() {
        // In replay mode, a nonexistent expired account gets a default
        // AccountData. ClearOnlineState is applied (a no-op on defaults).
        // This matches Go where lookup returns default for missing accounts.
        let fee_sink = Address([3u8; 32]);
        let nonexistent = Address([99u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![nonexistent]),
            None,
        );

        // Replay mode: no validation, just apply. Should succeed.
        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_expired_nonexistent_account_validate_errors() {
        // In validate mode, a nonexistent expired account has no vote key,
        // so it fails the "had no vote key" check.
        let fee_sink = Address([3u8; 32]);
        let nonexistent = Address([99u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![nonexistent]),
            None,
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("had no vote key"),
            "expected no-vote-key error for nonexistent expired, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_nonexistent_account_replay_applies_default() {
        // In replay mode, a nonexistent absent account gets a default
        // AccountData. Suspend is applied (sets Offline + not eligible).
        // This matches Go where lookup returns default for missing accounts.
        let fee_sink = Address([3u8; 32]);
        let nonexistent = Address([99u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![nonexistent]),
        );

        // Replay mode: no validation, just apply. Should succeed.
        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_absent_nonexistent_account_validate_errors() {
        // In validate mode, a nonexistent absent account has Offline status,
        // so it fails the "not Online" check.
        let fee_sink = Address([3u8; 32]);
        let nonexistent = Address([99u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![nonexistent]),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not Online"),
            "expected not-Online error for nonexistent absent, got: {}",
            err_msg
        );
    }

    // ── Validation-path tests (validate=true, matching Go's eval.validate) ──
    // These tests exercise the validate functions that are gated behind
    // ctx.validate=true (i.e., only during block validation, not replay).

    // Fix #2: Validate expired accounts have expired keys
    #[test]
    fn test_expired_validation_rejects_non_expired_keys() {
        // An account with vote_last_valid >= round should NOT be allowed in expired list.
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.vote_last_valid = 999; // Not expired (>= round 1)
            acct.vote_key_dilution = 50;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            None,
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("was not less than current round"),
            "expected non-expired key error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_expired_non_expired_keys_replay_succeeds() {
        // In replay mode, non-expired keys are NOT checked — apply just runs.
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.vote_last_valid = 999; // Not actually expired
            acct.vote_key_dilution = 50;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            None,
        );

        // Replay mode: validation skipped, apply succeeds.
        apply_block(&mut state, &block).unwrap();

        // Account should still be cleared (ClearOnlineState applied).
        let acct = state.get_account(&expired_addr).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert!(acct.vote_id.is_none());
    }

    #[test]
    fn test_expired_validation_rejects_no_vote_key() {
        // An account with no vote key should NOT be allowed in expired list.
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            // No vote_id set (None) -> should be rejected
            acct.vote_last_valid = 0;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr]),
            None,
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("had no vote key"),
            "expected no-vote-key error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_expired_validation_rejects_duplicate_addresses() {
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.vote_last_valid = 0;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr, expired_addr]), // duplicate!
            None,
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("duplicate address found"),
            "expected duplicate error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_expired_duplicate_addresses_replay_succeeds() {
        // In replay mode, duplicate check is skipped — apply just runs.
        let expired_addr = Address([10u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(expired_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&expired_addr);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.vote_last_valid = 0;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            Some(vec![expired_addr, expired_addr]), // duplicate
            None,
        );

        // Replay mode: no validation, apply succeeds.
        apply_block(&mut state, &block).unwrap();
    }

    // Fix #3: Validate absent accounts are Online, non-zero balance, IncentiveEligible
    #[test]
    fn test_absent_validation_rejects_offline_account() {
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Offline; // Not Online!
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr]),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not Online"),
            "expected not-Online error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_offline_account_replay_succeeds() {
        // In replay mode, Online check is skipped — Suspend just runs.
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Offline;
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr]),
        );

        // Replay mode: no validation, apply succeeds.
        apply_block(&mut state, &block).unwrap();
    }

    #[test]
    fn test_absent_validation_rejects_zero_balance() {
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.incentive_eligible = true;
            acct.micro_algos = 0; // Zero balance!
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr]),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("zero algos"),
            "expected zero-algos error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_validation_rejects_not_incentive_eligible() {
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.incentive_eligible = false; // Not incentive eligible!
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr]),
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not IncentiveEligible"),
            "expected not-IncentiveEligible error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_validation_rejects_duplicate_addresses() {
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr, absent_addr]), // duplicate!
        );

        let result = apply_block_validating(&mut state, &block);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("duplicate address found"),
            "expected duplicate error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_absent_duplicate_addresses_replay_succeeds() {
        // In replay mode, duplicate check is skipped — Suspend just runs.
        let absent_addr = Address([11u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state =
            make_state_with_accounts(&[(absent_addr, 5_000_000), (fee_sink, 0)], fee_sink);

        {
            let acct = state.get_or_default_account_mut(&absent_addr);
            acct.status = AccountStatus::Online;
            acct.incentive_eligible = true;
        }

        let block = make_empty_block_with_protocol(
            fee_sink,
            algo_types::consensus::CONSENSUS_V41,
            None,
            Some(vec![absent_addr, absent_addr]), // duplicate
        );

        // Replay mode: no validation, apply succeeds.
        apply_block(&mut state, &block).unwrap();
    }

    // Fix #4: Gate keyreg last_heartbeat/incentive_eligible on payouts_enabled
    #[test]
    fn test_keyreg_online_payouts_disabled_no_heartbeat_or_incentive() {
        // When payouts_enabled = false (pre-v40), keyreg should NOT set
        // last_heartbeat or incentive_eligible.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);

        // Use a pre-V40 consensus where payouts_enabled = false.
        let consensus = ConsensusParams {
            payouts_enabled: false,
            ..ConsensusParams::default()
        };

        let mut stx = keyreg_online_txn(sender, 3_000_000); // High fee
        stx.txn.fee = 3_000_000;

        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
            round: 1,
            mode: ApplyMode::Replay,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
            txn_counter: Cell::new(0),
            fee_credit: Cell::new(0),
            fee_residue: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
            avm_overrides: Default::default(),
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
        };

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Online);
        // With payouts disabled, last_heartbeat should remain 0.
        assert_eq!(
            acct.last_heartbeat, 0,
            "last_heartbeat should not be set when payouts_enabled = false"
        );
        // With payouts disabled, incentive_eligible should remain false.
        assert!(
            !acct.incentive_eligible,
            "incentive_eligible should not be set when payouts_enabled = false"
        );
    }

    #[test]
    fn test_keyreg_online_payouts_enabled_sets_heartbeat_and_incentive() {
        // When payouts_enabled = true (v40+) and fee >= go_online_fee,
        // keyreg should set last_heartbeat and incentive_eligible.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);

        let mut stx = keyreg_online_txn(sender, 2_000_000); // fee >= payouts_go_online_fee
        stx.txn.fee = 2_000_000;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Online);
        // With payouts enabled: last_heartbeat = round(1) + lookback(320) = 321.
        assert_eq!(acct.last_heartbeat, 321);
        // With payouts enabled and fee >= 2_000_000: incentive_eligible = true.
        assert!(acct.incentive_eligible);
    }

    #[test]
    fn test_keyreg_online_payouts_enabled_low_fee_no_incentive() {
        // When payouts_enabled = true but fee < go_online_fee,
        // last_heartbeat should be set but incentive_eligible should NOT.
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);

        let stx = keyreg_online_txn(sender, 1_000); // fee < payouts_go_online_fee

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Online);
        // last_heartbeat should still be set (independent of fee).
        assert_eq!(acct.last_heartbeat, 321);
        // But incentive_eligible should NOT be set (fee too low).
        assert!(!acct.incentive_eligible);
    }

    // ── Issue #586: AccountDeltas.app_resources/asset_resources/creatables/
    // totals population ─────────────────────────────────────────────────

    /// TDD regression for issue #586: before this fix, `apply_block_with_delta`
    /// hard-coded `asset_resources: Vec::new()` and `creatables: HashMap::new()`
    /// regardless of what the block actually did (a stale `TODO(#190)` --
    /// #190 itself is closed). An asset-create transaction must produce a
    /// real `AssetResourceRecord` (creator's params + holding) and a
    /// `ModifiedCreatable` entry.
    #[test]
    fn issue_586_asset_create_populates_asset_resources_and_creatables() {
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.asset_params = Some(algo_types::AssetParams {
            total: 1_000_000,
            unit_name: "UNIT".to_string(),
            asset_name: "Asset".to_string(),
            ..Default::default()
        });

        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };

        let delta = apply_block_with_delta(&mut state, &block).unwrap();

        assert_eq!(
            delta.accts.asset_resources.len(),
            1,
            "expected exactly one AssetResourceRecord: {:?}",
            delta.accts.asset_resources
        );
        let rec = &delta.accts.asset_resources[0];
        assert_eq!(rec.aidx, 1, "first txn_counter-derived asset id is 1");
        assert_eq!(rec.addr, creator);
        assert!(!rec.params.deleted);
        let params = rec.params.params.as_ref().expect("params delta present");
        assert_eq!(params.total, 1_000_000);
        assert_eq!(params.unit_name, "UNIT");
        assert!(!rec.holding.deleted);
        let holding = rec.holding.holding.as_ref().expect("holding delta present");
        assert_eq!(
            holding.amount, 1_000_000,
            "creator gets the full supply on create"
        );

        assert_eq!(delta.creatables.len(), 1);
        let creatable = delta.creatables.get(&1).expect("creatable entry for id 1");
        assert_eq!(creatable.ctype, 0, "0 = asset");
        assert!(creatable.created);
        assert_eq!(creatable.creator, creator);
    }

    /// TDD regression for issue #603 (found via live dual-node verification
    /// against a real go-algorand v4.7.0-stable node): an asset *destroy*
    /// Acfg must attribute the creator's holding removal too, not just the
    /// params removal. Before this fix, step 2b's `Acfg` match arm only
    /// tracked `asset_creators`/`asset_params_pre` for a non-create Acfg,
    /// never adding the creator to `asset_holding_keys` -- so even though
    /// `apply_acfg`'s destroy branch calls `store.remove_asset_holding`, the
    /// resulting `StateDelta.accts.asset_resources` entry for the destroy
    /// round only carried `Params: {Deleted: true}`, silently omitting
    /// `Holding: {Deleted: true}` even though the creator's holding really
    /// was removed by this round.
    #[test]
    fn issue_603_asset_destroy_populates_holding_removal() {
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        // Round 1: create the asset (manager = creator, so destroy is
        // authorized).
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "acfg".into();
        create.txn.sender = creator;
        create.txn.fee = 1_000;
        create.txn.asset_params = Some(algo_types::AssetParams {
            total: 1_000_000,
            unit_name: "UNIT".to_string(),
            asset_name: "Asset".to_string(),
            manager: Some(creator),
            ..Default::default()
        });
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        apply_block_with_delta(&mut state, &block1).unwrap();

        // Round 2: destroy it (empty `AssetParams` signals destroy).
        let mut destroy = SignedTransaction::default();
        destroy.txn.txn_type = "acfg".into();
        destroy.txn.sender = creator;
        destroy.txn.fee = 1_000;
        destroy.txn.config_asset = 1;
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![destroy],
            ..Block::default()
        };
        let delta = apply_block_with_delta(&mut state, &block2).unwrap();

        assert_eq!(
            delta.accts.asset_resources.len(),
            1,
            "expected exactly one AssetResourceRecord for the destroy round: {:?}",
            delta.accts.asset_resources
        );
        let rec = &delta.accts.asset_resources[0];
        assert_eq!(rec.aidx, 1);
        assert_eq!(rec.addr, creator);
        assert!(rec.params.deleted, "params must be marked deleted");
        assert!(rec.params.params.is_none());
        assert!(
            rec.holding.deleted,
            "creator's holding removal must be attributed to the destroy round \
             (apply_acfg calls remove_asset_holding on destroy): {rec:?}"
        );
        assert!(rec.holding.holding.is_none());

        let creatable = delta.creatables.get(&1).expect("creatable entry for id 1");
        assert_eq!(creatable.ctype, 0, "0 = asset");
        assert!(!creatable.created, "destroy => created=false");
        assert_eq!(creatable.creator, creator);
    }

    /// TDD regression for issue #603 (also found via live dual-node
    /// verification): a *reconfigure* Acfg that re-affirms identical
    /// manager/reserve/freeze/clawback values -- a legal, real no-op
    /// reconfigure -- must still produce a full `AssetResourceRecord`
    /// (both `Params` and `Holding`) in the round's `StateDelta`. Before
    /// this fix, both loops in step 4b only emitted a record when
    /// `pre != post`, so a value-identical reconfigure round produced an
    /// *empty* `asset_resources` -- go-algorand's real `/v2/deltas`
    /// response always includes the record regardless (its `AccountDeltas`
    /// tracks "was this resource `Put` during the round", not a value
    /// diff).
    #[test]
    fn issue_603_asset_reconfigure_with_unchanged_values_still_emits_record() {
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let mut create = SignedTransaction::default();
        create.txn.txn_type = "acfg".into();
        create.txn.sender = creator;
        create.txn.fee = 1_000;
        create.txn.asset_params = Some(algo_types::AssetParams {
            total: 1_000_000,
            unit_name: "UNIT".to_string(),
            asset_name: "Asset".to_string(),
            manager: Some(creator),
            reserve: Some(creator),
            freeze: Some(creator),
            clawback: Some(creator),
            ..Default::default()
        });
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        apply_block_with_delta(&mut state, &block1).unwrap();

        // Reconfigure with the exact same role addresses -- a real,
        // legal no-op reconfigure.
        let mut reconfig = SignedTransaction::default();
        reconfig.txn.txn_type = "acfg".into();
        reconfig.txn.sender = creator;
        reconfig.txn.fee = 1_000;
        reconfig.txn.config_asset = 1;
        reconfig.txn.asset_params = Some(algo_types::AssetParams {
            manager: Some(creator),
            reserve: Some(creator),
            freeze: Some(creator),
            clawback: Some(creator),
            ..Default::default()
        });
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![reconfig],
            ..Block::default()
        };
        let delta = apply_block_with_delta(&mut state, &block2).unwrap();

        assert_eq!(
            delta.accts.asset_resources.len(),
            1,
            "a value-identical reconfigure must still emit an AssetResourceRecord \
             (go tracks Put, not value diffs): {:?}",
            delta.accts.asset_resources
        );
        let rec = &delta.accts.asset_resources[0];
        assert_eq!(rec.aidx, 1);
        assert_eq!(rec.addr, creator);
        assert!(!rec.params.deleted);
        assert!(
            rec.params.params.is_some(),
            "Params must be present: {rec:?}"
        );
        assert!(!rec.holding.deleted);
        let holding = rec
            .holding
            .holding
            .as_ref()
            .expect("Holding must be present even though its value is unchanged");
        assert_eq!(holding.amount, 1_000_000);

        // A pure reconfigure is not a create/destroy transition -- no
        // Creatables entry.
        assert!(delta.creatables.is_empty());
    }

    /// TDD regression for issue #586: an app-create transaction must produce
    /// a real `AppResourceRecord` (creator's params delta) in
    /// `AccountDeltas::app_resources`, and a `ModifiedCreatable` entry.
    #[test]
    fn issue_586_app_create_populates_app_resources_and_creatables() {
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "appl".into();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01]));
        stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01]));

        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };

        let delta = apply_block_with_delta(&mut state, &block).unwrap();

        assert_eq!(
            delta.accts.app_resources.len(),
            1,
            "expected exactly one AppResourceRecord: {:?}",
            delta.accts.app_resources
        );
        let rec = &delta.accts.app_resources[0];
        assert_eq!(rec.aidx, 1, "first txn_counter-derived app id is 1");
        assert_eq!(rec.addr, creator);
        assert!(!rec.params.deleted);
        let params = rec.params.params.as_ref().expect("params delta present");
        assert_eq!(params.approval_program, vec![0x06, 0x81, 0x01]);

        assert_eq!(delta.creatables.len(), 1);
        let creatable = delta.creatables.get(&1).expect("creatable entry for id 1");
        assert_eq!(creatable.ctype, 1, "1 = app");
        assert!(creatable.created);
        assert_eq!(creatable.creator, creator);
    }

    /// TDD regression for issue #586: `StateDelta::totals` must reflect the
    /// real post-apply `AccountTotals`, not the permanent
    /// `AccountTotals::default()` stub. `LedgerState` computes this via a
    /// full scan (see `LedgerStore::account_totals`'s `LedgerState` impl in
    /// `state.rs`).
    #[test]
    fn issue_586_state_delta_totals_reflects_post_apply_balances() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (receiver, 0),
                (fee_sink, 0),
                (rewards_pool, 0),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;
        state.get_or_default_account_mut(&sender).status = AccountStatus::Online;
        state.get_or_default_account_mut(&receiver).status = AccountStatus::Online;

        let stx = pay_txn(sender, receiver, 1_000_000, 1_000);
        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };

        let delta = apply_block_with_delta(&mut state, &block).unwrap();

        // sender: 5_000_000 - 1_000_000 - 1_000 = 3_999_000; receiver:
        // 0 + 1_000_000 = 1_000_000; fee_sink (offline, excluded from
        // "online") absorbs the 1_000 fee. Total online money: 4_999_000.
        assert_eq!(delta.totals.online.money, 3_999_000 + 1_000_000);
        assert_eq!(
            delta.totals.online.reward_units,
            (3_999_000 / crate::rewards::REWARD_UNITS) + (1_000_000 / crate::rewards::REWARD_UNITS)
        );
    }

    // ── Issue #604: inner-transaction-touched resources ───────────────────

    /// TDD regression for issue #604: an `Appl` call whose approval program
    /// issues an inner `acfg` (asset create) via `itxn_submit` must produce
    /// a real `AssetResourceRecord` (the app account's params + holding, as
    /// creator) and a `ModifiedCreatable` entry -- not just apply the
    /// mutation to the ledger while silently omitting it from the
    /// `StateDelta`. Before this fix, step 2b's resource-key collection
    /// only walked the block's top-level `Acfg`/`Axfer`/`Afrz`/`Appl`
    /// fields, never an app call's inner transactions, so this asset
    /// simply never appeared in `delta.accts.asset_resources`/
    /// `delta.creatables` even though `store.get_asset_params` shows it was
    /// really created.
    ///
    /// Uses `ApplyMode::Execute` on a freshly-built (unexecuted) block, per
    /// the issue's own TDD instructions -- this is deliberately the harder
    /// case where no recorded `EvalDelta` exists before the apply to walk
    /// (see `recording_store`'s module doc comment for why that matters).
    #[test]
    fn issue_604_inner_acfg_create_populates_asset_resources_and_creatables() {
        // Scoped locally (not at module level) -- `LedgerState` has its own
        // inherent `get_or_default_account` with a different signature than
        // the trait's; see this module's top-of-file NOTE for why the
        // trait isn't brought into scope via a blanket `use`.
        use crate::store_trait::LedgerStore;

        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 20_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        // Approval program: on create (ApplicationID == 0), just approve.
        // On any later call, issue an inner acfg (asset create) and
        // approve. The same program runs for both create and call, exactly
        // like a real deployed app.
        let approval_src = "#pragma version 6\n\
            txn ApplicationID\n\
            bz approve\n\
            itxn_begin\n\
            int acfg\n\
            itxn_field TypeEnum\n\
            int 1000000\n\
            itxn_field ConfigAssetTotal\n\
            int 0\n\
            itxn_field ConfigAssetDecimals\n\
            byte \"UNIT\"\n\
            itxn_field ConfigAssetUnitName\n\
            byte \"Asset\"\n\
            itxn_field ConfigAssetName\n\
            itxn_submit\n\
            approve:\n\
            int 1\n\
            return\n";
        let approval = algo_avm::assembler::assemble_string(approval_src)
            .expect("approval program must assemble")
            .program;
        let clear = algo_avm::assembler::assemble_string("#pragma version 6\nint 1\nreturn\n")
            .expect("clear program must assemble")
            .program;

        // Round 1: create the app (no itxn -- ApplicationID == 0 on create).
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 1_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        assert_eq!(delta1.creatables.len(), 1, "app create must be a creatable");
        let (&app_id, app_creatable) = delta1.creatables.iter().next().unwrap();
        assert_eq!(app_creatable.ctype, 1, "1 = app");
        let app_addr = Address(crate::avm_context::app_address(app_id));

        // Round 2: fund the app account so its inner acfg can cover the
        // asset's minimum-balance requirement.
        let fund = pay_txn(creator, app_addr, 3_000_000, 1_000);
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![fund],
            ..Block::default()
        };
        apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute).unwrap();

        // Round 3: call the app -- its approval program itxn_submits an
        // inner acfg asset create. Outer fee covers the inner txn's fee via
        // fee pooling.
        let mut call = SignedTransaction::default();
        call.txn.txn_type = "appl".into();
        call.txn.sender = creator;
        call.txn.fee = 3_000;
        call.txn.application_id = app_id;
        let block3 = Block {
            round: Round(3),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![call],
            ..Block::default()
        };
        let delta3 = apply_block_with_delta_mode(&mut state, &block3, ApplyMode::Execute).unwrap();

        // Confirm the mutation itself really happened (the AVM execution
        // side was never in question -- only its *attribution* into the
        // StateDelta is what issue #604 is about).
        let created_asset_id = *state
            .created_assets_for_addr(&app_addr)
            .first()
            .map(|(id, _)| id)
            .expect("inner acfg must have created an asset owned by the app account");

        assert_eq!(
            delta3.accts.asset_resources.len(),
            1,
            "expected exactly one AssetResourceRecord for the inner-created asset: {:?}",
            delta3.accts.asset_resources
        );
        let rec = &delta3.accts.asset_resources[0];
        assert_eq!(rec.aidx, created_asset_id);
        assert_eq!(
            rec.addr, app_addr,
            "the app account (not the outer call's sender) is the inner acfg's creator"
        );
        assert!(!rec.params.deleted);
        let params = rec.params.params.as_ref().expect("params delta present");
        assert_eq!(params.total, 1_000_000);
        assert_eq!(params.unit_name, "UNIT");
        assert!(!rec.holding.deleted);
        let holding = rec.holding.holding.as_ref().expect("holding delta present");
        assert_eq!(
            holding.amount, 1_000_000,
            "the app account gets the full supply on create"
        );

        assert_eq!(
            delta3.creatables.len(),
            1,
            "expected exactly one ModifiedCreatable for the inner-created asset: {:?}",
            delta3.creatables
        );
        let creatable = delta3
            .creatables
            .get(&created_asset_id)
            .expect("creatable entry for the inner-created asset id");
        assert_eq!(creatable.ctype, 0, "0 = asset");
        assert!(creatable.created);
        assert_eq!(creatable.creator, app_addr);
    }

    /// TDD regression for issue #604, the harder half: an inner `acfg` that
    /// *reconfigures* an asset that already existed **before** this round
    /// (created by an ordinary top-level Acfg, not by the app). Unlike a
    /// create, this has a real pre-image to get right -- the fix must
    /// attribute the delta to the asset's original creator (not the app
    /// account that reconfigured it, matching go-algorand's
    /// creator-keyed `AssetParamsDelta`) and force-emit the creator's
    /// holding record alongside it (issue #603's "was this resource `Put`"
    /// semantics), using the value captured at the actual moment of
    /// mutation -- not a value read from the store after the whole block
    /// already applied, which would silently look like a no-op change.
    ///
    /// Reconfigure only lets an Acfg change the manager/reserve/freeze/
    /// clawback addresses (`apply_acfg`'s `Reconfigure` branch, matching
    /// go-algorand -- `unit_name`/`asset_name`/`total`/etc. are immutable
    /// after creation), so the inner acfg here reassigns the manager to a
    /// new address to produce a real, observable change.
    #[test]
    fn issue_604_inner_acfg_reconfigure_of_preexisting_asset_populates_asset_resources() {
        let creator = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([9u8; 32]);
        let new_manager = Address([7u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 20_000_000), (fee_sink, 0), (rewards_pool, 0)],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        // Approval program: on create, just approve. On any later call,
        // reconfigure the asset named by ApplicationArgs[0] (an 8-byte
        // big-endian asset id), reassigning its manager to the 32-byte
        // address in ApplicationArgs[1], then approve.
        let approval_src = "#pragma version 6\n\
            txn ApplicationID\n\
            bz approve\n\
            itxn_begin\n\
            int acfg\n\
            itxn_field TypeEnum\n\
            txna ApplicationArgs 0\n\
            btoi\n\
            itxn_field ConfigAsset\n\
            txna ApplicationArgs 1\n\
            itxn_field ConfigAssetManager\n\
            itxn_submit\n\
            approve:\n\
            int 1\n\
            return\n";
        let approval = algo_avm::assembler::assemble_string(approval_src)
            .expect("approval program must assemble")
            .program;
        let clear = algo_avm::assembler::assemble_string("#pragma version 6\nint 1\nreturn\n")
            .expect("clear program must assemble")
            .program;

        // Round 1: create the app.
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 1_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        let (&app_id, _) = delta1.creatables.iter().next().unwrap();
        let app_addr = Address(crate::avm_context::app_address(app_id));

        // Round 2: fund the app account (it must cover the inner acfg's
        // own fee via fee pooling in round 3) and have the creator create
        // a *separate*, pre-existing asset with the app account as
        // manager (so the app is authorized to reconfigure it later) --
        // an ordinary top-level Acfg, already correctly handled before
        // this fix.
        let fund = pay_txn(creator, app_addr, 3_000_000, 1_000);
        let mut asset_create = SignedTransaction::default();
        asset_create.txn.txn_type = "acfg".into();
        asset_create.txn.sender = creator;
        asset_create.txn.fee = 1_000;
        asset_create.txn.asset_params = Some(algo_types::AssetParams {
            total: 500_000,
            unit_name: "OLD".to_string(),
            asset_name: "Asset2".to_string(),
            manager: Some(app_addr),
            ..Default::default()
        });
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![fund, asset_create],
            ..Block::default()
        };
        let delta2 = apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute).unwrap();
        let (&asset_id, _) = delta2.creatables.iter().next().unwrap();

        // Round 3: call the app, passing the asset id as an app arg. Its
        // approval program itxn_submits an inner acfg reconfigure. Outer
        // fee covers the inner txn's fee via fee pooling.
        let mut call = SignedTransaction::default();
        call.txn.txn_type = "appl".into();
        call.txn.sender = creator;
        call.txn.fee = 3_000;
        call.txn.application_id = app_id;
        call.txn.app_arguments = Some(vec![
            Some(serde_bytes::ByteBuf::from(asset_id.to_be_bytes().to_vec())),
            Some(serde_bytes::ByteBuf::from(new_manager.0.to_vec())),
        ]);
        let block3 = Block {
            round: Round(3),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![call],
            ..Block::default()
        };
        let delta3 = apply_block_with_delta_mode(&mut state, &block3, ApplyMode::Execute).unwrap();

        assert_eq!(
            delta3.accts.asset_resources.len(),
            1,
            "expected exactly one AssetResourceRecord for the inner-reconfigured asset: {:?}",
            delta3.accts.asset_resources
        );
        let rec = &delta3.accts.asset_resources[0];
        assert_eq!(rec.aidx, asset_id);
        assert_eq!(
            rec.addr, creator,
            "the asset's original creator (not the reconfiguring app account) owns the params delta"
        );
        assert!(!rec.params.deleted);
        let params = rec.params.params.as_ref().expect("params delta present");
        assert_eq!(
            params.manager, new_manager,
            "the inner acfg's manager reassignment must have applied"
        );
        assert_eq!(
            params.unit_name, "OLD",
            "unit_name is immutable after creation -- reconfigure must not have touched it"
        );
        // Issue #603 force-emit semantics: the creator's holding record is
        // present even though its value (the original supply) is
        // unchanged by a reconfigure.
        assert!(!rec.holding.deleted);
        let holding = rec.holding.holding.as_ref().expect(
            "creator's holding must be force-emitted for an existing-asset Acfg, even via an inner txn",
        );
        assert_eq!(
            holding.amount, 500_000,
            "creator's original supply is unchanged"
        );

        assert!(
            delta3.creatables.is_empty(),
            "a pure reconfigure is not a create/destroy transition -- no Creatables entry: {:?}",
            delta3.creatables
        );
    }

    // ---- Issue #723: considerBudgetProgramWrites (oversized app-program
    // create/update gated behind the box I/O write budget) ----
    //
    // End-to-end tests through the full apply path (real AVM execution),
    // complementing the direct unit tests against
    // `LedgerAvmContext::consider_budget_program_writes` in
    // `avm_context.rs`'s test module. V41's free program-size tier is
    // `MaxAppTotalProgramLen(2048) * (1+MaxExtraAppProgramPages(3)) == 8192`
    // bytes (approval+clear combined); `BytesPerBoxReference == 2048`.

    /// An approving program of (approximately) `payload_len` extra bytes,
    /// built the same way as `bin/algod-rust/tests/
    /// live_fee_size_pricing_parity.rs`'s `program_of_len`: a `pushbytes`
    /// literal immediately `pop`ped, so the padding is real (assembled,
    /// executable) bytes rather than dead code after a terminator.
    fn padded_approving_program(payload_len: usize) -> Vec<u8> {
        // `pushbytes` literals are capped at 4096 bytes each, so split the
        // padding across as many chunks as needed (each immediately
        // `pop`ped) rather than one oversized literal.
        const CHUNK: usize = 3_800;
        let mut src = "#pragma version 6\n".to_string();
        let mut remaining = payload_len;
        while remaining > 0 {
            let take = remaining.min(CHUNK);
            src.push_str(&format!("pushbytes 0x{}\npop\n", "00".repeat(take)));
            remaining -= take;
        }
        src.push_str("int 1\nreturn\n");
        algo_avm::assembler::assemble_string(&src)
            .expect("padded program must assemble")
            .program
    }

    fn trivial_clear_program() -> Vec<u8> {
        algo_avm::assembler::assemble_string("#pragma version 6\nint 1\nreturn\n")
            .expect("clear program must assemble")
            .program
    }

    #[test]
    fn issue_723_create_with_oversized_program_and_no_box_refs_is_rejected() {
        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        let approval = padded_approving_program(8_200); // pushes total well past the 8192-byte free tier
        let clear = trivial_clear_program();
        let total_len = approval.len() + clear.len();
        assert!(
            total_len > 8_192,
            "test program must actually exceed V41's free tier, got {total_len}"
        );

        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        // No box refs supplied -> io_budget == 0, so any nonzero extra bytes
        // exceed it immediately.

        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };

        let err = apply_block_with_delta_mode(&mut state, &block, ApplyMode::Execute).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("write budget exceeded") && msg.contains("creating app"),
            "expected a write-budget-exceeded rejection for the oversized create, got: {msg}"
        );
    }

    #[test]
    fn issue_723_create_with_oversized_program_and_enough_box_bumps_is_accepted() {
        // Companion to the rejection test above: the identical oversized
        // create succeeds once enough empty ("io bump") box refs are
        // supplied to cover the program's extra bytes -- matching how
        // `bin/algod-rust/tests/live_fee_size_pricing_parity.rs`'s
        // `app_program_size_pricing_boundaries_match_live` works around
        // this exact gap today.
        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        let approval = padded_approving_program(8_200);
        let clear = trivial_clear_program();
        let total_len = approval.len() + clear.len();
        let extra = total_len.saturating_sub(8_192);
        let bumps_needed = extra.div_ceil(2_048); // V41 BytesPerBoxReference

        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        create.txn.boxes = Some(vec![algo_types::BoxRef::default(); bumps_needed]);

        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };

        let delta = apply_block_with_delta_mode(&mut state, &block, ApplyMode::Execute)
            .expect("enough io-bump box refs must satisfy the write budget");
        assert_eq!(
            delta.creatables.len(),
            1,
            "app create must succeed and register a creatable"
        );
    }

    #[test]
    fn issue_723_update_with_oversized_program_and_no_box_refs_is_rejected() {
        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        // Round 1: create a small (well within the free tier) app.
        let small_approval = trivial_clear_program();
        let small_clear = trivial_clear_program();
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(small_approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(small_clear));
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        let &app_id = delta1
            .creatables
            .keys()
            .next()
            .expect("app create must register a creatable");

        // Round 2: update it with an oversized program and no box refs.
        let approval = padded_approving_program(8_200);
        let clear = trivial_clear_program();
        let mut update = SignedTransaction::default();
        update.txn.txn_type = "appl".into();
        update.txn.sender = creator;
        update.txn.fee = 10_000;
        update.txn.application_id = app_id;
        update.txn.on_completion = ON_COMPLETION_UPDATE;
        update.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        update.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![update],
            ..Block::default()
        };

        let err = apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("write budget exceeded")
                && msg.contains(&format!("updating app {app_id}")),
            "expected a write-budget-exceeded rejection for the oversized update, got: {msg}"
        );
    }

    // ---- Issue #725: box read-I/O-budget check must run eagerly for every
    // top-level app call, not only when a box opcode actually executes ----
    //
    // Oracle: go-algorand's `EvalContract`'s eager
    // `if cx.caller == nil && !cx.readBudgetChecked { ... }` gate
    // (`data/transactions/logic/eval.go:1275-1344`) runs this check
    // unconditionally at the start of every top-level contract evaluation,
    // before a single opcode executes -- regardless of whether the
    // approval/clear-state program ever touches a box. Each test below uses
    // a trivial approval program (`int 1; return`) that never executes a
    // box opcode, so the *only* way the rejection below can fire is via the
    // eager top-level call added to `apply_appl` -- the pre-existing lazy
    // call sites (`available_app_box`, `itxn_submit`) are never reached.

    #[test]
    fn issue_725_no_box_opcode_but_oversized_referenced_box_is_rejected_eagerly() {
        use crate::store_trait::LedgerStore;

        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        // Round 1: create an app whose approval/clear programs never touch
        // any box opcode.
        let approval = trivial_clear_program();
        let clear = trivial_clear_program();
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        let &app_id = delta1
            .creatables
            .keys()
            .next()
            .expect("app create must register a creatable");

        // Directly seed an existing box for this app whose size (3000 bytes)
        // exceeds the I/O budget a single box reference grants
        // (`BytesPerBoxReference == 2048` under V41) -- standing in for a
        // box that was written to in some earlier round.
        state.set_box(app_id, b"mybox", vec![0u8; 3_000]);

        // Round 2: call the app again, referencing that box via `txn.boxes`,
        // but the approval program (still the same trivial, box-opcode-free
        // program) never actually reads it.
        let mut call = SignedTransaction::default();
        call.txn.txn_type = "appl".into();
        call.txn.sender = creator;
        call.txn.fee = 1_000;
        call.txn.application_id = app_id;
        call.txn.boxes = Some(vec![algo_types::BoxRef {
            index: 0,
            name: Some(serde_bytes::ByteBuf::from(b"mybox".to_vec())),
        }]);
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![call],
            ..Block::default()
        };

        let err = apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("read budget exceeded (3000 > 2048)"),
            "expected an eager read-budget rejection even though the program never executed a box opcode, got: {msg}"
        );
    }

    #[test]
    fn issue_725_no_box_opcode_and_small_referenced_box_is_accepted() {
        // Companion to the rejection test above: identical setup, but the
        // existing box is small enough to fit the I/O budget the single box
        // ref grants, so the call must succeed.
        use crate::store_trait::LedgerStore;

        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        let approval = trivial_clear_program();
        let clear = trivial_clear_program();
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        let &app_id = delta1
            .creatables
            .keys()
            .next()
            .expect("app create must register a creatable");

        // Well within the 2048-byte budget a single box ref grants.
        state.set_box(app_id, b"mybox", vec![0u8; 10]);

        let mut call = SignedTransaction::default();
        call.txn.txn_type = "appl".into();
        call.txn.sender = creator;
        call.txn.fee = 1_000;
        call.txn.application_id = app_id;
        call.txn.boxes = Some(vec![algo_types::BoxRef {
            index: 0,
            name: Some(serde_bytes::ByteBuf::from(b"mybox".to_vec())),
        }]);
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![call],
            ..Block::default()
        };

        apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute)
            .expect("a small existing box referenced without a box opcode must not be rejected");
    }

    #[test]
    fn issue_725_eager_check_does_not_double_count_when_box_opcode_also_runs() {
        // Regression for the `read_budget_checked` guard: a program that
        // *does* execute a box opcode (`box_len`) against the same
        // eagerly-checked box must not re-sum/re-reject on the lazy call
        // site inside `available_app_box` -- the eager `apply_appl` call
        // must have already flipped `read_budget_checked`, making the later
        // in-program call a no-op. Uses a box just under the budget so any
        // accidental double-counting (summing the box's bytes twice) would
        // push it over and wrongly reject.
        use crate::store_trait::LedgerStore;

        let creator = Address([7u8; 32]);
        let fee_sink = Address([0xFEu8; 32]);
        let rewards_pool = Address([0xFDu8; 32]);
        let mut state = make_state_with_accounts(&[(creator, 10_000_000)], fee_sink);

        // `box_len mybox` then discard both results, approve.
        let approval = algo_avm::assembler::assemble_string(
            "#pragma version 8\npushbytes \"mybox\"\nbox_len\npop\npop\nint 1\nreturn\n",
        )
        .expect("box_len program must assemble")
        .program;
        let clear = trivial_clear_program();
        let mut create = SignedTransaction::default();
        create.txn.txn_type = "appl".into();
        create.txn.sender = creator;
        create.txn.fee = 10_000;
        create.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval));
        create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(clear));
        create.txn.boxes = Some(vec![algo_types::BoxRef {
            index: 0,
            name: Some(serde_bytes::ByteBuf::from(b"mybox".to_vec())),
        }]);
        let block1 = Block {
            round: Round(1),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![create],
            ..Block::default()
        };
        let delta1 = apply_block_with_delta_mode(&mut state, &block1, ApplyMode::Execute).unwrap();
        let &app_id = delta1
            .creatables
            .keys()
            .next()
            .expect("app create must register a creatable");

        // Just under the single box ref's 2048-byte budget; double-counting
        // it (eager sum + a second, un-guarded lazy sum) would push the
        // total to 4000 and wrongly reject.
        state.set_box(app_id, b"mybox", vec![0u8; 2_000]);

        let approval2 = algo_avm::assembler::assemble_string(
            "#pragma version 8\npushbytes \"mybox\"\nbox_len\npop\npop\nint 1\nreturn\n",
        )
        .expect("box_len program must assemble")
        .program;
        let mut call = SignedTransaction::default();
        call.txn.txn_type = "appl".into();
        call.txn.sender = creator;
        call.txn.fee = 1_000;
        call.txn.application_id = app_id;
        call.txn.on_completion = ON_COMPLETION_UPDATE;
        call.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval2));
        call.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(trivial_clear_program()));
        call.txn.boxes = Some(vec![algo_types::BoxRef {
            index: 0,
            name: Some(serde_bytes::ByteBuf::from(b"mybox".to_vec())),
        }]);
        let block2 = Block {
            round: Round(2),
            fee_sink,
            rewards_pool,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![call],
            ..Block::default()
        };

        apply_block_with_delta_mode(&mut state, &block2, ApplyMode::Execute).expect(
            "eager read-budget check + a later in-program box opcode must not double-count the same box",
        );
    }
}
