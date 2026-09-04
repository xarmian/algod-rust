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

//! Simulation trace types for capturing AVM execution details.
//!
//! These types mirror go-algorand's `ledger/simulation/trace.go` and represent
//! the internal simulation result structure. They are separate from the REST
//! API model types; conversion to REST types happens in the API layer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use algo_avm::tracer::{AppStateAccess, AppStateOp, AppStateType};
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, Round, SignedTransaction, TealValue};

use crate::apply::ApplyData;
use crate::eval_delta::parse_eval_delta;

/// Configuration controlling what execution details to capture during simulation.
///
/// Mirrors go-algorand's `simulation.ExecTraceConfig`.
#[derive(Debug, Clone, Default)]
pub struct ExecTraceConfig {
    /// Whether execution tracing is enabled at all.
    pub enable: bool,
    /// Whether to capture stack state after each opcode.
    pub stack: bool,
    /// Whether to capture scratch space changes after each opcode.
    pub scratch: bool,
    /// Whether to capture application state changes (global/local/box).
    pub state: bool,
}

impl ExecTraceConfig {
    /// Returns `true` if any tracing feature is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enable
    }
}

/// A path identifying a transaction within a group, including inner
/// transaction nesting.
///
/// For a top-level transaction at index 2, this is `[2]`.
/// For the first inner transaction of that transaction, `[2, 0]`.
pub type TxnPath = Vec<usize>;

/// A single opcode trace entry.
///
/// Mirrors go-algorand's `simulation.OpcodeTraceUnit`.
#[derive(Debug, Clone, Default)]
pub struct OpcodeTraceUnit {
    /// Program counter (instruction index) of the executed opcode.
    pub pc: usize,
    /// Values added to the stack by this opcode (captured if `ExecTraceConfig::stack`).
    pub stack_additions: Vec<AvmValueTrace>,
    /// Number of values popped from the stack by this opcode.
    pub stack_pop_count: usize,
    /// Scratch space changes: `(slot_index, new_value)` pairs.
    pub scratch_changes: Vec<(usize, AvmValueTrace)>,
    /// Application state changes (global/local/box writes).
    pub state_changes: Vec<StateChange>,
    /// Indices of inner transactions spawned by this opcode.
    pub spawned_inners: Vec<usize>,
}

/// A traced AVM value (stack or scratch).
///
/// Separate from `algo_avm::machine::AvmValue` to allow serialization-friendly
/// representation without requiring the AVM crate's internal types.
#[derive(Debug, Clone)]
pub enum AvmValueTrace {
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Byte string.
    Bytes(Vec<u8>),
}

/// An application state change recorded during tracing.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// What kind of state was changed.
    pub kind: StateChangeKind,
    /// Whether the opcode wrote or deleted the state.
    ///
    /// Carried explicitly (rather than inferred from `new_value`) because a
    /// box write whose opcode errors leaves `new_value` empty — go-algorand
    /// still reports it as a write (`AppStateOp` is fixed in `BeforeOpcode`,
    /// the value is only filled on success in `AfterOpcode`).
    pub op: StateChangeOp,
    /// The application ID.
    pub app_id: u64,
    /// The state key.
    pub key: Vec<u8>,
    /// The new value (None for deletions, or a not-yet-filled box write).
    pub new_value: Option<AvmValueTrace>,
    /// The account address (for local state changes).
    pub account: Option<Address>,
}

/// Whether a recorded [`StateChange`] wrote or deleted state, mirroring the
/// write/delete cases of go-algorand's `logic.AppStateOpEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateChangeOp {
    /// A write (`app_global_put`, `app_local_put`, `box_put`/`box_create`/…).
    Write,
    /// A delete (`app_global_del`, `app_local_del`, `box_del`).
    Delete,
}

/// The kind of application state that was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateChangeKind {
    /// Global state write.
    GlobalState,
    /// Local state write.
    LocalState,
    /// Box storage write.
    BoxState,
}

/// Execution trace for a single program (approval, clear-state, or logicsig).
#[derive(Debug, Clone, Default)]
pub struct ProgramTrace {
    /// Opcode-level trace entries, one per executed opcode.
    pub opcodes: Vec<OpcodeTraceUnit>,
}

/// Execution trace for a single transaction, including inner transactions.
///
/// Mirrors go-algorand's `simulation.TransactionTrace`.
#[derive(Debug, Clone, Default)]
pub struct TransactionTrace {
    /// Trace of the approval program execution (if applicable).
    pub approval_program_trace: Option<ProgramTrace>,
    /// SHA-512/256 hash of the approval program, if one was executed.
    pub approval_program_hash: Option<[u8; 32]>,
    /// Trace of the clear-state program execution (if applicable).
    pub clear_state_program_trace: Option<ProgramTrace>,
    /// SHA-512/256 hash of the clear-state program, if one was executed.
    pub clear_state_program_hash: Option<[u8; 32]>,
    /// `true` if the clear-state program failed (rejected or errored) and its
    /// persistent state changes were rolled back. Mirrors go-algorand's
    /// `TransactionTrace.ClearStateRollback`.
    pub clear_state_rollback: bool,
    /// Error message explaining why the clear-state program failed. Populated
    /// only when [`Self::clear_state_rollback`] is `true` and the failure was
    /// due to an execution error (not a plain rejection). Mirrors
    /// go-algorand's `TransactionTrace.ClearStateRollbackError`.
    pub clear_state_rollback_error: Option<String>,
    /// Trace of the logic signature execution (if applicable).
    pub logicsig_trace: Option<ProgramTrace>,
    /// SHA-512/256 hash of the logic signature program, if one was executed.
    pub logicsig_hash: Option<[u8; 32]>,
    /// Traces of inner transactions spawned during execution.
    pub inner_traces: Vec<TransactionTrace>,
}

/// Result for a single transaction within a simulated group.
///
/// Mirrors go-algorand's `simulation.TxnResult`.
#[derive(Debug, Clone, Default)]
pub struct TxnResult {
    /// Application budget consumed by this transaction.
    pub app_budget_consumed: u64,
    /// LogicSig budget consumed by this transaction.
    pub logicsig_budget_consumed: u64,
    /// Execution trace (populated if tracing is enabled).
    pub trace: Option<TransactionTrace>,
    /// If FixSigners was requested, the corrected signer address.
    pub fixed_signer: Option<Address>,
    /// The original signed transaction.
    pub txn: Option<SignedTransaction>,
    /// Apply data from execution.
    pub apply_data: Option<ApplyData>,
    /// Total fee actually paid by this transaction, plus (recursively,
    /// saturating) every descendant inner transaction's fee. A plain factual
    /// report of what was paid — not what was *required* (see
    /// [`TxnGroupResult::group_usage`] for that). Mirrors go-algorand's
    /// `TxnResult.FeesPaid` (`ledger/simulation/trace.go`).
    ///
    /// There is deliberately no per-transaction `usage` field: upstream's own
    /// comment in `populateFeeUsage` explains that fees pool across the group
    /// and round up once for the whole tree, so usage is only actionable at
    /// the group level (see [`TxnGroupResult::group_usage`]).
    pub fees_paid: u64,
}

/// Result for a transaction group.
///
/// Mirrors go-algorand's `simulation.TxnGroupResult`.
#[derive(Debug, Clone, Default)]
pub struct TxnGroupResult {
    /// Per-transaction results.
    pub txn_results: Vec<TxnResult>,
    /// Human-readable failure message, if the group failed.
    pub failure_message: Option<String>,
    /// Path to the transaction that caused failure.
    pub failed_at: Option<TxnPath>,
    /// Total application budget added for this group.
    pub app_budget_added: u64,
    /// Total application budget consumed by this group.
    pub app_budget_consumed: u64,
    /// Unnamed resources accessed by the group, populated when the request
    /// set `allow_unnamed_resources` and any were accessed. Always reported
    /// at the group level (go-algorand additionally reports per-transaction
    /// for pre-resource-sharing program versions; this engine does not).
    pub unnamed_resources_accessed: Option<UnnamedResourcesAccessed>,
    /// Total fee usage (in `Micros`, see [`algo_validate::fee`]) required by
    /// this group and all descendant inner-transaction groups, recursively
    /// summed (saturating). Mirrors go-algorand's `TxnGroupResult.GroupUsage`.
    pub group_usage: u64,
    /// Total fee actually paid by this group and all descendant
    /// inner-transaction groups, recursively summed (saturating). Mirrors
    /// go-algorand's `TxnGroupResult.GroupFeesPaid`.
    pub group_fees_paid: u64,
}

/// Mirrors go-algorand's `summarizeTxnFeesPaid(txn)` (`ledger/simulation/trace.go`):
/// the fee actually paid by `txn`, plus (recursively, saturating) every
/// descendant inner transaction's fee, found by walking `eval_delta`'s `itx`
/// entries. `eval_delta` is the transaction's *own* post-execution delta
/// (`ApplyData.eval_delta` for a top-level transaction, or the `eval_delta`
/// field carried directly on an inner [`SignedTransaction`] — both shapes
/// nest the same way since each inner txn's `dt` is fully encoded before its
/// parent's is, per [`crate::eval_delta::encode_eval_delta`]'s doc comment).
pub fn summarize_txn_fees_paid(fee: u64, eval_delta: Option<&rmpv::Value>) -> u64 {
    let mut fees_paid = fee;
    if let Some(dt) = eval_delta {
        if let Ok(delta) = parse_eval_delta(dt) {
            if let Some(inner_txns) = &delta.inner_txns {
                for inner in inner_txns {
                    fees_paid = fees_paid.saturating_add(summarize_txn_fees_paid(
                        inner.txn.fee,
                        inner.eval_delta.as_ref(),
                    ));
                }
            }
        }
    }
    fees_paid
}

/// Mirrors go-algorand's `summarizeTxnGroupFeeUsage(txgroup, proto)`
/// (`ledger/simulation/trace.go`): the pooled fee usage/fees-paid required by
/// `txgroup` — via [`algo_validate::summarize_fees`], which mirrors go's
/// `transactions.SummarizeFees` — plus (recursively, saturating) the
/// usage/fees-paid of every member's descendant inner-txn group, found via
/// each member's own `eval_delta` field.
///
/// Every itxn_submit call spawned anywhere within one transaction's execution
/// is flattened into a single list on that transaction's `eval_delta` (see
/// [`crate::avm_context`]'s `to_avm_result`), matching go-algorand's flat
/// `ApplyData.EvalDelta.InnerTxns`; that flat list is itself treated as one
/// pooled group here, exactly as upstream does.
pub fn summarize_txn_group_fee_usage(
    txgroup: &[SignedTransaction],
    params: &ConsensusParams,
) -> (u64, u64) {
    let group_refs: Vec<&SignedTransaction> = txgroup.iter().collect();
    let (mut usage, mut fees_paid) = algo_validate::summarize_fees(&group_refs, params);
    for txn in txgroup {
        if let Some(dt) = &txn.eval_delta {
            if let Ok(delta) = parse_eval_delta(dt) {
                if let Some(inner_txns) = &delta.inner_txns {
                    let (inner_usage, inner_fees_paid) =
                        summarize_txn_group_fee_usage(inner_txns, params);
                    usage = usage.saturating_add(inner_usage);
                    fees_paid = fees_paid.saturating_add(inner_fees_paid);
                }
            }
        }
    }
    (usage, fees_paid)
}

/// Unnamed resources accessed during simulation, in deterministic order.
///
/// Mirrors go-algorand's `simulation.ResourceTracker` public fields
/// (`ledger/simulation/resources.go`) as surfaced in the REST
/// `SimulateUnnamedResourcesAccessed` model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnnamedResourcesAccessed {
    /// Accounts accessed outside the group's named accounts.
    pub accounts: BTreeSet<Address>,
    /// Asset IDs accessed outside the group's foreign-asset arrays.
    pub assets: BTreeSet<u64>,
    /// App IDs accessed outside the group's foreign-app arrays.
    pub apps: BTreeSet<u64>,
    /// Boxes `(app_id, name)` accessed without a matching box reference.
    pub boxes: BTreeSet<(u64, Vec<u8>)>,
    /// Asset holdings `(account, asset)` whose halves are named but never by
    /// the same transaction.
    pub asset_holdings: BTreeSet<(Address, u64)>,
    /// App local states `(account, app)` whose halves are named but never by
    /// the same transaction.
    pub app_locals: BTreeSet<(Address, u64)>,
    /// Number of additional empty box refs the group should add to satisfy
    /// I/O-budget requirements (or to reach a box owned by an app created
    /// during this simulation, which has no stable, resubmittable ID) --
    /// distinct from [`Self::boxes`], which suggests concrete `(app_id,
    /// name)` refs. Mirrors go-algorand's `ResourceTracker.NumEmptyBoxRefs`
    /// (`ledger/simulation/resources.go`, `1088a2aad7e` / `v3.18.0-beta`).
    pub num_empty_box_refs: usize,
    /// Largest number of additional new accounts the group could still
    /// accept beyond what is already named, computed from the submitted
    /// group's txn types and named reference-array lengths. Mirrors
    /// go-algorand's `ResourceTracker.MaxAccounts`
    /// (`makeGlobalResourceTracker`, `ledger/simulation/resources.go`).
    pub max_accounts: usize,
    /// Largest number of additional new assets the group could still accept.
    /// Mirrors go-algorand's `ResourceTracker.MaxAssets`.
    pub max_assets: usize,
    /// Largest number of additional new apps the group could still accept.
    /// Mirrors go-algorand's `ResourceTracker.MaxApps`.
    pub max_apps: usize,
    /// Largest number of additional new box refs the group could still
    /// accept. Mirrors go-algorand's `ResourceTracker.MaxBoxes`.
    pub max_boxes: usize,
    /// Largest number of additional new references of any kind the group
    /// could still accept. Mirrors go-algorand's
    /// `ResourceTracker.MaxTotalRefs`.
    pub max_total_refs: usize,
    /// Largest number of additional asset-holding/app-local cross-product
    /// references the group could still accept. Mirrors go-algorand's
    /// `ResourceTracker.MaxCrossProductReferences`.
    pub max_cross_product_references: usize,
}

impl UnnamedResourcesAccessed {
    /// Whether any unnamed resource was recorded (go-algorand's
    /// `HasResources`). The `Max*`/`MaxCrossProductReferences` capacity
    /// fields are excluded, matching go's own `HasResources`, which never
    /// consults them either.
    pub fn has_resources(&self) -> bool {
        !(self.accounts.is_empty()
            && self.assets.is_empty()
            && self.apps.is_empty()
            && self.boxes.is_empty()
            && self.asset_holdings.is_empty()
            && self.app_locals.is_empty()
            && self.num_empty_box_refs == 0)
    }

    /// Merge another set of accesses into this one. `Max*` capacity fields
    /// are group-level constants (see [`Self::set_capacity_fields`]), not
    /// per-transaction accumulations, so they are left untouched here --
    /// callers compute and assign them once, after merging every
    /// transaction's accesses.
    pub fn merge(&mut self, other: UnnamedResourcesAccessed) {
        self.accounts.extend(other.accounts);
        self.assets.extend(other.assets);
        self.apps.extend(other.apps);
        self.boxes.extend(other.boxes);
        self.asset_holdings.extend(other.asset_holdings);
        self.app_locals.extend(other.app_locals);
        self.num_empty_box_refs += other.num_empty_box_refs;
    }

    /// Populate the `Max*`/`MaxCrossProductReferences` capacity fields for
    /// the submitted group. See [`compute_resource_capacity`].
    pub fn set_capacity_fields(
        &mut self,
        txgroup: &[SignedTransaction],
        consensus: &ConsensusParams,
    ) {
        let cap = compute_resource_capacity(txgroup, consensus);
        self.max_accounts = cap.max_accounts;
        self.max_assets = cap.max_assets;
        self.max_apps = cap.max_apps;
        self.max_boxes = cap.max_boxes;
        self.max_total_refs = cap.max_total_refs;
        self.max_cross_product_references = cap.max_cross_product_references;
    }
}

/// The `Max*`/`MaxCrossProductReferences` capacity fields of go-algorand's
/// `ResourceTracker` (`ledger/simulation/resources.go`), computed for one
/// transaction group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceCapacity {
    /// Largest number of additional new accounts the group could accept.
    pub max_accounts: usize,
    /// Largest number of additional new assets the group could accept.
    pub max_assets: usize,
    /// Largest number of additional new apps the group could accept.
    pub max_apps: usize,
    /// Largest number of additional new box refs the group could accept.
    pub max_boxes: usize,
    /// Largest number of additional new references of any kind the group
    /// could accept.
    pub max_total_refs: usize,
    /// Largest number of additional asset-holding/app-local cross-product
    /// references the group could accept.
    pub max_cross_product_references: usize,
}

/// Compute the `Max*`/`MaxCrossProductReferences` capacity fields for a
/// transaction group, mirroring go-algorand's `makeGlobalResourceTracker`
/// (`ledger/simulation/resources.go`, `1088a2aad7e` / `v3.18.0-beta`).
///
/// These are static capacity numbers derived purely from the group's txn
/// types and named reference-array lengths -- how many *additional* unnamed
/// resources of each kind the group could accept in principle. They are used
/// both to populate [`UnnamedResourcesAccessed::set_capacity_fields`] (an
/// internal, non-wire field -- go's own `SimulateUnnamedResourcesAccessed`
/// REST model has no `Max*`/cross-product wire fields either, only
/// `extra-box-refs`) and, in `avm_context`, to cap how many unnamed
/// resources are *recorded* into the reported access sets once a group's
/// actual capacity for a category is exhausted. This crate (unlike
/// go-algorand's `ResourceTracker.add*`) does not reject the underlying AVM
/// access once capacity is exhausted -- only the *reporting* is
/// capacity-aware; see issue #970's tracking notes for that remaining
/// enforcement gap.
pub fn compute_resource_capacity(
    txgroup: &[SignedTransaction],
    consensus: &ConsensusParams,
) -> ResourceCapacity {
    let unused_txns = consensus.max_tx_group_size.saturating_sub(txgroup.len());
    let mut non_app_calls = 0usize;
    let (mut sum_accounts, mut sum_assets, mut sum_apps, mut sum_boxes, mut sum_total_refs) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    for stxn in txgroup {
        let txn = &stxn.txn;
        if txn.txn_type != "appl" {
            non_app_calls += 1;
            continue;
        }
        let n_accounts = txn.accounts.as_ref().map_or(0, |v| v.len());
        let n_foreign_apps = txn.foreign_apps.as_ref().map_or(0, |v| v.len());
        let n_foreign_assets = txn.foreign_assets.as_ref().map_or(0, |v| v.len());
        let n_boxes = txn.boxes.as_ref().map_or(0, |v| v.len());

        sum_accounts += (consensus.max_app_txn_accounts + consensus.max_app_txn_foreign_apps)
            .saturating_sub(n_accounts)
            .saturating_sub(n_foreign_apps);
        sum_assets += consensus
            .max_app_txn_foreign_assets
            .saturating_sub(n_foreign_assets);
        sum_apps += consensus
            .max_app_txn_foreign_apps
            .saturating_sub(n_foreign_apps);
        sum_boxes += consensus.max_app_box_references.saturating_sub(n_boxes);
        sum_total_refs += consensus
            .max_app_total_txn_references
            .saturating_sub(n_accounts)
            .saturating_sub(n_foreign_assets)
            .saturating_sub(n_foreign_apps)
            .saturating_sub(n_boxes);
    }

    // (MaxAppTxnForeignApps + 1) apps crossed with (MaxAppTxnForeignApps + 2)
    // accounts, minus the trivially-available app-own-account locals -- see
    // go's `makeGlobalResourceTracker` comment for the full derivation of
    // this simplified form.
    let max_cross_products_per_app_call =
        consensus.max_app_txn_foreign_apps * (consensus.max_app_txn_foreign_apps + 2);

    ResourceCapacity {
        max_cross_product_references: max_cross_products_per_app_call
            .saturating_mul(consensus.max_tx_group_size.saturating_sub(non_app_calls)),
        max_accounts: unused_txns
            .saturating_mul(consensus.max_app_txn_accounts + consensus.max_app_txn_foreign_apps)
            .saturating_add(sum_accounts),
        max_assets: unused_txns
            .saturating_mul(consensus.max_app_txn_foreign_assets)
            .saturating_add(sum_assets),
        max_apps: unused_txns
            .saturating_mul(consensus.max_app_txn_foreign_apps)
            .saturating_add(sum_apps),
        max_boxes: unused_txns
            .saturating_mul(consensus.max_app_box_references)
            .saturating_add(sum_boxes),
        max_total_refs: unused_txns
            .saturating_mul(consensus.max_app_total_txn_references)
            .saturating_add(sum_total_refs),
    }
}

/// Hard limit on how many bytes a transaction may log during simulation when
/// `allow_more_logging` is enabled. Mirrors go-algorand's
/// `simulation.LogBytesLimit`.
pub const LOG_BYTES_LIMIT: u64 = 65536;

/// The raised `log`-call limit applied when `allow_more_logging` is enabled.
/// Mirrors go-algorand's `bounds.MaxLogCalls` (the maximum
/// `MaxAppProgramLen` across consensus versions, 2048).
pub const SIMULATION_MAX_LOG_CALLS: u64 = 2048;

/// Hard limit on how much extra opcode budget a simulation request may add
/// to one transaction group. Mirrors go-algorand's
/// `simulation.MaxExtraOpcodeBudget` (`20000 * 16`).
pub const MAX_EXTRA_OPCODE_BUDGET: i64 = 20_000 * 16;

/// Evaluation overrides that were applied during simulation.
///
/// Mirrors go-algorand's `simulation.ResultEvalOverrides`.
#[derive(Debug, Clone, Default)]
pub struct ResultEvalOverrides {
    /// Whether empty signatures were allowed.
    pub allow_empty_signatures: bool,
    /// Whether unnamed resources were allowed.
    pub allow_unnamed_resources: bool,
    /// Extra opcode budget that was added.
    pub extra_opcode_budget: i64,
    /// Whether signers were automatically fixed.
    pub fix_signers: bool,
    /// Maximum log calls allowed (when AllowMoreLogging is set).
    pub max_log_calls: Option<u64>,
    /// Maximum log size allowed (when AllowMoreLogging is set).
    pub max_log_size: Option<u64>,
}

/// Initial states of resources before simulation, for the caller to diff
/// against the results.
#[derive(Debug, Clone, Default)]
pub struct ResourcesInitialStates {
    /// Per-app initial global state hashes/snapshots, keyed by app ID.
    pub app_initial_states: Vec<(u64, AppInitialState)>,
}

/// Initial state snapshot for a single application.
#[derive(Debug, Clone, Default)]
pub struct AppInitialState {
    /// Initial global state key-value pairs.
    pub global_state: Vec<(Vec<u8>, AvmValueTrace)>,
    /// Initial local states, keyed by (address, key).
    #[allow(clippy::type_complexity)]
    pub local_states: Vec<(Address, Vec<(Vec<u8>, AvmValueTrace)>)>,
    /// Initial box contents, keyed by box name.
    pub boxes: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The top-level simulation result.
///
/// Mirrors go-algorand's `simulation.Result`.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Simulation format version.
    pub version: u64,
    /// The round at which simulation was performed.
    pub last_round: Round,
    /// Results for each transaction group.
    pub txn_groups: Vec<TxnGroupResult>,
    /// Evaluation overrides that were applied.
    pub eval_overrides: ResultEvalOverrides,
    /// Trace configuration that was used.
    pub trace_config: ExecTraceConfig,
    /// Initial states of resources (for diffing).
    pub initial_states: Option<ResourcesInitialStates>,
}

impl SimulationResult {
    /// Create a minimal result for the given round.
    pub fn new(round: Round) -> Self {
        SimulationResult {
            version: 2,
            last_round: round,
            txn_groups: Vec::new(),
            eval_overrides: ResultEvalOverrides::default(),
            trace_config: ExecTraceConfig::default(),
            initial_states: None,
        }
    }
}

/// Accumulates pre-simulation ("initial") application state captured during
/// execution, mirroring go-algorand's `ResourcesInitialStates`
/// (`ledger/simulation/initialStates.go`).
///
/// Recording follows go-algorand's first-touch-wins semantics: the first time
/// an app global/local/box key is accessed, its value *before* the operation
/// is recorded; subsequent accesses to the same key are ignored. Keys created
/// during simulation, and apps created during simulation, are excluded.
///
/// Divergence note: go-algorand records an *empty* value when a never-existed
/// key is read or deleted. This accumulator instead omits such keys — an absent
/// entry and a recorded-empty entry carry the same "no initial value" meaning,
/// and the internal [`AvmValueTrace`] has no empty representation. The only
/// observable difference is an extra empty kv-pair in go-algorand's response
/// for the never-existed-key read/delete edge case.
#[derive(Debug, Clone, Default)]
pub struct InitialStatesAccumulator {
    /// Per-app captured state, keyed by app ID.
    apps: BTreeMap<u64, SingleAppInitialStates>,
    /// Apps created during simulation; their states are never recorded.
    created_apps: HashSet<u64>,
}

/// Captured initial state for a single application.
#[derive(Debug, Clone, Default)]
struct SingleAppInitialStates {
    globals: BTreeMap<Vec<u8>, TealValue>,
    created_globals: HashSet<Vec<u8>>,
    locals: HashMap<Address, BTreeMap<Vec<u8>, TealValue>>,
    created_locals: HashMap<Address, HashSet<Vec<u8>>>,
    boxes: BTreeMap<Vec<u8>, TealValue>,
    created_boxes: HashSet<Vec<u8>>,
}

impl SingleAppInitialStates {
    fn has_been_recorded(&self, state: AppStateType, key: &[u8], addr: Option<Address>) -> bool {
        match state {
            AppStateType::Global => self.globals.contains_key(key),
            AppStateType::Box => self.boxes.contains_key(key),
            AppStateType::Local => addr
                .and_then(|a| self.locals.get(&a))
                .is_some_and(|m| m.contains_key(key)),
        }
    }

    fn has_been_created(&self, state: AppStateType, key: &[u8], addr: Option<Address>) -> bool {
        match state {
            AppStateType::Global => self.created_globals.contains(key),
            AppStateType::Box => self.created_boxes.contains(key),
            AppStateType::Local => addr
                .and_then(|a| self.created_locals.get(&a))
                .is_some_and(|s| s.contains(key)),
        }
    }

    fn record_creation(&mut self, state: AppStateType, key: &[u8], addr: Option<Address>) {
        match state {
            AppStateType::Global => {
                self.created_globals.insert(key.to_vec());
            }
            AppStateType::Box => {
                self.created_boxes.insert(key.to_vec());
            }
            AppStateType::Local => {
                if let Some(a) = addr {
                    self.created_locals
                        .entry(a)
                        .or_default()
                        .insert(key.to_vec());
                }
            }
        }
    }

    fn record_value(
        &mut self,
        state: AppStateType,
        key: &[u8],
        addr: Option<Address>,
        value: TealValue,
    ) {
        match state {
            AppStateType::Global => {
                self.globals.insert(key.to_vec(), value);
            }
            AppStateType::Box => {
                self.boxes.insert(key.to_vec(), value);
            }
            AppStateType::Local => {
                if let Some(a) = addr {
                    self.locals
                        .entry(a)
                        .or_default()
                        .insert(key.to_vec(), value);
                }
            }
        }
    }

    /// Merge `other` into `self`, preserving `self`'s earlier-recorded values
    /// (first-touch-wins) and unioning the created-key sets.
    fn merge(&mut self, other: SingleAppInitialStates) {
        for (k, v) in other.globals {
            self.globals.entry(k).or_insert(v);
        }
        self.created_globals.extend(other.created_globals);
        for (k, v) in other.boxes {
            self.boxes.entry(k).or_insert(v);
        }
        self.created_boxes.extend(other.created_boxes);
        for (addr, kvs) in other.locals {
            let entry = self.locals.entry(addr).or_default();
            for (k, v) in kvs {
                entry.entry(k).or_insert(v);
            }
        }
        for (addr, keys) in other.created_locals {
            self.created_locals.entry(addr).or_default().extend(keys);
        }
    }
}

impl InitialStatesAccumulator {
    /// Mark an application as created during simulation, excluding its state
    /// from capture (matches go-algorand's `CreatedApp` set).
    pub fn mark_created_app(&mut self, app_id: u64) {
        self.created_apps.insert(app_id);
    }

    /// Snapshot of the apps created so far during simulation. Used to seed a
    /// later transaction's tracer so the created-app exclusion persists across
    /// the whole group (go-algorand keeps one `ResourcesInitialStates` for the
    /// entire simulation; the Rust engine uses per-transaction tracers).
    pub fn created_app_ids(&self) -> Vec<u64> {
        self.created_apps.iter().copied().collect()
    }

    /// Record an application-state access, following go-algorand's
    /// `AppsInitialStates.increment` semantics.
    pub fn record(&mut self, access: &AppStateAccess<'_>) {
        // Exclude accesses made from within an app created during simulation
        // (go-algorand checks `CreatedApp.Contains(cx.AppID())`).
        if self.created_apps.contains(&access.executing_app_id) {
            return;
        }

        let addr = access.account.map(Address);
        let app = self.apps.entry(access.app_id).or_default();

        // First-touch-wins: skip keys already recorded or already created.
        if app.has_been_recorded(access.state, access.key, addr) {
            return;
        }
        if app.has_been_created(access.state, access.key, addr) {
            return;
        }

        match access.op {
            // Writing to a non-existent key creates it; record as a creation
            // rather than capturing an initial value.
            AppStateOp::Write if access.pre_value.is_none() => {
                app.record_creation(access.state, access.key, addr);
            }
            // Read / Delete / write-over-existing: capture the pre-op value.
            // Never-existed reads/deletes (pre_value None) are omitted — see the
            // divergence note on [`InitialStatesAccumulator`].
            _ => {
                if let Some(value) = access.pre_value.clone() {
                    app.record_value(access.state, access.key, addr, value);
                }
            }
        }
    }

    /// Merge another accumulator (e.g. from a later transaction's tracer) into
    /// this one, preserving earlier-recorded values.
    pub fn merge(&mut self, other: InitialStatesAccumulator) {
        self.created_apps.extend(other.created_apps);
        for (app_id, app) in other.apps {
            self.apps.entry(app_id).or_default().merge(app);
        }
    }

    /// Convert into the output [`ResourcesInitialStates`]. App and key order is
    /// deterministic (apps and global/box keys sorted; local accounts sorted by
    /// address bytes).
    pub fn into_resources_initial_states(self) -> ResourcesInitialStates {
        let app_initial_states = self
            .apps
            .into_iter()
            .map(|(app_id, app)| {
                let global_state = app
                    .globals
                    .into_iter()
                    .map(|(k, v)| (k, teal_to_trace(&v)))
                    .collect();

                let mut local_accounts: Vec<(Address, BTreeMap<Vec<u8>, TealValue>)> =
                    app.locals.into_iter().collect();
                local_accounts.sort_by_key(|(addr, _)| addr.0);
                let local_states = local_accounts
                    .into_iter()
                    .map(|(addr, kvs)| {
                        let kv = kvs
                            .into_iter()
                            .map(|(k, v)| (k, teal_to_trace(&v)))
                            .collect();
                        (addr, kv)
                    })
                    .collect();

                let boxes = app
                    .boxes
                    .into_iter()
                    .map(|(k, v)| (k, teal_to_bytes(v)))
                    .collect();

                (
                    app_id,
                    AppInitialState {
                        global_state,
                        local_states,
                        boxes,
                    },
                )
            })
            .collect();

        ResourcesInitialStates { app_initial_states }
    }
}

/// Convert a [`TealValue`] to a trace-friendly [`AvmValueTrace`].
fn teal_to_trace(v: &TealValue) -> AvmValueTrace {
    match v {
        TealValue::Uint(n) => AvmValueTrace::Uint64(*n),
        TealValue::Bytes(b) => AvmValueTrace::Bytes(b.clone()),
    }
}

/// Extract raw box bytes from a [`TealValue`] (box contents are always bytes).
fn teal_to_bytes(v: TealValue) -> Vec<u8> {
    match v {
        TealValue::Bytes(b) => b,
        TealValue::Uint(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_trace_config_default_disabled() {
        let config = ExecTraceConfig::default();
        assert!(!config.is_enabled());
        assert!(!config.enable);
        assert!(!config.stack);
        assert!(!config.scratch);
        assert!(!config.state);
    }

    #[test]
    fn test_exec_trace_config_enabled() {
        let config = ExecTraceConfig {
            enable: true,
            stack: true,
            scratch: false,
            state: false,
        };
        assert!(config.is_enabled());
    }

    // --- InitialStatesAccumulator tests ---

    fn global_access<'a>(
        executing_app: u64,
        app_id: u64,
        op: AppStateOp,
        key: &'a [u8],
        pre: Option<TealValue>,
    ) -> AppStateAccess<'a> {
        AppStateAccess {
            executing_app_id: executing_app,
            app_id,
            state: AppStateType::Global,
            op,
            account: None,
            key,
            pre_value: pre,
            new_value: None,
        }
    }

    #[test]
    fn accumulator_records_global_read_pre_value() {
        let mut acc = InitialStatesAccumulator::default();
        acc.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(7)),
        ));
        let states = acc.into_resources_initial_states();
        assert_eq!(states.app_initial_states.len(), 1);
        let (id, app) = &states.app_initial_states[0];
        assert_eq!(*id, 100);
        assert_eq!(app.global_state.len(), 1);
        assert_eq!(app.global_state[0].0, b"k");
        assert!(matches!(app.global_state[0].1, AvmValueTrace::Uint64(7)));
    }

    #[test]
    fn accumulator_first_touch_wins_on_dedup() {
        let mut acc = InitialStatesAccumulator::default();
        // First read captures the true initial value.
        acc.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(1)),
        ));
        // A later write sees a mutated pre-value, but the key is already
        // recorded so it must be ignored.
        acc.record(&global_access(
            100,
            100,
            AppStateOp::Write,
            b"k",
            Some(TealValue::Uint(999)),
        ));
        let states = acc.into_resources_initial_states();
        let (_, app) = &states.app_initial_states[0];
        assert_eq!(app.global_state.len(), 1);
        assert!(matches!(app.global_state[0].1, AvmValueTrace::Uint64(1)));
    }

    #[test]
    fn accumulator_write_to_missing_key_is_creation_not_recorded() {
        let mut acc = InitialStatesAccumulator::default();
        // Write to a non-existent key: treated as a creation, no initial value.
        acc.record(&global_access(100, 100, AppStateOp::Write, b"k", None));
        // A subsequent read must not record it either (already created).
        acc.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(5)),
        ));
        let states = acc.into_resources_initial_states();
        let (_, app) = &states.app_initial_states[0];
        assert!(
            app.global_state.is_empty(),
            "created key must not appear in initial states"
        );
    }

    #[test]
    fn accumulator_excludes_apps_created_during_simulation() {
        let mut acc = InitialStatesAccumulator::default();
        acc.mark_created_app(100);
        // App 100 reading its own state must be excluded.
        acc.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(7)),
        ));
        let states = acc.into_resources_initial_states();
        assert!(states.app_initial_states.is_empty());
    }

    #[test]
    fn accumulator_foreign_app_read_recorded_under_target_app() {
        let mut acc = InitialStatesAccumulator::default();
        // Executing app 100 reads foreign app 200's global state (app_global_get_ex).
        acc.record(&global_access(
            100,
            200,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Bytes(b"v".to_vec())),
        ));
        let states = acc.into_resources_initial_states();
        assert_eq!(states.app_initial_states.len(), 1);
        assert_eq!(states.app_initial_states[0].0, 200);
    }

    #[test]
    fn accumulator_captures_local_and_box_state() {
        let mut acc = InitialStatesAccumulator::default();
        let addr = [0xAB; 32];
        acc.record(&AppStateAccess {
            executing_app_id: 100,
            app_id: 100,
            state: AppStateType::Local,
            op: AppStateOp::Read,
            account: Some(addr),
            key: b"lk",
            pre_value: Some(TealValue::Uint(3)),
            new_value: None,
        });
        acc.record(&AppStateAccess {
            executing_app_id: 100,
            app_id: 100,
            state: AppStateType::Box,
            op: AppStateOp::Read,
            account: None,
            key: b"bk",
            pre_value: Some(TealValue::Bytes(b"boxval".to_vec())),
            new_value: None,
        });
        let states = acc.into_resources_initial_states();
        let (_, app) = &states.app_initial_states[0];
        assert_eq!(app.local_states.len(), 1);
        assert_eq!(app.local_states[0].0, Address(addr));
        assert_eq!(app.local_states[0].1.len(), 1);
        assert_eq!(app.boxes.len(), 1);
        assert_eq!(app.boxes[0].0, b"bk");
        assert_eq!(app.boxes[0].1, b"boxval");
    }

    #[test]
    fn accumulator_merge_preserves_earliest_value() {
        let mut first = InitialStatesAccumulator::default();
        first.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(1)),
        ));
        let mut second = InitialStatesAccumulator::default();
        second.record(&global_access(
            100,
            100,
            AppStateOp::Read,
            b"k",
            Some(TealValue::Uint(2)),
        ));
        // Merging the later transaction's capture must not overwrite the
        // earlier value (first-touch-wins across transactions).
        first.merge(second);
        let states = first.into_resources_initial_states();
        let (_, app) = &states.app_initial_states[0];
        assert!(matches!(app.global_state[0].1, AvmValueTrace::Uint64(1)));
    }

    #[test]
    fn test_simulation_result_new() {
        let result = SimulationResult::new(Round(42));
        assert_eq!(result.version, 2);
        assert_eq!(result.last_round, Round(42));
        assert!(result.txn_groups.is_empty());
    }

    #[test]
    fn test_txn_group_result_default() {
        let group = TxnGroupResult::default();
        assert!(group.txn_results.is_empty());
        assert!(group.failure_message.is_none());
        assert!(group.failed_at.is_none());
        assert_eq!(group.app_budget_added, 0);
        assert_eq!(group.app_budget_consumed, 0);
        assert_eq!(group.group_usage, 0);
        assert_eq!(group.group_fees_paid, 0);
    }

    // --- summarize_txn_fees_paid / summarize_txn_group_fee_usage (issue #671) ---

    /// Build a signed txn of the given fee, with an `eval_delta` reporting
    /// `inner` as its (already-encoded) inner transactions -- mirrors how
    /// `encode_eval_delta` nests a parent's `itx` around children that already
    /// carry their own encoded `eval_delta`.
    fn stxn_with_inner(fee: u64, inner: Vec<SignedTransaction>) -> SignedTransaction {
        let mut stx = SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "appl".into(),
                fee,
                ..Default::default()
            },
            ..Default::default()
        };
        if !inner.is_empty() {
            let avm_result = algo_avm::eval::AvmResult {
                inner_transactions: inner,
                ..algo_avm::eval::AvmResult::empty()
            };
            stx.eval_delta = crate::eval_delta::encode_eval_delta(&avm_result, &stx.txn);
        }
        stx
    }

    fn v42() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::consensus::CONSENSUS_V42)
            .unwrap()
    }

    #[test]
    fn summarize_txn_fees_paid_leaf_is_own_fee() {
        assert_eq!(summarize_txn_fees_paid(1000, None), 1000);
    }

    #[test]
    fn summarize_txn_fees_paid_sums_recursively_over_nested_inners() {
        // grandchild (500) -> child (1000, carries grandchild) -> parent (2000, carries child)
        let grandchild = stxn_with_inner(500, vec![]);
        let child = stxn_with_inner(1000, vec![grandchild]);
        let parent_fee = 2000u64;
        let parent = stxn_with_inner(parent_fee, vec![child]);

        let total = summarize_txn_fees_paid(parent_fee, parent.eval_delta.as_ref());
        assert_eq!(total, 2000 + 1000 + 500);
    }

    #[test]
    fn summarize_txn_fees_paid_saturates_on_overflow() {
        let inner = stxn_with_inner(u64::MAX, vec![]);
        let parent = stxn_with_inner(u64::MAX, vec![inner]);
        let total = summarize_txn_fees_paid(u64::MAX, parent.eval_delta.as_ref());
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn summarize_txn_group_fee_usage_matches_summarize_fees_for_flat_group() {
        let p = v42();
        let a = stxn_with_inner(1000, vec![]);
        let b = stxn_with_inner(1000, vec![]);
        let group = vec![a, b];
        let (usage, paid) = summarize_txn_group_fee_usage(&group, &p);
        let refs: Vec<&SignedTransaction> = group.iter().collect();
        let (expected_usage, expected_paid) = algo_validate::summarize_fees(&refs, &p);
        assert_eq!(usage, expected_usage);
        assert_eq!(paid, expected_paid);
    }

    #[test]
    fn summarize_txn_group_fee_usage_adds_nested_inner_group_usage() {
        let p = v42();
        // Top-level single-txn group whose transaction spawned a two-txn
        // inner group -- the inner group's own SummarizeFees-equivalent
        // usage/fees must be pooled on top of the outer group's usage/fees.
        let inner_a = SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "pay".into(),
                fee: 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        let inner_b = SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "pay".into(),
                fee: 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        let outer = stxn_with_inner(2000, vec![inner_a.clone(), inner_b.clone()]);
        let group = vec![outer];

        let (usage, paid) = summarize_txn_group_fee_usage(&group, &p);

        let outer_refs: Vec<&SignedTransaction> = group.iter().collect();
        let (outer_usage, outer_paid) = algo_validate::summarize_fees(&outer_refs, &p);
        let inner_refs: Vec<&SignedTransaction> = vec![&inner_a, &inner_b];
        let (inner_usage, inner_paid) = algo_validate::summarize_fees(&inner_refs, &p);

        assert_eq!(usage, outer_usage + inner_usage);
        assert_eq!(paid, outer_paid + inner_paid);
        assert_eq!(paid, 2000 + 1000 + 1000);
    }

    #[test]
    fn summarize_txn_group_fee_usage_saturates_on_overflow() {
        let p = v42();
        let a = stxn_with_inner(u64::MAX, vec![]);
        let b = stxn_with_inner(u64::MAX, vec![]);
        let (_usage, paid) = summarize_txn_group_fee_usage(&[a, b], &p);
        assert_eq!(paid, u64::MAX);
    }

    // --- compute_resource_capacity (issue #970) ---

    /// Small, hand-computable consensus params so expected capacity numbers
    /// can be verified by hand rather than depending on the exact (and
    /// subject-to-change) production constants.
    fn small_consensus() -> ConsensusParams {
        ConsensusParams {
            max_tx_group_size: 4,
            max_app_txn_accounts: 2,
            max_app_txn_foreign_apps: 3,
            max_app_txn_foreign_assets: 5,
            max_app_box_references: 6,
            max_app_total_txn_references: 10,
            ..ConsensusParams::default()
        }
    }

    fn appl_txn() -> SignedTransaction {
        SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "appl".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn pay_txn() -> SignedTransaction {
        SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "pay".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Single-txn group, no named resources: every `Max*` field equals
    /// `unusedTxns * txnLimit + txnLimit` (this txn's own full allowance,
    /// since nothing is named), matching go-algorand's
    /// `makeGlobalResourceTracker` for a lone app call.
    #[test]
    fn compute_resource_capacity_single_unnamed_appl_txn() {
        let p = small_consensus();
        let cap = compute_resource_capacity(&[appl_txn()], &p);
        // unused_txns = 4 - 1 = 3
        assert_eq!(cap.max_accounts, 3 * (2 + 3) + (2 + 3));
        assert_eq!(cap.max_assets, 3 * 5 + 5);
        assert_eq!(cap.max_apps, 3 * 3 + 3);
        assert_eq!(cap.max_boxes, 3 * 6 + 6);
        assert_eq!(cap.max_total_refs, 3 * 10 + 10);
        // maxCrossProductsPerAppCall = 3*(3+2) = 15; non_app_calls = 0.
        assert_eq!(cap.max_cross_product_references, 15 * 4);
    }

    /// Named reference-array entries on the txn reduce that txn's own
    /// per-category allowance (but not the credit from unused group slots).
    #[test]
    fn compute_resource_capacity_named_arrays_reduce_per_txn_allowance() {
        let p = small_consensus();
        let mut txn = appl_txn();
        txn.txn.accounts = Some(vec![algo_types::Address([1; 32])]);
        txn.txn.foreign_apps = Some(vec![7]);
        txn.txn.foreign_assets = Some(vec![9]);
        txn.txn.boxes = Some(vec![algo_types::BoxRef {
            index: 0,
            name: Some(b"b".to_vec().into()),
        }]);
        let cap = compute_resource_capacity(&[txn], &p);
        // unused_txns = 3; this txn's own allowance drops by the named count.
        assert_eq!(cap.max_accounts, 3 * 5 + (5 - 1 - 1)); // accounts + foreign_apps both count
        assert_eq!(cap.max_assets, 3 * 5 + (5 - 1));
        assert_eq!(cap.max_apps, 3 * 3 + (3 - 1));
        assert_eq!(cap.max_boxes, 3 * 6 + (6 - 1));
        assert_eq!(cap.max_total_refs, 3 * 10 + (10 - 1 - 1 - 1 - 1));
    }

    /// A non-app-call txn contributes nothing to the per-txn sums (mirrors
    /// go's `makeTxnResourceTracker` returning a zero tracker for it) but
    /// still counts toward `nonAppCalls`, shrinking
    /// `MaxCrossProductReferences`.
    #[test]
    fn compute_resource_capacity_non_app_call_excluded_from_sums() {
        let p = small_consensus();
        let cap = compute_resource_capacity(&[pay_txn(), appl_txn()], &p);
        // unused_txns = 4 - 2 = 2; only the appl txn contributes to sums.
        assert_eq!(cap.max_accounts, 2 * 5 + 5);
        assert_eq!(cap.max_assets, 2 * 5 + 5);
        assert_eq!(cap.max_apps, 2 * 3 + 3);
        assert_eq!(cap.max_boxes, 2 * 6 + 6);
        assert_eq!(cap.max_total_refs, 2 * 10 + 10);
        // non_app_calls = 1: maxCrossProductsPerAppCall * (4 - 1) = 15 * 3.
        assert_eq!(cap.max_cross_product_references, 15 * 3);
    }

    #[test]
    fn unnamed_resources_accessed_set_capacity_fields_matches_compute() {
        let p = small_consensus();
        let group = [appl_txn()];
        let mut unnamed = UnnamedResourcesAccessed::default();
        unnamed.set_capacity_fields(&group, &p);
        let cap = compute_resource_capacity(&group, &p);
        assert_eq!(unnamed.max_accounts, cap.max_accounts);
        assert_eq!(unnamed.max_assets, cap.max_assets);
        assert_eq!(unnamed.max_apps, cap.max_apps);
        assert_eq!(unnamed.max_boxes, cap.max_boxes);
        assert_eq!(unnamed.max_total_refs, cap.max_total_refs);
        assert_eq!(
            unnamed.max_cross_product_references,
            cap.max_cross_product_references
        );
    }

    /// `has_resources` must treat a nonzero `num_empty_box_refs` as a real
    /// accessed resource (go's own `HasResources` includes
    /// `NumEmptyBoxRefs != 0`), even when every set-valued field is empty.
    #[test]
    fn has_resources_true_for_empty_box_refs_alone() {
        let mut unnamed = UnnamedResourcesAccessed::default();
        assert!(!unnamed.has_resources());
        unnamed.num_empty_box_refs = 1;
        assert!(unnamed.has_resources());
    }

    /// `merge` sums `num_empty_box_refs` across transactions (each
    /// transaction's own tracer only counts its own accesses) but leaves the
    /// `Max*` capacity fields alone -- those are a group-level constant the
    /// caller assigns once via `set_capacity_fields`, not a per-transaction
    /// accumulation.
    #[test]
    fn merge_sums_empty_box_refs_but_not_capacity_fields() {
        let mut a = UnnamedResourcesAccessed {
            num_empty_box_refs: 2,
            max_accounts: 100,
            ..Default::default()
        };
        let b = UnnamedResourcesAccessed {
            num_empty_box_refs: 3,
            max_accounts: 999,
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.num_empty_box_refs, 5);
        assert_eq!(a.max_accounts, 100, "merge must not touch capacity fields");
    }
}
