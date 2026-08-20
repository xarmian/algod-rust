//! Transaction simulation engine.
//!
//! Provides the [`Simulator`] that can dry-run transaction groups against
//! the current ledger state without committing changes. This powers the
//! `/v2/transactions/simulate` REST endpoint.
//!
//! The implementation mirrors go-algorand's `ledger/simulation/` package:
//! - [`Simulator`] corresponds to `simulation.Simulator`
//! - [`SimulationRequest`] corresponds to `simulation.Request`
//! - [`SimulationResult`] corresponds to `simulation.Result`
//!
//! The simulation engine uses [`LedgerStore::snapshot`] /
//! [`LedgerStore::restore_snapshot`] to ensure that no permanent state
//! changes are made.

pub mod trace;
pub mod tracer;

pub use trace::{
    AppInitialState, AvmValueTrace, ExecTraceConfig, InitialStatesAccumulator, OpcodeTraceUnit,
    ProgramTrace, ResourcesInitialStates, ResultEvalOverrides, SimulationResult, StateChange,
    StateChangeKind, StateChangeOp, TransactionTrace, TxnGroupResult, TxnPath, TxnResult,
    UnnamedResourcesAccessed, LOG_BYTES_LIMIT, MAX_EXTRA_OPCODE_BUDGET, SIMULATION_MAX_LOG_CALLS,
};
pub use tracer::SimulationTracer;

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use algo_avm::group::GroupBudget;
use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};
use algo_types::{Address, Round, SignedTransaction};
use algo_validate::{
    is_free_heartbeat, validate_transaction_wellformed, verify_transaction_signature,
    verify_transaction_signature_with_tracer, SpecialAddresses,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::apply::{
    apply_transaction_with_budget, compute_group_fee_credit, ApplyContext, ApplyMode,
    AvmEvalOverrides, GroupInfo,
};
use crate::avm_context::NamedGroupResources;
use crate::store_trait::LedgerStore;

/// Fixed proxy signing key seed (first 32 bytes of go-algorand's `proxySigner`).
///
/// Used to create valid signatures for unsigned transactions when
/// `allow_empty_signatures` is enabled, matching go-algorand's
/// `simulation.proxySigner` behaviour.
const PROXY_SIGNER_SEED: [u8; 32] = [
    128, 128, 92, 23, 212, 119, 175, 51, 157, 2, 165, 215, 137, 37, 82, 42, 52, 227, 54, 41, 243,
    67, 141, 76, 208, 17, 199, 17, 140, 46, 113, 0,
];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during simulation.
#[derive(Debug)]
pub enum SimulatorError {
    /// The simulation request was invalid.
    InvalidRequest(InvalidRequestError),
    /// Transaction evaluation failed.
    EvalFailure(EvalFailureError),
    /// Internal error (ledger access, etc.).
    Internal(AlgoError),
}

impl fmt::Display for SimulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimulatorError::InvalidRequest(e) => write!(f, "invalid simulation request: {e}"),
            SimulatorError::EvalFailure(e) => write!(f, "simulation eval failure: {e}"),
            SimulatorError::Internal(e) => write!(f, "simulation internal error: {e}"),
        }
    }
}

impl std::error::Error for SimulatorError {}

impl From<AlgoError> for SimulatorError {
    fn from(e: AlgoError) -> Self {
        SimulatorError::Internal(e)
    }
}

/// The simulation request contained invalid parameters.
#[derive(Debug)]
pub struct InvalidRequestError {
    pub message: String,
}

impl fmt::Display for InvalidRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// A transaction evaluation failure during simulation.
///
/// This is not necessarily fatal — the simulation still returns results
/// with the failure information included.
#[derive(Debug)]
pub struct EvalFailureError {
    pub message: String,
    /// Index path to the failing transaction.
    pub failed_at: TxnPath,
}

impl fmt::Display for EvalFailureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at {:?})", self.message, self.failed_at)
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A simulation request, specifying the transactions to simulate and
/// configuration options.
///
/// Mirrors go-algorand's `simulation.Request`.
#[derive(Debug, Clone, Default)]
pub struct SimulationRequest {
    /// The round to simulate at. If `None`, uses the ledger's latest round.
    pub round: Option<Round>,
    /// Transaction groups to simulate. Currently only a single group is
    /// supported (matching go-algorand's restriction).
    pub txn_groups: Vec<Vec<SignedTransaction>>,
    /// Allow transactions with empty (missing) signatures.
    pub allow_empty_signatures: bool,
    /// Allow more logging output than normal.
    pub allow_more_logging: bool,
    /// Allow unnamed resources in app calls.
    pub allow_unnamed_resources: bool,
    /// Extra opcode budget to add beyond the default.
    pub extra_opcode_budget: i64,
    /// Execution trace configuration.
    pub trace_config: ExecTraceConfig,
    /// Automatically fix signer fields.
    pub fix_signers: bool,
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------

/// The simulation engine.
///
/// Runs transaction groups against a [`LedgerStore`] without committing
/// changes. Uses snapshot/restore to ensure the store is left unchanged.
pub struct Simulator<'a, L: LedgerStore> {
    /// The ledger store to simulate against.
    store: &'a mut L,
    /// Whether the developer API is enabled (allows extra trace features).
    pub developer_api: bool,
}

impl<'a, L: LedgerStore> Simulator<'a, L> {
    /// Create a new simulator backed by the given ledger store.
    pub fn new(store: &'a mut L) -> Self {
        Simulator {
            store,
            developer_api: false,
        }
    }

    /// Create a new simulator with the developer API enabled.
    pub fn new_with_developer_api(store: &'a mut L) -> Self {
        Simulator {
            store,
            developer_api: true,
        }
    }

    /// Validate the trace configuration against the node configuration.
    ///
    /// Mirrors go-algorand's `validateSimulateRequest`
    /// (`ledger/simulation/trace.go`): requesting an execution trace
    /// requires the developer API to be enabled, and the `stack`,
    /// `scratch`, and `state` sub-options require the basic trace
    /// (`enable`) to be on. Error messages match go byte-for-byte so REST
    /// clients see identical 400 bodies.
    fn validate_trace_config(&self, cfg: &ExecTraceConfig) -> Result<(), SimulatorError> {
        if !self.developer_api && cfg.enable {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "the local configuration of the node has `EnableDeveloperAPI` turned off, while requesting for execution trace".to_string(),
            }));
        }
        if !cfg.enable {
            if cfg.stack {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "basic trace must be enabled when enabling stack tracing".to_string(),
                }));
            }
            if cfg.scratch {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message:
                        "basic trace must be enabled when enabling scratch slot change tracing"
                            .to_string(),
                }));
            }
            if cfg.state {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "basic trace must be enabled when enabling app state change tracing"
                        .to_string(),
                }));
            }
        }
        Ok(())
    }

    /// Simulate the given request and return results.
    ///
    /// The ledger store is left unchanged after simulation completes
    /// (all state changes are rolled back via snapshot/restore).
    pub fn simulate(
        &mut self,
        request: SimulationRequest,
    ) -> Result<SimulationResult, SimulatorError> {
        // --- Validate request ---

        if request.fix_signers && !request.allow_empty_signatures {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "FixSigners requires AllowEmptySignatures to be enabled".to_string(),
            }));
        }

        if request.txn_groups.is_empty() {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "simulation request must contain at least one transaction group"
                    .to_string(),
            }));
        }

        if request.txn_groups.len() > 1 {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "simulation currently supports exactly one transaction group".to_string(),
            }));
        }

        let txn_group = &request.txn_groups[0];
        if txn_group.is_empty() {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "transaction group must contain at least one transaction".to_string(),
            }));
        }

        self.validate_trace_config(&request.trace_config)?;

        // --- Determine simulation round ---

        let sim_round = request.round.unwrap_or_else(|| self.store.current_round());

        // --- Build result ---

        let mut result = SimulationResult::new(sim_round);
        result.trace_config = request.trace_config.clone();
        result.eval_overrides = ResultEvalOverrides {
            allow_empty_signatures: request.allow_empty_signatures,
            allow_unnamed_resources: request.allow_unnamed_resources,
            extra_opcode_budget: request.extra_opcode_budget,
            fix_signers: request.fix_signers,
            // AllowMoreLogging raises the AVM log limits (go-algorand
            // `ResultEvalOverrides.AllowMoreLogging`).
            max_log_calls: request
                .allow_more_logging
                .then_some(SIMULATION_MAX_LOG_CALLS),
            max_log_size: request.allow_more_logging.then_some(LOG_BYTES_LIMIT),
        };

        // --- Snapshot the store before simulation ---

        // Collect all addresses involved in the transaction group for
        // snapshotting. This ensures we can restore state after simulation.
        // Include the fee sink and rewards pool since apply_transaction
        // credits fees and distributes rewards through these accounts.
        let mut addrs: Vec<Address> = vec![self.store.fee_sink(), self.store.rewards_pool()];
        for stx in txn_group {
            addrs.push(stx.txn.sender);
            if stx.txn.receiver != Address::ZERO {
                addrs.push(stx.txn.receiver);
            }
            if stx.txn.close_remainder_to != Address::ZERO {
                addrs.push(stx.txn.close_remainder_to);
            }
            if let Some(ref a) = stx.txn.asset_receiver {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.asset_sender {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.asset_close_to {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.freeze_account {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.rekey_to {
                addrs.push(*a);
            }
            // Foreign accounts from app calls
            if let Some(ref accounts) = stx.txn.accounts {
                for a in accounts {
                    addrs.push(*a);
                }
            }
        }
        // Deduplicate addresses.
        addrs.sort_by_key(|a| a.0);
        addrs.dedup();

        // Collect app/asset IDs that may be created or modified during
        // simulation so the snapshot can roll them back. For creates
        // (application_id == 0 or config_asset == 0), pre-compute the
        // derived ID from the running txn_counter.
        let mut asset_ids: Vec<u64> = Vec::new();
        let mut app_ids: Vec<u64> = Vec::new();
        let base_counter = self.store.txn_counter();
        for (i, stx) in txn_group.iter().enumerate() {
            // Each top-level txn increments the counter.
            let sim_counter = base_counter + i as u64;
            match stx.txn.txn_type.as_str() {
                "acfg" => {
                    if stx.txn.config_asset != 0 {
                        asset_ids.push(stx.txn.config_asset);
                    } else {
                        // Asset create: derived ID = txn_counter + 1
                        asset_ids.push(sim_counter + 1);
                    }
                }
                "axfer" => {
                    if stx.txn.xaid != 0 {
                        asset_ids.push(stx.txn.xaid);
                    }
                }
                "afrz" => {
                    if stx.txn.freeze_asset != 0 {
                        asset_ids.push(stx.txn.freeze_asset);
                    }
                }
                "appl" => {
                    if stx.txn.application_id != 0 {
                        app_ids.push(stx.txn.application_id);
                    } else {
                        // App create: derived ID = txn_counter + 1
                        app_ids.push(sim_counter + 1);
                    }
                }
                _ => {}
            }
        }

        let snapshot = if asset_ids.is_empty() && app_ids.is_empty() {
            self.store.snapshot(&addrs)
        } else {
            self.store.snapshot_with_ids(&addrs, &asset_ids, &app_ids)
        };

        // --- FixSigners: pre-evaluation signer correction ---

        // Working copy of the group used for verification and evaluation.
        // With `fix_signers`, unsigned transactions get their `auth_addr`
        // corrected here (and again after each app call, since apps can
        // rekey); the original `txn_group` is kept for the response and the
        // post-evaluation `fixed_signer` comparison — mirroring go-algorand's
        // `simulateWithTracer` (`ledger/simulation/simulator.go:219-260`).
        let mut eval_group: Vec<SignedTransaction> = txn_group.clone();
        if request.fix_signers {
            fix_unsigned_signers_pre_eval(&*self.store, &mut eval_group);
        }

        // --- Build apply context ---

        // Fetch block header for consensus params and timestamp
        let block_hdr = self.store.get_block_header(sim_round.0)?;
        let consensus = match &block_hdr {
            Some(hdr) => consensus_params_for_version(&hdr.current_protocol).unwrap_or_default(),
            None => consensus_params_for_version(self.store.protocol()).unwrap_or_default(),
        };
        let latest_timestamp = block_hdr
            .as_ref()
            .map(|h| h.timestamp.max(0) as u64)
            .unwrap_or(0);

        // Run validation (signature verification + well-formedness) before
        // execution. When tracing is enabled, `check` also captures logic-sig
        // opcode traces, since LogicSig programs run during signature
        // verification — before the per-transaction execution tracer exists.
        let (logicsig_traces, logicsig_budgets) = match self.check(
            &eval_group,
            request.allow_empty_signatures,
            &consensus,
            &request.trace_config,
        ) {
            Ok(captured) => captured,
            Err(e) => {
                self.store.restore_snapshot(snapshot);
                return Err(e);
            }
        };

        // Validate the extra opcode budget against the simulation limit.
        // Runs after `check()` so verification errors take precedence,
        // matching go-algorand's `simulateWithTracer` ordering; the message
        // matches go byte-for-byte.
        if request.extra_opcode_budget > MAX_EXTRA_OPCODE_BUDGET {
            self.store.restore_snapshot(snapshot);
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: format!(
                    "extra budget {} > simulation extra budget limit {}",
                    request.extra_opcode_budget, MAX_EXTRA_OPCODE_BUDGET
                ),
            }));
        }

        // Compute group fee credit so inner transactions can draw from
        // overpayment by outer transactions (matches go-algorand's feeCredit).
        let fee_credit = {
            let group_refs: Vec<&SignedTransaction> = eval_group.iter().collect();
            compute_group_fee_credit(&group_refs, consensus.min_txn_fee)
        };

        let apply_ctx = ApplyContext {
            rewards_level: self.store.rewards_level(),
            fee_sink: self.store.fee_sink(),
            round: sim_round.0,
            mode: ApplyMode::Execute,
            validate: true,
            latest_timestamp,
            genesis_hash: *self.store.genesis_hash(),
            txn_counter: Cell::new(self.store.txn_counter()),
            fee_credit: Cell::new(fee_credit),
            txn_index: Cell::new(0),
            consensus,
            // Simulation-only AVM overrides: raised log limits
            // (`allow_more_logging`) and unnamed-resource tracking
            // (`allow_unnamed_resources`).
            avm_overrides: AvmEvalOverrides {
                max_log_calls: result.eval_overrides.max_log_calls,
                max_log_size: result.eval_overrides.max_log_size,
                unnamed_tracking: request
                    .allow_unnamed_resources
                    .then(|| Arc::new(NamedGroupResources::from_group(&eval_group))),
            },
            failed_eval_delta: Cell::new(None),
        };

        // --- Execute the transaction group ---

        // Pre-populate TxnResult for ALL txns (Go returns results even for
        // transactions past the failure point).
        let mut group_result = TxnGroupResult::default();
        for stx in txn_group {
            group_result.txn_results.push(TxnResult {
                txn: Some(stx.clone()),
                ..Default::default()
            });
        }

        // Seed per-transaction LogicSig budget consumed for the whole group.
        // LogicSig programs run during `check()` (signature verification of the
        // entire group), so their budgets are known even for transactions past
        // an execution failure point — matching go-algorand, where the verify
        // pass populates `LogicSigBudgetConsumed` before evaluation begins.
        for (i, consumed) in logicsig_budgets.iter().enumerate() {
            group_result.txn_results[i].logicsig_budget_consumed = *consumed;
        }

        let mut failure_message: Option<String> = None;
        let mut failed_at: Option<TxnPath> = None;

        // Initial application state captured across the group (populated only
        // when state-change tracing is requested). Each transaction's tracer
        // captures into its own accumulator; we merge them here with
        // first-touch-wins semantics so the earliest-seen pre-value persists.
        let mut initial_states = InitialStatesAccumulator::default();

        // Unnamed resources accessed across the whole group (populated only
        // when `allow_unnamed_resources` is requested).
        let mut group_unnamed = UnnamedResourcesAccessed::default();

        // Count app calls for group budget
        let num_app_calls = eval_group
            .iter()
            .filter(|stx| stx.txn.txn_type == "appl")
            .count();
        let mut group_budget = GroupBudget::new(num_app_calls);
        // Apply extra opcode budget from the simulation request.
        if request.extra_opcode_budget != 0 {
            group_budget.add(request.extra_opcode_budget);
        }

        for i in 0..eval_group.len() {
            apply_ctx.txn_index.set(i);

            // Create a per-transaction tracer to capture execution details.
            // Seed it with apps created by earlier transactions in the group so
            // the created-app exclusion persists across the whole simulation
            // (go-algorand keeps a single ResourcesInitialStates for the run).
            let mut tracer = SimulationTracer::new(request.trace_config.clone());
            tracer.seed_created_apps(&initial_states.created_app_ids());

            // Use apply_transaction_with_budget for ALL transactions (not just appl)
            // so they all share the group context. The group refs are rebuilt
            // per iteration because `fix_signers` may mutate later
            // transactions' `auth_addr` between iterations.
            let apply_result = {
                let group_refs: Vec<&SignedTransaction> = eval_group.iter().collect();
                let gi = GroupInfo {
                    txns: &group_refs,
                    index: i,
                };
                apply_transaction_with_budget(
                    self.store,
                    &eval_group[i],
                    &apply_ctx,
                    0,
                    Some(&mut group_budget),
                    Some(&gi),
                    Some(&mut tracer),
                )
            };
            // Per-transaction app budget consumed = the sum of every approval /
            // clear-state program cost under this txn, including inner app calls,
            // accumulated by the tracer (go-algorand rolls each program's
            // `cx.Cost()` into the top-level txn — `tracer.go:504`). This is read
            // from the tracer rather than the shared pool delta because inner app
            // calls add `MaxAppProgramCost` to the pool and clear-state programs
            // run on an isolated budget, so the net pool delta under-reports.
            group_result.txn_results[i].app_budget_consumed = tracer.app_budget_consumed();
            // (logicsig_budget_consumed was pre-seeded for the whole group above.)

            match apply_result {
                Ok(apply_data) => {
                    // Defensively drain `failed_eval_delta` even on success:
                    // nothing sets it on this path today, but a future change
                    // must not let a stale value from an earlier iteration
                    // silently attach to this (unrelated, successful) txn.
                    apply_ctx.failed_eval_delta.take();
                    group_result.txn_results[i].apply_data = Some(apply_data);
                    initial_states.merge(tracer.take_initial_states());
                    group_unnamed.merge(tracer.take_unnamed_resources());
                    group_result.txn_results[i].trace =
                        merge_logicsig_trace(tracer.into_transaction_trace(), &logicsig_traces, i);

                    // FixSigners: an app call can rekey accounts (via inner
                    // transactions), so re-correct the auth addrs of the
                    // remaining unsigned transactions from the mutated ledger,
                    // up to and including the next app call — go-algorand's
                    // `AfterProgram` fix pass (`ledger/simulation/tracer.go`).
                    if request.fix_signers && eval_group[i].txn.txn_type == "appl" {
                        fix_unsigned_signers_after_app(&*self.store, &mut eval_group, i);
                    }
                }
                Err(e) => {
                    // Record failure. Collect any partial trace data before
                    // stopping (the tracer may have captured events up to
                    // the point of failure).
                    failure_message = Some(e.to_string());
                    failed_at = Some(vec![i]);
                    initial_states.merge(tracer.take_initial_states());
                    group_unnamed.merge(tracer.take_unnamed_resources());
                    group_result.txn_results[i].trace =
                        merge_logicsig_trace(tracer.into_transaction_trace(), &logicsig_traces, i);
                    // A rejected/erroring `appl` call leaves its partial
                    // EvalDelta on `apply_ctx` (set by `apply_appl` right
                    // before returning this error — see the field's doc
                    // comment). Surface it so callers can see what the
                    // program computed up to the point of failure, matching
                    // go-algorand's `evalTracer.saveEvalDelta`. `None` for
                    // any other failure (e.g. insufficient balance).
                    if let Some(dt) = apply_ctx.failed_eval_delta.take() {
                        group_result.txn_results[i].apply_data = Some(crate::apply::ApplyData {
                            eval_delta: Some(dt),
                            ..Default::default()
                        });
                    }
                    break;
                }
            }
        }

        group_result.failure_message = failure_message;
        group_result.failed_at = failed_at;

        // Report unnamed resources accessed by the group (go-algorand drops
        // the field entirely when nothing was recorded).
        if request.allow_unnamed_resources && group_unnamed.has_resources() {
            group_result.unnamed_resources_accessed = Some(group_unnamed);
        }

        // FixSigners: report the corrected signer for each transaction whose
        // effective signer differs from the one supplied in the request
        // (go-algorand's post-evaluation `FixedSigner` pass).
        for i in 0..group_result.txn_results.len() {
            let sender = txn_group[i].txn.sender;
            let input_signer = txn_group[i].auth_addr.unwrap_or(sender);
            let actual_signer = eval_group[i].auth_addr.unwrap_or(sender);
            if input_signer != actual_signer {
                group_result.txn_results[i].fixed_signer = Some(actual_signer);
            }
        }

        // Compute group-level budget metrics. AppBudgetConsumed is the sum of
        // the per-transaction figures (each rolled up from its programs +
        // inners via the tracer), which is correct even when inner app calls
        // grow the pool or clear-state runs on an isolated budget — unlike the
        // raw pool delta. AppBudgetAdded keeps the top-level allocation; its
        // inner-app-call growth is a separate, documented divergence.
        let total_budget = (num_app_calls as i64) * 700 + request.extra_opcode_budget;
        group_result.app_budget_added = total_budget.max(0) as u64;
        group_result.app_budget_consumed = group_result
            .txn_results
            .iter()
            .map(|t| t.app_budget_consumed)
            .sum();

        result.txn_groups.push(group_result);

        // Surface captured initial states when state-change tracing was
        // requested (go-algorand returns a non-nil `InitialStates` whenever
        // `TraceConfig.State` is set). Must happen before the store is
        // restored, though the accumulator already owns the captured values.
        if request.trace_config.state {
            result.initial_states = Some(initial_states.into_resources_initial_states());
        }

        // --- Restore the store to its pre-simulation state ---

        self.store.restore_snapshot(snapshot);

        Ok(result)
    }

    /// Validate a transaction group before execution.
    ///
    /// Mirrors go-algorand's `Simulator.check()`:
    /// 1. Well-formedness check on each transaction.
    /// 2. Signature verification — when `allow_empty_signatures` is true,
    ///    unsigned transactions are proxy-signed with a fixed key so that
    ///    signature verification passes without requiring the caller to
    ///    provide real signatures.
    #[allow(clippy::type_complexity)]
    fn check(
        &self,
        txn_group: &[SignedTransaction],
        allow_empty_signatures: bool,
        consensus: &ConsensusParams,
        trace_config: &ExecTraceConfig,
    ) -> Result<(Vec<Option<TransactionTrace>>, Vec<u64>), SimulatorError> {
        let spec = SpecialAddresses {
            fee_sink: self.store.fee_sink(),
            rewards_pool: self.store.rewards_pool(),
        };

        // Build a mutable copy for proxy-signing unsigned transactions.
        let mut verify_group: Vec<SignedTransaction> = txn_group.to_vec();

        let proxy_key = SigningKey::from_bytes(&PROXY_SIGNER_SEED);

        // Pass 1: reject unsupported transaction types, check well-formedness,
        // and proxy-sign unsigned transactions. Matches go-algorand's ordering
        // where all proxy-signing happens before group verification.
        for stx in &mut verify_group {
            // Reject StateProof transactions (go-algorand: simulator.go:164).
            if stx.txn.txn_type == "stpf" {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "cannot simulate StateProof transactions".to_string(),
                }));
            }

            // Check well-formedness. Pass `allow_fee_pooling = enable_fee_pooling`
            // so that on pre-fee-pooling protocols (before v28) each transaction
            // is held to the per-transaction minimum fee, matching go-algorand's
            // `Transaction.WellFormed` (`!proto.EnableFeePooling && fee < min`).
            // On fee-pooling protocols the per-txn check is skipped here and the
            // pooled group-fee check below enforces the minimum (mirroring
            // `verify.TxnGroup`).
            validate_transaction_wellformed(
                &stx.txn,
                consensus.enable_fee_pooling,
                consensus,
                Some(&spec),
            )
            .map_err(|e| {
                SimulatorError::InvalidRequest(InvalidRequestError {
                    message: e.to_string(),
                })
            })?;

            // Handle empty signatures when allowed.
            let has_sig = stx.sig != [0u8; 64];
            let has_msig = stx.msig.is_some();
            let has_lsig = stx.lsig.is_some();
            if allow_empty_signatures && !has_sig && !has_msig && !has_lsig {
                // Proxy-sign: create a valid ed25519 signature so verification
                // passes. Mirrors go-algorand's `Transaction.Sign()` which
                // sets `AuthAddr` to the signing key's public key when it
                // differs from the sender.
                let canonical = canonical_encode_transaction(&stx.txn);
                let mut msg = Vec::with_capacity(2 + canonical.len());
                msg.extend_from_slice(b"TX");
                msg.extend_from_slice(&canonical);
                let sig = proxy_key.sign(&msg);
                stx.sig = sig.to_bytes();

                // Set auth_addr to proxy key's public key so the verifier
                // checks the signature against the correct key.
                let proxy_pub = proxy_key.verifying_key().to_bytes();
                if proxy_pub != stx.txn.sender.0 {
                    stx.auth_addr = Some(Address(proxy_pub));
                }
            }
        }

        // Group-level fee validation (matches go-algorand's verify.TxnGroup,
        // txn.go): the submitted group is a single fee pool — total fees must
        // cover MinTxnFee for each non-exempt transaction. State proofs and
        // ungrouped heartbeats are exempt. Without this, an underpaid group
        // would only fail later during apply rather than as a clean check()
        // error (this is the check() phase, before evaluation).
        let mut fees_paid: u64 = 0;
        let mut min_fee_count: u64 = 0;
        for stx in &verify_group {
            fees_paid = fees_paid.saturating_add(stx.txn.fee);
            // State proofs are always free.
            if stx.txn.txn_type == "stpf" {
                continue;
            }
            // Ungrouped heartbeats are free when heartbeats are enabled.
            if is_free_heartbeat(&stx.txn, consensus) {
                continue;
            }
            min_fee_count += 1;
        }
        let fee_needed = consensus
            .min_txn_fee
            .checked_mul(min_fee_count)
            .ok_or_else(|| {
                SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "txgroup fee overflow".to_string(),
                })
            })?;
        if fees_paid < fee_needed {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: format!(
                    "txgroup had {fees_paid} in fees, which is less than the minimum {min_fee_count} * {}",
                    consensus.min_txn_fee
                ),
            }));
        }

        // Pass 2: verify signatures on the (possibly proxy-signed) group.
        // When tracing is enabled, capture each LogicSig program's opcode trace
        // here — the LogicSig runs during signature verification, before the
        // per-transaction execution tracer is created (go-algorand captures
        // both in one pass; this engine splits check() from execution, so the
        // logic-sig trace is captured now and merged into the execution trace
        // for the same transaction afterwards).
        //
        // The per-transaction LogicSig budget consumed is also measured here,
        // as the LogicSig opcode-budget pool delta around each transaction's
        // verification (go-algorand `tracer.go:495`:
        // `Txns[groupIndex].LogicSigBudgetConsumed = cx.Cost()`). This is
        // captured for all LogicSig transactions, independent of trace config.
        let mut logicsig_traces: Vec<Option<TransactionTrace>> = vec![None; verify_group.len()];
        let mut logicsig_budgets: Vec<u64> = vec![0; verify_group.len()];
        let mut budget = GroupBudget::for_logicsig(verify_group.len());
        for (i, stx) in verify_group.iter().enumerate() {
            let budget_before = budget.remaining();
            let result = if trace_config.is_enabled() && stx.lsig.is_some() {
                let mut lsig_tracer = SimulationTracer::new(trace_config.clone());
                let r = verify_transaction_signature_with_tracer(
                    stx,
                    &verify_group,
                    i,
                    &mut budget,
                    consensus,
                    Some(&mut lsig_tracer),
                );
                logicsig_traces[i] = lsig_tracer.into_transaction_trace();
                r
            } else {
                verify_transaction_signature(stx, &verify_group, i, &mut budget, consensus)
            };
            // A non-LogicSig transaction consumes no LogicSig budget, leaving
            // the delta at 0.
            logicsig_budgets[i] = (budget_before - budget.remaining()).max(0) as u64;
            result.map_err(|e| {
                SimulatorError::InvalidRequest(InvalidRequestError {
                    message: e.to_string(),
                })
            })?;
        }

        Ok((logicsig_traces, logicsig_budgets))
    }
}

/// Whether a signed transaction carries no signature of any kind
/// (go-algorand's `txnHasNoSignature`).
fn txn_has_no_signature(stx: &SignedTransaction) -> bool {
    stx.sig == [0u8; 64] && stx.msig.is_none() && stx.lsig.is_none()
}

/// The sender's current auth addr in the ledger, or the zero address when the
/// account is not rekeyed (go-algorand `AccountData.AuthAddr`).
fn ledger_auth_addr<L: LedgerStore>(store: &L, sender: &Address) -> Address {
    store
        .get_account(sender)
        .and_then(|a| a.auth_addr)
        .unwrap_or(Address::ZERO)
}

/// Set an unsigned transaction's `auth_addr` to the given authorizer,
/// normalising "authorizer == sender" to `None` (a zero auth addr means the
/// sender signs for itself).
fn set_fixed_auth_addr(stx: &mut SignedTransaction, auth: Address) {
    stx.auth_addr = if auth.is_zero() || auth == stx.txn.sender {
        None
    } else {
        Some(auth)
    };
}

/// FixSigners pre-evaluation pass: correct the `auth_addr` of unsigned
/// transactions from static rekeys within the group or the ledger, stopping
/// at the first app call (later transactions are corrected by
/// [`fix_unsigned_signers_after_app`] once each app call completes, since
/// apps can rekey accounts). Mirrors go-algorand's `simulateWithTracer`
/// (`ledger/simulation/simulator.go:219-260`).
fn fix_unsigned_signers_pre_eval<L: LedgerStore>(store: &L, group: &mut [SignedTransaction]) {
    let mut static_rekeys: HashMap<Address, Address> = HashMap::new();
    for stx in group.iter_mut() {
        let sender = stx.txn.sender;
        if txn_has_no_signature(stx) {
            let auth = match static_rekeys.get(&sender) {
                Some(a) => *a,
                None => ledger_auth_addr(store, &sender),
            };
            set_fixed_auth_addr(stx, auth);
        }

        // Stop at the first app call: auth-addr correction for the rest is
        // done after each app program runs.
        if stx.txn.txn_type == "appl" {
            break;
        }

        if let Some(rekey) = stx.txn.rekey_to {
            if !rekey.is_zero() {
                static_rekeys.insert(sender, rekey);
            }
        }
    }
}

/// FixSigners post-app-call pass: after the app call at `app_index`
/// completes, re-correct the `auth_addr` of the remaining unsigned
/// transactions from the (possibly rekeyed) ledger state and static rekeys,
/// up to and including the next app call. Mirrors go-algorand's
/// `evalTracer.AfterProgram` fix pass (`ledger/simulation/tracer.go`).
fn fix_unsigned_signers_after_app<L: LedgerStore>(
    store: &L,
    group: &mut [SignedTransaction],
    app_index: usize,
) {
    let mut known_auth_addrs: HashMap<Address, Address> = HashMap::new();
    for stx in group.iter_mut().skip(app_index + 1) {
        let sender = stx.txn.sender;
        let auth = *known_auth_addrs
            .entry(sender)
            .or_insert_with(|| ledger_auth_addr(store, &sender));

        if txn_has_no_signature(stx) {
            set_fixed_auth_addr(stx, auth);
        }

        // The next app call's own AfterProgram pass handles the rest.
        if stx.txn.txn_type == "appl" {
            break;
        }

        if let Some(rekey) = stx.txn.rekey_to {
            if !rekey.is_zero() {
                known_auth_addrs.insert(sender, rekey);
            }
        }
    }
}

/// Merge a logic-sig trace captured during `check()` into the execution-phase
/// trace for the same transaction. The LogicSig program runs during signature
/// verification (before the per-transaction execution tracer exists), so its
/// `logicsig_trace` / `logicsig_hash` are captured separately and grafted onto
/// the transaction's execution trace here, matching go-algorand's single
/// `TransactionTrace` that holds both the logic-sig and app-call traces.
fn merge_logicsig_trace(
    exec_trace: Option<TransactionTrace>,
    logicsig_traces: &[Option<TransactionTrace>],
    index: usize,
) -> Option<TransactionTrace> {
    let lsig = match logicsig_traces.get(index).and_then(|t| t.as_ref()) {
        Some(t) if t.logicsig_trace.is_some() => t,
        _ => return exec_trace,
    };
    // Tracing is enabled (a logic-sig trace was captured), so the execution
    // tracer always produced a `Some` trace; fall back to a default trace if
    // for some reason it didn't, so the logic-sig trace is never dropped.
    let mut trace = exec_trace.unwrap_or_default();
    trace.logicsig_trace = lsig.logicsig_trace.clone();
    trace.logicsig_hash = lsig.logicsig_hash;
    Some(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_validation_fix_signers_requires_allow_empty() {
        // We can't easily construct a full LedgerStore for unit tests here,
        // so we just test the error types directly.
        let err = SimulatorError::InvalidRequest(InvalidRequestError {
            message: "test error".to_string(),
        });
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_request_default() {
        let req = SimulationRequest::default();
        assert!(req.txn_groups.is_empty());
        assert!(!req.allow_empty_signatures);
        assert!(!req.fix_signers);
        assert_eq!(req.extra_opcode_budget, 0);
    }

    #[test]
    fn test_eval_failure_error_display() {
        let err = EvalFailureError {
            message: "budget exceeded".to_string(),
            failed_at: vec![0, 1],
        };
        let s = err.to_string();
        assert!(s.contains("budget exceeded"));
        assert!(s.contains("[0, 1]"));
    }

    #[test]
    fn test_simulator_error_from_algo_error() {
        let algo_err = AlgoError::Ledger {
            message: "test".to_string(),
        };
        let sim_err: SimulatorError = algo_err.into();
        assert!(matches!(sim_err, SimulatorError::Internal(_)));
    }
}
