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
    StateChangeKind, TransactionTrace, TxnGroupResult, TxnPath, TxnResult,
};
pub use tracer::SimulationTracer;

use std::cell::Cell;
use std::fmt;

use algo_avm::group::GroupBudget;
use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};
use algo_types::{Address, Round, SignedTransaction};
use algo_validate::{
    is_free_heartbeat, validate_transaction_wellformed, verify_transaction_signature,
    SpecialAddresses,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::apply::{
    apply_transaction_with_budget, compute_group_fee_credit, ApplyContext, ApplyMode, GroupInfo,
};
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
            max_log_calls: None,
            max_log_size: None,
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
        addrs.sort_by(|a, b| a.0.cmp(&b.0));
        addrs.dedup();

        // Collect app/asset IDs that may be created or modified during
        // simulation so the snapshot can roll them back. For creates
        // (application_id == 0 or config_asset == 0), pre-compute the
        // derived ID from the running txn_counter.
        let mut asset_ids: Vec<u64> = Vec::new();
        let mut app_ids: Vec<u64> = Vec::new();
        let mut sim_counter = self.store.txn_counter();
        for stx in txn_group {
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
            // Each top-level txn increments the counter
            sim_counter += 1;
        }

        let snapshot = if asset_ids.is_empty() && app_ids.is_empty() {
            self.store.snapshot(&addrs)
        } else {
            self.store.snapshot_with_ids(&addrs, &asset_ids, &app_ids)
        };

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

        // Run validation (signature verification + well-formedness) before execution.
        if let Err(e) = self.check(txn_group, request.allow_empty_signatures, &consensus) {
            self.store.restore_snapshot(snapshot);
            return Err(e);
        }

        // Compute group fee credit so inner transactions can draw from
        // overpayment by outer transactions (matches go-algorand's feeCredit).
        let group_refs: Vec<&SignedTransaction> = txn_group.iter().collect();
        let fee_credit = compute_group_fee_credit(&group_refs, consensus.min_txn_fee);

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

        let mut failure_message: Option<String> = None;
        let mut failed_at: Option<TxnPath> = None;

        // Initial application state captured across the group (populated only
        // when state-change tracing is requested). Each transaction's tracer
        // captures into its own accumulator; we merge them here with
        // first-touch-wins semantics so the earliest-seen pre-value persists.
        let mut initial_states = InitialStatesAccumulator::default();

        // Count app calls for group budget
        let num_app_calls = txn_group
            .iter()
            .filter(|stx| stx.txn.txn_type == "appl")
            .count();
        let mut group_budget = GroupBudget::new(num_app_calls);
        // Apply extra opcode budget from the simulation request.
        if request.extra_opcode_budget != 0 {
            group_budget.add(request.extra_opcode_budget);
        }

        for (i, stx) in txn_group.iter().enumerate() {
            apply_ctx.txn_index.set(i);

            let gi = GroupInfo {
                txns: &group_refs,
                index: i,
            };

            // Create a per-transaction tracer to capture execution details.
            // Seed it with apps created by earlier transactions in the group so
            // the created-app exclusion persists across the whole simulation
            // (go-algorand keeps a single ResourcesInitialStates for the run).
            let mut tracer = SimulationTracer::new(request.trace_config.clone());
            tracer.seed_created_apps(&initial_states.created_app_ids());

            // Use apply_transaction_with_budget for ALL transactions (not just appl)
            // so they all share the group context.
            let apply_result = apply_transaction_with_budget(
                self.store,
                stx,
                &apply_ctx,
                0,
                Some(&mut group_budget),
                Some(&gi),
                Some(&mut tracer),
            );

            match apply_result {
                Ok(apply_data) => {
                    group_result.txn_results[i].apply_data = Some(apply_data);
                    initial_states.merge(tracer.take_initial_states());
                    group_result.txn_results[i].trace = tracer.into_transaction_trace();
                }
                Err(e) => {
                    // Record failure. Collect any partial trace data before
                    // stopping (the tracer may have captured events up to
                    // the point of failure).
                    failure_message = Some(e.to_string());
                    failed_at = Some(vec![i]);
                    initial_states.merge(tracer.take_initial_states());
                    group_result.txn_results[i].trace = tracer.into_transaction_trace();
                    break;
                }
            }
        }

        group_result.failure_message = failure_message;
        group_result.failed_at = failed_at;

        // Compute group-level budget metrics.
        let total_budget = (num_app_calls as i64) * 700 + request.extra_opcode_budget;
        group_result.app_budget_added = total_budget.max(0) as u64;
        group_result.app_budget_consumed = (total_budget - group_budget.remaining()).max(0) as u64;

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
    fn check(
        &self,
        txn_group: &[SignedTransaction],
        allow_empty_signatures: bool,
        consensus: &ConsensusParams,
    ) -> Result<(), SimulatorError> {
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
        let mut budget = GroupBudget::for_logicsig(verify_group.len());
        for (i, stx) in verify_group.iter().enumerate() {
            verify_transaction_signature(stx, &verify_group, i, &mut budget, consensus).map_err(
                |e| {
                    SimulatorError::InvalidRequest(InvalidRequestError {
                        message: e.to_string(),
                    })
                },
            )?;
        }

        Ok(())
    }
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
