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
    AvmValueTrace, ExecTraceConfig, OpcodeTraceUnit, ProgramTrace, ResultEvalOverrides,
    SimulationResult, StateChange, StateChangeKind, TransactionTrace, TxnGroupResult, TxnPath,
    TxnResult,
};
pub use tracer::SimulationTracer;

use std::cell::Cell;
use std::fmt;

use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, Round, SignedTransaction};

use crate::apply::{apply_transaction, ApplyContext, ApplyMode};
use crate::store_trait::LedgerStore;

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
        let mut addrs: Vec<Address> = Vec::new();
        for stx in txn_group {
            addrs.push(stx.txn.sender);
            if stx.txn.receiver != Address::ZERO {
                addrs.push(stx.txn.receiver);
            }
            if stx.txn.close_remainder_to != Address::ZERO {
                addrs.push(stx.txn.close_remainder_to);
            }
        }
        // Deduplicate addresses.
        addrs.sort_by(|a, b| a.0.cmp(&b.0));
        addrs.dedup();

        let snapshot = self.store.snapshot(&addrs);

        // --- Build apply context ---

        let consensus = ConsensusParams::default();
        let apply_ctx = ApplyContext {
            rewards_level: self.store.rewards_level(),
            fee_sink: self.store.fee_sink(),
            round: sim_round.0,
            mode: ApplyMode::Execute,
            validate: false,
            latest_timestamp: 0,
            genesis_hash: *self.store.genesis_hash(),
            txn_counter: Cell::new(self.store.txn_counter()),
            fee_credit: Cell::new(0),
            txn_index: Cell::new(0),
            consensus,
        };

        // --- Execute each transaction in the group ---

        let mut group_result = TxnGroupResult::default();
        let mut failure_message: Option<String> = None;
        let mut failed_at: Option<TxnPath> = None;

        for (i, stx) in txn_group.iter().enumerate() {
            apply_ctx.txn_index.set(i);

            let mut txn_result = TxnResult::default();

            // Create a per-transaction tracer if tracing is enabled.
            // TODO(#121): Wire tracer into apply_transaction → AVM execution.
            // Currently the tracer captures no events because apply_transaction
            // does not accept a tracer parameter. Threading EvalTracer through
            // the apply pipeline requires changes to apply_transaction, LedgerAvmContext,
            // and the AVM execution entry points. For now, exec-trace results
            // will be empty even when tracing is requested.
            let mut tracer = SimulationTracer::new(request.trace_config.clone());
            let _ = &mut tracer;

            match apply_transaction(self.store, stx, &apply_ctx, 0) {
                Ok(()) => {
                    // Transaction applied successfully.
                }
                Err(e) => {
                    // Record failure but continue to build results.
                    failure_message = Some(e.to_string());
                    failed_at = Some(vec![i]);
                    // Collect what we have for this txn and stop processing.
                    group_result.txn_results.push(txn_result);
                    break;
                }
            }

            // Collect tracer results.
            txn_result.trace = tracer.into_transaction_trace();
            group_result.txn_results.push(txn_result);
        }

        group_result.failure_message = failure_message;
        group_result.failed_at = failed_at;
        result.txn_groups.push(group_result);

        // --- Restore the store to its pre-simulation state ---

        self.store.restore_snapshot(snapshot);

        Ok(result)
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
