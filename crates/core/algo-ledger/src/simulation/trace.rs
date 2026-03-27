//! Simulation trace types for capturing AVM execution details.
//!
//! These types mirror go-algorand's `ledger/simulation/trace.go` and represent
//! the internal simulation result structure. They are separate from the REST
//! API model types; conversion to REST types happens in the API layer.

use algo_types::{Address, Round, SignedTransaction};

use crate::apply::ApplyData;

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
    /// The application ID.
    pub app_id: u64,
    /// The state key.
    pub key: Vec<u8>,
    /// The new value (None for deletions).
    pub new_value: Option<AvmValueTrace>,
    /// The account address (for local state changes).
    pub account: Option<Address>,
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
    /// Trace of the clear-state program execution (if applicable).
    pub clear_state_program_trace: Option<ProgramTrace>,
    /// Trace of the logic signature execution (if applicable).
    pub logicsig_trace: Option<ProgramTrace>,
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
}

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
    }
}
