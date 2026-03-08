//! AVM (Algorand Virtual Machine) core crate.
//!
//! Provides the opcode table, bytecode parser, program validator,
//! stack machine, and opcode implementations for TEAL program execution.

pub mod bytecode;
pub mod context;
pub mod eval;
pub mod fields;
pub mod group;
pub mod itxn;
pub mod machine;
pub mod opcode;
pub mod ops;
pub mod validator;

// Re-export key types for convenience.
pub use bytecode::{parse, Immediates, Instruction, Program};
pub use context::{AvmContext, NullContext};
pub use eval::{
    run_approval_program, run_clear_state_program, AvmResult, APP_BUDGET_PER_CALL, LOGICSIG_BUDGET,
    MAX_APP_PROGRAM_COST,
};
pub use group::{GroupBudget, GroupContext};
pub use itxn::compute_inner_txn_id;
pub use machine::{AvmMachine, AvmValue, CallFrame, ExecMode};
pub use opcode::{lookup, CostKind, ImmKind, Mode, OpSpec, MAX_AVM_VERSION};
pub use validator::check_program;
