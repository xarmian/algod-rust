//! AVM (Algorand Virtual Machine) core crate.
//!
//! Provides the opcode table, bytecode parser, program validator,
//! stack machine, and opcode implementations for TEAL program execution.

pub mod assembler;
pub mod bytecode;
pub mod context;
pub mod disassembler;
pub mod eval;
pub mod fields;
pub mod group;
pub mod itxn;
pub mod logicsig_context;
pub mod machine;
pub mod opcode;
pub mod ops;
pub mod sourcemap;
pub mod tracer;
pub mod txn_fields;
pub mod validator;

// Re-export key types for convenience.
pub use bytecode::{parse, Immediates, Instruction, Program};
pub use context::{AvmContext, NullContext};
pub use eval::{
    run_approval_program, run_approval_program_with_tracer, run_clear_state_program,
    run_clear_state_program_with_tracer, run_logicsig_program, run_logicsig_program_with_tracer,
    AvmResult, APP_BUDGET_PER_CALL, LOGICSIG_BUDGET, MAX_APP_PROGRAM_COST,
};
pub use group::{GroupBudget, GroupContext};
pub use itxn::compute_inner_txn_id;
pub use logicsig_context::LogicSigAvmContext;
pub use machine::{AvmMachine, AvmValue, CallFrame, ExecMode, OpcodeCoverage};
pub use opcode::{
    all_opcodes, defined_opcode_count, lookup, CostKind, ImmKind, Mode, OpSpec, MAX_AVM_VERSION,
};
pub use tracer::{EvalTracer, NullTracer, ProgramType};
pub use txn_fields::{read_txn_field, type_enum};
pub use validator::check_program;

// Assembler / disassembler / source map re-exports.
pub use assembler::{assemble_string, OpStream as AssemblerOpStream};
pub use disassembler::disassemble;
pub use sourcemap::{get_source_map, SourceMap};
