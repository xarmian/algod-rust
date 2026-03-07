//! AVM (Algorand Virtual Machine) core crate.
//!
//! Provides the opcode table, bytecode parser, program validator,
//! stack machine, and opcode implementations for TEAL program execution.

pub mod bytecode;
pub mod context;
pub mod fields;
pub mod machine;
pub mod opcode;
pub mod ops;
pub mod validator;

// Re-export key types for convenience.
pub use bytecode::{parse, Immediates, Instruction, Program};
pub use context::{AvmContext, NullContext};
pub use machine::{AvmMachine, AvmValue, CallFrame, ExecMode};
pub use opcode::{lookup, CostKind, ImmKind, Mode, OpSpec, MAX_AVM_VERSION};
pub use validator::check_program;
