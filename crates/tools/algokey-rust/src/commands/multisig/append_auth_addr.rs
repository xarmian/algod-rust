//! `algokey multisig append-auth-addr` — stub (TASK-169 fills this).
//!
//! Phase B Section 9: dispatch slot lives here so TASK-168 can land
//! the parent `multisig` command without flipping the bare-form path
//! on top of an unimplemented subcommand.

use std::process::ExitCode;

use crate::cli::AppendAuthAddrArgs;

pub fn run(_args: AppendAuthAddrArgs) -> ExitCode {
    eprintln!("not implemented");
    ExitCode::from(2)
}
