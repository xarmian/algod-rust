//! `goal clerk` — port of `../go-algorand/cmd/goal/clerk.go` (+ `multisig.go`,
//! `tealsign.go`).

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum ClerkCmd {
    /// Compile a contract program.
    Compile,
    /// Test a program offline.
    Dryrun,
    /// Test a program with algod's dryrun REST endpoint.
    #[command(name = "dryrun-remote")]
    DryrunRemote,
    /// Group transactions together.
    Group,
    /// Print a transaction file.
    Inspect,
    /// Provides tools working with multisig transactions.
    Multisig {
        #[command(subcommand)]
        cmd: Option<MultisigCmd>,
    },
    /// Send raw transactions.
    Rawsend,
    /// Send money to an address.
    Send,
    /// Sign a transaction file.
    Sign,
    /// Simulate a transaction or transaction group with algod's simulate
    /// REST endpoint.
    Simulate,
    /// Split a file containing many transactions into one transaction per
    /// file.
    Split,
    /// Sign data to be verified in a TEAL program.
    Tealsign,
}

#[derive(Subcommand, Debug)]
pub enum MultisigCmd {
    /// Merge multisig signatures on transactions.
    Merge,
    /// Add a signature to a multisig transaction.
    Sign,
    /// Add a signature to a multisig LogicSig.
    Signprogram,
}

pub fn run(cmd: ClerkCmd) -> ExitCode {
    let leaf: &str = match cmd {
        ClerkCmd::Compile => "compile",
        ClerkCmd::Dryrun => "dryrun",
        ClerkCmd::DryrunRemote => "dryrun-remote",
        ClerkCmd::Group => "group",
        ClerkCmd::Inspect => "inspect",
        ClerkCmd::Multisig { cmd } => {
            let Some(cmd) = cmd else {
                return crate::print_group_help(&["clerk", "multisig"]);
            };
            let leaf = match cmd {
                MultisigCmd::Merge => "merge",
                MultisigCmd::Sign => "sign",
                MultisigCmd::Signprogram => "signprogram",
            };
            return unimplemented("clerk multisig", leaf);
        }
        ClerkCmd::Rawsend => "rawsend",
        ClerkCmd::Send => "send",
        ClerkCmd::Sign => "sign",
        ClerkCmd::Simulate => "simulate",
        ClerkCmd::Split => "split",
        ClerkCmd::Tealsign => "tealsign",
    };
    unimplemented("clerk", leaf)
}
