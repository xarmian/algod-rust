//! `goal clerk` — port of `../go-algorand/cmd/goal/clerk.go` (+ `multisig.go`,
//! `tealsign.go`).
//!
//! `send` is implemented (the core payment path); the remaining leaves
//! (compile / dryrun* / group / inspect / multisig / rawsend / sign / simulate
//! / split / tealsign) are still stubbed pending their own follow-ups.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
// `Send` carries the full payment flag surface (many `Option<String>` fields);
// the other leaves are unit variants. Boxing a clap `Args` payload is awkward
// and buys nothing for a short-lived CLI parse, so allow the size disparity.
#[allow(clippy::large_enum_variant)]
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
    Send(SendArgs),
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

/// `clerk send` — send money from one account to another.
///
/// Mirrors Go's `sendCmd` (clerk.go:348-576) flag surface. Flag names, short
/// flags, and required-ness match Go: `-a/--amount` and `-t/--to` are required;
/// `-f/--from` defaults to the accountList default account; fee/validity follow
/// `addTxnFlags` (common.go:57-66).
///
/// **Out of scope (documented):** LogicSig / program-account sending
/// (`--from-program/-F`, `--from-program-bytes/-P`, `--logic-sig/-L`,
/// `--argb64`) and `--msig-params` (rekeyed-to-multisig signing) are not
/// implemented — those leaves remain a follow-up. They're omitted from the
/// flag set so `clerk send` only advertises what it can do.
#[derive(Args, Debug)]
pub struct SendArgs {
    /// Amount to transfer, in microAlgos. Required (Go `-a/--amount`).
    #[arg(short = 'a', long = "amount")]
    pub amount: u64,
    /// Account address (or accountList name) to send from. Defaults to the
    /// accountList default account (Go `-f/--from`).
    #[arg(short = 'f', long = "from")]
    pub from: Option<String>,
    /// Address (or accountList name) to send to. Required (Go `-t/--to`).
    #[arg(short = 't', long = "to")]
    pub to: String,
    /// Close the sender account, sending the remainder to this address
    /// (Go `-c/--close-to`).
    #[arg(short = 'c', long = "close-to")]
    pub close_to: Option<String>,
    /// Rekey the sender to this spending key/address (Go `--rekey-to`).
    #[arg(long = "rekey-to")]
    pub rekey_to: Option<String>,
    /// Transaction fee in microAlgos (Go `--fee`; suggested when unset).
    #[arg(long = "fee")]
    pub fee: Option<u64>,
    /// First round at which the transaction is valid (Go `--firstvalid`).
    #[arg(long = "firstvalid")]
    pub first_valid: Option<u64>,
    /// Last round at which the transaction is valid (Go `--lastvalid`).
    #[arg(long = "lastvalid")]
    pub last_valid: Option<u64>,
    /// Number of rounds for which the transaction is valid (Go `--validrounds`;
    /// mutually exclusive with `--lastvalid`).
    #[arg(long = "validrounds")]
    pub valid_rounds: Option<u64>,
    /// Note text (Go `-n/--note`; ignored if `--noteb64` is also given).
    #[arg(short = 'n', long = "note")]
    pub note: Option<String>,
    /// Note bytes, base64-encoded (Go `--noteb64`).
    #[arg(long = "noteb64")]
    pub note_b64: Option<String>,
    /// Lease value, base64-encoded, must decode to 32 bytes (Go `-x/--lease`).
    #[arg(short = 'x', long = "lease")]
    pub lease: Option<String>,
    /// Write the transaction to this file instead of broadcasting
    /// (Go `-o/--out`).
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,
    /// With `-o`, sign the written transaction (Go `-s/--sign`). Invalid
    /// without `-o`.
    #[arg(short = 's', long = "sign")]
    pub sign: bool,
    /// Don't wait for the transaction to commit (Go `-N/--no-wait` on rawsend;
    /// goal `send` also honors the global no-wait behavior).
    #[arg(short = 'N', long = "no-wait")]
    pub no_wait: bool,
    /// Wallet name. Go declares `-w/--wallet` as a *persistent* flag on the
    /// `clerk` group (clerk.go:101), so `goal clerk -w w send ...` works there.
    /// goal-rust places it on the leaf instead — `clerk send -w w ...` — the
    /// same documented divergence the `account` group already ships (every
    /// account leaf re-declares `-w` rather than inheriting a group flag). Pass
    /// `-w` after `send`.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,
    /// Wallet password (skip the prompt). goal-rust convention shared with the
    /// account leaves.
    #[arg(long = "password")]
    pub password: Option<String>,
}

pub fn run(cmd: ClerkCmd) -> ExitCode {
    use crate::cli_state::{datadirs, kmddir};

    let leaf: &str = match cmd {
        ClerkCmd::Send(args) => {
            return crate::cmd::clerk::run_send(args, datadirs(), kmddir());
        }
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
        ClerkCmd::Sign => "sign",
        ClerkCmd::Simulate => "simulate",
        ClerkCmd::Split => "split",
        ClerkCmd::Tealsign => "tealsign",
    };
    unimplemented("clerk", leaf)
}
