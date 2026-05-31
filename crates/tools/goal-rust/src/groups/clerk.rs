//! `goal clerk` — port of `../go-algorand/cmd/goal/clerk.go` (+ `multisig.go`,
//! `tealsign.go`).
//!
//! `send` plus the offline txn-file utilities (`inspect` / `split` / `group`)
//! and `rawsend` are implemented; the remaining leaves (compile / dryrun* /
//! multisig / sign / simulate / tealsign) are still stubbed pending their own
//! follow-ups.

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
    Group(GroupArgs),
    /// Print a transaction file.
    Inspect(InspectArgs),
    /// Provides tools working with multisig transactions.
    Multisig {
        #[command(subcommand)]
        cmd: Option<MultisigCmd>,
    },
    /// Send raw transactions.
    Rawsend(RawsendArgs),
    /// Send money to an address.
    Send(SendArgs),
    /// Sign a transaction file.
    Sign(SignArgs),
    /// Simulate a transaction or transaction group with algod's simulate
    /// REST endpoint.
    Simulate,
    /// Split a file containing many transactions into one transaction per
    /// file.
    Split(SplitArgs),
    /// Sign data to be verified in a TEAL program.
    Tealsign(TealsignArgs),
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
    /// Wallet password (skip the prompt). goal-rust convention shared with the
    /// account leaves.
    #[arg(long = "password")]
    pub password: Option<String>,
    // NOTE: `-w/--wallet` is declared on the `clerk` group (see
    // `RootCommand::Clerk`) as a `global = true` flag so both Go orderings
    // parse: `clerk -w w send ...` and `clerk send -w w ...`. It is threaded
    // into the handler via `run(.., wallet)` rather than living on `SendArgs`.
}

/// `clerk inspect [files...]` — pretty-print decoded transaction file(s).
///
/// Mirrors Go's `inspectCmd` (clerk.go:712): for each input file, stream-decode
/// `SignedTxn`s and print each as canonical JSON (`protocol.EncodeJSON` of the
/// `inspectSignedTxn` view — addresses in algorand base32 format, the LogicSig
/// program disassembled to TEAL).
#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Transaction files to decode and print. With none, nothing is printed
    /// (matches Go iterating over zero positional args).
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,
    /// Display the TxID for each transaction (Go `-t/--txid`).
    #[arg(short = 't', long = "txid")]
    pub txid: bool,
}

/// `clerk split -i <in> -o <out>` — split a multi-txn file into one file per
/// transaction. Mirrors Go's `splitCmd` (clerk.go:966): outputs are named
/// `<base>-<idx><ext>` derived from `-o`.
#[derive(Args, Debug)]
pub struct SplitArgs {
    /// File storing transactions to be split (Go `-i/--infile`). Required.
    #[arg(short = 'i', long = "infile")]
    pub infile: PathBuf,
    /// Base filename for the individual transactions; each is written to
    /// `<base>-<N><ext>` (Go `-o/--outfile`). Required.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: String,
}

/// `clerk group -i <in> -o <out>` — assign a computed group ID to the (unsigned)
/// transactions in a file. Mirrors Go's `groupCmd` (clerk.go:914).
#[derive(Args, Debug)]
pub struct GroupArgs {
    /// File storing transactions to be grouped (Go `-i/--infile`). Required.
    #[arg(short = 'i', long = "infile")]
    pub infile: PathBuf,
    /// Filename for writing the grouped transactions (Go `-o/--outfile`).
    /// Required.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: PathBuf,
}

/// `clerk rawsend -f <file> [-r rejects] [-N]` — submit a signed-txn file to
/// algod and (unless `-N`) wait for confirmation. Mirrors Go's `rawsendCmd`
/// (clerk.go:579).
#[derive(Args, Debug)]
pub struct RawsendArgs {
    /// Filename of file containing raw (msgpack `SignedTxn`) transactions
    /// (Go `-f/--filename`). Required.
    #[arg(short = 'f', long = "filename")]
    pub filename: PathBuf,
    /// Filename for writing rejected transactions to (Go `-r/--rejects`;
    /// default is `<filename>.rej`).
    #[arg(short = 'r', long = "rejects")]
    pub rejects: Option<PathBuf>,
    /// Don't wait for transactions to commit (Go `-N/--no-wait`).
    #[arg(short = 'N', long = "no-wait")]
    pub no_wait: bool,
}

/// `clerk sign -i <in> -o <out> [-S signer] [-p prog | -L lsig] [--argb64 ...]
/// [-P proto] [-w wallet] [--password]` — sign every transaction in a file.
///
/// Mirrors Go's `signCmd` (clerk.go:787-911). Two modes, keyed on whether a
/// program/logicsig source is given:
/// - **LogicSig** (`--program/-p` xor `--logic-sig/-L`, with `--argb64`):
///   attach the assembled/decoded LogicSig to each txn; with `-S/--signer`,
///   set the AuthAddr (the rekeyed spending account).
/// - **Wallet** (default): re-sign each txn's body via the kmd wallet, with
///   `-S/--signer` selecting the spending key when the sender was rekeyed.
#[derive(Args, Debug)]
pub struct SignArgs {
    /// Partially-signed transaction file to add a signature to
    /// (Go `-i/--infile`). Required.
    #[arg(short = 'i', long = "infile")]
    pub infile: PathBuf,
    /// Filename for writing the signed transaction (Go `-o/--outfile`).
    /// Required. May equal `--infile` to overwrite in place.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: PathBuf,
    /// Address of the key to sign with, if different from the transaction
    /// "from" address due to rekeying (Go `-S/--signer`).
    #[arg(short = 'S', long = "signer")]
    pub signer: Option<String>,
    /// Program source file to use as account logic (Go `-p/--program`).
    /// Mutually exclusive with `--logic-sig`.
    #[arg(short = 'p', long = "program")]
    pub program: Option<String>,
    /// LogicSig file (msgpack) to apply to the transaction (Go `-L/--logic-sig`).
    /// Mutually exclusive with `--program`.
    #[arg(short = 'L', long = "logic-sig")]
    pub logic_sig: Option<String>,
    /// Base64-encoded args to pass to the transaction logic (Go `--argb64`,
    /// repeatable / comma-separated).
    #[arg(long = "argb64", value_delimiter = ',')]
    pub argb64: Vec<String>,
    /// Consensus protocol version id string (Go `-P/--proto`). Accepted for
    /// flag parity. NOTE: unlike Go (which loads the consensus-param table to
    /// gate `LogicSigVersion`/`LogicSigMaxSize`), goal-rust does not load that
    /// table client-side, so this value is not used to lower the LogicSig
    /// version/size ceiling. The program is still checked against the Rust
    /// AVM's structural limits, and the node re-verifies on submit.
    #[arg(short = 'P', long = "proto")]
    pub proto: Option<String>,
    /// Wallet password (skip the prompt). goal-rust convention shared with the
    /// other clerk leaves.
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// `clerk tealsign` — sign data to be verified inside a TEAL program by the
/// `ed25519verify` opcode.
///
/// Mirrors Go's `tealsignCmd` (`cmd/goal/tealsign.go`). The signed payload is
/// domain-separated as `"ProgData" || program_hash || data`. The program hash
/// comes from either a LogicSig transaction (`--lsig-txn`) or a contract
/// address (`--contract-addr`); the data comes from one of `--data-file`,
/// `--data-b64`, `--data-b32`, or `--sign-txid`. The base64 signature is always
/// printed; with `--set-lsig-arg-idx`, it's also stored as a LogicSig arg in
/// the `--lsig-txn` file (rewritten in place).
#[derive(Args, Debug)]
pub struct TealsignArgs {
    /// algokey private-key (32-byte ed25519 seed) file to sign with
    /// (Go `--keyfile`).
    #[arg(long = "keyfile")]
    pub keyfile: Option<PathBuf>,
    /// Address of account to sign with (Go `--account`). Not yet supported
    /// (needs kmd logicsig-data signing), matching Go.
    #[arg(long = "account")]
    pub account: Option<String>,
    /// Transaction (with a LogicSig) to sign data for; supplies the program
    /// hash (Go `--lsig-txn`).
    #[arg(long = "lsig-txn")]
    pub lsig_txn: Option<PathBuf>,
    /// Contract address to sign data for; supplies the program hash directly.
    /// Not needed if `--lsig-txn` is provided (Go `--contract-addr`).
    #[arg(long = "contract-addr")]
    pub contract_addr: Option<String>,
    /// Use the txid of `--lsig-txn` as the data to sign (Go `--sign-txid`).
    #[arg(long = "sign-txid")]
    pub sign_txid: bool,
    /// Data file to sign (Go `--data-file`).
    #[arg(long = "data-file")]
    pub data_file: Option<PathBuf>,
    /// Base64 data to sign (Go `--data-b64`).
    #[arg(long = "data-b64")]
    pub data_b64: Option<String>,
    /// Base32 data to sign (Go `--data-b32`).
    #[arg(long = "data-b32")]
    pub data_b32: Option<String>,
    /// If `--lsig-txn` is also specified, set the LogicSig arg at this index to
    /// the raw signature bytes, rewriting the `--lsig-txn` file in place
    /// (Go `--set-lsig-arg-idx`; default `-1` = don't store).
    #[arg(long = "set-lsig-arg-idx", default_value_t = -1)]
    pub set_lsig_arg_idx: i64,
}

/// `wallet` is the group-level `-w` (Go's persistent clerk flag); leaves that
/// take a wallet thread it in here.
pub fn run(cmd: ClerkCmd, wallet: Option<String>) -> ExitCode {
    use crate::cli_state::{datadirs, kmddir};

    let leaf: &str = match cmd {
        ClerkCmd::Send(args) => {
            return crate::cmd::clerk::run_send(args, wallet, datadirs(), kmddir());
        }
        ClerkCmd::Inspect(args) => {
            return crate::cmd::clerk::run_inspect(args);
        }
        ClerkCmd::Split(args) => {
            return crate::cmd::clerk::run_split(args);
        }
        ClerkCmd::Group(args) => {
            return crate::cmd::clerk::run_group(args);
        }
        ClerkCmd::Rawsend(args) => {
            return crate::cmd::clerk::run_rawsend(args, datadirs());
        }
        ClerkCmd::Compile => "compile",
        ClerkCmd::Dryrun => "dryrun",
        ClerkCmd::DryrunRemote => "dryrun-remote",
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
        ClerkCmd::Sign(args) => {
            return crate::cmd::clerk::run_sign(args, wallet, datadirs(), kmddir());
        }
        ClerkCmd::Tealsign(args) => {
            return crate::cmd::clerk::run_tealsign(args);
        }
        ClerkCmd::Simulate => "simulate",
    };
    unimplemented("clerk", leaf)
}
