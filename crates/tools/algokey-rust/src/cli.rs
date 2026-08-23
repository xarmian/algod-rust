//! CLI surface for `algokey-rust`.
//!
//! Mirrors the cobra command tree from `../go-algorand/cmd/algokey/`
//! (v4.6.0-stable). Top-level subcommands match Go's registration order
//! (`generate`, `import`, `export`, `sign`, `multisig`, `part`). `keyreg`
//! lives under `part` exactly like Go (`part.go:185`); `append-auth-addr`
//! lives under `multisig` (`multisig.go:43`).
//!
//! Phase A (TASK-155) only wires the flag tree — every leaf returns
//! "not implemented" from `main.rs`. TASK-157/158/159 fill `generate`,
//! `import`, and `export`; later phases fill the rest.
//!
//! Short flags and required-flag rules track Go exactly:
//! - `-f` keyfile, `-p` pubkeyfile (`generate`, `export`)
//! - `-m` mnemonic, `-f` keyfile (`import`)
//! - `-k` keyfile, `-m` mnemonic, `-t` txfile, `-o` outfile (`sign`,
//!   `multisig`)
//! - `-p` params, `-t` txfile, `-o` outfile (`multisig append-auth-addr`)

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Top-level CLI entry point.
#[derive(Debug, Parser)]
#[command(
    name = "algokey-rust",
    about = "CLI for managing Algorand keys",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands — order matches `main.go:45-51`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate key.
    Generate(GenerateArgs),
    /// Import key file from mnemonic.
    Import(ImportArgs),
    /// Export key file to mnemonic and public key.
    Export(ExportArgs),
    /// Sign transactions from a file using a private key.
    Sign(SignArgs),
    /// Multisig helpers — add a signature, or rewrite auth-addr.
    Multisig(MultisigCli),
    /// Manage participation keys.
    Part(PartCli),
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

/// Flags for `algokey generate` — matches `generate.go:31-34`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Private key filename.
    #[arg(short = 'f', long = "keyfile")]
    pub keyfile: Option<PathBuf>,
    /// Public key filename.
    #[arg(short = 'p', long = "pubkeyfile")]
    pub pubkeyfile: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

/// Flags for `algokey import` — matches `import.go:31-35`.
///
/// `--mnemonic` is marked required (matches `MarkFlagRequired("mnemonic")`).
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Private key mnemonic.
    #[arg(short = 'm', long = "mnemonic")]
    pub mnemonic: String,
    /// Private key filename.
    #[arg(short = 'f', long = "keyfile")]
    pub keyfile: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

/// Flags for `algokey export` — matches `export.go:31-35`.
///
/// `--keyfile` is marked required (matches `MarkFlagRequired("keyfile")`).
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Private key filename.
    #[arg(short = 'f', long = "keyfile")]
    pub keyfile: PathBuf,
    /// Public key filename.
    #[arg(short = 'p', long = "pubkeyfile")]
    pub pubkeyfile: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

/// Flags for `algokey sign` — matches `sign.go:37-44`.
///
/// `--txfile` and `--outfile` are both required.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// Private key filename.
    #[arg(short = 'k', long = "keyfile")]
    pub keyfile: Option<PathBuf>,
    /// Private key mnemonic.
    #[arg(short = 'm', long = "mnemonic")]
    pub mnemonic: Option<String>,
    /// Transaction input filename.
    #[arg(short = 't', long = "txfile")]
    pub txfile: PathBuf,
    /// Transaction output filename.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: PathBuf,
}

// ---------------------------------------------------------------------------
// multisig + append-auth-addr
// ---------------------------------------------------------------------------

/// `multisig` command — owns flags for the default sign-multisig action
/// (matches `multisig.go:45-50`) and dispatches to a subcommand (currently
/// only `append-auth-addr`).
#[derive(Debug, Args)]
#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
pub struct MultisigCli {
    /// Private key filename.
    #[arg(short = 'k', long = "keyfile")]
    pub keyfile: Option<PathBuf>,
    /// Private key mnemonic.
    #[arg(short = 'm', long = "mnemonic")]
    pub mnemonic: Option<String>,
    /// Transaction input filename.
    #[arg(short = 't', long = "txfile", required = true)]
    pub txfile: Option<PathBuf>,
    /// Transaction output filename.
    #[arg(short = 'o', long = "outfile", required = true)]
    pub outfile: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<MultisigSub>,
}

#[derive(Debug, Subcommand)]
pub enum MultisigSub {
    /// Adds the necessary fields to a transaction that is sent from an
    /// account that was rekeyed to a multisig account.
    AppendAuthAddr(AppendAuthAddrArgs),
}

/// Flags for `algokey multisig append-auth-addr` — matches
/// `multisig.go:52-57`. `params` and `txfile` are required; `outfile` is
/// optional (defaults to overwriting `txfile`).
#[derive(Debug, Args)]
pub struct AppendAuthAddrArgs {
    /// Multisig pre-image parameters - "[threshold] [Address 1] [Address 2] ...".
    #[arg(short = 'p', long = "params")]
    pub params: String,
    /// Transaction input filename.
    #[arg(short = 't', long = "txfile")]
    pub txfile: PathBuf,
    /// Transaction output filename. If not specified, the original file
    /// will be modified.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// part + keyreg
// ---------------------------------------------------------------------------

/// `part` command tree (`part.go:181-202`). Go places `keyreg` under
/// `part` (`part.go:185`); we mirror that exactly.
///
/// Go's `partCmd.Run` (`part.go:43-46`) falls back to printing help when
/// invoked with no subcommand. We mirror that by making the subcommand
/// optional and dispatching to clap's help printer in `main.rs`.
#[derive(Debug, Args)]
pub struct PartCli {
    #[command(subcommand)]
    pub command: Option<PartSub>,
}

#[derive(Debug, Subcommand)]
pub enum PartSub {
    /// Generate participation key.
    Generate(PartGenerateArgs),
    /// Print participation key information.
    Info(PartInfoArgs),
    /// Change parent address of participation key.
    Reparent(PartReparentArgs),
    /// Make key registration transaction.
    Keyreg(KeyregArgs),
}

/// Flags for `algokey part generate` — matches `part.go:187-194`.
///
/// `--first`, `--last`, and `--keyfile` are required.
#[derive(Debug, Args)]
pub struct PartGenerateArgs {
    /// Participation key filename.
    #[arg(long = "keyfile")]
    pub keyfile: PathBuf,
    /// First round for participation key.
    #[arg(long = "first")]
    pub first: u64,
    /// Last round for participation key.
    #[arg(long = "last")]
    pub last: u64,
    /// Key dilution for two-level participation keys (defaults to sqrt of
    /// validity window).
    #[arg(long = "dilution", default_value_t = 0)]
    pub dilution: u64,
    /// Address of parent account.
    #[arg(long = "parent")]
    pub parent: Option<String>,
}

/// Flags for `algokey part info` — matches `part.go:196-197`.
#[derive(Debug, Args)]
pub struct PartInfoArgs {
    /// Participation key filename.
    #[arg(long = "keyfile")]
    pub keyfile: PathBuf,
}

/// Flags for `algokey part reparent` — matches `part.go:199-202`. Both
/// `--keyfile` and `--parent` are required.
#[derive(Debug, Args)]
pub struct PartReparentArgs {
    /// Participation key filename.
    #[arg(long = "keyfile")]
    pub keyfile: PathBuf,
    /// Address of parent account.
    #[arg(long = "parent")]
    pub parent: String,
}

/// Flags for `algokey part keyreg` — matches `keyreg.go:77-90`.
///
/// `--firstvalid` and `--network` are required. `--outputFile` accepts
/// `-` for stdout (matches Go's `stdoutFilenameValue`); semantics are
/// enforced by the implementation, not clap.
#[derive(Debug, Args)]
pub struct KeyregArgs {
    /// Transaction fee.
    #[arg(long = "fee", default_value_t = 1000)]
    pub fee: u64,
    /// First round where the transaction may be committed to the ledger.
    #[arg(long = "firstvalid")]
    pub firstvalid: u64,
    /// Last round where the generated transaction may be committed to the
    /// ledger (defaults to firstvalid + 1000).
    #[arg(long = "lastvalid", default_value_t = 0)]
    pub lastvalid: u64,
    /// Network where the provided keys will be registered, one of
    /// mainnet/testnet/betanet. Required (mirrors Go's
    /// `MarkFlagRequired("network")` at keyreg.go:84). Go documents a
    /// default of "mainnet" in help text, but the required-flag rule means
    /// the user must always pass `--network` explicitly.
    #[arg(long = "network", required = true)]
    pub network: String,
    /// Set to bring an account offline.
    #[arg(long = "offline", default_value_t = false)]
    pub offline: bool,
    /// Write signed transaction to this file, or '-' to write to stdout.
    #[arg(short = 'o', long = "outputFile")]
    pub output_file: Option<String>,
    /// Participation keys to register; only specify when bringing an
    /// account online.
    #[arg(long = "keyfile")]
    pub keyfile: Option<PathBuf>,
    /// Account address to bring offline; only specify when taking an
    /// account offline.
    #[arg(long = "account")]
    pub account: Option<String>,
}
