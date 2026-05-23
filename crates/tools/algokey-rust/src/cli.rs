//! CLI surface for algokey-rust.
//!
//! Mirrors the cobra command tree from `../go-algorand/cmd/algokey/main.go`
//! (subcommand order: generate, import, export, sign, multisig, part). The
//! `keyreg` subcommand is exposed as a top-level command for now; Go places
//! it under `part`, but Phase A only needs the names listed in --help.
//! TASK-155 will fill in flags and required-flag rules.
//!
//! Reference: `../go-algorand/cmd/algokey/main.go:31-71`.

use clap::{Parser, Subcommand};

/// Top-level CLI definition.
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

/// Phase A subcommand surface. Flags are stubbed in TASK-155; bodies are
/// stubbed in TASK-157/158/159 (`generate`, `import`, `export`) and later
/// phases (`sign`, `multisig`, `part`, `keyreg`).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a new key pair and mnemonic.
    Generate,
    /// Import a key from a 25-word mnemonic.
    Import,
    /// Export a key file to a 25-word mnemonic.
    Export,
    /// Sign a transaction file with a key.
    Sign,
    /// Multisig helpers (partial sigs, append-auth-addr).
    Multisig,
    /// Participation key generation and inspection.
    Part,
    /// Build a key-registration transaction.
    Keyreg,
}
