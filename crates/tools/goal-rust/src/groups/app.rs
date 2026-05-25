//! `goal app` — port of `../go-algorand/cmd/goal/application.go` (+ `box.go`).

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum AppCmd {
    /// Read application box data.
    Box {
        #[command(subcommand)]
        cmd: BoxCmd,
    },
    /// Call an application.
    Call,
    /// Clear out an application's state in your account.
    Clear,
    /// Close out of an application.
    Closeout,
    /// Create an application.
    Create,
    /// Delete an application.
    Delete,
    /// Look up current parameters for an application.
    Info,
    /// Invoke an ABI method.
    Method,
    /// Opt in to an application.
    Optin,
    /// Read local or global state for an application.
    Read,
    /// Update an application's programs.
    Update,
}

#[derive(Subcommand, Debug)]
pub enum BoxCmd {
    /// Retrieve information about an application box.
    Info,
    /// List all application boxes belonging to an application.
    List,
}

pub fn run(cmd: AppCmd) -> ExitCode {
    let leaf: &str = match &cmd {
        AppCmd::Box { cmd } => {
            let leaf = match cmd {
                BoxCmd::Info => "info",
                BoxCmd::List => "list",
            };
            return unimplemented("app box", leaf);
        }
        AppCmd::Call => "call",
        AppCmd::Clear => "clear",
        AppCmd::Closeout => "closeout",
        AppCmd::Create => "create",
        AppCmd::Delete => "delete",
        AppCmd::Info => "info",
        AppCmd::Method => "method",
        AppCmd::Optin => "optin",
        AppCmd::Read => "read",
        AppCmd::Update => "update",
    };
    unimplemented("app", leaf)
}
