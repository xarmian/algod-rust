//! `goal asset` — port of `../go-algorand/cmd/goal/asset.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum AssetCmd {
    /// Configure an asset.
    Config,
    /// Create an asset.
    Create,
    /// Destroy an asset.
    Destroy,
    /// Freeze assets.
    Freeze,
    /// Look up current parameters for an asset.
    Info,
    /// Optin to assets.
    Optin,
    /// Transfer assets.
    Send,
}

pub fn run(cmd: AssetCmd) -> ExitCode {
    let leaf = match cmd {
        AssetCmd::Config => "config",
        AssetCmd::Create => "create",
        AssetCmd::Destroy => "destroy",
        AssetCmd::Freeze => "freeze",
        AssetCmd::Info => "info",
        AssetCmd::Optin => "optin",
        AssetCmd::Send => "send",
    };
    unimplemented("asset", leaf)
}
