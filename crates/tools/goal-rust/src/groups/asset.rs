// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `goal asset` — port of `../go-algorand/cmd/goal/asset.go` (issue #1466).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum AssetCmd {
    /// Configure an asset.
    Config(ConfigArgs),
    /// Create an asset.
    Create(CreateArgs),
    /// Destroy an asset.
    Destroy(DestroyArgs),
    /// Freeze assets.
    Freeze(FreezeArgs),
    /// Look up current parameters for an asset.
    Info(InfoArgs),
    /// Optin to assets.
    Optin(OptinArgs),
    /// Transfer assets.
    Send(SendArgs),
}

/// The common fee/validity/note/lease/rekey/output-file flag surface every
/// txn-generating `asset` leaf shares (Go's `addTxnFlags`, applied uniformly
/// to `createAssetCmd`/`destroyAssetCmd`/`configAssetCmd`/`sendAssetCmd`/
/// `freezeAssetCmd`/`optinAssetCmd` — `asset.go:109-114`). Field-for-field
/// identical to `groups::app::AppTxnArgs`; kept as its own type so this
/// module has no dependency on `groups::app`.
#[derive(Args, Debug, Default)]
pub struct AssetTxnArgs {
    /// Transaction fee in microAlgos (Go `--fee`; suggested when unset).
    #[arg(long = "fee")]
    pub fee: Option<u64>,
    /// First round at which the transaction is valid (Go `--firstvalid`).
    #[arg(long = "firstvalid")]
    pub first_valid: Option<u64>,
    /// Last round at which the transaction is valid (Go `--lastvalid`).
    #[arg(long = "lastvalid")]
    pub last_valid: Option<u64>,
    /// Number of rounds for which the transaction is valid
    /// (Go `--validrounds`; mutually exclusive with `--lastvalid`).
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
    /// Rekey the sender to this spending key/address (Go `--rekey-to`).
    #[arg(long = "rekey-to")]
    pub rekey_to: Option<String>,
    /// Write the transaction(s) to this file instead of broadcasting
    /// (Go `-o/--outfile`).
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,
    /// With `-o`, sign the written transaction(s) (Go `-s/--sign`).
    #[arg(short = 's', long = "sign")]
    pub sign: bool,
    /// Don't wait for the transaction to commit (Go `-N/--no-wait`).
    #[arg(short = 'N', long = "no-wait")]
    pub no_wait: bool,
    /// Address of the key to sign with, if different from the sender due to
    /// rekeying (Go `-S/--signer`).
    #[arg(short = 'S', long = "signer")]
    pub signer: Option<String>,
    /// Wallet password (skip the prompt). goal-rust convention shared with
    /// the other signing leaves.
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// The `[--assetid <id> | --unitname <name> --creator <addr>]` asset-lookup
/// flags shared by every non-`create` leaf (Go's `lookupAssetID`,
/// `asset.go:150-186`).
#[derive(Args, Debug, Default)]
pub struct AssetLookupArgs {
    /// Asset ID (Go `--assetid`). Mutually exclusive with `--unitname`.
    #[arg(long = "assetid", default_value_t = 0)]
    pub asset_id: u64,
    /// Unit name of the asset, resolved via `--creator`'s created-assets
    /// list (Go `--unitname`). Mutually exclusive with `--assetid`.
    #[arg(long = "unitname")]
    pub unit_name: Option<String>,
}

/// `asset create --creator <addr> --total <n> [--decimals n]
/// [--defaultfrozen] [--unitname s] [--name s] [--asseturl s]
/// [--assetmetadatab64 s] [--manager addr] [--reserve addr] [--freezer addr]
/// [--clawback addr] [--no-manager] [--no-reserve] [--no-freezer]
/// [--no-clawback] [txn]`.
///
/// Mirrors Go's `createAssetCmd` (`asset.go:189-291`).
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Account address for creating an asset (Go `--creator`). Required.
    #[arg(long = "creator")]
    pub creator: String,
    /// Total amount of tokens for the created asset (Go `--total`). Required.
    #[arg(long = "total")]
    pub total: u64,
    /// Number of digits to use after the decimal point (Go `--decimals`).
    #[arg(long = "decimals", default_value_t = 0)]
    pub decimals: u32,
    /// Freeze holdings by default (Go `--defaultfrozen`).
    #[arg(long = "defaultfrozen")]
    pub default_frozen: bool,
    /// Name for the unit of asset (Go `--unitname`).
    #[arg(long = "unitname", default_value = "")]
    pub unit_name: String,
    /// Name for the entire asset (Go `--name`).
    #[arg(long = "name", default_value = "")]
    pub name: String,
    /// URL where more information about the asset can be found (Go
    /// `--asseturl`).
    #[arg(long = "asseturl", default_value = "")]
    pub asset_url: String,
    /// Base-64 encoded 32-byte commitment to asset metadata (Go
    /// `--assetmetadatab64`).
    #[arg(long = "assetmetadatab64", default_value = "")]
    pub asset_metadata_b64: String,
    /// Manager account that can reconfigure/destroy the asset (Go
    /// `--manager`).
    #[arg(long = "manager", default_value = "")]
    pub manager: String,
    /// Reserve account that non-minted assets reside in (Go `--reserve`).
    #[arg(long = "reserve", default_value = "")]
    pub reserve: String,
    /// Freezer account that can freeze/unfreeze holdings (Go `--freezer`).
    #[arg(long = "freezer", default_value = "")]
    pub freezer: String,
    /// Clawback account allowed to transfer assets between any holders (Go
    /// `--clawback`).
    #[arg(long = "clawback", default_value = "")]
    pub clawback: String,
    /// Explicitly declare the lack of a manager (Go `--no-manager`).
    #[arg(long = "no-manager")]
    pub no_manager: bool,
    /// Explicitly declare the lack of a reserve (Go `--no-reserve`).
    #[arg(long = "no-reserve")]
    pub no_reserve: bool,
    /// Explicitly declare the lack of a freezer (Go `--no-freezer`).
    #[arg(long = "no-freezer")]
    pub no_freezer: bool,
    /// Explicitly declare the lack of a clawback (Go `--no-clawback`).
    #[arg(long = "no-clawback")]
    pub no_clawback: bool,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset destroy [--manager addr] [--creator addr] [--assetid id |
/// --unitname s] [txn]`.
///
/// Mirrors Go's `destroyAssetCmd` (`asset.go:294-361`).
#[derive(Args, Debug)]
pub struct DestroyArgs {
    /// Manager account to issue the destroy transaction (Go `--manager`;
    /// defaults to `--creator`).
    #[arg(long = "manager", default_value = "")]
    pub manager: String,
    /// Creator account address for the asset to destroy (Go `--creator`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset config --manager <addr> [--creator addr] [--assetid id |
/// --unitname s] [--new-manager addr] [--new-reserve addr]
/// [--new-freezer addr] [--new-clawback addr] [txn]`.
///
/// Mirrors Go's `configAssetCmd` (`asset.go:412-467`).
#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Manager account to issue the config transaction (Go `--manager`).
    /// Required.
    #[arg(long = "manager")]
    pub manager: String,
    /// Account address for the asset to configure (Go `--creator`; defaults
    /// to `--manager`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    /// New manager address (Go `--new-manager`).
    #[arg(long = "new-manager")]
    pub new_manager: Option<String>,
    /// New reserve address (Go `--new-reserve`).
    #[arg(long = "new-reserve")]
    pub new_reserve: Option<String>,
    /// New freeze address (Go `--new-freezer`).
    #[arg(long = "new-freezer")]
    pub new_freezer: Option<String>,
    /// New clawback address (Go `--new-clawback`).
    #[arg(long = "new-clawback")]
    pub new_clawback: Option<String>,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset send [--clawback addr] [--creator addr] [--assetid id |
/// --unitname s] -f <from> -t <to> -a <amount> [-c <close-to>] [txn]`.
///
/// Mirrors Go's `sendAssetCmd` (`asset.go:503-576`).
#[derive(Args, Debug)]
pub struct SendArgs {
    /// Address to issue a clawback transaction from (Go `--clawback`;
    /// defaults to no clawback).
    #[arg(long = "clawback", default_value = "")]
    pub clawback: String,
    /// Account address for asset creator (Go `--creator`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    /// Account address to send from (Go `-f/--from`; defaults to the
    /// default account).
    #[arg(short = 'f', long = "from", default_value = "")]
    pub from: String,
    /// Address to send to (Go `-t/--to`). Required.
    #[arg(short = 't', long = "to")]
    pub to: String,
    /// Amount to transfer, in base units of the asset (Go `-a/--amount`).
    /// Required.
    #[arg(short = 'a', long = "amount")]
    pub amount: u64,
    /// Close asset account and send remainder to this address (Go
    /// `-c/--close-to`).
    #[arg(short = 'c', long = "close-to", default_value = "")]
    pub close_to: String,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset freeze --freezer <addr> [--creator addr] [--assetid id |
/// --unitname s] --account <addr> --freeze <bool> [txn]`.
///
/// Mirrors Go's `freezeAssetCmd` (`asset.go:594-655`).
#[derive(Args, Debug)]
pub struct FreezeArgs {
    /// Address to issue a freeze transaction from (Go `--freezer`).
    /// Required.
    #[arg(long = "freezer")]
    pub freezer: String,
    /// Account address for asset creator (Go `--creator`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    /// Account address to freeze/unfreeze (Go `--account`). Required.
    #[arg(long = "account")]
    pub account: String,
    /// Freeze or unfreeze (Go `--freeze`). Required.
    #[arg(long = "freeze")]
    pub freeze: bool,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset optin [--unitname s] [--assetid id] [-a <account>]
/// [--creator addr] [txn]`.
///
/// Mirrors Go's `optinAssetCmd` (`asset.go:679-742`).
#[derive(Args, Debug)]
pub struct OptinArgs {
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    /// Account address to opt in (Go `-a/--account`; defaults to the
    /// default account).
    #[arg(short = 'a', long = "account", default_value = "")]
    pub account: String,
    /// Account address for asset creator (Go `--creator`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
    #[command(flatten)]
    pub txn: AssetTxnArgs,
}

/// `asset info [--assetid id | --unitname s] [--creator addr]`.
///
/// Mirrors Go's `infoAssetCmd` (`asset.go:748-827`).
#[derive(Args, Debug)]
pub struct InfoArgs {
    #[command(flatten)]
    pub lookup: AssetLookupArgs,
    /// Account address of the asset creator (Go `--creator`).
    #[arg(long = "creator", default_value = "")]
    pub creator: String,
}

pub fn run(cmd: AssetCmd, wallet: Option<String>) -> ExitCode {
    match cmd {
        AssetCmd::Config(args) => crate::cmd::asset::run_config(args, wallet),
        AssetCmd::Create(args) => crate::cmd::asset::run_create(args, wallet),
        AssetCmd::Destroy(args) => crate::cmd::asset::run_destroy(args, wallet),
        AssetCmd::Freeze(args) => crate::cmd::asset::run_freeze(args, wallet),
        AssetCmd::Info(args) => crate::cmd::asset::run_info(args),
        AssetCmd::Optin(args) => crate::cmd::asset::run_optin(args, wallet),
        AssetCmd::Send(args) => crate::cmd::asset::run_send(args, wallet),
    }
}
