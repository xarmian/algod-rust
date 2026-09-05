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

//! `goal app` — port of `../go-algorand/cmd/goal/application.go` (+ `box.go`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
// `Call`/`Method`/the lifecycle leaves carry the full application-call flag
// surface; `Info`/`Read` are still unit variants pending a later slice (see
// issue #962's PR #1023 comment: `read`/`info` need byte-exact JSON parity
// work beyond what fits in this slice). See the `SendArgs` precedent in
// `groups::clerk` for why boxing isn't worth it here.
#[allow(clippy::large_enum_variant)]
pub enum AppCmd {
    /// Read application box data.
    Box {
        #[command(subcommand)]
        cmd: Option<BoxCmd>,
    },
    /// Call an application.
    Call(CallArgs),
    /// Clear out an application's state in your account.
    Clear(LifecycleArgs),
    /// Close out of an application.
    Closeout(LifecycleArgs),
    /// Create an application.
    Create(CreateArgs),
    /// Delete an application.
    Delete(LifecycleArgs),
    /// Look up current parameters for an application.
    Info,
    /// Invoke an ABI method.
    Method(MethodArgs),
    /// Opt in to an application.
    Optin(LifecycleArgs),
    /// Read local or global state for an application.
    Read,
    /// Update an application's programs.
    Update(UpdateArgs),
}

#[derive(Subcommand, Debug)]
pub enum BoxCmd {
    /// Retrieve information about an application box.
    Info(BoxInfoArgs),
    /// List all application boxes belonging to an application.
    List(BoxListArgs),
}

/// `app box info --app-id <id> -n/--name <encoding:value>`.
///
/// Mirrors Go's `appBoxInfoCmd` (`box.go:63-98`).
#[derive(Args, Debug)]
pub struct BoxInfoArgs {
    /// Application ID (Go's `appBoxCmd` persistent `--app-id`). Required.
    #[arg(long = "app-id")]
    pub app_id: u64,
    /// Application box name, `encoding:value` form (Go `-n/--name`).
    /// Required.
    #[arg(short = 'n', long = "name")]
    pub name: String,
}

/// `app box list --app-id <id> [-l <limit>] [-n <next>] [-p <prefix>] [-v] [-r <round>]`.
///
/// Mirrors Go's `appBoxListCmd` (`box.go:100-163`).
#[derive(Args, Debug)]
pub struct BoxListArgs {
    /// Application ID (Go's `appBoxCmd` persistent `--app-id`). Required.
    #[arg(long = "app-id")]
    pub app_id: u64,
    /// Maximum number of boxes per page (Go `-l/--limit`; default 1000,
    /// or 100 with `--values`, applied when unset/zero).
    #[arg(short = 'l', long = "limit", default_value_t = 0)]
    pub limit: u64,
    /// Pagination cursor from a previous response's `NextToken` (Go
    /// `-n/--next`).
    #[arg(short = 'n', long = "next")]
    pub next: Option<String>,
    /// Filter by box name prefix, `encoding:value` form (Go `-p/--prefix`).
    #[arg(short = 'p', long = "prefix")]
    pub prefix: Option<String>,
    /// Include box values in the output (Go `-v/--values`).
    #[arg(short = 'v', long = "values")]
    pub values: bool,
    /// Query boxes at a specific round; auto-pinned from the first page
    /// when unset (Go `-r/--round`).
    #[arg(short = 'r', long = "round", default_value_t = 0)]
    pub round: u64,
}

/// The resource-reference flag surface shared by every `app` leaf that can
/// submit an application-call transaction (Go's *persistent* flags on the
/// `app` command group, `application.go:116-126`).
///
/// `--app-arg` (`apps.AppCallBytes`-form `encoding:value` application
/// arguments) is intentionally on [`CallArgs`] only, not here: `goal app
/// method` rejects `--app-arg` in favor of `--arg` (`--arg and --app-arg are
/// mutually exclusive`, `application.go:1320-1322`).
#[derive(Args, Debug, Default)]
pub struct AppRefsArgs {
    /// Indexes of other apps whose global state is read in this transaction
    /// (Go `--foreign-app`, repeatable/comma-separated).
    #[arg(long = "foreign-app", value_delimiter = ',')]
    pub foreign_app: Vec<String>,
    /// Indexes of assets whose parameters are read in this transaction
    /// (Go `--foreign-asset`, repeatable/comma-separated).
    #[arg(long = "foreign-asset", value_delimiter = ',')]
    pub foreign_asset: Vec<String>,
    /// Accounts that may be accessed from application logic
    /// (Go `--app-account`, repeatable/comma-separated).
    #[arg(long = "app-account", value_delimiter = ',')]
    pub app_account: Vec<String>,
    /// A box that may be accessed by this transaction: `[<app-id>,]encoding:value`
    /// (Go `--box`, repeatable).
    #[arg(long = "box")]
    pub app_box: Vec<String>,
    /// A holding that may be accessed from application logic:
    /// `<asset-id>[+<address>]` (Go `--holding`, repeatable).
    #[arg(long = "holding")]
    pub holding: Vec<String>,
    /// A local state that may be accessed from application logic:
    /// `[<app-id>][+<address>]` (Go `--local`, repeatable).
    #[arg(long = "local")]
    pub local: Vec<String>,
    /// Number of empty references to add for additional I/O budget
    /// (Go `--empty-refs`).
    #[arg(long = "empty-refs", default_value_t = 0)]
    pub empty_refs: u64,
    /// Put references into the transaction's access list instead of the
    /// legacy foreign arrays (Go `--access`).
    #[arg(long = "access")]
    pub access: bool,
}

/// The transaction-header flag surface shared by every `app` leaf (fee /
/// validity / note / lease / rekey, output-file, wait behavior). Mirrors the
/// common flags `addTxnFlags` wires onto every `goal app` leaf plus the
/// `-o`/`-s`/`-N`/`-S` conventions already established by `clerk send`.
#[derive(Args, Debug, Default)]
pub struct AppTxnArgs {
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

/// The `--app-arg` flag shared by every `app` leaf that submits an
/// application-call transaction (Go's persistent `appCmd.PersistentFlags()
/// .StringArrayVar(&appArgs, "app-arg", ...)`, `application.go:118`).
/// [`CallArgs`] keeps its own copy of this field (predates this struct);
/// new leaves flatten this one instead of repeating the doc comment.
#[derive(Args, Debug, Default)]
pub struct AppArgArgs {
    /// Args to encode for the application call, `encoding:value` form (Go
    /// `--app-arg`, repeatable): `int:1234`, `b64:A==`, `str:hello`,
    /// `addr:XYZ...`, `b32:...`, or `abi:<type>:<json-value>`.
    #[arg(long = "app-arg")]
    pub app_arg: Vec<String>,
}

/// The approval/clear-state program flags shared by `app create`/`app
/// update` (Go's persistent `--approval-prog`/`--clear-prog`/
/// `--approval-prog-raw`/`--clear-prog-raw`, `application.go:128-132`).
#[derive(Args, Debug, Default)]
pub struct AppProgramArgs {
    /// (Uncompiled) TEAL assembly for the approval program (Go
    /// `--approval-prog`). Mutually exclusive with `--approval-prog-raw`;
    /// exactly one of the pair is required.
    #[arg(long = "approval-prog")]
    pub approval_prog: Option<PathBuf>,
    /// (Uncompiled) TEAL assembly for the clear-state program (Go
    /// `--clear-prog`). Mutually exclusive with `--clear-prog-raw`.
    #[arg(long = "clear-prog")]
    pub clear_prog: Option<PathBuf>,
    /// Compiled AVM bytecode for the approval program (Go
    /// `--approval-prog-raw`). Mutually exclusive with `--approval-prog`.
    #[arg(long = "approval-prog-raw")]
    pub approval_prog_raw: Option<PathBuf>,
    /// Compiled AVM bytecode for the clear-state program (Go
    /// `--clear-prog-raw`). Mutually exclusive with `--clear-prog`.
    #[arg(long = "clear-prog-raw")]
    pub clear_prog_raw: Option<PathBuf>,
}

/// `app optin`/`app closeout`/`app clear`/`app delete` -f <from> --app-id
/// <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `optInAppCmd`/`closeOutAppCmd`/`clearAppCmd`/`deleteAppCmd`
/// (`application.go:659-991`): all four share the exact same flag surface
/// (no programs, no schemas) and differ only in the numeric `OnCompletion`
/// they submit (`OptIn`=1, `CloseOut`=2, `ClearState`=3,
/// `DeleteApplication`=5) — see `crate::cmd::app::run_optin`/`run_closeout`/
/// `run_clear`/`run_delete`.
#[derive(Args, Debug)]
pub struct LifecycleArgs {
    /// Account to send the transaction from (Go `-f/--from`). Required.
    #[arg(short = 'f', long = "from")]
    pub from: String,
    /// Application ID (Go `--app-id`). Required.
    #[arg(long = "app-id")]
    pub app_id: u64,
    /// RejectVersion for the application transaction (Go `--reject-version`).
    #[arg(long = "reject-version", default_value_t = 0)]
    pub reject_version: u64,
    #[command(flatten)]
    pub app_args: AppArgArgs,
    #[command(flatten)]
    pub refs: AppRefsArgs,
    #[command(flatten)]
    pub txn: AppTxnArgs,
}

/// `app create --creator <addr> --approval-prog <f> --clear-prog <f>
/// [--on-completion oc] [schema flags] [--extra-pages n] [refs] [txn]`.
///
/// Mirrors Go's `createAppCmd` (`application.go:496-584`): build and submit
/// an `ApplicationCallTx` with `ApplicationID=0`, the given `OnCompletion`
/// (default `NoOp`; Go warns — doesn't reject — for `CloseOut`/`ClearState`),
/// the compiled approval/clear programs, and the global/local state schemas.
/// `--reject-version` is deliberately *not* exposed here: Go's
/// `MakeUnsignedAppCreateTx` never threads the persistent `--reject-version`
/// flag through to the built transaction (verified against
/// `libgoal/transactions.go:536-538`), so a value there would silently have
/// no effect.
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Account to create the application from (Go `--creator`). Required.
    #[arg(long = "creator")]
    pub creator: String,
    /// OnCompletion action for the application transaction (Go
    /// `--on-completion`).
    #[arg(long = "on-completion", default_value = "NoOp")]
    pub on_completion: String,
    /// Maximum global integer values (Go `--global-ints`).
    #[arg(long = "global-ints", default_value_t = 0)]
    pub global_ints: u64,
    /// Maximum global byte-slice values (Go `--global-byteslices`).
    #[arg(long = "global-byteslices", default_value_t = 0)]
    pub global_byteslices: u64,
    /// Maximum local integer values (Go `--local-ints`). Immutable.
    #[arg(long = "local-ints", default_value_t = 0)]
    pub local_ints: u64,
    /// Maximum local byte-slice values (Go `--local-byteslices`). Immutable.
    #[arg(long = "local-byteslices", default_value_t = 0)]
    pub local_byteslices: u64,
    /// Additional program pages (Go `--extra-pages`).
    #[arg(long = "extra-pages", default_value_t = 0)]
    pub extra_pages: u32,
    #[command(flatten)]
    pub programs: AppProgramArgs,
    #[command(flatten)]
    pub app_args: AppArgArgs,
    #[command(flatten)]
    pub refs: AppRefsArgs,
    #[command(flatten)]
    pub txn: AppTxnArgs,
}

/// `app update --app-id <id> -f <from> --approval-prog <f> --clear-prog <f>
/// [--global-ints n] [--global-byteslices n] [--extra-pages n] [refs] [txn]`.
///
/// Mirrors Go's `updateAppCmd` (`application.go:586-657`): submit an
/// `UpdateApplication` call replacing the approval/clear programs. Only the
/// *global* schema/extra-pages may grow on update (Go doesn't register
/// `--local-ints`/`--local-byteslices` on `updateAppCmd` at all — local
/// schema is immutable after creation).
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Application ID (Go `--app-id`). Required.
    #[arg(long = "app-id")]
    pub app_id: u64,
    /// Account to send the update transaction from (Go `-f/--from`).
    /// Required.
    #[arg(short = 'f', long = "from")]
    pub from: String,
    /// Maximum global integer values (Go `--global-ints`).
    #[arg(long = "global-ints", default_value_t = 0)]
    pub global_ints: u64,
    /// Maximum global byte-slice values (Go `--global-byteslices`).
    #[arg(long = "global-byteslices", default_value_t = 0)]
    pub global_byteslices: u64,
    /// Additional program pages (Go `--extra-pages`).
    #[arg(long = "extra-pages", default_value_t = 0)]
    pub extra_pages: u32,
    /// RejectVersion for the application transaction (Go `--reject-version`).
    #[arg(long = "reject-version", default_value_t = 0)]
    pub reject_version: u64,
    #[command(flatten)]
    pub programs: AppProgramArgs,
    #[command(flatten)]
    pub app_args: AppArgArgs,
    #[command(flatten)]
    pub refs: AppRefsArgs,
    #[command(flatten)]
    pub txn: AppTxnArgs,
}

/// `app call -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `callAppCmd` (`application.go:860-870` for the flag surface
/// and `MakeUnsignedAppNoOpTx` call): submit a **NoOp** application-call
/// transaction with raw (non-ABI) `apps.AppCallBytes`-form arguments. Unlike
/// `app method`, `app call` has no `--on-completion` flag at all — Go's
/// `callAppCmd` always builds a NoOp call; `optin`/`closeout`/`clear`/
/// `update`/`delete` are Go's separate leaves for the other `OnCompletion`
/// values (not yet implemented here — see the issue).
#[derive(Args, Debug)]
pub struct CallArgs {
    /// Account to call the app from (Go `-f/--from`). Required.
    #[arg(short = 'f', long = "from")]
    pub from: String,
    /// Application ID (Go `--app-id`). Required.
    #[arg(long = "app-id")]
    pub app_id: u64,
    /// Args to encode for the application call, `encoding:value` form (Go
    /// `--app-arg`, repeatable): `int:1234`, `b64:A==`, `str:hello`,
    /// `addr:XYZ...`, `b32:...`, or `abi:<type>:<json-value>`.
    #[arg(long = "app-arg")]
    pub app_arg: Vec<String>,
    /// RejectVersion for the application transaction (Go `--reject-version`).
    #[arg(long = "reject-version", default_value_t = 0)]
    pub reject_version: u64,
    #[command(flatten)]
    pub refs: AppRefsArgs,
    #[command(flatten)]
    pub txn: AppTxnArgs,
}

/// `app method -f <from> --app-id <id> --method <sig> [--arg ...]
/// [--on-completion oc] [--create [schema flags]] [refs] [txn]`.
///
/// Mirrors Go's `methodAppCmd` (`application.go:1310-1591`): compute the
/// ARC-4 method selector, ABI-encode `--arg` values per the method
/// signature's argument types (splitting out reference-type and
/// transaction-type arguments), resolve reference args into the
/// transaction's foreign-resource arrays, splice any transaction-type
/// arguments into the atomic group ahead of the app call, sign, submit, and
/// report the decoded return value the way Go's
/// `"method %s succeeded with output: %s"` does.
///
/// **goal-rust extension beyond Go's actual `v5.0.0-stable` flag surface:**
/// Go's `methodAppCmd` only accepts an inline `--method "name(t1,t2)ret"`
/// signature — it has no `--abi` flag (verified against the pinned
/// `cmd/goal/application.go`; no `abi`/`--abi` token appears anywhere in the
/// file). `algo-abi`'s `Contract`/`Interface` JSON parsing was built for
/// exactly this though (see its module docs, "for a future `--abi <file>`
/// flag"), so `goal-rust` adds `--abi <contract.json>` as a small, clearly
/// documented convenience: when given, `--method` is treated as a bare
/// method *name* looked up in the file instead of a full signature.
#[derive(Args, Debug)]
pub struct MethodArgs {
    /// Account to call the method from (Go `-f/--from`). Required.
    #[arg(short = 'f', long = "from")]
    pub from: String,
    /// Application ID (Go `--app-id`). Required unless `--create`.
    #[arg(long = "app-id")]
    pub app_id: Option<u64>,
    /// Method to call: an inline ARC-4 signature (`"add(uint64,uint64)uint64"`)
    /// or, with `--abi`, a bare method name to look up (Go `--method`).
    /// Required.
    #[arg(long = "method")]
    pub method: String,
    /// ARC-4 Contract/Interface JSON file to resolve a bare `--method` name
    /// against (goal-rust extension; see the struct docs).
    #[arg(long = "abi")]
    pub abi: Option<PathBuf>,
    /// Args to pass for calling the method, one per method argument, in
    /// order (Go `--arg`, repeatable). ABI-typed args are JSON values
    /// (`5`, `"hello"`, `["QQ==","asdf"]`, ...); `account`/`asset`/
    /// `application` reference args are a bare address/numeric ID;
    /// transaction-type args are a path to an unsigned (or Lsig-only)
    /// `SignedTxn` file.
    #[arg(long = "arg")]
    pub arg: Vec<String>,
    /// On-completion action for the application transaction (Go
    /// `--on-completion`).
    #[arg(long = "on-completion", default_value = "NoOp")]
    pub on_completion: String,
    /// RejectVersion for the application transaction (Go `--reject-version`).
    #[arg(long = "reject-version", default_value_t = 0)]
    pub reject_version: u64,
    /// Create an application in this method call (Go `--create`).
    #[arg(long = "create")]
    pub create: bool,
    /// Maximum global integer values (Go `--global-ints`; valid with
    /// `--create` or when updating).
    #[arg(long = "global-ints", default_value_t = 0)]
    pub global_ints: u64,
    /// Maximum global byte-slice values (Go `--global-byteslices`).
    #[arg(long = "global-byteslices", default_value_t = 0)]
    pub global_byteslices: u64,
    /// Maximum local integer values (Go `--local-ints`; only valid with
    /// `--create`).
    #[arg(long = "local-ints", default_value_t = 0)]
    pub local_ints: u64,
    /// Maximum local byte-slice values (Go `--local-byteslices`).
    #[arg(long = "local-byteslices", default_value_t = 0)]
    pub local_byteslices: u64,
    /// Additional program pages (Go `--extra-pages`; valid with `--create`
    /// or when updating).
    #[arg(long = "extra-pages", default_value_t = 0)]
    pub extra_pages: u32,
    /// (Uncompiled) TEAL assembly for the approval program (Go
    /// `--approval-prog`). Required with `--create` or
    /// `--on-completion UpdateApplication`, mutually exclusive with
    /// `--approval-prog-raw`.
    #[arg(long = "approval-prog")]
    pub approval_prog: Option<PathBuf>,
    /// (Uncompiled) TEAL assembly for the clear-state program (Go
    /// `--clear-prog`). Mutually exclusive with `--clear-prog-raw`.
    #[arg(long = "clear-prog")]
    pub clear_prog: Option<PathBuf>,
    /// Compiled AVM bytecode for the approval program (Go
    /// `--approval-prog-raw`). Mutually exclusive with `--approval-prog`.
    #[arg(long = "approval-prog-raw")]
    pub approval_prog_raw: Option<PathBuf>,
    /// Compiled AVM bytecode for the clear-state program (Go
    /// `--clear-prog-raw`). Mutually exclusive with `--clear-prog`.
    #[arg(long = "clear-prog-raw")]
    pub clear_prog_raw: Option<PathBuf>,
    #[command(flatten)]
    pub refs: AppRefsArgs,
    #[command(flatten)]
    pub txn: AppTxnArgs,
}

pub fn run(cmd: AppCmd, wallet: Option<String>) -> ExitCode {
    match cmd {
        AppCmd::Box { cmd } => {
            let Some(cmd) = cmd else {
                return crate::print_group_help(&["app", "box"]);
            };
            match cmd {
                BoxCmd::Info(args) => crate::cmd::app::run_box_info(args),
                BoxCmd::List(args) => crate::cmd::app::run_box_list(args),
            }
        }
        AppCmd::Call(args) => crate::cmd::app::run_call(args, wallet),
        AppCmd::Clear(args) => crate::cmd::app::run_clear(args, wallet),
        AppCmd::Closeout(args) => crate::cmd::app::run_closeout(args, wallet),
        AppCmd::Create(args) => crate::cmd::app::run_create(args, wallet),
        AppCmd::Delete(args) => crate::cmd::app::run_delete(args, wallet),
        AppCmd::Info => unimplemented("app", "info"),
        AppCmd::Method(args) => crate::cmd::app::run_method(args, wallet),
        AppCmd::Optin(args) => crate::cmd::app::run_optin(args, wallet),
        AppCmd::Read => unimplemented("app", "read"),
        AppCmd::Update(args) => crate::cmd::app::run_update(args, wallet),
    }
}
