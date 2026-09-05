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

//! `goal-rust app call` / `goal-rust app method` / `goal-rust app box info`
//! / `goal-rust app box list` — port of
//! `../go-algorand/cmd/goal/application.go`'s `callAppCmd`/`methodAppCmd`
//! (plus the shared `getAppInputs`/`parseAppInputs`/`populateMethodCall*`
//! helpers) and `../go-algorand/cmd/goal/box.go`'s `appBoxInfoCmd`/
//! `appBoxListCmd` (issue #962).
//!
//! ABI type/method encoding is delegated to `algo_abi` (issue #888 slice 1,
//! PR #896); the foreign-resource/access-list lowering is delegated to
//! [`crate::resource_resolution`] (issue #820 item 3, PR #887). This module
//! is the CLI-value-parsing and transaction-assembly glue between the two,
//! plus the `apps.AppCallBytes`-form (`encoding:value`) argument parsing
//! `goal app call`/the resource-ref flags use (`github.com/algorand/avm-abi/apps`,
//! not vendored at the `../go-algorand` pin — read from the Go module cache,
//! `apps/parsing.go`).

use std::path::Path;
use std::process::ExitCode;

use algo_abi::{
    encode_method_args, method_selector, parse_method_signature, AbiType, Contract, Interface,
    Method, MethodArgType, ReferenceType, TransactionType,
};
use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, compute_group_id,
    compute_txn_id, decode_signed_txn_stream,
};
use algo_error::AlgoError;
use algo_kmd_client::KmdClient;
use algo_rest_client::AlgodClient;
use algo_types::{Address, SignedTransaction, StateSchema, Transaction};
use base64::Engine;

use crate::accounts_list::AccountsList;
use crate::cmd::clerk::{
    build_algod_client_for_dir, build_kmd_client, compute_validity, kmd_msg, parse_lease,
    parse_note, resolve_wallet_and_init, write_file_0600,
};
use crate::cmd::clerk_sign::hash_program;
use crate::data_dir;
use crate::formatting::encode_bytes_as_app_call_bytes;
use crate::groups::app::{
    AppRefsArgs, AppTxnArgs, BoxInfoArgs, BoxListArgs, CallArgs, CreateArgs, LifecycleArgs,
    MethodArgs, UpdateArgs,
};
use crate::resource_resolution::{
    app_address, attach_references, BoxHint, HoldingHint, LocalHint, RefBundle,
};

/// The numeric `OnCompletion` values (matches [`parse_on_completion`]'s
/// mapping and Go's `transactions.OnCompletion` enum).
const ON_COMPLETION_NOOP: u64 = 0;
const ON_COMPLETION_OPTIN: u64 = 1;
const ON_COMPLETION_CLOSE_OUT: u64 = 2;
const ON_COMPLETION_CLEAR_STATE: u64 = 3;
const ON_COMPLETION_DELETE_APPLICATION: u64 = 5;

/// The 4-byte prefix ARC-4 (`https://arc.algorand.foundation/ARCs/arc-0004`)
/// specifies for a logged return value, matching Go's `abiReturnHash`
/// (`application.go:1566`, itself `abi.ReturnLogPrefix`).
const ABI_RETURN_HASH: [u8; 4] = [0x15, 0x1f, 0x7c, 0x75];

// ---------------------------------------------------------------------------
// apps.AppCallBytes-form (`encoding:value`) argument parsing
// ---------------------------------------------------------------------------

/// Parse a command-line `--app-arg`/box-name value of the form
/// `encoding:value` into raw bytes. Mirrors
/// `github.com/algorand/avm-abi/apps.AppCallBytes.Raw` (`apps/parsing.go`,
/// v0.2.0 — the module `cmd/goal/application.go` depends on for `--app-arg`;
/// not vendored into the `../go-algorand` checkout, read from the Go module
/// cache): `str`/`string`, `int`/`integer` (big-endian uint64), `addr`/
/// `address`, `b32`/`base32`/`"byte base32"`, `b64`/`base64`/
/// `"byte base64"`, and `abi:<type>:<json-value>` (ABI-encoded).
pub(crate) fn parse_app_call_bytes(arg: &str) -> Result<Vec<u8>, String> {
    let (encoding, value) = arg.split_once(':').ok_or_else(|| {
        "all arguments and box names should be of the form 'encoding:value'".to_string()
    })?;
    match encoding {
        "str" | "string" => Ok(value.as_bytes().to_vec()),
        "int" | "integer" => {
            let num: u64 = value
                .parse()
                .map_err(|e| format!("Could not parse uint64 from string ({value}): {e}"))?;
            Ok(num.to_be_bytes().to_vec())
        }
        "addr" | "address" => {
            let addr = Address::from_algorand_string(value).map_err(|e| {
                format!("Could not unmarshal checksummed address from string ({value}): {e}")
            })?;
            Ok(addr.0.to_vec())
        }
        "b32" | "base32" | "byte base32" => data_encoding::BASE32
            .decode(value.as_bytes())
            .map_err(|e| format!("Could not decode base32-encoded string ({value}): {e}")),
        "b64" | "base64" | "byte base64" => base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|e| format!("Could not decode base64-encoded string ({value}): {e}")),
        "abi" => {
            let (type_str, json_val) = value.split_once(':').ok_or_else(|| {
                format!("Could not decode abi string ({value}): should split abi-type and abi-value with colon")
            })?;
            let abi_type = algo_abi::type_of(type_str)
                .map_err(|e| format!("Could not decode abi type string ({type_str}): {e}"))?;
            let abi_value = algo_abi::unmarshal_from_json(&abi_type, json_val)
                .map_err(|e| format!("Could not decode abi value string ({json_val}): {e}"))?;
            algo_abi::encode(&abi_value)
        }
        other => Err(format!("Unknown encoding: {other}")),
    }
}

/// Resolve a CLI account/address value the way go's `cliAddress` does
/// (`application.go:387-401`): empty string means "the Sender" (zero
/// address), `"app(<id>)"` resolves to that app's account address, otherwise
/// it's parsed as a checksummed Algorand address.
pub(crate) fn cli_address(acct: &str) -> Result<Address, String> {
    if acct.is_empty() {
        return Ok(Address::ZERO);
    }
    if let Some(inner) = acct.strip_prefix("app(").and_then(|s| s.strip_suffix(')')) {
        let app_id: u64 = inner
            .parse()
            .map_err(|_| format!("Could not parse '{inner}' as app id"))?;
        return Ok(app_address(app_id));
    }
    Address::from_algorand_string(acct).map_err(|e| e.to_string())
}

/// Parse a `--box` value: `[<app-id>,]encoding:value` (Go's `parseBoxRef`,
/// `application.go:280-298`).
fn parse_box_ref(arg: &str) -> Result<(u64, Vec<u8>), String> {
    let (encoding, value) = arg
        .split_once(':')
        .ok_or_else(|| "box refs should be of the form '[<app>,]encoding:value'".to_string())?;
    let (app_id, encoding) = match encoding.split_once(',') {
        Some((app_str, enc)) => {
            let app_id: u64 = app_str
                .parse()
                .map_err(|_| format!("Could not parse '{app_str}' as app id in box ref"))?;
            (app_id, enc)
        }
        None => (0u64, encoding),
    };
    let name = parse_app_call_bytes(&format!("{encoding}:{value}"))?;
    Ok((app_id, name))
}

/// Parse a `--holding` value: `<asset-id>[+<address>]` (Go's
/// `parseHoldingRef`, `application.go:300-310`). An empty address means the
/// Sender.
fn parse_holding_ref(arg: &str) -> Result<(u64, String), String> {
    let (asset_str, address) = arg.split_once('+').unwrap_or((arg, ""));
    let asset_id: u64 = asset_str
        .parse()
        .map_err(|_| format!("Could not parse '{asset_str}' as asset id in holding ref"))?;
    Ok((asset_id, address.to_string()))
}

/// Parse a `--local` value: `[<app-id>][+<address>]` (Go's `parseLocalRef`,
/// `application.go:312-342`). No app-id means the app being called; no
/// address means the Sender; both may not be omitted simultaneously —
/// mirrors Go by leaving that check to the caller (Go doesn't reject it
/// either; it becomes a no-op reference).
fn parse_local_ref(arg: &str) -> Result<(u64, String), String> {
    if let Some((one, two)) = arg.split_once('+') {
        let app_id: u64 = one
            .parse()
            .map_err(|_| format!("Could not parse '{one}' as app id in local ref"))?;
        return Ok((app_id, two.to_string()));
    }
    // No '+': try as a bare app id number; otherwise treat as a bare address
    // (Go tries `strconv.ParseUint` first and falls back to an address).
    if let Ok(app_id) = arg.parse::<u64>() {
        Ok((app_id, String::new()))
    } else {
        Ok((0, arg.to_string()))
    }
}

/// Build a [`RefBundle`] from the shared `--foreign-app`/`--foreign-asset`/
/// `--app-account`/`--box`/`--holding`/`--local`/`--empty-refs`/`--access`
/// flags. Mirrors Go's `parseAppInputs` (`application.go:344-385`), minus the
/// `--app-arg` piece (handled separately per leaf: [`CallArgs::app_arg`] /
/// method-arg reference resolution).
fn build_ref_bundle_from_flags(refs: &AppRefsArgs) -> Result<RefBundle, String> {
    let mut accounts = Vec::with_capacity(refs.app_account.len());
    for a in &refs.app_account {
        accounts.push(cli_address(a)?);
    }
    let mut apps = Vec::with_capacity(refs.foreign_app.len());
    for a in &refs.foreign_app {
        apps.push(
            a.parse::<u64>()
                .map_err(|_| format!("Could not parse '{a}' as app id in foreign-app"))?,
        );
    }
    let mut assets = Vec::with_capacity(refs.foreign_asset.len());
    for a in &refs.foreign_asset {
        assets.push(
            a.parse::<u64>()
                .map_err(|_| format!("Could not parse '{a}' as asset id in foreign-asset"))?,
        );
    }
    let mut boxes = Vec::with_capacity(refs.app_box.len());
    for b in &refs.app_box {
        let (app, name) = parse_box_ref(b)?;
        boxes.push(BoxHint { app, name });
    }
    let mut holdings = Vec::with_capacity(refs.holding.len());
    for h in &refs.holding {
        let (asset, addr) = parse_holding_ref(h)?;
        holdings.push(HoldingHint {
            asset,
            address: cli_address(&addr)?,
        });
    }
    let mut locals = Vec::with_capacity(refs.local.len());
    for l in &refs.local {
        let (app, addr) = parse_local_ref(l)?;
        locals.push(LocalHint {
            app,
            address: cli_address(&addr)?,
        });
    }
    Ok(RefBundle {
        use_access: refs.access,
        accounts,
        assets,
        apps,
        holdings,
        locals,
        boxes,
        empty_refs: refs.empty_refs,
    })
}

/// Parse `--on-completion` (case-insensitive), mirroring Go's
/// `mustParseOnCompletion` (`application.go:446-464`). Returns the numeric
/// `OnCompletion` value the wire format uses.
pub(crate) fn parse_on_completion(s: &str) -> Result<u64, String> {
    match s.to_lowercase().as_str() {
        "noop" => Ok(0),
        "optin" => Ok(1),
        "closeout" => Ok(2),
        "clearstate" => Ok(3),
        "updateapplication" => Ok(4),
        "deleteapplication" => Ok(5),
        other => Err(format!(
            "unknown value for --on-completion: {other} (possible values: {{NoOp, OptIn, \
             CloseOut, ClearState, UpdateApplication, DeleteApplication}})"
        )),
    }
}

const ON_COMPLETION_UPDATE_APPLICATION: u64 = 4;

// ---------------------------------------------------------------------------
// Shared txn-header helpers
// ---------------------------------------------------------------------------

/// Resolve `--approval-prog`/`--approval-prog-raw` and
/// `--clear-prog`/`--clear-prog-raw` into compiled program bytes. Mirrors
/// Go's `mustParseProgArgs` (`application.go:472-494`): exactly one of the
/// (uncompiled TEAL) / (compiled bytecode) pair is required for each
/// program; the uncompiled source is compiled via the node's
/// `POST /v2/teal/compile` (see `crate::cmd::clerk::run_compile` for the
/// same pattern; goal-rust compiles server-side rather than with a local
/// assembler, unlike Go's `cmd/goal compile`).
fn resolve_programs(
    algod: &AlgodClient,
    rt: &tokio::runtime::Runtime,
    approval_prog: Option<&Path>,
    approval_prog_raw: Option<&Path>,
    clear_prog: Option<&Path>,
    clear_prog_raw: Option<&Path>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if approval_prog.is_some() == approval_prog_raw.is_some() {
        return Err("Exactly one of --approval-prog or --approval-prog-raw is required".into());
    }
    if clear_prog.is_some() == clear_prog_raw.is_some() {
        return Err("Exactly one of --clear-prog or --clear-prog-raw is required".into());
    }
    let approval = match approval_prog {
        Some(p) => compile_via_node(algod, rt, p)?,
        None => {
            let p = approval_prog_raw.expect("checked above");
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?
        }
    };
    let clear = match clear_prog {
        Some(p) => compile_via_node(algod, rt, p)?,
        None => {
            let p = clear_prog_raw.expect("checked above");
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?
        }
    };
    Ok((approval, clear))
}

fn compile_via_node(
    algod: &AlgodClient,
    rt: &tokio::runtime::Runtime,
    path: &Path,
) -> Result<Vec<u8>, String> {
    let source = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let result = rt
        .block_on(algod.teal_compile(&source))
        .map_err(|e| format!("Could not assemble: {e}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(&result.result)
        .map_err(|e| {
            format!(
                "{}: node returned an undecodable program: {e}",
                path.display()
            )
        })
}

/// The common fee/validity/note/lease/rekey header, resolved from
/// [`AppTxnArgs`] against the network's suggested params. Mirrors the tail
/// of Go's `callAppCmd`/`methodAppCmd` bodies (`FillUnsignedTxTemplate` +
/// `parseRekey`/`parseNoteField`/`parseLease`).
struct TxnHeader {
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: String,
    note: Vec<u8>,
    lease: [u8; 32],
    rekey_to: Option<Address>,
}

fn resolve_txn_header(
    txn_args: &AppTxnArgs,
    params: &algo_rest_client::SuggestedParams,
) -> Result<TxnHeader, String> {
    let note = parse_note(txn_args.note_b64.as_deref(), txn_args.note.as_deref())?;
    let lease = parse_lease(txn_args.lease.as_deref())?;
    let rekey_to = txn_args
        .rekey_to
        .as_deref()
        .map(|r| Address::from_algorand_string(r).map_err(|e| format!("rekey-to invalid: {e}")))
        .transpose()?;
    let (first, last) = compute_validity(
        txn_args.first_valid,
        txn_args.last_valid,
        txn_args.valid_rounds,
        params.last_round,
    )?;
    Ok(TxnHeader {
        fee: txn_args.fee.unwrap_or(0),
        first_valid: first,
        last_valid: last,
        genesis_hash: params.genesis_hash.0,
        genesis_id: params.genesis_id.clone(),
        note,
        lease,
        rekey_to,
    })
}

// ---------------------------------------------------------------------------
// app call / optin / closeout / clear / delete
// ---------------------------------------------------------------------------

/// `app call -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
pub fn run_call(args: CallArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| {
        // Go's `callAppCmd` always builds a NoOp call
        // (`client.MakeUnsignedAppNoOpTx`, `application.go:870`) — there is
        // no `--on-completion` flag on `app call` at all (see `CallArgs`'s
        // struct docs).
        submit_app_lifecycle_txn(
            args.app_id,
            &args.from,
            ON_COMPLETION_NOOP,
            &args.app_arg,
            &args.refs,
            args.reject_version,
            &args.txn,
            wallet,
        )
    })
}

/// `app optin -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `optInAppCmd` (`application.go:659-724`).
pub fn run_optin(args: LifecycleArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| {
        submit_app_lifecycle_txn(
            args.app_id,
            &args.from,
            ON_COMPLETION_OPTIN,
            &args.app_args.app_arg,
            &args.refs,
            args.reject_version,
            &args.txn,
            wallet,
        )
    })
}

/// `app closeout -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `closeOutAppCmd` (`application.go:726-791`).
pub fn run_closeout(args: LifecycleArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| {
        submit_app_lifecycle_txn(
            args.app_id,
            &args.from,
            ON_COMPLETION_CLOSE_OUT,
            &args.app_args.app_arg,
            &args.refs,
            args.reject_version,
            &args.txn,
            wallet,
        )
    })
}

/// `app clear -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `clearAppCmd` (`application.go:793-858`). Submitting
/// `OnCompletion=ClearState` is the only special handling this leaf needs:
/// go-algorand's ledger apply layer (`ledger/apply/application.go`) swallows
/// a rejecting/erroring ClearState program and never fails the outer
/// transaction for it — clearing out is always allowed. That's a ledger-side
/// property, not something the CLI submission path needs to replicate (see
/// `CLAUDE.md`'s "Simulation EvalDelta-on-Error Semantics" note for the
/// equivalent simulate-endpoint behavior).
pub fn run_clear(args: LifecycleArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| {
        submit_app_lifecycle_txn(
            args.app_id,
            &args.from,
            ON_COMPLETION_CLEAR_STATE,
            &args.app_args.app_arg,
            &args.refs,
            args.reject_version,
            &args.txn,
            wallet,
        )
    })
}

/// `app delete -f <from> --app-id <id> [--app-arg ...] [refs] [txn]`.
///
/// Mirrors Go's `deleteAppCmd` (`application.go:926-991`).
pub fn run_delete(args: LifecycleArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| {
        submit_app_lifecycle_txn(
            args.app_id,
            &args.from,
            ON_COMPLETION_DELETE_APPLICATION,
            &args.app_args.app_arg,
            &args.refs,
            args.reject_version,
            &args.txn,
            wallet,
        )
    })
}

/// Run `f`, mapping an `Err` into the `eprintln!` + exit-1 shape every leaf
/// in this module reports failures with.
fn run_and_report(f: impl FnOnce() -> Result<ExitCode, String>) -> ExitCode {
    match f() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

/// Build and submit a plain (no programs, no schema) application-call
/// transaction: `app call` (NoOp), `app optin`, `app closeout`, `app clear`,
/// `app delete`. Shared because Go's `callAppCmd`/`optInAppCmd`/
/// `closeOutAppCmd`/`clearAppCmd`/`deleteAppCmd` are all textually identical
/// aside from which `MakeUnsignedApp*Tx` (and thus which `OnCompletion`
/// value) they call (`application.go:660-991`).
#[allow(clippy::too_many_arguments)]
fn submit_app_lifecycle_txn(
    app_id: u64,
    from: &str,
    on_completion: u64,
    app_arg: &[String],
    refs_args: &AppRefsArgs,
    reject_version: u64,
    txn_args: &AppTxnArgs,
    wallet: Option<String>,
) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let from_resolved = accounts.address_for(from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let mut app_arguments = Vec::with_capacity(app_arg.len());
    for a in app_arg {
        if a.is_empty() {
            continue;
        }
        app_arguments.push(parse_app_call_bytes(a)?);
    }

    let refs = build_ref_bundle_from_flags(refs_args)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(txn_args, &params)?;

    let signer_addr = txn_args
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut txn = algo_txn_pipeline::ApplicationCallBuilder::new(from_addr, app_id, on_completion)
        .app_arguments(app_arguments)
        .reject_version(reject_version)
        .fee(header.fee)
        .validity(header.first_valid, header.last_valid)
        .genesis_hash(header.genesis_hash)
        .genesis_id(header.genesis_id)
        .note(header.note)
        .lease(header.lease);
    if let Some(rekey) = header.rekey_to {
        txn = txn.rekey_to(rekey);
    }
    let mut txn = txn.build().map_err(|e| e.to_string())?;
    attach_references(&mut txn, &refs);
    if txn_args.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    submit_single(
        txn,
        signer_addr,
        txn_args,
        wallet,
        &data_dir_path,
        &rt,
        algod,
        None,
    )?;
    Ok(ExitCode::SUCCESS)
}

/// The `"Attempting to {action} app (approval size {n}, hash {h}; clear
/// size {n}, hash {h})"` line `app create`/`app update` print right before
/// broadcasting. Mirrors Go's
/// `reportInfof("Attempting to %s app (approval size %d, hash %v; clear
/// size %d, hash %v)", ...)` (`application.go:564`/`641`): the hash is the
/// raw `logic.HashProgram` digest's base32 (no padding) string form — the
/// *program hash*, not a checksummed Algorand address (contrast
/// [`crate::cmd::clerk_sign::program_address`], which wraps the same digest
/// as an `Address`).
fn format_program_attempt_line(action: &str, approval: &[u8], clear: &[u8]) -> String {
    format!(
        "Attempting to {action} app (approval size {}, hash {}; clear size {}, hash {})",
        approval.len(),
        base32_digest(&hash_program(approval)),
        clear.len(),
        base32_digest(&hash_program(clear)),
    )
}

/// Base32 (RFC4648, standard alphabet, no padding) encoding of a digest,
/// matching Go's `crypto.Digest.String()` (`crypto/util.go:63-65`).
fn base32_digest(digest: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(digest)
}

/// `app create --creator <addr> --approval-prog <f> --clear-prog <f>
/// [--on-completion oc] [schema flags] [--extra-pages n] [refs] [txn]`.
///
/// Mirrors Go's `createAppCmd` (`application.go:496-584`).
pub fn run_create(args: CreateArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_create_inner(args, wallet))
}

fn run_create_inner(args: CreateArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let on_completion = parse_on_completion(&args.on_completion)?;
    if on_completion == ON_COMPLETION_CLOSE_OUT || on_completion == ON_COMPLETION_CLEAR_STATE {
        eprintln!(
            "Warning: '--on-completion {}' may be ill-formed for 'goal app create'",
            args.on_completion
        );
    }

    let local_schema = StateSchema {
        num_uint: args.local_ints,
        num_byte_slice: args.local_byteslices,
    };
    let global_schema = StateSchema {
        num_uint: args.global_ints,
        num_byte_slice: args.global_byteslices,
    };

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let creator_resolved = accounts.address_for(&args.creator);
    let creator_addr = Address::from_algorand_string(&creator_resolved)
        .map_err(|e| format!("Could not parse creator address {creator_resolved}: {e}"))?;

    let mut app_arguments = Vec::with_capacity(args.app_args.app_arg.len());
    for a in &args.app_args.app_arg {
        if a.is_empty() {
            continue;
        }
        app_arguments.push(parse_app_call_bytes(a)?);
    }
    let refs = build_ref_bundle_from_flags(&args.refs)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let (approval_prog, clear_prog) = resolve_programs(
        &algod,
        &rt,
        args.programs.approval_prog.as_deref(),
        args.programs.approval_prog_raw.as_deref(),
        args.programs.clear_prog.as_deref(),
        args.programs.clear_prog_raw.as_deref(),
    )?;

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut builder =
        algo_txn_pipeline::ApplicationCallBuilder::new(creator_addr, 0, on_completion)
            .app_arguments(app_arguments)
            .approval_program(approval_prog.clone())
            .clear_state_program(clear_prog.clone())
            .global_state_schema(global_schema)
            .local_state_schema(local_schema)
            .extra_program_pages(args.extra_pages)
            .fee(header.fee)
            .validity(header.first_valid, header.last_valid)
            .genesis_hash(header.genesis_hash)
            .genesis_id(header.genesis_id)
            .note(header.note)
            .lease(header.lease);
    if let Some(rekey) = header.rekey_to {
        builder = builder.rekey_to(rekey);
    }
    let mut txn = builder.build().map_err(|e| e.to_string())?;
    attach_references(&mut txn, &refs);
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    let extra_line = format_program_attempt_line("create", &approval_prog, &clear_prog);
    let info = submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
        Some(extra_line),
    )?;
    if let Some(info) = info {
        if let Some(app_idx) = info.application_index.filter(|i| *i != 0) {
            println!("Created app with app index {app_idx}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `app update --app-id <id> -f <from> --approval-prog <f> --clear-prog <f>
/// [--global-ints n] [--global-byteslices n] [--extra-pages n] [refs] [txn]`.
///
/// Mirrors Go's `updateAppCmd` (`application.go:586-657`).
pub fn run_update(args: UpdateArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_update_inner(args, wallet))
}

fn run_update_inner(args: UpdateArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let global_schema = StateSchema {
        num_uint: args.global_ints,
        num_byte_slice: args.global_byteslices,
    };

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let from_resolved = accounts.address_for(&args.from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let mut app_arguments = Vec::with_capacity(args.app_args.app_arg.len());
    for a in &args.app_args.app_arg {
        if a.is_empty() {
            continue;
        }
        app_arguments.push(parse_app_call_bytes(a)?);
    }
    let refs = build_ref_bundle_from_flags(&args.refs)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let (approval_prog, clear_prog) = resolve_programs(
        &algod,
        &rt,
        args.programs.approval_prog.as_deref(),
        args.programs.approval_prog_raw.as_deref(),
        args.programs.clear_prog.as_deref(),
        args.programs.clear_prog_raw.as_deref(),
    )?;

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    // Mirrors Go's `MakeUnsignedAppUpdateTx` (empty schemas/extra-pages 0)
    // immediately overwritten by the literal `tx.GlobalStateSchema =
    // ...; tx.ExtraProgramPages = ...` assignments in `updateAppCmd`
    // (`application.go:602-606`) — net effect is just "use the flags
    // as given"; local schema is never touched (immutable after create).
    let mut builder = algo_txn_pipeline::ApplicationCallBuilder::new(
        from_addr,
        args.app_id,
        ON_COMPLETION_UPDATE_APPLICATION,
    )
    .app_arguments(app_arguments)
    .reject_version(args.reject_version)
    .approval_program(approval_prog.clone())
    .clear_state_program(clear_prog.clone())
    .global_state_schema(global_schema)
    .extra_program_pages(args.extra_pages)
    .fee(header.fee)
    .validity(header.first_valid, header.last_valid)
    .genesis_hash(header.genesis_hash)
    .genesis_id(header.genesis_id)
    .note(header.note)
    .lease(header.lease);
    if let Some(rekey) = header.rekey_to {
        builder = builder.rekey_to(rekey);
    }
    let mut txn = builder.build().map_err(|e| e.to_string())?;
    attach_references(&mut txn, &refs);
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    let extra_line = format_program_attempt_line("update", &approval_prog, &clear_prog);
    submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
        Some(extra_line),
    )?;
    Ok(ExitCode::SUCCESS)
}

/// Sign (via wallet) and either write to file or broadcast a single
/// application-call transaction, reporting the txid the way Go's
/// `callAppCmd` et al. do. `extra_info_line`, when given, is printed
/// immediately after broadcasting and before the "Issued transaction..."
/// line (Go's `create`/`update` "Attempting to ... app (...)" line).
/// Returns the confirmed [`algo_rest_client::PendingTxnInfo`] (`None` when
/// `--no-wait` was given) so `app create` can report the new app index.
/// Shared by every plain-lifecycle leaf and `create`/`update`; `app method`
/// uses its own group-aware path (see [`run_method_inner`]).
#[allow(clippy::too_many_arguments)]
fn submit_single(
    txn: Transaction,
    signer_addr: Option<Address>,
    txn_args: &AppTxnArgs,
    wallet: Option<String>,
    data_dir_path: &Path,
    rt: &tokio::runtime::Runtime,
    algod: AlgodClient,
    extra_info_line: Option<String>,
) -> Result<Option<algo_rest_client::PendingTxnInfo>, String> {
    let want_wallet_sign = txn_args.out.is_none() || txn_args.sign;
    let stx = if want_wallet_sign {
        let kmd = build_kmd_client(data_dir_path, crate::cli_state::kmddir().as_deref())?;
        let mut accounts = AccountsList::load(data_dir_path);
        let (handle, _name, password) = resolve_wallet_and_init(
            rt,
            &kmd,
            &mut accounts,
            wallet.as_deref(),
            txn_args.password.as_deref(),
        )?;
        let signer_pk: [u8; 32] = signer_addr.map(|a| a.0).unwrap_or([0u8; 32]);
        let encoded = canonical_encode_transaction(&txn);
        let signed = rt
            .block_on(kmd.sign_transaction(&handle, &password, encoded, signer_pk))
            .map_err(|e| {
                format!(
                    "Couldn't sign tx with kmd: {} (for multisig accounts, write tx to file and \
                     sign manually)",
                    kmd_msg(&e)
                )
            })?;
        let mut decoded = decode_signed_txn_stream(&signed.signed_transaction)
            .map_err(|e| format!("kmd returned an undecodable signed transaction: {e}"))?;
        let mut s = decoded
            .pop()
            .ok_or("kmd returned an empty signed transaction")?;
        if signer_addr.is_some() {
            s.auth_addr = signer_addr;
        }
        s
    } else {
        if signer_addr.is_some() {
            return Err("Signer specified when txn won't be signed".to_string());
        }
        SignedTransaction {
            txn: txn.clone(),
            ..SignedTransaction::default()
        }
    };

    if let Some(out_path) = txn_args.out.as_ref() {
        let encoded = canonical_encode_signed_transaction(&stx);
        std::fs::write(out_path, &encoded)
            .map_err(|e| format!("Cannot write file {}: {e}", out_path.display()))?;
        return Ok(None);
    }

    let last_valid = txn.last_valid.0;
    let encoded_stx = canonical_encode_signed_transaction(&stx);
    let pipeline = algo_txn_pipeline::TxnPipeline::new(algod, None);
    let info = rt.block_on(async {
        let txid = pipeline
            .submit(&encoded_stx)
            .await
            .map_err(|e| format!("Couldn't broadcast tx with algod: {e}"))?;
        if let Some(line) = &extra_info_line {
            println!("{line}");
        }
        println!(
            "Issued transaction from account {}, txid {} (fee {})",
            txn.sender.to_algorand_string(),
            txid,
            txn.fee
        );
        if txn_args.no_wait {
            return Ok::<Option<algo_rest_client::PendingTxnInfo>, String>(None);
        }
        let info = pipeline
            .wait_for_confirmation(&txid, last_valid)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(round) = info.confirmed_round {
            println!("Transaction {txid} committed in round {round}");
        }
        Ok(Some(info))
    })?;
    Ok(info)
}

// ---------------------------------------------------------------------------
// app method
// ---------------------------------------------------------------------------

/// Resolve `--method` (+ optional `--abi`) into a parsed [`Method`]. With no
/// `--abi`, `--method` must be a full inline ARC-4 signature (Go's actual
/// behavior). With `--abi <contract.json>`, `--method` is a bare name looked
/// up in the file (goal-rust extension — see [`MethodArgs`] docs).
fn resolve_method(method: &str, abi: Option<&Path>) -> Result<Method, String> {
    let Some(path) = abi else {
        return parse_method_signature(method)
            .map_err(|e| format!("cannot parse method signature: {e}"));
    };
    let data = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Ok(contract) = serde_json::from_str::<Contract>(&data) {
        return contract
            .find_method(method)
            .and_then(|m| m.to_method())
            .map_err(|e| format!("{}: {e}", path.display()));
    }
    let iface: Interface = serde_json::from_str(&data).map_err(|e| {
        format!(
            "{}: not a valid ARC-4 Contract/Interface JSON: {e}",
            path.display()
        )
    })?;
    iface
        .find_method(method)
        .and_then(|m| m.to_method())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Resolve `account`/`asset`/`application` reference-type method args into
/// indices, mutating `refs` with any newly-discovered accounts/apps/assets.
/// Mirrors Go's `populateMethodCallReferenceArgs` (`application.go:1167-1238`)
/// **exactly**, including its literal-string sender comparison
/// (`value == sender`, comparing the raw `--arg`/`--from` CLI strings, not
/// parsed addresses) — a deliberate quirk we replicate rather than "fix",
/// since we must match Go's resolved indices bit-for-bit.
fn populate_method_call_reference_args(
    sender_raw: &str,
    current_app: u64,
    ref_types: &[ReferenceType],
    ref_values: &[String],
    refs: &mut RefBundle,
) -> Result<Vec<usize>, String> {
    let mut resolved = Vec::with_capacity(ref_values.len());
    for (i, value) in ref_values.iter().enumerate() {
        let idx = match ref_types[i] {
            ReferenceType::Account => {
                if value == sender_raw {
                    0
                } else {
                    let addr = cli_address(value)?;
                    match refs.accounts.iter().position(|a| *a == addr) {
                        Some(j) => j + 1,
                        None => {
                            refs.accounts.push(addr);
                            refs.accounts.len()
                        }
                    }
                }
            }
            ReferenceType::Application => {
                let app_id: u64 = value
                    .parse()
                    .map_err(|_| format!("Could not parse '{value}' as app id"))?;
                if app_id == current_app {
                    0
                } else {
                    match refs.apps.iter().position(|&a| a == app_id) {
                        Some(j) => j + 1,
                        None => {
                            refs.apps.push(app_id);
                            refs.apps.len()
                        }
                    }
                }
            }
            ReferenceType::Asset => {
                let asset_id: u64 = value
                    .parse()
                    .map_err(|_| format!("Could not parse '{value}' as asset id"))?;
                match refs.assets.iter().position(|&a| a == asset_id) {
                    Some(j) => j,
                    None => {
                        refs.assets.push(asset_id);
                        refs.assets.len() - 1
                    }
                }
            }
        };
        resolved.push(idx);
    }
    Ok(resolved)
}

/// Load and validate each `MethodArgType::Transaction` argument's file:
/// exactly one unsigned (or Lsig-only) `SignedTxn`, no group ID yet, and a
/// matching transaction type (`txn` accepts any type). Mirrors Go's
/// `populateMethodCallTxnArgs` (`application.go:1129-1165`).
fn populate_method_call_txn_args(
    types: &[TransactionType],
    values: &[String],
) -> Result<Vec<SignedTransaction>, String> {
    let mut out = Vec::with_capacity(values.len());
    for (i, path) in values.iter().enumerate() {
        let data = std::fs::read(path).map_err(|e| format!("Cannot read file {path}: {e}"))?;
        let stxns = decode_signed_txn_stream(&data)
            .map_err(|e| format!("Cannot decode transactions from {path}: {e}"))?;
        if stxns.len() != 1 {
            return Err(format!(
                "Cannot decode transactions from {path}: expected exactly one transaction, got {}",
                stxns.len()
            ));
        }
        let stxn = stxns.into_iter().next().expect("checked len == 1");
        if stxn.sig != [0u8; 64] || stxn.msig.is_some() {
            return Err(format!("Transaction from {path} has already been signed"));
        }
        if stxn.txn.group != [0u8; 32] {
            return Err(format!(
                "Transaction from {path} already has a group ID: {}",
                hex::encode(stxn.txn.group)
            ));
        }
        let expected = types[i];
        if !matches!(expected, TransactionType::Any) {
            let expected_str = expected.to_string();
            if stxn.txn.txn_type.as_str() != expected_str {
                return Err(format!(
                    "Transaction from {path} does not match method argument type. Expected \
                     {expected_str}, got {}",
                    stxn.txn.txn_type
                ));
            }
        }
        out.push(stxn);
    }
    Ok(out)
}

/// `app method -f <from> (--app-id <id> | --create) --method <sig> [--arg ...] [refs] [txn]`.
pub fn run_method(args: MethodArgs, wallet: Option<String>) -> ExitCode {
    match run_method_inner(args, wallet) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_method_inner(args: MethodArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let method = resolve_method(&args.method, args.abi.as_deref())?;
    let on_completion = parse_on_completion(&args.on_completion)?;

    let local_schema = StateSchema {
        num_uint: args.local_ints,
        num_byte_slice: args.local_byteslices,
    };
    let global_schema = StateSchema {
        num_uint: args.global_ints,
        num_byte_slice: args.global_byteslices,
    };

    let app_id = if args.create {
        if args.app_id.is_some() {
            return Err("--app-id and --create are mutually exclusive, only provide one".into());
        }
        if args.reject_version != 0 {
            return Err("--reject-version should not be provided with --create".into());
        }
        0u64
    } else {
        let app_id = args
            .app_id
            .filter(|id| *id != 0)
            .ok_or("one of --app-id or --create must be provided")?;
        if on_completion != ON_COMPLETION_UPDATE_APPLICATION {
            if !global_schema.is_empty() {
                return Err(
                    "--global-ints, --global-byteslices, --local-ints, and --local-byteslices must \
                     only be provided with --create or when updating"
                        .into(),
                );
            }
            if args.extra_pages != 0 {
                return Err(
                    "--extra-pages must only be provided with --create or when updating".into(),
                );
            }
        }
        if !local_schema.is_empty() {
            return Err(
                "--local-ints and --local-byteslices must only be provided with --create".into(),
            );
        }
        app_id
    };

    if args.arg.len() != method.args.len() {
        return Err(format!(
            "incorrect number of arguments, method expected {} but got {}",
            method.args.len(),
            args.arg.len()
        ));
    }

    // Split method args into transaction / reference / plain-ABI buckets,
    // mirroring Go's loop at `application.go:1398-1421`.
    let mut txn_arg_types = Vec::new();
    let mut txn_arg_values = Vec::new();
    let mut basic_arg_types: Vec<AbiType> = Vec::new();
    let mut basic_arg_values: Vec<String> = Vec::new();
    let mut ref_arg_types = Vec::new();
    let mut ref_arg_values = Vec::new();
    let mut ref_arg_index_to_basic_arg_index: Vec<usize> = Vec::new();
    for (i, arg_type) in method.args.iter().enumerate() {
        let arg_value = args.arg[i].clone();
        match arg_type {
            MethodArgType::Transaction(t) => {
                txn_arg_types.push(*t);
                txn_arg_values.push(arg_value);
            }
            MethodArgType::Reference(r) => {
                ref_arg_index_to_basic_arg_index.push(basic_arg_types.len());
                ref_arg_types.push(*r);
                ref_arg_values.push(arg_value);
                basic_arg_types.push(AbiType::Uint(8));
                basic_arg_values.push(String::new());
            }
            MethodArgType::Abi(t) => {
                basic_arg_types.push(t.clone());
                basic_arg_values.push(arg_value);
            }
        }
    }

    let mut refs = build_ref_bundle_from_flags(&args.refs)?;
    let ref_resolved = populate_method_call_reference_args(
        &args.from,
        app_id,
        &ref_arg_types,
        &ref_arg_values,
        &mut refs,
    )?;
    for (i, resolved) in ref_resolved.into_iter().enumerate() {
        basic_arg_values[ref_arg_index_to_basic_arg_index[i]] = resolved.to_string();
    }

    let basic_arg_value_refs: Vec<&str> = basic_arg_values.iter().map(String::as_str).collect();
    let mut app_arguments = vec![method_selector(&method.signature()).to_vec()];
    app_arguments.extend(encode_method_args(&basic_arg_types, &basic_arg_value_refs)?);

    let loaded_txn_args = populate_method_call_txn_args(&txn_arg_types, &txn_arg_values)?;

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let from_resolved = accounts.address_for(&args.from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    let (approval_prog, clear_prog) =
        if args.create || on_completion == ON_COMPLETION_UPDATE_APPLICATION {
            let (a, c) = resolve_programs(
                &algod,
                &rt,
                args.approval_prog.as_deref(),
                args.approval_prog_raw.as_deref(),
                args.clear_prog.as_deref(),
                args.clear_prog_raw.as_deref(),
            )?;
            (Some(a), Some(c))
        } else {
            (None, None)
        };

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &params)?;

    let mut builder =
        algo_txn_pipeline::ApplicationCallBuilder::new(from_addr, app_id, on_completion)
            .app_arguments(app_arguments)
            .reject_version(args.reject_version)
            .extra_program_pages(args.extra_pages)
            .fee(header.fee)
            .validity(header.first_valid, header.last_valid)
            .genesis_hash(header.genesis_hash)
            .genesis_id(header.genesis_id)
            .note(header.note)
            .lease(header.lease);
    if let Some(approval) = approval_prog {
        builder = builder.approval_program(approval);
    }
    if let Some(clear) = clear_prog {
        builder = builder.clear_state_program(clear);
    }
    if args.create {
        builder = builder.global_state_schema(global_schema);
        builder = builder.local_state_schema(local_schema);
    } else if on_completion == ON_COMPLETION_UPDATE_APPLICATION {
        builder = builder.global_state_schema(global_schema);
    }
    if let Some(rekey) = header.rekey_to {
        builder = builder.rekey_to(rekey);
    }
    let mut app_call_txn = builder.build().map_err(|e| e.to_string())?;
    attach_references(&mut app_call_txn, &refs);
    if args.txn.fee.is_none() {
        app_call_txn.fee =
            algo_txn_pipeline::estimate_fee(&app_call_txn, params.fee, params.min_fee);
    }

    // Assemble the group: leading transaction args, then the app call.
    let mut group: Vec<Transaction> = loaded_txn_args.iter().map(|s| s.txn.clone()).collect();
    group.push(app_call_txn.clone());
    if group.len() > 1 {
        let gid = compute_group_id(&group);
        for t in group.iter_mut() {
            t.group = gid.0;
        }
    }
    let app_call_txn = group.last().expect("just pushed").clone();

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    // The app-call transaction (last in the group) always needs wallet
    // signing when `want_wallet_sign`; a leading txn-arg only needs it when
    // it wasn't supplied with its own Lsig (mirrors Go's per-slot
    // `!txnFromArgs.Lsig.Blank()` branch, `application.go:1497-1511`). Since
    // the app-call slot always requires the wallet in that case, resolve the
    // kmd client/handle eagerly whenever `want_wallet_sign` is set.
    let want_wallet_sign = args.txn.out.is_none() || args.txn.sign;
    let kmd: Option<KmdClient> = if want_wallet_sign {
        Some(build_kmd_client(
            &data_dir_path,
            crate::cli_state::kmddir().as_deref(),
        )?)
    } else {
        None
    };
    let wallet_session = if let Some(kmd) = kmd.as_ref() {
        let mut acc = AccountsList::load(&data_dir_path);
        Some(resolve_wallet_and_init(
            &rt,
            kmd,
            &mut acc,
            wallet.as_deref(),
            args.txn.password.as_deref(),
        )?)
    } else {
        None
    };

    let mut signed_group: Vec<SignedTransaction> = Vec::with_capacity(group.len());
    for (i, unsigned_txn) in group.iter().enumerate() {
        if i < loaded_txn_args.len() {
            let arg_stxn = &loaded_txn_args[i];
            if arg_stxn.lsig.is_some() {
                signed_group.push(SignedTransaction {
                    txn: unsigned_txn.clone(),
                    lsig: arg_stxn.lsig.clone(),
                    auth_addr: arg_stxn.auth_addr,
                    ..SignedTransaction::default()
                });
                continue;
            }
        }
        let auth_addr_for_slot = if i < loaded_txn_args.len() {
            loaded_txn_args[i].auth_addr
        } else {
            signer_addr
        };
        if want_wallet_sign {
            let (handle, _name, password) = wallet_session
                .as_ref()
                .expect("kmd configured when want_wallet_sign");
            let kmd = kmd.as_ref().expect("kmd configured when want_wallet_sign");
            let signer_pk: [u8; 32] = auth_addr_for_slot.map(|a| a.0).unwrap_or([0u8; 32]);
            let encoded = canonical_encode_transaction(unsigned_txn);
            let signed = rt
                .block_on(kmd.sign_transaction(handle, password, encoded, signer_pk))
                .map_err(|e| format!("Couldn't sign tx with kmd: {}", kmd_msg(&e)))?;
            let mut decoded = decode_signed_txn_stream(&signed.signed_transaction)
                .map_err(|e| format!("kmd returned an undecodable signed transaction: {e}"))?;
            let mut s = decoded
                .pop()
                .ok_or("kmd returned an empty signed transaction")?;
            if auth_addr_for_slot.is_some() {
                s.auth_addr = auth_addr_for_slot;
            }
            signed_group.push(s);
        } else {
            if auth_addr_for_slot.is_some() {
                return Err("Signer specified when txn won't be signed".to_string());
            }
            signed_group.push(SignedTransaction {
                txn: unsigned_txn.clone(),
                ..SignedTransaction::default()
            });
        }
    }

    if let Some(out_path) = args.txn.out.as_ref() {
        let mut out = Vec::new();
        for s in &signed_group {
            out.extend_from_slice(&canonical_encode_signed_transaction(s));
        }
        write_file_0600(out_path, &out)?;
        return Ok(ExitCode::SUCCESS);
    }

    // Broadcast: concatenate every signed txn's canonical msgpack.
    let mut raw = Vec::new();
    for s in &signed_group {
        raw.extend_from_slice(&canonical_encode_signed_transaction(s));
    }
    let pipeline = algo_txn_pipeline::TxnPipeline::new(algod, None);
    let last_valid = app_call_txn.last_valid.0;
    // Compute the app-call txid client-side (mirrors Go's `stxn.Txn.ID()`)
    // rather than trusting the broadcast response, which only names the
    // first transaction in the group.
    let app_call_txid: algo_rest_client::TxId = compute_txn_id(&app_call_txn).to_string().into();

    rt.block_on(async {
        pipeline
            .submit(&raw)
            .await
            .map_err(|e| format!("Couldn't broadcast tx with algod: {e}"))?;
        println!("Issued {} transaction(s):", signed_group.len());
        for s in &signed_group {
            println!(
                "Issued transaction from account {}, txid {} (fee {})",
                s.txn.sender.to_algorand_string(),
                compute_txn_id(&s.txn),
                s.txn.fee
            );
        }
        Ok::<(), String>(())
    })?;

    if args.txn.no_wait {
        return Ok(ExitCode::SUCCESS);
    }

    let info = rt
        .block_on(pipeline.wait_for_confirmation(&app_call_txid, last_valid))
        .map_err(|e| e.to_string())?;

    if args.create {
        if let Some(app_idx) = info.application_index.filter(|i| *i != 0) {
            println!("Created app with app index {app_idx}");
        }
    }

    match &method.returns {
        None => {
            println!("method {} succeeded", method.signature());
        }
        Some(ret_type) => {
            let logs = info.logs.unwrap_or_default();
            let last_log = logs.last().ok_or_else(|| {
                format!(
                    "method {} succeed but did not log a return value",
                    method.signature()
                )
            })?;
            if !last_log.starts_with(&ABI_RETURN_HASH) {
                return Err(format!(
                    "method {} succeed but did not log a return value",
                    method.signature()
                ));
            }
            let raw_return = &last_log[ABI_RETURN_HASH.len()..];
            let decoded = algo_abi::decode(ret_type, raw_return).map_err(|e| {
                format!(
                    "method {} succeed but its return value could not be decoded.\nThe raw return \
                     value in hex is:{}\nThe error is: {e}",
                    method.signature(),
                    hex::encode(raw_return)
                )
            })?;
            let json = algo_abi::value_to_json_string(&decoded);
            println!(
                "method {} succeeded with output: {json}",
                method.signature()
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// app box info / app box list
// ---------------------------------------------------------------------------

/// `app box info --app-id <id> -n/--name <encoding:value>`.
///
/// Mirrors Go's `appBoxInfoCmd` (`cmd/goal/box.go:63-98`): fetch the box's
/// value via `GET /v2/applications/{id}/box`, cross-check the returned box
/// name against the one requested (guards against a server that resolves a
/// different box than intended), and print `Name:`/`Value:` in the
/// `apps.AppCallBytes` display form ([`encode_bytes_as_app_call_bytes`]).
pub fn run_box_info(args: BoxInfoArgs) -> ExitCode {
    match run_box_info_inner(args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_box_info_inner(args: BoxInfoArgs) -> Result<ExitCode, String> {
    if args.name.is_empty() {
        return Err("Box --name is required".to_string());
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    let box_resp = match rt.block_on(algod.get_application_box_by_name(args.app_id, &args.name)) {
        Ok(b) => b,
        Err(AlgoError::NotFound(msg)) if msg.contains("box not found") => {
            return Err(format!(
                "No box found for appid {} with name {}",
                args.app_id, args.name
            ));
        }
        Err(e) => return Err(format!("Error processing command: {e}")),
    };

    // Cross-check the returned box name against what was requested, mirroring
    // Go's belt-and-suspenders comparison (box.go:84-92) — reduces confusion
    // if the server ever resolved a different box representation.
    verify_box_name(&args.name, &box_resp.name)?;

    println!("Name:  {}", args.name);
    println!("Value: {}", encode_bytes_as_app_call_bytes(&box_resp.value));
    Ok(ExitCode::SUCCESS)
}

/// Verify a `GET /v2/applications/{id}/box` response's box name matches the
/// one requested, mirroring Go's belt-and-suspenders check
/// (`box.go:84-92`): re-decode `requested` (the raw `-n/--name` CLI value)
/// through [`parse_app_call_bytes`] and compare against `returned_name`
/// byte-for-byte.
fn verify_box_name(requested: &str, returned_name: &[u8]) -> Result<(), String> {
    let requested_bytes = parse_app_call_bytes(requested).map_err(|e| {
        format!("Failed to parse box name {requested}. It must have the same form as app-arg. Error: {e}")
    })?;
    if returned_name != requested_bytes {
        return Err(format!(
            "Inputted box name {} does not match box name {} received from algod",
            String::from_utf8_lossy(returned_name),
            String::from_utf8_lossy(&requested_bytes)
        ));
    }
    Ok(())
}

/// `app box list --app-id <id> [-l <limit>] [-n <next>] [-p <prefix>] [-v] [-r <round>]`.
///
/// Mirrors Go's `appBoxListCmd` (`cmd/goal/box.go:100-163`): page through
/// `GET /v2/applications/{id}/boxes` (always in the go-algorand
/// v4.7.0-beta cursor-pagination mode — `--limit`/`--next`/`--round` are
/// always sent, matching libgoal's `ApplicationBoxesPage`), auto-pinning
/// the round from the first page and printing a `NextToken:` line only
/// when the caller explicitly asked for a single page (`--limit`/`--next`
/// given) rather than exhausting every page automatically.
pub fn run_box_list(args: BoxListArgs) -> ExitCode {
    match run_box_list_inner(args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_box_list_inner(args: BoxListArgs) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    let limit = default_box_list_limit(args.limit, args.values);
    let explicit_next = args.next.clone().unwrap_or_default();
    let mut next = explicit_next.clone();
    let mut round = args.round;
    let prefix = args.prefix.as_deref().unwrap_or("");

    loop {
        let resp = rt
            .block_on(algod.get_application_boxes_page(
                args.app_id,
                limit,
                &next,
                prefix,
                args.values,
                round,
            ))
            .map_err(|e| format!("Error processing command: {e}"))?;

        if round == 0 {
            // Auto-pin round from the first page for consistent pagination.
            round = resp
                .round
                .ok_or("algod did not return a round for a paginated box listing")?;
            if resp.boxes.is_empty() {
                return Err("No matching boxes found".to_string());
            }
        }

        for descriptor in &resp.boxes {
            let encoded_name = encode_bytes_as_app_call_bytes(&descriptor.name);
            match (&args.values, &descriptor.value) {
                (true, Some(value)) => {
                    println!("{encoded_name} : {}", encode_bytes_as_app_call_bytes(value));
                }
                _ => println!("{encoded_name}"),
            }
        }

        next = resp.next_token.unwrap_or_default();
        if next.is_empty() {
            break;
        }
        if should_stop_after_page(args.limit, &explicit_next) {
            println!("NextToken: {next}");
            break;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The effective `--limit` to request, mirroring Go's
/// `if limit == 0 { limit = ... }` (`box.go:117-124`): the caller's explicit
/// `--limit` (`0` meaning unset), else 100 with `--values` or 1000 without.
fn default_box_list_limit(limit_flag: u64, values: bool) -> u64 {
    if limit_flag != 0 {
        return limit_flag;
    }
    if values {
        100
    } else {
        1000
    }
}

/// Whether to stop after a single page and print `NextToken:` rather than
/// looping through every page automatically, mirroring Go's
/// `if boxLimit > 0 || boxNext != ""` (`box.go:156-160`) — checked against
/// the *original* CLI flags, not the resolved/looped values.
fn should_stop_after_page(limit_flag: u64, explicit_next: &str) -> bool {
    limit_flag > 0 || !explicit_next.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_abi::{parse_method_signature, TransactionType};

    // --- apps.AppCallBytes-form parsing ---

    #[test]
    fn parses_str_encoding() {
        assert_eq!(
            parse_app_call_bytes("str:hello").unwrap(),
            b"hello".to_vec()
        );
    }

    #[test]
    fn parses_string_alias() {
        assert_eq!(parse_app_call_bytes("string:hi").unwrap(), b"hi".to_vec());
    }

    #[test]
    fn parses_int_encoding_big_endian_u64() {
        assert_eq!(
            parse_app_call_bytes("int:1234").unwrap(),
            1234u64.to_be_bytes().to_vec()
        );
    }

    #[test]
    fn parses_addr_encoding() {
        let addr = Address([0x11; 32]);
        let s = addr.to_algorand_string();
        let bytes = parse_app_call_bytes(&format!("addr:{s}")).unwrap();
        assert_eq!(bytes, addr.0.to_vec());
    }

    #[test]
    fn parses_b64_encoding() {
        assert_eq!(parse_app_call_bytes("b64:aGk=").unwrap(), b"hi".to_vec());
    }

    #[test]
    fn parses_b32_encoding() {
        // "hi" -> base32 (RFC4648, standard alphabet, padded) = "NBUQ===="
        let encoded = data_encoding::BASE32.encode(b"hi");
        assert_eq!(
            parse_app_call_bytes(&format!("b32:{encoded}")).unwrap(),
            b"hi".to_vec()
        );
    }

    #[test]
    fn parses_abi_encoding() {
        // abi:uint64:5 -> 8-byte big-endian 5.
        let bytes = parse_app_call_bytes("abi:uint64:5").unwrap();
        assert_eq!(bytes, 5u64.to_be_bytes().to_vec());
    }

    #[test]
    fn unknown_encoding_errors() {
        assert!(parse_app_call_bytes("bogus:x").is_err());
    }

    #[test]
    fn missing_colon_errors() {
        assert!(parse_app_call_bytes("nocolon").is_err());
    }

    // --- cli_address ---

    #[test]
    fn cli_address_empty_is_zero() {
        assert_eq!(cli_address("").unwrap(), Address::ZERO);
    }

    #[test]
    fn cli_address_app_form_matches_app_address() {
        let a = cli_address("app(1)").unwrap();
        assert_eq!(a, app_address(1));
    }

    #[test]
    fn cli_address_rejects_bad_address() {
        assert!(cli_address("not-an-address").is_err());
    }

    // --- on-completion ---

    #[test]
    fn on_completion_values_match_go_numbering() {
        assert_eq!(parse_on_completion("NoOp").unwrap(), 0);
        assert_eq!(parse_on_completion("optin").unwrap(), 1);
        assert_eq!(parse_on_completion("CloseOut").unwrap(), 2);
        assert_eq!(parse_on_completion("ClearState").unwrap(), 3);
        assert_eq!(parse_on_completion("UpdateApplication").unwrap(), 4);
        assert_eq!(parse_on_completion("DeleteApplication").unwrap(), 5);
        assert!(parse_on_completion("bogus").is_err());
    }

    // --- box / holding / local ref parsing ---

    #[test]
    fn box_ref_without_app_id_defaults_to_zero() {
        let (app, name) = parse_box_ref("str:mybox").unwrap();
        assert_eq!(app, 0);
        assert_eq!(name, b"mybox".to_vec());
    }

    #[test]
    fn box_ref_with_app_id() {
        let (app, name) = parse_box_ref("5,str:mybox").unwrap();
        assert_eq!(app, 5);
        assert_eq!(name, b"mybox".to_vec());
    }

    #[test]
    fn holding_ref_without_address() {
        let (asset, addr) = parse_holding_ref("111").unwrap();
        assert_eq!(asset, 111);
        assert_eq!(addr, "");
    }

    #[test]
    fn holding_ref_with_address() {
        let (asset, addr) = parse_holding_ref("111+SOMEADDR").unwrap();
        assert_eq!(asset, 111);
        assert_eq!(addr, "SOMEADDR");
    }

    #[test]
    fn local_ref_bare_number_is_app_id() {
        let (app, addr) = parse_local_ref("42").unwrap();
        assert_eq!(app, 42);
        assert_eq!(addr, "");
    }

    #[test]
    fn local_ref_bare_non_number_is_address() {
        let (app, addr) = parse_local_ref("SOMEADDR").unwrap();
        assert_eq!(app, 0);
        assert_eq!(addr, "SOMEADDR");
    }

    #[test]
    fn local_ref_app_plus_address() {
        let (app, addr) = parse_local_ref("42+SOMEADDR").unwrap();
        assert_eq!(app, 42);
        assert_eq!(addr, "SOMEADDR");
    }

    // --- reference-arg resolution (mirrors go's TestPopulateMethodCallReferenceArgs pattern) ---

    #[test]
    fn reference_args_sender_is_index_zero() {
        let mut refs = RefBundle::default();
        let resolved = populate_method_call_reference_args(
            "SENDERSTRING",
            111,
            &[ReferenceType::Account],
            &["SENDERSTRING".to_string()],
            &mut refs,
        )
        .unwrap();
        assert_eq!(resolved, vec![0]);
        assert!(refs.accounts.is_empty());
    }

    #[test]
    fn reference_args_current_app_is_index_zero() {
        let mut refs = RefBundle::default();
        let resolved = populate_method_call_reference_args(
            "SENDER",
            111,
            &[ReferenceType::Application],
            &["111".to_string()],
            &mut refs,
        )
        .unwrap();
        assert_eq!(resolved, vec![0]);
        assert!(refs.apps.is_empty());
    }

    #[test]
    fn reference_args_asset_is_zero_based_no_self() {
        let mut refs = RefBundle::default();
        let resolved = populate_method_call_reference_args(
            "SENDER",
            111,
            &[ReferenceType::Asset, ReferenceType::Asset],
            &["5".to_string(), "5".to_string()],
            &mut refs,
        )
        .unwrap();
        assert_eq!(resolved, vec![0, 0]);
        assert_eq!(refs.assets, vec![5]);
    }

    #[test]
    fn reference_args_new_account_appended_and_deduped() {
        let mut refs = RefBundle::default();
        let addr = Address([0x22; 32]).to_algorand_string();
        let resolved = populate_method_call_reference_args(
            "SENDER",
            111,
            &[ReferenceType::Account, ReferenceType::Account],
            &[addr.clone(), addr.clone()],
            &mut refs,
        )
        .unwrap();
        assert_eq!(resolved, vec![1, 1]);
        assert_eq!(refs.accounts.len(), 1);
    }

    // --- transaction-arg population ---

    #[test]
    fn txn_arg_requires_file_to_exist() {
        let err = populate_method_call_txn_args(
            &[TransactionType::Pay],
            &["/nonexistent/file".to_string()],
        )
        .unwrap_err();
        assert!(err.contains("Cannot read file"));
    }

    // --- method resolution ---

    #[test]
    fn resolve_method_inline_signature() {
        let m = resolve_method("add(uint64,uint64)uint64", None).unwrap();
        assert_eq!(m.name, "add");
        assert_eq!(m.signature(), "add(uint64,uint64)uint64");
    }

    #[test]
    fn resolve_method_matches_direct_parse() {
        let direct = parse_method_signature("empty()void").unwrap();
        let via_resolve = resolve_method("empty()void", None).unwrap();
        assert_eq!(direct, via_resolve);
    }

    // --- app box info / app box list ---

    #[test]
    fn verify_box_name_matches_accepts_identical_bytes() {
        assert!(verify_box_name("str:mybox", b"mybox").is_ok());
    }

    #[test]
    fn verify_box_name_matches_rejects_mismatch() {
        let err = verify_box_name("str:mybox", b"otherbox").unwrap_err();
        assert!(err.contains("does not match box name"), "got: {err}");
    }

    #[test]
    fn verify_box_name_matches_rejects_unparseable_requested_name() {
        let err = verify_box_name("nocolon", b"mybox").unwrap_err();
        assert!(err.contains("Failed to parse box name"), "got: {err}");
    }

    #[test]
    fn default_box_list_limit_uses_explicit_value_when_set() {
        assert_eq!(default_box_list_limit(42, false), 42);
        assert_eq!(default_box_list_limit(42, true), 42);
    }

    #[test]
    fn default_box_list_limit_defaults_to_1000_without_values() {
        assert_eq!(default_box_list_limit(0, false), 1000);
    }

    #[test]
    fn default_box_list_limit_defaults_to_100_with_values() {
        assert_eq!(default_box_list_limit(0, true), 100);
    }

    #[test]
    fn should_stop_after_page_when_limit_explicit() {
        assert!(should_stop_after_page(50, ""));
    }

    #[test]
    fn should_stop_after_page_when_next_explicit() {
        assert!(should_stop_after_page(0, "str:cursor"));
    }

    #[test]
    fn should_not_stop_after_page_with_neither_flag() {
        assert!(!should_stop_after_page(0, ""));
    }

    // --- app create/update/optin/closeout/clear/delete on-completion wiring ---

    #[test]
    fn lifecycle_on_completion_constants_match_parse_on_completion() {
        // Pins the numeric OnCompletion each lifecycle leaf submits against
        // the same mapping `parse_on_completion`/Go's
        // `transactions.OnCompletion` enum use, so `run_optin`/`run_closeout`/
        // `run_clear`/`run_delete`'s hard-coded constants can't silently
        // drift from that mapping.
        assert_eq!(ON_COMPLETION_NOOP, parse_on_completion("NoOp").unwrap());
        assert_eq!(ON_COMPLETION_OPTIN, parse_on_completion("OptIn").unwrap());
        assert_eq!(
            ON_COMPLETION_CLOSE_OUT,
            parse_on_completion("CloseOut").unwrap()
        );
        assert_eq!(
            ON_COMPLETION_CLEAR_STATE,
            parse_on_completion("ClearState").unwrap()
        );
        assert_eq!(
            ON_COMPLETION_UPDATE_APPLICATION,
            parse_on_completion("UpdateApplication").unwrap()
        );
        assert_eq!(
            ON_COMPLETION_DELETE_APPLICATION,
            parse_on_completion("DeleteApplication").unwrap()
        );
    }

    #[test]
    fn base32_digest_matches_go_crypto_digest_string() {
        // Go's `crypto.Digest.String()` is unpadded standard base32
        // (`crypto/util.go:63-65`); RFC4648 test vector for "hi" x2
        // hashed... instead, pin against a known digest computed the same
        // way `data_encoding::BASE32` (padded) would, minus padding.
        let digest = [0u8; 32];
        let encoded = base32_digest(&digest);
        // 256 bits at 5 bits/char = 52 chars, no padding — unlike the
        // padded BASE32 codec used elsewhere in this module for box
        // names/app-args.
        assert_eq!(encoded.len(), 52);
        assert!(encoded.chars().all(|c| c == 'A'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn format_program_attempt_line_matches_go_shape() {
        let approval = vec![0x06, 0x81, 0x01];
        let clear = vec![0x06, 0x81, 0x00];
        let line = format_program_attempt_line("create", &approval, &clear);
        let expected_approval_hash = base32_digest(&hash_program(&approval));
        let expected_clear_hash = base32_digest(&hash_program(&clear));
        assert_eq!(
            line,
            format!(
                "Attempting to create app (approval size 3, hash {expected_approval_hash}; \
                 clear size 3, hash {expected_clear_hash})"
            )
        );
    }

    #[test]
    fn format_program_attempt_line_reports_action_and_sizes() {
        let line = format_program_attempt_line("update", &[0u8; 5], &[0u8; 7]);
        assert!(line.starts_with("Attempting to update app (approval size 5, hash "));
        assert!(line.contains("clear size 7, hash "));
    }
}
