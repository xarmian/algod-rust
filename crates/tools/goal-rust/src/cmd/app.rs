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

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use algo_abi::{
    encode_method_args, method_selector, parse_method_signature, AbiType, Method, MethodArgType,
    ReferenceType, TransactionType,
};
use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, compute_group_id,
    compute_txn_id, decode_raw, decode_signed_txn_stream,
};
use algo_kmd_client::KmdClient;
use algo_rest_client::AlgodClient;
use algo_types::{Address, SignedTransaction, StateSchema, TealValue, Transaction};

use crate::accounts_list::AccountsList;
use crate::cmd::app_state_json::{encode_teal_state_json, heuristic_format_entries, TealEntry};
use crate::cmd::clerk::{
    build_full_algod_client_for_dir, build_wallet_handle_kmd_client, compute_validity, kmd_msg,
    parse_lease, parse_note, resolve_wallet_and_init, write_file_0600,
};
use crate::cmd::clerk_sign::{hash_program, program_address};
use crate::data_dir;
use crate::formatting::encode_bytes_as_app_call_bytes;
use crate::groups::app::{
    AppRefsArgs, AppTxnArgs, BoxInfoArgs, BoxListArgs, CallArgs, CreateArgs, InfoArgs,
    LifecycleArgs, MethodArgs, ReadArgs, UpdateArgs,
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
    let (encoding, value) = new_app_call_bytes(arg)?;
    raw_app_call_bytes(encoding, value)
}

/// go's `apps.NewAppCallBytes`: split `encoding:value` at the first colon.
fn new_app_call_bytes(arg: &str) -> Result<(&str, &str), String> {
    arg.split_once(':').ok_or_else(|| {
        "all arguments and box names should be of the form 'encoding:value'".to_string()
    })
}

/// go's `strconv.ParseUint(s, 10, 64)`: the reason of its error
/// (`errors.Unwrap(err)`): `invalid syntax` or `value out of range`.
fn go_parse_uint(s: &str) -> Result<u64, &'static str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid syntax");
    }
    s.parse::<u64>().map_err(|_| "value out of range")
}

/// go's `parseUInt64(number, thing, context...)`.
fn parse_uint64_ctx(number: &str, thing: &str, context: Option<&str>) -> Result<u64, String> {
    go_parse_uint(number).map_err(|reason| {
        let extra = context.map(|c| format!(" in {c}")).unwrap_or_default();
        format!("Could not parse '{number}' as {thing}{extra}: {reason}")
    })
}

/// go's `AppCallBytes.Raw` (`avm-abi/apps/parsing.go`).
fn raw_app_call_bytes(encoding: &str, value: &str) -> Result<Vec<u8>, String> {
    match encoding {
        "str" | "string" => Ok(value.as_bytes().to_vec()),
        "int" | "integer" => {
            let num = go_parse_uint(value).map_err(|reason| {
                format!(
                    "Could not parse uint64 from string ({value}): strconv.ParseUint: parsing {}: {reason}",
                    crate::cmd::ledger::go_quote(value)
                )
            })?;
            Ok(num.to_be_bytes().to_vec())
        }
        "addr" | "address" => address_from_string(value).map(|a| a.to_vec()).map_err(|e| {
            format!("Could not unmarshal checksummed address from string ({value}): {e}")
        }),
        "b32" | "base32" | "byte base32" => {
            algo_avm::assembler::go_base32_decode_string(value, true)
                .map_err(|e| format!("Could not decode base32-encoded string ({value}): {e}"))
        }
        "b64" | "base64" | "byte base64" => {
            if let Err(at) = crate::go_json::go_base64_check(value.as_bytes()) {
                return Err(format!(
                    "Could not decode base64-encoded string ({value}): illegal base64 data at input byte {at}"
                ));
            }
            use base64::Engine as _;
            base64::engine::general_purpose::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
            )
            .decode(value.replace(['\r', '\n'], ""))
            .map_err(|e| format!("Could not decode base64-encoded string ({value}): {e}"))
        }
        "abi" => {
            let (type_str, json_val) = value.split_once(':').ok_or_else(|| {
                format!("Could not decode abi string ({value}): should split abi-type and abi-value with colon")
            })?;
            let abi_type = algo_abi::type_of(type_str)
                .map_err(|e| format!("Could not decode abi type string ({type_str}): {e}"))?;
            let abi_value = algo_abi::unmarshal_from_json(&abi_type, json_val)
                .map_err(|e| format!("Could not decode abi value string ({json_val}): {e} "))?;
            algo_abi::encode(&abi_value)
        }
        other => Err(format!("Unknown encoding: {other}")),
    }
}

/// go's `address.FromString` (`avm-abi/address`): unpadded base32 of the 32
/// byte address and its 4 byte checksum (the last 4 bytes of SHA-512/256).
fn address_from_string(s: &str) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha512_256};
    let cast =
        |detail: String| format!("cannot cast encoded address string ({s}) to address: {detail}");
    let decoded = algo_avm::assembler::go_base32_decode_string(s, false)
        .map_err(|e| cast(format!("base32 decode error: {e}")))?;
    if decoded.len() != 36 {
        return Err(cast(
            "decoded byte length should equal 36 with address and checksum".to_string(),
        ));
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&decoded[..32]);
    let hash = Sha512_256::digest(addr);
    let checksum = &hash[28..32];
    if checksum != &decoded[32..] {
        let show = |b: &[u8]| {
            format!(
                "[{}]",
                b.iter().map(u8::to_string).collect::<Vec<_>>().join(" ")
            )
        };
        return Err(cast(format!(
            "decoded checksum mismatch, {} != {}",
            show(checksum),
            show(&decoded[32..])
        )));
    }
    Ok(addr)
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
        let app_id = parse_uint64_ctx(inner, "app id", Some(acct))?;
        return Ok(app_address(app_id));
    }
    // go: `basics.UnmarshalChecksumAddress`, its error printed as is
    let addr = algo_avm::assembler::unmarshal_checksum_address(acct)?;
    Ok(Address(addr.try_into().expect("32-byte address")))
}

/// Parse a `--box` value: `[<app-id>,]encoding:value` (Go's `parseBoxRef`,
/// `application.go:280-298`): the app id (0 when omitted) and the still
/// undecoded `AppCallBytes`.
fn parse_box_ref(arg: &str) -> Result<(u64, String, String), String> {
    let (encoding, value) = arg
        .split_once(':')
        .ok_or_else(|| "box refs should be of the form '[<app>,]encoding:value'".to_string())?;
    let (app_id, encoding) = match encoding.split_once(',') {
        Some((app_str, enc)) => (parse_uint64_ctx(app_str, "app id", Some("box ref"))?, enc),
        None => (0u64, encoding),
    };
    Ok((app_id, encoding.to_string(), value.to_string()))
}

/// Parse a `--holding` value: `<asset-id>[+<address>]` (Go's
/// `parseHoldingRef`, `application.go:300-310`). An empty address means the
/// Sender.
fn parse_holding_ref(arg: &str) -> Result<(u64, String), String> {
    let (asset_str, address) = arg.split_once('+').unwrap_or((arg, ""));
    let asset_id = parse_uint64_ctx(asset_str, "asset id", Some("holding ref"))?;
    Ok((asset_id, address.to_string()))
}

/// Parse a `--local` value: `[<app-id>][+<address>]` (Go's `parseLocalRef`,
/// `application.go:312-342`). No app-id means the app being called; no
/// address means the Sender; both may not be omitted simultaneously —
/// mirrors Go by leaving that check to the caller (Go doesn't reject it
/// either; it becomes a no-op reference).
fn parse_local_ref(arg: &str) -> Result<(u64, String), String> {
    if let Some((one, two)) = arg.split_once('+') {
        let app_id = parse_uint64_ctx(one, "app id", Some("local ref"))?;
        return Ok((app_id, two.to_string()));
    }
    // No '+': try as a bare app id number; otherwise treat as a bare address
    // (Go tries `strconv.ParseUint` first and falls back to an address).
    if let Ok(app_id) = go_parse_uint(arg) {
        Ok((app_id, String::new()))
    } else {
        Ok((0, arg.to_string()))
    }
}

/// go's `getAppInputs`: `getAppInputsFromCLI` (every non-empty `--app-arg`
/// split, then the reference flags parsed: foreign apps and assets, boxes,
/// holdings, locals) followed by `parseAppInputs` (the arguments decoded,
/// then the local and holding addresses, the box names and the accounts), each
/// failure go's text, in go's order. Returns the argument bytes and the
/// references.
fn parse_app_inputs(
    app_arg: &[String],
    refs: &AppRefsArgs,
) -> Result<(Vec<Vec<u8>>, RefBundle), String> {
    // getAppInputsFromCLI
    let mut args = Vec::new();
    for a in app_arg.iter().filter(|a| !a.is_empty()) {
        args.push(new_app_call_bytes(a)?);
    }
    let mut apps = Vec::with_capacity(refs.foreign_app.len());
    for a in &refs.foreign_app {
        apps.push(parse_uint64_ctx(a, "app id", Some("foreign-app"))?);
    }
    let mut assets = Vec::with_capacity(refs.foreign_asset.len());
    for a in &refs.foreign_asset {
        assets.push(parse_uint64_ctx(a, "asset id", Some("foreign-asset"))?);
    }
    let mut parsed_boxes = Vec::with_capacity(refs.app_box.len());
    for b in &refs.app_box {
        parsed_boxes.push(parse_box_ref(b)?);
    }
    let mut parsed_holdings = Vec::with_capacity(refs.holding.len());
    for h in &refs.holding {
        parsed_holdings.push(parse_holding_ref(h)?);
    }
    let mut parsed_locals = Vec::with_capacity(refs.local.len());
    for l in &refs.local {
        parsed_locals.push(parse_local_ref(l)?);
    }

    // parseAppInputs
    let mut raw_args = Vec::with_capacity(args.len());
    for (encoding, value) in &args {
        raw_args.push(
            raw_app_call_bytes(encoding, value)
                .map_err(|e| format!("Could not decode app-arg {encoding}:{value}: {e}"))?,
        );
    }
    let mut locals = Vec::with_capacity(parsed_locals.len());
    for (app, addr) in parsed_locals {
        locals.push(LocalHint {
            app,
            address: cli_address(&addr)?,
        });
    }
    let mut holdings = Vec::with_capacity(parsed_holdings.len());
    for (asset, addr) in parsed_holdings {
        holdings.push(HoldingHint {
            asset,
            address: cli_address(&addr)?,
        });
    }
    let mut boxes = Vec::with_capacity(parsed_boxes.len());
    for (app, encoding, value) in parsed_boxes {
        let name = raw_app_call_bytes(&encoding, &value)
            .map_err(|e| format!("Could not decode box name {{{encoding} {value}}}: {e}"))?;
        boxes.push(BoxHint { app, name });
    }
    let mut accounts = Vec::with_capacity(refs.app_account.len());
    for a in &refs.app_account {
        accounts.push(cli_address(a)?);
    }
    Ok((
        raw_args,
        RefBundle {
            use_access: refs.access,
            accounts,
            assets,
            apps,
            holdings,
            locals,
            boxes,
            empty_refs: refs.empty_refs,
        },
    ))
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
/// program; the uncompiled source is assembled locally, like go's
/// `assembleFile(fname, false)`.
fn resolve_programs(
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
        Some(p) => crate::cmd::clerk::assemble_file(&p.to_string_lossy())?,
        None => {
            let p = approval_prog_raw.expect("checked above");
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?
        }
    };
    let clear = match clear_prog {
        Some(p) => crate::cmd::clerk::assemble_file(&p.to_string_lossy())?,
        None => {
            let p = clear_prog_raw.expect("checked above");
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?
        }
    };
    Ok((approval, clear))
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
    data_dir: &Path,
    params: &algo_rest_client::SuggestedParams,
) -> Result<TxnHeader, String> {
    let note = parse_note(txn_args.note_b64.as_deref(), txn_args.note.as_deref())?;
    let lease = parse_lease(txn_args.lease.as_deref())?;
    let rekey_to = txn_args
        .rekey_to
        .as_deref()
        .map(|r| Address::from_algorand_string(r).map_err(|e| format!("rekey-to invalid: {e}")))
        .transpose()?;
    let max_txn_life =
        crate::cmd::clerk::resolve_max_txn_life(data_dir, &params.consensus_version)?;
    let (first, last) = compute_validity(
        txn_args.first_valid,
        txn_args.last_valid,
        txn_args.valid_rounds,
        params.last_round,
        max_txn_life,
    )?;
    Ok(TxnHeader {
        fee: txn_args.fee.unwrap_or(0),
        first_valid: first,
        last_valid: last,
        genesis_hash: params.genesis_hash.0,
        // go's `FillUnsignedTxTemplate` sets the genesis hash only.
        genesis_id: String::new(),
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
    let accounts = AccountsList::load_or_empty(&data_dir_path);
    let from_resolved = accounts.address_for(from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let (app_arguments, refs) = parse_app_inputs(app_arg, refs_args)?;

    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let params = crate::algod_txn::suggested_params(&rt, &algod)
        .map_err(|e| format!("Cannot determine last valid round: {e}"))?;
    let header = resolve_txn_header(txn_args, &data_dir_path, &params)?;

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
    let accounts = AccountsList::load_or_empty(&data_dir_path);
    let creator_resolved = accounts.address_for(&args.creator);
    let creator_addr = Address::from_algorand_string(&creator_resolved)
        .map_err(|e| format!("Could not parse creator address {creator_resolved}: {e}"))?;

    let (app_arguments, refs) = parse_app_inputs(&args.app_args.app_arg, &args.refs)?;

    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let (approval_prog, clear_prog) = resolve_programs(
        args.programs.approval_prog.as_deref(),
        args.programs.approval_prog_raw.as_deref(),
        args.programs.clear_prog.as_deref(),
        args.programs.clear_prog_raw.as_deref(),
    )?;

    let params = crate::algod_txn::suggested_params(&rt, &algod)
        .map_err(|e| format!("Cannot determine last valid round: {e}"))?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

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
    let accounts = AccountsList::load_or_empty(&data_dir_path);
    let from_resolved = accounts.address_for(&args.from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let (app_arguments, refs) = parse_app_inputs(&args.app_args.app_arg, &args.refs)?;

    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let (approval_prog, clear_prog) = resolve_programs(
        args.programs.approval_prog.as_deref(),
        args.programs.approval_prog_raw.as_deref(),
        args.programs.clear_prog.as_deref(),
        args.programs.clear_prog_raw.as_deref(),
    )?;

    let params = crate::algod_txn::suggested_params(&rt, &algod)
        .map_err(|e| format!("Cannot determine last valid round: {e}"))?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

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
        let kmd = build_wallet_handle_kmd_client(data_dir_path)?;
        let mut accounts = AccountsList::load(data_dir_path).map_err(|e| e.to_string())?;
        let (handle, _name, password) =
            resolve_wallet_and_init(rt, &kmd, &mut accounts, wallet.as_deref())?;
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
    let txid = crate::algod_txn::broadcast(rt, &algod, &encoded_stx)
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
        return Ok(None);
    }
    crate::algod_txn::wait_for_commit_info(rt, &algod, &txid, last_valid).map(Some)
}

// ---------------------------------------------------------------------------
// app info / app read
// ---------------------------------------------------------------------------

/// `app info --app-id <id>`.
///
/// Mirrors Go's `infoAppCmd` (`application.go:1073-1127`): fetch the
/// application's params via `GET /v2/applications/{id}` and print a
/// multi-field text block. The approval/clear "hash" lines are the
/// checksummed *address* form of `logic.HashProgram` ([`program_address`]),
/// not the raw digest `app create`/`app update`'s
/// [`format_program_attempt_line`] prints — go's `basics.Address(...)`
/// wrapping in `infoAppCmd` is exactly `program_address`.
pub fn run_info(args: InfoArgs) -> ExitCode {
    run_and_report(|| run_info_inner(args))
}

fn run_info_inner(args: InfoArgs) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let endpoint = crate::goal_client::ensure_algod_endpoint(
        &data_dir_path,
        crate::goal_client::ClientType::Full,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    // go: `client.ApplicationInformation(appIdx)` into a `model.Application`
    let meta = crate::algod_rest::get_json(
        &rt,
        &endpoint,
        &format!("/v2/applications/{}", args.app_id),
        &[],
        &crate::go_codec_json::APPLICATION,
    )
    .map_err(|e| crate::formatting::report_error_text(&format!("Error processing command: {e}")))?;
    let params = &meta["params"];
    let program = |f: &str| {
        use base64::Engine as _;
        params[f]
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default()
    };
    let u = |v: &serde_json::Value| v.as_u64().unwrap_or(0);

    // Field labels/spacing are copied byte-for-byte from
    // `application.go:1087-1124`'s `fmt.Printf` calls.
    let mut out = String::new();
    {
        use std::fmt::Write as _;
        let _ = writeln!(out, "Application ID:        {}", args.app_id);
        let _ = writeln!(
            out,
            "Application account:   {}",
            app_address(args.app_id).to_algorand_string()
        );
        let _ = writeln!(
            out,
            "Creator:               {}",
            params["creator"].as_str().unwrap_or("")
        );
        let _ = writeln!(
            out,
            "Approval hash:         {}",
            program_address(&program("approval-program")).to_algorand_string()
        );
        let _ = writeln!(
            out,
            "Clear hash:            {}",
            program_address(&program("clear-state-program")).to_algorand_string()
        );
        if params["version"].is_u64() {
            let _ = writeln!(out, "Program version:       {}", u(&params["version"]));
        }
        if let Some(sponsor) = params["size-sponsor"].as_str() {
            let _ = writeln!(out, "Size sponsor:        {sponsor}");
        }
        if params["extra-program-pages"].is_u64() {
            let _ = writeln!(
                out,
                "Extra program pages:   {}",
                u(&params["extra-program-pages"])
            );
        }
        if params["foreign-box-reads"] == true {
            let _ = writeln!(out, "Foreign box reads:     enabled");
        }
        if params["family-box-access"] == true {
            let _ = writeln!(out, "Family box access:     enabled");
        }
        let gsch = &params["global-state-schema"];
        if gsch.is_object() {
            let _ = writeln!(out, "Max global byteslices: {}", u(&gsch["num-byte-slice"]));
            let _ = writeln!(out, "Max global integers:   {}", u(&gsch["num-uint"]));
        }
        let lsch = &params["local-state-schema"];
        if lsch.is_object() {
            let _ = writeln!(out, "Max local byteslices:  {}", u(&lsch["num-byte-slice"]));
            let _ = writeln!(out, "Max local integers:    {}", u(&lsch["num-uint"]));
        }
    }
    // (go-codec's strings are raw bytes, printed unfiltered)
    crate::formatting::print_raw(&out);
    Ok(ExitCode::SUCCESS)
}

/// The two-level presence of a `("app-local-state","tkv")`/`("app-params",
/// "gs")` field pair extracted from a raw `GET .../applications/{id}
/// ?format=msgpack` response. Mirrors Go's two-level nil check
/// (`application.go:1022`/`1052`): the *outer* field (`AppLocalState`/
/// `AppParams`) being absent from the decoded payload means "not opted
/// in"/"didn't create this app"; the outer field being present but its
/// inner `KeyValue`/`GlobalState` field absent is a nil
/// `map[string]TealValue` (no entries were ever stored), which Go's
/// `protocol.EncodeJSON` renders as the JSON literal `null`.
enum AppResourceState {
    NotPresent,
    Present(Option<Vec<TealEntry>>),
}

fn as_msgpack_map(val: &rmpv::Value) -> Result<&Vec<(rmpv::Value, rmpv::Value)>, String> {
    val.as_map()
        .ok_or_else(|| "Error processing command: malformed application response".to_string())
}

fn find_map_entry<'a>(map: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> Option<&'a rmpv::Value> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

/// Decode a msgpack-string-format `TealKeyValue` key into its raw bytes.
/// Go's `map[string]TealValue` keys are binary-safe Go strings encoded as
/// msgpack str format (not bin) — see
/// `algo_codec::canonical_encode_teal_key_value`'s matching encode side.
fn teal_key_bytes(key: &rmpv::Value) -> Result<Vec<u8>, String> {
    match key {
        rmpv::Value::String(s) => Ok(s.as_bytes().to_vec()),
        other => Err(format!(
            "Error processing command: unexpected TealKeyValue key type: {other:?}"
        )),
    }
}

/// Decode a single msgpack-encoded `basics.TealValue` (`{"tt":...,"tb":...,
/// "ui":...}`, matching `algo_codec::canonical_encode_teal_value`'s encode
/// side) into a [`TealValue`].
fn decode_teal_value(val: &rmpv::Value) -> Result<TealValue, String> {
    let map = as_msgpack_map(val)?;
    let tt = find_map_entry(map, "tt")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if tt == 2 {
        let ui = find_map_entry(map, "ui")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(TealValue::Uint(ui))
    } else {
        let tb = find_map_entry(map, "tb")
            .and_then(|v| match v {
                rmpv::Value::String(s) => Some(s.as_bytes().to_vec()),
                _ => None,
            })
            .unwrap_or_default();
        Ok(TealValue::Bytes(tb))
    }
}

/// Extract the `(outer_key, inner_key)` field pair (`("app-local-state",
/// "tkv")` or `("app-params", "gs")`) from a raw
/// `GET .../applications/{id}?format=msgpack` response body.
fn extract_app_resource_state(
    raw: &[u8],
    outer_key: &str,
    inner_key: &str,
) -> Result<AppResourceState, String> {
    let val = decode_raw(raw)
        .map_err(|e| format!("Error processing command: malformed response: {e}"))?;
    let map = as_msgpack_map(&val)?;
    let Some(outer) = find_map_entry(map, outer_key) else {
        return Ok(AppResourceState::NotPresent);
    };
    let outer_map = as_msgpack_map(outer)?;
    let Some(inner) = find_map_entry(outer_map, inner_key) else {
        return Ok(AppResourceState::Present(None));
    };
    let inner_map = as_msgpack_map(inner)?;
    let mut entries = Vec::with_capacity(inner_map.len());
    for (k, v) in inner_map {
        entries.push((teal_key_bytes(k)?, decode_teal_value(v)?));
    }
    Ok(AppResourceState::Present(Some(entries)))
}

/// `app read --app-id <id> (--local --from <addr> | --global) [--guess-format]`.
///
/// Mirrors Go's `readStateAppCmd` (`application.go:993-1071`): fetch local
/// (via `--from`) or global state through the raw msgpack
/// `GET /v2/accounts/{addr}/applications/{id}?format=msgpack` endpoint
/// (go's `client.RawAccountApplicationInformation`, which decodes into the
/// basics-typed `AccountApplicationModel` -- a *different* wire shape from
/// the array-shaped `TealKeyValueStore` REST JSON model used elsewhere in
/// this tool), optionally apply the `--guess-format` heuristic, and write
/// go's exact `protocol.EncodeJSON` byte shape to stdout (no trailing
/// newline, matching Go's `os.Stdout.Write(enc)`).
pub fn run_read(args: ReadArgs) -> ExitCode {
    run_and_report(|| run_read_inner(args))
}

fn run_read_inner(args: ReadArgs) -> Result<ExitCode, String> {
    // Mirrors `if fetchLocal == fetchGlobal { reportErrorf(errorLocalGlobal) }`.
    if args.local == args.global {
        return Err("Exactly one of --local or --global is required".to_string());
    }
    let from = args.from.clone().unwrap_or_default();
    if args.local && from.is_empty() {
        return Err("--local requires --from account".to_string());
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    let state = if args.local {
        let accounts = AccountsList::load_or_empty(&data_dir_path);
        let resolved = accounts.address_for(&from);
        // Go's `--local` path treats a 404 specially (`errors.As(err,
        // &httpError) && httpError.StatusCode == http.StatusNotFound`) as
        // "not opted in"; any other transport error is generic
        // (`application.go:1013-1020`).
        let raw = match raw_account_application(&rt, &algod, &resolved, args.app_id) {
            Ok(b) => b,
            Err(e) if crate::algod_rest::http_error_status(&e) == Some(404) => {
                return Err(format!(
                    "{from} has not opted in to application {}",
                    args.app_id
                ));
            }
            Err(e) => return Err(format!("Error processing command: {e}")),
        };
        match extract_app_resource_state(&raw, "app-local-state", "tkv")? {
            AppResourceState::NotPresent => {
                return Err(format!(
                    "{from} has not opted in to application {}",
                    args.app_id
                ));
            }
            AppResourceState::Present(entries) => entries,
        }
    } else {
        // Go's `--global` path does NOT special-case 404 -- any error from
        // either call is the generic `errorRequestFail`
        // (`application.go:1041-1050`); only a *successful* response with a
        // nil `AppParams` becomes "not opted in" (`application.go:1052-1053`,
        // reusing the same message and the -- likely always empty --
        // `account`/`--from` value even though this is the global-state
        // path, a literal Go quirk we replicate for byte-exact CLI output).
        let meta = crate::algod_rest::get_json(
            &rt,
            &endpoint(&algod),
            &format!("/v2/applications/{}", args.app_id),
            &[],
            &crate::go_codec_json::APPLICATION,
        )
        .map_err(|e| format!("Error processing command: {e}"))?;
        let creator = meta["params"]["creator"].as_str().unwrap_or("").to_string();
        let raw = raw_account_application(&rt, &algod, &creator, args.app_id)
            .map_err(|e| format!("Error processing command: {e}"))?;
        match extract_app_resource_state(&raw, "app-params", "gs")? {
            AppResourceState::NotPresent => {
                return Err(format!(
                    "{from} has not opted in to application {}",
                    args.app_id
                ));
            }
            AppResourceState::Present(entries) => entries,
        }
    };

    let state = if args.guess_format {
        state.map(heuristic_format_entries)
    } else {
        state
    };

    let json = encode_teal_state_json(state);
    std::io::stdout()
        .write_all(&json)
        .map_err(|e| format!("Error processing command: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

/// The `(base URL, token)` of `algod` for [`crate::algod_rest`].
fn endpoint(algod: &AlgodClient) -> crate::algod_rest::Endpoint {
    (algod.base_url().to_string(), algod.token().to_string())
}

/// A `[]byte` field of a go-codec decoded answer (base64; `null` is empty).
fn json_bytes(v: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap_or(""))
        .unwrap_or_default()
}

/// go's libgoal `RawAccountApplicationInformation`: the msgpack of the
/// account's resource of the application (`format=msgpack`), which go
/// decodes into a `v2.AccountApplicationModel` (`protocol.Decode`: its
/// msgp-generated decoder, whose error is returned as is).
fn raw_account_application(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    address: &str,
    app_id: u64,
) -> Result<Vec<u8>, String> {
    let raw = crate::algod_rest::get(
        rt,
        &endpoint(algod),
        &format!("/v2/accounts/{address}/applications/{app_id}"),
        &[("format", "msgpack")],
    )?;
    crate::balance_record::check_account_application_model(&raw)?;
    Ok(raw)
}

// ---------------------------------------------------------------------------
// app method
// ---------------------------------------------------------------------------

/// Resolve `--method` (+ optional `--abi`) into a parsed [`Method`]. With no
/// `--abi`, `--method` must be a full inline ARC-4 signature (Go's actual
/// behavior). With `--abi <contract.json>`, `--method` is a bare name looked
/// up in the file (goal-rust extension — see [`MethodArgs`] docs).
fn resolve_method(method: &str) -> Result<Method, String> {
    parse_method_signature(method).map_err(|e| format!("cannot parse method signature: {e}"))
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
        // go v5.1: a normal, Msig or salted-key signature is a signature; a
        // LogicSig or an `ls`-scheme salted-key proof (which authorize by
        // program) is not.
        if stxn.sig != [0u8; 64]
            || stxn.msig.as_ref().is_some_and(|m| !m.blank())
            || stxn.pqsig.as_ref().is_some_and(|p| !p.blank() && !is_ls_scheme(p))
        {
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
    // go's `getDataDirAndClient`, then `getAppInputs` (every non-empty
    // `--app-arg` and the reference flags are parsed, in that order), then
    // the mutual exclusion of `--arg` and `--app-arg`.
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let _algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let (app_args_parsed, refs_parsed) = parse_app_inputs(&args.app_arg, &args.refs)?;
    if !app_args_parsed.is_empty() {
        return Err("--arg and --app-arg are mutually exclusive, do not use --app-arg".into());
    }
    let method = resolve_method(&args.method)?;
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

    let mut refs = refs_parsed;
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
    let accounts = AccountsList::load_or_empty(&data_dir_path);
    let from_resolved = accounts.address_for(&args.from);
    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;

    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    let (approval_prog, clear_prog) =
        if args.create || on_completion == ON_COMPLETION_UPDATE_APPLICATION {
            let (a, c) = resolve_programs(
                args.approval_prog.as_deref(),
                args.approval_prog_raw.as_deref(),
                args.clear_prog.as_deref(),
                args.clear_prog_raw.as_deref(),
            )?;
            (Some(a), Some(c))
        } else {
            (None, None)
        };

    let params = crate::algod_txn::suggested_params(&rt, &algod)
        .map_err(|e| format!("Cannot determine last valid round: {e}"))?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

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
        Some(build_wallet_handle_kmd_client(&data_dir_path)?)
    } else {
        None
    };
    let wallet_session = if let Some(kmd) = kmd.as_ref() {
        let mut acc = AccountsList::load(&data_dir_path).map_err(|e| e.to_string())?;
        Some(resolve_wallet_and_init(
            &rt,
            kmd,
            &mut acc,
            wallet.as_deref(),
        )?)
    } else {
        None
    };

    let mut signed_group: Vec<SignedTransaction> = Vec::with_capacity(group.len());
    for (i, unsigned_txn) in group.iter().enumerate() {
        if i < loaded_txn_args.len() {
            let arg_stxn = &loaded_txn_args[i];
            if arg_has_logicsig(arg_stxn) {
                signed_group.push(SignedTransaction {
                    txn: unsigned_txn.clone(),
                    lsig: arg_stxn.lsig.clone(),
                    pqsig: arg_stxn.pqsig.clone(),
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
    let last_valid = app_call_txn.last_valid.0;
    // Compute the app-call txid client-side (mirrors Go's `stxn.Txn.ID()`)
    // rather than trusting the broadcast response, which only names the
    // first transaction in the group.
    let app_call_txid: algo_rest_client::TxId = compute_txn_id(&app_call_txn).to_string().into();

    crate::algod_txn::broadcast(&rt, &algod, &raw)
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

    if args.txn.no_wait {
        return Ok(ExitCode::SUCCESS);
    }

    let info = crate::algod_txn::wait_for_commit_info(&rt, &algod, &app_call_txid.0, last_valid)?;

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
    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    // go: `client.GetApplicationBoxByName` through go's REST client; a
    // `box not found` anywhere in its error is go's own message
    let box_resp = match crate::algod_rest::get_json(
        &rt,
        &endpoint(&algod),
        &format!("/v2/applications/{}/box", args.app_id),
        &[("name", &args.name)],
        &crate::go_codec_json::BOX,
    ) {
        Ok(b) => b,
        Err(e) if e.contains("box not found") => {
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
    verify_box_name(&args.name, &json_bytes(&box_resp["name"]))?;

    println!("Name:  {}", args.name);
    println!(
        "Value: {}",
        encode_bytes_as_app_call_bytes(&json_bytes(&box_resp["value"]))
    );
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
    let algod = build_full_algod_client_for_dir(&data_dir_path)?;
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
        // go: `client.ApplicationBoxesPage`, its `applicationBoxesParams`
        // (`omitempty`) through go's REST client
        let (limit_s, round_s) = (limit.to_string(), round.to_string());
        let mut query: Vec<(&str, &str)> = Vec::new();
        if args.values {
            query.push(("include", "values"));
        }
        if limit != 0 {
            query.push(("limit", &limit_s));
        }
        if !next.is_empty() {
            query.push(("next", &next));
        }
        if !prefix.is_empty() {
            query.push(("prefix", prefix));
        }
        if round != 0 {
            query.push(("round", &round_s));
        }
        let resp = crate::algod_rest::get_json(
            &rt,
            &endpoint(&algod),
            &format!("/v2/applications/{}/boxes", args.app_id),
            &query,
            &crate::go_codec_json::BOXES,
        )
        .map_err(|e| format!("Error processing command: {e}"))?;
        let boxes = resp["boxes"].as_array().cloned().unwrap_or_default();

        if round == 0 {
            // Auto-pin round from the first page for consistent pagination.
            round = resp["round"]
                .as_u64()
                .ok_or("algod did not return a round for a paginated box listing")?;
            if boxes.is_empty() {
                return Err("No matching boxes found".to_string());
            }
        }

        for descriptor in &boxes {
            let encoded_name = encode_bytes_as_app_call_bytes(&json_bytes(&descriptor["name"]));
            match (args.values, descriptor.get("value")) {
                (true, Some(value)) => {
                    println!(
                        "{encoded_name} : {}",
                        encode_bytes_as_app_call_bytes(&json_bytes(value))
                    );
                }
                _ => println!("{encoded_name}"),
            }
        }

        next = resp["next-token"].as_str().unwrap_or("").to_string();
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

/// go's `SaltedKeySig.IsLogicSig()`: the `ls` scheme, a program standing in for
/// the public key.
fn is_ls_scheme(sksig: &algo_types::SaltedKeySig) -> bool {
    sksig.scheme == algo_types::SIG_SCHEME_LOGIC_SIG
}

/// Go `goal app method` (`cmd/goal/application.go`, v5.1):
/// `!txnFromArgs.Lsig.Blank() || txnFromArgs.SKsig.IsLogicSig()`.
fn arg_has_logicsig(stxn: &SignedTransaction) -> bool {
    stxn.lsig.as_ref().is_some_and(|l| !l.is_blank())
        || stxn.pqsig.as_ref().is_some_and(is_ls_scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_abi::{parse_method_signature, TransactionType};

    #[test]
    fn arg_has_logicsig_is_blank_aware() {
        let mut s = SignedTransaction::default();
        assert!(!arg_has_logicsig(&s));
        s.lsig = Some(algo_types::LogicSig::default());
        assert!(!arg_has_logicsig(&s), "blank lsig is not a logicsig");
        s.lsig = Some(algo_types::LogicSig {
            logic: serde_bytes::ByteBuf::from(vec![2, 0x20, 1, 1, 0x22]),
            ..Default::default()
        });
        assert!(arg_has_logicsig(&s));

        // an `ls`-scheme proof authorizes by program too (go v5.1)
        let mut ls = SignedTransaction::default();
        ls.pqsig = Some(algo_types::SaltedKeySig {
            scheme: *b"ls",
            public_key: serde_bytes::ByteBuf::from(vec![2, 0x20, 1, 1, 0x22]),
            ..Default::default()
        });
        assert!(arg_has_logicsig(&ls));
        // a key-scheme proof does not
        let mut key = SignedTransaction::default();
        key.pqsig = Some(algo_types::SaltedKeySig {
            scheme: *b"f1",
            public_key: serde_bytes::ByteBuf::from(vec![1]),
            ..Default::default()
        });
        assert!(!arg_has_logicsig(&key));
    }

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
        let (app, encoding, value) = parse_box_ref("str:mybox").unwrap();
        assert_eq!(app, 0);
        assert_eq!((encoding.as_str(), value.as_str()), ("str", "mybox"));
    }

    #[test]
    fn box_ref_with_app_id() {
        let (app, encoding, value) = parse_box_ref("5,str:mybox").unwrap();
        assert_eq!(app, 5);
        assert_eq!((encoding.as_str(), value.as_str()), ("str", "mybox"));
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
        let m = resolve_method("add(uint64,uint64)uint64").unwrap();
        assert_eq!(m.name, "add");
        assert_eq!(m.signature(), "add(uint64,uint64)uint64");
    }

    #[test]
    fn resolve_method_matches_direct_parse() {
        let direct = parse_method_signature("empty()void").unwrap();
        let via_resolve = resolve_method("empty()void").unwrap();
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

    // --- app info / app read: raw msgpack decode round-trip ---
    //
    // These build a raw `AccountApplicationModel` payload with this repo's
    // own server-side encoder (`algo_codec::canonical_encode_account_application_model`,
    // which mirrors go's `daemon/algod/api/spec/v2.AccountApplicationModel`
    // wire shape byte-for-byte -- see that function's doc comment) and
    // confirm `extract_app_resource_state`/`decode_teal_value` decode it
    // back correctly, proving the client and server sides of this repo
    // agree on the wire format `goal app read` depends on.

    use algo_types::{AppLocalState, AppParams, StateSchema};
    use std::collections::BTreeMap;

    #[test]
    fn extract_app_resource_state_not_present_when_field_absent() {
        // Neither app-local-state nor app-params present -> encodes as an
        // empty map (mirrors the server's 404 case, but here we're testing
        // the decode of a raw payload directly).
        let raw = algo_codec::canonical_encode_account_application_model(None, None);
        let state = extract_app_resource_state(&raw, "app-local-state", "tkv").unwrap();
        assert!(matches!(state, AppResourceState::NotPresent));
    }

    #[test]
    fn extract_app_resource_state_present_with_nil_inner_map() {
        // AppLocalState present (nonzero schema, so the "app-local-state"
        // wrapper itself isn't recursively-empty-omitted) but with an empty
        // KeyValue store -> the "tkv" field is omitted on the wire
        // (canonical omitempty), which must decode as `Present(None)` (Go's
        // nil-map -> JSON `null`).
        let als = AppLocalState {
            schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            },
            key_value: BTreeMap::new(),
        };
        let raw = algo_codec::canonical_encode_account_application_model(None, Some(&als));
        let state = extract_app_resource_state(&raw, "app-local-state", "tkv").unwrap();
        assert!(matches!(state, AppResourceState::Present(None)));
    }

    #[test]
    fn extract_app_resource_state_present_with_entries() {
        let mut kv = BTreeMap::new();
        kv.insert(b"foo".to_vec(), TealValue::Bytes(b"bar".to_vec()));
        kv.insert(b"num".to_vec(), TealValue::Uint(42));
        let als = AppLocalState {
            schema: StateSchema::default(),
            key_value: kv,
        };
        let raw = algo_codec::canonical_encode_account_application_model(None, Some(&als));
        let state = extract_app_resource_state(&raw, "app-local-state", "tkv").unwrap();
        let AppResourceState::Present(Some(mut entries)) = state else {
            panic!("expected Present(Some(entries)), got a different variant");
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                (b"foo".to_vec(), TealValue::Bytes(b"bar".to_vec())),
                (b"num".to_vec(), TealValue::Uint(42)),
            ]
        );
    }

    #[test]
    fn extract_app_resource_state_global_reads_gs_field() {
        let mut gs = BTreeMap::new();
        gs.insert(b"g".to_vec(), TealValue::Uint(7));
        let ap = AppParams {
            global_state: gs,
            ..AppParams::default()
        };
        let raw = algo_codec::canonical_encode_account_application_model(Some(&ap), None);
        let state = extract_app_resource_state(&raw, "app-params", "gs").unwrap();
        let AppResourceState::Present(Some(entries)) = state else {
            panic!("expected Present(Some(entries)), got a different variant");
        };
        assert_eq!(entries, vec![(b"g".to_vec(), TealValue::Uint(7))]);
    }

    #[test]
    fn extract_app_resource_state_wrong_outer_key_is_not_present() {
        let ap = AppParams::default();
        let raw = algo_codec::canonical_encode_account_application_model(Some(&ap), None);
        // Asking for "app-local-state" when only "app-params" is present.
        let state = extract_app_resource_state(&raw, "app-local-state", "tkv").unwrap();
        assert!(matches!(state, AppResourceState::NotPresent));
    }
}
