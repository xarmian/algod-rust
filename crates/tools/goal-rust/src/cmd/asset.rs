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

//! `goal-rust asset create/destroy/config/send/freeze/optin/info` — port of
//! `../go-algorand/cmd/goal/asset.go` (issue #1466).
//!
//! Mirrors `crate::cmd::app`'s structure and helpers (transaction-header
//! resolution, wallet-signing submit path) but builds `AssetConfig`/
//! `AssetTransfer`/`AssetFreeze` transactions directly against
//! `algo_types::Transaction` fields — there's no `algo-txn-pipeline` builder
//! for asset transactions yet, unlike payment/keyreg/app-call.

use std::path::Path;
use std::process::ExitCode;

use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, decode_signed_txn_stream,
};
use algo_error::AlgoError;
use algo_rest_client::AlgodClient;
use algo_types::{Address, AssetParams, Round, SignedTransaction, Transaction, TxnType};
use base64::Engine;

use crate::accounts_list::AccountsList;
use crate::cmd::clerk::{
    build_algod_client_for_dir, build_kmd_client, compute_validity, kmd_msg, parse_lease,
    parse_note, resolve_max_txn_life, resolve_wallet_and_init,
};
use crate::data_dir;
use crate::groups::asset::{
    AssetLookupArgs, AssetTxnArgs, ConfigArgs, CreateArgs, DestroyArgs, FreezeArgs, InfoArgs,
    OptinArgs, SendArgs,
};

/// Run `f`, mapping an `Err` into the `eprintln!` + exit-1 shape every leaf
/// in this module reports failures with (mirrors `crate::cmd::app`'s
/// `run_and_report`).
fn run_and_report(f: impl FnOnce() -> Result<ExitCode, String>) -> ExitCode {
    match f() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

/// Resolve a possibly-empty account-name/address string through the
/// accounts list, the way every `asset` leaf resolves `--creator`/
/// `--manager`/`-f`/etc. An empty input stays empty (Go's
/// `accountList.getAddressByName("")` returns `""`, not the default
/// account, in the `asset` leaves that pre-check for emptiness themselves).
fn resolve_name(accounts: &AccountsList, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    accounts.address_for(name)
}

fn parse_addr(s: &str) -> Result<Address, String> {
    Address::from_algorand_string(s).map_err(|e| format!("Could not parse address {s}: {e}"))
}

/// The common fee/validity/note/lease/rekey header, resolved from
/// [`AssetTxnArgs`] against the network's suggested params. Mirrors
/// `crate::cmd::app::resolve_txn_header`.
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
    txn_args: &AssetTxnArgs,
    data_dir_path: &Path,
    params: &algo_rest_client::SuggestedParams,
) -> Result<TxnHeader, String> {
    let note = parse_note(txn_args.note_b64.as_deref(), txn_args.note.as_deref())?;
    let lease = parse_lease(txn_args.lease.as_deref())?;
    let rekey_to = txn_args
        .rekey_to
        .as_deref()
        .map(|r| Address::from_algorand_string(r).map_err(|e| format!("rekey-to invalid: {e}")))
        .transpose()?;
    let max_txn_life = resolve_max_txn_life(data_dir_path, &params.consensus_version)?;
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
        genesis_id: params.genesis_id.clone(),
        note,
        lease,
        rekey_to,
    })
}

/// Sign (via wallet) and either write to file or broadcast a single asset
/// transaction, reporting the txid the way Go's `asset` leaves do. Returns
/// the confirmed [`algo_rest_client::PendingTxnInfo`] (`None` when
/// `--no-wait` was given, or when the txn was written to a file). Mirrors
/// `crate::cmd::app::submit_single`.
fn submit_single(
    txn: Transaction,
    signer_addr: Option<Address>,
    txn_args: &AssetTxnArgs,
    wallet: Option<String>,
    data_dir_path: &Path,
    rt: &tokio::runtime::Runtime,
    algod: AlgodClient,
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

/// Resolve `--assetid`/`--unitname`+`--creator` into an asset id. Mirrors
/// Go's `lookupAssetID` (`asset.go:150-186`). `creator_resolved` is the
/// already-account-list-resolved `--creator` address (empty string if
/// unset).
fn lookup_asset_id(
    algod: &AlgodClient,
    rt: &tokio::runtime::Runtime,
    creator_resolved: &str,
    lookup: &AssetLookupArgs,
) -> Result<u64, String> {
    let unit_specified = lookup.unit_name.is_some();
    if lookup.asset_id != 0 && unit_specified {
        return Err(
            "Only one of [--assetid] or [--unitname and --creator] should be specified".to_string(),
        );
    }
    if lookup.asset_id != 0 {
        return Ok(lookup.asset_id);
    }
    if !unit_specified {
        return Err(
            "Missing required parameter [--assetid] or [--unitname and --creator] must \
                     be specified"
                .to_string(),
        );
    }
    if creator_resolved.is_empty() {
        return Err(
            "Asset creator must be specified if finding asset by name. Use the asset's \
                     integer identifier [--assetid] if the creator account is unknown."
                .to_string(),
        );
    }
    let unit_name = lookup.unit_name.as_deref().unwrap_or("");
    let creator_addr = parse_addr(creator_resolved)?;
    let info = rt
        .block_on(algod.get_account(&creator_addr))
        .map_err(|e| format!("{e}"))?;
    let created = info.created_assets.unwrap_or_default();

    let mut matches: Vec<u64> = Vec::new();
    for asset in &created {
        let Some(params) = &asset.params else {
            continue;
        };
        let entry_unit = params.unit_name.as_deref().unwrap_or("");
        if entry_unit == unit_name {
            matches.push(asset.index);
        }
    }

    match matches.len() {
        0 => Err(format!(
            "No matches for asset unit name {unit_name} in creator {creator_resolved}"
        )),
        1 => Ok(matches[0]),
        _ => Err(format!(
            "Multiple matches for asset unit name {unit_name} in creator {creator_resolved}"
        )),
    }
}

// ---------------------------------------------------------------------------
// asset create
// ---------------------------------------------------------------------------

/// `asset create --creator <addr> --total <n> [...] [txn]`.
///
/// Mirrors Go's `createAssetCmd` (`asset.go:189-291`).
pub fn run_create(args: CreateArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_create_inner(args, wallet))
}

fn run_create_inner(args: CreateArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    if !args.manager.is_empty() && args.no_manager {
        return Err(
            "The [--manager] flag and the [--no-manager] flag are mutually exclusive, \
                     do not provide both flags."
                .to_string(),
        );
    }
    if !args.reserve.is_empty() && args.no_reserve {
        return Err(
            "The [--reserve] flag and the [--no-reserve] flag are mutually exclusive, \
                     do not provide both flags."
                .to_string(),
        );
    }
    if !args.freezer.is_empty() && args.no_freezer {
        return Err(
            "The [--freezer] flag and the [--no-freezer] flag are mutually exclusive, \
                     do not provide both flags."
                .to_string(),
        );
    }
    if !args.clawback.is_empty() && args.no_clawback {
        return Err(
            "The [--clawback] flag and the [--no-clawback] flag are mutually exclusive, \
                     do not provide both flags."
                .to_string(),
        );
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let creator_resolved = accounts.address_for(&args.creator);
    let creator_addr = parse_addr(&creator_resolved)?;

    let manager = if args.no_manager {
        String::new()
    } else if !args.manager.is_empty() {
        resolve_name(&accounts, &args.manager)
    } else {
        creator_resolved.clone()
    };
    let reserve = if args.no_reserve {
        String::new()
    } else if !args.reserve.is_empty() {
        resolve_name(&accounts, &args.reserve)
    } else {
        creator_resolved.clone()
    };
    let freezer = if args.no_freezer {
        String::new()
    } else if !args.freezer.is_empty() {
        resolve_name(&accounts, &args.freezer)
    } else {
        creator_resolved.clone()
    };
    let clawback = if args.no_clawback {
        String::new()
    } else if !args.clawback.is_empty() {
        resolve_name(&accounts, &args.clawback)
    } else {
        creator_resolved.clone()
    };

    let metadata_hash = if args.asset_metadata_b64.is_empty() {
        None
    } else {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&args.asset_metadata_b64)
            .map_err(|e| {
                format!(
                    "Cannot base64-decode metadata hash {}: {e}",
                    args.asset_metadata_b64
                )
            })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "Cannot base64-decode metadata hash {}: decoded length {} != 32",
                args.asset_metadata_b64,
                v.len()
            )
        })?;
        Some(arr)
    };

    let asset_params = AssetParams {
        total: args.total,
        decimals: args.decimals,
        default_frozen: args.default_frozen,
        unit_name: args.unit_name.clone(),
        asset_name: args.name.clone(),
        url: args.asset_url.clone(),
        metadata_hash,
        manager: opt_addr(&manager)?,
        reserve: opt_addr(&reserve)?,
        freeze: opt_addr(&freezer)?,
        clawback: opt_addr(&clawback)?,
    };

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut txn = Transaction {
        txn_type: TxnType::Acfg,
        sender: creator_addr,
        fee: header.fee,
        first_valid: Round(header.first_valid),
        last_valid: Round(header.last_valid),
        genesis_id: header.genesis_id,
        genesis_hash: header.genesis_hash,
        note: header.note.into(),
        lease: header.lease,
        rekey_to: header.rekey_to,
        config_asset: 0,
        asset_params: Some(asset_params),
        ..Transaction::default()
    };
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    let info = submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
    )?;
    if let Some(info) = info {
        if let Some(idx) = info.asset_index.filter(|i| *i != 0) {
            println!("Created asset with asset index {idx}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Resolve a possibly-empty address string into `Option<Address>` the way an
/// empty manager/reserve/freeze/clawback means "no such role" in
/// [`AssetParams`].
fn opt_addr(s: &str) -> Result<Option<Address>, String> {
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parse_addr(s)?))
    }
}

// ---------------------------------------------------------------------------
// asset destroy
// ---------------------------------------------------------------------------

/// `asset destroy [--manager addr] [--creator addr] [--assetid id |
/// --unitname s] [txn]`.
///
/// Mirrors Go's `destroyAssetCmd` (`asset.go:294-361`).
pub fn run_destroy(args: DestroyArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_destroy_inner(args, wallet))
}

fn run_destroy_inner(args: DestroyArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);

    if args.manager.is_empty() && args.creator.is_empty() {
        return Err("Missing required parameter [--manager] or [--creator]".to_string());
    }
    let manager_name = if args.manager.is_empty() {
        args.creator.clone()
    } else {
        args.manager.clone()
    };

    let creator_resolved = resolve_name(&accounts, &args.creator);
    let manager_resolved = resolve_name(&accounts, &manager_name);
    let manager_addr = parse_addr(&manager_resolved)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut txn = Transaction {
        txn_type: TxnType::Acfg,
        sender: manager_addr,
        fee: header.fee,
        first_valid: Round(header.first_valid),
        last_valid: Round(header.last_valid),
        genesis_id: header.genesis_id,
        genesis_hash: header.genesis_hash,
        note: header.note.into(),
        lease: header.lease,
        rekey_to: header.rekey_to,
        config_asset: asset_id,
        asset_params: None,
        ..Transaction::default()
    };
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
    )?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// asset config
// ---------------------------------------------------------------------------

/// `asset config --manager <addr> [...] [txn]`.
///
/// Mirrors Go's `configAssetCmd` (`asset.go:412-467`).
pub fn run_config(args: ConfigArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_config_inner(args, wallet))
}

fn run_config_inner(args: ConfigArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);

    let creator_name = if args.creator.is_empty() {
        args.manager.clone()
    } else {
        args.creator.clone()
    };
    let creator_resolved = resolve_name(&accounts, &creator_name);
    let manager_resolved = resolve_name(&accounts, &args.manager);
    let manager_addr = parse_addr(&manager_resolved)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;
    let creator_addr = parse_addr(&creator_resolved)?;

    // Mirrors Go's `client.MakeUnsignedAssetConfigTx`
    // (`libgoal/transactions.go`): fetch the asset's current params and
    // apply only the new-manager/reserve/freeze/clawback overrides the CLI
    // was given, leaving every other field as-is.
    let current = rt
        .block_on(algod.get_asset(asset_id))
        .map_err(|e| format!("Error processing command: {e}"))?;

    let resolve_new = |flag: &Option<String>| -> Result<Option<String>, String> {
        match flag {
            None => Ok(None),
            Some(s) => Ok(Some(resolve_name(&accounts, s))),
        }
    };
    let new_manager = resolve_new(&args.new_manager)?;
    let new_reserve = resolve_new(&args.new_reserve)?;
    let new_freezer = resolve_new(&args.new_freezer)?;
    let new_clawback = resolve_new(&args.new_clawback)?;

    let asset_params = AssetParams {
        total: current.params.total,
        decimals: current.params.decimals as u32,
        default_frozen: current.params.default_frozen,
        unit_name: current.params.unit_name.clone().unwrap_or_default(),
        asset_name: current.params.name.clone().unwrap_or_default(),
        url: current.params.url.clone().unwrap_or_default(),
        metadata_hash: current
            .params
            .metadata_hash
            .clone()
            .and_then(|v| v.try_into().ok()),
        manager: match new_manager {
            Some(s) => opt_addr(&s)?,
            None => current
                .params
                .manager
                .as_deref()
                .map(parse_addr)
                .transpose()?,
        },
        reserve: match new_reserve {
            Some(s) => opt_addr(&s)?,
            None => current
                .params
                .reserve
                .as_deref()
                .map(parse_addr)
                .transpose()?,
        },
        freeze: match new_freezer {
            Some(s) => opt_addr(&s)?,
            None => current
                .params
                .freeze
                .as_deref()
                .map(parse_addr)
                .transpose()?,
        },
        clawback: match new_clawback {
            Some(s) => opt_addr(&s)?,
            None => current
                .params
                .clawback
                .as_deref()
                .map(parse_addr)
                .transpose()?,
        },
    };

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let _ = creator_addr;
    let mut txn = Transaction {
        txn_type: TxnType::Acfg,
        sender: manager_addr,
        fee: header.fee,
        first_valid: Round(header.first_valid),
        last_valid: Round(header.last_valid),
        genesis_id: header.genesis_id,
        genesis_hash: header.genesis_hash,
        note: header.note.into(),
        lease: header.lease,
        rekey_to: header.rekey_to,
        config_asset: asset_id,
        asset_params: Some(asset_params),
        ..Transaction::default()
    };
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
    )?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// asset send / optin (shared MakeUnsignedAssetSendTx path)
// ---------------------------------------------------------------------------

/// Build and submit an `AssetTransfer` transaction. Shared by `asset send`
/// and `asset optin` (Go's `MakeUnsignedAssetSendTx`, called by both
/// `sendAssetCmd` and `optinAssetCmd` — `optin` is just `send` with a
/// zero amount, sender == receiver, and no clawback/close-to).
#[allow(clippy::too_many_arguments)]
fn submit_asset_send(
    asset_id: u64,
    amount: u64,
    to_resolved: &str,
    close_to_resolved: &str,
    sender_for_clawback: &str,
    sender_resolved: &str,
    txn_args: &AssetTxnArgs,
    wallet: Option<String>,
    data_dir_path: &Path,
    algod: AlgodClient,
) -> Result<Option<algo_rest_client::PendingTxnInfo>, String> {
    // Mirrors Go's `client.MakeUnsignedAssetSendTx(assetID, amount, to,
    // closeTo, senderForClawback)`: when a clawback sender is given, the
    // *transaction* sender is the clawback account and `AssetSender` names
    // the account the funds are clawed back from; otherwise the sender is
    // the account moving its own holding and `AssetSender` is unset.
    let (txn_sender, asset_sender) = if !sender_for_clawback.is_empty() {
        (sender_for_clawback, Some(sender_resolved))
    } else {
        (sender_resolved, None)
    };
    let sender_addr = parse_addr(txn_sender)?;
    let to_addr = parse_addr(to_resolved)?;
    let asset_sender_addr = asset_sender.map(parse_addr).transpose()?;
    let close_to_addr = if close_to_resolved.is_empty() {
        None
    } else {
        Some(parse_addr(close_to_resolved)?)
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(txn_args, data_dir_path, &params)?;

    let signer_addr = txn_args
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut txn = Transaction {
        txn_type: TxnType::Axfer,
        sender: sender_addr,
        fee: header.fee,
        first_valid: Round(header.first_valid),
        last_valid: Round(header.last_valid),
        genesis_id: header.genesis_id,
        genesis_hash: header.genesis_hash,
        note: header.note.into(),
        lease: header.lease,
        rekey_to: header.rekey_to,
        xaid: asset_id,
        asset_amount: amount,
        asset_receiver: Some(to_addr),
        asset_sender: asset_sender_addr,
        asset_close_to: close_to_addr,
        ..Transaction::default()
    };
    if txn_args.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    submit_single(
        txn,
        signer_addr,
        txn_args,
        wallet,
        data_dir_path,
        &rt,
        algod,
    )
}

/// `asset send [--clawback addr] [--creator addr] [--assetid id |
/// --unitname s] -f <from> -t <to> -a <amount> [-c <close-to>] [txn]`.
///
/// Mirrors Go's `sendAssetCmd` (`asset.go:503-576`).
pub fn run_send(args: SendArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_send_inner(args, wallet))
}

fn run_send_inner(args: SendArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);

    let from_name = if args.from.is_empty() {
        accounts.default_account.clone()
    } else {
        args.from.clone()
    };
    if from_name.is_empty() {
        return Err("no default account set; specify the sender with -f/--from".to_string());
    }
    let mut sender_resolved = resolve_name(&accounts, &from_name);
    let to_resolved = resolve_name(&accounts, &args.to);
    let creator_resolved = resolve_name(&accounts, &args.creator);

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;
    drop(rt);

    let clawback_resolved = if args.clawback.is_empty() {
        String::new()
    } else {
        resolve_name(&accounts, &args.clawback)
    };
    let sender_for_clawback = if clawback_resolved.is_empty() {
        String::new()
    } else {
        let for_clawback = sender_resolved.clone();
        sender_resolved = clawback_resolved;
        for_clawback
    };
    let close_to_resolved = if args.close_to.is_empty() {
        String::new()
    } else {
        resolve_name(&accounts, &args.close_to)
    };

    submit_asset_send(
        asset_id,
        args.amount,
        &to_resolved,
        &close_to_resolved,
        &sender_for_clawback,
        &sender_resolved,
        &args.txn,
        wallet,
        &data_dir_path,
        algod,
    )?;
    Ok(ExitCode::SUCCESS)
}

/// `asset optin [--unitname s] [--assetid id] [-a <account>]
/// [--creator addr] [txn]`.
///
/// Mirrors Go's `optinAssetCmd` (`asset.go:679-742`): a zero-amount
/// self-transfer.
pub fn run_optin(args: OptinArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_optin_inner(args, wallet))
}

fn run_optin_inner(args: OptinArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let creator_resolved = resolve_name(&accounts, &args.creator);

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;
    drop(rt);

    let account_name = if args.account.is_empty() {
        accounts.default_account.clone()
    } else {
        args.account.clone()
    };
    if account_name.is_empty() {
        return Err("no default account set; specify the account with -a/--account".to_string());
    }
    let account_resolved = resolve_name(&accounts, &account_name);

    submit_asset_send(
        asset_id,
        0,
        &account_resolved,
        "",
        "",
        &account_resolved,
        &args.txn,
        wallet,
        &data_dir_path,
        algod,
    )?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// asset freeze
// ---------------------------------------------------------------------------

/// `asset freeze --freezer <addr> [--creator addr] [--assetid id |
/// --unitname s] --account <addr> --freeze <bool> [txn]`.
///
/// Mirrors Go's `freezeAssetCmd` (`asset.go:594-655`).
pub fn run_freeze(args: FreezeArgs, wallet: Option<String>) -> ExitCode {
    run_and_report(|| run_freeze_inner(args, wallet))
}

fn run_freeze_inner(args: FreezeArgs, wallet: Option<String>) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let freezer_resolved = resolve_name(&accounts, &args.freezer);
    let freezer_addr = parse_addr(&freezer_resolved)?;
    let creator_resolved = resolve_name(&accounts, &args.creator);
    let account_resolved = resolve_name(&accounts, &args.account);
    let account_addr = parse_addr(&account_resolved)?;

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;

    let params = rt
        .block_on(algod.suggested_transaction_params())
        .map_err(|e| e.to_string())?;
    let header = resolve_txn_header(&args.txn, &data_dir_path, &params)?;

    let signer_addr = args
        .txn
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let mut txn = Transaction {
        txn_type: TxnType::Afrz,
        sender: freezer_addr,
        fee: header.fee,
        first_valid: Round(header.first_valid),
        last_valid: Round(header.last_valid),
        genesis_id: header.genesis_id,
        genesis_hash: header.genesis_hash,
        note: header.note.into(),
        lease: header.lease,
        rekey_to: header.rekey_to,
        freeze_asset: asset_id,
        freeze_account: Some(account_addr),
        asset_frozen: args.freeze,
        ..Transaction::default()
    };
    if args.txn.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    submit_single(
        txn,
        signer_addr,
        &args.txn,
        wallet,
        &data_dir_path,
        &rt,
        algod,
    )?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// asset info
// ---------------------------------------------------------------------------

/// `assetDecimalsFmt`: format `amount` with `decimals` digits after the
/// decimal point (Go's `asset.go:668-677`).
fn asset_decimals_fmt(amount: u64, decimals: u64) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let pow = 10u64.pow(decimals as u32);
    format!(
        "{}.{:0width$}",
        amount / pow,
        amount % pow,
        width = decimals as usize
    )
}

/// `asset info [--assetid id | --unitname s] [--creator addr]`.
///
/// Mirrors Go's `infoAssetCmd` (`asset.go:748-827`).
pub fn run_info(args: InfoArgs) -> ExitCode {
    run_and_report(|| run_info_inner(args))
}

fn run_info_inner(args: InfoArgs) -> Result<ExitCode, String> {
    let data_dir_path = data_dir::ensure_single_data_dir(&crate::cli_state::datadirs())
        .map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);
    let creator_resolved = resolve_name(&accounts, &args.creator);

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let asset_id = lookup_asset_id(&algod, &rt, &creator_resolved, &args.lookup)?;

    let asset = rt
        .block_on(algod.get_asset(asset_id))
        .map_err(|e| format!("Error processing command: {e}"))?;

    let (reserve_empty, reserve_addr) = match &asset.params.reserve {
        Some(r) if !r.is_empty() => (false, r.clone()),
        _ => (true, asset.params.creator.clone()),
    };

    let mut reserve_amount = 0u64;
    match rt.block_on(algod.get_account_asset(&reserve_addr, asset_id)) {
        Ok(holding) => {
            if let Some(h) = holding.asset_holding {
                reserve_amount = h.amount;
            }
        }
        Err(AlgoError::NotFound(_)) => {}
        Err(e) => return Err(format!("Error processing command: {e}")),
    }

    println!("Asset ID:         {asset_id}");
    println!("Creator:          {}", asset.params.creator);
    println!(
        "Asset name: {}",
        asset.params.name.as_deref().unwrap_or("<unnamed>")
    );
    let units = asset
        .params
        .unit_name
        .clone()
        .unwrap_or_else(|| "units".to_string());
    println!("Unit name:        {units}");
    println!(
        "Maximum issue:    {} {units}",
        asset_decimals_fmt(asset.params.total, asset.params.decimals)
    );
    println!(
        "Reserve amount:   {} {units}",
        asset_decimals_fmt(reserve_amount, asset.params.decimals)
    );
    println!(
        "Issued:           {} {units}",
        asset_decimals_fmt(
            asset.params.total.saturating_sub(reserve_amount),
            asset.params.decimals
        )
    );
    println!("Decimals:         {}", asset.params.decimals);
    println!("Default frozen:   {}", asset.params.default_frozen);
    println!("URL: {}", asset.params.url.clone().unwrap_or_default());
    println!(
        "Manager address:  {}",
        asset.params.manager.clone().unwrap_or_default()
    );
    if reserve_empty {
        println!(
            "Reserve address:  {} (Empty. Defaulting to creator)",
            asset.params.reserve.clone().unwrap_or_default()
        );
    } else {
        println!(
            "Reserve address:  {}",
            asset.params.reserve.clone().unwrap_or_default()
        );
    }
    println!(
        "Freeze address:   {}",
        asset.params.freeze.clone().unwrap_or_default()
    );
    println!(
        "Clawback address: {}",
        asset.params.clawback.clone().unwrap_or_default()
    );

    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::asset::AssetLookupArgs;

    // ---- asset_decimals_fmt -------------------------------------------
    // Direct port of go's `assetDecimalsFmt` (`asset.go:668-677`).

    #[test]
    fn asset_decimals_fmt_zero_decimals_is_raw_integer() {
        assert_eq!(asset_decimals_fmt(12345, 0), "12345");
    }

    #[test]
    fn asset_decimals_fmt_pads_fractional_digits() {
        // 12345 with 3 decimals -> 12.345
        assert_eq!(asset_decimals_fmt(12345, 3), "12.345");
        // 5 with 3 decimals -> 0.005 (zero-padded)
        assert_eq!(asset_decimals_fmt(5, 3), "0.005");
    }

    #[test]
    fn asset_decimals_fmt_two_decimals_matches_go_example() {
        assert_eq!(asset_decimals_fmt(100, 2), "1.00");
        assert_eq!(asset_decimals_fmt(1, 2), "0.01");
    }

    // ---- opt_addr -------------------------------------------------------

    #[test]
    fn opt_addr_empty_string_is_none() {
        assert_eq!(opt_addr("").unwrap(), None);
    }

    #[test]
    fn opt_addr_invalid_address_errors() {
        assert!(opt_addr("not-an-address").is_err());
    }

    // ---- resolve_name -----------------------------------------------------

    #[test]
    fn resolve_name_empty_stays_empty() {
        let dir = tempfile::tempdir().unwrap();
        let accounts = AccountsList::new_empty(dir.path());
        assert_eq!(resolve_name(&accounts, ""), "");
    }

    // ---- lookup_asset_id: the flag-shape validation paths that don't need
    // network I/O (both-flags-given / neither-flag-given / missing-creator).
    // Mirrors go's `lookupAssetID` (`asset.go:150-186`) error messages.

    fn dummy_client() -> AlgodClient {
        AlgodClient::new("http://127.0.0.1:1", "dummy-token")
    }

    #[test]
    fn lookup_asset_id_returns_assetid_directly_when_given() {
        let algod = dummy_client();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lookup = AssetLookupArgs {
            asset_id: 42,
            unit_name: None,
        };
        let id = lookup_asset_id(&algod, &rt, "", &lookup).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn lookup_asset_id_rejects_both_assetid_and_unitname() {
        let algod = dummy_client();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lookup = AssetLookupArgs {
            asset_id: 42,
            unit_name: Some("usdc".to_string()),
        };
        let err = lookup_asset_id(&algod, &rt, "", &lookup).unwrap_err();
        assert!(
            err.contains("Only one of [--assetid] or [--unitname and --creator]"),
            "got: {err}"
        );
    }

    #[test]
    fn lookup_asset_id_rejects_neither_assetid_nor_unitname() {
        let algod = dummy_client();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lookup = AssetLookupArgs {
            asset_id: 0,
            unit_name: None,
        };
        let err = lookup_asset_id(&algod, &rt, "", &lookup).unwrap_err();
        assert!(
            err.contains("Missing required parameter [--assetid]"),
            "got: {err}"
        );
    }

    #[test]
    fn lookup_asset_id_rejects_unitname_without_creator() {
        let algod = dummy_client();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lookup = AssetLookupArgs {
            asset_id: 0,
            unit_name: Some("usdc".to_string()),
        };
        let err = lookup_asset_id(&algod, &rt, "", &lookup).unwrap_err();
        assert!(
            err.contains("Asset creator must be specified"),
            "got: {err}"
        );
    }
}
