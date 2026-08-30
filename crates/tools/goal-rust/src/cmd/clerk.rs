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

//! `goal-rust clerk` leaf handlers.
//!
//! Ports the payment path + offline txn-file utilities of
//! `../go-algorand/cmd/goal/clerk.go`:
//! - `send` → clerk.go:348-576 (`sendCmd`), via `libgoal.ConstructPayment`
//!   (libgoal.go:571) and `computeValidityRounds` (libgoal.go:525).
//! - `inspect` → clerk.go:712 (`inspectCmd`) + `inspect.go` (`inspectTxn`).
//! - `split` → clerk.go:966 (`splitCmd`).
//! - `group` → clerk.go:914 (`groupCmd`).
//! - `rawsend` → clerk.go:579 (`rawsendCmd`).
//! - `sign` → clerk.go:787 (`signCmd`) — wallet (kmd) and LogicSig signing.
//! - `tealsign` → `cmd/goal/tealsign.go` — domain-separated data signing for
//!   the `ed25519verify` opcode.
//!
//! Signing + submission reuse the same build → sign (kmd) → submit → confirm
//! pipeline as the account keyreg leaves
//! ([`algo_txn_pipeline::TxnPipeline`]); the wallet-handle resolution mirrors
//! `crate::cmd::account` (Go's `getWalletHandleMaybePassword`). The shared
//! LogicSig / multisig signing helpers live in [`crate::cmd::clerk_sign`].
//!
//! The rest of the `clerk` group (compile / simulate / multisig) is
//! still stubbed — see [`crate::groups::clerk`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_codec::{
    canonical_encode_signed_transaction, compute_group_id, compute_txn_id, decode_signed_txn_stream,
};
use algo_kmd_client::{KmdClient, KmdError};
use algo_types::{Address, SignedTransaction};
use base64::Engine;

use crate::accounts_list::AccountsList;
use crate::cmd::clerk_sign;
use crate::data_dir;
use crate::groups::clerk::{
    GroupArgs, InspectArgs, MultisigMergeArgs, MultisigSignArgs, MultisigSignProgramArgs,
    RawsendArgs, SendArgs, SignArgs, SimulateArgs, SplitArgs, TealsignArgs,
};

/// Typical protocol `MaxTxnLife` (rounds). The consensus-param table isn't
/// loaded client-side, so the validity-window default uses this — matching the
/// assumption already made by `crate::cmd::account::compute_validity`
/// (go-algorand's `computeValidityRounds` uses the protocol's `MaxTxnLife`).
const MAX_TXN_LIFE: u64 = 1000;

/// Mirrors Go's `Could not contact kmd; is it running?` error path.
const ERROR_KMD_UNREACHABLE: &str = "Could not contact kmd; is it running?";

// ---- clerk send -----------------------------------------------------------

/// `clerk send -a <amt> -f <from> -t <to> [-c close] [--rekey-to] [--fee]
/// [--firstvalid/--lastvalid/--validrounds] [--note/--noteb64] [--lease]
/// [-F prog | -P progbytes | -L lsig] [--argb64 ...] [--msig-params ...]
/// [-S signer] [-N] [-o out [-s]] [-w wallet] [--password]`.
///
/// Mirrors Go's `sendCmd` (clerk.go:348-576), including the LogicSig /
/// program-account (`--from-program/-F`, `--from-program-bytes/-P`,
/// `--logic-sig/-L`, `--argb64`) and `--msig-params` paths, which reuse the
/// shared signing helpers in [`crate::cmd::clerk_sign`].
pub fn run_send(
    args: SendArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match run_send_inner(args, wallet, cli_d, kmd_dir_flag) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_send_inner(
    args: SendArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> Result<ExitCode, String> {
    // -s is invalid without -o (clerk.go:354-357, soFlagError).
    if args.out.is_none() && args.sign {
        return Err("-s is not meaningful without -o".to_string());
    }

    // --msig-params is invalid without -o (clerk.go:359-362, noOutputFileError).
    if args.out.is_none() && args.msig_params.is_some() {
        return Err("--msig-params must be specified with an output file name (-o)".to_string());
    }

    // Validity-period flag guards (commands.go:543-551).
    if args.valid_rounds.is_some() && args.last_valid.is_some() {
        return Err("Only one of [--validrounds] or [--lastvalid] can be specified".to_string());
    }
    if matches!(args.valid_rounds, Some(0)) {
        return Err("[--validrounds] can not be zero".to_string());
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);

    // Resolve the program/LogicSig source (clerk.go:370-396). Exactly one of
    // `-P/--from-program-bytes` (raw bytes), `-F/--from-program` (TEAL source),
    // or `-L/--logic-sig` (msgpack LogicSig file) may be set; `--argb64` supplies
    // the program args (overriding any args in a `-L` file). The `program_account`
    // variant (`-F`/`-P`) makes the sender default to the program's escrow
    // address and attaches the LogicSig with the resolved AuthAddr, while the
    // `delegated` variant (`-L`) runs the LogicSig sanity check and attaches the
    // LogicSig verbatim — matching Go's two distinct branches.
    let resolved_lsig = resolve_send_lsig(
        args.from_program.as_deref(),
        args.from_program_bytes.as_deref(),
        args.logic_sig.as_deref(),
        &args.argb64,
    )?;

    // Resolve from (default account if unset) + to via the accountList name map
    // (clerk.go:388-403). With a `-F`/`-P` program account and no `-f`, the
    // sender defaults to the program's escrow address (clerk.go:388-396);
    // otherwise Go falls back to the default account when `-f` is empty.
    let from_name = match args.from {
        Some(f) => f,
        None => match resolved_lsig.as_ref() {
            Some(r) if r.is_program_account => r.escrow_address.to_algorand_string(),
            _ => {
                let def = accounts.default_account.clone();
                if def.is_empty() {
                    return Err(
                        "no default account set; specify the sender with -f/--from".to_string()
                    );
                }
                def
            }
        },
    };
    let from_resolved = accounts.address_for(&from_name);
    let to_resolved = accounts.address_for(&args.to);

    let from_addr = Address::from_algorand_string(&from_resolved)
        .map_err(|e| format!("Could not parse from address {from_resolved}: {e}"))?;
    let to_addr = Address::from_algorand_string(&to_resolved)
        .map_err(|e| format!("Could not parse to address {to_resolved}: {e}"))?;

    // Note: --noteb64 wins over --note; otherwise Go fills 8 random bytes so
    // back-to-back identical payments get distinct txids (clerk.go:314-331).
    let note = parse_note(args.note_b64.as_deref(), args.note.as_deref())?;
    let lease = parse_lease(args.lease.as_deref())?;

    let close_resolved = args
        .close_to
        .as_deref()
        .map(|c| accounts.address_for(c))
        .map(|c| {
            Address::from_algorand_string(&c).map_err(|e| format!("Could not parse close-to: {e}"))
        })
        .transpose()?;
    let rekey_addr = args
        .rekey_to
        .as_deref()
        .map(|r| Address::from_algorand_string(r).map_err(|e| format!("rekey-to invalid: {e}")))
        .transpose()?;

    // Resolve --signer/-S into an AuthAddr; it must differ from the sender
    // (clerk.go:271-277). Applied on the program-account and wallet paths.
    let auth_addr = args
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;
    if let Some(signer) = auth_addr {
        if signer == from_addr {
            return Err("AuthAddr cannot be the same as the transaction sender".to_string());
        }
    }

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Request failed: {e}"))?;

    // The wallet (kmd) is only needed when no LogicSig source was supplied AND we
    // intend to sign: `signTx := sign || (out == "")` (clerk.go:495). With a
    // LogicSig (`-F`/`-P`/`-L`) the txn is self-authorized, so kmd is never
    // contacted, even when broadcasting (clerk.go:464-490).
    let want_wallet_signature = resolved_lsig.is_none() && (args.out.is_none() || args.sign);
    let kmd = if want_wallet_signature {
        Some(build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref())?)
    } else {
        None
    };
    let pipeline = algo_txn_pipeline::TxnPipeline::new(algod, kmd);

    // Build the payment: resolve validity off suggested params (Go's
    // ComputeValidityRounds + ConstructPayment), then the fee.
    let params = rt
        .block_on(pipeline.suggested_params())
        .map_err(|e| e.to_string())?;
    let (first, last) = compute_validity(
        args.first_valid,
        args.last_valid,
        args.valid_rounds,
        params.last_round,
    )?;
    let mut builder = algo_txn_pipeline::PaymentBuilder::new(from_addr, to_addr, args.amount)
        .fee(args.fee.unwrap_or(0))
        .validity(first, last)
        .genesis_hash(params.genesis_hash.0)
        .genesis_id(params.genesis_id.clone())
        .note(note)
        .lease(lease);
    if let Some(close) = close_resolved {
        builder = builder.close_remainder_to(close);
    }
    if let Some(rekey) = rekey_addr {
        builder = builder.rekey_to(rekey);
    }
    let mut txn = builder.build().map_err(|e| e.to_string())?;

    // ConstructPayment fills the suggested fee only when --fee is *unset*. An
    // explicit `--fee 0` is INTENTIONALLY kept at 0 (not bumped to the
    // suggested/min fee): Go's sendCmd keys this on `cmd.Flags().Changed("fee")`
    // and the comment at clerk.go:441-447 spells out that a deliberate
    // `--fee=0` should be honored verbatim, since zero/low fees make sense in a
    // group where another txn covers the pooled fee. Matching Go faithfully
    // here, so a standalone `--fee 0` send may be rejected by min-fee
    // validation exactly as Go's would.
    if args.fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }

    let last_valid = txn.last_valid.0;

    // Assemble the SignedTxn (`stx`) per the active path (clerk.go:464-505):
    //  - delegated LogicSig (`-L`): run the LogicSig sanity check and attach the
    //    LogicSig verbatim (no AuthAddr override) — clerk.go:464-481;
    //  - program account (`-F`/`-P`): attach the LogicSig with the resolved
    //    AuthAddr (no sanity check) — clerk.go:482-489;
    //  - wallet: kmd-sign the body when `signTx` (sign || out==""), else emit a
    //    blank-sig SignedTxn — clerk.go:490-505.
    let want_wallet_sign = args.out.is_none() || args.sign;
    let mut stx = if let Some(resolved) = resolved_lsig.as_ref() {
        let mut s = SignedTransaction {
            txn: txn.clone(),
            lsig: Some(resolved.lsig.clone()),
            ..SignedTransaction::default()
        };
        if resolved.is_program_account {
            // Program-account path: set the AuthAddr (clerk.go:484-488). Go runs
            // no sanity check here; the node verifies on submit.
            s.auth_addr = auth_addr;
        } else {
            // Delegated LogicSig path: structural + delegation sanity check
            // before broadcast (clerk.go:465-481, verify.LogicSigSanityCheck),
            // split the same way `clerk sign` does (see run_sign_inner).
            clerk_sign::logicsig_program_check(&resolved.lsig)
                .map_err(|e| format!("{}: txn error {e}", out_label(args.out.as_deref())))?;
            algo_validate::logicsig_sanity_check(&s, &resolved.lsig)
                .map_err(|e| format!("{}: txn error {e}", out_label(args.out.as_deref())))?;
        }
        s
    } else if want_wallet_sign {
        // Wallet path: kmd-sign the txn body, then decode the returned SignedTxn
        // so we can (a) apply the rekey AuthAddr and (b) attach --msig-params.
        //
        // With `-S/--signer` (the rekey case) kmd must sign with the *signer's*
        // key, not the sender's, so pass `signer.0` as the requested key —
        // mirroring Go's `SignTransactionWithWalletAndSigner` (clerk.go:244) and
        // the same call `run_sign_inner` makes. Using `sign_with_kmd` here would
        // force kmd to infer the sender key (`[0u8; 32]`), which for a rekeyed
        // account either fails (sender key not in the wallet) or emits a
        // signature by the *old* sender that won't verify against the AuthAddr.
        let kmd = pipeline.kmd().ok_or("no kmd client configured")?;
        let mut accounts = AccountsList::load(&data_dir_path);
        let (handle, _wallet_name, password) = resolve_wallet_and_init(
            &rt,
            kmd,
            &mut accounts,
            wallet.as_deref(),
            args.password.as_deref(),
        )?;
        let signer_pk: [u8; 32] = auth_addr.map(|a| a.0).unwrap_or([0u8; 32]);
        let encoded = algo_codec::canonical_encode_transaction(&txn);
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
        // The kmd-rust server signs with the requested key but leaves `sgnr`
        // unset (TASK-216), so set the AuthAddr here when `--signer` differs
        // from the sender (mirrors `createSignedTransaction(.., authAddr)`,
        // clerk.go:498, and `Transaction.Sign`, transaction.go:271-274).
        if auth_addr.is_some() {
            s.auth_addr = auth_addr;
        }
        s
    } else {
        // -o without -s and no LogicSig: a blank-sig SignedTxn so msgpack still
        // encodes the txn type, matching Go's `AssembleSignedTxn(tx, Signature{},
        // MultisigSig{})`. A --signer here would never be honored, matching Go's
        // "Signer specified when txn won't be signed" guard (clerk.go:491-494).
        if auth_addr.is_some() {
            return Err("Signer specified when txn won't be signed".to_string());
        }
        SignedTransaction {
            txn: txn.clone(),
            ..SignedTransaction::default()
        }
    };

    // --msig-params: the sender was rekeyed to a multisig account. Attach the
    // blank multisig preimage and set the AuthAddr to the derived multisig
    // address (clerk.go:507-543). The output-file guard above ensures `-o` is set.
    //
    // The msig preimage *is* the authorization: the multisig signers fill it in
    // later (`clerk multisig sign`). Any signature attached by the branches above
    // is meaningless here, so clear it. Go's normal flow is `-o` without `-s`,
    // where the wallet branch already produced a blank-sig SignedTxn so there is
    // nothing to clear; this only diverges from Go's *literal* behavior for the
    // pathological `-o -s --msig-params` combination, where Go leaves the
    // wallet's top-level `Sig` set alongside `Msig` and emits an unsubmittable
    // dual-signed txn ("should only have one signature"). Clearing it keeps every
    // `--msig-params` output a valid single-authorization txn.
    if let Some(params_str) = args.msig_params.as_deref() {
        let pre = clerk_sign::parse_msig_params(params_str)?;
        if pre.address == txn.sender {
            return Err("AuthAddr cannot be the same as the transaction sender".to_string());
        }
        stx.sig = [0u8; 64];
        stx.lsig = None;
        stx.msig = Some(pre.msig);
        stx.auth_addr = Some(pre.address);
    }

    // --out: write the SignedTxn to a file instead of broadcasting
    // (clerk.go:565-573).
    if let Some(out_path) = args.out {
        let encoded = canonical_encode_signed_transaction(&stx);
        std::fs::write(&out_path, &encoded)
            .map_err(|e| format!("Cannot write file {}: {e}", out_path.display()))?;
        return Ok(ExitCode::SUCCESS);
    }

    // Broadcast path: submit the assembled SignedTxn, report, optionally wait.
    let encoded_stx = canonical_encode_signed_transaction(&stx);
    let result = rt.block_on(async {
        let txid = pipeline
            .submit(&encoded_stx)
            .await
            .map_err(|e| format!("Couldn't broadcast tx with algod: {e}"))?;

        // infoTxIssued (messages.go:112): the fee reported is the txn's actual fee.
        println!(
            "Sent {} MicroAlgos from account {} to address {}, transaction ID: {}. Fee set to {}",
            args.amount, from_resolved, to_resolved, txid, txn.fee
        );

        if args.no_wait {
            return Ok::<(), String>(());
        }
        let info = pipeline
            .wait_for_confirmation(&txid, last_valid)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(round) = info.confirmed_round {
            // infoTxCommitted (messages.go:113).
            println!("Transaction {txid} committed in round {round}");
        }
        Ok(())
    });
    result?;
    Ok(ExitCode::SUCCESS)
}

/// The label Go uses in LogicSig sanity-check errors: the output filename, or an
/// empty string when broadcasting (Go's `outFilename`, clerk.go:478). Matches
/// Go's `"%s: txn error %s"` formatting for both the `-o` and broadcast cases.
fn out_label(out: Option<&Path>) -> String {
    out.map(|p| p.display().to_string()).unwrap_or_default()
}

/// A LogicSig resolved from `clerk send`'s `-F`/`-P`/`-L` flags, plus whether it
/// is a *program account* (`-F`/`-P`, which drives the sender-default + AuthAddr
/// behavior) vs a *delegated* LogicSig (`-L`).
#[derive(Debug)]
struct ResolvedSendLsig {
    lsig: algo_types::LogicSig,
    /// `-F`/`-P`: the program acts as the account (sender defaults to its escrow
    /// address; AuthAddr from `--signer` is attached). `-L` is a delegated
    /// LogicSig (`false`).
    is_program_account: bool,
    /// The program's escrow address (`HashProgram`), used as the default sender
    /// for a program account. Only meaningful when `is_program_account`.
    escrow_address: Address,
}

/// Resolve `clerk send`'s LogicSig source flags, mirroring Go's `sendCmd`
/// (clerk.go:370-396). At most one of `-P/--from-program-bytes` (raw program
/// bytes), `-F/--from-program` (TEAL source), or `-L/--logic-sig` (msgpack
/// LogicSig file) may be set. `-F`/`-L` reuse [`clerk_sign::lsig_from_args`];
/// `-P` builds the LogicSig from the raw bytes directly. `--argb64` supplies the
/// program args in all cases. Returns `Ok(None)` when no source flag is set.
fn resolve_send_lsig(
    from_program: Option<&str>,
    from_program_bytes: Option<&str>,
    logic_sig_file: Option<&str>,
    arg_b64: &[String],
) -> Result<Option<ResolvedSendLsig>, String> {
    const COLLISION: &str = "should use at most one of --from-program/-F or \
                             --from-program-bytes/-P --logic-sig/-L";
    match (from_program_bytes, from_program, logic_sig_file) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            Err(COLLISION.into())
        }
        (Some(file), None, None) => {
            // `-P`: raw program bytes; build the LogicSig with --argb64 args.
            let program = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            let args = clerk_sign::parse_arg_b64(arg_b64)?;
            let args_field = if args.is_empty() {
                None
            } else {
                Some(args.into_iter().map(serde_bytes::ByteBuf::from).collect())
            };
            let escrow_address = clerk_sign::program_address(&program);
            Ok(Some(ResolvedSendLsig {
                lsig: algo_types::LogicSig {
                    logic: serde_bytes::ByteBuf::from(program),
                    args: args_field,
                    ..algo_types::LogicSig::default()
                },
                is_program_account: true,
                escrow_address,
            }))
        }
        (None, Some(_), None) => {
            // `-F`: TEAL source → assemble (program account).
            let lsig = match clerk_sign::lsig_from_args(from_program, None, arg_b64)? {
                Some(l) => l,
                None => return Ok(None),
            };
            let escrow_address = clerk_sign::program_address(&lsig.logic);
            Ok(Some(ResolvedSendLsig {
                lsig,
                is_program_account: true,
                escrow_address,
            }))
        }
        (None, None, Some(_)) => {
            // `-L`: msgpack LogicSig file (delegated).
            let lsig = match clerk_sign::lsig_from_args(None, logic_sig_file, arg_b64)? {
                Some(l) => l,
                None => return Ok(None),
            };
            Ok(Some(ResolvedSendLsig {
                lsig,
                is_program_account: false,
                escrow_address: Address::default(),
            }))
        }
        (None, None, None) => Ok(None),
    }
}

/// Resolve the note field: `--noteb64` (base64) wins, then `--note` text,
/// otherwise 8 random bytes (clerk.go:314-331).
fn parse_note(note_b64: Option<&str>, note: Option<&str>) -> Result<Vec<u8>, String> {
    if let Some(b64) = note_b64 {
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("Cannot base64-decode note {b64}: {e}"));
    }
    if let Some(text) = note {
        return Ok(text.as_bytes().to_vec());
    }
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(buf.to_vec())
}

/// Parse the optional base64 lease, requiring exactly 32 bytes (clerk.go:333-346).
fn parse_lease(lease: Option<&str>) -> Result<[u8; 32], String> {
    let Some(raw) = lease else {
        return Ok([0u8; 32]);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| format!("Cannot base64-decode lease {raw}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Cannot base64-decode lease {raw}: lease length {} != 32",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Compute a transaction's `[first_valid, last_valid]` window, mirroring
/// go-algorand's `computeValidityRounds` (libgoal.go:525) with the full
/// `validRounds` resolution table.
fn compute_validity(
    first_valid: Option<u64>,
    last_valid: Option<u64>,
    valid_rounds: Option<u64>,
    last_round: u64,
) -> Result<(u64, u64), String> {
    let valid_rounds = valid_rounds.unwrap_or(0);
    let last_valid_in = last_valid.unwrap_or(0);
    if valid_rounds != 0 && last_valid_in != 0 {
        return Err(format!(
            "cannot construct transaction: ambiguous input: lastValid = {last_valid_in}, \
             validRounds = {valid_rounds}"
        ));
    }

    let first = match first_valid {
        Some(f) if f != 0 => f,
        _ => {
            if last_round > 0 {
                last_round
            } else {
                1
            }
        }
    };

    let last = if valid_rounds != 0 {
        // validRounds = maxTxnLife+1 ⇒ lastValid = firstValid + maxTxnLife.
        if valid_rounds > MAX_TXN_LIFE.saturating_add(1) {
            return Err(format!(
                "cannot construct transaction: txn validity period {} is greater than protocol \
                 max txn lifetime {MAX_TXN_LIFE}",
                valid_rounds - 1
            ));
        }
        first.saturating_add(valid_rounds).saturating_sub(1)
    } else if last_valid_in == 0 {
        first.saturating_add(MAX_TXN_LIFE)
    } else {
        last_valid_in
    };

    if first > last {
        return Err(format!(
            "cannot construct transaction: txn would first be valid on round {first} which is \
             after last valid round {last}"
        ));
    }
    if last - first > MAX_TXN_LIFE {
        return Err(format!(
            "cannot construct transaction: txn validity period ( {first} to {last} ) is greater \
             than protocol max txn lifetime {MAX_TXN_LIFE}"
        ));
    }
    Ok((first, last))
}

// ---- clerk sign -----------------------------------------------------------

/// `clerk sign -i <in> -o <out> [-S signer] [-p prog | -L lsig] [--argb64 ...]
/// [-P proto] [-w wallet] [--password]`.
///
/// Mirrors Go's `signCmd` (clerk.go:787-911). When a `--program`/`--logic-sig`
/// source is supplied, every transaction in the file gets that LogicSig
/// attached (and, with `-S`, the AuthAddr set); otherwise each transaction's
/// body is re-signed through the kmd wallet (Go's
/// `SignTransactionWithWalletAndSigner`).
pub fn run_sign(
    args: SignArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match run_sign_inner(args, wallet, cli_d, kmd_dir_flag) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_sign_inner(
    args: SignArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> Result<(), String> {
    let data = std::fs::read(&args.infile)
        .map_err(|e| format!("Cannot read file {}: {e}", args.infile.display()))?;
    let mut stxns = decode_signed_txn_stream(&data).map_err(|e| {
        format!(
            "Cannot decode transactions from {}: {e}",
            args.infile.display()
        )
    })?;

    // Build the LogicSig from --program/--logic-sig + --argb64, if any
    // (clerk.go:804-812). `None` ⇒ wallet-sign path.
    let lsig = clerk_sign::lsig_from_args(
        args.program.as_deref(),
        args.logic_sig.as_deref(),
        &args.argb64,
    )?;

    // Resolve the optional --signer (AuthAddr) once (clerk.go:818-823).
    let signer_addr = args
        .signer
        .as_deref()
        .map(|s| Address::from_algorand_string(s).map_err(|e| format!("Signer invalid ({s}): {e}")))
        .transpose()?;

    let out_data = if let Some(lsig) = lsig {
        // --- LogicSig path: attach lsig (+ AuthAddr) to every txn. ---
        // Go runs verify.LogicSigSanityCheck per txn (it depends on the txn's
        // authorizer). We mirror it in two steps that together match Go without
        // needing the consensus-param table loaded client-side:
        //   1. `clerk_sign::logicsig_program_check` — program structure +
        //      pooled-size (len(logic) + sum(args)) check;
        //   2. `algo_validate::logicsig_sanity_check` — the at-most-one-sig rule
        //      and the actual delegation-signature verification (sig / msig /
        //      lmsig over "Program"||logic, or the contract-account
        //      authorizer == HashProgram check). This is the load-bearing
        //      security check: it rejects an invalid/unsigned delegated lsig
        //      before we write the file. The node re-runs the full check
        //      (including TEAL execution) on submit.
        let mut out = Vec::new();
        for (idx, stxn) in stxns.iter_mut().enumerate() {
            stxn.lsig = Some(lsig.clone());
            // A LogicSig-authorized txn must carry exactly one signature type.
            // If the input file already had a top-level ed25519 sig or msig
            // (e.g. it was re-fed from a signed file), clear them so we don't
            // emit a dual-signed txn the node rejects with "should only have
            // one signature". (Go's signCmd assumes an unsigned input here and
            // leaves these untouched; clearing is the safe superset.)
            stxn.sig = [0u8; 64];
            stxn.msig = None;
            if let Some(signer) = signer_addr {
                if signer == stxn.txn.sender {
                    return Err("AuthAddr cannot be the same as the transaction sender".into());
                }
                stxn.auth_addr = Some(signer);
            }
            clerk_sign::logicsig_program_check(&lsig)
                .map_err(|e| format!("{}: txn[{idx}] error {e}", args.infile.display()))?;
            algo_validate::logicsig_sanity_check(stxn, &lsig)
                .map_err(|e| format!("{}: txn[{idx}] error {e}", args.infile.display()))?;
            out.extend_from_slice(&canonical_encode_signed_transaction(stxn));
        }
        out
    } else {
        // --- Wallet path: re-sign each txn body through kmd. ---
        let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
        let kmd = build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref())?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Error processing command: {e}"))?;
        let mut accounts = AccountsList::load(&data_dir_path);
        let (handle, _wallet_name, password) = resolve_wallet_and_init(
            &rt,
            &kmd,
            &mut accounts,
            wallet.as_deref(),
            args.password.as_deref(),
        )?;

        // `[0u8; 32]` ⇒ kmd infers the signer from the sender; a non-zero
        // signer pubkey selects a specific spending key (rekey case).
        let signer_pk: [u8; 32] = signer_addr.map(|a| a.0).unwrap_or([0u8; 32]);

        let mut out = Vec::new();
        for stxn in &stxns {
            let encoded = algo_codec::canonical_encode_transaction(&stxn.txn);
            let signed = rt
                .block_on(kmd.sign_transaction(&handle, &password, encoded, signer_pk))
                .map_err(|e| format!("Couldn't sign tx with kmd: {}", kmd_msg(&e)))?;
            // Go's `Transaction.Sign` (transaction.go:271-274) sets AuthAddr
            // whenever the signing key differs from the sender (the rekey
            // case). The kmd-rust server signs with the requested key but
            // leaves `sgnr` unset (TASK-216), so set it here when `--signer`
            // differs from the sender — otherwise the emitted txn would carry
            // a signature checked against the wrong (sender) key and fail
            // verification.
            if let Some(signer) = signer_addr {
                if signer != stxn.txn.sender {
                    let mut signed_txn = decode_signed_txn_stream(&signed.signed_transaction)
                        .map_err(|e| {
                            format!("kmd returned an undecodable signed transaction: {e}")
                        })?;
                    let mut s = signed_txn
                        .pop()
                        .ok_or("kmd returned an empty signed transaction for a single-txn sign")?;
                    s.auth_addr = Some(signer);
                    out.extend_from_slice(&canonical_encode_signed_transaction(&s));
                    continue;
                }
            }
            out.extend_from_slice(&signed.signed_transaction);
        }
        out
    };

    write_file_0600(&args.outfile, &out_data)?;
    Ok(())
}

// ---- clerk tealsign -------------------------------------------------------

/// `clerk tealsign --keyfile <f> (--lsig-txn <f> | --contract-addr <a>)
/// (--data-file <f> | --data-b64 <s> | --data-b32 <s> | --sign-txid)
/// [--set-lsig-arg-idx <n>]`.
///
/// Mirrors Go's `tealsignCmd` (`cmd/goal/tealsign.go`). Signs the
/// domain-separated payload `"ProgData" || program_hash || data` with the
/// ed25519 seed from `--keyfile`, prints the base64 signature, and optionally
/// stores it as a LogicSig arg in the `--lsig-txn` file.
pub fn run_tealsign(args: TealsignArgs) -> ExitCode {
    match run_tealsign_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_tealsign_inner(args: TealsignArgs) -> Result<(), String> {
    use ed25519_dalek::{Signer, SigningKey};

    // 1. Fetch the signing key. --keyfile xor --account; --account is not yet
    //    supported (matches Go tealsign.go:75-96).
    if args.keyfile.is_some() == args.account.is_some() {
        return Err(
            "goal clerk tealsign requires exactly one of --keyfile or --account".to_string(),
        );
    }
    if args.account.is_some() {
        return Err("goal clerk tealsign --account is not yet supported".to_string());
    }
    let keyfile = args
        .keyfile
        .as_ref()
        .ok_or("goal clerk tealsign requires exactly one of --keyfile or --account")?;
    let kdata = std::fs::read(keyfile).map_err(|e| format!("Cannot read key file: {e}"))?;
    // Go copies the file bytes into a 32-byte Seed (extra bytes ignored, short
    // files zero-padded). GenerateSignatureSecrets(seed) == ed25519 from seed.
    let mut seed = [0u8; 32];
    let n = kdata.len().min(32);
    seed[..n].copy_from_slice(&kdata[..n]);
    let signing_key = SigningKey::from_bytes(&seed);

    // 2. Resolve the program hash: exactly one of --lsig-txn / --contract-addr
    //    (tealsign.go:108-152).
    let mut lsig_args: usize = 0;
    if args.lsig_txn.is_some() {
        lsig_args += 1;
    }
    if args.contract_addr.is_some() {
        lsig_args += 1;
    }
    if lsig_args != 1 {
        return Err(
            "goal clerk tealsign requires exactly one of --lsig-txn or --contract-addr".to_string(),
        );
    }

    let mut lsig_stxn: Option<SignedTransaction> = None;
    let program_hash: [u8; 32] =
        if let Some(path) = args.lsig_txn.as_ref() {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("Cannot read file {}: {e}", path.display()))?;
            // Go's tealsign reads `--lsig-txn` as a SINGLE SignedTxn via
            // `protocol.Decode` (tealsign.go:131) — trailing txns in the file
            // are ignored, and `--set-lsig-arg-idx` rewrites only that first
            // txn (`protocol.Encode(&stxn)`, tealsign.go:222). We mirror that:
            // decode the stream and take the first txn.
            let stxns = decode_signed_txn_stream(&bytes)
                .map_err(|e| format!("Cannot decode transactions from {}: {e}", path.display()))?;
            let stxn = stxns.into_iter().next().ok_or_else(|| {
                format!("Cannot decode transactions from {}: empty", path.display())
            })?;
            let program = match stxn.lsig.as_ref() {
                Some(l) if !l.logic.is_empty() => l.logic.to_vec(),
                _ => return Err(
                    "The transaction's logic sig contains no program. Can't compute program hash"
                        .to_string(),
                ),
            };
            let h = clerk_sign::hash_program(&program);
            lsig_stxn = Some(stxn);
            h
        } else {
            let addr_str = args.contract_addr.as_deref().unwrap_or_default();
            Address::from_algorand_string(addr_str)
                .map_err(|e| format!("Cannot parse contract address: {e}"))?
                .0
        };

    // 3. Resolve the data to sign: exactly one of --data-file / --data-b64 /
    //    --data-b32 / --sign-txid (tealsign.go:158-194).
    let mut data_args: usize = 0;
    let mut data_to_sign: Vec<u8> = Vec::new();
    if let Some(path) = args.data_file.as_ref() {
        data_to_sign =
            std::fs::read(path).map_err(|e| format!("Cannot parse data to sign: {e}"))?;
        data_args += 1;
    }
    if let Some(b64) = args.data_b64.as_deref() {
        data_to_sign = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("Cannot parse base64 data to sign: {e}"))?;
        data_args += 1;
    }
    if let Some(b32) = args.data_b32.as_deref() {
        data_to_sign = data_encoding::BASE32_NOPAD
            .decode(b32.as_bytes())
            .map_err(|e| format!("Cannot parse base32 data to sign: {e}"))?;
        data_args += 1;
    }
    if args.sign_txid {
        let stxn = lsig_stxn.as_ref().ok_or(
            "--sign-txid requires --lsig-txn so there is a transaction whose txid can be signed",
        )?;
        data_to_sign = compute_txn_id(&stxn.txn).0.to_vec();
        data_args += 1;
    }
    if data_args != 1 {
        return Err(
            "goal clerk tealsign requires exactly one of --data-file, --data-b64, --data-b32, or \
             --sign-txid"
                .to_string(),
        );
    }

    // 4. Sign the domain-separated payload (tealsign.go:200-203).
    let payload = clerk_sign::tealsign_payload(&program_hash, &data_to_sign);
    let signature = signing_key.sign(&payload).to_bytes();

    // 5. Optionally store the signature as a LogicSig arg, rewriting the
    //    --lsig-txn file in place (tealsign.go:209-227).
    if args.set_lsig_arg_idx >= 0 {
        let idx = args.set_lsig_arg_idx as usize;
        let mut stxn = lsig_stxn.ok_or(
            "--set-lsig-arg-idx requires --lsig-txn so there is a logic sig to store the arg in",
        )?;
        if idx > clerk_sign::EVAL_MAX_ARGS - 1 {
            return Err(format!(
                "--set-lsig-arg-idx too large: a logic sig can have at most {} args",
                clerk_sign::EVAL_MAX_ARGS
            ));
        }
        let lsig = stxn.lsig.get_or_insert_with(algo_types::LogicSig::default);
        let mut existing = lsig.args.take().unwrap_or_default();
        while existing.len() < idx + 1 {
            existing.push(serde_bytes::ByteBuf::new());
        }
        existing[idx] = serde_bytes::ByteBuf::from(signature.to_vec());
        lsig.args = Some(existing);

        let path = args
            .lsig_txn
            .as_ref()
            .expect("lsig_txn present when set-lsig-arg-idx >= 0 and lsig_stxn was Some");
        let encoded = canonical_encode_signed_transaction(&stxn);
        std::fs::write(path, &encoded)
            .map_err(|e| format!("Cannot write file {}: {e}", path.display()))?;
        println!(
            "Updated lsig arg {idx} in {} with the signature",
            path.display()
        );
    }

    // Always print the base64 signature (tealsign.go:229-231).
    println!(
        "Signature: {}",
        base64::engine::general_purpose::STANDARD.encode(signature)
    );
    Ok(())
}

// ---- clerk compile --------------------------------------------------------

/// Sentinel filename meaning stdin/stdout in goal (`-`), matching Go's
/// `stdinFileNameValue` / `stdoutFilenameValue` (common.go:27-28).
const STDIN_STDOUT: &str = "-";

/// `clerk compile [files...] [-o out] [-n]`.
///
/// Mirrors Go's `compileCmd` (clerk.go:1090) output/flag surface. Each input
/// file's TEAL source is compiled, the raw program bytes are written to
/// `<file>.tok` (or `-o`/`-`), and the contract address is printed as
/// `<file>: <address>` unless the output target is stdout.
///
/// **Intentional divergence from Go (TASK-291 scope):** Go's `goal clerk
/// compile` assembles *locally* via `logic.AssembleString` (works offline,
/// independent of any node), whereas this leaf is specified to compile via the
/// node's `POST /v2/teal/compile` endpoint. Consequences, by design:
/// it requires a reachable algod data dir + a running node, and the node must
/// have `EnableDeveloperAPI=true` (else the endpoint 404s, surfaced here as
/// `Could not assemble: ...`).
/// Compiling against the node guarantees the produced bytecode matches the
/// exact assembler the target node runs; the assembler itself
/// (`algo_avm::assembler`) is byte-identical to go-algorand's, so for a given
/// program the result equals Go's local-compile output (verified for parity).
pub fn run_compile(args: crate::groups::clerk::CompileArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    match run_compile_inner(args, cli_d) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_compile_inner(
    args: crate::groups::clerk::CompileArgs,
    cli_d: Vec<PathBuf>,
) -> Result<(), String> {
    // With no input files Go's compileCmd iterates an empty list — a no-op that
    // never contacts a node. Mirror that and skip data-dir/client setup.
    if args.files.is_empty() {
        return Ok(());
    }
    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    for fname in &args.files {
        let fname_str = fname.to_string_lossy().to_string();
        // Resolve the output target the same way Go does (clerk.go:1100-1108):
        // -o wins; else stdout for stdin source, else "<file>.tok".
        let outname = match args.outfile.as_deref() {
            Some(o) => o.to_string(),
            None => {
                if fname_str == STDIN_STDOUT {
                    STDIN_STDOUT.to_string()
                } else {
                    format!("{fname_str}.tok")
                }
            }
        };
        let should_print_address = outname != STDIN_STDOUT;

        // Read the TEAL source (stdin for "-").
        let source = if fname_str == STDIN_STDOUT {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("{fname_str}: {e}"))?;
            buf
        } else {
            std::fs::read(fname).map_err(|e| format!("{fname_str}: {e}"))?
        };

        // Compile via the node. A 404 means the node has the developer API
        // disabled; surface it like Go's "Could not assemble".
        let result = rt
            .block_on(algod.teal_compile(&source))
            .map_err(|e| format!("Could not assemble: {e}"))?;
        let program = base64::engine::general_purpose::STANDARD
            .decode(&result.result)
            .map_err(|e| format!("{fname_str}: node returned an undecodable program: {e}"))?;

        // Write the binary program unless --no-out (clerk.go:1138-1143).
        if !args.no_out {
            if outname == STDIN_STDOUT {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&program)
                    .map_err(|e| format!("{outname}: {e}"))?;
            } else {
                // Go writes the compile output with 0666 perms (clerk.go:1140).
                std::fs::write(&outname, &program).map_err(|e| format!("{outname}: {e}"))?;
            }
        }

        // Print "<file>: <address>" unless writing to stdout (clerk.go:1157-1161).
        // The node already returns the program hash as an Algorand address.
        if should_print_address {
            println!("{fname_str}: {}", result.hash);
        }
    }
    Ok(())
}

// ---- clerk simulate -------------------------------------------------------

/// `clerk simulate (-t <txfile> | --request <file>) [--request-only-out <file>
/// | -o <file>] [flags]`.
///
/// Mirrors Go's `simulateCmd` (clerk.go:1300). Builds a `SimulateRequest` from a
/// transaction-group file (`--txfile`) or runs a pre-built request file
/// (`--request`), POSTs it to `POST /v2/transactions/simulate`, and prints the
/// pretty-printed JSON response (or writes it to `-o`). `--request-only-out`
/// writes the constructed request JSON and exits without simulating.
///
/// **Note vs Go:** Go encodes the request as msgpack and round-trips the
/// response through `protocol.EncodeJSON`. goal-rust sends JSON (the Rust node
/// decodes either; JSON avoids msgpack-roundtrip quirks for embedded txn bytes)
/// and pretty-prints the JSON the node returns. The `--request` path therefore
/// expects a JSON request file (the same JSON `--request-only-out` writes),
/// rather than Go's msgpack request blob.
pub fn run_simulate(args: SimulateArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    match run_simulate_inner(args, cli_d) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_simulate_inner(args: SimulateArgs, cli_d: Vec<PathBuf>) -> Result<(), String> {
    // Exactly one of --txfile / --request (clerk.go:1306-1309).
    let tx_provided = args.txfile.is_some();
    let request_provided = args.request.is_some();
    if tx_provided == request_provided {
        return Err("exactly one of --txfile or --request must be provided".into());
    }

    // --allow-more-opcode-budget and --extra-opcode-budget are mutually
    // exclusive (clerk.go:1311-1314).
    if args.allow_more_opcode_budget && args.extra_opcode_budget.is_some() {
        return Err(
            "--allow-extra-opcode-budget and --extra-opcode-budget are mutually exclusive".into(),
        );
    }
    // Go's `simulation.MaxExtraOpcodeBudget` (320000).
    const MAX_EXTRA_OPCODE_BUDGET: i64 = 320_000;
    let extra_opcode_budget = if args.allow_more_opcode_budget {
        Some(MAX_EXTRA_OPCODE_BUDGET)
    } else {
        args.extra_opcode_budget
    };

    // --request-only-out and --result-out are mutually exclusive
    // (clerk.go:1320-1323).
    if args.request_only_out.is_some() && args.result_out.is_some() {
        return Err("--request-only-out and --result-out are mutually exclusive".into());
    }

    // --request-only-out: build a request from --txfile and write it, no
    // simulation (clerk.go:1325-1351).
    if let Some(out) = args.request_only_out.as_ref() {
        if request_provided {
            return Err("--request-only-out and --request are mutually exclusive".into());
        }
        let txfile = args
            .txfile
            .as_ref()
            .ok_or("--request-only-out requires --txfile")?;
        let request = build_simulate_request(txfile, &args, extra_opcode_budget)?;
        let json = serde_json::to_vec(&request)
            .map_err(|e| format!("could not encode simulate request: {e}"))?;
        write_file_0600(out, &json)?;
        return Ok(());
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;

    // Request body: build from --txfile, or read the pre-built --request JSON.
    let request_json = if let Some(txfile) = args.txfile.as_ref() {
        let request = build_simulate_request(txfile, &args, extra_opcode_budget)?;
        serde_json::to_vec(&request)
            .map_err(|e| format!("could not encode simulate request: {e}"))?
    } else {
        let path = args.request.as_ref().expect("request set");
        std::fs::read(path).map_err(|e| format!("Cannot read file {}: {e}", path.display()))?
    };

    let resp = rt
        .block_on(algod.simulate_transactions(&request_json))
        .map_err(|e| format!("simulation error: {e}"))?;

    // Go prints `protocol.EncodeJSON(&simulateResponse)` (compact, no trailing
    // newline) to stdout, or writes it to -o. We pretty-print to stdout for
    // readability and write compact JSON to -o.
    if let Some(out) = args.result_out.as_ref() {
        let encoded =
            serde_json::to_vec(&resp).map_err(|e| format!("could not encode result: {e}"))?;
        write_file_0600(out, &encoded)?;
    } else {
        let pretty = serde_json::to_string_pretty(&resp)
            .map_err(|e| format!("could not encode result: {e}"))?;
        println!("{pretty}");
    }
    Ok(())
}

/// Build the JSON `SimulateRequest` body from a transaction-group file plus the
/// command flags. Mirrors Go's `PreEncodedSimulateRequest` construction
/// (clerk.go:1333-1371): one group containing the file's `SignedTxn`s, with the
/// request-level flags. Each txn is JSON-encoded the way the Rust node decodes
/// them (`serde_json::from_value::<SignedTransaction>`).
fn build_simulate_request(
    txfile: &Path,
    args: &SimulateArgs,
    extra_opcode_budget: Option<i64>,
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    let data =
        std::fs::read(txfile).map_err(|e| format!("Cannot read file {}: {e}", txfile.display()))?;
    let stxns = decode_signed_txn_stream(&data)
        .map_err(|e| format!("Cannot decode transactions from {}: {e}", txfile.display()))?;

    let mut txns_json = Vec::with_capacity(stxns.len());
    for stxn in &stxns {
        txns_json.push(
            serde_json::to_value(stxn)
                .map_err(|e| format!("Cannot encode transaction for simulate: {e}"))?,
        );
    }

    // exec-trace-config (traceCmdOptionToSimulateTraceConfigModel, clerk.go:1417):
    // --full-trace turns everything on; --trace/--stack/--scratch/--state OR in.
    let enable = args.full_trace || args.trace;
    let stack = args.full_trace || args.stack;
    let scratch = args.full_trace || args.scratch;
    let state = args.full_trace || args.state;
    let mut trace_config = serde_json::Map::new();
    if enable {
        trace_config.insert("enable".into(), json!(true));
    }
    if stack {
        trace_config.insert("stack-change".into(), json!(true));
    }
    if scratch {
        trace_config.insert("scratch-change".into(), json!(true));
    }
    if state {
        trace_config.insert("state-change".into(), json!(true));
    }

    let mut request = serde_json::Map::new();
    request.insert(
        "txn-groups".into(),
        json!([{ "txns": serde_json::Value::Array(txns_json) }]),
    );
    if let Some(round) = args.round {
        request.insert("round".into(), json!(round));
    }
    if args.allow_empty_signatures {
        request.insert("allow-empty-signatures".into(), json!(true));
    }
    if args.allow_more_logging {
        request.insert("allow-more-logging".into(), json!(true));
    }
    if args.allow_unnamed_resources {
        request.insert("allow-unnamed-resources".into(), json!(true));
    }
    if let Some(budget) = extra_opcode_budget {
        request.insert("extra-opcode-budget".into(), json!(budget));
    }
    if !trace_config.is_empty() {
        request.insert(
            "exec-trace-config".into(),
            serde_json::Value::Object(trace_config),
        );
    }

    Ok(serde_json::Value::Object(request))
}

// ---- clerk multisig sign --------------------------------------------------

/// `clerk multisig sign -t <txfile> [-a addr | -n] [-w wallet] [--password]`.
///
/// Mirrors Go's `addSigCmd` (multisig.go:75): for each `SignedTxn` in `--tx`,
/// start or extend its multisig (rewriting the file in place). With `-n/--no-sig`
/// it only populates the blank multisig preimage looked up from the wallet's
/// multisig account; otherwise it signs with the `-a/--address` key via kmd
/// (passing the txn's AuthAddr when the sender was rekeyed).
pub fn run_multisig_sign(
    args: MultisigSignArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match run_multisig_sign_inner(args, wallet, cli_d, kmd_dir_flag) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_multisig_sign_inner(
    args: MultisigSignArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> Result<(), String> {
    let data = std::fs::read(&args.tx)
        .map_err(|e| format!("Cannot read file {}: {e}", args.tx.display()))?;
    let mut stxns = decode_signed_txn_stream(&data)
        .map_err(|e| format!("Cannot decode transactions from {}: {e}", args.tx.display()))?;

    // --address and --no-sig are mutually exclusive; exactly one is required
    // (multisig.go:88-93, `addrNoSigError`).
    let addr_msg = "must specify exactly one of --address or --no-sig";
    match (args.address.as_deref(), args.no_sig) {
        (None, false) | (Some(_), true) => return Err(addr_msg.into()),
        _ => {}
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let kmd = build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, password) = resolve_wallet_and_init(
        &rt,
        &kmd,
        &mut accounts,
        wallet.as_deref(),
        args.password.as_deref(),
    )?;

    let mut out_data = Vec::new();
    for stxn in stxns.iter_mut() {
        let new_msig = if args.no_sig {
            // Populate a blank multisig preimage looked up from the wallet's
            // multisig account by the txn SENDER (Go's `addSigCmd`:
            // `LookupMultisigAccount(wh, stxn.Txn.Sender.String())` →
            // msigInfoToMsig, multisig.go:113-119). Go looks up by sender, not
            // AuthAddr, even for a rekeyed sender — we match that verbatim.
            let sender = stxn.txn.sender.to_algorand_string();
            let exp = rt
                .block_on(kmd.export_multisig(&handle, &sender))
                .map_err(|e| format!("multisig lookup error: {}", kmd_msg(&e)))?;
            algo_consensus_crypto::multisig_preimage_from_pks(exp.version, exp.threshold, &exp.pks)
        } else {
            // Sign with the -a/--address key via kmd.
            let addr_str = args.address.as_deref().expect("address set");
            let signer = Address::from_algorand_string(addr_str)
                .map_err(|e| format!("Cannot decode address {addr_str}: {e}"))?;
            let encoded = algo_codec::canonical_encode_transaction(&stxn.txn);
            // Partial multisig already on the txn (blank if first signer).
            let partial = to_kmd_msig(stxn.msig.as_ref());
            // AuthAddr: zero when unset (Go passes stxn.AuthAddr.GetUserAddress()
            // only when non-zero; the kmd-rust client takes a 32-byte key with
            // all-zero meaning "none"). This is the rekey signer override Go
            // forwards via `MultisigSignTransactionWithWalletAndSigner`
            // (multisig.go:124). NOTE: like go-algorand's kmd, the *fresh*
            // (no partial) sign path looks up the preimage by the txn sender,
            // not AuthAddr (sqlite.go:1188) — so first-signing a rekeyed-to-
            // multisig txn requires the txn to already carry the blank msig
            // preimage (e.g. via a prior `multisig sign --no-sig`). This
            // matches `goal multisig sign`; it is not a goal-rust-only limit.
            let auth_addr = stxn.auth_addr.map(|a| a.0).unwrap_or([0u8; 32]);
            let resp = rt
                .block_on(kmd.multisig_sign_transaction(
                    &handle, &password, encoded, signer.0, partial, auth_addr,
                ))
                .map_err(|e| format!("Couldn't sign tx with kmd: {}", kmd_msg(&e)))?;
            algo_codec::decode_multisig(&resp.multisig)
                .map_err(|e| format!("kmd returned an undecodable multisig: {e}"))?
        };

        stxn.msig = Some(new_msig);
        out_data.extend_from_slice(&canonical_encode_signed_transaction(stxn));
    }

    write_file_0600(&args.tx, &out_data)?;
    Ok(())
}

// ---- clerk multisig signprogram -------------------------------------------

/// `clerk multisig signprogram -a <addr> [-p prog | -P progbytes | -L lsig]
/// [-A msig-addr] [-o lsig-out] [--legacy-msig] [-w wallet] [--password]`.
///
/// Mirrors Go's `signProgramCmd` (multisig.go:144): start or extend a multisig
/// on a LogicSig program and write the (partial) LogicSig blob. The partial
/// multisig comes from the `-L` LogicSig file (its `Msig`/`LMsig`) or is looked
/// up from `-A/--msig-address`. Whether the signature lands in `Msig` (legacy)
/// or `LMsig` is keyed on `--legacy-msig`.
///
/// NOTE vs Go: Go auto-detects `useLegacyMsig` from the *live node's* current
/// consensus params (`!LogicSigLMsig`) when the flag is unset. goal-rust does
/// NOT: `algo_types::ConsensusParams` models `logic_sig_lmsig`/`logic_sig_msig`
/// (issue #752), but this is an offline signing command with no node
/// connection and no consensus version to look the flag up under, so there's
/// nothing to detect client-side — it defaults to the modern `LMsig` field;
/// pass `--legacy-msig` for the legacy `Msig` field (see
/// [`MultisigSignProgramArgs::legacy_msig`]).
pub fn run_multisig_signprogram(
    args: MultisigSignProgramArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match run_multisig_signprogram_inner(args, wallet, cli_d, kmd_dir_flag) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_multisig_signprogram_inner(
    args: MultisigSignProgramArgs,
    wallet: Option<String>,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> Result<(), String> {
    use algo_types::LogicSig;

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let kmd = build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, password) = resolve_wallet_and_init(
        &rt,
        &kmd,
        &mut accounts,
        wallet.as_deref(),
        args.password.as_deref(),
    )?;

    // Resolve the program + base LogicSig from -p / -P / -L (multisig.go:151-217).
    let collision = "goal multisig signprogram should have at most one of --program/-p, \
                     --program-bytes/-P, or --lsig/-L";
    let mut lsig = LogicSig::default();
    let mut out_name = args.lsig_out.clone();
    let mut got_partial = false;
    let program: Vec<u8>;

    if let Some(src) = args.program.as_deref() {
        if args.lsig.is_some() || args.program_bytes.is_some() {
            return Err(collision.into());
        }
        let text = std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))?;
        let ops = algo_avm::assembler::assemble_string(&text)
            .map_err(|errs| clerk_sign::format_assembly_errors(src, &errs))?;
        program = ops.program;
        lsig.logic = serde_bytes::ByteBuf::from(program.clone());
        if out_name.is_none() {
            out_name = Some(format!("{src}.lsig"));
        }
    } else if let Some(file) = args.lsig.as_deref() {
        if args.program_bytes.is_some() {
            return Err(collision.into());
        }
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        lsig = algo_codec::decode_logicsig(&bytes).map_err(|e| format!("{file}: {e}"))?;
        program = lsig.logic.to_vec();
        if out_name.is_none() {
            out_name = Some(file.to_string());
        }
        got_partial = true;
    } else if let Some(file) = args.program_bytes.as_deref() {
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        program = bytes;
        lsig.logic = serde_bytes::ByteBuf::from(program.clone());
        if out_name.is_none() {
            out_name = Some(format!("{file}.lsig"));
        }
    } else {
        return Err("one of --program/-p, --program-bytes/-P, or --lsig/-L is required".into());
    }

    // Go auto-detects `useLegacyMsig` from the live node's current consensus
    // params (`!LogicSigLMsig`) when `--legacy-msig` is omitted
    // (multisig.go:219-226). goal-rust does NOT: `algo_types::ConsensusParams`
    // models `logic_sig_lmsig`/`logic_sig_msig` (issue #752), but this is an
    // offline command with no node connection and no consensus version to
    // look the flag up under, so there is nothing to detect client-side. We
    // default to the modern `LMsig` field (useLegacyMsig=false);
    // `--legacy-msig` forces the legacy `Msig` field. See the flag's
    // doc-comment for the full rationale.
    let use_legacy_msig = args.legacy_msig;

    // Get or create the partial multisig (multisig.go:228-251).
    let partial: algo_types::MultisigSig = if got_partial {
        if use_legacy_msig {
            if lsig.lmsig.as_ref().is_some_and(|m| !m.subsigs.is_empty()) {
                return Err(
                    "LogicSig file contains LMsig field, but --legacy-msig=true is set, \
                            which uses Msig. Specify --legacy-msig=false to use LMsig, or provide \
                            a LogicSig file with Msig field"
                        .into(),
                );
            }
            lsig.msig.clone().unwrap_or_default()
        } else {
            if lsig.msig.as_ref().is_some_and(|m| !m.subsigs.is_empty()) {
                return Err(
                    "LogicSig file contains Msig field, but --legacy-msig=false is set, \
                            which uses LMsig. Specify --legacy-msig=true to use Msig, or provide \
                            a LogicSig file with LMsig field"
                        .into(),
                );
            }
            lsig.lmsig.clone().unwrap_or_default()
        }
    } else {
        let msig_addr = args
            .msig_address
            .as_deref()
            .ok_or("--msig-address/-A required when partial LogicSig not available")?;
        let exp = rt
            .block_on(kmd.export_multisig(&handle, msig_addr))
            .map_err(|e| format!("multisig lookup error: {}", kmd_msg(&e)))?;
        algo_consensus_crypto::multisig_preimage_from_pks(exp.version, exp.threshold, &exp.pks)
    };

    // Sign the program via kmd. The kmd `address` is the *multisig* address
    // (derived from the partial), NOT the signer key — it scopes the preimage
    // lookup and the modern `"MsigProgram" || addr || program` signing domain.
    // The signer key is passed only as `public_key`. Mirrors Go's
    // `MultisigSignProgramWithWallet` (libgoal/transactions.go:152-156:
    // `MultisigAddrGenWithSubsigs(partial...)` → kmd `address`; signerAddr →
    // `public_key`).
    let signer = Address::from_algorand_string(&args.address)
        .map_err(|e| format!("Cannot decode address {}: {e}", args.address))?;
    let pks: Vec<[u8; 32]> = partial.subsigs.iter().map(|s| s.public_key).collect();
    let msig_address =
        algo_consensus_crypto::multisig_addr_gen(partial.version, partial.threshold, &pks)
            .map_err(|e| format!("Cannot derive multisig address from partial: {e}"))?
            .to_algorand_string();
    let resp = rt
        .block_on(kmd.multisig_sign_program(
            &handle,
            &password,
            &msig_address,
            signer.0,
            to_kmd_msig(Some(&partial)),
            program,
            use_legacy_msig,
        ))
        .map_err(|e| format!("Couldn't sign program with kmd: {}", kmd_msg(&e)))?;
    let msig = algo_codec::decode_multisig(&resp.multisig)
        .map_err(|e| format!("kmd returned an undecodable multisig: {e}"))?;

    if use_legacy_msig {
        lsig.msig = Some(msig);
        lsig.lmsig = None;
    } else {
        lsig.msig = None;
        lsig.lmsig = Some(msig);
    }

    let out_name = out_name.expect("out_name set by one of the program branches");
    let blob = algo_codec::canonical_encode_logicsig(&lsig);
    write_file_0600(Path::new(&out_name), &blob)?;
    Ok(())
}

// ---- clerk multisig merge -------------------------------------------------

/// `clerk multisig merge -o <out> <file1> <file2> ...`.
///
/// Mirrors Go's `mergeSigCmd` (multisig.go:259): combine partially-signed
/// multisig transaction files (same txn IDs in the same order) into one file
/// with merged multisig signatures.
pub fn run_multisig_merge(args: MultisigMergeArgs) -> ExitCode {
    match run_multisig_merge_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_multisig_merge_inner(args: MultisigMergeArgs) -> Result<(), String> {
    if args.files.is_empty() {
        return Err("must specify at least one transaction file to merge".into());
    }

    // Decode each input file into its list of SignedTxns (multisig.go:264-289).
    let mut txn_lists: Vec<Vec<SignedTransaction>> = Vec::with_capacity(args.files.len());
    for file in &args.files {
        let data =
            std::fs::read(file).map_err(|e| format!("Cannot read file {}: {e}", file.display()))?;
        let txns = decode_signed_txn_stream(&data)
            .map_err(|e| format!("Cannot decode transactions from {}: {e}", file.display()))?;
        txn_lists.push(txns);
    }

    // All lists must be the same length (multisig.go:291-296).
    let len0 = txn_lists[0].len();
    for list in &txn_lists {
        if list.len() != len0 {
            return Err("transaction files do not have the same number of transactions".into());
        }
    }

    // For each txn position, merge the multisigs across all files
    // (multisig.go:298-318). Equality is by TxID.
    let mut merged_data = Vec::new();
    for i in 0..len0 {
        let base_id = compute_txn_id(&txn_lists[0][i].txn);
        // Collect the partial msig from each file's i-th txn.
        let mut partials: Vec<algo_types::MultisigSig> = Vec::with_capacity(txn_lists.len());
        for list in &txn_lists {
            if compute_txn_id(&list[i].txn) != base_id {
                return Err("transactions don't match up; cannot merge".into());
            }
            partials.push(list[i].msig.clone().unwrap_or_default());
        }

        // Go's `crypto.MultisigMerge` (crypto/multisig.go:328) rejects
        // CONFLICTING non-blank signatures for the same subsig position
        // (`errInvalidDuplicates`); the shared `multisig_assemble` primitive
        // instead silently last-writer-wins. Match Go by detecting conflicts
        // here before assembling. (Differing subsig counts / keys / threshold /
        // version are caught by `multisig_assemble` itself, mirroring Go's
        // `errKeysNotMatch` / `errInvalidThreshold`.)
        detect_conflicting_subsigs(&partials)?;

        // multisig_assemble requires >= 2 partials; a single input file
        // self-merges (matching Go's tx0-with-tx0 first iteration).
        if partials.len() == 1 {
            partials.push(partials[0].clone());
        }
        let merged = algo_consensus_crypto::multisig_assemble(&partials)
            .map_err(|e| format!("Cannot merge multisig signatures: {e}"))?;

        let mut tx = txn_lists[0][i].clone();
        tx.msig = Some(merged);
        merged_data.extend_from_slice(&canonical_encode_signed_transaction(&tx));
    }

    write_file_0600(&args.out, &merged_data)?;
    Ok(())
}

/// Reject conflicting non-blank signatures for the same subsig position across
/// the multisig partials being merged. Mirrors `crypto.MultisigMerge`'s
/// `errInvalidDuplicates` (crypto/multisig.go): two partials carrying *different*
/// non-blank signatures at the same index is an error (the shared
/// `multisig_assemble` primitive would otherwise silently keep the last one).
fn detect_conflicting_subsigs(partials: &[algo_types::MultisigSig]) -> Result<(), String> {
    let Some(width) = partials.iter().map(|p| p.subsigs.len()).max() else {
        return Ok(());
    };
    for j in 0..width {
        let mut seen: Option<[u8; 64]> = None;
        for p in partials {
            let Some(sub) = p.subsigs.get(j) else {
                continue;
            };
            if sub.signature == [0u8; 64] {
                continue;
            }
            match seen {
                None => seen = Some(sub.signature),
                Some(prev) if prev != sub.signature => {
                    return Err(
                        "Cannot merge multisig signatures: invalid duplicates (conflicting \
                         signatures for the same key)"
                            .into(),
                    );
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// Convert an `algo_types::MultisigSig` (txn/codec model) into the kmd client's
/// `MultisigSig` request type. A `None`/blank input yields kmd's default
/// (`MultisigSig::default()`), which kmd treats as "no partial multisig yet".
fn to_kmd_msig(msig: Option<&algo_types::MultisigSig>) -> algo_kmd_api_types::common::MultisigSig {
    use algo_kmd_api_types::common::{MultisigSig as KmdMsig, MultisigSubsig as KmdSubsig};
    match msig {
        None => KmdMsig::default(),
        Some(m) => KmdMsig {
            version: m.version,
            threshold: m.threshold,
            subsigs: m
                .subsigs
                .iter()
                .map(|s| KmdSubsig {
                    public_key: s.public_key,
                    signature: s.signature,
                })
                .collect(),
        },
    }
}

/// Write `data` to `path` with `0600` perms, mirroring Go's `writeFile(..,
/// 0600)` (commands.go:510) used by the signing paths. As in Go, the path
/// `-` (`stdoutFilenameValue`) writes to stdout instead of a file.
fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), String> {
    if path.as_os_str() == STDIN_STDOUT {
        use std::io::Write;
        return std::io::stdout()
            .write_all(data)
            .map_err(|e| format!("Cannot write to stdout: {e}"));
    }
    std::fs::write(path, data).map_err(|e| format!("Cannot write file {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---- clerk inspect --------------------------------------------------------

/// `clerk inspect [files...]` — decode and pretty-print transaction file(s).
///
/// Mirrors Go's `inspectCmd` (clerk.go:712): for each file, stream-decode the
/// `SignedTxn`s and print each as canonical JSON. The JSON view matches Go's
/// `inspectSignedTxn` (`inspect.go`): addresses render in algorand base32+
/// checksum form, the LogicSig program is disassembled to TEAL, and other byte
/// fields are base64.
pub fn run_inspect(args: InspectArgs) -> ExitCode {
    for file in &args.files {
        if let Err(msg) = inspect_one_file(file, args.txid) {
            eprintln!("{msg}");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn inspect_one_file(file: &Path, with_txid: bool) -> Result<(), String> {
    let data =
        std::fs::read(file).map_err(|e| format!("Cannot read file {}: {e}", file.display()))?;
    let stxns = decode_signed_txn_stream(&data)
        .map_err(|e| format!("Cannot decode transactions from {}: {e}", file.display()))?;
    for (idx, stxn) in stxns.iter().enumerate() {
        let json = inspect_signed_txn_json(stxn);
        let rendered = serde_json::to_string_pretty(&json)
            .map_err(|e| format!("Cannot decode transactions from {}: {e}", file.display()))?;
        if with_txid {
            let txid = compute_txn_id(&stxn.txn).to_string();
            println!("{}[{idx}] - {txid}\n{rendered}\n", file.display());
        } else {
            println!("{}[{idx}]\n{rendered}\n", file.display());
        }
    }
    Ok(())
}

/// Build the JSON inspect view of a `SignedTransaction`, mirroring Go's
/// `protocol.EncodeJSON(inspectSignedTxn)` (`inspect.go`).
///
/// We start from the canonical msgpack encoding (which already applies Go's
/// omitempty + canonical field ordering for a `SignedTxn`), decode it to a
/// generic `rmpv::Value`, and render that to JSON — base32-encoding the fields
/// Go types as addresses and disassembling the LogicSig program.
fn inspect_signed_txn_json(stxn: &SignedTransaction) -> serde_json::Value {
    let encoded = canonical_encode_signed_transaction(stxn);
    // Decode back to a generic msgpack tree; the canonical encoder produced it,
    // so this round-trips without error.
    let value = match rmpv::decode::read_value(&mut &encoded[..]) {
        Ok(v) => v,
        Err(_) => return serde_json::Value::Null,
    };
    msgpack_to_inspect_json(&value, JsonKey::Root, "")
}

/// The contextual meaning of the JSON key whose value we're currently
/// rendering, so byte blobs can be formatted the way Go's `inspectSignedTxn`
/// types dictate (base32 address vs. disassembled program vs. base64).
#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonKey {
    /// Top of the tree (the whole map) or any non-special context: byte blobs
    /// render as base64.
    Root,
    /// `basics.Address` / `crypto.PublicKey` field: base32 + checksum.
    Address,
    /// LogicSig program (`inspectProgram`): disassembled to TEAL text.
    Program,
}

/// Classify a `(parent, key)` pair into the `JsonKey` describing how the value's
/// byte blobs should render. `parent` is the codec tag of the enclosing map (or
/// array, for array elements) — needed because several single-letter tags
/// (`a`/`c`/`d`/`f`/`l`/`m`/`r`) mean *address* under one parent but something
/// else (e.g. a byte digest) under another. Without structural context, e.g.
/// state-proof `sp.c` (`SigCommit`, a digest) would be mis-rendered as an
/// address.
///
/// Mirrors the `basics.Address` / `inspectProgram`-typed fields of Go's
/// `inspectSignedTxn` (`cmd/goal/inspect.go`).
fn classify_key(parent: &str, key: &str) -> JsonKey {
    match (parent, key) {
        // AssetParams (apar): manager/reserve/freeze/clawback addresses.
        ("apar", "m" | "r" | "f" | "c") => JsonKey::Address,
        // HeartbeatTxnFields (hb): the heartbeat address.
        ("hb", "a") => JsonKey::Address,
        // Access-list resource refs (al[] elements): direct address ref ("d").
        ("al", "d") => JsonKey::Address,
        // msig subsig public key, wherever the "subsig" array nests it.
        ("subsig", "pk") => JsonKey::Address,
        // Top-level (or otherwise unambiguous) address tags. "apat" is an array
        // of addresses — classifying the field Address makes its (key-less)
        // array elements inherit the Address value-classification.
        (
            _,
            "snd" | "rcv" | "close" | "asnd" | "arcv" | "aclose" | "fadd" | "rekey" | "sgnr"
            | "apat",
        ) => JsonKey::Address,
        // LogicSig program ("l") at the lsig level. apap/apsu (approval/clear
        // programs) are plain []byte in Go's inspect view → base64. Other "l"
        // tags (e.g. ResourceRef.locals, AppLocalState) are maps/ints, not the
        // program, and are unaffected since Program only formats byte blobs.
        ("lsig", "l") => JsonKey::Program,
        _ => JsonKey::Root,
    }
}

fn msgpack_to_inspect_json(value: &rmpv::Value, key: JsonKey, parent: &str) -> serde_json::Value {
    use rmpv::Value;
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            if let Some(u) = i.as_u64() {
                serde_json::Value::from(u)
            } else if let Some(s) = i.as_i64() {
                serde_json::Value::from(s)
            } else {
                serde_json::Value::Null
            }
        }
        Value::F32(x) => serde_json::Number::from_f64(*x as f64)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::F64(x) => serde_json::Number::from_f64(*x)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::String(s) => serde_json::Value::String(s.as_str().unwrap_or("").to_string()),
        Value::Binary(bytes) => render_bytes(bytes, key),
        Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                // Array elements inherit both the value-classification (e.g.
                // "apat" is an array of addresses) and the parent tag, so a map
                // element (e.g. an "al" resource-ref) can classify its own keys.
                .map(|v| msgpack_to_inspect_json(v, key, parent))
                .collect(),
        ),
        Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key_str = k.as_str().unwrap_or("").to_string();
                let child_key = classify_key(parent, &key_str);
                // The child's value becomes the new parent context for its
                // descendants.
                map.insert(
                    key_str.clone(),
                    msgpack_to_inspect_json(v, child_key, &key_str),
                );
            }
            serde_json::Value::Object(map)
        }
        Value::Ext(_, bytes) => render_bytes(bytes, JsonKey::Root),
    }
}

/// Render a byte blob according to its key context: base32+checksum address,
/// disassembled TEAL program, or base64 (Go's default for `[]byte`).
fn render_bytes(bytes: &[u8], key: JsonKey) -> serde_json::Value {
    match key {
        JsonKey::Address if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            serde_json::Value::String(Address(arr).to_algorand_string())
        }
        JsonKey::Program => match algo_avm::disassembler::disassemble(bytes) {
            Ok(text) => serde_json::Value::String(text),
            // Go's inspectProgram.MarshalText surfaces the disassembly error as
            // the field's text; mirror that rather than failing the whole print.
            Err(e) => serde_json::Value::String(e),
        },
        _ => serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

// ---- clerk split ----------------------------------------------------------

/// `clerk split -i <in> -o <out>` — write each transaction in the input file to
/// its own `<base>-<idx><ext>` file. Mirrors Go's `splitCmd` (clerk.go:966).
pub fn run_split(args: SplitArgs) -> ExitCode {
    match run_split_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_split_inner(args: SplitArgs) -> Result<(), String> {
    let data = std::fs::read(&args.infile)
        .map_err(|e| format!("Cannot read file {}: {e}", args.infile.display()))?;
    let stxns = decode_signed_txn_stream(&data).map_err(|e| {
        format!(
            "Cannot decode transactions from {}: {e}",
            args.infile.display()
        )
    })?;

    // Split the output filename into base + extension the same way Go's
    // filepath.Ext does (extension = final '.'-segment of the last path
    // component, empty if none).
    let (base, ext) = split_ext(&args.outfile);

    for (idx, stxn) in stxns.iter().enumerate() {
        let fname = format!("{base}-{idx}{ext}");
        let encoded = canonical_encode_signed_transaction(stxn);
        std::fs::write(&fname, &encoded)
            .map_err(|e| format!("Cannot write file {}: {e}", args.outfile))?;
        println!("Wrote transaction {idx} to {fname}");
    }
    Ok(())
}

/// Split a filename into `(base, ext)` where `ext` includes the leading dot,
/// matching Go's `filepath.Ext` (only the final component's extension counts).
fn split_ext(name: &str) -> (String, String) {
    // Find the final path separator so an extension only counts within the last
    // component (mirrors filepath.Ext scanning back to a separator).
    let last_component_start = name.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    match name[last_component_start..].rfind('.') {
        Some(rel_dot) => {
            let dot = last_component_start + rel_dot;
            (name[..dot].to_string(), name[dot..].to_string())
        }
        None => (name.to_string(), String::new()),
    }
}

// ---- clerk group ----------------------------------------------------------

/// `clerk group -i <in> -o <out>` — assign a computed group ID to the unsigned
/// transactions in a file. Mirrors Go's `groupCmd` (clerk.go:914).
pub fn run_group(args: GroupArgs) -> ExitCode {
    match run_group_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_group_inner(args: GroupArgs) -> Result<(), String> {
    let data = std::fs::read(&args.infile)
        .map_err(|e| format!("Cannot read file {}: {e}", args.infile.display()))?;
    let mut stxns = decode_signed_txn_stream(&data).map_err(|e| {
        format!(
            "Cannot decode transactions from {}: {e}",
            args.infile.display()
        )
    })?;

    // Reject already-grouped or already-signed inputs (clerk.go:933-940). Go
    // preserves the LogicSig (the group can be verified by a logicsig arg), so
    // only the ed25519 sig + multisig must be absent.
    for (idx, stxn) in stxns.iter().enumerate() {
        if stxn.txn.group != [0u8; 32] {
            let id = compute_txn_id(&stxn.txn);
            return Err(format!(
                "Transaction #{idx} with ID of {id} is already part of a group."
            ));
        }
        if stxn.sig != [0u8; 64] || stxn.msig.is_some() {
            let id = compute_txn_id(&stxn.txn);
            return Err(format!(
                "Transaction #{idx} with ID of {id} is already signed"
            ));
        }
    }

    let txns: Vec<algo_types::Transaction> = stxns.iter().map(|s| s.txn.clone()).collect();
    let group_hash = compute_group_id(&txns);
    let mut out = Vec::new();
    for stxn in &mut stxns {
        stxn.txn.group = group_hash.0;
        out.extend_from_slice(&canonical_encode_signed_transaction(stxn));
    }
    std::fs::write(&args.outfile, &out)
        .map_err(|e| format!("Cannot write file {}: {e}", args.outfile.display()))?;
    Ok(())
}

// ---- clerk rawsend --------------------------------------------------------

/// `clerk rawsend -f <file> [-r rejects] [-N]` — submit a signed-txn file to
/// algod, then (unless `-N`) wait for each transaction to commit. Mirrors Go's
/// `rawsendCmd` (clerk.go:579).
pub fn run_rawsend(args: RawsendArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    match run_rawsend_inner(args, cli_d) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn run_rawsend_inner(args: RawsendArgs, cli_d: Vec<PathBuf>) -> Result<ExitCode, String> {
    let rejects_filename = args.rejects.clone().unwrap_or_else(|| {
        let mut p = args.filename.clone().into_os_string();
        p.push(".rej");
        PathBuf::from(p)
    });

    let data = std::fs::read(&args.filename)
        .map_err(|e| format!("Cannot read file {}: {e}", args.filename.display()))?;
    let txns = decode_signed_txn_stream(&data).map_err(|e| {
        format!(
            "Cannot decode transactions from {}: {e}",
            args.filename.display()
        )
    })?;

    // Duplicate detection by txid (clerk.go:607-613).
    let mut seen: HashMap<String, ()> = HashMap::new();
    for stxn in &txns {
        let txid = compute_txn_id(&stxn.txn).to_string();
        if seen.insert(txid.clone(), ()).is_some() {
            return Err(format!(
                "Duplicate transaction {txid} in {}",
                args.filename.display()
            ));
        }
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Error processing command: {e}"))?;
    let pipeline = algo_txn_pipeline::TxnPipeline::new(algod, None);

    // Group the transactions by their group ID, preserving file order, and
    // broadcast each group together (clerk.go:617-637, SignedTxnsToGroups +
    // BroadcastTransactionGroup).
    let groups = signed_txns_to_groups(&txns);

    // txid -> error message, for the rejects file (preserve file order below).
    let mut txn_errors: HashMap<String, String> = HashMap::new();
    // txid of every successfully-broadcast txn, to poll for confirmation.
    let mut pending: Vec<String> = Vec::new();

    rt.block_on(async {
        for group in &groups {
            let mut raw = Vec::new();
            for stxn in group {
                raw.extend_from_slice(&canonical_encode_signed_transaction(stxn));
            }
            match pipeline.submit(&raw).await {
                Ok(_) => {
                    for stxn in group {
                        let txid = compute_txn_id(&stxn.txn).to_string();
                        // infoRawTxIssued (messages.go:126).
                        println!("Raw transaction ID {txid} issued");
                        pending.push(txid);
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    for stxn in group {
                        txn_errors.insert(compute_txn_id(&stxn.txn).to_string(), msg.clone());
                    }
                    // reportWarnf(errorBroadcastingTX) — a warning, not fatal.
                    eprintln!("Couldn't broadcast tx with algod: {msg}");
                }
            }
        }
    });

    if args.no_wait {
        return Ok(ExitCode::SUCCESS);
    }

    // Poll each pending txn to confirmation. `last_valid == 0` waits until the
    // node either commits or evicts the txn (mirrors Go's per-round loop, which
    // has no explicit deadline beyond the node forgetting the txid).
    rt.block_on(async {
        for txid in &pending {
            let tid = algo_rest_client::TxId(txid.clone());
            match pipeline.wait_for_confirmation(&tid, 0).await {
                Ok(info) => {
                    if let Some(round) = info.confirmed_round {
                        // infoTxCommitted (messages.go:113).
                        println!("Transaction {txid} committed in round {round}");
                    }
                }
                Err(e) => {
                    txn_errors.insert(txid.clone(), e.to_string());
                    eprintln!("Error processing command: {e}");
                }
            }
        }
    });

    if !txn_errors.is_empty() {
        println!(
            "Encountered errors in sending {} transactions:",
            txn_errors.len()
        );
        let mut rejects_data = Vec::new();
        // Preserve the original file order so groups stay together (clerk.go:684).
        for stxn in &txns {
            let txid = compute_txn_id(&stxn.txn).to_string();
            if let Some(err) = txn_errors.get(&txid) {
                println!("  {txid}: {err}");
                rejects_data.extend_from_slice(&canonical_encode_signed_transaction(stxn));
            }
        }
        // O_EXCL: refuse to clobber an existing rejects file (clerk.go:695).
        write_new_file(&rejects_filename, &rejects_data)?;
        println!(
            "Rejected transactions written to {}",
            rejects_filename.display()
        );
        return Ok(ExitCode::from(1));
    }

    Ok(ExitCode::SUCCESS)
}

/// Partition signed transactions into groups, preserving first-seen order.
/// Mirrors `bookkeeping.SignedTxnsToGroups`: contiguous runs sharing a non-zero
/// group ID form a group; a zero group ID (ungrouped) is its own singleton.
fn signed_txns_to_groups(txns: &[SignedTransaction]) -> Vec<Vec<SignedTransaction>> {
    let mut groups: Vec<Vec<SignedTransaction>> = Vec::new();
    let mut current: Vec<SignedTransaction> = Vec::new();
    for stxn in txns {
        if stxn.txn.group == [0u8; 32] {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
            groups.push(vec![stxn.clone()]);
            continue;
        }
        if let Some(first) = current.first() {
            if first.txn.group != stxn.txn.group {
                groups.push(std::mem::take(&mut current));
            }
        }
        current.push(stxn.clone());
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

/// Write `data` to `path`, failing if the file already exists (Go's
/// `os.O_WRONLY|O_CREATE|O_EXCL`).
fn write_new_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Cannot write file {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("Cannot write file {}: {e}", path.display()))?;
    Ok(())
}

// ---- shared client + wallet helpers (mirrors crate::cmd::account) ---------

fn is_valid_api_token(token: &str) -> bool {
    (64..=256).contains(&token.len())
}

fn build_algod_endpoint(data_dir_path: &Path) -> Option<(String, String)> {
    let net = std::fs::read_to_string(data_dir_path.join("algod.net")).ok()?;
    let net = net.trim();
    if net.is_empty() {
        return None;
    }
    let admin = data_dir::read_algod_admin_token(data_dir_path)
        .ok()
        .filter(|t| is_valid_api_token(t));
    let tok = match admin {
        Some(t) => t,
        None => data_dir::read_algod_token(data_dir_path)
            .ok()
            .filter(|t| is_valid_api_token(t))?,
    };
    let base = if net.starts_with("http://") || net.starts_with("https://") {
        net.to_string()
    } else {
        format!("http://{net}")
    };
    Some((base, tok))
}

fn build_algod_client_for_dir(dd: &Path) -> Result<algo_rest_client::AlgodClient, String> {
    let (base, token) = build_algod_endpoint(dd)
        .ok_or_else(|| "Could not contact algod: algod.net/algod.token missing".to_string())?;
    Ok(algo_rest_client::AlgodClient::new(&base, &token))
}

fn build_kmd_client(
    data_dir_path: &Path,
    kmd_dir_flag: Option<&Path>,
) -> Result<KmdClient, String> {
    let kmd_dir =
        data_dir::resolve_kmd_data_dir(kmd_dir_flag, data_dir_path).map_err(|e| e.to_string())?;
    let net = std::fs::read_to_string(kmd_dir.join("kmd.net"))
        .map_err(|_| ERROR_KMD_UNREACHABLE.to_string())?;
    let tok = std::fs::read_to_string(kmd_dir.join("kmd.token"))
        .map_err(|_| ERROR_KMD_UNREACHABLE.to_string())?;
    let net = net.trim();
    let tok = tok.trim();
    if net.is_empty() || tok.is_empty() {
        return Err(ERROR_KMD_UNREACHABLE.to_string());
    }
    KmdClient::new(net, tok).map_err(|e| e.to_string())
}

/// Mirrors `getWalletHandleMaybePassword(true)` (commands.go:342-410); a port
/// of the same helper in `crate::cmd::account`. Returns (handle, name, pw).
fn resolve_wallet_and_init(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    accounts: &mut AccountsList,
    wallet_flag: Option<&str>,
    password_flag: Option<&str>,
) -> Result<(String, String, String), String> {
    let (wallet_id, wallet_name) =
        match wallet_flag {
            Some(name) => {
                let listed = rt
                    .block_on(client.list_wallets())
                    .map_err(|e| format!("Request failed: {}", kmd_msg(&e)))?;
                let mut matched: Option<String> = None;
                for w in listed.wallets {
                    if w.name == name {
                        if matched.is_some() {
                            return Err(format!(
                                "Wallet name '{name}' is ambiguous; multiple wallets share it."
                            ));
                        }
                        matched = Some(w.id);
                    }
                }
                match matched {
                    Some(id) => (id, name.to_string()),
                    None => return Err(format!("Could not find a wallet named '{name}'.")),
                }
            }
            None => {
                let mut wallet_id = accounts.default_wallet_id.clone();
                let mut wallet_name = String::new();
                if wallet_id.is_empty() {
                    let listed = rt
                        .block_on(client.list_wallets())
                        .map_err(|e| format!("Request failed: {}", kmd_msg(&e)))?;
                    match listed.wallets.len() {
                        0 => return Err(
                            "Wallet not found. Create a wallet using `goal wallet new` and try \
                             again."
                                .to_string(),
                        ),
                        1 => {
                            wallet_id = listed.wallets[0].id.clone();
                            wallet_name = listed.wallets[0].name.clone();
                            let _ = accounts.set_default_wallet_id(&wallet_id);
                        }
                        _ => return Err(
                            "More than one wallet exists; please specify which one to use with -w."
                                .to_string(),
                        ),
                    }
                }
                if wallet_name.is_empty() {
                    if let Ok(listed) = rt.block_on(client.list_wallets()) {
                        for w in listed.wallets {
                            if w.id == wallet_id {
                                wallet_name = w.name;
                                break;
                            }
                        }
                    }
                }
                (wallet_id, wallet_name)
            }
        };

    let password = match password_flag {
        Some(p) => p.to_string(),
        None => read_password_for(&wallet_name)?,
    };

    let handle = rt
        .block_on(client.init_wallet(&wallet_id, &password))
        .map_err(|e| format!("Request failed: {}", kmd_msg(&e)))?
        .wallet_handle_token;
    Ok((handle, wallet_name, password))
}

fn read_password_for(wallet_name: &str) -> Result<String, String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        print!("Please enter the password for wallet '{wallet_name}': ");
        let _ = std::io::stdout().flush();
        let pw = rpassword::read_password().map_err(|e| format!("Request failed: {e}"))?;
        println!();
        Ok(pw)
    } else {
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("Request failed: {e}"))?;
        let trimmed = line.strip_suffix('\n').unwrap_or(&line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        Ok(trimmed.to_string())
    }
}

fn kmd_msg(e: &KmdError) -> String {
    match e {
        KmdError::Api { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Transaction, TxnType};

    fn sample_payment(amount: u64, receiver: [u8; 32]) -> Transaction {
        Transaction {
            txn_type: TxnType::Pay,
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1001.into(),
            genesis_hash: [9u8; 32],
            amount,
            receiver: Address(receiver),
            ..Transaction::default()
        }
    }

    fn unsigned(txn: Transaction) -> SignedTransaction {
        SignedTransaction {
            txn,
            ..SignedTransaction::default()
        }
    }

    #[test]
    fn split_ext_matches_filepath_ext() {
        assert_eq!(
            split_ext("out.txn"),
            ("out".to_string(), ".txn".to_string())
        );
        assert_eq!(split_ext("out"), ("out".to_string(), String::new()));
        // Only the final path component's extension counts.
        assert_eq!(
            split_ext("dir.v2/out"),
            ("dir.v2/out".to_string(), String::new())
        );
        assert_eq!(
            split_ext("a/b/out.tx"),
            ("a/b/out".to_string(), ".tx".to_string())
        );
        // A leading dot in the final component is still an extension to
        // filepath.Ext.
        assert_eq!(split_ext(".rej"), (String::new(), ".rej".to_string()));
    }

    #[test]
    fn group_assigns_shared_group_id() {
        let a = unsigned(sample_payment(1, [2u8; 32]));
        let b = unsigned(sample_payment(2, [3u8; 32]));
        let txns = [a.txn.clone(), b.txn.clone()];
        let gid = compute_group_id(&txns);
        assert!(!gid.is_zero());

        // Both transactions should carry the same group hash, and recomputing
        // the group ID over the now-grouped txns (grp zeroed internally) is
        // stable.
        let mut grouped: Vec<SignedTransaction> = vec![a, b];
        for s in &mut grouped {
            s.txn.group = gid.0;
        }
        let regrouped: Vec<Transaction> = grouped.iter().map(|s| s.txn.clone()).collect();
        assert_eq!(compute_group_id(&regrouped), gid, "group id must be stable");
        assert_eq!(grouped[0].txn.group, grouped[1].txn.group);
    }

    #[test]
    fn signed_txns_to_groups_partitions_by_group_id() {
        // Two txns sharing a group, then one ungrouped singleton.
        let mut g1a = unsigned(sample_payment(1, [2u8; 32]));
        let mut g1b = unsigned(sample_payment(2, [3u8; 32]));
        g1a.txn.group = [7u8; 32];
        g1b.txn.group = [7u8; 32];
        let solo = unsigned(sample_payment(3, [4u8; 32]));

        let groups = signed_txns_to_groups(&[g1a, g1b, solo]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2, "the grouped pair stays together");
        assert_eq!(groups[1].len(), 1, "the ungrouped txn is its own group");
    }

    #[test]
    fn inspect_json_renders_addresses_base32() {
        let txn = sample_payment(5, [0xAB; 32]);
        let stxn = unsigned(txn.clone());
        let json = inspect_signed_txn_json(&stxn);
        let inner = &json["txn"];
        // snd/rcv are Address-typed → base32 (matches goal inspect).
        assert_eq!(
            inner["snd"].as_str().unwrap(),
            Address([1u8; 32]).to_algorand_string()
        );
        assert_eq!(
            inner["rcv"].as_str().unwrap(),
            Address([0xAB; 32]).to_algorand_string()
        );
        // gh is a Digest → base64, NOT base32.
        assert_eq!(
            inner["gh"].as_str().unwrap(),
            base64::engine::general_purpose::STANDARD.encode([9u8; 32])
        );
        assert_eq!(inner["amt"].as_u64().unwrap(), 5);
        assert_eq!(inner["type"].as_str().unwrap(), "pay");
    }

    #[test]
    fn inspect_json_renders_apat_accounts_base32() {
        // App-call with an Accounts reference list (apat) — each element is an
        // Address and must render base32, not base64 (Codex round 1, finding 1).
        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1001.into(),
            genesis_hash: [9u8; 32],
            application_id: 42,
            accounts: Some(vec![Address([0x55; 32]), Address([0x66; 32])]),
            ..Transaction::default()
        };
        let json = inspect_signed_txn_json(&unsigned(txn));
        let apat = json["txn"]["apat"].as_array().expect("apat array");
        assert_eq!(apat.len(), 2);
        assert_eq!(
            apat[0].as_str().unwrap(),
            Address([0x55; 32]).to_algorand_string()
        );
        assert_eq!(
            apat[1].as_str().unwrap(),
            Address([0x66; 32]).to_algorand_string()
        );
    }

    #[test]
    fn inspect_json_keeps_stateproof_commit_base64() {
        // sp.c (StateProofBody.sig_commit) is a byte digest, NOT an address —
        // it must render base64 even at 32 bytes, despite "c" meaning a
        // (clawback) address under "apar" (Codex round 2 collision finding).
        use algo_types::StateProofBody;
        let commit = vec![0x7Au8; 32];
        let txn = Transaction {
            txn_type: TxnType::Stpf,
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1001.into(),
            genesis_hash: [9u8; 32],
            state_proof_type: 0,
            state_proof: Some(StateProofBody {
                sig_commit: commit.clone().into(),
                signed_weight: 5,
                ..StateProofBody::default()
            }),
            ..Transaction::default()
        };
        let json = inspect_signed_txn_json(&unsigned(txn));
        let c = json["txn"]["sp"]["c"].as_str().expect("sp.c present");
        assert_eq!(
            c,
            base64::engine::general_purpose::STANDARD.encode(&commit),
            "state-proof commit must stay base64, not an address"
        );
    }

    #[test]
    fn inspect_json_renders_assetparams_addresses_base32() {
        // apar.m/r/f/c are AssetParams addresses → base32 (context-sensitive:
        // "c" under "apar" is an address, but under "sp" it's a digest).
        use algo_types::AssetParams;
        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1001.into(),
            genesis_hash: [9u8; 32],
            asset_params: Some(AssetParams {
                total: 100,
                clawback: Some(Address([0xCC; 32])),
                manager: Some(Address([0x11; 32])),
                ..AssetParams::default()
            }),
            ..Transaction::default()
        };
        let json = inspect_signed_txn_json(&unsigned(txn));
        assert_eq!(
            json["txn"]["apar"]["c"].as_str().unwrap(),
            Address([0xCC; 32]).to_algorand_string()
        );
        assert_eq!(
            json["txn"]["apar"]["m"].as_str().unwrap(),
            Address([0x11; 32]).to_algorand_string()
        );
    }

    #[test]
    fn write_file_0600_dash_goes_to_stdout_not_a_file() {
        // `-` must write to stdout (Go's writeFile), never create a file named
        // "-" in the cwd.
        let cwd = std::env::current_dir().expect("cwd");
        let dash = cwd.join("-");
        let pre_existing = dash.exists();
        write_file_0600(Path::new("-"), b"to-stdout").expect("stdout write ok");
        // We didn't create a `-` file (unless one already existed before).
        if !pre_existing {
            assert!(
                !dash.exists(),
                "write_file_0600(\"-\") must not create a file"
            );
        }
        // A real path still writes a file.
        let tmp = std::env::temp_dir().join(format!("task291-wf-{}.bin", std::process::id()));
        write_file_0600(&tmp, b"hello").expect("file write ok");
        assert_eq!(std::fs::read(&tmp).expect("read back"), b"hello");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn stream_round_trips_through_canonical_encode() {
        let a = unsigned(sample_payment(1, [2u8; 32]));
        let b = unsigned(sample_payment(2, [3u8; 32]));
        let mut buf = Vec::new();
        buf.extend_from_slice(&canonical_encode_signed_transaction(&a));
        buf.extend_from_slice(&canonical_encode_signed_transaction(&b));
        let decoded = decode_signed_txn_stream(&buf).expect("decode stream");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].txn.amount, 1);
        assert_eq!(decoded[1].txn.amount, 2);
    }

    fn simulate_args() -> SimulateArgs {
        SimulateArgs {
            txfile: None,
            request: None,
            request_only_out: None,
            result_out: None,
            round: None,
            allow_empty_signatures: false,
            allow_more_logging: false,
            allow_more_opcode_budget: false,
            extra_opcode_budget: None,
            allow_unnamed_resources: false,
            full_trace: false,
            trace: false,
            stack: false,
            scratch: false,
            state: false,
        }
    }

    #[test]
    fn build_simulate_request_wraps_txns_in_one_group() {
        let dir = tempfile::tempdir().unwrap();
        let txfile = dir.path().join("group.txn");
        let a = unsigned(sample_payment(1, [2u8; 32]));
        let b = unsigned(sample_payment(2, [3u8; 32]));
        let mut buf = Vec::new();
        buf.extend_from_slice(&canonical_encode_signed_transaction(&a));
        buf.extend_from_slice(&canonical_encode_signed_transaction(&b));
        std::fs::write(&txfile, &buf).unwrap();

        let args = simulate_args();
        let req = build_simulate_request(&txfile, &args, None).expect("build request");
        let groups = req["txn-groups"].as_array().expect("txn-groups array");
        assert_eq!(groups.len(), 1);
        let txns = groups[0]["txns"].as_array().expect("txns array");
        assert_eq!(txns.len(), 2);
        // No optional flags ⇒ those keys are omitted (matches Go's omitempty).
        assert!(req.get("round").is_none());
        assert!(req.get("allow-empty-signatures").is_none());
        assert!(req.get("exec-trace-config").is_none());
    }

    #[test]
    fn build_simulate_request_sets_flags_and_trace() {
        let dir = tempfile::tempdir().unwrap();
        let txfile = dir.path().join("one.txn");
        std::fs::write(
            &txfile,
            canonical_encode_signed_transaction(&unsigned(sample_payment(1, [2u8; 32]))),
        )
        .unwrap();

        let mut args = simulate_args();
        args.round = Some(7);
        args.allow_empty_signatures = true;
        args.allow_more_logging = true;
        args.allow_unnamed_resources = true;
        // --full-trace turns on enable + stack + scratch + state.
        args.full_trace = true;

        let req = build_simulate_request(&txfile, &args, Some(123)).expect("build request");
        assert_eq!(req["round"], 7);
        assert_eq!(req["allow-empty-signatures"], true);
        assert_eq!(req["allow-more-logging"], true);
        assert_eq!(req["allow-unnamed-resources"], true);
        assert_eq!(req["extra-opcode-budget"], 123);
        let trace = &req["exec-trace-config"];
        assert_eq!(trace["enable"], true);
        assert_eq!(trace["stack-change"], true);
        assert_eq!(trace["scratch-change"], true);
        assert_eq!(trace["state-change"], true);
    }

    #[test]
    fn to_kmd_msig_maps_fields_and_handles_blank() {
        assert_eq!(
            to_kmd_msig(None),
            algo_kmd_api_types::common::MultisigSig::default()
        );

        let msig = algo_types::MultisigSig {
            version: 1,
            threshold: 2,
            subsigs: vec![
                algo_types::MultisigSubsig {
                    public_key: [7u8; 32],
                    signature: [0u8; 64],
                },
                algo_types::MultisigSubsig {
                    public_key: [8u8; 32],
                    signature: [9u8; 64],
                },
            ],
        };
        let kmd = to_kmd_msig(Some(&msig));
        assert_eq!(kmd.version, 1);
        assert_eq!(kmd.threshold, 2);
        assert_eq!(kmd.subsigs.len(), 2);
        assert_eq!(kmd.subsigs[0].public_key, [7u8; 32]);
        assert_eq!(kmd.subsigs[1].signature, [9u8; 64]);
    }

    fn msig_with_sigs(sigs: &[[u8; 64]]) -> algo_types::MultisigSig {
        algo_types::MultisigSig {
            version: 1,
            threshold: 2,
            subsigs: sigs
                .iter()
                .enumerate()
                .map(|(i, &s)| algo_types::MultisigSubsig {
                    public_key: [i as u8 + 1; 32],
                    signature: s,
                })
                .collect(),
        }
    }

    #[test]
    fn detect_conflicting_subsigs_accepts_disjoint_and_agreeing() {
        // alice signs slot 0, bob signs slot 1 — disjoint, no conflict.
        let a = msig_with_sigs(&[[1u8; 64], [0u8; 64], [0u8; 64]]);
        let b = msig_with_sigs(&[[0u8; 64], [2u8; 64], [0u8; 64]]);
        assert!(detect_conflicting_subsigs(&[a.clone(), b]).is_ok());
        // The same partial twice (self-merge / identical re-sign) agrees.
        assert!(detect_conflicting_subsigs(&[a.clone(), a]).is_ok());
        // Empty input is a no-op.
        assert!(detect_conflicting_subsigs(&[]).is_ok());
    }

    #[test]
    fn detect_conflicting_subsigs_rejects_conflicts() {
        // Two partials carry DIFFERENT non-blank sigs at slot 0 — Go's
        // errInvalidDuplicates.
        let a = msig_with_sigs(&[[1u8; 64], [0u8; 64]]);
        let b = msig_with_sigs(&[[9u8; 64], [0u8; 64]]);
        let err = detect_conflicting_subsigs(&[a, b]).unwrap_err();
        assert!(err.contains("invalid duplicates"), "got: {err}");
    }

    #[test]
    fn resolve_send_lsig_none_without_source() {
        assert!(resolve_send_lsig(None, None, None, &[]).unwrap().is_none());
    }

    #[test]
    fn resolve_send_lsig_rejects_multiple_sources() {
        // Any pair of the three program-source flags collides (clerk.go:374-385).
        let err = resolve_send_lsig(Some("a.teal"), None, Some("b.lsig"), &[]).unwrap_err();
        assert!(err.contains("at most one of"), "got: {err}");
        let err = resolve_send_lsig(None, Some("p.bin"), Some("b.lsig"), &[]).unwrap_err();
        assert!(err.contains("at most one of"), "got: {err}");
    }

    #[test]
    fn resolve_send_lsig_from_program_bytes_is_program_account() {
        // `-P`: raw program bytes act as the account; the sender default is the
        // program's escrow address (HashProgram).
        let dir = tempfile::tempdir().unwrap();
        let prog = dir.path().join("prog.bin");
        // `int 1` assembled for v2: 0x0220010122.
        let bytes = [0x02u8, 0x20, 0x01, 0x01, 0x22];
        std::fs::write(&prog, bytes).unwrap();
        let resolved = resolve_send_lsig(None, Some(prog.to_str().unwrap()), None, &[])
            .unwrap()
            .expect("resolved lsig");
        assert!(resolved.is_program_account);
        assert_eq!(resolved.lsig.logic.as_ref(), &bytes);
        assert_eq!(resolved.escrow_address, clerk_sign::program_address(&bytes));
    }

    #[test]
    fn resolve_send_lsig_from_program_source_assembles() {
        // `-F`: TEAL source assembled into a program account, with --argb64 args.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("prog.teal");
        std::fs::write(&src, "#pragma version 2\nint 1\n").unwrap();
        let resolved = resolve_send_lsig(
            Some(src.to_str().unwrap()),
            None,
            None,
            &["AQ==".to_string()],
        )
        .unwrap()
        .expect("resolved lsig");
        assert!(resolved.is_program_account);
        assert!(!resolved.lsig.logic.is_empty());
        let args = resolved.lsig.args.expect("args present");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].as_ref(), &[1u8]);
        // Escrow address is HashProgram of the assembled bytes.
        assert_eq!(
            resolved.escrow_address,
            clerk_sign::program_address(&resolved.lsig.logic)
        );
    }

    #[test]
    fn out_label_renders_path_or_empty() {
        assert_eq!(out_label(None), "");
        assert_eq!(out_label(Some(Path::new("out.tx"))), "out.tx");
    }
}
