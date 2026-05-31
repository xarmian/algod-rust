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
//! The rest of the `clerk` group (compile / dryrun* / simulate / multisig) is
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
    GroupArgs, InspectArgs, RawsendArgs, SendArgs, SignArgs, SplitArgs, TealsignArgs,
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
/// [-N] [-o out [-s]] [-w wallet] [--password]`.
///
/// Mirrors Go's `sendCmd` (clerk.go:348-576). LogicSig / program-account
/// (`--from-program*`, `--logic-sig`, `--argb64`) and `--msig-params` paths are
/// out of scope and rejected up front (see [`SendArgs`]).
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

    // Validity-period flag guards (commands.go:543-551).
    if args.valid_rounds.is_some() && args.last_valid.is_some() {
        return Err("Only one of [--validrounds] or [--lastvalid] can be specified".to_string());
    }
    if matches!(args.valid_rounds, Some(0)) {
        return Err("[--validrounds] can not be zero".to_string());
    }

    let data_dir_path = data_dir::ensure_single_data_dir(&cli_d).map_err(|e| e.to_string())?;
    let accounts = AccountsList::load(&data_dir_path);

    // Resolve from (default account if unset) + to via the accountList name map
    // (clerk.go:397-403). Go falls back to the default account when -f is empty.
    let from_name = match args.from {
        Some(f) => f,
        None => {
            let def = accounts.default_account.clone();
            if def.is_empty() {
                return Err("no default account set; specify the sender with -f/--from".to_string());
            }
            def
        }
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

    let algod = build_algod_client_for_dir(&data_dir_path)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Request failed: {e}"))?;

    // The output-only path never needs kmd unless we're also asked to sign.
    let want_signature = args.out.is_none() || args.sign;
    let kmd = if want_signature {
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

    // --out: write the (optionally signed) transaction to a file instead of
    // broadcasting (clerk.go:565-573). `signTx := sign || (outFilename == "")`.
    if let Some(out_path) = args.out {
        let encoded = if want_signature {
            // kmd returns the already-msgpack-encoded SignedTxn bytes.
            let kmd = pipeline.kmd().ok_or("no kmd client configured")?;
            let mut accounts = AccountsList::load(&data_dir_path);
            let (handle, _wallet_name, password) = resolve_wallet_and_init(
                &rt,
                kmd,
                &mut accounts,
                wallet.as_deref(),
                args.password.as_deref(),
            )?;
            rt.block_on(pipeline.sign_with_kmd(&handle, &password, &txn))
                .map_err(|e| {
                    format!(
                        "Couldn't sign tx with kmd: {e} (for multisig accounts, write tx to file \
                         and sign manually)"
                    )
                })?
        } else {
            // Blank-sig SignedTxn so msgpack still encodes the txn type, matching
            // Go's `AssembleSignedTxn(tx, Signature{}, MultisigSig{})`.
            let stx = SignedTransaction {
                txn: txn.clone(),
                ..SignedTransaction::default()
            };
            canonical_encode_signed_transaction(&stx)
        };
        std::fs::write(&out_path, &encoded)
            .map_err(|e| format!("Cannot write file {}: {e}", out_path.display()))?;
        return Ok(ExitCode::SUCCESS);
    }

    // Broadcast path: sign via kmd, submit, report, optionally wait.
    let mut accounts = AccountsList::load(&data_dir_path);
    let kmd = pipeline.kmd().ok_or("no kmd client configured")?;
    let (handle, _wallet_name, password) = resolve_wallet_and_init(
        &rt,
        kmd,
        &mut accounts,
        wallet.as_deref(),
        args.password.as_deref(),
    )?;

    let last_valid = txn.last_valid.0;
    let result = rt.block_on(async {
        let signed = pipeline
            .sign_with_kmd(&handle, &password, &txn)
            .await
            .map_err(|e| {
                format!(
                    "Couldn't sign tx with kmd: {e} (for multisig accounts, write tx to file \
                     and sign manually)"
                )
            })?;
        let txid = pipeline
            .submit(&signed)
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

/// Write `data` to `path` with `0600` perms, mirroring Go's `writeFile(..,
/// 0600)` used by the signing paths.
fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), String> {
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
}
