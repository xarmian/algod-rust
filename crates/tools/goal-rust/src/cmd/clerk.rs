//! `goal-rust clerk` leaf handlers.
//!
//! Ports the payment path of `../go-algorand/cmd/goal/clerk.go`:
//! - `send` → clerk.go:348-576 (`sendCmd`), via `libgoal.ConstructPayment`
//!   (libgoal.go:571) and `computeValidityRounds` (libgoal.go:525).
//!
//! Signing + submission reuse the same build → sign (kmd) → submit → confirm
//! pipeline as the account keyreg leaves
//! ([`algo_txn_pipeline::TxnPipeline`]); the wallet-handle resolution mirrors
//! `crate::cmd::account` (Go's `getWalletHandleMaybePassword`).
//!
//! The rest of the `clerk` group (rawsend / sign / group / split / compile /
//! dryrun* / simulate / inspect / multisig / tealsign) is still stubbed — see
//! [`crate::groups::clerk`].

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_codec::canonical_encode_signed_transaction;
use algo_kmd_client::{KmdClient, KmdError};
use algo_types::{Address, SignedTransaction};
use base64::Engine;

use crate::accounts_list::AccountsList;
use crate::data_dir;
use crate::groups::clerk::SendArgs;

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

    // ConstructPayment fills the suggested fee when --fee is unset; an explicit
    // --fee (even 0) is honored verbatim (clerk.go:441-447).
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
