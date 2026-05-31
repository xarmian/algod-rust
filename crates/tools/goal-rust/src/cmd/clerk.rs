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
//!
//! Signing + submission reuse the same build → sign (kmd) → submit → confirm
//! pipeline as the account keyreg leaves
//! ([`algo_txn_pipeline::TxnPipeline`]); the wallet-handle resolution mirrors
//! `crate::cmd::account` (Go's `getWalletHandleMaybePassword`).
//!
//! The rest of the `clerk` group (sign / compile / dryrun* / simulate /
//! multisig / tealsign) is still stubbed — see [`crate::groups::clerk`].

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
use crate::data_dir;
use crate::groups::clerk::{GroupArgs, InspectArgs, RawsendArgs, SendArgs, SplitArgs};

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
    msgpack_to_inspect_json(&value, JsonKey::Root)
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

/// Map a (msgpack) field key to the `JsonKey` describing how its *value*'s byte
/// blobs should be rendered. Keys correspond to the codec tags Go uses for the
/// `basics.Address` / program-typed fields in `inspectSignedTxn`.
fn classify_key(key: &str) -> JsonKey {
    match key {
        // Transaction address fields (data/transactions/transaction.go) +
        // SignedTxn.AuthAddr ("sgnr") + msig subsig public key ("pk"). apar's
        // m/r/f/c (AssetParams manager/reserve/freeze/clawback) and apat
        // (accounts) are also addresses.
        "snd" | "rcv" | "close" | "asnd" | "arcv" | "aclose" | "fadd" | "rekey" | "sgnr" | "pk"
        | "m" | "r" | "f" | "c" => JsonKey::Address,
        // LogicSig program ("l"). apap/apsu (approval/clear programs) are plain
        // []byte in Go's inspect view → base64, so they are NOT classified here.
        "l" => JsonKey::Program,
        _ => JsonKey::Root,
    }
}

fn msgpack_to_inspect_json(value: &rmpv::Value, key: JsonKey) -> serde_json::Value {
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
                // Array element context inherits the parent key (e.g. "apat" is
                // an array of addresses, "arg" an array of byte blobs).
                .map(|v| msgpack_to_inspect_json(v, key))
                .collect(),
        ),
        Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key_str = k.as_str().unwrap_or("").to_string();
                let child_key = classify_key(&key_str);
                map.insert(key_str, msgpack_to_inspect_json(v, child_key));
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
