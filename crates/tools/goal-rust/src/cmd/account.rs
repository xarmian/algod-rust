//! `goal-rust account` lifecycle leaves (TASK-235 / B3).
//!
//! Ports four lifecycle leaves from `../go-algorand/cmd/goal/account.go`:
//! - `new`   → account.go:313-359
//! - `delete`→ account.go:379-398
//! - `rename`→ account.go:281-310
//! - `dump`  → account.go:828-855 (REST-shaped pretty JSON — see
//!   [`crate::groups::account::DumpArgs`] for the intentional
//!   divergence vs Go's `protocol.EncodeJSONStrict(&BalanceRecord)`).
//!
//! Wallet-handle resolution mirrors Go's `getWalletHandleMaybePassword`
//! (commands.go:342-410): explicit `-w` ⇒ look up by name; no `-w` ⇒
//! use accountList.json's `DefaultWalletID`; if no default, fall back
//! to "single wallet auto-promotes to default"; else error.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_consensus_crypto::{key_to_mnemonic, mnemonic_to_key};
use algo_kmd_client::{KmdClient, KmdError};

use crate::accounts_list::AccountsList;
use crate::data_dir;
use crate::groups::account::{
    AddpartkeyArgs, AddressArgs, AssetdetailsArgs, DeleteArgs, DeletepartkeyArgs, DumpArgs,
    ExportArgs, ImportArgs, ImportRootKeyArgs, InfoArgs, InstallpartkeyArgs, ListArgs,
    MsigDeleteArgs, MsigInfoArgs, MsigNewArgs, NewArgs, RenameArgs, RenewallpartkeysArgs,
    RenewpartkeyArgs,
};

/// Mirrors `messages.go:32` (`infoRenamedAccount`).
const INFO_RENAMED_ACCOUNT: &str = "Renamed account '{}' to '{}'";

/// Mirrors `messages.go:36` (`infoCreatedNewAccount`).
const INFO_CREATED_NEW_ACCOUNT: &str = "Created new account with address {}";

/// Mirrors `messages.go:31` (`infoNoAccounts`).
const INFO_NO_ACCOUNTS: &str = "Did not find any account. Please import or create a new one.";

/// Mirrors `messages.go:37` (`errorNameAlreadyTaken`).
const ERROR_NAME_ALREADY_TAKEN: &str =
    "The account name '{}' is already taken, please choose another.";

/// Mirrors `messages.go:38` (`errorNameDoesntExist`).
const ERROR_NAME_DOESNT_EXIST: &str = "An account named '{}' does not exist.";

/// Mirrors Go's generic `errorRequestFail` template
/// (`messages.go:46`).
const ERROR_REQUEST_FAIL: &str = "Request failed: {}";

/// Mirrors `messages.go:194` for the wallet-password prompt.
const PROMPT_EXISTING_PASSWORD: &str = "Please enter the password for wallet '{}': ";

/// Mirrors Go's `Could not contact kmd; is it running?` error path.
const ERROR_KMD_UNREACHABLE: &str = "Could not contact kmd; is it running?";

/// Mirrors Go's `errNoWallets` / `errNoDefaultWallet` flavor.
const ERROR_NO_WALLETS: &str =
    "Wallet not found. Create a wallet using `goal wallet new` and try again.";
const ERROR_NO_DEFAULT_WALLET: &str =
    "More than one wallet exists; please specify which one to use with -w.";

// ---- account new ----------------------------------------------------------

pub fn run_new(args: NewArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    let mut accounts = AccountsList::load(&data_dir_path);

    // Pick the account name (positional or auto-generated).
    let account_name = match args.name {
        Some(n) => n,
        None => accounts.next_unnamed(),
    };

    // Mirror Go's isValidName guard (accountsList.go:48-52) — refuse
    // a name that parses as an Algorand address.
    if algo_types::Address::from_algorand_string(&account_name).is_ok() {
        eprintln!("An Algorand address cannot be used as an account name.");
        return ExitCode::from(1);
    }
    if accounts.is_taken(&account_name) {
        eprintln!(
            "{}",
            format_message(ERROR_NAME_ALREADY_TAKEN, &[&account_name])
        );
        return ExitCode::from(1);
    }

    // Resolve wallet + open handle.
    let (wallet_id, _wallet_name, _password) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };
    let handle = wallet_id; // resolve_wallet_and_init returns (handle, name, pw)

    // Generate the key.
    let generated = match rt.block_on(client.generate_key(&handle)) {
        Ok(g) => g.address,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };

    // Persist friendly name and (optionally) the new account as default.
    if let Err(e) = accounts.add_account(&account_name, &generated) {
        eprintln!("{e}");
        // Non-fatal: the kmd key exists; surface but exit 0 as Go's
        // dumpList silently logs.
    }
    if args.set_default {
        if let Err(e) = accounts.set_default(&account_name) {
            eprintln!("{e}");
        }
    }

    println!(
        "{}",
        format_message(INFO_CREATED_NEW_ACCOUNT, &[&generated])
    );
    ExitCode::SUCCESS
}

// ---- account list ---------------------------------------------------------

pub fn run_list(args: ListArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let accounts = AccountsList::load(&data_dir_path);

    // Enumerate wallets (filtered by -w if given).
    let listed = match rt.block_on(client.list_wallets()) {
        Ok(l) => l.wallets,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };
    let wallets: Vec<_> = match &args.wallet {
        Some(name) => {
            let filtered: Vec<_> = listed.into_iter().filter(|w| &w.name == name).collect();
            // An explicit -w that matches nothing should error rather
            // than silently print infoNoAccounts (Codex round-1 P2 — a
            // typo'd wallet name was previously indistinguishable from
            // an empty wallet). No -w + no wallets ⇒ still prints
            // infoNoAccounts below.
            if filtered.is_empty() {
                eprintln!("Could not find a wallet named '{name}'.");
                return ExitCode::from(1);
            }
            filtered
        }
        None => listed,
    };
    if wallets.is_empty() {
        // No wallets at all — Go prints infoNoAccounts.
        println!("{INFO_NO_ACCOUNTS}");
        return ExitCode::SUCCESS;
    }

    // Optional REST client for balances. Failure to read algod files
    // is non-fatal — we still list addresses with `[n/a]` balance.
    let algod = build_algod_endpoint(&data_dir_path);

    // Collect every (address, wallet_name) pair. init_wallet requires
    // a password; for non-interactive use, --password applies to ALL
    // wallets (kmd's single-password mode).
    let mut rows: Vec<AccountRow> = Vec::new();
    let mut had_kmd_error = false;
    for w in &wallets {
        // For each wallet, open a handle. Use the supplied password
        // (or prompt once per wallet on TTY). If init fails, log + skip.
        let pw = match &args.password {
            Some(p) => p.clone(),
            None => match read_password_for(&w.name) {
                Ok(p) => p,
                Err(()) => return ExitCode::from(1),
            },
        };
        let handle = match rt.block_on(client.init_wallet(&w.id, &pw)) {
            Ok(r) => r.wallet_handle_token,
            Err(e) => {
                eprintln!("Could not open wallet '{}': {}", w.name, kmd_msg(&e));
                had_kmd_error = true;
                continue;
            }
        };
        let key_list = match rt.block_on(client.list_keys(&handle)) {
            Ok(r) => r.addresses,
            Err(e) => {
                eprintln!(
                    "Could not list keys for wallet '{}': {}",
                    w.name,
                    kmd_msg(&e)
                );
                had_kmd_error = true;
                let _ = rt.block_on(client.release_wallet_handle(&handle));
                continue;
            }
        };
        // Multisig preimages are stored separately in kmd; Go's
        // ListAddressesWithInfo returns the union AND surfaces an
        // error if ListMultisigAddrs fails (mirror that — a silent
        // unwrap_or_default would let a wallet that holds only msig
        // preimages print infoNoAccounts and exit 0).
        let msig_list = match rt.block_on(client.list_multisig_addrs(&handle)) {
            Ok(r) => r.addresses,
            Err(e) => {
                eprintln!(
                    "Could not list multisig accounts for wallet '{}': {}",
                    w.name,
                    kmd_msg(&e)
                );
                had_kmd_error = true;
                let _ = rt.block_on(client.release_wallet_handle(&handle));
                continue;
            }
        };
        let _ = rt.block_on(client.release_wallet_handle(&handle));

        for addr in key_list {
            rows.push(AccountRow {
                address: addr,
                wallet_name: w.name.clone(),
                is_multisig: false,
            });
        }
        for addr in msig_list {
            rows.push(AccountRow {
                address: addr,
                wallet_name: w.name.clone(),
                is_multisig: true,
            });
        }
    }

    if rows.is_empty() {
        println!("{INFO_NO_ACCOUNTS}");
        return if had_kmd_error {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

    // Fetch balances + statuses (best-effort).
    let mut any_balance_error = false;
    for row in &rows {
        let (status, amount) = match &algod {
            Some((base, token)) => fetch_status_and_amount(&rt, base, token, &row.address)
                .unwrap_or_else(|_| {
                    any_balance_error = true;
                    ("n/a".to_string(), None)
                }),
            None => {
                any_balance_error = true;
                ("n/a".to_string(), None)
            }
        };
        // Go's getNameByAddress falls back to the address itself when
        // no friendly name is registered (accountsList.go:174-177);
        // `AccountsList::name_for` already does that. Use as-is —
        // earlier `<no name>` placeholder broke the fixed-column
        // contract (Codex round-2 finding).
        let name_display = accounts.name_for(&row.address);
        let amount_display = match amount {
            Some(a) => format!("{a} microAlgos"),
            None => "[n/a] microAlgos".to_string(),
        };
        // Column order matches Go's outputAccount (accountsList.go:207-280):
        // `[status]\t<name>\t<address>\t<amount> microAlgos[\t*Default]`.
        // Round-1 Codex review flagged that the earlier prefix-`*` /
        // address-before-name layout broke existing scripts that key
        // on field position.
        let default_suffix = if accounts.is_default(&row.address) {
            "\t*Default"
        } else {
            ""
        };
        let multisig_suffix = if row.is_multisig {
            // Go renders `\t[N/M multisig]` after the amount; we
            // don't yet know N/M without an export_multisig call
            // per address, so emit the constant marker. B8's
            // multisig leaves can fill in the threshold later.
            "\t[multisig]"
        } else {
            ""
        };
        println!(
            "[{status}]\t{name_display}\t{}\t{amount_display}{multisig_suffix}{default_suffix}",
            row.address
        );
    }

    if had_kmd_error {
        ExitCode::from(1)
    } else {
        // Balance fetch failures are non-fatal — Go's listCmd also
        // proceeds without algod info when AccountInformation errors
        // (account.go:519 "it's okay to proceed without algod info").
        let _ = any_balance_error;
        ExitCode::SUCCESS
    }
}

struct AccountRow {
    address: String,
    // wallet_name kept for future per-wallet headers (multi-wallet
    // grouping when len > 1). Currently informational only.
    #[allow(dead_code)]
    wallet_name: String,
    /// True if this address came from `list_multisig_addrs` rather
    /// than `list_keys`. Used to render `[multisig]` suffix matching
    /// Go's outputAccount path.
    is_multisig: bool,
}

/// Resolve algod base URL + token for the data dir. Returns None when
/// `algod.net` or `algod.token` is missing — list_addresses still
/// renders with `[n/a]` balances in that case.
fn build_algod_endpoint(data_dir_path: &Path) -> Option<(String, String)> {
    let net = std::fs::read_to_string(data_dir_path.join("algod.net")).ok()?;
    let tok = std::fs::read_to_string(data_dir_path.join("algod.token")).ok()?;
    let net = net.trim();
    let tok = tok.trim();
    if net.is_empty() || tok.is_empty() {
        return None;
    }
    let base = if net.starts_with("http://") || net.starts_with("https://") {
        net.to_string()
    } else {
        format!("http://{net}")
    };
    Some((base, tok.to_string()))
}

fn fetch_status_and_amount(
    rt: &tokio::runtime::Runtime,
    base: &str,
    token: &str,
    address: &str,
) -> Result<(String, Option<u64>), String> {
    let url = format!("{}/v2/accounts/{}", base.trim_end_matches('/'), address);
    rt.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .get(&url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let status_str = match v.get("status").and_then(|s| s.as_str()) {
            Some("Online") => "online",
            Some("Offline") => "offline",
            // Go renders NotParticipating as `[excluded]`
            // (accountsList.go:226). Match for parity.
            Some("NotParticipating") => "excluded",
            Some(other) => {
                // Pass through anything algod returns we don't model;
                // matches the spirit of Go's switch+default-panic by
                // surfacing the verbatim status instead.
                return Ok((other.to_string(), v.get("amount").and_then(|a| a.as_u64())));
            }
            None => "n/a",
        };
        let amount = v.get("amount").and_then(|a| a.as_u64());
        Ok::<_, String>((status_str.to_string(), amount))
    })
}

// ---- account delete -------------------------------------------------------

pub fn run_delete(
    args: DeleteArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, password) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };

    match rt.block_on(client.delete_key(&handle, &password, &args.address)) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    }
    if let Err(e) = accounts.remove_account(&args.address) {
        eprintln!("{e}");
        // Non-fatal: key was deleted server-side; the local-only
        // accountList.json entry didn't update cleanly. Surface, exit
        // success (Go's dumpList swallows write errors).
    }
    ExitCode::SUCCESS
}

// ---- account rename -------------------------------------------------------

pub fn run_rename(args: RenameArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let mut accounts = AccountsList::load(&data_dir_path);

    // isValidName(newName) — Go checks the *new* name only.
    if algo_types::Address::from_algorand_string(&args.new_name).is_ok() {
        eprintln!("An Algorand address cannot be used as an account name.");
        return ExitCode::from(1);
    }
    if !accounts.is_taken(&args.old_name) {
        eprintln!(
            "{}",
            format_message(ERROR_NAME_DOESNT_EXIST, &[&args.old_name])
        );
        return ExitCode::from(1);
    }
    if accounts.is_taken(&args.new_name) {
        eprintln!(
            "{}",
            format_message(ERROR_NAME_ALREADY_TAKEN, &[&args.new_name])
        );
        return ExitCode::from(1);
    }
    if let Err(e) = accounts.rename(&args.old_name, &args.new_name) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    println!(
        "{}",
        format_message(INFO_RENAMED_ACCOUNT, &[&args.old_name, &args.new_name])
    );
    ExitCode::SUCCESS
}

// ---- account dump ---------------------------------------------------------

pub fn run_dump(args: DumpArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    // Validate the address so a typo errors before we issue the HTTP
    // call (Go does the same in account.go:838-841 via
    // basics.UnmarshalChecksumAddress).
    if let Err(e) = algo_types::Address::from_algorand_string(&args.address) {
        eprintln!("Could not parse address: {e}");
        return ExitCode::from(1);
    }
    let net = match std::fs::read_to_string(data_dir_path.join("algod.net")) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("Could not contact algod: algod.net missing");
            return ExitCode::from(1);
        }
    };
    let token = match std::fs::read_to_string(data_dir_path.join("algod.token")) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("Could not contact algod: algod.token missing");
            return ExitCode::from(1);
        }
    };
    let base = if net.starts_with("http://") || net.starts_with("https://") {
        net
    } else {
        format!("http://{net}")
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    // Fetch as untyped JSON so unknown fields (assets, created-assets,
    // apps-local-state, created-apps, participation, etc.) round-trip
    // unmolested. The narrow `algo_rest_client::AccountInfo` deserialize
    // would silently drop them (Codex review TASK-235 round 1).
    let url = format!(
        "{}/v2/accounts/{}",
        base.trim_end_matches('/'),
        args.address
    );
    let body_result = rt.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .get(&url)
            .header("X-Algo-API-Token", &token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes).trim()
            ));
        }
        // Re-pretty-print to match Go's MarshalIndent shape (2-space
        // indent). Use serde_json::Value so all REST fields survive.
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from algod: {e}"))?;
        let pretty =
            serde_json::to_string_pretty(&parsed).map_err(|e| format!("re-encode failed: {e}"))?;
        Ok::<String, String>(pretty)
    });
    let body = match body_result {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e]));
            return ExitCode::from(1);
        }
    };
    match args.outfile {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, body.as_bytes()) {
                eprintln!("Failed to write {}: {e}", path.display());
                return ExitCode::from(1);
            }
        }
        None => println!("{body}"),
    }
    ExitCode::SUCCESS
}

// ---- shared helpers -------------------------------------------------------

fn build_runtime() -> Result<tokio::runtime::Runtime, ()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        })
}

fn build_kmd_client(data_dir_path: &Path, kmd_dir_flag: Option<&Path>) -> Result<KmdClient, ()> {
    let kmd_dir = data_dir::resolve_kmd_data_dir(kmd_dir_flag, data_dir_path).map_err(|e| {
        eprintln!("{e}");
    })?;
    let net = std::fs::read_to_string(kmd_dir.join("kmd.net")).map_err(|_| {
        eprintln!("{ERROR_KMD_UNREACHABLE}");
    })?;
    let tok = std::fs::read_to_string(kmd_dir.join("kmd.token")).map_err(|_| {
        eprintln!("{ERROR_KMD_UNREACHABLE}");
    })?;
    let net = net.trim();
    let tok = tok.trim();
    if net.is_empty() || tok.is_empty() {
        eprintln!("{ERROR_KMD_UNREACHABLE}");
        return Err(());
    }
    KmdClient::new(net, tok).map_err(|e| {
        eprintln!("{e}");
    })
}

/// Mirrors `getWalletHandleMaybePassword(true)` —
/// `commands.go:342-410`. Returns (handle, wallet_name, password).
fn resolve_wallet_and_init(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    accounts: &mut AccountsList,
    wallet_flag: Option<&str>,
    password_flag: Option<&str>,
) -> Result<(String, String, String), ()> {
    // 1. Resolve wallet ID + name.
    let (wallet_id, wallet_name) = match wallet_flag {
        Some(name) => {
            // Find by name.
            let listed = rt.block_on(client.list_wallets()).map_err(|e| {
                eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            })?;
            let mut matched: Option<String> = None;
            for w in listed.wallets {
                if w.name == name {
                    if matched.is_some() {
                        eprintln!("Wallet name '{name}' is ambiguous; multiple wallets share it.");
                        return Err(());
                    }
                    matched = Some(w.id);
                }
            }
            match matched {
                Some(id) => (id, name.to_string()),
                None => {
                    eprintln!("Could not find a wallet named '{name}'.");
                    return Err(());
                }
            }
        }
        None => {
            // No -w: use accountList.json's default, or fall back to
            // single-wallet auto-promote.
            let mut wallet_id = accounts.default_wallet_id.clone();
            let mut wallet_name = String::new();
            if wallet_id.is_empty() {
                let listed = rt.block_on(client.list_wallets()).map_err(|e| {
                    eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
                })?;
                match listed.wallets.len() {
                    0 => {
                        eprintln!("{ERROR_NO_WALLETS}");
                        return Err(());
                    }
                    1 => {
                        wallet_id = listed.wallets[0].id.clone();
                        wallet_name = listed.wallets[0].name.clone();
                        // Promote to default (best-effort, mirrors Go's
                        // accountList.setDefaultWalletID call).
                        let _ = accounts.set_default_wallet_id(&wallet_id);
                    }
                    _ => {
                        eprintln!("{ERROR_NO_DEFAULT_WALLET}");
                        return Err(());
                    }
                }
            }
            if wallet_name.is_empty() {
                // Look up name for prompting / error messages.
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

    // 2. Resolve password.
    let password = match password_flag {
        Some(p) => p.to_string(),
        None => read_password_for(&wallet_name)?,
    };

    // 3. Init handle.
    let handle = rt
        .block_on(client.init_wallet(&wallet_id, &password))
        .map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
        })?
        .wallet_handle_token;
    Ok((handle, wallet_name, password))
}

fn read_password_for(wallet_name: &str) -> Result<String, ()> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        use std::io::Write;
        print!(
            "{}",
            format_message(PROMPT_EXISTING_PASSWORD, &[wallet_name])
        );
        let _ = std::io::stdout().flush();
        let pw = rpassword::read_password().map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        })?;
        println!();
        Ok(pw)
    } else {
        let mut line = String::new();
        if let Err(e) = stdin.lock().read_line(&mut line) {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
            return Err(());
        }
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

fn format_message(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut i = 0;
    while let Some(idx) = rest.find("{}") {
        out.push_str(&rest[..idx]);
        if i < args.len() {
            out.push_str(args[i]);
            i += 1;
        }
        rest = &rest[idx + 2..];
    }
    out.push_str(rest);
    out
}

// ---- account import / export (TASK-238 / B6) ------------------------------

/// `account import [name] [-w] [--password] [--mnemonic] [-f]` —
/// recover a key from a 25-word mnemonic into the chosen wallet's kmd.
/// Mirrors `importCmd` (account.go:1281-1338).
pub fn run_import(
    args: ImportArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    let mut accounts = AccountsList::load(&data_dir_path);

    // Account name selection (same isValidName / isTaken guards as
    // run_new — account.go:1289-1303).
    let account_name = match args.name {
        Some(n) => n,
        None => accounts.next_unnamed(),
    };
    if algo_types::Address::from_algorand_string(&account_name).is_ok() {
        eprintln!("An Algorand address cannot be used as an account name.");
        return ExitCode::from(1);
    }
    if accounts.is_taken(&account_name) {
        eprintln!(
            "{}",
            format_message(ERROR_NAME_ALREADY_TAKEN, &[&account_name])
        );
        return ExitCode::from(1);
    }

    // Read the mnemonic (--mnemonic flag overrides stdin).
    let mnemonic = match args.mnemonic {
        Some(m) => m,
        None => {
            // Go prints `fmt.Println(infoRecoveryPrompt)` → prompt + \n.
            println!(
                "Please type your recovery mnemonic below, and hit return when you are done: "
            );
            let mut line = String::new();
            if let Err(e) = std::io::stdin().lock().read_line(&mut line) {
                eprintln!("Failed to read mnemonic: {e}");
                return ExitCode::from(1);
            }
            line.trim().to_string()
        }
    };

    // Decode mnemonic → 32-byte seed.
    let seed = match mnemonic_to_key(&mnemonic) {
        Ok(k) => k,
        Err(e) => {
            // messages.go:187: `errorBadMnemonic = "Problem with mnemonic: %s"`
            eprintln!("Problem with mnemonic: {e}");
            return ExitCode::from(1);
        }
    };

    // kmd expects 64-byte expanded SK: seed[0..32] || pubkey[32..64].
    let expanded = expand_seed_to_sk(&seed);

    // Resolve wallet + open handle.
    let (handle, _wallet_name, _password) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };

    let imported = match rt.block_on(client.import_key(&handle, expanded)) {
        Ok(r) => r.address,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };

    println!("Imported {imported}"); // messages.go:33

    // Persist friendly name + optional default.
    if let Err(e) = accounts.add_account(&account_name, &imported) {
        eprintln!("{e}");
    }
    if args.set_default {
        if let Err(e) = accounts.set_default(&account_name) {
            eprintln!("{e}");
        }
    }

    ExitCode::SUCCESS
}

/// `account export -a <addr> [-w] [--password]` — export the account
/// key as a 25-word mnemonic. Mirrors `exportCmd`
/// (account.go:1339-1371).
pub fn run_export(
    args: ExportArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = algo_types::Address::from_algorand_string(&args.address) {
        eprintln!("Could not parse address: {e}");
        return ExitCode::from(1);
    }
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, password) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };

    let exported = match rt.block_on(client.export_key(&handle, &password, &args.address)) {
        Ok(r) => r.private_key,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };

    // First 32 bytes of the expanded SK is the seed (kmd-rust's
    // `keypair_from_expanded` at keys.rs:74-82 confirms the layout
    // and validates pubkey consistency on the server side).
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&exported[..32]);
    let mnemonic = match key_to_mnemonic(&seed) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Could not convert key to mnemonic: {e}");
            return ExitCode::from(1);
        }
    };

    // messages.go:34: `infoExportedKey = "Exported key for account %s: \"%s\""`
    println!("Exported key for account {}: \"{mnemonic}\"", args.address);
    ExitCode::SUCCESS
}

/// Build kmd's expanded 64-byte SK from a 32-byte seed by deriving the
/// public key via ed25519 and laying out `seed[0..32] || pubkey[32..64]`.
/// Matches `keypair_from_seed` in kmd-rust (`keys.rs:60-67`) and the
/// canonical Ed25519/libsodium representation Algorand uses.
fn expand_seed_to_sk(seed: &[u8; 32]) -> [u8; 64] {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let pubkey: [u8; 32] = signing.verifying_key().to_bytes();
    let mut sk = [0u8; 64];
    sk[..32].copy_from_slice(seed);
    sk[32..].copy_from_slice(&pubkey);
    sk
}

// ---- account partkey leaves (TASK-242 / B10) ------------------------------

/// `account addpartkey -a <addr> --roundFirstValid <r> --roundLastValid <r>
/// [--keyDilution <n>]`. Mirrors `addParticipationKeyCmd`
/// (account.go:973-1011). See [`AddpartkeyArgs`] for the documented
/// divergence from Go (REST server-side generation vs client-side).
pub fn run_addpartkey(args: AddpartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    if let Err(e) = algo_types::Address::from_algorand_string(&args.address) {
        eprintln!("Could not parse address: {e}");
        return ExitCode::from(1);
    }
    // Inclusive range — `algokey-rust part generate` accepts
    // last==first (a one-round participation key) and only rejects
    // last < first. Codex round-1 finding.
    if args.round_last_valid < args.round_first_valid {
        eprintln!(
            "--roundLastValid ({}) must be >= --roundFirstValid ({})",
            args.round_last_valid, args.round_first_valid
        );
        return ExitCode::from(1);
    }

    let client = match build_algod_client(&cli_d) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    println!("Please stand by while generating keys. This might take a few minutes...");
    if let Err(e) = rt.block_on(client.generate_participation_keys(
        &args.address,
        args.round_first_valid,
        args.round_last_valid,
        args.key_dilution,
    )) {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        return ExitCode::from(1);
    }
    // Go prints the new ParticipationID; the REST generate endpoint
    // currently returns just "{}" (handlers.go:300 — future
    // enrichment), so we surface a generic success message instead.
    println!(
        "Participation key generation requested for {}.",
        args.address
    );
    ExitCode::SUCCESS
}

/// `account installpartkey --partkey <path> --delete-input`. Mirrors
/// `installParticipationKeyCmd` (account.go:1012-1052).
pub fn run_installpartkey(args: InstallpartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    if !args.delete_input {
        // Byte-exact Go refusal text (account.go:1017-1026).
        eprintln!("The installpartkey command deletes the input participation file on");
        eprintln!("successful installation.  Please acknowledge this by passing the");
        eprintln!("\"--delete-input\" flag to the installpartkey command.  You can make");
        eprintln!("a copy of the input file if needed, but please keep in mind that");
        eprintln!("participation keys must be securely deleted for each round, to ensure");
        eprintln!("forward security.  Storing old participation keys compromises overall");
        eprintln!("system security.");
        eprintln!();
        eprintln!("No --delete-input flag specified, exiting without installing key.");
        return ExitCode::from(1);
    }
    let client = match build_algod_client(&cli_d) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let bytes = match std::fs::read(&args.partkey) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Could not read {}: {e}", args.partkey.display());
            return ExitCode::from(1);
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let part_id = match rt.block_on(client.add_participation_key(&bytes)) {
        Ok(r) => r.part_id,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
            return ExitCode::from(1);
        }
    };

    // Verify the key is actually installed before deleting the input
    // file. Mirrors Go's `client.VerifyParticipationKey(time.Minute,
    // addResponse.PartId)` (account.go:1040-1045) — algod can ack
    // the POST then drop the key, and silently deleting the only copy
    // would leave the operator with no way to retry. Poll
    // list_participation_keys for up to 60s. Codex round-1 P1 finding.
    let verified = rt.block_on(async {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match client.list_participation_keys().await {
                Ok(parts) => {
                    if parts.iter().any(|p| p.id == part_id) {
                        return Ok::<(), String>(());
                    }
                }
                Err(e) => return Err(e.to_string()),
            }
            if std::time::Instant::now() >= deadline {
                return Err("key install acknowledged but not visible after 60s".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
    if let Err(why) = verified {
        eprintln!(
            "unable to verify key installation. Verify with 'goal account partkeyinfo' \
             and delete '{}', or retry the command. Error: {why}",
            args.partkey.display(),
        );
        return ExitCode::from(1);
    }

    println!("Participation key installed successfully, Participation ID: {part_id}");
    // Go deletes the input file on success (account.go:1048-1051).
    if let Err(e) = std::fs::remove_file(&args.partkey) {
        eprintln!(
            "An error occurred while removing the partkey file, please delete it manually: {e}"
        );
    }
    ExitCode::SUCCESS
}

/// `account listpartkeys`. Mirrors `listParticipationKeysCmd`
/// (account.go:1220-1278). Columns + format match Go's hdrFormat /
/// rowFormat (squeezed to 77 chars wide).
pub fn run_listpartkeys(cli_d: Vec<PathBuf>) -> ExitCode {
    let client = match build_algod_client(&cli_d) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let parts = match rt.block_on(client.list_participation_keys()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
            return ExitCode::from(1);
        }
    };
    // Mirror Go's `%-10s  %-11s  %-15s  %10s  %11s  %10s\n` header
    // (account.go:1235-1237).
    println!(
        "{:<10}  {:<11}  {:<15}  {:>10}  {:>11}  {:>10}",
        "Registered", "Account", "ParticipationID", "Last Used", "First round", "Last round"
    );
    for part in &parts {
        // Online / registered determination requires AccountInformation
        // — we don't compute it (would require a per-row REST call and
        // doesn't change the table shape). Show `?` instead.
        let online = "?";
        let addr_short = if part.address.len() >= 8 {
            format!(
                "{}...{}",
                &part.address[..4],
                &part.address[part.address.len() - 4..]
            )
        } else {
            part.address.clone()
        };
        let id_short = if part.id.len() >= 8 {
            format!("{}...", &part.id[..8])
        } else {
            part.id.clone()
        };
        let last_used = part
            .last_vote
            .max(part.last_block_proposal)
            .max(part.last_state_proof)
            .unwrap_or(0);
        let last_used_str = if last_used == 0 {
            "N/A".to_string()
        } else {
            last_used.to_string()
        };
        println!(
            "{:<10}  {:<11}  {:<15}  {:>10}  {:>11}  {:>10}",
            online,
            addr_short,
            id_short,
            last_used_str,
            part.key.vote_first_valid,
            part.key.vote_last_valid,
        );
    }
    ExitCode::SUCCESS
}

/// `account partkeyinfo`. Mirrors `partkeyInfoCmd`
/// (account.go:1464-1502).
pub fn run_partkeyinfo(cli_d: Vec<PathBuf>) -> ExitCode {
    // Go's partkeyInfoCmd uses datadir.OnDataDirs (account.go:1470)
    // which iterates every -d data dir, printing a block per dir.
    // Codex round-1 finding: the single-dir ensure_single_data_dir
    // call rejected multi -d invocations.
    let dirs = match data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    use base64::Engine;
    let mut had_error = false;
    for data_dir_path in &dirs {
        println!(
            "Dumping participation key info from {}...",
            data_dir_path.display()
        );
        let client = match build_algod_client_for_dir(data_dir_path) {
            Ok(c) => c,
            Err(()) => {
                had_error = true;
                continue;
            }
        };
        let parts = match rt.block_on(client.list_participation_keys()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
                had_error = true;
                continue;
            }
        };
        for part in &parts {
            println!();
            println!("Participation ID:          {}", part.id);
            println!("Parent address:            {}", part.address);
            println!("Last vote round:           {}", round_or_na(part.last_vote));
            println!(
                "Last block proposal round: {}",
                round_or_na(part.last_block_proposal)
            );
            println!(
                "Effective first round:     {}",
                round_or_na(part.effective_first_valid)
            );
            println!(
                "Effective last round:      {}",
                round_or_na(part.effective_last_valid)
            );
            println!("First round:               {}", part.key.vote_first_valid);
            println!("Last round:                {}", part.key.vote_last_valid);
            println!("Key dilution:              {}", part.key.vote_key_dilution);
            println!(
                "Selection key:             {}",
                base64::engine::general_purpose::STANDARD
                    .encode(&part.key.selection_participation_key)
            );
            println!(
                "Voting key:                {}",
                base64::engine::general_purpose::STANDARD.encode(&part.key.vote_participation_key)
            );
            if let Some(spk) = &part.key.state_proof_key {
                println!(
                    "State proof key:           {}",
                    base64::engine::general_purpose::STANDARD.encode(spk)
                );
            }
        }
    }
    if had_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `account deletepartkey --partkeyid <id>`. Mirrors
/// `deletePartKeyCmd` (account.go:361-377).
pub fn run_deletepartkey(args: DeletepartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let client = match build_algod_client(&cli_d) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    if let Err(e) = rt.block_on(client.delete_participation_key(&args.partkeyid)) {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Build an `AlgodClient` from the single -d data dir, reading
/// algod.net + algod.token. Returns Err after printing Go-style
/// "Could not contact algod" text.
fn build_algod_client(cli_d: &[PathBuf]) -> Result<algo_rest_client::AlgodClient, ()> {
    let dd = match data_dir::ensure_single_data_dir(cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    build_algod_client_for_dir(&dd)
}

fn build_algod_client_for_dir(dd: &Path) -> Result<algo_rest_client::AlgodClient, ()> {
    let (base, token) = match build_algod_endpoint(dd) {
        Some(e) => e,
        None => {
            eprintln!("Could not contact algod: algod.net/algod.token missing");
            return Err(());
        }
    };
    Ok(algo_rest_client::AlgodClient::new(&base, &token))
}

/// `roundOrNA(value)` — Go's helper for printing optional rounds
/// (account.go:1454-1459). 0/None ⇒ `N/A`.
fn round_or_na(value: Option<u64>) -> String {
    match value {
        Some(v) if v != 0 => v.to_string(),
        _ => "N/A".to_string(),
    }
}

// ---- account renewpartkey / renewallpartkeys (TASK-243 / B11) -------------

const RENEW_REGISTER_DEFERRED: &str =
    "--register requires keyreg-transaction submission, which lands in B12 \
     (Phase B12: account changeonlinestatus). Use `goal-rust account \
     changeonlinestatus -a <addr> --online` after this command in the \
     meantime.";

/// `account renewpartkey -a <addr> --roundLastValid <r> [--keyDilution]
/// [--register]`. Mirrors `renewParticipationKeyCmd`
/// (account.go:1053-1099). See `RenewpartkeyArgs` for divergences.
pub fn run_renewpartkey(args: RenewpartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    if args.register {
        eprintln!("{RENEW_REGISTER_DEFERRED}");
        return ExitCode::from(1);
    }
    if let Err(e) = algo_types::Address::from_algorand_string(&args.address) {
        eprintln!("Could not parse address: {e}");
        return ExitCode::from(1);
    }
    let client = match build_algod_client(&cli_d) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    // Preflight: list existing partkeys; reject if a key for this
    // address already covers roundLastValid. Mirrors Go's
    // errExistingPartKey at account.go:1080-1088. Codex round-1.
    let rt_ref = &rt;
    let preflight = rt_ref.block_on(client.list_participation_keys());
    if let Ok(parts) = preflight {
        if parts
            .iter()
            .any(|p| p.address == args.address && p.key.vote_last_valid >= args.round_last_valid)
        {
            eprintln!(
                "An existing partkey for {} is already valid through round >= {}; \
                 renewing would install an older duplicate.",
                args.address, args.round_last_valid,
            );
            return ExitCode::from(1);
        }
    }
    let renewed = rt.block_on(renew_one(
        &client,
        &args.address,
        args.round_last_valid,
        args.key_dilution,
    ));
    match renewed {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e]));
            ExitCode::from(1)
        }
    }
}

/// `account renewallpartkeys --roundLastValid <r> [--keyDilution]
/// [--register]`. Mirrors `renewAllParticipationKeyCmd`
/// (account.go:1132-1219). Iterates every -d data dir; per dir,
/// lists existing partkeys, renews each unique address. Skips
/// addresses that already have a partkey with `vote_last_valid >=
/// round_last_valid` (Go's preflight check at
/// account.go:1080-1088).
pub fn run_renewallpartkeys(args: RenewallpartkeysArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    if args.register {
        eprintln!("{RENEW_REGISTER_DEFERRED}");
        return ExitCode::from(1);
    }
    let dirs = match data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let mut had_error = false;
    for dd in &dirs {
        println!("Renewing participation keys in {}...", dd.display());
        let client = match build_algod_client_for_dir(dd) {
            Ok(c) => c,
            Err(()) => {
                had_error = true;
                continue;
            }
        };
        let parts = match rt.block_on(client.list_participation_keys()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
                had_error = true;
                continue;
            }
        };
        let mut seen_addrs: std::collections::HashSet<String> = Default::default();
        for part in &parts {
            if !seen_addrs.insert(part.address.clone()) {
                continue;
            }
            // Skip accounts that already have a partkey valid through
            // the requested roundLastValid (Go's preflight check at
            // account.go:1080-1088 — "renewed partkey would be older
            // than current one").
            if parts.iter().any(|p| {
                p.address == part.address && p.key.vote_last_valid >= args.round_last_valid
            }) {
                let part_address = &part.address;
                println!(
                    "  Skipping {part_address}: an existing partkey is already valid \
                     through round {}",
                    args.round_last_valid
                );
                continue;
            }
            if let Err(e) = rt.block_on(renew_one(
                &client,
                &part.address,
                args.round_last_valid,
                args.key_dilution,
            )) {
                let part_address = &part.address;
                eprintln!("  Renew failed for {part_address}: {e}");
                had_error = true;
            }
        }
    }
    if had_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Issue one renew via the REST generate endpoint. Uses
/// `first = current_round` (matches Go's `client.GenParticipationKeys`
/// call which passes `currentRound` as first) and the requested
/// `last`. Status fetch picks up `last_round` from `/v2/status`.
async fn renew_one(
    client: &algo_rest_client::AlgodClient,
    address: &str,
    round_last_valid: u64,
    key_dilution: Option<u64>,
) -> Result<(), String> {
    use algo_rest_client::BlockSource;
    let status = BlockSource::get_status(client)
        .await
        .map_err(|e| e.to_string())?;
    let first = status.last_round;
    // Go's renew commands require `roundLastValid > currentRound +
    // MaxTxnLife` (account.go:1074-1076 + 1180-1184) — the generated
    // key must stay valid long enough for the keyreg-online
    // transaction to land. We don't have the consensus-param table
    // loaded, so use the typical default MaxTxnLife=1000. Operators
    // who know their consensus version can bypass via a wider window.
    // Codex round-1 finding.
    const TYPICAL_MAX_TXN_LIFE: u64 = 1000;
    let earliest_valid = first.saturating_add(TYPICAL_MAX_TXN_LIFE);
    if round_last_valid <= earliest_valid {
        return Err(format!(
            "--roundLastValid ({round_last_valid}) must be greater than \
             current round ({first}) + MaxTxnLife (~{TYPICAL_MAX_TXN_LIFE}) = {earliest_valid}"
        ));
    }
    println!("Renewing participation key for {address} (rounds {first}..{round_last_valid})");
    client
        .generate_participation_keys(address, first, round_last_valid, key_dilution)
        .await
        .map_err(|e| e.to_string())?;
    println!("  Participation key generation requested");
    Ok(())
}

// ---- account multisig new/delete/info (TASK-240 / B8) ---------------------

/// `account multisig new -T <threshold> <addr1> <addr2> ...`. Mirrors
/// `newMultisigCmd` (account.go:400-441).
pub fn run_multisig_new(
    args: MsigNewArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if args.addresses.is_empty() {
        eprintln!("error: need at least one component address");
        return ExitCode::from(1);
    }
    if args.threshold == 0 {
        eprintln!("Threshold must be greater than zero.");
        return ExitCode::from(1);
    }
    if (args.threshold as usize) > args.addresses.len() {
        // Mirror Go's pre-kmd validation rejecting impossible thresholds.
        // Go's CreateMultisigAccount surfaces this via kmd; we add a
        // local guard so the error doesn't require a round-trip.
        eprintln!(
            "Threshold ({}) cannot exceed the number of component addresses ({}).",
            args.threshold,
            args.addresses.len()
        );
        return ExitCode::from(1);
    }

    // Parse each address to its 32-byte pubkey before any kmd call.
    let mut pks: Vec<[u8; 32]> = Vec::with_capacity(args.addresses.len());
    for addr in &args.addresses {
        match algo_types::Address::from_algorand_string(addr) {
            Ok(a) => pks.push(a.0),
            Err(e) => {
                eprintln!("Could not parse address '{addr}': {e}");
                return ExitCode::from(1);
            }
        }
    }

    // Duplicate-PK warning (Go's warnMultisigDuplicatesDetected at
    // account.go:425-432).
    let mut seen: std::collections::HashMap<&String, usize> = std::collections::HashMap::new();
    for a in &args.addresses {
        *seen.entry(a).or_insert(0) += 1;
    }
    if seen.values().any(|c| *c > 1) {
        eprintln!("Warning: multisig has duplicate component addresses.");
    }

    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, _pw) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };

    // Multisig version is fixed at 1 (Algorand's only ratified
    // version — protocol/multisig.go).
    let msig_addr = match rt.block_on(client.import_multisig(&handle, 1, args.threshold, pks)) {
        Ok(r) => r.address,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };

    // Persist friendly name from accountList's next_unnamed (Go does
    // the same at account.go:436).
    let name = accounts.next_unnamed();
    if let Err(e) = accounts.add_account(&name, &msig_addr) {
        eprintln!("{e}");
    }

    // Go uses infoCreatedNewAccount (`Created new account with
    // address %s`) — the same template used by `account new`.
    println!(
        "{}",
        format_message(INFO_CREATED_NEW_ACCOUNT, &[&msig_addr])
    );
    ExitCode::SUCCESS
}

/// `account multisig delete -a <addr>`. Mirrors `deleteMultisigCmd`
/// (account.go:443-462).
pub fn run_multisig_delete(
    args: MsigDeleteArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let mut accounts = AccountsList::load(&data_dir_path);
    let (handle, _wallet_name, password) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };
    if let Err(e) = rt.block_on(client.delete_multisig(&handle, &password, &args.address)) {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
        return ExitCode::from(1);
    }
    if let Err(e) = accounts.remove_account(&args.address) {
        eprintln!("{e}");
    }
    ExitCode::SUCCESS
}

/// `account multisig info -a <addr>`. Mirrors `infoMultisigCmd`
/// (account.go:464-487).
pub fn run_multisig_info(
    args: MsigInfoArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let mut accounts = AccountsList::load(&data_dir_path);
    // Multisig info is structural metadata, but kmd still requires
    // a wallet handle which requires a password for encrypted
    // wallets. The earlier code forced empty password unconditionally,
    // which failed encrypted wallets even when the operator passed
    // --password explicitly. Go's libgoal uses a cached-handle path
    // we don't have; mirror the other read-leaves and let
    // resolve_wallet_and_init prompt on TTY when --password is
    // omitted. Unencrypted wallets still work via `--password ''`.
    let (handle, _wallet_name, _pw) = match resolve_wallet_and_init(
        &rt,
        &client,
        &mut accounts,
        args.wallet.as_deref(),
        args.password.as_deref(),
    ) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };

    let exp = match rt.block_on(client.export_multisig(&handle, &args.address)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };

    println!("Version: {}", exp.version);
    println!("Threshold: {}", exp.threshold);
    println!("Public keys:");
    for pk in &exp.pks {
        // Render each pubkey as a base32-checksummed address — Go
        // returns these in PKs as already-formatted strings; we
        // format them ourselves from the raw [u8; 32].
        println!("  {}", algo_types::Address(*pk).to_algorand_string());
    }
    ExitCode::SUCCESS
}

// ---- account importrootkey (TASK-239 / B7) --------------------------------

/// `account importrootkey [-u] [-w <wallet>]` — iterate
/// `<data_dir>/<gid>/*.rootkey` SQLite files, decode the
/// msgpack-encoded SignatureSecrets, and import each into the named
/// wallet's kmd. Mirrors `importRootKeysCmd` (account.go:1372-1463).
pub fn run_importrootkey(
    args: ImportRootKeyArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let mut accounts = AccountsList::load(&data_dir_path);

    // Go's `client.GenesisID()` returns the genesis id from algod's
    // GenesisJSON; we read it directly from disk via the data_dir
    // helper. Failure → exit silently (matches Go's `return` at
    // account.go:1386).
    let genesis_id = match data_dir::read_genesis_id(&data_dir_path) {
        Ok(g) => g,
        Err(_) => return ExitCode::SUCCESS,
    };
    let key_dir = data_dir_path.join(&genesis_id);
    let entries = match std::fs::read_dir(&key_dir) {
        Ok(e) => e,
        Err(_) => return ExitCode::SUCCESS,
    };

    // Wallet-handle resolution is deferred until we've actually
    // opened + restored a `.rootkey` (Go opens a fresh handle inside
    // the per-file loop AFTER the restore succeeds — account.go:1422).
    // That means an empty or all-corrupt key dir must NOT prompt for a
    // password, NOT auto-create unencrypted-default-wallet, and must
    // just print `Imported 0 keys`. We cache the handle after the
    // first successful restore so subsequent imports reuse it (avoids
    // N password prompts within one call). Codex round-3 finding.
    let mut handle: Option<String> = None;

    let mut imported = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let filename = entry.file_name().to_string_lossy().into_owned();
        if !is_root_key_filename(&filename) {
            continue;
        }
        let secrets = match read_rootkey_secrets(&path) {
            Ok(s) => s,
            Err(_) => continue, // matches Go's "couldn't read it, skip it"
        };
        // Lazily resolve the wallet handle now that we have at least
        // one valid rootkey to import.
        if handle.is_none() {
            let h = if args.unencrypted {
                // Mirrors `client.GetUnencryptedWalletHandle()`
                // (libgoal/unencryptedWallet.go:45-61).
                match resolve_unencrypted_wallet_handle(&rt, &client) {
                    Ok(h) => h,
                    Err(()) => return ExitCode::from(1),
                }
            } else {
                let (h, _wallet_name, _pw) = match resolve_wallet_and_init(
                    &rt,
                    &client,
                    &mut accounts,
                    args.wallet.as_deref(),
                    args.password.as_deref(),
                ) {
                    Ok(v) => v,
                    Err(()) => return ExitCode::from(1),
                };
                h
            };
            handle = Some(h);
        }
        let handle_ref = handle.as_deref().expect("handle resolved");
        let address_for_log = match rt.block_on(client.import_key(handle_ref, secrets.sk)) {
            Ok(r) => r.address,
            Err(e) => {
                let msg = kmd_msg(&e);
                if msg.contains("key already exists") {
                    // Go warns + continues for duplicates
                    // (account.go:1442-1444).
                    eprintln!("Warning: {msg}\n > Key File: {filename}");
                    continue;
                }
                // Go's reportErrorf hard-exits on every non-duplicate
                // import failure (account.go:1445-1447) — anything
                // else is a real wallet/session/server error and
                // letting the loop silently roll past would mask
                // failures. Codex round-2 finding.
                eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&msg]));
                return ExitCode::from(1);
            }
        };
        imported += 1;
        println!("Imported {address_for_log}"); // messages.go:33 infoImportedKey
    }

    // messages.go:35 `infoImportedNKeys = "Imported %d key%s"`
    let plural = if imported == 1 { "" } else { "s" };
    println!("Imported {imported} key{plural}");
    ExitCode::SUCCESS
}

/// Mirrors Go's `client.GetUnencryptedWalletHandle()`
/// (libgoal/unencryptedWallet.go:45-61): look up the kmd wallet
/// named `unencrypted-default-wallet`, auto-create it with empty
/// password if missing, then `init_wallet` (also with empty
/// password) and return the handle.
fn resolve_unencrypted_wallet_handle(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
) -> Result<String, ()> {
    const UNENCRYPTED_WALLET_NAME: &str = "unencrypted-default-wallet";
    let listed = rt.block_on(client.list_wallets()).map_err(|e| {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
    })?;
    let mut wallet_id: Option<String> = None;
    let mut duplicates = 0usize;
    for w in listed.wallets {
        if w.name == UNENCRYPTED_WALLET_NAME {
            duplicates += 1;
            wallet_id.get_or_insert(w.id);
        }
    }
    if duplicates > 1 {
        eprintln!("multiple default unencrypted wallets exist");
        return Err(());
    }
    let wallet_id = match wallet_id {
        Some(id) => id,
        None => {
            // Create with empty password + zero MDK (mirrors Go's
            // `kmd.CreateWallet(UnencryptedWalletName, "sqlite", nil, crypto.MasterDerivationKey{})`).
            let created = rt
                .block_on(client.create_wallet(UNENCRYPTED_WALLET_NAME, "sqlite", "", [0u8; 32]))
                .map_err(|e| {
                    eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
                })?;
            created.wallet.id
        }
    };
    let init = rt
        .block_on(client.init_wallet(&wallet_id, ""))
        .map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
        })?;
    Ok(init.wallet_handle_token)
}

/// Mirrors Go's `IsRootKeyFilename` (config/keyfile.go:81): the file
/// must end in `.rootkey` and have a non-empty stem (Go's check is
/// that the trimmed name re-formats to the original filename).
fn is_root_key_filename(filename: &str) -> bool {
    if let Some(stem) = filename.strip_suffix(".rootkey") {
        !stem.is_empty()
    } else {
        false
    }
}

/// Decoded `crypto.SignatureSecrets` from one `.rootkey` SQLite file.
#[derive(Debug)]
struct RootKeySecrets {
    sk: [u8; 64],
    #[allow(dead_code)]
    pubkey: [u8; 32],
}

/// Read `<path>` as a SQLite database; pull `RootAccount.data` (the
/// canonical msgpack-encoded SignatureSecrets blob — see
/// `../go-algorand/crypto/msgp_gen.go::SignatureSecrets.MarshalMsg`),
/// decode the 2-key map (`SK` 64 bytes + `SignatureVerifier` 32 bytes),
/// and return both.
fn read_rootkey_secrets(path: &Path) -> Result<RootKeySecrets, String> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
    let blob: Vec<u8> = conn
        .query_row("SELECT data FROM RootAccount", [], |row| row.get(0))
        .map_err(|e| format!("select RootAccount.data: {e}"))?;
    parse_signature_secrets_blob(&blob)
}

/// Parse the msgpack `SignatureSecrets` blob. Wire shape (per
/// `MarshalMsg` at `../go-algorand/crypto/msgp_gen.go`):
/// `{ "SK": <64 bytes>, "SignatureVerifier": <32 bytes> }`.
fn parse_signature_secrets_blob(blob: &[u8]) -> Result<RootKeySecrets, String> {
    let mut rd: &[u8] = blob;
    let v = rmpv::decode::read_value(&mut rd).map_err(|e| format!("msgpack decode: {e}"))?;
    let map = v
        .as_map()
        .ok_or_else(|| "rootkey blob is not a msgpack map".to_string())?;
    let mut sk: Option<Vec<u8>> = None;
    let mut sv: Option<Vec<u8>> = None;
    for (k, value) in map {
        let key = k.as_str().ok_or_else(|| "non-string map key".to_string())?;
        match key {
            "SK" => {
                let bytes = value
                    .as_slice()
                    .ok_or_else(|| "SK is not bin".to_string())?;
                sk = Some(bytes.to_vec());
            }
            "SignatureVerifier" => {
                let bytes = value
                    .as_slice()
                    .ok_or_else(|| "SignatureVerifier is not bin".to_string())?;
                sv = Some(bytes.to_vec());
            }
            _ => {} // unknown key — tolerate forward additions
        }
    }
    let sk = sk.ok_or_else(|| "missing SK in rootkey blob".to_string())?;
    let sv = sv.ok_or_else(|| "missing SignatureVerifier in rootkey blob".to_string())?;
    if sk.len() != 64 {
        return Err(format!("SK has wrong length: {} (want 64)", sk.len()));
    }
    if sv.len() != 32 {
        return Err(format!(
            "SignatureVerifier has wrong length: {} (want 32)",
            sv.len(),
        ));
    }
    let mut sk_arr = [0u8; 64];
    sk_arr.copy_from_slice(&sk);
    let mut sv_arr = [0u8; 32];
    sv_arr.copy_from_slice(&sv);
    Ok(RootKeySecrets {
        sk: sk_arr,
        pubkey: sv_arr,
    })
}

// ---- account info / balance / rewards / assetdetails (TASK-237 / B5) ------

/// `account balance -a <addr>` — print `<microAlgos> microAlgos\n`.
/// Mirrors `account.go:810-825` (`balanceCmd`).
pub fn run_balance(args: AddressArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    match fetch_account_json(&args.address, &cli_d) {
        Ok(v) => {
            let amount = v.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
            println!("{amount} microAlgos");
            ExitCode::SUCCESS
        }
        Err(()) => ExitCode::from(1),
    }
}

/// `account rewards -a <addr>` — print `<rewards> microAlgos\n`.
/// Mirrors `account.go:856-870` (`rewardsCmd`).
pub fn run_rewards(args: AddressArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    match fetch_account_json(&args.address, &cli_d) {
        Ok(v) => {
            let rewards = v.get("rewards").and_then(|a| a.as_u64()).unwrap_or(0);
            println!("{rewards} microAlgos");
            ExitCode::SUCCESS
        }
        Err(()) => ExitCode::from(1),
    }
}

/// `account assetdetails -a <addr> [-l <n>] [-n <token>]` — print
/// the per-asset detail block. Mirrors `printAccountAssetsInformation`
/// (`account.go:797+`). Routes through the paginated
/// `/v2/accounts/{addr}/assets` endpoint so `--limit` / `--next` round-
/// trip with Go's `goal account assetdetails` semantics (Codex round-1
/// finding — the prior implementation incorrectly walked the unpaged
/// `/v2/accounts/{addr}` shape and ignored both flags).
pub fn run_assetdetails(args: AssetdetailsArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = algo_types::Address::from_algorand_string(&args.address) {
        eprintln!("Could not parse address: {e}");
        return ExitCode::from(1);
    }
    let endpoint = match build_algod_endpoint(&dd) {
        Some(e) => e,
        None => {
            eprintln!("Could not contact algod: algod.net/algod.token missing");
            return ExitCode::from(1);
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    // Build the paginated assets URL.
    let mut url = format!(
        "{}/v2/accounts/{}/assets",
        endpoint.0.trim_end_matches('/'),
        args.address
    );
    let mut qs: Vec<String> = Vec::new();
    if let Some(l) = args.limit {
        qs.push(format!("limit={l}"));
    }
    if let Some(n) = args.next.as_deref().filter(|s| !s.is_empty()) {
        qs.push(format!("next={n}"));
    }
    if !qs.is_empty() {
        url.push('?');
        url.push_str(&qs.join("&"));
    }

    let resp_json = rt.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .get(&url)
            .header("X-Algo-API-Token", &endpoint.1)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = r.status();
        let bytes = r.bytes().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())
    });
    let resp = match resp_json {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e]));
            return ExitCode::from(1);
        }
    };

    let round = resp.get("round").and_then(|r| r.as_u64()).unwrap_or(0);
    let next_token = resp
        .get("next-token")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());
    let mut assets: Vec<(serde_json::Value, Option<serde_json::Value>)> = Vec::new();
    if let Some(arr) = resp.get("asset-holdings").and_then(|a| a.as_array()) {
        for entry in arr {
            // The paginated endpoint nests holding + optional params
            // under each `asset-holdings[i]` entry as:
            //   { "asset-holding": {...}, "asset-params": {...?} }
            let holding = entry
                .get("asset-holding")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let params = entry.get("asset-params").cloned();
            assets.push((holding, params));
        }
    }

    let s = format_assetdetails(&args.address, round, next_token.as_deref(), &assets);
    print!("{s}");
    ExitCode::SUCCESS
}

/// `account info -a <addr>` — multi-section dump: Created Assets,
/// Held Assets, Created Apps, Opted In Apps, Minimum Balance.
/// Mirrors `printAccountInfo` (`account.go:592-770`).
pub fn run_info(args: InfoArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let v = match fetch_account_json(&args.address, &cli_d) {
        Ok(v) => v,
        Err(()) => return ExitCode::from(1),
    };
    let endpoint = build_algod_endpoint_from(&cli_d);
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    // When --onlyShowAssetIDs is set, skip the per-asset metadata
    // fetch entirely. Mirrors Go's onlyShowAssetIDs branch
    // (account.go:660-664) which prints `\tID N\n` per holding without
    // an AssetInformation call.
    let mut held_params: std::collections::HashMap<u64, AssetFetch> =
        std::collections::HashMap::new();
    if !args.only_show_asset_ids {
        if let (Some(ep), Some(holdings)) = (&endpoint, v.get("assets").and_then(|a| a.as_array()))
        {
            for h in holdings {
                let aid = h.get("asset-id").and_then(|x| x.as_u64()).unwrap_or(0);
                let fetched = match fetch_asset_params_with_status(&rt, ep, aid) {
                    Ok((404, _)) => AssetFetch::Missing,
                    Ok((_, Some(p))) => AssetFetch::Found(p),
                    Ok((_, None)) => AssetFetch::Error,
                    Err(_) => AssetFetch::Error,
                };
                held_params.insert(aid, fetched);
            }
        } else if v
            .get("assets")
            .and_then(|a| a.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            // No algod endpoint but holdings exist — every held asset
            // becomes AssetFetch::Error so the rendered row is `\tID N, error`.
            for h in v.get("assets").unwrap().as_array().unwrap() {
                let aid = h.get("asset-id").and_then(|x| x.as_u64()).unwrap_or(0);
                held_params.insert(aid, AssetFetch::Error);
            }
        }
    }

    let (report, errors, has_error) = format_info(&v, &held_params, args.only_show_asset_ids);
    if !errors.is_empty() {
        eprint!("{errors}");
    }
    print!("{report}");
    if has_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ---- read-path helpers ----------------------------------------------------

fn build_algod_endpoint_from(cli_d: &[PathBuf]) -> Option<(String, String)> {
    let dd = data_dir::ensure_single_data_dir(cli_d).ok()?;
    build_algod_endpoint(&dd)
}

fn fetch_account_json(address: &str, cli_d: &[PathBuf]) -> Result<serde_json::Value, ()> {
    let dd = match data_dir::ensure_single_data_dir(cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    if let Err(e) = algo_types::Address::from_algorand_string(address) {
        eprintln!("Could not parse address: {e}");
        return Err(());
    }
    let endpoint = match build_algod_endpoint(&dd) {
        Some(e) => e,
        None => {
            eprintln!("Could not contact algod: algod.net/algod.token missing");
            return Err(());
        }
    };
    let rt = build_runtime()?;
    let url = format!(
        "{}/v2/accounts/{}",
        endpoint.0.trim_end_matches('/'),
        address
    );
    rt.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .get(&url)
            .header("X-Algo-API-Token", &endpoint.1)
            .send()
            .await
            .map_err(|e| {
                eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        })?;
        if !status.is_success() {
            eprintln!(
                "{}",
                format_message(ERROR_REQUEST_FAIL, &[&format!("HTTP {}", status.as_u16())])
            );
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
        })
    })
}

/// `(status_code, asset_params)` from `GET /v2/assets/{aid}`. Returns
/// Ok((status, None)) when the response is non-2xx or parse fails (the
/// status lets the caller distinguish 404 "deleted/unknown" from other
/// failures). Async fetch wrapped in a sync helper.
fn fetch_asset_params_with_status(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    asset_id: u64,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let url = format!(
        "{}/v2/assets/{}",
        endpoint.0.trim_end_matches('/'),
        asset_id
    );
    rt.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .get(&url)
            .header("X-Algo-API-Token", &endpoint.1)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Ok((status.as_u16(), None));
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let params = v.get("params").cloned();
        Ok((status.as_u16(), params))
    })
}

// `fetch_asset_params` (single-shot, non-status-aware) was used by the
// earlier non-paginated assetdetails path. The paginated endpoint
// surfaces asset-params inline, so the helper has been removed.

/// Outcome of a per-asset fetch in `account info`'s Held Assets section.
enum AssetFetch {
    Found(serde_json::Value),
    Missing, // 404 → `<deleted/unknown asset>`
    Error,   // anything else → `error` + non-zero exit
}

// ---- formatters (pure for unit-testability) ------------------------------

/// Render `account info` output. Returns `(report, errors, has_error)`
/// — `report` to stdout, `errors` to stderr, `has_error` ⇒ exit 1.
fn format_info(
    v: &serde_json::Value,
    held_params: &std::collections::HashMap<u64, AssetFetch>,
    only_show_asset_ids: bool,
) -> (String, String, bool) {
    use std::fmt::Write as _;
    let mut report = String::new();
    let mut errors = String::new();
    let mut has_error = false;

    // Sort created/held assets by id; created/opted apps by id.
    let mut created_assets: Vec<&serde_json::Value> = v
        .get("created-assets")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    created_assets.sort_by_key(|a| a.get("index").and_then(|i| i.as_u64()).unwrap_or(0));

    let mut held_assets: Vec<&serde_json::Value> = v
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    held_assets.sort_by_key(|a| a.get("asset-id").and_then(|i| i.as_u64()).unwrap_or(0));

    let mut created_apps: Vec<&serde_json::Value> = v
        .get("created-apps")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    created_apps.sort_by_key(|a| a.get("id").and_then(|i| i.as_u64()).unwrap_or(0));

    let mut opted_apps: Vec<&serde_json::Value> = v
        .get("apps-local-state")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    opted_apps.sort_by_key(|a| a.get("id").and_then(|i| i.as_u64()).unwrap_or(0));

    let _ = writeln!(report, "Created Assets:");
    if created_assets.is_empty() {
        let _ = writeln!(report, "\t<none>");
    }
    for a in &created_assets {
        let id = a.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
        let params = a.get("params");
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let units = params
            .and_then(|p| p.get("unit-name"))
            .and_then(|n| n.as_str())
            .unwrap_or("units");
        let total = params
            .and_then(|p| p.get("total"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let decimals = params
            .and_then(|p| p.get("decimals"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0) as u32;
        let total_fmt = asset_decimals_fmt(total, decimals);
        let url = params
            .and_then(|p| p.get("url"))
            .and_then(|n| n.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| format!(", {s}"))
            .unwrap_or_default();
        let _ = writeln!(report, "\tID {id}, {name}, supply {total_fmt} {units}{url}");
    }

    let _ = writeln!(report, "Held Assets:");
    if held_assets.is_empty() {
        let _ = writeln!(report, "\t<none>");
    }
    for h in &held_assets {
        let aid = h.get("asset-id").and_then(|i| i.as_u64()).unwrap_or(0);
        if only_show_asset_ids {
            // Go's onlyShowAssetIDs branch (account.go:660-664) skips
            // the AssetInformation call and just prints `\tID N\n`.
            let _ = writeln!(report, "\tID {aid}");
            continue;
        }
        match held_params.get(&aid) {
            Some(AssetFetch::Found(params)) => {
                let decimals = params.get("decimals").and_then(|n| n.as_u64()).unwrap_or(0) as u32;
                let amount = h.get("amount").and_then(|n| n.as_u64()).unwrap_or(0);
                let amount_fmt = asset_decimals_fmt(amount, decimals);
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("<unnamed>");
                let unit = params
                    .get("unit-name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("units");
                let frozen = if h
                    .get("is-frozen")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
                {
                    " (frozen)"
                } else {
                    ""
                };
                let _ = writeln!(
                    report,
                    "\tID {aid}, {name}, balance {amount_fmt} {unit}{frozen}"
                );
            }
            Some(AssetFetch::Missing) => {
                let _ = writeln!(report, "\tID {aid}, <deleted/unknown asset>");
            }
            Some(AssetFetch::Error) | None => {
                let _ = writeln!(
                    errors,
                    "Error: Unable to retrieve asset information for asset {aid}"
                );
                let _ = writeln!(report, "\tID {aid}, error");
                has_error = true;
            }
        }
    }

    let _ = writeln!(report, "Created Apps:");
    if created_apps.is_empty() {
        let _ = writeln!(report, "\t<none>");
    }
    for app in &created_apps {
        let id = app.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
        let params = app.get("params");
        let global_schema = params.and_then(|p| p.get("global-state-schema"));
        let alloc_ints = global_schema
            .and_then(|s| s.get("num-uint"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let alloc_bytes = global_schema
            .and_then(|s| s.get("num-byte-slice"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let (used_ints, used_bytes) = count_kv_types(params.and_then(|p| p.get("global-state")));
        let extra_pages = params
            .and_then(|p| p.get("extra-program-pages"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let extra = if extra_pages == 0 {
            String::new()
        } else {
            let plural = if extra_pages == 1 { "" } else { "s" };
            format!(", {extra_pages} extra page{plural}")
        };
        let version = params
            .and_then(|p| p.get("version"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let _ = writeln!(
            report,
            "\tID {id}{extra}, global state used {used_ints}/{alloc_ints} uints, {used_bytes}/{alloc_bytes} byte slices, version {version}"
        );
    }

    let _ = writeln!(report, "Opted In Apps:");
    if opted_apps.is_empty() {
        let _ = writeln!(report, "\t<none>");
    }
    for app in &opted_apps {
        let id = app.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
        let schema = app.get("schema");
        let alloc_ints = schema
            .and_then(|s| s.get("num-uint"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let alloc_bytes = schema
            .and_then(|s| s.get("num-byte-slice"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let (used_ints, used_bytes) = count_kv_types(app.get("key-value"));
        let _ = writeln!(
            report,
            "\tID {id}, local state used {used_ints}/{alloc_ints} uints, {used_bytes}/{alloc_bytes} byte slices"
        );
    }

    let min_bal = v.get("min-balance").and_then(|n| n.as_u64()).unwrap_or(0);
    let _ = writeln!(report, "Minimum Balance:\t{min_bal} microAlgos");

    (report, errors, has_error)
}

/// Count (uint, byteslice) entries in a KV array. Each entry is
/// `{key, value: {type, ...}}` where TEAL type 2 = uint, 1 = bytes.
fn count_kv_types(kv: Option<&serde_json::Value>) -> (u64, u64) {
    let mut uints = 0u64;
    let mut bytes = 0u64;
    if let Some(arr) = kv.and_then(|k| k.as_array()) {
        for entry in arr {
            let t = entry
                .get("value")
                .and_then(|v| v.get("type"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            // Algorand TealType: bytes=1, uint=2 (basics/teal.go).
            if t == 2 {
                uints += 1;
            } else {
                bytes += 1;
            }
        }
    }
    (uints, bytes)
}

/// `assetDecimalsFmt(value, decimals)` — Go's `basics.AssetAmount.Fmt`
/// at account.go:413-?. Renders `12345` with decimals=3 as `12.345`.
fn asset_decimals_fmt(value: u64, decimals: u32) -> String {
    if decimals == 0 {
        return value.to_string();
    }
    let s = format!("{value:0>width$}", width = (decimals as usize) + 1);
    let split = s.len() - decimals as usize;
    let (whole, frac) = s.split_at(split);
    format!("{whole}.{frac}")
}

/// `printAccountAssetsInformation` (account.go:797+). Pure, returns
/// the rendered string. Each `(holding, params_opt)` pair is one
/// asset block. `next_token` is rendered between `Round:` and
/// `Assets:` when non-empty (Go's
/// `NextToken (to retrieve more account assets): <token>` line).
fn format_assetdetails(
    address: &str,
    round: u64,
    next_token: Option<&str>,
    assets: &[(serde_json::Value, Option<serde_json::Value>)],
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Account: {address}");
    let _ = writeln!(out, "Round: {round}");
    if let Some(t) = next_token.filter(|s| !s.is_empty()) {
        let _ = writeln!(out, "NextToken (to retrieve more account assets): {t}");
    }
    let _ = writeln!(out, "Assets:");
    for (holding, params) in assets {
        let aid = holding
            .get("asset-id")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let _ = writeln!(out, "  Asset ID: {aid}");
        match params {
            Some(p) => {
                let amount = holding.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                let decimals = p.get("decimals").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let amount_fmt = asset_decimals_fmt(amount, decimals);
                let _ = writeln!(out, "    Amount: {amount_fmt}");
                let frozen = holding
                    .get("is-frozen")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let _ = writeln!(out, "    IsFrozen: {frozen}");
                let _ = writeln!(out, "  Asset Params:");
                let creator = p.get("creator").and_then(|x| x.as_str()).unwrap_or("");
                let _ = writeln!(out, "    Creator: {creator}");
                let name = p
                    .get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("<unnamed>");
                let _ = writeln!(out, "    Name: {name}");
                let unit_name = p
                    .get("unit-name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("units");
                let _ = writeln!(out, "    Units: {unit_name}");
                let total = p.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
                let _ = writeln!(out, "    Total: {total}");
                let _ = writeln!(out, "    Decimals: {decimals}");
                let url = p.get("url").and_then(|x| x.as_str()).unwrap_or("");
                let _ = writeln!(out, "    URL: {url}");
            }
            None => {
                let amount = holding.get("amount").and_then(|x| x.as_u64()).unwrap_or(0);
                let _ = writeln!(out, "    Amount (without formatting): {amount}");
                let frozen = holding
                    .get("is-frozen")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let _ = writeln!(out, "    IsFrozen: {frozen}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_created_template_matches_go() {
        // messages.go:36: `infoCreatedNewAccount = "Created new account with address %s"`
        assert_eq!(
            format_message(INFO_CREATED_NEW_ACCOUNT, &["ADDRESS"]),
            "Created new account with address ADDRESS",
        );
    }

    #[test]
    fn info_renamed_template_matches_go() {
        // messages.go:32: `infoRenamedAccount = "Renamed account '%s' to '%s'"`
        assert_eq!(
            format_message(INFO_RENAMED_ACCOUNT, &["a", "b"]),
            "Renamed account 'a' to 'b'",
        );
    }

    #[test]
    fn error_templates_match_go() {
        assert_eq!(
            format_message(ERROR_NAME_ALREADY_TAKEN, &["foo"]),
            "The account name 'foo' is already taken, please choose another.",
        );
        assert_eq!(
            format_message(ERROR_NAME_DOESNT_EXIST, &["foo"]),
            "An account named 'foo' does not exist.",
        );
    }

    // ---- TASK-237 (B5) formatter unit tests ------------------------------

    #[test]
    fn asset_decimals_fmt_matches_go_assetdecimalsfmt() {
        // Reference: cmd/goal/utils.go assetDecimalsFmt
        // 0 decimals → integer.
        assert_eq!(asset_decimals_fmt(12345, 0), "12345");
        // 3 decimals → `12.345`.
        assert_eq!(asset_decimals_fmt(12345, 3), "12.345");
        // Padding when value < 10^decimals → `0.001`.
        assert_eq!(asset_decimals_fmt(1, 3), "0.001");
        // 6 decimals on a small value.
        assert_eq!(asset_decimals_fmt(7, 6), "0.000007");
    }

    #[test]
    fn count_kv_types_classifies_teal_uints_and_bytes() {
        // type 2 = uint, anything else (1 here) = bytes.
        let kv = serde_json::json!([
            {"key": "k1", "value": {"type": 2, "uint": 5}},
            {"key": "k2", "value": {"type": 1, "bytes": "aGVsbG8="}},
            {"key": "k3", "value": {"type": 2, "uint": 7}},
        ]);
        assert_eq!(count_kv_types(Some(&kv)), (2, 1));
        // Missing kv → (0, 0).
        assert_eq!(count_kv_types(None), (0, 0));
    }

    #[test]
    fn format_info_empty_account_uses_none_placeholders() {
        let v = serde_json::json!({
            "address": "X",
            "amount": 0,
            "rewards": 0,
            "min-balance": 100000,
            "round": 1,
            "status": "Offline",
        });
        let (report, errors, has_error) = format_info(&v, &std::collections::HashMap::new(), false);
        assert_eq!(errors, "");
        assert!(!has_error);
        // Every section header present with the <none> placeholder.
        for header in [
            "Created Assets:\n\t<none>\n",
            "Held Assets:\n\t<none>\n",
            "Created Apps:\n\t<none>\n",
            "Opted In Apps:\n\t<none>\n",
        ] {
            assert!(
                report.contains(header),
                "expected {header:?} in report; got {report:?}",
            );
        }
        assert!(report.contains("Minimum Balance:\t100000 microAlgos\n"));
    }

    #[test]
    fn format_info_renders_created_held_apps_and_minimum_balance() {
        let v = serde_json::json!({
            "address": "X",
            "amount": 1_000_000,
            "rewards": 0,
            "min-balance": 200000,
            "round": 1,
            "status": "Online",
            "created-assets": [{
                "index": 42,
                "params": {
                    "name": "ACME",
                    "unit-name": "AC",
                    "total": 1000,
                    "decimals": 2,
                    "url": "https://acme.example",
                },
            }],
            "assets": [{
                "asset-id": 42,
                "amount": 250,
                "is-frozen": true,
            }],
            "created-apps": [{
                "id": 7,
                "params": {
                    "global-state-schema": {"num-uint": 4, "num-byte-slice": 2},
                    "global-state": [
                        {"key": "k1", "value": {"type": 2, "uint": 1}},
                        {"key": "k2", "value": {"type": 1, "bytes": "QQ=="}},
                    ],
                    "extra-program-pages": 1,
                    "version": 8,
                },
            }],
            "apps-local-state": [{
                "id": 11,
                "schema": {"num-uint": 1, "num-byte-slice": 1},
                "key-value": [
                    {"key": "x", "value": {"type": 2, "uint": 9}},
                ],
            }],
        });
        let mut held = std::collections::HashMap::new();
        held.insert(
            42u64,
            AssetFetch::Found(serde_json::json!({
                "decimals": 2, "name": "ACME", "unit-name": "AC",
            })),
        );
        let (report, errors, has_error) = format_info(&v, &held, false);
        assert_eq!(errors, "");
        assert!(!has_error);
        assert!(
            report.contains("\tID 42, ACME, supply 10.00 AC, https://acme.example\n"),
            "created asset row format: got {report}",
        );
        assert!(
            report.contains("\tID 42, ACME, balance 2.50 AC (frozen)\n"),
            "held asset row format: got {report}",
        );
        assert!(
            report.contains(
                "\tID 7, 1 extra page, global state used 1/4 uints, 1/2 byte slices, version 8\n"
            ),
            "created apps row format: got {report}",
        );
        assert!(
            report.contains("\tID 11, local state used 1/1 uints, 0/1 byte slices\n"),
            "opted-in apps row format: got {report}",
        );
        assert!(report.contains("Minimum Balance:\t200000 microAlgos\n"));
    }

    #[test]
    fn format_info_held_asset_404_is_deleted_unknown() {
        let v = serde_json::json!({
            "address": "X", "amount": 0, "rewards": 0, "min-balance": 0, "round": 0,
            "assets": [{"asset-id": 99, "amount": 0, "is-frozen": false}],
        });
        let mut held = std::collections::HashMap::new();
        held.insert(99u64, AssetFetch::Missing);
        let (report, _errors, has_error) = format_info(&v, &held, false);
        assert!(!has_error, "404 must not flag has_error");
        assert!(report.contains("\tID 99, <deleted/unknown asset>\n"));
    }

    #[test]
    fn format_info_held_asset_error_sets_has_error_and_writes_stderr() {
        let v = serde_json::json!({
            "address": "X", "amount": 0, "rewards": 0, "min-balance": 0, "round": 0,
            "assets": [{"asset-id": 99, "amount": 0, "is-frozen": false}],
        });
        let mut held = std::collections::HashMap::new();
        held.insert(99u64, AssetFetch::Error);
        let (report, errors, has_error) = format_info(&v, &held, false);
        assert!(has_error, "non-404 fetch error must set has_error");
        assert!(report.contains("\tID 99, error\n"));
        assert!(errors.contains("Error: Unable to retrieve asset information for asset 99"));
    }

    #[test]
    fn format_assetdetails_renders_one_asset_block() {
        let holding = serde_json::json!({"asset-id": 42, "amount": 250, "is-frozen": false});
        let params = serde_json::json!({
            "creator": "CREATOR", "name": "ACME", "unit-name": "AC",
            "total": 1000, "decimals": 2, "url": "https://acme",
        });
        let s = format_assetdetails("ADDR", 99, None, &[(holding, Some(params))]);
        // Pin every header + value Go emits, in order.
        let expected = "\
Account: ADDR
Round: 99
Assets:
  Asset ID: 42
    Amount: 2.50
    IsFrozen: false
  Asset Params:
    Creator: CREATOR
    Name: ACME
    Units: AC
    Total: 1000
    Decimals: 2
    URL: https://acme
";
        assert_eq!(s, expected, "assetdetails block diverges from Go format");
    }

    // ---- TASK-239 (B7) unit tests --------------------------------------

    #[test]
    fn is_root_key_filename_matches_go_rule() {
        // Go's IsRootKeyFilename requires `<stem>.rootkey` with
        // non-empty stem (config/keyfile.go:81).
        assert!(is_root_key_filename("alice.rootkey"));
        assert!(is_root_key_filename("X.rootkey"));
        assert!(!is_root_key_filename(".rootkey"));
        assert!(!is_root_key_filename("alice.partkey"));
        assert!(!is_root_key_filename("alice"));
        assert!(!is_root_key_filename(""));
    }

    #[test]
    fn parse_signature_secrets_blob_round_trips() {
        // Mirror Go's wire format from crypto/msgp_gen.go: 2-key map
        // { "SK": <64 bytes>, "SignatureVerifier": <32 bytes> }.
        // Hand-build the msgpack bytes to be sure we're matching Go.
        let sk = [0xABu8; 64];
        let sv = [0xCDu8; 32];
        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 2).unwrap();
        rmp::encode::write_str(&mut buf, "SK").unwrap();
        rmp::encode::write_bin(&mut buf, &sk).unwrap();
        rmp::encode::write_str(&mut buf, "SignatureVerifier").unwrap();
        rmp::encode::write_bin(&mut buf, &sv).unwrap();
        let parsed = parse_signature_secrets_blob(&buf).expect("decode");
        assert_eq!(parsed.sk, sk);
        assert_eq!(parsed.pubkey, sv);
    }

    #[test]
    fn parse_signature_secrets_blob_rejects_wrong_sizes() {
        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 2).unwrap();
        rmp::encode::write_str(&mut buf, "SK").unwrap();
        rmp::encode::write_bin(&mut buf, &[0u8; 32]).unwrap(); // wrong size
        rmp::encode::write_str(&mut buf, "SignatureVerifier").unwrap();
        rmp::encode::write_bin(&mut buf, &[0u8; 32]).unwrap();
        let err = parse_signature_secrets_blob(&buf).unwrap_err();
        assert!(err.contains("SK has wrong length"), "got {err}");
    }

    #[test]
    fn format_assetdetails_without_params_uses_unformatted_amount() {
        let holding = serde_json::json!({"asset-id": 5, "amount": 17, "is-frozen": true});
        let s = format_assetdetails("ADDR", 1, None, &[(holding, None)]);
        assert!(
            s.contains("    Amount (without formatting): 17\n"),
            "no-params branch must render `Amount (without formatting):`; got {s}",
        );
        assert!(s.contains("    IsFrozen: true\n"));
    }
}
