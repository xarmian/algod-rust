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

use algo_kmd_client::{KmdClient, KmdError};

use crate::accounts_list::AccountsList;
use crate::data_dir;
use crate::groups::account::{
    AddressArgs, AssetdetailsArgs, DeleteArgs, DumpArgs, InfoArgs, ListArgs, NewArgs, RenameArgs,
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
