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
use crate::groups::account::{DeleteArgs, DumpArgs, NewArgs, RenameArgs};

/// Mirrors `messages.go:32` (`infoRenamedAccount`).
const INFO_RENAMED_ACCOUNT: &str = "Renamed account '{}' to '{}'";

/// Mirrors `messages.go:36` (`infoCreatedNewAccount`).
const INFO_CREATED_NEW_ACCOUNT: &str = "Created new account with address {}";

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
    let address = match algo_types::Address::from_algorand_string(&args.address) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Could not parse address: {e}");
            return ExitCode::from(1);
        }
    };
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
    let client = algo_rest_client::AlgodClient::new(&base, &token);
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let info = match rt.block_on(client.get_account(&address)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e.to_string()]));
            return ExitCode::from(1);
        }
    };
    match serde_json::to_string_pretty(&info) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to render JSON: {e}");
            ExitCode::from(1)
        }
    }
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
}
