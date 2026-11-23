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

//! `goal-rust account` lifecycle leaves (TASK-235 / B3).
//!
//! Ports four lifecycle leaves from `../go-algorand/cmd/goal/account.go`:
//! - `new`   → account.go:313-359
//! - `delete`→ account.go:379-398
//! - `rename`→ account.go:281-310
//! - `dump`  → account.go `dumpCmd` (the `basics.BalanceRecord`, see
//!   [`crate::balance_record`]).
//!
//! Wallet-handle resolution mirrors Go's `getWalletHandleMaybePassword`
//! (commands.go:342-410): explicit `-w` ⇒ look up by name; no `-w` ⇒
//! use accountList.json's `DefaultWalletID`; if no default, fall back
//! to "single wallet auto-promotes to default"; else error.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_consensus_crypto::{key_to_mnemonic, mnemonic_to_key};
use algo_kmd_client::{KmdClient, KmdError};

use crate::accounts_list::AccountsList;
use crate::data_dir;
use crate::groups::account::{
    AddpartkeyArgs, AddressArgs, ApplicationdetailsArgs, AssetdetailsArgs, ChangeonlinestatusArgs,
    DeleteArgs, DeletepartkeyArgs, DumpArgs, ExportArgs, ImportArgs, ImportRootKeyArgs, InfoArgs,
    InstallpartkeyArgs, ListArgs, MarknonparticipatingArgs, MsigDeleteArgs, MsigInfoArgs,
    MsigNewArgs, NewArgs, RenameArgs, RenewallpartkeysArgs, RenewpartkeyArgs,
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

/// go: `errorRequestFail` (`cmd/goal/messages.go`).
pub(crate) const ERROR_REQUEST_FAIL: &str = "Error processing command: {}";

/// go: `errNoWallets` / `errNoDefaultWallet` (`cmd/goal/messages.go`).
const ERROR_NO_WALLETS: &str =
    "No wallets found. Create a new wallet with `goal wallet new [wallet name]`";
const ERROR_NO_DEFAULT_WALLET: &str = "No default wallet found. Specify a wallet by name with -w, \
     or set a default with `goal wallet -f [wallet name]";

/// go's `makeAccountsList`: the data dir's accounts list, or go's
/// `errorGenesisIDFail` on stderr when its genesis ID cannot be read
/// (issue #2436); the caller exits 1.
fn load_accounts(data_dir_path: &Path) -> Result<AccountsList, ()> {
    AccountsList::load(data_dir_path).map_err(|e| eprintln!("{e}"))
}

/// Mirrors `messages.go:39` (`infoSetAccountToDefault`).
const INFO_SET_ACCOUNT_TO_DEFAULT: &str = "Set account '{}' to be the default account";

// ---- account (no subcommand) ----------------------------------------------

/// Port of `accountCmd`'s `Run` (`account.go`): go builds the accounts
/// list first (so a data dir without a readable genesis ID stops with
/// `errorGenesisIDFail` even without `-f`), then `-f/--default <name>` marks
/// that account the default one; without it (or with an empty name) the
/// group's help is printed. kmd is not contacted.
pub fn run_root(default_name: Option<String>, cli_d: Vec<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let Some(name) = default_name.filter(|n| !n.is_empty()) else {
        return crate::print_group_help(&["account"]);
    };
    if !accounts.is_taken(&name) {
        eprintln!("{}", format_message(ERROR_NAME_DOESNT_EXIST, &[&name]));
        return ExitCode::from(1);
    }
    if let Err(e) = accounts.set_default(&name) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    println!("{}", format_message(INFO_SET_ACCOUNT_TO_DEFAULT, &[&name]));
    ExitCode::SUCCESS
}

// ---- account new ----------------------------------------------------------

pub fn run_new(args: NewArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    // go builds the accounts list first (account.go:332).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let _ = kmd_dir_flag;
    let client = match build_wallet_handle_kmd_client(&data_dir_path) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

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
    let (wallet_id, _wallet_name, _password) =
        match resolve_wallet_no_password(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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

/// Port of `listCmd` (`account.go`): the accounts of the one wallet go's
/// `ensureWalletHandle` picks (`-w`, else the default wallet, else the
/// only one), each with what algod knows of it (`outputAccount`), and
/// with `--info` its assets and apps (`printAccountInfo`).
pub fn run_list(args: ListArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    // go builds the accounts list first (account.go:508).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    // go: `ensureWalletHandle(dataDir, walletName)`, whose own kmd client
    // fails with `kmd client init error: ...` (issue #2454).
    let wh_client = match build_wallet_handle_kmd_client(&data_dir_path) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let (handle, _wallet_name, _pw) =
        match resolve_wallet_no_password(&rt, &wh_client, &mut accounts, args.wallet.as_deref()) {
            Ok(v) => v,
            Err(()) => return ExitCode::from(1),
        };
    // go: `client := ensureKmdClient(dataDir)`.
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    // go: `client.ListAddressesWithInfo(wh)` -- the keys, then the
    // multisig addresses.
    let listed = rt.block_on(async {
        let keys = client.list_keys(&handle).await?.addresses;
        let msigs = client.list_multisig_addrs(&handle).await?.addresses;
        Ok::<_, KmdError>((keys, msigs))
    });
    let (keys, msigs) = match listed {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
            return ExitCode::from(1);
        }
    };
    if keys.is_empty() && msigs.is_empty() {
        println!("{INFO_NO_ACCOUNTS}");
        return ExitCode::SUCCESS;
    }

    // `client.AccountInformation(addr, true)` builds the algod client on
    // first use; any failure leaves the account `[n/a]`.
    let algod = build_algod_endpoint(&data_dir_path);
    let mut account_info_error = false;
    let listed = keys
        .into_iter()
        .map(|a| (a, false))
        .chain(msigs.into_iter().map(|a| (a, true)));
    for (addr, multisig) in listed {
        let info = algod
            .as_ref()
            .and_then(|ep| account_information(&rt, ep, &addr))
            .unwrap_or_else(|| serde_json::json!({}));
        let msig = if multisig {
            match rt.block_on(client.export_multisig(&handle, &addr)) {
                Ok(m) => Some((m.threshold, m.pks.len())),
                Err(e) => {
                    println!("multisig lookup err");
                    eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&kmd_msg(&e)]));
                    return ExitCode::from(1);
                }
            }
        } else {
            None
        };
        match output_account(&accounts, &addr, &info, msig) {
            Ok(line) => println!("{line}"),
            Err(status) => {
                // go panics here (`outputAccount`)
                eprintln!("panic: unexpected account status: {status}");
                return ExitCode::from(2);
            }
        }
        if args.info {
            let held = held_asset_params(&rt, algod.as_ref(), &info, false);
            let (report, errors, has_error) = format_info(&addr, &info, &held, false);
            crate::algod_rest::eprint_raw(&errors);
            print!("{report}");
            account_info_error |= has_error;
        }
    }
    if account_info_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// go's `AccountsList.outputAccount`: one `account list` line (without the
/// newline). `Err` is a status go's switch does not know (go panics).
fn output_account(
    accounts: &AccountsList,
    addr: &str,
    info: &serde_json::Value,
    multisig: Option<(u8, usize)>,
) -> Result<String, String> {
    use std::fmt::Write as _;
    let name = accounts.name_for(addr);
    let mut line = match info.get("address").and_then(|a| a.as_str()) {
        None | Some("") => format!("[n/a]\t{name}\t{addr}\t[n/a] microAlgos"),
        Some(_) => {
            let status = info.get("status").and_then(|s| s.as_str()).unwrap_or("");
            let status = match status {
                "Online" => "online",
                "Offline" => "offline",
                "Not Participating" => "excluded",
                other => return Err(other.to_string()),
            };
            let amount = info.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
            format!("[{status}]\t{name}\t{addr}\t{amount} microAlgos")
        }
    };
    if let Some((threshold, pks)) = multisig {
        let _ = write!(line, "\t[{threshold}/{pks} multisig]");
    }
    let list = |key: &str| {
        info.get(key)
            .and_then(|a| a.as_array())
            .filter(|a| !a.is_empty())
    };
    if let Some(assets) = list("created-assets") {
        let out: Vec<String> = assets
            .iter()
            .map(|a| {
                let params = a.get("params");
                let field = |k: &str| params.and_then(|p| p.get(k));
                let unit = field("unit-name")
                    .and_then(|u| u.as_str())
                    .map(|u| crate::formatting::unicode_printable(u).1)
                    .unwrap_or_default();
                format!(
                    "{} ({} {unit})",
                    a.get("index").and_then(|i| i.as_u64()).unwrap_or(0),
                    field("total").and_then(|t| t.as_u64()).unwrap_or(0)
                )
            })
            .collect();
        let _ = write!(line, "\t[created asset IDs: {}]", out.join(", "));
    }
    let ids = |apps: &Vec<serde_json::Value>| {
        apps.iter()
            .map(|a| {
                a.get("id")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(0)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(apps) = list("created-apps") {
        let _ = write!(line, "\t[created app IDs: {}]", ids(apps));
    }
    if let Some(apps) = list("apps-local-state") {
        let _ = write!(line, "\t[opted in app IDs: {}]", ids(apps));
    }
    if accounts.is_default(addr) {
        line.push_str("\t*Default");
    }
    Ok(line)
}

/// Resolve algod base URL + token for the data dir. Returns None when
/// `algod.net` or `algod.token` is missing — list_addresses still
/// renders with `[n/a]` balances in that case.
/// Whether an API token passes go-algorand's length check (`ValidateAPIToken`,
/// `util/tokens/tokens.go`): 64–256 chars. goal-rust falls back from the admin
/// token to the regular one when the admin token is missing *or* invalid,
/// matching `tokens.GetAndValidateAPIToken`.
fn is_valid_api_token(token: &str) -> bool {
    (64..=256).contains(&token.len())
}

fn build_algod_endpoint(data_dir_path: &Path) -> Option<(String, String)> {
    // go builds a client here, whose `getGoalClient` creates the cache dir
    // first (issue #2449).
    crate::goal_client::prepare_or_exit(data_dir_path);
    let net = std::fs::read_to_string(data_dir_path.join("algod.net")).ok()?;
    let net = net.trim();
    if net.is_empty() {
        return None;
    }
    // Prefer the admin token, falling back to the regular token. The admin
    // token is accepted on every endpoint AND is required for the admin-gated
    // `/v2/participation*` handlers (addpartkey/listpartkeys/deletepartkey) —
    // the regular token alone gets a 401 from a real Go algod there. A token is
    // only used if it passes go's length check (an invalid admin token falls
    // back to the regular one). Mirrors go-algorand's libgoal `nc.AlgodClient()`
    // → `tokens.GetAndValidateAPIToken` (nodecontrol/algodControl.go:72,
    // util/tokens/tokens.go) and our own `cmd/node.rs` (TASK-261).
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

/// go's `client.AccountInformation(addr, true)`: the account as algod
/// reports it, `None` on any failure.
fn account_information(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    address: &str,
) -> Option<serde_json::Value> {
    get_account(rt, endpoint, address, true).ok()
}

/// go's `RestClient.AccountInformation(address, includeCreatables)`:
/// `GET /v2/accounts/<address>?exclude=<none|all>&format=json` decoded into
/// a `model.Account`, or go's error text (issue #2466).
fn get_account(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    address: &str,
    include_creatables: bool,
) -> Result<serde_json::Value, String> {
    let exclude = if include_creatables { "none" } else { "all" };
    crate::algod_rest::get_json(
        rt,
        endpoint,
        &format!("/v2/accounts/{address}"),
        &[("exclude", exclude), ("format", "json")],
        &crate::go_codec_json::ACCOUNT,
    )
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
    // go builds the accounts list first (account.go:399).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

    let (handle, _wallet_name, password) =
        match resolve_wallet_and_init(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };

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
    // go's dumpCmd: `ensureAlgodClient(dataDir)` (issue #2454), then the
    // address (`basics.UnmarshalChecksumAddress`), then `client.AccountData`:
    // algod's msgpack `basics.AccountData` (issue #2467).
    let Ok(endpoint) = ensure_algod_endpoint(&data_dir_path) else {
        return ExitCode::from(1);
    };
    let addr: [u8; 32] = match algo_avm::assembler::unmarshal_checksum_address(&args.address)
        .and_then(|a| <[u8; 32]>::try_from(a.as_slice()).map_err(|e| e.to_string()))
    {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to parse addr: {e}");
            return ExitCode::from(1);
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let path = format!("/v2/accounts/{}", args.address);
    let record = crate::algod_rest::get(&rt, &endpoint, &path, &[("format", "msgpack")])
        .and_then(|answer| crate::balance_record::dump(&addr, &answer, args.outfile.is_some()));
    let data = match record {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}",
                crate::formatting::report_error_text(&format_message(ERROR_REQUEST_FAIL, &[&e]))
            );
            return ExitCode::from(1);
        }
    };
    match args.outfile {
        // go: `writeFile(dumpOutFile, data, 0644)`, its error ignored
        Some(path) => {
            let _ = write_file_0644(&path, &data);
        }
        None => println!("{}", String::from_utf8_lossy(&data)),
    }
    ExitCode::SUCCESS
}

/// go's `writeFile(filename, data, 0644)`: `-` is stdout.
fn write_file_0644(filename: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if filename == "-" {
        let mut out = std::io::stdout().lock();
        return out.write_all(data).and_then(|()| out.flush());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    opts.open(filename)?.write_all(data)
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

/// go's `ensureKmdClient(dataDir)`, which starts kmd when it is not running
/// (the `-k` flag is the one `goal_client` resolves; issue #2454).
fn build_kmd_client(data_dir_path: &Path, _kmd_dir_flag: Option<&Path>) -> Result<KmdClient, ()> {
    crate::goal_client::ensure_kmd_client(data_dir_path).map_err(|e| {
        eprintln!("{e}");
    })
}

/// The kmd client of go's `ensureWalletHandle(dataDir, walletName)` when no
/// `ensureKmdClient` comes before it (`account new`, `account list`): its
/// failure is `kmd client init error: <err>` (issue #2454).
fn build_wallet_handle_kmd_client(data_dir_path: &Path) -> Result<KmdClient, ()> {
    crate::goal_client::wallet_handle_kmd_client(data_dir_path).map_err(|e| {
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
) -> Result<(String, String, String), ()> {
    resolve_wallet(rt, client, accounts, wallet_flag, true)
}

/// `getWalletHandleMaybePassword(.., getPassword = false)`: callers that need
/// no password (go's `ensureWalletHandle`).
fn resolve_wallet_no_password(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    accounts: &mut AccountsList,
    wallet_flag: Option<&str>,
) -> Result<(String, String, String), ()> {
    resolve_wallet(rt, client, accounts, wallet_flag, false)
}

fn resolve_wallet(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    accounts: &mut AccountsList,
    wallet_flag: Option<&str>,
    get_password: bool,
) -> Result<(String, String, String), ()> {
    // 1. Resolve wallet ID + name.
    let (wallet_id, wallet_name) =
        wallet_id_and_name(rt, client, accounts, wallet_flag).map_err(|e| eprintln!("{e}"))?;

    // 2. The (cached) wallet handle token and the password.
    let (handle, password) = crate::wallet_token::wallet_handle_and_password(
        rt,
        client,
        &accounts.data_dir,
        &wallet_id,
        &wallet_name,
        get_password,
    )
    .map_err(|e| {
        eprintln!("{e}");
    })?;
    Ok((handle, wallet_name, password))
}

/// The wallet ID and name of go's `getWalletHandleMaybePassword`
/// (`cmd/goal/commands.go`): the wallet named by `-w`, else the default
/// wallet of the accounts list, else the only wallet kmd has (made the
/// default). `Err` is go's error text.
pub(crate) fn wallet_id_and_name(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    accounts: &mut AccountsList,
    wallet_flag: Option<&str>,
) -> Result<(String, String), String> {
    let wallets = || {
        rt.block_on(client.list_wallets())
            .map(|l| l.wallets)
            .map_err(|e| kmd_msg(&e))
    };
    match wallet_flag.filter(|n| !n.is_empty()) {
        Some(name) => {
            // `FindWalletIDByName`
            let listed = wallets().map_err(|e| format!("Couldn't find wallet: {e}"))?;
            let matching: Vec<_> = listed.iter().filter(|w| w.name == name).collect();
            if matching.len() > 1 {
                return Err(format!(
                    "More than one wallet named '{name}' exists. Please remove any wallets                      with the same name from the kmd wallet directory"
                ));
            }
            match matching.last() {
                Some(w) if !w.id.is_empty() => Ok((w.id.clone(), name.to_string())),
                _ => Err(format!("Wallet '{name}' not found")),
            }
        }
        None => {
            let mut wallet_id = accounts.default_wallet_id.clone();
            if wallet_id.is_empty() {
                let listed = wallets().map_err(|e| format!("Couldn't list wallets: {e}"))?;
                match listed.len() {
                    0 => return Err(ERROR_NO_WALLETS.to_string()),
                    1 => {
                        wallet_id = listed[0].id.clone();
                        let _ = accounts.set_default_wallet_id(&wallet_id);
                    }
                    _ => return Err(ERROR_NO_DEFAULT_WALLET.to_string()),
                }
            }
            // `FindWalletNameByID`: a duplicate before an error
            let listed = wallets();
            let matching: Vec<_> = listed
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|w| w.id == wallet_id)
                .collect();
            if matching.len() > 1 {
                return Err(format!(
                    "More than one wallet with ID '{wallet_id}' exists. Please remove any                      wallets with the samd ID from the kmd wallet directory"
                ));
            }
            if let Err(e) = listed {
                return Err(format!(
                    "Couldn't get wallet name from ID '{wallet_id}': {e}"
                ));
            }
            match matching.last() {
                Some(w) if !w.name.is_empty() => Ok((wallet_id, w.name.clone())),
                _ => Err(format!(
                    "Wallet with ID '{wallet_id}' not found. Was the default wallet deleted?"
                )),
            }
        }
    }
}

pub(crate) fn kmd_msg(e: &KmdError) -> String {
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

/// `account import [name] [-w] [--mnemonic] [-f]` —
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
    // go builds the accounts list first (account.go:1389).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };

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
    let (handle, _wallet_name, _password) =
        match resolve_wallet_no_password(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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

/// `account export -a <addr> [-w]` — export the account
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

    // go: `ensureWalletHandleMaybePassword` → `makeAccountsList`.
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let (handle, _wallet_name, password) =
        match resolve_wallet_and_init(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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

/// go's `errorDirectoryNotExist` (`cmd/goal/messages.go`).
const ERROR_DIRECTORY_NOT_EXIST: &str = "Specified directory '{}' does not exist.";

/// `account addpartkey -a <addr> --roundFirstValid <r> --roundLastValid <r>
/// [-o <dir>] [--keyDilution <n>]`: go's `addParticipationKeyCmd`
/// (cmd/goal/account.go). The key is generated locally
/// (`participation.GenParticipationKeysTo`) into `--outdir`, or into
/// `$TMPDIR` and installed with `POST /v2/participation`.
pub fn run_addpartkey(args: AddpartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let out_dir = args.outdir.as_deref().filter(|d| !d.is_empty());
    if let Some(d) = out_dir {
        if !Path::new(d).is_dir() {
            eprintln!("{}", format_message(ERROR_DIRECTORY_NOT_EXIST, &[d]));
            return ExitCode::from(1);
        }
    }
    // go: `ensureFullClient(dataDir)`, which starts kmd.
    let endpoint = match crate::goal_client::ensure_algod_endpoint(
        &dd,
        crate::goal_client::ClientType::Full,
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(rt) = build_runtime() else {
        return ExitCode::from(1);
    };

    println!("Please stand by while generating keys. This might take a few minutes...");
    let generated = run_with_spinning_cursor(|| {
        gen_participation_keys(
            &rt,
            &endpoint,
            &args.address,
            args.round_first_valid,
            args.round_last_valid,
            args.key_dilution.unwrap_or(0),
            out_dir.map(Path::new),
        )
    });
    let part_id = match generated {
        Ok((id, _)) => id,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e]));
            return ExitCode::from(1);
        }
    };
    // go's `reportInfof("...%s\n")`: every line of the text, the empty one
    // after its trailing newline too.
    println!("Participation key generation successful. Participation ID: {part_id}\n");
    println!(
        "\nGenerated with goal v{}",
        crate::cmd::info::current_version_string()
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
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(endpoint) = ensure_algod_endpoint(&dd) else {
        return ExitCode::from(1);
    };
    let fail = |e: &str| {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[e]));
        ExitCode::from(1)
    };
    // go's `client.AddParticipationKey(file)`: the file read, then the POST
    let bytes = match std::fs::read(&args.partkey) {
        Ok(b) => b,
        Err(e) => {
            return fail(&format!(
                "open {}: {}",
                args.partkey.display(),
                data_dir::go_os_error(&e)
            ))
        }
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let part_id = match crate::algod_rest::post_json(
        &rt,
        &endpoint,
        "/v2/participation",
        &[],
        Some(&bytes),
        &crate::go_codec_json::POST_PARTICIPATION,
    ) {
        Ok(r) => r["partId"].as_str().unwrap_or("").to_string(),
        Err(e) => return fail(&e),
    };

    // Verify the key is actually installed before deleting the input
    // file. Mirrors Go's `client.VerifyParticipationKey(time.Minute,
    // addResponse.PartId)` (account.go:1040-1045) — algod can ack
    // the POST then drop the key, and silently deleting the only copy
    // would leave the operator with no way to retry. Poll
    // list_participation_keys for up to 60s. Codex round-1 P1 finding.
    // go's `client.VerifyParticipationKey(time.Minute, partId)`: the
    // listing every second until the key shows up
    let start = std::time::Instant::now();
    let verified = loop {
        match participation_keys(&rt, &endpoint) {
            Ok(parts) if parts.iter().any(|p| p["id"].as_str() == Some(&part_id)) => {
                break Ok(());
            }
            Ok(_) => {}
            Err(e) => break Err(e),
        }
        if start.elapsed() > std::time::Duration::from_secs(60) {
            break Err("timeout waiting for key to appear".to_string());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    if let Err(why) = verified {
        return fail(&format!(
            "unable to verify key installation. Verify key installation with 'goal account \
             partkeyinfo' and delete '{}', or retry the command. Error: {why}",
            args.partkey.display(),
        ));
    }

    // go's `reportInfof` of a text ending in a newline: an empty line after
    println!("Participation key installed successfully, Participation ID: {part_id}\n");
    // Go deletes the input file on success (account.go:1048-1051).
    if let Err(e) = std::fs::remove_file(&args.partkey) {
        eprintln!(
            "An error occurred while removing the partkey file, please delete it manually:              remove {}: {}",
            args.partkey.display(),
            crate::data_dir::go_os_error(&e)
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// go: `client.ListParticipationKeys()`: `GET /v2/participation` into a
/// `model.ParticipationKeysResponse`.
fn participation_keys(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
) -> Result<Vec<serde_json::Value>, String> {
    let v = crate::algod_rest::get_json(
        rt,
        endpoint,
        "/v2/participation",
        &[],
        &crate::go_codec_json::PARTICIPATION_KEYS,
    )?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

/// go: `roundOrNA` of a `*basics.Round` field.
fn json_round_or_na(v: &serde_json::Value) -> String {
    round_or_na(v.as_u64())
}

/// `account listpartkeys`: go's `listParticipationKeysCmd`. A key whose
/// account cannot be read is left out, like go.
pub fn run_listpartkeys(cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    // go: `ensureGoalClient(dataDir, DynamicClient)`; its
    // `ListParticipationKeys` then needs the algod client, whose failure is
    // `errorRequestFail` (issue #2454).
    if let Err(e) =
        crate::goal_client::ensure_goal_client(&dd, crate::goal_client::ClientType::Dynamic)
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    let report = |e: &str| {
        eprintln!(
            "{}",
            crate::formatting::report_error_text(&format_message(ERROR_REQUEST_FAIL, &[e]))
        );
        ExitCode::from(1)
    };
    let endpoint = match crate::goal_client::algod_endpoint(&dd) {
        Ok(ep) => ep,
        Err(e) => return report(&e),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let parts = match participation_keys(&rt, &endpoint) {
        Ok(p) => p,
        Err(e) => return report(&e),
    };
    println!(
        "{:<10}  {:<11}  {:<15}  {:>10}  {:>11}  {:>10}",
        "Registered", "Account", "ParticipationID", "Last Used", "First round", "Last round"
    );
    for part in &parts {
        let address = part["address"].as_str().unwrap_or("");
        let Ok(account) = get_account(&rt, &endpoint, address, false) else {
            continue;
        };
        let key = &part["key"];
        let online = &account["participation"];
        // go compares the `[]byte` keys as strings: nil and empty are equal
        let bytes_eq = |f: &str| online[f].as_str().unwrap_or("") == key[f].as_str().unwrap_or("");
        let registered = online.is_object()
            && bytes_eq("vote-participation-key")
            && bytes_eq("selection-participation-key")
            && online["vote-first-valid"] == key["vote-first-valid"]
            && online["vote-last-valid"] == key["vote-last-valid"]
            && online["vote-key-dilution"] == key["vote-key-dilution"];
        let last_used = ["last-vote", "last-block-proposal", "last-state-proof"]
            .iter()
            .filter_map(|f| part[*f].as_u64())
            .max()
            .unwrap_or(0);
        let id = part["id"].as_str().unwrap_or("");
        // go slices `Address[:4]` / `Id[:8]` (byte offsets)
        let head = |s: &str, n: usize| s.get(..n).unwrap_or(s).to_string();
        let tail = |s: &str, n: usize| s.get(s.len().saturating_sub(n)..).unwrap_or(s).to_string();
        println!(
            "{:<10}  {:<11}  {:<15}  {:>10}  {:>11}  {:>10}",
            if registered { "yes" } else { "no" },
            format!("{}...{}", head(address, 4), tail(address, 4)),
            format!("{}...", head(id, 8)),
            round_or_na(Some(last_used)),
            key["vote-first-valid"].as_u64().unwrap_or(0),
            key["vote-last-valid"].as_u64().unwrap_or(0),
        );
    }
    ExitCode::SUCCESS
}

/// go v5.1's `isPartkeyRegistered`: `part` is the participation key currently
/// registered on `account`. The `[]byte` keys compare with `bytes.Equal`, so nil
/// and empty are equal.
fn is_partkey_registered(account: &serde_json::Value, part: &serde_json::Value) -> bool {
    let key = &part["key"];
    let online = &account["participation"];
    let bytes_eq = |f: &str| online[f].as_str().unwrap_or("") == key[f].as_str().unwrap_or("");
    online.is_object()
        && bytes_eq("vote-participation-key")
        && bytes_eq("selection-participation-key")
        && online["vote-first-valid"] == key["vote-first-valid"]
        && online["vote-last-valid"] == key["vote-last-valid"]
        && online["vote-key-dilution"] == key["vote-key-dilution"]
}

/// `account partkeyinfo`: go's `partkeyInfoCmd`, every data dir in turn;
/// the first failure ends the command (`reportErrorf`).
pub fn run_partkeyinfo(cli_d: Vec<PathBuf>) -> ExitCode {
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
    use std::io::Write as _;
    for data_dir_path in &dirs {
        println!(
            "Dumping participation key info from {}...",
            data_dir_path.display()
        );
        let _ = std::io::stdout().flush();
        let Ok(endpoint) = ensure_algod_endpoint(data_dir_path) else {
            return ExitCode::from(1);
        };
        let parts = match participation_keys(&rt, &endpoint) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}",
                    crate::formatting::report_error_text(&format_message(
                        ERROR_REQUEST_FAIL,
                        &[&e]
                    ))
                );
                return ExitCode::from(1);
            }
        };
        let mut out = String::new();
        for part in &parts {
            use std::fmt::Write as _;
            let key = &part["key"];
            let s = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
            let u = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
            // `[]byte` fields are base64 in the decoded value already
            let _ = writeln!(out);
            let _ = writeln!(out, "Participation ID:          {}", s(&part["id"]));
            let _ = writeln!(out, "Parent address:            {}", s(&part["address"]));
            // go v5.1: `Registered: yes|no|unknown`, from one more account
            // request per key (`isPartkeyRegistered`).
            let registered = match get_account(&rt, &endpoint, &s(&part["address"]), false) {
                Err(_) => "unknown",
                Ok(account) => {
                    if is_partkey_registered(&account, part) {
                        "yes"
                    } else {
                        "no"
                    }
                }
            };
            let _ = writeln!(out, "Registered:                {registered}");
            let _ = writeln!(
                out,
                "Last vote round:           {}",
                json_round_or_na(&part["last-vote"])
            );
            let _ = writeln!(
                out,
                "Last block proposal round: {}",
                json_round_or_na(&part["last-block-proposal"])
            );
            let _ = writeln!(
                out,
                "Effective first round:     {}",
                json_round_or_na(&part["effective-first-valid"])
            );
            let _ = writeln!(
                out,
                "Effective last round:      {}",
                json_round_or_na(&part["effective-last-valid"])
            );
            let _ = writeln!(
                out,
                "First round:               {}",
                u(&key["vote-first-valid"])
            );
            let _ = writeln!(
                out,
                "Last round:                {}",
                u(&key["vote-last-valid"])
            );
            let _ = writeln!(
                out,
                "Key dilution:              {}",
                u(&key["vote-key-dilution"])
            );
            let _ = writeln!(
                out,
                "Selection key:             {}",
                s(&key["selection-participation-key"])
            );
            let _ = writeln!(
                out,
                "Voting key:                {}",
                s(&key["vote-participation-key"])
            );
            if key["state-proof-key"].is_string() {
                let _ = writeln!(
                    out,
                    "State proof key:           {}",
                    s(&key["state-proof-key"])
                );
            }
        }
        crate::formatting::print_raw(&out);
    }
    ExitCode::SUCCESS
}

/// `account deletepartkey --partkeyid <id>`. Mirrors
/// `deletePartKeyCmd` (account.go:361-377).
pub fn run_deletepartkey(args: DeletepartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(endpoint) = ensure_algod_endpoint(&dd) else {
        return ExitCode::from(1);
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    // go: `RemoveParticipationKeyByID`, a DELETE that expects no content
    let path = format!("/v2/participation/{}", args.partkeyid);
    if let Err(e) = crate::algod_rest::delete(
        &rt,
        &endpoint,
        &path,
        &crate::go_codec_json::POST_PARTICIPATION,
        true,
    ) {
        eprintln!("{}", format_message(ERROR_REQUEST_FAIL, &[&e]));
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// go's `ensureAlgodClient(dataDir)`: the algod base URL and token, else go's
/// `Cannot contact Algorand node: <err>` printed (issue #2454).
fn ensure_algod_endpoint(dd: &Path) -> Result<(String, String), ()> {
    crate::goal_client::ensure_algod_endpoint(dd, crate::goal_client::ClientType::Algod)
        .map_err(|e| eprintln!("{e}"))
}

/// `roundOrNA(value)` — Go's helper for printing optional rounds
/// (account.go:1454-1459). 0/None ⇒ `N/A`.
fn round_or_na(value: Option<u64>) -> String {
    match value {
        Some(v) if v != 0 => v.to_string(),
        _ => "N/A".to_string(),
    }
}

// ---- keyreg status-change pipeline (TASK-244 / B12) -----------------------

/// The stock `MaxTxnLife` value for every real go-algorand consensus
/// version to date (test fixture only -- production code never references
/// this constant). The real bound comes from
/// [`crate::cmd::clerk::resolve_max_txn_life`] (reads `<data_dir>/consensus.json`
/// overrides merged onto the built-in per-version table, keyed by the
/// node-reported consensus version), mirroring go-algorand's
/// `libgoal.Client.ComputeValidityRounds` (libgoal.go:509-521) — see issue
/// #1295.
#[cfg(test)]
const MAX_TXN_LIFE: u64 = 1000;

/// Compute a transaction's `[first_valid, last_valid]` window, mirroring
/// go-algorand's `libgoal.computeValidityRounds` (libgoal.go:525) with
/// `validRounds = 0`: an unset `first` defaults to the current round (or 1),
/// an unset `last` defaults to `first + max_txn_life`, and the span is
/// validated. `max_txn_life` should come from
/// [`crate::cmd::clerk::resolve_max_txn_life`] rather than a hardcoded
/// constant, so a `consensus.json` override on the active consensus version
/// is respected the same way go's `cparams.MaxTxnLife` lookup is.
fn compute_validity(
    first_valid: Option<u64>,
    last_valid: Option<u64>,
    last_round: u64,
    max_txn_life: u64,
) -> Result<(u64, u64), String> {
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
    let last = match last_valid {
        Some(l) if l != 0 => l,
        _ => first.saturating_add(max_txn_life),
    };
    if first > last {
        return Err(format!(
            "txn would first be valid on round {first} which is after last valid round {last}"
        ));
    }
    if last - first > max_txn_life {
        return Err(format!(
            "txn validity period ({first} to {last}) is greater than max txn lifetime {max_txn_life}"
        ));
    }
    Ok((first, last))
}

/// Pick the participation key for `address` valid at `round` that expires
/// farthest in the future, the first listed of those expiring together.
/// Mirrors go-algorand's `Client.chooseParticipation`
/// (libgoal/participation.go:30), whose `VoteLastValid > expiry` (expiry
/// starting at 0) keeps the first maximum.
fn choose_participation<'a>(
    parts: &'a [algo_rest_client::ParticipationKey],
    address: &str,
    round: u64,
) -> Option<&'a algo_rest_client::ParticipationKey> {
    let mut chosen = None;
    let mut expiry = 0;
    for p in parts {
        if p.key.vote_first_valid <= round
            && round <= p.key.vote_last_valid
            && p.address == address
            && p.key.vote_last_valid > expiry
        {
            chosen = Some(p);
            expiry = p.key.vote_last_valid;
        }
    }
    chosen
}

/// Sign (via kmd), broadcast, and optionally wait for a status-change keyreg.
/// `label` is interpolated into Go's `Transaction id for {label} transaction:`
/// line (account.go:921 / 1542); go's `waitForCommit` prints the commit, and
/// its error is prefixed with `wait_prefix`.
#[allow(clippy::too_many_arguments)]
fn sign_submit_confirm(
    rt: &tokio::runtime::Runtime,
    pipeline: &algo_txn_pipeline::TxnPipeline,
    txn: &algo_types::Transaction,
    handle: &str,
    password: &str,
    no_wait: bool,
    label: &str,
    wait_prefix: &str,
) -> Result<(), String> {
    let last_valid = txn.last_valid.0;
    let signed = rt
        .block_on(pipeline.sign_with_kmd(handle, password, txn))
        .map_err(|e| format!("Couldn't sign tx with kmd: {e}"))?;
    let txid = crate::algod_txn::broadcast(rt, pipeline.algod(), &signed)
        .map_err(|e| format!("Couldn't broadcast tx with algod: {e}"))?;
    println!("Transaction id for {label} transaction: {txid}");

    if no_wait {
        println!("Note: status will not change until transaction is finalized");
        return Ok(());
    }
    crate::algod_txn::wait_for_commit(rt, pipeline.algod(), &txid, last_valid)
        .map(|_| ())
        .map_err(|e| format!("{wait_prefix}{e}"))
}

/// `account changeonlinestatus`. Mirrors Go's `changeOnlineCmd` and
/// `changeAccountOnlineStatus` (`cmd/goal/account.go`): every failure is
/// go's text, in go's order.
pub fn run_changeonlinestatus(
    args: ChangeonlinestatusArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match change_online_status(args, &cli_d, kmd_dir_flag) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // go's `reportErrorf`/`reportErrorln`: the text, then a newline.
            // An empty text: the helper that failed already reported it.
            if !e.is_empty() {
                eprintln!("{e}");
            }
            ExitCode::from(1)
        }
    }
}

/// go's `checkTxValidityPeriodCmdFlags` (`cmd/goal/commands.go`).
fn check_tx_validity_period_flags(
    valid_rounds: Option<u64>,
    last_valid: Option<u64>,
) -> Result<(), String> {
    if valid_rounds.is_some() && last_valid.is_some() {
        return Err("Only one of [--validrounds] or [--lastvalid] can be specified".to_string());
    }
    if valid_rounds == Some(0) {
        return Err("[--validrounds] can not be zero".to_string());
    }
    Ok(())
}

/// go's `scLeaseBytes`: the 32-byte `--lease`. Its error names go's other
/// `lease` variable (`malformedLease, lease, err`), which this command never
/// sets, so the value printed is empty.
fn status_change_lease(lease: Option<&str>) -> Result<[u8; 32], String> {
    let Some(raw) = lease else {
        return Ok([0; 32]);
    };
    let malformed = |e: String| format!("Cannot base64-decode lease : {e}");
    if let Err(at) = crate::go_json::go_base64_check(raw.as_bytes()) {
        return Err(malformed(format!("illegal base64 data at input byte {at}")));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
    .decode(raw.replace(['\r', '\n'], ""))
    .map_err(|e| malformed(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(malformed(format!("lease length {} != 32", bytes.len())));
    }
    let mut out = [0; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// go's `MakeErasableAccessor(partKeyFile)` + `RestoreParticipation`: the
/// parent address of the participation key in `path`.
fn partkey_file_parent(path: &str) -> Result<algo_types::Address, String> {
    use algo_ledger::erasable_db::{ErasableDb, Error as DbError};
    let db = ErasableDb::open(path).map_err(|e| {
        let e = match e {
            DbError::Sqlite { source, .. } => source.to_string(),
            other => other.to_string(),
        };
        format!("Cannot open partkey {path}: {e}\n")
    })?;
    let load = |e: String| format!("Cannot load partkey {path}: {e}\n");
    // go's `Migrate` → `partMigrate` (`data/account/partInstall.go`): the
    // `schema` table must name the `parttable` at version 3.
    const UNSUPPORTED: &str = "unsupported participation file schema version (expected 3)";
    let version: Option<i64> = db
        .conn()
        .query_row(
            "SELECT version FROM schema WHERE tablename = 'parttable'",
            [],
            |r| r.get(0),
        )
        .ok();
    if version != Some(3) {
        return Err(load(UNSUPPORTED.to_string()));
    }
    algo_ledger::participation::restore::restore_participation(&db)
        .map(|p| p.parent)
        .map_err(|e| load(e.to_string()))
}

fn change_online_status(
    args: ChangeonlinestatusArgs,
    cli_d: &[PathBuf],
    kmd_dir_flag: Option<PathBuf>,
) -> Result<(), String> {
    check_tx_validity_period_flags(args.valid_rounds, args.last_valid)?;
    let mut address = args.address.clone();
    if address.is_empty() && args.partkeyfile.is_empty() {
        return Err("Must specify one of --address or --partkeyfile\n".to_string());
    }
    if !args.partkeyfile.is_empty() && !args.online {
        return Err("Going offline does not support --partkeyfile\n".to_string());
    }
    let data_dir_path = data_dir::ensure_single_data_dir(cli_d).map_err(|e| e.to_string())?;
    // go: writing a txn needs no kmd (`ensureAlgodClient`), else
    // `ensureFullClient`.
    let _ = kmd_dir_flag;
    let client_type = if args.txfile.is_empty() {
        crate::goal_client::ClientType::Full
    } else {
        crate::goal_client::ClientType::Algod
    };
    let endpoint = crate::goal_client::ensure_algod_endpoint(&data_dir_path, client_type)
        .map_err(|e| e.to_string())?;
    if !args.partkeyfile.is_empty() {
        let parent = partkey_file_parent(&args.partkeyfile)?;
        if address.is_empty() {
            address = parent.to_string();
        }
    }
    let rt = build_runtime().map_err(|()| String::new())?;

    // go's `client.ComputeValidityRounds(firstValid, lastValid,
    // numValidRounds)`: the suggested params, the protocol's MaxTxnLife.
    let algod = algo_rest_client::AlgodClient::new(&endpoint.0, &endpoint.1);
    let params = crate::algod_txn::suggested_params(&rt, &algod)?;
    let consensus_version = params.consensus_version.clone();
    let last_round = params.last_round;
    let suggested_fee = params.fee;
    let min_fee = params.min_fee;
    let genesis_hash = params.genesis_hash.0;
    let max_txn_life = crate::cmd::clerk::resolve_max_txn_life(&data_dir_path, &consensus_version)?;
    let (first, last) = crate::cmd::clerk::compute_validity(
        args.first_valid,
        args.last_valid,
        args.valid_rounds,
        last_round,
        max_txn_life,
    )?;
    let lease = status_change_lease(args.lease.as_deref())?;

    // go's `MakeUnsignedGoOnlineTx` / `MakeUnsignedGoOfflineTx`.
    let sender = algo_avm::assembler::unmarshal_checksum_address(&address)?;
    let sender = algo_types::Address(sender.try_into().expect("32-byte address"));
    let fee = args.fee.unwrap_or(0);
    let builder = if args.online {
        let parts = list_part_keys_raw(&rt, &endpoint)?;
        let part = choose_participation(&parts, &address, first).ok_or_else(|| {
            format!(
                "couldn't find a participation key database for address {address} valid at \
                 round {first} in participation registry"
            )
        })?;
        algo_txn_pipeline::KeyregBuilder::online(sender, &part.key).map_err(|e| e.to_string())?
    } else {
        algo_txn_pipeline::KeyregBuilder::offline(sender)
    };
    let mut txn = builder
        .fee(fee)
        .validity(first, last)
        .lease(lease)
        .genesis_hash(genesis_hash)
        .build()
        .map_err(|e| e.to_string())?;
    if fee == 0 {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, suggested_fee, min_fee);
    }
    // go: `utx.RekeyTo = parseRekey(rekeyToAddress)`, after the fee.
    if !args.rekey_to.is_empty() {
        let rekey = algo_avm::assembler::unmarshal_checksum_address(&args.rekey_to)?;
        txn.rekey_to = Some(algo_types::Address(
            rekey.try_into().expect("32-byte address"),
        ));
    }

    finish_status_change(
        &rt,
        &algod,
        &data_dir_path,
        &StatusChangeOpts {
            txfile: &args.txfile,
            signer: &args.signer,
            wallet: args.wallet.as_deref(),
            no_wait: args.no_wait,
            label: "status change",
            wait_prefix: "",
        },
        txn,
        last,
    )
}

/// The flags every status-change command (`changeonlinestatus`,
/// `marknonparticipating`) shares at its end.
struct StatusChangeOpts<'a> {
    txfile: &'a str,
    signer: &'a str,
    wallet: Option<&'a str>,
    no_wait: bool,
    /// The `Transaction id for {label} transaction` line.
    label: &'a str,
    /// Prefix of go's error from waiting for the commit (`reportErrorf` in
    /// `markNonparticipatingCmd`; `changeAccountOnlineStatus` returns it as is).
    wait_prefix: &'a str,
}

/// go's end of `changeAccountOnlineStatus` / `markNonparticipatingCmd`:
/// `--txfile` writes the txn (`writeTxnToFile`), otherwise it is signed
/// (`SignTransactionWithWalletAndSigner`), broadcast and waited for.
fn finish_status_change(
    rt: &tokio::runtime::Runtime,
    algod: &algo_rest_client::AlgodClient,
    data_dir_path: &Path,
    opts: &StatusChangeOpts<'_>,
    txn: algo_types::Transaction,
    last: u64,
) -> Result<(), String> {
    if !opts.txfile.is_empty() {
        return write_status_change_txn(rt, data_dir_path, opts, txn);
    }

    // Sign & broadcast (go: `ensureWalletHandleMaybePassword`, then
    // `SignTransactionWithWalletAndSigner`).
    let kmd = build_wallet_handle_kmd_client(data_dir_path).map_err(|()| String::new())?;
    let mut accounts = load_accounts(data_dir_path).map_err(|()| String::new())?;
    let (handle, _wallet_name, password) =
        resolve_wallet_and_init(rt, &kmd, &mut accounts, opts.wallet)
            .map_err(|()| String::new())?;
    let signing_error = |e: String| {
        format!(
            "Couldn't sign tx with kmd: {e} (for multisig accounts, write tx to file and sign \
             manually)"
        )
    };
    let signer_pk = if opts.signer.is_empty() {
        [0u8; 32]
    } else {
        let pk =
            algo_avm::assembler::unmarshal_checksum_address(opts.signer).map_err(signing_error)?;
        pk.try_into().expect("32-byte address")
    };
    let encoded = algo_codec::canonical_encode_transaction(&txn);
    let signed = rt
        .block_on(kmd.sign_transaction(&handle, &password, encoded, signer_pk))
        .map_err(|e| signing_error(crate::cmd::clerk::kmd_msg(&e)))?;
    let txid = crate::algod_txn::broadcast(rt, algod, &signed.signed_transaction)
        .map_err(|e| format!("Couldn't broadcast tx with algod: {e}"))?;
    println!("Transaction id for {} transaction: {txid}", opts.label);
    if opts.no_wait {
        println!("Note: status will not change until transaction is finalized");
        return Ok(());
    }
    crate::algod_txn::wait_for_commit(rt, algod, &txid, last)
        .map(|_| ())
        .map_err(|e| format!("{}{e}", opts.wait_prefix))
}

/// go's `writeTxnToFile(client, false, ..)`: `--signer` is checked but not
/// used, the txn is written unsigned with the blank multisig of a multisig
/// sender (`populateBlankMultisig`, whose wallet lookup failures are
/// ignored).
fn write_status_change_txn(
    rt: &tokio::runtime::Runtime,
    data_dir_path: &Path,
    opts: &StatusChangeOpts<'_>,
    txn: algo_types::Transaction,
) -> Result<(), String> {
    if !opts.signer.is_empty() {
        let auth = algo_avm::assembler::unmarshal_checksum_address(opts.signer)
            .map_err(|e| format!("Signer invalid ({}): {e}", opts.signer))?;
        if auth.as_slice() == txn.sender.0.as_slice() {
            return Err("AuthAddr cannot be the same as the transaction sender".to_string());
        }
    }
    let msig = blank_multisig_of(rt, data_dir_path, opts.wallet, &txn.sender);
    let stx = algo_types::SignedTransaction {
        txn,
        msig,
        ..algo_types::SignedTransaction::default()
    };
    let encoded = algo_codec::canonical_encode_signed_transaction(&stx);
    crate::cmd::clerk::write_file_0600(Path::new(opts.txfile), &encoded)
}

/// go's `populateBlankMultisig`: the blank multisig of `sender` when the
/// wallet (opened without a password) knows it as a multisig account.
fn blank_multisig_of(
    rt: &tokio::runtime::Runtime,
    data_dir_path: &Path,
    wallet: Option<&str>,
    sender: &algo_types::Address,
) -> Option<algo_types::MultisigSig> {
    let kmd = crate::goal_client::wallet_handle_kmd_client(data_dir_path).ok()?;
    let mut accounts = AccountsList::load(data_dir_path).ok()?;
    let (wallet_id, wallet_name) = wallet_id_and_name(rt, &kmd, &mut accounts, wallet).ok()?;
    let (handle, _) = crate::wallet_token::wallet_handle_and_password(
        rt,
        &kmd,
        &accounts.data_dir,
        &wallet_id,
        &wallet_name,
        false,
    )
    .ok()?;
    let exp = rt
        .block_on(kmd.export_multisig(&handle, &sender.to_string()))
        .ok()?;
    Some(algo_consensus_crypto::multisig_preimage_from_pks(
        exp.version,
        exp.threshold,
        &exp.pks,
    ))
}

/// `account marknonparticipating -a <addr> ...`. Mirrors Go's
/// `markNonparticipatingCmd` (account.go:1605-1658), step by step.
/// Irreversible on-chain.
pub fn run_marknonparticipating(
    args: MarknonparticipatingArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    match mark_nonparticipating(args, &cli_d, kmd_dir_flag) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            ExitCode::from(1)
        }
    }
}

fn mark_nonparticipating(
    args: MarknonparticipatingArgs,
    cli_d: &[PathBuf],
    kmd_dir_flag: Option<PathBuf>,
) -> Result<(), String> {
    // go's `errorConstructingTX`.
    let construct = |e: String| format!("Couldn't construct tx: {e}");
    check_tx_validity_period_flags(args.valid_rounds, args.last_valid)?;
    let data_dir_path = data_dir::ensure_single_data_dir(cli_d).map_err(|e| e.to_string())?;
    // go: `ensureFullClient(dataDir)`, which starts kmd; the wallet handle
    // comes later (`ensureWalletHandleMaybePassword`).
    let _ = kmd_dir_flag;
    let endpoint = crate::goal_client::ensure_algod_endpoint(
        &data_dir_path,
        crate::goal_client::ClientType::Full,
    )
    .map_err(|e| e.to_string())?;
    let rt = build_runtime().map_err(|()| String::new())?;
    let algod = algo_rest_client::AlgodClient::new(&endpoint.0, &endpoint.1);

    // go's `client.ComputeValidityRounds(firstValid, lastValid,
    // numValidRounds)`.
    let params = crate::algod_txn::suggested_params(&rt, &algod).map_err(construct)?;
    let max_txn_life =
        crate::cmd::clerk::resolve_max_txn_life(&data_dir_path, &params.consensus_version)
            .map_err(construct)?;
    let (first, last) = crate::cmd::clerk::compute_validity(
        args.first_valid,
        args.last_valid,
        args.valid_rounds,
        params.last_round,
        max_txn_life,
    )
    .map_err(construct)?;

    // go's `MakeUnsignedBecomeNonparticipatingTx`.
    let sender =
        algo_avm::assembler::unmarshal_checksum_address(&args.address).map_err(construct)?;
    let sender = algo_types::Address(sender.try_into().expect("32-byte address"));
    let fee = args.fee.unwrap_or(0);
    let mut txn = algo_txn_pipeline::KeyregBuilder::nonparticipating(sender)
        .fee(fee)
        .validity(first, last)
        .genesis_hash(params.genesis_hash.0)
        .build()
        .map_err(|e| construct(e.to_string()))?;
    if fee == 0 {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }
    // go: `utx.RekeyTo = parseRekey(rekeyToAddress)`, after the fee.
    if !args.rekey_to.is_empty() {
        let rekey = algo_avm::assembler::unmarshal_checksum_address(&args.rekey_to)?;
        txn.rekey_to = Some(algo_types::Address(
            rekey.try_into().expect("32-byte address"),
        ));
    }

    finish_status_change(
        &rt,
        &algod,
        &data_dir_path,
        &StatusChangeOpts {
            txfile: &args.txfile,
            signer: &args.signer,
            wallet: args.wallet.as_deref(),
            no_wait: args.no_wait,
            label: "mark-nonparticipating",
            wait_prefix: "error waiting for transaction to be committed: ",
        },
        txn,
        last,
    )
}

/// go's `MakeUnsignedGoOnlineTx`: the go-online keyreg of `sender` with the
/// node's participation key valid at its first round (`chooseParticipation`).
#[allow(clippy::too_many_arguments)]
fn build_online_keyreg(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    algod: &algo_rest_client::AlgodClient,
    data_dir: &Path,
    sender: algo_types::Address,
    fee: Option<u64>,
    first_valid: Option<u64>,
    last_valid: Option<u64>,
) -> Result<algo_types::Transaction, String> {
    let params = crate::algod_txn::suggested_params(rt, algod)?;
    let max_txn_life =
        crate::cmd::clerk::resolve_max_txn_life(data_dir, &params.consensus_version)?;
    let (first, last) = compute_validity(first_valid, last_valid, params.last_round, max_txn_life)?;
    // go's `ListParticipationKeys` error is returned as is.
    let parts = list_part_keys_raw(rt, endpoint)?;
    let address = sender.to_string();
    let part = choose_participation(&parts, &address, first).ok_or_else(|| {
        format!(
            "couldn't find a participation key database for address {address} valid at round \
             {first} in participation registry"
        )
    })?;
    let mut txn = algo_txn_pipeline::KeyregBuilder::online(sender, &part.key)
        .map_err(|e| e.to_string())?
        .fee(fee.unwrap_or(0))
        .validity(first, last)
        .genesis_hash(params.genesis_hash.0)
        .build()
        .map_err(|e| e.to_string())?;
    if fee.is_none() {
        txn.fee = algo_txn_pipeline::estimate_fee(&txn, params.fee, params.min_fee);
    }
    Ok(txn)
}

// ---- account renewpartkey / renewallpartkeys (issue #2474) -----------------

/// go: `errLastRoundInvalid` (`cmd/goal/messages.go`).
const ERR_LAST_ROUND_INVALID: &str = "roundLastValid needs to be well after the current round ({})";

/// go: `errExistingPartKey`.
const ERR_EXISTING_PART_KEY: &str =
    "Account already has a participation key valid at least until roundLastValid ({}) - current is {}";

/// The state of the node a renewal starts from: go's `client.CurrentRound()`,
/// `client.SuggestedParams()` and the `MaxTxnLife` of its consensus version
/// (`config.Consensus[...]`: zero for a version goal does not know).
struct RenewRounds {
    current_round: u64,
    max_txn_life: u64,
}

fn renew_rounds(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    dd: &Path,
) -> Result<RenewRounds, String> {
    let fail = |e: String| format_message(ERROR_REQUEST_FAIL, &[&e]);
    let status = crate::algod_rest::get_json(
        rt,
        endpoint,
        "/v2/status",
        &[],
        &crate::go_codec_json::NODE_STATUS,
    )
    .map_err(fail)?;
    let current_round = status["last-round"].as_u64().unwrap_or(0);
    let params = crate::algod_rest::get_json(
        rt,
        endpoint,
        "/v2/transactions/params",
        &[],
        &crate::go_codec_json::TRANSACTION_PARAMETERS,
    )
    .map_err(fail)?;
    let version = params["consensus-version"].as_str().unwrap_or("");
    let max_txn_life = algo_types::consensus::preload_configurable_consensus_protocols(dd)
        .ok()
        .and_then(|t| t.get(version).map(|p| p.max_txn_life))
        .unwrap_or(0);
    Ok(RenewRounds {
        current_round,
        max_txn_life,
    })
}

/// go's `client.ListParticipationKeys()`, a failure reported as go's
/// `errorRequestFail`.
fn list_part_keys(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
) -> Result<Vec<algo_rest_client::ParticipationKey>, String> {
    list_part_keys_raw(rt, endpoint).map_err(|e| format_message(ERROR_REQUEST_FAIL, &[&e]))
}

/// go's `client.ListParticipationKeys()`, its error as is.
fn list_part_keys_raw(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
) -> Result<Vec<algo_rest_client::ParticipationKey>, String> {
    let parts = participation_keys(rt, endpoint)?;
    serde_json::from_value(serde_json::Value::Array(parts)).map_err(|e| e.to_string())
}

/// go's `util.RunFuncWithSpinningCursor`: `f` runs while one of `/-\|` and a
/// backspace is drawn on stdout every 100 ms.
fn run_with_spinning_cursor<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    use std::io::Write as _;
    use std::sync::mpsc;
    let (done, finished) = mpsc::channel::<()>();
    std::thread::scope(|s| {
        let job = s.spawn(move || {
            let out = f();
            let _ = done.send(());
            out
        });
        let progress = ["/", "-", "\\", "|"];
        let mut i = 0;
        while let Err(mpsc::RecvTimeoutError::Timeout) =
            finished.recv_timeout(std::time::Duration::from_millis(100))
        {
            let mut stdout = std::io::stdout();
            let _ = write!(stdout, "{}\u{8}", progress[i]);
            let _ = stdout.flush();
            i = (i + 1) % progress.len();
        }
        job.join().expect("the spinning-cursor job panicked")
    })
}

/// Removes a file when dropped (go's `defer os.Remove(name)`).
struct RemoveOnDrop<'a>(&'a Path);

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// go's `participation.GenParticipationKeysTo(address, first, last, dilution,
/// out_dir, installFunc)`: the key is generated into
/// `<out_dir>/<address>.<first>.<last>.partkey`; without `out_dir` (as
/// `client.GenParticipationKeys` calls it) into `os.TempDir()`, posted to
/// algod (`AddParticipationKey`) and the file removed. Returns the key's
/// `ParticipationID` and the file's path.
fn gen_participation_keys(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    address: &str,
    first: u64,
    last: u64,
    dilution: u64,
    out_dir: Option<&Path>,
) -> Result<(String, PathBuf), String> {
    let parsed = algo_avm::assembler::unmarshal_checksum_address(address)?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&parsed);
    let install = out_dir.is_none();
    let dir = out_dir.map_or_else(std::env::temp_dir, Path::to_path_buf);
    let path = dir.join(format!("{address}.{first}.{last}.partkey"));
    match std::fs::metadata(&path) {
        Ok(_) => {
            return Err(format!(
                "ParticipationKeys exist for the range {first} to {last}"
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "participation key file '{}' cannot be accessed : {e}",
                path.display()
            ))
        }
    }
    let _remove = install.then(|| RemoveOnDrop(&path));
    let dilution = if dilution == 0 {
        algo_ledger::participation::default_key_dilution(
            algo_types::Round(first),
            algo_types::Round(last),
        )
    } else {
        dilution
    };
    let part = {
        let mut db =
            algo_ledger::erasable_db::ErasableDb::open(&path).map_err(|e| e.to_string())?;
        algo_ledger::participation::fill_db_with_participation_keys(
            &mut db,
            algo_types::Address(pk),
            algo_types::Round(first),
            algo_types::Round(last),
            dilution,
        )
        .map_err(|e| e.to_string())?
    };
    if install {
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        crate::algod_rest::post_json(
            rt,
            endpoint,
            "/v2/participation",
            &[],
            Some(&bytes),
            &crate::go_codec_json::POST_PARTICIPATION,
        )?;
    }
    Ok((part.id().to_string(), path.clone()))
}

/// The flags of `renewpartkey` / `renewallpartkeys` a renewal passes on.
struct RenewFlags<'a> {
    fee: u64,
    dilution: u64,
    wallet: Option<&'a str>,
    no_wait: bool,
    rekey_to: &'a str,
}

/// go's `generateAndRegisterPartKey`: generate and install a key valid for
/// `current_round..=key_last_valid`, then register it online with the
/// wallet of `-w` (`changeAccountOnlineStatus`, the keyreg valid for
/// `current_round..=tx_last_valid`). A failed registration only prints a
/// note; a failed generation is the error.
#[allow(clippy::too_many_arguments)]
fn generate_and_register_part_key(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    dd: &Path,
    address: &str,
    current_round: u64,
    key_last_valid: u64,
    tx_last_valid: u64,
    flags: &RenewFlags<'_>,
) -> Result<(), String> {
    use std::io::Write as _;
    println!("Please stand by while generating keys. This might take a few minutes...");
    let generated = run_with_spinning_cursor(|| {
        let r = gen_participation_keys(
            rt,
            endpoint,
            address,
            current_round,
            key_last_valid,
            flags.dilution,
            None,
        )
        .map_err(|e| format_message(ERROR_REQUEST_FAIL, &[&e]));
        // go prints this whether or not the generation failed.
        println!("Participation key generation successful");
        let _ = std::io::stdout().flush();
        r
    });
    let (part_id, key_path) = generated?;
    if register_renewed_key(
        rt,
        endpoint,
        dd,
        address,
        current_round,
        tx_last_valid,
        flags,
    )
    .is_err()
    {
        let _ = std::fs::remove_file(&key_path);
        eprintln!(
            "  Error registering keys - deleting newly-generated key file: {}",
            key_path.display()
        );
    }
    println!("Participation key installed successfully, Participation ID: {part_id}");
    Ok(())
}

/// go's `changeAccountOnlineStatus(address, goOnline=true, "", wallet, first,
/// last, fee, lease, dataDir, client)`: build the go-online keyreg
/// (`MakeUnsignedGoOnlineTx`), then get the wallet handle and password, sign,
/// broadcast and wait. Failing to get the wallet handle exits, like go's
/// `ensureWalletHandleMaybePassword`.
fn register_renewed_key(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    dd: &Path,
    address: &str,
    first: u64,
    last: u64,
    flags: &RenewFlags<'_>,
) -> Result<(), String> {
    let sender = algo_types::Address::from_algorand_string(address).map_err(|e| e.to_string())?;
    let algod = algo_rest_client::AlgodClient::new(&endpoint.0, &endpoint.1);
    let mut txn = build_online_keyreg(
        rt,
        endpoint,
        &algod,
        dd,
        sender,
        Some(flags.fee).filter(|f| *f != 0),
        Some(first),
        Some(last),
    )?;
    match crate::cmd::clerk::parse_rekey(flags.rekey_to) {
        Ok(a) if a != algo_types::Address::default() => txn.rekey_to = Some(a),
        Ok(_) => {}
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    let Ok(kmd) = build_wallet_handle_kmd_client(dd) else {
        std::process::exit(1);
    };
    let Ok(mut accounts) = load_accounts(dd) else {
        std::process::exit(1);
    };
    let Ok((handle, _wallet_name, password)) =
        resolve_wallet_and_init(rt, &kmd, &mut accounts, flags.wallet)
    else {
        std::process::exit(1);
    };
    let pipeline = algo_txn_pipeline::TxnPipeline::new(algod, Some(kmd));
    sign_submit_confirm(
        rt,
        &pipeline,
        &txn,
        &handle,
        &password,
        flags.no_wait,
        "status change",
        "",
    )
}

/// `account renewpartkey`: go's `renewParticipationKeyCmd`.
pub fn run_renewpartkey(args: RenewpartkeyArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(endpoint) = ensure_algod_endpoint(&dd) else {
        return ExitCode::from(1);
    };
    let Ok(rt) = build_runtime() else {
        return ExitCode::from(1);
    };
    let rounds = match renew_rounds(&rt, &endpoint, &dd) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let earliest = rounds.current_round.saturating_add(rounds.max_txn_life);
    if args.round_last_valid <= earliest {
        eprintln!(
            "{}",
            format_message(ERR_LAST_ROUND_INVALID, &[&rounds.current_round.to_string()])
        );
        return ExitCode::from(1);
    }
    // Make sure there is no key valid for (or after) roundLastValid already.
    let parts = match list_part_keys(&rt, &endpoint) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Some(p) = parts
        .iter()
        .find(|p| p.address == args.address && p.key.vote_last_valid >= args.round_last_valid)
    {
        eprintln!(
            "{}",
            format_message(
                ERR_EXISTING_PART_KEY,
                &[
                    &args.round_last_valid.to_string(),
                    &p.key.vote_last_valid.to_string()
                ]
            )
        );
        return ExitCode::from(1);
    }
    let flags = RenewFlags {
        fee: args.fee,
        dilution: args.key_dilution.unwrap_or(0),
        wallet: args.wallet.as_deref(),
        no_wait: args.no_wait,
        rekey_to: args.rekey_to.as_deref().unwrap_or(""),
    };
    if let Err(e) = generate_and_register_part_key(
        &rt,
        &endpoint,
        &dd,
        &args.address,
        rounds.current_round,
        args.round_last_valid,
        earliest,
        &flags,
    ) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    println!(
        "\nGenerated with goal v{}",
        crate::cmd::info::current_version_string()
    );
    ExitCode::SUCCESS
}

/// `account renewallpartkeys`: go's `renewAllParticipationKeyCmd`, every
/// data dir (`OnDataDirs`), a failed one reported as `  Error: <err>`
/// without failing the command.
pub fn run_renewallpartkeys(args: RenewallpartkeysArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let Ok(rt) = build_runtime() else {
        return ExitCode::from(1);
    };
    let flags = RenewFlags {
        fee: args.fee,
        dilution: args.key_dilution.unwrap_or(0),
        wallet: args.wallet.as_deref(),
        no_wait: args.no_wait,
        rekey_to: args.rekey_to.as_deref().unwrap_or(""),
    };
    let ran = data_dir::on_data_dirs(&cli_d, |dd| {
        println!("Renewing participation keys in {}...", dd.display());
        if let Err(e) = renew_part_keys_in_dir(&rt, dd, args.round_last_valid, &flags) {
            eprintln!("  Error: {e}");
        }
    });
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

/// go's `renewPartKeysInDir`.
fn renew_part_keys_in_dir(
    rt: &tokio::runtime::Runtime,
    dd: &Path,
    last_valid_round: u64,
    flags: &RenewFlags<'_>,
) -> Result<(), String> {
    let Ok(endpoint) = ensure_algod_endpoint(dd) else {
        std::process::exit(1);
    };
    // The accounts to renew: every account with a key, with its latest one.
    let parts = list_part_keys(rt, &endpoint)?;
    let mut renew_accounts: Vec<algo_rest_client::ParticipationKey> = Vec::new();
    for part in parts {
        match renew_accounts
            .iter_mut()
            .find(|p| p.address == part.address)
        {
            // go keeps the key it saw first when that one starts after this
            // one ends.
            Some(existing) if existing.key.vote_first_valid >= part.key.vote_last_valid => {}
            Some(existing) => *existing = part,
            None => renew_accounts.push(part),
        }
    }
    let rounds = renew_rounds(rt, &endpoint, dd)?;
    let earliest = rounds.current_round.saturating_add(rounds.max_txn_life);
    if last_valid_round <= earliest {
        return Err(format_message(
            ERR_LAST_ROUND_INVALID,
            &[&rounds.current_round.to_string()],
        ));
    }
    let mut any_errors = false;
    for renew_part in &renew_accounts {
        let vote_last_valid = renew_part.key.vote_last_valid;
        if vote_last_valid >= last_valid_round {
            println!(
                "  Skipping account {}: Already has a part key valid beyond {last_valid_round} (currently {vote_last_valid})",
                renew_part.address
            );
            continue;
        }
        // go: an account whose latest key ends before roundLastValid is left
        // to an explicit `renewpartkey`, so no account reaches the renewal
        // below (as in go v5.0.5-stable).
        if vote_last_valid < last_valid_round {
            println!(
                "  Skipping account {}: This account has part keys that have expired.  Please renew this account explicitly using 'renewpartkey'",
                renew_part.address
            );
            continue;
        }
        let address = &renew_part.address;
        if let Err(e) = generate_and_register_part_key(
            rt,
            &endpoint,
            dd,
            address,
            rounds.current_round,
            last_valid_round,
            earliest,
            flags,
        ) {
            eprintln!("  Error renewing part key for account {address}: {e}");
            any_errors = true;
        }
    }
    if any_errors {
        return Err("one or more renewal attempts had errors".to_string());
    }
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
    // go builds the accounts list first (account.go:420).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
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
    let (handle, _wallet_name, _pw) =
        match resolve_wallet_no_password(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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
    // go builds the accounts list first (account.go:463).
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    let client = match build_kmd_client(&data_dir_path, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let (handle, _wallet_name, password) =
        match resolve_wallet_and_init(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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
    // go: `ensureWalletHandleMaybePassword` → `makeAccountsList`.
    let mut accounts = match load_accounts(&data_dir_path) {
        Ok(a) => a,
        Err(()) => return ExitCode::from(1),
    };
    // go: `ensureWalletHandle` (the password prompt only when no handle
    // token can be had without one).
    let (handle, _wallet_name, _pw) =
        match resolve_wallet_no_password(&rt, &client, &mut accounts, args.wallet.as_deref()) {
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
    // go builds no accounts list here: an unreadable genesis ID makes the
    // command return silently just below, and `ensureWalletHandle` (which
    // does build one) only runs once a key file is read.
    let mut accounts = AccountsList::load_or_empty(&data_dir_path);

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
                let (h, _wallet_name, _pw) = match resolve_wallet_no_password(
                    &rt,
                    &client,
                    &mut accounts,
                    args.wallet.as_deref(),
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
    match fetch_account_json(&args.address, &cli_d, false) {
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
    match fetch_account_json(&args.address, &cli_d, false) {
        Ok(v) => {
            let rewards = v.get("rewards").and_then(|a| a.as_u64()).unwrap_or(0);
            println!("{rewards} microAlgos");
            ExitCode::SUCCESS
        }
        Err(()) => ExitCode::from(1),
    }
}

/// `account applicationdetails -a <addr> [-l <n>] [-n <token>]
/// [--include-params]`: go's `applicationDetailsCmd`: the pages of `GET
/// /v2/accounts/<addr>/applications` (`AccountApplicationsInformation`)
/// printed by `printAccountApplicationsInformation`, one page only when
/// `--limit` or `--next` is given.
pub fn run_applicationdetails(args: ApplicationdetailsArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(endpoint) = ensure_algod_endpoint(&dd) else {
        return ExitCode::from(1);
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let limit = args.limit.unwrap_or(0);
    let next = args.next.clone().unwrap_or_default();
    let mut token = next.clone();
    let mut out = format!("Account: {}\nApplications:\n", args.address);
    let flush = |out: &mut String| {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        // (go-codec's strings are raw bytes, printed unfiltered)
        let _ = stdout.write_all(&algo_types::raw_text::decode(out));
        let _ = stdout.flush();
        out.clear();
    };
    loop {
        let limit_text = limit.to_string();
        let mut query: Vec<(&str, &str)> = Vec::new();
        if !token.is_empty() {
            query.push(("next", &token));
        }
        if limit > 0 {
            query.push(("limit", &limit_text));
        }
        if args.include_params {
            query.push(("include", "params"));
        }
        let response = match crate::algod_rest::get_json(
            &rt,
            &endpoint,
            &format!("/v2/accounts/{}/applications", args.address),
            &query,
            &crate::go_codec_json::ACCOUNT_APPLICATIONS_INFORMATION,
        ) {
            Ok(r) => r,
            Err(e) => {
                flush(&mut out);
                eprintln!(
                    "{}",
                    crate::formatting::report_error_text(&format_message(
                        ERROR_REQUEST_FAIL,
                        &[&e]
                    ))
                );
                return ExitCode::from(1);
            }
        };
        // go dereferences `*response.ApplicationResources`: an answer without
        // it is a nil-pointer panic
        if response["application-resources"].is_null() {
            flush(&mut out);
            eprintln!("panic: runtime error: invalid memory address or nil pointer dereference");
            return ExitCode::from(2);
        }
        out.push_str(&format_account_applications_information(&response));
        token = response["next-token"].as_str().unwrap_or("").to_string();
        if token.is_empty() {
            break;
        }
        if limit > 0 || !next.is_empty() {
            // go: `reportInfof("NextToken: %s", token)`
            out.push_str(&crate::formatting::report_info_text(&format!(
                "NextToken: {token}"
            )));
            break;
        }
    }
    flush(&mut out);
    ExitCode::SUCCESS
}

/// go's `printAccountApplicationsInformation`.
fn format_account_applications_information(response: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let u = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    // go counts a TEAL value of type 2 (uint) as used ints, every other one
    // as used byte slices
    let used = |store: &serde_json::Value| -> (u64, u64) {
        let mut ints = 0;
        let mut bytes = 0;
        for kv in store.as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if kv["value"]["type"].as_u64() == Some(2) {
                ints += 1;
            } else {
                bytes += 1;
            }
        }
        (ints, bytes)
    };
    for app in response["application-resources"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let _ = writeln!(out, "  Application ID: {}", u(&app["id"]));
        let params = &app["params"];
        if params.is_object() {
            let _ = writeln!(out, "  Application Params:");
            let _ = writeln!(
                out,
                "    Creator: {}",
                params["creator"].as_str().unwrap_or("")
            );
            let schema = &params["global-state-schema"];
            let (allocated_ints, allocated_bytes) = if schema.is_object() {
                (u(&schema["num-uint"]), u(&schema["num-byte-slice"]))
            } else {
                (0, 0)
            };
            let (used_ints, used_bytes) = used(&params["global-state"]);
            let _ = writeln!(
                out,
                "    Global State: {used_ints}/{allocated_ints} uints, {used_bytes}/{allocated_bytes} byte slices"
            );
            let pages = u(&params["extra-program-pages"]);
            if pages != 0 {
                let _ = writeln!(out, "    Extra Program Pages: {pages}");
            }
        }
        let local = &app["app-local-state"];
        if local.is_object() {
            let schema = &local["schema"];
            let (used_ints, used_bytes) = used(&local["key-value"]);
            let _ = writeln!(
                out,
                "    Local State: {used_ints}/{} uints, {used_bytes}/{} byte slices",
                u(&schema["num-uint"]),
                u(&schema["num-byte-slice"])
            );
        }
    }
    out
}

/// `account assetdetails -a <addr> [-l <n>] [-n <token>]`: go's
/// `assetDetailsCmd`: the pages of `GET /v2/accounts/<addr>/assets`
/// (`AccountAssetsInformation`) printed by `printAccountAssetsInformation`,
/// one page only when `--limit` or `--next` is given.
pub fn run_assetdetails(args: AssetdetailsArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dd = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let Ok(endpoint) = ensure_algod_endpoint(&dd) else {
        return ExitCode::from(1);
    };
    let rt = match build_runtime() {
        Ok(r) => r,
        Err(()) => return ExitCode::from(1),
    };
    let limit = args.limit.unwrap_or(0);
    let next = args.next.clone().unwrap_or_default();
    let mut token = next.clone();
    let mut out = format!("Account: {}\nAssets:\n", args.address);
    let flush = |out: &mut String| {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        // (go-codec's strings are raw bytes, printed unfiltered)
        let _ = stdout.write_all(&algo_types::raw_text::decode(out));
        let _ = stdout.flush();
        out.clear();
    };
    loop {
        let limit_text = limit.to_string();
        let mut query: Vec<(&str, &str)> = Vec::new();
        if !token.is_empty() {
            query.push(("next", &token));
        }
        if limit > 0 {
            query.push(("limit", &limit_text));
        }
        let response = match crate::algod_rest::get_json(
            &rt,
            &endpoint,
            &format!("/v2/accounts/{}/assets", args.address),
            &query,
            &crate::go_codec_json::ACCOUNT_ASSETS_INFORMATION,
        ) {
            Ok(r) => r,
            Err(e) => {
                flush(&mut out);
                eprintln!(
                    "{}",
                    crate::formatting::report_error_text(&format_message(
                        ERROR_REQUEST_FAIL,
                        &[&e]
                    ))
                );
                return ExitCode::from(1);
            }
        };
        out.push_str(&format_account_assets_information(&response));
        token = response["next-token"].as_str().unwrap_or("").to_string();
        if token.is_empty() {
            break;
        }
        if limit > 0 || !next.is_empty() {
            // go: `reportInfof("NextToken: %s", token)`
            out.push_str(&crate::formatting::report_info_text(&format!(
                "NextToken: {token}"
            )));
            break;
        }
    }
    flush(&mut out);
    ExitCode::SUCCESS
}

/// go's `printAccountAssetsInformation`.
fn format_account_assets_information(response: &serde_json::Value) -> String {
    use crate::formatting::{asset_decimals_fmt, printable};
    use std::fmt::Write as _;
    let mut out = String::new();
    let holdings = response["asset-holdings"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let u = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let s = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
    for asset in holdings {
        let holding = &asset["asset-holding"];
        let _ = writeln!(out, "  Asset ID: {}", u(&holding["asset-id"]));
        let params = &asset["asset-params"];
        if params.is_object() {
            let decimals = u(&params["decimals"]);
            let amount = asset_decimals_fmt(u(&holding["amount"]), decimals);
            let _ = writeln!(out, "    Amount: {amount}");
            let _ = writeln!(out, "    IsFrozen: {}", holding["is-frozen"] == true);
            let _ = writeln!(out, "  Asset Params:");
            let _ = writeln!(out, "    Creator: {}", s(&params["creator"]));
            let name = params["name"]
                .as_str()
                .map_or_else(|| "<unnamed>".to_string(), printable);
            let _ = writeln!(out, "    Asset name: {name}");
            let units = params["unit-name"]
                .as_str()
                .map_or_else(|| "units".to_string(), printable);
            let _ = writeln!(out, "    Unit name: {units}");
            let _ = writeln!(out, "    Total: {}", u(&params["total"]));
            let _ = writeln!(out, "    Decimals: {decimals}");
            let _ = writeln!(
                out,
                "    Default frozen:   {}",
                params["default-frozen"] == true
            );
            let url = params["url"].as_str().map(printable).unwrap_or_default();
            let _ = writeln!(out, "    URL: {url}");
            let _ = writeln!(out, "    Manager address:  {}", s(&params["manager"]));
            let _ = writeln!(out, "    Reserve address:  {}", s(&params["reserve"]));
            let _ = writeln!(out, "    Freeze address:   {}", s(&params["freeze"]));
            let _ = writeln!(out, "    Clawback address: {}", s(&params["clawback"]));
        } else {
            let _ = writeln!(
                out,
                "    Amount (without formatting): {}",
                u(&holding["amount"])
            );
            let _ = writeln!(out, "    IsFrozen: {}", holding["is-frozen"] == true);
        }
    }
    out
}

/// The account's `assets` array; an absent key and `[]` are the same
/// "no holdings" (go-algorand always emits `assets`, as `[]` when empty).
fn held_asset_entries(v: &serde_json::Value) -> &[serde_json::Value] {
    v.get("assets")
        .and_then(|a| a.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// `account info -a <addr>` — multi-section dump: Created Assets,
/// Held Assets, Created Apps, Opted In Apps, Minimum Balance.
/// Mirrors `printAccountInfo` (`account.go:592-770`).
pub fn run_info(args: InfoArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let v = match fetch_account_json(&args.address, &cli_d, true) {
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
    let held_params = held_asset_params(&rt, endpoint.as_ref(), &v, args.only_show_asset_ids);

    let (report, errors, has_error) =
        format_info(&args.address, &v, &held_params, args.only_show_asset_ids);
    crate::algod_rest::eprint_raw(&errors);
    print!("{report}");
    if has_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ---- read-path helpers ----------------------------------------------------

/// The params of each asset `v` holds (go's `client.AssetInformation` in
/// `printAccountInfo`), none with `only_show_asset_ids`.
fn held_asset_params(
    rt: &tokio::runtime::Runtime,
    endpoint: Option<&(String, String)>,
    v: &serde_json::Value,
    only_show_asset_ids: bool,
) -> std::collections::HashMap<u64, AssetFetch> {
    let mut held_params = std::collections::HashMap::new();
    if only_show_asset_ids {
        return held_params;
    }
    // An absent `assets` key and an empty array both mean "no holdings"
    // (go always emits `assets`, `[]` when empty), so there is nothing to
    // fetch. Without an algod endpoint every holding is `AssetFetch::Error`
    // so the rendered row is `	ID N, error`.
    for h in held_asset_entries(v) {
        let aid = h.get("asset-id").and_then(|x| x.as_u64()).unwrap_or(0);
        let fetched = match endpoint {
            Some(ep) => match crate::algod_rest::asset_information(rt, ep, aid) {
                Ok(a) => AssetFetch::Found(a["params"].clone()),
                Err(e) if crate::algod_rest::http_error_status(&e) == Some(404) => {
                    AssetFetch::Missing
                }
                Err(e) => AssetFetch::Error(e),
            },
            None => AssetFetch::Error(String::new()),
        };
        held_params.insert(aid, fetched);
    }
    held_params
}

fn build_algod_endpoint_from(cli_d: &[PathBuf]) -> Option<(String, String)> {
    let dd = data_dir::ensure_single_data_dir(cli_d).ok()?;
    build_algod_endpoint(&dd)
}

fn fetch_account_json(
    address: &str,
    cli_d: &[PathBuf],
    include_creatables: bool,
) -> Result<serde_json::Value, ()> {
    let dd = match data_dir::ensure_single_data_dir(cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    // go: `ensureAlgodClient(dataDir)` first (issue #2454).
    let endpoint = ensure_algod_endpoint(&dd)?;
    if let Err(e) = algo_types::Address::from_algorand_string(address) {
        eprintln!("Could not parse address: {e}");
        return Err(());
    }
    let rt = build_runtime()?;
    get_account(&rt, &endpoint, address, include_creatables).map_err(|e| {
        eprintln!(
            "{}",
            crate::formatting::report_error_text(&format_message(ERROR_REQUEST_FAIL, &[&e]))
        );
    })
}

// `fetch_asset_params` (single-shot, non-status-aware) was used by the
// earlier non-paginated assetdetails path. The paginated endpoint
// surfaces asset-params inline, so the helper has been removed.

/// Outcome of a per-asset fetch in `account info`'s Held Assets section.
enum AssetFetch {
    Found(serde_json::Value),
    Missing, // 404 → `<deleted/unknown asset>`
    /// anything else → `error` + non-zero exit: go's error text
    Error(String),
}

// ---- formatters (pure for unit-testability) ------------------------------

/// Render `account info` output. Returns `(report, errors, has_error)`
/// — `report` to stdout, `errors` to stderr, `has_error` ⇒ exit 1.
fn format_info(
    address: &str,
    v: &serde_json::Value,
    held_params: &std::collections::HashMap<u64, AssetFetch>,
    only_show_asset_ids: bool,
) -> (String, String, bool) {
    use crate::formatting::asset_decimals_fmt;
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
            .map_or_else(|| "<unnamed>".to_string(), crate::formatting::printable);
        let units = params
            .and_then(|p| p.get("unit-name"))
            .and_then(|n| n.as_str())
            .map_or_else(|| "units".to_string(), crate::formatting::printable);
        let total = params
            .and_then(|p| p.get("total"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let decimals = params
            .and_then(|p| p.get("decimals"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let total_fmt = asset_decimals_fmt(total, decimals);
        let url = params
            .and_then(|p| p.get("url"))
            .and_then(|n| n.as_str())
            .map(|s| format!(", {}", crate::formatting::printable(s)))
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
                let decimals = params.get("decimals").and_then(|n| n.as_u64()).unwrap_or(0);
                let amount = h.get("amount").and_then(|n| n.as_u64()).unwrap_or(0);
                let amount_fmt = asset_decimals_fmt(amount, decimals);
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map_or_else(|| "<unnamed>".to_string(), crate::formatting::printable);
                let unit = params
                    .get("unit-name")
                    .and_then(|n| n.as_str())
                    .map_or_else(|| "units".to_string(), crate::formatting::printable);
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
            Some(AssetFetch::Error(e)) => {
                let _ = writeln!(
                    errors,
                    "Error: Unable to retrieve asset information for asset {aid} referred to by account {address}: {e}"
                );
                let _ = writeln!(report, "\tID {aid}, error");
                has_error = true;
            }
            None => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formatting::asset_decimals_fmt;

    #[test]
    fn build_algod_endpoint_prefers_admin_token() {
        let admin = "a".repeat(64);
        let regular = "b".repeat(64);
        let tmp = tempfile::tempdir().unwrap();
        let dd = tmp.path();
        std::fs::write(dd.join("algod.net"), "127.0.0.1:1234\n").unwrap();
        std::fs::write(dd.join("algod.token"), format!("{regular}\n")).unwrap();
        std::fs::write(dd.join("algod.admin.token"), format!("{admin}\n")).unwrap();
        let (base, tok) = build_algod_endpoint(dd).expect("endpoint");
        assert_eq!(base, "http://127.0.0.1:1234");
        assert_eq!(tok, admin, "admin token must win when present + valid");
    }

    #[test]
    fn build_algod_endpoint_falls_back_to_regular_token() {
        let regular = "b".repeat(64);
        let tmp = tempfile::tempdir().unwrap();
        let dd = tmp.path();
        std::fs::write(dd.join("algod.net"), "http://host:9\n").unwrap();
        std::fs::write(dd.join("algod.token"), format!("{regular}\n")).unwrap();
        // No admin token file → regular.
        let (base, tok) = build_algod_endpoint(dd).expect("endpoint");
        assert_eq!(base, "http://host:9");
        assert_eq!(tok, regular);
        // Empty admin token → regular.
        std::fs::write(dd.join("algod.admin.token"), "\n").unwrap();
        assert_eq!(build_algod_endpoint(dd).unwrap().1, regular);
        // Present-but-invalid (too-short) admin token also falls back, matching
        // go's GetAndValidateAPIToken (Codex review TASK-261).
        std::fs::write(dd.join("algod.admin.token"), "tooshort\n").unwrap();
        assert_eq!(build_algod_endpoint(dd).unwrap().1, regular);
    }

    #[test]
    fn compute_validity_defaults_to_current_round_window() {
        // Unset first ⇒ current round; unset last ⇒ first + MaxTxnLife.
        assert_eq!(
            compute_validity(None, None, 500, MAX_TXN_LIFE).unwrap(),
            (500, 1500)
        );
        // first==0 with no last_round ⇒ first defaults to 1.
        assert_eq!(
            compute_validity(Some(0), None, 0, MAX_TXN_LIFE).unwrap(),
            (1, 1001)
        );
        // Explicit window honored.
        assert_eq!(
            compute_validity(Some(10), Some(20), 999, MAX_TXN_LIFE).unwrap(),
            (10, 20)
        );
    }

    #[test]
    fn compute_validity_rejects_bad_windows() {
        assert!(compute_validity(Some(100), Some(50), 0, MAX_TXN_LIFE).is_err());
        // Span wider than MaxTxnLife.
        assert!(compute_validity(Some(1), Some(1 + MAX_TXN_LIFE + 1), 0, MAX_TXN_LIFE).is_err());
    }

    #[test]
    fn compute_validity_respects_a_smaller_max_txn_life() {
        // Issue #1295: compute_validity must respect the resolved
        // MaxTxnLife it's given rather than a hardcoded default -- a
        // consensus.json override with a smaller MaxTxnLife for the active
        // consensus version must shrink both the default window and the
        // explicit-window upper bound.
        assert_eq!(compute_validity(None, None, 500, 5).unwrap(), (500, 505));
        assert!(compute_validity(Some(1), Some(7), 0, 5).is_err());
    }

    #[test]
    fn choose_participation_picks_farthest_expiry_for_address() {
        let mk = |addr: &str, first: u64, last: u64| algo_rest_client::ParticipationKey {
            id: format!("{addr}-{last}"),
            address: addr.to_string(),
            effective_first_valid: None,
            effective_last_valid: None,
            last_block_proposal: None,
            last_state_proof: None,
            last_vote: None,
            key: algo_rest_client::AccountParticipation {
                selection_participation_key: vec![0; 32],
                state_proof_key: Some(vec![0; 64]),
                vote_first_valid: first,
                vote_key_dilution: 100,
                vote_last_valid: last,
                vote_participation_key: vec![0; 32],
            },
        };
        let parts = vec![
            mk("AAA", 1, 4000),
            mk("AAA", 1, 5000),    // farthest expiry for AAA
            mk("BBB", 1, 9000),    // different address — ignored
            mk("AAA", 6000, 9000), // not valid at round 100
        ];
        let chosen = choose_participation(&parts, "AAA", 100).expect("a valid key for AAA");
        assert_eq!(chosen.key.vote_last_valid, 5000);
        // No key for an unknown address.
        assert!(choose_participation(&parts, "CCC", 100).is_none());
        // No key valid at a round beyond every key's window.
        assert!(choose_participation(&parts, "AAA", 100_000).is_none());
        // Of keys expiring together go keeps the first listed (issue #2488).
        let mut tied = vec![mk("AAA", 1, 5000), mk("AAA", 1, 5000)];
        tied[0].id = "first".into();
        tied[1].id = "second".into();
        let chosen = choose_participation(&tied, "AAA", 100).expect("a valid key for AAA");
        assert_eq!(chosen.id, "first");
    }

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
        let (report, errors, has_error) =
            format_info("A", &v, &std::collections::HashMap::new(), false);
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

    /// go-algorand always serializes the four resource lists, so an account
    /// with no resources arrives as `[]` (not absent, #2156); `goal account
    /// info` must render both the same way.
    #[test]
    fn format_info_empty_resource_arrays_render_like_absent_ones() {
        let absent = serde_json::json!({
            "address": "X", "amount": 0, "rewards": 0,
            "min-balance": 100000, "round": 1, "status": "Offline",
        });
        let empty = serde_json::json!({
            "address": "X", "amount": 0, "rewards": 0,
            "min-balance": 100000, "round": 1, "status": "Offline",
            "assets": [], "created-assets": [], "created-apps": [],
            "apps-local-state": [],
            "apps-total-schema": {"num-byte-slice": 0, "num-uint": 0},
            "reward-base": 0,
        });
        let none = std::collections::HashMap::new();
        let want = format_info("A", &absent, &none, false);
        let got = format_info("A", &empty, &none, false);
        assert_eq!(got, want);
        assert!(
            got.0.contains(
                "Held Assets:
	<none>
"
            ),
            "{:?}",
            got.0
        );
        // The held-asset fetch list is empty for both shapes.
        assert!(held_asset_entries(&absent).is_empty());
        assert!(held_asset_entries(&empty).is_empty());
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
        let (report, errors, has_error) = format_info("A", &v, &held, false);
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
        let (report, _errors, has_error) = format_info("A", &v, &held, false);
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
        held.insert(99u64, AssetFetch::Error("boom".to_string()));
        let (report, errors, has_error) = format_info("A", &v, &held, false);
        assert!(has_error, "non-404 fetch error must set has_error");
        assert!(report.contains("\tID 99, error\n"));
        assert!(errors.contains("Error: Unable to retrieve asset information for asset 99"));
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
}
