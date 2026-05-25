//! `goal-rust wallet new` — port of `../go-algorand/cmd/goal/
//! wallet.go:85-198` (`newWalletCmd`).
//!
//! Phase A subset:
//! - No recovery-from-mnemonic flow (`--recover-mnemonic`).
//! - No backup-phrase prompt after creation.
//! - No unencrypted-wallet flag.
//! - No `--default` setting (Go marks the wallet default when it's
//!   the first one; we omit that for Phase A — listings still work).
//!
//! All deferred behavior lives in a later Phase B task alongside the
//! `account` subcommand group.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_kmd_client::{KmdClient, KmdError};

use crate::data_dir::{self, DataDirError};
use crate::groups::wallet::{NewArgs, RenameArgs};

/// Mirrors `messages.go:170` (`infoChoosePasswordPrompt`).
const PROMPT_CHOOSE: &str = "Please choose a password for wallet '{}': ";
/// Mirrors `messages.go:171` (`infoPasswordConfirmation`).
const PROMPT_CONFIRM: &str = "Please confirm the password: ";
/// Mirrors `messages.go:172` (`infoCreatingWallet`).
const INFO_CREATING: &str = "Creating wallet...";
/// Mirrors `messages.go:173` (`infoCreatedWallet`).
const INFO_CREATED: &str = "Created wallet '{}'";
/// Mirrors `messages.go:180` (`errorCouldntCreateWallet`).
const ERROR_COULDNT_CREATE: &str = "Couldn't create wallet: {}";
/// Mirrors `messages.go:186` (`errorPasswordConfirmation`).
const ERROR_PW_CONFIRM: &str = "Password confirmation did not match";

/// Mirrors Go's `Could not contact kmd; is it running?` error path
/// (`commands.go` / `kmdControl.go` — when kmd.net or kmd.token is
/// missing, the Go libgoal client surfaces this exact text).
const ERROR_KMD_UNREACHABLE: &str = "Could not contact kmd; is it running?";

/// Mirrors `messages.go:178` (`infoNoWallets`).
const INFO_NO_WALLETS: &str = "No wallets found. You can create a wallet with `goal wallet new`";

/// Mirrors `messages.go:184` (`errorCouldntListWallets`).
const ERROR_COULDNT_LIST: &str = "Couldn't list wallets: {}";

/// Mirrors `messages.go:179` (`infoRenamedWallet`).
const INFO_RENAMED: &str = "Renamed wallet '{}' to '{}'";

/// Mirrors `messages.go:185` (`errorCouldntFindWallet`).
const ERROR_COULDNT_FIND: &str = "Couldn't find wallet: {}";

/// Mirrors `messages.go:191` (`errorCouldntRenameWallet`).
const ERROR_COULDNT_RENAME: &str = "Couldn't rename wallet: {}";

/// Mirrors `messages.go:194` (`infoPasswordPrompt` for the
/// existing-wallet password). Distinct from `infoChoosePasswordPrompt`
/// (which is the `wallet new` prompt).
const PROMPT_EXISTING_PASSWORD: &str = "Please enter the password for wallet '{}': ";

/// Banner / separator emitted between and around each wallet block.
/// Mirrors `wallet.go:275` and `:281`
/// (`strings.Repeat("#", 50)` = 50 hash characters).
const WALLET_SEPARATOR: &str = "##################################################";

/// Resolve the single `-d` data dir, derive the kmd directory via
/// A2, read `kmd.net` + `kmd.token`, and build a [`KmdClient`].
/// Returns `Err(())` after writing the matching Go error text to
/// stderr — caller maps to `ExitCode::from(1)`.
///
/// Factored out of `run_new` so `run_list` and subsequent wallet
/// subcommands share one place for kmd discovery (Codex-style
/// review pass for TASK-227).
fn ensure_kmd_client_single(
    cli_d: &[PathBuf],
    kmd_dir_flag: Option<&Path>,
) -> Result<KmdClient, ()> {
    let data_dir = match data_dir::ensure_single_data_dir(cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    let kmd_dir = match data_dir::resolve_kmd_data_dir(kmd_dir_flag, &data_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    let (kmd_addr, kmd_token) = read_kmd_endpoint(&kmd_dir)?;
    KmdClient::new(&kmd_addr, &kmd_token).map_err(|e| {
        eprintln!(
            "{}",
            format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
        );
    })
}

pub fn run_new(args: NewArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let client = match ensure_kmd_client_single(&cli_d, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let password = match resolve_password(&args) {
        Ok(p) => p,
        Err(()) => return ExitCode::from(1),
    };

    // Go prints "Creating wallet..." just before the RPC. Match.
    println!("{INFO_CREATING}");

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
            );
            return ExitCode::from(1);
        }
    };
    match rt.block_on(client.create_wallet(&args.name, &args.driver, &password, [0u8; 32])) {
        Ok(_) => {
            println!("{}", format_message(INFO_CREATED, &[&args.name]));
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Surface kmd's server-side `message` verbatim where we
            // have it — operators rely on this text for diagnosis.
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_CREATE, &[&msg]));
            ExitCode::from(1)
        }
    }
}

/// Port of `listWalletsCmd` + `printWallets`
/// (`wallet.go:199-281`). Iterates every `-d` data dir Go's
/// `datadir.OnDataDirs` would visit (with the same `[Data Directory:
/// <dir>]` header when more than one) and lists each kmd's wallets.
/// Output byte-identical to Go for the empty + populated cases on a
/// single data dir.
///
/// (The `(default)` suffix isn't surfaced — Phase A doesn't persist a
/// default-wallet selection; tracking under Phase B with the account
/// group.)
pub fn run_list(cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let dirs = match data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_COULDNT_LIST, &[&e.to_string()]));
            return ExitCode::from(1);
        }
    };
    let multi = dirs.len() > 1;
    for d in &dirs {
        if multi {
            // Mirrors `cmd/util/datadir/messages.go:infoDataDir`.
            println!("[Data Directory: {}]", d.display());
        }
        // Go's OnDataDirs callback uses reportErrorf which os.Exits
        // immediately — we mirror that by returning a non-zero exit
        // code on the first per-dir failure rather than continuing to
        // later dirs and producing partial mixed output (Codex review
        // TASK-227 round 2).
        let client = match ensure_kmd_client_for_dir(d, kmd_dir_flag.as_deref(), ERROR_COULDNT_LIST)
        {
            Ok(c) => c,
            Err(()) => return ExitCode::from(1),
        };
        match rt.block_on(client.list_wallets()) {
            Ok(resp) => print_wallets(&resp.wallets),
            Err(e) => {
                let msg = match &e {
                    KmdError::Api { message, .. } => message.clone(),
                    other => other.to_string(),
                };
                eprintln!("{}", format_message(ERROR_COULDNT_LIST, &[&msg]));
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

/// Per-data-dir variant of [`ensure_kmd_client_single`]: builds the
/// kmd client for one already-resolved data dir. `client_error_tpl`
/// is the error-message template the caller wants used when
/// `KmdClient::new` itself fails (so a kmd-dir read error from
/// `wallet list` is labeled "Couldn't list wallets" rather than
/// "Couldn't create wallet" — Codex review TASK-227 round 2).
fn ensure_kmd_client_for_dir(
    data_dir_path: &Path,
    kmd_dir_flag: Option<&Path>,
    client_error_tpl: &str,
) -> Result<KmdClient, ()> {
    let kmd_dir = match data_dir::resolve_kmd_data_dir(kmd_dir_flag, data_dir_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return Err(());
        }
    };
    let (kmd_addr, kmd_token) = read_kmd_endpoint(&kmd_dir)?;
    KmdClient::new(&kmd_addr, &kmd_token).map_err(|e| {
        eprintln!("{}", format_message(client_error_tpl, &[&e.to_string()]));
    })
}

/// Port of `printWallets` (`wallet.go:261-281`). Each wallet block
/// is bracketed by `##########...` (50 `#` chars). Empty list →
/// Go's `infoNoWallets` line + return.
///
/// Default-wallet indicator (`(default)` suffix on Wallet line) is
/// not produced in Phase A — `goal-rust wallet new` doesn't persist
/// a per-data-dir default. Tracking under the Phase B account work.
fn print_wallets(wallets: &[algo_kmd_api_types::common::APIV1Wallet]) {
    if wallets.is_empty() {
        println!("{INFO_NO_WALLETS}");
        return;
    }
    for w in wallets {
        println!("{WALLET_SEPARATOR}");
        println!("Wallet:\t{}", w.name);
        println!("ID:\t{}", w.id);
    }
    println!("{WALLET_SEPARATOR}");
}

/// Port of `renameWalletCmd` (`wallet.go:215-280`).
pub fn run_rename(
    args: RenameArgs,
    cli_d: Vec<PathBuf>,
    kmd_dir_flag: Option<PathBuf>,
) -> ExitCode {
    if args.old_name == args.new_name {
        eprintln!(
            "{}",
            format_message(
                ERROR_COULDNT_RENAME,
                &["new name is identical to current name"],
            ),
        );
        return ExitCode::from(1);
    }

    let client = match ensure_kmd_client_single(&cli_d, kmd_dir_flag.as_deref()) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_RENAME, &[&e.to_string()])
            );
            return ExitCode::from(1);
        }
    };

    // Resolve old name → wallet id via ListWallets. Mirrors Go's
    // `FindWalletIDByName` (wallet.go:241) which loops the list and
    // also detects duplicates.
    let wallets = match rt.block_on(client.list_wallets()) {
        Ok(r) => r.wallets,
        Err(e) => {
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_RENAME, &[&msg]));
            return ExitCode::from(1);
        }
    };
    let mut matched_id: Option<String> = None;
    let mut duplicate = false;
    for w in &wallets {
        if w.name == args.old_name {
            if matched_id.is_some() {
                duplicate = true;
                break;
            }
            matched_id = Some(w.id.clone());
        }
    }
    let Some(wallet_id) = matched_id else {
        eprintln!("{}", format_message(ERROR_COULDNT_FIND, &[&args.old_name]));
        return ExitCode::from(1);
    };
    if duplicate {
        eprintln!(
            "{}",
            format_message(
                ERROR_COULDNT_RENAME,
                &["Multiple wallets by the same name are not supported"],
            ),
        );
        return ExitCode::from(1);
    }

    let password = match resolve_password_for_existing(&args) {
        Ok(p) => p,
        Err(()) => return ExitCode::from(1),
    };

    match rt.block_on(client.rename_wallet(&wallet_id, &args.new_name, &password)) {
        Ok(_) => {
            println!(
                "{}",
                format_message(INFO_RENAMED, &[&args.old_name, &args.new_name]),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_RENAME, &[&msg]));
            ExitCode::from(1)
        }
    }
}

/// Password prompt for `wallet rename` — distinct from `wallet new`'s
/// because we're asking for an EXISTING wallet's password (no
/// confirmation step). Same TTY-vs-non-TTY Phase-A semantics as
/// `resolve_password`.
fn resolve_password_for_existing(args: &RenameArgs) -> Result<String, ()> {
    if let Some(pw) = &args.password {
        return Ok(pw.clone());
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        use std::io::Write;
        print!(
            "{}",
            format_message(PROMPT_EXISTING_PASSWORD, &[&args.old_name])
        );
        let _ = std::io::stdout().flush();
        let pw = rpassword::read_password().map_err(|e| {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_RENAME, &[&e.to_string()])
            );
        })?;
        println!();
        Ok(pw)
    } else {
        let mut line = String::new();
        if let Err(e) = std::io::stdin().read_line(&mut line) {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_RENAME, &[&e.to_string()])
            );
            return Err(());
        }
        let trimmed = line.strip_suffix('\n').unwrap_or(&line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        Ok(trimmed.to_string())
    }
}

fn read_kmd_endpoint(kmd_dir: &Path) -> Result<(String, String), ()> {
    let net = match std::fs::read_to_string(kmd_dir.join("kmd.net")) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("{ERROR_KMD_UNREACHABLE}");
            return Err(());
        }
    };
    let token = match std::fs::read_to_string(kmd_dir.join("kmd.token")) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("{ERROR_KMD_UNREACHABLE}");
            return Err(());
        }
    };
    if net.is_empty() || token.is_empty() {
        eprintln!("{ERROR_KMD_UNREACHABLE}");
        return Err(());
    }
    Ok((net, token))
}

/// Resolve the wallet password:
/// - `--password <pw>` flag → use it.
/// - TTY stdin → prompt twice and confirm. Mirrors
///   `wallet.go:127-137`.
/// - Non-TTY stdin (piped) → read one line as the password.
///
/// **Intentional divergence from Go (TASK-226 scope):** Go's
/// `wallet.go` always calls `terminal.ReadPassword(os.Stdin.Fd())`,
/// which errors on piped stdin. The Phase-A task spec explicitly
/// chose "non-TTY stdin reads one line" for CI/scripting
/// friendliness — this lets `echo pw | goal-rust wallet new …`
/// work in CI without a tty allocation, and it's the behavior
/// goal-rust's downstream users expect when wrapping the binary.
/// Operators who want Go-strict behavior should pass `--password`
/// (still the safest in scripts anyway).
fn resolve_password(args: &NewArgs) -> Result<String, ()> {
    if let Some(pw) = &args.password {
        return Ok(pw.clone());
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        // Print the prompt to stdout via Rust's print! (matches Go's
        // fmt.Printf at wallet.go:130-136 which goes to stdout —
        // tools that capture stdout from an interactive run see the
        // prompt text). Then use rpassword::read_password() for the
        // masked terminal read so the typed password isn't echoed.
        // (Codex review TASK-226 round 2: rpassword::prompt_password
        // writes the prompt to /dev/tty rather than stdout, which
        // diverges from Go.)
        use std::io::Write;
        print!("{}", format_message(PROMPT_CHOOSE, &[&args.name]));
        let _ = std::io::stdout().flush();
        let p1 = match rpassword::read_password() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}",
                    format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
                );
                return Err(());
            }
        };
        // Go's ensurePassword() emits a trailing newline on stdout
        // after each masked read (terminal.ReadPassword consumes the
        // user's CR but doesn't echo it). Match that so callers
        // capturing stdout see the same line breaks Go produces.
        // (Codex review TASK-226 round 3.)
        println!();
        print!("{PROMPT_CONFIRM}");
        let _ = std::io::stdout().flush();
        let p2 = match rpassword::read_password() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}",
                    format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
                );
                return Err(());
            }
        };
        println!();
        if p1 != p2 {
            eprintln!("{ERROR_PW_CONFIRM}");
            return Err(());
        }
        Ok(p1)
    } else {
        let mut line = String::new();
        if let Err(e) = std::io::stdin().read_line(&mut line) {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
            );
            return Err(());
        }
        // Strip a single trailing newline only — passwords with
        // intentional trailing whitespace are valid otherwise.
        let trimmed = line.strip_suffix('\n').unwrap_or(&line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        Ok(trimmed.to_string())
    }
}

/// Trivial template formatter (same shape as `cmd/node.rs`): replaces
/// `{}` placeholders left-to-right with the supplied args.
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

/// Surface `DataDirError` through the same formatter so test assertions
/// can target a known string. Currently unused but kept for symmetry —
/// callers can lean on the From impl below if they want it.
#[allow(dead_code)]
fn format_data_dir_error(e: DataDirError) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_message_substitutes_placeholders_in_order() {
        assert_eq!(
            format_message("Created wallet '{}'", &["w1"]),
            "Created wallet 'w1'",
        );
        assert_eq!(format_message("{} = {}", &["k", "v"]), "k = v",);
    }

    #[test]
    fn info_created_template_matches_go() {
        // Byte-exact vs Go's messages.go:173.
        assert_eq!(
            format_message(INFO_CREATED, &["my-wallet"]),
            "Created wallet 'my-wallet'",
        );
    }
}
