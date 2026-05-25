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
use crate::groups::wallet::NewArgs;

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
/// (`wallet.go:199-281`). Output byte-identical to Go for the
/// empty + populated cases (the `(default)` indicator isn't
/// surfaced — Phase A doesn't persist a default wallet selection,
/// so the suffix never applies and operators get the same shape
/// as Go on a freshly-created data dir with one wallet).
pub fn run_list(cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
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
            eprintln!("{}", format_message(ERROR_COULDNT_LIST, &[&e.to_string()]));
            return ExitCode::from(1);
        }
    };
    let resp = match rt.block_on(client.list_wallets()) {
        Ok(r) => r,
        Err(e) => {
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_LIST, &[&msg]));
            return ExitCode::from(1);
        }
    };
    print_wallets(&resp.wallets);
    ExitCode::SUCCESS
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
