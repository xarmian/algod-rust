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

pub fn run_new(args: NewArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let data_dir = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let kmd_dir = match data_dir::resolve_kmd_data_dir(kmd_dir_flag.as_deref(), &data_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let (kmd_addr, kmd_token) = match read_kmd_endpoint(&kmd_dir) {
        Ok(t) => t,
        Err(()) => return ExitCode::from(1),
    };

    let client = match KmdClient::new(&kmd_addr, &kmd_token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
            );
            return ExitCode::from(1);
        }
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
        let p1 = match rpassword::prompt_password(format_message(PROMPT_CHOOSE, &[&args.name])) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}",
                    format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
                );
                return Err(());
            }
        };
        let p2 = match rpassword::prompt_password(PROMPT_CONFIRM) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}",
                    format_message(ERROR_COULDNT_CREATE, &[&e.to_string()])
                );
                return Err(());
            }
        };
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
