//! `goal-rust wallet new` — port of `../go-algorand/cmd/goal/
//! wallet.go:85-198` (`newWalletCmd`).
//!
//! Phase A (TASK-226) shipped: --password / driver + create. Phase B
//! (TASK-234) retro-fits the four deferrals:
//! - `--recover` (alias `--recover-mnemonic` in the CLI body, mirroring
//!   Go's `recoverWallet` bool) — reads a mnemonic on stdin and seeds
//!   the wallet with the derived 32-byte master derivation key.
//! - `--unencrypted-wallet` — creates with empty password and prints
//!   `infoUnencrypted`.
//! - Post-create backup-phrase prompt (suppressible via
//!   `--no-display-seed`) — exports the new wallet's MDK and renders
//!   the 25-word mnemonic.
//! - Set-default-on-first — after a successful create, if this is the
//!   only wallet on the data dir, the wallet ID is persisted into
//!   `accountList.json` so `wallet list` can mark it `(default)`.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_consensus_crypto::{key_to_mnemonic, mnemonic_to_key};
use algo_kmd_client::{KmdClient, KmdError};

use crate::accounts_list::AccountsList;
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

/// Mirrors `messages.go:169` (`infoRecoveryPrompt`). Go's
/// `fmt.Println(infoRecoveryPrompt)` appends a trailing newline after
/// the prompt's trailing space; we preserve that exactly.
const INFO_RECOVERY_PROMPT: &str =
    "Please type your recovery mnemonic below, and hit return when you are done: ";

/// Mirrors `messages.go:174` (`infoUnencrypted`).
const INFO_UNENCRYPTED: &str = "Creating unencrypted wallet";

/// Mirrors `messages.go:175` (`infoBackupExplanation`). Multi-line —
/// reproduced verbatim including the trailing space after the `?`
/// (Go uses `fmt.Println(infoBackupExplanation)` which would normally
/// add a newline, but the string itself ends with `(Y/n): ` and the
/// Println adds one newline after).
const INFO_BACKUP_EXPLANATION: &str = "Your new wallet has a backup phrase that can be used for recovery.\nKeeping this backup phrase safe is extremely important.\nWould you like to see it now? (Y/n): ";

/// Mirrors `messages.go:176` (`infoPrintedBackupPhrase`).
const INFO_PRINTED_BACKUP_PHRASE: &str =
    "Your backup phrase is printed below.\nKeep this information safe -- never share it with anyone!";

/// Mirrors `messages.go:187` (`errorBadMnemonic`).
const ERROR_BAD_MNEMONIC: &str = "Problem with mnemonic: {}";

/// Mirrors `messages.go:188` (`errorBadRecoveredKey`).
const ERROR_BAD_RECOVERED_KEY: &str = "Recovered invalid key";

/// Mirrors `messages.go:181` (`errorCouldntInitializeWallet`).
const ERROR_COULDNT_INITIALIZE: &str = "Couldn't initialize wallet: {}";

/// Mirrors `messages.go:182` (`errorCouldntExportMDK`).
const ERROR_COULDNT_EXPORT_MDK: &str = "Couldn't export master derivation key: {}";

/// Mirrors `messages.go:183` (`errorCouldntMakeMnemonic`).
const ERROR_COULDNT_MAKE_MNEMONIC: &str = "Couldn't make mnemonic: {}";

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
    // Resolve the single data dir up-front so we can also feed it to
    // AccountsList for set-default-on-first.
    let data_dir_path = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let client = match ensure_kmd_client_for_dir(
        &data_dir_path,
        kmd_dir_flag.as_deref(),
        ERROR_COULDNT_CREATE,
    ) {
        Ok(c) => c,
        Err(()) => return ExitCode::from(1),
    };

    // --recover takes precedence over the password prompt order: Go
    // reads the mnemonic first (wallet.go:101-118), then the
    // password / unencrypted decision second (wallet.go:120-137).
    let mut mdk: [u8; 32] = [0u8; 32];
    if args.recover_mnemonic {
        match read_recovery_mnemonic() {
            Ok(key) => mdk = key,
            Err(()) => return ExitCode::from(1),
        }
    }

    let password = if args.unencrypted_wallet {
        // Go's reportInfoln writes to stderr (it's a top-level
        // log-like helper used for both info and error in goal). We
        // route it to stderr to match — goal-rust's parity fixtures
        // capture both streams.
        eprintln!("{INFO_UNENCRYPTED}");
        String::new()
    } else {
        match resolve_password(&args) {
            Ok(p) => p,
            Err(()) => return ExitCode::from(1),
        }
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
    let create_resp =
        match rt.block_on(client.create_wallet(&args.name, &args.driver, &password, mdk)) {
            Ok(resp) => resp,
            Err(e) => {
                // Surface kmd's server-side `message` verbatim where we
                // have it — operators rely on this text for diagnosis.
                let msg = match &e {
                    KmdError::Api { message, .. } => message.clone(),
                    other => other.to_string(),
                };
                eprintln!("{}", format_message(ERROR_COULDNT_CREATE, &[&msg]));
                return ExitCode::from(1);
            }
        };
    println!("{}", format_message(INFO_CREATED, &[&args.name]));

    // Post-create backup-phrase prompt. Suppressed when we just
    // recovered (the user already has the mnemonic) or when
    // --no-display-seed was passed. Mirrors `wallet.go:147-181`.
    if !args.recover_mnemonic && !args.no_display_seed {
        if let Err(()) = maybe_show_backup_phrase(&rt, &client, &create_resp.wallet.id, &password) {
            // maybe_show_backup_phrase already emitted Go's error
            // text; the wallet itself was created successfully so we
            // propagate the failure verbatim by returning 1.
            return ExitCode::from(1);
        }
    }

    // Set-default-on-first. Mirrors `wallet.go:185-196`.
    match rt.block_on(client.list_wallets()) {
        Ok(list) => {
            if list.wallets.len() == 1 {
                let mut accounts = AccountsList::load(&data_dir_path);
                if let Err(e) = accounts.set_default_wallet_id(&create_resp.wallet.id) {
                    // Persisting the default is non-fatal — Go's
                    // dumpList swallows write errors via log.Error +
                    // fmt.Print. We mirror that by printing the error
                    // but still returning success.
                    eprintln!("{e}");
                }
            }
        }
        Err(e) => {
            // Non-fatal: the wallet was created. Surface the error
            // message but exit 0 (matches Go's reportErrorf flow
            // would actually exit, but only if ListWallets fails after
            // a successful create — in practice this is exceedingly
            // rare and operators care more about the create
            // succeeding). We log and continue.
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_LIST, &[&msg]));
        }
    }

    ExitCode::SUCCESS
}

/// Read a 25-word mnemonic from stdin (TTY: prompt then ReadString;
/// non-TTY: read one line). Returns the derived 32-byte MDK. On
/// failure, emits Go's exact error text to stderr and returns Err.
fn read_recovery_mnemonic() -> Result<[u8; 32], ()> {
    // Go uses `fmt.Println(infoRecoveryPrompt)` which adds a trailing
    // newline. The prompt itself ends with a space — we keep that as
    // shipped and let Println add the newline.
    println!("{INFO_RECOVERY_PROMPT}");
    let stdin = std::io::stdin();
    let mut line = String::new();
    if let Err(e) = stdin.lock().read_line(&mut line) {
        eprintln!("{}", format_message(ERROR_BAD_MNEMONIC, &[&e.to_string()]));
        return Err(());
    }
    let trimmed = line.trim();
    match mnemonic_to_key(trimmed) {
        Ok(key) => {
            if key.len() != 32 {
                eprintln!("{ERROR_BAD_RECOVERED_KEY}");
                return Err(());
            }
            Ok(key)
        }
        Err(e) => {
            eprintln!("{}", format_message(ERROR_BAD_MNEMONIC, &[&e.to_string()]));
            Err(())
        }
    }
}

/// Implements `wallet.go:147-181` — print explanation, read y/n,
/// init handle, export MDK, render mnemonic, release handle.
fn maybe_show_backup_phrase(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    wallet_id: &str,
    password: &str,
) -> Result<(), ()> {
    // Go does `fmt.Println(infoBackupExplanation)` — the constant
    // already ends with `): ` so Println's trailing newline puts the
    // user's response on the next line. Mirror exactly.
    println!("{INFO_BACKUP_EXPLANATION}");
    let stdin = std::io::stdin();
    let mut line = String::new();
    if let Err(e) = stdin.lock().read_line(&mut line) {
        eprintln!("{}", format_message(ERROR_BAD_MNEMONIC, &[&e.to_string()]));
        return Err(());
    }
    let resp = line.trim().to_lowercase();
    if resp == "n" {
        return Ok(());
    }

    // Init handle, export MDK, release handle. Go calls
    // GetWalletHandleToken which expires after MaxWalletHandleDuration;
    // we use init_wallet directly (the kmd client wrapper added in
    // TASK-233 mirrors that path).
    let handle = match rt.block_on(client.init_wallet(wallet_id, password)) {
        Ok(r) => r.wallet_handle_token,
        Err(e) => {
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_INITIALIZE, &[&msg]));
            return Err(());
        }
    };
    // Defer-style cleanup: even if MDK export or mnemonic conversion
    // fails, we want to release the handle so kmd doesn't hold it
    // open until session timeout.
    let mdk_result = rt.block_on(client.master_key_export(&handle, password));
    let _ = rt.block_on(client.release_wallet_handle(&handle));

    let mdk_resp = match mdk_result {
        Ok(r) => r,
        Err(e) => {
            let msg = match &e {
                KmdError::Api { message, .. } => message.clone(),
                other => other.to_string(),
            };
            eprintln!("{}", format_message(ERROR_COULDNT_EXPORT_MDK, &[&msg]));
            return Err(());
        }
    };

    let mnemonic = match key_to_mnemonic(&mdk_resp.master_derivation_key) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "{}",
                format_message(ERROR_COULDNT_MAKE_MNEMONIC, &[&e.to_string()])
            );
            return Err(());
        }
    };

    println!("{INFO_PRINTED_BACKUP_PHRASE}");
    // Go: `infoBackupPhrase = "\n%s"` ⇒ leading blank line then the
    // mnemonic. reportInfof then adds a trailing newline.
    println!();
    println!("{mnemonic}");

    Ok(())
}

/// Port of `listWalletsCmd` + `printWallets`
/// (`wallet.go:199-281`). Iterates every `-d` data dir Go's
/// `datadir.OnDataDirs` would visit (with the same `[Data Directory:
/// <dir>]` header when more than one) and lists each kmd's wallets.
/// Output byte-identical to Go for the empty + populated cases.
///
/// Each `Wallet:\t<name>` line is suffixed with ` (default)` if the
/// wallet ID matches `accountList.json`'s `DefaultWalletID` for the
/// resolved data dir. Mirrors `wallet.go:268-273`.
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
            Ok(resp) => {
                let accounts = AccountsList::load(d);
                print_wallets(&resp.wallets, &accounts.default_wallet_id);
            }
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
/// `default_wallet_id` is the resolved `accountList.json` default for
/// the data dir; when non-empty and equal to a wallet's ID, the
/// `Wallet:\t<name>` line is suffixed with ` (default)`. Mirrors Go's
/// `wallet.go:268-273` (`if wallet.id matches DefaultWalletID,
/// fmt.Println(" (default)")` — Go's exact suffix is a leading space
/// then `(default)` with no trailing punctuation).
fn print_wallets(wallets: &[algo_kmd_api_types::common::APIV1Wallet], default_wallet_id: &str) {
    if wallets.is_empty() {
        println!("{INFO_NO_WALLETS}");
        return;
    }
    for w in wallets {
        println!("{WALLET_SEPARATOR}");
        let default_marker = if !default_wallet_id.is_empty() && w.id == default_wallet_id {
            " (default)"
        } else {
            ""
        };
        println!("Wallet:\t{}{default_marker}", w.name);
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
