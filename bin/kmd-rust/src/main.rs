//! kmd-rust — Rust port of Algorand's Key Management Daemon binary.
//!
//! Phase A: loads `kmd_config.json` from `--data-dir` and logs that the
//! daemon is starting. Wallet operations and the REST API surface land in
//! subsequent tasks (see PLAN-151).
//!
//! Go reference: `../go-algorand/daemon/kmd/kmd.go` (v4.5.1-stable).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Algorand Key Management Daemon (Rust port).
#[derive(Parser, Debug)]
#[command(
    name = "kmd-rust",
    version,
    about = "Algorand Key Management Daemon (Rust port)",
    long_about = None,
)]
struct Cli {
    /// Path to the kmd data directory. Must contain (or will receive) a
    /// `kmd_config.json` and wallet SQLite databases.
    #[arg(short = 'd', long = "data-dir")]
    data_dir: PathBuf,
}

fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();

    let cfg = match algo_kmd::load_kmd_config(&cli.data_dir) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!(
                "kmd-rust: failed to load config from {}: {}",
                cli.data_dir.display(),
                err
            );
            return ExitCode::from(1);
        }
    };

    tracing::info!(
        data_dir = %cli.data_dir.display(),
        session_lifetime_secs = cfg.session_lifetime_secs,
        scrypt_n = cfg.driver_config.sqlite.scrypt_params.scrypt_n,
        scrypt_r = cfg.driver_config.sqlite.scrypt_params.scrypt_r,
        scrypt_p = cfg.driver_config.sqlite.scrypt_params.scrypt_p,
        "kmd-rust starting (Phase A: config loaded; wallet ops and REST not yet wired)"
    );

    // Phase A intentionally does not start a server. Exit cleanly so the
    // binary is usable in scripts that just want to validate config.
    ExitCode::SUCCESS
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
