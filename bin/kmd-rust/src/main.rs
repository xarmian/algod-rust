//! kmd-rust — Rust port of Algorand's Key Management Daemon binary.
//!
//! Phase B / B9 wires every component into a long-running `serve` mode:
//!
//! ```text
//! kmd-rust check-config --data-dir <path>   # Phase A: just parse the config
//! kmd-rust serve        --data-dir <path>   # Phase B: bring up the HTTP API
//! ```
//!
//! Go reference: `../go-algorand/daemon/kmd/kmd.go` (v4.5.1-stable).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use algo_kmd::{
    load_kmd_config, validate_or_generate_api_token, SessionManager, WalletDriver, WalletServer,
    WalletServerConfig,
};

/// Algorand Key Management Daemon (Rust port).
#[derive(Parser, Debug)]
#[command(
    name = "kmd-rust",
    version,
    about = "Algorand Key Management Daemon (Rust port)",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Parse `<data_dir>/kmd_config.json` and exit.  Useful for
    /// scripts that just want to validate a deployment.
    CheckConfig {
        /// Path to the kmd data directory.
        #[arg(short = 'd', long = "data-dir")]
        data_dir: PathBuf,
    },
    /// Bind the HTTP API and run until SIGINT / SIGTERM.  Writes
    /// `kmd.net`, `kmd.pid`, `kmd.lock` into the data dir.
    Serve {
        /// Path to the kmd data directory.  Must contain
        /// `kmd_config.json`; the wallets/ subdir, `kmd.token`, and
        /// lifecycle files are created as needed.
        #[arg(short = 'd', long = "data-dir")]
        data_dir: PathBuf,

        /// Optional `host:port` to bind.  When omitted, kmd-rust
        /// tries `127.0.0.1:7833` first and falls back to an
        /// OS-assigned port.
        #[arg(short = 'a', long = "address")]
        address: Option<SocketAddr>,

        /// Optional inactivity timeout in seconds.  Not implemented
        /// yet (Go's watchdog timer); accepted for CLI parity but
        /// currently has no effect.
        #[arg(short = 't', long = "timeout")]
        timeout: Option<u64>,

        /// Comma-separated list of allowed CORS origins.  Use `*`
        /// to reflect the request's origin (matching Go).
        #[arg(long = "allow-origin", value_delimiter = ',')]
        allowed_origins: Vec<String>,

        /// Set the `Access-Control-Allow-Private-Network` response
        /// header on OPTIONS preflights (Chrome PNA).  Matches Go's
        /// `--allow-header-pna`.
        #[arg(long = "allow-header-pna", default_value_t = false)]
        allow_header_pna: bool,
    },
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::CheckConfig { data_dir } => match load_kmd_config(&data_dir) {
            Ok(cfg) => {
                tracing::info!(
                    data_dir = %data_dir.display(),
                    session_lifetime_secs = cfg.session_lifetime_secs,
                    scrypt_n = cfg.driver_config.sqlite.scrypt_params.scrypt_n,
                    scrypt_r = cfg.driver_config.sqlite.scrypt_params.scrypt_r,
                    scrypt_p = cfg.driver_config.sqlite.scrypt_params.scrypt_p,
                    "kmd-rust: config OK",
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!(
                    "kmd-rust: failed to load config from {}: {}",
                    data_dir.display(),
                    err,
                );
                ExitCode::from(1)
            }
        },
        Command::Serve {
            data_dir,
            address,
            timeout,
            allowed_origins,
            allow_header_pna,
        } => {
            if timeout.is_some() {
                tracing::warn!(
                    "kmd-rust: --timeout is accepted for CLI parity but not yet enforced \
                     (Go's watchdog timer is not ported)",
                );
            }
            // Build a single-threaded tokio runtime — kmd is I/O-bound
            // and dispatches CPU-heavy SQLite/scrypt work to
            // `spawn_blocking`, so a single reactor thread is enough.
            // A multi-threaded runtime would also work; the choice
            // doesn't affect correctness.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("kmd-rust: failed to build tokio runtime: {err}");
                    return ExitCode::from(1);
                }
            };
            match rt.block_on(serve(data_dir, address, allowed_origins, allow_header_pna)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("kmd-rust: serve failed: {err}");
                    ExitCode::from(1)
                }
            }
        }
    }
}

async fn serve(
    data_dir: PathBuf,
    address: Option<SocketAddr>,
    allowed_origins: Vec<String>,
    allow_header_pna: bool,
) -> Result<(), String> {
    let cfg = load_kmd_config(&data_dir).map_err(|e| format!("load config: {e}"))?;

    // Validate or generate the API token.  We do this on the runtime
    // thread (it's cheap; reading 64 hex chars from disk).
    let api_token = validate_or_generate_api_token(&data_dir)
        .map_err(|e| format!("validate or generate kmd.token: {e}"))?;

    // Spin up the wallet driver (creates the wallets/ subdir if
    // needed) and the session manager.
    let wallet_driver = WalletDriver::from_kmd_config(&data_dir, &cfg.driver_config.sqlite)
        .map_err(|e| format!("wallet driver init: {e}"))?;
    let session_manager = Arc::new(SessionManager::from_lifetime_secs(
        cfg.session_lifetime_secs,
    ));

    let server_cfg = WalletServerConfig {
        api_token,
        data_dir: data_dir.clone(),
        address,
        allowed_origins,
        allow_header_pna,
        session_manager: session_manager.clone(),
        wallet_driver: Arc::new(wallet_driver),
    };

    let server = WalletServer::bind(server_cfg)
        .await
        .map_err(|e| format!("server bind: {e}"))?;
    let bound = server.local_addr();
    tracing::info!(
        data_dir = %data_dir.display(),
        address = %bound,
        "kmd-rust serving",
    );

    // Spawn the periodic session-cleanup task.  Lives on the runtime
    // for the duration of the server; the JoinHandle is dropped on
    // serve()-exit, which aborts the loop.
    let cleanup_sm = session_manager.clone();
    let cleanup = tokio::spawn(async move {
        let mut tick = tokio::time::interval(algo_kmd::HANDLE_CLEANUP_INTERVAL);
        tick.tick().await; // immediate first tick
        loop {
            tick.tick().await;
            cleanup_sm.delete_expired_handles();
        }
    });

    // Wire SIGINT / SIGTERM to a oneshot the server can await.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("kmd-rust: shutdown signal received");
        // If the receiver is gone the server has already exited; ignore.
        let _ = shutdown_tx.send(());
    });

    // Block on the server task.  When it returns, the cleanup task
    // is cancelled by dropping its JoinHandle, the SessionManager
    // drops, kmd.net/kmd.pid are removed, and the file lock is
    // released.
    let result = server.serve(shutdown_rx).await;
    cleanup.abort();
    // Best-effort: a brief delay so the abort propagates before the
    // runtime tears down (not load-bearing for correctness).
    let _ = tokio::time::timeout(Duration::from_millis(50), cleanup).await;

    result.map_err(|e| format!("server error: {e}"))
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    // Windows: only Ctrl-C is portably available via tokio.
    let _ = tokio::signal::ctrl_c().await;
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
