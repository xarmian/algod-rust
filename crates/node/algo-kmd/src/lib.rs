//! algo-kmd — Rust port of go-algorand's `daemon/kmd` (Key Management Daemon).
//!
//! Reference: `../go-algorand/daemon/kmd/` pinned to v4.5.1-stable.
//!
//! Phase A scope:
//! - Config loading (this file's module: [`config`]) — port of
//!   `daemon/kmd/config/config.go`.
//! - SQLite wallet schema + driver (later tasks).
//! - Scrypt KDF + AEAD wallet encryption (later tasks).
//!
//! REST API surface, signing operations, and participation-key wallet ops are
//! deferred to Phases B+.

pub mod config;
pub mod error;
pub mod sqlite;

pub use config::{
    load_kmd_config, save_kmd_config, DriverConfig, KMDConfig, LedgerWalletDriverConfig,
    SQLiteWalletDriverConfig, ScryptParams, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_P, DEFAULT_SCRYPT_R,
    DEFAULT_SESSION_LIFETIME_SECS, KMD_CONFIG_EXAMPLE_FILENAME, KMD_CONFIG_FILENAME,
};
pub use error::{Error, Result};
pub use sqlite::{
    is_database_filename, name_id_to_path, sanitize_filename, ClaimedWallets, WalletDb,
    WalletMetadata, SQLITE_MAX_WALLET_ID_LEN, SQLITE_MAX_WALLET_NAME_LEN, SQLITE_WALLETS_DIR_NAME,
    SQLITE_WALLETS_DIR_PERMISSIONS, SQLITE_WALLET_DRIVER_NAME, SQLITE_WALLET_DRIVER_VERSION,
    WALLET_SCHEMA,
};
