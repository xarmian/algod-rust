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

pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod multisig;
pub mod server;
pub mod session;
pub mod sign;
pub mod sqlite;
pub mod wallet;

pub use auth::{validate_api_token, validate_or_generate_api_token, KMD_TOKEN_FILENAME};
pub use server::{
    read_net_file, WalletServer, WalletServerConfig, DEFAULT_KMD_HOST, DEFAULT_KMD_PORT,
    KMD_TOKEN_HEADER, LOCK_FILENAME, NET_FILENAME, PID_FILENAME,
};
pub use session::{AuthorizedHandle, SessionManager, HANDLE_CLEANUP_INTERVAL};

pub use keys::{extract_seed_with_index, ADDRESS_LEN, SECRET_KEY_LEN};
pub use multisig::MultisigPreimage;
pub use wallet::{Wallet, WalletDriver, WalletDriverConfig};

pub use crypto::{
    decrypt_blob_with_password, encrypt_blob_with_key, encrypt_blob_with_nonce_and_salt,
    encrypt_blob_with_password, Kdf, PlaintextType, MASTER_KEY_LEN, MIN_SCRYPT_N, MIN_SCRYPT_P,
    MIN_SCRYPT_R, NONCE_LEN, SALT_LEN,
};

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
