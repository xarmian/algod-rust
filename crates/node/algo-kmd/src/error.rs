//! Error types for `algo-kmd`.
//!
//! `SQLiteWalletNotAbsolute` mirrors `ErrSQLiteWalletNotAbsolute` from
//! `../go-algorand/daemon/kmd/config/errors.go`.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Returned when the configured SQLite wallets directory is a relative path.
    /// Matches `ErrSQLiteWalletNotAbsolute` in go-algorand
    /// (`daemon/kmd/config/errors.go:24`).
    #[error("sqlite wallets path must be absolute path")]
    SQLiteWalletNotAbsolute,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
