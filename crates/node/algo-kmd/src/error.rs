//! Error types for `algo-kmd`.
//!
//! Variants mirror the named errors in go-algorand's
//! `daemon/kmd/wallet/driver/sqlite_errors.go` and
//! `daemon/kmd/config/errors.go`, plus the I/O and JSON wrappers we need
//! at this layer.

use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Returned when the configured SQLite wallets directory is a
    /// relative path. Matches `ErrSQLiteWalletNotAbsolute`
    /// (`daemon/kmd/config/errors.go:24`).
    #[error("sqlite wallets path must be absolute path")]
    SQLiteWalletNotAbsolute,

    /// A row violates a UNIQUE constraint. Matches `errKeyExists`
    /// (`daemon/kmd/wallet/driver/sqlite.go:354–357`).
    #[error("key already exists")]
    KeyExists,

    /// Generic database error — mirrors Go's coarse `errDatabase`.
    #[error("database error")]
    Database,

    /// Could not open the SQLite database. Mirrors `errDatabaseConnect`.
    #[error("failed to connect to wallet database")]
    DatabaseConnect,

    /// The DB's `driver_name` is not `sqlite`. Mirrors `errWrongDriver`.
    #[error("wallet database has wrong driver name")]
    WrongDriver,

    /// The DB's `driver_version` is not the one this build expects.
    /// Mirrors `errWrongDriverVer`.
    #[error("wallet database has wrong driver version")]
    WrongDriverVersion,

    /// Another wallet with the same name is already claimed. Mirrors
    /// `errSameName`.
    #[error("wallet with same name already exists")]
    SameName,

    /// Another wallet with the same id is already claimed. Mirrors
    /// `errSameID`.
    #[error("wallet with same id already exists")]
    SameId,

    /// A wallet database already exists at the target path. `create()`
    /// guards against clobbering an existing file; mirrors the
    /// `os.Stat` / `os.IsNotExist` check in `claimWalletNameID`
    /// (`sqlite.go:383–386`).
    #[error("wallet database already exists at {0}")]
    WalletExists(PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
