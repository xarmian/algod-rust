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

    /// Scrypt key derivation failed or was supplied invalid parameters.
    /// Mirrors `errDeriveKey` (`sqlite_crypto.go`).
    #[error("failed to derive encryption key")]
    DeriveKey,

    /// OS RNG returned an error. Mirrors `errRandBytes`.
    #[error("failed to read random bytes")]
    RandBytes,

    /// secretbox open failed (wrong key, corrupted blob, tampered
    /// nonce). Mirrors `errDecrypt`.
    #[error("failed to decrypt blob")]
    Decrypt,

    /// `plaintext_type` on a decrypted envelope did not match what the
    /// caller expected. Mirrors `errTypeMismatch`.
    #[error("decrypted plaintext type does not match expected type")]
    TypeMismatch,

    /// Generic crypto / msgpack envelope error (malformed blob, AEAD
    /// init failure). Coarser than Go's surface; the kmd reference uses
    /// `errDecrypt` for AEAD failures and never surfaces parse errors
    /// directly to the caller.
    #[error("wallet crypto envelope error")]
    Crypto,

    /// Configured scrypt parameter is below the production minimum and
    /// `allow_unsafe_scrypt` is not set. Mirrors the `errors.New(...)`
    /// calls in `InitWithConfig` (sqlite.go:142–151). The carried
    /// `&'static str` names which parameter (`"N"`, `"R"`, `"P"`).
    #[error("scrypt parameter {0} is below the production minimum")]
    ScryptTooWeak(&'static str),

    /// Wallet name longer than `sqliteMaxWalletNameLen`. Mirrors
    /// `errNameTooLong` (sqlite.go:415).
    #[error(
        "wallet name exceeds {} bytes",
        crate::sqlite::SQLITE_MAX_WALLET_NAME_LEN
    )]
    NameTooLong,

    /// Wallet id longer than `sqliteMaxWalletIDLen`. Mirrors
    /// `errIDTooLong` (sqlite.go:419).
    #[error("wallet id exceeds {} bytes", crate::sqlite::SQLITE_MAX_WALLET_ID_LEN)]
    IdTooLong,

    /// No wallet with the requested id exists. Mirrors
    /// `errWalletNotFound` (sqlite.go:512).
    #[error("wallet not found")]
    WalletNotFound,

    /// Multiple wallets share the requested id (i.e. someone dropped a
    /// duplicate `.db` file into the wallets directory). Mirrors
    /// `errIDConflict` (sqlite.go:518).
    #[error("multiple wallets with the same id")]
    IdConflict,

    /// Address not found in the `keys` table. Mirrors `errKeyNotFound`
    /// (`sqlite_errors.go`).
    #[error("key not found")]
    KeyNotFound,

    /// Re-deriving a public key from the decrypted secret key didn't
    /// match the address we used to look it up — indicates on-disk
    /// tampering. Mirrors `errTampering` (sqlite.go:829).
    #[error("on-disk tampering detected")]
    Tampering,

    /// Reached the hard cap on derived-key indices (`sqliteIntOverflow`
    /// = `1 << 63`). Mirrors `errTooManyKeys` (sqlite.go:919).
    #[error("wallet exceeded the derived-key index limit")]
    TooManyKeys,

    /// `(version, threshold, pks)` rejected by multisig address
    /// derivation — version != 1, threshold == 0 or > len(pks),
    /// pks empty, or > 255 keys. Mirrors errors from `MultisigAddrGen`
    /// (`crypto/multisig.go:96–112`).
    #[error("invalid multisig preimage")]
    MultisigInvalid,

    /// Multisig address not found in `msig_addrs`. Mirrors
    /// `errMsigDataNotFound` (`sqlite_errors.go`).
    #[error("multisig address not found")]
    MultisigNotFound,

    /// Wallet-handle token is malformed, the handle ID is unknown,
    /// or the secret doesn't match. Mirrors the "wrong number of
    /// token parts" / "invalid wallet handle id" / "handle does not
    /// exist" / "invalid token" errors in
    /// `daemon/kmd/session/auth.go`.
    #[error("invalid wallet handle token")]
    WalletHandleInvalid,

    /// Wallet handle has expired (no use within the session lifetime).
    /// Mirrors `fmt.Errorf("handle expired")` at
    /// `daemon/kmd/session/auth.go:75`.
    #[error("wallet handle expired")]
    WalletHandleExpired,

    /// API token shorter than `minimumAPITokenLength` (64). Mirrors
    /// the length-too-short error in `util/tokens/tokens.go:93`.
    #[error("API token is too short")]
    ApiTokenTooShort,

    /// API token longer than `maximumAPITokenLength` (256). Mirrors
    /// `util/tokens/tokens.go:97`.
    #[error("API token is too long")]
    ApiTokenTooLong,

    /// Operation requires [`crate::wallet::Wallet::init`] to have
    /// succeeded first. Go enforces this implicitly because every key
    /// op runs `Init`-like checks; we make it explicit.
    #[error("wallet has not been unlocked (call Wallet::init first)")]
    WalletNotInitialized,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
