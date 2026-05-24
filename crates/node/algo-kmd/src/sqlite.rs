//! SQLite wallet driver primitives — schema, DB open/create/close,
//! filename helpers, and the in-memory claimed-wallets registry.
//!
//! Ported from `../go-algorand/daemon/kmd/wallet/driver/sqlite.go`
//! (v4.5.1-stable). TASK-202 scope is structural only: encrypted columns
//! are written and read as opaque BLOBs. Wallet-level operations
//! (`CreateWallet`, key derivation, etc.) layer on top in TASK-204+.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use rusqlite::Connection;

use crate::error::{Error, Result};

/// Schema applied to a newly-created wallet DB. Byte-identical to Go's
/// `walletSchema` (sqlite.go:58–81). The bytes live in
/// `src/wallet_schema.sql`; an integration test asserts they equal a
/// separately-tracked fixture extracted from go-algorand
/// (`tests/fixtures/wallet_schema.sql`) so any divergence trips CI.
pub const WALLET_SCHEMA: &str = include_str!("wallet_schema.sql");

/// `sqliteWalletDriverName` (sqlite.go:42).
pub const SQLITE_WALLET_DRIVER_NAME: &str = "sqlite";

/// `sqliteWalletDriverVersion` (sqlite.go:43). Stored in the `metadata`
/// row; refuses to open databases with a different version.
pub const SQLITE_WALLET_DRIVER_VERSION: u32 = 1;

/// `sqliteWalletsDirName` (sqlite.go:44). Subdirectory of the kmd data
/// dir that holds wallet `.db` files when no explicit `wallets_dir` is
/// configured.
pub const SQLITE_WALLETS_DIR_NAME: &str = "sqlite_wallets";

/// `sqliteWalletsDirPermissions` (sqlite.go:45). Octal `0700`. Only
/// applied on Unix targets; on Windows directory permissions are
/// inherited.
pub const SQLITE_WALLETS_DIR_PERMISSIONS: u32 = 0o700;

/// `sqliteMaxWalletNameLen` (sqlite.go:47).
pub const SQLITE_MAX_WALLET_NAME_LEN: usize = 64;

/// `sqliteMaxWalletIDLen` (sqlite.go:48).
pub const SQLITE_MAX_WALLET_ID_LEN: usize = 64;

/// Disallowed-character filter applied to wallet names and IDs when
/// computing on-disk filenames. Mirrors `disallowedFilenameRegex`
/// (sqlite.go:55): `[^a-zA-Z0-9_-]*`, used with `ReplaceAll` to *remove*
/// disallowed runs.
fn disallowed_filename_regex() -> &'static BytesRegex {
    use std::sync::OnceLock;
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    // (?-u:) disables Unicode mode so the negated class matches arbitrary
    // bytes (including invalid UTF-8) — matching Go's regexp behavior on
    // []byte input, where `[^a-zA-Z0-9_-]` matches any non-allowed byte.
    RE.get_or_init(|| BytesRegex::new("(?-u:[^a-zA-Z0-9_-])*").expect("static regex compiles"))
}

/// Matches filenames that look like SQLite wallet databases (anything
/// ending in `.db`). Mirrors `databaseFilenameRegex` (sqlite.go:56):
/// `^.*\.db$`.
fn database_filename_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^.*\.db$").expect("static regex compiles"))
}

/// Remove every character outside `[a-zA-Z0-9_-]`. Mirrors Go's
/// `disallowedFilenameRegex.ReplaceAll(input, []byte(""))`
/// (sqlite.go:332,334).
pub fn sanitize_filename(input: &[u8]) -> Vec<u8> {
    disallowed_filename_regex()
        .replace_all(input, &b""[..])
        .into_owned()
}

/// True iff `filename` matches `^.*\.db$`. Used to filter directory
/// listings down to plausible wallet databases. Mirrors Go's use of
/// `databaseFilenameRegex.Match` (sqlite.go:239).
pub fn is_database_filename(filename: &str) -> bool {
    database_filename_regex().is_match(filename)
}

/// Build the on-disk path for a `(name, id)` wallet pair under
/// `wallets_dir`. Mirrors `nameIDToPath` (sqlite.go:330): sanitize both,
/// concatenate as `name.id.db`, or just `id.db` if sanitized name and id
/// are identical.
pub fn name_id_to_path(wallets_dir: &Path, name: &[u8], id: &[u8]) -> PathBuf {
    let safe_name = sanitize_filename(name);
    let safe_id = sanitize_filename(id);
    let filename = if safe_name == safe_id {
        format!("{}.db", String::from_utf8_lossy(&safe_id))
    } else {
        format!(
            "{}.{}.db",
            String::from_utf8_lossy(&safe_name),
            String::from_utf8_lossy(&safe_id)
        )
    };
    wallets_dir.join(filename)
}

/// Wallet metadata recovered from the `metadata` row. Mirrors the subset
/// of `wallet.Metadata` populated by `walletMetadataFromDB`
/// (sqlite.go:177–212) that does not require crypto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletMetadata {
    pub id: Vec<u8>,
    pub name: Vec<u8>,
    pub driver_name: String,
    pub driver_version: u32,
}

/// In-memory registry of `(name, id)` pairs that are mid-creation, used
/// to reject duplicate concurrent `CreateWallet` calls before the row
/// hits SQLite. Mirrors `SQLiteWalletDriver.claimedWallets` + its mutex
/// (sqlite.go:90, 364–410).
///
/// Note: Go never removes entries from `claimedWallets` (see TODO at
/// sqlite.go:427); we mirror that behavior so the semantics are
/// identical. The registry is purely a short-lived dedup; for long-term
/// uniqueness the on-disk metadata + UNIQUE constraint are authoritative.
#[derive(Default)]
pub struct ClaimedWallets {
    inner: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl ClaimedWallets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve `(name, id)` against the in-memory list only. Returns
    /// `ErrSameName` or `ErrSameId` if a matching entry is already
    /// claimed. Most callers should use [`Self::claim_with`] so the
    /// on-disk dup-check happens inside the same critical section
    /// (matching Go's `claimWalletNameID`).
    pub fn claim(&self, name: &[u8], id: &[u8]) -> Result<()> {
        self.claim_with(name, id, |_, _| Ok(()))
    }

    /// Reserve `(name, id)` atomically with an extra validation step.
    /// Mirrors `claimWalletNameID` (sqlite.go:364–410): under a single
    /// lock acquisition, check the in-memory list, run the caller's
    /// disk-side dup check, and only then append to the registry. If
    /// `extra_check` fails the registry is unchanged, so a later retry
    /// after the on-disk conflict is cleared can succeed — matching
    /// Go's behavior where `claimedWallets` is only appended *after*
    /// `os.Stat` + `findDBPathsBy{Name,ID}` all return clean
    /// (sqlite.go:382–409).
    pub fn claim_with<F>(&self, name: &[u8], id: &[u8], extra_check: F) -> Result<()>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<()>,
    {
        let mut guard = self.inner.lock().expect("ClaimedWallets mutex poisoned");
        for (n, i) in guard.iter() {
            if n.as_slice() == name {
                return Err(Error::SameName);
            }
            if i.as_slice() == id {
                return Err(Error::SameId);
            }
        }
        extra_check(name, id)?;
        guard.push((name.to_vec(), id.to_vec()));
        Ok(())
    }

    /// Test-only accessor for the current claim list. Useful for
    /// asserting that successful claims do persist (per Go's
    /// no-removal behavior).
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner
            .lock()
            .expect("ClaimedWallets mutex poisoned")
            .clone()
    }
}

/// A handle to a single wallet's SQLite database file.
///
/// Wraps a rusqlite [`Connection`] with the connection-flags Go applies
/// via its `_secure_delete=on` / `_txlock=exclusive` URL options
/// (sqlite.go:46). `secure_delete` is a PRAGMA we set on open;
/// `_txlock=exclusive` is per-transaction behavior and is applied when
/// the wallet-level operations land in TASK-204 (the schema-only Phase
/// of TASK-202 does not start any transactions).
pub struct WalletDb {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for WalletDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl WalletDb {
    /// Create a new wallet database at `path`, run the schema, and
    /// return an open handle. Fails if the file already exists, matching
    /// Go's expectation that the caller has already reserved the path
    /// via `claimWalletNameID` (sqlite.go:383–386).
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::WalletExists(path.to_path_buf()));
        }
        let conn = Connection::open(path).map_err(|_| Error::DatabaseConnect)?;
        Self::apply_connection_pragmas(&conn)?;
        conn.execute_batch(WALLET_SCHEMA)
            .map_err(|_| Error::Database)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Open an existing wallet database at `path`. Does not run the
    /// schema (`CREATE TABLE IF NOT EXISTS` makes that safe in
    /// principle, but the caller is asserting the DB is already a
    /// wallet). Mirrors `walletMetadataFromDBPath`'s `sqlx.Connect`
    /// (sqlite.go:218).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::DatabaseConnect);
        }
        let conn = Connection::open(path).map_err(|_| Error::DatabaseConnect)?;
        Self::apply_connection_pragmas(&conn)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    fn apply_connection_pragmas(conn: &Connection) -> Result<()> {
        // Mirrors Go's `_secure_delete=on` URL option (sqlite.go:46).
        // Other go-sqlite3 URL options (`_txlock=exclusive`) are
        // per-transaction and applied where transactions are opened.
        conn.pragma_update(None, "secure_delete", "ON")
            .map_err(|_| Error::Database)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run `f` inside an exclusive SQLite transaction. Mirrors the
    /// `db.Beginx() ... tx.Commit() / tx.Rollback()` pattern in
    /// `GenerateKey` (sqlite.go:857–878). Any error from `f` is
    /// propagated and the transaction is rolled back (rusqlite's
    /// `Transaction` rolls back on drop unless committed).
    ///
    /// The closure receives `&self` so it can call the existing
    /// `insert_key` / `update_max_key_idx_encrypted` / etc. methods —
    /// those issue SQL through `self.conn`, which while a transaction
    /// is open executes inside it.
    pub fn with_transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Self) -> Result<R>,
    {
        // unchecked_transaction lets us hand out a Transaction without
        // needing &mut self; the borrow checker is satisfied because
        // the Transaction holds a borrow of self.conn and we don't
        // touch self.conn directly while it's alive.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| Error::Database)?;
        let result = f(self)?;
        tx.commit().map_err(|_| Error::Database)?;
        Ok(result)
    }

    /// Insert the single metadata row. Encrypted blobs are opaque to
    /// this layer — the caller provides whatever bytes the crypto path
    /// produces. Mirrors the `INSERT INTO metadata` in `CreateWallet`
    /// (sqlite.go:483).
    pub fn insert_metadata(
        &self,
        id: &[u8],
        name: &[u8],
        mep_encrypted: &[u8],
        mdk_encrypted: &[u8],
        max_key_idx_encrypted: &[u8],
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO metadata (driver_name, driver_version, wallet_id, wallet_name, \
                 mep_encrypted, mdk_encrypted, max_key_idx_encrypted) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    SQLITE_WALLET_DRIVER_NAME,
                    SQLITE_WALLET_DRIVER_VERSION,
                    id,
                    name,
                    mep_encrypted,
                    mdk_encrypted,
                    max_key_idx_encrypted,
                ],
            )
            .map(|_| ())
            .map_err(map_constraint_error)
    }

    /// Read the metadata row. Mirrors `walletMetadataFromDB`
    /// (sqlite.go:177–212), minus the unused crypto/transaction-support
    /// flags which we'll add as wallet-level surface lands.
    pub fn read_metadata(&self) -> Result<WalletMetadata> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT driver_name, driver_version, wallet_id, wallet_name \
                 FROM metadata LIMIT 1",
            )
            .map_err(|_| Error::Database)?;

        let meta = stmt
            .query_row([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| Error::Database)?;

        let (driver_name, driver_version, id, name) = meta;

        if driver_name != SQLITE_WALLET_DRIVER_NAME {
            return Err(Error::WrongDriver);
        }
        if driver_version != SQLITE_WALLET_DRIVER_VERSION {
            return Err(Error::WrongDriverVersion);
        }
        Ok(WalletMetadata {
            id,
            name,
            driver_name,
            driver_version,
        })
    }

    /// Return the underlying SQLite version string. Useful for tests
    /// and version probes; not part of Go's surface.
    pub fn sqlite_version(&self) -> String {
        rusqlite::version().to_string()
    }

    /// Fetch the `mep_encrypted` blob from the metadata row. Mirrors
    /// `decryptAndGetMasterKey`'s SELECT (sqlite.go:613).
    pub fn read_mep_encrypted(&self) -> Result<Vec<u8>> {
        self.read_blob_column("mep_encrypted")
    }

    /// Fetch the `mdk_encrypted` blob from the metadata row. Mirrors
    /// `decryptAndGetMasterDerivationKey`'s SELECT (sqlite.go:637).
    pub fn read_mdk_encrypted(&self) -> Result<Vec<u8>> {
        self.read_blob_column("mdk_encrypted")
    }

    /// Fetch the `max_key_idx_encrypted` blob from the metadata row.
    /// Used by key-derivation operations (TASK-205).
    pub fn read_max_key_idx_encrypted(&self) -> Result<Vec<u8>> {
        self.read_blob_column("max_key_idx_encrypted")
    }

    fn read_blob_column(&self, column: &'static str) -> Result<Vec<u8>> {
        // `column` is a compile-time constant chosen from a known set
        // above, so concatenation here is safe from injection.
        let sql = format!("SELECT {column} FROM metadata LIMIT 1");
        let mut stmt = self.conn.prepare(&sql).map_err(|_| Error::Database)?;
        let bytes: Vec<u8> = stmt
            .query_row([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Database)?;
        Ok(bytes)
    }

    /// Replace the `max_key_idx_encrypted` blob. Mirrors
    /// `generateKeyTxLocked`'s `UPDATE metadata SET
    /// max_key_idx_encrypted = ?` (sqlite.go:968).
    pub fn update_max_key_idx_encrypted(&self, blob: &[u8]) -> Result<()> {
        let rows = self
            .conn
            .execute(
                "UPDATE metadata SET max_key_idx_encrypted = ?1",
                rusqlite::params![blob],
            )
            .map_err(|_| Error::Database)?;
        if rows == 0 {
            return Err(Error::WalletNotFound);
        }
        Ok(())
    }

    /// Insert a row into `keys`. `key_idx` is `Some(n)` for keys derived
    /// from the MDK via `extractKeyWithIndex`, `None` for imported keys
    /// (the column allows NULL per the schema). Mirrors both inserts in
    /// the Go reference: `GenerateKey` (sqlite.go:956) and `ImportKey`
    /// (sqlite.go:764).
    pub fn insert_key(
        &self,
        addr: &[u8],
        secret_key_encrypted: &[u8],
        key_idx: Option<u64>,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO keys (address, secret_key_encrypted, key_idx) VALUES (?1, ?2, ?3)",
                rusqlite::params![addr, secret_key_encrypted, key_idx],
            )
            .map_err(map_constraint_error)?;
        Ok(())
    }

    /// True iff a row in `keys` has the supplied address. Mirrors the
    /// `SELECT COUNT(1) FROM keys WHERE address=?` probe used both
    /// during derived-key generation (`generateKeyTxLocked`, sqlite.go:934)
    /// and as the underlying lookup primitive.
    pub fn key_exists(&self, addr: &[u8]) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM keys WHERE address = ?1 LIMIT 1")
            .map_err(|_| Error::Database)?;
        let exists = stmt
            .query_row(rusqlite::params![addr], |_| Ok(()))
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                _ => Err(Error::Database),
            })?;
        Ok(exists)
    }

    /// Read `secret_key_encrypted` for the supplied address, or return
    /// `Error::KeyNotFound`. Mirrors `fetchSecretKey`'s SELECT
    /// (sqlite.go:799).
    pub fn read_secret_key_encrypted(&self, addr: &[u8]) -> Result<Vec<u8>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key_encrypted FROM keys WHERE address = ?1")
            .map_err(|_| Error::Database)?;
        stmt.query_row(rusqlite::params![addr], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::KeyNotFound,
                _ => Error::Database,
            })
    }

    /// All addresses in `keys`. Mirrors `ListKeys` (sqlite.go:707).
    pub fn list_key_addresses(&self) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT address FROM keys")
            .map_err(|_| Error::Database)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Database)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| Error::Database)?);
        }
        Ok(out)
    }

    /// Delete a key row. Mirrors `DeleteKey` (sqlite.go:993). Returns
    /// `Ok(())` even when the address doesn't exist, matching Go's
    /// behavior (the underlying DELETE is silent on no-match).
    pub fn delete_key(&self, addr: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM keys WHERE address = ?1",
                rusqlite::params![addr],
            )
            .map_err(|_| Error::Database)?;
        Ok(())
    }

    /// `UPDATE metadata SET wallet_name=? WHERE wallet_id=?`. Mirrors
    /// `RenameWallet`'s UPDATE (sqlite.go:581).
    pub fn update_wallet_name(&self, id: &[u8], new_name: &[u8]) -> Result<()> {
        let rows = self
            .conn
            .execute(
                "UPDATE metadata SET wallet_name = ?1 WHERE wallet_id = ?2",
                rusqlite::params![new_name, id],
            )
            .map_err(|_| Error::Database)?;
        if rows == 0 {
            return Err(Error::WalletNotFound);
        }
        Ok(())
    }
}

/// Map a rusqlite error to the closest Go counterpart. UNIQUE-constraint
/// violations become [`Error::KeyExists`] (Go's `errKeyExists`,
/// sqlite.go:354–357); everything else collapses to [`Error::Database`]
/// to match Go's coarse error surface.
fn map_constraint_error(err: rusqlite::Error) -> Error {
    if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err {
        if ffi_err.code == rusqlite::ErrorCode::ConstraintViolation {
            return Error::KeyExists;
        }
    }
    Error::Database
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_strips_disallowed() {
        // (input, expected) — mirrors Go's
        // disallowedFilenameRegex.ReplaceAll behavior.
        let cases: &[(&[u8], &[u8])] = &[
            (b"abc", b"abc"),
            (b"a b c", b"abc"),
            (b"hello!@#world", b"helloworld"),
            (b"under_score-dash", b"under_score-dash"),
            (b"path/with/slashes", b"pathwithslashes"),
            (b"unicode\xc3\xa9", b"unicode"),
            (b"", b""),
            (b"!!!", b""),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_filename(input),
                expected.to_vec(),
                "sanitize_filename({:?})",
                input
            );
        }
    }

    #[test]
    fn database_filename_match() {
        for ok in &["wallet.db", "x.db", "a.b.db", ".db"] {
            assert!(is_database_filename(ok), "{ok} should match");
        }
        for bad in &["wallet", "wallet.dbx", "wallet.db.bak", "db", ""] {
            assert!(!is_database_filename(bad), "{bad} should not match");
        }
    }

    #[test]
    fn name_id_to_path_joins_safe_components() {
        let dir = Path::new("/w");

        // Distinct name + id
        assert_eq!(
            name_id_to_path(dir, b"my wallet", b"abc123"),
            Path::new("/w/mywallet.abc123.db")
        );

        // "abc!123" → "abc123", "abc-123" → "abc-123" (dash is allowed).
        // Sanitized values differ, so the path keeps both components.
        assert_eq!(
            name_id_to_path(dir, b"abc!123", b"abc-123"),
            Path::new("/w/abc123.abc-123.db")
        );
        assert_eq!(name_id_to_path(dir, b"abc", b"abc"), Path::new("/w/abc.db"));
    }

    #[test]
    fn claimed_wallets_rejects_duplicates() {
        let cw = ClaimedWallets::new();
        cw.claim(b"alpha", b"id-1").unwrap();
        assert!(matches!(cw.claim(b"alpha", b"id-2"), Err(Error::SameName)));
        assert!(matches!(cw.claim(b"beta", b"id-1"), Err(Error::SameId)));
        cw.claim(b"beta", b"id-2").unwrap();
        // Go never removes entries; verify ours mirrors that.
        assert_eq!(cw.snapshot().len(), 2);
    }
}
