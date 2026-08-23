//! Wallet-level operations — `CreateWallet`, `ListWalletMetadatas`,
//! `FetchWallet`, `RenameWallet`, plus the unlock / export-MDK flow.
//!
//! Wires together the schema/lifecycle primitives from [`crate::sqlite`]
//! and the crypto envelopes from [`crate::crypto`] into the surface
//! described in `daemon/kmd/wallet/wallet.go` (v4.6.0-stable).
//!
//! TASK-204 scope: enough surface to create + open + rename wallets
//! and export the master-derivation key. Per-key generation/import,
//! multisig, and the REST handler that wraps these calls land in
//! TASK-205+ and Phase B.

use std::path::{Path, PathBuf};

use rand::RngCore;
use sha2::{Digest as _, Sha512_256};
use subtle::ConstantTimeEq;

use crate::config::{SQLiteWalletDriverConfig, ScryptParams};
use crate::crypto::{
    decrypt_blob_with_password, encrypt_blob_with_key, encrypt_blob_with_password, Kdf,
    PlaintextType, MASTER_KEY_LEN, MIN_SCRYPT_N, MIN_SCRYPT_P, MIN_SCRYPT_R,
};
use crate::error::{Error, Result};
use crate::sqlite::{
    is_database_filename, name_id_to_path, ClaimedWallets, WalletDb, WalletMetadata,
    SQLITE_MAX_WALLET_ID_LEN, SQLITE_MAX_WALLET_NAME_LEN, SQLITE_WALLETS_DIR_NAME,
    SQLITE_WALLETS_DIR_PERMISSIONS,
};

/// Resolved configuration for a [`WalletDriver`] instance.
///
/// `wallets_dir` is the directory holding `.db` files. When the global
/// kmd config's `wallets_dir` is empty, the driver substitutes
/// `<data_dir>/sqlite_wallets` — see [`WalletDriver::from_kmd_config`]
/// which mirrors `walletsDir()` (sqlite.go:321).
#[derive(Clone, Debug)]
pub struct WalletDriverConfig {
    pub wallets_dir: PathBuf,
    pub scrypt_params: ScryptParams,
    pub allow_unsafe_scrypt: bool,
}

/// Driver-level handle: owns the wallets directory, the scrypt config,
/// and the in-memory `ClaimedWallets` registry. Mirrors
/// `SQLiteWalletDriver` (sqlite.go:85–91); the per-call mutex lives
/// inside [`ClaimedWallets`].
pub struct WalletDriver {
    cfg: WalletDriverConfig,
    claimed: ClaimedWallets,
}

impl std::fmt::Debug for WalletDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDriver")
            .field("wallets_dir", &self.cfg.wallets_dir)
            .field("allow_unsafe_scrypt", &self.cfg.allow_unsafe_scrypt)
            .finish_non_exhaustive()
    }
}

impl WalletDriver {
    /// Construct a driver and ensure the wallets directory exists.
    /// Mirrors `InitWithConfig` (sqlite.go:137) — same scrypt-params
    /// validation, then `maybeMakeWalletsDir` (sqlite.go:310). We
    /// deliberately widen Go's non-recursive `os.Mkdir` to a recursive
    /// `create_dir_all` so a fresh kmd-rust install on a path whose
    /// parents don't yet exist succeeds rather than erroring out; the
    /// leaf permissions (`0700` on Unix) still match Go.
    pub fn new(cfg: WalletDriverConfig) -> Result<Self> {
        if !cfg.allow_unsafe_scrypt {
            if (cfg.scrypt_params.scrypt_n as u32) < MIN_SCRYPT_N {
                return Err(Error::ScryptTooWeak("N"));
            }
            if (cfg.scrypt_params.scrypt_r as u32) < MIN_SCRYPT_R {
                return Err(Error::ScryptTooWeak("R"));
            }
            if (cfg.scrypt_params.scrypt_p as u32) < MIN_SCRYPT_P {
                return Err(Error::ScryptTooWeak("P"));
            }
        }
        maybe_make_wallets_dir(&cfg.wallets_dir)?;
        Ok(Self {
            cfg,
            claimed: ClaimedWallets::new(),
        })
    }

    /// Convenience constructor that pulls wallets_dir + scrypt params
    /// out of a [`SQLiteWalletDriverConfig`] + the kmd data dir, applying
    /// the same `walletsDir()` fallback Go uses (sqlite.go:321).
    pub fn from_kmd_config(data_dir: &Path, sqlite_cfg: &SQLiteWalletDriverConfig) -> Result<Self> {
        let wallets_dir = if sqlite_cfg.wallets_dir.is_empty() {
            data_dir.join(SQLITE_WALLETS_DIR_NAME)
        } else {
            PathBuf::from(&sqlite_cfg.wallets_dir)
        };
        Self::new(WalletDriverConfig {
            wallets_dir,
            scrypt_params: sqlite_cfg.scrypt_params.clone(),
            allow_unsafe_scrypt: sqlite_cfg.unsafe_scrypt,
        })
    }

    pub fn wallets_dir(&self) -> &Path {
        &self.cfg.wallets_dir
    }

    /// Mirrors `CreateWallet` (sqlite.go:414). When `mdk` is `None`, a
    /// fresh 32-byte MDK is generated via OS RNG (matching Go's
    /// "zero-valued mdk → generate" branch at sqlite.go:451).
    pub fn create_wallet(
        &self,
        name: &[u8],
        id: &[u8],
        password: &[u8],
        mdk: Option<[u8; MASTER_KEY_LEN]>,
    ) -> Result<()> {
        if name.len() > SQLITE_MAX_WALLET_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        if id.len() > SQLITE_MAX_WALLET_ID_LEN {
            return Err(Error::IdTooLong);
        }

        // Reserve the (name, id) pair atomically with the on-disk
        // dup-check, matching Go's claimWalletNameID (sqlite.go:364).
        // The registry is only appended to after every check passes,
        // so a failed creation leaves no stale claim that would block
        // a legitimate retry.
        let db_path = name_id_to_path(&self.cfg.wallets_dir, name, id);
        self.claimed.claim_with(name, id, |n, i| {
            if db_path.exists() {
                return Err(Error::WalletExists(db_path.clone()));
            }
            if !self.find_db_paths_by_name(n)?.is_empty() {
                return Err(Error::SameName);
            }
            if !self.find_db_paths_by_id(i)?.is_empty() {
                return Err(Error::SameId);
            }
            Ok(())
        })?;

        let db = WalletDb::create(&db_path)?;

        // Generate the master encryption password (MEP) — 32 random bytes.
        let mut master_key = [0u8; MASTER_KEY_LEN];
        fill_random(&mut master_key)?;

        // Use the caller-supplied MDK if non-zero, otherwise generate one.
        let mut mdk_bytes = mdk.unwrap_or([0u8; MASTER_KEY_LEN]);
        if mdk_bytes == [0u8; MASTER_KEY_LEN] {
            fill_random(&mut mdk_bytes)?;
        }

        // Encrypt MEP under the user's password (scrypt path). The
        // ciphertext doubles as a password check: if a future password
        // can't decrypt this blob, the password is wrong.
        let mep_encrypted = encrypt_blob_with_password(
            &master_key,
            PlaintextType::MasterKey,
            password,
            Kdf::Scrypt(&self.cfg.scrypt_params),
        )?;

        // Encrypt MDK under the MEP (raw-key path — MEP is already a
        // cryptographic key, no need to re-scrypt).
        let mdk_encrypted =
            encrypt_blob_with_key(&mdk_bytes, PlaintextType::MasterDerivationKey, &master_key)?;

        // Encrypt max_key_idx = 0 under MEP (integrity-only — prevents
        // tampering with the on-disk index counter).
        let max_idx_encoded = encode_max_key_idx(0)?;
        let max_idx_encrypted =
            encrypt_blob_with_key(&max_idx_encoded, PlaintextType::MaxKeyIdx, &master_key)?;

        db.insert_metadata(id, name, &mep_encrypted, &mdk_encrypted, &max_idx_encrypted)?;
        Ok(())
    }

    /// Mirrors `RenameWallet` (sqlite.go:543). Verifies the password,
    /// checks the new name isn't taken, then `UPDATE metadata`. The
    /// `.db` filename is **not** renamed — matching Go's comment
    /// "doing so safely is tricky".
    pub fn rename_wallet(&self, id: &[u8], new_name: &[u8], password: &[u8]) -> Result<()> {
        if new_name.len() > SQLITE_MAX_WALLET_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        if !self.find_db_paths_by_name(new_name)?.is_empty() {
            return Err(Error::SameName);
        }
        let mut wallet = self.fetch_wallet(id)?;
        wallet.check_password(password)?;
        wallet.rename_in_db(id, new_name)?;
        Ok(())
    }

    /// Mirrors `ListWalletMetadatas` (sqlite.go:250). Scans the wallets
    /// directory, attempts to read metadata from each `.db` file, and
    /// silently skips files that don't look like wallets (matches Go's
    /// "ignore errors" behavior).
    pub fn list_wallet_metadatas(&self) -> Result<Vec<WalletMetadata>> {
        let mut metas = Vec::new();
        for path in self.potential_wallet_paths()? {
            if let Ok(db) = WalletDb::open(&path) {
                if let Ok(meta) = db.read_metadata() {
                    metas.push(meta);
                }
            }
        }
        Ok(metas)
    }

    /// Mirrors `FetchWallet` (sqlite.go:493). Returns the unique wallet
    /// whose metadata id equals `id`; rejects if zero or multiple
    /// matches are found.
    pub fn fetch_wallet(&self, id: &[u8]) -> Result<Wallet> {
        let paths = self.find_db_paths_by_id(id)?;
        match paths.len() {
            0 => Err(Error::WalletNotFound),
            1 => Ok(Wallet::locked(paths.into_iter().next().unwrap())),
            _ => Err(Error::IdConflict),
        }
    }

    /// All `.db` files in `wallets_dir`. Mirrors
    /// `potentialWalletPaths` (sqlite.go:230).
    fn potential_wallet_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let entries = match std::fs::read_dir(&self.cfg.wallets_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let entry = entry.map_err(Error::Io)?;
            let file_type = entry.file_type().map_err(Error::Io)?;
            if file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !is_database_filename(&name_str) {
                continue;
            }
            paths.push(entry.path());
        }
        Ok(paths)
    }

    fn find_db_paths_by_field<F>(&self, predicate: F) -> Result<Vec<PathBuf>>
    where
        F: Fn(&WalletMetadata) -> bool,
    {
        let mut out = Vec::new();
        for path in self.potential_wallet_paths()? {
            if let Ok(db) = WalletDb::open(&path) {
                if let Ok(meta) = db.read_metadata() {
                    if predicate(&meta) {
                        out.push(path);
                    }
                }
            }
        }
        Ok(out)
    }

    fn find_db_paths_by_id(&self, id: &[u8]) -> Result<Vec<PathBuf>> {
        self.find_db_paths_by_field(|m| m.id == id)
    }

    fn find_db_paths_by_name(&self, name: &[u8]) -> Result<Vec<PathBuf>> {
        self.find_db_paths_by_field(|m| m.name == name)
    }
}

/// A wallet handle obtained from [`WalletDriver::fetch_wallet`].
///
/// Starts in `Locked` state — [`Wallet::init`] (or
/// [`Wallet::check_password`] with a password attempt) decrypts the MEP
/// and MDK into memory, mirroring `Init` (sqlite.go:652).
#[derive(Clone)]
pub struct Wallet {
    db_path: PathBuf,
    state: WalletState,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locked = matches!(self.state, WalletState::Locked);
        f.debug_struct("Wallet")
            .field("db_path", &self.db_path)
            .field("locked", &locked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum WalletState {
    Locked,
    Unlocked {
        master_encryption_key: [u8; MASTER_KEY_LEN],
        master_derivation_key: [u8; MASTER_KEY_LEN],
        password_salt: [u8; 32],
        password_hash: [u8; 32],
    },
}

impl Wallet {
    fn locked(db_path: PathBuf) -> Self {
        Self {
            db_path,
            state: WalletState::Locked,
        }
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Read the metadata row. Mirrors `Metadata()` (sqlite.go:590).
    pub fn metadata(&self) -> Result<WalletMetadata> {
        WalletDb::open(&self.db_path)?.read_metadata()
    }

    /// Decrypt MEP + MDK with `password` and cache them in memory.
    /// Mirrors `Init` (sqlite.go:652).
    pub fn init(&mut self, password: &[u8]) -> Result<()> {
        let mep = self.decrypt_mep(password)?;
        let mdk = self.decrypt_mdk(&mep)?;

        let mut salt = [0u8; 32];
        fill_random(&mut salt)?;
        let hash = fast_hash_with_salt(password, &salt);

        let mut mep_arr = [0u8; MASTER_KEY_LEN];
        mep_arr.copy_from_slice(&mep);
        let mut mdk_arr = [0u8; MASTER_KEY_LEN];
        mdk_arr.copy_from_slice(&mdk);

        self.state = WalletState::Unlocked {
            master_encryption_key: mep_arr,
            master_derivation_key: mdk_arr,
            password_salt: salt,
            password_hash: hash,
        };
        Ok(())
    }

    /// Verify `password`. Mirrors `CheckPassword` (sqlite.go:679):
    /// uses the constant-time-compared hash cached by [`Self::init`]
    /// when present; otherwise falls back to running the scrypt path
    /// and discarding the derived key.
    pub fn check_password(&self, password: &[u8]) -> Result<()> {
        if let WalletState::Unlocked {
            password_salt,
            password_hash,
            ..
        } = &self.state
        {
            let candidate = fast_hash_with_salt(password, password_salt);
            if bool::from(candidate.ct_eq(password_hash)) {
                return Ok(());
            }
            return Err(Error::Decrypt);
        }
        // Locked: attempt the scrypt decrypt without caching.
        self.decrypt_mep(password).map(|_| ())
    }

    /// Mirrors `ExportMasterDerivationKey` (sqlite.go:722). Requires
    /// the wallet to have been initialized; calling on a locked wallet
    /// returns [`Error::WalletNotInitialized`]. Wrong password returns
    /// [`Error::Decrypt`].
    pub fn export_master_derivation_key(&self, password: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
        self.check_password(password)?;
        match &self.state {
            WalletState::Unlocked {
                master_derivation_key,
                ..
            } => Ok(*master_derivation_key),
            WalletState::Locked => Err(Error::WalletNotInitialized),
        }
    }

    /// The cached master-encryption-password (MEP) — populated by
    /// [`Self::init`], consumed by key/multisig encryption in
    /// TASK-205+. Returns `None` if the wallet is still locked.
    pub(crate) fn master_encryption_key(&self) -> Option<&[u8; MASTER_KEY_LEN]> {
        match &self.state {
            WalletState::Unlocked {
                master_encryption_key,
                ..
            } => Some(master_encryption_key),
            WalletState::Locked => None,
        }
    }

    /// Internal accessor for the cached MDK. The public-facing
    /// derivation-key consumer is [`crate::keys`].
    pub(crate) fn master_derivation_key_internal(&self) -> Option<&[u8; MASTER_KEY_LEN]> {
        match &self.state {
            WalletState::Unlocked {
                master_derivation_key,
                ..
            } => Some(master_derivation_key),
            WalletState::Locked => None,
        }
    }

    fn decrypt_mep(&self, password: &[u8]) -> Result<Vec<u8>> {
        let db = WalletDb::open(&self.db_path)?;
        let blob = db.read_mep_encrypted()?;
        decrypt_blob_with_password(&blob, PlaintextType::MasterKey, password)
    }

    fn decrypt_mdk(&self, mep: &[u8]) -> Result<Vec<u8>> {
        let db = WalletDb::open(&self.db_path)?;
        let blob = db.read_mdk_encrypted()?;
        decrypt_blob_with_password(&blob, PlaintextType::MasterDerivationKey, mep)
    }

    fn rename_in_db(&mut self, id: &[u8], new_name: &[u8]) -> Result<()> {
        let db = WalletDb::open(&self.db_path)?;
        db.update_wallet_name(id, new_name)
    }
}

/// SHA-512/256 of `salt || password` — the "fast hash" used to short-circuit
/// repeated password checks after [`Wallet::init`] runs the (expensive)
/// scrypt path once. Mirrors `fastHashWithSalt` (sqlite_crypto.go:259) /
/// `crypto.Hash` (`go-algorand/crypto/util.go:92` — SHA-512/256).
fn fast_hash_with_salt(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(salt);
    hasher.update(password);
    hasher.finalize().into()
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    rand::rngs::OsRng
        .try_fill_bytes(out)
        .map_err(|_| Error::RandBytes)
}

/// Encode `n` as a canonical-msgpack `uint`. Mirrors `msgpackEncode(int)`
/// (sqlite_crypto.go:477 calls `msgpackEncode(maxKeyIdx)` on a plain
/// Go `int` — go-codec with `PositiveIntUnsigned=true` writes the
/// smallest unsigned representation, which `rmp::encode::write_uint`
/// produces).
fn encode_max_key_idx(n: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(9);
    rmp::encode::write_uint(&mut buf, n).map_err(|_| Error::Crypto)?;
    Ok(buf)
}

fn maybe_make_wallets_dir(dir: &Path) -> Result<()> {
    // Recursive create — see WalletDriver::new doc for the deliberate
    // divergence from Go's non-recursive os.Mkdir (sqlite.go:312). We
    // still apply 0700 perms to the leaf directory below so a freshly
    // created tree gets the same final mode Go uses.
    let already_existed = dir.exists();
    std::fs::create_dir_all(dir).map_err(Error::Io)?;
    if !already_existed {
        set_unix_perms(dir, SQLITE_WALLETS_DIR_PERMISSIONS)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_unix_perms(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(dir, perms).map_err(Error::Io)
}

#[cfg(not(unix))]
fn set_unix_perms(_dir: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weak_driver_cfg(dir: &Path) -> WalletDriverConfig {
        WalletDriverConfig {
            wallets_dir: dir.to_path_buf(),
            scrypt_params: ScryptParams {
                // Production-weak; the safety check is bypassed via
                // allow_unsafe_scrypt so tests stay fast.
                scrypt_n: 1024,
                scrypt_r: 1,
                scrypt_p: 1,
            },
            allow_unsafe_scrypt: true,
        }
    }

    #[test]
    fn driver_rejects_weak_scrypt_without_unsafe_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = weak_driver_cfg(dir.path());
        cfg.allow_unsafe_scrypt = false;
        let err = WalletDriver::new(cfg).unwrap_err();
        assert!(matches!(err, Error::ScryptTooWeak(_)), "got {err:?}");
    }

    #[test]
    fn fast_hash_with_salt_concatenates_salt_first() {
        // Locks in `salt || password` (not `password || salt`) — matches
        // Go's `append(salt, password...)` (sqlite_crypto.go:260). We
        // compute the reference here from sha2 directly so the test is
        // self-checking; the byte-equality vs Go-produced wallets is
        // covered by the interop fixture test.
        use sha2::{Digest, Sha512_256};

        let mut h = Sha512_256::new();
        h.update(b"the-salt");
        h.update(b"the-password");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(fast_hash_with_salt(b"the-password", b"the-salt"), expected);

        // Swapping salt/password produces a different hash, proving
        // order matters.
        let mut h = Sha512_256::new();
        h.update(b"the-password");
        h.update(b"the-salt");
        let swapped: [u8; 32] = h.finalize().into();
        assert_ne!(fast_hash_with_salt(b"the-password", b"the-salt"), swapped);
    }
}
