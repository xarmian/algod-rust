//! Wallet-handle session manager.
//!
//! Ported from `../go-algorand/daemon/kmd/session/{session,auth}.go`
//! (v4.5.1-stable). Wallets are unlocked once via [`SessionManager::init_wallet_handle`]
//! and accessed afterwards by an ephemeral handle token of the form
//! `<16-hex-id>.<64-hex-secret>`. Handles expire after
//! `session_lifetime`; periodic cleanup removes expired entries.
//!
//! ## Threading
//!
//! All state lives behind a single `Mutex` — Go's `Manager` uses
//! `deadlock.Mutex` for the same shape. The mutex protects the
//! handle map and is held for the duration of each public method.
//!
//! ## Cleanup task
//!
//! Go spawns a goroutine in `MakeManager` that ticks every 60s. Rust
//! doesn't pull tokio in at this layer — we expose
//! [`SessionManager::delete_expired_handles`] for the caller (the
//! HTTP server in TASK-212 / B4) to schedule on whatever runtime it
//! owns.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::wallet::Wallet;

/// `wHandleIDBytes` (auth.go:31) — handle ID is 8 random bytes,
/// 16 hex characters on the wire.
const HANDLE_ID_BYTES: usize = 8;
/// `wHandleSecretBytes` (auth.go:32) — secret is 32 random bytes,
/// 64 hex characters on the wire.
const HANDLE_SECRET_BYTES: usize = 32;
/// `handleCleanupSeconds` (auth.go:33). The cleanup task should tick
/// at this interval; we expose it so callers can match Go.
pub const HANDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// Token separator between handle ID and secret. Matches
/// `wHandleTokenSplitChar` (auth.go:36).
const TOKEN_SEPARATOR: char = '.';

const HANDLE_ID_HEX_LEN: usize = HANDLE_ID_BYTES * 2;
const HANDLE_SECRET_HEX_LEN: usize = HANDLE_SECRET_BYTES * 2;

/// Per-handle state held in the manager's map. Mirrors `walletHandle`
/// (session.go:28).
#[derive(Clone)]
struct Handle {
    secret_hex: String,
    expires: Instant,
    wallet: Wallet,
}

/// In-memory session store. One per running kmd-rust daemon.
///
/// Mirrors `session.Manager` (session.go:37). Wallets are kept in
/// memory between requests so the user only enters the password once.
pub struct SessionManager {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("SessionManager mutex poisoned");
        f.debug_struct("SessionManager")
            .field("handles", &inner.handles.len())
            .field("session_lifetime", &inner.session_lifetime)
            .finish()
    }
}

struct Inner {
    handles: HashMap<String, Handle>,
    session_lifetime: Duration,
}

/// What [`SessionManager::auth_with_token`] /
/// [`SessionManager::renew_wallet_handle`] return: a clone of the
/// unlocked wallet plus the remaining lifetime in seconds (Go shape,
/// session.go:227).
#[derive(Clone, Debug)]
pub struct AuthorizedHandle {
    pub wallet: Wallet,
    pub expires_seconds: i64,
}

impl SessionManager {
    /// Mirrors `MakeManager` (session.go:48). The cleanup task is **not**
    /// spawned here; the caller is responsible for scheduling
    /// [`Self::delete_expired_handles`] (see module-level docs).
    pub fn new(session_lifetime: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                handles: HashMap::new(),
                session_lifetime,
            }),
        }
    }

    /// Construct from the session lifetime in seconds (matches Go's
    /// `cfg.SessionLifetimeSecs`).
    pub fn from_lifetime_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Initialize a wallet handle. `wallet` must already be unlocked
    /// (`Wallet::init` called with the right password) — Go does the
    /// init inline at session.go:130, but doing it here would force
    /// this module to know the password-checking API. The handler
    /// layer (TASK-213) will call `wallet.init(password)?` first then
    /// pass the result to `init_wallet_handle`.
    ///
    /// Returns the `<id>.<secret>` token the caller should give back
    /// to the HTTP client.
    pub fn init_wallet_handle(&self, wallet: Wallet) -> Result<String> {
        let (id_hex, secret_hex) = generate_handle_id_and_secret()?;
        let handle = Handle {
            secret_hex: secret_hex.clone(),
            expires: Instant::now() + self.session_lifetime_unlocked(),
            wallet,
        };
        let mut guard = self.lock();
        guard.handles.insert(id_hex.clone(), handle);
        Ok(format!("{id_hex}{TOKEN_SEPARATOR}{secret_hex}"))
    }

    /// Release a handle by token. Mirrors `ReleaseWalletHandle`
    /// (session.go:184). Returns `Error::WalletHandleInvalid` on any
    /// malformed/unknown/wrong-secret token.
    pub fn release_wallet_handle(&self, token: &str) -> Result<()> {
        let mut guard = self.lock();
        let (id, _) = guard.lookup_and_authorize(token)?;
        guard.handles.remove(&id);
        Ok(())
    }

    /// Look up + authorize without changing expiry. Mirrors
    /// `AuthWithWalletHandleToken` (session.go:242).
    ///
    /// Returns a **clone** of the wallet so HTTP handlers can use it
    /// without holding the session mutex. The wallet is cheap to
    /// clone (db_path + cached key material).
    pub fn auth_with_token(&self, token: &str) -> Result<AuthorizedHandle> {
        self.auth_maybe_renew(token, false)
    }

    /// Look up + bump expiry. Mirrors `RenewWalletHandleToken`
    /// (session.go:235).
    pub fn renew_wallet_handle(&self, token: &str) -> Result<AuthorizedHandle> {
        self.auth_maybe_renew(token, true)
    }

    fn auth_maybe_renew(&self, token: &str, renew: bool) -> Result<AuthorizedHandle> {
        let mut guard = self.lock();
        let (id, _secret) = guard.lookup_and_authorize(token)?;

        let now = Instant::now();
        // Cache the lifetime before grabbing a mutable borrow of
        // handles — needed for the `renew` path below.
        let session_lifetime = guard.session_lifetime;

        let handle = guard
            .handles
            .get_mut(&id)
            .expect("authorize confirmed key exists");
        if now > handle.expires {
            // Expired — drop it and report.
            guard.handles.remove(&id);
            return Err(Error::WalletHandleExpired);
        }

        if renew {
            handle.expires = now + session_lifetime;
        }
        let expires_seconds = handle.expires.saturating_duration_since(now).as_secs() as i64;
        let wallet = handle.wallet.clone();
        Ok(AuthorizedHandle {
            wallet,
            expires_seconds,
        })
    }

    /// Remove all expired handles. Mirrors `deleteExpiredHandles`
    /// (session.go:116). Call periodically (every
    /// [`HANDLE_CLEANUP_INTERVAL`]) from the daemon's runtime.
    pub fn delete_expired_handles(&self) {
        let mut guard = self.lock();
        let now = Instant::now();
        guard.handles.retain(|_, h| now <= h.expires);
    }

    /// Count of currently-active handles. Useful for monitoring and
    /// tests; not exposed in Go's public API.
    pub fn handle_count(&self) -> usize {
        self.lock().handles.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("SessionManager mutex poisoned")
    }

    fn session_lifetime_unlocked(&self) -> Duration {
        self.lock().session_lifetime
    }
}

impl Inner {
    /// Parse `token`, find the handle, constant-time-compare the
    /// secret. Returns `(handle_id, secret)` on success.
    fn lookup_and_authorize(&self, token: &str) -> Result<(String, String)> {
        let (id, secret) = split_handle(token)?;
        let handle = self.handles.get(&id).ok_or(Error::WalletHandleInvalid)?;
        let eq: bool = secret.as_bytes().ct_eq(handle.secret_hex.as_bytes()).into();
        if !eq {
            return Err(Error::WalletHandleInvalid);
        }
        Ok((id, secret))
    }
}

/// Split a `<id>.<secret>` token, validate each half. Mirrors
/// `splitHandle` + `validateHandleID` + `validateHandleSecret`
/// (auth.go:54).
fn split_handle(token: &str) -> Result<(String, String)> {
    let (id, secret) = token
        .split_once(TOKEN_SEPARATOR)
        .ok_or(Error::WalletHandleInvalid)?;
    if id.len() != HANDLE_ID_HEX_LEN || !is_lower_hex(id) {
        return Err(Error::WalletHandleInvalid);
    }
    if secret.len() != HANDLE_SECRET_HEX_LEN || !is_lower_hex(secret) {
        return Err(Error::WalletHandleInvalid);
    }
    Ok((id.to_string(), secret.to_string()))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Generate a fresh `(id_hex, secret_hex)` pair. Mirrors
/// `generateHandleIDAndSecret` (auth.go:81) — uses the OS RNG and
/// lowercase hex encoding.
fn generate_handle_id_and_secret() -> Result<(String, String)> {
    let mut id_bytes = [0u8; HANDLE_ID_BYTES];
    let mut secret_bytes = [0u8; HANDLE_SECRET_BYTES];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut id_bytes)
        .map_err(|_| Error::RandBytes)?;
    rng.try_fill_bytes(&mut secret_bytes)
        .map_err(|_| Error::RandBytes)?;
    Ok((hex_lower(&id_bytes), hex_lower(&secret_bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ScryptParams, WalletDriver, WalletDriverConfig};
    use tempfile::TempDir;

    fn weak_cfg(dir: &std::path::Path) -> WalletDriverConfig {
        WalletDriverConfig {
            wallets_dir: dir.to_path_buf(),
            scrypt_params: ScryptParams {
                scrypt_n: 1024,
                scrypt_r: 1,
                scrypt_p: 1,
            },
            allow_unsafe_scrypt: true,
        }
    }

    fn unlocked_wallet(dir: &std::path::Path, name: &[u8], id: &[u8]) -> Wallet {
        let driver = WalletDriver::new(weak_cfg(dir)).unwrap();
        driver.create_wallet(name, id, b"pw", None).unwrap();
        let mut w = driver.fetch_wallet(id).unwrap();
        w.init(b"pw").unwrap();
        w
    }

    #[test]
    fn token_format_is_id_dot_secret() {
        let dir = TempDir::new().unwrap();
        let w = unlocked_wallet(dir.path(), b"a", b"id-a");
        let mgr = SessionManager::from_lifetime_secs(60);
        let token = mgr.init_wallet_handle(w).unwrap();
        let (id, secret) = token.split_once('.').expect("token has separator");
        assert_eq!(id.len(), HANDLE_ID_HEX_LEN);
        assert_eq!(secret.len(), HANDLE_SECRET_HEX_LEN);
        assert!(is_lower_hex(id) && is_lower_hex(secret));
    }

    #[test]
    fn init_use_release_round_trip() {
        let dir = TempDir::new().unwrap();
        let w = unlocked_wallet(dir.path(), b"a", b"id-a");
        let mgr = SessionManager::from_lifetime_secs(60);
        let token = mgr.init_wallet_handle(w).unwrap();
        assert_eq!(mgr.handle_count(), 1);

        // Use without renew.
        let h = mgr.auth_with_token(&token).unwrap();
        assert!(h.expires_seconds > 0 && h.expires_seconds <= 60);
        // Wallet returned by clone is still functional.
        assert!(h.wallet.export_master_derivation_key(b"pw").is_ok());

        // Release deletes it.
        mgr.release_wallet_handle(&token).unwrap();
        assert_eq!(mgr.handle_count(), 0);
        assert!(matches!(
            mgr.auth_with_token(&token),
            Err(Error::WalletHandleInvalid)
        ));
    }

    #[test]
    fn invalid_tokens_are_rejected() {
        let mgr = SessionManager::from_lifetime_secs(60);
        for bad in [
            "",
            "nosep",
            "0123456789abcdef.short",
            "0123456789ABCDEF.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // uppercase id
            "0123456789abcdef.GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", // non-hex secret
        ] {
            assert!(
                matches!(mgr.auth_with_token(bad), Err(Error::WalletHandleInvalid)),
                "token {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn wrong_secret_is_rejected_constant_time() {
        let dir = TempDir::new().unwrap();
        let w = unlocked_wallet(dir.path(), b"b", b"id-b");
        let mgr = SessionManager::from_lifetime_secs(60);
        let token = mgr.init_wallet_handle(w).unwrap();
        let (id, _) = token.split_once('.').unwrap();
        // Swap the secret for a same-length all-zero hex string.
        let fake = format!("{id}.{}", "0".repeat(HANDLE_SECRET_HEX_LEN));
        assert!(matches!(
            mgr.auth_with_token(&fake),
            Err(Error::WalletHandleInvalid)
        ));
    }

    #[test]
    fn renew_extends_expiry() {
        let dir = TempDir::new().unwrap();
        let w = unlocked_wallet(dir.path(), b"c", b"id-c");
        // Use a very short lifetime so renewal's bump is observable
        // without sleeping.
        let mgr = SessionManager::from_lifetime_secs(5);
        let token = mgr.init_wallet_handle(w).unwrap();

        let before = mgr.auth_with_token(&token).unwrap().expires_seconds;
        // Force the stored expiry into the past so the renewal must
        // shift it forward by the full lifetime.
        {
            let mut guard = mgr.inner.lock().unwrap();
            for h in guard.handles.values_mut() {
                h.expires = std::time::Instant::now() + std::time::Duration::from_secs(1);
            }
        }
        let renewed = mgr.renew_wallet_handle(&token).unwrap();
        assert!(
            renewed.expires_seconds >= before,
            "renew must not shrink expiry: before={before} renewed={}",
            renewed.expires_seconds
        );
        // The renewed lifetime should be close to the full session_lifetime.
        assert!(renewed.expires_seconds >= 4 && renewed.expires_seconds <= 5);
    }

    #[test]
    fn expired_handle_is_rejected_and_removed() {
        let dir = TempDir::new().unwrap();
        let w = unlocked_wallet(dir.path(), b"d", b"id-d");
        let mgr = SessionManager::from_lifetime_secs(60);
        let token = mgr.init_wallet_handle(w).unwrap();
        // Force the handle into the past.
        {
            let mut guard = mgr.inner.lock().unwrap();
            for h in guard.handles.values_mut() {
                h.expires = std::time::Instant::now() - std::time::Duration::from_secs(1);
            }
        }
        assert!(matches!(
            mgr.auth_with_token(&token),
            Err(Error::WalletHandleExpired)
        ));
        // And it was removed as a side effect.
        assert_eq!(mgr.handle_count(), 0);
    }

    #[test]
    fn delete_expired_handles_removes_only_stale_entries() {
        let dir = TempDir::new().unwrap();
        let live = unlocked_wallet(dir.path(), b"l", b"id-l");
        let stale = unlocked_wallet(dir.path(), b"s", b"id-s");
        let mgr = SessionManager::from_lifetime_secs(60);
        let _live_tok = mgr.init_wallet_handle(live).unwrap();
        let _stale_tok = mgr.init_wallet_handle(stale).unwrap();
        assert_eq!(mgr.handle_count(), 2);

        // Backdate the second handle.
        {
            let mut guard = mgr.inner.lock().unwrap();
            let stale_id = guard
                .handles
                .iter()
                .find_map(|(id, h)| {
                    if h.wallet.db_path().ends_with("s.id-s.db") {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .expect("must find stale handle");
            guard.handles.get_mut(&stale_id).unwrap().expires =
                std::time::Instant::now() - std::time::Duration::from_secs(1);
        }
        mgr.delete_expired_handles();
        assert_eq!(mgr.handle_count(), 1, "stale handle removed");
    }
}
