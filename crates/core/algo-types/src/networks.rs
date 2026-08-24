//! Hardcoded Algorand genesis hashes per network, plus the helper used
//! by `algokey-rust keyreg` to resolve a network name (case-insensitive)
//! to a 32-byte digest. Honors the `ALGOKEY_GENESIS_HASH` environment
//! variable as a manual override.
//!
//! Mirrors `../go-algorand/cmd/algokey/keyreg.go:93-132` byte-for-byte.
//! The four canonical genesis hashes are encoded as base64 in Go's
//! `validNetworks` map; we decode at compile-time via the constants
//! below so any divergence between the b64 string and the in-memory
//! bytes is caught by a single fixture test.
//!
//! This module lives in `algo-types` (not `algokey-rust`) so future
//! consumers (`goal-rust`, `tealdbg-rust`, wallet code) can share the
//! same network → digest table without re-pasting the hashes.

use std::fmt;

use data_encoding::BASE64;

use crate::Digest;

/// Algorand network identifier — exactly the four names Go's
/// `validNetworks` map accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    Betanet,
    Devnet,
}

/// Returned when a network name doesn't match any of the four known
/// values. Display format matches Go's
/// `"unknown network '<n>' provided. Supported networks: mainnet, testnet, betanet, devnet"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetwork {
    pub name: String,
}

impl fmt::Display for UnknownNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown network '{}' provided. Supported networks: {}",
            self.name,
            Network::all()
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for UnknownNetwork {}

/// Errors from [`resolve_genesis_hash`] — either an unknown network
/// name or a malformed `ALGOKEY_GENESIS_HASH` env override.
#[derive(Debug)]
pub enum ResolveGenesisError {
    /// Network name didn't match any known network.
    UnknownNetwork(UnknownNetwork),
    /// `ALGOKEY_GENESIS_HASH` was set but couldn't be decoded into a
    /// 32-byte digest. Wording matches Go's `mustConvertB64ToDigest`
    /// at `keyreg.go:103-113`.
    InvalidOverride { value: String, reason: String },
}

impl fmt::Display for ResolveGenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNetwork(e) => write!(f, "{e}"),
            Self::InvalidOverride { value, reason } => {
                write!(f, "Unable to decode digest '{value}': {reason}")
            }
        }
    }
}

impl std::error::Error for ResolveGenesisError {}

// Hashes verbatim from `cmd/algokey/keyreg.go:93-98`.
//
// We embed them as the b64 strings (not pre-decoded byte arrays) so
// reviewers can grep for the exact text Go uses; the `parse_b64_digest`
// const-equivalent runs at runtime once per network. A unit test
// asserts the decoded bytes match the b64 input byte-for-byte.
const MAINNET_B64: &str = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=";
const TESTNET_B64: &str = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";
const BETANET_B64: &str = "mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=";
const DEVNET_B64: &str = "sjkznd5fmOPzTzMi6BAHa2Ir9DyOxu5H7NH3ratQG1w=";

/// Name of the environment variable Go honors as a digest override.
/// Same string as Go's `os.Getenv("ALGOKEY_GENESIS_HASH")` at
/// `keyreg.go:118`.
pub const GENESIS_HASH_OVERRIDE_ENV: &str = "ALGOKEY_GENESIS_HASH";

impl Network {
    /// Lower-case canonical name (also what Go's `validNetworks` keys
    /// off — Go matches case-insensitively via `strings.ToLower`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Betanet => "betanet",
            Self::Devnet => "devnet",
        }
    }

    /// Parse a network name case-insensitively. Mirrors Go's
    /// `strings.ToLower(network)` lookup at `keyreg.go:124`.
    pub fn from_str_ci(s: &str) -> Result<Self, UnknownNetwork> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "betanet" => Ok(Self::Betanet),
            "devnet" => Ok(Self::Devnet),
            _ => Err(UnknownNetwork {
                name: s.to_string(),
            }),
        }
    }

    /// 32-byte genesis hash for this network.
    pub fn genesis_hash(&self) -> Digest {
        let b64 = match self {
            Self::Mainnet => MAINNET_B64,
            Self::Testnet => TESTNET_B64,
            Self::Betanet => BETANET_B64,
            Self::Devnet => DEVNET_B64,
        };
        Digest(
            decode_b64_digest(b64)
                .expect("compile-time genesis-hash constants must be valid 32-byte base64"),
        )
    }

    /// All four networks, in Go's `validNetworkList` order. (Go derives
    /// the list from `maps.Keys` which is unordered, but the error
    /// message lists them; we pin a stable order so the error wording
    /// is reproducible.)
    pub fn all() -> &'static [Network] {
        &[
            Network::Mainnet,
            Network::Testnet,
            Network::Betanet,
            Network::Devnet,
        ]
    }
}

/// Resolve a network name to a 32-byte digest, honoring the
/// `ALGOKEY_GENESIS_HASH` env override.
///
/// Mirrors Go's `getGenesisInformation` (`keyreg.go:116-132`):
///
/// 1. If `ALGOKEY_GENESIS_HASH` is set and non-empty, decode it via
///    base64; that override wins regardless of the `network` argument.
/// 2. Otherwise look up the network case-insensitively.
pub fn resolve_genesis_hash(network: &str) -> Result<Digest, ResolveGenesisError> {
    if let Ok(override_b64) = std::env::var(GENESIS_HASH_OVERRIDE_ENV) {
        if !override_b64.is_empty() {
            let bytes = decode_b64_digest(&override_b64).map_err(|reason| {
                ResolveGenesisError::InvalidOverride {
                    value: override_b64.clone(),
                    reason,
                }
            })?;
            return Ok(Digest(bytes));
        }
    }
    Network::from_str_ci(network)
        .map(|n| n.genesis_hash())
        .map_err(ResolveGenesisError::UnknownNetwork)
}

/// Helper: decode a base64 string into a 32-byte digest. Mirrors the
/// length + decode-error checks Go does in `mustConvertB64ToDigest`
/// (`keyreg.go:102-113`).
fn decode_b64_digest(b64: &str) -> Result<[u8; 32], String> {
    let decoded = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "Unexpected decoded digest length: expected 32 bytes, got {}",
            decoded.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four canonical hashes must decode cleanly and yield exactly
    /// 32 bytes each. A failure here means a typo in the b64 string.
    #[test]
    fn all_network_hashes_decode_to_32_bytes() {
        for net in Network::all() {
            let digest = net.genesis_hash();
            assert!(!digest.is_zero(), "{net:?} hash must be non-zero");
        }
    }

    /// Case-insensitive parse — every casing maps to the right variant.
    #[test]
    fn from_str_ci_accepts_mixed_case() {
        for (input, expected) in [
            ("mainnet", Network::Mainnet),
            ("MAINNET", Network::Mainnet),
            ("MainNet", Network::Mainnet),
            ("testnet", Network::Testnet),
            ("BETANET", Network::Betanet),
            ("DevNet", Network::Devnet),
        ] {
            assert_eq!(Network::from_str_ci(input).unwrap(), expected);
        }
    }

    /// Unknown networks return an error whose Display matches Go's
    /// wording.
    #[test]
    fn unknown_network_lists_all_known_names_in_error() {
        let err = Network::from_str_ci("private-relay").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown network 'private-relay'"));
        for known in ["mainnet", "testnet", "betanet", "devnet"] {
            assert!(
                msg.contains(known),
                "error should list `{known}` in supported list: {msg}"
            );
        }
    }

    /// Issue #509: go-algorand v4.6.0-stable ([#6556](https://github.com/algorand/go-algorand/pull/6556))
    /// corrected `devnet`'s genesis hash constant in `cmd/algokey/keyreg.go:97`
    /// from `sC3P7e2SdbqKJK0tbiCdK9tdSpbe6XeCGKdoNzmlj0E=` to
    /// `sjkznd5fmOPzTzMi6BAHa2Ir9DyOxu5H7NH3ratQG1w=`. Pinned against the
    /// literal go-algorand value (not `DEVNET_B64`) so this fails before
    /// the constant is updated, not just round-trips against itself.
    #[test]
    fn devnet_genesis_hash_matches_go_algorand_v4_6_0_stable() {
        const GO_ALGORAND_V4_6_0_STABLE_DEVNET_B64: &str =
            "sjkznd5fmOPzTzMi6BAHa2Ir9DyOxu5H7NH3ratQG1w=";
        assert_eq!(
            DEVNET_B64, GO_ALGORAND_V4_6_0_STABLE_DEVNET_B64,
            "devnet genesis hash constant is stale — see go-algorand PR #6556"
        );
    }

    /// Round-trip: re-encoding the bytes via base64 yields back the
    /// canonical input string for each network. This catches any
    /// silent re-padding / charset bug.
    #[test]
    fn b64_round_trip_for_every_network() {
        for (net, want) in [
            (Network::Mainnet, MAINNET_B64),
            (Network::Testnet, TESTNET_B64),
            (Network::Betanet, BETANET_B64),
            (Network::Devnet, DEVNET_B64),
        ] {
            let bytes = net.genesis_hash().0;
            let re_encoded = BASE64.encode(&bytes);
            assert_eq!(re_encoded, want, "round-trip diverges for {net:?}");
        }
    }

    /// `resolve_genesis_hash` without the override returns the
    /// network's canonical hash.
    #[test]
    fn resolve_falls_back_to_network_when_env_unset() {
        // Use a scoped guard since other tests may set ALGOKEY_GENESIS_HASH.
        let _guard = EnvGuard::clear(GENESIS_HASH_OVERRIDE_ENV);
        assert_eq!(
            resolve_genesis_hash("mainnet").unwrap(),
            Network::Mainnet.genesis_hash()
        );
        assert_eq!(
            resolve_genesis_hash("DevNet").unwrap(),
            Network::Devnet.genesis_hash()
        );
    }

    /// When `ALGOKEY_GENESIS_HASH` is set, it overrides the network
    /// argument entirely — even an unknown network resolves to the
    /// override. Matches Go's `keyreg.go:118-121`.
    #[test]
    fn env_override_takes_precedence_over_network_arg() {
        // Use a custom 32-byte payload encoded as b64.
        let custom = [0xAAu8; 32];
        let custom_b64 = BASE64.encode(&custom);
        let _guard = EnvGuard::set(GENESIS_HASH_OVERRIDE_ENV, &custom_b64);
        assert_eq!(
            resolve_genesis_hash("mainnet").unwrap().0,
            custom,
            "override should win over a known network"
        );
        // Even an unknown name resolves while the override is active.
        assert_eq!(resolve_genesis_hash("nonsense").unwrap().0, custom);
    }

    /// Empty env value is treated as unset (matches Go's `if hashOverride != ""`).
    #[test]
    fn empty_env_override_is_ignored() {
        let _guard = EnvGuard::set(GENESIS_HASH_OVERRIDE_ENV, "");
        assert_eq!(
            resolve_genesis_hash("testnet").unwrap(),
            Network::Testnet.genesis_hash()
        );
    }

    /// Malformed override surfaces a typed error with Go-compatible
    /// wording.
    #[test]
    fn invalid_env_override_surfaces_typed_error() {
        let _guard = EnvGuard::set(GENESIS_HASH_OVERRIDE_ENV, "not-base64-!!!");
        match resolve_genesis_hash("mainnet") {
            Err(ResolveGenesisError::InvalidOverride { value, .. }) => {
                assert_eq!(value, "not-base64-!!!");
            }
            other => panic!("expected InvalidOverride, got {other:?}"),
        }
    }

    /// Wrong-length override (valid b64 but not 32 bytes) is rejected.
    #[test]
    fn wrong_length_env_override_rejected() {
        let _guard = EnvGuard::set(GENESIS_HASH_OVERRIDE_ENV, &BASE64.encode(&[0u8; 16]));
        match resolve_genesis_hash("mainnet") {
            Err(ResolveGenesisError::InvalidOverride { reason, .. }) => {
                assert!(reason.contains("expected 32 bytes"), "got: {reason}");
            }
            other => panic!("expected InvalidOverride, got {other:?}"),
        }
    }

    /// Scoped env-var guard: sets / clears a variable for the test
    /// duration and restores the prior value on drop. Tests that touch
    /// `ALGOKEY_GENESIS_HASH` must use this to avoid leaking state into
    /// sibling tests (Rust runs tests concurrently by default).
    struct EnvGuard {
        key: String,
        prev: Option<String>,
        // Tests touching the same env var must serialize. We
        // acquire a process-wide mutex on construction.
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prev = std::env::var(key).ok();
            // SAFETY: env mutation is racy across threads; we serialize
            // via the process-wide mutex above. No `unsafe` needed on
            // current stable Rust (1.75+).
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                prev,
                _lock,
            }
        }

        fn clear(key: &str) -> Self {
            let _lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self {
                key: key.to_string(),
                prev,
                _lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
