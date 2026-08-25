//! Peer identity management for the libp2p P2P transport.
//!
//! Mirrors go-algorand's `network/p2p/peerID.go` `GetPrivKey` semantics: a
//! node's libp2p [`Keypair`] (and therefore its [`PeerId`]) is loaded from a
//! user-supplied path, falls back to a default path inside the node's data
//! directory, and — if neither exists — a fresh Ed25519 key is generated. The
//! freshly generated key is persisted to the default path only when the
//! caller opts in (`persist_peer_id`, matching go's `cfg.P2PPersistPeerID`),
//! so ephemeral nodes (most tests, `--data-dir`-less runs) get a new PeerId
//! every start while long-running nodes keep a stable one across restarts.
//!
//! Reference: `../go-algorand/network/p2p/peerID.go` (`GetPrivKey`,
//! `loadPrivateKeyFromFile`, `writePrivateKeyToFile`, `generatePrivKey`).

use std::path::{Path, PathBuf};

use libp2p::identity::Keypair;

use crate::errors::P2pError;

/// Default filename (relative to the node's data directory) that a
/// generated peer identity key is persisted to.
///
/// Go: `p2p.DefaultPrivKeyPath = "peerIDPrivKey.key"`.
pub const DEFAULT_PRIV_KEY_FILENAME: &str = "peerIDPrivKey.key";

/// Configuration controlling how the P2P peer identity key is sourced.
#[derive(Debug, Clone, Default)]
pub struct IdentityConfig {
    /// Explicit path to a private key file. Takes priority over everything
    /// else when set. Go: `cfg.P2PPrivateKeyLocation`.
    pub private_key_path: Option<PathBuf>,

    /// The node's data directory. When set (and `private_key_path` is not),
    /// `<data_dir>/peerIDPrivKey.key` is checked next and used as the
    /// persistence target for a freshly generated key.
    pub data_dir: Option<PathBuf>,

    /// Whether a freshly generated key should be written to the default
    /// path so the PeerId is stable across restarts. Go: `cfg.P2PPersistPeerID`.
    pub persist_peer_id: bool,
}

/// Load or create the node's libp2p [`Keypair`], following the same
/// precedence as go-algorand's `GetPrivKey`:
///
/// 1. `private_key_path`, if set — load from there (error if missing/invalid).
/// 2. `<data_dir>/peerIDPrivKey.key`, if it exists — load from there.
/// 3. Otherwise generate a new Ed25519 key, persisting it to the default
///    path when `persist_peer_id` is set and a `data_dir` is configured.
pub fn get_or_create_keypair(cfg: &IdentityConfig) -> Result<Keypair, P2pError> {
    if let Some(path) = &cfg.private_key_path {
        return load_keypair_from_file(path);
    }

    let default_path = cfg
        .data_dir
        .as_ref()
        .map(|dir| dir.join(DEFAULT_PRIV_KEY_FILENAME));

    if let Some(path) = &default_path {
        if path.exists() {
            return load_keypair_from_file(path);
        }
    }

    let keypair = Keypair::generate_ed25519();
    if cfg.persist_peer_id {
        if let Some(path) = &default_path {
            write_keypair_to_file(path, &keypair)?;
        }
    }
    Ok(keypair)
}

/// Read a libp2p protobuf-encoded private key from `path`.
fn load_keypair_from_file(path: &Path) -> Result<Keypair, P2pError> {
    let bytes = std::fs::read(path)?;
    Keypair::from_protobuf_encoding(&bytes).map_err(|e| P2pError::KeyDecode(e.to_string()))
}

/// Write `keypair`'s protobuf encoding to `path`, creating parent
/// directories if needed and restricting file permissions to the owner on
/// Unix (mirrors go's `os.OpenFile(path, ..., 0600)`).
fn write_keypair_to_file(path: &Path, keypair: &Keypair) -> Result<(), P2pError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| P2pError::KeyDecode(e.to_string()))?;
    std::fs::write(path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ephemeral_key_when_unconfigured() {
        let cfg = IdentityConfig::default();
        let kp1 = get_or_create_keypair(&cfg).expect("should generate a key");
        let kp2 = get_or_create_keypair(&cfg).expect("should generate a key");
        // Two independent calls with no persistence configured produce
        // different (ephemeral) identities.
        assert_ne!(kp1.public().to_peer_id(), kp2.public().to_peer_id());
    }

    #[test]
    fn persists_generated_key_and_reloads_same_peer_id() {
        let dir =
            std::env::temp_dir().join(format!("algo-p2p-identity-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = IdentityConfig {
            private_key_path: None,
            data_dir: Some(dir.clone()),
            persist_peer_id: true,
        };

        let kp1 = get_or_create_keypair(&cfg).expect("first call should generate + persist");
        let key_path = dir.join(DEFAULT_PRIV_KEY_FILENAME);
        assert!(key_path.exists(), "key file should be persisted to disk");

        let kp2 = get_or_create_keypair(&cfg).expect("second call should load the persisted key");
        assert_eq!(
            kp1.public().to_peer_id(),
            kp2.public().to_peer_id(),
            "reloading a persisted identity must yield the same PeerId"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_persist_when_not_requested() {
        let dir =
            std::env::temp_dir().join(format!("algo-p2p-identity-test-np-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let cfg = IdentityConfig {
            private_key_path: None,
            data_dir: Some(dir.clone()),
            persist_peer_id: false,
        };

        let _kp = get_or_create_keypair(&cfg).expect("should generate a key");
        let key_path = dir.join(DEFAULT_PRIV_KEY_FILENAME);
        assert!(
            !key_path.exists(),
            "key file must not be written unless persist_peer_id is set"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn explicit_private_key_path_errors_when_missing() {
        let cfg = IdentityConfig {
            private_key_path: Some(PathBuf::from(
                "/nonexistent/path/that/should/not/exist/key.pk8",
            )),
            data_dir: None,
            persist_peer_id: false,
        };
        let result = get_or_create_keypair(&cfg);
        assert!(result.is_err(), "missing explicit key path should error");
    }
}
