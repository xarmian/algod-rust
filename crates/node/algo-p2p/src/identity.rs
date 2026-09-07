// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

use ed25519_dalek::SigningKey;
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

/// Derive the raw Ed25519 signing key underlying `keypair`, so it can drive
/// `algo_network::identity`'s netidentity challenge/response/verification
/// scheme (the 3-message exchange described in that module's doc comment)
/// as its own signer.
///
/// Mirrors go-algorand's `network/p2p.PeerIDChallengeSigner`
/// (`peerID.go`), a thin adapter wrapping a libp2p `crypto.PrivKey` to
/// implement the `network` package's `identityChallengeSigner` interface
/// (`Sign`/`SignBytes`/`PublicKey`). That adapter has exactly one
/// production call site — `P2PNetwork.PeerIDSigner()`, consumed by
/// `NewHybridP2PNetwork` (`network/hybridNetwork.go:73`) to build the
/// hybrid-mode identity-challenge scheme its WS-gossip leg uses — so this
/// crate's equivalent adapter exists for the same reason: letting a node
/// running both the WS-gossip and P2P transports (`Hybrid` mode) sign
/// identity challenges/responses with the *same* key its P2P `PeerId` is
/// derived from, so a peer that connects over both transports presents the
/// same verified identity key on each, and can be recognized as a
/// duplicate connection (see issue #1133).
///
/// Where go's adapter stays an opaque object wrapping the libp2p
/// `crypto.PrivKey` trait object, algod-rust's `algo_network::identity`
/// functions take a concrete `ed25519_dalek::SigningKey` by value, so this
/// adapter extracts the raw key material once up front instead.
///
/// Returns [`P2pError::KeyDecode`] if `keypair` is not Ed25519 — the only
/// key type [`get_or_create_keypair`] (this module) ever produces or
/// loads, mirroring go's `loadPrivateKeyFromFile`/`generatePrivKey`, which
/// likewise only support Ed25519 P2P peer identities.
pub fn to_identity_signing_key(keypair: &Keypair) -> Result<SigningKey, P2pError> {
    let ed25519_keypair = keypair.clone().try_into_ed25519().map_err(|e| {
        P2pError::KeyDecode(format!(
            "P2P peer identity key is not Ed25519 ({e}); the netidentity challenge scheme \
             requires an Ed25519 signer"
        ))
    })?;
    // `ed25519::Keypair::to_bytes()` (libp2p-identity) returns
    // `secret_scalar(32) || compressed_public_point(32)` — RFC 8032
    // section 5.1.5's "expanded" concatenated format, which is exactly the
    // layout `ed25519_dalek::SigningKey::to_keypair_bytes()` produces
    // internally (libp2p-identity's ed25519 module is itself a thin
    // wrapper over `ed25519_dalek::SigningKey`). `SigningKey::from_bytes`
    // only needs the 32-byte seed half; the verifying key is re-derived
    // deterministically from it, so this reconstructs the identical
    // signer, not merely a "compatible" one.
    let raw = ed25519_keypair.to_bytes();
    let secret_seed: [u8; 32] = raw[..32]
        .try_into()
        .expect("ed25519 keypair's secret half is always 32 bytes");
    Ok(SigningKey::from_bytes(&secret_seed))
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

    // -----------------------------------------------------------------------
    // `to_identity_signing_key` — mirrors go's `TestPeerIDChallengeSigner`
    // (`network/p2p/peerID_test.go`).
    // -----------------------------------------------------------------------

    /// Go: `TestPeerIDChallengeSigner` asserts the adapter's `PublicKey()`
    /// equals the wrapped libp2p key's own raw public key. Same assertion
    /// here, against our adapter's derived `SigningKey::verifying_key()`.
    #[test]
    fn to_identity_signing_key_public_key_matches_keypair() {
        let keypair = Keypair::generate_ed25519();
        let signing_key =
            to_identity_signing_key(&keypair).expect("ed25519 keypair should convert");

        let expected_pub = keypair
            .public()
            .try_into_ed25519()
            .expect("public half is ed25519 too")
            .to_bytes();
        assert_eq!(signing_key.verifying_key().to_bytes(), expected_pub);
    }

    /// The adapter must reconstruct the *identical* signer, not merely a
    /// key that happens to verify: signatures it produces must match what
    /// libp2p's own `Keypair::sign` produces for the same message (go's
    /// `PeerIDChallengeSigner.SignBytes` delegates straight to the wrapped
    /// `crypto.PrivKey.Sign` for exactly this reason).
    #[test]
    fn to_identity_signing_key_signs_identically_to_libp2p() {
        use ed25519_dalek::Signer;

        let keypair = Keypair::generate_ed25519();
        let signing_key =
            to_identity_signing_key(&keypair).expect("ed25519 keypair should convert");

        let message = b"algod-rust netidentity challenge payload";
        let our_sig = signing_key.sign(message);
        let libp2p_sig = keypair.sign(message).expect("libp2p sign should succeed");

        assert_eq!(our_sig.to_bytes().as_slice(), libp2p_sig.as_slice());
        assert!(signing_key
            .verifying_key()
            .verify_strict(message, &our_sig)
            .is_ok());
    }

    /// Loading the same on-disk key twice (the normal `--p2p-persist-peer-id`
    /// path) must derive the same signing key both times — the adapter is
    /// deterministic, not tied to a single in-memory `Keypair` instance.
    #[test]
    fn to_identity_signing_key_is_deterministic_across_reload() {
        let dir = std::env::temp_dir().join(format!(
            "algo-p2p-identity-signing-key-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = IdentityConfig {
            private_key_path: None,
            data_dir: Some(dir.clone()),
            persist_peer_id: true,
        };

        let kp1 = get_or_create_keypair(&cfg).expect("first call should generate + persist");
        let kp2 = get_or_create_keypair(&cfg).expect("second call should load the persisted key");

        let key1 = to_identity_signing_key(&kp1).expect("kp1 should convert");
        let key2 = to_identity_signing_key(&kp2).expect("kp2 should convert");
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        std::fs::remove_dir_all(&dir).ok();
    }
}
