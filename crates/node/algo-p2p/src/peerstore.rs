//! Persistent peer address cache for the P2P DHT.
//!
//! Go-algorand's `network/p2p/peerstore.PeerStore` (`network/p2p/peerstore/peerstore.go`)
//! wraps an in-memory `pstoremem` peerstore with phonebook-style retry/role
//! bookkeeping — it does not itself persist to disk. This module is the
//! on-disk complement issue #539 asks for: a small JSON snapshot of known
//! peer addresses, loaded at startup and saved on demand, so a restarted
//! node can seed its DHT routing table (via
//! [`crate::host::P2pHost::add_bootstrap_peer`]) with previously-known-good
//! peers instead of only the configured bootstrap/`dnsaddr` list — the
//! "known-good peers survive a restart" requirement from the issue.
//!
//! Kept deliberately independent of [`crate::host::P2pHost`]: callers
//! record addresses (e.g. from `SwarmEvent::ConnectionEstablished`) and
//! decide when to load/save, rather than the host silently doing disk I/O
//! on every connection.

use std::collections::HashMap;
use std::path::Path;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::errors::P2pError;

/// Default filename (relative to the node's data directory) for the
/// persisted peer cache.
pub const DEFAULT_PEERSTORE_FILENAME: &str = "p2p_peerstore.json";

/// On-disk representation of a single cached peer's known addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedPeer {
    addrs: Vec<String>,
}

/// A simple on-disk cache of known peer addresses, keyed by [`PeerId`].
#[derive(Debug, Clone, Default)]
pub struct PersistentPeerStore {
    peers: HashMap<PeerId, Vec<Multiaddr>>,
}

impl PersistentPeerStore {
    /// An empty, unpersisted store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a previously persisted peer cache from `path`.
    ///
    /// Returns an empty store (not an error) when `path` does not exist
    /// yet — a fresh node's first start has nothing to load.
    /// Individual entries that fail to parse (corrupt `PeerId`/`Multiaddr`
    /// strings) are skipped rather than failing the whole load, since a
    /// stale/malformed cache entry should not block startup.
    pub fn load(path: &Path) -> Result<Self, P2pError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)?;
        let raw: HashMap<String, PersistedPeer> =
            serde_json::from_slice(&bytes).map_err(|e| P2pError::PeerstoreDecode(e.to_string()))?;

        let mut peers = HashMap::with_capacity(raw.len());
        for (peer_id_str, persisted) in raw {
            let Ok(peer_id) = peer_id_str.parse::<PeerId>() else {
                continue;
            };
            let addrs = persisted
                .addrs
                .into_iter()
                .filter_map(|a| a.parse::<Multiaddr>().ok())
                .collect();
            peers.insert(peer_id, addrs);
        }
        Ok(Self { peers })
    }

    /// Persist the current cache to `path`, creating parent directories as
    /// needed.
    pub fn save(&self, path: &Path) -> Result<(), P2pError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let raw: HashMap<String, PersistedPeer> = self
            .peers
            .iter()
            .map(|(id, addrs)| {
                (
                    id.to_string(),
                    PersistedPeer {
                        addrs: addrs.iter().map(|a| a.to_string()).collect(),
                    },
                )
            })
            .collect();
        let bytes = serde_json::to_vec_pretty(&raw)
            .map_err(|e| P2pError::PeerstoreDecode(e.to_string()))?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Record (or extend) the known addresses for `peer_id`, deduplicating
    /// against addresses already cached for it.
    pub fn record(&mut self, peer_id: PeerId, addrs: impl IntoIterator<Item = Multiaddr>) {
        let entry = self.peers.entry(peer_id).or_default();
        for addr in addrs {
            if !entry.contains(&addr) {
                entry.push(addr);
            }
        }
    }

    /// All known peers and their cached addresses.
    pub fn known_peers(&self) -> impl Iterator<Item = (&PeerId, &Vec<Multiaddr>)> {
        self.peers.iter()
    }

    /// Number of distinct peers cached.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "algo-p2p-peerstore-test-{name}-{}",
            std::process::id()
        ))
    }

    fn sample_peer_and_addr() -> (PeerId, Multiaddr) {
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4160".parse().unwrap();
        (peer_id, addr)
    }

    #[test]
    fn load_missing_file_returns_empty_store() {
        let path = tmp_path("missing");
        let store = PersistentPeerStore::load(&path).expect("missing file should not error");
        assert!(store.is_empty());
    }

    #[test]
    fn record_then_save_then_reload_round_trips() {
        let path = tmp_path("roundtrip");
        let (peer_id, addr) = sample_peer_and_addr();

        let mut store = PersistentPeerStore::new();
        store.record(peer_id, [addr.clone()]);
        store.save(&path).expect("save should succeed");

        let reloaded = PersistentPeerStore::load(&path).expect("reload should succeed");
        let addrs: Vec<_> = reloaded
            .known_peers()
            .find(|(id, _)| **id == peer_id)
            .map(|(_, addrs)| addrs.clone())
            .expect("peer should have survived the round trip");
        assert_eq!(addrs, vec![addr]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_deduplicates_addresses() {
        let (peer_id, addr) = sample_peer_and_addr();
        let mut store = PersistentPeerStore::new();
        store.record(peer_id, [addr.clone()]);
        store.record(peer_id, [addr.clone()]);
        let addrs: Vec<_> = store
            .known_peers()
            .find(|(id, _)| **id == peer_id)
            .map(|(_, addrs)| addrs.clone())
            .unwrap();
        assert_eq!(addrs, vec![addr]);
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = std::env::temp_dir().join(format!(
            "algo-p2p-peerstore-test-dir-{}",
            std::process::id()
        ));
        let path = dir.join("nested").join(DEFAULT_PEERSTORE_FILENAME);
        let (peer_id, addr) = sample_peer_and_addr();

        let mut store = PersistentPeerStore::new();
        store.record(peer_id, [addr]);
        store.save(&path).expect("save should create parent dirs");
        assert!(path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_entries_are_skipped_not_fatal() {
        let path = tmp_path("corrupt");
        std::fs::write(
            &path,
            r#"{"not-a-valid-peer-id": {"addrs": ["/ip4/127.0.0.1/tcp/4160"]}}"#,
        )
        .unwrap();

        let store = PersistentPeerStore::load(&path).expect("corrupt entries should be skipped");
        assert!(store.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn len_and_is_empty_reflect_cache_size() {
        let mut store = PersistentPeerStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let (peer_id, addr) = sample_peer_and_addr();
        store.record(peer_id, [addr]);
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
}
