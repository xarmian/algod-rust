//! Optional TOML configuration for the `algod-rust` binary.
//!
//! Parsed from an `algod-rust.toml` file passed via `--config`. Every
//! field is optional — missing values fall back to CLI defaults or to
//! the subcommand's built-in behavior. Individual CLI flags always
//! override the TOML equivalent so operators can hot-override a value
//! without editing the file.
//!
//! The schema is intentionally minimal for PLAN-74 TASK-79 (REST server
//! startup). Future tasks can layer on additional sections without
//! breaking backward compatibility — `serde(default)` + unknown fields
//! are ignored.
//!
//! Example:
//!
//! ```toml
//! [rest]
//! listen = "127.0.0.1:8080"
//! data_dir = "/var/lib/algod"
//! # Optional — usually read from `<data_dir>/algod.token` instead.
//! api_token = "abcd..."
//! admin_token = "efgh..."
//! ```
//!
//! Reference (conceptually): go-algorand's `config/localTemplate.go`,
//! which spells out `EndpointAddress` / token paths in the node's
//! `config.json`.

use std::path::Path;

use serde::Deserialize;

/// Top-level `algod-rust.toml` schema.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AlgodRustConfig {
    /// Settings for the REST API server (`participate --rest-listen …`).
    pub rest: Option<RestConfig>,

    /// P2P/hybrid transport selection (`participate --enable-p2p …`).
    /// Mirrors go-algorand's `config.Local` P2P fields — see
    /// [`P2pConfig`].
    pub p2p: Option<P2pConfig>,
}

/// REST API server settings. Mirrors the CLI flags on the `participate`
/// subcommand. Fields are applied as defaults when the corresponding
/// CLI flag is unset.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RestConfig {
    /// Socket address to bind (e.g. `127.0.0.1:8080`).
    pub listen: Option<String>,

    /// Data directory for `algod.token` / `algod.admin.token` /
    /// `algod.net`.
    pub data_dir: Option<std::path::PathBuf>,

    /// Override for the public API token. Usually omitted so the server
    /// reads from `<data_dir>/algod.token`.
    pub api_token: Option<String>,

    /// Override for the admin API token. Usually omitted so the server
    /// reads from `<data_dir>/algod.admin.token`.
    pub admin_token: Option<String>,

    /// Path to `genesis.json`. Defaults to `<data_dir>/genesis.json`
    /// when unset.
    pub genesis_path: Option<std::path::PathBuf>,

    /// Bounded admission window for
    /// `POST /v2/transactions/async` (see
    /// [`AlgodNodeInterface::with_async_backlog_capacity`]). Defaults
    /// to `DEFAULT_ASYNC_BACKLOG_SIZE` (26 000) when unset — matching
    /// go-algorand's `TxBacklogSize`. Operators on resource-constrained
    /// hosts may want to lower this; busy relays may raise it.
    ///
    /// [`AlgodNodeInterface::with_async_backlog_capacity`]: crate::node_interface_impl::AlgodNodeInterface::with_async_backlog_capacity
    pub async_backlog_size: Option<usize>,
}

/// P2P/hybrid transport settings. Mirrors go-algorand's `config.Local`
/// fields `EnableP2P`, `EnableP2PHybridMode`, `P2PPersistPeerID`
/// (`../go-algorand/config/localTemplate.go`), plus a bootstrap-peer list
/// and listen address for the libp2p transport (`algo-p2p`). Fields are
/// applied as defaults when the corresponding CLI flag on `participate`
/// is unset; see [`crate::commands::p2p_transport::P2pOptions::resolve`].
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct P2pConfig {
    /// Enable the libp2p P2P transport. Go: `EnableP2P`.
    pub enable_p2p: bool,

    /// Run both the WS-gossip and libp2p P2P stacks simultaneously.
    /// Takes precedence over `enable_p2p` alone, matching go's doc
    /// comment on `EnableP2PHybridMode`: "When both EnableP2P and
    /// EnableP2PHybridMode are set, EnableP2PHybridMode takes
    /// precedence." Go: `EnableP2PHybridMode`.
    pub enable_p2p_hybrid_mode: bool,

    /// Persist the libp2p node identity's private key to disk so the
    /// PeerId is stable across restarts. Go: `P2PPersistPeerID`.
    pub p2p_persist_peer_id: bool,

    /// Multiaddrs to dial as bootstrap peers for DHT discovery and
    /// gossipsub mesh formation (e.g.
    /// `"/ip4/1.2.3.4/tcp/4190/p2p/12D3KooW..."`).
    pub p2p_bootstrap_peers: Vec<String>,

    /// Listen multiaddr for the libp2p P2P transport (e.g.
    /// `"/ip4/0.0.0.0/tcp/4190"`). Unset means outbound-only P2P
    /// participation — no inbound P2P listener.
    pub p2p_listen_address: Option<String>,
}

impl AlgodRustConfig {
    /// Read and parse a config file. Returns `Ok(Default)` (empty
    /// config) when `path` is `None` — callers fall back to CLI flags.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let bytes = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read algod-rust config at {}: {e}",
                path.display()
            )
        })?;
        let cfg: Self = toml::from_str(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse algod-rust config at {}: {e}",
                path.display()
            )
        })?;
        Ok(cfg)
    }

    /// Borrow the REST section if present. Returns `None` when either
    /// the `[rest]` table is absent from the TOML or the config itself
    /// was never loaded.
    pub fn rest(&self) -> Option<&RestConfig> {
        self.rest.as_ref()
    }

    /// Borrow the `[p2p]` section if present.
    pub fn p2p(&self) -> Option<&P2pConfig> {
        self.p2p.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_path_returns_empty_config() {
        let cfg = AlgodRustConfig::load(None).expect("none is ok");
        assert!(cfg.rest().is_none());
    }

    #[test]
    fn missing_file_surfaces_as_error() {
        let err =
            AlgodRustConfig::load(Some(Path::new("/this/path/does/not/exist/algod-rust.toml")))
                .unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compatibility() {
        // A TOML with a future `[agreement]` section should still load
        // cleanly as long as the schema uses `#[serde(default)]`.
        let mut tmp = tempfile_stub("unknown-fields.toml");
        writeln!(tmp, r#"[agreement]"#).unwrap();
        writeln!(tmp, r#"proposer_timeout_ms = 4200"#).unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, r#"[rest]"#).unwrap();
        writeln!(tmp, r#"listen = "127.0.0.1:7777""#).unwrap();
        tmp.flush().unwrap();
        let cfg = AlgodRustConfig::load(Some(tmp.path())).expect("parses");
        let rest = cfg.rest().expect("rest section present");
        assert_eq!(rest.listen.as_deref(), Some("127.0.0.1:7777"));
    }

    #[test]
    fn rest_block_round_trips_every_field() {
        let mut tmp = tempfile_stub("rest-block.toml");
        writeln!(tmp, r#"[rest]"#).unwrap();
        writeln!(tmp, r#"listen = "0.0.0.0:8080""#).unwrap();
        writeln!(tmp, r#"data_dir = "/srv/algod""#).unwrap();
        writeln!(tmp, r#"api_token = "api-abc""#).unwrap();
        writeln!(tmp, r#"admin_token = "admin-xyz""#).unwrap();
        writeln!(tmp, r#"genesis_path = "/srv/algod/genesis.json""#).unwrap();
        tmp.flush().unwrap();
        let cfg = AlgodRustConfig::load(Some(tmp.path())).expect("parses");
        let rest = cfg.rest().unwrap();
        assert_eq!(rest.listen.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(rest.data_dir.as_deref(), Some(Path::new("/srv/algod")));
        assert_eq!(rest.api_token.as_deref(), Some("api-abc"));
        assert_eq!(rest.admin_token.as_deref(), Some("admin-xyz"));
        assert_eq!(
            rest.genesis_path.as_deref(),
            Some(Path::new("/srv/algod/genesis.json"))
        );
    }

    #[test]
    fn p2p_block_round_trips_every_field() {
        let mut tmp = tempfile_stub("p2p-block.toml");
        writeln!(tmp, r#"[p2p]"#).unwrap();
        writeln!(tmp, r#"enable_p2p = true"#).unwrap();
        writeln!(tmp, r#"enable_p2p_hybrid_mode = true"#).unwrap();
        writeln!(tmp, r#"p2p_persist_peer_id = true"#).unwrap();
        writeln!(
            tmp,
            r#"p2p_bootstrap_peers = ["/ip4/1.2.3.4/tcp/4190/p2p/12D3KooWExample"]"#
        )
        .unwrap();
        writeln!(tmp, r#"p2p_listen_address = "/ip4/0.0.0.0/tcp/4190""#).unwrap();
        tmp.flush().unwrap();
        let cfg = AlgodRustConfig::load(Some(tmp.path())).expect("parses");
        let p2p = cfg.p2p().expect("p2p section present");
        assert!(p2p.enable_p2p);
        assert!(p2p.enable_p2p_hybrid_mode);
        assert!(p2p.p2p_persist_peer_id);
        assert_eq!(
            p2p.p2p_bootstrap_peers,
            vec!["/ip4/1.2.3.4/tcp/4190/p2p/12D3KooWExample".to_string()]
        );
        assert_eq!(
            p2p.p2p_listen_address.as_deref(),
            Some("/ip4/0.0.0.0/tcp/4190")
        );
    }

    #[test]
    fn missing_p2p_section_is_none() {
        let cfg = AlgodRustConfig::load(None).expect("none is ok");
        assert!(cfg.p2p().is_none());
    }

    /// Extremely small temp-file shim so we don't pull in `tempfile`
    /// just for tests. The path is under the system temp dir and the
    /// file is deleted on drop via `std::fs::remove_file` in the tests'
    /// own cleanup — adequate for these single-threaded parser tests.
    struct TmpFile {
        path: std::path::PathBuf,
        file: std::fs::File,
    }

    impl TmpFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl std::io::Write for TmpFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.file.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    fn tempfile_stub(name: &str) -> TmpFile {
        let mut path = std::env::temp_dir();
        // Add the process ID so concurrent test runs don't clobber each other.
        path.push(format!("algod-rust-test-{}-{}", std::process::id(), name));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open temp file");
        TmpFile { path, file }
    }
}
