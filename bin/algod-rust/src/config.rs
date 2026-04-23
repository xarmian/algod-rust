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
