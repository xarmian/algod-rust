//! KMD configuration types and load/save helpers.
//!
//! Ported from `../go-algorand/daemon/kmd/config/config.go` (v4.5.1-stable).
//! JSON field names and default values match Go byte-for-byte so a
//! `kmd_config.json` written by either implementation can be read by the
//! other.
//!
//! Go reference points cited inline as `config.go:LINE` per project convention
//! [[CONVE-7]] (cross-reference go-algorand for consensus-adjacent code).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Filename of the kmd config inside the data directory.
/// Matches `kmdConfigFilename` (config.go:28).
pub const KMD_CONFIG_FILENAME: &str = "kmd_config.json";

/// Filename of the example config written when no config exists.
/// Matches `kmdConfigExampleFilename` (config.go:29).
pub const KMD_CONFIG_EXAMPLE_FILENAME: &str = "kmd_config.json.example";

/// Default session lifetime in seconds. Matches `defaultSessionLifetimeSecs`
/// (config.go:30).
pub const DEFAULT_SESSION_LIFETIME_SECS: u64 = 60;

/// Default scrypt `N` parameter. Matches `defaultScryptN` (config.go:31).
pub const DEFAULT_SCRYPT_N: i64 = 65536;

/// Default scrypt `r` parameter. Matches `defaultScryptR` (config.go:32).
pub const DEFAULT_SCRYPT_R: i64 = 1;

/// Default scrypt `p` parameter. Matches `defaultScryptP` (config.go:33).
pub const DEFAULT_SCRYPT_P: i64 = 32;

fn default_session_lifetime_secs() -> u64 {
    DEFAULT_SESSION_LIFETIME_SECS
}

fn default_scrypt_n() -> i64 {
    DEFAULT_SCRYPT_N
}

fn default_scrypt_r() -> i64 {
    DEFAULT_SCRYPT_R
}

fn default_scrypt_p() -> i64 {
    DEFAULT_SCRYPT_P
}

/// Treat JSON `null` as `T::default()`. Mirrors Go's `json.Unmarshal`
/// behavior on a pre-populated struct: an explicit `null` for a non-pointer
/// field is a no-op (the field keeps its existing value), so on a struct
/// pre-populated with Go defaults `null` effectively resolves to the
/// default. We replicate that here by deserializing into `Option<T>` and
/// falling back to `T::default()` on `None`.
///
/// For fields whose Go default is *not* the type's zero value
/// (`session_lifetime_secs`, `scrypt_n`, `scrypt_r`, `scrypt_p`), use a
/// per-field helper below so the fallback returns the Go default rather
/// than the numeric zero.
fn null_or_type_default<'de, T, D>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: Deserialize<'de> + Default,
    D: serde::Deserializer<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn null_or_default_session_lifetime<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<u64>::deserialize(deserializer)?.unwrap_or(DEFAULT_SESSION_LIFETIME_SECS))
}

fn null_or_default_scrypt_n<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or(DEFAULT_SCRYPT_N))
}

fn null_or_default_scrypt_r<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or(DEFAULT_SCRYPT_R))
}

fn null_or_default_scrypt_p<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or(DEFAULT_SCRYPT_P))
}

/// Global configuration for kmd.
///
/// Ported from `KMDConfig` (config.go:37). `data_dir` carries Go's
/// `json:"-"` semantics and is never serialized — it is populated by the
/// caller of [`load_kmd_config`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KMDConfig {
    /// Path to the kmd data directory. Skipped on (de)serialization to match
    /// Go's `json:"-"` tag.
    #[serde(skip)]
    pub data_dir: PathBuf,

    #[serde(rename = "drivers", default, deserialize_with = "null_or_type_default")]
    pub driver_config: DriverConfig,

    #[serde(
        rename = "session_lifetime_secs",
        default = "default_session_lifetime_secs",
        deserialize_with = "null_or_default_session_lifetime"
    )]
    pub session_lifetime_secs: u64,

    #[serde(default, deserialize_with = "null_or_type_default")]
    pub address: String,

    /// `[]string` in Go. Go's `json.Marshal` distinguishes a *nil* slice
    /// (writes `null`) from an *empty* slice (writes `[]`); on unmarshal
    /// `null` produces nil and `[]` produces a non-nil empty slice. We
    /// preserve both states via `Option<Vec<String>>` so a config written
    /// by either implementation round-trips byte-stably under the other:
    /// `None` ↔ `null`, `Some(vec)` ↔ JSON array (even when empty).
    #[serde(rename = "allowed_origins", default)]
    pub allowed_origins: Option<Vec<String>>,

    #[serde(
        rename = "allow_header_pna",
        default,
        deserialize_with = "null_or_type_default"
    )]
    pub allow_header_pna: bool,
}

impl Default for KMDConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::new(),
            driver_config: DriverConfig::default(),
            session_lifetime_secs: DEFAULT_SESSION_LIFETIME_SECS,
            address: String::new(),
            // Matches Go: zero-valued KMDConfig has a nil AllowedOrigins,
            // which marshals as `null` — see fixture
            // `tests/fixtures/kmd_config_default.json`.
            allowed_origins: None,
            allow_header_pna: false,
        }
    }
}

/// Per-driver configuration container. Ported from `DriverConfig`
/// (config.go:47).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DriverConfig {
    #[serde(rename = "sqlite", default, deserialize_with = "null_or_type_default")]
    pub sqlite: SQLiteWalletDriverConfig,

    #[serde(rename = "ledger", default, deserialize_with = "null_or_type_default")]
    pub ledger: LedgerWalletDriverConfig,
}

/// SQLite wallet-driver configuration. Ported from
/// `SQLiteWalletDriverConfig` (config.go:53).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SQLiteWalletDriverConfig {
    #[serde(
        rename = "wallets_dir",
        default,
        deserialize_with = "null_or_type_default"
    )]
    pub wallets_dir: String,

    /// Mirrors Go's `UnsafeScrypt bool \`json:"allow_unsafe_scrypt"\``.
    /// Allows running with scrypt parameters below the production minimum;
    /// only intended for tests.
    #[serde(
        rename = "allow_unsafe_scrypt",
        default,
        deserialize_with = "null_or_type_default"
    )]
    pub unsafe_scrypt: bool,

    #[serde(rename = "scrypt", default, deserialize_with = "null_or_type_default")]
    pub scrypt_params: ScryptParams,
}

/// Ledger hardware-wallet driver configuration. Ported from
/// `LedgerWalletDriverConfig` (config.go:60).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LedgerWalletDriverConfig {
    #[serde(default, deserialize_with = "null_or_type_default")]
    pub disable: bool,
}

/// Scrypt KDF parameters. Ported from `ScryptParams` (config.go:66).
///
/// Field defaults match Go's `defaultConfig` (config.go:78–92) on a
/// per-field basis so a partial `kmd_config.json` (only some scrypt fields
/// set) still merges with defaults the way Go's `json.Unmarshal` does on a
/// pre-populated struct.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScryptParams {
    #[serde(
        rename = "scrypt_n",
        default = "default_scrypt_n",
        deserialize_with = "null_or_default_scrypt_n"
    )]
    pub scrypt_n: i64,

    #[serde(
        rename = "scrypt_r",
        default = "default_scrypt_r",
        deserialize_with = "null_or_default_scrypt_r"
    )]
    pub scrypt_r: i64,

    #[serde(
        rename = "scrypt_p",
        default = "default_scrypt_p",
        deserialize_with = "null_or_default_scrypt_p"
    )]
    pub scrypt_p: i64,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            scrypt_n: DEFAULT_SCRYPT_N,
            scrypt_r: DEFAULT_SCRYPT_R,
            scrypt_p: DEFAULT_SCRYPT_P,
        }
    }
}

impl KMDConfig {
    /// Build the default KMDConfig for a given data directory. Mirrors
    /// `DefaultConfig` (config.go:73).
    pub fn defaults(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            ..Self::default()
        }
    }

    /// Validate the configuration. Mirrors `KMDConfig.Validate`
    /// (config.go:96).
    pub fn validate(&self) -> Result<()> {
        let wallets_dir = &self.driver_config.sqlite.wallets_dir;
        if !wallets_dir.is_empty() && !Path::new(wallets_dir).is_absolute() {
            return Err(Error::SQLiteWalletNotAbsolute);
        }
        Ok(())
    }
}

/// Load the kmd config from `<data_dir>/kmd_config.json`, merging the
/// default config with any fields present in the file. Mirrors
/// `LoadKMDConfig` (config.go:109).
///
/// If the file does not exist, writes `<data_dir>/kmd_config.json.example`
/// (best-effort) and returns the defaults. Errors from writing the example
/// are intentionally swallowed, matching Go behavior (config.go:115–118).
pub fn load_kmd_config(data_dir: impl Into<PathBuf>) -> Result<KMDConfig> {
    let data_dir = data_dir.into();
    let config_path = data_dir.join(KMD_CONFIG_FILENAME);

    match std::fs::read(&config_path) {
        Ok(bytes) => {
            let mut cfg: KMDConfig = serde_json::from_slice(&bytes)?;
            // data_dir is #[serde(skip)] so it is `PathBuf::new()` after
            // deserialization. Restore it from the caller-supplied value to
            // match Go, which keeps DataDir on the pre-populated struct.
            cfg.data_dir = data_dir;
            cfg.validate()?;
            Ok(cfg)
        }
        Err(_) => {
            let cfg = KMDConfig::defaults(&data_dir);
            // Best-effort write of the example file; ignore errors per
            // config.go:115–118.
            let example_path = data_dir.join(KMD_CONFIG_EXAMPLE_FILENAME);
            let _ = write_config_json(&example_path, &cfg);
            Ok(cfg)
        }
    }
}

/// Save the kmd config to `<data_dir>/kmd_config.json`. Mirrors
/// `SaveKMDConfig` (config.go:131).
pub fn save_kmd_config(data_dir: impl AsRef<Path>, cfg: &KMDConfig) -> Result<()> {
    cfg.validate()?;
    let path = data_dir.as_ref().join(KMD_CONFIG_FILENAME);
    write_config_json(&path, cfg)
}

fn write_config_json(path: &Path, cfg: &KMDConfig) -> Result<()> {
    // Match Go's `codecs.NewFormattedJSONEncoder` exactly: tab indent
    // (util/codecs/json.go:35) + trailing newline (json.Encoder.Encode
    // always appends one). Without this, a file written by kmd-rust would
    // not be byte-equal to one written by Go kmd for the same config.
    let mut buf = Vec::with_capacity(256);
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    cfg.serialize(&mut ser)?;
    buf.push(b'\n');
    std::fs::write(path, buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_go_constants() {
        let cfg = KMDConfig::defaults("/tmp/x");
        assert_eq!(cfg.session_lifetime_secs, DEFAULT_SESSION_LIFETIME_SECS);
        assert_eq!(
            cfg.driver_config.sqlite.scrypt_params.scrypt_n,
            DEFAULT_SCRYPT_N
        );
        assert_eq!(
            cfg.driver_config.sqlite.scrypt_params.scrypt_r,
            DEFAULT_SCRYPT_R
        );
        assert_eq!(
            cfg.driver_config.sqlite.scrypt_params.scrypt_p,
            DEFAULT_SCRYPT_P
        );
        assert_eq!(cfg.data_dir, std::path::PathBuf::from("/tmp/x"));
    }

    #[test]
    fn validate_rejects_relative_wallets_dir() {
        // `Path::is_absolute()` requires a drive letter (or UNC prefix) on
        // Windows, so a Unix-style "/abs/path" literal is NOT absolute
        // there; use a path literal that's actually absolute on the
        // platform running the test.
        #[cfg(windows)]
        let abs_path = "C:\\abs\\path";
        #[cfg(not(windows))]
        let abs_path = "/abs/path";

        let mut cfg = KMDConfig::defaults("/tmp/x");
        cfg.driver_config.sqlite.wallets_dir = "relative/path".into();
        assert!(matches!(
            cfg.validate(),
            Err(Error::SQLiteWalletNotAbsolute)
        ));

        cfg.driver_config.sqlite.wallets_dir = abs_path.into();
        assert!(cfg.validate().is_ok());

        cfg.driver_config.sqlite.wallets_dir = String::new();
        assert!(cfg.validate().is_ok());
    }
}
