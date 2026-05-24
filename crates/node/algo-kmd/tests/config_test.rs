//! Integration tests for `algo_kmd::config` against a Go-shaped fixture.
//!
//! The fixture in `tests/fixtures/kmd_config_default.json` reflects what
//! `codecs.SaveObjectToFile` writes for `DefaultConfig("/tmp/data")` in
//! go-algorand v4.5.1-stable
//! (`daemon/kmd/config/config.go:73–92`, `:131–138`).

use algo_kmd::{
    load_kmd_config, save_kmd_config, KMDConfig, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R, DEFAULT_SESSION_LIFETIME_SECS, KMD_CONFIG_EXAMPLE_FILENAME,
    KMD_CONFIG_FILENAME,
};
use tempfile::TempDir;

const GO_FIXTURE: &str = include_str!("fixtures/kmd_config_default.json");

#[test]
fn parses_go_default_fixture() {
    let cfg: KMDConfig =
        serde_json::from_str(GO_FIXTURE).expect("Go fixture must parse into KMDConfig");
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
    assert!(!cfg.driver_config.sqlite.unsafe_scrypt);
    assert!(cfg.driver_config.sqlite.wallets_dir.is_empty());
    assert!(!cfg.driver_config.ledger.disable);
    assert!(cfg.address.is_empty());
    assert!(!cfg.allow_header_pna);
}

#[test]
fn partial_json_merges_with_defaults() {
    // Go's json.Unmarshal onto a pre-populated struct only overwrites fields
    // present in the JSON. Verify that serde achieves the same via per-field
    // defaults.
    let partial = br#"{"session_lifetime_secs": 120}"#;
    let cfg: KMDConfig = serde_json::from_slice(partial).unwrap();
    assert_eq!(cfg.session_lifetime_secs, 120);
    assert_eq!(
        cfg.driver_config.sqlite.scrypt_params.scrypt_n,
        DEFAULT_SCRYPT_N
    );
    assert_eq!(
        cfg.driver_config.sqlite.scrypt_params.scrypt_r,
        DEFAULT_SCRYPT_R
    );
}

#[test]
fn partial_scrypt_merges_with_defaults() {
    // Only one scrypt field set; others must retain Go defaults.
    let partial = br#"{"drivers": {"sqlite": {"scrypt": {"scrypt_n": 1024}}}}"#;
    let cfg: KMDConfig = serde_json::from_slice(partial).unwrap();
    assert_eq!(cfg.driver_config.sqlite.scrypt_params.scrypt_n, 1024);
    assert_eq!(
        cfg.driver_config.sqlite.scrypt_params.scrypt_r,
        DEFAULT_SCRYPT_R
    );
    assert_eq!(
        cfg.driver_config.sqlite.scrypt_params.scrypt_p,
        DEFAULT_SCRYPT_P
    );
}

#[test]
fn load_writes_example_when_missing() {
    let dir = TempDir::new().unwrap();
    let cfg = load_kmd_config(dir.path()).unwrap();
    assert_eq!(cfg.session_lifetime_secs, DEFAULT_SESSION_LIFETIME_SECS);
    assert_eq!(cfg.data_dir, dir.path());

    let example = dir.path().join(KMD_CONFIG_EXAMPLE_FILENAME);
    assert!(
        example.exists(),
        "example file should be written when config is missing"
    );

    // The example file itself must parse cleanly.
    let example_bytes = std::fs::read(&example).unwrap();
    let _: KMDConfig = serde_json::from_slice(&example_bytes).unwrap();
}

#[test]
fn save_then_load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let mut cfg = KMDConfig::defaults(dir.path());
    cfg.session_lifetime_secs = 999;
    cfg.driver_config.sqlite.scrypt_params.scrypt_n = 1024;
    cfg.driver_config.sqlite.unsafe_scrypt = true;
    save_kmd_config(dir.path(), &cfg).unwrap();

    let on_disk = dir.path().join(KMD_CONFIG_FILENAME);
    assert!(on_disk.exists());

    let loaded = load_kmd_config(dir.path()).unwrap();
    assert_eq!(loaded.session_lifetime_secs, 999);
    assert_eq!(loaded.driver_config.sqlite.scrypt_params.scrypt_n, 1024);
    assert!(loaded.driver_config.sqlite.unsafe_scrypt);
}

#[test]
fn save_format_matches_go_byte_for_byte() {
    // Go's codecs.SaveObjectToFile uses tab indent (util/codecs/json.go:35)
    // and json.Encoder.Encode appends a trailing newline. A nil []string
    // marshals as null. The fixture reflects all three; saving the default
    // config under kmd-rust must produce identical bytes so a file written
    // by either implementation reads cleanly under the other.
    let dir = TempDir::new().unwrap();
    let cfg = KMDConfig::defaults(dir.path());
    save_kmd_config(dir.path(), &cfg).unwrap();
    let written = std::fs::read_to_string(dir.path().join(KMD_CONFIG_FILENAME)).unwrap();
    assert_eq!(
        written, GO_FIXTURE,
        "kmd-rust's serialization must match Go's byte-for-byte"
    );
}

#[test]
fn load_rejects_relative_wallets_dir() {
    let dir = TempDir::new().unwrap();
    let bad = br#"{"drivers": {"sqlite": {"wallets_dir": "relative/path"}}}"#;
    std::fs::write(dir.path().join(KMD_CONFIG_FILENAME), bad).unwrap();
    let err = load_kmd_config(dir.path()).unwrap_err();
    assert!(
        matches!(err, algo_kmd::Error::SQLiteWalletNotAbsolute),
        "expected SQLiteWalletNotAbsolute, got {err:?}"
    );
}
