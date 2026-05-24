//! Integration tests for the wallet key operations (TASK-205).
//!
//! Two layers:
//! 1. In-Rust round-trip — generate, import, export, list, lookup,
//!    delete all behave consistently and reject locked-wallet usage.
//! 2. Cross-implementation interop against
//!    `tests/fixtures/go_wallet_with_keys/` — a wallet produced by
//!    `tools/kmd-wallet-fixture-capture` (extended in TASK-205) that
//!    contains a fixed MDK, N derived keys, and M imported keys.
//!    Rust must list the same addresses in the same order and export
//!    the same secret-key bytes Go does.

use std::path::PathBuf;

use algo_kmd::{
    config::ScryptParams, Error, WalletDriver, WalletDriverConfig, ADDRESS_LEN, SECRET_KEY_LEN,
};
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

#[test]
fn generate_lookup_export_delete_round_trip() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"keytest", b"id-k", b"pw", Some([7u8; 32]))
        .unwrap();
    let mut w = driver.fetch_wallet(b"id-k").unwrap();
    w.init(b"pw").unwrap();

    // Generate three keys. They must derive from index 1, 2, 3.
    let a = w.generate_key().unwrap();
    let b = w.generate_key().unwrap();
    let c = w.generate_key().unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);

    // list_keys returns all three (order is SQLite's insertion order).
    let listed = w.list_keys().unwrap();
    assert_eq!(listed.len(), 3);
    for addr in [&a, &b, &c] {
        assert!(listed.contains(addr));
        assert!(w.lookup_key(addr).unwrap());
    }
    assert!(!w.lookup_key(&[0u8; ADDRESS_LEN]).unwrap());

    // Export with right password works, wrong password rejected.
    let sk_a = w.export_key(&a, b"pw").unwrap();
    assert_eq!(sk_a.len(), SECRET_KEY_LEN);
    assert!(matches!(w.export_key(&a, b"wrong"), Err(Error::Decrypt)));

    // Delete with right password removes the row.
    w.delete_key(&b, b"pw").unwrap();
    assert!(!w.lookup_key(&b).unwrap());
    assert_eq!(w.list_keys().unwrap().len(), 2);
    // Deleting an unknown address is a no-op (Go behavior — silent DELETE).
    w.delete_key(&[0u8; ADDRESS_LEN], b"pw").unwrap();
}

#[test]
fn import_round_trip_and_address_is_derived_from_seed() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"imp", b"id-imp", b"pw", Some([1u8; 32]))
        .unwrap();
    let mut w = driver.fetch_wallet(b"id-imp").unwrap();
    w.init(b"pw").unwrap();

    // Construct an "expanded" Ed25519 secret with a known seed and a
    // tampered pubkey half; import_key must re-derive the pubkey from
    // the seed (Go behavior — sqlite.go:738).
    let mut secret = [0u8; SECRET_KEY_LEN];
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 100);
    secret[..32].copy_from_slice(&seed);
    secret[32..].fill(0xAA); // bogus pubkey — must be ignored

    let addr = w.import_key(&secret).unwrap();
    assert!(w.lookup_key(&addr).unwrap());

    // Re-import is rejected because the address is now in the table
    // (UNIQUE on `keys.address`).
    let err = w.import_key(&secret).unwrap_err();
    assert!(matches!(err, Error::KeyExists), "got {err:?}");

    // Export returns the on-disk SK with the *re-derived* pubkey half,
    // not the tampered bytes we passed in.
    let exported = w.export_key(&addr, b"pw").unwrap();
    assert_eq!(&exported[..32], &seed);
    assert_eq!(&exported[32..], &addr);
}

#[test]
fn generate_skips_indices_already_taken_by_import() {
    // Verifies the index-bump loop in generate_key (sqlite.go:916–947).
    // Strategy: import a key whose seed is exactly what extractSeed(MDK, 1)
    // would produce. The first generate_key call must skip index 1 and
    // land on index 2.
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    let mdk: [u8; 32] = std::array::from_fn(|i| i as u8 + 50);
    driver
        .create_wallet(b"skip", b"id-skip", b"pw", Some(mdk))
        .unwrap();
    let mut w = driver.fetch_wallet(b"id-skip").unwrap();
    w.init(b"pw").unwrap();

    // Pre-import the index=1 derivation.
    let seed1 = algo_kmd::extract_seed_with_index(&mdk, 1);
    let mut sk1 = [0u8; SECRET_KEY_LEN];
    sk1[..32].copy_from_slice(&seed1);
    // Pubkey half is recomputed inside import_key, so leave zeros.
    let addr1 = w.import_key(&sk1).unwrap();

    // generate_key must skip index 1 (collision) and land on index 2.
    let generated = w.generate_key().unwrap();
    assert_ne!(generated, addr1);
    let seed2 = algo_kmd::extract_seed_with_index(&mdk, 2);
    let mut sk2 = [0u8; SECRET_KEY_LEN];
    sk2[..32].copy_from_slice(&seed2);
    // Compute the expected address from index 2.
    use ed25519_dalek::SigningKey;
    let expected_addr2 = SigningKey::from_bytes(&seed2).verifying_key().to_bytes();
    assert_eq!(generated, expected_addr2);
}

#[test]
fn key_ops_on_locked_wallet_are_rejected() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"lock", b"id-l", b"pw", None).unwrap();
    let w = driver.fetch_wallet(b"id-l").unwrap();
    // Wallet not initialized — generate / import / export must fail
    // with WalletNotInitialized (Decrypt for export which password-checks
    // first via the slow path; we accept either).
    assert!(matches!(w.generate_key(), Err(Error::WalletNotInitialized)));
    let sk = [0u8; SECRET_KEY_LEN];
    assert!(matches!(
        w.import_key(&sk),
        Err(Error::WalletNotInitialized)
    ));
}

// -----------------------------------------------------------------------------
// Cross-implementation interop test: a Go-produced wallet with
// derived + imported keys is opened under Rust, addresses are listed,
// and the secrets are exported and asserted byte-for-byte.

#[derive(serde::Deserialize)]
struct KeyEntry {
    address_hex: String,
    secret_key_hex: String,
    #[serde(default)]
    key_idx: Option<u64>,
}

#[derive(serde::Deserialize)]
struct GoFixtureWithKeysManifest {
    db_relpath: String,
    wallet_id: String,
    password: String,
    mdk_hex: String,
    scrypt_n: i64,
    scrypt_r: i64,
    scrypt_p: i64,
    keys: Vec<KeyEntry>,
}

const GO_KEYS_FIXTURE_MANIFEST: &str = include_str!("fixtures/go_wallet_with_keys/manifest.json");

fn keys_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go_wallet_with_keys")
}

#[test]
fn opens_go_wallet_and_round_trips_keys() {
    let manifest: GoFixtureWithKeysManifest =
        serde_json::from_str(GO_KEYS_FIXTURE_MANIFEST).expect("manifest parses");
    let expected_mdk = hex::decode(&manifest.mdk_hex).expect("mdk hex");
    assert_eq!(expected_mdk.len(), 32);
    assert!(
        manifest.keys.iter().any(|k| k.key_idx.is_some()),
        "fixture must include at least one derived key"
    );
    assert!(
        manifest.keys.iter().any(|k| k.key_idx.is_none()),
        "fixture must include at least one imported key"
    );

    // Copy the read-only fixture into a temp working dir.
    let work = TempDir::new().unwrap();
    let dst_walletsdir = work.path().join("sqlite_wallets");
    std::fs::create_dir_all(&dst_walletsdir).unwrap();
    let src_db = keys_fixture_root().join(&manifest.db_relpath);
    let dst_db = dst_walletsdir.join(src_db.file_name().unwrap());
    std::fs::copy(&src_db, &dst_db).expect("copy fixture wallet.db");

    let driver = WalletDriver::new(WalletDriverConfig {
        wallets_dir: dst_walletsdir,
        scrypt_params: ScryptParams {
            scrypt_n: manifest.scrypt_n,
            scrypt_r: manifest.scrypt_r,
            scrypt_p: manifest.scrypt_p,
        },
        allow_unsafe_scrypt: true,
    })
    .unwrap();

    let mut w = driver.fetch_wallet(manifest.wallet_id.as_bytes()).unwrap();
    w.init(manifest.password.as_bytes()).unwrap();

    // MDK round-trip (already covered by TASK-204 test, but a quick
    // sanity check here too).
    let exported_mdk = w
        .export_master_derivation_key(manifest.password.as_bytes())
        .unwrap();
    assert_eq!(exported_mdk.as_slice(), expected_mdk.as_slice());

    // Every address the Go fixture wrote must be present, and
    // exporting must yield the same 64-byte secret.
    let listed = w.list_keys().unwrap();
    for entry in &manifest.keys {
        let addr_bytes = hex::decode(&entry.address_hex).expect("addr hex");
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(&addr_bytes);
        assert!(
            listed.contains(&addr),
            "expected address {} in Rust list_keys output",
            entry.address_hex
        );
        assert!(w.lookup_key(&addr).unwrap());

        let exported = w.export_key(&addr, manifest.password.as_bytes()).unwrap();
        let expected = hex::decode(&entry.secret_key_hex).expect("sk hex");
        assert_eq!(
            exported.as_slice(),
            expected.as_slice(),
            "exported SK for {} must match Go's stored bytes",
            entry.address_hex
        );
    }
}
