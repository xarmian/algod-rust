//! `goal-rust account importrootkey` E2E (TASK-239 / B7). Pre-stages
//! two synthetic .rootkey SQLite files in the data dir's <gid>
//! subdir, runs the leaf, and asserts:
//! - both addresses appear via the kmd-rust client's list_keys
//! - the Imported N keys footer pluralizes correctly
//! - corrupt files are silently skipped, valid ones still import
//! - empty key dir prints `Imported 0 keys`

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn kmd_rust_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", "kmd-rust"])
        .current_dir(&root)
        .status()
        .expect("cargo build kmd-rust");
    assert!(status.success());
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = root.join("target").join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found");
}

fn write_kmd_config(dir: &Path) {
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {"scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1}, "allow_unsafe_scrypt": true},
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_ready(dir: &Path) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (
            std::fs::read_to_string(dir.join("kmd.net")),
            std::fs::read_to_string(dir.join("kmd.token")),
        ) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("kmd-rust never ready".into())
}

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct KmdGuard(Child);
impl Drop for KmdGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn setup_data_dir() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    let kmd = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    ).unwrap();
    let key_dir = dd.join("testnet-v1");
    std::fs::create_dir_all(&key_dir).unwrap();
    (tmp, dd, kmd, key_dir)
}

fn spawn_kmd(kmd_dir: &Path) -> KmdGuard {
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let g = KmdGuard(child);
    poll_ready(kmd_dir).expect("ready");
    g
}

fn create_default_wallet(dd: &Path) {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(["wallet", "new", "w", "-w", "pw", "--no-display-seed"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("wallet new");
    assert!(
        out.status.success(),
        "wallet new: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Build a synthetic <name>.rootkey SQLite file at `key_dir`. Returns
/// the 32-byte pubkey for assertion. The msgpack blob shape matches
/// Go's `crypto.SignatureSecrets.MarshalMsg` exactly:
/// { "SK": <64 bytes>, "SignatureVerifier": <32 bytes> }.
fn write_synthetic_rootkey(key_dir: &Path, name: &str, seed_byte: u8) -> [u8; 32] {
    let seed = [seed_byte; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pubkey: [u8; 32] = signing.verifying_key().to_bytes();
    let mut sk = [0u8; 64];
    sk[..32].copy_from_slice(&seed);
    sk[32..].copy_from_slice(&pubkey);
    let mut blob = Vec::new();
    rmp::encode::write_map_len(&mut blob, 2).unwrap();
    rmp::encode::write_str(&mut blob, "SK").unwrap();
    rmp::encode::write_bin(&mut blob, &sk).unwrap();
    rmp::encode::write_str(&mut blob, "SignatureVerifier").unwrap();
    rmp::encode::write_bin(&mut blob, &pubkey).unwrap();

    let path = key_dir.join(format!("{name}.rootkey"));
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE RootAccount (data BLOB);")
        .unwrap();
    conn.execute("INSERT INTO RootAccount (data) VALUES (?1)", [&blob])
        .unwrap();
    drop(conn);
    pubkey
}

fn pubkey_to_address(pk: &[u8; 32]) -> String {
    use data_encoding::BASE32_NOPAD;
    use sha2::{Digest, Sha512_256};
    let hash = Sha512_256::digest(pk);
    let mut payload = [0u8; 36];
    payload[..32].copy_from_slice(pk);
    payload[32..].copy_from_slice(&hash[28..32]);
    BASE32_NOPAD.encode(&payload)
}

#[test]
fn importrootkey_imports_every_rootkey_in_data_dir() {
    let (_t, dd, kmd_dir, key_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let pk1 = write_synthetic_rootkey(&key_dir, "alpha", 0x11);
    let pk2 = write_synthetic_rootkey(&key_dir, "beta", 0x22);
    let addr1 = pubkey_to_address(&pk1);
    let addr2 = pubkey_to_address(&pk2);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "importrootkey: {stdout:?}, {stderr:?}"
    );
    assert!(
        stdout.contains(&format!("Imported {addr1}")),
        "stdout must report alpha addr; got {stdout:?}",
    );
    assert!(
        stdout.contains(&format!("Imported {addr2}")),
        "stdout must report beta addr; got {stdout:?}",
    );
    // Plural-form rule: 2 keys → `keys`.
    assert!(
        stdout.contains("Imported 2 keys"),
        "stdout footer must pluralize; got {stdout:?}",
    );
}

#[test]
fn importrootkey_pluralization_singular_for_one_key() {
    let (_t, dd, kmd_dir, key_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    write_synthetic_rootkey(&key_dir, "solo", 0x33);
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    // 1 key → `Imported 1 key` (no trailing `s`).
    assert!(
        stdout.contains("Imported 1 key\n"),
        "singular pluralization must drop the `s`; got {stdout:?}",
    );
}

#[test]
fn importrootkey_empty_directory_prints_imported_zero_keys() {
    let (_t, dd, kmd_dir, _kd) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.contains("Imported 0 keys"),
        "empty key dir must emit `Imported 0 keys`; got {stdout:?}",
    );
}

#[test]
fn importrootkey_u_with_empty_dir_does_not_create_default_wallet() {
    // Codex round-3 finding: Go opens the wallet handle inside the
    // per-file loop AFTER restoring a rootkey, so an empty key dir
    // must NOT auto-create `unencrypted-default-wallet`.
    use algo_kmd_client::KmdClient;
    let (_t, dd, kmd_dir, _kd) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    // No wallets at all + no .rootkey files.

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "-u"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "must exit 0 on empty dir");
    assert!(stdout.contains("Imported 0 keys"));

    // Verify no `unencrypted-default-wallet` was created — query kmd
    // directly so we don't depend on goal-rust's own listing.
    let net = std::fs::read_to_string(kmd_dir.join("kmd.net")).unwrap();
    let tok = std::fs::read_to_string(kmd_dir.join("kmd.token")).unwrap();
    let client = KmdClient::new(net.trim(), tok.trim()).expect("client");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let wallets = rt.block_on(client.list_wallets()).expect("list_wallets");
    assert!(
        !wallets
            .wallets
            .iter()
            .any(|w| w.name == "unencrypted-default-wallet"),
        "empty .rootkey dir must NOT trigger unencrypted-default-wallet creation; got {:?}",
        wallets.wallets,
    );
}

#[test]
fn importrootkey_unencrypted_wallet_flag_auto_creates_default_wallet() {
    // No `wallet new` pre-step — Go's GetUnencryptedWalletHandle must
    // create `unencrypted-default-wallet` on demand
    // (libgoal/unencryptedWallet.go:45-85).
    let (_t, dd, kmd_dir, key_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    let pk = write_synthetic_rootkey(&key_dir, "uenc", 0x55);
    let addr = pubkey_to_address(&pk);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "-u"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey -u");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "-u must auto-create unencrypted-default-wallet; stderr={stderr:?}, stdout={stdout:?}",
    );
    assert!(
        stdout.contains(&format!("Imported {addr}")),
        "stdout must report import; got {stdout:?}",
    );
}

#[test]
fn importrootkey_skips_corrupt_files_and_imports_the_rest() {
    let (_t, dd, kmd_dir, key_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Valid one + a corrupt file with the .rootkey extension.
    let pk = write_synthetic_rootkey(&key_dir, "good", 0x44);
    let addr = pubkey_to_address(&pk);
    std::fs::write(
        key_dir.join("broken.rootkey"),
        b"not a sqlite database at all",
    )
    .unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "importrootkey", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("importrootkey");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "corrupt file must not abort the loop");
    assert!(
        stdout.contains(&format!("Imported {addr}")),
        "valid rootkey must still import; got {stdout:?}",
    );
    // Only one key imported → singular footer.
    assert!(stdout.contains("Imported 1 key\n"));
}
