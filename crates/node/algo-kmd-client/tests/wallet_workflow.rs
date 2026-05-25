//! End-to-end happy path: spawn `kmd-rust serve` against a fresh
//! data dir and drive the wallet workflow (create → init → rename
//! → release) through [`KmdClient`].
//!
//! Mirrors the spawn-server / wait-for-port / SIGTERM-on-drop pattern
//! from `crates/node/algo-kmd/tests/rest_interop_test.rs` so the
//! same operational invariants apply (Unix-only, requires a writable
//! tmpdir, picks an ephemeral port via kmd-rust's auto-bind).
//!
//! No `MIXED_CLUSTER` gate — this exercises pure Rust↔Rust and is
//! cheap enough to keep in the default test run.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_kmd_client::{KmdClient, KmdError};

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
        .expect("invoke cargo build");
    assert!(status.success(), "cargo build -p kmd-rust failed");
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = root.join("target").join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found under {}/target", root.display());
}

fn write_minimal_config(data_dir: &Path) {
    // Match the config used by algo-kmd's rest_interop_test.rs — the
    // insecure scrypt params keep create/init under a second, and
    // `allow_unsafe_scrypt: true` is required for N=1024.
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {
                "scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1},
                "allow_unsafe_scrypt": true,
            },
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        data_dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_for_listening(data_dir: &Path, timeout: Duration) -> Result<(String, String), String> {
    let net_path = data_dir.join("kmd.net");
    let token_path = data_dir.join("kmd.token");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let (Ok(net), Ok(tok)) = (
            std::fs::read_to_string(&net_path),
            std::fs::read_to_string(&token_path),
        ) {
            let net = net.trim().to_string();
            let tok = tok.trim().to_string();
            if !net.is_empty() && !tok.is_empty() {
                return Ok((net, tok));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "kmd.net / kmd.token never appeared at {}",
        data_dir.display()
    ))
}

fn send_sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

/// RAII guard that SIGTERMs the spawned kmd-rust process when dropped
/// so test failures don't leak child processes.
struct KmdGuard(Child);

impl Drop for KmdGuard {
    fn drop(&mut self) {
        send_sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn spawn_kmd(data_dir: &Path) -> (KmdGuard, String, String) {
    write_minimal_config(data_dir);
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    let (net, tok) = poll_for_listening(data_dir, Duration::from_secs(20))
        .expect("kmd-rust failed to start within 20s");
    (guard, net, tok)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[test]
fn create_init_rename_release_happy_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        // versions: unauthenticated GET — sanity check the spawn.
        let v = client.versions().await.expect("versions");
        assert!(
            !v.versions.is_empty(),
            "versions returned at least one entry"
        );

        // create wallet
        let create = client
            .create_wallet("integ-wallet", "sqlite", "secret123", [0u8; 32])
            .await
            .expect("create");
        let wallet_id = create.wallet.id.clone();
        assert!(!wallet_id.is_empty(), "create returned a wallet id");
        assert_eq!(create.wallet.name, "integ-wallet");

        // list_wallets sees the new wallet
        let listed = client.list_wallets().await.expect("list");
        assert!(
            listed.wallets.iter().any(|w| w.id == wallet_id),
            "list_wallets must include the created wallet id {wallet_id}; got {:?}",
            listed.wallets,
        );

        // init wallet → handle
        let init = client
            .init_wallet(&wallet_id, "secret123")
            .await
            .expect("init");
        let handle = init.wallet_handle_token.clone();
        assert!(!handle.is_empty(), "init returned a handle");

        // wallet_info round-trips
        let info = client.wallet_info(&handle).await.expect("info");
        assert_eq!(info.wallet_handle.wallet.id, wallet_id);

        // rename
        client
            .rename_wallet(&wallet_id, "renamed", "secret123")
            .await
            .expect("rename");
        let listed = client.list_wallets().await.expect("list after rename");
        let found = listed
            .wallets
            .iter()
            .find(|w| w.id == wallet_id)
            .expect("wallet still present after rename");
        assert_eq!(found.name, "renamed");

        // release handle
        client
            .release_wallet_handle(&handle)
            .await
            .expect("release");

        // Using the released handle should now produce an Api error
        // with a non-empty server-side message.
        let after = client.wallet_info(&handle).await;
        match after {
            Err(KmdError::Api { message, .. }) => {
                assert!(
                    !message.is_empty(),
                    "released handle must produce a non-empty error message"
                );
            }
            other => panic!("expected KmdError::Api after release, got {other:?}"),
        }
    });
}

#[test]
fn invalid_token_surfaces_api_error_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, _real_tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, "wrong-token-not-the-real-one").expect("client");

    rt().block_on(async {
        let err = client
            .list_wallets()
            .await
            .expect_err("must reject bad token");
        // kmd's auth middleware sends back an envelope with the
        // wrong-token message rather than a bare HTTP 401, so we
        // surface it as KmdError::Api. (If the middleware ever
        // changes to plain text, this would become KmdError::Status —
        // either signals the failure correctly.)
        match err {
            KmdError::Api { message, .. } => {
                assert!(
                    !message.is_empty(),
                    "wrong-token error must carry a message"
                );
            }
            KmdError::Status { status, .. } => {
                assert!(
                    status == 401 || status == 403,
                    "expected 401/403, got {status}",
                );
            }
            other => panic!("expected Api or Status error for wrong token, got {other:?}"),
        }
    });
}

#[test]
fn unknown_driver_surfaces_api_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_guard, net, tok) = spawn_kmd(tmp.path());
    let client = KmdClient::new(&net, &tok).expect("client");

    rt().block_on(async {
        let err = client
            .create_wallet("foo", "definitely-not-a-driver", "pw", [0u8; 32])
            .await
            .expect_err("unknown driver must fail");
        match err {
            KmdError::Api { message, .. } => {
                assert!(!message.is_empty(), "unknown driver must carry a message");
            }
            other => panic!("expected KmdError::Api for unknown driver, got {other:?}"),
        }
    });
}
