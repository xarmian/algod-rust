//! Cross-impl interop: proves `goal-rust` is wire-compatible with
//! Go's `algod` binary, not just our in-tree algod-rust port.
//!
//! Spawns Go's `algod` against a fresh data dir (devnet genesis from
//! `../go-algorand/installer/genesis/devnet/genesis.json`), then
//! drives `goal-rust node status` and `goal-rust node lastround`
//! against the running daemon, asserting structural Go-format output.
//!
//! Gated on `MIXED_CLUSTER=1` (the canonical algod-rust signal for
//! "you may exec / talk to ../go-algorand"). Unix-only.
//!
//! Usage:
//!
//! ```bash
//! # Default: skips with a friendly note.
//! cargo test -p goal-rust --test algod_interop_test
//!
//! # Full cross-impl run:
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_interop_test
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

/// Workspace root — `<this crate>/../../..`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Build Go's `algod` from `../go-algorand/cmd/algod` and return the
/// path to the binary. Panics on failure with a runnable
/// reproduction. Cached in `target/algod-interop/algod` so repeated
/// test runs don't rebuild.
fn ensure_go_algod() -> PathBuf {
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("algod");
    let goalg = workspace_root().join("../go-algorand");
    assert!(
        goalg.join("cmd/algod").exists(),
        "../go-algorand/cmd/algod not found at {}; this test requires a v4.6.0-stable checkout",
        goalg.display(),
    );
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./cmd/algod")
        .current_dir(&goalg)
        .status()
        .expect("invoke go build");
    assert!(
        status.success(),
        "go build -o {} ./cmd/algod failed; rerun manually for diagnostics: \n\
         cd {} && go build -o {} ./cmd/algod",
        bin.display(),
        goalg.display(),
        bin.display(),
    );
    bin
}

/// Stage a fresh algod data dir with the devnet genesis. We avoid
/// participation keys, peer config, and DNS bootstrap — defaults are
/// fine for a `node status` test (algod listens on 127.0.0.1:0 by
/// default).
fn stage_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let genesis_src = workspace_root().join("../go-algorand/installer/genesis/devnet/genesis.json");
    std::fs::copy(&genesis_src, tmp.path().join("genesis.json"))
        .unwrap_or_else(|e| panic!("copy devnet genesis from {}: {e}", genesis_src.display()));
    // Disable DNS bootstrap and outbound peer attempts so the test
    // stays purely local — algod still happily serves /v2/status
    // without any peers.
    let cfg = serde_json::json!({
        "EndpointAddress": "127.0.0.1:0",
        "DNSBootstrapID": "",
        "ForceFetchTransactions": false,
        "EnableDeveloperAPI": true,
    });
    std::fs::write(
        tmp.path().join("config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    tmp
}

/// Poll for algod's readiness markers, also watching the child
/// process. If algod exits before `algod.net` / `algod.token`
/// appear, surface the captured stdout/stderr so the test reporter
/// shows the actual startup failure (Codex review TASK-230 round 1:
/// the readiness-timeout-only path was hiding errors like
/// "listen tcp 127.0.0.1:0: socket: operation not permitted").
fn poll_for_ready(child: &mut Child, data_dir: &Path) -> Result<(), String> {
    let net = data_dir.join("algod.net");
    let tok = data_dir.join("algod.token");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        // If algod has exited, no point waiting for files it'll
        // never write. Pull its captured streams into the error so
        // the operator sees the actual diagnostic.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "algod exited before readiness (status {status:?}):\n{}",
                drain_child_output(child),
            ));
        }
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // Timeout: kill the child first so its stdout/stderr handles
    // close, then drain.
    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "algod did not write algod.net/algod.token within 60s at {}:\n{}",
        data_dir.display(),
        drain_child_output(child),
    ))
}

/// Read everything that's accumulated on the child's piped stdout +
/// stderr into a single newline-tagged blob suitable for embedding
/// in an `assert!` message.
fn drain_child_output(child: &mut Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut s) = child.stdout.take() {
        let mut tmp = Vec::new();
        let _ = s.read_to_end(&mut tmp);
        if !tmp.is_empty() {
            buf.push_str("[algod stdout]\n");
            buf.push_str(&String::from_utf8_lossy(&tmp));
            buf.push('\n');
        }
    }
    if let Some(mut s) = child.stderr.take() {
        let mut tmp = Vec::new();
        let _ = s.read_to_end(&mut tmp);
        if !tmp.is_empty() {
            buf.push_str("[algod stderr]\n");
            buf.push_str(&String::from_utf8_lossy(&tmp));
            buf.push('\n');
        }
    }
    if buf.is_empty() {
        "(no algod output captured)".to_string()
    } else {
        buf
    }
}

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct AlgodGuard(Child);
impl Drop for AlgodGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn spawn_algod(bin: &Path, data_dir: &Path) -> AlgodGuard {
    // Pipe stdout/stderr so we can surface them on startup failures —
    // dropping to /dev/null hid real errors like
    // "listen tcp 127.0.0.1:0: socket: operation not permitted"
    // (Codex review TASK-230 round 1).
    let mut child = Command::new(bin)
        .args(["-d"])
        .arg(data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn algod");
    if let Err(e) = poll_for_ready(&mut child, data_dir) {
        // Best-effort SIGTERM in case the child is still alive but
        // wedged in some non-readiness state.
        let _ = child.kill();
        let _ = child.wait();
        panic!("algod ready: {e}");
    }
    AlgodGuard(child)
}

#[test]
fn goal_rust_node_status_and_lastround_against_go_algod() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: algod_interop_test requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_interop_test",
        );
        return;
    }
    let go_algod = ensure_go_algod();
    let data_dir = stage_data_dir();
    let _guard = spawn_algod(&go_algod, data_dir.path());

    // node status
    let status_out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "status"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node status");
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    let stderr = String::from_utf8_lossy(&status_out.stderr);
    assert!(
        status_out.status.success(),
        "node status against Go algod failed: exit={:?}\n  stdout={stdout}\n  stderr={stderr}",
        status_out.status.code(),
    );
    assert!(
        stdout.starts_with("Last committed block: "),
        "stdout must start with Go's exact prefix; got {stdout:?}",
    );
    assert!(
        stdout.contains("\nGenesis hash: "),
        "stdout must include `Genesis hash:` line; got {stdout:?}",
    );

    // node lastround → `\d+\n`
    let lr_out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "lastround"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node lastround");
    assert!(
        lr_out.status.success(),
        "node lastround against Go algod failed: exit={:?}, stderr={}",
        lr_out.status.code(),
        String::from_utf8_lossy(&lr_out.stderr),
    );
    let stdout = String::from_utf8_lossy(&lr_out.stdout);
    let trimmed = stdout.trim_end_matches('\n');
    assert!(
        !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()),
        "lastround must print `<round>\\n`; got {stdout:?}",
    );
    assert!(
        stdout.ends_with('\n'),
        "lastround must terminate with a single newline; got {stdout:?}",
    );
}
