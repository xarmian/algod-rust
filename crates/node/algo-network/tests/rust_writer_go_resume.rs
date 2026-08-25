//! Phase B acceptance gate (TASK-127 / PLAN-36) — Rust writer, Go resumer.
//!
//! Demonstrates that go-algorand can boot against a tracker DB + block
//! DB produced exclusively by `algod-rust` and continue reading the last
//! Rust-written round without schema or migration errors. This is the
//! end-to-end signal that the Phase B writer-side work
//! (`canonical_encode_*` round-trips, no Rust-only schema leakage)
//! actually produces a Go-compatible data dir.
//!
//! The test itself is a thin Rust harness that shells out to
//! `ops/mixed-cluster/scripts/handoff-rust-to-go.sh`. Splitting the
//! orchestration into a stand-alone bash script means humans can
//! reproduce the handoff by hand (`bash ops/mixed-cluster/scripts/
//! handoff-rust-to-go.sh`) without needing to drive cargo, while the
//! Rust test still gates CI / `cargo test` invocations cleanly.
//!
//! ## Running
//!
//! ```bash
//! # Default: 20-round handoff against the existing 3-node Go cluster.
//! MIXED_CLUSTER=1 cargo test -p algo-network --test rust_writer_go_resume -- --ignored --nocapture
//!
//! # Larger handoff (50 rounds):
//! MIXED_CLUSTER=1 HANDOFF_ROUNDS=50 cargo test -p algo-network \
//!     --test rust_writer_go_resume -- --ignored --nocapture
//! ```
//!
//! ## Prerequisites
//!
//! * Docker + Docker Compose v2
//! * `algorand/algod:4.7.0-stable` image available locally (the script
//!   pulls it if missing)
//! * `sqlite3`, `jq`, `curl`, `xxd` on PATH
//! * Built `algod-rust` binary (the script runs `cargo build --release`
//!   itself)
//!
//! ## Why `#[ignore]` + env-gated
//!
//! End-to-end handoffs take 3-5 minutes (Go cluster bootstrap + Rust
//! sync + Go re-boot) and require Docker, neither of which belongs in
//! the default `cargo test --workspace` path.

use std::path::PathBuf;
use std::process::Command;

/// Returns the repo root by walking up from this test file's directory
/// until we find the workspace `Cargo.toml`. Cargo sets
/// `CARGO_MANIFEST_DIR` to the crate dir; the workspace root is two
/// levels up (`crates/node/algo-network` -> repo root).
fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crate_dir.join("../../.."))
}

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER"), Ok(v) if !v.is_empty() && v != "0")
}

#[test]
#[ignore = "requires MIXED_CLUSTER=1 + Docker + algorand/algod:4.7.0-stable image"]
fn rust_writer_go_resume_handoff() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: rust_writer_go_resume_handoff requires MIXED_CLUSTER=1 (and Docker). \
             Run with:\n  \
             MIXED_CLUSTER=1 cargo test -p algo-network --test rust_writer_go_resume \
             -- --ignored --nocapture"
        );
        return;
    }

    let root = repo_root();
    let script = root
        .join("ops")
        .join("mixed-cluster")
        .join("scripts")
        .join("handoff-rust-to-go.sh");
    assert!(
        script.exists(),
        "expected handoff script at {}",
        script.display()
    );

    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        // Inherit stdio so test output shows the script's progress live.
        .status()
        .expect("failed to spawn handoff-rust-to-go.sh");

    assert!(
        status.success(),
        "handoff script exited with {:?} — see preserved $HANDOFF_DIR in the output above",
        status.code()
    );
}
