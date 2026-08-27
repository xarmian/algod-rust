//! Issue #469 acceptance gate — the Rust node as an active participant
//! in the 3-Go + 1-Rust mixed cluster.
//!
//! Demonstrates that `algod-rust participate`, holding ONLINE stake from
//! a `goal network create` genesis and the `.partkey` that same command
//! generated, runs consensus alongside three go-algorand v4.6.0-stable
//! nodes: all four nodes advance in lockstep, the Rust node's own REST
//! `/v2/status` reports the advancing round, and no Go node logs an
//! agreement-level rejection of a peer message for the whole run.
//!
//! Like `rust_writer_go_resume.rs`, the orchestration lives in a
//! stand-alone bash script so a human can reproduce the run by hand
//! (`bash ops/mixed-cluster/scripts/participation-smoke.sh`) without
//! driving cargo, while this test still gates it from `cargo test`.
//!
//! ## Running
//!
//! ```bash
//! # Default: 30 rounds on the 4-node cluster.
//! MIXED_CLUSTER=1 cargo test -p algo-network --test mixed_cluster_participation \
//!     -- --ignored --nocapture
//!
//! # Longer soak, keeping the cluster up afterwards for inspection:
//! MIXED_CLUSTER=1 SMOKE_ROUNDS=100 KEEP_CLUSTER=1 cargo test -p algo-network \
//!     --test mixed_cluster_participation -- --ignored --nocapture
//! ```
//!
//! ## Prerequisites
//!
//! * Docker + Docker Compose v2
//! * `algorand/algod:4.7.2-stable` image available locally
//! * `curl` + `python3` on PATH
//! * The script builds the `algod-rust` image itself via `start.sh`.
//!
//! ## Why `#[ignore]` + env-gated
//!
//! A 30-round run costs several minutes of wall clock plus a Docker
//! image build, neither of which belongs in the default
//! `cargo test --workspace` path.

use std::path::PathBuf;
use std::process::Command;

/// Repo root: walk up from `CARGO_MANIFEST_DIR` until the workspace
/// `Cargo.toml` + `crates/` pair shows up.
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
#[ignore = "requires MIXED_CLUSTER=1 + Docker + algorand/algod:4.7.2-stable image"]
fn rust_node_participates_in_mixed_cluster() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: rust_node_participates_in_mixed_cluster requires MIXED_CLUSTER=1 \
             (and Docker). Run with:\n  \
             MIXED_CLUSTER=1 cargo test -p algo-network --test mixed_cluster_participation \
             -- --ignored --nocapture"
        );
        return;
    }

    let root = repo_root();
    let script = root
        .join("ops")
        .join("mixed-cluster")
        .join("scripts")
        .join("participation-smoke.sh");
    assert!(
        script.exists(),
        "expected smoke script at {}",
        script.display()
    );

    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        // Inherit stdio so the script's per-round progress streams live.
        .status()
        .expect("failed to spawn participation-smoke.sh");

    assert!(
        status.success(),
        "participation-smoke.sh exited with {:?} — see the log above; rerun with \
         KEEP_CLUSTER=1 to inspect the running cluster",
        status.code()
    );
}
