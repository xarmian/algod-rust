//! Issue #470 (Epic 42c) acceptance gate — positive Layer-9 consensus
//! conformance for the Rust node in the 3-Go + 1-Rust mixed cluster.
//!
//! This is the cargo-visible entry point for
//! `ops/mixed-cluster/scripts/consensus-conformance.sh`, which runs
//! cluster-up -> forced period advancement -> a 200+ round soak ->
//! verification (fork-freedom, certificates under both implementations,
//! proposer share against a documented binomial bound, vote-step
//! coverage, cadence, zero Go-side rejections) -> cluster-down, and
//! writes a machine-readable `summary.json`.
//!
//! The orchestration deliberately lives in bash — like
//! `mixed_cluster_participation.rs` — so a human can reproduce a run by
//! hand without driving cargo, while this test still gates it from
//! `cargo test`.
//!
//! ## Running
//!
//! ```bash
//! # Default: 200 rounds.
//! MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
//!     -- --ignored --nocapture
//!
//! # Longer run, keeping the cluster up afterwards for inspection:
//! MIXED_CLUSTER=1 ROUNDS=500 KEEP_CLUSTER=1 cargo test -p algo-network \
//!     --test consensus_conformance -- --ignored --nocapture
//!
//! # Equivalent make entry point:
//! make consensus-cluster-test ROUNDS=200
//! ```
//!
//! ## Prerequisites
//!
//! * Docker + Docker Compose v2, and a sibling `../go-algorand` checkout
//!   at `v4.5.1-stable` (the Go-side certificate authenticator is built
//!   from it inside a `golang:1.25-bookworm` container, which also runs
//!   `make libsodium` — see `tools/cert-authenticate/run-in-docker.sh`).
//! * `algorand/algod:4.5.1-stable` image available locally.
//! * `curl` + `python3` on PATH.
//! * `algo-fork-detector` + `algo-cert-crossverify` built into
//!   `target/debug` (the make target builds them; run
//!   `cargo build -p algo-fork-detector -p algo-cert-crossverify` first
//!   when invoking the test directly).
//!
//! ## Why `#[ignore]` + env-gated
//!
//! A 200-round run costs tens of minutes of wall clock plus Docker image
//! builds for both the Rust node and the Go verifier — neither belongs
//! in the default `cargo test --workspace` path.

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
#[ignore = "requires MIXED_CLUSTER=1 + Docker + a ../go-algorand checkout"]
fn rust_node_passes_positive_consensus_conformance() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: rust_node_passes_positive_consensus_conformance requires \
             MIXED_CLUSTER=1 (and Docker). Run with:\n  \
             MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
             -- --ignored --nocapture"
        );
        return;
    }

    let root = repo_root();
    let script = root
        .join("ops")
        .join("mixed-cluster")
        .join("scripts")
        .join("consensus-conformance.sh");
    assert!(
        script.exists(),
        "expected orchestration script at {}",
        script.display()
    );

    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        // Inherit stdio so per-phase progress streams live.
        .status()
        .expect("failed to spawn consensus-conformance.sh");

    assert!(
        status.success(),
        "consensus-conformance.sh exited with {:?} — read the printed check list \
         and the summary.json it names; rerun with KEEP_CLUSTER=1 to inspect the \
         running cluster",
        status.code()
    );
}
