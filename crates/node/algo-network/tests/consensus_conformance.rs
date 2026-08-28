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
//!   at `v4.6.0-stable` (the Go-side certificate authenticator is built
//!   from it inside a `golang:1.25-bookworm` container, which also runs
//!   `make libsodium` — see `tools/cert-authenticate/run-in-docker.sh`).
//! * `algorand/algod:5.0.0-stable` image available locally.
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

/// Issue #471 (Epic 42d) — restart / rejoin conformance.
///
/// Drives `ops/mixed-cluster/scripts/restart-rejoin.sh`, which takes the
/// Rust node down *while rounds are being produced* and asserts it comes
/// back correctly:
///
/// * **graceful** — `docker restart` (SIGTERM).
/// * **kill** — `docker kill -s KILL`, so recovery actually runs against
///   whatever the async persistence loop had committed to `crash.sqlite`
///   at the instant the process died.
/// * **proposer** — the SIGKILL is timed into a round the node holds a
///   proposer credential for (detected from its own `assembled N proposal
///   message(s) at (round, period)` log line).
///
/// Each scenario asserts: rejoin to lockstep within a round budget,
/// resumed attesting, no Go-quorum stall, no fork across all four nodes,
/// and — the safety-critical one — **no equivocation**, checked from both
/// the Rust node's own vote log and go-algorand's
/// `voteTracker: observed an equivocator` detector.
///
/// ## Running
///
/// ```bash
/// # Against an already-running cluster (make consensus-cluster-up first):
/// MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
///     restart -- --ignored --nocapture
///
/// # Just one scenario:
/// MIXED_CLUSTER=1 RESTART_MODE=kill cargo test -p algo-network \
///     --test consensus_conformance restart -- --ignored --nocapture
/// ```
///
/// ## Prerequisites
///
/// The 4-node cluster must already be **up and in lockstep** — this test
/// does not manage cluster lifetime, so a failed run leaves the cluster
/// available for inspection. `algo-fork-detector` must be built into
/// `target/debug`.
#[test]
#[ignore = "requires MIXED_CLUSTER=1 + a running mixed cluster"]
fn rust_node_rejoins_consensus_after_restart() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: rust_node_rejoins_consensus_after_restart requires \
             MIXED_CLUSTER=1 and a running cluster. Run with:\n  \
             make consensus-cluster-up\n  \
             MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
             restart -- --ignored --nocapture"
        );
        return;
    }

    let root = repo_root();
    let script = root
        .join("ops")
        .join("mixed-cluster")
        .join("scripts")
        .join("restart-rejoin.sh");
    assert!(
        script.exists(),
        "expected orchestration script at {}",
        script.display()
    );

    let status = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg(std::env::var("RESTART_MODE").unwrap_or_else(|_| "all".to_string()))
        .current_dir(&root)
        .status()
        .expect("failed to spawn restart-rejoin.sh");

    assert!(
        status.success(),
        "restart-rejoin.sh exited with {:?} — read the printed check list and the \
         restart-summary.json it names. A `no_equivocation_*` failure is a \
         consensus-safety bug, not a flake: treat it as such.",
        status.code()
    );
}
