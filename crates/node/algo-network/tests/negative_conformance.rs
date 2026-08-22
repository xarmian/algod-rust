//! Layer-9 **negative** consensus conformance (issue #472).
//!
//! The positive suite (#470, `consensus_conformance.rs`) proves a Rust node's
//! *valid* agreement messages are accepted by a Go quorum. This suite proves
//! the converse: a Go node **rejects** a Rust-constructed agreement message
//! that carries exactly one injected fault, and stays healthy afterwards.
//!
//! The four required cases are:
//!
//! 1. bad VRF proof (valid-shaped, does not verify under the account's
//!    registered selection key),
//! 2. wrong committee weight (a credential for a `(round, period, step)` at
//!    which the account wins zero committee seats),
//! 3. wrong OTS domain separation (correct key, wrong domain-separation
//!    prefix on the signed message),
//! 4. malformed proposal (structurally invalid block payload).
//!
//! Message construction and corruption are unit tested without Docker in
//! `crates/tools/algo-agreement-fuzz`. This file only drives the live
//! injection against a real go-algorand node.
//!
//! Run with:
//! ```text
//! MIXED_CLUSTER=1 cargo test -p algo-network --test negative_conformance -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates").is_dir() {
            return dir;
        }
        if !dir.pop() {
            panic!("could not locate repository root from CARGO_MANIFEST_DIR");
        }
    }
}

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER"), Ok(v) if !v.is_empty() && v != "0")
}

/// Drive `ops/mixed-cluster/scripts/negative-conformance.sh`, which brings up
/// the cluster, injects one faulted agreement message per case into
/// `phase6-go-node-1`, and asserts Go rejected each one (peer disconnected
/// with `BadData` and/or a `malformed vote`/`rejected block` log line) while
/// the cluster kept making rounds.
#[test]
#[ignore = "requires MIXED_CLUSTER=1 + Docker"]
fn go_node_rejects_faulted_agreement_messages() {
    if !mixed_cluster_enabled() {
        eprintln!("SKIPPED: set MIXED_CLUSTER=1 to run the negative conformance suite");
        return;
    }

    let root = repo_root();
    let script = root.join("ops/mixed-cluster/scripts/negative-conformance.sh");
    assert!(
        script.exists(),
        "missing negative conformance driver: {}",
        script.display()
    );

    // Pass a repo-relative POSIX path: an absolute Windows path (`C:\...`)
    // reaches Git Bash with its backslashes eaten and cannot be opened.
    let status = Command::new("bash")
        .arg("ops/mixed-cluster/scripts/negative-conformance.sh")
        .current_dir(&root)
        .status()
        .expect("failed to spawn bash for negative-conformance.sh");

    assert!(
        status.success(),
        "negative-conformance.sh failed (exit {:?}): Go did not reject every faulted message, \
         or the cluster did not stay healthy",
        status.code()
    );
}
