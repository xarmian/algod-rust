//! Build script for algo-rest-api.
//!
//! Extracts git metadata (commit hash, branch) and Cargo package version
//! at compile time, making them available via environment variables for
//! the `/versions` endpoint.

use std::process::Command;

fn main() {
    // Re-run if git HEAD changes (new commits, branch switches).
    // .git/ lives at workspace root, not in this crate directory.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let git_head = std::path::Path::new(&manifest_dir).join("../../../.git/HEAD");
    println!("cargo:rerun-if-changed={}", git_head.display());

    // Git commit hash
    let commit_hash = git_output(&["rev-parse", "--short=12", "HEAD"]);
    println!("cargo:rustc-env=ALGO_BUILD_COMMIT_HASH={commit_hash}");

    // Git branch name
    let branch = git_output(&["rev-parse", "--abbrev-ref", "HEAD"]);
    println!("cargo:rustc-env=ALGO_BUILD_BRANCH={branch}");
}

/// Run a git command and return its stdout, trimmed.
/// Returns "unknown" if the command fails (e.g. not in a git repo).
fn git_output(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
