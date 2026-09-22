// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! Shared `build.rs` helper: resolves the short git ref a crate is being
//! built from and emits it as a `cargo:rustc-env` variable.
//!
//! Consumed as a build-dependency by any crate that wants to bake a build
//! identifier (e.g. into a `User-Agent` string) into its compiled output —
//! see `crates/node/algo-rest-api/build.rs`, `crates/node/algo-rest-client/build.rs`,
//! and `crates/node/algo-network/build.rs`.
//!
//! `.git` is not present in the Docker build context (`docker/Dockerfile`
//! only `COPY`s `crates/`, `bin/`, and the Cargo manifests), so a plain `git`
//! invocation inside that build always falls back to `"unknown"`. To keep a
//! Docker-built binary's build ref identifiable, the Docker build passes it
//! in explicitly via an environment variable (see `docker/Dockerfile`'s `ARG
//! GIT_TAG`/`ENV ALGO_BUILD_GIT_TAG`, set from
//! `.github/workflows/docker-image.yml`); [`emit_git_ref_env`] prefers that
//! value when present and only shells out to `git` as a fallback for plain
//! `cargo build` runs inside a real checkout.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the build ref for the crate currently being built and emit it as
/// `cargo:rustc-env=<env_var>=<ref>`, available to that crate's own source
/// via `env!(env_var)`.
///
/// `override_env_var` is checked first (e.g. `ALGO_BUILD_GIT_TAG`, settable
/// by a Docker `ENV`/`ARG`); if unset or empty, falls back to `git describe
/// --tags --always --dirty` run against the workspace's `.git` directory
/// (located by walking up from `CARGO_MANIFEST_DIR`), and finally to
/// `"unknown"` if that also fails (e.g. building outside a git checkout).
pub fn emit_git_ref_env(env_var: &str, override_env_var: &str) {
    println!("cargo:rerun-if-env-changed={override_env_var}");

    let git_ref = std::env::var(override_env_var)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
                .expect("CARGO_MANIFEST_DIR is set by cargo when running build.rs");
            match find_git_head(Path::new(&manifest_dir)) {
                Some(git_head) => {
                    println!("cargo:rerun-if-changed={}", git_head.display());
                    git_output(&["describe", "--tags", "--always", "--dirty"])
                }
                None => "unknown".to_string(),
            }
        });

    println!("cargo:rustc-env={env_var}={git_ref}");
}

/// Emits `cargo:rerun-if-changed=<path-to-.git/HEAD>` for the workspace this
/// `CARGO_MANIFEST_DIR`-rooted crate lives in, if one can be found (a no-op
/// otherwise, e.g. in a Docker build where `.git` was never copied in).
///
/// Useful alongside [`git_output`] for a `build.rs` that computes its own
/// git-derived values directly (rather than via [`emit_git_ref_env`]) but
/// still wants a rebuild whenever `HEAD` moves.
pub fn track_git_head(manifest_dir: &str) {
    if let Some(git_head) = find_git_head(Path::new(manifest_dir)) {
        println!("cargo:rerun-if-changed={}", git_head.display());
    }
}

/// Walk up from `start` looking for a `.git` entry (directory for a normal
/// checkout, file for a worktree/submodule), returning the path to its
/// `HEAD` file for `cargo:rerun-if-changed` tracking. Returns `None` if no
/// `.git` is found before reaching the filesystem root (e.g. a Docker build
/// where `.git` was never copied in).
fn find_git_head(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        let candidate = dir.join(".git");
        if candidate.exists() {
            return Some(candidate.join("HEAD"));
        }
        dir = dir.parent()?;
    }
}

/// Run a git command and return its stdout, trimmed.
/// Returns "unknown" if the command fails (e.g. not in a git repo).
pub fn git_output(args: &[&str]) -> String {
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
