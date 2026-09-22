// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build script for algo-rest-client.
//!
//! Exposes the short git ref this build was made from as
//! `ALGO_BUILD_GIT_TAG`, consumed by `http_block_fetcher`'s `USER_AGENT_VALUE`.
//!
//! `.git` is not present in the Docker build context (`docker/Dockerfile`
//! only `COPY`s `crates/`, `bin/`, and the Cargo manifests), so a plain
//! `git describe` inside that build always falls back to `"unknown"`. To
//! keep the Docker-built binary's User-Agent identifiable, the Docker build
//! passes the ref in explicitly via the `ALGO_BUILD_GIT_TAG` environment
//! variable (see `docker/Dockerfile`'s `ARG GIT_TAG`/`ENV
//! ALGO_BUILD_GIT_TAG`, set from `.github/workflows/docker-image.yml`); this
//! script prefers that value when present and only shells out to `git` as a
//! fallback for plain `cargo build` runs inside a real checkout.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=ALGO_BUILD_GIT_TAG");

    let tag = std::env::var("ALGO_BUILD_GIT_TAG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            // .git/ lives at the workspace root, not in this crate directory.
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let git_head = std::path::Path::new(&manifest_dir).join("../../../.git/HEAD");
            println!("cargo:rerun-if-changed={}", git_head.display());
            git_output(&["describe", "--tags", "--always", "--dirty"])
        });

    println!("cargo:rustc-env=ALGO_BUILD_GIT_TAG={tag}");
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
