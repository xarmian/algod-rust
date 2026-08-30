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

//! Issue #762: the real, go-algorand-authored `docker/config/vfuture-consensus.json`
//! fixture (already used by issue #750's own tests in
//! `consensus_json_load_test.rs`), loaded through the exact same
//! `preload_configurable_consensus_protocols` call bin/algod-rust's startup
//! path uses, must become visible through `consensus_params_for_version`
//! globally -- not just to whatever local variable happened to receive
//! `preload_configurable_consensus_protocols`'s return value (which is all
//! issue #750/PR #761 wired up).
//!
//! Its own integration-test file/process, like
//! `consensus_override_registry_test.rs`, since `install_consensus_overrides`
//! writes a process-global `OnceLock` at most once.

use std::path::PathBuf;

use algo_types::consensus::{
    built_in_consensus_protocols, consensus_params_for_version, install_consensus_overrides,
    preload_configurable_consensus_protocols, CONSENSUS_FUTURE, CONSENSUS_V42,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root must exist")
}

fn vfuture_fixture_path() -> PathBuf {
    repo_root().join("docker/config/vfuture-consensus.json")
}

/// Minimal self-contained tempdir helper (mirrors `consensus_json_load_test.rs`'s).
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempfile_dir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("algo-types-consensus-override-fixture-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

#[test]
fn real_vfuture_fixture_load_is_visible_globally_through_consensus_params_for_version() {
    // ── Regression check first: before any startup simulation, the "future"
    // version must resolve to its pristine built-in definition. Capture the
    // whole pristine table now -- calling `built_in_consensus_protocols()`
    // again *after* installing overrides would itself route through the
    // now-registry-aware `consensus_params_for_version` for any version the
    // registry touches, so all post-install comparisons below reuse this
    // pre-install snapshot rather than recomputing it.
    let pristine = built_in_consensus_protocols();
    let pristine_future = pristine.get(CONSENSUS_FUTURE).cloned().unwrap();
    assert_eq!(
        consensus_params_for_version(CONSENSUS_FUTURE),
        Some(pristine_future.clone()),
        "pre-install, consensus_params_for_version must match the built-in table exactly"
    );

    // ── Simulate bin/algod-rust's startup: copy the real fixture into a
    // fresh data dir, load+merge it exactly like `node.rs` does, then
    // install the result as the process-global override registry.
    let fixture_path = vfuture_fixture_path();
    let dir = tempfile_dir();
    std::fs::copy(&fixture_path, dir.path().join("consensus.json")).unwrap_or_else(|e| {
        panic!(
            "expected real fixture at {} ({e}) -- see issue #750",
            fixture_path.display()
        )
    });

    let merged = preload_configurable_consensus_protocols(dir.path())
        .expect("the real go-algorand-authored vfuture-consensus.json must parse");
    install_consensus_overrides(&merged);

    // ── The override is now visible through consensus_params_for_version
    // itself, globally, exactly like every one of the 57 real call sites
    // throughout ledger/AVM/agreement/REST would observe it -- not just
    // through the local `merged` map `preload_configurable_consensus_protocols`
    // happened to return.
    let future_after = consensus_params_for_version(CONSENSUS_FUTURE)
        .expect("\"future\" must still resolve after the fixture overrides it");
    assert_eq!(future_after.min_balance, 100_000);
    assert_eq!(future_after.logic_sig_version, 13);
    assert_eq!(future_after.max_tx_group_size, 16);
    assert!(future_after.enable_heartbeat);
    assert_ne!(
        future_after, pristine_future,
        "the fixture must actually change \"future\"'s effective params"
    );

    // A version the fixture never mentions must be completely unaffected.
    assert_eq!(
        consensus_params_for_version(CONSENSUS_V42),
        pristine.get(CONSENSUS_V42).cloned(),
        "the fixture only overrides \"future\" -- v42 must stay byte-for-byte identical"
    );
}
