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

//! Issue #750: a Rust equivalent of go-algorand's
//! `PreloadConfigurableConsensusProtocols` / `LoadConfigurableConsensusProtocols`
//! / `SaveConfigurableConsensus` (`config/config.go`) and
//! `ConsensusProtocols.Merge` (`config/consensus.go`).
//!
//! Pins: missing-file fallback, malformed-file error, per-version
//! delete-or-replace-wholesale merge semantics (including pruning a
//! dangling `approved_upgrade` reference to a deleted version), and a
//! byte-for-byte-compatible load of the real go-algorand-authored
//! `docker/config/vfuture-consensus.json` fixture already checked into this
//! repo (used elsewhere to feed a real go-algorand sibling container — see
//! `docker/docker-compose.vfuture.yml` — but never parsed by any Rust code
//! path before this issue).

use std::collections::HashMap;
use std::path::PathBuf;

use algo_types::consensus::{
    built_in_consensus_protocols, merge_consensus_protocols,
    preload_configurable_consensus_protocols, save_configurable_consensus, ConsensusOverrides,
    ConsensusParamsOverride, CONSENSUS_FUTURE, CONSENSUS_V41, CONSENSUS_V42,
};

fn repo_root() -> PathBuf {
    // crates/core/algo-types -> repo root is three levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root must exist")
}

fn vfuture_fixture_path() -> PathBuf {
    repo_root().join("docker/config/vfuture-consensus.json")
}

/// A missing `consensus.json` must fall back cleanly to the built-in table,
/// not error (Go: `PreloadConfigurableConsensusProtocols` returns
/// `Consensus, nil` on `os.IsNotExist`).
#[test]
fn missing_consensus_json_falls_back_to_built_in_table() {
    let empty_dir = tempfile_dir();
    let loaded = preload_configurable_consensus_protocols(empty_dir.path())
        .expect("a missing consensus.json must not error");
    let built_in = built_in_consensus_protocols();

    assert_eq!(loaded.len(), built_in.len());
    assert_eq!(loaded.get(CONSENSUS_V42), built_in.get(CONSENSUS_V42));
    assert_eq!(loaded.get(CONSENSUS_V41), built_in.get(CONSENSUS_V41));
}

/// A present-but-malformed `consensus.json` must surface as a real error,
/// never be silently ignored.
#[test]
fn malformed_consensus_json_is_a_real_error() {
    let dir = tempfile_dir();
    std::fs::write(dir.path().join("consensus.json"), b"{ this is not json").unwrap();

    let result = preload_configurable_consensus_protocols(dir.path());
    assert!(
        result.is_err(),
        "malformed consensus.json must not be silently swallowed"
    );
}

/// An override entry with `ApprovedUpgrades` present (even `{}`) replaces
/// the targeted version's *entire* `ConsensusParams` wholesale — fields the
/// override omits take Go zero values, not the built-in version's old
/// values.
#[test]
fn override_with_approved_upgrades_replaces_version_wholesale() {
    let base = built_in_consensus_protocols();
    let built_in_v42 = base.get(CONSENSUS_V42).unwrap().clone();
    assert_ne!(
        built_in_v42.min_txn_fee, 42,
        "precondition: built-in v42 MinTxnFee isn't already 42"
    );

    let mut overrides: ConsensusOverrides = HashMap::new();
    let ov = ConsensusParamsOverride {
        min_txn_fee: 42,
        approved_upgrades: Some(HashMap::new()), // present, empty -> not a delete.
        ..Default::default()
    };
    overrides.insert(CONSENSUS_V42.to_string(), ov);

    let merged = merge_consensus_protocols(base, overrides);
    let merged_v42 = merged.get(CONSENSUS_V42).expect("v42 must still exist");

    assert_eq!(merged_v42.min_txn_fee, 42, "the override value must win");
    // Whole-struct replace: a field the override never set (e.g.
    // min_balance) must be the JSON-absent Go zero value (0), not the
    // built-in table's old value -- proving this is a replace, not a
    // field-by-field merge.
    assert_eq!(
        merged_v42.min_balance, 0,
        "fields the override omits must be Go zero values (whole-struct replace), \
         not inherited from the built-in table"
    );
}

/// An override entry with `ApprovedUpgrades` absent/null deletes that
/// version from the effective table, and prunes any other version's
/// `approved_upgrade` that pointed at the deleted version (Go:
/// `ConsensusProtocols.Merge`, `config/consensus.go` ~line 858).
#[test]
fn override_with_no_approved_upgrades_deletes_version_and_prunes_dangling_reference() {
    let base = built_in_consensus_protocols();
    // v41 approves an upgrade to v42 in the built-in table.
    assert_eq!(
        base.get(CONSENSUS_V41).unwrap().approved_upgrade,
        Some((CONSENSUS_V42, 208_000))
    );

    let mut overrides: ConsensusOverrides = HashMap::new();
    overrides.insert(
        CONSENSUS_V42.to_string(),
        ConsensusParamsOverride::default(),
    );
    // `approved_upgrades` defaults to `None` -> delete signal.

    let merged = merge_consensus_protocols(base, overrides);

    assert!(
        !merged.contains_key(CONSENSUS_V42),
        "v42 must be deleted from the effective table"
    );
    assert_eq!(
        merged.get(CONSENSUS_V41).unwrap().approved_upgrade,
        None,
        "v41's dangling approved_upgrade pointing at the deleted v42 must be pruned"
    );
}

/// A wholly new version name (not in the built-in table at all) is simply
/// added.
#[test]
fn override_can_add_a_brand_new_version() {
    let base = built_in_consensus_protocols();
    assert!(!base.contains_key("mycustomversion"));

    let mut overrides: ConsensusOverrides = HashMap::new();
    let ov = ConsensusParamsOverride {
        min_txn_fee: 7,
        approved_upgrades: Some(HashMap::new()),
        ..Default::default()
    };
    overrides.insert("mycustomversion".to_string(), ov);

    let merged = merge_consensus_protocols(base, overrides);
    assert_eq!(merged.get("mycustomversion").unwrap().min_txn_fee, 7);
}

/// Round-trip through the writer: an empty override map deletes an existing
/// file (Go: `SaveConfigurableConsensus` with zero entries).
#[test]
fn save_with_empty_overrides_deletes_existing_file() {
    let dir = tempfile_dir();
    let path = dir.path().join("consensus.json");
    std::fs::write(&path, b"{}").unwrap();
    assert!(path.exists());

    save_configurable_consensus(dir.path(), &HashMap::new()).unwrap();
    assert!(!path.exists(), "an empty override map must remove the file");

    // Deleting an already-absent file is not an error either.
    save_configurable_consensus(dir.path(), &HashMap::new()).unwrap();
}

/// Writing non-empty overrides, then loading them back, reproduces the same
/// effective merge as constructing it directly in-process.
#[test]
fn save_then_preload_round_trips() {
    let dir = tempfile_dir();
    let mut overrides: ConsensusOverrides = HashMap::new();
    let ov = ConsensusParamsOverride {
        min_txn_fee: 12345,
        approved_upgrades: Some(HashMap::new()),
        ..Default::default()
    };
    overrides.insert(CONSENSUS_FUTURE.to_string(), ov);

    save_configurable_consensus(dir.path(), &overrides).unwrap();
    let loaded = preload_configurable_consensus_protocols(dir.path()).unwrap();

    assert_eq!(loaded.get(CONSENSUS_FUTURE).unwrap().min_txn_fee, 12345);
}

/// The acceptance-criteria centerpiece: load the *real*, go-algorand-authored
/// `docker/config/vfuture-consensus.json` fixture through the new Rust
/// loader and confirm it merges correctly onto the built-in table, proving
/// byte-for-byte JSON-shape compatibility with a real file, not just a
/// hand-rolled Rust test fixture.
#[test]
fn real_vfuture_consensus_json_fixture_loads_and_merges_correctly() {
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

    let future = merged
        .get(CONSENSUS_FUTURE)
        .expect("the fixture overrides the \"future\" version");

    // Spot-check a representative sample of values straight out of the
    // fixture (docker/config/vfuture-consensus.json), across scalar,
    // duration, and nested-struct fields, so this test would fail if any of
    // those three JSON shapes silently stopped deserializing correctly.
    assert_eq!(future.min_balance, 100_000);
    assert_eq!(future.min_txn_fee, 1_000);
    assert_eq!(future.logic_sig_version, 13);
    assert_eq!(future.max_tx_group_size, 16);
    assert!(
        future.enable_heartbeat,
        "\"Heartbeat\": true in the fixture"
    );
    assert!(
        !future.enable_pq_scheme_falcon1024,
        "the fixture never sets \"EnablePQSchemeFalcon1024\" -- must default to false"
    );
    assert_eq!(
        future.agreement_filter_timeout,
        std::time::Duration::from_secs(4),
        "\"AgreementFilterTimeout\": 4000000000 (ns) in the fixture"
    );
    assert_eq!(
        future.fast_recovery_lambda,
        std::time::Duration::from_secs(300),
        "\"FastRecoveryLambda\": 300000000000 (ns) in the fixture"
    );
    assert!(
        future.payouts_enabled,
        "\"Payouts\": {{ \"Enabled\": true }} in the fixture"
    );
    assert_eq!(future.payouts_percent, 50);
    assert_eq!(future.bonus_base_amount, 10_000_000);
    assert_eq!(
        future.approved_upgrade, None,
        "\"ApprovedUpgrades\": {{}} in the fixture -- present but empty, so no outbound proposal"
    );

    // Every other built-in version must be untouched by this override.
    let built_in = built_in_consensus_protocols();
    assert_eq!(merged.get(CONSENSUS_V42), built_in.get(CONSENSUS_V42));
    assert_eq!(
        merged.len(),
        built_in.len(),
        "the fixture only overrides \"future\", never adds/removes any other version"
    );
}

/// Minimal self-contained tempdir helper (this crate has no existing
/// tempfile dev-dependency) -- a unique, auto-cleaned-up subdirectory under
/// the OS temp dir.
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
    let dir = std::env::temp_dir().join(format!("algo-types-consensus-json-test-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}
