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

//! Issue #762: `consensus_params_for_version` must consult a process-global,
//! write-once-at-startup override registry FIRST, falling back to the
//! compile-time built-in table only when no override exists for a version.
//!
//! This is deliberately its own integration-test *file* (a separate test
//! binary/process from every other test in this crate and workspace):
//! [`algo_types::consensus::install_consensus_overrides`] populates a
//! `std::sync::OnceLock` that is process-global and can be written at most
//! once, so any test that calls it must not share a process with a test that
//! assumes the pristine (no-override) built-in-table-only behavior. Keeping
//! every install-touching assertion inside a single `#[test]` function run
//! sequentially (rather than spread across multiple functions that cargo
//! would run concurrently within one binary) makes the ordering
//! deterministic.
//!
//! Covers:
//! - Regression: before any install, `consensus_params_for_version` behaves
//!   exactly as it does without this feature at all (the default for the
//!   vast majority of this workspace's tests/tools, which never touch a data
//!   directory or consensus.json).
//! - A version present in the installed override map (built from the same
//!   `merge_consensus_protocols` result `preload_configurable_consensus_protocols`
//!   already produces) wins wholesale over the built-in table.
//! - A version *deleted* by the override (no `ApprovedUpgrades`) becomes
//!   unknown (`None`) through `consensus_params_for_version`, not silently
//!   falling back to its old built-in definition.
//! - A version untouched by the override is unaffected.
//! - Write-once: a second `install_consensus_overrides` call is a no-op; the
//!   first call's values keep winning.

use std::collections::HashMap;

use algo_types::consensus::{
    built_in_consensus_protocols, consensus_params_for_version, install_consensus_overrides,
    merge_consensus_protocols, ConsensusOverrides, ConsensusParamsOverride, CONSENSUS_V41,
    CONSENSUS_V7,
};

#[test]
fn override_registry_write_once_threads_through_consensus_params_for_version() {
    // A version name no build of algod-rust has ever shipped -- guaranteed
    // absent from the built-in table, so it can only ever come from an
    // override.
    let brand_new_version = "issue762-brand-new-test-version";

    // ── Step 1: regression, no override installed yet ──────────────────
    // This is the behavior the overwhelming majority of this workspace's
    // tests/tools rely on today, and it must not change.
    assert_eq!(
        consensus_params_for_version(brand_new_version),
        None,
        "an unknown version must still resolve to None pre-install"
    );
    let pristine_built_in = built_in_consensus_protocols();
    assert_eq!(
        consensus_params_for_version(CONSENSUS_V41),
        pristine_built_in.get(CONSENSUS_V41).cloned(),
        "pre-install, consensus_params_for_version must match the built-in table exactly"
    );
    assert!(
        pristine_built_in.contains_key(CONSENSUS_V7),
        "precondition: v7 is a real built-in version"
    );

    // ── Step 2: build overrides exercising all three merge outcomes ────
    // (replace-wholesale, brand-new addition, delete), then install via the
    // exact same `preload_configurable_consensus_protocols` merge result
    // bin/algod-rust's startup path produces.
    let mut overrides: ConsensusOverrides = HashMap::new();
    overrides.insert(
        CONSENSUS_V41.to_string(),
        ConsensusParamsOverride {
            min_txn_fee: 987_654,
            approved_upgrades: Some(HashMap::new()), // present -> replace wholesale.
            ..Default::default()
        },
    );
    overrides.insert(
        brand_new_version.to_string(),
        ConsensusParamsOverride {
            min_txn_fee: 55,
            approved_upgrades: Some(HashMap::new()),
            ..Default::default()
        },
    );
    overrides.insert(CONSENSUS_V7.to_string(), ConsensusParamsOverride::default());
    // v7's `approved_upgrades` defaults to `None` -> delete signal.

    let merged = merge_consensus_protocols(built_in_consensus_protocols(), overrides);
    install_consensus_overrides(&merged);

    // ── Step 3: overridden/added versions now resolve through the registry ──
    assert_eq!(
        consensus_params_for_version(CONSENSUS_V41)
            .expect("v41 still known")
            .min_txn_fee,
        987_654,
        "an override with ApprovedUpgrades present must win wholesale"
    );
    assert_eq!(
        consensus_params_for_version(brand_new_version)
            .expect("a wholly new override-added version must resolve")
            .min_txn_fee,
        55
    );
    assert_eq!(
        consensus_params_for_version(CONSENSUS_V7),
        None,
        "a deleted version (ApprovedUpgrades absent) must become unknown, \
         not silently fall back to its old built-in definition"
    );

    // ── Step 4: an untouched known version is unaffected ───────────────
    // (every one of the 57 call sites elsewhere in the codebase that never
    // deals with this specific overridden version must see zero change).
    let v42_after = consensus_params_for_version(algo_types::CONSENSUS_V42);
    assert_eq!(
        v42_after,
        pristine_built_in.get(algo_types::CONSENSUS_V42).cloned(),
        "a version the override never touches must stay byte-for-byte identical"
    );

    // ── Step 5: write-once -- a second install is silently ignored ─────
    let mut second_overrides: ConsensusOverrides = HashMap::new();
    second_overrides.insert(
        CONSENSUS_V41.to_string(),
        ConsensusParamsOverride {
            min_txn_fee: 1,
            approved_upgrades: Some(HashMap::new()),
            ..Default::default()
        },
    );
    let second_merged = merge_consensus_protocols(built_in_consensus_protocols(), second_overrides);
    install_consensus_overrides(&second_merged);

    assert_eq!(
        consensus_params_for_version(CONSENSUS_V41)
            .expect("v41 still known")
            .min_txn_fee,
        987_654,
        "a second install call must not clobber the first (write-once, read-only-after)"
    );
}
