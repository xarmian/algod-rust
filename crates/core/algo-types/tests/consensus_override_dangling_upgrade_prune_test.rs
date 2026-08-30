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

//! Issue #762, consensus-critical edge case: `install_consensus_overrides`
//! diffs the caller's already-merged table against a fresh
//! `built_in_consensus_protocols()` snapshot to decide which versions to
//! record in the registry. This must correctly pick up a version that
//! `merge_consensus_protocols` changed only *indirectly* -- via its dangling
//! `approved_upgrade`-pruning rule (`config/consensus.go`'s
//! `ConsensusProtocols.Merge`: deleting a version also clears any other
//! version's outbound upgrade proposal that pointed at it) -- not just a
//! version the loaded `consensus.json` named directly. Getting this wrong
//! would leave a stale, dangling upgrade-proposal target visible through
//! `consensus_params_for_version` after the target version was deleted,
//! even though the plain `merge_consensus_protocols` output (already tested
//! in `consensus_json_load_test.rs`) is correct -- exactly the kind of
//! "correct locally, wrong once threaded through the registry" gap this
//! issue exists to close.
//!
//! Its own integration-test file/process, like the other override tests:
//! `install_consensus_overrides` writes a process-global `OnceLock` at most
//! once.

use std::collections::HashMap;

use algo_types::consensus::{
    built_in_consensus_protocols, consensus_params_for_version, install_consensus_overrides,
    merge_consensus_protocols, ConsensusOverrides, ConsensusParamsOverride, CONSENSUS_V41,
    CONSENSUS_V42,
};

#[test]
fn deleting_a_version_prunes_the_dangling_approved_upgrade_through_the_registry_too() {
    let built_in = built_in_consensus_protocols();
    assert_eq!(
        built_in.get(CONSENSUS_V41).unwrap().approved_upgrade,
        Some((CONSENSUS_V42, 208_000)),
        "precondition: v41's built-in table proposes an upgrade to v42"
    );

    // The consensus.json only names v42 (delete it) -- it never mentions v41
    // at all.
    let mut overrides: ConsensusOverrides = HashMap::new();
    overrides.insert(
        CONSENSUS_V42.to_string(),
        ConsensusParamsOverride::default(),
    );
    // `approved_upgrades` defaults to `None` -> delete signal.

    let merged = merge_consensus_protocols(built_in_consensus_protocols(), overrides);
    // Sanity on the input `merge_consensus_protocols` itself produces --
    // already covered by `consensus_json_load_test.rs`, re-asserted here only
    // to pin exactly what `install_consensus_overrides` receives.
    assert!(!merged.contains_key(CONSENSUS_V42));
    assert_eq!(merged.get(CONSENSUS_V41).unwrap().approved_upgrade, None);

    install_consensus_overrides(&merged);

    assert_eq!(
        consensus_params_for_version(CONSENSUS_V42),
        None,
        "the deleted version must be unknown through the registry"
    );
    assert_eq!(
        consensus_params_for_version(CONSENSUS_V41)
            .expect("v41 itself was never deleted")
            .approved_upgrade,
        None,
        "v41's dangling approved_upgrade pointing at the now-deleted v42 must be pruned \
         through consensus_params_for_version -- even though the consensus.json only \
         named v42, never v41 directly"
    );
}
