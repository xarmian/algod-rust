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

//! Issue #1728 review: `genesis_flags_for_version` and
//! `consensus_params_for_version` share one resolution, so a
//! `consensus.json` override (replaced flags, deleted protocol, brand-new
//! protocol) is seen identically by both -- including a lookup made BEFORE
//! the overrides were installed (no stale cache).

use std::collections::HashMap;

use algo_types::consensus::{
    built_in_consensus_protocols, consensus_params_for_version, genesis_flags_for_version,
    install_consensus_overrides, merge_consensus_protocols, ConsensusOverrides,
    ConsensusParamsOverride, DefaultTrue, GenesisProtocolFlags, CONSENSUS_V15, CONSENSUS_V41,
    KNOWN_PROTOCOL_VERSIONS,
};

const NEW: &str = "issue1728-new-test-version";

fn assert_agree(version: &str) {
    let full = consensus_params_for_version(version).map(|p| GenesisProtocolFlags {
        require_genesis_hash: p.require_genesis_hash,
        support_signed_txn_in_block: p.support_signed_txn_in_block,
    });
    assert_eq!(genesis_flags_for_version(version), full, "{version}");
}

#[test]
fn flags_lookup_follows_consensus_overrides_without_stale_cache() {
    // Before install (warms any cache): built-in values.
    let before = genesis_flags_for_version(CONSENSUS_V41).unwrap();
    assert!(before.require_genesis_hash && before.support_signed_txn_in_block);
    assert!(genesis_flags_for_version(CONSENSUS_V15).is_some());
    assert_eq!(genesis_flags_for_version(NEW), None);

    let mut overrides: ConsensusOverrides = HashMap::new();
    // Some entry with flags differing from the built-in.
    overrides.insert(
        CONSENSUS_V41.to_string(),
        ConsensusParamsOverride {
            require_genesis_hash: false,
            support_signed_txn_in_block: DefaultTrue(false),
            approved_upgrades: Some(HashMap::new()),
            ..Default::default()
        },
    );
    // A brand-new protocol with custom flags.
    overrides.insert(
        NEW.to_string(),
        ConsensusParamsOverride {
            require_genesis_hash: true,
            approved_upgrades: Some(HashMap::new()),
            ..Default::default()
        },
    );
    // None entry (delete signal: no ApprovedUpgrades) hides a protocol.
    overrides.insert(CONSENSUS_V15.to_string(), ConsensusParamsOverride::default());
    install_consensus_overrides(&merge_consensus_protocols(
        built_in_consensus_protocols(),
        overrides,
    ));

    let v41 = genesis_flags_for_version(CONSENSUS_V41).unwrap();
    assert!(!v41.require_genesis_hash && !v41.support_signed_txn_in_block);
    assert_eq!(genesis_flags_for_version(CONSENSUS_V15), None);
    assert_eq!(
        genesis_flags_for_version(NEW),
        Some(GenesisProtocolFlags {
            require_genesis_hash: true,
            support_signed_txn_in_block: true
        })
    );
    for v in KNOWN_PROTOCOL_VERSIONS.iter().copied().chain([NEW, "nonsense"]) {
        assert_agree(v);
    }
}
