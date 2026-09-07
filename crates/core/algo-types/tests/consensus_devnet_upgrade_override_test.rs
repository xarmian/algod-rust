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

//! Issue #1138: a Rust port of go-algorand's
//! `ApplyShorterUpgradeRoundsForDevNetworks` (`config/config.go:384-399`),
//! pinned against go's own `TestConsensusUpgradeWindow_NetworkOverrides`
//! (`config/consensus_test.go`).
//!
//! go-algorand shortens every version's pending-upgrade delay
//! (`ApprovedUpgrades[v]`) down to that version's own
//! `MinUpgradeWaitRounds` for the Devnet/Betanet/Fnet genesis networks, and
//! is a no-op for every other network (Mainnet/Testnet included) — called
//! once at startup, before any `consensus.json` override is merged on top
//! (`cmd/algod/main.go:204-212`).

use std::collections::HashMap;

use algo_types::consensus::{
    apply_shorter_upgrade_rounds_for_dev_networks, built_in_consensus_protocols,
};

/// For every version with a pending upgrade and a non-zero
/// `MinUpgradeWaitRounds`/`MaxUpgradeWaitRounds`, Devnet shortens the delay
/// to exactly that version's `MinUpgradeWaitRounds` — matching go's
/// `TestConsensusUpgradeWindow_NetworkOverrides`'s Devnet assertions
/// (`require.Equalf(t, delay, params.MinUpgradeWaitRounds, ...)`).
#[test]
fn devnet_shortens_every_pending_upgrade_to_min_upgrade_wait_rounds() {
    let mut table = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut table, "devnet");

    let mut saw_a_shortened_upgrade = false;
    for params in table.values() {
        if let Some((_, delay)) = params.approved_upgrade {
            if params.min_upgrade_wait_rounds != 0 || params.max_upgrade_wait_rounds != 0 {
                assert_ne!(delay, 0, "shortened delay must stay non-zero");
                assert_eq!(
                    delay, params.min_upgrade_wait_rounds,
                    "devnet must shorten the delay down to MinUpgradeWaitRounds"
                );
                assert!(
                    delay <= params.max_upgrade_wait_rounds,
                    "shortened delay must not exceed MaxUpgradeWaitRounds"
                );
                saw_a_shortened_upgrade = true;
            } else {
                assert_eq!(
                    delay, 0,
                    "pre-v22 versions with no MinUpgradeWaitRounds must stay untouched at zero"
                );
            }
        }
    }
    assert!(
        saw_a_shortened_upgrade,
        "the built-in table must contain at least one v22+ pending upgrade to exercise the shortening"
    );
}

/// Betanet gets the identical treatment to Devnet.
#[test]
fn betanet_shortens_every_pending_upgrade_to_min_upgrade_wait_rounds() {
    let mut table = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut table, "betanet");

    for params in table.values() {
        if let Some((_, delay)) = params.approved_upgrade {
            if params.min_upgrade_wait_rounds != 0 || params.max_upgrade_wait_rounds != 0 {
                assert_eq!(delay, params.min_upgrade_wait_rounds);
            }
        }
    }
}

/// Fnet gets the identical treatment to Devnet.
#[test]
fn fnet_shortens_every_pending_upgrade_to_min_upgrade_wait_rounds() {
    let mut table = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut table, "fnet");

    for params in table.values() {
        if let Some((_, delay)) = params.approved_upgrade {
            if params.min_upgrade_wait_rounds != 0 || params.max_upgrade_wait_rounds != 0 {
                assert_eq!(delay, params.min_upgrade_wait_rounds);
            }
        }
    }
}

/// Mainnet must be a complete no-op — matches go's
/// `require.EqualValues(t, origConsensus, Consensus)` after
/// `ApplyShorterUpgradeRoundsForDevNetworks(Mainnet)`.
#[test]
fn mainnet_is_a_no_op() {
    let before = built_in_consensus_protocols();
    let mut after = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut after, "mainnet");
    assert_eq!(before, after, "mainnet must not touch any upgrade delay");
}

/// Testnet must also be a complete no-op — matches go's parallel Testnet
/// assertion in the same test.
#[test]
fn testnet_is_a_no_op() {
    let before = built_in_consensus_protocols();
    let mut after = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut after, "testnet");
    assert_eq!(before, after, "testnet must not touch any upgrade delay");
}

/// An unknown/empty network id (e.g. a private network with a custom
/// genesis `network` field) must also be a no-op — go's function only ever
/// special-cases the three literal strings, matching nothing else.
#[test]
fn unknown_network_is_a_no_op() {
    let before = built_in_consensus_protocols();
    let mut after = built_in_consensus_protocols();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut after, "my-private-net");
    assert_eq!(before, after);
}

/// Devnet actually diverges from the un-shortened built-in table — i.e.
/// the override function does *something* observable, not merely returns
/// without panicking. Guards against a no-op implementation vacuously
/// passing every assertion above.
#[test]
fn devnet_table_actually_differs_from_built_in_table() {
    let before = built_in_consensus_protocols();
    let mut after: HashMap<_, _> = before.clone();
    apply_shorter_upgrade_rounds_for_dev_networks(&mut after, "devnet");
    assert_ne!(
        before, after,
        "devnet must shorten at least one version's upgrade delay"
    );
}
