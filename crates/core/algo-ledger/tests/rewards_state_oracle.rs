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

//! Byte-level go-algorand oracle parity for `algo_ledger::rewards::next_rewards_state`
//! (issue #760, follow-up to #747/PR #759).
//!
//! #747 verified `next_rewards_state`'s `PendingResidueRewards` (v18+) and
//! `RewardsCalculationFix` (v31+) gating only by direct line-by-line
//! arithmetic comparison against go-algorand's
//! `bookkeeping.RewardsState.NextRewardsState` source -- not by running
//! go-algorand's own code and diffing real output. This test closes that
//! gap: `tools/rewards-innertxid-oracle` runs the exact same scenario
//! through real go-algorand's `NextRewardsState` at every consensus version
//! this repo tracks (V10..V42) and records the output in
//! `tests/fixtures/rewards_innertxid/oracle.json`. This test replays the
//! identical scenario through Rust's `next_rewards_state` and asserts
//! byte-for-byte (field-for-field) agreement with go's recorded output at
//! every version -- including the V17->V18 and V30->V31 boundaries the
//! scenario was hand-tuned to distinguish (see the Go tool's module docs).
//!
//! Regeneration: see `docs/DEV_WORKFLOW.md` -> "Rewards/InnerTxnID Oracle
//! Regeneration". In brief:
//!
//! ```bash
//! cd tools/rewards-innertxid-oracle
//! go run .
//! ```
//!
//! The fixture is checked in; any change to it must be justified by a
//! deliberate go-algorand pin bump or a scenario/schema change, and is
//! continuously verified for staleness by
//! `.github/workflows/rewards-innertxid-oracle.yml` (which rebuilds
//! go-algorand from source and re-runs the capture tool on every PR
//! touching the relevant paths).

use std::path::PathBuf;

use algo_ledger::rewards::{next_rewards_state, RewardsState};
use algo_types::consensus::consensus_params_for_version;
use serde::Deserialize;

/// The fixed scenario the Go oracle tool ran through every version --
/// mirrored here so this test doesn't need to parse it out of the fixture
/// (the fixture only records per-version *outputs*, since the input is a
/// deliberately shared constant -- see `tools/rewards-innertxid-oracle`'s
/// `fixedRewardsScenario`).
fn scenario_prev_state() -> RewardsState {
    RewardsState {
        rewards_level: 1000,
        rewards_rate: 250,
        rewards_residue: 1000,
        rewards_recalculation_round: 1_000_000,
    }
}

const SCENARIO_NEXT_ROUND: u64 = 1_000_000;
const SCENARIO_INCENTIVE_POOL_BALANCE: u64 = 600_400;
const SCENARIO_TOTAL_REWARD_UNITS: u64 = 7;

#[derive(Debug, Deserialize)]
struct RewardsVector {
    version: String,
    pending_residue_rewards: bool,
    rewards_calculation_fix: bool,
    min_balance: u64,
    rewards_rate_refresh_interval: u64,
    next_level: u64,
    next_rate: u64,
    next_residue: u64,
    next_recalculation_round: u64,
}

#[derive(Debug, Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    go_algorand_pin: String,
    rewards_vectors: Vec<RewardsVector>,
    #[allow(dead_code)]
    inner_id_vectors: Vec<serde_json::Value>,
}

fn load_corpus() -> Corpus {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/rewards_innertxid/oracle.json");
    let bytes = std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read rewards/inner-txn-id oracle fixture {p:?}: {e}. \
             Run `cd tools/rewards-innertxid-oracle && go run .` to regenerate."
        )
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("malformed oracle fixture {p:?}: {e}"))
}

/// The Go tool's `allVersions()` emits exactly V10..V42 (33 versions, see
/// its module docs for why that range) -- a corpus with a different count
/// means either the tool's version list or this repo's own captured
/// fixture has drifted from that range and needs investigation before
/// trusting the per-version assertions below.
#[test]
fn corpus_covers_every_tracked_version_v10_through_v42() {
    let corpus = load_corpus();
    assert!(
        !corpus.rewards_vectors.is_empty(),
        "oracle fixture has no rewards_vectors -- still the placeholder; \
         run `cd tools/rewards-innertxid-oracle && go run .` against a real \
         go-algorand v5.0.0-stable checkout and commit the result"
    );

    const EXPECTED_VERSION_COUNT: usize = 42 - 10 + 1; // V10..V42 inclusive
    assert_eq!(
        corpus.rewards_vectors.len(),
        EXPECTED_VERSION_COUNT,
        "expected exactly V10..V42 ({EXPECTED_VERSION_COUNT} versions); got {}: {:?}",
        corpus.rewards_vectors.len(),
        corpus
            .rewards_vectors
            .iter()
            .map(|v| v.version.as_str())
            .collect::<Vec<_>>()
    );
}

/// Byte-for-byte (field-for-field) parity: for every captured version,
/// Rust's `next_rewards_state` over the shared scenario must match
/// go-algorand's real recorded `RewardsState` output exactly.
#[test]
fn rust_matches_go_on_every_captured_version() {
    let corpus = load_corpus();
    assert!(
        !corpus.rewards_vectors.is_empty(),
        "oracle fixture is empty -- regenerate before relying on this test"
    );

    for v in &corpus.rewards_vectors {
        let params = consensus_params_for_version(&v.version).unwrap_or_else(|| {
            panic!(
                "Rust has no ConsensusParams for version {:?} captured by Go. \
                 Add it to algo-types or drop it from the capture matrix.",
                v.version
            )
        });

        // Sanity: the flags/constants Go recorded for this version must
        // match Rust's ConsensusParams table -- a mismatch here is itself a
        // consensus-correctness bug distinct from (and prior to) the
        // NextRewardsState formula itself.
        assert_eq!(
            params.pending_residue_rewards, v.pending_residue_rewards,
            "{}: pending_residue_rewards drift: Rust={}, Go={}",
            v.version, params.pending_residue_rewards, v.pending_residue_rewards
        );
        assert_eq!(
            params.rewards_calculation_fix, v.rewards_calculation_fix,
            "{}: rewards_calculation_fix drift: Rust={}, Go={}",
            v.version, params.rewards_calculation_fix, v.rewards_calculation_fix
        );
        assert_eq!(
            params.min_balance, v.min_balance,
            "{}: min_balance drift: Rust={}, Go={}",
            v.version, params.min_balance, v.min_balance
        );
        assert_eq!(
            params.rewards_rate_refresh_interval, v.rewards_rate_refresh_interval,
            "{}: rewards_rate_refresh_interval drift: Rust={}, Go={}",
            v.version, params.rewards_rate_refresh_interval, v.rewards_rate_refresh_interval
        );

        let got = next_rewards_state(
            scenario_prev_state(),
            SCENARIO_NEXT_ROUND,
            &params,
            SCENARIO_INCENTIVE_POOL_BALANCE,
            SCENARIO_TOTAL_REWARD_UNITS,
        );

        assert_eq!(
            got.rewards_level, v.next_level,
            "{}: rewards_level divergence: Rust={}, Go={}",
            v.version, got.rewards_level, v.next_level
        );
        assert_eq!(
            got.rewards_rate, v.next_rate,
            "{}: rewards_rate divergence: Rust={}, Go={}",
            v.version, got.rewards_rate, v.next_rate
        );
        assert_eq!(
            got.rewards_residue, v.next_residue,
            "{}: rewards_residue divergence: Rust={}, Go={}",
            v.version, got.rewards_residue, v.next_residue
        );
        assert_eq!(
            got.rewards_recalculation_round, v.next_recalculation_round,
            "{}: rewards_recalculation_round divergence: Rust={}, Go={}",
            v.version, got.rewards_recalculation_round, v.next_recalculation_round
        );
    }
}

/// Explicit boundary assertions on the real captured go-algorand output --
/// pins that the shared scenario actually distinguishes both flags (not
/// just "the fixture has 33 entries"), so a future scenario edit that
/// accidentally stops exercising the boundary fails loudly here rather than
/// silently in `rust_matches_go_on_every_captured_version` alone.
#[test]
fn go_output_actually_distinguishes_both_version_boundaries() {
    let corpus = load_corpus();
    assert!(!corpus.rewards_vectors.is_empty(), "fixture is empty");

    let find = |version: &str| -> &RewardsVector {
        corpus
            .rewards_vectors
            .iter()
            .find(|v| v.version == version)
            .unwrap_or_else(|| panic!("version {version} missing from oracle fixture"))
    };

    let v17 = find(algo_types::consensus::CONSENSUS_V17);
    let v18 = find(algo_types::consensus::CONSENSUS_V18);
    let v30 = find(algo_types::consensus::CONSENSUS_V30);
    let v31 = find(algo_types::consensus::CONSENSUS_V31);

    // PendingResidueRewards (v17->v18): the refreshed rate must differ,
    // while this round's level/residue (computed from the *old* rate on
    // both sides, since RewardsCalculationFix is off for both) stay equal.
    assert_ne!(
        v17.next_rate, v18.next_rate,
        "v17->v18 must change the refreshed RewardsRate (PendingResidueRewards \
         changes how much of the pool balance counts against MinBalance)"
    );
    assert_eq!(
        (v17.next_level, v17.next_residue),
        (v18.next_level, v18.next_residue),
        "v17->v18 must NOT change this round's level/residue \
         (RewardsCalculationFix is off for both, so both use the pre-refresh rate)"
    );

    // RewardsCalculationFix (v30->v31): the refreshed rate is identical on
    // both (PendingResidueRewards is on for both), but v31 must use it
    // immediately for this round's level/residue while v30 uses the stale
    // pre-refresh rate -- so level/residue must differ.
    assert_eq!(
        v30.next_rate, v31.next_rate,
        "v30->v31 refreshed RewardsRate should be identical \
         (PendingResidueRewards is on for both)"
    );
    assert_ne!(
        (v30.next_level, v30.next_residue),
        (v31.next_level, v31.next_residue),
        "v30->v31 must change this round's level/residue \
         (RewardsCalculationFix changes which rate is used for the same-round advance)"
    );
}
