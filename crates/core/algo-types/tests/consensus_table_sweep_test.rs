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

//! Whole-consensus-table invariant sweep, mirroring go-algorand's
//! `config/consensus_test.go` `TestConsensusParams` and
//! `TestConsensusStateProofParams`: iterate every known
//! [`ConsensusParams`] (not just the handful of versions
//! `crates/core/algo-types/src/consensus.rs`'s existing unit tests spot
//! check) and assert the structural invariants that must hold across the
//! *whole* table at once.
//!
//! `config/config_test.go`'s `TestEncodedAccountAllocationBounds` (the
//! third go test named by issue #946) cross-checks
//! `MaxAssetsPerAccount`/`MaxAppsCreated`/`MaxAppsOptedIn`/`Max{Local,
//! Global}SchemaEntries` against *fixed codec allocbound constants*
//! (`bounds.EncodedMaxAssetsPerAccount` etc.) that exist in go-algorand to
//! cap how much a malicious msgpack payload's length prefix can make the
//! decoder pre-allocate. algod-rust's msgpack decode path
//! (`crates/core/algo-codec`) uses `rmp_serde` into ordinary growable
//! `Vec`/`HashMap` collections rather than fixed-capacity codec allocbound
//! constants, so there is no equivalent fixed-bound table in this crate to
//! cross-check `ConsensusParams` against -- this is a genuine architectural
//! difference, not a gap in this sweep. (See `docs/phase17/parity_config_proto_sp.md`.)

use algo_types::consensus::{
    consensus_params_for_version, ConsensusParams, KNOWN_PROTOCOL_VERSIONS,
};

/// The five structural invariants go's `TestConsensusParams` checks per
/// protocol, extracted into a standalone function so it can be exercised
/// against both a deliberately-broken synthetic `ConsensusParams` (proving
/// the check actually fires) and the real table.
fn check_consensus_params_invariants(version: &str, p: &ConsensusParams) -> Result<(), String> {
    // "It makes no sense to have the 'Absolute' smaller than the
    // non-absolute values" -- but algod-rust models "this bound doesn't
    // exist yet at this version" as 0 (a single flat struct spans every
    // version, unlike go's per-version struct literals which simply omit
    // the field before it existed), so 0 is an explicit "unset" sentinel
    // here, not a real zero-byte cap.
    if p.max_absolute_txn_note_bytes != 0 && p.max_absolute_txn_note_bytes < p.max_txn_note_bytes {
        return Err(format!(
            "{version}: max_absolute_txn_note_bytes ({}) < max_txn_note_bytes ({})",
            p.max_absolute_txn_note_bytes, p.max_txn_note_bytes
        ));
    }
    if p.max_absolute_extra_program_pages != 0
        && p.max_absolute_extra_program_pages < p.max_extra_app_program_pages
    {
        return Err(format!(
            "{version}: max_absolute_extra_program_pages ({}) < max_extra_app_program_pages ({})",
            p.max_absolute_extra_program_pages, p.max_extra_app_program_pages
        ));
    }
    if p.max_absolute_total_arg_len != 0 && p.max_absolute_total_arg_len < p.max_app_total_arg_len {
        return Err(format!(
            "{version}: max_absolute_total_arg_len ({}) < max_app_total_arg_len ({})",
            p.max_absolute_total_arg_len, p.max_app_total_arg_len
        ));
    }
    if p.max_absolute_logic_sig_program_size != 0
        && p.max_absolute_logic_sig_program_size < p.logic_sig_max_size
    {
        return Err(format!(
            "{version}: max_absolute_logic_sig_program_size ({}) < logic_sig_max_size ({})",
            p.max_absolute_logic_sig_program_size, p.logic_sig_max_size
        ));
    }

    // "To figure out challenges, nodes must be able to lookup headers up to
    // two GracePeriods back" (go: 2*ChallengeGracePeriod <=
    // MaxTxnLife+DeeperBlockHeaderHistory).
    if 2 * p.payouts_challenge_grace_period > p.max_txn_life + p.deeper_block_header_history {
        return Err(format!(
            "{version}: grace period is too long (2*{} > {}+{})",
            p.payouts_challenge_grace_period, p.max_txn_life, p.deeper_block_header_history
        ));
    }

    Ok(())
}

/// go's `TestConsensusStateProofParams`: `(MaxKeyregValidPeriod+1) /
/// StateProofInterval == 1<<16` whenever state proofs are enabled.
fn check_state_proof_key_capacity(version: &str, p: &ConsensusParams) -> Result<(), String> {
    if p.state_proof_interval == 0 {
        return Ok(());
    }
    let generated_keys = (p.max_keyreg_valid_period + 1) / p.state_proof_interval;
    if generated_keys != 1 << 16 {
        return Err(format!(
            "{version}: (max_keyreg_valid_period+1)/state_proof_interval = {generated_keys}, want {}",
            1u64 << 16
        ));
    }
    Ok(())
}

fn base_params_for_synthetic_test() -> ConsensusParams {
    // v41 is a fully-populated, "current era" set of params -- a realistic
    // starting point to mutate one field at a time for the TDD checks
    // below, rather than hand-building a whole ConsensusParams from field
    // literals (which would silently drift from the struct's real shape).
    consensus_params_for_version(algo_types::consensus::CONSENSUS_V41).expect("V41 must resolve")
}

// ---------------------------------------------------------------------------
// TDD: the checkers themselves must catch a synthetic regression first.
// ---------------------------------------------------------------------------

#[test]
fn consensus_params_checker_catches_synthetic_absolute_bound_regression() {
    let good = base_params_for_synthetic_test();
    assert!(check_consensus_params_invariants("good", &good).is_ok());

    let mut broken = good.clone();
    // Absolute cap silently regressed below the soft cap -- exactly the
    // shape of bug go's TestConsensusParams exists to catch.
    broken.max_absolute_txn_note_bytes = broken.max_txn_note_bytes.saturating_sub(1).max(1);
    // Make sure we actually created a violation (only meaningful if the
    // soft cap is nonzero and the absolute cap doesn't end up unset).
    assert!(broken.max_absolute_txn_note_bytes < broken.max_txn_note_bytes);
    let err = check_consensus_params_invariants("broken", &broken)
        .expect_err("must catch the absolute-bound regression");
    assert!(
        err.contains("max_absolute_txn_note_bytes"),
        "unexpected error: {err}"
    );
}

#[test]
fn consensus_params_checker_catches_synthetic_grace_period_regression() {
    let good = base_params_for_synthetic_test();
    assert!(check_consensus_params_invariants("good", &good).is_ok());

    let mut broken = good.clone();
    broken.payouts_challenge_grace_period =
        broken.max_txn_life + broken.deeper_block_header_history + 1;
    let err = check_consensus_params_invariants("broken", &broken)
        .expect_err("must catch the grace-period regression");
    assert!(err.contains("grace period"), "unexpected error: {err}");
}

#[test]
fn state_proof_checker_catches_synthetic_key_capacity_regression() {
    let good = base_params_for_synthetic_test();
    assert!(check_state_proof_key_capacity("good", &good).is_ok());

    let mut broken = good.clone();
    if broken.state_proof_interval == 0 {
        broken.state_proof_interval = 256;
        broken.max_keyreg_valid_period = 256 * (1 << 16) - 1;
    }
    // Nudge the interval by one to break the exact division invariant.
    broken.state_proof_interval += 1;
    let err = check_state_proof_key_capacity("broken", &broken)
        .expect_err("must catch the key-capacity regression");
    assert!(err.contains("want"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Real-table sweeps
// ---------------------------------------------------------------------------

#[test]
fn consensus_params_invariants_hold_across_every_known_version() {
    assert!(
        KNOWN_PROTOCOL_VERSIONS.len() > 10,
        "sanity: table not empty"
    );
    for &version in KNOWN_PROTOCOL_VERSIONS {
        let params = consensus_params_for_version(version)
            .unwrap_or_else(|| panic!("{version} must resolve to ConsensusParams"));
        check_consensus_params_invariants(version, &params).expect("invariant violated");
    }
}

#[test]
fn consensus_state_proof_key_capacity_holds_across_every_known_version() {
    for &version in KNOWN_PROTOCOL_VERSIONS {
        let params = consensus_params_for_version(version)
            .unwrap_or_else(|| panic!("{version} must resolve to ConsensusParams"));
        check_state_proof_key_capacity(version, &params).expect("invariant violated");
    }

    // Mirrors go's implicit assumption that this isn't a vacuous check: at
    // least one known version must actually have state proofs enabled.
    let any_state_proof_enabled = KNOWN_PROTOCOL_VERSIONS.iter().any(|&v| {
        consensus_params_for_version(v)
            .unwrap()
            .state_proof_interval
            != 0
    });
    assert!(
        any_state_proof_enabled,
        "expected at least one known version to enable state proofs"
    );
}

#[test]
fn consensus_upgrade_wait_rounds_and_delay_bounds_hold_across_every_known_version() {
    // go's TestConsensusUpgradeWindow: MaxUpgradeWaitRounds >=
    // MinUpgradeWaitRounds, and every ApprovedUpgrades delay is zero iff
    // both wait-round bounds are zero, else within [min, max].
    for &version in KNOWN_PROTOCOL_VERSIONS {
        let p = consensus_params_for_version(version).unwrap();
        assert!(
            p.max_upgrade_wait_rounds >= p.min_upgrade_wait_rounds,
            "{version}: max_upgrade_wait_rounds ({}) < min_upgrade_wait_rounds ({})",
            p.max_upgrade_wait_rounds,
            p.min_upgrade_wait_rounds
        );
        if let Some((_, delay)) = p.approved_upgrade {
            if p.min_upgrade_wait_rounds != 0 || p.max_upgrade_wait_rounds != 0 {
                assert_ne!(
                    delay, 0,
                    "{version}: approved-upgrade delay must be nonzero"
                );
                assert!(
                    delay >= p.min_upgrade_wait_rounds && delay <= p.max_upgrade_wait_rounds,
                    "{version}: approved-upgrade delay {delay} out of [{}, {}]",
                    p.min_upgrade_wait_rounds,
                    p.max_upgrade_wait_rounds
                );
            } else {
                assert_eq!(
                    delay, 0,
                    "{version}: approved-upgrade delay must be zero when wait-round bounds are unset"
                );
            }
        }
    }
}
