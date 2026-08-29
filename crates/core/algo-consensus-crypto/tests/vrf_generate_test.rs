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

//! Writer-side parity tests for `VrfKeypair::generate` / `generate_with_rng`.
//!
//! Mirrors `../go-algorand/crypto/vrf.go::GenerateVRFSecrets` —
//! the OS-RNG path. Read paths (sign / verify) are covered by the
//! existing `vrf_parity` integration test and inline `vrf.rs` tests.

use algo_consensus_crypto::vrf::VrfKeypair;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;

#[test]
fn generate_produces_unique_keypairs_over_100_iterations() {
    let mut pks: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..100 {
        let kp = VrfKeypair::generate();
        assert!(
            pks.insert(kp.pk.0),
            "iteration {i}: VrfKeypair::generate returned a duplicate public key — RNG is broken"
        );
    }
}

#[test]
fn generate_with_rng_is_deterministic_for_a_fixed_seed() {
    // Two ChaCha20 streams seeded identically must produce identical keypairs.
    let mut rng_a = ChaCha20Rng::seed_from_u64(0xCAFE_F00D_DEAD_BEEF);
    let mut rng_b = ChaCha20Rng::seed_from_u64(0xCAFE_F00D_DEAD_BEEF);

    let kp_a = VrfKeypair::generate_with_rng(&mut rng_a);
    let kp_b = VrfKeypair::generate_with_rng(&mut rng_b);

    assert_eq!(
        kp_a.pk.0, kp_b.pk.0,
        "deterministic seed must yield same pk"
    );
    assert_eq!(
        kp_a.sk.seed(),
        kp_b.sk.seed(),
        "deterministic seed must yield same sk seed"
    );
}

#[test]
fn generate_with_rng_advances_state_across_successive_calls() {
    // Calls draw from the RNG in sequence, so successive calls on the same
    // RNG must produce distinct keypairs (assuming RNG state advances).
    let mut rng = ChaCha20Rng::seed_from_u64(0x1234_5678);
    let kp1 = VrfKeypair::generate_with_rng(&mut rng);
    let kp2 = VrfKeypair::generate_with_rng(&mut rng);
    assert_ne!(
        kp1.pk.0, kp2.pk.0,
        "successive generate_with_rng calls must consume RNG state"
    );
}

#[test]
fn generate_then_prove_then_verify_roundtrip() {
    // A freshly-generated keypair must round-trip: prove with sk, verify with pk.
    for _ in 0..16 {
        let kp = VrfKeypair::generate();
        let msg = b"sortition input alpha";
        let (proof, output) = kp.sk.prove(msg);

        let verified = kp.pk.verify(&proof, msg);
        assert!(
            verified.is_some(),
            "generated keypair must verify its own proof"
        );
        assert_eq!(
            verified.unwrap().0,
            output.0,
            "verified output must match prove output"
        );
    }
}
