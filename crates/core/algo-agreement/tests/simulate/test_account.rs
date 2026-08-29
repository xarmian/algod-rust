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

// Test-account fabrication for the full-consensus simulate harness.
//
// Mirrors go-algorand `agreement/agreementtest/simulate_test.go::generateNAccounts`
// (the helper that fills a temp DB with participation keys for `TestSimulate`).
//
// Each `TestAccount` carries a real VRF keypair + real OTS secrets, plus the
// derived public-key fields the agreement protocol exposes via
// `OnlineAccountData` and `ParticipationRecord`. These are what the
// pseudonode signs proposals/votes with and what the verifier checks
// credentials against.

use algo_consensus_crypto::vrf::VrfKeypair;
use algo_consensus_crypto::OneTimeSignatureSecrets;
use algo_types::{Address, Round};
use sha2::{Digest, Sha512_256};

/// One participant's full key material — secrets (used by the pseudonode
/// for signing) plus the derived public IDs (used by the ledger /
/// `ParticipationRecord` for verification + sortition).
pub struct TestAccount {
    /// Account address (= 32-byte hash of the VRF public key, so each
    /// fabricated account has a deterministic, distinct address).
    pub address: Address,
    /// VRF keypair: secret used to prove sortition; public used by the
    /// committee module to verify the proof.
    pub vrf: VrfKeypair,
    /// One-time-signature secrets covering rounds [first_valid, last_valid].
    pub ots: OneTimeSignatureSecrets,
    /// Public OTS verifier (= "VoteID" in the Go protocol). Cached for
    /// `OnlineAccountData::vote_id` and `ParticipationRecord::vote_id`.
    pub vote_id: [u8; 32],
    /// First round these keys are valid.
    pub vote_first_valid: Round,
    /// Last round these keys are valid.
    pub vote_last_valid: Round,
    /// Key dilution parameter — the OTS key tree's branching factor.
    pub vote_key_dilution: u64,
}

impl TestAccount {
    /// Public VRF selection key (= "SelectionID" in the Go protocol).
    pub fn selection_id(&self) -> [u8; 32] {
        *self.vrf.pk.as_bytes()
    }
}

/// Generate `n` test accounts with deterministic VRF + OTS keys covering
/// rounds `[first_round, last_round]` at the given key dilution.
///
/// Mirrors Go's `generateNAccounts(t, N, firstRound, lastRound, fee)` —
/// but Rust avoids Go's per-account temp DB plumbing because
/// `OneTimeSignatureSecrets::generate` already produces an in-memory
/// secrets object covering the requested batch range.
///
/// Determinism: each account's **VRF keypair and address** are seeded
/// from `(salt, index)` so two calls with the same `salt` produce the
/// same VRF keys and the same addresses. The OTS secrets, by contrast,
/// are produced via `OneTimeSignatureSecrets::generate(...)` which uses
/// fresh ed25519 randomness internally — so OTS verifiers / signatures
/// differ across calls. That's acceptable for the simulate harness:
/// vote signatures verify against whatever `vote_id` was published in
/// the same run, and tests don't rely on cross-run signature stability.
/// The salt still lets multiple tests (or repeated runs) get independent
/// account *identities* without collision.
pub fn generate_n_accounts(
    n: usize,
    first_round: Round,
    last_round: Round,
    key_dilution: u64,
    salt: u64,
) -> Vec<TestAccount> {
    use algo_consensus_crypto::one_time_id_for_round;
    let first_id = one_time_id_for_round(first_round.0, key_dilution);
    let last_id = one_time_id_for_round(last_round.0, key_dilution);
    // Inclusive batch range. `OneTimeSignatureSecrets::generate(start, num)`
    // generates `num` consecutive batches starting at `start`.
    let num_batches = last_id.batch.saturating_sub(first_id.batch) + 1;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // Seed = SHA-512/256("test-account" || salt || index) — gives a
        // deterministic, namespaced 32-byte value per account.
        let mut hasher = Sha512_256::new();
        hasher.update(b"test-account");
        hasher.update(salt.to_le_bytes());
        hasher.update((i as u64).to_le_bytes());
        let seed: [u8; 32] = hasher.finalize().into();

        let vrf = VrfKeypair::from_seed(seed);
        let ots = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = ots.verifier();

        // Address = SHA-512/256("test-account-addr" || vrf.pk). Distinct
        // per account (VRF pks are distinct because seeds are distinct).
        let mut addr_hasher = Sha512_256::new();
        addr_hasher.update(b"test-account-addr");
        addr_hasher.update(vrf.pk.as_bytes());
        let addr_bytes: [u8; 32] = addr_hasher.finalize().into();

        out.push(TestAccount {
            address: Address(addr_bytes),
            vrf,
            ots,
            vote_id,
            vote_first_valid: first_round,
            vote_last_valid: last_round,
            vote_key_dilution: key_dilution,
        });
    }
    out
}
