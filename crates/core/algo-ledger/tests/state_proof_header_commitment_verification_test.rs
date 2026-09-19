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

//! Port of go-algorand's `TestStateProofMessageCommitmentVerification`
//! (`test/e2e-go/features/stateproofs/stateproofs_test.go:316`, part of
//! Phase 17 issue #1457 batch 9, docs/phase17/parity_e2e.md): for every
//! round attested to by a state-proof message, the message's
//! `BlockHeadersCommitment` must validate a single-leaf Merkle inclusion
//! proof of that round's light block header.
//!
//! Go's version drives this against a live 3-node network (fetching each
//! round's proof over `LightBlockHeaderProof` REST calls and the message
//! over the state-proofs endpoint). algod-rust has no live goal-rust-driven
//! multi-round network harness that reaches state-proof rounds, but the
//! exact cryptographic claim under test — "each attested round's light
//! header is a genuine, verifiable leaf of the message's
//! `BlockHeadersCommitment`" — only depends on
//! `algo_ledger::stateproof_message::generate_state_proof_message`/
//! `fetch_light_headers` and `algo_consensus_crypto::merklearray`'s
//! prove/verify pair, so this test reconstructs the same claim entirely
//! from ledger state: build `StateProofInterval` real block headers, derive
//! the message (as a signing node would), then for *every* round in
//! `[FirstAttestedRound, LastAttestedRound]` independently rebuild the
//! vector-commitment tree, generate that round's single-leaf proof, and
//! verify it against the message's own `BlockHeadersCommitment` via
//! `verify_vector_commitment` — the same call go's test makes via
//! `merklearray.VerifyVectorCommitment`. A final negative case (tampering
//! one header) proves the verifier actually rejects a wrong leaf rather
//! than trivially accepting everything.

use algo_consensus_crypto::light_block_header::LightBlockHeaderArray;
use algo_consensus_crypto::merklearray::{
    build_vector_commitment_tree, verify_vector_commitment, HashFactory, HashType,
};
use algo_ledger::stateproof_message::{fetch_light_headers, generate_state_proof_message};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::LedgerState;
use algo_types::consensus::CONSENSUS_V41;
use algo_types::{BlockHeader, Round};

/// v41's `StateProofInterval` (also used by the crate-internal
/// `stateproof_message` unit tests and `stateproof_runtime_integration_test.rs`).
const INTERVAL: u64 = 256;

/// A nonzero online-weight tracking value on the interval-closing header,
/// so `calculate_ln_proven_weight` inside `generate_state_proof_message`
/// has something to take the log of (mirrors `stateproof_message.rs`'s own
/// `tracking_value` test helper).
fn tracking(total_weight: u64) -> Option<rmpv::Value> {
    Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(0u64),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("t"),
            rmpv::Value::from(total_weight),
        )]),
    )]))
}

fn header_at(round: u64, state_proof_tracking: Option<rmpv::Value>) -> BlockHeader {
    BlockHeader {
        round: Round(round),
        current_protocol: CONSENSUS_V41.to_string(),
        genesis_hash: [0xABu8; 32],
        state_proof_tracking,
        // Distinct per-round txn256 (and hence a distinct light-header
        // block_hash, since v41 has StateProofBlockHashInLightHeader=true)
        // so every leaf in the interval is unique -- a commitment built
        // over identical leaves wouldn't actually exercise per-index
        // inclusion.
        txn256: [
            (round & 0xFF) as u8,
            ((round >> 8) & 0xFF) as u8,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
            0xEE,
        ],
        ..BlockHeader::default()
    }
}

fn put_header(store: &mut LedgerState, hdr: &BlockHeader) {
    let bytes = algo_codec::canonical_encode_block_header(hdr);
    store
        .put_block(hdr.round.0, &hdr.current_protocol, &bytes, &[])
        .unwrap();
}

#[test]
fn every_attested_round_in_the_message_proves_against_block_headers_commitment() {
    let mut store = LedgerState::new();
    for r in 1..INTERVAL {
        put_header(&mut store, &header_at(r, None));
    }
    put_header(&mut store, &header_at(INTERVAL, tracking(5_000_000)));

    let msg = generate_state_proof_message(&store, INTERVAL).unwrap();
    assert_eq!(msg.first_attested_round, 1);
    assert_eq!(msg.last_attested_round, INTERVAL);

    // Independently rebuild the exact vector-commitment tree
    // `generate_state_proof_message`/`create_header_commitment` built
    // internally (it only returns the root), so we can generate
    // single-leaf proofs to check against that root.
    let light_headers = fetch_light_headers(&store, INTERVAL, INTERVAL).unwrap();
    assert_eq!(light_headers.len(), INTERVAL as usize);
    let array = LightBlockHeaderArray(light_headers.clone());
    let factory = HashFactory::new(HashType::Sha256);
    let tree = build_vector_commitment_tree(&array, factory).unwrap();
    assert_eq!(
        tree.root(),
        msg.block_headers_commitment.clone().into_vec(),
        "independently rebuilt tree must have the same root as the message's own \
         BlockHeadersCommitment"
    );

    // go's test: `for rnd := stateProofMessage.FirstAttestedRound; rnd <=
    // stateProofMessage.LastAttestedRound; rnd++` -- fetch each round's
    // proof and verify it against `stateProofMessage.BlockHeadersCommitment`
    // via `merklearray.VerifyVectorCommitment`.
    for round in msg.first_attested_round..=msg.last_attested_round {
        let idx = round - msg.first_attested_round;
        let single_leaf = tree
            .prove_single_leaf(idx)
            .unwrap_or_else(|e| panic!("prove_single_leaf({idx}) for round {round} failed: {e}"));
        let header = &light_headers[idx as usize];
        assert_eq!(header.round, round);

        verify_vector_commitment(
            &msg.block_headers_commitment.clone().into_vec(),
            &[(
                idx,
                header as &dyn algo_consensus_crypto::merklearray::Hashable,
            )],
            &single_leaf.proof,
        )
        .unwrap_or_else(|e| {
            panic!("verify_vector_commitment failed for round {round} (idx {idx}): {e}")
        });
    }

    // Negative case: a proof for round R must NOT verify against a
    // different round's light header -- proves the check is a genuine
    // per-leaf binding, not a proof that happens to always pass.
    let idx0 = 0u64;
    let proof0 = tree.prove_single_leaf(idx0).unwrap();
    let wrong_header = &light_headers[idx0 as usize + 1];
    let mismatch = verify_vector_commitment(
        &msg.block_headers_commitment.clone().into_vec(),
        &[(
            idx0,
            wrong_header as &dyn algo_consensus_crypto::merklearray::Hashable,
        )],
        &proof0.proof,
    );
    assert!(
        mismatch.is_err(),
        "a proof for one round's index must not verify against a different round's header"
    );
}
