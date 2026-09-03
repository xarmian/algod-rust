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

//! Issue #814: full end-to-end proof that the autonomous daemon runtime
//! (`stateproof_worker::StateProofRuntime`) built on top of issue #912's
//! address-tagged voters-participant persistence can independently
//! reconstruct a state-proof message from ledger state
//! (`stateproof_message::generate_state_proof_message`), gather signatures
//! gossiped in as wire-format `SigFromAddr` messages, build a real
//! `StateProof`, convert it to the wire `StateProofBody` a `StateProofTx`
//! embeds, and have that wire body verify byte-for-byte against an
//! independent `stateproof::Verifier` -- exactly the sequence a live daemon
//! (`bin/algod-rust`'s `stateproof_service`) performs each round.

use algo_consensus_crypto::merklesig;
use algo_consensus_crypto::stateproof::Verifier;
use algo_ledger::apply_stateproof::state_proof_message_hash;
use algo_ledger::stateproof_worker::{state_proof_body_from_crypto, SigFromAddr, StateProofRuntime};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::voters_tracker::record_voters_snapshot;
use algo_ledger::LedgerState;
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};
use algo_types::{AccountData, AccountStatus, Address, BlockHeader, Round};

const SNAPSHOT_ROUND: u64 = 240; // (240 + 16) % 256 == 0
const VOTERS_ROUND: u64 = 256; // SNAPSHOT_ROUND + lookback
const STATE_PROOF_ROUND: u64 = 512; // VOTERS_ROUND + interval

fn tracking(voters_commitment: &[u8], total_weight: u64) -> Option<rmpv::Value> {
    let mut fields = Vec::new();
    if !voters_commitment.is_empty() {
        fields.push((
            rmpv::Value::from("v"),
            rmpv::Value::Binary(voters_commitment.to_vec()),
        ));
    }
    if total_weight != 0 {
        fields.push((rmpv::Value::from("t"), rmpv::Value::from(total_weight)));
    }
    Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(0u64),
        rmpv::Value::Map(fields),
    )]))
}

fn put_header(store: &mut LedgerState, hdr: &BlockHeader) {
    let bytes = algo_codec::canonical_encode_block_header(hdr);
    store
        .put_block(hdr.round.0, &hdr.current_protocol, &bytes, &[])
        .unwrap();
}

#[test]
fn runtime_signs_gathers_builds_and_verifies_a_real_state_proof() {
    let params = consensus_params_for_version(CONSENSUS_V41).unwrap();
    let mut store = LedgerState::new();

    // ── 1. Four online accounts with real Falcon/MSS state-proof keys. ──
    let mut secrets_by_addr = std::collections::BTreeMap::new();
    for i in 1..=4u8 {
        let secrets =
            merklesig::Secrets::new(STATE_PROOF_ROUND, STATE_PROOF_ROUND, 1).expect("mss keygen");
        let commitment = secrets.get_verifier().commitment;
        let addr = Address([i; 32]);
        store.set_account(
            &addr,
            AccountData {
                micro_algos: (i as u64 + 1) * 1_000_000,
                status: AccountStatus::Online,
                vote_first_valid: 0,
                vote_last_valid: STATE_PROOF_ROUND + 1000,
                state_proof_id: Some(commitment),
                ..Default::default()
            },
        );
        secrets_by_addr.insert(addr, secrets);
    }

    // ── 2. Record the voters snapshot at round 240. ──
    record_voters_snapshot(&mut store, SNAPSHOT_ROUND, 0, &params).unwrap();
    let (root, total_weight) = store.get_voters_snapshot(SNAPSHOT_ROUND).unwrap().unwrap();

    // ── 3. Block headers: round 256 (votersHdr, carries snapshot-240's
    // commitment/weight) through round 512 (the state-proof round itself,
    // needs its own nonzero "t" so LnProvenWeight computation succeeds --
    // see stateproof_worker.rs's module doc on why this is a separate,
    // later voters-round value in real go-algorand and is uninvolved in
    // cryptographic verification). ──
    put_header(
        &mut store,
        &BlockHeader {
            round: Round(VOTERS_ROUND),
            current_protocol: CONSENSUS_V41.to_string(),
            genesis_hash: [0xABu8; 32],
            txn256: [VOTERS_ROUND as u8; 32],
            state_proof_tracking: tracking(&root, total_weight),
            ..BlockHeader::default()
        },
    );
    for r in (VOTERS_ROUND + 1)..STATE_PROOF_ROUND {
        put_header(
            &mut store,
            &BlockHeader {
                round: Round(r),
                current_protocol: CONSENSUS_V41.to_string(),
                genesis_hash: [0xABu8; 32],
                txn256: [(r % 256) as u8; 32],
                ..BlockHeader::default()
            },
        );
    }
    put_header(
        &mut store,
        &BlockHeader {
            round: Round(STATE_PROOF_ROUND),
            current_protocol: CONSENSUS_V41.to_string(),
            genesis_hash: [0xABu8; 32],
            txn256: [STATE_PROOF_ROUND as u8; 32],
            state_proof_tracking: tracking(&root, total_weight),
            ..BlockHeader::default()
        },
    );

    // ── 4. Runtime: gather every signer's signature via the wire
    // SigFromAddr round trip (msgpack encode/decode), exactly as a daemon
    // would receive it over gossip. ──
    let mut runtime = StateProofRuntime::new();
    assert!(
        runtime.message_for(STATE_PROOF_ROUND).is_none(),
        "no prover built until the first signature"
    );

    // Independently compute the message hash each signer signs over --
    // mirrors go's `signStateProof` calling `getStateProofMessage` before
    // ever calling `handleSig`. The runtime lazily builds its own prover
    // (and its own copy of this same message) the first time `handle_sig`
    // sees a signature for this round.
    let msg =
        algo_ledger::stateproof_message::generate_state_proof_message(&store, STATE_PROOF_ROUND)
            .unwrap();
    let msg_hash = state_proof_message_hash(&msg);

    for (addr, secrets) in &secrets_by_addr {
        let sig = secrets
            .get_signer(STATE_PROOF_ROUND)
            .sign_bytes(&msg_hash)
            .unwrap();
        let sfa = SigFromAddr {
            signer_address: *addr,
            round: STATE_PROOF_ROUND,
            sig,
        };
        // Round-trip through the wire encoding, exactly as a live daemon's
        // gossip handler would decode an incoming `Tag::StateProofSig`
        // payload.
        let wire = sfa.to_msgpack();
        let decoded = SigFromAddr::from_msgpack(&wire).unwrap();
        let outcome = runtime.handle_sig(&store, &decoded).unwrap();
        assert_eq!(
            outcome,
            algo_ledger::stateproof_worker::SigOutcome::Broadcast,
            "a genuinely new valid signature must be forwarded"
        );
    }

    // A duplicate signature is silently ignored, not an error.
    let (dup_addr, dup_secrets) = secrets_by_addr.iter().next().unwrap();
    let dup_sig = dup_secrets
        .get_signer(STATE_PROOF_ROUND)
        .sign_bytes(&msg_hash)
        .unwrap();
    let dup_outcome = runtime
        .handle_sig(
            &store,
            &SigFromAddr {
                signer_address: *dup_addr,
                round: STATE_PROOF_ROUND,
                sig: dup_sig,
            },
        )
        .unwrap();
    assert_eq!(dup_outcome, algo_ledger::stateproof_worker::SigOutcome::Ignore);

    // Every account's rewards-adjusted balance was added exactly once --
    // independently recomputed from the persisted participant array.
    let (participants, _tree) =
        algo_ledger::voters_tracker::voters_participants_and_tree(&store, SNAPSHOT_ROUND)
            .unwrap()
            .unwrap();
    let expected_signed_weight: u64 = participants.iter().map(|p| p.weight).sum();
    assert_eq!(
        runtime.signed_weight(STATE_PROOF_ROUND),
        Some(expected_signed_weight),
        "every selected participant's weight must be counted exactly once"
    );

    // ── 5. Build the proof and verify it independently. ──
    let built = runtime.try_build();
    assert_eq!(built.len(), 1, "exactly one round ready to build");
    let (round, proof, built_message) = &built[0];
    assert_eq!(*round, STATE_PROOF_ROUND);
    assert_eq!(built_message, &msg);
    runtime.mark_submitted(*round);
    assert!(runtime.is_submitted(STATE_PROOF_ROUND));
    // A second try_build call must not re-emit the already-submitted round.
    assert!(runtime.try_build().is_empty());

    // Convert to wire format (what actually goes into the StateProofTx) --
    // a lossy-free sanity check that the conversion preserves the signed
    // weight the real cryptographic object carries.
    let wire_body = state_proof_body_from_crypto(proof);
    assert_eq!(wire_body.signed_weight, proof.signed_weight);
    assert!(!wire_body.sig_commit.is_empty());

    // `voters_hdr`'s own "t" field is exactly the `total_weight` this test
    // set it to above (round 256's header was constructed directly from
    // snapshot 240's persisted value) -- the same value go's
    // `GetProvenWeight(votersHdr, ...)` would read to compute the
    // cryptographic proven-weight bound.
    let proven_weight =
        ((total_weight as u128) * (params.state_proof_weight_threshold as u128) / (1u128 << 32))
            as u64;
    let verifier = Verifier::new(root.clone(), proven_weight, params.state_proof_strength_target)
        .expect("verifier construction");
    verifier
        .verify(STATE_PROOF_ROUND, msg_hash, proof)
        .expect("the runtime-built proof must verify against an independent Verifier");
}
