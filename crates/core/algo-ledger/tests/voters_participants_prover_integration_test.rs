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

//! Issue #912: full end-to-end proof that persisting the voters snapshot's
//! full `Vec<Participant>` array (rather than just its compact commitment
//! digest) is actually *sufficient* to build a state proof -- not merely
//! that the array round-trips through storage as inert bytes.
//!
//! Round trip exercised here, against both `LedgerStore` backends
//! (`LedgerState` and `SqliteLedger`):
//!
//! 1. Record a voters snapshot (`voters_tracker::record_voters_snapshot`)
//!    for a set of online accounts with real Falcon-backed state-proof
//!    keys (`merklesig::Secrets`).
//! 2. Retrieve the full participant array + rebuilt vector-commitment tree
//!    from storage (`voters_tracker::voters_participants_and_tree`) --
//!    simulating what a future signing/proving daemon (issue #814) would
//!    do long after the snapshot round itself has been pruned from any
//!    in-memory cache.
//! 3. Build a real `algo_consensus_crypto::stateproof::Prover` from that
//!    retrieved data (`Prover::make_prover`), have each participant sign
//!    the message with their actual secrets, gather the signatures via
//!    `stateproof_worker::SigCollector` (PR #898/#814's gathering logic),
//!    and produce a `StateProof`.
//! 4. Independently verify the produced proof with
//!    `stateproof::Verifier`, constructed only from the compact commitment
//!    root [`voters_tracker`] already persisted separately -- proving the
//!    two persisted artifacts (compact commitment, full participant array)
//!    are mutually consistent.

use std::collections::BTreeMap;

use algo_consensus_crypto::merklesig;
use algo_consensus_crypto::stateproof::{MessageHash, Prover, Verifier};
use algo_ledger::stateproof_worker::SigCollector;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::voters_tracker::{record_voters_snapshot, voters_participants_and_tree};
use algo_ledger::LedgerState;
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};
use algo_types::{AccountData, AccountStatus, Address};

/// Build `n` online accounts, each with a real `merklesig::Secrets` keypair
/// registered as its `state_proof_id` commitment, and record a voters
/// snapshot for them at `snapshot_round`. Returns the secrets (in the same
/// order as the accounts were inserted -- selection order is by descending
/// balance, so callers should use descending balances if they need a
/// specific order) keyed by address.
fn record_snapshot_with_real_keys<L: LedgerStore>(
    store: &mut L,
    snapshot_round: u64,
    params: &algo_types::consensus::ConsensusParams,
    n: u8,
) -> BTreeMap<Address, merklesig::Secrets> {
    let vote_rnd = snapshot_round
        .saturating_add(params.state_proof_voters_lookback)
        .saturating_add(params.state_proof_interval);

    let mut secrets_by_addr = BTreeMap::new();
    for i in 1..=n {
        let secrets = merklesig::Secrets::new(vote_rnd, vote_rnd, 1).unwrap();
        let commitment = secrets.get_verifier().commitment;
        let addr = Address([i; 32]);
        store.set_account(
            &addr,
            AccountData {
                micro_algos: (i as u64 + 1) * 1_000_000,
                status: AccountStatus::Online,
                vote_first_valid: 0,
                vote_last_valid: vote_rnd + 1000,
                state_proof_id: Some(commitment),
                ..Default::default()
            },
        );
        secrets_by_addr.insert(addr, secrets);
    }

    record_voters_snapshot(store, snapshot_round, 0, params).unwrap();
    secrets_by_addr
}

/// The shared end-to-end assertion, generic over the `LedgerStore` backend
/// so it runs identically against `LedgerState` and `SqliteLedger`.
fn build_and_verify_proof_from_stored_participants<L: LedgerStore>(mut store: L) {
    let params = consensus_params_for_version(CONSENSUS_V41).unwrap();
    // v41: interval 256, lookback 16 -- 240 is a snapshot round
    // ((240 + 16) % 256 == 0).
    let snapshot_round = 240u64;
    let state_proof_round =
        snapshot_round + params.state_proof_voters_lookback + params.state_proof_interval; // 512

    let secrets_by_addr = record_snapshot_with_real_keys(&mut store, snapshot_round, &params, 4);

    // Simulate a signing/proving daemon reading this back long after
    // `record_voters_snapshot` returned -- the whole point of issue #912.
    let (participants, tree) = voters_participants_and_tree(&store, snapshot_round)
        .unwrap()
        .expect("full participant array must survive the round trip through storage");
    assert_eq!(participants.len(), secrets_by_addr.len());

    // The rebuilt tree's root must match the compact commitment persisted
    // separately -- the two artifacts must describe the exact same voter
    // set.
    let (commitment_root, _online_total_weight) =
        store.get_voters_snapshot(snapshot_round).unwrap().unwrap();
    assert_eq!(tree.root(), commitment_root);

    // addr -> position in the participant/commitment array, exactly as a
    // real daemon would build it from the retrieved data (go:
    // `voters.AddrToPos`).
    let mut addr_to_pos = BTreeMap::new();
    for (addr, secrets) in &secrets_by_addr {
        let commitment = secrets.get_verifier().commitment;
        let pos = participants
            .iter()
            .position(|p| p.pk.commitment == commitment)
            .expect("every registered participant must appear in the retrieved array");
        addr_to_pos.insert(*addr, pos as u64);
    }

    let message_hash: MessageHash = [0x5Au8; 32];
    let proven_weight: u64 = participants.iter().map(|p| p.weight).min().unwrap_or(0);

    let prover = Prover::make_prover(
        message_hash,
        state_proof_round,
        proven_weight,
        participants,
        tree,
        0, // strength_target: 0 accepts any nonzero signed weight, matching this workspace's other Prover tests.
    )
    .unwrap();
    let mut collector = SigCollector::new(prover, addr_to_pos);

    for (addr, secrets) in &secrets_by_addr {
        let sig = secrets
            .get_signer(state_proof_round)
            .sign_bytes(&message_hash)
            .unwrap();
        collector.insert_sig(*addr, sig, true).unwrap_or_else(|e| {
            panic!("signature from a retrieved-from-storage participant must insert: {e}")
        });
    }
    assert!(collector.prover.ready(), "all four participants signed");

    let proof = collector
        .prover
        .create_proof()
        .expect("a state proof must be constructible from the retrieved participant array");

    // Independently verify against the *compact* commitment root -- proving
    // the full participant array retrieved from storage produces a proof
    // that a verifier holding only the (separately persisted) commitment
    // digest accepts.
    let verifier = Verifier::new(commitment_root, proven_weight, 0).unwrap();
    verifier
        .verify(state_proof_round, message_hash, &proof)
        .expect("proof built from the ledger-retrieved participant array must verify");
}

#[test]
fn round_trips_through_ledger_state_into_a_verifiable_proof() {
    build_and_verify_proof_from_stored_participants(LedgerState::new());
}

#[test]
fn round_trips_through_sqlite_ledger_into_a_verifiable_proof() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("voters_participants_prover.sqlite");
    let store = algo_ledger::sqlite::SqliteLedger::open(&path).expect("open sqlite ledger");
    build_and_verify_proof_from_stored_participants(store);
}

/// Pruning (`voters_tracker::prune_voters_snapshots`) must actually delete
/// the persisted participant rows in the real SQLite backend, not just in
/// the in-memory `LedgerState` map already covered by `voters_tracker.rs`'s
/// own unit tests.
#[test]
fn sqlite_ledger_prunes_participants_past_the_recovery_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("voters_participants_prune.sqlite");
    let mut store = algo_ledger::sqlite::SqliteLedger::open(&path).expect("open sqlite ledger");

    let params = consensus_params_for_version(CONSENSUS_V41).unwrap();
    let snapshot_round = 240u64; // (240 + 16) % 256 == 0

    let _secrets = record_snapshot_with_real_keys(&mut store, snapshot_round, &params, 2);
    assert!(
        voters_participants_and_tree(&store, snapshot_round)
            .unwrap()
            .is_some(),
        "participants must be present right after the snapshot"
    );

    // Far enough ahead that round 240's served state-proof round (512)
    // falls below the recovery floor -- mirrors
    // `prune_voters_snapshots_removes_entries_past_the_recovery_window` in
    // `voters_tracker.rs`'s own unit tests, but against the real sqlite
    // backend.
    let far_round = 512 + 256 * 10 + 1000;
    algo_ledger::voters_tracker::prune_voters_snapshots(&mut store, far_round, &None, &params)
        .unwrap();
    assert!(
        voters_participants_and_tree(&store, snapshot_round)
            .unwrap()
            .is_none(),
        "stale participant array must be pruned from the sqlite table"
    );
}
