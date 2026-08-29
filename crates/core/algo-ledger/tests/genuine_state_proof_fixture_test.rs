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

//! Issue #632: end-to-end acceptance of a GENUINE, honestly-produced
//! go-algorand v4.7.2-stable state proof, captured from a live 4-node
//! mixed-cluster run (3 real go-algorand relay+propose nodes + 1
//! algod-rust participate node, all online, real gossip/agreement over
//! real wall-clock time -- not synthetic/hand-constructed data).
//!
//! See `tests/fixtures/stateproof/_meta.json` for full provenance. This
//! closes the two acceptance criteria #626/#631's tracker work left open:
//! a genuine state proof captured as a golden fixture and verified through
//! `apply_state_proof`, and live mixed-cluster acceptance (the cluster's
//! own algod-rust node independently synced and accepted this exact block
//! over the real network as part of normal cluster operation).

use std::path::PathBuf;

use algo_ledger::apply_stateproof::apply_state_proof;
use algo_ledger::{ApplyContext, LedgerState, LedgerStore};
use algo_types::Address;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/stateproof")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path:?}: {e}"))
}

#[test]
fn accepts_genuine_captured_state_proof_from_live_cluster() {
    let voters_block = algo_codec::decode_block(&fixture("block_256_voters.bin"))
        .expect("decode captured voters-round block (256)");
    let prev_block = algo_codec::decode_block(&fixture("block_660_prev.bin"))
        .expect("decode captured prev block (660)");
    let stpf_block = algo_codec::decode_block(&fixture("block_661_stpf.bin"))
        .expect("decode captured stpf-carrying block (661)");

    assert_eq!(
        stpf_block.payset.len(),
        1,
        "block 661 must carry exactly the one real stpf txn"
    );
    let stpf_txn = &stpf_block.payset[0].txn;
    assert_eq!(stpf_txn.txn_type, algo_types::TxnType::from("stpf"));
    let message = stpf_txn
        .state_proof_message
        .as_ref()
        .expect("real stpf txn carries a state proof message");
    assert_eq!(message.last_attested_round, 512);
    let proof = stpf_txn
        .state_proof
        .as_ref()
        .expect("real stpf txn carries a state proof body");
    assert!(
        proof.signed_weight > 0,
        "genuine proof must have real signed weight"
    );
    assert!(
        proof
            .reveals
            .as_ref()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "genuine proof must carry at least one reveal"
    );

    // Build a ledger whose header chain matches what the real network had:
    // the voters-round block (256) whose StateProofTracking is this proof's
    // verification context, and the immediately-preceding block (660)
    // whose StateProofTracking.NextRound (512) the round-matching check
    // expects.
    let mut store = LedgerState::new();
    store
        .put_block(
            voters_block.round.0,
            &voters_block.current_protocol,
            &algo_codec::canonical_encode_block_header_from_block(&voters_block),
            &[],
        )
        .unwrap();
    store
        .put_block(
            prev_block.round.0,
            &prev_block.current_protocol,
            &algo_codec::canonical_encode_block_header_from_block(&prev_block),
            &[],
        )
        .unwrap();

    // Populate the verification-context tracker (issue #632) exactly as
    // `apply::apply_block_impl` would have when the real network first
    // applied the voters-round block (256) -- this is the actual, primary
    // resolution path for any consensus version this repo targets (v38+),
    // not the pre-v38 header fallback.
    let consensus =
        algo_types::consensus::consensus_params_for_version(&voters_block.current_protocol)
            .unwrap();
    algo_ledger::apply_stateproof::record_state_proof_verification_context(
        &mut store,
        voters_block.round.0,
        &voters_block.current_protocol,
        &voters_block.state_proof_tracking,
        consensus.state_proof_interval,
    )
    .unwrap();

    let mut ctx = ApplyContext::new_replay(0, Address::ZERO, stpf_block.round.0);
    ctx.validate = true;

    apply_state_proof(&store, &ctx, stpf_txn).unwrap_or_else(|e| {
        panic!("genuine, live-cluster-produced state proof must be accepted: {e}")
    });
}
