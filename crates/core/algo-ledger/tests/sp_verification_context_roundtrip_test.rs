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

//! TDD regression for issue #1057: the `stateproofverification.verificationcontext`
//! BLOB written by `apply_stateproof.rs`'s real production writer
//! (`record_state_proof_verification_context`) must be decodable by
//! `catchpoint/verify.rs`'s catchpoint-export reader
//! (`build_sp_verification_blob` / `read_sp_verification_contexts`).
//!
//! Before the fix, the writer used a hand-rolled, non-msgpack binary layout
//! while the reader `rmp_serde::from_slice`d expecting go's real
//! `ledgercore.StateProofVerificationContext` msgpack shape — any row
//! written by the real production path failed to export with "invalid
//! type: integer `0`, expected struct SpVerificationCtxFull" as soon as the
//! `stateproofverification` table had any rows (past the first
//! state-proof-interval boundary).
//!
//! This test writes a context through the actual production call
//! (`record_state_proof_verification_context`, exactly as
//! `apply::apply_block_impl` calls it on every "voters round" block), then
//! opens a second, independent connection to the same on-disk tracker
//! database — mirroring the real read-only snapshot connection automatic
//! catchpoint export opens — and confirms `build_sp_verification_blob`
//! decodes it successfully.

use algo_ledger::apply_stateproof::record_state_proof_verification_context;
use algo_ledger::catchpoint::verify::build_sp_verification_blob;
use algo_ledger::sqlite::{tracker_path_for_prefix, SqliteLedger};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};

fn temp_ledger_path(test_name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "algod-rust-sp-verification-roundtrip-{test_name}-{}",
        std::process::id()
    ))
}

/// Build a `"spt"` tracking value with `v` (voters commitment) and `t`
/// (online total weight) fields under map key `0`
/// (`protocol.StateProofBasic`), matching the wire shape
/// `block_header::state_proof_voters_commitment`/
/// `state_proof_online_total_weight` read back out. Mirrors the private
/// `tracking_value` test helper in `apply_stateproof.rs`.
fn tracking_value(voters_commitment: &[u8], total_weight: u64) -> Option<rmpv::Value> {
    let fields = vec![
        (
            rmpv::Value::from("v"),
            rmpv::Value::Binary(voters_commitment.to_vec()),
        ),
        (rmpv::Value::from("t"), rmpv::Value::from(total_weight)),
    ];
    Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(0u64),
        rmpv::Value::Map(fields),
    )]))
}

#[test]
fn context_written_by_the_real_tracker_decodes_via_the_catchpoint_export_reader() {
    let ledger_path = temp_ledger_path("basic");
    let _ = std::fs::remove_file(tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));

    let interval = consensus_params_for_version(CONSENSUS_V41)
        .unwrap()
        .state_proof_interval;

    {
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();

        // Exactly what `apply::apply_block_impl` does for every applied
        // "voters round" block (round % StateProofInterval == 0),
        // independent of whether that round itself carries a StateProofTx.
        let voters_commitment = vec![0xABu8; 64];
        record_state_proof_verification_context(
            &mut ledger,
            0, // voters round
            CONSENSUS_V41,
            &tracking_value(&voters_commitment, 1_000_000_000),
            interval,
        )
        .unwrap();
    }

    // Open a fresh, independent connection to the same on-disk tracker
    // database, mirroring the read-only snapshot connection real automatic
    // catchpoint export opens (`SqliteLedger`'s spawned export thread).
    let read_conn = rusqlite::Connection::open(tracker_path_for_prefix(&ledger_path)).unwrap();

    // Before the fix: this returned
    // `Err(VerificationError("decode state proof verification context: ..."))`
    // because the writer's hand-rolled bytes aren't valid msgpack for the
    // reader's expected struct shape.
    let blob = build_sp_verification_blob(&read_conn)
        .expect("catchpoint export must decode a context written by the real production writer");

    // Sanity: the blob actually carries the recorded context (not just an
    // empty wrapper masking a silently-skipped row).
    let decoded: rmpv::Value = rmpv::decode::read_value(&mut &blob[..]).unwrap();
    let rmpv::Value::Map(pairs) = &decoded else {
        panic!("expected a map, got {decoded:?}");
    };
    assert_eq!(
        pairs.len(),
        1,
        "expected the single 'spd' field, got {pairs:?}"
    );
    assert_eq!(pairs[0].0.as_str(), Some("spd"));
    let rmpv::Value::Array(entries) = &pairs[0].1 else {
        panic!("expected an array for 'spd', got {:?}", pairs[0].1);
    };
    assert_eq!(entries.len(), 1);

    let _ = std::fs::remove_file(tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}
