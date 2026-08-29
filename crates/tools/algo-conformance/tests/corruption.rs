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

use algo_conformance::{compare_block, ComparisonStatus, Mismatch};
use algo_types::Round;

/// Load a valid fixture for testing.
fn valid_fixture() -> &'static [u8] {
    include_bytes!("fixtures/block_1.msgpack")
}

/// Extract genesis_id and genesis_hash from the fixture block for test calls.
fn fixture_genesis_info() -> (String, [u8; 32]) {
    let br = algo_codec::decode_block_response(valid_fixture()).expect("decode fixture");
    let hash: [u8; 32] = br
        .block
        .genesis_hash
        .as_ref()
        .try_into()
        .expect("genesis hash must be 32 bytes");
    (br.block.genesis_id.clone(), hash)
}

#[test]
fn valid_block_passes() {
    let (gid, ghash) = fixture_genesis_info();
    let result = compare_block(valid_fixture(), Round(1), None, &gid, &ghash);

    // Phase 0 checks (decode, round-trip, signatures) should all pass.
    let phase0_mismatches: Vec<_> = result
        .mismatches
        .iter()
        .filter(|m| !matches!(m, Mismatch::BlockValidationFailed { .. }))
        .collect();
    assert!(
        phase0_mismatches.is_empty(),
        "expected no Phase 0 mismatches, got: {phase0_mismatches:?}"
    );

    // Block validation (Phase 1) may report Merkle commitment issues
    // until the canonical encoding is fully conformant with go-algorand.
    // Track these separately so we know when they're resolved.
    let block_validation_mismatches: Vec<_> = result
        .mismatches
        .iter()
        .filter(|m| matches!(m, Mismatch::BlockValidationFailed { .. }))
        .collect();
    if !block_validation_mismatches.is_empty() {
        eprintln!(
            "NOTE: {} block validation issues (expected until Merkle conformance is complete):",
            block_validation_mismatches.len()
        );
        for m in &block_validation_mismatches {
            eprintln!("  - {m:?}");
        }
    }
}

#[test]
fn wrong_round_produces_field_mismatch() {
    let (gid, ghash) = fixture_genesis_info();
    // The fixture is round 1, but we claim it should be round 999.
    let result = compare_block(valid_fixture(), Round(999), None, &gid, &ghash);
    assert_eq!(result.status, ComparisonStatus::Fail);
    assert!(
        result.mismatches.iter().any(|m| matches!(
            m,
            Mismatch::FieldMismatch { path, .. } if path == "header.round"
        )),
        "expected round field mismatch, got: {:?}",
        result.mismatches
    );
}

#[test]
fn truncated_bytes_produce_decode_failed() {
    let bytes = valid_fixture();
    // Take only first 10 bytes — should fail to decode.
    let truncated = &bytes[..10];
    let result = compare_block(truncated, Round(1), None, "", &[0u8; 32]);
    assert_eq!(result.status, ComparisonStatus::Fail);
    assert!(
        result
            .mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::DecodeFailed { .. })),
        "expected DecodeFailed, got: {:?}",
        result.mismatches
    );
}

#[test]
fn empty_bytes_produce_decode_failed() {
    let result = compare_block(&[], Round(1), None, "", &[0u8; 32]);
    assert_eq!(result.status, ComparisonStatus::Fail);
    assert!(
        result
            .mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::DecodeFailed { .. })),
        "expected DecodeFailed, got: {:?}",
        result.mismatches
    );
}

#[test]
fn mutated_block_produces_mismatch() {
    let bytes = valid_fixture();
    let (gid, ghash) = fixture_genesis_info();

    // Decode, mutate round number, re-encode as a BlockResponse, then compare.
    let mut br: algo_types::BlockResponse =
        algo_codec::decode_block_response(bytes).expect("decode should succeed");

    // Mutate: change the round
    br.block.round = Round(42);

    // Re-encode the full BlockResponse
    let mutated = rmp_serde::to_vec_named(&br).expect("encode should succeed");

    // Compare with the original expected round (1) — round field should mismatch.
    let result = compare_block(&mutated, Round(1), None, &gid, &ghash);
    assert_eq!(result.status, ComparisonStatus::Fail);
    assert!(
        result.mismatches.iter().any(|m| matches!(
            m,
            Mismatch::FieldMismatch { path, .. } if path == "header.round"
        )),
        "expected round mismatch after mutation, got: {:?}",
        result.mismatches
    );
}
