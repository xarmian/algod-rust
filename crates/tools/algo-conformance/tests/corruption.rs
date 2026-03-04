use algo_conformance::{compare_block, ComparisonStatus, Mismatch};
use algo_types::Round;

/// Load a valid fixture for testing.
fn valid_fixture() -> &'static [u8] {
    include_bytes!("fixtures/block_1.msgpack")
}

#[test]
fn valid_block_passes() {
    let result = compare_block(valid_fixture(), Round(1));
    assert_eq!(result.status, ComparisonStatus::Pass);
    assert!(result.mismatches.is_empty());
}

#[test]
fn wrong_round_produces_field_mismatch() {
    // The fixture is round 1, but we claim it should be round 999.
    let result = compare_block(valid_fixture(), Round(999));
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
    let result = compare_block(truncated, Round(1));
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
    let result = compare_block(&[], Round(1));
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

    // Decode, mutate round number, re-encode as a BlockResponse, then compare.
    let mut br: algo_types::BlockResponse =
        algo_codec::decode_block_response(bytes).expect("decode should succeed");

    // Mutate: change the round
    br.block.round = Round(42);

    // Re-encode the full BlockResponse
    let mutated = rmp_serde::to_vec_named(&br).expect("encode should succeed");

    // Compare with the original expected round (1) — round field should mismatch.
    let result = compare_block(&mutated, Round(1));
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
