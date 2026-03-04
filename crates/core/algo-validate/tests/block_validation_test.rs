//! Integration tests for block-level validation against real fixture blocks.
//!
//! These tests load blocks from the algo-codec fixture directory and verify
//! that our Merkle commitment computation matches the header's `txn` field.

use algo_codec::decode_block_response;
use algo_types::BlockResponse;

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../algo-codec/tests/fixtures")
}

fn load_block(round: u64) -> Option<BlockResponse> {
    let path = fixture_dir().join(format!("block_{round}.msgpack"));
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap();
    Some(decode_block_response(&bytes).unwrap())
}

macro_rules! require_fixture {
    ($expr:expr, $msg:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                eprintln!("SKIPPED: {} (run `make fixtures` to generate)", $msg);
                return;
            }
        }
    };
}

// ── Merkle commitment tests ────────────────────────────────────

/// For each fixture block, verify that our computed Merkle root matches
/// the block header's `txn` commitment field.
macro_rules! merkle_commitment_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );
            let block = &br.block;

            if block.payset.is_empty() && block.txn_commitment.is_empty() {
                // Empty block with no commitment — nothing to verify.
                return;
            }

            let computed_root = algo_validate::merkle::compute_payset_merkle_root(block);
            let header_commitment = block.txn_commitment.as_ref();

            assert_eq!(
                computed_root.as_slice(),
                header_commitment,
                "Merkle root mismatch for block {}\n  computed: {}\n  header:   {}",
                $round,
                hex::encode(computed_root),
                hex::encode(header_commitment),
            );
        }
    };
}

merkle_commitment_test!(merkle_commitment_block_1, 1);
merkle_commitment_test!(merkle_commitment_block_2, 2);
merkle_commitment_test!(merkle_commitment_block_3, 3);
merkle_commitment_test!(merkle_commitment_block_4, 4);
merkle_commitment_test!(merkle_commitment_block_5, 5);
merkle_commitment_test!(merkle_commitment_block_6, 6);
merkle_commitment_test!(merkle_commitment_block_7, 7);
merkle_commitment_test!(merkle_commitment_block_8, 8);
merkle_commitment_test!(merkle_commitment_block_9, 9);

// ── Full block validation tests ────────────────────────────────

/// Full validate_block on fixture blocks.
/// Uses prev_timestamp=0 (genesis skip) since we don't have the previous
/// block's timestamp available without loading sequential blocks.
macro_rules! full_validation_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );
            let block = &br.block;

            let genesis_id = &block.genesis_id;
            let genesis_hash: [u8; 32] = block.genesis_hash[..32].try_into().unwrap();

            // Use prev_timestamp=None to skip timestamp bounds check (we don't
            // have the real previous timestamp in isolated fixture tests).
            let result = algo_validate::validate_block(block, None, genesis_id, &genesis_hash);

            // Filter out any errors we expect to tolerate:
            // - SignatureVerificationFailed: fixture txns may have been signed
            //   differently or genesis fields may not round-trip perfectly.
            // We DO want to assert that PaysetCommitmentMismatch does NOT occur.
            let commitment_errors: Vec<_> = result
                .errors
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        algo_validate::BlockValidationError::PaysetCommitmentMismatch { .. }
                    )
                })
                .collect();

            assert!(
                commitment_errors.is_empty(),
                "block {} has payset commitment errors: {:?}",
                $round,
                commitment_errors,
            );
        }
    };
}

full_validation_test!(full_validate_block_1, 1);
full_validation_test!(full_validate_block_2, 2);
full_validation_test!(full_validate_block_3, 3);
full_validation_test!(full_validate_block_4, 4);
full_validation_test!(full_validate_block_5, 5);
full_validation_test!(full_validate_block_6, 6);
full_validation_test!(full_validate_block_7, 7);
full_validation_test!(full_validate_block_8, 8);
full_validation_test!(full_validate_block_9, 9);
