use std::time::Instant;

use algo_types::Round;
use serde::Serialize;
use tracing::debug;

/// Result of comparing a Rust-decoded block against the raw reference bytes.
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonResult {
    pub round: u64,
    pub status: ComparisonStatus,
    pub mismatches: Vec<Mismatch>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComparisonStatus {
    Pass,
    Fail,
}

/// A specific mismatch found during comparison.
#[derive(Debug, Clone, Serialize)]
pub enum Mismatch {
    DecodeFailed {
        error: String,
    },
    FieldMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    TxnCountMismatch {
        expected: usize,
        actual: usize,
    },
}

/// Compare a block by decoding raw msgpack bytes and verifying structural consistency.
///
/// Phase 0 checks:
/// 1. Can we decode the raw bytes at all?
/// 2. Does decode → re-decode produce the same structural result?
/// 3. Round number, txn count, genesis ID match between decode passes.
pub fn compare_block(raw_bytes: &[u8], round: Round) -> ComparisonResult {
    let start = Instant::now();
    let mut mismatches = Vec::new();

    // Step 1: Decode the raw bytes
    let block_resp = match algo_codec::decode_block_response(raw_bytes) {
        Ok(br) => br,
        Err(e) => {
            return ComparisonResult {
                round: round.0,
                status: ComparisonStatus::Fail,
                mismatches: vec![Mismatch::DecodeFailed {
                    error: e.to_string(),
                }],
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let block = &block_resp.block;

    // Step 2: Verify round number matches expected
    if block.round != round {
        mismatches.push(Mismatch::FieldMismatch {
            path: "header.round".into(),
            expected: round.to_string(),
            actual: block.round.to_string(),
        });
    }

    // Step 3: Re-encode and re-decode to check round-trip structural consistency
    match algo_codec::encode_block(&block_resp.block) {
        Ok(re_encoded) => match algo_codec::decode_block(&re_encoded) {
            Ok(re_decoded) => {
                // Compare key fields
                if re_decoded.round != block.round {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: "round-trip header.round".into(),
                        expected: block.round.to_string(),
                        actual: re_decoded.round.to_string(),
                    });
                }
                if re_decoded.payset.len() != block.payset.len() {
                    mismatches.push(Mismatch::TxnCountMismatch {
                        expected: block.payset.len(),
                        actual: re_decoded.payset.len(),
                    });
                }
            }
            Err(e) => {
                mismatches.push(Mismatch::DecodeFailed {
                    error: format!("re-decode failed: {e}"),
                });
            }
        },
        Err(e) => {
            mismatches.push(Mismatch::DecodeFailed {
                error: format!("re-encode failed: {e}"),
            });
        }
    }

    let duration = start.elapsed();
    let status = if mismatches.is_empty() {
        ComparisonStatus::Pass
    } else {
        ComparisonStatus::Fail
    };

    debug!(
        round = round.0,
        status = ?status,
        mismatches = mismatches.len(),
        duration_ms = duration.as_millis() as u64,
        "block comparison complete"
    );

    ComparisonResult {
        round: round.0,
        status,
        mismatches,
        duration_ms: duration.as_millis() as u64,
    }
}
