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
/// 4. Field-level comparison of header fields and per-transaction fields.
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
                // Compare round
                if re_decoded.round != block.round {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: "round-trip header.round".into(),
                        expected: block.round.to_string(),
                        actual: re_decoded.round.to_string(),
                    });
                }

                // Compare txn count
                if re_decoded.payset.len() != block.payset.len() {
                    mismatches.push(Mismatch::TxnCountMismatch {
                        expected: block.payset.len(),
                        actual: re_decoded.payset.len(),
                    });
                }

                // Step 4: Field-level header comparisons on round-trip
                compare_field(
                    &mut mismatches,
                    "round-trip header.genesis_id",
                    &block.genesis_id,
                    &re_decoded.genesis_id,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.genesis_hash",
                    &hex::encode(&block.genesis_hash),
                    &hex::encode(&re_decoded.genesis_hash),
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.timestamp",
                    &block.timestamp,
                    &re_decoded.timestamp,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.current_protocol",
                    &block.current_protocol,
                    &re_decoded.current_protocol,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.fee_sink",
                    &block.fee_sink,
                    &re_decoded.fee_sink,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.rewards_pool",
                    &block.rewards_pool,
                    &re_decoded.rewards_pool,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.branch",
                    &hex::encode(&block.branch),
                    &hex::encode(&re_decoded.branch),
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.seed",
                    &hex::encode(&block.seed),
                    &hex::encode(&re_decoded.seed),
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.txn_commitment",
                    &hex::encode(&block.txn_commitment),
                    &hex::encode(&re_decoded.txn_commitment),
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.txn_counter",
                    &block.txn_counter,
                    &re_decoded.txn_counter,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.rewards_level",
                    &block.rewards_level,
                    &re_decoded.rewards_level,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.rewards_rate",
                    &block.rewards_rate,
                    &re_decoded.rewards_rate,
                );
                compare_field(
                    &mut mismatches,
                    "round-trip header.proposer",
                    &block.proposer,
                    &re_decoded.proposer,
                );

                // Step 5: Per-transaction field comparisons
                let txn_count = block.payset.len().min(re_decoded.payset.len());
                for i in 0..txn_count {
                    let orig = &block.payset[i];
                    let rt = &re_decoded.payset[i];

                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].type"),
                        &orig.txn.txn_type,
                        &rt.txn.txn_type,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].sender"),
                        &orig.txn.sender,
                        &rt.txn.sender,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].fee"),
                        &orig.txn.fee,
                        &rt.txn.fee,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].first_valid"),
                        &orig.txn.first_valid,
                        &rt.txn.first_valid,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].last_valid"),
                        &orig.txn.last_valid,
                        &rt.txn.last_valid,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].amount"),
                        &orig.txn.amount,
                        &rt.txn.amount,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].receiver"),
                        &orig.txn.receiver,
                        &rt.txn.receiver,
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].sig"),
                        &hex::encode(&orig.sig),
                        &hex::encode(&rt.sig),
                    );
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].note"),
                        &hex::encode(&orig.txn.note),
                        &hex::encode(&rt.txn.note),
                    );
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

/// Compare two values, pushing a FieldMismatch if they differ.
fn compare_field<T: std::fmt::Display + PartialEq>(
    mismatches: &mut Vec<Mismatch>,
    path: &str,
    expected: &T,
    actual: &T,
) {
    if expected != actual {
        mismatches.push(Mismatch::FieldMismatch {
            path: path.into(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
}
