use std::time::Instant;

use algo_types::Round;
use serde::Serialize;
use tracing::{debug, info, warn};

/// Result of comparing a Rust-decoded block against the raw reference bytes.
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonResult {
    pub round: u64,
    pub status: ComparisonStatus,
    pub mismatches: Vec<Mismatch>,
    pub duration_ms: u64,
    /// The block's timestamp (None if decode failed), so callers can track
    /// prev_timestamp for the next block without cascading false failures.
    pub block_timestamp: Option<i64>,
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
    SignatureInvalid {
        txn_index: usize,
        error: String,
    },
    BlockValidationFailed {
        error: String,
    },
}

/// Compare a block by decoding raw msgpack bytes and verifying structural consistency.
///
/// Phase 0 checks:
/// 1. Can we decode the raw bytes at all?
/// 2. Does decode → re-decode produce the same structural result?
/// 3. Round number, txn count, genesis ID match between decode passes.
/// 4. Field-level comparison of header fields and per-transaction fields.
///
/// Phase 1 checks (Epic 11):
/// 8. Block-level validation (protocol, timestamps, commitments, aggregate size).
///
/// # Arguments
///
/// * `raw_bytes` - The raw msgpack bytes of the block response.
/// * `round` - The expected round number.
/// * `prev_timestamp` - The previous block's timestamp, or `None` for genesis /
///   round-0 (skips timestamp validation).
/// * `genesis_id` - The expected genesis ID string.
/// * `genesis_hash` - The expected 32-byte genesis hash.
pub fn compare_block(
    raw_bytes: &[u8],
    round: Round,
    prev_timestamp: Option<i64>,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
) -> ComparisonResult {
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
                block_timestamp: None,
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

                    // Step 5b: Type-specific field comparisons
                    compare_txn_type_fields(&mut mismatches, i, &orig.txn, &rt.txn);

                    // Step 5c: Verify computed txn IDs are consistent across round-trip
                    let orig_txn_id = algo_codec::compute_txn_id(&orig.txn);
                    let rt_txn_id = algo_codec::compute_txn_id(&rt.txn);
                    compare_field(
                        &mut mismatches,
                        &format!("round-trip txns[{i}].computed_txid"),
                        &hex::encode(orig_txn_id.as_bytes()),
                        &hex::encode(rt_txn_id.as_bytes()),
                    );
                }

                // Step 6: Verify block digest is consistent across round-trip
                let orig_digest = algo_codec::compute_block_digest(&block_resp.block);
                let rt_digest = algo_codec::compute_block_digest(&re_decoded);
                compare_field(
                    &mut mismatches,
                    "round-trip header.computed_digest",
                    &hex::encode(orig_digest.as_bytes()),
                    &hex::encode(rt_digest.as_bytes()),
                );
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

    // Step 7+8 (merged): Block-level validation includes signature verification,
    // protocol checks, timestamps, commitments, and aggregate size.
    let validation_result =
        algo_validate::validate_block(block, prev_timestamp, genesis_id, genesis_hash);
    if !validation_result.is_valid {
        for err in &validation_result.errors {
            // Map signature errors to SignatureInvalid for backwards compatibility.
            match err {
                algo_validate::BlockValidationError::SignatureVerificationFailed {
                    txn_index,
                    error,
                } => {
                    mismatches.push(Mismatch::SignatureInvalid {
                        txn_index: *txn_index,
                        error: error.clone(),
                    });
                }
                _ => {
                    mismatches.push(Mismatch::BlockValidationFailed {
                        error: err.to_string(),
                    });
                }
            }
        }
    }
    info!(
        round = round.0,
        txn_count = validation_result.txn_count,
        total_txn_bytes = validation_result.total_txn_bytes,
        block_valid = validation_result.is_valid,
        "block validation complete"
    );

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
        block_timestamp: Some(block.timestamp),
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

/// Compare optional Address fields.
fn compare_opt_address(
    mismatches: &mut Vec<Mismatch>,
    path: &str,
    expected: &Option<algo_types::Address>,
    actual: &Option<algo_types::Address>,
) {
    match (expected, actual) {
        (Some(e), Some(a)) => compare_field(mismatches, path, e, a),
        (None, None) => {}
        (e, a) => {
            mismatches.push(Mismatch::FieldMismatch {
                path: path.into(),
                expected: format!("{e:?}"),
                actual: format!("{a:?}"),
            });
        }
    }
}

/// Compare optional ByteBuf fields as hex strings.
fn compare_opt_bytes_hex(
    mismatches: &mut Vec<Mismatch>,
    path: &str,
    expected: &Option<serde_bytes::ByteBuf>,
    actual: &Option<serde_bytes::ByteBuf>,
) {
    let e_hex = expected.as_ref().map(|b| hex::encode(b.as_slice()));
    let a_hex = actual.as_ref().map(|b| hex::encode(b.as_slice()));
    if e_hex != a_hex {
        mismatches.push(Mismatch::FieldMismatch {
            path: path.into(),
            expected: e_hex.unwrap_or_else(|| "None".into()),
            actual: a_hex.unwrap_or_else(|| "None".into()),
        });
    }
}

/// Compare optional Vec elements using a formatter function.
/// First compares lengths, then compares each element via `fmt`.
fn compare_opt_vec_elements<T>(
    mismatches: &mut Vec<Mismatch>,
    path: &str,
    expected: &Option<Vec<T>>,
    actual: &Option<Vec<T>>,
    fmt: impl Fn(&T) -> String,
) {
    match (expected, actual) {
        (None, None) => {}
        (Some(ev), Some(av)) => {
            if ev.len() != av.len() {
                mismatches.push(Mismatch::FieldMismatch {
                    path: format!("{path}.len"),
                    expected: ev.len().to_string(),
                    actual: av.len().to_string(),
                });
                return;
            }
            for (i, (e, a)) in ev.iter().zip(av.iter()).enumerate() {
                let e_str = fmt(e);
                let a_str = fmt(a);
                if e_str != a_str {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: format!("{path}[{i}]"),
                        expected: e_str,
                        actual: a_str,
                    });
                }
            }
        }
        (e, a) => {
            mismatches.push(Mismatch::FieldMismatch {
                path: format!("{path}.len"),
                expected: format!("{:?}", e.as_ref().map(|v| v.len())),
                actual: format!("{:?}", a.as_ref().map(|v| v.len())),
            });
        }
    }
}

/// Compare type-specific transaction fields based on the transaction type.
fn compare_txn_type_fields(
    mismatches: &mut Vec<Mismatch>,
    idx: usize,
    orig: &algo_types::Transaction,
    rt: &algo_types::Transaction,
) {
    let prefix = format!("round-trip txns[{idx}]");

    match orig.txn_type.as_str() {
        "pay" => {
            // Pay fields already compared in the common section (amount, receiver).
            compare_field(
                mismatches,
                &format!("{prefix}.close_remainder_to"),
                &orig.close_remainder_to,
                &rt.close_remainder_to,
            );
        }
        "axfer" => {
            compare_field(mismatches, &format!("{prefix}.xaid"), &orig.xaid, &rt.xaid);
            compare_field(
                mismatches,
                &format!("{prefix}.asset_amount"),
                &orig.asset_amount,
                &rt.asset_amount,
            );
            compare_opt_address(
                mismatches,
                &format!("{prefix}.asset_sender"),
                &orig.asset_sender,
                &rt.asset_sender,
            );
            compare_opt_address(
                mismatches,
                &format!("{prefix}.asset_receiver"),
                &orig.asset_receiver,
                &rt.asset_receiver,
            );
            compare_opt_address(
                mismatches,
                &format!("{prefix}.asset_close_to"),
                &orig.asset_close_to,
                &rt.asset_close_to,
            );
        }
        "acfg" => {
            compare_field(
                mismatches,
                &format!("{prefix}.config_asset"),
                &orig.config_asset,
                &rt.config_asset,
            );
            // Compare asset params if present
            match (&orig.asset_params, &rt.asset_params) {
                (Some(ep), Some(ap)) => {
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apar.total"),
                        &ep.total,
                        &ap.total,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apar.decimals"),
                        &ep.decimals,
                        &ap.decimals,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apar.default_frozen"),
                        &ep.default_frozen,
                        &ap.default_frozen,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apar.unit_name"),
                        &ep.unit_name,
                        &ap.unit_name,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apar.asset_name"),
                        &ep.asset_name,
                        &ap.asset_name,
                    );
                    compare_field(mismatches, &format!("{prefix}.apar.url"), &ep.url, &ap.url);
                    compare_opt_bytes_hex(
                        mismatches,
                        &format!("{prefix}.apar.metadata_hash"),
                        &ep.metadata_hash,
                        &ap.metadata_hash,
                    );
                    compare_opt_address(
                        mismatches,
                        &format!("{prefix}.apar.manager"),
                        &ep.manager,
                        &ap.manager,
                    );
                    compare_opt_address(
                        mismatches,
                        &format!("{prefix}.apar.reserve"),
                        &ep.reserve,
                        &ap.reserve,
                    );
                    compare_opt_address(
                        mismatches,
                        &format!("{prefix}.apar.freeze"),
                        &ep.freeze,
                        &ap.freeze,
                    );
                    compare_opt_address(
                        mismatches,
                        &format!("{prefix}.apar.clawback"),
                        &ep.clawback,
                        &ap.clawback,
                    );
                }
                (None, None) => {}
                (e, a) => {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: format!("{prefix}.asset_params"),
                        expected: (if e.is_some() { "Some" } else { "None" }).to_string(),
                        actual: (if a.is_some() { "Some" } else { "None" }).to_string(),
                    });
                }
            }
        }
        "afrz" => {
            compare_field(
                mismatches,
                &format!("{prefix}.freeze_asset"),
                &orig.freeze_asset,
                &rt.freeze_asset,
            );
            compare_opt_address(
                mismatches,
                &format!("{prefix}.freeze_account"),
                &orig.freeze_account,
                &rt.freeze_account,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.asset_frozen"),
                &orig.asset_frozen,
                &rt.asset_frozen,
            );
        }
        "appl" => {
            compare_field(
                mismatches,
                &format!("{prefix}.application_id"),
                &orig.application_id,
                &rt.application_id,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.on_completion"),
                &orig.on_completion,
                &rt.on_completion,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.extra_program_pages"),
                &orig.extra_program_pages,
                &rt.extra_program_pages,
            );
            compare_opt_bytes_hex(
                mismatches,
                &format!("{prefix}.approval_program"),
                &orig.approval_program,
                &rt.approval_program,
            );
            compare_opt_bytes_hex(
                mismatches,
                &format!("{prefix}.clear_state_program"),
                &orig.clear_state_program,
                &rt.clear_state_program,
            );
            // app_arguments: compare each element as hex bytes
            compare_opt_vec_elements(
                mismatches,
                &format!("{prefix}.app_arguments"),
                &orig.app_arguments,
                &rt.app_arguments,
                |e| hex::encode(e.as_slice()),
            );
            // accounts: compare each element
            compare_opt_vec_elements(
                mismatches,
                &format!("{prefix}.accounts"),
                &orig.accounts,
                &rt.accounts,
                |e| e.to_string(),
            );
            // foreign_apps: compare each element
            compare_opt_vec_elements(
                mismatches,
                &format!("{prefix}.foreign_apps"),
                &orig.foreign_apps,
                &rt.foreign_apps,
                |e| e.to_string(),
            );
            // foreign_assets: compare each element
            compare_opt_vec_elements(
                mismatches,
                &format!("{prefix}.foreign_assets"),
                &orig.foreign_assets,
                &rt.foreign_assets,
                |e| e.to_string(),
            );
            // boxes: compare each element's index and name
            compare_opt_vec_elements(
                mismatches,
                &format!("{prefix}.boxes"),
                &orig.boxes,
                &rt.boxes,
                |b| {
                    let name_hex = b
                        .name
                        .as_ref()
                        .map(|n| hex::encode(n.as_slice()))
                        .unwrap_or_default();
                    format!("{{i:{},n:{}}}", b.index, name_hex)
                },
            );
            // Global state schema
            match (&orig.global_state_schema, &rt.global_state_schema) {
                (Some(es), Some(as_)) => {
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apgs.num_uint"),
                        &es.num_uint,
                        &as_.num_uint,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apgs.num_byte_slice"),
                        &es.num_byte_slice,
                        &as_.num_byte_slice,
                    );
                }
                (None, None) => {}
                (e, a) => {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: format!("{prefix}.global_state_schema"),
                        expected: (if e.is_some() { "Some" } else { "None" }).to_string(),
                        actual: (if a.is_some() { "Some" } else { "None" }).to_string(),
                    });
                }
            }
            // Local state schema
            match (&orig.local_state_schema, &rt.local_state_schema) {
                (Some(es), Some(as_)) => {
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apls.num_uint"),
                        &es.num_uint,
                        &as_.num_uint,
                    );
                    compare_field(
                        mismatches,
                        &format!("{prefix}.apls.num_byte_slice"),
                        &es.num_byte_slice,
                        &as_.num_byte_slice,
                    );
                }
                (None, None) => {}
                (e, a) => {
                    mismatches.push(Mismatch::FieldMismatch {
                        path: format!("{prefix}.local_state_schema"),
                        expected: (if e.is_some() { "Some" } else { "None" }).to_string(),
                        actual: (if a.is_some() { "Some" } else { "None" }).to_string(),
                    });
                }
            }
        }
        "keyreg" => {
            compare_field(
                mismatches,
                &format!("{prefix}.vote_first"),
                &orig.vote_first,
                &rt.vote_first,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.vote_last"),
                &orig.vote_last,
                &rt.vote_last,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.vote_key_dilution"),
                &orig.vote_key_dilution,
                &rt.vote_key_dilution,
            );
            compare_field(
                mismatches,
                &format!("{prefix}.non_participation"),
                &orig.non_participation,
                &rt.non_participation,
            );
            compare_opt_bytes_hex(
                mismatches,
                &format!("{prefix}.vote_pk"),
                &orig.vote_pk,
                &rt.vote_pk,
            );
            compare_opt_bytes_hex(
                mismatches,
                &format!("{prefix}.selection_pk"),
                &orig.selection_pk,
                &rt.selection_pk,
            );
            compare_opt_bytes_hex(
                mismatches,
                &format!("{prefix}.state_proof_pk"),
                &orig.state_proof_pk,
                &rt.state_proof_pk,
            );
        }
        "stpf" => {
            compare_field(
                mismatches,
                &format!("{prefix}.state_proof_type"),
                &orig.state_proof_type,
                &rt.state_proof_type,
            );
            // Compare state proof body presence
            if orig.state_proof.is_some() != rt.state_proof.is_some() {
                mismatches.push(Mismatch::FieldMismatch {
                    path: format!("{prefix}.state_proof"),
                    expected: (if orig.state_proof.is_some() {
                        "Some"
                    } else {
                        "None"
                    })
                    .to_string(),
                    actual: (if rt.state_proof.is_some() {
                        "Some"
                    } else {
                        "None"
                    })
                    .to_string(),
                });
            }
        }
        other => {
            warn!(
                txn_index = idx,
                txn_type = other,
                "unknown transaction type, skipping type-specific field comparison"
            );
        }
    }
}
