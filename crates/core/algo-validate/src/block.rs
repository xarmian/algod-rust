// Epic 11: Block-level validation orchestrator.
//
// Validates a complete block by checking:
//   1. Protocol version (known version list)
//   2. Timestamp bounds (monotonic, max increment)
//   3. Per-transaction rules (fees, rounds, note size, etc.)
//   4. Signature verification (ed25519, multisig, logicsig)
//   5. Transaction group validity
//   6. Genesis field consistency
//   7. Payset Merkle commitment (txn field in block header)
//   8. Aggregate block size (total encoded txn bytes)
//
// Collects ALL errors rather than failing fast, returning a complete
// validation report.

use std::fmt;

use algo_avm::group::GroupBudget;
use algo_codec::canonical_encode_signed_txn_in_block;
use algo_types::{Block, SignedTransaction};

use crate::merkle::{
    compute_payset_flat_commitment, compute_payset_flat_commitment_raw, compute_payset_merkle_root,
    compute_payset_merkle_root_raw, compute_vector_commitment, compute_vector_commitment_raw,
    HashAlgo,
};
use crate::rules::{
    consensus_params_for_version, has_payset_commit_merkle, has_txn256, has_txn512,
    max_txn_bytes_per_block, validate_genesis_consistency, validate_group_fees_with_params,
    validate_lease_constraints, validate_transaction_group, validate_transaction_wellformed,
    SpecialAddresses, MAX_TIMESTAMP_INCREMENT,
};
use crate::signature::{verify_auth_addr_sender_diff, verify_transaction_signature};

/// Result of validating a complete block.
#[derive(Debug, Clone)]
pub struct BlockValidationResult {
    /// The round number of the validated block.
    pub round: u64,
    /// Whether the block passed all validation checks.
    pub is_valid: bool,
    /// All validation errors found (empty if is_valid is true).
    pub errors: Vec<BlockValidationError>,
    /// Number of transactions in the block's payset.
    pub txn_count: usize,
    /// Total encoded size of all transactions (canonical SignedTxnInBlock bytes).
    pub total_txn_bytes: usize,
}

/// An error found during block validation.
#[derive(Debug, Clone)]
pub enum BlockValidationError {
    /// The block's protocol version is not in the known version list.
    UnknownProtocolVersion { version: String },
    /// The block's protocol version is empty.
    EmptyProtocolVersion,
    /// Block timestamp is earlier than the previous block's timestamp.
    TimestampTooOld { current: i64, previous: i64 },
    /// Block timestamp exceeds the previous block's timestamp by more than the
    /// maximum allowed increment.
    TimestampTooNew {
        current: i64,
        previous: i64,
        max_increment: i64,
    },
    /// The block header's `txn` commitment does not match the computed Merkle root.
    PaysetCommitmentMismatch { expected: String, computed: String },
    /// A transaction failed per-txn rules validation.
    TransactionValidationFailed { txn_index: usize, error: String },
    /// A transaction's signature verification failed.
    SignatureVerificationFailed { txn_index: usize, error: String },
    /// Transaction group validation failed.
    GroupValidationFailed { error: String },
    /// Lease constraint validation failed (duplicate sender+lease within a group).
    LeaseConstraintFailed { error: String },
    /// Genesis ID/hash consistency check failed.
    GenesisConsistencyFailed { error: String },
    /// A transaction group's pooled fees are insufficient.
    GroupFeePoolingFailed {
        group_id: String,
        total_fee: u64,
        required_fee: u64,
    },
    /// A vector commitment field (txn256 or txn512) does not match the computed value.
    VectorCommitmentMismatch {
        field: String,
        expected: String,
        computed: String,
    },
    /// Total encoded transaction bytes exceed the per-block limit.
    AggregateBlockSizeExceeded {
        total_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProtocolVersion { version } => {
                write!(f, "unknown protocol version: {version}")
            }
            Self::EmptyProtocolVersion => write!(f, "block protocol version is empty"),
            Self::TimestampTooOld { current, previous } => {
                write!(
                    f,
                    "block timestamp {current} is before previous block timestamp {previous}"
                )
            }
            Self::TimestampTooNew {
                current,
                previous,
                max_increment,
            } => {
                write!(
                    f,
                    "block timestamp {current} exceeds previous {previous} by more than {max_increment}s"
                )
            }
            Self::PaysetCommitmentMismatch { expected, computed } => {
                write!(
                    f,
                    "payset commitment mismatch: header={expected}, computed={computed}"
                )
            }
            Self::TransactionValidationFailed { txn_index, error } => {
                write!(f, "txn {txn_index} rules failed: {error}")
            }
            Self::SignatureVerificationFailed { txn_index, error } => {
                write!(f, "txn {txn_index} signature failed: {error}")
            }
            Self::GroupValidationFailed { error } => {
                write!(f, "group validation failed: {error}")
            }
            Self::LeaseConstraintFailed { error } => {
                write!(f, "lease constraint failed: {error}")
            }
            Self::GenesisConsistencyFailed { error } => {
                write!(f, "genesis consistency failed: {error}")
            }
            Self::GroupFeePoolingFailed {
                group_id,
                total_fee,
                required_fee,
            } => {
                write!(
                    f,
                    "group {group_id} pooled fee {total_fee} is below required {required_fee}"
                )
            }
            Self::VectorCommitmentMismatch {
                field,
                expected,
                computed,
            } => {
                write!(
                    f,
                    "vector commitment mismatch for {field}: header={expected}, computed={computed}"
                )
            }
            Self::AggregateBlockSizeExceeded {
                total_bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "aggregate block size {total_bytes} exceeds limit {max_bytes}"
                )
            }
        }
    }
}

/// Validate a complete block.
///
/// # Arguments
///
/// * `block` - The block to validate.
/// * `prev_timestamp` - The previous block's timestamp, or `None` for genesis /
///   round-0 (skips timestamp validation). When `Some(t)` where `t <= 0`,
///   timestamp bounds are also skipped, matching Go's `prev.TimeStamp > 0` guard.
/// * `genesis_id` - The expected genesis ID string (from the block header or network config).
/// * `genesis_hash` - The expected 32-byte genesis hash.
///
/// # Validation steps
///
/// 1. Protocol version check
/// 2. Timestamp bounds (skipped when prev_timestamp is None)
/// 3. Per-transaction: restore genesis fields, then validate rules + signatures
/// 4. Transaction group validation
/// 5. Genesis consistency
/// 6. Lease constraints
/// 7. Payset Merkle commitment
/// 8. Aggregate block size
///
/// All errors are collected (no fail-fast) and returned in the result.
pub fn validate_block(
    block: &Block,
    prev_timestamp: Option<i64>,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    raw_payset_blobs: Option<&[Vec<u8>]>,
) -> BlockValidationResult {
    let mut errors = Vec::new();
    let round = block.round.0;
    let txn_count = block.payset.len();

    // 1. Protocol version.
    if block.current_protocol.is_empty() {
        errors.push(BlockValidationError::EmptyProtocolVersion);
    } else if crate::rules::validate_protocol_version(&block.current_protocol).is_err() {
        errors.push(BlockValidationError::UnknownProtocolVersion {
            version: block.current_protocol.clone(),
        });
    }

    // 2. Timestamp bounds.
    // Go (block.go PreCheck): only checks timestamp when prev.TimeStamp > 0.
    // A zero or negative previous timestamp means we're in the prefix of the
    // chain where timestamps haven't been established yet — skip the check.
    // We also skip when prev_timestamp is None (genesis / round-0).
    if let Some(prev_ts) = prev_timestamp {
        if prev_ts > 0 {
            if block.timestamp < prev_ts {
                errors.push(BlockValidationError::TimestampTooOld {
                    current: block.timestamp,
                    previous: prev_ts,
                });
            }
            if block.timestamp > prev_ts + MAX_TIMESTAMP_INCREMENT {
                errors.push(BlockValidationError::TimestampTooNew {
                    current: block.timestamp,
                    previous: prev_ts,
                    max_increment: MAX_TIMESTAMP_INCREMENT,
                });
            }
        }
    }

    // 3. Per-transaction validation.
    // Clone the payset so we can restore genesis fields for signature verification.
    // The block strips genesis_id (when hgi=true) and genesis_hash (always) from
    // transactions for space efficiency. We must restore them before verifying
    // signatures since the signed message includes these fields.
    //
    // IMPORTANT: Restore from the block header's own genesis fields, NOT from the
    // caller-supplied expected values. This ensures signatures are verified against
    // what the block actually claims, and the separate genesis consistency check
    // (step 5) can detect if the block's genesis fields differ from expected.
    // Resolve version-aware consensus params for this block's protocol.
    let params = consensus_params_for_version(&block.current_protocol).unwrap_or_default();
    let spec = SpecialAddresses {
        fee_sink: block.fee_sink,
        rewards_pool: block.rewards_pool,
    };

    let mut restored_payset = block.payset.clone();
    for stx in &mut restored_payset {
        if stx.has_genesis_id && stx.txn.genesis_id.is_empty() {
            stx.txn.genesis_id.clone_from(&block.genesis_id);
        }
        if stx.txn.genesis_hash.is_empty() {
            stx.txn.genesis_hash.clone_from(&block.genesis_hash);
        }
    }

    let mut total_txn_bytes: usize = 0;

    // Detect transaction groups for per-group LogicSig budget pooling.
    // go-algorand isolates LogicSig budget per transaction group — each group
    // gets its own pool of `group_size * LOGICSIG_BUDGET` opcodes.
    let groups = detect_validation_groups(&restored_payset);

    for group in &groups {
        let mut lsig_budget = GroupBudget::for_logicsig(group.len());

        for &(idx, stx) in group {
            // State proof transactions (`stpf`) are special protocol-level
            // transactions injected by consensus. They legitimately have fee=0
            // and carry no standard ed25519/multisig/logicsig signature. Skip
            // per-txn rules and signature verification for these; their validity
            // is ensured by the state proof verification layer (out of scope for
            // stateless validation).
            if stx.txn.txn_type == "stpf" && stx.txn.state_proof.is_some() {
                // Still accumulate encoded size for aggregate block size check.
                let encoded = canonical_encode_signed_txn_in_block(&block.payset[idx]);
                total_txn_bytes += encoded.len();
                continue;
            }

            // Per-txn rules (fees, rounds, note size, etc.)
            // If the transaction is part of a group, allow fee pooling so the
            // per-txn minimum fee check is skipped. Group-level fee validation
            // happens after the group ID check (step 4b).
            // Free heartbeats (ungrouped, fee < min, v40+) are also fee-exempt.
            let allow_fee_pooling = !stx.txn.group.is_empty();
            if let Err(e) =
                validate_transaction_wellformed(&stx.txn, allow_fee_pooling, &params, Some(&spec))
            {
                errors.push(BlockValidationError::TransactionValidationFailed {
                    txn_index: idx,
                    error: e.to_string(),
                });
            }

            // Signature verification (includes LogicSig TEAL evaluation).
            if let Err(e) =
                verify_transaction_signature(stx, &restored_payset, idx, &mut lsig_budget)
            {
                errors.push(BlockValidationError::SignatureVerificationFailed {
                    txn_index: idx,
                    error: e.to_string(),
                });
            }

            // AuthAddr != Sender check (Go: EnforceAuthAddrSenderDiff, future only).
            if let Err(e) = verify_auth_addr_sender_diff(stx, params.enforce_auth_addr_sender_diff)
            {
                errors.push(BlockValidationError::TransactionValidationFailed {
                    txn_index: idx,
                    error: e.to_string(),
                });
            }

            // Accumulate encoded size for aggregate check.
            // Use the original (stripped) encoding for size, matching go-algorand
            // which counts the in-block encoded size.
            let encoded = canonical_encode_signed_txn_in_block(&block.payset[idx]);
            total_txn_bytes += encoded.len();
        }
    }

    // 4a. Transaction group validation (uses restored payset for group ID computation).
    if let Err(e) = validate_transaction_group(&restored_payset) {
        errors.push(BlockValidationError::GroupValidationFailed {
            error: e.to_string(),
        });
    }

    // 4b. Group fee pooling — verify each group's total fees meet the minimum.
    // Uses version-aware params for heartbeat exemption and min fee.
    {
        let txn_refs: Vec<&SignedTransaction> = restored_payset.iter().collect();
        if let Err(e) = validate_group_fees_with_params(&txn_refs, &params) {
            errors.push(e);
        }
    }

    // 5. Genesis consistency — two levels:
    // 5a. Block header's genesis fields must match the expected (caller-supplied) values.
    //     This detects cross-network blocks or header corruption.
    if !block.genesis_id.is_empty() && block.genesis_id != genesis_id {
        errors.push(BlockValidationError::GenesisConsistencyFailed {
            error: format!(
                "block header genesis ID '{}' does not match expected '{}'",
                block.genesis_id, genesis_id
            ),
        });
    }
    if !block.genesis_hash.is_empty() && block.genesis_hash.as_ref() != genesis_hash {
        errors.push(BlockValidationError::GenesisConsistencyFailed {
            error: format!(
                "block header genesis hash {} does not match expected {}",
                hex::encode(&block.genesis_hash),
                hex::encode(genesis_hash)
            ),
        });
    }
    // 5b. Per-txn genesis fields (restored from block header) must be self-consistent.
    if let Err(e) = validate_genesis_consistency(
        &restored_payset,
        &block.genesis_id,
        block.genesis_hash.as_ref(),
    ) {
        errors.push(BlockValidationError::GenesisConsistencyFailed {
            error: e.to_string(),
        });
    }

    // 6. Lease constraints.
    if let Err(e) = validate_lease_constraints(&restored_payset) {
        errors.push(BlockValidationError::LeaseConstraintFailed {
            error: e.to_string(),
        });
    }

    // 7. Payset commitment.
    // The `txn` field in the block header is the commitment over the payset.
    // For v26+ this uses a Merkle tree; for older versions it uses a flat hash.
    //
    // When raw_payset_blobs is provided, we use the raw bytes directly for STIB
    // hashing (preserving unknown fields), and commitment mismatches are errors.
    // When None (unit tests, backward compat), we use typed re-encoding and
    // mismatches are warn-only.
    let version = &block.current_protocol;
    // Only use raw blobs if the count matches the payset; otherwise fall back
    // to warn-only typed path to avoid panics on malformed input.
    let raw_payset_blobs = raw_payset_blobs.filter(|blobs| blobs.len() == block.payset.len());
    let has_raw = raw_payset_blobs.is_some();
    if !block.txn_commitment.is_empty() || !block.payset.is_empty() {
        if has_payset_commit_merkle(version) {
            // Merkle tree commitment (v26+).
            let computed_root = if let Some(raw_blobs) = raw_payset_blobs {
                compute_payset_merkle_root_raw(block, raw_blobs)
            } else {
                compute_payset_merkle_root(block)
            };
            let expected = block.txn_commitment.as_ref();
            if expected != computed_root.as_slice() {
                if has_raw {
                    errors.push(BlockValidationError::PaysetCommitmentMismatch {
                        expected: hex::encode(expected),
                        computed: hex::encode(computed_root),
                    });
                } else {
                    eprintln!(
                        "WARNING: round {}: payset commitment mismatch: header={}, computed={}",
                        round,
                        hex::encode(expected),
                        hex::encode(computed_root),
                    );
                }
            }
        } else {
            // Flat commitment (pre-v26).
            let computed_flat = if let Some(raw_blobs) = raw_payset_blobs {
                compute_payset_flat_commitment_raw(raw_blobs)
            } else {
                compute_payset_flat_commitment(&block.payset)
            };
            let expected = block.txn_commitment.as_ref();
            if expected != computed_flat.as_slice() {
                if has_raw {
                    errors.push(BlockValidationError::PaysetCommitmentMismatch {
                        expected: hex::encode(expected),
                        computed: hex::encode(computed_flat),
                    });
                } else {
                    eprintln!(
                        "WARNING: round {}: payset commitment mismatch: header={}, computed={}",
                        round,
                        hex::encode(expected),
                        hex::encode(computed_flat),
                    );
                }
            }
        }
    }

    // 7b. Vector commitment: txn256 (SHA-256, v34+).
    if has_txn256(version) && !block.txn256.is_empty() {
        let computed = if let Some(raw_blobs) = raw_payset_blobs {
            compute_vector_commitment_raw(block, HashAlgo::Sha256, raw_blobs)
        } else {
            compute_vector_commitment(block, HashAlgo::Sha256)
        };
        if block.txn256.as_ref() != computed.as_slice() {
            if has_raw {
                errors.push(BlockValidationError::VectorCommitmentMismatch {
                    field: "txn256".into(),
                    expected: hex::encode(&block.txn256),
                    computed: hex::encode(&computed),
                });
            } else {
                eprintln!(
                    "WARNING: round {}: txn256 vector commitment mismatch: header={}, computed={}",
                    round,
                    hex::encode(&block.txn256),
                    hex::encode(&computed),
                );
            }
        }
    }

    // 7c. Vector commitment: txn512 (SHA-512, v41+).
    if has_txn512(version) && !block.txn512.is_empty() {
        let computed = if let Some(raw_blobs) = raw_payset_blobs {
            compute_vector_commitment_raw(block, HashAlgo::Sha512, raw_blobs)
        } else {
            compute_vector_commitment(block, HashAlgo::Sha512)
        };
        if block.txn512.as_ref() != computed.as_slice() {
            if has_raw {
                errors.push(BlockValidationError::VectorCommitmentMismatch {
                    field: "txn512".into(),
                    expected: hex::encode(&block.txn512),
                    computed: hex::encode(&computed),
                });
            } else {
                eprintln!(
                    "WARNING: round {}: txn512 vector commitment mismatch: header={}, computed={}",
                    round,
                    hex::encode(&block.txn512),
                    hex::encode(&computed),
                );
            }
        }
    }

    // 8. Aggregate block size.
    if !block.current_protocol.is_empty() {
        if let Ok(max_bytes) = max_txn_bytes_per_block(&block.current_protocol) {
            if total_txn_bytes > max_bytes {
                errors.push(BlockValidationError::AggregateBlockSizeExceeded {
                    total_bytes: total_txn_bytes,
                    max_bytes,
                });
            }
        }
    }

    let is_valid = errors.is_empty();
    BlockValidationResult {
        round,
        is_valid,
        errors,
        txn_count,
        total_txn_bytes,
    }
}

/// Detect transaction groups within a payset for per-group LogicSig budget pooling.
///
/// Returns groups of `(original_index, &SignedTransaction)` tuples. Consecutive
/// transactions sharing the same non-empty `group` hash form an atomic group.
/// Transactions with an empty group hash are standalone (single-txn group).
fn detect_validation_groups(payset: &[SignedTransaction]) -> Vec<Vec<(usize, &SignedTransaction)>> {
    let mut groups: Vec<Vec<(usize, &SignedTransaction)>> = Vec::new();
    let mut i = 0;
    while i < payset.len() {
        let stx = &payset[i];
        if stx.txn.group.is_empty() {
            groups.push(vec![(i, stx)]);
            i += 1;
        } else {
            let group_hash = &stx.txn.group;
            let mut group = vec![(i, stx)];
            i += 1;
            while i < payset.len() && payset[i].txn.group == *group_hash {
                group.push((i, &payset[i]));
                i += 1;
            }
            groups.push(group);
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, SignedTransaction, Transaction};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;

    fn test_genesis_hash() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    /// Build a minimal valid block with zero transactions.
    fn empty_block() -> Block {
        Block {
            round: Round(1),
            branch: ByteBuf::from(vec![0u8; 32]),
            seed: ByteBuf::from(vec![0u8; 32]),
            txn_commitment: ByteBuf::new(),
            timestamp: 100,
            genesis_id: "test-v1".into(),
            genesis_hash: ByteBuf::from(test_genesis_hash().to_vec()),
            proposer: Address::default(),
            fee_sink: Address::default(),
            rewards_pool: Address::default(),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: "future".into(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: ByteBuf::new(),
            txn256: ByteBuf::new(),
            txn512: ByteBuf::new(),
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            payset: vec![],
        }
    }

    /// Create a properly signed transaction for testing.
    fn make_signed_txn(key: &SigningKey, amount: u64) -> SignedTransaction {
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            amount,
            receiver: Address([2u8; 32]),
            genesis_id: "test-v1".into(),
            genesis_hash: ByteBuf::from(test_genesis_hash().to_vec()),
            ..Default::default()
        };

        // Sign the transaction: "TX" || canonical_encode(txn)
        let canonical = algo_codec::canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);

        // In the block, genesis fields are stripped. has_genesis_id and
        // has_genesis_hash flags indicate they were present.
        let mut stripped_txn = txn;
        stripped_txn.genesis_id = String::new();
        stripped_txn.genesis_hash = ByteBuf::new();

        SignedTransaction {
            txn: stripped_txn,
            sig: ByteBuf::from(sig.to_bytes().to_vec()),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: true,
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            eval_delta: None,
            apply_data_config_asset: 0,
            apply_data_application_id: 0,
        }
    }

    #[test]
    fn empty_block_valid() {
        let block = empty_block();
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash(), None);
        assert!(
            result.is_valid,
            "empty block should be valid, errors: {:?}",
            result.errors
        );
        assert_eq!(result.txn_count, 0);
        assert_eq!(result.total_txn_bytes, 0);
    }

    #[test]
    fn unknown_protocol_version_error() {
        let mut block = empty_block();
        block.current_protocol = "v99-nonexistent".into();
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash(), None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::UnknownProtocolVersion { .. })));
    }

    #[test]
    fn empty_protocol_version_error() {
        let mut block = empty_block();
        block.current_protocol = String::new();
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash(), None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::EmptyProtocolVersion)));
    }

    #[test]
    fn timestamp_too_old_error() {
        let mut block = empty_block();
        block.timestamp = 50;
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash(), None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::TimestampTooOld { .. })));
    }

    #[test]
    fn timestamp_too_new_error() {
        let mut block = empty_block();
        block.timestamp = 200;
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash(), None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::TimestampTooNew { .. })));
    }

    #[test]
    fn timestamp_skip_when_prev_is_zero() {
        // Go: prev.TimeStamp > 0 guard means a zero previous timestamp skips
        // the bounds check entirely. Even an "unreasonable" current timestamp
        // should not produce timestamp errors.
        let mut block = empty_block();
        block.timestamp = 999_999_999; // would be "too new" vs a positive prev
        let result = validate_block(&block, Some(0), "test-v1", &test_genesis_hash(), None);
        assert!(
            !result.errors.iter().any(|e| matches!(
                e,
                BlockValidationError::TimestampTooOld { .. }
                    | BlockValidationError::TimestampTooNew { .. }
            )),
            "timestamp bounds should be skipped when prev_timestamp=0, errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn timestamp_skip_when_prev_is_negative() {
        // Negative previous timestamps also skip the check (Go uses > 0).
        let mut block = empty_block();
        block.timestamp = 1;
        let result = validate_block(&block, Some(-5), "test-v1", &test_genesis_hash(), None);
        assert!(
            !result.errors.iter().any(|e| matches!(
                e,
                BlockValidationError::TimestampTooOld { .. }
                    | BlockValidationError::TimestampTooNew { .. }
            )),
            "timestamp bounds should be skipped when prev_timestamp is negative, errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn timestamp_enforced_when_prev_positive() {
        // When prev_timestamp > 0, bounds ARE enforced.
        let mut block = empty_block();
        block.timestamp = 50; // before prev=100
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash(), None);
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, BlockValidationError::TimestampTooOld { .. })),
            "timestamp too old should be caught when prev_timestamp > 0"
        );

        let mut block2 = empty_block();
        block2.timestamp = 200; // beyond prev + MAX_TIMESTAMP_INCREMENT (25)
        let result2 = validate_block(&block2, Some(100), "test-v1", &test_genesis_hash(), None);
        assert!(
            result2
                .errors
                .iter()
                .any(|e| matches!(e, BlockValidationError::TimestampTooNew { .. })),
            "timestamp too new should be caught when prev_timestamp > 0"
        );
    }

    #[test]
    fn timestamp_skip_for_genesis() {
        let mut block = empty_block();
        block.timestamp = -1; // would fail vs any positive prev, but genesis skips check
        let result = validate_block(&block, None, "test-v1", &test_genesis_hash(), None);
        // Should not have timestamp errors (genesis skip).
        assert!(!result.errors.iter().any(|e| matches!(
            e,
            BlockValidationError::TimestampTooOld { .. }
                | BlockValidationError::TimestampTooNew { .. }
        )));
    }

    #[test]
    fn block_with_valid_txn() {
        let key = test_signing_key();
        let stx = make_signed_txn(&key, 5000);

        let mut block = empty_block();
        block.payset = vec![stx];
        // Compute the correct commitment (needs full block for genesis restoration).
        let root = compute_payset_merkle_root(&block);
        block.txn_commitment = ByteBuf::from(root.to_vec());

        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash(), None);
        assert!(
            result.is_valid,
            "block with valid txn should pass, errors: {:?}",
            result.errors
        );
        assert_eq!(result.txn_count, 1);
        assert!(result.total_txn_bytes > 0);
    }

    #[test]
    fn payset_commitment_mismatch_warns_not_errors() {
        let key = test_signing_key();
        let stx = make_signed_txn(&key, 5000);

        let mut block = empty_block();
        block.payset = vec![stx];
        // Wrong commitment — should warn (eprintln) but not produce a validation error.
        // Commitment verification is warn-only until Epic 12a implements raw-passthrough
        // encoding for STIB hashing.
        block.txn_commitment = ByteBuf::from(vec![0xFF; 32]);

        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash(), None);
        assert!(
            result.is_valid,
            "commitment mismatch should be warn-only, but got errors: {:?}",
            result.errors
        );
        assert!(!result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::PaysetCommitmentMismatch { .. })));
    }

    #[test]
    fn collects_multiple_errors() {
        let mut block = empty_block();
        block.current_protocol = "v99-bad".into();
        block.timestamp = 50; // too old vs prev=100
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash(), None);
        assert!(!result.is_valid);
        // Should have at least 2 errors.
        assert!(
            result.errors.len() >= 2,
            "expected multiple errors, got: {:?}",
            result.errors
        );
    }
}
