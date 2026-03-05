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

use algo_codec::canonical_encode_signed_txn_in_block;
use algo_types::Block;

use crate::merkle::compute_payset_merkle_root;
use crate::rules::{
    max_txn_bytes_per_block, validate_genesis_consistency, validate_lease_constraints,
    validate_transaction_group, validate_transaction_rules, MAX_TIMESTAMP_INCREMENT,
};
use crate::signature::verify_transaction_signature;

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
///   round-0 (skips timestamp validation).
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

    // 2. Timestamp bounds (skip when prev_timestamp is None, i.e. genesis).
    if let Some(prev_ts) = prev_timestamp {
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

    for (idx, stx) in restored_payset.iter().enumerate() {
        // Per-txn rules (fees, rounds, note size, etc.)
        if let Err(e) = validate_transaction_rules(&stx.txn) {
            errors.push(BlockValidationError::TransactionValidationFailed {
                txn_index: idx,
                error: e.to_string(),
            });
        }

        // Signature verification.
        if let Err(e) = verify_transaction_signature(stx) {
            errors.push(BlockValidationError::SignatureVerificationFailed {
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

    // 4. Transaction group validation (uses restored payset for group ID computation).
    if let Err(e) = validate_transaction_group(&restored_payset) {
        errors.push(BlockValidationError::GroupValidationFailed {
            error: e.to_string(),
        });
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

    // 7. Payset Merkle commitment.
    // The `txn` field in the block header is the Merkle root of the payset.
    // For modern protocol versions (v24+), this uses the Merkle tree commitment.
    // The txid in each leaf uses genesis-restored transaction fields, while the
    // STIB hash uses the payset entry as stored (with ApplyData, without genesis).
    if !block.txn_commitment.is_empty() || !block.payset.is_empty() {
        let computed_root = compute_payset_merkle_root(block);
        let expected = block.txn_commitment.as_ref();
        if expected != computed_root.as_slice() {
            errors.push(BlockValidationError::PaysetCommitmentMismatch {
                expected: hex::encode(expected),
                computed: hex::encode(computed_root),
            });
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
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash());
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
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash());
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
        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash());
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
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash());
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
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash());
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::TimestampTooNew { .. })));
    }

    #[test]
    fn timestamp_skip_for_genesis() {
        let mut block = empty_block();
        block.timestamp = -1; // would fail vs any positive prev, but genesis skips check
        let result = validate_block(&block, None, "test-v1", &test_genesis_hash());
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

        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash());
        assert!(
            result.is_valid,
            "block with valid txn should pass, errors: {:?}",
            result.errors
        );
        assert_eq!(result.txn_count, 1);
        assert!(result.total_txn_bytes > 0);
    }

    #[test]
    fn payset_commitment_mismatch_error() {
        let key = test_signing_key();
        let stx = make_signed_txn(&key, 5000);

        let mut block = empty_block();
        block.payset = vec![stx];
        // Wrong commitment.
        block.txn_commitment = ByteBuf::from(vec![0xFF; 32]);

        let result = validate_block(&block, Some(90), "test-v1", &test_genesis_hash());
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, BlockValidationError::PaysetCommitmentMismatch { .. })));
    }

    #[test]
    fn collects_multiple_errors() {
        let mut block = empty_block();
        block.current_protocol = "v99-bad".into();
        block.timestamp = 50; // too old vs prev=100
        let result = validate_block(&block, Some(100), "test-v1", &test_genesis_hash());
        assert!(!result.is_valid);
        // Should have at least 2 errors.
        assert!(
            result.errors.len() >= 2,
            "expected multiple errors, got: {:?}",
            result.errors
        );
    }
}
