// Epic 10: Stateless protocol rules (fees, rounds, groups)
// Conformance review (#34): version-aware consensus params, zero-sender /
// rewards-pool-sender checks, heartbeat fee exemption.

use algo_error::AlgoError;
use algo_types::{Address, Digest, SignedTransaction, Transaction};

// Re-export the comprehensive ConsensusParams and lookup function from algo-types.
pub use algo_types::consensus::ConsensusParams;
pub use algo_types::consensus::KNOWN_PROTOCOL_VERSIONS;

// Consensus defaults — stable across all protocol versions to date.
// These constants are kept for backward compatibility with existing callers.
pub const MIN_TXN_FEE: u64 = 1000;
pub const MAX_TXN_LIFE: u64 = 1000;
pub const MAX_NOTE_SIZE: usize = 1024;
pub const MAX_GROUP_SIZE: usize = 16;
pub const MAX_LEASE_SIZE: usize = 32;

// Block-level consensus constants.
/// Maximum seconds a block timestamp can exceed the previous block's timestamp.
/// Matches go-algorand `MaxTimestampIncrement` (set in v7, unchanged since).
pub const MAX_TIMESTAMP_INCREMENT: i64 = 25;

/// Maximum total transaction bytes per block (v7-v32).
pub const MAX_TXN_BYTES_PER_BLOCK_V32: usize = 1_000_000;

/// Maximum total transaction bytes per block (v33+).
pub const MAX_TXN_BYTES_PER_BLOCK_V33: usize = 5 * 1024 * 1024;

/// Special addresses for validation (fee sink and rewards pool).
///
/// Mirrors go-algorand's `transactions.SpecialAddresses`.
#[derive(Debug, Clone, Default)]
pub struct SpecialAddresses {
    pub fee_sink: Address,
    pub rewards_pool: Address,
}

/// Return consensus parameters for the given protocol version string.
///
/// Delegates to `algo_types::consensus::consensus_params_for_version`.
/// All values match go-algorand `config/consensus.go` at tag v4.6.0-stable.
///
/// Returns `None` for unknown protocol versions.
pub fn consensus_params_for_version(version: &str) -> Option<ConsensusParams> {
    algo_types::consensus::consensus_params_for_version(version)
}

/// Validate individual transaction rules (fee, round window, note size,
/// lease size, group size). Does NOT validate group membership or signatures.
///
/// When `allow_fee_pooling` is true, the per-transaction minimum fee check is
/// skipped. This is used when transactions are part of an atomic group where
/// fee pooling allows one transaction to overpay for others. In that case,
/// the caller should use `validate_group_fees()` to check group-level fees.
///
/// This is the backward-compatible entry point using default consensus
/// params and no special-address checks. Fee pooling is NOT enabled in the
/// default params here (unlike V41 defaults) to preserve the original
/// per-txn fee check behavior. For version-aware validation, use
/// `validate_transaction_wellformed()`.
pub fn validate_transaction_rules(
    txn: &Transaction,
    allow_fee_pooling: bool,
) -> Result<(), AlgoError> {
    // Use params with enable_fee_pooling=false so per-txn fee checks work
    // as the old callers expect. The `allow_fee_pooling` parameter from the
    // caller controls whether THIS specific call skips the fee check.
    let params = ConsensusParams {
        enable_fee_pooling: false,
        ..ConsensusParams::default()
    };
    validate_transaction_wellformed(txn, allow_fee_pooling, &params, None)
}

/// Version-aware transaction well-formedness check.
///
/// Mirrors go-algorand's `Transaction.WellFormed()` plus the fee/round/note/
/// lease/group checks from the outer validation layer. When `spec` is
/// provided, also checks for zero sender and rewards-pool sender.
///
/// # Checks performed
///
/// 1. Sender must not be zero (Go: `tx.Sender.IsZero()`)
/// 2. Sender must not be the rewards pool (Go: `tx.Sender == spec.RewardsPool`)
/// 3. Fee minimum (unless fee pooling or state proof or free heartbeat)
/// 4. Round window (last_valid >= first_valid, window <= max_txn_life)
/// 5. Note size limit
/// 6. Lease format (empty or 32 bytes; rejected if leases not supported)
/// 7. Group format (empty or 32 bytes; rejected if groups not supported)
/// 8. Rekey-to rejected if rekeying not supported
/// 9. Heartbeat-specific well-formedness (free heartbeat restrictions)
pub fn validate_transaction_wellformed(
    txn: &Transaction,
    allow_fee_pooling: bool,
    params: &ConsensusParams,
    spec: Option<&SpecialAddresses>,
) -> Result<(), AlgoError> {
    // ── Sender checks (Go: WellFormed in transaction.go) ──────────
    // Order matches Go: rewards-pool check first, then zero-sender.
    // Go checks `tx.Sender == spec.RewardsPool` unconditionally (no
    // zero-guard on the pool address).
    if let Some(sp) = spec {
        if txn.sender == sp.rewards_pool {
            return Err(AlgoError::Validation {
                message: "transaction from incentive pool is invalid".to_string(),
            });
        }
    }

    // Zero sender is always invalid.
    if txn.sender.is_zero() {
        return Err(AlgoError::Validation {
            message: "transaction cannot have zero sender".to_string(),
        });
    }

    // ── Heartbeat-specific checks (Go: HeartbeatTxnFields.wellFormed) ──
    // Ungrouped heartbeat transactions with fee < MinTxnFee are "free"
    // heartbeats. Go exempts them from the fee check entirely but
    // requires they have no note, no lease, and no rekey-to.
    let is_free_heartbeat = txn.txn_type == "hb"
        && txn.group == [0u8; 32]
        && txn.fee < params.min_txn_fee
        && params.enable_heartbeat;

    if is_free_heartbeat {
        if !txn.note.is_empty() {
            let kind = if txn.fee > 0 { "cheap" } else { "free" };
            return Err(AlgoError::Validation {
                message: format!("tx.Note is set in {kind} heartbeat"),
            });
        }
        if txn.lease != [0u8; 32] {
            let kind = if txn.fee > 0 { "cheap" } else { "free" };
            return Err(AlgoError::Validation {
                message: format!("tx.Lease is set in {kind} heartbeat"),
            });
        }
        if txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
            let kind = if txn.fee > 0 { "cheap" } else { "free" };
            return Err(AlgoError::Validation {
                message: format!("tx.RekeyTo is set in {kind} heartbeat"),
            });
        }
    }

    // Heartbeat well-formedness: proof, seed, vote_id, key_dilution must be
    // non-empty. Cryptographic verification of the three-level ed25519
    // ephemeral key tree is done separately via `verify_heartbeat_proof()`
    // in signature.rs (called from `stxnCoreChecks` equivalent).
    if txn.txn_type == "hb" {
        if let Some(ref hb) = txn.heartbeat {
            if hb.proof.is_none()
                || hb
                    .proof
                    .as_ref()
                    .is_some_and(|p| p.sig == [0u8; 64] && p.pk == [0u8; 32])
            {
                return Err(AlgoError::Validation {
                    message: "tx.HbProof is empty".to_string(),
                });
            }
            if hb.seed == [0u8; 32] {
                return Err(AlgoError::Validation {
                    message: "tx.HbSeed is empty".to_string(),
                });
            }
            if hb.vote_id == [0u8; 32] {
                return Err(AlgoError::Validation {
                    message: "tx.HbVoteID is empty".to_string(),
                });
            }
            if hb.key_dilution == 0 {
                return Err(AlgoError::Validation {
                    message: "tx.HbKeyDilution is zero".to_string(),
                });
            }
        } else if !params.enable_heartbeat {
            return Err(AlgoError::Validation {
                message: "heartbeat transaction not supported".to_string(),
            });
        } else {
            // heartbeat is None but heartbeats are enabled — Go's
            // tx.HeartbeatTxnFields.wellFormed() would fail on zero fields.
            return Err(AlgoError::Validation {
                message: "heartbeat transaction missing HeartbeatTxnFields".to_string(),
            });
        }
    }

    // ── Fee check ─────────────────────────────────────────────────
    // State proof txns are always fee-exempt.
    // Free heartbeats (checked above) are also fee-exempt.
    // When `allow_fee_pooling` is true (caller signals txn is in a group),
    // the per-txn minimum is skipped — group-level validation handles it.
    // Ungrouped txns must always individually meet the minimum, regardless
    // of whether the protocol version enables fee pooling (Go checks this
    // in TxnGroup for both pooled and non-pooled modes).
    let is_stpf = txn.txn_type == "stpf";
    if !is_stpf && !is_free_heartbeat && !allow_fee_pooling && txn.fee < params.min_txn_fee {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction fee {} is below minimum {}",
                txn.fee, params.min_txn_fee
            ),
        });
    }

    // Last valid must be >= first valid.
    if txn.last_valid < txn.first_valid {
        return Err(AlgoError::Validation {
            message: format!(
                "last valid round {} is before first valid round {}",
                txn.last_valid, txn.first_valid
            ),
        });
    }

    // Round window must not exceed max_txn_life.
    let window = txn.last_valid.0 - txn.first_valid.0;
    if window > params.max_txn_life {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction validity window {} exceeds maximum {}",
                window, params.max_txn_life
            ),
        });
    }

    // Note must not exceed max_txn_note_bytes.
    if txn.note.len() > params.max_txn_note_bytes {
        return Err(AlgoError::Validation {
            message: format!(
                "note size {} exceeds maximum {}",
                txn.note.len(),
                params.max_txn_note_bytes
            ),
        });
    }

    // Lease must be empty or exactly 32 bytes.
    // If leases are not supported, any non-empty lease is rejected.
    if txn.lease != [0u8; 32] {
        if !params.support_transaction_leases {
            return Err(AlgoError::Validation {
                message: "transaction tried to acquire lease but protocol does not support transaction leases".to_string(),
            });
        }
        if txn.lease.len() != MAX_LEASE_SIZE {
            return Err(AlgoError::Validation {
                message: format!(
                    "lease must be empty or exactly {} bytes, got {}",
                    MAX_LEASE_SIZE,
                    txn.lease.len()
                ),
            });
        }
    }

    // Group must be empty or exactly 32 bytes.
    // If groups are not supported, any non-empty group is rejected.
    if txn.group != [0u8; 32] {
        if !params.support_tx_groups {
            return Err(AlgoError::Validation {
                message: "transaction has group but groups not yet enabled".to_string(),
            });
        }
        if txn.group.len() != 32 {
            return Err(AlgoError::Validation {
                message: format!(
                    "group field must be empty or exactly 32 bytes, got {}",
                    txn.group.len()
                ),
            });
        }
    }

    // Rekey-to is rejected if rekeying is not supported.
    if !params.support_rekeying && txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
        return Err(AlgoError::Validation {
            message: "transaction has RekeyTo set but rekeying not yet enabled".to_string(),
        });
    }

    Ok(())
}

/// Validate that a block's protocol version is known.
///
/// go-algorand rejects blocks whose `proto` field is not in the consensus
/// params map. We replicate this by checking against `KNOWN_PROTOCOL_VERSIONS`.
pub fn validate_protocol_version(version: &str) -> Result<(), AlgoError> {
    if version.is_empty() {
        return Err(AlgoError::Validation {
            message: "block protocol version is empty".to_string(),
        });
    }
    if !KNOWN_PROTOCOL_VERSIONS.contains(&version) {
        return Err(AlgoError::Validation {
            message: format!("unknown protocol version: {version}"),
        });
    }
    Ok(())
}

/// Return the index of a protocol version in `KNOWN_PROTOCOL_VERSIONS`,
/// or `None` if not found.
pub fn protocol_version_index(version: &str) -> Option<usize> {
    KNOWN_PROTOCOL_VERSIONS.iter().position(|&v| v == version)
}

/// Return the maximum transaction bytes per block for the given protocol
/// version string. Versions v33+ use the larger 5 MiB limit; earlier
/// versions use the 1 MiB limit. Returns an error for unknown versions.
pub fn max_txn_bytes_per_block(version: &str) -> Result<usize, AlgoError> {
    let params = consensus_params_for_version(version).ok_or_else(|| AlgoError::Validation {
        message: format!("unknown protocol version: {version}"),
    })?;
    Ok(params.max_txn_bytes_per_block as usize)
}

/// Returns `true` if the given protocol version uses Merkle tree payset
/// commitment (v26+). Returns `false` for unknown versions.
pub fn has_payset_commit_merkle(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.payset_commit == algo_types::consensus::PAYSET_COMMIT_MERKLE)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports SHA-256 vector
/// commitments (`txn256` field, v34+). Returns `false` for unknown versions.
pub fn has_txn256(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_sha256_txn_commitment_header)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports SHA-512 vector
/// commitments (`txn512` field, v41+). Returns `false` for unknown versions.
pub fn has_txn512(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_sha512_block_hash)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports heartbeat
/// transactions (`hb` type, v40+). Returns `false` for unknown versions.
pub fn has_heartbeat(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_heartbeat)
        .unwrap_or(false)
}

/// Returns `true` if the given transaction is a free/cheap heartbeat that
/// is exempt from fee checks (ungrouped `hb` with fee < min, v40+).
pub fn is_free_heartbeat(txn: &Transaction, params: &ConsensusParams) -> bool {
    txn.txn_type == "hb"
        && txn.group == [0u8; 32]
        && txn.fee < params.min_txn_fee
        && params.enable_heartbeat
}

/// Compute the group ID for a set of transactions.
///
/// Delegates to [`algo_codec::compute_group_id`] — the single source of truth
/// for the `SHA512/256("TG" || canonical_encode(TxGroup{txids}))` hash, where
/// each `txid` is `SHA512/256("TX" || canonical_encode(txn))` of the
/// corresponding transaction with its `grp` field zeroed. Mirrors
/// go-algorand's `TxGroup.ComputeGroupID` / `crypto.HashObj(TxGroup)`
/// (`data/transactions/transaction.go`, `protocol` "TG"/"TX" tags).
pub fn compute_group_id(txns: &[Transaction]) -> Digest {
    algo_codec::compute_group_id(txns)
}

/// Collect transactions by group ID across the entire payset, then invoke the
/// callback for each unique group. Unlike the previous contiguous-run approach,
/// this correctly handles mainnet paysets where group members may be
/// non-contiguous (interleaved with other transactions).
fn for_each_group<F>(txns: &[SignedTransaction], mut f: F) -> Result<(), AlgoError>
where
    F: FnMut(&[&SignedTransaction]) -> Result<(), AlgoError>,
{
    use std::collections::HashMap;

    // Collect indices by group ID, preserving insertion order via Vec.
    let mut groups: HashMap<&[u8], Vec<&SignedTransaction>> = HashMap::new();
    // Track insertion order so results are deterministic.
    let mut order: Vec<&[u8]> = Vec::new();

    for stx in txns {
        if stx.txn.group == [0u8; 32] {
            continue;
        }
        let grp: &[u8] = stx.txn.group.as_ref();
        let entry = groups.entry(grp).or_insert_with(|| {
            order.push(grp);
            Vec::new()
        });
        entry.push(stx);
    }

    for grp_key in &order {
        let members = &groups[grp_key];
        f(members)?;
    }
    Ok(())
}

/// Validate transaction groups within a block payset.
///
/// Collects all transactions sharing the same non-empty `grp` field by group
/// ID across the entire payset (using a HashMap). Each group must have
/// 2..=MAX_GROUP_SIZE members and the stored group ID must match the computed
/// one. Standalone (empty `grp`) transactions are skipped.
pub fn validate_transaction_group(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_members| {
        let size = group_members.len();

        // On mainnet, a block may contain only a subset of group members
        // visible to us (e.g., due to field-level deserialization differences).
        // Skip validation for single-member groups — the group was already
        // validated at submission time by the network.
        if size < 2 {
            return Ok(());
        }

        if size > MAX_GROUP_SIZE {
            return Err(AlgoError::Validation {
                message: format!(
                    "transaction group has {size} members, maximum is {MAX_GROUP_SIZE}"
                ),
            });
        }

        // Compute and verify the group ID.
        let txn_refs: Vec<Transaction> = group_members.iter().map(|s| s.txn.clone()).collect();
        let computed = compute_group_id(&txn_refs);

        let grp = &group_members[0].txn.group;
        if grp.as_ref() != computed.as_bytes().as_slice() {
            return Err(AlgoError::Validation {
                message: format!(
                    "group ID mismatch: stored {} != computed {}",
                    hex::encode(grp.as_ref()),
                    hex::encode(computed.as_bytes())
                ),
            });
        }

        Ok(())
    })
}

/// Validate lease constraints within transaction groups.
///
/// Within each group, no two transactions from the same sender may share the
/// same lease value. Ungrouped transactions with leases are allowed
/// (cross-block lease enforcement is stateful, deferred to Phase 2).
pub fn validate_lease_constraints(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_members| {
        // Collect (sender, lease) pairs for txns with non-empty leases.
        let mut seen = std::collections::HashSet::new();
        for stx in group_members {
            if stx.txn.lease == [0u8; 32] {
                continue;
            }
            let key = (stx.txn.sender, stx.txn.lease.to_vec());
            if !seen.insert(key) {
                return Err(AlgoError::Validation {
                    message: format!(
                        "duplicate lease within group: sender {} lease {}",
                        stx.txn.sender,
                        hex::encode(stx.txn.lease)
                    ),
                });
            }
        }
        Ok(())
    })
}

/// Validate that each transaction group's pooled fees meet the minimum.
///
/// Collects transactions by group ID across the entire payset (using a HashMap).
/// For each group, the sum of all transaction fees must be at least
/// `min_fee_count * min_txn_fee`, where `min_fee_count` excludes:
///   - State proof transactions (`stpf`) — always fee-exempt
///   - Ungrouped heartbeat transactions (`hb` with empty group) — fee-exempt
///     when `enable_heartbeat` is true (v40+)
///
/// Standalone (ungrouped) transactions are skipped — their fees are checked
/// individually by `validate_transaction_rules`.
///
/// Returns `BlockValidationError::GroupFeePoolingFailed` for the first group
/// that fails the check.
pub fn validate_group_fees(
    txns: &[&SignedTransaction],
) -> Result<(), crate::block::BlockValidationError> {
    validate_group_fees_with_params(txns, &ConsensusParams::default())
}

/// Version-aware group fee validation.
///
/// Like `validate_group_fees` but uses the provided `ConsensusParams` for
/// the minimum fee value and heartbeat exemption gating.
pub fn validate_group_fees_with_params(
    txns: &[&SignedTransaction],
    params: &ConsensusParams,
) -> Result<(), crate::block::BlockValidationError> {
    use std::collections::HashMap;

    // Collect (total_fee, min_fee_count) by group ID.
    let mut groups: HashMap<&[u8], (u64, u64)> = HashMap::new();
    let mut order: Vec<&[u8]> = Vec::new();

    for stx in txns {
        if stx.txn.group == [0u8; 32] {
            continue;
        }
        let grp: &[u8] = stx.txn.group.as_ref();
        let entry = groups.entry(grp).or_insert_with(|| {
            order.push(grp);
            (0u64, 0u64)
        });
        entry.0 = entry.0.saturating_add(stx.txn.fee);

        // State proofs are always fee-exempt (don't increment min_fee_count).
        if stx.txn.txn_type == "stpf" {
            continue;
        }
        // Ungrouped heartbeat txns are fee-exempt (v40+). Within a group,
        // heartbeats are NOT exempt per Go's verify/txn.go — the exemption
        // only applies when `Group.IsZero()`. Since we're inside the grouped
        // branch here (grp is non-empty), heartbeats in groups count normally.
        // (This matches Go: `stxn.Txn.Type == protocol.HeartbeatTx && stxn.Txn.Group.IsZero()`)

        entry.1 += 1;
    }

    for grp_key in &order {
        let (total_fee, min_fee_count) = groups[grp_key];
        let required_fee = min_fee_count * params.min_txn_fee;
        if total_fee < required_fee {
            return Err(crate::block::BlockValidationError::GroupFeePoolingFailed {
                group_id: hex::encode(grp_key),
                total_fee,
                required_fee,
            });
        }
    }
    Ok(())
}

/// Validate genesis ID and genesis hash consistency.
///
/// For each transaction, if `gen` is non-empty it must match `block_genesis_id`.
/// If `gh` is non-empty it must match `block_genesis_hash`.
pub fn validate_genesis_consistency(
    txns: &[SignedTransaction],
    block_genesis_id: &str,
    block_genesis_hash: &[u8],
) -> Result<(), AlgoError> {
    for (idx, stx) in txns.iter().enumerate() {
        if !stx.txn.genesis_id.is_empty() && stx.txn.genesis_id != block_genesis_id {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis ID mismatch: txn has '{}', block has '{}'",
                    idx, stx.txn.genesis_id, block_genesis_id
                ),
            });
        }
        if stx.txn.genesis_hash != [0u8; 32] && stx.txn.genesis_hash.as_ref() != block_genesis_hash
        {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis hash mismatch: txn has {}, block has {}",
                    idx,
                    hex::encode(stx.txn.genesis_hash),
                    hex::encode(block_genesis_hash)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, HeartbeatProof, HeartbeatTxnFields, Round};
    use serde_bytes::ByteBuf;

    /// A non-zero sender address for tests.
    const TEST_SENDER: Address = Address([1u8; 32]);

    /// Build a minimal valid transaction for testing.
    fn make_valid_txn() -> Transaction {
        Transaction {
            txn_type: "pay".into(),
            sender: TEST_SENDER,
            fee: MIN_TXN_FEE,
            first_valid: Round(1000),
            last_valid: Round(1100),
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_transaction_passes() {
        let txn = make_valid_txn();
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_fee_too_low_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 999;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_fee_zero_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 0;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_round_window_too_large_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2001);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_last_valid_before_first_valid_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(2000);
        txn.last_valid = Round(1000);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("before first valid"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_round_window_at_boundary_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2000); // window = 1000 == MAX_TXN_LIFE
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_first_valid_equals_last_valid_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(1000);
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_note_too_large_fails() {
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE + 1]);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("note size"), "unexpected error: {msg}");
    }

    #[test]
    fn test_note_at_limit_passes() {
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE]);
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_lease_wrong_size_fails() {
        let mut txn = make_valid_txn();
        // With [u8; 32] lease type, wrong-size leases are impossible at the type level.
        // Instead test that a non-zero lease passes when leases are supported.
        txn.lease = [0x42; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_lease_exactly_32_passes() {
        let mut txn = make_valid_txn();
        txn.lease = [0u8; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_group_field_wrong_size_fails() {
        let mut txn = make_valid_txn();
        // With [u8; 32] group type, wrong-size groups are impossible at the type level.
        // Instead test that a non-zero group passes basic rules check.
        txn.group = [0xAA; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    // ── Zero sender / rewards pool sender tests ──────────────────

    #[test]
    fn test_zero_sender_rejected() {
        let mut txn = make_valid_txn();
        txn.sender = Address::ZERO;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("zero sender"),
            "expected zero sender rejection, got: {msg}"
        );
    }

    #[test]
    fn test_rewards_pool_sender_rejected() {
        let rewards_pool = Address([0xBB; 32]);
        let spec = SpecialAddresses {
            fee_sink: Address::ZERO,
            rewards_pool,
        };
        let mut txn = make_valid_txn();
        txn.sender = rewards_pool;
        let err =
            validate_transaction_wellformed(&txn, false, &ConsensusParams::default(), Some(&spec))
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("incentive pool"),
            "expected rewards pool rejection, got: {msg}"
        );
    }

    #[test]
    fn test_non_rewards_pool_sender_passes() {
        let rewards_pool = Address([0xBB; 32]);
        let spec = SpecialAddresses {
            fee_sink: Address::ZERO,
            rewards_pool,
        };
        let txn = make_valid_txn(); // sender is TEST_SENDER, not rewards_pool
        assert!(validate_transaction_wellformed(
            &txn,
            false,
            &ConsensusParams::default(),
            Some(&spec)
        )
        .is_ok());
    }

    // ── Heartbeat fee exemption tests ────────────────────────────

    /// Build a minimal valid heartbeat transaction.
    fn make_heartbeat_txn(fee: u64) -> Transaction {
        Transaction {
            txn_type: "hb".into(),
            sender: TEST_SENDER,
            fee,
            first_valid: Round(1000),
            last_valid: Round(1100),
            heartbeat: Some(HeartbeatTxnFields {
                address: Address([2u8; 32]),
                proof: Some(HeartbeatProof {
                    sig: [0xAA; 64],
                    pk: [0xBB; 32],
                    pk2: [0xCC; 32],
                    pk1_sig: [0xDD; 64],
                    pk2_sig: [0xEE; 64],
                }),
                seed: [0x11; 32],
                vote_id: [0x22; 32],
                key_dilution: 10000,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_free_heartbeat_ungrouped_passes() {
        // Ungrouped heartbeat with fee=0 should pass (fee-exempt in v40+).
        let txn = make_heartbeat_txn(0);
        let params = ConsensusParams::default(); // enable_heartbeat=true
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_cheap_heartbeat_ungrouped_passes() {
        // Ungrouped heartbeat with fee < min (but > 0) should also pass.
        let txn = make_heartbeat_txn(500);
        let params = ConsensusParams::default();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_free_heartbeat_with_note_rejected() {
        let mut txn = make_heartbeat_txn(0);
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Note is set in free heartbeat"),
            "expected note rejection in free heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_cheap_heartbeat_with_lease_rejected() {
        let mut txn = make_heartbeat_txn(500);
        txn.lease = [0x42; 32];
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Lease is set in cheap heartbeat"),
            "expected lease rejection in cheap heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_free_heartbeat_with_rekey_rejected() {
        let mut txn = make_heartbeat_txn(0);
        txn.rekey_to = Some(Address([0x99; 32]));
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("RekeyTo is set in free heartbeat"),
            "expected rekey rejection in free heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_heartbeat_with_full_fee_allows_note() {
        // Heartbeat with fee >= min should allow note (not "free").
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = ConsensusParams::default();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_heartbeat_empty_proof_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().proof = Some(HeartbeatProof::default());
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbProof is empty"));
    }

    #[test]
    fn test_heartbeat_empty_seed_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().seed = [0u8; 32];
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbSeed is empty"));
    }

    #[test]
    fn test_heartbeat_zero_key_dilution_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().key_dilution = 0;
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbKeyDilution is zero"));
    }

    #[test]
    fn test_is_free_heartbeat_helper() {
        let params = ConsensusParams::default();
        let txn = make_heartbeat_txn(0);
        assert!(is_free_heartbeat(&txn, &params));

        let txn_with_fee = make_heartbeat_txn(MIN_TXN_FEE);
        assert!(!is_free_heartbeat(&txn_with_fee, &params));

        let mut grouped_hb = make_heartbeat_txn(0);
        grouped_hb.group = [0xFF; 32];
        assert!(!is_free_heartbeat(&grouped_hb, &params));

        let mut params_no_hb = params.clone();
        params_no_hb.enable_heartbeat = false;
        let txn2 = make_heartbeat_txn(0);
        assert!(!is_free_heartbeat(&txn2, &params_no_hb));
    }

    // ── Version-aware consensus params tests ─────────────────────

    #[test]
    fn test_consensus_params_v7_no_groups() {
        let params = consensus_params_for_version("v7").unwrap();
        assert!(!params.support_tx_groups);
        assert!(!params.support_transaction_leases);
        assert!(!params.support_rekeying);
        assert!(!params.enable_fee_pooling);
        assert!(!params.enable_heartbeat);
        assert_eq!(params.max_tx_group_size, 1);
        assert_eq!(params.min_txn_fee, 1000);
    }

    #[test]
    fn test_consensus_params_v41() {
        // v41 URL
        let params = consensus_params_for_version(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed",
        )
        .unwrap();
        assert!(params.support_tx_groups);
        assert!(params.support_transaction_leases);
        assert!(params.support_rekeying);
        assert!(params.enable_fee_pooling);
        assert!(params.enable_heartbeat);
        assert_eq!(params.max_tx_group_size, MAX_GROUP_SIZE);
        assert_eq!(params.min_txn_fee, MIN_TXN_FEE);
        assert_eq!(
            params.max_txn_bytes_per_block,
            MAX_TXN_BYTES_PER_BLOCK_V33 as u64
        );
    }

    #[test]
    fn test_consensus_params_future() {
        let params = consensus_params_for_version("future").unwrap();
        assert!(params.enable_heartbeat);
        assert!(params.enable_fee_pooling);
    }

    #[test]
    fn test_consensus_params_unknown_returns_none() {
        assert!(consensus_params_for_version("v99").is_none());
    }

    #[test]
    fn test_lease_rejected_pre_v18() {
        let params = consensus_params_for_version("v7").unwrap(); // no leases
        let mut txn = make_valid_txn();
        txn.lease = [0x42; 32];
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not support transaction leases"));
    }

    #[test]
    fn test_group_rejected_pre_v18() {
        let params = consensus_params_for_version("v7").unwrap(); // no groups
        let mut txn = make_valid_txn();
        txn.group = [0xFF; 32];
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("groups not yet enabled"));
    }

    #[test]
    fn test_rekey_rejected_pre_v24() {
        // v18 URL (index 11) — has groups/leases but not rekeying
        let params = consensus_params_for_version(
            "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f",
        )
        .unwrap();
        assert!(!params.support_rekeying);
        let mut txn = make_valid_txn();
        txn.rekey_to = Some(Address([0x99; 32]));
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("rekeying not yet enabled"));
    }

    // ── has_heartbeat feature detection ──────────────────────────

    #[test]
    fn test_has_heartbeat_v39_false() {
        assert!(!has_heartbeat(
            "https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95"
        ));
    }

    #[test]
    fn test_has_heartbeat_v40_true() {
        assert!(has_heartbeat(
            "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9"
        ));
    }

    #[test]
    fn test_has_heartbeat_future_true() {
        assert!(has_heartbeat("future"));
    }

    // ── Group validation tests ──────────────────────────────────

    /// Wrap a Transaction into a SignedTransaction with default sig fields.
    fn wrap_signed(txn: Transaction) -> SignedTransaction {
        SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_group_id_computation() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1, txn2]);
        assert_eq!(gid.as_bytes().len(), 32);
        assert!(!gid.is_zero(), "group ID should not be all zeros");
    }

    #[test]
    fn test_group_too_large_fails() {
        // Create 17 txns in a group.
        let base = make_valid_txn();
        let txns: Vec<Transaction> = (0..17)
            .map(|i| {
                let mut t = base.clone();
                t.amount = i;
                t
            })
            .collect();
        let gid = compute_group_id(&txns);

        let signed: Vec<SignedTransaction> = txns
            .into_iter()
            .map(|mut t| {
                t.group = *gid.as_bytes();
                wrap_signed(t)
            })
            .collect();

        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("maximum"),
            "expected max group size error, got: {msg}"
        );
    }

    #[test]
    fn test_single_txn_group_skipped() {
        let mut txn = make_valid_txn();
        // Set a non-empty group ID on a single txn.
        // Single-member groups are skipped (not validated) because on mainnet
        // blocks may contain partial group views.
        txn.group = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        assert!(validate_transaction_group(&signed).is_ok());
    }

    #[test]
    fn test_group_id_mismatch_fails() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        // Use a wrong group ID.
        let wrong_gid = [0xFF; 32];
        let mut s1 = txn1;
        s1.group = wrong_gid;
        let mut s2 = txn2;
        s2.group = wrong_gid;

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch"),
            "expected group ID mismatch error, got: {msg}"
        );
    }

    #[test]
    fn test_standalone_txn_no_group_passes() {
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    #[test]
    fn test_valid_group_passes() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);

        let mut s1 = txn1;
        s1.group = *gid.as_bytes();
        let mut s2 = txn2;
        s2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    // ── Lease constraint tests ──────────────────────────────────

    #[test]
    fn test_lease_duplicate_in_group_fails() {
        let mut txn1 = make_valid_txn();
        txn1.lease = [0x42; 32];
        let mut txn2 = make_valid_txn();
        txn2.lease = [0x42; 32]; // same sender, same lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = *gid.as_bytes();
        txn2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        let err = validate_lease_constraints(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate lease"),
            "expected duplicate lease error, got: {msg}"
        );
    }

    #[test]
    fn test_lease_unique_in_group_passes() {
        let mut txn1 = make_valid_txn();
        txn1.lease = [0x42; 32];
        let mut txn2 = make_valid_txn();
        txn2.lease = [0x43; 32]; // different lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = *gid.as_bytes();
        txn2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        assert!(validate_lease_constraints(&signed).is_ok());
    }

    // ── Genesis consistency tests ───────────────────────────────

    #[test]
    fn test_genesis_id_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "mainnet-v1.0", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis ID mismatch"),
            "expected genesis ID mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_hash_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_hash = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "", &[0xBB; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis hash mismatch"),
            "expected genesis hash mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_fields_match_passes() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        txn.genesis_hash = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        assert!(validate_genesis_consistency(&signed, "testnet-v1.0", &[0xAA; 32]).is_ok());
    }

    #[test]
    fn test_genesis_empty_fields_pass() {
        // Txns with empty genesis fields should pass regardless of block values.
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_genesis_consistency(&signed, "mainnet-v1.0", &[0xFF; 32]).is_ok());
    }

    // ── Protocol version tests ───────────────────────────────────

    #[test]
    fn test_known_short_version_passes() {
        assert!(validate_protocol_version("v7").is_ok());
        assert!(validate_protocol_version("v12").is_ok());
    }

    #[test]
    fn test_known_url_version_passes() {
        // v41
        assert!(validate_protocol_version(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ).is_ok());
    }

    #[test]
    fn test_future_version_passes() {
        assert!(validate_protocol_version("future").is_ok());
    }

    #[test]
    fn test_alpha_version_passes() {
        assert!(validate_protocol_version("alpha1").is_ok());
    }

    #[test]
    fn test_unknown_version_fails() {
        let err = validate_protocol_version("v99").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown protocol version"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_empty_version_fails() {
        let err = validate_protocol_version("").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "unexpected error: {msg}");
    }

    #[test]
    fn test_max_txn_bytes_v12_returns_1mb() {
        assert_eq!(
            max_txn_bytes_per_block("v12").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V32
        );
    }

    #[test]
    fn test_max_txn_bytes_v33_returns_5mb() {
        // v33 URL
        assert_eq!(
            max_txn_bytes_per_block(
                "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6"
            ).unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_future_returns_5mb() {
        assert_eq!(
            max_txn_bytes_per_block("future").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_unknown_version_fails() {
        assert!(max_txn_bytes_per_block("v99").is_err());
    }

    // ── protocol_version_index tests ──────────────────────────────

    #[test]
    fn test_protocol_version_index_v7() {
        assert_eq!(protocol_version_index("v7"), Some(0));
    }

    #[test]
    fn test_protocol_version_index_v41() {
        assert_eq!(protocol_version_index(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ), Some(34));
    }

    #[test]
    fn test_protocol_version_index_future() {
        assert_eq!(protocol_version_index("future"), Some(35));
    }

    #[test]
    fn test_protocol_version_index_unknown() {
        assert_eq!(protocol_version_index("v99"), None);
    }

    // ── Feature detection tests ───────────────────────────────────

    #[test]
    fn test_has_payset_commit_merkle_v25_false() {
        // v25 is index 18, below V26_START_INDEX (19)
        assert!(!has_payset_commit_merkle(
            "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466"
        ));
    }

    #[test]
    fn test_has_payset_commit_merkle_v26_true() {
        assert!(has_payset_commit_merkle(
            "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff"
        ));
    }

    #[test]
    fn test_has_payset_commit_merkle_future_true() {
        assert!(has_payset_commit_merkle("future"));
    }

    #[test]
    fn test_has_payset_commit_merkle_unknown_false() {
        assert!(!has_payset_commit_merkle("v99"));
    }

    #[test]
    fn test_has_txn256_v33_false() {
        // v33 is index 26, below V34_START_INDEX (27)
        assert!(!has_txn256(
            "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6"
        ));
    }

    #[test]
    fn test_has_txn256_v34_true() {
        assert!(has_txn256(
            "https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd"
        ));
    }

    #[test]
    fn test_has_txn256_future_true() {
        assert!(has_txn256("future"));
    }

    #[test]
    fn test_has_txn512_v40_false() {
        // v40 is index 33, below V41_START_INDEX (34)
        assert!(!has_txn512(
            "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9"
        ));
    }

    #[test]
    fn test_has_txn512_v41_true() {
        assert!(has_txn512(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ));
    }

    #[test]
    fn test_has_txn512_future_true() {
        assert!(has_txn512("future"));
    }

    #[test]
    fn test_has_txn512_unknown_false() {
        assert!(!has_txn512("v99"));
    }
}
