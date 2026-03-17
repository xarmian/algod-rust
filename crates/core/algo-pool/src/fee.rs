//! Fee escalation logic for the transaction pool.
//!
//! Mirrors go-algorand's `computeFeePerByte` and `checkSufficientFee`
//! from `data/pools/transactionPool.go`.
//!
//! When the pool is under load (multiple "whole blocks" worth of pending
//! transactions), the required fee-per-byte grows exponentially:
//!
//!   fee_per_byte = exponential_increase_factor ^ (num_pending_whole_blocks - 1)
//!
//! A special exception is made for state proof transactions issued by the
//! canonical `STATE_PROOF_SENDER` address with zero fee.

use algo_codec::canonical_encode_signed_transaction;
use algo_types::{Address, ConsensusParams, SignedTransaction, TxnType};

use crate::error::PoolError;

/// Re-export for convenience: the canonical state-proof sender address.
///
/// See [`Address::STATE_PROOF_SENDER`] for the full doc comment.
pub const STATE_PROOF_SENDER: Address = Address::STATE_PROOF_SENDER;

/// Compute the fee-per-byte threshold given the current pool load.
///
/// Mirrors go-algorand's `TransactionPool.computeFeePerByte()`.
///
/// When `num_pending_whole_blocks <= 1`, no fee escalation is applied and the
/// returned value is `0` (meaning only the flat `MinTxnFee` from consensus
/// governs admission).
///
/// When `num_pending_whole_blocks > 1`, the fee ramps exponentially:
///
///   `fee_per_byte = exponential_increase_factor ^ (num_pending_whole_blocks - 1)`
///
/// In go-algorand the baseline is `1 * feeThresholdMultiplier`, but the
/// simplified formula here captures the steady-state exponent that the pool
/// converges to after the multiplier adapts. The caller is responsible for
/// incorporating the `feeThresholdMultiplier` if needed.
pub fn compute_fee_per_byte(
    num_pending_whole_blocks: u64,
    exponential_increase_factor: u64,
) -> u64 {
    if num_pending_whole_blocks <= 1 {
        return 0;
    }

    // fee_per_byte = exponential_increase_factor ^ (num_pending_whole_blocks - 1)
    //
    // Go computes this with a simple loop; we do the same to avoid
    // any floating-point or overflow subtleties.
    let mut fee_per_byte: u64 = 1;
    for _ in 0..(num_pending_whole_blocks - 1) {
        fee_per_byte = fee_per_byte.saturating_mul(exponential_increase_factor);
    }
    fee_per_byte
}

/// Verify that a signed transaction pays a sufficient fee to enter the pool.
///
/// Mirrors go-algorand's `TransactionPool.checkSufficientFee()`.
///
/// # Special cases
///
/// - **State proof exception**: a state-proof transaction (`"stpf"`) sent from
///   [`STATE_PROOF_SENDER`] with zero fee is always accepted, bypassing fee
///   checks entirely. This matches the Go code that exempts singleton groups
///   with `t.Type == protocol.StateProofTx && t.Sender == transactions.StateProofSender && t.Fee.IsZero()`.
///
/// # Fee threshold
///
/// `fee_threshold = fee_per_byte * encoded_len` where `encoded_len` is the
/// canonical msgpack size of the `SignedTransaction`. If the transaction's fee
/// is below this threshold, `PoolError::FeeBelowThreshold` is returned.
///
/// Note: the flat `MinTxnFee` from consensus is enforced elsewhere (in the
/// block evaluator). This function only checks the pool's dynamic fee-per-byte
/// threshold.
pub fn check_sufficient_fee(
    txn: &SignedTransaction,
    fee_per_byte: u64,
    _consensus: &ConsensusParams,
    group_size: usize,
) -> Result<(), PoolError> {
    // Special case: state proof transactions from the designated sender
    // with zero fee are always accepted, but only in singleton groups.
    // Mirrors Go: `len(txgroup) == 1 && t.Type == protocol.StateProofTx && ...`
    if group_size == 1
        && txn.txn.txn_type == TxnType::Stpf
        && txn.txn.sender == STATE_PROOF_SENDER
        && txn.txn.fee == 0
    {
        return Ok(());
    }

    // When fee_per_byte is 0, the dynamic threshold is 0 and all
    // transactions pass (the flat MinTxnFee is checked elsewhere).
    if fee_per_byte == 0 {
        return Ok(());
    }

    let encoded = canonical_encode_signed_transaction(txn);
    let encoded_len = encoded.len() as u64;
    let fee_threshold = fee_per_byte.saturating_mul(encoded_len);

    if txn.txn.fee < fee_threshold {
        return Err(PoolError::FeeBelowThreshold {
            fee: txn.txn.fee,
            fee_threshold,
            fee_per_byte,
            encoded_len,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute_fee_per_byte tests ──────────────────────────────

    #[test]
    fn fee_per_byte_zero_blocks() {
        assert_eq!(compute_fee_per_byte(0, 2), 0);
    }

    #[test]
    fn fee_per_byte_one_block() {
        assert_eq!(compute_fee_per_byte(1, 2), 0);
    }

    #[test]
    fn fee_per_byte_two_blocks_factor_2() {
        // 2^(2-1) = 2
        assert_eq!(compute_fee_per_byte(2, 2), 2);
    }

    #[test]
    fn fee_per_byte_three_blocks_factor_2() {
        // 2^(3-1) = 4
        assert_eq!(compute_fee_per_byte(3, 2), 4);
    }

    #[test]
    fn fee_per_byte_four_blocks_factor_2() {
        // 2^(4-1) = 8
        assert_eq!(compute_fee_per_byte(4, 2), 8);
    }

    #[test]
    fn fee_per_byte_two_blocks_factor_5() {
        // 5^(2-1) = 5
        assert_eq!(compute_fee_per_byte(2, 5), 5);
    }

    #[test]
    fn fee_per_byte_three_blocks_factor_5() {
        // 5^(3-1) = 25
        assert_eq!(compute_fee_per_byte(3, 5), 25);
    }

    #[test]
    fn fee_per_byte_factor_1_never_escalates() {
        // 1^anything = 1
        assert_eq!(compute_fee_per_byte(5, 1), 1);
    }

    #[test]
    fn fee_per_byte_saturates_on_overflow() {
        // Very large exponent should saturate instead of panicking
        let result = compute_fee_per_byte(100, u64::MAX);
        assert_eq!(result, u64::MAX);
    }

    // ── check_sufficient_fee tests ──────────────────────────────

    fn make_test_txn(fee: u64, txn_type: TxnType, sender: Address) -> SignedTransaction {
        let mut txn = SignedTransaction::default();
        txn.txn.fee = fee;
        txn.txn.txn_type = txn_type;
        txn.txn.sender = sender;
        txn
    }

    fn default_consensus() -> ConsensusParams {
        ConsensusParams::default()
    }

    #[test]
    fn sufficient_fee_zero_fee_per_byte_passes() {
        let txn = make_test_txn(0, TxnType::Pay, Address::ZERO);
        let result = check_sufficient_fee(&txn, 0, &default_consensus(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn sufficient_fee_high_fee_passes() {
        let txn = make_test_txn(1_000_000, TxnType::Pay, Address::ZERO);
        let result = check_sufficient_fee(&txn, 1, &default_consensus(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn sufficient_fee_low_fee_fails() {
        // A minimal pay txn with fee=1 and fee_per_byte=1000 will fail
        // because the encoded size will be larger than 1 byte.
        let txn = make_test_txn(1, TxnType::Pay, Address::ZERO);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            PoolError::FeeBelowThreshold {
                fee,
                fee_threshold,
                fee_per_byte,
                encoded_len,
            } => {
                assert_eq!(fee, 1);
                assert_eq!(fee_per_byte, 1000);
                assert!(fee_threshold > 0);
                assert!(encoded_len > 0);
            }
            other => panic!("expected FeeBelowThreshold, got: {:?}", other),
        }
    }

    #[test]
    fn state_proof_sender_zero_fee_passes() {
        let txn = make_test_txn(0, TxnType::Stpf, STATE_PROOF_SENDER);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 1);
        assert!(
            result.is_ok(),
            "state proof sender with zero fee should be exempt"
        );
    }

    #[test]
    fn state_proof_sender_nonzero_fee_checked_normally() {
        // A state proof txn with a non-zero fee does NOT get the exemption
        // (in Go, the exemption only fires when `t.Fee.IsZero()`).
        let txn = make_test_txn(1, TxnType::Stpf, STATE_PROOF_SENDER);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 1);
        // This should fail because fee=1 < fee_per_byte * encoded_len
        assert!(result.is_err());
    }

    #[test]
    fn state_proof_type_wrong_sender_checked_normally() {
        // State proof txn type from a random sender: no exemption.
        let txn = make_test_txn(0, TxnType::Stpf, Address::ZERO);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn state_proof_sender_wrong_type_checked_normally() {
        // Correct sender but wrong txn type: no exemption.
        let txn = make_test_txn(0, TxnType::Pay, STATE_PROOF_SENDER);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn state_proof_non_singleton_group_checked_normally() {
        // State proof exemption only applies to singleton groups (group_size == 1).
        // In a multi-txn group, the exemption does not apply.
        let txn = make_test_txn(0, TxnType::Stpf, STATE_PROOF_SENDER);
        let result = check_sufficient_fee(&txn, 1000, &default_consensus(), 2);
        assert!(
            result.is_err(),
            "state proof in non-singleton group should not be exempt"
        );
    }

    // ── STATE_PROOF_SENDER constant test ────────────────────────

    #[test]
    fn state_proof_sender_address_not_zero() {
        assert!(!STATE_PROOF_SENDER.is_zero());
    }

    #[test]
    fn state_proof_sender_matches_go_hash() {
        // Verify against the known hex value computed from Go:
        // SHA512/256("SpecialAddr" || "StateProofSender")
        let expected_hex = "bb3c5262a9d5c74d2027e3a7eae4d6ff70cf6c4ce4c5e057c11ed39b95344205";
        let actual_hex = hex::encode(STATE_PROOF_SENDER.0);
        assert_eq!(actual_hex, expected_hex);
    }
}
