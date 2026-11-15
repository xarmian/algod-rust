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

// Bridge implementation connecting the agreement BlockValidator trait to
// the block validation pipeline in algo-validate.
//
// Mirrors the pattern in go-algorand where the node's Validate method
// delegates to the ledger's block validation and wraps the result as a
// ValidatedBlock for the agreement protocol.

use std::sync::{Arc, Mutex};

use tracing::warn;

use algo_types::Block;
use algo_validate::block::validate_block_with_cache;
use algo_validate::{BlockValidationResult, VerifiedTransactionCache};

use crate::traits::{AgreementError, BlockValidator, ValidatedBlock};

// ---------------------------------------------------------------------------
// ValidatedBlockImpl
// ---------------------------------------------------------------------------

/// A `ValidatedBlock` wrapping a block that has passed validation.
///
/// Mirrors Go's `data/datatest.validatedBlock` and
/// `ledgercore.ValidatedBlock`.
pub struct ValidatedBlockImpl {
    /// The validated block.
    block: Block,
    /// The validation result (retained for diagnostics).
    #[allow(dead_code)]
    result: BlockValidationResult,
}

impl ValidatedBlockImpl {
    /// Wrap a block and its validation result.
    pub fn new(block: Block, result: BlockValidationResult) -> Self {
        Self { block, result }
    }
}

impl ValidatedBlock for ValidatedBlockImpl {
    fn block(&self) -> &Block {
        &self.block
    }
}

// ---------------------------------------------------------------------------
// BlockValidatorBridge
// ---------------------------------------------------------------------------

/// A `BlockValidator` implementation that delegates to `algo_validate::validate_block`.
///
/// Mirrors the pattern in Go where the node's `Validate` implementation
/// calls the ledger's block validation pipeline.
///
/// The bridge holds the contextual information needed by the validation
/// function: previous block timestamp, genesis ID, and genesis hash.
///
/// The bridge alone is stateless: it does NOT detect a repeated (sender,
/// lease) or txid, in a group or in the block, because go has no stateless
/// check for it (go's `checkDup` runs only in the validating evaluator,
/// issue #2129). The node never uses the bridge bare: it wraps it in
/// `algo_ledger::PayoutCheckingValidator` (`agreement_block_validator`), which
/// adds go's `Alive`/`checkDup`/authorizer/payout checks against the ledger
/// (issues #2127, PR #2128).
pub struct BlockValidatorBridge {
    /// The genesis ID string for this network.
    genesis_id: String,
    /// The 32-byte genesis hash for this network.
    genesis_hash: [u8; 32],
    /// Previous block timestamp provider.
    ///
    /// In a full implementation this would query the ledger for the previous
    /// block's timestamp. For now, it accepts an optional fixed value.
    /// `None` skips timestamp validation (suitable for genesis / round 0).
    ///
    /// Uses `Mutex` for thread-safe interior mutability so
    /// `set_prev_timestamp` can take `&self` rather than `&mut self`.
    prev_timestamp: Mutex<Option<i64>>,
    /// The node's verified-transaction cache (issue #2344): groups the pool
    /// already verified are not verified again when a proposal carrying
    /// them is validated (go: `eval.go` `GetUnverifiedTransactionGroups`).
    verified_txn_cache: Option<Arc<VerifiedTransactionCache>>,
}

impl BlockValidatorBridge {
    /// Create a new bridge with the given genesis parameters.
    pub fn new(genesis_id: String, genesis_hash: [u8; 32], prev_timestamp: Option<i64>) -> Self {
        Self {
            genesis_id,
            genesis_hash,
            prev_timestamp: Mutex::new(prev_timestamp),
            verified_txn_cache: None,
        }
    }

    /// Share the node's verified-transaction cache with this validator, so a
    /// proposal's transactions the pool already verified are not verified
    /// again (issue #2344).
    pub fn with_verified_txn_cache(mut self, cache: Arc<VerifiedTransactionCache>) -> Self {
        self.verified_txn_cache = Some(cache);
        self
    }

    /// Update the previous block timestamp (call after each committed block).
    pub fn set_prev_timestamp(&self, ts: i64) {
        match self.prev_timestamp.lock() {
            Ok(mut guard) => *guard = Some(ts),
            Err(e) => {
                warn!("prev_timestamp lock poisoned in set_prev_timestamp: {e}");
            }
        }
    }
}

impl BlockValidator for BlockValidatorBridge {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        let prev_ts = match self.prev_timestamp.lock() {
            Ok(guard) => *guard,
            Err(e) => {
                warn!(
                    "prev_timestamp lock poisoned in validate: {e}, skipping timestamp validation"
                );
                None
            }
        };
        let result = validate_block_with_cache(
            block,
            prev_ts,
            &self.genesis_id,
            &self.genesis_hash,
            None, // no raw payset blobs in the agreement path
            self.verified_txn_cache.as_deref(),
        );

        if result.is_valid {
            Ok(Box::new(ValidatedBlockImpl::new(block.clone(), result)))
        } else {
            // Collect all error messages into a single validation failure.
            let error_msgs: Vec<String> = result.errors.iter().map(|e| e.to_string()).collect();
            Err(AgreementError::ValidationFailed(error_msgs.join("; ")))
        }
    }

    fn set_prev_timestamp(&self, ts: i64) {
        // Delegate to the inherent method.
        BlockValidatorBridge::set_prev_timestamp(self, ts);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Round;

    fn make_valid_empty_block() -> Block {
        Block {
            round: Round(1),
            timestamp: 100,
            genesis_id: "test-v1".into(),
            genesis_hash: [0xAA; 32],
            current_protocol: "future".into(),
            ..Default::default()
        }
    }

    #[test]
    fn validated_block_impl_returns_block() {
        let block = make_valid_empty_block();
        let result = BlockValidationResult {
            round: 1,
            is_valid: true,
            errors: vec![],
            txn_count: 0,
            total_txn_bytes: 0,
        };
        let vb = ValidatedBlockImpl::new(block.clone(), result);
        assert_eq!(vb.block().round, Round(1));
    }

    #[test]
    fn bridge_accepts_valid_block() {
        let block = make_valid_empty_block();
        let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
        let result = validator.validate(&block);
        assert!(
            result.is_ok(),
            "valid block should pass: {:?}",
            result.err()
        );
    }

    /// Issue #2344: a proposal's transaction group the node's pool already
    /// verified (it is in the shared cache under the block's context) is not
    /// verified again; without the cache the very same block is rejected for
    /// its signature. (The cached group is a stand-in with a bogus signature,
    /// which only a skipped verification can accept.)
    #[test]
    fn a_cached_group_is_not_reverified_when_a_proposal_is_validated() {
        use algo_types::{Address, SignedTransaction, Transaction};
        use algo_validate::rules::SpecialAddresses;
        use algo_validate::{GroupContext, VerificationContext};

        let mut block = make_valid_empty_block();
        let txn = Transaction {
            txn_type: "pay".into(),
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            amount: 5,
            receiver: Address([2u8; 32]),
            genesis_id: "test-v1".into(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let mut stripped = txn.clone();
        stripped.genesis_id = String::new();
        stripped.genesis_hash = [0u8; 32];
        let stx = SignedTransaction {
            txn: stripped,
            sig: [7u8; 64], // not a signature of this transaction
            has_genesis_id: true,
            ..Default::default()
        };
        block.payset = vec![stx.clone()];
        if let Ok(max) = algo_validate::rules::max_txn_bytes_per_block(&block.current_protocol) {
            let bytes: usize = block
                .payset
                .iter()
                .map(|s| algo_codec::canonical_encode_signed_txn_in_block(s).len())
                .sum();
            block.load = algo_validate::rules::compute_expected_load(bytes, max);
        }

        let uncached = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
        assert!(
            uncached.validate(&block).is_err(),
            "a bad signature must be rejected without the cache"
        );

        let cache = Arc::new(VerifiedTransactionCache::new(16));
        let mut restored = stx;
        restored.txn = txn;
        cache.add(Arc::new(GroupContext::new(
            VerificationContext {
                spec_addrs: SpecialAddresses {
                    fee_sink: block.fee_sink,
                    rewards_pool: block.rewards_pool,
                },
                consensus_version: block.current_protocol.clone(),
            },
            vec![restored],
        )));
        let cached = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90))
            .with_verified_txn_cache(cache);
        let verdict = cached.validate(&block);
        assert!(
            verdict.is_ok(),
            "the cached group must not be verified again: {:?}",
            verdict.err()
        );
    }

    #[test]
    fn bridge_rejects_invalid_protocol() {
        let mut block = make_valid_empty_block();
        block.current_protocol = "v99-nonexistent".into();
        let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
        let result = validator.validate(&block);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown protocol version"),
            "error should mention protocol version: {msg}"
        );
    }

    #[test]
    fn bridge_rejects_timestamp_too_old() {
        let mut block = make_valid_empty_block();
        block.timestamp = 50; // before prev=100
        let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(100));
        let result = validator.validate(&block);
        assert!(result.is_err());
    }
}
