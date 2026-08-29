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

use std::sync::Mutex;

use tracing::warn;

use algo_types::Block;
use algo_validate::{validate_block, BlockValidationResult};

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
}

impl BlockValidatorBridge {
    /// Create a new bridge with the given genesis parameters.
    pub fn new(genesis_id: String, genesis_hash: [u8; 32], prev_timestamp: Option<i64>) -> Self {
        Self {
            genesis_id,
            genesis_hash,
            prev_timestamp: Mutex::new(prev_timestamp),
        }
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
        let result = validate_block(
            block,
            prev_ts,
            &self.genesis_id,
            &self.genesis_hash,
            None, // no raw payset blobs in the agreement path
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
