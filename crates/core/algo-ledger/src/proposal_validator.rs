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

// State-aware proposal validation for the participating node (issue #1798).
//
// `algo_validate::validate_block` (behind `BlockValidatorBridge`) is
// stateless, so it cannot judge a peer proposal's `FeesCollected`,
// `Proposer` and `ProposerPayout` header fields: those depend on the fee
// sink and proposer balances after the payset. go validates every proposal
// through the ledger evaluator (`validateForPayouts` in `endOfBlock`) before
// voting for it. This wrapper adds that check, against the committed ledger
// state, after the stateless validation.

use std::sync::{Arc, Mutex};

use algo_agreement::{AgreementError, BlockValidator, ValidatedBlock};
use algo_types::Block;

use crate::shadow_execute::{scratch_validate_payouts, ScratchFailure};
use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

/// Wraps a stateless [`BlockValidator`] with go's `validateForPayouts`
/// evaluated on a rolled-back scratch apply over the ledger.
pub struct PayoutCheckingValidator<V: BlockValidator> {
    inner: V,
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl<V: BlockValidator> PayoutCheckingValidator<V> {
    pub fn new(inner: V, ledger: Arc<Mutex<SqliteLedger>>) -> Self {
        Self { inner, ledger }
    }
}

impl<V: BlockValidator> BlockValidator for PayoutCheckingValidator<V> {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        let validated = self.inner.validate(block)?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| AgreementError::ValidationFailed("ledger lock poisoned".into()))?;
        let current = ledger.current_round().0;
        // A proposal for an already committed round can no longer pay
        // anything; there is no pre-block state left to judge it against.
        if block.round.0 <= current {
            return Ok(validated);
        }
        if block.round.0 != current + 1 {
            return Err(AgreementError::ValidationFailed(format!(
                "cannot validate proposal for round {}: ledger is at round {current}",
                block.round.0
            )));
        }
        match scratch_validate_payouts(&mut *ledger, block) {
            Ok(()) => Ok(validated),
            Err(ScratchFailure::Txn { index, error }) => Err(AgreementError::ValidationFailed(
                format!("payset transaction {index}: {error}"),
            )),
            Err(ScratchFailure::Other(error)) => {
                Err(AgreementError::ValidationFailed(error.to_string()))
            }
            Err(ScratchFailure::Unsupported) => Err(AgreementError::ValidationFailed(
                "ledger cannot evaluate the proposal right now".into(),
            )),
        }
    }

    fn set_prev_timestamp(&self, ts: i64) {
        self.inner.set_prev_timestamp(ts);
    }
}
