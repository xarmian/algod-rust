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

//! Transaction pool configuration.
//!
//! Default values are derived from go-algorand:
//! - `data/pools/transactionPool.go` — pool-internal constants
//! - `config/local_defaults.go` — TxPoolSize, TxPoolExponentialIncreaseFactor
//! - `config/localTemplate.go` — ProposalAssemblyTime

use std::time::Duration;

/// Configuration for the transaction pool.
///
/// All defaults match the go-algorand reference implementation (v4.6.0-stable).
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of pending transactions in the pool.
    ///
    /// go-algorand: `config/local_defaults.go` `TxPoolSize: 75000`
    pub pool_size: usize,

    /// Factor by which the fee threshold increases exponentially when the pool
    /// is congested.
    ///
    /// go-algorand: `config/local_defaults.go` `TxPoolExponentialIncreaseFactor: 2`
    pub exponential_increase_factor: u64,

    /// Maximum time to spend assembling a proposal block.
    ///
    /// go-algorand: `config/localTemplate.go` `ProposalAssemblyTime` version[23] = 500ms
    pub proposal_assembly_time: Duration,

    /// Number of rounds of expired transaction history to retain.
    ///
    /// go-algorand: `data/pools/transactionPool.go` `expiredHistory = 10`
    pub expired_history: usize,

    /// How long `Remember()` / `Test()` wait for `OnNewBlock()` to process
    /// a new block that has appeared in the ledger.
    ///
    /// go-algorand: `data/pools/transactionPool.go` `timeoutOnNewBlock = time.Second`
    pub timeout_on_new_block: Duration,

    /// Extra time `AssembleBlock()` waits past the deadline before giving up.
    ///
    /// go-algorand: `data/pools/transactionPool.go` `assemblyWaitEps = 150 * time.Millisecond`
    pub assembly_wait_eps: Duration,

    /// Base duration estimate for `GenerateBlock()`.
    ///
    /// go-algorand: `data/pools/transactionPool.go` `generateBlockBaseDuration = 2 * time.Millisecond`
    pub generate_block_base_duration: Duration,

    /// Per-transaction duration estimate for `GenerateBlock()`.
    ///
    /// go-algorand: `data/pools/transactionPool.go` `generateBlockTransactionDuration = 2155 * time.Nanosecond`
    pub generate_block_transaction_duration: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 75_000,
            exponential_increase_factor: 2,
            proposal_assembly_time: Duration::from_millis(500),
            expired_history: 10,
            timeout_on_new_block: Duration::from_secs(1),
            assembly_wait_eps: Duration::from_millis(150),
            generate_block_base_duration: Duration::from_millis(2),
            generate_block_transaction_duration: Duration::from_nanos(2155),
        }
    }
}
