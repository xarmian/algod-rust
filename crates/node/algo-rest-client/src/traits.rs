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

use algo_error::Result;
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;

use crate::NodeStatus;

/// Abstraction for fetching blocks from an Algorand node.
///
/// This trait enables different block sources:
/// - `AlgodClient` for live REST API access
/// - File-based fixture replay for offline testing
/// - Mock implementations for unit tests
#[async_trait]
pub trait BlockSource: Send + Sync {
    /// Fetch the raw msgpack bytes for a block at the given round.
    async fn get_block_raw(&self, round: Round) -> Result<Vec<u8>>;

    /// Fetch and decode a block response at the given round.
    async fn get_block(&self, round: Round) -> Result<BlockResponse>;

    /// Get the current node status.
    async fn get_status(&self) -> Result<NodeStatus>;

    /// Wait for the node to advance past the given round.
    /// Returns the new status once the round is reached.
    async fn wait_for_round(&self, round: Round) -> Result<NodeStatus>;
}
