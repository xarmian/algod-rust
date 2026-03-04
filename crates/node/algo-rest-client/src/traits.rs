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
