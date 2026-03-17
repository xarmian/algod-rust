// Bridge implementation connecting the agreement BlockFactory trait to
// the transaction pool's block assembly pipeline.
//
// Mirrors the pattern in go-algorand/node/node.go where
// `AlgorandFullNode.AssembleBlock` wraps the transaction pool and converts
// pool errors into agreement errors.

use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_pool::{PoolError, TransactionPool};
use algo_types::{Address, Block, Round};

use crate::seed::Seed;
use crate::traits::{AgreementError, BlockFactory, UnfinishedBlock};

/// Default proposal assembly duration (250ms), matching Go's
/// `config.Defaults.ProposalAssemblyTime`.
const DEFAULT_PROPOSAL_ASSEMBLY_DURATION: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// PoolUnfinishedBlock
// ---------------------------------------------------------------------------

/// An `UnfinishedBlock` backed by a block produced by the transaction pool.
///
/// Mirrors Go's `node.unfinishedBlock` wrapper in `node/node.go`.
pub struct PoolUnfinishedBlock {
    /// The assembled block (header fields like seed/proposer not yet set).
    block: Block,
}

impl PoolUnfinishedBlock {
    /// Wrap a pool-produced block as an `UnfinishedBlock`.
    pub fn new(block: Block) -> Self {
        Self { block }
    }
}

impl UnfinishedBlock for PoolUnfinishedBlock {
    fn finish_block(&self, seed: Seed, proposer: Address, eligible: bool) -> Block {
        let mut finished = self.block.clone();
        finished.seed = seed.0;
        finished.proposer = proposer;
        if !eligible {
            // When not eligible, zero out the proposer payout.
            // Mirrors Go: `if !eligible { blk.ProposerPayout = MicroAlgos{} }`
            finished.proposer_payout = 0;
        }
        finished
    }

    fn round(&self) -> Round {
        self.block.round
    }
}

// ---------------------------------------------------------------------------
// BlockFactoryBridge
// ---------------------------------------------------------------------------

/// A `BlockFactory` implementation that delegates to a `TransactionPool`.
///
/// Mirrors the `AssembleBlock` method on Go's `AlgorandFullNode` which wraps
/// the pool's `AssembleBlock` and converts `ErrStaleBlockAssemblyRequest`
/// into `agreement.ErrAssembleBlockRoundStale`.
pub struct BlockFactoryBridge {
    /// Shared reference to the transaction pool.
    pool: Arc<TransactionPool>,
    /// How long to allow for proposal assembly before the deadline.
    proposal_assembly_duration: Duration,
}

impl BlockFactoryBridge {
    /// Create a new bridge with the given pool and default assembly duration.
    pub fn new(pool: Arc<TransactionPool>) -> Self {
        Self {
            pool,
            proposal_assembly_duration: DEFAULT_PROPOSAL_ASSEMBLY_DURATION,
        }
    }

    /// Create a new bridge with a custom assembly duration.
    pub fn with_duration(pool: Arc<TransactionPool>, duration: Duration) -> Self {
        Self {
            pool,
            proposal_assembly_duration: duration,
        }
    }
}

impl BlockFactory for BlockFactoryBridge {
    fn assemble_block(
        &self,
        round: Round,
        _addresses: &[Address],
    ) -> Result<Box<dyn UnfinishedBlock>, AgreementError> {
        let deadline = Instant::now() + self.proposal_assembly_duration;

        match self.pool.assemble_block(round, deadline) {
            Ok(block) => Ok(Box::new(PoolUnfinishedBlock::new(block))),
            Err(PoolError::StaleBlockAssemblyRequest) => {
                // Convert pool-specific stale error to agreement-level error.
                // Mirrors Go: `err = agreement.ErrAssembleBlockRoundStale`
                Err(AgreementError::RoundStale(round))
            }
            Err(e) => Err(AgreementError::Other(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_unfinished_block_round() {
        let block = Block {
            round: Round(42),
            ..Default::default()
        };
        let ub = PoolUnfinishedBlock::new(block);
        assert_eq!(ub.round(), Round(42));
    }

    #[test]
    fn pool_unfinished_block_finish_sets_fields() {
        let block = Block {
            round: Round(10),
            proposer_payout: 1000,
            ..Default::default()
        };
        let ub = PoolUnfinishedBlock::new(block);

        let seed = Seed([0xab; 32]);
        let proposer = Address([0x01; 32]);
        let finished = ub.finish_block(seed, proposer, true);

        assert_eq!(finished.seed, [0xab; 32]);
        assert_eq!(finished.proposer, proposer);
        assert_eq!(finished.proposer_payout, 1000); // preserved when eligible
    }

    #[test]
    fn pool_unfinished_block_finish_clears_payout_when_ineligible() {
        let block = Block {
            round: Round(10),
            proposer_payout: 5000,
            ..Default::default()
        };
        let ub = PoolUnfinishedBlock::new(block);

        let seed = Seed([0xcd; 32]);
        let proposer = Address([0x02; 32]);
        let finished = ub.finish_block(seed, proposer, false);

        assert_eq!(finished.seed, [0xcd; 32]);
        assert_eq!(finished.proposer, proposer);
        assert_eq!(finished.proposer_payout, 0); // zeroed when ineligible
    }
}
