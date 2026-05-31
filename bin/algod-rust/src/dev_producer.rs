//! Dev-mode block production.
//!
//! Mirrors go-algorand's `node.writeDevmodeBlock` + `TransactionPool.AssembleDevModeBlock`
//! (`node/node.go`, `data/pools/transactionPool.go`): on each locally submitted
//! transaction group, assemble a block from the pending pool, finish it with a
//! deterministic seed, commit block + state, and advance the pool. There is no
//! agreement, no VRF, and no certificate — single-node immediate finality.
//!
//! This is intentionally protocol-faithful to go's *dev mode* (not to network
//! consensus): the seed is `committee.Seed(prev.Hash())`, the proposer is left
//! unset, and the block is committed with no certificate. Because the seed and
//! all advanced header fields match go's dev-mode `MakeBlock`/`writeDevmodeBlock`,
//! the produced block digests match a go dev chain.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use algo_codec::{canonical_encode_block_header_from_block, compute_txn_id, encode_block};
use algo_ledger::apply::apply_block;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::SqliteLedger;
use algo_pool::TransactionPool;
use algo_types::{Block, Digest, SignedTransaction};

/// Compute the canonical transaction id of a transaction *as committed in a
/// block*, restoring the genesis hash the block's STIB encoding strips.
///
/// A block stores transactions in `SignedTxnInBlock` form, which omits
/// `genesis_hash` when it equals the block's (always, under modern protocols
/// that require it). The decoded `payset` therefore carries a zero
/// `genesis_hash`, so a naive `compute_txn_id` would differ from the id the
/// submitter computed (which includes the genesis hash). Restore it before
/// hashing so committed-id matching and confirmation lookups agree with the
/// submitter.
///
/// Note: a transaction whose `genesis_id` matched the network (and was thus
/// stripped) cannot be reconstructed from `payset` alone; modern clients set
/// `genesis_hash` but not `genesis_id`, so this restores only the hash.
pub fn block_txn_id(stx: &SignedTransaction, block: &Block) -> Digest {
    if stx.txn.genesis_hash == [0u8; 32] && block.genesis_hash != [0u8; 32] {
        let mut txn = stx.txn.clone();
        txn.genesis_hash = block.genesis_hash;
        compute_txn_id(&txn)
    } else {
        compute_txn_id(&stx.txn)
    }
}

/// Assemble, finish, commit, and announce one dev-mode block built from the
/// pool's pending transactions. Returns the committed block.
///
/// Steps (mirroring go):
/// 1. `assemble_dev_mode_block` — recompute the evaluator and assemble pending
///    transactions into a next-round block whose header is already advanced
///    (round+1, branch = prev.Hash(), rewards) by the evaluator's
///    `start_evaluator`.
/// 2. Deterministic dev seed: `seed = committee.Seed(prev.Hash())`. The
///    evaluator already set `branch = prev.Hash()`, and the dev seed is that
///    same value, so `seed = branch`. The proposer (and thus payout) stay zero,
///    matching `writeDevmodeBlock`.
/// 3. Commit block + state atomically (`begin_block` → `put_block` →
///    `apply_block` → `commit_block`). No certificate is stored — dev blocks
///    aren't agreed upon, so `get_block_cert` returns `None` (a valid
///    `{block}`-only envelope, exactly as for the genesis block).
/// 4. `on_new_block` so the pool drops the now-committed transactions and
///    rebuilds its evaluator for the next round.
pub fn produce_dev_block(
    pool: &Arc<TransactionPool>,
    ledger: &Arc<Mutex<SqliteLedger>>,
) -> anyhow::Result<Block> {
    let mut block = pool
        .assemble_dev_mode_block()
        .map_err(|e| anyhow::anyhow!("assemble dev-mode block: {e}"))?;

    // Deterministic dev finality seed (see step 2 above).
    block.seed = block.branch;

    let proto = block.current_protocol.clone();
    let hdr_data = canonical_encode_block_header_from_block(&block);
    let blk_data =
        encode_block(&block).map_err(|e| anyhow::anyhow!("encode dev-mode block: {e}"))?;
    let committed_txids: HashSet<Digest> = block
        .payset
        .iter()
        .map(|stx| block_txn_id(stx, &block))
        .collect();

    {
        let mut l = ledger
            .lock()
            .map_err(|e| anyhow::anyhow!("ledger lock poisoned: {e}"))?;
        l.begin_block()
            .map_err(|e| anyhow::anyhow!("begin_block: {e}"))?;
        let result = (|| -> Result<(), algo_error::AlgoError> {
            l.put_block(block.round.0, &proto, &hdr_data, &blk_data)?;
            apply_block(&mut *l, &block)?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = l.rollback_block();
            return Err(anyhow::anyhow!(
                "commit dev-mode block {}: {e}",
                block.round.0
            ));
        }
        l.commit_block()
            .map_err(|e| anyhow::anyhow!("commit_block: {e}"))?;
    }

    // Advance the pool past the committed block: drops confirmed transactions
    // and rebuilds the evaluator for the next round.
    pool.on_new_block(&block, &committed_txids);
    Ok(block)
}
