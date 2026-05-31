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

/// Restore the genesis fields a block's STIB encoding strips, returning the
/// transaction in the canonical form the submitter signed and hashed.
///
/// A block stores transactions in `SignedTxnInBlock` form, which omits
/// `genesis_id` (when it matched the network, flagged by `has_genesis_id`) and
/// `genesis_hash` (when it equals the block's — always, under modern protocols
/// that require it). The decoded `payset` therefore carries the stripped form,
/// so hashing it directly would differ from the submitter's txid. This mirrors
/// the evaluator's `restore_genesis_fields`:
/// - restore `genesis_id` from the block when `has_genesis_id` is set and the
///   field is empty;
/// - restore `genesis_hash` from the block when the field is zero and the block
///   carries one.
///
/// `genesis_id` is gated on the `has_genesis_id` flag because an empty
/// `genesis_id` is a legal, common state (the flag distinguishes "stripped
/// because it matched the network" from "genuinely empty"). `genesis_hash` is
/// gated only on zero-ness, not the flag: the block encoder here does not
/// reliably set `has_genesis_hash` when it strips the hash, and dev-mode block
/// production runs on modern protocols (`require_genesis_hash`) where every
/// committed transaction carries a genesis hash equal to the block's — so a zero
/// hash in a committed block unambiguously means it was stripped. (On legacy
/// protocols where the hash is optional this would be ambiguous, but dev mode
/// never runs there.)
pub fn restore_block_genesis_fields(stx: &SignedTransaction, block: &Block) -> SignedTransaction {
    let mut out = stx.clone();
    if out.has_genesis_id && out.txn.genesis_id.is_empty() {
        out.txn.genesis_id.clone_from(&block.genesis_id);
    }
    if out.txn.genesis_hash == [0u8; 32] && block.genesis_hash != [0u8; 32] {
        out.txn.genesis_hash = block.genesis_hash;
    }
    out
}

/// Canonical txid of a transaction *as committed in a block* — the id the
/// submitter computed, with the block's stripped genesis fields restored (see
/// [`restore_block_genesis_fields`]).
pub fn block_txn_id(stx: &SignedTransaction, block: &Block) -> Digest {
    compute_txn_id(&restore_block_genesis_fields(stx, block).txn)
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

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Round, Transaction, TxnType};

    fn block_with_genesis(id: &str, hash: [u8; 32]) -> Block {
        Block {
            round: Round(1),
            genesis_id: id.to_string(),
            genesis_hash: hash,
            ..Block::default()
        }
    }

    #[test]
    fn block_txn_id_matches_submitter_when_both_genesis_fields_stripped() {
        // The submitter signs/hashes the full transaction.
        let full = Transaction {
            txn_type: TxnType::Pay,
            sender: algo_types::Address([1u8; 32]),
            genesis_id: "net-x".to_string(),
            genesis_hash: [7u8; 32],
            ..Default::default()
        };
        let want = compute_txn_id(&full);

        // The block stores the STIB-stripped form: genesis_id/hash removed, flags set.
        let stripped = SignedTransaction {
            txn: Transaction {
                genesis_id: String::new(),
                genesis_hash: [0u8; 32],
                ..full.clone()
            },
            has_genesis_id: true,
            has_genesis_hash: true,
            ..Default::default()
        };
        let block = block_with_genesis("net-x", [7u8; 32]);

        assert_eq!(
            block_txn_id(&stripped, &block),
            want,
            "restored txid must match the submitter's full-transaction txid",
        );
    }

    #[test]
    fn restore_leaves_unflagged_genesis_id_empty() {
        // A transaction that genuinely had no genesis_id (flag unset) must keep
        // it empty — restoring it would change the txid.
        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                genesis_id: String::new(),
                genesis_hash: [0u8; 32],
                ..Default::default()
            },
            has_genesis_id: false,
            has_genesis_hash: true,
            ..Default::default()
        };
        let block = block_with_genesis("net-x", [7u8; 32]);
        let restored = restore_block_genesis_fields(&stx, &block);
        assert!(
            restored.txn.genesis_id.is_empty(),
            "unflagged genesis_id stays empty"
        );
        assert_eq!(
            restored.txn.genesis_hash, [7u8; 32],
            "genesis_hash restored"
        );
    }
}
