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
//!
//! Blocks are committed in [`ApplyMode::Execute`], which runs the AVM: an `appl`
//! transaction whose approval (or clear-state) program rejects fails the apply,
//! so the submission errors and nothing is confirmed — rather than confirming an
//! invalid app call. (The pool's assembly evaluator only does stateless +
//! balance/resource checks, so this commit-time execution is what enforces
//! program correctness in dev mode.) Surfacing the resulting ApplyData
//! (created ids, eval delta, logs, inner txns) in the confirmed-transaction
//! response is tracked in TASK-278; today the response carries `confirmed_round`
//! and the transaction.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use algo_codec::{canonical_encode_block_header_from_block, compute_txn_id, encode_block};
use algo_ledger::apply::{apply_block_with_mode, ApplyMode};
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
/// - restore `genesis_hash` from the block when the field is zero and the hash
///   was stripped — i.e. the block's protocol requires a genesis hash (so every
///   committed txn carries one) or the `has_genesis_hash` flag is set.
///
/// This mirrors the evaluator's `restore_genesis_fields` (`require_genesis_hash
/// || has_genesis_hash`) and is protocol-aware via the block's `current_protocol`
/// — so a transaction that genuinely omitted its genesis hash on a legacy
/// optional-genesis-hash protocol is left untouched, keeping its txid stable.
/// `genesis_id` is flag-gated because an empty `genesis_id` is a legal, common
/// state the flag distinguishes from "stripped because it matched the network".
pub fn restore_block_genesis_fields(stx: &SignedTransaction, block: &Block) -> SignedTransaction {
    let mut out = stx.clone();
    if out.has_genesis_id && out.txn.genesis_id.is_empty() {
        out.txn.genesis_id.clone_from(&block.genesis_id);
    }
    let requires_genesis_hash =
        algo_types::consensus::consensus_params_for_version(&block.current_protocol)
            .is_some_and(|p| p.require_genesis_hash);
    if out.txn.genesis_hash == [0u8; 32]
        && block.genesis_hash != [0u8; 32]
        && (requires_genesis_hash || out.has_genesis_hash)
    {
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
///    `apply_block_with_mode(Execute)` → `commit_block`). Execute mode runs the
///    AVM, so a rejecting app program fails the apply and the whole commit rolls
///    back (the submission errors; nothing is confirmed). No certificate is
///    stored — dev blocks aren't agreed upon, so `get_block_cert` returns `None`
///    (a valid `{block}`-only envelope, exactly as for the genesis block).
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
            // Execute mode runs the AVM, rejecting transactions whose programs
            // fail (rather than confirming an invalid app call as Replay would).
            apply_block_with_mode(&mut *l, &block, ApplyMode::Execute)?;
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
    use algo_types::{Round, Transaction, TxnType, CONSENSUS_V41};

    fn block_with_genesis(proto: &str, id: &str, hash: [u8; 32]) -> Block {
        Block {
            round: Round(1),
            current_protocol: proto.to_string(),
            genesis_id: id.to_string(),
            genesis_hash: hash,
            ..Block::default()
        }
    }

    #[test]
    fn block_txn_id_matches_submitter_on_modern_protocol() {
        // The submitter signs/hashes the full transaction.
        let full = Transaction {
            txn_type: TxnType::Pay,
            sender: algo_types::Address([1u8; 32]),
            genesis_id: "net-x".to_string(),
            genesis_hash: [7u8; 32],
            ..Default::default()
        };
        let want = compute_txn_id(&full);

        // The block stores the STIB-stripped form. genesis_id is flag-gated;
        // genesis_hash is restored because the protocol (v41) requires it, even
        // though the encoder left has_genesis_hash unset.
        let stripped = SignedTransaction {
            txn: Transaction {
                genesis_id: String::new(),
                genesis_hash: [0u8; 32],
                ..full.clone()
            },
            has_genesis_id: true,
            has_genesis_hash: false,
            ..Default::default()
        };
        let block = block_with_genesis(CONSENSUS_V41, "net-x", [7u8; 32]);

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
        let block = block_with_genesis(CONSENSUS_V41, "net-x", [7u8; 32]);
        let restored = restore_block_genesis_fields(&stx, &block);
        assert!(
            restored.txn.genesis_id.is_empty(),
            "unflagged genesis_id stays empty"
        );
        // has_genesis_hash set → genesis_hash restored.
        assert_eq!(
            restored.txn.genesis_hash, [7u8; 32],
            "flagged genesis_hash restored"
        );
    }

    #[test]
    fn restore_skips_genesis_hash_when_optional_and_unflagged() {
        // Protocol does not require a genesis hash and the flag is unset → a
        // genuinely-omitted hash stays zero (restoring would change the txid).
        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                genesis_hash: [0u8; 32],
                ..Default::default()
            },
            has_genesis_hash: false,
            ..Default::default()
        };
        // Unknown protocol → require_genesis_hash treated as false.
        let block = block_with_genesis("legacy-optional-gh", "net-x", [7u8; 32]);
        let restored = restore_block_genesis_fields(&stx, &block);
        assert_eq!(
            restored.txn.genesis_hash, [0u8; 32],
            "optional + unflagged genesis_hash must stay zero",
        );
    }
}
