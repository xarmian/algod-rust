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

//! Production `algo_pool::TransactionPool` adapters for [`TxSyncer`]
//! (issue #774).
//!
//! [`TxSyncer`]'s engine (`sync_round`, the start/stop lifecycle) was
//! wired up in the PR-1 skeleton but never given real implementations of
//! its three collaborator traits — this module supplies two of them:
//!
//! - [`PoolPendingTxAggregate`]: `PendingTxAggregate` backed by
//!   `TransactionPool::pending_tx_ids`.
//! - [`PoolSolicitedTxHandler`]: `SolicitedTxHandler` that submits groups
//!   pulled from a peer into the pool via [`PoolIngest`], deduping against
//!   the shared [`SeenTxCache`] exactly like the inbound gossip path
//!   ([`TxTagHandler`]) does — so a transaction that arrives via pull
//!   after already arriving via gossip (or vice versa) is a cheap cache
//!   hit rather than a second pool round-trip.
//!
//! The third collaborator, [`PeerSource`], is transport-specific (it needs
//! to sample a live peer and hand back something that can make a network
//! call) and lives with the binary's other transport adapters rather than
//! here — see `bin/algod-rust`'s tx-sync client module.
//!
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer
//! [`PeerSource`]: crate::tx_syncer::PeerSource
//! [`TxTagHandler`]: crate::tx_tag_handler::TxTagHandler

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use algo_codec::compute_txn_id;
use algo_pool::TransactionPool;
use algo_types::{Digest, SignedTransaction};

use crate::local_tx_broadcast::PoolIngest;
use crate::tx_sync_service::PendingTxGroupsSource;
use crate::tx_syncer::{PendingTxAggregate, SeenTxCache, SolicitedTxHandler, TxSyncError};

/// [`PendingTxAggregate`] backed by a real `TransactionPool`.
pub struct PoolPendingTxAggregate {
    pool: Arc<TransactionPool>,
}

impl PoolPendingTxAggregate {
    /// Wrap `pool` as a [`PendingTxAggregate`].
    #[must_use]
    pub fn new(pool: Arc<TransactionPool>) -> Self {
        Self { pool }
    }
}

impl PendingTxAggregate for PoolPendingTxAggregate {
    fn pending_tx_ids(&self) -> Vec<Digest> {
        self.pool.pending_tx_ids()
    }
}

impl PendingTxGroupsSource for PoolPendingTxAggregate {
    fn pending_tx_groups(&self) -> Vec<Vec<SignedTransaction>> {
        self.pool.pending_tx_groups()
    }
}

/// [`SolicitedTxHandler`] that submits pulled transaction groups into the
/// pool.
///
/// Mirrors [`TxTagHandler`]'s dedupe-then-ingest logic exactly (see that
/// module's doc comment for the rationale): a group is skipped entirely
/// if every txid in it is already in `seen` (cheap dedup against the
/// gossip path's own recent activity), otherwise it's submitted to the
/// pool and, on success, every txid is recorded in `seen` so a gossip
/// echo of the same transaction short-circuits instead of re-hitting the
/// pool.
///
/// [`TxTagHandler`]: crate::tx_tag_handler::TxTagHandler
pub struct PoolSolicitedTxHandler {
    ingest: Arc<dyn PoolIngest>,
    seen: Arc<SeenTxCache>,
}

impl PoolSolicitedTxHandler {
    /// Build a new handler. `seen` should be the same cache shared with
    /// the inbound [`TxTagHandler`] and the local-broadcast path so all
    /// three agree on "what we've already processed".
    ///
    /// [`TxTagHandler`]: crate::tx_tag_handler::TxTagHandler
    #[must_use]
    pub fn new(ingest: Arc<dyn PoolIngest>, seen: Arc<SeenTxCache>) -> Self {
        Self { ingest, seen }
    }
}

#[async_trait]
impl SolicitedTxHandler for PoolSolicitedTxHandler {
    async fn handle(&self, txgroup: Vec<SignedTransaction>) -> Result<(), TxSyncError> {
        if txgroup.is_empty() {
            return Ok(());
        }

        let txids: Vec<Digest> = txgroup.iter().map(|tx| compute_txn_id(&tx.txn)).collect();
        if txids.iter().all(|id| self.seen.contains(id)) {
            debug!(
                group_len = txgroup.len(),
                "PoolSolicitedTxHandler: all txns in group already seen, dropping",
            );
            return Ok(());
        }

        match self.ingest.ingest(txgroup).await {
            Ok(()) => {
                for id in &txids {
                    self.seen.insert(*id);
                }
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "PoolSolicitedTxHandler: pool rejected pulled TX group");
                Err(TxSyncError::Handler(e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn make_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.fee = fee;
        stx
    }

    struct FakeIngest {
        calls: Mutex<Vec<Vec<SignedTransaction>>>,
        result: Result<(), String>,
    }

    #[async_trait]
    impl PoolIngest for FakeIngest {
        async fn ingest(&self, group: Vec<SignedTransaction>) -> Result<(), String> {
            self.calls.lock().unwrap().push(group);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn new_group_is_ingested_and_marked_seen() {
        let ingest = Arc::new(FakeIngest {
            calls: Mutex::new(Vec::new()),
            result: Ok(()),
        });
        let seen = Arc::new(SeenTxCache::new(100));
        let handler = PoolSolicitedTxHandler::new(ingest.clone(), seen.clone());

        let tx = make_txn(7);
        let id = compute_txn_id(&tx.txn);
        handler.handle(vec![tx]).await.expect("ingest ok");

        assert_eq!(ingest.calls.lock().unwrap().len(), 1);
        assert!(seen.contains(&id));
    }

    #[tokio::test]
    async fn already_seen_group_is_not_reingested() {
        let ingest = Arc::new(FakeIngest {
            calls: Mutex::new(Vec::new()),
            result: Ok(()),
        });
        let seen = Arc::new(SeenTxCache::new(100));
        let handler = PoolSolicitedTxHandler::new(ingest.clone(), seen.clone());

        let tx = make_txn(9);
        let id = compute_txn_id(&tx.txn);
        seen.insert(id);

        handler
            .handle(vec![tx])
            .await
            .expect("dedup short-circuit ok");
        assert_eq!(
            ingest.calls.lock().unwrap().len(),
            0,
            "pool should not be called for an already-seen group"
        );
    }

    #[tokio::test]
    async fn pool_rejection_is_not_marked_seen() {
        let ingest = Arc::new(FakeIngest {
            calls: Mutex::new(Vec::new()),
            result: Err("bad txn".to_string()),
        });
        let seen = Arc::new(SeenTxCache::new(100));
        let handler = PoolSolicitedTxHandler::new(ingest.clone(), seen.clone());

        let tx = make_txn(11);
        let id = compute_txn_id(&tx.txn);
        let err = handler.handle(vec![tx]).await.unwrap_err();
        assert!(matches!(err, TxSyncError::Handler(_)));
        assert!(
            !seen.contains(&id),
            "a rejected group must not suppress a future valid retry"
        );
    }

    #[tokio::test]
    async fn empty_group_is_a_noop() {
        let ingest = Arc::new(FakeIngest {
            calls: Mutex::new(Vec::new()),
            result: Ok(()),
        });
        let seen = Arc::new(SeenTxCache::new(100));
        let handler = PoolSolicitedTxHandler::new(ingest, seen);
        handler.handle(vec![]).await.expect("empty group ok");
    }
}
