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

//! TX-tag message handler — inbound transaction ingestion.
//!
//! Registers on the gossip node's [`Multiplexer`] for [`Tag::Transaction`]
//! (tag `TX`) and routes decoded signed transactions into the
//! [`TransactionPool`]. This closes the inbound half of gap **G1** in
//! [`DOC-23`]; the outbound (local-broadcast) half lands in TASK-70.
//!
//! ## Wire format
//!
//! A single TX message payload is a **streaming msgpack concatenation**
//! of up to `MaxTxGroupSize` (= 16, per consensus v18+) `SignedTransaction`
//! values. Mirrors `go-algorand/data/txHandler.go::decodeMsg` at
//! v4.6.0-stable.
//!
//! ## Dedup
//!
//! Incoming txids are tested against the [`SeenTxCache`] shared with
//! [`TxSyncer`]. A cache hit means we've processed this txid recently
//! (either via another gossip message or via a sync response), so we
//! drop it without another round-trip to the pool. Cache misses are
//! inserted before the pool call.
//!
//! ## Pool call
//!
//! The whole decoded group is submitted as one unit via
//! [`TransactionPool::remember`]. Pool-side validation errors are
//! logged at `warn!` level and do **not** propagate up to the
//! dispatcher — matching Go's "drop-on-error" posture for unsolicited
//! inbound txns.
//!
//! ## Return value
//!
//! Always returns [`OutgoingMessage`] with [`ForwardingPolicy::Ignore`].
//! Relay-path rebroadcast (Go's `TxHandler.net.Relay`) is intentionally
//! out of scope for TASK-69 and tracked as a PLAN-33 follow-up. Local
//! (REST-origin) broadcast lives in TASK-70.
//!
//! ## Application-call excessive-rate-limiter (ARL) gate (issue #821)
//!
//! `TxTagHandler` is the correct, and — after re-tracing go-algorand's
//! actual pull-sync path — the *only* legitimate wiring point for
//! [`algo_pool::AppRateLimiter`] in algod-rust. This is a genuinely
//! unsolicited, peer-pushed transaction ingestion path (a peer relays a
//! `TX`-tagged gossip message without algod-rust having asked for it),
//! the exact architectural analogue of go-algorand's
//! `TxHandler.processIncomingTxn`/`validateIncomingTxMessage` — the only
//! two call sites in go-algorand @ v5.0.0-stable that invoke
//! `incomingTxGroupAppRateLimit`/`appLimiter.shouldDrop`. See
//! [`algo_pool::app_rate_limiter`]'s module doc for the full trace
//! establishing that go's own pull-sync mechanism
//! (`rpcs.TxSyncer`/`data.SolicitedTxHandler`, the analogue of
//! `crates/node/algo-network/src/tx_syncer.rs`) never applies this gate,
//! and why that rules out wiring it into `tx_syncer.rs` instead.
//!
//! When [`TxTagHandler::with_app_rate_limiter`] has been used to attach a
//! limiter:
//!
//! * **Admission gate**, mirroring `incomingTxGroupAppRateLimit`: once
//!   the pool's pending-transaction count exceeds
//!   `congestion_threshold` (the analogue of go's
//!   `len(handler.backlogQueue) > handler.appLimiterBacklogThreshold` —
//!   algod-rust has no separate backlog queue on this path, since a
//!   decoded group goes straight to `spawn_blocking(|| pool.remember(..))`,
//!   so *pool occupancy* is the natural congestion signal here instead of
//!   *unprocessed-message-queue depth*), a group containing an
//!   application call is checked against
//!   [`AppRateLimiter::should_drop`][algo_pool::AppRateLimiter::should_drop]
//!   keyed by the sending peer's address (IP only, port stripped — the
//!   `origin` analogue of go's `wsPeer.RoutingAddr()`) and dropped
//!   (`Ignore`, never reaching the pool) if the app is over its rate.
//! * **Eval-error penalty**, mirroring `postProcessCheckedTxn`'s
//!   `appLimiter.penalizeEvalError` call: when `pool.remember(group)`
//!   returns an error,
//!   [`AppRateLimiter::penalize_eval_error`][algo_pool::AppRateLimiter::penalize_eval_error]
//!   is called with the same group/origin so a misbehaving app is rate
//!   limited faster than its raw request volume alone would trigger. Go
//!   excludes two specific error kinds from this call
//!   (`bookkeeping.TxnDeadError` — the txn's `LastValid` has already
//!   passed, which can just mean this node fell behind, not the app's
//!   fault — and `ledgercore.ErrEvaluatorCorruptedState`, an internal
//!   fault); algod-rust's [`algo_pool::PoolError`] has no variants
//!   corresponding to either today, so this port penalizes on every
//!   `remember` failure. If/when those distinctions are added to
//!   `PoolError`, this call site should skip penalizing them too, to stay
//!   in parity.
//!
//! Without a limiter attached (the default from [`TxTagHandler::new`]),
//! behavior is unchanged from before issue #821: no per-app rate limiting
//! is applied.
//!
//! [`Multiplexer`]: crate::handler::Multiplexer
//! [`TransactionPool`]: algo_pool::TransactionPool
//! [`DOC-23`]: #
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use algo_codec::compute_txn_id;
use algo_pool::{AppRateLimiter, TransactionPool};
use algo_types::SignedTransaction;

use crate::forwarding_policy::ForwardingPolicy;
use crate::handler::MessageHandler;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;
use crate::tx_syncer::SeenTxCache;

/// Maximum number of signed transactions in a single TX-tag message.
///
/// Matches `MaxTxGroupSize` in `config/consensus.go` for v18+ consensus
/// versions. Messages carrying more than this are truncated to this
/// many and the excess is reported as a decode error.
pub const MAX_TX_GROUP_SIZE: usize = 16;

/// Errors raised during TX-tag decoding or handling.
#[derive(Debug, thiserror::Error)]
pub enum TxTagError {
    /// Payload decoded to zero signed transactions.
    #[error("empty TX group (zero signed transactions)")]
    EmptyGroup,

    /// Payload contained more than [`MAX_TX_GROUP_SIZE`] signed
    /// transactions.
    #[error("TX group too large (> {MAX_TX_GROUP_SIZE})")]
    GroupTooLarge,

    /// Payload bytes remained after decoding the allowed maximum
    /// — the message is malformed.
    #[error("trailing bytes after TX group")]
    TrailingBytes,

    /// msgpack decode failed.
    #[error("msgpack decode failed at offset {offset}: {source}")]
    Decode {
        /// Byte offset within the payload where decoding failed.
        offset: u64,
        /// Underlying decoder error.
        #[source]
        source: rmp_serde::decode::Error,
    },
}

/// Decode a TX-tag payload as a streaming concatenation of
/// [`SignedTransaction`] values.
///
/// Mirrors `go-algorand/data/txHandler.go::decodeMsg` at v4.6.0-stable:
/// we read values back-to-back until either the buffer is exhausted
/// (Ok) or a decode error occurs. An empty group is rejected as Go
/// does.
pub fn decode_tx_message(data: &[u8]) -> Result<Vec<SignedTransaction>, TxTagError> {
    if data.is_empty() {
        return Err(TxTagError::EmptyGroup);
    }

    let mut cursor = Cursor::new(data);
    let mut group: Vec<SignedTransaction> = Vec::with_capacity(1);

    loop {
        // Cap the group at MAX_TX_GROUP_SIZE. If more values remain in
        // the buffer, that's an overflow — matches Go's `dec.Remaining()
        // > 0` check after MaxTxGroupSize.
        if group.len() == MAX_TX_GROUP_SIZE {
            if (cursor.position() as usize) < data.len() {
                return Err(TxTagError::TrailingBytes);
            }
            break;
        }

        let offset = cursor.position();
        match rmp_serde::from_read::<_, SignedTransaction>(&mut cursor) {
            Ok(tx) => group.push(tx),
            Err(e) => {
                // Clean end-of-stream means we *started* the read at
                // EOF — i.e. the previous decode exactly exhausted the
                // buffer. Checking where the cursor *landed* after an
                // `UnexpectedEof` is wrong: a truncated trailing
                // object (e.g. a valid txn followed by a partial
                // msgpack prefix that consumes the remaining bytes)
                // can also end with the cursor at `data.len()`, and
                // that case must be rejected as malformed — not
                // silently accepted with the partial tail dropped.
                if is_eof_like(&e) && (offset as usize) == data.len() {
                    break;
                }
                return Err(TxTagError::Decode { offset, source: e });
            }
        }
    }

    if group.is_empty() {
        return Err(TxTagError::EmptyGroup);
    }

    Ok(group)
}

fn is_eof_like(err: &rmp_serde::decode::Error) -> bool {
    use rmp_serde::decode::Error::*;
    matches!(err, InvalidMarkerRead(e) | InvalidDataRead(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// Multiplexer handler for the TX tag.
///
/// One instance per node. Cloneable via `Arc` — registration expects an
/// `Arc<dyn MessageHandler>`.
pub struct TxTagHandler {
    pool: Arc<TransactionPool>,
    seen: Arc<SeenTxCache>,
    app_limiter: Option<Arc<AppRateLimiter>>,
    app_limiter_congestion_threshold: usize,
}

impl std::fmt::Debug for TxTagHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxTagHandler")
            .field("seen_cache", &*self.seen)
            .field("app_limiter_enabled", &self.app_limiter.is_some())
            .field(
                "app_limiter_congestion_threshold",
                &self.app_limiter_congestion_threshold,
            )
            .finish()
    }
}

impl TxTagHandler {
    /// Create a new handler.
    ///
    /// `seen` should be shared with the [`TxSyncer`] so outbound and
    /// inbound paths agree on "what we've already processed".
    ///
    /// No [`AppRateLimiter`] is attached by default — see
    /// [`Self::with_app_rate_limiter`] to enable the per-app rate-limiting
    /// gate (issue #821).
    ///
    /// [`TxSyncer`]: crate::tx_syncer::TxSyncer
    #[must_use]
    pub fn new(pool: Arc<TransactionPool>, seen: Arc<SeenTxCache>) -> Self {
        Self {
            pool,
            seen,
            app_limiter: None,
            app_limiter_congestion_threshold: 0,
        }
    }

    /// Attach an [`AppRateLimiter`] (issue #821), mirroring go-algorand's
    /// `TxHandler.appLimiter`/`appLimiterBacklogThreshold`. `limiter`
    /// should typically be shared (same `Arc`) across every `TxTagHandler`
    /// instance registered on this node (e.g. one per active transport —
    /// WS-gossip and libp2p both route inbound `TX`-tagged messages
    /// through their own `TxTagHandler`), since go-algorand's `appLimiter`
    /// is a single node-wide limiter regardless of which peer/transport a
    /// message arrived on.
    ///
    /// `congestion_threshold` is compared against
    /// `TransactionPool::pending_count()`: the rate-limit check only runs
    /// once the pool holds more than this many pending transactions,
    /// mirroring go's `appLimiterBacklogThreshold = TxBacklogSize *
    /// TxBacklogAppRateLimitingCongestionPct / 100` (default 10%) applied
    /// to its backlog-queue depth. See the module doc for why algod-rust
    /// uses pool occupancy rather than a message-backlog-queue depth as
    /// the congestion signal.
    #[must_use]
    pub fn with_app_rate_limiter(
        mut self,
        limiter: Arc<AppRateLimiter>,
        congestion_threshold: usize,
    ) -> Self {
        self.app_limiter = Some(limiter);
        self.app_limiter_congestion_threshold = congestion_threshold;
        self
    }

    /// Returns a reference to the shared seen-tx cache.
    #[must_use]
    pub fn seen_cache(&self) -> Arc<SeenTxCache> {
        self.seen.clone()
    }
}

/// Extract the `origin` byte string used to key [`AppRateLimiter`]
/// entries from a gossip message's sender address string (e.g.
/// `"1.2.3.4:4160"`). Strips the port, mirroring go-algorand's
/// `wsPeer.RoutingAddr()`/`gsPeer.RoutingAddr()` (both return the peer's
/// IP only, deliberately excluding the ephemeral port so that repeated
/// connections from the same origin address bucket together). Falls back
/// to the raw sender string's bytes when it doesn't parse as a
/// `host:port` socket address (e.g. a synthetic/test sender, or a P2P
/// peer id string) — still deterministic per distinct sender, just not
/// byte-identical to go's IP-octet encoding, which is immaterial since
/// these bytes are only ever hashed locally within this process.
fn origin_bytes(sender: &str) -> Vec<u8> {
    match sender.parse::<std::net::SocketAddr>() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        },
        Err(_) => sender.as_bytes().to_vec(),
    }
}

#[async_trait]
impl MessageHandler for TxTagHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        // Decode the payload.
        let group = match decode_tx_message(&msg.data) {
            Ok(g) => g,
            Err(e) => {
                warn!(
                    sender = %msg.sender,
                    bytes = msg.data.len(),
                    error = %e,
                    "TxTagHandler: failed to decode TX message",
                );
                return OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: Tag::Transaction,
                    payload: Vec::new(),
                    topics: None,
                };
            }
        };

        // Compute txids once up front — `compute_txn_id` hashes the
        // Transaction body (not the signature), so we can dedup
        // consistently across different signed variants of the same
        // txn.
        let txids: Vec<algo_types::Digest> =
            group.iter().map(|tx| compute_txn_id(&tx.txn)).collect();

        // Dedup fast-path: if every txid in the group has already been
        // *successfully ingested* (see below — we only insert on
        // Ok(())), the pool would just return duplicates. Skip the
        // round-trip.
        let any_new = txids.iter().any(|id| !self.seen.contains(id));
        if !any_new {
            debug!(
                sender = %msg.sender,
                group_len = group.len(),
                "TxTagHandler: all txns in group already seen, dropping",
            );
            return OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: Tag::Transaction,
                payload: Vec::new(),
                topics: None,
            };
        }

        // Application-call excessive-rate-limiter (ARL) admission gate
        // (issue #821), mirroring go's
        // `TxHandler.incomingTxGroupAppRateLimit`: only engages once the
        // pool is congested, and only ever drops the *entire* group (a
        // single over-rate app in a group is enough to drop it all,
        // matching go's `shouldDrop` semantics — see
        // `algo_pool::app_rate_limiter`'s doc comment).
        if let Some(limiter) = &self.app_limiter {
            let congested = self.pool.pending_count() > self.app_limiter_congestion_threshold;
            if congested {
                let origin = origin_bytes(&msg.sender);
                if limiter.should_drop(&group, &origin) {
                    debug!(
                        sender = %msg.sender,
                        group_len = group.len(),
                        "TxTagHandler: dropped by application rate limiter",
                    );
                    return OutgoingMessage {
                        action: ForwardingPolicy::Ignore,
                        tag: Tag::Transaction,
                        payload: Vec::new(),
                        topics: None,
                    };
                }
            }
        }

        // Submit the whole group to the pool on the blocking executor.
        // `TransactionPool::remember` is a synchronous mutex/condvar
        // flow that can wait up to ~`timeout_on_new_block` (default
        // 1 s) when the evaluator lags, so running it inline on a
        // Tokio worker would stall peer dispatch under TX bursts. We
        // offload to `spawn_blocking` so the async receive task can
        // proceed to the next message immediately.
        //
        // On `Ok(())` we record the txids in the seen cache so
        // subsequent duplicates short-circuit. On failure, the txids
        // are NOT recorded — a bad-signed or otherwise rejected
        // variant must not suppress a valid retransmission of the
        // same Transaction body (txids are body-derived).
        //
        // Errors are logged and dropped; unsolicited inbound txns
        // must never panic or propagate back to the dispatcher.
        // Cloned only when a limiter is attached: `penalize_eval_error`
        // needs the group's app ids after `remember` has moved `group`
        // into the blocking task. Mirrors go's `postProcessCheckedTxn`
        // calling `appLimiter.penalizeEvalError(wi.unverifiedTxGroup, ...)`
        // on a `Remember` failure.
        let group_for_penalty = self.app_limiter.is_some().then(|| group.clone());
        let sender = msg.sender.clone();
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || pool.remember(group)).await;
        match result {
            Ok(Ok(())) => {
                for id in &txids {
                    self.seen.insert(*id);
                }
                debug!(
                    sender = %msg.sender,
                    ingested = txids.len(),
                    "TxTagHandler: group accepted",
                );
            }
            Ok(Err(e)) => {
                warn!(
                    sender = %msg.sender,
                    error = %e,
                    "TxTagHandler: pool rejected inbound TX group",
                );
                if let (Some(limiter), Some(group)) = (&self.app_limiter, group_for_penalty) {
                    let origin = origin_bytes(&sender);
                    limiter.penalize_eval_error(&group, &origin);
                }
            }
            Err(join_err) => {
                warn!(
                    sender = %msg.sender,
                    error = %join_err,
                    "TxTagHandler: pool ingest task join failed",
                );
            }
        }

        OutgoingMessage {
            action: ForwardingPolicy::Ignore,
            tag: Tag::Transaction,
            payload: Vec::new(),
            topics: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    /// Build a minimal valid-shape signed transaction for decode tests.
    ///
    /// These txns do not have real signatures or fees — they are used
    /// only to exercise the msgpack decoder path, not the pool. We
    /// start from [`Default`] and tweak just the `fee` field so the
    /// round-trip test can distinguish decoded txns.
    fn make_signed_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.fee = fee;
        stx
    }

    fn encode_group(group: &[SignedTransaction]) -> Vec<u8> {
        let mut out = Vec::new();
        for tx in group {
            let bytes = rmp_serde::to_vec_named(tx).expect("encode stxn");
            out.extend_from_slice(&bytes);
        }
        out
    }

    #[test]
    fn decode_single_txn() {
        let tx = make_signed_txn(1000);
        let encoded = encode_group(std::slice::from_ref(&tx));
        let group = decode_tx_message(&encoded).expect("single-txn decode");
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].txn.fee, 1000);
    }

    #[test]
    fn decode_group_of_three() {
        let group_in = vec![make_signed_txn(1), make_signed_txn(2), make_signed_txn(3)];
        let encoded = encode_group(&group_in);
        let group = decode_tx_message(&encoded).expect("group decode");
        assert_eq!(group.len(), 3);
        assert_eq!(group[0].txn.fee, 1);
        assert_eq!(group[1].txn.fee, 2);
        assert_eq!(group[2].txn.fee, 3);
    }

    #[test]
    fn decode_empty_payload_is_error() {
        let err = decode_tx_message(&[]).unwrap_err();
        assert!(matches!(err, TxTagError::EmptyGroup));
    }

    #[test]
    fn decode_oversized_group_is_error() {
        let big: Vec<SignedTransaction> = (0..MAX_TX_GROUP_SIZE + 2)
            .map(|i| make_signed_txn(i as u64 + 1))
            .collect();
        let encoded = encode_group(&big);
        let err = decode_tx_message(&encoded).unwrap_err();
        assert!(
            matches!(err, TxTagError::TrailingBytes),
            "expected TrailingBytes, got {err:?}",
        );
    }

    #[test]
    fn decode_malformed_msgpack_is_error() {
        // 0xC1 is "never used" in msgpack and decodes to an error.
        let err = decode_tx_message(&[0xC1, 0xC1, 0xC1]).unwrap_err();
        assert!(
            matches!(err, TxTagError::Decode { .. }),
            "expected Decode, got {err:?}",
        );
    }

    #[test]
    fn decode_truncated_tail_is_error() {
        // A valid txn followed by a truncated msgpack object must be
        // rejected, not silently accepted with the partial tail
        // dropped. Regression for a prior bug where the EOF-check
        // keyed off the cursor *after* an UnexpectedEof, which could
        // land at `data.len()` when the partial object consumed the
        // remaining bytes.
        let good = encode_group(&[make_signed_txn(42)]);
        let mut truncated = good.clone();
        // Append a msgpack "map of 3 entries" header (0x83) with no
        // entries — an unexpected-EOF candidate.
        truncated.push(0x83);

        let err = decode_tx_message(&truncated).unwrap_err();
        assert!(
            matches!(err, TxTagError::Decode { .. }),
            "expected Decode error for truncated tail, got {err:?}",
        );
    }

    #[test]
    fn decode_exactly_max_group_size() {
        let group_in: Vec<SignedTransaction> = (0..MAX_TX_GROUP_SIZE)
            .map(|i| make_signed_txn(i as u64 + 1))
            .collect();
        let encoded = encode_group(&group_in);
        let group = decode_tx_message(&encoded).expect("max-size group decode");
        assert_eq!(group.len(), MAX_TX_GROUP_SIZE);
    }

    // -----------------------------------------------------------------
    // origin_bytes (issue #821)
    // -----------------------------------------------------------------

    #[test]
    fn origin_bytes_strips_port_from_ipv4_socket_addr() {
        assert_eq!(origin_bytes("1.2.3.4:4160"), vec![1u8, 2, 3, 4]);
        // Same IP, different port -> same origin bytes (go's RoutingAddr
        // deliberately ignores the ephemeral port so reconnects bucket
        // together).
        assert_eq!(origin_bytes("1.2.3.4:9999"), vec![1u8, 2, 3, 4]);
    }

    #[test]
    fn origin_bytes_falls_back_to_raw_string_for_unparseable_sender() {
        // A P2P peer-id-shaped sender (not a `host:port` socket address)
        // still yields a deterministic, non-empty byte string.
        let a = origin_bytes("12D3KooWAbCdEf");
        let b = origin_bytes("12D3KooWAbCdEf");
        let c = origin_bytes("12D3KooWDifferent");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tests: application rate limiter wiring (issue #821)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod app_rate_limiter_wiring_tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use algo_error::AlgoError;
    use algo_pool::traits::{BlockEvaluator, PoolLedger};
    use algo_pool::{AppRateLimiter, PoolConfig, TransactionPool};
    use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, TxnType};

    use super::*;
    use crate::tx_syncer::SeenTxCache;

    /// Minimal stub ledger, replicated from the pattern already used by
    /// `tests/tx_propagation_inproc.rs` — see that file's doc comment.
    /// `fail` lets a test force `remember` to fail so the eval-error
    /// penalty path can be exercised deterministically.
    struct StubLedger {
        round: Round,
        fail: std::sync::Arc<AtomicBool>,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
        }
        fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
            Ok(BlockHeader::default())
        }
        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
            Ok(ConsensusParams::default())
        }
        fn start_evaluator(
            &self,
            _hdr: BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
                fail: self.fail.clone(),
            }))
        }
    }

    struct StubEvaluator {
        round: Round,
        fail: std::sync::Arc<AtomicBool>,
    }

    impl BlockEvaluator for StubEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            if self.fail.load(Ordering::SeqCst) {
                Err(AlgoError::Validation {
                    message: "stub eval failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    /// Build a pool with a stub evaluator wired via `on_new_block`, plus
    /// the shared `fail` flag that controls whether `remember` succeeds.
    fn make_pool() -> (Arc<TransactionPool>, std::sync::Arc<AtomicBool>) {
        let fail = std::sync::Arc::new(AtomicBool::new(false));
        let ledger: Arc<dyn PoolLedger> = Arc::new(StubLedger {
            round: Round(1),
            fail: fail.clone(),
        });
        let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
        pool.on_new_block(&Block::default(), &HashSet::new());
        (pool, fail)
    }

    /// An application-call transaction touching `app_id`, otherwise
    /// well-formed enough to pass the pool's admission checks.
    fn make_app_call_txn(app_id: u64, note: u8) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Appl;
        stx.txn.sender = Address([1u8; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.application_id = app_id;
        stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
        stx
    }

    fn encode_group(group: &[SignedTransaction]) -> Vec<u8> {
        let mut out = Vec::new();
        for tx in group {
            let bytes = rmp_serde::to_vec_named(tx).expect("encode stxn");
            out.extend_from_slice(&bytes);
        }
        out
    }

    fn incoming(group: &[SignedTransaction], sender: &str) -> IncomingMessage {
        let data = encode_group(group);
        IncomingMessage::new(Tag::Transaction, data, sender.to_string(), 0)
    }

    /// Below the congestion threshold, the limiter must never engage —
    /// mirrors go's `congestedARL := len(handler.backlogQueue) >
    /// handler.appLimiterBacklogThreshold` guard on
    /// `incomingTxGroupAppRateLimit`.
    #[tokio::test]
    async fn admits_when_pool_is_not_congested_even_if_limiter_would_drop() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // A limiter with rate 0/window: the very first attempt would be
        // dropped once congested. Congestion threshold is high (100), so
        // with an empty pool this must NOT engage.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 100);

        let tx = make_app_call_txn(7, 1);
        let msg = incoming(&[tx.clone()], "1.2.3.4:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);

        let txid = compute_txn_id(&tx.txn);
        assert!(
            pool.pending_tx_ids().contains(&txid),
            "group should be admitted to the pool while uncongested"
        );
    }

    /// Once the pool is congested (pending count > threshold), a *second*
    /// attempt from the same app/origin pair, over the configured rate,
    /// must be dropped before it ever reaches the pool — mirrors go's
    /// `incomingTxGroupAppRateLimit`/`shouldDrop`. (A brand-new
    /// `(app, origin)` pair is always admitted unconditionally on its
    /// first sighting — see `AppRateLimiter::should_drop_keys` — so the
    /// rate check only bites from the second attempt onward.)
    #[tokio::test]
    async fn drops_over_rate_app_group_once_congested() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // Rate 0/window, congestion threshold 0: any pending txn counts
        // as "congested", and any repeat attempt is instantly over rate.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // Prime the pool with an unrelated pending txn so pending_count()
        // > congestion_threshold (0) for every subsequent group.
        let filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([2u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xAA]);
            stx
        };
        pool.remember(vec![filler]).expect("filler txn admitted");
        assert!(pool.pending_count() > 0);

        // First attempt for app 7 from this origin: a brand-new
        // (app, origin) pair is always admitted.
        let tx1 = make_app_call_txn(7, 1);
        let txid1 = compute_txn_id(&tx1.txn);
        let msg1 = incoming(&[tx1], "1.2.3.4:4160");
        let out1 = handler.handle(msg1).await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert!(
            pool.pending_tx_ids().contains(&txid1),
            "first attempt for a fresh (app, origin) pair must be admitted"
        );

        // Second attempt, same app + same origin: now over rate.
        let tx2 = make_app_call_txn(7, 2);
        let txid2 = compute_txn_id(&tx2.txn);
        let msg2 = incoming(&[tx2], "1.2.3.4:4160");
        let out2 = handler.handle(msg2).await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert!(
            !pool.pending_tx_ids().contains(&txid2),
            "over-rate app group must be dropped before reaching the pool"
        );
    }

    /// A `remember` failure must penalize the app so a *subsequent*
    /// attempt from the same app/origin gets rate limited faster than
    /// raw volume alone would trigger — mirrors go's
    /// `postProcessCheckedTxn`'s `appLimiter.penalizeEvalError` call.
    #[tokio::test]
    async fn penalizes_app_on_remember_failure() {
        let (pool, fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // Rate 0/window: the penalty (`max(1, service_rate_per_window /
        // 4)` = `max(1, 0)` = 1) plus the next attempt's own `+1` already
        // exceeds the window's admitted rate of 0, so a *second* attempt
        // for the same (app, origin) pair — this time via the success
        // path — must be dropped. Congestion threshold 0 so the gate
        // always runs once anything is pending.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // First: force `remember` to fail and penalize app 9.
        fail.store(true, Ordering::SeqCst);
        let failing_tx = make_app_call_txn(9, 1);
        let msg = incoming(&[failing_tx], "5.6.7.8:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(pool.pending_count(), 0, "failed remember admits nothing");

        // Now let remember succeed again, and prime congestion with an
        // unrelated txn.
        fail.store(false, Ordering::SeqCst);
        let filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([3u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xBB]);
            stx
        };
        pool.remember(vec![filler]).expect("filler txn admitted");

        // Same app id + same origin: the penalty already recorded should
        // now cause this admission attempt to be dropped even though it's
        // the "first" successful attempt from this origin.
        let tx = make_app_call_txn(9, 2);
        let txid = compute_txn_id(&tx.txn);
        let msg = incoming(&[tx], "5.6.7.8:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert!(
            !pool.pending_tx_ids().contains(&txid),
            "app penalized for the earlier eval error should be rate limited on retry"
        );
    }

    /// A non-application-call group must never be gated by the app rate
    /// limiter, congested or not — mirrors `txgroupToKeys` returning
    /// `None`/empty for a group with no `ApplicationCallTx`.
    #[tokio::test]
    async fn non_app_call_group_is_never_gated() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // Prime congestion so the gate actually runs (congestion
        // threshold is 0, so any pending txn is enough) — this test
        // must prove the app rate limiter itself never engages for a
        // non-application-call group, not merely that the congestion
        // pre-check was skipped.
        let congestion_filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([5u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xDD]);
            stx
        };
        pool.remember(vec![congestion_filler])
            .expect("congestion filler admitted");
        assert!(pool.pending_count() > 0);

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = Address([4u8; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.note = serde_bytes::ByteBuf::from(vec![0xCC]);
        let txid = compute_txn_id(&stx.txn);

        let msg = incoming(&[stx], "9.9.9.9:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert!(
            pool.pending_tx_ids().contains(&txid),
            "a plain payment group must never be gated by the app rate limiter"
        );
    }
}
