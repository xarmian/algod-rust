//! Transaction synchronizer (`TxSyncer`) — skeleton.
//!
//! Mirrors [`go-algorand/rpcs/txSyncer.go`][go-src] (v4.6.0-stable).
//! A background task ticks at a configurable interval, samples a peer, and
//! asks it for transactions missing from the local pool. Accepted transaction
//! groups are forwarded to a [`SolicitedTxHandler`] which (once TASK-69 lands)
//! will submit them to `algo-pool::TransactionPool`.
//!
//! ## Scope
//!
//! This module is the PR-1 skeleton landed under
//! [PLAN-33 · P2P & Gossip Completion]. It intentionally ships:
//!
//! - State machine: [`TxSyncer`], start/stop lifecycle, [`sync_round`].
//! - Peer / pool / handler abstractions ([`TxSyncPeerClient`], [`PeerSource`],
//!   [`PendingTxAggregate`], [`SolicitedTxHandler`]).
//! - A bounded FIFO LRU ([`SeenTxCache`]) for deduping incoming tx IDs — used
//!   by the follow-up tasks (TASK-69 TX-tag handler, TASK-70 broadcast path).
//! - Unit tests exercising `sync_round` against mock peers and validating the
//!   LRU dedup / eviction semantics.
//!
//! The skeleton intentionally does **not** yet:
//!
//! - Register a TX-tag handler on the gossip node (TASK-69).
//! - Broadcast local transactions on pool acceptance (TASK-70).
//! - Negotiate the bloom-filter wire protocol that Go's HTTP `TxSync` uses.
//!   The `pending` argument is passed to the peer client as a plain slice;
//!   the wire format is an implementation detail of the peer client and
//!   lands with the TX-tag work.
//!
//! [go-src]: https://github.com/algorand/go-algorand/blob/rel/stable/rpcs/txSyncer.go
//! [PLAN-33 · P2P & Gossip Completion]: #

use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{select, task::JoinHandle, time};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use algo_types::{Digest, SignedTransaction};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the transaction synchronizer.
///
/// Defaults mirror `go-algorand/config/local_defaults.go`:
/// `TxSyncIntervalSeconds = 60`, `TxSyncTimeoutSeconds = 30`,
/// `TxSyncServeResponseSize = 1_000_000`.
#[derive(Debug, Clone)]
pub struct TxSyncerConfig {
    /// Interval between sync rounds.
    pub sync_interval: Duration,
    /// Per-round request timeout.
    pub sync_timeout: Duration,
    /// Capacity of the recently-seen txid LRU.
    pub seen_cache_size: usize,
    /// Server-side cap on response size (bytes). Surfaced here so the
    /// skeleton owns the full configuration surface; enforced by the
    /// tx-service endpoint when it lands.
    pub server_response_size: usize,
}

impl Default for TxSyncerConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(60),
            sync_timeout: Duration::from_secs(30),
            seen_cache_size: 100_000,
            server_response_size: 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised during a sync round.
#[derive(Debug, thiserror::Error)]
pub enum TxSyncError {
    /// The peer returned an error.
    #[error("peer {peer} sync failed: {message}")]
    Peer {
        /// Remote address of the peer (for logs).
        peer: String,
        /// Underlying error message.
        message: String,
    },

    /// The peer did not respond before `sync_timeout` elapsed.
    #[error("peer {peer} sync timed out after {elapsed:?}")]
    Timeout {
        /// Remote address of the peer.
        peer: String,
        /// The configured timeout that elapsed.
        elapsed: Duration,
    },

    /// The [`SolicitedTxHandler`] rejected a transaction group.
    #[error("handler rejected transaction group: {0}")]
    Handler(String),
}

// ---------------------------------------------------------------------------
// Peer abstraction
// ---------------------------------------------------------------------------

/// A peer-level client for fetching missing transactions.
///
/// Mirrors Go's `TxSyncClient` interface. One method fetches transaction
/// groups that the peer believes we are missing; the `pending` argument
/// describes what we already hold.
#[async_trait]
pub trait TxSyncPeerClient: Send + Sync {
    /// Remote address, used only for logging / error reporting.
    fn address(&self) -> String;

    /// Ask the peer for transaction groups missing from `pending`.
    ///
    /// The production implementation will encode `pending` as a bloom
    /// filter on the wire (see `go-algorand/rpcs/txService.go`). The
    /// skeleton hands through the slice as-is; the peer client is
    /// responsible for framing.
    ///
    /// Must respect `timeout` — implementations that can't honour the
    /// deadline must return [`TxSyncError::Timeout`].
    async fn sync(
        &self,
        pending: &[Digest],
        timeout: Duration,
    ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError>;
}

/// A source of peers that can participate in a sync round.
///
/// Production implementations wrap `GossipNode::get_peers(PeersConnectedOut)`
/// and randomly sample one peer per round (matching Go's
/// `TxSyncer.syncFromClient` selection).
pub trait PeerSource: Send + Sync {
    /// Return a peer client to sync against, or `None` if no peers are ready.
    ///
    /// Returning `None` causes the round to be a no-op — the next tick will
    /// try again.
    fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>>;
}

// ---------------------------------------------------------------------------
// Pool / handler abstractions
// ---------------------------------------------------------------------------

/// Read-only view of the pool's current pending txids.
///
/// Mirrors Go's `PendingTxAggregate` interface. Kept narrow on purpose so
/// the syncer does not pull the concrete `TransactionPool` as a generic
/// parameter — tests can supply a trivial fake.
pub trait PendingTxAggregate: Send + Sync {
    /// Snapshot of every pending txid currently held by the pool.
    fn pending_tx_ids(&self) -> Vec<Digest>;
}

/// Handler invoked for each transaction group accepted from a peer.
///
/// Production wiring (TASK-69) funnels groups into
/// `algo-pool::TransactionPool::remember`. The default
/// [`NoOpSolicitedTxHandler`] exists to let TASK-68 land without dragging
/// that wiring along — callers not yet on TASK-69 use it to keep the
/// compile-time type parameter satisfied.
#[async_trait]
pub trait SolicitedTxHandler: Send + Sync {
    /// Handle one transaction group returned by a peer.
    ///
    /// Errors are logged and do not propagate up the sync loop — they
    /// affect only the current round.
    async fn handle(&self, txgroup: Vec<SignedTransaction>) -> Result<(), TxSyncError>;
}

/// Default handler that drops every group. Replaced by TASK-69.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpSolicitedTxHandler;

#[async_trait]
impl SolicitedTxHandler for NoOpSolicitedTxHandler {
    async fn handle(&self, _txgroup: Vec<SignedTransaction>) -> Result<(), TxSyncError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Seen-hash LRU
// ---------------------------------------------------------------------------

/// Bounded FIFO cache of recently-seen incoming txids.
///
/// Used by the follow-up TX-tag handler (TASK-69) and local-broadcast
/// path (TASK-70) to reject duplicate txids cheaply without round-tripping
/// to the pool. Clonable via `Arc` — every caller sees the same cache.
///
/// The eviction policy is FIFO (insertion order), not true LRU. This
/// matches what we need in practice (keep the most recent N) while
/// staying cheap: `O(1)` insert, `O(1)` membership test, no
/// reshuffling on read.
pub struct SeenTxCache {
    capacity: usize,
    inner: Mutex<SeenTxCacheInner>,
}

struct SeenTxCacheInner {
    seen: HashSet<Digest>,
    order: VecDeque<Digest>,
}

impl SeenTxCache {
    /// Create a cache that retains up to `capacity` txids.
    ///
    /// `capacity == 0` is treated as `1` — a zero-capacity cache would be a
    /// silent footgun for callers who pass an unset config value.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            inner: Mutex::new(SeenTxCacheInner {
                seen: HashSet::with_capacity(capacity),
                order: VecDeque::with_capacity(capacity),
            }),
        }
    }

    /// Record `txid` as seen.
    ///
    /// Returns `true` if this is the first time we've seen the txid since
    /// it was last evicted, or `false` if it was already present.
    pub fn insert(&self, txid: Digest) -> bool {
        let mut g = self.inner.lock().expect("SeenTxCache mutex poisoned");
        if !g.seen.insert(txid) {
            return false;
        }
        g.order.push_back(txid);
        while g.order.len() > self.capacity {
            if let Some(oldest) = g.order.pop_front() {
                g.seen.remove(&oldest);
            } else {
                break;
            }
        }
        true
    }

    /// Returns `true` if `txid` is currently in the cache.
    #[must_use]
    pub fn contains(&self, txid: &Digest) -> bool {
        self.inner
            .lock()
            .expect("SeenTxCache mutex poisoned")
            .seen
            .contains(txid)
    }

    /// Current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("SeenTxCache mutex poisoned")
            .order
            .len()
    }

    /// Returns `true` if the cache has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Configured maximum number of entries.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl fmt::Debug for SeenTxCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeenTxCache")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TxSyncer
// ---------------------------------------------------------------------------

/// Background transaction synchronizer.
///
/// Call [`TxSyncer::start`] to spawn the sync loop; [`TxSyncer::stop`] to
/// cancel it. `start`/`stop` are idempotent — calling twice is a no-op.
///
/// The struct holds [`Arc`] references to its collaborators so the spawned
/// Tokio task can own its own copies independently of the caller.
/// Lifecycle state held under a single mutex.
///
/// `cancel` and `task` must be kept in sync — the token inside `cancel` is
/// always the one wired into the task in `task`. Updating them atomically
/// prevents `start`/`stop` interleavings from handing one call a cancelled
/// token while another call holds the fresh task handle.
struct TxSyncerLifecycle {
    /// Cancellation token for the currently-running task (or a stale token
    /// left over from the last `stop()` — `start()` replaces it before
    /// spawning).
    cancel: CancellationToken,
    /// Join handle for the currently-running task, if any.
    task: Option<JoinHandle<()>>,
}

pub struct TxSyncer {
    config: TxSyncerConfig,
    pool: Arc<dyn PendingTxAggregate>,
    peer_source: Arc<dyn PeerSource>,
    handler: Arc<dyn SolicitedTxHandler>,
    seen: Arc<SeenTxCache>,
    /// Combined lifecycle state: cancellation token + running task handle.
    ///
    /// A single mutex is used (rather than separate locks for `cancel` and
    /// `task`) so that any `start`/`stop` pair observes them atomically —
    /// otherwise two concurrent `stop()` calls bracketing a `start()` can
    /// take the handle of a freshly-spawned task while leaving its token
    /// un-cancelled, which hangs the caller that awaits it.
    lifecycle: Mutex<TxSyncerLifecycle>,
}

impl fmt::Debug for TxSyncer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let running = self
            .lifecycle
            .lock()
            .map(|g| g.task.is_some())
            .unwrap_or(false);
        f.debug_struct("TxSyncer")
            .field("config", &self.config)
            .field("seen_cache", &*self.seen)
            .field("running", &running)
            .finish()
    }
}

impl TxSyncer {
    /// Build a new syncer. The loop is not running until [`start`](Self::start)
    /// is called.
    #[must_use]
    pub fn new(
        config: TxSyncerConfig,
        pool: Arc<dyn PendingTxAggregate>,
        peer_source: Arc<dyn PeerSource>,
        handler: Arc<dyn SolicitedTxHandler>,
    ) -> Self {
        let seen = Arc::new(SeenTxCache::new(config.seen_cache_size));
        Self {
            config,
            pool,
            peer_source,
            handler,
            seen,
            lifecycle: Mutex::new(TxSyncerLifecycle {
                cancel: CancellationToken::new(),
                task: None,
            }),
        }
    }

    /// Shared seen-hash cache.
    ///
    /// The TX-tag handler (TASK-69) and the local-broadcast path (TASK-70)
    /// clone this `Arc` to dedupe their hot paths without re-walking the
    /// pool.
    #[must_use]
    pub fn seen_cache(&self) -> Arc<SeenTxCache> {
        self.seen.clone()
    }

    /// Snapshot of the active configuration.
    #[must_use]
    pub fn config(&self) -> &TxSyncerConfig {
        &self.config
    }

    /// Start the background sync loop.
    ///
    /// Idempotent: calling `start()` while already running is a no-op and
    /// does not double-spawn the task.
    ///
    /// If the previous token has been cancelled (typical after a
    /// `stop()`), install a fresh one so the new task is not born
    /// already-cancelled.
    pub fn start(&self) {
        let mut state = self
            .lifecycle
            .lock()
            .expect("TxSyncer.lifecycle mutex poisoned");
        if state.task.is_some() {
            return;
        }

        // Replace a stale (cancelled) token so the new task is not born
        // already-cancelled.
        if state.cancel.is_cancelled() {
            state.cancel = CancellationToken::new();
        }
        let cancel = state.cancel.clone();

        let config = self.config.clone();
        let pool = self.pool.clone();
        let peer_source = self.peer_source.clone();
        let handler = self.handler.clone();

        // Defensive clamp: `tokio::time::interval` panics on a zero
        // duration. A bad config should degrade to "effectively busy"
        // rather than crash the sync loop on startup.
        let tick_interval = config.sync_interval.max(MIN_TICK_INTERVAL);

        let task = tokio::spawn(async move {
            debug!(
                interval = ?tick_interval,
                timeout = ?config.sync_timeout,
                "TxSyncer loop started",
            );
            let mut ticker = time::interval(tick_interval);
            // Match Go's `time.After` semantics: wait a full interval before
            // the first sync round.
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            // The first `tick()` from `interval` fires immediately; consume
            // it so our first *real* round waits the full `sync_interval`.
            ticker.tick().await;

            loop {
                select! {
                    biased;
                    () = cancel.cancelled() => {
                        debug!("TxSyncer loop cancelled");
                        return;
                    }
                    _ = ticker.tick() => {
                        // Race the sync round against cancellation too.
                        // Otherwise `stop()` can stall up to the peer's
                        // full `sync_timeout` (30 s by default) waiting
                        // for an in-flight `peer.sync(...)` to return,
                        // or even longer for a misbehaving peer.
                        //
                        // Dropping the round's future cancels any
                        // in-flight peer I/O via standard Tokio future
                        // cancellation semantics.
                        select! {
                            biased;
                            () = cancel.cancelled() => {
                                debug!("TxSyncer loop cancelled mid-round");
                                return;
                            }
                            res = sync_round(
                                &config,
                                pool.as_ref(),
                                peer_source.as_ref(),
                                handler.as_ref(),
                            ) => {
                                if let Err(e) = res {
                                    warn!(error = %e, "TxSyncer sync round failed");
                                }
                            }
                        }
                    }
                }
            }
        });
        state.task = Some(task);
    }

    /// Stop the background sync loop and await its termination.
    ///
    /// Idempotent. The cancel-signal and handle-extraction happen under a
    /// single lock so a concurrent `start()` cannot swap the handle out
    /// from under us after we cancel — which would otherwise leave us
    /// awaiting a *new* task whose token we never signalled.
    ///
    /// The cancelled token is left in place; the next call to
    /// [`start`](Self::start) will replace it with a fresh one, so syncing
    /// can be resumed.
    pub async fn stop(&self) {
        let handle = {
            let mut state = self
                .lifecycle
                .lock()
                .expect("TxSyncer.lifecycle mutex poisoned");
            state.cancel.cancel();
            state.task.take()
        };
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    /// Is the background task currently running?
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.lifecycle
            .lock()
            .map(|g| g.task.is_some())
            .unwrap_or(false)
    }
}

/// Floor for the sync-loop tick interval.
///
/// `tokio::time::interval` panics on a zero duration; clamping to 1 ms
/// turns a misconfigured `TxSyncerConfig::sync_interval == 0` into a
/// "tight-ish loop" instead of a startup crash. Matches the defensive
/// posture of [`SeenTxCache::new`] for `seen_cache_size == 0`.
const MIN_TICK_INTERVAL: Duration = Duration::from_millis(1);

/// One cycle of the sync loop.
///
/// Sample a peer, ask it for groups missing from `pool`, and feed each
/// returned group to `handler`. Exposed at module scope so tests can
/// exercise the round without involving timers or spawning tasks.
///
/// Returns `Ok(())` both when a round completes successfully and when no
/// peer was available — the latter is the typical state on a freshly
/// connected node and should not be surfaced as an error.
pub async fn sync_round(
    config: &TxSyncerConfig,
    pool: &dyn PendingTxAggregate,
    peer_source: &dyn PeerSource,
    handler: &dyn SolicitedTxHandler,
) -> Result<(), TxSyncError> {
    let Some(peer) = peer_source.sample_peer() else {
        debug!("TxSyncer.sync_round: no peer available");
        return Ok(());
    };

    let pending = pool.pending_tx_ids();
    debug!(
        peer = %peer.address(),
        pending = pending.len(),
        "TxSyncer.sync_round",
    );

    let groups = peer.sync(&pending, config.sync_timeout).await?;

    for group in groups {
        handler.handle(group).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    // ── Test helpers ─────────────────────────────────────────────

    /// Build a deterministic 32-byte digest from a single byte, for tests.
    fn d(b: u8) -> Digest {
        Digest([b; 32])
    }

    struct FakePeer {
        addr: String,
        calls: Arc<StdMutex<Vec<Vec<Digest>>>>,
        canned: Vec<Vec<SignedTransaction>>,
    }

    #[async_trait]
    impl TxSyncPeerClient for FakePeer {
        fn address(&self) -> String {
            self.addr.clone()
        }

        async fn sync(
            &self,
            pending: &[Digest],
            _timeout: Duration,
        ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError> {
            self.calls
                .lock()
                .expect("calls mutex poisoned")
                .push(pending.to_vec());
            Ok(self.canned.clone())
        }
    }

    struct FakePeerSource {
        peer: Arc<FakePeer>,
    }

    impl PeerSource for FakePeerSource {
        fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
            Some(self.peer.clone())
        }
    }

    struct EmptyPeerSource;
    impl PeerSource for EmptyPeerSource {
        fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
            None
        }
    }

    struct FakePool(Vec<Digest>);
    impl PendingTxAggregate for FakePool {
        fn pending_tx_ids(&self) -> Vec<Digest> {
            self.0.clone()
        }
    }

    struct CountingHandler {
        calls: Arc<StdMutex<u32>>,
    }
    #[async_trait]
    impl SolicitedTxHandler for CountingHandler {
        async fn handle(&self, _txgroup: Vec<SignedTransaction>) -> Result<(), TxSyncError> {
            *self.calls.lock().expect("handler mutex poisoned") += 1;
            Ok(())
        }
    }

    // ── sync_round ──────────────────────────────────────────────

    #[tokio::test]
    async fn sync_round_forwards_pending_and_dispatches_groups() {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let handler_calls = Arc::new(StdMutex::new(0));
        let peer = Arc::new(FakePeer {
            addr: "peer-a".into(),
            calls: calls.clone(),
            // Two empty groups is enough to show the loop iterates; we don't
            // need real transactions for the skeleton.
            canned: vec![vec![], vec![]],
        });
        let cfg = TxSyncerConfig::default();
        let pool = FakePool(vec![d(1), d(2), d(3)]);
        let source = FakePeerSource { peer };
        let handler = CountingHandler {
            calls: handler_calls.clone(),
        };

        sync_round(&cfg, &pool, &source, &handler)
            .await
            .expect("sync_round should succeed");

        // Peer was asked exactly once, with our pending set.
        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1, "peer called exactly once per round");
        assert_eq!(recorded[0], vec![d(1), d(2), d(3)]);

        // Handler fired once per returned group.
        assert_eq!(*handler_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn sync_round_is_noop_when_no_peer_available() {
        let cfg = TxSyncerConfig::default();
        let pool = FakePool(vec![d(1)]);
        let source = EmptyPeerSource;
        let handler = NoOpSolicitedTxHandler;
        sync_round(&cfg, &pool, &source, &handler)
            .await
            .expect("no-peer round should succeed");
    }

    #[tokio::test]
    async fn sync_round_propagates_peer_error() {
        struct FailingPeer;
        #[async_trait]
        impl TxSyncPeerClient for FailingPeer {
            fn address(&self) -> String {
                "failing".into()
            }
            async fn sync(
                &self,
                _pending: &[Digest],
                _timeout: Duration,
            ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError> {
                Err(TxSyncError::Peer {
                    peer: "failing".into(),
                    message: "boom".into(),
                })
            }
        }
        struct Src(Arc<FailingPeer>);
        impl PeerSource for Src {
            fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
                Some(self.0.clone())
            }
        }

        let cfg = TxSyncerConfig::default();
        let pool = FakePool(vec![]);
        let src = Src(Arc::new(FailingPeer));
        let handler = NoOpSolicitedTxHandler;
        let err = sync_round(&cfg, &pool, &src, &handler).await.unwrap_err();
        assert!(matches!(err, TxSyncError::Peer { .. }));
    }

    // ── Seen-hash LRU ───────────────────────────────────────────

    #[test]
    fn seen_cache_inserts_new_and_dedupes_repeats() {
        let c = SeenTxCache::new(3);
        assert!(c.insert(d(1)));
        assert!(c.insert(d(2)));
        assert!(!c.insert(d(1)), "repeat insert returns false");
        assert!(c.contains(&d(1)));
        assert!(c.contains(&d(2)));
        assert!(!c.contains(&d(9)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn seen_cache_evicts_oldest_past_capacity() {
        let c = SeenTxCache::new(3);
        assert!(c.insert(d(1)));
        assert!(c.insert(d(2)));
        assert!(c.insert(d(3)));
        assert!(c.insert(d(4))); // evicts d(1)
        assert!(!c.contains(&d(1)));
        assert!(c.contains(&d(2)));
        assert!(c.contains(&d(3)));
        assert!(c.contains(&d(4)));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn seen_cache_zero_capacity_is_treated_as_one() {
        let c = SeenTxCache::new(0);
        assert_eq!(c.capacity(), 1);
        assert!(c.insert(d(1)));
        assert!(c.insert(d(2))); // evicts d(1)
        assert!(!c.contains(&d(1)));
        assert!(c.contains(&d(2)));
    }

    // ── TxSyncer lifecycle ──────────────────────────────────────

    #[tokio::test]
    async fn txsyncer_start_stop_is_idempotent() {
        let peer = Arc::new(FakePeer {
            addr: "peer-a".into(),
            calls: Arc::new(StdMutex::new(Vec::new())),
            canned: Vec::new(),
        });
        let cfg = TxSyncerConfig {
            // Long enough that the first real tick never fires during this test.
            sync_interval: Duration::from_secs(60),
            ..TxSyncerConfig::default()
        };
        let syncer = TxSyncer::new(
            cfg,
            Arc::new(FakePool(Vec::new())),
            Arc::new(FakePeerSource { peer }),
            Arc::new(NoOpSolicitedTxHandler),
        );

        assert!(!syncer.is_running());
        syncer.start();
        assert!(syncer.is_running());
        // Second start is a no-op.
        syncer.start();
        assert!(syncer.is_running());

        syncer.stop().await;
        assert!(!syncer.is_running());
        // Second stop is a no-op.
        syncer.stop().await;
        assert!(!syncer.is_running());
    }

    #[tokio::test]
    async fn txsyncer_seen_cache_is_shared() {
        let syncer = TxSyncer::new(
            TxSyncerConfig::default(),
            Arc::new(FakePool(Vec::new())),
            Arc::new(EmptyPeerSource),
            Arc::new(NoOpSolicitedTxHandler),
        );
        let a = syncer.seen_cache();
        let b = syncer.seen_cache();
        a.insert(d(7));
        assert!(b.contains(&d(7)));
    }

    /// Regression: `stop()` must not wait for an in-flight peer.sync to
    /// return. The sync loop races peer I/O against cancellation so
    /// shutdown cannot stall on a slow or hung peer.
    #[tokio::test]
    async fn txsyncer_stop_cancels_in_flight_peer_sync() {
        /// A peer whose `sync` holds for 5 seconds. If the loop were to
        /// `.await` this unconditionally, `stop()` would stall.
        struct SlowPeer;
        #[async_trait]
        impl TxSyncPeerClient for SlowPeer {
            fn address(&self) -> String {
                "slow".into()
            }
            async fn sync(
                &self,
                _pending: &[Digest],
                _timeout: Duration,
            ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError> {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(Vec::new())
            }
        }
        struct Src(Arc<SlowPeer>);
        impl PeerSource for Src {
            fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
                Some(self.0.clone())
            }
        }

        let cfg = TxSyncerConfig {
            // Tick immediately so we enter sync_round right away.
            sync_interval: Duration::from_millis(10),
            ..TxSyncerConfig::default()
        };
        let syncer = TxSyncer::new(
            cfg,
            Arc::new(FakePool(Vec::new())),
            Arc::new(Src(Arc::new(SlowPeer))),
            Arc::new(NoOpSolicitedTxHandler),
        );

        syncer.start();
        // Give the loop time to wake, tick, and enter peer.sync's 5 s sleep.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop. Must return well before the 5 s peer sleep completes.
        let started = std::time::Instant::now();
        syncer.stop().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "stop() stalled on in-flight peer.sync (took {elapsed:?})",
        );
        assert!(!syncer.is_running());
    }

    /// Regression: `start()` with `sync_interval == Duration::ZERO` must
    /// not panic. `tokio::time::interval(0)` panics, so `start()` clamps to
    /// `MIN_TICK_INTERVAL`.
    #[tokio::test]
    async fn txsyncer_zero_sync_interval_is_clamped() {
        let cfg = TxSyncerConfig {
            sync_interval: Duration::ZERO,
            ..TxSyncerConfig::default()
        };
        let syncer = TxSyncer::new(
            cfg,
            Arc::new(FakePool(Vec::new())),
            Arc::new(EmptyPeerSource),
            Arc::new(NoOpSolicitedTxHandler),
        );
        // No panic on start.
        syncer.start();
        // Give the spawned task a moment to reach its tick loop, to prove
        // the clamp took effect rather than the task panicking immediately.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(syncer.is_running());
        syncer.stop().await;
        assert!(!syncer.is_running());
    }

    /// Regression: a stopped syncer must be restartable.
    ///
    /// `CancellationToken::cancel()` is permanent — every clone observes
    /// "cancelled" forever. If `start()` were to reuse the same token
    /// after a prior `stop()`, the newly-spawned task's cancel branch
    /// would fire immediately and the loop would exit without ever
    /// running a sync round.
    #[tokio::test]
    async fn txsyncer_can_be_restarted_after_stop() {
        struct CountingPeer {
            calls: Arc<StdMutex<u32>>,
        }
        #[async_trait]
        impl TxSyncPeerClient for CountingPeer {
            fn address(&self) -> String {
                "counter".into()
            }
            async fn sync(
                &self,
                _pending: &[Digest],
                _timeout: Duration,
            ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError> {
                *self.calls.lock().expect("counter mutex poisoned") += 1;
                Ok(vec![])
            }
        }
        struct Src(Arc<CountingPeer>);
        impl PeerSource for Src {
            fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
                Some(self.0.clone())
            }
        }

        let calls = Arc::new(StdMutex::new(0));
        let peer = Arc::new(CountingPeer {
            calls: calls.clone(),
        });
        // Short interval so we see at least one real tick in each phase.
        let cfg = TxSyncerConfig {
            sync_interval: Duration::from_millis(30),
            ..TxSyncerConfig::default()
        };
        let syncer = TxSyncer::new(
            cfg,
            Arc::new(FakePool(Vec::new())),
            Arc::new(Src(peer)),
            Arc::new(NoOpSolicitedTxHandler),
        );

        // Phase 1: run, wait for a tick, stop.
        syncer.start();
        tokio::time::sleep(Duration::from_millis(150)).await;
        syncer.stop().await;
        let after_first = *calls.lock().unwrap();
        assert!(
            after_first > 0,
            "first run should tick at least once (got {after_first})",
        );

        // Phase 2: restart. With a stale cancellation token this would
        // exit immediately; with the fix a fresh token is installed and
        // the loop ticks again.
        syncer.start();
        tokio::time::sleep(Duration::from_millis(150)).await;
        syncer.stop().await;
        let after_second = *calls.lock().unwrap();
        assert!(
            after_second > after_first,
            "restart should tick again (first={after_first}, second={after_second})",
        );
    }
}
