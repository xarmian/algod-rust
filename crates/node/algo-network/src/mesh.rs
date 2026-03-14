//! Mesh connectivity thread.
//!
//! Maintains the target outgoing connection count (typically `GossipFanout`,
//! default 4) by periodically checking how many outgoing peers are connected
//! and dialing new ones from the phonebook when below target.
//!
//! The design mirrors go-algorand's `network/mesh.go` (`baseMesher.meshThread`)
//! and `network/wsNetwork.go` (`meshThreadInner`, `checkNewConnectionsNeeded`,
//! `tryConnectReserveAddr`).
//!
//! # Architecture
//!
//! [`MeshThread`] is spawned as a tokio task. It wakes on either:
//! - A periodic timer (`mesh_interval`, default 1 minute)
//! - An on-demand notification via `mesh_update_rx` (e.g. from `OnNetworkAdvance`)
//!
//! On each wake it:
//! 1. Counts current outgoing peers (via a callback)
//! 2. If below target, fetches candidate addresses from the phonebook
//! 3. Skips addresses already in-progress or already connected
//! 4. Initiates connection attempts up to the deficit
//! 5. Uses exponential backoff when the phonebook returns no usable addresses
//! 6. Resets backoff on any successful connection attempt initiation

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::peer_role::{Role, RELAY_ROLE};
use crate::phonebook::Phonebook;
use crate::reconnect::ExponentialBackoff;

// ---------------------------------------------------------------------------
// Constants (matching go-algorand)
// ---------------------------------------------------------------------------

/// Default mesh thread wake interval — matches Go's `meshThreadInterval`.
pub const DEFAULT_MESH_INTERVAL: Duration = Duration::from_secs(60);

/// Default target outgoing connection count — matches Go's default
/// `GossipFanout` value.
pub const DEFAULT_GOSSIP_FANOUT: usize = 4;

/// Minimum backoff delay when no peers are available (matches Go's 2s).
const BACKOFF_MIN: Duration = Duration::from_secs(2);

/// Maximum backoff delay — capped at the mesh interval (matches Go's
/// `meshThreadInterval` = 1 minute).
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Backoff multiplier (matches Go's `ExponentialDecorrelatedJitter` factor).
const BACKOFF_MULTIPLIER: f64 = 3.0;

// ---------------------------------------------------------------------------
// MeshRequest
// ---------------------------------------------------------------------------

/// A request to trigger an immediate mesh refresh cycle.
///
/// Mirrors Go's `meshRequest` — the optional `done` channel is signalled
/// after the mesh cycle completes so callers can synchronously wait.
#[derive(Debug)]
pub struct MeshRequest {
    /// If `Some`, the sender is notified after the mesh cycle completes.
    pub done: Option<tokio::sync::oneshot::Sender<()>>,
}

// ---------------------------------------------------------------------------
// ConnectFn trait
// ---------------------------------------------------------------------------

/// Abstraction over the "dial a peer" operation.
///
/// The mesh thread calls this for each address it wants to connect to.
/// The future resolves to `true` if a connection was successfully initiated
/// (the peer may still be negotiating), or `false` on failure.
///
/// Implementors are expected to handle phonebook rate-limiting and the
/// full `try_connect` sequence internally.
pub trait ConnectFn: Send + Sync + 'static {
    /// Attempt to connect to `addr`. Returns `true` if the attempt was
    /// initiated (not necessarily completed).
    fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

/// Blanket implementation for closures / function pointers that return a
/// pinned future.
impl<F, Fut> ConnectFn for F
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin((self)(addr))
    }
}

// ---------------------------------------------------------------------------
// PeerCounter trait
// ---------------------------------------------------------------------------

/// Provides the mesh thread with the current outgoing peer count and the
/// set of currently-connected addresses.
pub trait PeerCounter: Send + Sync + 'static {
    /// Returns `(num_outgoing_peers, connected_addresses)`.
    fn outgoing_peer_info(&self) -> (usize, HashSet<String>);
}

// ---------------------------------------------------------------------------
// MeshThread
// ---------------------------------------------------------------------------

/// Maintains the target outgoing connection count by periodically dialing
/// new peers from the phonebook.
///
/// Spawned as a tokio task via [`MeshThread::run`].
pub struct MeshThread<C: ConnectFn, P: PeerCounter> {
    /// Target number of outgoing connections (GossipFanout).
    target_conn_count: usize,

    /// How often the mesh thread wakes up to check connectivity.
    mesh_interval: Duration,

    /// Cancellation token for clean shutdown.
    cancel: CancellationToken,

    /// Receiver for on-demand mesh refresh requests (e.g. from
    /// `OnNetworkAdvance`).
    mesh_update_rx: mpsc::Receiver<MeshRequest>,

    /// Phonebook — source of candidate peer addresses.
    phonebook: Arc<Phonebook>,

    /// Role to query from the phonebook (typically `RELAY_ROLE`).
    role: Role,

    /// Dial function — called to initiate a connection to an address.
    connect_fn: C,

    /// Provides current outgoing peer count and connected addresses.
    peer_counter: P,

    /// Addresses currently being dialed (prevents duplicate dials).
    /// Shared with the connection completion callbacks.
    in_progress: Arc<Mutex<HashSet<String>>>,

    /// Exponential backoff — engaged when no addresses are available.
    backoff: ExponentialBackoff,

    /// Our own public address — excluded from dial targets to prevent
    /// self-connections (mirrors Go's `wn.config.PublicAddress` filter).
    public_address: Option<String>,
}

impl<C: ConnectFn, P: PeerCounter> MeshThread<C, P> {
    /// Create a new mesh thread.
    ///
    /// # Arguments
    ///
    /// * `target_conn_count` — desired outgoing peer count (GossipFanout)
    /// * `mesh_interval` — periodic wake interval
    /// * `cancel` — cancellation token for shutdown
    /// * `mesh_update_rx` — channel for on-demand refresh notifications
    /// * `phonebook` — source of candidate addresses
    /// * `connect_fn` — function to initiate connections
    /// * `peer_counter` — provides current outgoing peer state
    pub fn new(
        target_conn_count: usize,
        mesh_interval: Duration,
        cancel: CancellationToken,
        mesh_update_rx: mpsc::Receiver<MeshRequest>,
        phonebook: Arc<Phonebook>,
        connect_fn: C,
        peer_counter: P,
    ) -> Self {
        Self {
            target_conn_count,
            mesh_interval,
            cancel,
            mesh_update_rx,
            phonebook,
            role: RELAY_ROLE,
            connect_fn,
            peer_counter,
            in_progress: Arc::new(Mutex::new(HashSet::new())),
            backoff: ExponentialBackoff::new(
                BACKOFF_MIN,
                BACKOFF_MAX,
                BACKOFF_MULTIPLIER,
                true, // jitter
            ),
            public_address: None,
        }
    }

    /// Set our own public address to exclude from dial targets.
    pub fn with_public_address(mut self, addr: String) -> Self {
        self.public_address = Some(addr);
        self
    }

    /// Set the phonebook role to query (default: `RELAY_ROLE`).
    pub fn with_role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }

    /// Returns a clone of the in-progress address set for external use
    /// (e.g. counting pending connections).
    pub fn in_progress_handle(&self) -> Arc<Mutex<HashSet<String>>> {
        Arc::clone(&self.in_progress)
    }

    /// Run the mesh thread loop. This should be spawned as a tokio task.
    ///
    /// The loop exits when the cancellation token is cancelled.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.mesh_interval);
        // The first tick fires immediately — consume it so we don't
        // double-fire on startup (Go's NewTicker also fires after the first
        // interval, not immediately).
        interval.tick().await;

        loop {
            let request: Option<MeshRequest>;

            tokio::select! {
                _ = self.cancel.cancelled() => {
                    tracing::debug!("mesh thread shutting down");
                    return;
                }
                _ = interval.tick() => {
                    request = None;
                }
                Some(req) = self.mesh_update_rx.recv() => {
                    request = Some(req);
                }
            }

            let num_initiated = self.mesh_cycle().await;

            // Backoff logic — mirrors Go's baseMesher.meshThread
            if num_initiated > 0 {
                self.backoff.reset();
                interval.reset();
            } else {
                let delay = self.backoff.next_delay();
                interval.reset_after(delay);
            }

            // Signal completion to the requester (if any).
            if let Some(req) = request {
                if let Some(done) = req.done {
                    let _ = done.send(());
                }
            }
        }
    }

    /// Execute one mesh cycle: check peer count, dial if needed.
    ///
    /// Returns the number of connection attempts initiated.
    async fn mesh_cycle(&self) -> usize {
        let (num_outgoing, connected_addrs) = self.peer_counter.outgoing_peer_info();
        let num_pending = {
            let guard = self.in_progress.lock().unwrap();
            guard.len()
        };
        let total_outgoing = num_outgoing + num_pending;

        if total_outgoing >= self.target_conn_count {
            tracing::trace!(
                outgoing = num_outgoing,
                pending = num_pending,
                target = self.target_conn_count,
                "mesh: at or above target, no new connections needed"
            );
            return 0;
        }

        let need = self.target_conn_count - total_outgoing;

        // Get more addresses than we need so we can skip duplicates.
        // Mirrors Go's `GetAddresses(targetConnCount + numOutgoingTotal, ...)`.
        let fetch_count = self.target_conn_count + total_outgoing;
        let candidates = self.phonebook.get_addresses(fetch_count, self.role);

        if candidates.is_empty() {
            tracing::debug!("mesh: phonebook returned no addresses");
            return 0;
        }

        let mut initiated = 0;

        for addr in candidates {
            if initiated >= need {
                break;
            }

            // Skip our own address.
            if let Some(ref pub_addr) = self.public_address {
                if addr == *pub_addr {
                    continue;
                }
            }

            // Skip already-connected addresses.
            if connected_addrs.contains(&addr) {
                continue;
            }

            // Try to reserve the address (prevent duplicate dials).
            let reserved = {
                let mut guard = self.in_progress.lock().unwrap();
                guard.insert(addr.clone())
            };
            if !reserved {
                // Already being dialed.
                continue;
            }

            // Spawn the connection attempt. On completion (success or
            // failure), remove from in_progress.
            let in_progress = Arc::clone(&self.in_progress);
            let addr_clone = addr.clone();
            let success = self.connect_fn.try_dial(addr.clone()).await;

            // Remove from in_progress set regardless of outcome.
            {
                let mut guard = in_progress.lock().unwrap();
                guard.remove(&addr_clone);
            }

            if success {
                initiated += 1;
                tracing::debug!(addr = %addr_clone, "mesh: connection initiated");
            } else {
                tracing::debug!(addr = %addr_clone, "mesh: connection attempt failed");
            }
        }

        if initiated > 0 {
            tracing::info!(
                initiated,
                need,
                outgoing = num_outgoing,
                target = self.target_conn_count,
                "mesh: initiated new connections"
            );
        }

        initiated
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Mock PeerCounter
    // -----------------------------------------------------------------------

    /// A test peer counter that returns a configurable outgoing count and
    /// connected address set.
    struct MockPeerCounter {
        outgoing: AtomicUsize,
        connected: Mutex<HashSet<String>>,
    }

    impl MockPeerCounter {
        fn new(outgoing: usize) -> Self {
            Self {
                outgoing: AtomicUsize::new(outgoing),
                connected: Mutex::new(HashSet::new()),
            }
        }

        fn with_connected(outgoing: usize, addrs: Vec<String>) -> Self {
            Self {
                outgoing: AtomicUsize::new(outgoing),
                connected: Mutex::new(addrs.into_iter().collect()),
            }
        }

        #[allow(dead_code)]
        fn set_outgoing(&self, n: usize) {
            self.outgoing.store(n, Ordering::SeqCst);
        }
    }

    impl PeerCounter for MockPeerCounter {
        fn outgoing_peer_info(&self) -> (usize, HashSet<String>) {
            let count = self.outgoing.load(Ordering::SeqCst);
            let addrs = self.connected.lock().unwrap().clone();
            (count, addrs)
        }
    }

    // Also implement for Arc<MockPeerCounter> for shared usage.
    impl PeerCounter for Arc<MockPeerCounter> {
        fn outgoing_peer_info(&self) -> (usize, HashSet<String>) {
            (**self).outgoing_peer_info()
        }
    }

    // -----------------------------------------------------------------------
    // Mock ConnectFn
    // -----------------------------------------------------------------------

    /// A mock connect function that records which addresses were dialed
    /// and always succeeds.
    #[derive(Clone)]
    struct MockConnect {
        dialed: Arc<Mutex<Vec<String>>>,
        should_succeed: Arc<AtomicUsize>, // 1 = succeed, 0 = fail
    }

    impl MockConnect {
        fn new(succeed: bool) -> Self {
            Self {
                dialed: Arc::new(Mutex::new(Vec::new())),
                should_succeed: Arc::new(AtomicUsize::new(if succeed { 1 } else { 0 })),
            }
        }

        fn dialed_addrs(&self) -> Vec<String> {
            self.dialed.lock().unwrap().clone()
        }
    }

    impl ConnectFn for MockConnect {
        fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let dialed = Arc::clone(&self.dialed);
            let succeed = self.should_succeed.load(Ordering::SeqCst) != 0;
            Box::pin(async move {
                dialed.lock().unwrap().push(addr);
                succeed
            })
        }
    }

    // Also implement for Arc<MockConnect> for shared usage.
    impl ConnectFn for Arc<MockConnect> {
        fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            (**self).try_dial(addr)
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a phonebook with relay addresses
    // -----------------------------------------------------------------------

    fn make_phonebook(addrs: &[&str]) -> Arc<Phonebook> {
        let pb = Phonebook::new(10, Duration::from_secs(3600));
        let addr_strings: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();
        pb.replace_peer_list(&addr_strings, "test", RELAY_ROLE);
        Arc::new(pb)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn mesh_thread_construction_defaults() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b", "c", "d"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            DEFAULT_GOSSIP_FANOUT,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect,
            counter,
        );

        assert_eq!(mesh.target_conn_count, 4);
        assert_eq!(mesh.mesh_interval, Duration::from_secs(60));
        assert!(mesh.public_address.is_none());
    }

    #[test]
    fn mesh_thread_with_public_address() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&[]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(4, DEFAULT_MESH_INTERVAL, cancel, rx, pb, connect, counter)
            .with_public_address("my-addr:4161".into());

        assert_eq!(mesh.public_address.as_deref(), Some("my-addr:4161"));
    }

    #[tokio::test]
    async fn mesh_cycle_dials_up_to_target() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b", "c", "d", "e", "f"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        let initiated = mesh.mesh_cycle().await;
        assert_eq!(initiated, 4);
        assert_eq!(connect.dialed_addrs().len(), 4);
    }

    #[tokio::test]
    async fn mesh_cycle_skips_already_connected() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b", "c"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::with_connected(2, vec!["a".into(), "b".into()]);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        let initiated = mesh.mesh_cycle().await;
        // Need 2 more (target=4, outgoing=2), only "c" is available
        assert_eq!(initiated, 1);
        let dialed = connect.dialed_addrs();
        assert_eq!(dialed, vec!["c"]);
    }

    #[tokio::test]
    async fn mesh_cycle_skips_public_address() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["self-addr", "other"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        )
        .with_public_address("self-addr".into());

        let initiated = mesh.mesh_cycle().await;
        // Should have dialed "other" but skipped "self-addr"
        assert_eq!(initiated, 1);
        let dialed = connect.dialed_addrs();
        assert_eq!(dialed, vec!["other"]);
    }

    #[tokio::test]
    async fn mesh_cycle_no_action_at_target() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b", "c", "d"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(4); // already at target

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        let initiated = mesh.mesh_cycle().await;
        assert_eq!(initiated, 0);
        assert!(connect.dialed_addrs().is_empty());
    }

    #[tokio::test]
    async fn mesh_cycle_empty_phonebook() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&[]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        let initiated = mesh.mesh_cycle().await;
        assert_eq!(initiated, 0);
    }

    #[tokio::test]
    async fn mesh_cycle_counts_pending_toward_target() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b", "c", "d", "e"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(2);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        // Pre-populate in_progress with one address to simulate a pending dial.
        {
            let mut guard = mesh.in_progress.lock().unwrap();
            guard.insert("pending-addr".into());
        }

        let initiated = mesh.mesh_cycle().await;
        // Need = 4 - (2 outgoing + 1 pending) = 1
        assert_eq!(initiated, 1);
    }

    #[tokio::test]
    async fn mesh_cycle_duplicate_dial_prevention() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        // Phonebook has only one address.
        let pb = make_phonebook(&["a"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        // Pre-mark "a" as in-progress.
        {
            let mut guard = mesh.in_progress.lock().unwrap();
            guard.insert("a".into());
        }

        let initiated = mesh.mesh_cycle().await;
        // "a" should be skipped because it's already in-progress.
        // But need = 4 - (0 + 1 pending) = 3, and no other candidates.
        assert_eq!(initiated, 0);
        assert!(connect.dialed_addrs().is_empty());
    }

    #[tokio::test]
    async fn mesh_cycle_failed_connect_not_counted() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b"]);
        let connect = MockConnect::new(false); // all connections fail
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            DEFAULT_MESH_INTERVAL,
            cancel,
            rx,
            pb,
            connect.clone(),
            counter,
        );

        let initiated = mesh.mesh_cycle().await;
        // Both addresses were attempted but failed.
        assert_eq!(initiated, 0);
        assert_eq!(connect.dialed_addrs().len(), 2);
    }

    #[tokio::test]
    async fn backoff_engages_when_no_peers_available() {
        // Verify that the backoff produces increasing delays when
        // mesh_cycle returns 0.
        let mut backoff =
            ExponentialBackoff::new(BACKOFF_MIN, BACKOFF_MAX, BACKOFF_MULTIPLIER, false);

        let d1 = backoff.next_delay();
        let d2 = backoff.next_delay();
        let d3 = backoff.next_delay();

        // Without jitter, delays should strictly increase.
        assert!(d2 > d1, "d2={d2:?} should be > d1={d1:?}");
        assert!(d3 > d2, "d3={d3:?} should be > d2={d2:?}");
        assert!(
            d3 <= BACKOFF_MAX,
            "d3={d3:?} should be <= max={BACKOFF_MAX:?}"
        );
    }

    #[tokio::test]
    async fn backoff_resets_on_success() {
        let mut backoff =
            ExponentialBackoff::new(BACKOFF_MIN, BACKOFF_MAX, BACKOFF_MULTIPLIER, false);

        // Advance backoff a few times.
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();

        // Reset.
        backoff.reset();

        // Next delay should be back to minimum.
        let d = backoff.next_delay();
        assert_eq!(d, BACKOFF_MIN);
    }

    #[tokio::test]
    async fn mesh_run_responds_to_cancellation() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&[]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(
            4,
            Duration::from_secs(3600), // long interval so we rely on cancellation
            cancel.clone(),
            rx,
            pb,
            connect,
            counter,
        );

        let handle = tokio::spawn(mesh.run());

        // Cancel immediately.
        cancel.cancel();

        // The task should complete promptly.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "mesh thread should exit on cancellation");
    }

    #[tokio::test]
    async fn mesh_run_responds_to_on_demand_request() {
        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel(4);
        let pb = make_phonebook(&["a", "b", "c", "d"]);
        let connect = Arc::new(MockConnect::new(true));
        let counter = Arc::new(MockPeerCounter::new(0));

        let mesh = MeshThread::new(
            2,
            Duration::from_secs(3600), // long interval
            cancel.clone(),
            rx,
            pb,
            connect.clone(),
            counter.clone(),
        );

        let handle = tokio::spawn(mesh.run());

        // Send an on-demand request and wait for completion.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tx.send(MeshRequest {
            done: Some(done_tx),
        })
        .await
        .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), done_rx).await;
        assert!(result.is_ok(), "on-demand request should complete");

        // Should have dialed 2 addresses (target=2, outgoing=0).
        let dialed = connect.dialed_addrs();
        assert_eq!(dialed.len(), 2);

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn in_progress_cleaned_up_after_dial() {
        let cancel = CancellationToken::new();
        let (_tx, rx) = mpsc::channel(1);
        let pb = make_phonebook(&["a", "b"]);
        let connect = MockConnect::new(true);
        let counter = MockPeerCounter::new(0);

        let mesh = MeshThread::new(4, DEFAULT_MESH_INTERVAL, cancel, rx, pb, connect, counter);
        let in_progress = mesh.in_progress_handle();

        let _ = mesh.mesh_cycle().await;

        // After mesh_cycle completes, in_progress should be empty
        // (addresses are removed after dial completes).
        let guard = in_progress.lock().unwrap();
        assert!(guard.is_empty(), "in_progress should be empty after cycle");
    }
}
