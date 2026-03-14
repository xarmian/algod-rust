//! Integration tests for MeshThread + WebsocketNetwork working together.
//!
//! These tests verify that the MeshThread correctly manages connection targets,
//! coordinates with the phonebook, and responds to on-demand requests and
//! cancellation — all using the WebsocketNetwork's PeerCounter / ConnectFn
//! abstractions.
//!
//! No real network connections are made; these tests use mock implementations
//! to validate control flow and coordination.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_network::mesh::{ConnectFn, MeshRequest, MeshThread, PeerCounter};
use algo_network::peer_role::RELAY_ROLE;
use algo_network::phonebook::Phonebook;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::GossipNode;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Mock ConnectFn that tracks dials
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TrackingConnect {
    dialed: Arc<Mutex<Vec<String>>>,
    succeed: bool,
}

impl TrackingConnect {
    fn new(succeed: bool) -> Self {
        Self {
            dialed: Arc::new(Mutex::new(Vec::new())),
            succeed,
        }
    }

    fn dialed(&self) -> Vec<String> {
        self.dialed.lock().unwrap().clone()
    }
}

impl ConnectFn for TrackingConnect {
    fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let dialed = Arc::clone(&self.dialed);
        let succeed = self.succeed;
        Box::pin(async move {
            dialed.lock().unwrap().push(addr);
            succeed
        })
    }
}

// ---------------------------------------------------------------------------
// Mock PeerCounter
// ---------------------------------------------------------------------------

/// Shared state for the mock peer counter.
struct MockCounterInner {
    outgoing: AtomicUsize,
    connected: Mutex<HashSet<String>>,
}

/// A clonable peer counter that wraps shared state.
///
/// This newtype satisfies the orphan rule (we own the type) and lets us
/// share mutable state between the mesh thread and test assertions.
#[derive(Clone)]
struct MockCounter(Arc<MockCounterInner>);

impl MockCounter {
    fn new(outgoing: usize) -> Self {
        Self(Arc::new(MockCounterInner {
            outgoing: AtomicUsize::new(outgoing),
            connected: Mutex::new(HashSet::new()),
        }))
    }

    fn set_outgoing(&self, n: usize) {
        self.0.outgoing.store(n, Ordering::SeqCst);
    }
}

impl PeerCounter for MockCounter {
    fn outgoing_peer_info(&self) -> (usize, HashSet<String>) {
        let count = self.0.outgoing.load(Ordering::SeqCst);
        let addrs = self.0.connected.lock().unwrap().clone();
        (count, addrs)
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_phonebook(addrs: &[&str]) -> Arc<Phonebook> {
    let pb = Phonebook::new(10, Duration::from_secs(3600));
    let strings: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();
    pb.replace_peer_list(&strings, "test", RELAY_ROLE);
    Arc::new(pb)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// MeshThread dials up to GossipFanout targets from the phonebook, then stops.
#[tokio::test]
async fn mesh_thread_dials_to_fanout_target() {
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel(4);
    let pb = make_phonebook(&["r1:4161", "r2:4161", "r3:4161", "r4:4161", "r5:4161"]);
    let connect = TrackingConnect::new(true);
    let counter = MockCounter::new(0);

    let mesh = MeshThread::new(
        4, // GossipFanout = 4
        Duration::from_secs(3600),
        cancel.clone(),
        rx,
        pb,
        connect.clone(),
        counter,
    );

    let handle = tokio::spawn(mesh.run());

    // Send an on-demand request and wait for completion.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tx.send(MeshRequest {
        done: Some(done_tx),
    })
    .await
    .unwrap();

    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("mesh cycle should complete")
        .expect("done channel should not be dropped");

    let dialed = connect.dialed();
    assert_eq!(
        dialed.len(),
        4,
        "should dial exactly GossipFanout addresses"
    );

    cancel.cancel();
    let _ = handle.await;
}

/// MeshThread skips dialing when already at target.
#[tokio::test]
async fn mesh_thread_no_action_when_at_target() {
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel(4);
    let pb = make_phonebook(&["r1:4161", "r2:4161"]);
    let connect = TrackingConnect::new(true);
    let counter = MockCounter::new(4); // already at fanout

    let mesh = MeshThread::new(
        4,
        Duration::from_secs(3600),
        cancel.clone(),
        rx,
        pb,
        connect.clone(),
        counter,
    );

    let handle = tokio::spawn(mesh.run());

    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tx.send(MeshRequest {
        done: Some(done_tx),
    })
    .await
    .unwrap();

    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("mesh cycle should complete")
        .expect("done channel should not be dropped");

    assert!(
        connect.dialed().is_empty(),
        "should not dial when already at target"
    );

    cancel.cancel();
    let _ = handle.await;
}

/// WebsocketNetwork can create, query peers, broadcast, and stop without panicking.
#[tokio::test]
async fn ws_network_lifecycle() {
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    phonebook.replace_peer_list(
        &["relay1:4161".to_string(), "relay2:4161".to_string()],
        "test",
        RELAY_ROLE,
    );

    let config = WebsocketNetworkConfig {
        gossip_fanout: 4,
        genesis_id: "testnet-v1.0".to_string(),
        network_id: "testnet".to_string(),
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // Verify initial state.
    assert_eq!(net.peer_count().await, 0);
    assert_eq!(net.get_genesis_id(), "testnet-v1.0");

    // Verify phonebook peers are accessible via get_peers.
    let pb_peers = net.get_peers(&[algo_network::gossip_node::PeerOption::PeersPhonebookRelays]);
    assert_eq!(pb_peers.len(), 2);

    // Broadcast on empty network should succeed.
    let result = net
        .broadcast(algo_network::Tag::Transaction, vec![1, 2, 3], false, None)
        .await;
    assert!(result.is_ok());

    // on_network_advance should not panic.
    net.on_network_advance();

    // Stop should complete cleanly.
    net.stop().await;
}

/// WebsocketNetwork start_arc spawns background tasks that respond to cancellation.
#[tokio::test]
async fn ws_network_start_arc_and_stop() {
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let config = WebsocketNetworkConfig {
        genesis_id: "test".to_string(),
        network_id: "test".to_string(),
        // Use a very long mesh interval so the mesh task relies on cancellation.
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // start_arc should succeed (no peers to connect to, but tasks are spawned).
    net.start_arc()
        .await
        .expect("start_arc should succeed on empty phonebook");

    // Give background tasks a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stop should cancel all background tasks.
    let stop_result = tokio::time::timeout(Duration::from_secs(5), net.stop()).await;
    assert!(stop_result.is_ok(), "stop should complete within 5 seconds");
}

/// MeshThread responds to multiple on-demand requests sequentially.
#[tokio::test]
async fn mesh_thread_multiple_on_demand_requests() {
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel(8);
    let pb = make_phonebook(&["a:1", "b:2", "c:3", "d:4"]);
    let connect = TrackingConnect::new(true);
    let counter = MockCounter::new(0);

    let mesh = MeshThread::new(
        2, // lower fanout for faster test
        Duration::from_secs(3600),
        cancel.clone(),
        rx,
        pb.clone(),
        connect.clone(),
        counter.clone(),
    );

    let handle = tokio::spawn(mesh.run());

    // First request: should dial 2 peers.
    let (done1_tx, done1_rx) = tokio::sync::oneshot::channel();
    tx.send(MeshRequest {
        done: Some(done1_tx),
    })
    .await
    .unwrap();
    done1_rx.await.unwrap();

    let first_dialed = connect.dialed().len();
    assert_eq!(first_dialed, 2, "first cycle should dial 2 peers");

    // Simulate that those 2 peers are now connected.
    counter.set_outgoing(2);

    // Second request: should dial 0 (already at target).
    let (done2_tx, done2_rx) = tokio::sync::oneshot::channel();
    tx.send(MeshRequest {
        done: Some(done2_tx),
    })
    .await
    .unwrap();
    done2_rx.await.unwrap();

    let total_dialed = connect.dialed().len();
    assert_eq!(
        total_dialed, first_dialed,
        "second cycle should not dial more (at target)"
    );

    cancel.cancel();
    let _ = handle.await;
}
