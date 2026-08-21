//! In-process two-node tx-propagation integration test.
//!
//! This is the rescoped PLAN-33 / TASK-73 acceptance gate. It spins up
//! **two `WebsocketNetwork` instances in a single test process** on
//! loopback, wires each with its own `TransactionPool` + `TxTagHandler` +
//! `LocalTxBroadcaster`, submits a txn to node A's `LocalTxBroadcaster`
//! directly (simulating the REST path), and asserts that it appears in
//! node B's pool via the gossip TX tag.
//!
//! A true two-binary REST-driven E2E test requires production
//! `NodeInterface` wiring that does not yet exist; tracked under PLAN-74.
//! The in-process variant proves the complete gossip layer — the
//! chain `LocalTxBroadcaster → WebsocketNetwork.broadcast →
//! TxTagHandler → pool.remember` — which is what PLAN-33 is about.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_codec::compute_txn_id;
use algo_error::AlgoError;
use algo_network::handler::TaggedMessageHandler;
use algo_network::local_tx_broadcast::{LocalTxBroadcaster, PoolIngestAdapter};
use algo_network::phonebook::Phonebook;
use algo_network::tag::Tag;
use algo_network::tx_syncer::SeenTxCache;
use algo_network::tx_tag_handler::TxTagHandler;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::GossipNode;
use algo_pool::traits::{BlockEvaluator, PoolLedger};
use algo_pool::{PoolConfig, TransactionPool};
use algo_types::{Address, Block, BlockHeader, ConsensusParams, Digest, Round, SignedTransaction};

// ---------------------------------------------------------------------------
// Minimal stubs (replicated from algo-pool's private test helpers)
// ---------------------------------------------------------------------------

/// Minimal stub ledger. Claims to be at `Round(1)` and hands out
/// `StubEvaluator`s anchored at `Round(2)` so `pool.remember` passes
/// the wait-for-OnNewBlock gate.
///
/// `confirmed` models the ledger's committed-transaction history (what a
/// real `PoolLedgerAdapter` derives from the txtail, per issue #456) so
/// tests can simulate a transaction confirming and clearing the pending
/// pool, then assert a resubmission of the identical bytes is rejected.
struct StubLedger {
    round: Round,
    confirmed: std::sync::Mutex<HashSet<Digest>>,
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
        }))
    }
    fn contains_confirmed_txid(&self, txid: Digest) -> bool {
        self.confirmed
            .lock()
            .map(|c| c.contains(&txid))
            .unwrap_or(false)
    }
}

/// Minimal stub evaluator that accepts every transaction group.
struct StubEvaluator {
    round: Round,
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
        Ok(())
    }
    fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
        Ok(Block::default())
    }
    fn reset_txn_bytes(&mut self) {}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=info,tx_propagation_inproc=debug")
        .with_test_writer()
        .try_init();
}

/// Build a pool seeded with a stub evaluator so `remember` can proceed.
/// Returns the pool plus the concrete `StubLedger` (via its `Arc`, cloned
/// before the trait-object upcast) so tests can mark txids confirmed.
fn make_pool() -> (Arc<TransactionPool>, Arc<StubLedger>) {
    let stub = Arc::new(StubLedger {
        round: Round(1),
        confirmed: std::sync::Mutex::new(HashSet::new()),
    });
    let ledger: Arc<dyn PoolLedger> = stub.clone();
    let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
    // Install the evaluator via the public `on_new_block` path — the
    // pool's private `mu` field is not reachable from an integration
    // test crate.
    pool.on_new_block(&Block::default(), &HashSet::new());
    (pool, stub)
}

/// Node state: all the pieces needed to submit locally and receive over
/// gossip on a single loopback node.
struct InProcNode {
    pool: Arc<TransactionPool>,
    ledger: Arc<StubLedger>,
    broadcaster: Arc<LocalTxBroadcaster>,
    /// Retained for the lifetime of the test — dropping the shared seen
    /// cache would break the TxTagHandler's dedup.
    _seen: Arc<SeenTxCache>,
}

/// Build one in-process node: network, pool, shared seen cache,
/// registered TX-tag handler, and LocalTxBroadcaster.
fn build_node(genesis: &str, relay: bool) -> Arc<WebsocketNetwork> {
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let config = WebsocketNetworkConfig {
        genesis_id: genesis.to_string(),
        network_id: "test".to_string(),
        net_address: if relay {
            Some("127.0.0.1:0".to_string())
        } else {
            None
        },
        relay_messages: relay,
        gossip_fanout: 2,
        // Long mesh interval so the mesh thread doesn't fire during
        // the test; we drive connectivity explicitly.
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    Arc::new(WebsocketNetwork::new(config, phonebook))
}

/// Wire pool + TxTagHandler + LocalTxBroadcaster onto a network that
/// has already been constructed (but not started).
fn wire_node(net: &Arc<WebsocketNetwork>) -> InProcNode {
    let (pool, ledger) = make_pool();
    let seen = Arc::new(SeenTxCache::new(1024));

    net.multiplexer()
        .register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(TxTagHandler::new(pool.clone(), seen.clone())),
        }]);

    let broadcaster = Arc::new(LocalTxBroadcaster::new(
        Arc::new(PoolIngestAdapter::new(pool.clone())),
        net.clone() as Arc<dyn GossipNode>,
        seen.clone(),
    ));

    InProcNode {
        pool,
        ledger,
        broadcaster,
        _seen: seen,
    }
}

/// Seed `b`'s phonebook with `a`'s bound address so B will dial A.
async fn connect_to(b: &Arc<WebsocketNetwork>, a_addr: &str) {
    use algo_network::peer_role::RELAY_ROLE;
    b.phonebook()
        .replace_peer_list(&[a_addr.to_string()], "test", RELAY_ROLE);
}

/// Build a signed transaction that will pass the pool's fee check.
fn make_tx(note: u8) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = algo_types::TxnType::Pay;
    stx.txn.fee = 1_000_000; // well above MinTxnFee (1_000)
    stx.txn.first_valid = Round(1);
    stx.txn.last_valid = Round(1_000);
    // Unique note per test txn so txids differ.
    stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
    stx
}

/// Poll `pool.pending_tx_ids` until `txid` appears or `deadline`
/// elapses.
async fn wait_for_txid(pool: &TransactionPool, txid: &Digest, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if pool.pending_tx_ids().contains(txid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Local submission on node A → gossip TX tag → inbound handler on
/// node B → node B's pool sees the txid.
#[tokio::test]
async fn txn_propagates_from_a_to_b_via_gossip() {
    init_tracing();

    // Node A acts as the relay so B can dial it.
    let net_a = build_node("test-v1.0", true);
    let node_a = wire_node(&net_a);
    net_a.start_arc().await.expect("node A start");

    // Read A's bound address before starting B.
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");
    assert!(!a_addr.is_empty());

    // Node B dials A. Not a relay — just a participant.
    let net_b = build_node("test-v1.0", false);
    let node_b = wire_node(&net_b);
    connect_to(&net_b, &a_addr).await;
    net_b.start_arc().await.expect("node B start");

    // Trigger B → A connection establishment. `start_arc` does not
    // eagerly dial with a 1-hour mesh interval, so ask for outgoing
    // connections explicitly.
    net_b.request_connect_outgoing(false).await;

    // Wait for A to see one incoming peer.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if net_a.peer_count().await >= 1 && net_b.peer_count().await >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        net_a.peer_count().await >= 1,
        "node A should have at least one peer (B)"
    );
    assert!(
        net_b.peer_count().await >= 1,
        "node B should have at least one peer (A)"
    );

    // Submit a txn to node A's LocalTxBroadcaster. This is the same
    // path the REST `POST /v2/transactions` handler will follow once
    // PLAN-74 wires the NodeInterface.
    let tx = make_tx(0x42);
    let txid = compute_txn_id(&tx.txn);
    let returned = node_a
        .broadcaster
        .submit_group(vec![tx])
        .await
        .expect("local submit should succeed");
    assert_eq!(returned, txid, "submit_group should return first txid");

    // Node A's pool has it immediately.
    assert!(
        node_a.pool.pending_tx_ids().contains(&txid),
        "node A's pool should contain the locally-submitted txid",
    );

    // Node B's pool should receive it via gossip within 5 s.
    let appeared = wait_for_txid(&node_b.pool, &txid, Duration::from_secs(5)).await;
    assert!(
        appeared,
        "node B's pool did not see the txid within 5 s — pending: {:?}",
        node_b.pool.pending_tx_ids(),
    );

    // Clean shutdown.
    net_b.stop().await;
    net_a.stop().await;
}

/// Issue #456: `LocalTxBroadcaster::submit_group` (the non-dev-mode
/// relay/participate broadcast path) must reject resubmission of an
/// already-confirmed transaction, mirroring go's
/// `ledgercore.TransactionInLedgerError`. Confirmation is simulated by
/// (1) telling the pool the block committed via `on_new_block` — clearing
/// the pending-pool duplicate check's only line of defense — and (2)
/// marking the txid confirmed on the `StubLedger`, exactly as a real
/// `PoolLedgerAdapter` would report via its txtail scan (see
/// `algo_pool::traits::PoolLedger::contains_confirmed_txid`).
#[tokio::test]
async fn resubmitting_a_confirmed_txn_is_rejected() {
    init_tracing();

    let net_a = build_node("test-v1.0", true);
    let node_a = wire_node(&net_a);
    net_a.start_arc().await.expect("node A start");

    let tx = make_tx(0x99);
    let txid = compute_txn_id(&tx.txn);

    // First submission succeeds and lands in the pending pool.
    node_a
        .broadcaster
        .submit_group(vec![tx.clone()])
        .await
        .expect("first submission should succeed");
    assert!(node_a.pool.pending_tx_ids().contains(&txid));

    // Simulate the transaction confirming into a block: the pool drops it
    // from pending (on_new_block), and the ledger now reports it as
    // confirmed (what a real txtail scan would find).
    let mut committed = HashSet::new();
    committed.insert(txid);
    // `make_pool`'s initial `on_new_block` advances the stub evaluator to
    // round 2 (`StubLedger { round: Round(1) }`'s `start_evaluator` hands
    // out `round.next()`); `on_new_block` only recomputes the evaluator
    // (which is what clears committed txids from pending) when the new
    // block's round is `>= eval.round()`, so this simulated "confirmation"
    // block must itself be at round 2 or later.
    let confirmed_block = Block {
        round: Round(2),
        ..Default::default()
    };
    node_a.pool.on_new_block(&confirmed_block, &committed);
    node_a
        .ledger
        .confirmed
        .lock()
        .expect("stub ledger lock")
        .insert(txid);
    assert!(
        !node_a.pool.pending_tx_ids().contains(&txid),
        "txid should have cleared the pending pool after on_new_block"
    );

    // Resubmitting the identical signed bytes must now be rejected, not
    // silently re-accepted and re-broadcast.
    let result = node_a.broadcaster.submit_group(vec![tx]).await;
    assert!(
        result.is_err(),
        "resubmitting an already-confirmed txn should be rejected, got {result:?}"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("already in ledger"),
        "error should surface go's ledgercore.TransactionInLedgerError-style message, got: {err}"
    );

    net_a.stop().await;
}
