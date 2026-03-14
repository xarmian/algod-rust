//! GossipBlockSource: a [`BlockSource`] backed by WebSocket peer unicast.
//!
//! Implements the block-fetch side of Algorand's catchup protocol, requesting
//! blocks from peers via the `UniEnsBlockReq` (`UE`) tagged message flow.
//!
//! This is the Rust equivalent of Go's `universalBlockFetcher` from
//! `catchup/universalFetcher.go`, restricted to the WS unicast path.
//! HTTP-based block fetching can be layered on top via an optional fallback.
//!
//! ## Protocol summary
//!
//! 1. Build request topics with [`make_block_request_topics`] (round as uvarint).
//! 2. Send via [`UnicastPeer::request`] with tag `UniEnsBlockReq`.
//! 3. Parse the response topics with [`parse_block_response`] to get raw
//!    `blockData` + `certData` bytes.
//! 4. Decode each payload from msgpack into `Block` and cert `Value`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use algo_codec::decode_block;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::{debug, warn};

use algo_network::block_fetcher::{make_block_request_topics, parse_block_response};
use algo_network::gossip_node::UnicastPeer;
use algo_network::tag::Tag;

use crate::{BlockSource, NodeStatus};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`GossipBlockSource`].
#[derive(Debug, Clone)]
pub struct GossipBlockSourceConfig {
    /// Timeout for a single WS block request (default: 4s).
    ///
    /// This value should be passed to [`WsPeerConfig::request_timeout`] when
    /// constructing peers that will be used with this source.  The peer's own
    /// `request()` method applies the timeout internally and properly cleans
    /// up `RequestTracker` state on expiry — avoiding the tracker leak that
    /// occurs when an outer `tokio::time::timeout` drops the request future.
    pub request_timeout: Duration,

    /// Maximum number of peers to try per round before giving up (default: 5).
    pub max_peer_attempts: usize,

    /// Backoff between retry attempts when polling in `wait_for_round`
    /// (default: 500ms).
    pub poll_backoff: Duration,

    /// Maximum total wait time for `wait_for_round` (default: 5 minutes).
    pub max_wait: Duration,
}

impl Default for GossipBlockSourceConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(4),
            max_peer_attempts: 5,
            poll_backoff: Duration::from_millis(500),
            max_wait: Duration::from_secs(300),
        }
    }
}

// ---------------------------------------------------------------------------
// GossipBlockSource
// ---------------------------------------------------------------------------

/// A [`BlockSource`] that fetches blocks from peers via WebSocket unicast.
///
/// Peers are tried in round-robin order. On failure, the next peer is
/// attempted up to [`GossipBlockSourceConfig::max_peer_attempts`] times.
pub struct GossipBlockSource {
    /// The set of unicast peers available for block requests.
    peers: Vec<Arc<dyn UnicastPeer>>,

    /// Round-robin index into `peers` (wraps around).
    next_peer: AtomicU64,

    /// The last round successfully fetched (used for `get_status`).
    last_fetched_round: AtomicU64,

    /// Configuration knobs.
    config: GossipBlockSourceConfig,
}

impl GossipBlockSource {
    /// Create a new `GossipBlockSource` with the given peers and default config.
    pub fn new(peers: Vec<Arc<dyn UnicastPeer>>) -> Self {
        Self::with_config(peers, GossipBlockSourceConfig::default())
    }

    /// Create a new `GossipBlockSource` with the given peers and custom config.
    pub fn with_config(peers: Vec<Arc<dyn UnicastPeer>>, config: GossipBlockSourceConfig) -> Self {
        Self {
            peers,
            next_peer: AtomicU64::new(0),
            last_fetched_round: AtomicU64::new(0),
            config,
        }
    }

    /// Replace the peer set (e.g. after a phonebook refresh).
    pub fn set_peers(&mut self, peers: Vec<Arc<dyn UnicastPeer>>) {
        self.peers = peers;
        self.next_peer.store(0, Ordering::SeqCst);
    }

    /// Returns the number of peers currently configured.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Select the next peer in round-robin order.
    ///
    /// Returns `None` if there are no peers.
    fn select_peer(&self) -> Option<Arc<dyn UnicastPeer>> {
        if self.peers.is_empty() {
            return None;
        }
        let idx = self.next_peer.fetch_add(1, Ordering::Relaxed) as usize % self.peers.len();
        Some(Arc::clone(&self.peers[idx]))
    }

    /// Attempt to fetch a block from a single peer via WS unicast.
    ///
    /// Mirrors Go's `wsFetcherClient.requestBlock()`.
    ///
    /// Timeout handling is delegated to the peer's own `request()` method,
    /// which uses the peer's configured `request_timeout` (set via
    /// [`WsPeerConfig::request_timeout`]) and properly cleans up its
    /// `RequestTracker` entry on expiry.  Callers should configure peers
    /// with the desired timeout (e.g. [`GossipBlockSourceConfig::request_timeout`])
    /// rather than wrapping with an outer `tokio::time::timeout`, which
    /// would leak tracker entries.
    async fn fetch_from_peer(&self, peer: &dyn UnicastPeer, round: Round) -> Result<BlockResponse> {
        let topics = make_block_request_topics(round.0);

        // Send the request and await the response. The peer's own timeout
        // (configurable via WsPeerConfig::request_timeout) handles cleanup
        // of pending tracker state.
        let response_topics = peer
            .request(Tag::UniEnsBlockReq, topics)
            .await
            .map_err(|e| AlgoError::Network {
                message: format!(
                    "WS block request failed for round {} from peer {}: {}",
                    round,
                    peer.get_address(),
                    e
                ),
            })?;

        // Parse the response topics to get raw block+cert bytes.
        let data = parse_block_response(&response_topics).map_err(|e| AlgoError::Network {
            message: format!(
                "failed to parse block response for round {} from peer {}: {}",
                round,
                peer.get_address(),
                e
            ),
        })?;

        // Decode block+cert from their raw msgpack bytes.
        decode_block_cert(&data.block_data, &data.cert_data)
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Decode separate block and certificate msgpack blobs into a [`BlockResponse`].
///
/// In the WS protocol the block and cert arrive as distinct topic values
/// (unlike the REST API which wraps them in a `{block: ..., cert: ...}`
/// envelope). This function decodes each independently and assembles the
/// response struct.
pub fn decode_block_cert(block_data: &[u8], cert_data: &[u8]) -> Result<BlockResponse> {
    // Decode the block.
    let block = decode_block(block_data)?;

    // Decode the certificate as an opaque msgpack Value (same representation
    // used by BlockResponse::cert from the REST path).
    let cert: Option<rmpv::Value> = if cert_data.is_empty() {
        None
    } else {
        let val = rmpv::decode::read_value(&mut &cert_data[..]).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "failed to decode certificate from msgpack".into(),
        })?;
        Some(val)
    };

    Ok(BlockResponse { block, cert })
}

// ---------------------------------------------------------------------------
// BlockSource implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl BlockSource for GossipBlockSource {
    async fn get_block_raw(&self, round: Round) -> Result<Vec<u8>> {
        // For the gossip path we don't have a single "raw" blob in the REST
        // envelope format. Instead, fetch the block and re-encode it. This is
        // less efficient than the REST path but satisfies the trait contract.
        let block_response = self.get_block(round).await?;
        rmp_serde::to_vec_named(&block_response).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: format!("re-encoding block response for round {round}"),
        })
    }

    async fn get_block(&self, round: Round) -> Result<BlockResponse> {
        if self.peers.is_empty() {
            return Err(AlgoError::Network {
                message: "no peers available for block fetch".into(),
            });
        }

        let attempts = self.config.max_peer_attempts.min(self.peers.len());
        let mut last_err = None;

        for attempt in 0..attempts {
            let peer = match self.select_peer() {
                Some(p) => p,
                None => {
                    return Err(AlgoError::Network {
                        message: "no peers available for block fetch".into(),
                    })
                }
            };

            debug!(
                round = %round,
                peer = peer.get_address(),
                attempt = attempt + 1,
                max_attempts = attempts,
                "requesting block via WS unicast"
            );

            match self.fetch_from_peer(peer.as_ref(), round).await {
                Ok(response) => {
                    // Update our tracked last-fetched round.
                    self.last_fetched_round
                        .fetch_max(round.0, Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => {
                    warn!(
                        round = %round,
                        peer = peer.get_address(),
                        attempt = attempt + 1,
                        error = %e,
                        "WS block fetch failed, trying next peer"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AlgoError::Network {
            message: format!("all {attempts} peers failed for round {round}"),
        }))
    }

    async fn get_status(&self) -> Result<NodeStatus> {
        // For gossip-only mode we don't have a REST status endpoint.
        // Return a synthetic status based on the last successfully fetched round.
        let last_round = self.last_fetched_round.load(Ordering::Relaxed);
        Ok(NodeStatus {
            last_round,
            time_since_last_round: 0,
            catchup_time: 0,
            last_version: String::new(),
            next_version: String::new(),
            next_version_round: 0,
            next_version_supported: true,
            stopped_at_unsupported_round: false,
            last_catchpoint: None,
        })
    }

    async fn wait_for_round(&self, round: Round) -> Result<NodeStatus> {
        // Poll with backoff until we can successfully fetch the target round.
        let deadline = tokio::time::Instant::now() + self.config.max_wait;

        loop {
            // Check if the round is already known from prior fetches.
            let current = self.last_fetched_round.load(Ordering::Relaxed);
            if current >= round.0 {
                return self.get_status().await;
            }

            // Try fetching the block at `round`.
            match self.get_block(round).await {
                Ok(_) => return self.get_status().await,
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(AlgoError::Network {
                            message: format!(
                                "timed out waiting for round {} after {:?}: {}",
                                round, self.config.max_wait, e
                            ),
                        });
                    }
                    debug!(
                        round = %round,
                        error = %e,
                        backoff_ms = self.config.poll_backoff.as_millis() as u64,
                        "round not yet available, retrying"
                    );
                    tokio::time::sleep(self.config.poll_backoff).await;
                }
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
    use algo_network::errors::PeerError;
    use algo_network::topics::{Topic, Topics, BLOCK_DATA_KEY, CERT_DATA_KEY, ERROR_KEY};
    use std::sync::Mutex;
    use std::time::Duration;

    // -- Mock UnicastPeer ---------------------------------------------------

    /// A configurable mock peer for testing.
    struct MockPeer {
        addr: String,
        /// Responses to serve, keyed by round. Each entry is consumed on use.
        responses: Mutex<std::collections::HashMap<u64, MockResponse>>,
    }

    enum MockResponse {
        /// Successful response with block + cert topic data.
        Success {
            block_data: Vec<u8>,
            cert_data: Vec<u8>,
        },
        /// Peer returns an error topic.
        ServiceError(String),
        /// Peer request itself fails (e.g. connection closed).
        RequestError(PeerError),
    }

    impl MockPeer {
        fn new(addr: &str) -> Self {
            Self {
                addr: addr.to_string(),
                responses: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn with_success(self, round: u64, block_data: Vec<u8>, cert_data: Vec<u8>) -> Self {
            self.responses.lock().unwrap().insert(
                round,
                MockResponse::Success {
                    block_data,
                    cert_data,
                },
            );
            self
        }

        fn with_service_error(self, round: u64, msg: &str) -> Self {
            self.responses
                .lock()
                .unwrap()
                .insert(round, MockResponse::ServiceError(msg.to_string()));
            self
        }

        fn with_request_error(self, round: u64, err: PeerError) -> Self {
            self.responses
                .lock()
                .unwrap()
                .insert(round, MockResponse::RequestError(err));
            self
        }
    }

    impl algo_network::gossip_node::Peer for MockPeer {
        fn get_address(&self) -> &str {
            &self.addr
        }

        fn get_connection_latency(&self) -> Duration {
            Duration::ZERO
        }

        fn routing_addr(&self) -> &[u8] {
            &[]
        }
    }

    #[async_trait]
    impl UnicastPeer for MockPeer {
        async fn request(
            &self,
            _tag: Tag,
            topics: Topics,
        ) -> std::result::Result<Topics, PeerError> {
            // Extract the round from the request topics.
            let round_bytes = topics
                .get_value("roundKey")
                .expect("request missing roundKey");
            let round =
                algo_network::block_fetcher::decode_round_from_uvarint(round_bytes).unwrap();

            let mut map = self.responses.lock().unwrap();
            let response = map.remove(&round);
            drop(map);

            match response {
                Some(MockResponse::Success {
                    block_data,
                    cert_data,
                }) => {
                    let resp = Topics::from_vec(vec![
                        Topic::new(BLOCK_DATA_KEY, block_data),
                        Topic::new(CERT_DATA_KEY, cert_data),
                    ]);
                    Ok(resp)
                }
                Some(MockResponse::ServiceError(msg)) => {
                    let resp = Topics::from_vec(vec![Topic::new(ERROR_KEY, msg.into_bytes())]);
                    Ok(resp)
                }
                Some(MockResponse::RequestError(e)) => Err(e),
                None => {
                    // Default: return a service error for unknown rounds.
                    let resp = Topics::from_vec(vec![Topic::new(
                        ERROR_KEY,
                        b"requested block is not available".to_vec(),
                    )]);
                    Ok(resp)
                }
            }
        }

        async fn respond(
            &self,
            _request_hash: u64,
            _topics: Topics,
        ) -> std::result::Result<(), PeerError> {
            Ok(())
        }
    }

    // -- Helper: create a minimal valid block msgpack -----------------------

    /// Create a minimal Block encoded as msgpack with the given round number.
    fn make_block_msgpack(round: u64) -> Vec<u8> {
        let json = serde_json::json!({
            "rnd": round
        });
        // Parse JSON into a Block then encode as msgpack.
        let block: algo_types::Block = serde_json::from_value(json).expect("mock block");
        rmp_serde::to_vec_named(&block).expect("msgpack encode")
    }

    /// Create a minimal Certificate encoded as msgpack.
    fn make_cert_msgpack() -> Vec<u8> {
        // Empty map is a valid default certificate.
        let cert = algo_network::Certificate::default();
        rmp_serde::to_vec_named(&cert).expect("msgpack encode cert")
    }

    // -- decode_block_cert tests -------------------------------------------

    #[test]
    fn decode_block_cert_success() {
        let block_bytes = make_block_msgpack(42);
        let cert_bytes = make_cert_msgpack();

        let resp = decode_block_cert(&block_bytes, &cert_bytes).unwrap();
        assert_eq!(resp.block.round.0, 42);
        assert!(resp.cert.is_some());
    }

    #[test]
    fn decode_block_cert_empty_cert() {
        let block_bytes = make_block_msgpack(10);
        let cert_bytes = Vec::new();

        let resp = decode_block_cert(&block_bytes, &cert_bytes).unwrap();
        assert_eq!(resp.block.round.0, 10);
        assert!(resp.cert.is_none());
    }

    #[test]
    fn decode_block_cert_invalid_block() {
        let result = decode_block_cert(b"not-valid-msgpack", b"");
        assert!(result.is_err());
    }

    // -- GossipBlockSource tests -------------------------------------------

    #[tokio::test]
    async fn no_peers_returns_error() {
        let src = GossipBlockSource::new(vec![]);
        let result = src.get_block(Round(1)).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no peers"),
            "expected 'no peers' error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn successful_single_peer_fetch() {
        let block_bytes = make_block_msgpack(5);
        let cert_bytes = make_cert_msgpack();

        let peer =
            Arc::new(MockPeer::new("10.0.0.1:4160").with_success(5, block_bytes, cert_bytes));

        let src = GossipBlockSource::new(vec![peer as Arc<dyn UnicastPeer>]);
        let resp = src.get_block(Round(5)).await.unwrap();
        assert_eq!(resp.block.round.0, 5);
    }

    #[tokio::test]
    async fn round_robin_peer_selection() {
        let block1 = make_block_msgpack(1);
        let block2 = make_block_msgpack(2);
        let cert = make_cert_msgpack();

        let peer_a: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer-a:4160").with_success(1, block1.clone(), cert.clone()));
        let peer_b: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer-b:4160").with_success(2, block2.clone(), cert.clone()));

        let src = GossipBlockSource::new(vec![peer_a, peer_b]);

        // First fetch goes to peer_a (index 0).
        let r1 = src.get_block(Round(1)).await.unwrap();
        assert_eq!(r1.block.round.0, 1);

        // Second fetch goes to peer_b (index 1).
        let r2 = src.get_block(Round(2)).await.unwrap();
        assert_eq!(r2.block.round.0, 2);
    }

    #[tokio::test]
    async fn failover_to_next_peer() {
        let block = make_block_msgpack(10);
        let cert = make_cert_msgpack();

        // First peer always fails, second peer has the block.
        let bad_peer: Arc<dyn UnicastPeer> = Arc::new(
            MockPeer::new("bad-peer:4160").with_request_error(10, PeerError::ConnectionClosed),
        );
        let good_peer: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("good-peer:4160").with_success(10, block, cert));

        let src = GossipBlockSource::new(vec![bad_peer, good_peer]);
        let resp = src.get_block(Round(10)).await.unwrap();
        assert_eq!(resp.block.round.0, 10);
    }

    #[tokio::test]
    async fn service_error_triggers_failover() {
        let block = make_block_msgpack(7);
        let cert = make_cert_msgpack();

        let err_peer: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("err-peer:4160").with_service_error(7, "block not available"));
        let ok_peer: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("ok-peer:4160").with_success(7, block, cert));

        let src = GossipBlockSource::new(vec![err_peer, ok_peer]);
        let resp = src.get_block(Round(7)).await.unwrap();
        assert_eq!(resp.block.round.0, 7);
    }

    #[tokio::test]
    async fn all_peers_fail_returns_last_error() {
        let peer_a: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("a:4160").with_service_error(3, "not available"));
        let peer_b: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("b:4160").with_request_error(3, PeerError::ConnectionClosed));

        let src = GossipBlockSource::new(vec![peer_a, peer_b]);
        let result = src.get_block(Round(3)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_status_reflects_last_fetched_round() {
        let block = make_block_msgpack(42);
        let cert = make_cert_msgpack();

        let peer: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer:4160").with_success(42, block, cert));

        let src = GossipBlockSource::new(vec![peer]);

        // Before any fetch, last_round is 0.
        let status = src.get_status().await.unwrap();
        assert_eq!(status.last_round, 0);

        // After fetching round 42, status should reflect it.
        let _ = src.get_block(Round(42)).await.unwrap();
        let status = src.get_status().await.unwrap();
        assert_eq!(status.last_round, 42);
    }

    #[tokio::test]
    async fn get_block_raw_returns_reencoded_msgpack() {
        let block = make_block_msgpack(99);
        let cert = make_cert_msgpack();

        let peer: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer:4160").with_success(99, block, cert));

        let src = GossipBlockSource::new(vec![peer]);
        let raw = src.get_block_raw(Round(99)).await.unwrap();

        // The raw bytes should be valid msgpack that decodes back to a BlockResponse.
        let decoded: BlockResponse = rmp_serde::from_slice(&raw).expect("decode re-encoded block");
        assert_eq!(decoded.block.round.0, 99);
    }

    #[test]
    fn peer_count() {
        let peer: Arc<dyn UnicastPeer> = Arc::new(MockPeer::new("a:4160"));
        let src = GossipBlockSource::new(vec![peer]);
        assert_eq!(src.peer_count(), 1);

        let empty = GossipBlockSource::new(vec![]);
        assert_eq!(empty.peer_count(), 0);
    }

    #[test]
    fn config_defaults() {
        let cfg = GossipBlockSourceConfig::default();
        assert_eq!(cfg.request_timeout, Duration::from_secs(4));
        assert_eq!(cfg.max_peer_attempts, 5);
        assert_eq!(cfg.poll_backoff, Duration::from_millis(500));
        assert_eq!(cfg.max_wait, Duration::from_secs(300));
    }
}
