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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use algo_codec::decode_block;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::{debug, warn};

use algo_network::block_fetcher::{make_block_request_topics, parse_block_response};
use algo_network::gossip_node::UnicastPeer;
use algo_network::peer_ranker::{
    create_peer_selector, ClassBasedPeerSelector, PeerClassKind, PeerSelector, PeersRetriever,
    PEER_RANK_DOWNLOAD_FAILED,
};
use algo_network::tag::Tag;

use crate::{BlockSource, NodeStatus};

// ---------------------------------------------------------------------------
// Peer-ranking wiring
// ---------------------------------------------------------------------------

/// Feeds [`GossipBlockSource`]'s live peer-address list into the
/// [`ClassBasedPeerSelector`] ranker.
///
/// All configured peers are reported under the `ConnectedOut` class (the
/// class go-algorand uses for a node's own outbound connections in
/// `catchup/service.go`'s `createPeerSelector`), since `GossipBlockSource`'s
/// flat `Arc<dyn UnicastPeer>` list carries no phonebook-relay/archival/
/// inbound distinction at this layer. Every other class always reports no
/// peers, so [`ClassBasedPeerSelector`] falls straight through to
/// `ConnectedOut` — the same class ordering `create_peer_selector` uses,
/// preserved here for topology parity with go's real wiring rather than
/// collapsing to a single flat [`PeerRanker`].
struct GossipPeersRetriever {
    addrs: StdMutex<Vec<String>>,
}

impl PeersRetriever for GossipPeersRetriever {
    fn get_peers(&self, class: PeerClassKind) -> Vec<String> {
        if class == PeerClassKind::ConnectedOut {
            self.addrs
                .lock()
                .expect("peer address list lock poisoned")
                .clone()
        } else {
            Vec::new()
        }
    }
}

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
/// Peer selection is delegated to a [`ClassBasedPeerSelector`] (issue #901),
/// so that a peer which has recently been slow or unreliable is
/// deprioritized in favor of a better-ranked one — mirroring go-algorand's
/// `catchup/service.go` `fetchAndWrite`, which calls
/// `peerSelector.getNextPeer()`/`rankPeer()` around each block fetch rather
/// than cycling peers in a fixed order. On failure, the next-ranked peer is
/// attempted up to [`GossipBlockSourceConfig::max_peer_attempts`] times.
pub struct GossipBlockSource {
    /// The set of unicast peers available for block requests.
    peers: Vec<Arc<dyn UnicastPeer>>,

    /// Live peer-address list backing `peer_selector`'s retriever, kept in
    /// sync with `peers` (including across `set_peers`).
    peer_addrs: Arc<GossipPeersRetriever>,

    /// Ranks peers by historical download performance and picks the next
    /// peer to try. Guarded by a std `Mutex` since selection/ranking are
    /// synchronous, in-memory operations never held across an `.await`.
    peer_selector: StdMutex<ClassBasedPeerSelector>,

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
        let peer_addrs = Arc::new(GossipPeersRetriever {
            addrs: StdMutex::new(peers.iter().map(|p| p.get_address().to_string()).collect()),
        });
        let peer_selector = StdMutex::new(create_peer_selector(
            peer_addrs.clone() as Arc<dyn PeersRetriever>
        ));
        Self {
            peers,
            peer_addrs,
            peer_selector,
            last_fetched_round: AtomicU64::new(0),
            config,
        }
    }

    /// Replace the peer set (e.g. after a phonebook refresh).
    pub fn set_peers(&mut self, peers: Vec<Arc<dyn UnicastPeer>>) {
        *self
            .peer_addrs
            .addrs
            .lock()
            .expect("peer address list lock poisoned") =
            peers.iter().map(|p| p.get_address().to_string()).collect();
        self.peers = peers;
    }

    /// Returns the number of peers currently configured.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Fetch a block from a single peer via WS unicast, returning both the
    /// decoded [`BlockResponse`] and the raw block msgpack bytes (for payset
    /// blob extraction).
    ///
    /// Mirrors Go's `wsFetcherClient.requestBlock()`.
    ///
    /// Timeout handling is delegated to the peer's own `request()` method,
    /// which uses the peer's configured `request_timeout` (set via
    /// [`WsPeerConfig::request_timeout`]) and properly cleans up its
    /// `RequestTracker` entry on expiry. Callers should configure peers
    /// with the desired timeout (e.g. [`GossipBlockSourceConfig::request_timeout`])
    /// rather than wrapping with an outer `tokio::time::timeout`, which
    /// would leak tracker entries.
    async fn fetch_from_peer(
        &self,
        peer: &dyn UnicastPeer,
        round: Round,
    ) -> Result<(BlockResponse, Vec<u8>)> {
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

        // Decode block+cert from their raw msgpack bytes. decode_block_cert
        // borrows the data, so we can move block_data into the return tuple
        // afterward — avoiding a clone.
        let response = decode_block_cert(&data.block_data, &data.cert_data)?;
        Ok((response, data.block_data))
    }

    /// Fetch a block with retry/failover across available peers, returning
    /// both the decoded [`BlockResponse`] and the raw block msgpack bytes.
    ///
    /// This is the shared retry engine used by both [`BlockSource::get_block`]
    /// and [`get_block_with_raw_data`]. The raw bytes can be fed to
    /// [`algo_codec::extract_raw_payset_blobs_from_block`] for payset
    /// commitment verification.
    async fn fetch_with_retry(&self, round: Round) -> Result<(BlockResponse, Vec<u8>)> {
        if self.peers.is_empty() {
            return Err(AlgoError::Network {
                message: "no peers available for block fetch".into(),
            });
        }

        // Unlike round-robin (where each attempt was guaranteed a distinct
        // peer, so capping attempts at `peers.len()` made sense), ranked
        // selection offers no such guarantee: the ranker can legitimately
        // return the same (currently best-ranked, or only-untried-enough)
        // peer more than once before a failing peer's rank has moved far
        // enough to fall behind a reliable one — e.g. two peers landing in
        // the same rank bucket and being tie-broken at random. Capping
        // attempts at the peer count risked exhausting the retry budget on
        // the same bad peer twice while a good one sat untried. Use the
        // full configured attempt budget instead, decoupled from peer
        // count — closer to go's `catchupRetryLimit`, which is likewise
        // independent of how many peers are available.
        let attempts = self.config.max_peer_attempts;
        let mut last_err = None;

        for attempt in 0..attempts {
            // Ask the ranker for the next peer to try (lowest-rank
            // non-empty pool, ties broken at random) rather than cycling
            // through `peers` in a fixed order.
            let psp = {
                let mut selector = self
                    .peer_selector
                    .lock()
                    .expect("peer selector lock poisoned");
                selector.get_next_peer()
            };
            let psp = match psp {
                Ok(psp) => psp,
                Err(_) => {
                    // No peer pools available at all (e.g. every peer has
                    // been dropped from the retriever's live list).
                    break;
                }
            };
            let peer = match self.peers.iter().find(|p| p.get_address() == psp.peer_id) {
                Some(p) => Arc::clone(p),
                None => {
                    // Stale entry (peer removed since the selector last
                    // refreshed its pools) — try the next-ranked peer.
                    continue;
                }
            };

            debug!(
                round = %round,
                peer = peer.get_address(),
                attempt = attempt + 1,
                max_attempts = attempts,
                "requesting block via WS unicast (ranked selection)"
            );

            let started = Instant::now();
            match self.fetch_from_peer(peer.as_ref(), round).await {
                Ok((response, raw_block_data)) => {
                    // Mirrors go's `peerSelector.peerDownloadDurationToRank`
                    // + `rankPeer` call in `fetchAndWrite` on success: feed
                    // the observed download duration back into the ranker
                    // so a consistently fast peer is preferred next time.
                    let elapsed = started.elapsed();
                    let mut selector = self
                        .peer_selector
                        .lock()
                        .expect("peer selector lock poisoned");
                    let rank = selector.peer_download_duration_to_rank(&psp, elapsed);
                    selector.rank_peer(&psp, rank);
                    drop(selector);

                    self.last_fetched_round
                        .fetch_max(round.0, Ordering::Relaxed);
                    return Ok((response, raw_block_data));
                }
                Err(e) => {
                    warn!(
                        round = %round,
                        peer = peer.get_address(),
                        attempt = attempt + 1,
                        error = %e,
                        "WS block fetch failed, ranking peer down and trying next"
                    );
                    // Mirrors go's `peerSelector.rankPeer(psp,
                    // peerRankDownloadFailed)` on a failed fetch.
                    let mut selector = self
                        .peer_selector
                        .lock()
                        .expect("peer selector lock poisoned");
                    selector.rank_peer(&psp, PEER_RANK_DOWNLOAD_FAILED);
                    drop(selector);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AlgoError::Network {
            message: format!("all {attempts} peers failed for round {round}"),
        }))
    }

    /// Fetch a block with retry/failover, returning both the decoded response
    /// and the raw block msgpack bytes (for payset blob extraction).
    ///
    /// The raw bytes can be fed to [`algo_codec::extract_raw_payset_blobs_from_block`]
    /// to obtain the original wire-format STIB blobs for payset commitment verification.
    pub async fn get_block_with_raw_data(&self, round: Round) -> Result<(BlockResponse, Vec<u8>)> {
        self.fetch_with_retry(round).await
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
        self.fetch_with_retry(round).await.map(|(resp, _)| resp)
    }

    async fn get_status(&self) -> Result<NodeStatus> {
        // For gossip-only mode we don't have a REST status endpoint.
        // Return a synthetic status based on the last successfully fetched round.
        let last_round = self.last_fetched_round.load(Ordering::Relaxed);
        Ok(NodeStatus {
            last_round,
            next_version_supported: true,
            ..NodeStatus::default()
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::time::Duration;

    // -- Mock UnicastPeer ---------------------------------------------------

    /// A configurable mock peer for testing.
    struct MockPeer {
        addr: String,
        /// Responses to serve, keyed by round. Each entry is consumed on use.
        responses: Mutex<std::collections::HashMap<u64, MockResponse>>,
        /// Number of times `request()` was invoked on this peer — used to
        /// assert which peer the ranked selector actually chose.
        request_count: AtomicUsize,
        /// If `true`, every request fails with `ConnectionClosed` regardless
        /// of `responses`, simulating a consistently unreliable peer.
        always_fail: bool,
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
                request_count: AtomicUsize::new(0),
                always_fail: false,
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

        /// Marks this peer as consistently unreliable: every `request()`
        /// call fails, regardless of which round is requested or what's in
        /// `responses`.
        fn always_failing(mut self) -> Self {
            self.always_fail = true;
            self
        }

        fn request_count(&self) -> usize {
            self.request_count.load(Ordering::Relaxed)
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
            self.request_count.fetch_add(1, Ordering::Relaxed);

            if self.always_fail {
                return Err(PeerError::ConnectionClosed);
            }

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
    async fn ranked_selection_fails_over_when_the_chosen_peer_lacks_the_round() {
        // Each peer only has one of the two rounds configured. Ranked
        // selection (unlike a fixed index order) may pick either peer
        // first, but with `max_peer_attempts >= 2` it must fail over to
        // the peer that actually has the requested round.
        let block1 = make_block_msgpack(1);
        let block2 = make_block_msgpack(2);
        let cert = make_cert_msgpack();

        let peer_a: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer-a:4160").with_success(1, block1.clone(), cert.clone()));
        let peer_b: Arc<dyn UnicastPeer> =
            Arc::new(MockPeer::new("peer-b:4160").with_success(2, block2.clone(), cert.clone()));

        let src = GossipBlockSource::new(vec![peer_a, peer_b]);

        let r1 = src.get_block(Round(1)).await.unwrap();
        assert_eq!(r1.block.round.0, 1);

        let r2 = src.get_block(Round(2)).await.unwrap();
        assert_eq!(r2.block.round.0, 2);
    }

    #[tokio::test]
    async fn ranked_selector_prefers_the_reliable_peer_after_the_unreliable_one_fails() {
        // TDD regression for issue #901: GossipBlockSource must route block
        // fetches through the peer_ranker's ClassBasedPeerSelector rather
        // than plain round-robin, and must feed fetch outcomes back into
        // it, so a peer that fails is deprioritized in favor of a
        // consistently reliable one for subsequent fetches.
        //
        // This must fail against the old round-robin `select_peer()`
        // (which alternates peers on a fixed index regardless of past
        // outcomes, so the unreliable peer would still be picked roughly
        // half the time) and pass once ranked selection with feedback is
        // wired in.
        let cert = make_cert_msgpack();
        let bad: Arc<MockPeer> = Arc::new(MockPeer::new("bad-peer:4160").always_failing());
        let good: Arc<MockPeer> = Arc::new(MockPeer::new("good-peer:4160"));

        // Configure the reliable peer to serve every round used below.
        const ROUNDS: u64 = 10;
        {
            let mut good_ref = good.responses.lock().unwrap();
            for round in 1..=ROUNDS {
                good_ref.insert(
                    round,
                    MockResponse::Success {
                        block_data: make_block_msgpack(round),
                        cert_data: cert.clone(),
                    },
                );
            }
        }

        let src = GossipBlockSource::new(vec![
            bad.clone() as Arc<dyn UnicastPeer>,
            good.clone() as Arc<dyn UnicastPeer>,
        ]);

        for round in 1..=ROUNDS {
            let resp = src
                .get_block(Round(round))
                .await
                .unwrap_or_else(|e| panic!("round {round} fetch failed: {e}"));
            assert_eq!(resp.block.round.0, round);
        }

        // Both peers start tied, so the bad peer may unavoidably be tried
        // once (or, worst case, twice within a single round's two allowed
        // attempts) before the ranker learns it always fails. After that
        // it must be consistently deprioritized: across 10 rounds it
        // should be touched only in that initial settling window, while
        // the reliable peer should serve nearly every fetch.
        assert!(
            bad.request_count() <= 2,
            "unreliable peer should be deprioritized after failing, but was retried {} times",
            bad.request_count()
        );
        assert!(
            good.request_count() >= ROUNDS as usize - 2,
            "reliable peer should be preferred for almost every fetch, got {} of {ROUNDS} requests",
            good.request_count()
        );
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
