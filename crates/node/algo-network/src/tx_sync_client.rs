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

//! Transaction-sync client — HTTP peer side of the [`TxSyncer`] pull
//! protocol (issue #774).
//!
//! [`HttpTxSyncClient`] implements [`TxSyncPeerClient`] against
//! [`crate::tx_sync_service::TxSyncService`]'s HTTP endpoint.
//! [`GossipTxSyncPeerSource`] implements [`PeerSource`] by sampling one
//! outgoing-connected peer from any [`GossipNode`] (`WebsocketNetwork` or
//! the libp2p `P2pTransport` both qualify), matching Go's
//! `TxSyncer.syncFromClient` peer selection
//! (`GossipNode.GetPeers(PeersConnectedOut)` + random pick) — see that
//! trait method's own doc comment for why only *outgoing* connections are
//! sampled: those are the peers we dialed via their advertised
//! `net_address`, which is exactly the host:port this module's HTTP
//! client needs to be dialable (an inbound peer's ephemeral source port
//! is not).
//!
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer
//! [`PeerSource`]: crate::tx_syncer::PeerSource

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use rand::Rng;

use algo_types::{Digest, SignedTransaction};

use crate::gossip_node::{GossipNode, PeerOption};
use crate::tx_sync_service::TX_SYNC_REQUEST_CONTENT_TYPE;
use crate::tx_syncer::{PeerSource, TxSyncError, TxSyncPeerClient};

/// [`TxSyncPeerClient`] that pulls missing transactions from a peer over
/// HTTP, against [`crate::tx_sync_service::TxSyncService`]'s endpoint.
pub struct HttpTxSyncClient {
    peer_addr: String,
    genesis_id: String,
    http: reqwest::Client,
    /// Cap on the total response bytes read from the peer — defense
    /// against a peer that lies about (or omits) `Content-Length` and
    /// streams an unbounded body. Mirrors go's `maxTxSyncResponseBytes`.
    response_size_limit: usize,
}

impl HttpTxSyncClient {
    /// Build a client that will sync against `peer_addr`
    /// (`host:port`, dialable — see module doc).
    #[must_use]
    pub fn new(
        peer_addr: String,
        genesis_id: String,
        http: reqwest::Client,
        response_size_limit: usize,
    ) -> Self {
        Self {
            peer_addr,
            genesis_id,
            http,
            response_size_limit: response_size_limit.max(1),
        }
    }
}

#[async_trait]
impl TxSyncPeerClient for HttpTxSyncClient {
    fn address(&self) -> String {
        self.peer_addr.clone()
    }

    async fn sync(
        &self,
        pending: &[Digest],
        timeout: Duration,
    ) -> Result<Vec<Vec<SignedTransaction>>, TxSyncError> {
        let body = rmp_serde::to_vec(&pending.to_vec()).map_err(|e| TxSyncError::Peer {
            peer: self.peer_addr.clone(),
            message: format!("encode pending ids: {e}"),
        })?;
        let url = format!(
            "http://{}/v1/{}/rust-txsync",
            self.peer_addr, self.genesis_id
        );

        let send_result = tokio::time::timeout(
            timeout,
            self.http
                .post(&url)
                .header("Content-Type", TX_SYNC_REQUEST_CONTENT_TYPE)
                .body(body)
                .send(),
        )
        .await;
        let response = match send_result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                return Err(TxSyncError::Peer {
                    peer: self.peer_addr.clone(),
                    message: e.to_string(),
                })
            }
            Err(_) => {
                return Err(TxSyncError::Timeout {
                    peer: self.peer_addr.clone(),
                    elapsed: timeout,
                })
            }
        };

        if !response.status().is_success() {
            return Err(TxSyncError::Peer {
                peer: self.peer_addr.clone(),
                message: format!("unexpected status {}", response.status()),
            });
        }

        let bytes = self.read_bounded(response, timeout).await?;
        rmp_serde::from_slice(&bytes).map_err(|e| TxSyncError::Peer {
            peer: self.peer_addr.clone(),
            message: format!("decode response: {e}"),
        })
    }
}

impl HttpTxSyncClient {
    /// Read `response`'s body, aborting as soon as it would exceed
    /// `response_size_limit` bytes or `timeout` elapses — whichever
    /// comes first. Never trusts `Content-Length` alone: a peer can omit
    /// or understate it and still stream an unbounded body, so the
    /// stream itself is capped as it's read.
    async fn read_bounded(
        &self,
        response: reqwest::Response,
        timeout: Duration,
    ) -> Result<Vec<u8>, TxSyncError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = Vec::new();
        let mut stream = response.bytes_stream();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let next = tokio::time::timeout(remaining, stream.next())
                .await
                .map_err(|_| TxSyncError::Timeout {
                    peer: self.peer_addr.clone(),
                    elapsed: timeout,
                })?;
            match next {
                Some(Ok(chunk)) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() > self.response_size_limit {
                        return Err(TxSyncError::Peer {
                            peer: self.peer_addr.clone(),
                            message: format!(
                                "response exceeded {}-byte cap",
                                self.response_size_limit
                            ),
                        });
                    }
                }
                Some(Err(e)) => {
                    return Err(TxSyncError::Peer {
                        peer: self.peer_addr.clone(),
                        message: e.to_string(),
                    })
                }
                None => break,
            }
        }
        Ok(buf)
    }
}

/// [`PeerSource`] backed by any [`GossipNode`]'s outgoing-connected
/// peers.
///
/// Sampling only [`PeerOption::PeersConnectedOut`] (rather than all
/// peers, or `PeersConnectedIn`) means every candidate is a peer *this*
/// node dialed via its advertised `net_address` — the same host:port
/// that peer's HTTP server (block service, tx-sync service) listens on.
/// An inbound peer's observed address is its ephemeral outbound source
/// port, which is not meaningfully dialable, so it's deliberately never
/// sampled here (mirrors go's `TxSyncer` peer selection, and this
/// module's own `crate::tx_syncer` skeleton doc comment).
pub struct GossipTxSyncPeerSource {
    gossip: Arc<dyn GossipNode>,
    genesis_id: String,
    http: reqwest::Client,
    response_size_limit: usize,
}

impl GossipTxSyncPeerSource {
    /// Build a peer source over `gossip`.
    #[must_use]
    pub fn new(
        gossip: Arc<dyn GossipNode>,
        genesis_id: String,
        http: reqwest::Client,
        response_size_limit: usize,
    ) -> Self {
        Self {
            gossip,
            genesis_id,
            http,
            response_size_limit,
        }
    }
}

impl PeerSource for GossipTxSyncPeerSource {
    fn sample_peer(&self) -> Option<Arc<dyn TxSyncPeerClient>> {
        let peers = self.gossip.get_peers(&[PeerOption::PeersConnectedOut]);
        if peers.is_empty() {
            return None;
        }
        let idx = rand::thread_rng().gen_range(0..peers.len());
        let addr = peers[idx].get_address().to_string();
        Some(Arc::new(HttpTxSyncClient::new(
            addr,
            self.genesis_id.clone(),
            self.http.clone(),
            self.response_size_limit,
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip_node::Peer;
    use crate::tx_sync_service::{PendingTxGroupsSource, TxSyncService};
    use algo_codec::compute_txn_id;
    use std::net::TcpListener;

    fn make_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.fee = fee;
        stx
    }

    struct FakePool(Vec<Vec<SignedTransaction>>);
    impl PendingTxGroupsSource for FakePool {
        fn pending_tx_groups(&self) -> Vec<Vec<SignedTransaction>> {
            self.0.clone()
        }
    }

    /// Bind an ephemeral loopback port and spawn `router` on it via
    /// axum, returning the bound `host:port`.
    async fn spawn_router(router: axum::Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local_addr");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn http_client_pulls_missing_group_from_real_server() {
        let missing = make_txn(7);
        let missing_id = compute_txn_id(&missing.txn);
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![missing.clone()]])),
            "test-genesis".to_string(),
            1_000_000,
        );
        let addr = spawn_router(service.http_router()).await;
        // Give the listener a moment to accept.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = HttpTxSyncClient::new(
            addr,
            "test-genesis".to_string(),
            reqwest::Client::new(),
            1_000_000,
        );
        let groups = client
            .sync(&[], Duration::from_secs(5))
            .await
            .expect("sync should succeed");
        assert_eq!(groups.len(), 1);
        assert_eq!(compute_txn_id(&groups[0][0].txn), missing_id);
    }

    #[tokio::test]
    async fn http_client_times_out_against_unreachable_peer() {
        // Port 0 never accepts a connection from a real dial.
        let client = HttpTxSyncClient::new(
            "127.0.0.1:1".to_string(), // reserved, nothing listens here
            "g".to_string(),
            reqwest::Client::new(),
            1_000,
        );
        let result = client.sync(&[], Duration::from_millis(200)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_not_buffered_unbounded() {
        // Server has no cap of its own here — the fake pool returns one
        // big group, and the *client's* response_size_limit is what
        // must bite.
        let big_note = vec![0u8; 4096];
        let mut big_txn = make_txn(1);
        big_txn.txn.note = serde_bytes::ByteBuf::from(big_note);
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![big_txn]])),
            "g".to_string(),
            10_000_000, // server-side cap is generous
        );
        let addr = spawn_router(service.http_router()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = HttpTxSyncClient::new(
            addr,
            "g".to_string(),
            reqwest::Client::new(),
            16, // client-side cap: far smaller than the actual response
        );
        let result = client.sync(&[], Duration::from_secs(5)).await;
        assert!(
            matches!(result, Err(TxSyncError::Peer { .. })),
            "expected a bounded-size rejection, got {result:?}"
        );
    }

    struct FakeGossip {
        peers: Vec<Arc<dyn Peer>>,
    }

    #[async_trait]
    impl GossipNode for FakeGossip {
        fn address(&self) -> (String, bool) {
            (String::new(), false)
        }
        async fn broadcast(
            &self,
            _tag: crate::tag::Tag,
            _data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn relay(
            &self,
            _tag: crate::tag::Tag,
            _data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn disconnect(&self, _peer: Arc<dyn Peer>) {}
        fn disconnect_peers(&self) {}
        async fn request_connect_outgoing(&self, _replace: bool) {}
        fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
            self.peers.clone()
        }
        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn stop(&self) {}
        fn register_handlers(&self, _dispatch: Vec<crate::handler::TaggedMessageHandler>) {}
        fn clear_handlers(&self) {}
        fn register_validator_handlers(
            &self,
            _dispatch: Vec<crate::handler::TaggedMessageValidatorHandler>,
        ) {
        }
        fn clear_validator_handlers(&self) {}
        fn on_network_advance(&self) {}
        fn get_genesis_id(&self) -> &str {
            "g"
        }
        fn register_http_handler(&self, _path: &str, _handler: axum::Router) {}
    }

    #[test]
    fn peer_source_returns_none_with_no_peers() {
        let source = GossipTxSyncPeerSource::new(
            Arc::new(FakeGossip { peers: vec![] }),
            "g".to_string(),
            reqwest::Client::new(),
            1_000,
        );
        assert!(source.sample_peer().is_none());
    }

    struct FakePeer {
        addr: String,
    }
    impl Peer for FakePeer {
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

    #[test]
    fn peer_source_returns_a_client_addressed_to_the_sampled_peer() {
        let source = GossipTxSyncPeerSource::new(
            Arc::new(FakeGossip {
                peers: vec![Arc::new(FakePeer {
                    addr: "10.0.0.5:1234".to_string(),
                })],
            }),
            "g".to_string(),
            reqwest::Client::new(),
            1_000,
        );
        let client = source.sample_peer().expect("one peer available");
        assert_eq!(client.address(), "10.0.0.5:1234");
    }
}
