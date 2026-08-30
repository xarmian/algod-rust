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

//! Issue #789: `MessageFilter` (the digest-dedup gossip filter,
//! config-driven since #768) was fully built and unit-tested but never
//! attached to any *real* peer connection — `WsPeerConfig`'s
//! `incoming_filter`/`outgoing_filter` slots stayed `None` on both the
//! outbound mesh-dial path (`NetworkConnectFn::try_dial`) and the inbound
//! accept path (`PeerHandle::new_inbound`, which didn't even take filters
//! as a parameter). This meant `enable_incoming_message_filter` had zero
//! live effect: a duplicate gossip message sent twice by a peer was
//! reprocessed (and, for a relay, re-broadcast) twice.
//!
//! This test spins up two real `WebsocketNetwork`s connected over loopback
//! (mirroring `tx_propagation_inproc.rs`'s in-process harness) and proves,
//! over the real wire in both connection directions, that a duplicate
//! `TX`-tagged message is only handed to the multiplexer once when the
//! receiving side has `enable_incoming_message_filter` on.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_network::forwarding_policy::ForwardingPolicy;
use algo_network::handler::{MessageHandler, TaggedMessageHandler};
use algo_network::message::{IncomingMessage, OutgoingMessage};
use algo_network::peer_role::RELAY_ROLE;
use algo_network::phonebook::Phonebook;
use algo_network::tag::Tag;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::GossipNode;
use async_trait::async_trait;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=info,message_filter_wiring=debug")
        .with_test_writer()
        .try_init();
}

/// Counts invocations for a given tag; never re-broadcasts (avoids
/// feeding its own dedup state back into the test).
struct CountingHandler {
    count: Arc<AtomicUsize>,
}

#[async_trait]
impl MessageHandler for CountingHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        self.count.fetch_add(1, Ordering::SeqCst);
        OutgoingMessage {
            action: ForwardingPolicy::Accept,
            tag: msg.tag,
            payload: Vec::new(),
            topics: None,
        }
    }
}

/// Build one loopback `WebsocketNetwork`. `relay` controls whether it binds
/// a listener (so the other side can dial it); `incoming_filter` controls
/// `enable_incoming_message_filter` (the config-driven knob issue #768
/// wired up, which this issue makes actually take effect).
fn build_node(relay: bool, incoming_filter: bool) -> Arc<WebsocketNetwork> {
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: if relay {
            Some("127.0.0.1:0".to_string())
        } else {
            None
        },
        relay_messages: relay,
        gossip_fanout: 2,
        enable_incoming_message_filter: incoming_filter,
        // Long mesh interval — connectivity is driven explicitly by the
        // test via `request_connect_outgoing`, matching
        // `tx_propagation_inproc.rs`.
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    Arc::new(WebsocketNetwork::new(config, phonebook))
}

/// Seed `dialer`'s phonebook with `target_addr` so `dialer` will dial it.
fn point_at(dialer: &Arc<WebsocketNetwork>, target_addr: &str) {
    dialer
        .phonebook()
        .replace_peer_list(&[target_addr.to_string()], "test", RELAY_ROLE);
}

/// Wait until both networks see at least one peer, or panic after 5s.
async fn wait_for_mutual_peering(a: &Arc<WebsocketNetwork>, b: &Arc<WebsocketNetwork>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if a.peer_count().await >= 1 && b.peer_count().await >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "peers did not connect within 5s (a={}, b={})",
        a.peer_count().await,
        b.peer_count().await
    );
}

/// Send the identical `TX`-tagged payload `n` times from `sender` to all
/// its peers, waiting briefly between sends so they arrive as distinct
/// WebSocket frames rather than being coalesced.
async fn broadcast_duplicate(sender: &Arc<WebsocketNetwork>, payload: &[u8], n: usize) {
    for _ in 0..n {
        sender
            .broadcast(Tag::Transaction, payload.to_vec(), true, None)
            .await
            .expect("broadcast should succeed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Issue #789 (inbound/accept-path wiring): a *dialing* peer's duplicate
/// `TX` messages must be deduplicated by the *accepting* relay's incoming
/// filter. Node B (participant) dials node A (relay); the connection A
/// holds for B is created by `handle_gossip_websocket` /
/// `PeerHandle::new_inbound` — the accept path this issue wires up.
#[tokio::test]
async fn inbound_accept_path_deduplicates_duplicate_tx_messages() {
    init_tracing();

    let net_a = build_node(true, true); // relay, incoming filter ON
    let count = Arc::new(AtomicUsize::new(0));
    net_a
        .multiplexer()
        .register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(CountingHandler {
                count: count.clone(),
            }),
        }]);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    let net_b = build_node(false, false); // participant, dials A
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;

    wait_for_mutual_peering(&net_a, &net_b).await;

    // Same payload sent twice from B; A's incoming filter (once wired to
    // the real accept-path connection) must drop the second copy before
    // it ever reaches the multiplexer.
    let payload = vec![0xAB; 64];
    broadcast_duplicate(&net_b, &payload, 2).await;

    // Give the second (would-be-duplicate) message time to arrive if the
    // filter is not actually wired.
    tokio::time::sleep(Duration::from_millis(300)).await;

    net_b.stop().await;
    net_a.stop().await;

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "node A's incoming_message_filter should have deduplicated the \
         second identical TX message received on the real accepted \
         connection from B (handler should fire exactly once)"
    );
}

/// Issue #789 (outbound/dial-path wiring): the mirror image of the above —
/// the *dialing* node's own incoming filter must dedup messages received
/// on the connection *it* opened. Node B dials node A; A sends the
/// duplicate, and B's connection to A (built by
/// `NetworkConnectFn::try_dial`) is the dial path this issue wires up.
#[tokio::test]
async fn outbound_dial_path_deduplicates_duplicate_tx_messages() {
    init_tracing();

    let net_a = build_node(true, false); // relay, no incoming filter needed
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    let net_b = build_node(false, true); // participant, dials A, incoming filter ON
    let count = Arc::new(AtomicUsize::new(0));
    net_b
        .multiplexer()
        .register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(CountingHandler {
                count: count.clone(),
            }),
        }]);
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;

    wait_for_mutual_peering(&net_a, &net_b).await;

    // A sends the same payload twice; B's own dial-path connection to A
    // must be the one consulting B's incoming filter.
    let payload = vec![0xCD; 64];
    broadcast_duplicate(&net_a, &payload, 2).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    net_b.stop().await;
    net_a.stop().await;

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "node B's incoming_message_filter should have deduplicated the \
         second identical TX message received on the real dialed \
         connection to A (handler should fire exactly once)"
    );
}
