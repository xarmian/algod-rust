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

//! Issue #803: `outgoing_message_filter` used to be a single `MessageFilter`
//! instance shared across every peer connection, instead of a genuinely
//! per-connection filter (go's `wsPeer.outgoingMsgFilter`,
//! `network/wsPeer.go:213`, constructed fresh per connection in
//! `wsPeer.init()`, `network/wsPeer.go:469`).
//!
//! Consequence of the bug: if peer B tells hub A "I already have digest D"
//! (a `MsgDigestSkip` notification), that digest landed in the *one* shared
//! filter every connection's write loop consulted. A later attempt to send
//! a distinct message matching digest D to peer C — who never sent any
//! `MsgDigestSkip` and has never actually seen that data — was wrongly
//! suppressed too, because C's connection consulted the same shared filter
//! state B had populated.
//!
//! This test spins up three real `WebsocketNetwork`s over loopback: a relay
//! hub `A` with participants `B` and `C` dialing in (mirroring
//! `msg_digest_skip_broadcast.rs`'s harness). `B` sends `A` a real
//! `MsgDigestSkip` for digest `D`. `A` then broadcasts a real `TX` message
//! whose digest is `D` to all its peers. `B` (having claimed to already
//! have it) must not receive it — but `C`, a completely different
//! connection that never made any such claim, must still receive it.
//!
//! Before the fix, `C`'s handler never fires (the shared filter, populated
//! by B's notification, wrongly suppresses A's send to C too) and this test
//! fails. After the fix, each connection's filter is independent, so only
//! B's send is suppressed and C's handler fires exactly once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_network::forwarding_policy::ForwardingPolicy;
use algo_network::handler::{MessageHandler, TaggedMessageHandler};
use algo_network::message::{IncomingMessage, OutgoingMessage};
use algo_network::message_filter::{generate_message_digest, MESSAGE_FILTER_SIZE};
use algo_network::peer_role::RELAY_ROLE;
use algo_network::phonebook::Phonebook;
use algo_network::tag::Tag;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::GossipNode;
use async_trait::async_trait;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=info,per_peer_outgoing_message_filter=debug")
        .with_test_writer()
        .try_init();
}

/// Counts invocations for a given tag; never re-broadcasts (avoids feeding
/// its own dedup state back into the test).
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

/// Build one loopback `WebsocketNetwork`, at default (enabled) outgoing
/// filtering config, matching go's `EnableOutgoingNetworkMessageFiltering`
/// default of `true`.
fn build_node(relay: bool) -> Arc<WebsocketNetwork> {
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
        // Long mesh interval — connectivity is driven explicitly by the
        // test via `request_connect_outgoing`, matching
        // `msg_digest_skip_broadcast.rs`.
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

/// Wait until `net` has at least `n` connected peers, or panic after 5s.
async fn wait_for_peer_count(net: &Arc<WebsocketNetwork>, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if net.peer_count().await >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "peer count did not reach {n} within 5s (actual={})",
        net.peer_count().await
    );
}

/// Wait until one of `net`'s currently connected peer addresses has an
/// outgoing filter recording `digest`, returning that address, or panic
/// after 5s. Used to deterministically know a `MsgDigestSkip` was actually
/// processed before moving on, rather than relying on a fixed sleep and
/// hoping it was long enough. `net`'s peer-map keys for *inbound*
/// connections are OS-assigned socket addresses neither side predicts in
/// advance, hence polling [`WebsocketNetwork::peer_addresses`] rather than
/// checking one address directly.
async fn wait_for_digest_recorded_on_any_peer(
    net: &Arc<WebsocketNetwork>,
    digest: &[u8; 32],
) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        for addr in net.peer_addresses().await {
            if let Some(filter) = net.peer_outgoing_message_filter(&addr).await {
                // add=false — just check, don't mutate, so retrying doesn't
                // corrupt the result.
                if filter.check_digest(digest, false, false) {
                    return addr;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no peer connection recorded the digest within 5s");
}

#[tokio::test]
async fn msg_digest_skip_from_one_peer_does_not_suppress_send_to_another() {
    init_tracing();

    // Node A: relay hub that both B and C dial into.
    let net_a = build_node(true);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    // Node B: will claim (via MsgDigestSkip) that it already has digest D.
    // A must record that claim only against its connection to B.
    let net_b = build_node(false);
    let b_count = Arc::new(AtomicUsize::new(0));
    net_b
        .multiplexer()
        .register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(CountingHandler {
                count: b_count.clone(),
            }),
        }]);
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;

    // Node C: must still receive A's broadcast of the message matching D —
    // it never claimed anything and is a completely different connection.
    let net_c = build_node(false);
    let c_count = Arc::new(AtomicUsize::new(0));
    net_c
        .multiplexer()
        .register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(CountingHandler {
                count: c_count.clone(),
            }),
        }]);
    point_at(&net_c, &a_addr);
    net_c.start_arc().await.expect("node C start");
    net_c.request_connect_outgoing(false).await;

    // A should see both B and C connected (accept path, both inbound).
    wait_for_peer_count(&net_a, 2).await;
    wait_for_peer_count(&net_b, 1).await;
    wait_for_peer_count(&net_c, 1).await;

    let payload = vec![0xEF_u8; MESSAGE_FILTER_SIZE];
    let digest = generate_message_digest(&Tag::Transaction, &payload);

    // B tells A (its only peer) "I already have this digest" via a real
    // MsgDigestSkip message — mirrors go's handleFilterMessage() being
    // driven by an actual wsPeer.outgoingMsgFilter.CheckDigest() call.
    net_b
        .broadcast(Tag::MsgDigestSkip, digest.to_vec(), true, None)
        .await
        .expect("MsgDigestSkip broadcast should succeed");

    // Wait until A has actually recorded B's claim before broadcasting.
    wait_for_digest_recorded_on_any_peer(&net_a, &digest).await;

    // A broadcasts the real message matching digest D to all its peers
    // (B and C). Old (buggy) behavior: the one shared outgoing filter,
    // populated by B's notification, suppresses the send to C as well.
    // Fixed behavior: only B's own connection's filter was updated, so C
    // still receives it while B (having claimed to already have it) does
    // not.
    net_a
        .broadcast(Tag::Transaction, payload.clone(), true, None)
        .await
        .expect("broadcast should succeed");

    // Give both peers time to receive and dispatch the message if it
    // wasn't suppressed.
    tokio::time::sleep(Duration::from_millis(500)).await;

    net_b.stop().await;
    net_c.stop().await;
    net_a.stop().await;

    assert_eq!(
        c_count.load(Ordering::SeqCst),
        1,
        "node C must still receive A's broadcast of the message matching \
         digest D: B's MsgDigestSkip notification for D must only suppress \
         A's sends to B (a per-connection outgoing filter), never to C (a \
         completely different connection) — issue #803"
    );
    assert_eq!(
        b_count.load(Ordering::SeqCst),
        0,
        "node B, having claimed to already have digest D via MsgDigestSkip, \
         should not receive A's re-send of it (sanity check that the \
         suppression mechanism itself is actually exercised by this test)"
    );
}

/// Direct proof (rather than end-to-end delivery) that A's per-connection
/// outgoing filter for B is where B's `MsgDigestSkip` digest lands, and
/// that A's *other* peer connection (C) never sees it — i.e. the two
/// connections genuinely hold independent `MessageFilter` instances rather
/// than one shared one.
#[tokio::test]
async fn hub_records_digest_only_on_the_notifying_peers_own_connection() {
    init_tracing();

    let net_a = build_node(true);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    let net_b = build_node(false);
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;

    let net_c = build_node(false);
    point_at(&net_c, &a_addr);
    net_c.start_arc().await.expect("node C start");
    net_c.request_connect_outgoing(false).await;

    wait_for_peer_count(&net_a, 2).await;
    wait_for_peer_count(&net_b, 1).await;
    wait_for_peer_count(&net_c, 1).await;

    let payload = vec![0xEF_u8; MESSAGE_FILTER_SIZE];
    let digest = generate_message_digest(&Tag::Transaction, &payload);

    net_b
        .broadcast(Tag::MsgDigestSkip, digest.to_vec(), true, None)
        .await
        .expect("MsgDigestSkip broadcast should succeed");

    // Find which of A's two peer-map entries recorded the digest (B's) —
    // there are only two, and only B ever sent the notification.
    let recording_addr = wait_for_digest_recorded_on_any_peer(&net_a, &digest).await;

    // Every *other* connected address on A must show no trace of the
    // digest in its own outgoing filter — proving that filter is a
    // genuinely separate instance from the one B's notification updated.
    let other_addrs: Vec<String> = net_a
        .peer_addresses()
        .await
        .into_iter()
        .filter(|a| *a != recording_addr)
        .collect();
    assert_eq!(
        other_addrs.len(),
        1,
        "expected exactly one other connected peer (C) besides the one that recorded the digest (B)"
    );
    let other_filter = net_a
        .peer_outgoing_message_filter(&other_addrs[0])
        .await
        .expect("outgoing filtering is enabled by default, so C's connection has its own filter");
    assert!(
        !other_filter.check_digest(&digest, false, false),
        "the other peer's (C's) outgoing filter must not contain the digest \
         B reported — each connection owns an independent MessageFilter \
         instance (issue #803), so B's claim must never appear in C's"
    );

    net_b.stop().await;
    net_c.stop().await;
    net_a.stop().await;
}
