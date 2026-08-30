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

//! Issue #798: algod-rust's *receiving* side of `MsgDigestSkip` (updating
//! `outgoing_filter` on receipt, and consulting it before a send) was fully
//! wired end-to-end by issue #789. However, the *sending* side was never
//! implemented: when a node processed a large (`>= MESSAGE_FILTER_SIZE`)
//! dedup-safe (`AV`/`TX`) message, it never told its *other* connected peers
//! "I already have this, don't bother re-sending it" — the actual
//! bandwidth-savings half of go-algorand's dedup feature
//! (`msgHandler.sendFilterMessage()`, `network/wsNetwork.go:1326`, invoked
//! from `messageHandlerThread` at `network/wsNetwork.go:1249-1250`).
//!
//! This test spins up three real `WebsocketNetwork`s connected over loopback
//! (mirroring `message_filter_wiring.rs`'s harness): a relay hub `A` with two
//! participants `B` and `C` dialing in. `B` sends a large `TX`-tagged
//! message to `A`. Proving the send-side fix requires showing that `A`
//! broadcasts a real `MsgDigestSkip` message to `C` (excluding `B`, the
//! original sender) — observed here by checking that `C`'s own
//! `outgoing_message_filter` ends up containing the message's digest, which
//! is exactly the effect a received `MsgDigestSkip` has (issue #789's
//! `ws_peer.rs` receive-side handling, exercised over the real wire on `C`'s
//! dial-path connection to `A`).
//!
//! Before the fix, `A` never sends anything beyond forwarding the `TX`
//! itself, so `C`'s outgoing filter never contains the digest and this test
//! fails.

use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_network::message_filter::{generate_message_digest, MESSAGE_FILTER_SIZE};
use algo_network::peer_role::RELAY_ROLE;
use algo_network::phonebook::Phonebook;
use algo_network::tag::Tag;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::GossipNode;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=info,msg_digest_skip_broadcast=debug")
        .with_test_writer()
        .try_init();
}

/// Build one loopback `WebsocketNetwork`. `relay` controls whether it binds
/// a listener (so other nodes can dial it).  Both incoming and outgoing
/// message filtering are left at their defaults
/// (`enable_outgoing_network_message_filtering` defaults to `true`, matching
/// go), since this test is specifically about the outgoing/send-side path.
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
        // Long mesh interval — connectivity is driven explicitly by the test
        // via `request_connect_outgoing`, matching `message_filter_wiring.rs`.
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

#[tokio::test]
async fn hub_broadcasts_digest_skip_to_other_peers_after_processing_large_tx() {
    init_tracing();

    // Node A: relay hub that both B and C dial into.
    let net_a = build_node(true);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    // Node B: sends the large TX message.
    let net_b = build_node(false);
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;

    // Node C: the "other peer" that should receive A's MsgDigestSkip.
    let net_c = build_node(false);
    point_at(&net_c, &a_addr);
    net_c.start_arc().await.expect("node C start");
    net_c.request_connect_outgoing(false).await;

    // A should see both B and C connected (accept path, both inbound).
    wait_for_peer_count(&net_a, 2).await;
    wait_for_peer_count(&net_b, 1).await;
    wait_for_peer_count(&net_c, 1).await;

    // B broadcasts a large (>= MESSAGE_FILTER_SIZE) TX-tagged message. Its
    // only peer is A, so this arrives on A's real accepted connection to B.
    let payload = vec![0xEF_u8; MESSAGE_FILTER_SIZE];
    net_b
        .broadcast(Tag::Transaction, payload.clone(), true, None)
        .await
        .expect("broadcast should succeed");

    // Give A time to process the message and broadcast MsgDigestSkip to C,
    // and C time to receive and apply it to its outgoing filter.
    let digest = generate_message_digest(&Tag::Transaction, &payload);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline {
        if let Some(filter) = net_c.outgoing_message_filter() {
            // `add=false` — just check, don't mutate the filter, so a
            // retry loop iteration doesn't corrupt the result.
            if filter.check_digest(&digest, false, false) {
                seen = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    net_b.stop().await;
    net_c.stop().await;
    net_a.stop().await;

    assert!(
        seen,
        "node C's outgoing_message_filter should contain the digest of the \
         large TX message B sent to A: A should have broadcast a real \
         MsgDigestSkip notification to C (its other connected peer, \
         excluding B, the original sender) after processing B's message, \
         mirroring go's sendFilterMessage()"
    );
}
