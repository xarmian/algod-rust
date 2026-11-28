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

//! go v5.1.1 `Relay` sends the `MsgDigestSkip` filter message of a relayed
//! proposal payload (`msgHandler.sendRelayFilterMessage`,
//! `network/wsNetwork.go`; `network/p2pNetwork.go`), computed over the
//! uncompressed payload: `messageHandlerThread` skips PP because the payload
//! is still compressed when it arrives. A node that does not relay messages
//! sends it too, since `Relay` calls it before checking `relayMessages`.
//!
//! Here a relay hub `A` with peers `B` and `C` relays a large PP; both peers'
//! per-connection outgoing filters must then hold the digest of the payload.

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
        .with_env_filter("algo_network=info,relay_proposal_filter_message=debug")
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
async fn relay_of_large_proposal_sends_digest_skip_to_peers() {
    init_tracing();
    let net_a = build_node(true);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, _) = net_a.address();

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

    // the digest of the *uncompressed* payload
    let payload = vec![0xAB_u8; MESSAGE_FILTER_SIZE];
    let digest = generate_message_digest(&Tag::ProposalPayload, &payload);
    net_a
        .relay(Tag::ProposalPayload, payload, false, None)
        .await
        .expect("relay");

    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut b_seen, mut c_seen) = (false, false);
    while Instant::now() < deadline && !(b_seen && c_seen) {
        for (net, seen) in [(&net_b, &mut b_seen), (&net_c, &mut c_seen)] {
            if let Some(f) = net.peer_outgoing_message_filter(&a_addr).await {
                if f.check_digest(&digest, false, false) {
                    *seen = true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    net_b.stop().await;
    net_c.stop().await;
    net_a.stop().await;
    assert!(b_seen && c_seen, "b={b_seen} c={c_seen}");
}

/// A node with `relay_messages` off still sends the filter message (go's
/// `Relay` calls `sendRelayFilterMessage` before checking `relayMessages`).
#[tokio::test]
async fn non_relaying_node_sends_the_filter_message_too() {
    init_tracing();
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        relay_messages: false,
        gossip_fanout: 2,
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let net_a = Arc::new(WebsocketNetwork::new(config, phonebook));
    net_a.start_arc().await.expect("node A start");
    let (a_addr, _) = net_a.address();
    let net_b = build_node(false);
    point_at(&net_b, &a_addr);
    net_b.start_arc().await.expect("node B start");
    net_b.request_connect_outgoing(false).await;
    wait_for_peer_count(&net_b, 1).await;
    wait_for_peer_count(&net_a, 1).await;

    let payload = vec![0xCD_u8; MESSAGE_FILTER_SIZE + 1];
    let digest = generate_message_digest(&Tag::ProposalPayload, &payload);
    net_a
        .relay(Tag::ProposalPayload, payload, false, None)
        .await
        .expect("relay");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        if let Some(f) = net_b.peer_outgoing_message_filter(&a_addr).await {
            seen = f.check_digest(&digest, false, false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    net_b.stop().await;
    net_a.stop().await;
    assert!(seen);
}

/// go v5.1.1 `TestDupFilter` now uses `VoteBundleTag` as its large tag: the
/// network sends a filter message for every large message as it arrives except
/// a proposal payload (`messageHandlerThread`), not only for `AV`/`TX`.
#[tokio::test]
async fn large_vote_bundle_triggers_a_filter_message_to_the_other_peers() {
    init_tracing();
    let net_a = build_node(true);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, _) = net_a.address();
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

    let payload = vec![0x5A_u8; MESSAGE_FILTER_SIZE];
    let digest = generate_message_digest(&Tag::VoteBundle, &payload);
    net_b
        .broadcast(Tag::VoteBundle, payload, true, None)
        .await
        .expect("broadcast");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        if let Some(f) = net_c.peer_outgoing_message_filter(&a_addr).await {
            seen = f.check_digest(&digest, false, false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    net_b.stop().await;
    net_c.stop().await;
    net_a.stop().await;
    assert!(
        seen,
        "C never received A's filter message for the vote bundle"
    );
}
