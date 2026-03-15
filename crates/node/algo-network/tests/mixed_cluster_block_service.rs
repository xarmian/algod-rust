//! Mixed-cluster conformance tests for block serving and message relay.
//!
//! These tests validate that a Rust relay node can serve blocks to a Go
//! non-relay node and forward gossip messages in a mixed Go/Rust cluster.
//!
//! # Topology (from docker-compose.mixed-cluster.yml)
//!
//! ```text
//!   go-relay (4001/REST, 4161/gossip)  -->  block producer
//!   rust-relay (4160/gossip)           -->  connects to go-relay, serves blocks
//!   go-nonrelay (4002/REST)            -->  bootstraps against rust-relay
//!   txn-generator                      -->  sends transactions to go-relay
//! ```
//!
//! # Running
//!
//! ```bash
//! docker compose -f docker/docker-compose.mixed-cluster.yml up -d
//! # Wait for services to be healthy, then:
//! MIXED_CLUSTER=1 cargo test -p algo-network --test mixed_cluster_block_service -- --ignored --nocapture
//! ```
//!
//! All tests are `#[ignore]` by default since they require a running cluster.

mod test_helpers;

use std::time::Duration;

use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("mixed_cluster_block_service=debug")
        .with_test_writer()
        .try_init();
}

// ---------------------------------------------------------------------------
// Test 1: Go non-relay syncs blocks via the Rust relay (deliverable 4)
// ---------------------------------------------------------------------------

/// Verify that the Go non-relay node can fetch blocks from the Rust relay.
///
/// The go-nonrelay node is configured to bootstrap against rust-relay.
/// We poll its `/v2/status` endpoint until it advances past round 5,
/// confirming that blocks are flowing through the Rust relay.
#[tokio::test]
#[ignore = "requires mixed cluster: docker compose -f docker/docker-compose.mixed-cluster.yml up -d"]
async fn test_go_fetches_block_from_rust_relay() {
    init_tracing();
    skip_unless_mixed_cluster!();

    let client = test_helpers::algod_client();
    let go_relay_rest = test_helpers::go_relay_rest_addr();
    let go_nonrelay_rest = test_helpers::go_nonrelay_rest_addr();

    // First verify the Go relay is producing blocks.
    let relay_status = test_helpers::get_status(&client, &go_relay_rest)
        .await
        .expect("go-relay should be reachable");
    let relay_round =
        test_helpers::extract_last_round(&relay_status).expect("go-relay should report last-round");
    eprintln!("go-relay is at round {relay_round}");

    // Now poll the Go non-relay node until it syncs past round 5.
    // This proves blocks are flowing: go-relay -> rust-relay -> go-nonrelay.
    let target_round = 5u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    loop {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "go-nonrelay did not reach round {target_round} within 60s — \
                 block serving via rust-relay may be broken"
            );
        }

        match test_helpers::get_status(&client, &go_nonrelay_rest).await {
            Ok(status) => {
                if let Some(round) = test_helpers::extract_last_round(&status) {
                    eprintln!("go-nonrelay at round {round}");
                    if round >= target_round {
                        eprintln!(
                            "go-nonrelay reached round {round} (>= {target_round}) — \
                             block serving via rust-relay confirmed"
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("go-nonrelay not ready yet: {e}");
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// ---------------------------------------------------------------------------
// Test 2: Rust relay forwards gossip messages (deliverable 7)
// ---------------------------------------------------------------------------

/// Connect a WebSocket client to the Rust relay, subscribe via MsgOfInterest,
/// and verify that gossip messages (proposals, votes) are forwarded.
///
/// This confirms the Rust relay is receiving messages from the Go relay and
/// forwarding them to connected peers.
#[tokio::test]
#[ignore = "requires mixed cluster: docker compose -f docker/docker-compose.mixed-cluster.yml up -d"]
async fn test_rust_relay_forwards_messages() {
    init_tracing();
    skip_unless_mixed_cluster!();

    use algo_network::connect::{try_connect, ConnectConfig};
    use algo_network::message::OutgoingMessage;
    use algo_network::msg_of_interest::marshal_msg_of_interest;
    use algo_network::peer_features::PeerFeatureFlags;
    use algo_network::tag::Tag;
    use ed25519_dalek::SigningKey;

    // Discover genesis ID from go-relay REST API.
    let client = test_helpers::algod_client();
    let go_relay_rest = test_helpers::go_relay_rest_addr();
    let rust_relay_gossip = test_helpers::rust_relay_gossip_addr();
    let rust_relay_host_port = rust_relay_gossip
        .strip_prefix("ws://")
        .unwrap_or(&rust_relay_gossip);

    let genesis_url = format!("{go_relay_rest}/genesis");
    let genesis_id = match client.get(&genesis_url).send().await {
        Ok(resp) => {
            let text = resp.text().await.unwrap_or_default();
            serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                .unwrap_or_else(|| "v1".to_string())
        }
        Err(_) => "v1".to_string(),
    };
    eprintln!("using genesis_id: {genesis_id}");

    // Generate a random signing key.
    let mut key_bytes = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let config = ConnectConfig {
        genesis_id,
        node_random: rand::random(),
        our_identity_key: Some(signing_key),
        our_address: None,
        instance_name: "mixed-cluster-test".to_string(),
        location: String::new(),
        telemetry_id: String::new(),
        our_features: PeerFeatureFlags::COMPRESSED_PROPOSAL,
        handshake_timeout: Duration::from_secs(15),
        peer_config: None,
    };

    let mut handle = try_connect(rust_relay_host_port, &config)
        .await
        .expect("should connect to rust-relay via WebSocket");

    eprintln!(
        "connected to rust-relay, negotiated protocol {}",
        handle.version()
    );

    // Send MsgOfInterest for all active tags so the relay forwards us messages.
    let all_tags = Tag::active_tags();
    let mi_payload = marshal_msg_of_interest(&all_tags);
    let mi_msg = OutgoingMessage::new(Tag::MsgOfInterest, mi_payload);
    handle
        .send_priority(mi_msg)
        .expect("should send MsgOfInterest");

    // Wait for gossip messages from the Rust relay. In a dev-mode network
    // with transactions being generated, we should see proposals or votes.
    let mut received_count = 0u32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, handle.recv()).await {
            Ok(Some(msg)) => {
                received_count += 1;
                eprintln!(
                    "received message #{received_count}: tag={}, len={}",
                    msg.tag,
                    msg.data.len()
                );
                // Once we have a few messages, we have confirmed forwarding works.
                if received_count >= 3 {
                    break;
                }
            }
            Ok(None) => {
                eprintln!("peer channel closed");
                break;
            }
            Err(_) => {
                eprintln!("timeout waiting for messages");
                break;
            }
        }
    }

    assert!(
        received_count > 0,
        "should have received at least one forwarded message from rust-relay; \
         got {received_count}. The Rust relay may not be forwarding gossip."
    );
    eprintln!("received {received_count} forwarded messages — relay forwarding confirmed");

    handle.close();
}

// ---------------------------------------------------------------------------
// Test 3: Block content consistency across the relay path
// ---------------------------------------------------------------------------

/// Fetch a block from go-relay and from go-nonrelay (which received it via
/// rust-relay) and verify they have identical content.
///
/// This validates end-to-end block integrity through the Rust relay.
#[tokio::test]
#[ignore = "requires mixed cluster: docker compose -f docker/docker-compose.mixed-cluster.yml up -d"]
async fn test_block_content_consistency() {
    init_tracing();
    skip_unless_mixed_cluster!();

    let client = test_helpers::algod_client();
    let go_relay_rest = test_helpers::go_relay_rest_addr();
    let go_nonrelay_rest = test_helpers::go_nonrelay_rest_addr();

    // Wait until go-nonrelay has synced to at least round 3 so we have
    // a block that both nodes should have.
    let target_round = 3u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    let nonrelay_round = loop {
        if tokio::time::Instant::now() > deadline {
            panic!("go-nonrelay did not reach round {target_round} within 60s");
        }

        match test_helpers::get_status(&client, &go_nonrelay_rest).await {
            Ok(status) => {
                if let Some(round) = test_helpers::extract_last_round(&status) {
                    if round >= target_round {
                        break round;
                    }
                    eprintln!("go-nonrelay at round {round}, waiting for {target_round}...");
                }
            }
            Err(e) => {
                eprintln!("go-nonrelay not ready: {e}");
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // Pick a round that both nodes definitely have.
    let compare_round = target_round.min(nonrelay_round);
    eprintln!("comparing block at round {compare_round}");

    // Fetch the same block from both nodes.
    let block_from_relay = test_helpers::get_block(&client, &go_relay_rest, compare_round)
        .await
        .expect("should fetch block from go-relay");

    let block_from_nonrelay = test_helpers::get_block(&client, &go_nonrelay_rest, compare_round)
        .await
        .expect("should fetch block from go-nonrelay");

    // Compare round numbers.
    let relay_rnd = block_from_relay
        .pointer("/block/rnd")
        .and_then(|v| v.as_u64());
    let nonrelay_rnd = block_from_nonrelay
        .pointer("/block/rnd")
        .and_then(|v| v.as_u64());

    assert_eq!(
        relay_rnd, nonrelay_rnd,
        "block round should match: relay={relay_rnd:?} vs nonrelay={nonrelay_rnd:?}"
    );
    eprintln!("round matches: {relay_rnd:?}");

    // Compare block hashes. The REST API returns the block hash in the
    // response. Check common field names used by the Algorand REST API.
    let relay_hash = block_from_relay
        .pointer("/block/prev")
        .or_else(|| block_from_relay.get("hash"));
    let nonrelay_hash = block_from_nonrelay
        .pointer("/block/prev")
        .or_else(|| block_from_nonrelay.get("hash"));

    if let (Some(rh), Some(nh)) = (relay_hash, nonrelay_hash) {
        assert_eq!(
            rh, nh,
            "block prev-hash should match: relay={rh} vs nonrelay={nh}"
        );
        eprintln!("prev-hash matches");
    }

    // Compare genesis ID in the block.
    let relay_gen = block_from_relay.pointer("/block/gen");
    let nonrelay_gen = block_from_nonrelay.pointer("/block/gen");
    if let (Some(rg), Some(ng)) = (relay_gen, nonrelay_gen) {
        assert_eq!(
            rg, ng,
            "genesis ID in block should match: relay={rg} vs nonrelay={ng}"
        );
        eprintln!("genesis ID matches: {rg}");
    }

    // Compare genesis hash.
    let relay_gh = block_from_relay.pointer("/block/gh");
    let nonrelay_gh = block_from_nonrelay.pointer("/block/gh");
    if let (Some(rgh), Some(ngh)) = (relay_gh, nonrelay_gh) {
        assert_eq!(
            rgh, ngh,
            "genesis hash in block should match: relay={rgh} vs nonrelay={ngh}"
        );
        eprintln!("genesis hash matches");
    }

    // Compare transaction root (tc) if present.
    let relay_tc = block_from_relay.pointer("/block/tc");
    let nonrelay_tc = block_from_nonrelay.pointer("/block/tc");
    if let (Some(rtc), Some(ntc)) = (relay_tc, nonrelay_tc) {
        assert_eq!(
            rtc, ntc,
            "txn commitment should match: relay={rtc} vs nonrelay={ntc}"
        );
        eprintln!("txn commitment matches");
    }

    eprintln!(
        "block content at round {compare_round} is consistent across \
         go-relay and go-nonrelay (via rust-relay)"
    );
}
