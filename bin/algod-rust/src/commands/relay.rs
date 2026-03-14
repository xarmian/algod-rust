use std::sync::Arc;
use std::time::Duration;

use algo_network::{
    BlockService, BlockServiceError, GossipNode, LedgerForBlockService, Phonebook,
    WebsocketNetwork, WebsocketNetworkConfig, RELAY_ROLE,
};
use tracing::info;

use crate::commands::network_common::genesis_id_for;

// ---------------------------------------------------------------------------
// Stub ledger — returns "not available" for every round
// ---------------------------------------------------------------------------

/// A no-op ledger that always reports round 0 and has no blocks.
///
/// Used to wire up the `BlockService` HTTP handler before a real ledger
/// integration is available.
struct StubLedger;

impl LedgerForBlockService for StubLedger {
    fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
        Err(BlockServiceError::BlockNotAvailable {
            round,
            latest_round: Some(0),
        })
    }

    fn latest_round(&self) -> u64 {
        0
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// Run the relay command: start a relay node that listens for inbound
/// connections and forwards gossip messages.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    bind_address: &str,
    genesis_id: &str,
    network: &str,
    peers: &[String],
    incoming_limit: u32,
    max_per_ip: u32,
    rate_limit: u32,
    broadcast_limit: u32,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    mem_cap_mb: u64,
) -> anyhow::Result<()> {
    // Resolve genesis ID: use the provided value, or look it up by network name.
    let resolved_genesis_id = if genesis_id.is_empty() {
        genesis_id_for(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network '{}': use --genesis-id to specify the genesis ID",
                    network
                )
            })?
            .to_string()
    } else {
        genesis_id.to_string()
    };

    let mem_cap = mem_cap_mb * 1024 * 1024;

    info!(
        bind = bind_address,
        genesis_id = %resolved_genesis_id,
        network = network,
        incoming_limit = incoming_limit,
        max_per_ip = max_per_ip,
        rate_limit = rate_limit,
        broadcast_limit = broadcast_limit,
        mem_cap_mb = mem_cap_mb,
        peers = peers.len(),
        "starting relay node"
    );

    // Build phonebook and seed with any initial peer addresses.
    let phonebook = Arc::new(Phonebook::new(rate_limit as usize, Duration::from_secs(60)));

    if !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    }

    // Build network config with relay mode enabled.
    let config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: Some(bind_address.to_string()),
        relay_messages: true,
        incoming_connections_limit: incoming_limit,
        max_connections_per_ip: max_per_ip,
        connections_rate_limiting_count: rate_limit,
        broadcast_connections_limit: broadcast_limit,
        tls_cert_file: tls_cert.map(|s| s.to_string()),
        tls_key_file: tls_key.map(|s| s.to_string()),
        block_service_mem_cap: mem_cap,
        gossip_fanout: if peers.is_empty() {
            algo_network::DEFAULT_GOSSIP_FANOUT
        } else {
            peers.len().max(algo_network::DEFAULT_GOSSIP_FANOUT)
        },
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // Register the block service HTTP handler (stub ledger for now).
    let ledger: Arc<dyn LedgerForBlockService> = Arc::new(StubLedger);
    let block_service = BlockService::new(ledger, resolved_genesis_id.clone(), mem_cap);
    net.register_http_handler("/", block_service.http_router());

    // Start the network (listener + mesh + monitor tasks).
    net.start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let (addr, listening) = net.address();
    if listening {
        info!(address = %addr, "relay node listening");
    } else {
        info!("relay node started (no listener)");
    }

    info!(
        genesis_id = %resolved_genesis_id,
        "relay node active — press Ctrl+C to stop"
    );

    // Wait for Ctrl+C.
    tokio::signal::ctrl_c().await?;

    info!("shutting down relay node...");
    net.stop().await;
    info!("relay node stopped");

    Ok(())
}
