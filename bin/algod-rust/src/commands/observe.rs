use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use algo_network::{
    Discovery, GossipNode, HickorySrvResolver, IncomingMessage, MessageHandler, OutgoingMessage,
    Phonebook, Tag, TaggedMessageHandler, WebsocketNetwork, WebsocketNetworkConfig,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use tracing::info;

use crate::commands::network_common::{genesis_id_for, DNS_BOOTSTRAP_TEMPLATE};

// ---------------------------------------------------------------------------
// Catch-all message handler: logs every message as JSON
// ---------------------------------------------------------------------------

/// Handler that prints a structured JSON line for every incoming gossip message.
struct ObserveHandler;

#[async_trait]
impl MessageHandler for ObserveHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let tag_str = msg.tag.as_str();
        let size = msg.data.len();
        let sender = &msg.sender;
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let line = json!({
            "timestamp": now,
            "tag": tag_str,
            "from": sender,
            "size": size,
        });

        // Write to stdout with explicit flush to avoid tracing intermixing.
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        let _ = writeln!(handle, "{}", line);
        let _ = handle.flush();

        OutgoingMessage {
            action: algo_network::ForwardingPolicy::Ignore,
            tag: msg.tag,
            payload: Vec::new(),
            topics: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// Run the observe command: connect to relay peers and log all gossip messages.
pub async fn run(
    network: &str,
    relay_addrs: &[String],
    genesis_id_override: Option<&str>,
    dns_bootstrap_override: Option<&str>,
) -> anyhow::Result<()> {
    // Resolve genesis ID.
    let genesis_id = genesis_id_override
        .or_else(|| genesis_id_for(network))
        .unwrap_or("");
    if genesis_id.is_empty() {
        anyhow::bail!(
            "unknown network '{}': use --genesis-id to specify the genesis ID",
            network
        );
    }

    info!(
        network = network,
        genesis_id = genesis_id,
        relay_count = relay_addrs.len(),
        "starting observe mode"
    );

    // Build phonebook and populate with any explicit relay addresses.
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));

    if !relay_addrs.is_empty() {
        phonebook.replace_peer_list(relay_addrs, "cli", algo_network::RELAY_ROLE);
        info!(count = relay_addrs.len(), "added CLI relay addresses");
    }

    // If no explicit relays were given, do DNS discovery.
    if relay_addrs.is_empty() {
        let dns_template = dns_bootstrap_override.unwrap_or(DNS_BOOTSTRAP_TEMPLATE);
        let resolver = Box::new(HickorySrvResolver::new(None));
        let discovery = Discovery::new(
            phonebook.clone(),
            resolver,
            dns_template,
            network,
            dns_bootstrap_override.is_some(),
        )?;
        discovery.refresh_phonebook_addresses().await;
        info!("DNS discovery complete");
    }

    // Build network config.
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: network.to_string(),
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // Register a catch-all handler for every active tag.
    let handler: Arc<dyn MessageHandler> = Arc::new(ObserveHandler);
    let handlers: Vec<TaggedMessageHandler> = Tag::ACTIVE_TAGS
        .iter()
        .map(|&tag| TaggedMessageHandler {
            tag,
            handler: handler.clone(),
        })
        .collect();
    net.register_handlers(handlers);

    // Start the network (with background mesh + monitor tasks).
    net.start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    info!("observe mode active — press Ctrl+C to stop");

    // Wait for Ctrl+C.
    tokio::signal::ctrl_c().await?;

    info!("shutting down...");
    net.stop().await;

    Ok(())
}
