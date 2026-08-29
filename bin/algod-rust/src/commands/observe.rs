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

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use algo_network::{
    Discovery, GossipNode, HickorySrvResolver, IncomingMessage, MessageHandler, OutgoingMessage,
    Phonebook, Tag, TaggedMessageHandler, WebsocketNetwork, WebsocketNetworkConfig,
    DEFAULT_GOSSIP_FANOUT,
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
    // When explicit relay addresses are provided, ensure gossip_fanout is at
    // least as large as the number of addresses so that start_arc() dials all
    // of them instead of silently ignoring extras beyond the default fanout.
    let fanout = if relay_addrs.is_empty() {
        DEFAULT_GOSSIP_FANOUT
    } else {
        relay_addrs.len().max(DEFAULT_GOSSIP_FANOUT)
    };
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: network.to_string(),
        gossip_fanout: fanout,
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
