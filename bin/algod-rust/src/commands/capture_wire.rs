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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use algo_network::{
    GossipNode, IncomingMessage, MessageHandler, OutgoingMessage, Phonebook, Tag,
    TaggedMessageHandler, WebsocketNetwork, WebsocketNetworkConfig, DEFAULT_GOSSIP_FANOUT,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Manifest entry
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct ManifestEntry {
    filename: String,
    tag: String,
    size: usize,
    timestamp: String,
    sequence: u64,
}

// ---------------------------------------------------------------------------
// Capture handler: saves each raw message to disk
// ---------------------------------------------------------------------------

struct CaptureHandler {
    output_dir: PathBuf,
    sequence: AtomicU64,
    manifest: Mutex<Vec<ManifestEntry>>,
    captured: AtomicU64,
    max_count: u64,
    /// Notify the main loop that we've reached the capture limit.
    done_tx: tokio::sync::watch::Sender<bool>,
}

#[async_trait]
impl MessageHandler for CaptureHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let already = self.captured.fetch_add(1, Ordering::Relaxed);
        if already >= self.max_count {
            // Already at limit — don't save more.
            return OutgoingMessage {
                action: algo_network::ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            };
        }

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let tag_str = msg.tag.as_str();
        let now = Utc::now();
        let ts = now.format("%Y%m%dT%H%M%S%.3fZ").to_string();
        let filename = format!("{}_{ts}_{seq}.bin", tag_str.trim());
        let filepath = self.output_dir.join(&filename);
        let size = msg.data.len();

        // Write the raw payload (without the 2-byte tag prefix) to disk.
        if let Err(e) = tokio::fs::write(&filepath, &msg.data).await {
            warn!(path = %filepath.display(), error = %e, "failed to write wire fixture");
        } else {
            info!(tag = tag_str, size, seq, file = %filepath.display(), "captured message");
        }

        // Record in manifest.
        {
            let entry = ManifestEntry {
                filename,
                tag: tag_str.to_string(),
                size,
                timestamp: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                sequence: seq,
            };
            self.manifest.lock().await.push(entry);
        }

        // Signal done if we've reached the limit.
        if already + 1 >= self.max_count {
            let _ = self.done_tx.send(true);
        }

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

/// Run the capture-wire command: connect to a relay and save raw gossip
/// messages to disk for offline regression testing.
pub async fn run(
    relay_addr: &str,
    output_dir: &Path,
    max_count: u64,
    max_duration_secs: u64,
    genesis_id_override: Option<&str>,
) -> anyhow::Result<()> {
    // Resolve genesis ID — fall back to mainnet if not provided.
    let genesis_id = genesis_id_override.unwrap_or("mainnet-v1.0");

    info!(
        relay = relay_addr,
        output = %output_dir.display(),
        max_count,
        max_duration_secs,
        genesis_id,
        "starting wire capture"
    );

    // Create output directory.
    tokio::fs::create_dir_all(output_dir).await?;

    // Build phonebook with the single relay address.
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    phonebook.replace_peer_list(&[relay_addr.to_string()], "cli", algo_network::RELAY_ROLE);

    // Network config.
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: "custom".to_string(),
        gossip_fanout: DEFAULT_GOSSIP_FANOUT,
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // Done channel — used by the handler to signal we've captured enough.
    let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);

    let handler = Arc::new(CaptureHandler {
        output_dir: output_dir.to_path_buf(),
        sequence: AtomicU64::new(0),
        manifest: Mutex::new(Vec::new()),
        captured: AtomicU64::new(0),
        max_count,
        done_tx,
    });

    // Register the handler for every active tag.
    let msg_handler: Arc<dyn MessageHandler> = handler.clone();
    let handlers: Vec<TaggedMessageHandler> = Tag::ACTIVE_TAGS
        .iter()
        .map(|&tag| TaggedMessageHandler {
            tag,
            handler: msg_handler.clone(),
        })
        .collect();
    net.register_handlers(handlers);

    // Start the network.
    net.start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    info!("connected — capturing messages (Ctrl+C to stop early)");

    // Wait until either:
    //  1. max_count messages captured
    //  2. duration timeout
    //  3. Ctrl+C
    let duration = Duration::from_secs(max_duration_secs);
    tokio::select! {
        _ = done_rx.wait_for(|&v| v) => {
            info!("reached message count limit ({})", max_count);
        }
        _ = tokio::time::sleep(duration) => {
            info!("reached duration limit ({max_duration_secs}s)");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("interrupted by user");
        }
    }

    // Write manifest.
    let manifest_path = output_dir.join("manifest.json");
    let entries = handler.manifest.lock().await;
    let manifest = json!({
        "relay_addr": relay_addr,
        "genesis_id": genesis_id,
        "captured_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "message_count": entries.len(),
        "messages": *entries,
    });
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    tokio::fs::write(&manifest_path, manifest_json).await?;

    info!(
        count = entries.len(),
        manifest = %manifest_path.display(),
        "wire capture complete"
    );

    // Shut down.
    net.stop().await;

    Ok(())
}
