use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_ledger::{LedgerStore, SqliteLedger};
use algo_network::{
    Discovery, GossipNode, HickorySrvResolver, Phonebook, WebsocketNetwork, WebsocketNetworkConfig,
    RELAY_ROLE,
};
use algo_rest_client::{AlgodClient, BlockSource, GossipBlockSource, ParallelBlockFetcher};
use algo_types::Round;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::commands::network_common::{genesis_id_for, DNS_BOOTSTRAP_TEMPLATE};

// ---------------------------------------------------------------------------
// FallbackBlockSource — tries gossip, then REST
// ---------------------------------------------------------------------------

/// A [`BlockSource`] wrapper that tries gossip first, then falls back to REST.
///
/// On each block request, the gossip peers are obtained dynamically from the
/// [`WebsocketNetwork`] via [`get_unicast_peers()`], so the set of peers
/// automatically reflects any connections established (or dropped) by the
/// background [`MeshThread`].  This avoids creating a static peer list at
/// construction time and eliminates the double-dial race where manually
/// connected handles conflict with mesh-managed connections.
///
/// This enables `ParallelBlockFetcher` to transparently retry failed gossip
/// fetches via the REST API, so that a single-round gossip failure does not
/// cancel the entire batch pipeline.
struct FallbackBlockSource {
    ws_network: Arc<WebsocketNetwork>,
    rest: Arc<AlgodClient>,
}

#[async_trait]
impl BlockSource for FallbackBlockSource {
    async fn get_block_raw(&self, round: Round) -> algo_error::Result<Vec<u8>> {
        let peers = self.ws_network.get_unicast_peers().await;
        if !peers.is_empty() {
            let gossip = GossipBlockSource::new(peers);
            match gossip.get_block_raw(round).await {
                Ok(raw) => return Ok(raw),
                Err(_gossip_err) => {
                    debug!(
                        round = round.0,
                        "gossip get_block_raw failed, falling back to REST"
                    );
                }
            }
        }
        self.rest.get_block_raw(round).await
    }

    async fn get_block(&self, round: Round) -> algo_error::Result<algo_types::BlockResponse> {
        let peers = self.ws_network.get_unicast_peers().await;
        if !peers.is_empty() {
            let gossip = GossipBlockSource::new(peers);
            match gossip.get_block(round).await {
                Ok(block) => return Ok(block),
                Err(_gossip_err) => {
                    debug!(
                        round = round.0,
                        "gossip get_block failed, falling back to REST"
                    );
                }
            }
        }
        self.rest.get_block(round).await
    }

    async fn get_status(&self) -> algo_error::Result<algo_rest_client::NodeStatus> {
        // Delegate status to REST — gossip source has only synthetic status.
        self.rest.get_status().await
    }

    async fn wait_for_round(
        &self,
        round: Round,
    ) -> algo_error::Result<algo_rest_client::NodeStatus> {
        self.rest.wait_for_round(round).await
    }
}

// ---------------------------------------------------------------------------
// Gossip network setup
// ---------------------------------------------------------------------------

/// Set up gossip networking: discover relay peers, start the
/// [`WebsocketNetwork`] (which spawns a [`MeshThread`] to dial peers), and
/// return the network handle.
///
/// The returned [`WebsocketNetwork`] provides dynamic access to connected
/// peers via [`get_unicast_peers()`]; the [`FallbackBlockSource`] uses this
/// on every block request so the peer set automatically reflects mesh changes.
///
/// Connection establishment is entirely delegated to the `MeshThread` — no
/// manual `try_connect` / `add_peer` calls are made here, avoiding the
/// double-dial race where manually-added peers conflict with mesh-managed ones.
async fn setup_gossip_network(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    genesis_id_override: Option<&str>,
    relay_addrs_cli: &[String],
) -> anyhow::Result<Arc<WebsocketNetwork>> {
    // Resolve genesis ID for WS handshake:
    // 1. Explicit --genesis-id override
    // 2. Well-known network name lookup
    // 3. Query the algod REST endpoint
    let genesis_id: String = if let Some(id) = genesis_id_override {
        id.to_string()
    } else if let Some(id) = genesis_id_for(network) {
        id.to_string()
    } else {
        info!("unknown network '{network}', querying algod REST endpoint for genesis ID");
        fetch_genesis_id(algod_url, algod_token).await?
    };
    if genesis_id.is_empty() {
        anyhow::bail!(
            "could not determine genesis ID for network '{network}'; \
             use --genesis-id to specify it explicitly"
        );
    }

    info!(
        network,
        genesis_id, "setting up gossip network for block sync"
    );

    // Build phonebook and populate via DNS discovery or explicit CLI relay addrs.
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));

    if !relay_addrs_cli.is_empty() {
        // Explicit --relay-addr flags take priority; skip DNS discovery.
        phonebook.replace_peer_list(relay_addrs_cli, "cli", RELAY_ROLE);
        info!(count = relay_addrs_cli.len(), "added CLI relay addresses");
    } else if matches!(network, "mainnet" | "testnet" | "devnet" | "betanet") {
        // Known networks: discover relay peers via DNS SRV.
        let resolver = Box::new(HickorySrvResolver::new(None));
        let discovery = Discovery::new(
            phonebook.clone(),
            resolver,
            DNS_BOOTSTRAP_TEMPLATE,
            network,
            false,
        )?;
        discovery.refresh_phonebook_addresses().await;
        info!("DNS discovery complete");
    } else {
        // Custom network with no explicit relay addresses — try to derive a
        // peer address from the algod REST URL so we have *something* to dial.
        if let Some(host_port) = extract_host_port(algod_url) {
            warn!(
                addr = %host_port,
                "no --relay-addr provided for custom network; \
                 using algod URL as gossip peer (port may differ from actual gossip port)"
            );
            phonebook.replace_peer_list(&[host_port], "algod-url", RELAY_ROLE);
        } else {
            warn!(
                "gossip mode on custom network with no --relay-addr; \
                 use --relay-addr to specify relay peers for gossip"
            );
        }
    }

    // Get relay addresses from phonebook.
    let relay_addrs = phonebook.get_addresses(10, RELAY_ROLE);
    if relay_addrs.is_empty() {
        anyhow::bail!(
            "no relay peers found for gossip sync; \
             use --relay-addr to specify relay peers, or use a known network name"
        );
    }
    info!(count = relay_addrs.len(), "discovered relay peers");

    // Build WebsocketNetwork for mesh management and on_network_advance().
    let ws_config = WebsocketNetworkConfig {
        genesis_id: genesis_id.clone(),
        network_id: network.to_string(),
        ..Default::default()
    };
    let ws_network = Arc::new(WebsocketNetwork::new(ws_config, phonebook));

    // Start the network — this spawns the MeshThread which dials peers from
    // the phonebook, plus a peer monitor task.  All connection establishment
    // is handled by MeshThread; no manual try_connect calls are needed.
    ws_network
        .start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start WebsocketNetwork: {e}"))?;

    // Give the MeshThread a moment to establish initial connections before
    // block fetching begins.  The FallbackBlockSource will transparently
    // fall back to REST if gossip peers are not yet ready, so this is just
    // an optimistic warm-up.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let peer_count = ws_network.peer_count().await;
    info!(
        connected = peer_count,
        total = relay_addrs.len(),
        "gossip network started, MeshThread managing connections"
    );

    Ok(ws_network)
}

/// Run the sync command: fetch blocks in parallel and apply them to the ledger.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    genesis_path: Option<&Path>,
    db_path: &Path,
    start: u64,
    end: Option<u64>,
    concurrency: usize,
    avm_execute: bool,
    fail_fast: bool,
    trie: bool,
    gossip: bool,
    genesis_id_override: Option<&str>,
    relay_addrs: &[String],
) -> anyhow::Result<()> {
    let client = Arc::new(AlgodClient::new(algod_url, algod_token));

    // Open or create the SQLite ledger.
    let db_exists = db_path.exists();
    let mut store = SqliteLedger::open(db_path)?;

    let effective_start = if db_exists {
        if let Some(last_round) = store.last_committed_round()? {
            let resume = last_round + 1;
            info!(
                last_committed = last_round,
                resuming_from = resume,
                "resuming sync from existing DB"
            );
            resume
        } else {
            // DB exists but no committed round — stale/partial DB.
            warn!("existing DB has no committed round — recreating");
            drop(store);
            std::fs::remove_file(db_path)?;
            store = SqliteLedger::open(db_path)?;
            if start == 0 {
                load_genesis_into_store(&mut store, genesis_path)?;
                // Genesis populates round 0 state; start fetching from round 1.
                1
            } else {
                anyhow::bail!(
                    "cannot start sync at round {start} with a stale database; \
                     either use --start 0 with --genesis to initialize from genesis, \
                     or provide an existing DB that already has state"
                );
            }
        }
    } else if start == 0 {
        load_genesis_into_store(&mut store, genesis_path)?;
        // Genesis populates round 0 state; start fetching from round 1.
        1
    } else {
        anyhow::bail!(
            "cannot start sync at round {start} with a fresh database; \
             either use --start 0 with --genesis to initialize from genesis, \
             or provide an existing DB that already has state"
        );
    };

    // Enable Merkle trie tracking if requested.
    if trie {
        store.enable_trie();
        info!("Merkle trie tracking enabled");
    }

    // Determine target round (always via REST — gossip has no status endpoint).
    let target = match end {
        Some(e) => e,
        None => {
            let status = client.get_status().await?;
            info!(
                last_round = status.last_round,
                "fetched chain tip from node"
            );
            status.last_round
        }
    };

    if effective_start > target {
        info!(
            effective_start,
            target, "already past target round, nothing to sync"
        );
        return Ok(());
    }

    // Set up block source: gossip-first with REST fallback, or REST-only.
    let (block_source, ws_network): (Arc<dyn BlockSource>, Option<Arc<WebsocketNetwork>>) =
        if gossip {
            let ws_net = setup_gossip_network(
                network,
                algod_url,
                algod_token,
                genesis_id_override,
                relay_addrs,
            )
            .await?;
            let fallback: Arc<dyn BlockSource> = Arc::new(FallbackBlockSource {
                ws_network: Arc::clone(&ws_net),
                rest: Arc::clone(&client),
            });
            (fallback, Some(ws_net))
        } else {
            (Arc::clone(&client) as Arc<dyn BlockSource>, None)
        };

    let mode_str = if gossip { "gossip+REST" } else { "REST" };
    info!(
        network,
        algod_url,
        effective_start,
        target,
        concurrency,
        avm_execute,
        trie,
        fail_fast,
        mode = mode_str,
        db = %db_path.display(),
        "starting parallel block sync"
    );

    // Create parallel fetcher.
    let fetcher = ParallelBlockFetcher::new(block_source, concurrency);
    let cancel = CancellationToken::new();

    // fetch_range uses half-open [start, end), so add 1 to include the target round.
    let mut rx = fetcher.fetch_range(Round(effective_start), Round(target + 1), cancel.clone());

    let timer = Instant::now();
    let mut blocks_applied: u64 = 0;
    let mut blocks_failed: u64 = 0;
    let mut total_txns: u64 = 0;
    let mut eval_delta_stats = algo_ledger::EvalDeltaStats::default();
    let progress_interval: u64 = 1000;
    let mut last_received_round: Option<u64> = None;

    while let Some((round, block_resp)) = rx.recv().await {
        last_received_round = Some(round.0);
        let block = &block_resp.block;

        // Count transactions.
        total_txns += block.payset.len() as u64;

        // Apply block to ledger.
        store.begin_block()?;
        let apply_result = if avm_execute {
            let (result, block_stats) = algo_ledger::apply_block_with_comparison(&mut store, block);
            eval_delta_stats += block_stats;
            result
        } else {
            algo_ledger::apply_block(&mut store, block)
        };

        match apply_result {
            Ok(()) => {
                if trie {
                    store.finalize_trie_updates();
                }
                store.commit_block()?;
                blocks_applied += 1;

                // Signal the gossip network that we advanced, so mesh
                // maintenance can react (e.g. refresh peer connections).
                if let Some(ref net) = ws_network {
                    net.on_network_advance();
                }
            }
            Err(e) => {
                warn!(round = round.0, error = %e, "apply_block failed");
                let _ = store.rollback_block();
                blocks_failed += 1;
                if fail_fast {
                    error!(round = round.0, "fail-fast: stopping on apply failure");
                    cancel.cancel();
                    break;
                }
            }
        }

        // Progress logging.
        let blocks_done = blocks_applied + blocks_failed;
        if blocks_done % progress_interval == 0 || round.0 == target {
            let elapsed = timer.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                blocks_done as f64 / elapsed
            } else {
                0.0
            };
            info!(
                "Block {}/{} ({:.1}s, {:.1} blocks/sec)",
                round.0, target, elapsed, rate
            );
        }
    }

    // Shut down gossip network if we started one.
    if let Some(ref net) = ws_network {
        info!("stopping gossip network");
        net.stop().await;
    }

    // Check if the pipeline closed before we received the target round.
    // This distinguishes fetch failures from apply failures (which are tracked via blocks_failed).
    let pipeline_failed = match last_received_round {
        Some(r) if r >= target => false,
        _ if blocks_applied + blocks_failed == 0 && effective_start <= target => true,
        Some(_) => true, // last received round < target means pipeline stopped early
        None => effective_start <= target, // received nothing but had work to do
    };
    if pipeline_failed {
        error!("block fetch pipeline closed before reaching target round — sync incomplete");
        anyhow::bail!("block fetch pipeline failed");
    }

    let elapsed = timer.elapsed().as_secs_f64();
    let total_blocks = blocks_applied + blocks_failed;
    let blocks_per_sec = if elapsed > 0.0 {
        total_blocks as f64 / elapsed
    } else {
        0.0
    };

    // Print summary.
    println!("=== Sync Summary ===");
    println!("Network:          {network}");
    println!("Rounds:           {effective_start} - {target}");
    println!("Blocks applied:   {total_blocks} ({blocks_applied} passed, {blocks_failed} failed)");
    println!("Total txns:       {total_txns}");
    println!("Elapsed:          {elapsed:.1}s ({blocks_per_sec:.1} blocks/sec)");
    println!("Mode:             {mode_str}");

    if trie {
        println!("Trie enabled:     yes");
    }

    if avm_execute {
        eval_delta_stats.print_summary();
    }

    if blocks_failed > 0 {
        anyhow::bail!("{blocks_failed} blocks failed apply");
    }

    Ok(())
}

/// Extract "host:port" from a URL like "http://host:port/path".
///
/// Falls back to port 4160 if no port is present. Returns `None` if the URL
/// cannot be parsed.
fn extract_host_port(url: &str) -> Option<String> {
    // Strip scheme.
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ws://"))
        .or_else(|| url.strip_prefix("wss://"))?;

    // Take everything before the first '/'.
    let host_port = after_scheme.split('/').next()?;

    if host_port.is_empty() {
        return None;
    }

    // If no port, add default.
    if host_port.contains(':') {
        Some(host_port.to_string())
    } else {
        Some(format!("{host_port}:4160"))
    }
}

/// Fetch the genesis ID from an algod REST endpoint by querying `GET /genesis`.
///
/// The response is the full genesis JSON; we parse just the `"id"` field.
async fn fetch_genesis_id(algod_url: &str, algod_token: &str) -> anyhow::Result<String> {
    let url = format!("{}/genesis", algod_url.trim_end_matches('/'));
    let mut request = reqwest::Client::new().get(&url);
    if !algod_token.is_empty() {
        request = request.header("X-Algo-API-Token", algod_token);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch /genesis from {algod_url}: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "GET /genesis returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse /genesis JSON from {algod_url}: {e}"))?;
    let id = body["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("genesis JSON from {algod_url} has no 'id' field"))?;
    info!(genesis_id = id, "fetched genesis ID from REST endpoint");
    Ok(id.to_string())
}

/// Load genesis JSON and populate the store. Requires `--genesis` to be set.
fn load_genesis_into_store(
    store: &mut SqliteLedger,
    genesis_path: Option<&Path>,
) -> anyhow::Result<()> {
    let path = genesis_path.ok_or_else(|| {
        anyhow::anyhow!("--genesis is required when starting from round 0 without an existing DB")
    })?;
    let genesis_json = std::fs::read_to_string(path)?;
    let genesis = algo_ledger::parse_genesis_json(&genesis_json)?;
    algo_ledger::populate_store(store, &genesis)?;
    info!(genesis_path = %path.display(), "genesis loaded into ledger");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_port_http_with_port() {
        assert_eq!(
            extract_host_port("http://example.com:4001"),
            Some("example.com:4001".to_string())
        );
    }

    #[test]
    fn extract_host_port_https_with_port() {
        assert_eq!(
            extract_host_port("https://node.example.com:443/v2/status"),
            Some("node.example.com:443".to_string())
        );
    }

    #[test]
    fn extract_host_port_ws_scheme() {
        assert_eq!(
            extract_host_port("ws://relay.algorand.network:4160"),
            Some("relay.algorand.network:4160".to_string())
        );
    }

    #[test]
    fn extract_host_port_wss_scheme() {
        assert_eq!(
            extract_host_port("wss://relay.algorand.network:443"),
            Some("relay.algorand.network:443".to_string())
        );
    }

    #[test]
    fn extract_host_port_no_port_adds_default() {
        assert_eq!(
            extract_host_port("http://example.com"),
            Some("example.com:4160".to_string())
        );
    }

    #[test]
    fn extract_host_port_with_path() {
        assert_eq!(
            extract_host_port("http://example.com:4001/v2/blocks/123"),
            Some("example.com:4001".to_string())
        );
    }

    #[test]
    fn extract_host_port_no_scheme_returns_none() {
        assert_eq!(extract_host_port("example.com:4001"), None);
    }

    #[test]
    fn extract_host_port_empty_host_returns_none() {
        assert_eq!(extract_host_port("http://"), None);
    }

    #[test]
    fn extract_host_port_localhost() {
        assert_eq!(
            extract_host_port("http://localhost:4001"),
            Some("localhost:4001".to_string())
        );
    }

    #[test]
    fn genesis_id_for_known_networks() {
        assert_eq!(genesis_id_for("mainnet"), Some("mainnet-v1.0"));
        assert_eq!(genesis_id_for("testnet"), Some("testnet-v1.0"));
        assert_eq!(genesis_id_for("devnet"), Some("devnet-v1.0"));
        assert_eq!(genesis_id_for("betanet"), Some("betanet-v1.0"));
    }

    #[test]
    fn genesis_id_for_unknown_network() {
        assert_eq!(genesis_id_for("foonet"), None);
    }
}
