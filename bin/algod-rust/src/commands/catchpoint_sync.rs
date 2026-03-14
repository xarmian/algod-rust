use std::path::PathBuf;
use std::sync::Arc;

use algo_codec::{canonical_encode_block_header_from_block, decode_block_response, encode_block};
use algo_error::AlgoError;
use algo_ledger::sync::{SyncBackend, SyncConfig, SyncOrchestrator};
use algo_rest_client::{
    AlgodClient, BlockSource, CatchpointDownloader, GossipBlockSource, HttpBlockFetcher,
    ParallelBlockFetcher,
};
use algo_types::{Block, Round};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// AlgodSyncBackend — real SyncBackend using AlgodClient
// ---------------------------------------------------------------------------

/// A real [`SyncBackend`] implementation backed by [`AlgodClient`] and
/// [`CatchpointDownloader`].
///
/// This bridges the gap between `algo-ledger` (which cannot depend on
/// `algo-rest-client`) and the actual network operations needed for sync.
struct AlgodSyncBackend {
    client: AlgodClient,
    downloader: CatchpointDownloader,
    /// Tokio runtime handle for running async operations from sync context.
    rt: tokio::runtime::Handle,
    /// Stored URL for constructing parallel fetchers.
    algod_url: String,
    /// Stored token for constructing parallel fetchers.
    algod_token: String,
}

impl AlgodSyncBackend {
    fn new(algod_url: &str, algod_token: &str) -> Self {
        let client = AlgodClient::new(algod_url, algod_token);
        let downloader = CatchpointDownloader::new(algod_url, algod_token);
        let rt = tokio::runtime::Handle::current();
        Self {
            client,
            downloader,
            rt,
            algod_url: algod_url.to_string(),
            algod_token: algod_token.to_string(),
        }
    }
}

impl SyncBackend for AlgodSyncBackend {
    fn is_noop(&self) -> bool {
        false
    }

    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> Result<(), AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                self.downloader
                    .download::<fn(algo_rest_client::DownloadProgress)>(
                        genesis_id, round, dest_path, None,
                    )
                    .await
            })
        })
    }

    fn fetch_block_raw(&self, round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let raw = self.client.get_block_raw(Round(round)).await?;
                let br = decode_block_response(&raw)?;
                let proto = br.block.current_protocol.clone();
                // Encode in the same format that apply_block uses:
                // hdrdata = canonical block header encoding (for heartbeat
                //           validation and block digest computation)
                // blkdata = full block msgpack encoding (for block replay)
                let hdrdata = canonical_encode_block_header_from_block(&br.block);
                let blkdata = encode_block(&br.block)?;
                Ok((proto, hdrdata, blkdata))
            })
        })
    }

    fn fetch_block(&self, round: u64) -> Result<Block, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let raw = self.client.get_block_raw(Round(round)).await?;
                let br = decode_block_response(&raw)?;
                Ok(br.block)
            })
        })
    }

    fn get_current_round(&self) -> Result<u64, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let status = self.client.get_status().await?;
                Ok(status.last_round)
            })
        })
    }

    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let status = self.client.get_status().await?;
                Ok(status.last_catchpoint)
            })
        })
    }

    fn fetch_blocks_batch(
        &self,
        start: u64,
        end: u64,
        concurrency: usize,
    ) -> Result<Vec<(u64, Block)>, AlgoError> {
        if start > end {
            return Ok(Vec::new());
        }

        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let source: Arc<dyn BlockSource> =
                    Arc::new(AlgodClient::new(&self.algod_url, &self.algod_token));
                let fetcher = ParallelBlockFetcher::new(source, concurrency);
                let cancel = CancellationToken::new();
                // fetch_range uses half-open [start, end), so add 1 to include `end`.
                let mut rx = fetcher.fetch_range(Round(start), Round(end + 1), cancel);

                let mut blocks = Vec::with_capacity((end - start + 1) as usize);
                while let Some((round, block_resp)) = rx.recv().await {
                    blocks.push((round.0, block_resp.block));
                }

                if blocks.len() != (end - start + 1) as usize {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "parallel fetch incomplete: expected {} blocks, got {}",
                            end - start + 1,
                            blocks.len()
                        ),
                    });
                }

                Ok(blocks)
            })
        })
    }
}

// ---------------------------------------------------------------------------
// GossipSyncBackend — SyncBackend using gossip-first with HTTP fallback
// ---------------------------------------------------------------------------

/// Source selection policy for block fetching.
///
/// Mirrors Go's catchup service approach: gossip (WebSocket unicast) is
/// preferred for live blocks because it is lower latency and leverages
/// the existing peer mesh. HTTP block fetch is used as a fallback when
/// gossip fails or for gap-fill / recovery scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Public API — used by integration code and tests.
pub enum BlockSourcePolicy {
    /// Try gossip first, fall back to HTTP on failure (default for live sync).
    GossipFirst,
    /// Use HTTP only (for recovery / gap-fill when no peers are available).
    HttpOnly,
    /// Use gossip only (when HTTP endpoint is not available).
    GossipOnly,
}

// ---------------------------------------------------------------------------
// HttpBlockFetcherSource — BlockSource adapter for HttpBlockFetcher
// ---------------------------------------------------------------------------

/// A [`BlockSource`] adapter that wraps [`HttpBlockFetcher`] so it can be used
/// with [`ParallelBlockFetcher`] and other `BlockSource`-based infrastructure.
///
/// This ensures batch fetches route through the same HTTP block fetcher that
/// single-block fetches use, rather than constructing ad-hoc `AlgodClient`
/// instances.
struct HttpBlockFetcherSource {
    fetcher: HttpBlockFetcher,
}

#[async_trait::async_trait]
impl BlockSource for HttpBlockFetcherSource {
    async fn get_block_raw(&self, round: Round) -> algo_error::Result<Vec<u8>> {
        self.fetcher
            .fetch_block(round.0)
            .await
            .map_err(|e| AlgoError::Network {
                message: format!("HTTP block fetch failed for round {}: {e}", round.0),
            })
    }

    async fn get_block(
        &self,
        round: Round,
    ) -> algo_error::Result<algo_types::BlockResponse> {
        let raw = self.get_block_raw(round).await?;
        let br = decode_block_response(&raw)?;
        Ok(br)
    }

    async fn get_status(&self) -> algo_error::Result<algo_rest_client::NodeStatus> {
        // HttpBlockFetcher does not support status queries; this adapter is
        // only used by ParallelBlockFetcher which never calls get_status.
        Err(AlgoError::Network {
            message: "HttpBlockFetcherSource does not support get_status".into(),
        })
    }

    async fn wait_for_round(
        &self,
        _round: Round,
    ) -> algo_error::Result<algo_rest_client::NodeStatus> {
        Err(AlgoError::Network {
            message: "HttpBlockFetcherSource does not support wait_for_round".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// FallbackBlockSource — tries gossip, then HTTP
// ---------------------------------------------------------------------------

/// A [`BlockSource`] wrapper that tries gossip first, then falls back to HTTP.
///
/// This enables `ParallelBlockFetcher` to transparently retry failed gossip
/// fetches via HTTP, so that a single-round gossip failure does not cancel
/// the entire batch pipeline.
///
/// The HTTP fallback uses [`HttpBlockFetcherSource`] to ensure consistency
/// with the single-block fetch path (which routes through `HttpBlockFetcher`).
struct FallbackBlockSource {
    gossip: Arc<GossipBlockSource>,
    http: HttpBlockFetcherSource,
}

#[async_trait::async_trait]
impl BlockSource for FallbackBlockSource {
    async fn get_block_raw(&self, round: Round) -> algo_error::Result<Vec<u8>> {
        match self.gossip.get_block_raw(round).await {
            Ok(raw) => Ok(raw),
            Err(_gossip_err) => {
                debug!(
                    round = round.0,
                    "gossip get_block_raw failed, falling back to HTTP"
                );
                self.http.get_block_raw(round).await
            }
        }
    }

    async fn get_block(&self, round: Round) -> algo_error::Result<algo_types::BlockResponse> {
        match self.gossip.get_block(round).await {
            Ok(block) => Ok(block),
            Err(_gossip_err) => {
                debug!(
                    round = round.0,
                    "gossip get_block failed, falling back to HTTP"
                );
                self.http.get_block(round).await
            }
        }
    }

    async fn get_status(&self) -> algo_error::Result<algo_rest_client::NodeStatus> {
        // Status queries are not supported via the HTTP block fetcher;
        // callers needing status should use the REST client directly.
        Err(AlgoError::Network {
            message: "FallbackBlockSource does not support get_status".into(),
        })
    }

    async fn wait_for_round(
        &self,
        _round: Round,
    ) -> algo_error::Result<algo_rest_client::NodeStatus> {
        Err(AlgoError::Network {
            message: "FallbackBlockSource does not support wait_for_round".into(),
        })
    }
}

/// A [`SyncBackend`] implementation that fetches blocks via gossip (WebSocket
/// unicast) with HTTP fallback, suitable for the live sync phase after an
/// initial catchpoint/REST bootstrap completes.
///
/// This is the gossip-aware counterpart to [`AlgodSyncBackend`], which uses
/// only the REST API. The source selection policy determines the priority
/// order for block fetching:
///
/// - **Live blocks**: gossip-first (`GossipBlockSource`), HTTP fallback
/// - **Gap fill / recovery**: HTTP (`HttpBlockFetcher`), gossip fallback
///
/// The `download_catchpoint` and `discover_catchpoint` operations delegate
/// to the REST client since those are inherently HTTP operations.
#[allow(dead_code)] // Public API — used by integration code and tests.
pub struct GossipSyncBackend {
    /// Gossip-based block source (WebSocket unicast to peers).
    gossip: Arc<GossipBlockSource>,
    /// HTTP block fetcher for fallback / gap-fill.
    http_fetcher: HttpBlockFetcher,
    /// REST client for operations that are inherently HTTP-only
    /// (catchpoint download, catchpoint discovery, status queries).
    rest_client: AlgodClient,
    /// Catchpoint downloader for `download_catchpoint`.
    downloader: CatchpointDownloader,
    /// Tokio runtime handle for running async operations from sync context.
    rt: tokio::runtime::Handle,
    /// Source selection policy.
    policy: BlockSourcePolicy,
    /// Stored URL for constructing parallel fetchers.
    algod_url: String,
    /// Stored token for constructing parallel fetchers.
    algod_token: String,
    /// Concurrency for batch fetches.
    concurrency: usize,
}

#[allow(dead_code)] // Public API — used by integration code and tests.
impl GossipSyncBackend {
    /// Create a new `GossipSyncBackend`.
    ///
    /// # Arguments
    ///
    /// * `gossip` — The gossip block source (WebSocket unicast peers).
    /// * `http_fetcher` — HTTP block fetcher for fallback.
    /// * `algod_url` — REST API URL for status/catchpoint operations.
    /// * `algod_token` — REST API token.
    /// * `policy` — Source selection policy (default: `GossipFirst`).
    /// * `concurrency` — Number of concurrent fetches for batch operations.
    pub fn new(
        gossip: Arc<GossipBlockSource>,
        http_fetcher: HttpBlockFetcher,
        algod_url: &str,
        algod_token: &str,
        policy: BlockSourcePolicy,
        concurrency: usize,
    ) -> Self {
        let rest_client = AlgodClient::new(algod_url, algod_token);
        let downloader = CatchpointDownloader::new(algod_url, algod_token);
        let rt = tokio::runtime::Handle::current();
        Self {
            gossip,
            http_fetcher,
            rest_client,
            downloader,
            rt,
            policy,
            algod_url: algod_url.to_string(),
            algod_token: algod_token.to_string(),
            concurrency,
        }
    }

    /// Fetch a block via gossip, returning the decoded `Block`.
    async fn fetch_block_gossip(&self, round: u64) -> Result<Block, AlgoError> {
        let resp = self.gossip.get_block(Round(round)).await?;
        Ok(resp.block)
    }

    /// Fetch a block via HTTP, returning the decoded `Block`.
    async fn fetch_block_http(&self, round: u64) -> Result<Block, AlgoError> {
        let raw = self
            .http_fetcher
            .fetch_block(round)
            .await
            .map_err(|e| AlgoError::Network {
                message: format!("HTTP block fetch failed for round {round}: {e}"),
            })?;
        let br = decode_block_response(&raw)?;
        Ok(br.block)
    }

    /// Fetch a block using the configured source selection policy.
    async fn fetch_block_with_policy(&self, round: u64) -> Result<Block, AlgoError> {
        match self.policy {
            BlockSourcePolicy::GossipFirst => {
                // Try gossip first.
                match self.fetch_block_gossip(round).await {
                    Ok(block) => {
                        debug!(round, "block fetched via gossip");
                        Ok(block)
                    }
                    Err(gossip_err) => {
                        debug!(
                            round,
                            error = %gossip_err,
                            "gossip fetch failed, falling back to HTTP"
                        );
                        self.fetch_block_http(round)
                            .await
                            .map_err(|http_err| AlgoError::Network {
                                message: format!(
                                    "block fetch failed for round {round}: \
                                     gossip: {gossip_err}; HTTP: {http_err}"
                                ),
                            })
                    }
                }
            }
            BlockSourcePolicy::HttpOnly => self.fetch_block_http(round).await,
            BlockSourcePolicy::GossipOnly => self.fetch_block_gossip(round).await,
        }
    }

    /// Fetch raw block bytes using the configured source selection policy.
    ///
    /// Returns `(proto, header_data, block_data)` in the same format as
    /// `AlgodSyncBackend::fetch_block_raw`.
    async fn fetch_block_raw_with_policy(
        &self,
        round: u64,
    ) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        let block = self.fetch_block_with_policy(round).await?;
        let proto = block.current_protocol.clone();
        let hdrdata = canonical_encode_block_header_from_block(&block);
        let blkdata = encode_block(&block)?;
        Ok((proto, hdrdata, blkdata))
    }
}

impl SyncBackend for GossipSyncBackend {
    fn is_noop(&self) -> bool {
        false
    }

    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> Result<(), AlgoError> {
        // Catchpoint download is always via REST.
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                self.downloader
                    .download::<fn(algo_rest_client::DownloadProgress)>(
                        genesis_id, round, dest_path, None,
                    )
                    .await
            })
        })
    }

    fn fetch_block_raw(&self, round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        tokio::task::block_in_place(|| self.rt.block_on(self.fetch_block_raw_with_policy(round)))
    }

    fn fetch_block(&self, round: u64) -> Result<Block, AlgoError> {
        tokio::task::block_in_place(|| self.rt.block_on(self.fetch_block_with_policy(round)))
    }

    fn get_current_round(&self) -> Result<u64, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                match self.policy {
                    BlockSourcePolicy::GossipOnly => {
                        // In GossipOnly mode, use the gossip source's synthetic
                        // status (based on last fetched round) instead of REST.
                        let status = self.gossip.get_status().await?;
                        Ok(status.last_round)
                    }
                    BlockSourcePolicy::GossipFirst | BlockSourcePolicy::HttpOnly => {
                        // Use REST for authoritative round info.
                        let status = self.rest_client.get_status().await?;
                        Ok(status.last_round)
                    }
                }
            })
        })
    }

    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        // Catchpoint discovery is always via REST.
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let status = self.rest_client.get_status().await?;
                Ok(status.last_catchpoint)
            })
        })
    }

    fn fetch_blocks_batch(
        &self,
        start: u64,
        end: u64,
        concurrency: usize,
    ) -> Result<Vec<(u64, Block)>, AlgoError> {
        if start > end {
            return Ok(Vec::new());
        }

        // For batch fetches, use the gossip source wrapped as a BlockSource
        // via ParallelBlockFetcher when gossip is available. Fall back to
        // REST-based parallel fetch when in HttpOnly mode.
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let source: Arc<dyn BlockSource> = match self.policy {
                    BlockSourcePolicy::HttpOnly => {
                        // Use HttpBlockFetcherSource to route through the
                        // configured HttpBlockFetcher, matching the single-
                        // block fetch path.
                        Arc::new(HttpBlockFetcherSource {
                            fetcher: self.http_fetcher.clone(),
                        })
                    }
                    BlockSourcePolicy::GossipOnly => {
                        Arc::clone(&self.gossip) as Arc<dyn BlockSource>
                    }
                    BlockSourcePolicy::GossipFirst => {
                        // Wrap gossip + HTTP in a FallbackBlockSource so that
                        // per-round gossip failures fall back to HTTP instead
                        // of cancelling the entire batch pipeline.
                        Arc::new(FallbackBlockSource {
                            gossip: Arc::clone(&self.gossip),
                            http: HttpBlockFetcherSource {
                                fetcher: self.http_fetcher.clone(),
                            },
                        })
                    }
                };

                let effective_concurrency = if concurrency > 0 {
                    concurrency
                } else {
                    self.concurrency
                };
                let fetcher = ParallelBlockFetcher::new(source, effective_concurrency);
                let cancel = CancellationToken::new();
                // fetch_range uses half-open [start, end), so add 1 to include `end`.
                let mut rx = fetcher.fetch_range(Round(start), Round(end + 1), cancel);

                let mut blocks = Vec::with_capacity((end - start + 1) as usize);
                while let Some((round, block_resp)) = rx.recv().await {
                    blocks.push((round.0, block_resp.block));
                }

                if blocks.len() != (end - start + 1) as usize {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "parallel fetch incomplete: expected {} blocks, got {}",
                            end - start + 1,
                            blocks.len()
                        ),
                    });
                }

                Ok(blocks)
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Bootstrap handoff — REST catchpoint -> gossip live stream
// ---------------------------------------------------------------------------

/// After the initial catchpoint/REST bootstrap completes, transition to using
/// `GossipSyncBackend` for live block streaming.
///
/// This function creates a `GossipSyncBackend` and runs a block-by-block
/// live sync loop starting from the ledger's current round, without re-running
/// the catchpoint download/import/verify phases.
///
/// # Source selection policy
///
/// - **Gossip-first** for live blocks (low latency via peer mesh)
/// - **HTTP fallback** for gap-fill / recovery when gossip peers fail
///
/// # Arguments
///
/// * `gossip_source` — Pre-connected gossip block source with active peers.
/// * `http_fetcher` — HTTP block fetcher for fallback.
/// * `config` — Sync configuration (db_path, follow_after_sync, etc.).
/// * `cancel` — Cancellation token for graceful shutdown.
#[allow(dead_code)] // Public API — used by integration code when gossip peers are connected.
pub async fn handoff_to_gossip_sync(
    gossip_source: Arc<GossipBlockSource>,
    http_fetcher: HttpBlockFetcher,
    config: SyncConfig,
    cancel: CancellationToken,
) -> anyhow::Result<algo_ledger::sync::SyncResult> {
    use std::time::Instant;

    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

    info!(
        algod_url = %config.algod_url,
        genesis_id = %config.genesis_id,
        concurrency = config.concurrency,
        follow = config.follow_after_sync,
        "bootstrap handoff: transitioning to gossip-based live sync"
    );

    let peer_count = gossip_source.peer_count();
    let policy = if peer_count == 0 {
        warn!("no gossip peers available — using HTTP-only mode for live sync");
        BlockSourcePolicy::HttpOnly
    } else {
        info!(
            peer_count,
            "gossip peers available — using gossip-first source selection"
        );
        BlockSourcePolicy::GossipFirst
    };

    let backend = GossipSyncBackend::new(
        gossip_source,
        http_fetcher,
        &config.algod_url,
        &config.algod_token,
        policy,
        config.concurrency,
    );

    // Open the ledger to determine the current round.
    let ledger =
        algo_ledger::SqliteLedger::open(&config.db_path).map_err(|e| AlgoError::Ledger {
            message: format!("open ledger for gossip handoff: {e}"),
        })?;
    let mut current_round = ledger
        .last_committed_round()
        .map_err(|e| AlgoError::Ledger {
            message: format!("query last committed round: {e}"),
        })?
        .ok_or_else(|| AlgoError::Ledger {
            message: "gossip handoff: no committed round in ledger".to_string(),
        })?;
    // Drop the read-only handle before entering the sync loop.
    drop(ledger);

    info!(
        start_round = current_round,
        "gossip handoff: starting live sync from ledger round"
    );

    let start = Instant::now();
    let mut blocks_synced: u64 = 0;
    let mut eval_delta_stats = algo_ledger::EvalDeltaStats::default();

    loop {
        // Check for cancellation.
        if cancel.is_cancelled() {
            info!(
                blocks_synced,
                last_round = current_round,
                "gossip handoff: cancellation requested"
            );
            break;
        }

        // Get the current network round.
        let network_round = match backend.get_current_round() {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "gossip handoff: failed to get current round, retrying");
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        // If we're caught up, either exit or keep following.
        if current_round >= network_round {
            if config.follow_after_sync {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            } else {
                info!(
                    round = current_round,
                    "gossip handoff: caught up to network tip"
                );
                break;
            }
        }

        // Fetch and apply blocks one at a time from current+1 to network_round.
        while current_round < network_round {
            if cancel.is_cancelled() {
                info!(
                    blocks_synced,
                    last_round = current_round,
                    "gossip handoff: cancellation requested"
                );
                break;
            }

            let next_round = current_round + 1;

            let block = match backend.fetch_block(next_round) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        round = next_round,
                        error = %e,
                        "gossip handoff: block fetch failed, retrying"
                    );
                    tokio::time::sleep(POLL_INTERVAL).await;
                    break;
                }
            };

            // Open ledger, apply, commit.
            let mut store = algo_ledger::SqliteLedger::open(&config.db_path).map_err(|e| {
                AlgoError::Ledger {
                    message: format!("open ledger for block {next_round}: {e}"),
                }
            })?;

            // Enable Merkle trie tracking if configured, matching the
            // SyncOrchestrator replay/follow paths.
            if config.trie_path.is_some() {
                use algo_ledger::LedgerStore;
                store.enable_trie();
            }

            store.begin_block().map_err(|e| AlgoError::Ledger {
                message: format!("begin_block at round {next_round}: {e}"),
            })?;

            let apply_result = if config.compare_mode || config.avm_execute {
                let (result, block_stats) =
                    algo_ledger::apply_block_with_comparison(&mut store, &block);
                eval_delta_stats += block_stats;
                result
            } else {
                algo_ledger::apply_block(&mut store, &block)
            };

            match apply_result {
                Ok(()) => {
                    // Finalize trie updates before commit, matching the
                    // SyncOrchestrator replay/follow paths.
                    if config.trie_path.is_some() {
                        use algo_ledger::LedgerStore;
                        store.finalize_trie_updates();
                    }
                    store.commit_block().map_err(|e| AlgoError::Ledger {
                        message: format!("commit_block at round {next_round}: {e}"),
                    })?;
                    blocks_synced += 1;
                    current_round = next_round;

                    if blocks_synced % 1000 == 0 {
                        info!(
                            round = current_round,
                            blocks_synced, "gossip handoff: sync progress"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        round = next_round,
                        error = %e,
                        "gossip handoff: apply_block failed"
                    );
                    let _ = store.rollback_block();
                    if config.compare_mode || config.avm_execute {
                        eval_delta_stats.print_summary();
                    }
                    return Err(anyhow::anyhow!(
                        "gossip handoff: block apply failed at round {next_round}: {e}"
                    ));
                }
            }
        }
    }

    // Print AVM/EvalDelta stats if compare or AVM execution was enabled.
    if config.compare_mode || config.avm_execute {
        eval_delta_stats.print_summary();
    }

    Ok(algo_ledger::sync::SyncResult {
        final_round: current_round,
        accounts_imported: 0, // No catchpoint import in handoff.
        blocks_replayed: blocks_synced,
        duration: start.elapsed(),
    })
}

// ---------------------------------------------------------------------------
// Genesis info resolution
// ---------------------------------------------------------------------------

/// Known genesis IDs for well-known networks.
fn genesis_id_for_network(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("mainnet-v1.0"),
        "testnet" => Some("testnet-v1.0"),
        _ => None,
    }
}

/// Resolve genesis_id and genesis_hash by fetching block info from the node.
///
/// If `network` is a known preset ("mainnet", "testnet"), the genesis_id is
/// set directly. The genesis_hash is always fetched from the node (by
/// requesting a recent block and reading its header).
async fn resolve_genesis_info(
    client: &AlgodClient,
    network: &str,
) -> anyhow::Result<(String, [u8; 32])> {
    // If the network has a known genesis_id, use it.
    // Either way, we need the genesis_hash from the node.
    let status = client.get_status().await?;
    let round = status.last_round;

    // Fetch a recent block to extract genesis info.
    let raw = client.get_block_raw(Round(round)).await?;
    let br = decode_block_response(&raw)?;

    let genesis_id = if let Some(known_id) = genesis_id_for_network(network) {
        known_id.to_string()
    } else {
        let id = br.block.genesis_id.clone();
        if id.is_empty() {
            anyhow::bail!(
                "could not determine genesis_id: block {round} has no genesis_id and \
                 --network is '{network}' (not a known preset)"
            );
        }
        id
    };

    let genesis_hash: [u8; 32] = br
        .block
        .genesis_hash
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("genesis_hash from block {round} is not 32 bytes"))?;

    info!(
        genesis_id = %genesis_id,
        genesis_hash = hex::encode(genesis_hash),
        source_round = round,
        "resolved genesis info from node"
    );

    Ok((genesis_id, genesis_hash))
}

// Inline hex encoding since we may not have the `hex` crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the catchpoint sync path: build a SyncConfig from CLI args, construct
/// a SyncOrchestrator, and drive it through all phases.
///
/// Sets up a progress callback for phase-transition logging and a Ctrl+C
/// handler for graceful shutdown with checkpoint persistence.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    db_path: &std::path::Path,
    catchpoint_label: Option<&str>,
    catchpoint_auto: bool,
    concurrency: usize,
    follow: bool,
    compare: bool,
    trie_path: Option<&std::path::Path>,
    avm_execute: bool,
    fail_fast: bool,
    end: Option<u64>,
) -> anyhow::Result<()> {
    // Determine the catchpoint label to use.
    let label = match (catchpoint_label, catchpoint_auto) {
        (Some(label), _) => {
            info!(catchpoint = label, "using explicit catchpoint label");
            Some(label.to_string())
        }
        (None, true) => {
            info!("auto-discovery mode: orchestrator will discover latest catchpoint");
            None
        }
        (None, false) => {
            // This shouldn't happen — main.rs guards against it — but be safe.
            anyhow::bail!(
                "catchpoint sync requires either --catchpoint <LABEL> or --catchpoint-auto"
            );
        }
    };

    // Resolve genesis info from network preset / node.
    let client = AlgodClient::new(algod_url, algod_token);
    let (genesis_id, genesis_hash) = resolve_genesis_info(&client, network).await?;

    let config = SyncConfig {
        catchpoint_label: label,
        algod_url: algod_url.to_string(),
        algod_token: algod_token.to_string(),
        genesis_id,
        genesis_hash,
        db_path: db_path.to_path_buf(),
        concurrency,
        follow_after_sync: follow,
        compare_mode: compare,
        trie_path: trie_path.map(PathBuf::from),
        avm_execute,
        fail_fast,
        end_round: end,
    };

    info!(
        catchpoint = ?config.catchpoint_label,
        genesis_id = %config.genesis_id,
        algod_url,
        concurrency,
        follow,
        compare,
        avm_execute,
        fail_fast,
        db = %db_path.display(),
        "starting catchpoint sync"
    );

    // Set up cancellation token and Ctrl+C handler.
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Ctrl+C received — shutting down gracefully, saving checkpoint...");
        cancel_clone.cancel();
    });

    // Create the real backend and orchestrator.
    let backend = AlgodSyncBackend::new(algod_url, algod_token);
    let mut orchestrator = SyncOrchestrator::with_backend(config, backend);
    orchestrator.set_cancel(cancel);
    orchestrator.set_progress_callback(Box::new(|progress| {
        let pct = (progress.phase_progress * 100.0) as u32;
        let eta_str = match progress.eta {
            Some(eta) => format!(", ETA {:.0}s", eta.as_secs_f64()),
            None => String::new(),
        };
        info!(
            phase = %progress.state,
            progress_pct = pct,
            elapsed_secs = format!("{:.1}", progress.elapsed.as_secs_f64()),
            "{}{}",
            progress.phase_detail,
            eta_str,
        );
    }));

    let result = orchestrator.run().await?;

    info!(
        final_round = result.final_round,
        accounts_imported = result.accounts_imported,
        blocks_replayed = result.blocks_replayed,
        duration = ?result.duration,
        "catchpoint sync completed"
    );

    println!("=== Catchpoint Sync Summary ===");
    println!("Final round:        {}", result.final_round);
    println!("Accounts imported:  {}", result.accounts_imported);
    println!("Blocks replayed:    {}", result.blocks_replayed);
    println!("Duration:           {:.1}s", result.duration.as_secs_f64());

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BlockSourcePolicy tests ------------------------------------------

    #[test]
    fn block_source_policy_debug() {
        // Verify Debug is implemented and variants are distinct.
        let gossip_first = BlockSourcePolicy::GossipFirst;
        let http_only = BlockSourcePolicy::HttpOnly;
        let gossip_only = BlockSourcePolicy::GossipOnly;

        assert_ne!(gossip_first, http_only);
        assert_ne!(gossip_first, gossip_only);
        assert_ne!(http_only, gossip_only);

        // Debug output should contain variant name.
        assert!(format!("{gossip_first:?}").contains("GossipFirst"));
        assert!(format!("{http_only:?}").contains("HttpOnly"));
        assert!(format!("{gossip_only:?}").contains("GossipOnly"));
    }

    #[test]
    fn block_source_policy_clone_and_copy() {
        let policy = BlockSourcePolicy::GossipFirst;
        let copied = policy; // Copy trait
        let copied2 = copied; // Copy again — original still valid
        assert_eq!(policy, copied);
        assert_eq!(policy, copied2);
    }

    // -- GossipSyncBackend construction tests ----------------------------

    #[tokio::test]
    async fn gossip_sync_backend_is_not_noop() {
        // Create a GossipSyncBackend with no peers and verify it reports
        // is_noop() = false.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:4001", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:4001",
            "",
            BlockSourcePolicy::GossipFirst,
            4,
        );

        assert!(!backend.is_noop());
    }

    #[tokio::test]
    async fn gossip_sync_backend_fetch_blocks_batch_empty_range() {
        // fetch_blocks_batch with start > end should return empty vec.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:4001", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:4001",
            "",
            BlockSourcePolicy::GossipFirst,
            4,
        );

        let result = backend.fetch_blocks_batch(10, 5, 4);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_sync_backend_gossip_first_no_peers_fails() {
        // With no gossip peers and GossipFirst policy, fetch_block should
        // try gossip (which fails with no peers), then fall back to HTTP
        // (which also fails since there's no server).
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:19999", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:19999",
            "",
            BlockSourcePolicy::GossipFirst,
            4,
        );

        let result = backend.fetch_block(1);
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_sync_backend_http_only_no_server_fails() {
        // With HttpOnly policy and no server, fetch_block should fail.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:19999", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:19999",
            "",
            BlockSourcePolicy::HttpOnly,
            4,
        );

        let result = backend.fetch_block(1);
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_sync_backend_gossip_only_no_peers_fails() {
        // With GossipOnly policy and no peers, fetch_block should fail.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:19999", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:19999",
            "",
            BlockSourcePolicy::GossipOnly,
            4,
        );

        let result = backend.fetch_block(1);
        assert!(result.is_err());
    }

    // -- Source selection logic tests -------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_first_policy_tries_gossip_then_http() {
        // With GossipFirst and no peers, the error message should indicate
        // both gossip and HTTP were attempted.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:19999", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:19999",
            "",
            BlockSourcePolicy::GossipFirst,
            4,
        );

        let err = backend.fetch_block(42).unwrap_err();
        let err_msg = err.to_string();
        // The error should mention both gossip and HTTP failures.
        assert!(
            err_msg.contains("gossip") || err_msg.contains("no peers") || err_msg.contains("HTTP"),
            "expected error mentioning gossip/HTTP, got: {err_msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_block_raw_returns_proto_and_data() {
        // fetch_block_raw with no server should fail, but verify the
        // error path is clean.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let http = HttpBlockFetcher::new("http://localhost:19999", "test-v1.0").unwrap();

        let backend = GossipSyncBackend::new(
            gossip,
            http,
            "http://localhost:19999",
            "",
            BlockSourcePolicy::HttpOnly,
            4,
        );

        let result = backend.fetch_block_raw(1);
        assert!(result.is_err());
    }

    // -- Bootstrap handoff logic tests -----------------------------------

    #[test]
    fn handoff_selects_http_only_when_no_peers() {
        // Verify the policy selection logic: no peers -> HttpOnly.
        let gossip = Arc::new(GossipBlockSource::new(vec![]));
        let peer_count = gossip.peer_count();
        let policy = if peer_count == 0 {
            BlockSourcePolicy::HttpOnly
        } else {
            BlockSourcePolicy::GossipFirst
        };
        assert_eq!(policy, BlockSourcePolicy::HttpOnly);
    }

    #[test]
    fn genesis_id_for_known_networks() {
        assert_eq!(genesis_id_for_network("mainnet"), Some("mainnet-v1.0"));
        assert_eq!(genesis_id_for_network("testnet"), Some("testnet-v1.0"));
        assert_eq!(genesis_id_for_network("devnet"), None);
        assert_eq!(genesis_id_for_network("custom"), None);
    }
}
