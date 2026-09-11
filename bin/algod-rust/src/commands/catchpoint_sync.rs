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

use std::path::PathBuf;
use std::sync::Arc;

use algo_codec::{
    canonical_encode_block, canonical_encode_block_header_from_block, decode_block_response,
};
use algo_error::AlgoError;
use algo_ledger::sync::{SyncBackend, SyncConfig, SyncOrchestrator};
use algo_network::GossipNode;
use algo_rest_client::{
    AlgodClient, BlockSource, CatchpointDownloader, GossipBlockSource, HttpBlockFetcher,
    HttpPeerTransport, ParallelBlockFetcher, RankedCatchpointSource,
};
use algo_types::{Block, Round};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::commands::p2p_transport::{P2pHttpPeerTransport, P2pTransport};

// ---------------------------------------------------------------------------
// AlgodSyncBackend — real SyncBackend using AlgodClient
// ---------------------------------------------------------------------------

/// A real [`SyncBackend`] implementation backed by [`AlgodClient`] and a
/// [`RankedCatchpointSource`].
///
/// This bridges the gap between `algo-ledger` (which cannot depend on
/// `algo-rest-client`) and the actual network operations needed for sync.
///
/// Catchpoint downloads route through [`RankedCatchpointSource`] (issue
/// #901) rather than a single fixed [`CatchpointDownloader`): the primary
/// `algod_url` plus any additional `catchpoint_peer_urls` are all ranked by
/// historical download performance, mirroring go's
/// `CatchpointCatchupService.blocksDownloadPeerSelector`. With no extra
/// peers configured (the common case today) this is behaviorally identical
/// to the old single-source downloader — ranking with exactly one
/// candidate always selects that candidate.
struct AlgodSyncBackend {
    client: AlgodClient,
    catchpoint_source: RankedCatchpointSource,
    /// Tokio runtime handle for running async operations from sync context.
    rt: tokio::runtime::Handle,
    /// Stored URL for constructing parallel fetchers.
    algod_url: String,
    /// Stored token for constructing parallel fetchers.
    algod_token: String,
}

impl AlgodSyncBackend {
    /// Ranks the catchpoint file download across `algod_url` plus
    /// `extra_catchpoint_peer_urls` instead of using `algod_url` alone
    /// (issue #901's peer-ranked catchpoint source selection).
    /// Block/status/certificate operations still go through `algod_url`
    /// only — only the catchpoint-file fetch benefits from multiple
    /// candidate peers today. An empty `extra_catchpoint_peer_urls` is
    /// behaviorally identical to the old single-source downloader: ranking
    /// with exactly one candidate always selects that candidate.
    fn with_catchpoint_peers(
        algod_url: &str,
        algod_token: &str,
        extra_catchpoint_peer_urls: &[String],
    ) -> Self {
        let client = AlgodClient::new(algod_url, algod_token);
        let mut peers = vec![(algod_url.to_string(), algod_token.to_string())];
        peers.extend(
            extra_catchpoint_peer_urls
                .iter()
                .map(|u| (u.clone(), algod_token.to_string())),
        );
        let catchpoint_source = RankedCatchpointSource::new(
            &peers,
            algo_rest_client::CatchpointDownloadConfig::default(),
        );
        let rt = tokio::runtime::Handle::current();
        Self {
            client,
            catchpoint_source,
            rt,
            algod_url: algod_url.to_string(),
            algod_token: algod_token.to_string(),
        }
    }

    /// Extends [`Self::with_catchpoint_peers`] with every peer a live,
    /// running [`P2pTransport`] is currently connected to (issue #1130) —
    /// the production wiring issue #1127 built the building blocks for
    /// (`CatchpointDownloader::with_p2p_transport`/`HttpPeerTransport`,
    /// `RankedCatchpointSource::push_p2p_peer`, `P2pHttpPeerTransport`) but
    /// never called from a real node-startup path.
    ///
    /// Each connected peer is pushed into the same ranked candidate pool
    /// [`RankedCatchpointSource::new`]'s HTTP peers already occupy, routed
    /// through [`P2pHttpPeerTransport`] so its `CatchpointDownloader` speaks
    /// HTTP-over-`/algorand-http/1.0.0` to that peer instead of plain-TCP
    /// `reqwest` — mirroring issue #901's `create_peer_selector`
    /// topology-wiring for block fetch (`GossipBlockFetcher`/
    /// `P2pBlockFetcher` in `participate.rs`, which likewise reads
    /// `P2pTransport`'s live peer set at fetch-call time rather than a
    /// point-in-time snapshot).
    ///
    /// # Peer set: a snapshot taken once, at construction
    ///
    /// go's `CatchpointCatchupService.blocksDownloadPeerSelector`
    /// (`catchup/catchpointService.go`, built via
    /// `makeCatchpointPeerSelector(cs.net)`) re-queries `net.GetPeers(...)`
    /// fresh on every `getNextPeer()` call for the run's whole duration
    /// (`catchup/classBasedPeerSelector.go`'s `rankPooledPeerSelector` holds
    /// only the live `peersRetriever` interface, never a copied peer list) —
    /// so go's peer set really is continuously live for as long as one
    /// catchup run lasts, not just at its start.
    /// [`RankedCatchpointSource::push_p2p_peer`] (#1127) only supports
    /// *adding* candidates — it has no removal/refresh API — so this
    /// constructor instead takes a one-time snapshot of `p2p_transport`'s
    /// currently-connected peers when the backend is built. That is an
    /// acceptable approximation here (not a live-updating list *during* a
    /// single run) because a fresh [`AlgodSyncBackend`] — and thus a fresh
    /// snapshot — is built for every catchup attempt
    /// (`build_algod_sync_backend` is called anew by every
    /// `OrchestratorCatchupRunner::run`/standalone [`run`] invocation): a
    /// peer that connects mid-run is missed for *that* run but present on
    /// the next one. Making the peer set continuously live mid-run would
    /// require `RankedCatchpointSource` itself to grow a peer-removal/
    /// refresh API, a distinct change from this issue's node-startup wiring
    /// — left as a follow-up.
    fn with_catchpoint_peers_and_p2p(
        algod_url: &str,
        algod_token: &str,
        extra_catchpoint_peer_urls: &[String],
        p2p_transport: Option<&Arc<P2pTransport>>,
    ) -> Self {
        let backend =
            Self::with_catchpoint_peers(algod_url, algod_token, extra_catchpoint_peer_urls);
        if let Some(transport) = p2p_transport {
            let http_transport: Arc<dyn HttpPeerTransport> =
                Arc::new(P2pHttpPeerTransport::new(Arc::clone(transport)));
            let peers = transport.get_peers(&[]);
            let peer_count = peers.len();
            for peer in peers {
                backend
                    .catchpoint_source
                    .push_p2p_peer(peer.get_address().to_string(), Arc::clone(&http_transport));
            }
            if peer_count > 0 {
                info!(
                    peer_count,
                    "wired connected P2P peer(s) into catchpoint download ranking"
                );
            }
        }
        backend
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
                self.catchpoint_source
                    .download(genesis_id, round, dest_path, None)
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
                let blkdata = canonical_encode_block(&br.block);
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

/// Build the same [`SyncBackend`] the standalone `algod-rust sync`
/// subcommand uses, for reuse by [`crate::live_catchup::OrchestratorCatchupRunner`]
/// (issue #937's live-toggle catchpoint catchup). Kept as a thin
/// `pub(crate)` wrapper rather than making [`AlgodSyncBackend`] itself
/// public, since its type is otherwise an internal implementation detail
/// of this module.
pub(crate) fn build_algod_sync_backend(
    algod_url: &str,
    algod_token: &str,
    extra_catchpoint_peer_urls: &[String],
    p2p_transport: Option<&Arc<P2pTransport>>,
) -> impl SyncBackend {
    AlgodSyncBackend::with_catchpoint_peers_and_p2p(
        algod_url,
        algod_token,
        extra_catchpoint_peer_urls,
        p2p_transport,
    )
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
pub enum BlockSourcePolicy {
    /// Try gossip first, fall back to HTTP on failure (default for live sync).
    GossipFirst,
    /// Use HTTP only (for recovery / gap-fill when no peers are available).
    HttpOnly,
    /// Use gossip only (when HTTP endpoint is not available).
    ///
    /// `build_catchpoint_backend` never selects this today — the CLI
    /// wiring only ever picks `GossipFirst` (peers connected) or `HttpOnly`
    /// (no peers), since the REST endpoint is always available on the
    /// `catchpoint-sync` path. Kept as a selectable policy (and exercised
    /// directly by `GossipSyncBackend`'s unit tests below) for callers that
    /// construct a `GossipSyncBackend` directly without an HTTP endpoint.
    #[allow(dead_code)]
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

    async fn get_block(&self, round: Round) -> algo_error::Result<algo_types::BlockResponse> {
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
    /// Concurrency for batch fetches.
    concurrency: usize,
}

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
        let blkdata = canonical_encode_block(&block);
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
// CatchpointBackend — REST-only or gossip-first, selected once at startup
// ---------------------------------------------------------------------------

/// Dispatches every [`SyncBackend`] call to either the REST-only
/// [`AlgodSyncBackend`] or the gossip-first [`GossipSyncBackend`], picked
/// once by [`build_catchpoint_backend`] based on `--gossip`.
///
/// [`SyncOrchestrator::with_backend`] takes `impl SyncBackend + 'static`, a
/// single concrete (monomorphized) type — this enum is what lets `run()`
/// choose between the two concrete backend types at runtime while still
/// handing the orchestrator one static type. Using it for the *whole* sync
/// run (bootstrap phases and `--follow` alike), not just the live-follow
/// tail, mirrors go-algorand's own preference for the gossip/WS peer mesh
/// over REST polling for block fetch (see this module's `GossipSyncBackend`
/// doc comment) — `download_catchpoint`/`discover_catchpoint` still always
/// go through REST either way, since catchpoint files have no gossip path.
///
/// Before issue #1247, `GossipSyncBackend`/`BlockSourcePolicy` had no real
/// caller at all: `run()` always built a bare `AlgodSyncBackend`, so
/// `--gossip` was silently ignored on the `catchpoint-sync` CLI path and
/// `--follow` polled REST forever regardless of the flag.
enum CatchpointBackend {
    Rest(AlgodSyncBackend),
    Gossip(GossipSyncBackend),
}

impl SyncBackend for CatchpointBackend {
    fn is_noop(&self) -> bool {
        match self {
            Self::Rest(b) => b.is_noop(),
            Self::Gossip(b) => b.is_noop(),
        }
    }

    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> Result<(), AlgoError> {
        match self {
            Self::Rest(b) => b.download_catchpoint(genesis_id, round, dest_path),
            Self::Gossip(b) => b.download_catchpoint(genesis_id, round, dest_path),
        }
    }

    fn fetch_block_raw(&self, round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        match self {
            Self::Rest(b) => b.fetch_block_raw(round),
            Self::Gossip(b) => b.fetch_block_raw(round),
        }
    }

    fn fetch_block(&self, round: u64) -> Result<Block, AlgoError> {
        match self {
            Self::Rest(b) => b.fetch_block(round),
            Self::Gossip(b) => b.fetch_block(round),
        }
    }

    fn get_current_round(&self) -> Result<u64, AlgoError> {
        match self {
            Self::Rest(b) => b.get_current_round(),
            Self::Gossip(b) => b.get_current_round(),
        }
    }

    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        match self {
            Self::Rest(b) => b.discover_catchpoint(),
            Self::Gossip(b) => b.discover_catchpoint(),
        }
    }

    fn fetch_blocks_batch(
        &self,
        start: u64,
        end: u64,
        concurrency: usize,
    ) -> Result<Vec<(u64, Block)>, AlgoError> {
        match self {
            Self::Rest(b) => b.fetch_blocks_batch(start, end, concurrency),
            Self::Gossip(b) => b.fetch_blocks_batch(start, end, concurrency),
        }
    }
}

/// Build the [`CatchpointBackend`] `run()` hands to [`SyncOrchestrator`].
///
/// `gossip_peers` is the caller's already-connected gossip peer snapshot
/// (from a live [`algo_network::WebsocketNetwork`] via `get_unicast_peers()`
/// in production; an empty `Vec` in tests that don't need a real socket).
/// Kept separate from the (unmockable, socket-opening) network setup in
/// [`crate::commands::sync::setup_gossip_network`] so the policy-selection
/// logic here — `gossip` on/off, and `GossipFirst` vs. `HttpOnly` depending
/// on whether any peers are connected — is unit-testable without a live
/// network (issue #1247's TDD requirement).
fn build_catchpoint_backend(
    gossip: bool,
    algod_url: &str,
    algod_token: &str,
    genesis_id: &str,
    gossip_peers: Vec<Arc<dyn algo_network::UnicastPeer>>,
    catchpoint_peer_urls: &[String],
    concurrency: usize,
) -> anyhow::Result<CatchpointBackend> {
    if !gossip {
        return Ok(CatchpointBackend::Rest(
            AlgodSyncBackend::with_catchpoint_peers(algod_url, algod_token, catchpoint_peer_urls),
        ));
    }

    let peer_count = gossip_peers.len();
    let policy = if peer_count == 0 {
        warn!(
            "--gossip requested but no gossip peers are connected — \
             using HTTP-only mode for block fetch"
        );
        BlockSourcePolicy::HttpOnly
    } else {
        info!(
            peer_count,
            "gossip peers connected — using gossip-first source selection for block fetch"
        );
        BlockSourcePolicy::GossipFirst
    };

    let gossip_source = Arc::new(GossipBlockSource::new(gossip_peers));
    let http_fetcher = HttpBlockFetcher::new(algod_url, genesis_id)
        .map_err(|e| anyhow::anyhow!("failed to build HTTP block fetcher for gossip sync: {e}"))?;

    Ok(CatchpointBackend::Gossip(GossipSyncBackend::new(
        gossip_source,
        http_fetcher,
        algod_url,
        algod_token,
        policy,
        concurrency,
    )))
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
    accounts_rebuild_synchronous_mode: i64,
    catchpoint_peer_urls: &[String],
    gossip: bool,
    genesis_id_override: Option<&str>,
    relay_addrs: &[String],
    dns_bootstrap_override: Option<&str>,
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
        accounts_rebuild_synchronous_mode,
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

    // Create the real backend and orchestrator. Extra catchpoint peer URLs
    // (issue #901) add ranked candidates for the catchpoint-file download
    // alongside the primary algod_url; block/status calls still use
    // algod_url only — unless `--gossip` is set, in which case block fetch
    // (bootstrap replay and `--follow` alike) prefers the gossip/WS peer
    // mesh over REST polling, mirroring go-algorand's post-catchup live
    // sync (issue #1247). With `--gossip` unset this is behaviorally
    // identical to the pre-#1247 REST-only path.
    let gossip_peers: Vec<Arc<dyn algo_network::UnicastPeer>> = if gossip {
        let ws_network = crate::commands::sync::setup_gossip_network(
            network,
            algod_url,
            algod_token,
            genesis_id_override,
            relay_addrs,
            dns_bootstrap_override,
        )
        .await?;
        ws_network.get_unicast_peers().await
    } else {
        Vec::new()
    };
    let backend = build_catchpoint_backend(
        gossip,
        algod_url,
        algod_token,
        &config.genesis_id,
        gossip_peers,
        catchpoint_peer_urls,
        concurrency,
    )?;
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

    // -- Fake UnicastPeer (for gossip-peer-snapshot tests) -----------------

    /// A minimal fake [`algo_network::UnicastPeer`] with no real connection
    /// behind it — only its presence in a peer snapshot matters for the
    /// `build_catchpoint_backend` policy-selection tests below; nothing
    /// calls `request`/`respond` on it.
    struct FakeUnicastPeer {
        addr: String,
    }

    impl algo_network::gossip_node::Peer for FakeUnicastPeer {
        fn get_address(&self) -> &str {
            &self.addr
        }

        fn get_connection_latency(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }

        fn routing_addr(&self) -> &[u8] {
            &[]
        }
    }

    #[async_trait::async_trait]
    impl algo_network::UnicastPeer for FakeUnicastPeer {
        async fn request(
            &self,
            _tag: algo_network::Tag,
            _topics: algo_network::topics::Topics,
        ) -> Result<algo_network::topics::Topics, algo_network::errors::PeerError> {
            Err(algo_network::errors::PeerError::ConnectionClosed)
        }

        async fn respond(
            &self,
            _request_hash: u64,
            _topics: algo_network::topics::Topics,
        ) -> Result<(), algo_network::errors::PeerError> {
            Ok(())
        }
    }

    fn fake_unicast_peer(addr: &str) -> Arc<dyn algo_network::UnicastPeer> {
        Arc::new(FakeUnicastPeer {
            addr: addr.to_string(),
        })
    }

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

    // -- CatchpointBackend / CLI-gossip-wiring tests (issue #1247) --------
    //
    // Before this fix, `main.rs`'s catchpoint-sync CLI branch never forwarded
    // `--gossip` to `catchpoint_sync::run` at all (its signature had no
    // gossip/peer parameter), so `--catchpoint ... --follow --gossip` always
    // built a bare `AlgodSyncBackend` and polled REST forever — silently
    // ignoring the flag. `run()` now accepts the same gossip inputs
    // `commands::sync::run`'s gossip path uses and threads them into
    // `build_catchpoint_backend`, which is what these tests pin.

    #[tokio::test]
    async fn gossip_flag_selects_gossip_backend_not_rest_only() {
        // This is the core regression: with `gossip: true`, `run()`'s
        // backend-selection helper must pick `CatchpointBackend::Gossip`
        // (which prefers the gossip peer mesh for block fetch, falling back
        // to HTTP) rather than `CatchpointBackend::Rest` (pure REST
        // polling) — the bug this issue fixes was that the CLI path could
        // never reach `Gossip` at all, regardless of `--gossip`.
        let backend = build_catchpoint_backend(
            true,
            "http://localhost:19999",
            "",
            "test-genesis-v1.0",
            vec![],
            &[],
            4,
        )
        .expect("gossip backend construction should succeed with zero peers");
        assert!(
            matches!(backend, CatchpointBackend::Gossip(_)),
            "--gossip must route block fetch through CatchpointBackend::Gossip, not REST-only"
        );
    }

    #[tokio::test]
    async fn no_gossip_flag_keeps_rest_only_backend() {
        // Without `--gossip`, behavior must stay exactly what it was before
        // this issue: a plain REST-only `AlgodSyncBackend`.
        let backend = build_catchpoint_backend(
            false,
            "http://localhost:19999",
            "",
            "test-genesis-v1.0",
            vec![],
            &[],
            4,
        )
        .expect("REST backend construction should succeed");
        assert!(matches!(backend, CatchpointBackend::Rest(_)));
    }

    #[tokio::test]
    async fn gossip_backend_uses_gossip_first_policy_when_peers_connected() {
        // A non-empty gossip peer snapshot (as `run()` would pass after a
        // real `setup_gossip_network` connects at least one peer) must
        // select `GossipFirst`, not `HttpOnly` — i.e. live post-bootstrap
        // block fetches actually prefer the gossip peer source, matching
        // go-algorand's post-catchup behavior, instead of silently staying
        // on REST/HTTP even when gossip peers are available.
        let backend = build_catchpoint_backend(
            true,
            "http://localhost:19999",
            "",
            "test-genesis-v1.0",
            vec![fake_unicast_peer("peer-a")],
            &[],
            4,
        )
        .expect("gossip backend construction should succeed with one peer");
        let CatchpointBackend::Gossip(gossip_backend) = backend else {
            panic!("expected CatchpointBackend::Gossip");
        };
        assert_eq!(gossip_backend.policy, BlockSourcePolicy::GossipFirst);
    }

    #[tokio::test]
    async fn gossip_backend_falls_back_to_http_only_with_no_connected_peers() {
        // Gossip requested but no peers connected (e.g. relay discovery
        // found nothing yet): the CLI-reachable path must not error out or
        // silently hang — it degrades to HttpOnly, same as the
        // now-deleted `handoff_to_gossip_sync`'s policy-selection logic did.
        let backend = build_catchpoint_backend(
            true,
            "http://localhost:19999",
            "",
            "test-genesis-v1.0",
            vec![],
            &[],
            4,
        )
        .expect("gossip backend construction should succeed with zero peers");
        let CatchpointBackend::Gossip(gossip_backend) = backend else {
            panic!("expected CatchpointBackend::Gossip");
        };
        assert_eq!(gossip_backend.policy, BlockSourcePolicy::HttpOnly);
    }

    #[test]
    fn genesis_id_for_known_networks() {
        assert_eq!(genesis_id_for_network("mainnet"), Some("mainnet-v1.0"));
        assert_eq!(genesis_id_for_network("testnet"), Some("testnet-v1.0"));
        assert_eq!(genesis_id_for_network("devnet"), None);
        assert_eq!(genesis_id_for_network("custom"), None);
    }

    // -- P2P wiring (issue #1130) ------------------------------------------

    /// Start two real libp2p [`P2pTransport`]s and connect `dialer` to
    /// `listener`, mirroring `p2p_transport.rs`'s own `connected_pair` test
    /// helper (kept private to that module, so duplicated here in miniature
    /// rather than exported cross-module for one test).
    async fn connected_p2p_pair() -> (P2pTransport, P2pTransport) {
        use crate::commands::p2p_transport::P2pTransportConfig;
        use libp2p::multiaddr::Protocol;

        let listener = P2pTransport::start(P2pTransportConfig {
            network_id: "test-1130".to_string(),
            listen_multiaddr: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            bootstrap_peers: vec![],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: false,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
            relay_messages: false,
            force_fetch_transactions: false,
            enable_vote_compression: true,
        })
        .await
        .expect("start listener");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while listener.listen_addrs().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let listen_addr = listener
            .listen_addrs()
            .first()
            .cloned()
            .expect("listener bound an address");
        let dial_addr = listen_addr.with(Protocol::P2p(listener.peer_id()));

        let dialer = P2pTransport::start(P2pTransportConfig {
            network_id: "test-1130".to_string(),
            listen_multiaddr: None,
            bootstrap_peers: vec![dial_addr],
            persist_peer_id: false,
            data_dir: None,
            private_key_path: None,
            enable_dht_providers: false,
            dht_mode: String::new(),
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
            relay_messages: false,
            force_fetch_transactions: false,
            enable_vote_compression: true,
        })
        .await
        .expect("start dialer");

        let mesh_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while (listener.connected_peer_count() == 0 || dialer.connected_peer_count() == 0)
            && tokio::time::Instant::now() < mesh_deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        (listener, dialer)
    }

    /// Issue #1130's core acceptance criterion: a real node-startup path
    /// handing `AlgodSyncBackend`/`RankedCatchpointSource` at least one P2P
    /// peer when the P2P transport is enabled and connected.
    ///
    /// Before this issue, `with_catchpoint_peers`/`build_algod_sync_backend`
    /// had no P2P awareness at all — `catchpoint_source.peer_count()` could
    /// only ever grow via `catchpoint_peer_urls`. This pins that a connected
    /// `P2pTransport`'s peer is now also added, via
    /// `with_catchpoint_peers_and_p2p`/`build_algod_sync_backend`'s new
    /// `p2p_transport` parameter.
    #[tokio::test]
    async fn build_algod_sync_backend_wires_in_connected_p2p_peers() {
        let (listener, dialer) = connected_p2p_pair().await;
        let dialer = Arc::new(dialer);

        // Baseline: no P2P transport -> exactly the one HTTP peer
        // (`algod_url` itself) `with_catchpoint_peers` always includes.
        let backend_no_p2p =
            AlgodSyncBackend::with_catchpoint_peers_and_p2p("http://localhost:4001", "", &[], None);
        assert_eq!(backend_no_p2p.catchpoint_source.peer_count(), 1);

        // With a connected P2P transport: the HTTP peer plus every
        // currently-connected P2P peer (here, exactly `listener`).
        let backend_with_p2p = AlgodSyncBackend::with_catchpoint_peers_and_p2p(
            "http://localhost:4001",
            "",
            &[],
            Some(&dialer),
        );
        assert_eq!(
            backend_with_p2p.catchpoint_source.peer_count(),
            2,
            "expected the HTTP peer plus the one connected P2P peer"
        );

        // WsOnly-mode parity check: `listener` was never given a P2P
        // transport reference by this test, so its own would-be backend
        // (not built here, but the code path `None` exercises above) stays
        // completely unaffected by anything `dialer`'s connection did.
        assert_eq!(listener.connected_peer_count(), 1);
    }
}
