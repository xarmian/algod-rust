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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::{
    AccountSigningKeys, AsyncCryptoVerifier, BlockFactoryBridge, BlockValidatorBridge,
    EventsProcessingMonitor, NetworkAdvancer, Parameters, RandomSource, Service, SystemClock,
};
use algo_avm::group::GroupBudget;
use algo_codec::{
    canonical_encode_block, canonical_encode_block_header_from_block,
    canonical_encode_signed_txn_in_block, canonical_encode_transaction,
};
use algo_ledger::participation::{restore_participation, ParticipationStore};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{
    make_genesis_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis,
    AgreementKeyManagerBridge, AgreementLedgerBridge, BlockFetcher, CatchupService, FetchError,
    FetchedBlockCert, SqliteLedger,
};
use algo_network::local_tx_broadcast::{LocalTxBroadcaster, PoolIngestAdapter};
use algo_network::{
    AgreementNetworkBridge, BlockService, BlockServiceError, GossipNode, LedgerForBlockService,
    Phonebook, WebsocketNetwork, WebsocketNetworkConfig, RELAY_ROLE,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_rest_api::node::BuildVersion;
use algo_rest_api::server::{ApiServer, ApiServerConfig};
use algo_rest_client::GossipBlockSource;
use algo_types::consensus::CONSENSUS_V41;
use algo_types::{AccountData, Address, BlockHeader, Digest, Round, TxnType};
use algo_validate::merkle::{compute_payset_merkle_root, compute_vector_commitment, HashAlgo};
use algo_validate::rules::{has_txn256, has_txn512};
use algo_validate::signature::verify_transaction_signature;
use rand::Rng;
use sha2::{Digest as _, Sha512_256};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::commands::dual_gossip_node;
use crate::commands::network_common::{
    genesis_id_for, resolve_automatic_catchpoint_config, resolve_gossip_fanout,
};
use crate::commands::p2p_transport::{NetworkMode, P2pOptions, P2pTransport, P2pTransportConfig};
use crate::config::RestConfig;
use crate::live_catchup::NormalSyncControl;
use crate::node_interface_impl::{AlgodNodeInterface, NodeInterfaceConfig};

/// Upper bound on how long Ctrl-C is willing to wait for the REST
/// server's graceful shutdown to drain. The `wait_for_round` handler
/// already honours the shutdown token and should return promptly; this
/// cap is defence-in-depth for a hypothetical future handler that
/// forgets to. Short enough that operators aren't tempted to SIGKILL
/// the process, long enough that normal in-flight requests finish.
const REST_SHUTDOWN_HARD_CAP: Duration = Duration::from_secs(5);

/// How long shutdown waits for an in-flight automatic catchpoint export
/// (issue #770) to finish before giving up (issue #794). Bounded rather
/// than unconditional: `export_catchpoint_file` writes atomically (temp
/// file + rename, issue #794), so an abandoned wait can only lose the
/// newest catchpoint being written -- it can never leave a half-written
/// file at a path a restart or a peer's catchpoint download would treat
/// as valid.
const CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// A no-op `EventsProcessingMonitor` for production use.
///
/// Unlike `StubEventsProcessingMonitor` which stores all events in a Vec
/// (leaking memory), this implementation does nothing.
struct NoOpMonitor;

impl EventsProcessingMonitor for NoOpMonitor {
    fn update_events_queue(&self, _queue_name: &str, _queue_length: usize) {}
}

/// A `RandomSource` backed by the OS/thread-local CSPRNG.
///
/// Replaces `StubRandomSource::constant(42)` for production use.
struct RealRandomSource;

impl RandomSource for RealRandomSource {
    fn uint64(&self) -> u64 {
        rand::thread_rng().gen()
    }
}

/// A concrete [`NetworkAdvancer`] that wraps the gossip node.
///
/// When the agreement service makes progress (e.g. a certificate arrives or a
/// block is committed), it calls `on_network_advance()`. This adapter
/// delegates to the `GossipNode::on_network_advance()` method, which triggers
/// mesh maintenance (e.g. clique-resolution peer cycling).
///
/// Mirrors Go's `agreementLedger.n.OnNetworkAdvance()` in `node/impls.go`.
struct GossipNetworkAdvancer {
    node: Arc<dyn GossipNode>,
}

impl NetworkAdvancer for GossipNetworkAdvancer {
    fn on_network_advance(&self) {
        self.node.on_network_advance();
    }
}

/// Fetch a block+cert for `round` from a set of [`UnicastPeer`]s via
/// [`GossipBlockSource`], shared by every [`BlockFetcher`] adapter in this
/// module regardless of which transport supplied the peer list — the
/// `UniEnsBlockReq`/`TopicMsgResp` wire protocol
/// ([`algo_network::block_fetcher`]) and its response decoding are
/// transport-agnostic (issue #591: this is what let the P2P transport reuse
/// the exact same fetch protocol the WS-gossip transport already had,
/// rather than inventing a parallel one).
///
/// Mirrors Go's `universalFetcher.fetchBlock` used in `catchup/service.go`,
/// which is likewise transport-agnostic over its `FetcherClient`
/// implementations.
async fn fetch_block_via_unicast_peers(
    peers: Vec<Arc<dyn algo_network::gossip_node::UnicastPeer>>,
    round: Round,
) -> Result<FetchedBlockCert, FetchError> {
    if peers.is_empty() {
        return Err(FetchError::NoPeersAvailable);
    }
    let source = GossipBlockSource::new(peers);
    let (response, raw_block_data) = source.get_block_with_raw_data(round).await.map_err(|e| {
        FetchError::NetworkError(format!("block fetch failed for round {}: {}", round, e))
    })?;

    // Extract raw payset blobs from the wire-format block bytes.
    // These are used for payset commitment verification, avoiding
    // re-encoding from typed structs which may lose unknown fields.
    let raw_payset_blobs = match algo_codec::extract_raw_payset_blobs_from_block(&raw_block_data) {
        Ok(blobs) => Some(blobs),
        Err(e) => {
            tracing::warn!(
                round = %round,
                error = %e,
                "could not extract raw payset blobs, falling back to typed re-encoding"
            );
            None
        }
    };

    // Try to parse the gossip response's certificate data
    // (rmpv::Value) into a typed Certificate for fork detection.
    // If parsing fails, gracefully degrade to cert: None — the
    // catchup service already has the agreement cert and can
    // still commit blocks; fork detection just won't fire.
    //
    // The rmpv::Value preserves Go's codec tags ("rnd", "per",
    // "prop", etc.) as map keys. We re-encode to bytes and then
    // use the agreement codec's `decode_bundle` which understands
    // those tags, rather than rmp_serde which expects Rust field
    // names.
    let cert = response.cert.and_then(|val| {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &val).ok()?;
        match algo_agreement::codec::decode_bundle(&bytes) {
            Ok(bundle) => Some(algo_agreement::Certificate::from_bundle(&bundle)),
            Err(e) => {
                tracing::debug!(
                    round = %round,
                    error = %e,
                    "could not parse fetched certificate, fork detection unavailable for this block"
                );
                None
            }
        }
    });
    Ok(FetchedBlockCert {
        block: response.block,
        cert,
        raw_payset_blobs,
    })
}

/// A concrete [`BlockFetcher`] that fetches blocks from peers via the gossip
/// network's WebSocket unicast protocol.
///
/// The catchup service runs on a dedicated background thread and calls
/// `fetch_block` synchronously. This adapter bridges the async
/// `GossipBlockSource` to the sync trait by using `tokio::runtime::Handle::block_on`.
///
/// Mirrors Go's `universalFetcher` used in `catchup/service.go`.
struct GossipBlockFetcher {
    ws_network: Arc<WebsocketNetwork>,
    rt_handle: tokio::runtime::Handle,
}

impl BlockFetcher for GossipBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        // SAFETY: This is called from the CatchupService's background std::thread,
        // NOT from a tokio worker thread. Calling block_on from within the tokio
        // runtime would panic.
        self.rt_handle.block_on(async {
            let peers = self.ws_network.get_unicast_peers().await;
            fetch_block_via_unicast_peers(peers, round).await
        })
    }
}

/// A concrete [`BlockFetcher`] that fetches blocks from peers via the P2P
/// transport's `/algorand-ws/2.2.0` stream (issue #591) — the P2P-transport
/// counterpart of [`GossipBlockFetcher`], using
/// [`crate::commands::p2p_transport::P2pTransport::unicast_peers`] instead
/// of `WebsocketNetwork::get_unicast_peers()`.
///
/// This is what `P2pOnly` mode was entirely missing before this issue: with
/// no WS-gossip listener and no WS-gossip peers by design, a single missed
/// live-agreement round previously had no recovery path at all — every
/// catch-up attempt failed with `FetchError::NoPeersAvailable` forever.
struct P2pBlockFetcher {
    p2p_transport: Arc<P2pTransport>,
    rt_handle: tokio::runtime::Handle,
}

impl BlockFetcher for P2pBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        // SAFETY: see `GossipBlockFetcher::fetch_block` — same
        // background-thread / `block_on` constraint applies here.
        self.rt_handle.block_on(async {
            let peers = self.p2p_transport.unicast_peers();
            fetch_block_via_unicast_peers(peers, round).await
        })
    }
}

/// Tries `primary`, falling back to `secondary` only if `primary` fails.
/// Used to wire `Hybrid` mode's [`CatchupService`] (issue #591's acceptance
/// criteria: "ideally Hybrid, falling back to WS-gossip only when P2P fetch
/// fails") — the P2P transport is preferred since it is the transport
/// `Hybrid` mode's agreement traffic actually flows over, but WS-gossip
/// stays available as a safety net exactly as it already was pre-#591.
struct FallbackBlockFetcher {
    primary: Arc<dyn BlockFetcher>,
    secondary: Arc<dyn BlockFetcher>,
}

impl BlockFetcher for FallbackBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        match self.primary.fetch_block(round) {
            Ok(fetched) => Ok(fetched),
            Err(primary_err) => {
                debug!(
                    round = %round,
                    error = %primary_err,
                    "P2P block fetch failed, falling back to WS-gossip"
                );
                self.secondary.fetch_block(round)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Live catchpoint-catchup: pause/resume the agreement Service (issue #940)
// ---------------------------------------------------------------------------

/// The agreement `Service` + `CatchupService` pair currently running, if any.
///
/// These are the *only* two writers to the participate ledger (the
/// agreement service via `ensure_block`/`ensure_digest`, the catchup
/// service via the certificates `ensure_digest` hands it) — see
/// [`ParticipateAgreementControl`]'s doc comment for why stopping exactly
/// this pair (and no other service) is what makes a live catchpoint catchup
/// safe against the ledger.
struct RunningAgreementCycle {
    handle: algo_agreement::service::ServiceHandle,
    catchup_service: CatchupService,
}

/// A [`crate::live_catchup::NormalSyncControl`] that pauses/resumes the live
/// agreement `Service` + `CatchupService` pair for `algod-rust participate`
/// (issue #940, follow-up to issue #937's `node start --follow` wiring).
///
/// # Why the agreement `Service` can't be paused in place
///
/// go-algorand's `SetCatchpointCatchupMode(true)` stops seven independent
/// node services before recreating the node context, then
/// `SetCatchpointCatchupMode(false)` restarts all of them
/// (`../go-algorand/node/node.go:1275-1317`): `net.ClearHandlers()`/
/// `ClearValidatorHandlers()`, `heartbeatService.Stop()`,
/// `stateProofWorker.Stop()`, `txHandler.Stop()`, `agreementService.Shutdown()`,
/// `catchupService.Stop()`, `txPoolSyncerService.Stop()`, `blockService.Stop()`,
/// `ledgerService.Stop()`.
///
/// algod-rust's `algo_agreement::service::Service` has no equivalent
/// in-place pause: `Service::start(self)` consumes `self` and
/// `ServiceHandle::shutdown(self)` consumes `self` too — there is
/// deliberately no "stop, then restart the exact same instance" API,
/// because the two loop threads it spawns own their bridge values
/// (network/ledger/key-manager/etc.) outright once started
/// (`service.rs`'s `Parameters { network, ledger, .. } = self.params;`
/// destructure). The only safe pattern is "shut this instance down
/// completely, then construct and start a brand new one from freshly-built
/// bridges" — [`Self::build_cycle`] does exactly that, and
/// `crates/core/algo-agreement/src/service.rs`'s
/// `service_survives_repeated_reconstruct_start_shutdown_cycles` test pins
/// that this construct/start/shutdown/reconstruct cycle is safe to repeat.
///
/// # Why only these two services are stopped (not go's other five)
///
/// Of go's seven, only `agreementService` and `catchupService` ever write
/// to the ledger in algod-rust's architecture — both through an
/// `AgreementLedgerBridge::ensure_block`/`ensure_digest` call. `txHandler`
/// (routes inbound transactions into the pool), `blockService`/
/// `ledgerService` (serve reads to peers), `txPoolSyncerService` (pool-only
/// sync), and `heartbeatService`/`stateProofWorker` (submit transactions
/// through the pool like any other local sender, never write the ledger
/// directly) are all downstream of the ledger, not writers to it. The
/// acceptance criterion this exists to satisfy — "must not race the live
/// agreement service's own block writes against the catchpoint-catchup
/// task's writes to the same ledger" — is fully satisfied by quiescing
/// exactly the two ledger writers; leaving the other five running (they
/// keep serving reads / relaying transactions through the pause) is a
/// deliberate, narrower deviation from go's exact service list, not an
/// oversight.
///
/// # What's captured once vs. rebuilt every cycle
///
/// Fields below fall into two groups:
/// - Stable for the node's whole lifetime, shared with services that are
///   *not* restarted here (the pool-block-follower, heartbeat, and
///   state-proof-worker threads spawned once in [`run`]): `ledger`,
///   `pool`, `round_advanced` (the condvar those threads block on via
///   `wait_for_round`/`round_notify` — see
///   `algo_ledger::AgreementLedgerBridge::new_with_catchup_and_condvar`'s
///   doc comment for why reusing the *same* `Arc<Condvar>` across rebuilds
///   is required, not optional).
/// - Rebuilt fresh every [`Self::resume`] call, mirroring what [`run`]
///   built exactly once before this issue: the `AgreementNetworkBridge`
///   (handler registration is last-write-wins per
///   `algo_network::handler::Multiplexer::register_handlers`, so a fresh
///   bridge's `start()` naturally supersedes the paused one's — no
///   explicit `clear_handlers` needed), a fresh `ParticipationStore`
///   handle + freshly-loaded signing secrets (participation keys can
///   change on disk while paused), a fresh `BlockValidatorBridge` (its
///   `prev_timestamp` is re-derived from whatever round the ledger is at
///   *after* the catchup, not the round it was at before), a fresh
///   `AsyncCryptoVerifier` (its worker threads are joined cleanly by its
///   `Drop` impl when the old one is dropped), and a fresh
///   `AgreementLedgerBridge`/`cert_rx`/`CatchupService` triple (the
///   certificate channel is 1:1 with one `AgreementLedgerBridge`
///   instance, so the pair must be rebuilt together).
struct ParticipateAgreementControl {
    ledger: Arc<Mutex<SqliteLedger>>,
    ledger_path: PathBuf,
    /// Resolved crash-recovery DB path (issue #953) — see
    /// [`resolve_resource_paths`]. Computed once at startup from
    /// `ledger_path` and the loaded `config.json`'s `HotDataDir`/
    /// `CrashDBDir`, rather than re-derived from `ledger_path` on every
    /// `open_crash_db` call.
    crash_db_path: PathBuf,
    p2p_active_gossip_node: Arc<dyn GossipNode>,
    gossip_node: Arc<WebsocketNetwork>,
    rt_handle: tokio::runtime::Handle,
    agreement_network_config: algo_network::AgreementNetworkConfig,
    partkey_path: PathBuf,
    resolved_genesis_id: String,
    genesis_hash: [u8; 32],
    pool: Arc<TransactionPool>,
    round_advanced: Arc<std::sync::Condvar>,
    participation_metrics: Arc<algo_agreement::ParticipationMetrics>,
    enable_agreement_reporting: bool,
    enable_agreement_time_metrics: bool,
    network_mode: NetworkMode,
    p2p_transport: Option<Arc<P2pTransport>>,
    catchup_parallel_blocks: u64,
    running: tokio::sync::Mutex<Option<RunningAgreementCycle>>,
}

impl ParticipateAgreementControl {
    /// Build and start a fresh agreement `Service` + `CatchupService` pair,
    /// exactly mirroring what [`run`] used to build inline exactly once
    /// (see the removed "4. Build agreement bridges" / "5. Build and start
    /// the catchup service" / "6. Build and start the agreement Service"
    /// steps this replaces). Synchronous and potentially blocking (SQLite
    /// opens, `Mutex::lock`s, and the two `Service::start`/
    /// `CatchupService::start_with_parallelism` calls, which themselves
    /// only spawn `std::thread`s and return promptly) — always called from
    /// inside `spawn_blocking` by [`Self::resume`].
    fn build_cycle(&self) -> anyhow::Result<RunningAgreementCycle> {
        let agreement_network = AgreementNetworkBridge::new(
            self.p2p_active_gossip_node.clone(),
            self.rt_handle.clone(),
            self.agreement_network_config.clone(),
        );

        let network_advancer: Arc<dyn NetworkAdvancer> = Arc::new(GossipNetworkAdvancer {
            node: self.p2p_active_gossip_node.clone(),
        });

        // Reuse the SAME `round_advanced` condvar across every rebuild — the
        // pool-block-follower/heartbeat/state-proof-worker threads (spawned
        // once and never restarted) are blocked waiting on this exact
        // `Arc<Condvar>` instance for the node's whole lifetime.
        let (agreement_ledger, cert_rx) = AgreementLedgerBridge::new_with_catchup_and_condvar(
            self.ledger.clone(),
            network_advancer.clone(),
            self.round_advanced.clone(),
        );

        let latest = {
            let l = self.ledger.lock().expect("ledger lock poisoned");
            l.current_round().0
        };
        let vote_round = Round(latest + 1);
        let keys_round = {
            let params_round = algo_agreement::params_round(vote_round);
            let proto = {
                let l = self.ledger.lock().expect("ledger lock poisoned");
                l.get_block_header_data(params_round.0)
                    .ok()
                    .flatten()
                    .and_then(|bytes| BlockHeader::decode_from_bytes(&bytes).ok())
                    .map(|hdr| hdr.current_protocol)
            };
            match proto.and_then(|p| algo_types::consensus::consensus_params_for_version(&p)) {
                Some(cp) => algo_agreement::balance_round(vote_round, &cp),
                None => {
                    warn!(
                        round = params_round.0,
                        "could not resolve consensus params for the balance-round lookback; \
                         using the vote round as the keys round"
                    );
                    vote_round
                }
            }
        };

        let part_store = ParticipationStore::open(&self.partkey_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to (re)open participation key store at {}: {}",
                self.partkey_path.display(),
                e
            )
        })?;
        let signing_keys = load_signing_keys_for_round(&part_store, vote_round, keys_round);
        if signing_keys.is_empty() {
            warn!(
                vote_round = vote_round.0,
                keys_round = keys_round.0,
                "no participation signing secrets loaded — node will not produce valid proposals or votes"
            );
        } else {
            info!(
                accounts = signing_keys.len(),
                vote_round = vote_round.0,
                keys_round = keys_round.0,
                "loaded participation signing secrets for consensus"
            );
        }
        let key_manager = AgreementKeyManagerBridge::new(part_store);
        let block_factory = BlockFactoryBridge::new(self.pool.clone());

        let prev_timestamp: Option<i64> = {
            let l = self.ledger.lock().expect("ledger lock poisoned");
            let current = l.current_round().0;
            if current > 0 {
                l.get_block_header_data(current)
                    .ok()
                    .flatten()
                    .and_then(|bytes| BlockHeader::decode_from_bytes(&bytes).ok())
                    .map(|hdr| hdr.timestamp)
            } else {
                None
            }
        };
        let block_validator: Arc<BlockValidatorBridge> = Arc::new(BlockValidatorBridge::new(
            self.resolved_genesis_id.clone(),
            self.genesis_hash,
            prev_timestamp,
        ));

        let random_source = RealRandomSource;
        let monitor = NoOpMonitor;

        let crypto_ledger = Arc::new(AgreementLedgerBridge::new(self.ledger.clone()));
        let crypto =
            AsyncCryptoVerifier::new_with_validator(crypto_ledger, Arc::clone(&block_validator));

        let catchup_bridge = Arc::new(AgreementLedgerBridge::new_with_advancer_and_condvar(
            self.ledger.clone(),
            network_advancer,
            agreement_ledger.round_advanced_condvar(),
        ));

        let ws_block_fetcher: Arc<dyn BlockFetcher> = Arc::new(GossipBlockFetcher {
            ws_network: self.gossip_node.clone(),
            rt_handle: self.rt_handle.clone(),
        });
        let block_fetcher: Arc<dyn BlockFetcher> = match (&self.network_mode, &self.p2p_transport) {
            (NetworkMode::P2pOnly, Some(p2p)) => Arc::new(P2pBlockFetcher {
                p2p_transport: Arc::clone(p2p),
                rt_handle: self.rt_handle.clone(),
            }),
            (NetworkMode::Hybrid, Some(p2p)) => Arc::new(FallbackBlockFetcher {
                primary: Arc::new(P2pBlockFetcher {
                    p2p_transport: Arc::clone(p2p),
                    rt_handle: self.rt_handle.clone(),
                }),
                secondary: ws_block_fetcher,
            }),
            _ => ws_block_fetcher,
        };
        let catchup_ledger: Arc<dyn algo_ledger::CatchupLedger> = catchup_bridge;
        let catchup_service = CatchupService::start_with_parallelism(
            cert_rx,
            catchup_ledger,
            block_fetcher,
            self.catchup_parallel_blocks,
        );
        info!("catchup service (re)started");

        let crash_db = open_crash_db(&self.crash_db_path)?;
        let params = Parameters {
            network: agreement_network,
            ledger: agreement_ledger,
            key_manager,
            block_factory,
            block_validator,
            random_source,
            monitor,
            crypto,
            clock: SystemClock::new(),
            crash_db: Some(crash_db),
            signing_keys,
        };
        let agreement_tracer = algo_agreement::Tracer::new(
            self.enable_agreement_reporting,
            self.enable_agreement_time_metrics,
        );
        let service = Service::new(params)
            .with_metrics(self.participation_metrics.clone())
            .with_tracer(agreement_tracer);
        let handle = service.start();
        info!(
            genesis_id = %self.resolved_genesis_id,
            latest_round = latest,
            "consensus participation (re)started"
        );

        Ok(RunningAgreementCycle {
            handle,
            catchup_service,
        })
    }
}

#[async_trait::async_trait]
impl crate::live_catchup::NormalSyncControl for ParticipateAgreementControl {
    async fn pause(&self) {
        let mut guard = self.running.lock().await;
        if let Some(cycle) = guard.take() {
            // `ServiceHandle::shutdown`/`CatchupService::stop` join real OS
            // threads — run them on a blocking-pool thread so this doesn't
            // stall the tokio runtime the REST server and `LiveCatchupManager`
            // share.
            let joined = tokio::task::spawn_blocking(move || {
                let RunningAgreementCycle {
                    handle,
                    mut catchup_service,
                } = cycle;
                // Mirrors `run`'s original shutdown order: agreement service
                // before catchup service, so no new certificates are handed
                // to catchup after it stops.
                handle.shutdown();
                catchup_service.stop();
            })
            .await;
            if let Err(e) = joined {
                warn!(error = %e, "agreement pause: shutdown task panicked");
            }
            info!("consensus participation paused for live catchpoint catchup");
        }
    }

    async fn resume(&self) {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return;
        }
        // `build_cycle` does blocking SQLite/mutex work; run it off the
        // tokio runtime like `pause`'s shutdown does.
        let this = self.clone_for_rebuild();
        let built = tokio::task::spawn_blocking(move || this.build_cycle()).await;
        match built {
            Ok(Ok(cycle)) => {
                *guard = Some(cycle);
            }
            Ok(Err(e)) => {
                warn!(error = %e, "failed to resume consensus participation after live catchpoint catchup");
            }
            Err(e) => {
                warn!(error = %e, "agreement resume: build task panicked");
            }
        }
    }
}

impl ParticipateAgreementControl {
    /// A cheap `Arc`-cloning "clone" of the fields `build_cycle` needs, so
    /// `resume` can move a self-contained value into `spawn_blocking`
    /// without requiring `ParticipateAgreementControl` itself (which holds
    /// the non-`Clone` `running` mutex) to be `Clone`.
    fn clone_for_rebuild(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
            ledger_path: self.ledger_path.clone(),
            crash_db_path: self.crash_db_path.clone(),
            p2p_active_gossip_node: self.p2p_active_gossip_node.clone(),
            gossip_node: self.gossip_node.clone(),
            rt_handle: self.rt_handle.clone(),
            agreement_network_config: self.agreement_network_config.clone(),
            partkey_path: self.partkey_path.clone(),
            resolved_genesis_id: self.resolved_genesis_id.clone(),
            genesis_hash: self.genesis_hash,
            pool: self.pool.clone(),
            round_advanced: self.round_advanced.clone(),
            participation_metrics: self.participation_metrics.clone(),
            enable_agreement_reporting: self.enable_agreement_reporting,
            enable_agreement_time_metrics: self.enable_agreement_time_metrics,
            network_mode: self.network_mode,
            p2p_transport: self.p2p_transport.clone(),
            catchup_parallel_blocks: self.catchup_parallel_blocks,
            running: tokio::sync::Mutex::new(None),
        }
    }
}

/// Domain separation prefix for transaction ID hashing (matches go-algorand).
const TX_PREFIX: &[u8] = b"TX";

/// Compute the transaction ID: SHA512/256("TX" || canonical_encode(txn)).
///
/// The transaction should have genesis fields restored before calling this,
/// since Go's `txn.ID()` is computed over the full transaction including
/// genesis_id and genesis_hash.
fn compute_txid(txn: &algo_types::Transaction) -> [u8; 32] {
    let canonical = canonical_encode_transaction(txn);
    let mut hasher = Sha512_256::new();
    hasher.update(TX_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the effective minimum balance for an account based on its
/// resource holdings and consensus parameters.
///
/// Mirrors Go's `MinBalance()` in `data/basics/userBalance.go`:
/// - Base min_balance
/// - Per asset opted-in: +min_balance each
/// - Per app created: +app_flat_params_min_balance each
/// - Per app opted-in: +app_flat_opt_in_min_balance each
/// - Per extra app page: +app_flat_params_min_balance each
/// - Schema entries: schema_min_balance_per_entry * num_entries
/// - Schema uints: schema_uint_min_balance * num_uint
/// - Schema bytes: schema_bytes_min_balance * num_byte_slice
/// - Per box: +box_flat_min_balance each
/// - Per box byte: +box_byte_min_balance each
fn effective_min_balance(account: &AccountData, params: &algo_types::ConsensusParams) -> u64 {
    let mut min: u64 = params.min_balance;

    // Per-asset holding cost
    min = min.saturating_add(
        params
            .min_balance
            .saturating_mul(account.total_assets_opted_in),
    );

    // Per-app created cost
    min = min.saturating_add(
        params
            .app_flat_params_min_balance
            .saturating_mul(account.total_created_apps),
    );

    // Per-app opted-in cost
    min = min.saturating_add(
        params
            .app_flat_opt_in_min_balance
            .saturating_mul(account.total_apps_opted_in),
    );

    // Schema cost: flat per entry + per-uint + per-bytes
    let schema = &account.total_app_schema;
    let num_entries = schema.num_uint.saturating_add(schema.num_byte_slice);
    min = min.saturating_add(
        params
            .schema_min_balance_per_entry
            .saturating_mul(num_entries),
    );
    min = min.saturating_add(
        params
            .schema_uint_min_balance
            .saturating_mul(schema.num_uint),
    );
    min = min.saturating_add(
        params
            .schema_bytes_min_balance
            .saturating_mul(schema.num_byte_slice),
    );

    // Per extra app page cost
    min = min.saturating_add(
        params
            .app_flat_params_min_balance
            .saturating_mul(account.total_extra_app_pages as u64),
    );

    // Per-box cost
    min = min.saturating_add(
        params
            .box_flat_min_balance
            .saturating_mul(account.total_boxes),
    );

    // Per box byte cost
    min = min.saturating_add(
        params
            .box_byte_min_balance
            .saturating_mul(account.total_box_bytes),
    );

    min
}

/// Apply a signed delta to an unsigned u64 value, clamping at 0.
/// Mirrors Go's `basics.AddSaturate` / `basics.SubSaturate` pattern.
fn apply_delta(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub(delta.unsigned_abs())
    }
}

/// Apply a signed delta to an unsigned u32 value, clamping at 0.
fn apply_delta_u32(base: u32, delta: i64) -> u32 {
    if delta >= 0 {
        base.saturating_add(delta as u32)
    } else {
        base.saturating_sub(delta.unsigned_abs() as u32)
    }
}

/// Read-only snapshot of ledger state captured at evaluator creation.
///
/// Mirrors Go's `roundCowBase` pattern: snapshot the relevant state once at
/// the start of block evaluation, then release the ledger lock so agreement
/// and catchup can proceed concurrently.
///
/// Account reads use a dedicated read-only SQLite connection (via
/// [`algo_ledger::ReadSnapshot`]) that holds a deferred read transaction.
/// In WAL mode this provides true MVCC snapshot isolation — all account
/// reads see the database state as of snapshot creation, regardless of
/// concurrent writes by the main ledger connection (catchup, block commit).
/// The main ledger mutex is acquired only once during construction to
/// capture the lease table and open the snapshot connection; no further
/// locking is needed for individual account lookups.
///
/// For in-memory databases (tests), the `ReadSnapshot` is unavailable
/// because each in-memory connection is independent. In that case we fall
/// back to locking the ledger per account lookup with a round-consistency
/// guard that returns `None` if the ledger has advanced.
struct LedgerSnapshot {
    /// Cached account balances (sender address -> AccountData).
    /// Populated lazily on first access and cached for the block.
    accounts: HashMap<Address, Option<AccountData>>,
    /// Lease table snapshot from the ledger at evaluator creation time.
    lease_table: algo_ledger::LeaseTable,
    /// The round being evaluated.
    round: u64,
    /// The ledger's current round at snapshot creation time.
    /// Used to verify point-in-time consistency when falling back to the
    /// ledger mutex (in-memory DB path).
    snapshot_round: Round,
    /// Read-only snapshot connection for point-in-time account lookups.
    /// `Some` for file-backed databases (production), `None` for in-memory
    /// databases (tests) where a separate connection cannot share state.
    read_snapshot: Option<algo_ledger::ReadSnapshot>,
}

impl LedgerSnapshot {
    /// Create a new snapshot by briefly locking the ledger to capture lease
    /// state, open a read-only snapshot connection, and record the current
    /// round. The ledger lock is released before returning; subsequent
    /// account lookups go through the snapshot connection without locking.
    fn from_ledger(ledger: &Arc<Mutex<SqliteLedger>>, round: u64) -> Self {
        let l = ledger.lock().expect("ledger lock for snapshot");
        // Clone the lease table while holding the lock so the snapshot
        // reflects the actual lease state from prior committed blocks.
        let lease_table = l.lease_table().clone();
        // Capture the ledger's current round for consistency checks
        // (used only in the in-memory fallback path).
        let snapshot_round = l.current_round();
        // Open a read-only snapshot connection. In WAL mode this begins a
        // deferred read transaction that pins the reader to the current DB
        // state. For in-memory databases this returns None.
        let read_snapshot = l.open_read_snapshot();
        drop(l);
        LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table,
            round,
            snapshot_round,
            read_snapshot,
        }
    }

    /// Look up an account, checking the cache first, then the snapshot.
    ///
    /// When a `ReadSnapshot` is available (file-backed DB), account reads
    /// go directly through the snapshot connection — no mutex acquisition.
    /// For in-memory databases, falls back to locking the ledger with a
    /// round-consistency guard.
    fn get_account(
        &mut self,
        addr: &Address,
        ledger: &Arc<Mutex<SqliteLedger>>,
    ) -> Option<AccountData> {
        if let Some(cached) = self.accounts.get(addr) {
            return cached.clone();
        }
        let result = if let Some(ref snap) = self.read_snapshot {
            // Fast path: read from the snapshot connection (no mutex).
            snap.get_account(addr)
        } else {
            // Fallback for in-memory databases: acquire the ledger lock
            // and verify round consistency before reading.
            let l = ledger.lock().expect("ledger lock for account lookup");
            let current = l.current_round();
            if current != self.snapshot_round {
                warn!(
                    snapshot_round = self.snapshot_round.0,
                    current_round = current.0,
                    "ledger advanced during block evaluation; snapshot consistency violated"
                );
                return None;
            }
            l.get_account(addr)
        };
        self.accounts.insert(*addr, result.clone());
        result
    }

    /// Check whether a lease is active in the ledger snapshot.
    ///
    /// The snapshot's lease table was cloned from the ledger at evaluator
    /// creation time, so this is a pure read with no lock acquisition.
    fn check_lease(&self, sender: &Address, lease: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        self.lease_table.check(sender, lease, self.round)
    }
}

/// Per-address resource count deltas tracked in the COW overlay.
///
/// In Go, the cow layer stores modified `AccountData` records that include
/// updated `TotalAssets`, `TotalAppLocalStates`, `TotalAppParams`, etc.
/// We cannot store full `AccountData` because the block evaluator only
/// has snapshot access — so instead we track *deltas* that are merged with
/// snapshot data when computing effective min-balance.
///
/// Each field is a signed delta (i64) so it can represent both additions
/// (asset create, app opt-in) and removals (asset close-out, app delete).
#[derive(Debug, Clone, Default, PartialEq)]
struct ResourceCountDeltas {
    /// Delta for `total_assets_opted_in` (asset holdings).
    /// +1 on acfg create (creator auto-holds), +1 on axfer opt-in,
    /// -1 on axfer close-out.
    delta_total_assets_opted_in: i64,
    /// Delta for `total_created_assets` (asset params owned by creator).
    /// +1 on acfg create, -1 on acfg destroy.
    delta_total_created_assets: i64,
    /// Delta for `total_apps_opted_in` (app local states).
    /// +1 on appl opt-in, -1 on appl close-out / clear-state.
    delta_total_apps_opted_in: i64,
    /// Delta for `total_created_apps` (app params owned by creator).
    /// +1 on appl create, -1 on appl delete.
    delta_total_created_apps: i64,
    /// Delta for `total_extra_app_pages`.
    /// +extra_program_pages on appl create.
    delta_total_extra_app_pages: i64,
    /// Delta for `total_app_schema.num_uint`.
    delta_schema_num_uint: i64,
    /// Delta for `total_app_schema.num_byte_slice`.
    delta_schema_num_byte_slice: i64,
}

/// Copy-on-write overlay that accumulates mutations during block evaluation.
///
/// Mirrors Go's `roundCowState` pattern: reads check the overlay first, then
/// fall back to the snapshot/ledger. Writes go only to the overlay. The
/// overlay is discarded if the block is abandoned.
struct CowOverlay {
    /// Balance adjustments: maps address to remaining microAlgos.
    /// When a transaction is accepted, the sender's fee (and amount for
    /// payment txns) is deducted and the receiver's balance is credited.
    balance_deltas: HashMap<Address, u64>,
    /// Leases recorded within this block. Maps (sender, lease) to last_valid.
    leases: HashMap<(Address, [u8; 32]), u64>,
    /// Transaction IDs seen within this block, for duplicate detection.
    seen_txids: HashSet<[u8; 32]>,
    /// Auth-addr (rekey) overrides accumulated during block evaluation.
    /// Maps sender address to their new auth_addr after a RekeyTo transaction.
    /// `Some(addr)` means rekeyed to `addr`; `None` means rekeyed back to self
    /// (auth_addr cleared). Mirrors Go's `apply.Rekey()` which updates
    /// `acct.AuthAddr` in the cow state.
    auth_addr_deltas: HashMap<Address, Option<Address>>,
    /// Resource count deltas accumulated during block evaluation.
    /// Tracks changes to asset/app counts that affect min-balance computation.
    /// Mirrors Go's cow layer where modified AccountData includes updated
    /// TotalAssets, TotalAppLocalStates, TotalAppParams, etc.
    resource_deltas: HashMap<Address, ResourceCountDeltas>,
}

/// Lease key type used in the COW overlay: (sender, lease_bytes).
type LeaseKey = (Address, [u8; 32]);

/// An incremental checkpoint of `CowOverlay` state for tentative-apply rollback.
///
/// Instead of cloning all three collections (expensive near the 5000-txn limit),
/// we record only the keys that changed since the checkpoint was taken. On
/// rollback we iterate these small vecs and undo each change. On commit we
/// simply drop the checkpoint (clearing the tracking vecs).
///
/// This mirrors the conceptual pattern of Go's child-cow: only the delta
/// needs to be unwound, not the entire state.
struct CowCheckpoint {
    /// Balance keys modified since the checkpoint.
    /// Stores (address, Option<old_balance>). `None` means the key did not
    /// exist before the checkpoint — on rollback we remove it.
    balance_keys: Vec<(Address, Option<u64>)>,
    /// Lease keys added since the checkpoint.
    /// Stores (key, Option<old_last_valid>). `None` means the lease was new
    /// — on rollback we remove it.
    lease_keys: Vec<(LeaseKey, Option<u64>)>,
    /// Transaction IDs added since the checkpoint — on rollback we remove them.
    txid_keys: Vec<[u8; 32]>,
    /// Auth-addr keys modified since the checkpoint.
    /// Stores (address, Option<old_auth_addr>). The outer `Option` follows
    /// the same convention as balance_keys: `None` means the key did not
    /// exist before — on rollback we remove it.
    auth_addr_keys: Vec<(Address, Option<Option<Address>>)>,
    /// Resource delta keys modified since the checkpoint.
    /// Stores (address, Option<old_deltas>). `None` means the key did not
    /// exist before — on rollback we remove it.
    resource_delta_keys: Vec<(Address, Option<ResourceCountDeltas>)>,
}

impl CowOverlay {
    fn new() -> Self {
        CowOverlay {
            balance_deltas: HashMap::new(),
            leases: HashMap::new(),
            seen_txids: HashSet::new(),
            auth_addr_deltas: HashMap::new(),
            resource_deltas: HashMap::new(),
        }
    }

    /// Create an incremental checkpoint for rollback.
    ///
    /// This is O(1) — it just initialises empty tracking vecs. All
    /// subsequent mutations (via `set_balance_tracked`, `record_txid_tracked`,
    /// `record_lease_tracked`) will record the old value so we can undo them.
    fn checkpoint(&self) -> CowCheckpoint {
        CowCheckpoint {
            balance_keys: Vec::new(),
            lease_keys: Vec::new(),
            txid_keys: Vec::new(),
            auth_addr_keys: Vec::new(),
            resource_delta_keys: Vec::new(),
        }
    }

    /// Restore the overlay to a previous checkpoint by undoing only the
    /// mutations recorded since the checkpoint was taken.
    fn restore(&mut self, cp: CowCheckpoint) {
        // Undo balance changes.
        for (addr, old_val) in cp.balance_keys {
            match old_val {
                Some(v) => {
                    self.balance_deltas.insert(addr, v);
                }
                None => {
                    self.balance_deltas.remove(&addr);
                }
            }
        }
        // Undo lease changes.
        for (key, old_val) in cp.lease_keys {
            match old_val {
                Some(v) => {
                    self.leases.insert(key, v);
                }
                None => {
                    self.leases.remove(&key);
                }
            }
        }
        // Undo txid additions.
        for txid in cp.txid_keys {
            self.seen_txids.remove(&txid);
        }
        // Undo auth_addr changes.
        for (addr, old_val) in cp.auth_addr_keys {
            match old_val {
                Some(v) => {
                    self.auth_addr_deltas.insert(addr, v);
                }
                None => {
                    self.auth_addr_deltas.remove(&addr);
                }
            }
        }
        // Undo resource delta changes.
        for (addr, old_val) in cp.resource_delta_keys {
            match old_val {
                Some(v) => {
                    self.resource_deltas.insert(addr, v);
                }
                None => {
                    self.resource_deltas.remove(&addr);
                }
            }
        }
    }

    /// Set a balance in the overlay and record the old value in the checkpoint
    /// for potential rollback. If `cp` is `None`, behaves like `set_balance`.
    fn set_balance_tracked(&mut self, addr: &Address, balance: u64, cp: &mut CowCheckpoint) {
        let old = self.balance_deltas.insert(*addr, balance);
        cp.balance_keys.push((*addr, old));
    }

    /// Record a transaction ID and track it in the checkpoint for rollback.
    fn record_txid_tracked(&mut self, txid: [u8; 32], cp: &mut CowCheckpoint) {
        self.seen_txids.insert(txid);
        cp.txid_keys.push(txid);
    }

    /// Record a lease and track the old value in the checkpoint for rollback.
    fn record_lease_tracked(
        &mut self,
        sender: &Address,
        lease: &[u8; 32],
        last_valid: u64,
        cp: &mut CowCheckpoint,
    ) {
        if *lease == [0u8; 32] {
            return;
        }
        let key = (*sender, *lease);
        let old = self.leases.insert(key, last_valid);
        cp.lease_keys.push((key, old));
    }

    /// Record a rekey (auth_addr change) in the overlay with checkpoint tracking.
    ///
    /// Mirrors Go's `apply.Rekey()`: if `rekey_to == sender`, the auth_addr is
    /// cleared (set to `None`); otherwise it is set to the new address.
    fn set_auth_addr_tracked(
        &mut self,
        sender: &Address,
        rekey_to: &Address,
        cp: &mut CowCheckpoint,
    ) {
        let old = self.auth_addr_deltas.get(sender).cloned();
        // Special case: rekeying to self clears the auth_addr (Go sets it to Address{}).
        let new_auth = if rekey_to == sender {
            None
        } else {
            Some(*rekey_to)
        };
        self.auth_addr_deltas.insert(*sender, new_auth);
        cp.auth_addr_keys.push((*sender, old));
    }

    /// Apply a mutation to the resource count deltas for an address,
    /// recording the old value in the checkpoint for rollback.
    ///
    /// The `mutate` closure receives a mutable reference to the current
    /// `ResourceCountDeltas` for the address (initialised to the default
    /// zero-delta if no entry exists yet).
    fn mutate_resource_deltas_tracked(
        &mut self,
        addr: &Address,
        cp: &mut CowCheckpoint,
        mutate: impl FnOnce(&mut ResourceCountDeltas),
    ) {
        let old = self.resource_deltas.get(addr).cloned();
        let entry = self.resource_deltas.entry(*addr).or_default();
        mutate(entry);
        cp.resource_delta_keys.push((*addr, old));
    }

    /// Get the resource count deltas for an address from the overlay.
    /// Returns `None` if the overlay has no resource delta entry.
    fn get_resource_deltas(&self, addr: &Address) -> Option<&ResourceCountDeltas> {
        self.resource_deltas.get(addr)
    }

    /// Get the auth_addr override for an address from the overlay.
    /// Returns `Some(Some(addr))` if rekeyed to `addr`, `Some(None)` if
    /// rekeyed back to self (auth_addr cleared), `None` if the overlay has
    /// no entry (caller should fall back to the snapshot/ledger).
    fn get_auth_addr(&self, addr: &Address) -> Option<Option<Address>> {
        self.auth_addr_deltas.get(addr).cloned()
    }

    /// Check whether a lease conflicts with an already-included transaction
    /// in this block's overlay.
    fn check_lease_in_overlay(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        round: u64,
    ) -> Result<(), algo_error::AlgoError> {
        // All-zero lease is always allowed.
        if *lease == [0u8; 32] {
            return Ok(());
        }
        if let Some(&last_valid) = self.leases.get(&(*sender, *lease)) {
            if last_valid >= round {
                return Err(algo_error::AlgoError::Ledger {
                    message: "duplicate lease in block".into(),
                });
            }
        }
        Ok(())
    }

    /// Record a lease in the overlay. No-op for zero leases.
    /// Used only in tests; production code uses `record_lease_tracked`.
    #[cfg(test)]
    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        if *lease == [0u8; 32] {
            return;
        }
        self.leases.insert((*sender, *lease), last_valid);
    }

    /// Check whether a transaction ID has already been seen in this block.
    fn check_txid(&self, txid: &[u8; 32]) -> Result<(), algo_error::AlgoError> {
        if self.seen_txids.contains(txid) {
            return Err(algo_error::AlgoError::Ledger {
                message: "duplicate transaction ID in block".into(),
            });
        }
        Ok(())
    }

    /// Record a transaction ID in the overlay.
    /// Used only in tests; production code uses `record_txid_tracked`.
    #[cfg(test)]
    fn record_txid(&mut self, txid: [u8; 32]) {
        self.seen_txids.insert(txid);
    }

    /// Get the effective balance for an address from the overlay.
    /// Returns `None` if the overlay has no entry for this address (caller
    /// should fall back to the snapshot/ledger).
    fn get_balance(&self, addr: &Address) -> Option<u64> {
        self.balance_deltas.get(addr).copied()
    }

    /// Set the effective balance for an address in the overlay.
    /// Used only in tests; production code uses `set_balance_tracked`.
    #[cfg(test)]
    fn set_balance(&mut self, addr: &Address, balance: u64) {
        self.balance_deltas.insert(*addr, balance);
    }
}

/// A `BlockEvaluator` that validates transactions using stateless rules and
/// stateful checks (balance, lease, txid dedup) via a COW overlay.
///
/// Stateless validation covers: well-formedness (fees, round window, note/
/// lease/group size), group ID consistency, group fee pooling, and signature
/// verification. Stateful validation includes balance pre-checks, lease
/// uniqueness, and transaction ID duplicate detection using the COW overlay
/// on top of a ledger snapshot.
struct SimpleBlockEvaluator {
    hdr: algo_types::BlockHeader,
    /// Consensus parameters for the protocol version of this block.
    consensus_params: algo_types::ConsensusParams,
    /// Transactions included in the block so far.
    included_txns: Vec<algo_types::SignedTransaction>,
    /// Running total of serialized transaction bytes (for the per-block cap).
    txn_bytes: usize,
    /// Maximum transaction bytes allowed in this block. This is the minimum
    /// of the caller-provided limit and the consensus protocol limit.
    max_txn_bytes: usize,
    /// Handle to the shared ledger for snapshot reads.
    ledger: Arc<Mutex<SqliteLedger>>,
    /// Read-only snapshot of ledger state captured at evaluator creation.
    snapshot: LedgerSnapshot,
    /// COW overlay accumulating mutations from accepted transaction groups.
    overlay: CowOverlay,
    /// Running total of fees collected in this block.
    /// Mirrors Go's `eval.block.FeesCollected` used in v39+ headers.
    fees_collected: u64,
}

impl SimpleBlockEvaluator {
    /// Restore genesis fields on a signed transaction that may have had them
    /// stripped (STIB format). If `has_genesis_id` is set and genesis_id is
    /// empty, fill it from the block header. If genesis_hash is zero, fill
    /// it from the block header. This is needed for signature verification
    /// and txid computation.
    fn restore_genesis_fields(&self, stx: &mut algo_types::SignedTransaction) {
        if stx.has_genesis_id && stx.txn.genesis_id.is_empty() {
            stx.txn.genesis_id.clone_from(&self.hdr.genesis_id);
        }
        // Restore genesis_hash when the protocol requires it (modern protocols)
        // or when the STIB flag indicates the hash was stripped. On old protocols
        // where genesis_hash is optional, only restore if has_genesis_hash is set
        // to avoid mutating transactions that were legitimately signed without a
        // genesis hash. Mirrors Go's DecodeSignedTxn logic.
        if stx.txn.genesis_hash == [0u8; 32]
            && (self.consensus_params.require_genesis_hash || stx.has_genesis_hash)
        {
            stx.txn.genesis_hash.clone_from(&self.hdr.genesis_hash);
        }
    }

    /// Perform stateless validation only (well-formedness, group ID, fees,
    /// signatures). Returns the group with genesis fields restored so that
    /// `validate_group` can reuse it for txid computation without cloning
    /// the group a second time.
    ///
    /// Used by `test_transaction_group` (which takes `&self`) via
    /// a thin wrapper that discards the returned Vec.
    fn validate_group_stateless_inner(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<Vec<algo_types::SignedTransaction>, algo_error::AlgoError> {
        if txgroup.is_empty() {
            return Err(algo_error::AlgoError::Validation {
                message: "empty transaction group".into(),
            });
        }

        let params = &self.consensus_params;
        let round = self.hdr.round;

        // 1. (formerly) blanket-reject state proof (stpf) transactions here.
        // Issue #814 live mixed-cluster verification: this guard's own
        // rationale -- "state-proof block assembly is unimplemented in this
        // binary" -- went stale the moment #918 implemented
        // `stateproof_service`'s `LocalTxBroadcaster::submit_group` path, and
        // the guard kept firing on it: the Rust node's own state-proof
        // worker submits its locally-built `StateProofTx` through this exact
        // `ingest`/`validate_group_stateless_inner` path, so the blanket
        // rejection silently discarded the node's own real proof before it
        // ever reached the pool. It also rejected a Go peer's legitimately
        // gossiped `StateProofTx` (observed live: `go-node-3` broadcasting
        // its own worker's proof, rejected here with this exact message).
        // go-algorand's own pool has no such rejection --
        // `data/pools/transactionPool.go` special-cases `StateProofTx` for
        // *acceptance* (pool-size overflow allowance, zero-fee exemption at
        // `checkPendingQueueSize`/fee summarization), never excludes it.
        // algod-rust's downstream checks are already stpf-aware and need no
        // help from this guard: `validate_transaction_wellformed` (below)
        // enforces stpf's own field shape (`Address::STATE_PROOF_SENDER`,
        // zero fee/note/group/lease/rekey — `rules.rs`'s dedicated
        // `txn_type == "stpf"` branch), `summarize_fees` prices it at zero
        // fee-usage, and `verify_transaction_signature` already special-cases
        // its zero-signature category (mirrors go's `verify/txn.go:344`).
        //
        // Heartbeat (hb) transactions went through the identical fix in
        // issue #820 for the identical reason: go's own heartbeat service
        // (`heartbeat/service.go`) submits via the same
        // `BroadcastInternalSignedTxGroup` path any locally-originated
        // transaction uses, with no pool-admission special case, and
        // rejecting it here meant algod-rust could never itself propose a
        // block containing a heartbeat -- even one its own heartbeat service
        // had submitted to the pool moments earlier. Heartbeat's own
        // correctness gates (proof verification, challenge eligibility,
        // free-fee eligibility) are enforced elsewhere: LogicSig signature
        // verification a few lines below (this account's accepting
        // program), `block.rs`'s block-level `verify_heartbeat_proof` call,
        // and `apply::apply_heartbeat`'s challenge/vote-ID/seed checks.

        // 2. Per-transaction well-formedness.
        let in_group = txgroup.len() > 1;
        for stx in txgroup {
            algo_validate::validate_transaction_wellformed(
                &stx.txn,
                in_group && params.enable_fee_pooling,
                params,
                None, // SpecialAddresses not available without ledger lookup
            )?;

            // Check that the transaction's round window covers this block's round.
            if round < stx.txn.first_valid || round > stx.txn.last_valid {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction round window [{}, {}] does not cover block round {}",
                        stx.txn.first_valid.0, stx.txn.last_valid.0, round.0,
                    ),
                });
            }
        }

        // 3. Group ID consistency.
        algo_validate::validate_transaction_group(txgroup)?;

        // 4. Group fee total check. Go's `CheckGroupFees`/`SummarizeFees`
        // (`ledger/eval/eval.go`) run unconditionally for every top-level
        // group -- including a size-1 (ungrouped) submission -- not just
        // "multi-txn groups with pooling enabled"; `EnableFeePooling` was a
        // real config flag pre-v28 but go-algorand has since removed it
        // entirely (see `ledger/eval_simple_test.go`'s `TestFeePooling`:
        // "FeePooling was added in v28, but we have now removed the
        // consensus flag"), and never gated whether the group-total *size-
        // pricing surcharge* (v42+) gets computed at all. Gating this call
        // on `in_group` (issue #703's live-parity testing surfaced this: a
        // single oversized-LogicSig transaction, submitted ungrouped, was
        // wrongly accepted underpaid) skipped the only place
        // `logic_sig_program_fee_contribution`'s pooled program-byte
        // surcharge is folded into the required fee -- note/app-args/
        // app-program surcharges are covered by `txn_fee_factor` inside the
        // per-transaction well-formedness check above regardless of
        // grouping, but the LogicSig surcharge is pooled across the group
        // and only visible to `summarize_fees`. `block.rs`'s block-level
        // validation already calls this unconditionally (see 4b there);
        // this matches that established, correct pattern.
        {
            let refs: Vec<&algo_types::SignedTransaction> = txgroup.iter().collect();
            algo_validate::validate_group_fees_with_params(&refs, params).map_err(|e| {
                algo_error::AlgoError::Validation {
                    message: format!("group fee validation failed: {e}"),
                }
            })?;
        }

        // 5. Signature verification.
        // Restore genesis fields before verification — signatures are computed
        // over the ORIGINAL transaction (with genesis_id and genesis_hash), but
        // the pool receives transactions with these fields present. For pool
        // transactions the genesis fields should already be populated, but we
        // ensure they're set matching the block header, mirroring the pattern
        // from block.rs.
        let mut restored: Vec<algo_types::SignedTransaction> = txgroup.to_vec();
        for stx in &mut restored {
            self.restore_genesis_fields(stx);
        }

        // Create a per-group LogicSig budget for logicsig evaluation.
        let mut lsig_budget = GroupBudget::for_logicsig(restored.len());

        for (intra_group_idx, stx) in restored.iter().enumerate() {
            verify_transaction_signature(
                stx,
                &restored,
                intra_group_idx,
                &mut lsig_budget,
                params,
            )?;
        }

        Ok(restored)
    }

    /// Perform stateless validation only, discarding the restored group.
    /// Convenience wrapper for `test_transaction_group` which only needs
    /// the pass/fail result.
    fn validate_group_stateless(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group_stateless_inner(txgroup).map(|_| ())
    }

    /// Validate a transaction group using both stateless and stateful checks.
    ///
    /// Stateful checks (txid dedup, lease uniqueness, balance precheck) require
    /// `&mut self` because the snapshot cache is populated lazily.
    ///
    /// Checks performed (in addition to stateless):
    /// 6. Transaction ID duplicate detection (in-block overlay + ledger)
    /// 7. Lease uniqueness check (in-block overlay + ledger snapshot)
    /// 8. Rekey/auth-addr validation (authorizer matches ledger's auth_addr)
    /// 9. Sender balance precheck (fee + amount against overlay/snapshot)
    fn validate_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // Run all stateless checks first; reuse the restored (genesis fields
        // populated) copies rather than cloning + restoring the group again.
        let restored = self.validate_group_stateless_inner(txgroup)?;

        let round = self.hdr.round;

        // 6. Transaction ID duplicate detection.
        // Compute txid for each transaction (with genesis fields restored)
        // and check for duplicates WITHIN the current group first, then
        // against the in-block overlay. Mirrors Go's cow.checkDup(txid)
        // which checks mods.Txids first.
        {
            let mut group_txids = HashSet::new();
            for stx in &restored {
                let txid = compute_txid(&stx.txn);
                if !group_txids.insert(txid) {
                    return Err(algo_error::AlgoError::Ledger {
                        message: "duplicate transaction ID within group".into(),
                    });
                }
                self.overlay.check_txid(&txid)?;
            }
        }

        // 7. Lease uniqueness check.
        // For each transaction with a non-zero lease, check:
        //   a. Duplicates WITHIN the current group (same sender + lease)
        //   b. The in-block overlay (already-included txns in this block)
        //   c. The ledger snapshot (existing leases from prior blocks)
        // Mirrors Go's cow.checkDup() which checks mods.Txleases then
        // delegates to roundCowBase.checkDup -> ledger.CheckDup.
        {
            let mut group_leases: HashSet<(Address, [u8; 32])> = HashSet::new();
            for stx in &restored {
                if stx.txn.lease != [0u8; 32] {
                    // Check within current group first
                    if !group_leases.insert((stx.txn.sender, stx.txn.lease)) {
                        return Err(algo_error::AlgoError::Ledger {
                            message: "duplicate lease within group".into(),
                        });
                    }
                    // Check overlay (leases from earlier groups in this block)
                    self.overlay.check_lease_in_overlay(
                        &stx.txn.sender,
                        &stx.txn.lease,
                        round.0,
                    )?;
                    // Check ledger snapshot (leases from prior committed blocks)
                    self.snapshot.check_lease(&stx.txn.sender, &stx.txn.lease)?;
                }
            }
        }

        // 8. Rekey/auth-addr validation.
        // Mirrors Go's `transaction()` (eval.go:1183-1195): verify that
        // the transaction's claimed authorizer matches the ledger's expected
        // authorizer for the sender. If the sender has been rekeyed, the
        // signature must be from the rekeyed-to address.
        //
        // The "authorizer" of a signed transaction is:
        //   - `stx.auth_addr` if set (non-None), else `stx.txn.sender`
        // The "correct authorizer" from the ledger is:
        //   - `acct.auth_addr` if set (non-zero), else `sender`
        //
        // We iterate `txgroup` (not `restored`) here because `auth_addr`
        // lives on SignedTransaction and is unaffected by genesis field
        // restoration.
        for stx in txgroup {
            let sender = &stx.txn.sender;
            let correct_authorizer = self.expected_authorizer(sender);

            // The transaction's claimed authorizer (Go's txn.Authorizer()).
            let txn_authorizer = match &stx.auth_addr {
                Some(addr) => *addr,
                None => stx.txn.sender,
            };

            if txn_authorizer != correct_authorizer {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction should have been authorized by {} but was actually authorized by {}",
                        correct_authorizer, txn_authorizer,
                    ),
                });
            }
        }

        // 9. Sender balance precheck.
        // Verify each sender has sufficient balance for fee + amount (for
        // payment transactions). This is a read-only precheck — actual
        // balance mutation is deferred to transaction_group() on acceptance.
        // Mirrors Go's approach of checking balances via cow.lookup() which
        // first checks the overlay, then falls back to the parent/ledger.
        //
        // We accumulate per-sender costs within this group to handle groups
        // where the same sender appears multiple times.
        //
        // Only payment transactions include the `amount` field in the Algo
        // cost. Other transaction types (axfer, acfg, afrz, appl, keyreg,
        // stpf, hb) only cost the fee in Algos.
        let mut group_costs: HashMap<Address, u64> = HashMap::new();
        for stx in txgroup {
            let sender = &stx.txn.sender;
            let cost = if stx.txn.txn_type == TxnType::Pay {
                stx.txn.fee.saturating_add(stx.txn.amount)
            } else {
                stx.txn.fee
            };
            let entry = group_costs.entry(*sender).or_insert(0);
            *entry = entry.saturating_add(cost);
        }

        for (sender, required) in &group_costs {
            // Check overlay first for cumulative effects of earlier groups,
            // then fall back to the ledger snapshot.
            let bal = self.effective_balance(sender);

            if bal < *required {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "sender {} has insufficient balance: need {} microAlgos, have {}",
                        sender, required, bal,
                    ),
                });
            }
        }

        Ok(())
    }
}

impl SimpleBlockEvaluator {
    /// Compute the reward-adjusted balance for an account.
    ///
    /// Mirrors Go's `WithUpdatedRewards()` in `data/basics/userBalance.go`:
    /// before any debit/credit, the raw `MicroAlgos` is adjusted by pending
    /// rewards that have accrued since the account's `RewardsBase` was last
    /// updated. `NotParticipating` accounts are excluded from rewards.
    ///
    /// Formula:
    ///   reward_units = micro_algos / consensus.reward_unit
    ///   rewards_delta = block.rewards_level - account.rewards_base
    ///   pending = reward_units * rewards_delta
    ///   adjusted = micro_algos + pending
    fn balance_with_rewards(&self, acct: &AccountData) -> u64 {
        algo_ledger::compute_pending_rewards(acct, self.hdr.rewards_level)
            .checked_add(acct.micro_algos)
            .expect("reward overflow: account rewards exceeded u64 max")
    }

    /// Get the effective balance for an address, checking the overlay first
    /// then falling back to the snapshot/ledger.
    ///
    /// This is the single source of truth for balance lookups during
    /// evaluation, ensuring cross-group visibility of balance changes.
    ///
    /// When reading from the snapshot, the balance is adjusted for pending
    /// rewards using `balance_with_rewards()`, mirroring Go's
    /// `WithUpdatedRewards()` which is called in `Move()` and balance
    /// operations before any debit or credit.
    fn effective_balance(&mut self, addr: &Address) -> u64 {
        match self.overlay.get_balance(addr) {
            Some(bal) => bal,
            None => self
                .snapshot
                .get_account(addr, &self.ledger)
                .map(|acct| self.balance_with_rewards(&acct))
                .unwrap_or(0),
        }
    }

    /// Get the AccountData for an address, merging snapshot data with any
    /// overlay resource-count deltas.
    ///
    /// Mirrors Go's `cow.lookup(addr)` which returns modified account data
    /// from the cow layer. Resource count fields (total_assets_opted_in,
    /// total_created_assets, total_apps_opted_in, total_created_apps,
    /// total_extra_app_pages, total_app_schema) are adjusted by the
    /// overlay deltas so that effective_min_balance sees the up-to-date
    /// resource counts.
    fn get_account_data(&mut self, addr: &Address) -> Option<AccountData> {
        let mut acct = self.snapshot.get_account(addr, &self.ledger)?;
        if let Some(deltas) = self.overlay.get_resource_deltas(addr) {
            acct.total_assets_opted_in = apply_delta(
                acct.total_assets_opted_in,
                deltas.delta_total_assets_opted_in,
            );
            acct.total_created_assets =
                apply_delta(acct.total_created_assets, deltas.delta_total_created_assets);
            acct.total_apps_opted_in =
                apply_delta(acct.total_apps_opted_in, deltas.delta_total_apps_opted_in);
            acct.total_created_apps =
                apply_delta(acct.total_created_apps, deltas.delta_total_created_apps);
            acct.total_extra_app_pages = apply_delta_u32(
                acct.total_extra_app_pages,
                deltas.delta_total_extra_app_pages,
            );
            acct.total_app_schema.num_uint =
                apply_delta(acct.total_app_schema.num_uint, deltas.delta_schema_num_uint);
            acct.total_app_schema.num_byte_slice = apply_delta(
                acct.total_app_schema.num_byte_slice,
                deltas.delta_schema_num_byte_slice,
            );
        }
        Some(acct)
    }

    /// Determine the expected authorizer for a sender address.
    ///
    /// Mirrors Go's rekey check in `transaction()` (eval.go:1183-1195):
    /// 1. Check the COW overlay for a rekey delta from an earlier transaction
    ///    in this block.
    /// 2. Fall back to the ledger snapshot's `auth_addr` field.
    /// 3. If the account has no auth_addr set, the sender itself is the
    ///    expected authorizer.
    ///
    /// Returns the address that must match `txn.Authorizer()` (i.e.,
    /// `stx.auth_addr` if set, else `stx.txn.sender`).
    fn expected_authorizer(&mut self, sender: &Address) -> Address {
        // 1. Check overlay for rekey delta from earlier in this block.
        if let Some(overlay_auth) = self.overlay.get_auth_addr(sender) {
            return match overlay_auth {
                Some(addr) => addr,
                None => *sender, // rekeyed back to self
            };
        }
        // 2. Fall back to ledger snapshot.
        if let Some(acct) = self.snapshot.get_account(sender, &self.ledger) {
            if let Some(auth) = acct.auth_addr {
                if auth != Address::default() {
                    return auth;
                }
            }
        }
        // 3. Default: sender is its own authorizer.
        *sender
    }
}

impl algo_pool::traits::BlockEvaluator for SimpleBlockEvaluator {
    fn round(&self) -> Round {
        self.hdr.round
    }

    fn pay_set_size(&self) -> usize {
        self.included_txns.len()
    }

    fn test_transaction_group(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // test_transaction_group performs stateless checks only (matching
        // Go's TestTransactionGroup which does well-formedness + group
        // consistency but doesn't mutate evaluator state). The full
        // stateful checks (txid dedup, lease, balance) run in
        // transaction_group() when the group is actually committed.
        self.validate_group_stateless(txgroup)
    }

    fn transaction_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group(txgroup)?;

        // Convert each transaction to STIB (SignedTxnInBlock) format:
        // strip genesis fields and set has_genesis_id / has_genesis_hash flags.
        // This mirrors go-algorand's BlockHeader.EncodeSignedTxn().
        //
        // Before stripping, validate that genesis fields match the block
        // header. Go returns an error on mismatch — we do the same.
        let mut stibs: Vec<algo_types::SignedTransaction> = Vec::with_capacity(txgroup.len());
        for stx in txgroup {
            let mut stib = stx.clone();

            // Reject transactions whose genesis_id doesn't match the block.
            if !stib.txn.genesis_id.is_empty() && stib.txn.genesis_id != self.hdr.genesis_id {
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "transaction genesis_id '{}' does not match block header '{}'",
                        stib.txn.genesis_id, self.hdr.genesis_id,
                    ),
                });
            }

            // Reject transactions whose genesis_hash doesn't match the block.
            if stib.txn.genesis_hash != [0u8; 32] && stib.txn.genesis_hash != self.hdr.genesis_hash
            {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash does not match block header".into(),
                });
            }

            // If the protocol requires genesis_hash, reject transactions with a zero hash.
            if self.consensus_params.require_genesis_hash && stib.txn.genesis_hash == [0u8; 32] {
                return Err(algo_error::AlgoError::Validation {
                    message: "transaction genesis_hash is required but missing".into(),
                });
            }

            // Strip genesis_id if present (it matched above).
            if !stib.txn.genesis_id.is_empty() {
                stib.txn.genesis_id = String::new();
                stib.has_genesis_id = true;
            }

            // Strip genesis_hash if present (it matched above).
            if stib.txn.genesis_hash != [0u8; 32] {
                stib.txn.genesis_hash = [0u8; 32];
                // Only set has_genesis_hash if the protocol doesn't
                // require it (matching go-algorand behavior).
                if !self.consensus_params.require_genesis_hash {
                    stib.has_genesis_hash = true;
                }
            }

            stibs.push(stib);
        }

        // Use exact byte counting via canonical STIB encoding.
        let max_bytes = self.max_txn_bytes;
        let exact_bytes: usize = stibs
            .iter()
            .map(|stib| canonical_encode_signed_txn_in_block(stib).len())
            .sum();

        if self.txn_bytes + exact_bytes > max_bytes {
            return Err(algo_error::AlgoError::Ledger {
                message: format!(
                    "transaction group would exceed block byte limit ({} + {} > {})",
                    self.txn_bytes, exact_bytes, max_bytes,
                ),
            });
        }

        // ── Tentative apply with rollback ────────────────────────────
        // Create an incremental checkpoint before making any mutations.
        // If the min-balance check (or any later check) fails, we restore
        // only the mutations tracked by the checkpoint, avoiding the cost
        // of cloning the entire overlay. This mirrors Go's child-cow
        // pattern where `cow.commitToParent()` is only called after all
        // checks pass.
        // Note: `included_txns` and `txn_bytes` do not need checkpointing —
        // they are only extended AFTER the min-balance check passes, so
        // rollback never needs to undo them.
        let mut checkpoint = self.overlay.checkpoint();
        let fees_collected_checkpoint = self.fees_collected;

        // The FeeSink address from the block header. Fees are credited
        // to this address in the overlay, mirroring Go's `takeFee()`
        // which calls `cow.Move(sender, FeeSink, fee)`.
        let fee_sink = self.hdr.fee_sink;

        // Record txids, leases, and balance deltas in the COW overlay.
        // This mirrors Go's cow.addTx() which records txids and leases,
        // and the balance mutations from applyTransaction().
        //
        // All mutations use the `_tracked` variants so the checkpoint
        // records what to undo on rollback.
        for stx in txgroup {
            // Restore genesis fields for txid computation.
            let mut restored = stx.clone();
            self.restore_genesis_fields(&mut restored);

            // Record transaction ID.
            let txid = compute_txid(&restored.txn);
            self.overlay.record_txid_tracked(txid, &mut checkpoint);

            // Record lease if non-zero.
            if stx.txn.lease != [0u8; 32] {
                self.overlay.record_lease_tracked(
                    &stx.txn.sender,
                    &stx.txn.lease,
                    stx.txn.last_valid.0,
                    &mut checkpoint,
                );
            }

            // Update balances in overlay following Go's apply.Payment() order:
            // 1. Debit fee from sender, credit fee to FeeSink (takeFee)
            // 2. Move amount from sender to receiver (cow.Move)
            // 3. If close_remainder_to is set, move remaining balance
            //    to close address and zero the sender (cow.CloseAccount)
            let sender = &stx.txn.sender;
            let sender_balance = self.effective_balance(sender);

            // Credit fee to FeeSink (mirrors Go's takeFee -> cow.Move).
            // Track fees_collected running total for the block header.
            //
            // Go's cow.Move(sender, FeeSink, fee) is a no-op when sender
            // IS the FeeSink (src == dst), so the fee neither leaves nor
            // arrives — the balance is unchanged. We mirror this by
            // skipping the fee debit/credit entirely when sender == fee_sink.
            //
            // When the sender IS the FeeSink, Go's takeFee does NOT add
            // the fee to feesCollected (eval.go:1253-1254) because there
            // are no net algos added to the Sink.
            let sender_after_fee = if sender == &fee_sink {
                // Self-transfer of fee: balance unchanged, no fees_collected bump.
                sender_balance
            } else {
                if stx.txn.fee > 0 {
                    let fee_sink_balance = self.effective_balance(&fee_sink);
                    self.overlay.set_balance_tracked(
                        &fee_sink,
                        fee_sink_balance.saturating_add(stx.txn.fee),
                        &mut checkpoint,
                    );
                    self.fees_collected = self.fees_collected.saturating_add(stx.txn.fee);
                }
                sender_balance.saturating_sub(stx.txn.fee)
            };

            // ── Transaction-type-specific balance mutations ────────
            // In Go, `applyTransaction()` (eval.go:1276) switches on the
            // transaction type after `takeFee()`. Only payment transactions
            // move Algos (amount + close_remainder_to). All other types
            // (keyreg, acfg, axfer, afrz, appl, stpf, hb) only pay the
            // fee — any type-specific side effects (asset units for axfer,
            // app state for appl, etc.) do not affect Algo balances.
            match stx.txn.txn_type {
                TxnType::Pay => {
                    // Credit receiver for payment transactions.
                    // This must happen BEFORE close-out so that when
                    // receiver == sender, the balance is correctly computed
                    // before zeroing. Mirrors Go's cow.Move(sender,
                    // receiver, amount).
                    if stx.txn.amount > 0 && !stx.txn.receiver.is_zero() {
                        let receiver = &stx.txn.receiver;
                        if receiver == sender {
                            // Self-payment: fee is debited but amount is a
                            // no-op (debit and credit cancel out). Just
                            // debit fee.
                            self.overlay.set_balance_tracked(
                                sender,
                                sender_after_fee,
                                &mut checkpoint,
                            );
                        } else {
                            let recv_balance = self.effective_balance(receiver);
                            self.overlay.set_balance_tracked(
                                receiver,
                                recv_balance.saturating_add(stx.txn.amount),
                                &mut checkpoint,
                            );
                            self.overlay.set_balance_tracked(
                                sender,
                                sender_after_fee.saturating_sub(stx.txn.amount),
                                &mut checkpoint,
                            );
                        }
                    } else {
                        self.overlay.set_balance_tracked(
                            sender,
                            sender_after_fee.saturating_sub(stx.txn.amount),
                            &mut checkpoint,
                        );
                    }

                    // Handle close_remainder_to: the sender's entire
                    // remaining balance (after fee + amount + receiver
                    // credit) goes to the close address and the sender's
                    // balance becomes 0. Closing an account to zero is
                    // valid (the account is deleted). Mirrors Go's
                    // apply.Payment() -> cow.CloseAccount().
                    if !stx.txn.close_remainder_to.is_zero() {
                        let close_addr = &stx.txn.close_remainder_to;
                        let remaining = self.effective_balance(sender);
                        if remaining > 0 && close_addr != sender {
                            let close_balance = self.effective_balance(close_addr);
                            self.overlay.set_balance_tracked(
                                close_addr,
                                close_balance.saturating_add(remaining),
                                &mut checkpoint,
                            );
                        }
                        // Sender balance goes to zero after close.
                        self.overlay.set_balance_tracked(sender, 0, &mut checkpoint);
                    }
                }
                // All non-payment transaction types: only the fee (already
                // deducted above) affects Algo balances. Asset transfers
                // move asset units (not Algos), and all other types have no
                // Algo balance side effects beyond the fee.
                _ => {
                    self.overlay
                        .set_balance_tracked(sender, sender_after_fee, &mut checkpoint);
                }
            }

            // Handle RekeyTo: update the sender's auth_addr in the overlay.
            // Mirrors Go's `apply.Rekey()` (apply.go:113-128) which is called
            // in `applyTransaction()` after `takeFee()`. If RekeyTo == sender,
            // the auth_addr is cleared (rekeyed back to self). Otherwise the
            // auth_addr is set to the RekeyTo address. This ensures subsequent
            // transactions from the same sender in this block see the updated
            // authorizer.
            if let Some(rekey_to) = &stx.txn.rekey_to {
                if *rekey_to != Address::default() {
                    self.overlay
                        .set_auth_addr_tracked(sender, rekey_to, &mut checkpoint);
                }
            }

            // ── Resource count delta tracking ────────────────────────
            // Track changes to resource counts that affect min-balance
            // computation. Mirrors Go's cow layer where apply.AssetConfig,
            // apply.AssetTransfer, and apply.ApplicationCall update
            // TotalAssets, TotalAppLocalStates, TotalAppParams, etc.
            match stx.txn.txn_type {
                TxnType::Acfg => {
                    if stx.txn.config_asset == 0 {
                        // Asset create: creator gets +1 total_created_assets
                        // and +1 total_assets_opted_in (auto-holding).
                        // Mirrors Go's asset.go:87-88.
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_assets += 1;
                                d.delta_total_assets_opted_in += 1;
                            });
                    } else if stx.txn.asset_params.is_none() {
                        // Asset destroy: creator gets -1 total_created_assets
                        // and -1 total_assets_opted_in (holding removed).
                        // Mirrors Go's asset.go:149-150.
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_assets -= 1;
                                d.delta_total_assets_opted_in -= 1;
                            });
                    }
                    // Reconfigure (config_asset != 0 && asset_params.is_some())
                    // does not change resource counts.
                }
                TxnType::Axfer => {
                    // Opt-in: sender == asset_receiver, amount == 0, no
                    // close-to. The sender is opting into the asset.
                    // Mirrors Go's asset.go:305 (TotalAssets += 1).
                    let asset_receiver = stx.txn.asset_receiver.unwrap_or_default();
                    if asset_receiver == *sender
                        && stx.txn.asset_amount == 0
                        && stx.txn.asset_close_to.is_none()
                    {
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_assets_opted_in += 1;
                            });
                    }
                    // Close-out: asset_close_to is set.
                    // Mirrors Go's asset.go:419 (TotalAssets -= 1).
                    if let Some(close_to) = &stx.txn.asset_close_to {
                        if !close_to.is_zero() {
                            // The source of the close-out is the sender
                            // (or asset_sender for clawback, but clawback
                            // close is rejected by Go).
                            self.overlay.mutate_resource_deltas_tracked(
                                sender,
                                &mut checkpoint,
                                |d| {
                                    d.delta_total_assets_opted_in -= 1;
                                },
                            );
                        }
                    }
                }
                TxnType::Appl => {
                    if stx.txn.application_id == 0 {
                        // App create: creator gets +1 total_created_apps,
                        // plus schema and extra pages.
                        // Mirrors Go's application.go:106-115.
                        let global_schema = stx
                            .txn
                            .global_state_schema
                            .as_ref()
                            .cloned()
                            .unwrap_or_default();
                        let extra_pages = stx.txn.extra_program_pages;
                        self.overlay
                            .mutate_resource_deltas_tracked(sender, &mut checkpoint, |d| {
                                d.delta_total_created_apps += 1;
                                d.delta_total_extra_app_pages += extra_pages as i64;
                                d.delta_schema_num_uint += global_schema.num_uint as i64;
                                d.delta_schema_num_byte_slice +=
                                    global_schema.num_byte_slice as i64;
                            });
                    } else {
                        match stx.txn.on_completion {
                            1 => {
                                // OptIn: sender gets +1 total_apps_opted_in
                                // plus local schema added to total_app_schema.
                                // Mirrors Go's application.go:301-306.
                                //
                                // NOTE: We don't have access to the app's
                                // local schema from the txn fields alone
                                // (it's stored in app params). For now we
                                // track the opt-in count; the local schema
                                // contribution would require looking up the
                                // app params which the block evaluator doesn't
                                // currently do.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_apps_opted_in += 1;
                                    },
                                );
                            }
                            2 | 3 => {
                                // CloseOut (2) or ClearState (3): sender gets
                                // -1 total_apps_opted_in.
                                // Mirrors Go's application.go:354.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_apps_opted_in -= 1;
                                    },
                                );
                            }
                            5 => {
                                // DeleteApplication: creator gets -1
                                // total_created_apps.
                                // Mirrors Go's application.go:150.
                                //
                                // NOTE: The schema and extra pages removal
                                // would require looking up the app params.
                                // For now we track the app count.
                                self.overlay.mutate_resource_deltas_tracked(
                                    sender,
                                    &mut checkpoint,
                                    |d| {
                                        d.delta_total_created_apps -= 1;
                                    },
                                );
                            }
                            _ => {
                                // NoOp (0), UpdateApplication (4): no
                                // resource count changes.
                            }
                        }
                    }
                }
                _ => {
                    // Pay, KeyReg, AssetFreeze, StateProof, Heartbeat:
                    // no resource count changes.
                }
            }
        }

        // ── Min-balance check after apply ────────────────────────────
        // After tentatively applying all balance mutations for this
        // group, verify that no affected account has dropped below the
        // effective minimum balance. Mirrors Go's `checkMinBalance(cow)`
        // which calls `dataNew.MinBalance(&eval.proto)` accounting for
        // assets, apps, schema, boxes, and extra app pages.
        //
        // Accounts at exactly zero are allowed — this represents a
        // closed/deleted account, matching Go's `data.IsZero()` check.

        // Collect addresses modified in this group for the check.
        let mut modified_addrs: HashSet<Address> = HashSet::new();
        for stx in txgroup {
            modified_addrs.insert(stx.txn.sender);
            // Only payment transactions modify receiver/close-to balances.
            if stx.txn.txn_type == TxnType::Pay {
                if !stx.txn.receiver.is_zero() {
                    modified_addrs.insert(stx.txn.receiver);
                }
                if !stx.txn.close_remainder_to.is_zero() {
                    modified_addrs.insert(stx.txn.close_remainder_to);
                }
            }
        }

        for addr in &modified_addrs {
            // Skip FeeSink, RewardsPool, and StateProofSender from
            // min-balance checks, matching Go's checkMinBalance
            // (eval.go:1113-1119).
            if *addr == self.hdr.fee_sink
                || *addr == self.hdr.rewards_pool
                || *addr == Address::STATE_PROOF_SENDER
            {
                continue;
            }

            let balance = self.effective_balance(addr);
            // A zero balance is valid (account closed/deleted), matching
            // Go's `if data.IsZero() { continue }` in checkMinBalance.
            if balance == 0 {
                continue;
            }
            // Compute the effective min balance from the account's
            // resource counts (assets, apps, schema, boxes).
            let acct_data = self.get_account_data(addr);
            let min_bal = match &acct_data {
                Some(acct) => effective_min_balance(acct, &self.consensus_params),
                // Unknown account with non-zero balance: use base min.
                None => self.consensus_params.min_balance,
            };
            if balance < min_bal {
                // Min-balance violation — rollback overlay and fees.
                self.overlay.restore(checkpoint);
                self.fees_collected = fees_collected_checkpoint;
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "account {} balance {} below minimum {} after transaction group",
                        addr, balance, min_bal,
                    ),
                });
            }
            // Check MaximumMinimumBalance: if the effective min exceeds
            // this threshold, the transaction is rejected. Mirrors Go's
            // checkMinBalance (eval.go:1146-1149). The field is 0 (no
            // limit) from v32+, but earlier versions enforce it.
            let max_min = self.consensus_params.maximum_minimum_balance;
            if max_min > 0 && min_bal > max_min {
                self.overlay.restore(checkpoint);
                self.fees_collected = fees_collected_checkpoint;
                return Err(algo_error::AlgoError::Validation {
                    message: format!(
                        "account {} would use too much space after this transaction. \
                         Minimum balance requirements would be {} (greater than max {})",
                        addr, min_bal, max_min,
                    ),
                });
            }
        }

        // All checks passed — commit the STIB data and byte counts.
        self.txn_bytes += exact_bytes;
        self.included_txns.extend(stibs);

        Ok(())
    }

    fn generate_block(
        &mut self,
        voting_accounts: &[algo_types::Address],
    ) -> Result<algo_types::Block, algo_error::AlgoError> {
        let txn_count = self.included_txns.len() as u64;

        // Take ownership of included transactions for payset assembly.
        let payset = std::mem::take(&mut self.included_txns);

        // Compute the expired-participation-accounts sweep list (issue #526).
        // Mirrors go's `generateKnockOfflineAccountsList`'s expiry half
        // (`ledger/eval/eval.go`), invoked as part of the proposer's own
        // block assembly (`eval.endOfBlock` → `generateKnockOfflineAccountsList`
        // before `resetExpiredOnlineAccountsParticipationKeys` runs at apply
        // time). Without this, a self-produced block never lists an account
        // whose participation key has expired, so the apply-side sweep
        // (`algo_ledger::apply::reset_expired_online_accounts`, which already
        // reads this field correctly) never fires and the account stays
        // `Online` forever.
        let max_expired = self.consensus_params.max_proposed_expired_online_accounts;
        let expired = if max_expired > 0 {
            let candidates = self
                .ledger
                .lock()
                .map_err(|e| algo_error::AlgoError::Ledger {
                    message: format!("ledger lock poisoned: {e}"),
                })?
                .expired_participation_account_candidates(self.hdr.round.0, max_expired)?;
            if candidates.is_empty() {
                None
            } else {
                Some(candidates)
            }
        } else {
            None
        };

        // Compute the absent-participation-accounts sweep list (issue #845).
        // Mirrors go's `generateKnockOfflineAccountsList`'s absentee half
        // (`ledger/eval/eval.go`): for every `Online && IncentiveEligible`
        // account not among this node's own participating addresses or
        // already listed as expired above, check `isAbsent` (silent for
        // longer than its stake-scaled allowance) or an active-challenge
        // failure, and list it for suspension. Without this, a self-produced
        // block's `ParticipationUpdates.AbsentParticipationAccounts` was
        // always empty (`hdr.absent_participation_accounts.clone()` below
        // just carried forward the previous header's -- always `None` --
        // value), so this node never proposed suspending a genuinely absent
        // online account; the apply-side sweep
        // (`algo_ledger::apply::validate_absent_online_accounts`, the
        // consumer/validator side) was already correct.
        let mut absent_exclude: std::collections::HashSet<algo_types::Address> =
            voting_accounts.iter().copied().collect();
        if let Some(expired) = &expired {
            absent_exclude.extend(expired.iter().copied());
        }
        let absent = {
            let candidates = self
                .ledger
                .lock()
                .map_err(|e| algo_error::AlgoError::Ledger {
                    message: format!("ledger lock poisoned: {e}"),
                })?
                .absent_participation_account_candidates(
                    self.hdr.round.0,
                    &self.consensus_params,
                    &absent_exclude,
                )?;
            if candidates.is_empty() {
                None
            } else {
                Some(candidates)
            }
        };

        // Build the block by propagating ALL header fields from self.hdr,
        // then overriding the computed fields (txn_counter, commitments,
        // payset). This ensures fee_sink, rewards_pool, rewards_level,
        // rewards_rate, rewards_residue, rewards_recalculation_round,
        // proposer, and all other header fields are preserved.
        let hdr = &self.hdr;
        let mut block = algo_types::Block {
            round: hdr.round,
            branch: hdr.branch,
            seed: hdr.seed,
            timestamp: hdr.timestamp,
            genesis_id: hdr.genesis_id.clone(),
            genesis_hash: hdr.genesis_hash,
            proposer: hdr.proposer,
            fee_sink: hdr.fee_sink,
            rewards_pool: hdr.rewards_pool,
            rewards_level: hdr.rewards_level,
            rewards_rate: hdr.rewards_rate,
            rewards_residue: hdr.rewards_residue,
            rewards_recalculation_round: hdr.rewards_recalculation_round,
            current_protocol: hdr.current_protocol.clone(),
            next_protocol: hdr.next_protocol.clone(),
            next_protocol_approvals: hdr.next_protocol_approvals,
            next_protocol_switch_on: hdr.next_protocol_switch_on,
            next_protocol_vote_before: hdr.next_protocol_vote_before,
            txn_counter: hdr.txn_counter.saturating_add(txn_count),
            fees_collected: self.fees_collected,
            bonus: hdr.bonus,
            proposer_payout: hdr.proposer_payout,
            prev512: hdr.prev512,
            state_proof_tracking: hdr.state_proof_tracking.clone(),
            upgrade_propose: hdr.upgrade_propose.clone(),
            upgrade_delay: hdr.upgrade_delay,
            upgrade_approve: hdr.upgrade_approve,
            expired_participation_accounts: expired,
            absent_participation_accounts: absent,
            // CongestionTax was already advanced from prev round's Load/Tax by
            // make_next_block_header (go's MakeBlock → NextCongestionTax).
            // Load, however, depends on THIS round's own final payset size, so
            // it can only be computed now that self.txn_bytes reflects every
            // included transaction — mirrors go's `endOfBlock`:
            // `if eval.proto.LoadTracking { eval.block.BlockHeader.Load =
            // ComputeLoad(eval.blockTxBytes, eval.proto.MaxTxnBytesPerBlock) }`.
            // Uses the raw consensus MaxTxnBytesPerBlock (not the possibly
            // smaller caller-provided `self.max_txn_bytes`), matching go.
            load: if self.consensus_params.load_tracking {
                algo_ledger::compute_load(
                    self.txn_bytes as u64,
                    self.consensus_params.max_txn_bytes_per_block,
                )
            } else {
                0
            },
            congestion_tax: hdr.congestion_tax,
            payset,
            // Commitment fields are computed below.
            txn_commitment: [0u8; 32],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
        };

        // Compute the SHA-512/256 Merkle root (the primary `txn` commitment).
        // This matches go-algorand's PaysetCommit() → paysetCommit(PaysetCommitMerkle).
        block.txn_commitment = compute_payset_merkle_root(&block);

        // Protocol-gated vector commitments.
        let proto = &self.hdr.current_protocol;

        // SHA-256 vector commitment (txn256 field, v34+).
        if has_txn256(proto) {
            let vc256 = compute_vector_commitment(&block, HashAlgo::Sha256);
            block.txn256.copy_from_slice(&vc256);
        }

        // SHA-512 vector commitment (txn512 field, v41+).
        if has_txn512(proto) {
            let vc512 = compute_vector_commitment(&block, HashAlgo::Sha512);
            block.txn512.copy_from_slice(&vc512);
        }

        Ok(block)
    }

    fn reset_txn_bytes(&mut self) {
        self.txn_bytes = 0;
    }
}

/// A minimal `PoolLedger` that wraps `SqliteLedger` behind a `Mutex`.
///
/// The `TransactionPool` requires an `Arc<dyn PoolLedger>`, so we provide
/// this thin adapter that delegates to the same SQLite ledger used by the
/// agreement bridges. Reused by `node start --dev` (TASK-264) so its
/// consensus-critical `start_evaluator` (next-round header advance) is not
/// duplicated.
/// Adapter exposing the participation node's ledger to the gossip
/// [`BlockService`], so a Rust node that listens for inbound gossip can serve
/// `/v{n}/{genesisID}/block/{round}` and `UniEnsBlockReq` like a Go relay.
///
/// Before issue #478 only `algod-rust relay` registered a block service, so a
/// Rust node started with `participate --listen-address ... --relay-messages`
/// (the relay role in the #100 stress topology) answered every block request
/// with a 404 / request timeout: Go peers could not catch up from it, and
/// neither could other Rust nodes.
struct ParticipateBlockService {
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl LedgerForBlockService for ParticipateBlockService {
    fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: None,
            })?;
        let latest = ledger.current_round().0;

        let block_data = ledger
            .get_block_data(round)
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?
            .ok_or(BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?;

        let cert_data = ledger
            .get_block_cert(round)
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?
            .unwrap_or_default();

        Ok((block_data, cert_data))
    }

    fn latest_round(&self) -> u64 {
        self.ledger.lock().map(|l| l.current_round().0).unwrap_or(0)
    }
}

/// Serves `UniEnsBlockReq` gossip messages from the local ledger.
///
/// Mirrors `relay.rs`'s `BlockRequestHandler`.
struct ParticipateBlockRequestHandler {
    block_service: Arc<BlockService>,
}

#[async_trait::async_trait]
impl algo_network::MessageHandler for ParticipateBlockRequestHandler {
    async fn handle(&self, msg: algo_network::IncomingMessage) -> algo_network::OutgoingMessage {
        let (response_topics, _guard) = self.block_service.handle_ws_block_request(&msg.data);
        algo_network::OutgoingMessage {
            action: algo_network::ForwardingPolicy::Respond,
            tag: algo_network::Tag::TopicMsgResp,
            payload: Vec::new(),
            topics: Some(response_topics),
        }
    }
}

pub(crate) struct PoolLedgerAdapter {
    ledger: Arc<Mutex<SqliteLedger>>,
    /// In-memory mirror of the recent txtail for duplicate checks —
    /// go-algorand keeps the whole tail in memory (`ledger/txtail.go`)
    /// and never re-reads it from SQLite per submission. See
    /// [`algo_ledger::txtail_cache::TxTailDupCache`].
    dup_cache: Mutex<algo_ledger::txtail_cache::TxTailDupCache>,
    /// Single-entry header cache: `block_hdr`/`consensus_params` are
    /// called for the latest round on every pool ingest; a committed
    /// round's header is immutable, so caching the last one read is
    /// trivially coherent.
    hdr_cache: Mutex<Option<(u64, BlockHeader)>>,
}

impl PoolLedgerAdapter {
    /// Wrap a shared ledger as a pool ledger.
    pub(crate) fn new(ledger: Arc<Mutex<SqliteLedger>>) -> Self {
        Self {
            ledger,
            dup_cache: Mutex::new(algo_ledger::txtail_cache::TxTailDupCache::new()),
            hdr_cache: Mutex::new(None),
        }
    }
}

impl algo_pool::traits::PoolLedger for PoolLedgerAdapter {
    fn latest(&self) -> Round {
        self.ledger
            .lock()
            .map(|l| l.current_round())
            .unwrap_or(Round(0))
    }

    fn block_hdr(&self, round: Round) -> Result<algo_types::BlockHeader, algo_error::AlgoError> {
        // Fast path: a committed round's header never changes, so the
        // last header read can be reused without touching SQLite. Mirrors
        // go's in-memory block-header caching in its ledger trackers
        // (`ledger/txtail.go` keeps `blockHeaderData` in memory for the
        // recent window and serves `BlockHdr` from it).
        if let Ok(cache) = self.hdr_cache.lock() {
            if let Some((cached_round, hdr)) = cache.as_ref() {
                if *cached_round == round.0 {
                    return Ok(hdr.clone());
                }
            }
        }
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("ledger lock poisoned: {e}"),
            })?;
        let hdr_data = ledger
            .get_block_header_data(round.0)
            .map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("block_hdr({}) read error: {e}", round.0),
            })?
            .ok_or_else(|| algo_error::AlgoError::Ledger {
                message: format!("no block header data for round {}", round.0),
            })?;
        let hdr = BlockHeader::decode_from_bytes(&hdr_data).map_err(|e| {
            algo_error::AlgoError::Ledger {
                message: format!("block_hdr({}) decode error: {e}", round.0),
            }
        })?;
        if let Ok(mut cache) = self.hdr_cache.lock() {
            *cache = Some((round.0, hdr.clone()));
        }
        Ok(hdr)
    }

    fn consensus_params(
        &self,
        round: Round,
    ) -> Result<algo_types::ConsensusParams, algo_error::AlgoError> {
        let hdr = self.block_hdr(round)?;
        algo_types::consensus::consensus_params_for_version(&hdr.current_protocol).ok_or_else(
            || algo_error::AlgoError::Ledger {
                message: format!(
                    "unknown protocol version '{}' in block header for round {}",
                    hdr.current_protocol, round.0
                ),
            },
        )
    }

    fn contains_confirmed_txid(&self, txid: algo_types::Digest) -> bool {
        // Mirrors go's ledger txtail duplicate check (`ledger/txtail.go`'s
        // `checkDup`): consult the recent-history window (go's `MaxTxnLife`,
        // 1000 rounds) — a transaction older than that can never be a live
        // duplicate (its own `last_valid` would already have expired).
        //
        // Like go's `txTail` tracker, the window lives in memory
        // (`TxTailDupCache`), loaded from the ledger's txtail rows once and
        // advanced incrementally as blocks commit. The pre-cache
        // implementation re-read and decoded every txtail blob in the
        // window from SQLite on every submission (~1.9 ms/call at 100
        // rounds × 420 txns, measured) — the dominant CPU/allocation sink
        // in the issue #100 stress bench. The cache answers identically
        // (same rows, same window) in O(1).
        let Ok(ledger) = self.ledger.lock() else {
            return false;
        };
        let Ok(mut cache) = self.dup_cache.lock() else {
            return false;
        };
        let current = ledger.current_round().0;
        cache.sync(current, |round| ledger.get_txtail(round).ok().flatten());
        drop(ledger);
        cache.contains(&txid)
    }

    fn start_evaluator(
        &self,
        hdr: algo_types::BlockHeader,
        _payset_hint: usize,
        max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn algo_pool::traits::BlockEvaluator>, algo_error::AlgoError> {
        // `hdr` is the PREVIOUS (committed) block header. The consensus params
        // for the round we're about to build are the previous protocol's unless
        // a protocol switch occurs — and block production never crosses an
        // upgrade (see make_next_block_header), so the previous protocol's
        // params govern.
        let consensus_params = algo_types::consensus::consensus_params_for_version(
            &hdr.current_protocol,
        )
        .ok_or_else(|| {
            // Go returns protocol.Error(hdr.CurrentProtocol) for unknown
            // versions — do the same instead of silently falling back.
            algo_error::AlgoError::Ledger {
                message: format!(
                    "unknown protocol version '{}' in block header",
                    hdr.current_protocol
                ),
            }
        })?;

        // Snapshot the committed state at the previous round — evaluation reads
        // balances as of the block we build on. This briefly acquires the mutex,
        // captures lease state, then releases.
        let mut snapshot = LedgerSnapshot::from_ledger(&self.ledger, hdr.round.0);

        // Advance the header to the next round, mirroring go's
        // eval.StartEvaluator: read the rewards-pool balance (with pending
        // rewards applied at the previous level) and the total reward units,
        // advance the rewards state, then build the next-round header skeleton.
        // Without this the evaluator would carry the previous header verbatim
        // (wrong round/branch and a stale rewards level).
        let next_round = hdr.round.0 + 1;
        let pool_balance = snapshot
            .get_account(&hdr.rewards_pool, &self.ledger)
            .map(|acct| {
                algo_ledger::compute_pending_rewards(&acct, hdr.rewards_level)
                    .saturating_add(acct.micro_algos)
            })
            .unwrap_or(0);
        let (total_reward_units, voters_tracking) = {
            let l = self
                .ledger
                .lock()
                .map_err(|e| algo_error::AlgoError::Ledger {
                    message: format!("ledger lock poisoned: {e}"),
                })?;
            // Issue #780: resolve the voters snapshot cache for the block
            // being built -- (voters_commitment, online_total_weight) for
            // the header's "spt" map, or (vec![], 0) when `next_round` isn't
            // a StateProofInterval multiple or no snapshot has been recorded
            // yet, exactly like go's `stateProofVotersAndTotal`.
            let voters_tracking = algo_ledger::voters_tracker::expected_voters_tracking(
                &*l,
                next_round,
                &consensus_params,
            )?;
            (l.total_reward_units()?, voters_tracking)
        };
        let prev_rewards = algo_ledger::RewardsState {
            rewards_level: hdr.rewards_level,
            rewards_rate: hdr.rewards_rate,
            rewards_residue: hdr.rewards_residue,
            rewards_recalculation_round: hdr.rewards_recalculation_round.0,
        };
        let rewards = algo_ledger::next_rewards_state(
            prev_rewards,
            next_round,
            &consensus_params,
            pool_balance,
            total_reward_units,
        );
        // Proposer wall-clock time (clamped inside make_next_block_header),
        // matching go's MakeBlock `time.Now()`. Falls back to the previous
        // timestamp if the system clock is before the Unix epoch.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(hdr.timestamp);
        let next_hdr =
            algo_ledger::make_next_block_header(&hdr, timestamp, rewards, voters_tracking)?;

        // Use the caller-provided byte limit, or the consensus protocol
        // default if the caller passed 0. Take the minimum of the two when
        // both are non-zero, matching Go's behavior.
        let consensus_max = consensus_params.max_txn_bytes_per_block as usize;
        let max_txn_bytes = if max_txn_bytes_per_block == 0 {
            consensus_max
        } else {
            max_txn_bytes_per_block.min(consensus_max)
        };

        Ok(Box::new(SimpleBlockEvaluator {
            hdr: next_hdr,
            consensus_params,
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes,
            ledger: self.ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// Pool block follower.
// ---------------------------------------------------------------------------

/// Minimal read view over committed blocks, used by [`run_pool_block_follower`]
/// so its catch-up logic can be unit tested without a full `SqliteLedger` +
/// genesis setup.
///
/// `None` from either method means "not available right now" (block not yet
/// readable, or the underlying store is gone) — the follower must retry
/// rather than treat it as "nothing to do".
trait CommittedBlockSource: Send + Sync {
    /// The highest committed round, or `None` if the source is unavailable
    /// (e.g. a poisoned lock), in which case the follower should stop.
    fn current_round(&self) -> Option<u64>;

    /// The full block committed at `round`, or `None` if it isn't readable
    /// yet (including transient errors) — the caller must not advance past
    /// this round on `None`.
    fn get_block(&self, round: u64) -> Option<algo_types::Block>;
}

impl CommittedBlockSource for Arc<Mutex<SqliteLedger>> {
    fn current_round(&self) -> Option<u64> {
        self.lock().ok().map(|l| l.current_round().0)
    }

    fn get_block(&self, round: u64) -> Option<algo_types::Block> {
        let l = self.lock().ok()?;
        let bytes = match l.get_block_data(round) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return None,
            Err(e) => {
                warn!(round, error = %e, "pool follower: could not read committed block");
                return None;
            }
        };
        drop(l);
        match algo_types::Block::decode_from_bytes(&bytes) {
            Ok(b) => Some(b),
            Err(e) => {
                warn!(round, error = %e, "pool follower: could not decode committed block");
                None
            }
        }
    }
}

/// Drive `pool.on_new_block()` for every block committed to the ledger.
///
/// Mirrors go-algorand's ledger block listener (`node.go`'s `blockListener`),
/// which `ledger.go`'s tracker-commit path invokes synchronously for *every*
/// committed round. Here the trigger is `round_advanced`, the same `Condvar`
/// that `AgreementLedgerBridge::ensure_block` notifies immediately after a
/// block commits (see `algo_ledger::agreement_bridge`) — so the pool's
/// pending-block evaluator is rebuilt right after each commit instead of
/// being discovered on a fixed polling cadence.
///
/// Issue #492: the original implementation unconditionally slept for the
/// full `poll_interval` at the *top* of every loop iteration before ever
/// checking the ledger. Under sustained load, round-commit cadence can run
/// faster than `poll_interval`, so by the time the sleep elapsed several
/// rounds had already committed; the drain loop below did catch all of them
/// up, but the *next* sleep started the same fixed-delay race over again
/// against an even busier ledger — so the gap between "ledger round" and
/// "evaluator round" never shrank back to its steady state, it grew with
/// throughput. Waiting on `round_advanced` instead (keeping `poll_interval`
/// only as a bounded fallback for missed/lost notifications, since
/// `ensure_block` notifies *after* releasing its lock) lets this thread
/// react within one wakeup of the commit, independent of round-commit rate.
///
/// This also fixes a silent round-skip in the original loop: it advanced
/// `last_seen` even when the block for that round could not be read back
/// (e.g. a transient decode error), permanently losing that round's
/// `on_new_block` call and leaving the evaluator stuck one round further
/// behind than it needed to be. Now a failed read stops the drain for this
/// tick without advancing `last_seen`, so the same round is retried on the
/// next wakeup.
///
/// `initial_round` (the last round already accounted for, typically the
/// round the pool's evaluator was primed against) is supplied by the
/// caller rather than read from `ledger` here: this function runs inside
/// the follower's own thread, which the OS may not schedule until some
/// arbitrary time after `std::thread::spawn` returns, so deriving it here
/// would race real commits made in that gap and silently treat them as
/// "already seen" without ever calling `on_new_block` for them.
fn run_pool_block_follower<S: CommittedBlockSource>(
    pool: &TransactionPool,
    ledger: &S,
    round_advanced: &std::sync::Condvar,
    stop: &std::sync::atomic::AtomicBool,
    poll_interval: Duration,
    initial_round: u64,
) {
    use std::sync::atomic::Ordering;

    // Paired only with `round_advanced` for `wait_timeout`'s API — it does
    // not, and need not, guard any shared state (see doc comment above on
    // why `ensure_block` can't hand us a mutex whose state transition is
    // safe to rendezvous on).
    let wait_gate = Mutex::new(());

    let mut last_seen = initial_round;

    while !stop.load(Ordering::Relaxed) {
        let latest = match ledger.current_round() {
            Some(r) => r,
            None => break,
        };

        while last_seen < latest {
            let round = last_seen + 1;
            let Some(block) = ledger.get_block(round) else {
                // Not readable yet (or a transient error) — stop draining
                // this tick; we'll retry `round` on the next wakeup instead
                // of silently skipping it.
                break;
            };
            let committed_txids: HashSet<algo_types::Digest> = block
                .payset
                .iter()
                .map(|stx| crate::dev_producer::block_txn_id(stx, &block))
                .collect();
            pool.on_new_block(&block, &committed_txids);
            last_seen = round;
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }

        let guard = wait_gate.lock().expect("wait_gate mutex poisoned");
        let _ = round_advanced.wait_timeout(guard, poll_interval);
    }
}

/// Parse a hex-encoded genesis hash into a 32-byte array.
fn parse_genesis_hash(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        anyhow::bail!(
            "genesis hash must be 64 hex characters (32 bytes), got {} chars",
            hex_str.len()
        );
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in genesis hash at byte {}: {}", i, e))?;
    }
    Ok(arr)
}

/// Load the VRF + one-time-signature signing secrets for the participation
/// key(s) the pseudonode will vote with at `vote_round`, keyed by account
/// address, for the agreement `Parameters.signing_keys` map.
///
/// Without these secrets the `AsyncPseudonode` emits placeholder (zero-filled)
/// VRF proofs and OTS signatures, which the crypto verifier rejects — so the
/// node can never produce a valid proposal or vote and rounds never advance.
/// This is the node-side analogue of Go's wiring, where `account.Participation`
/// carries the `*crypto.VRFSecrets` + `*crypto.OneTimeSignatureSecrets` into the
/// agreement service. Here the secrets live in the [`ParticipationStore`]; we
/// reconstruct them per key via `get_for_round` (VRF from its 32-byte seed, OTS
/// from its msgpack blob).
///
/// Key selection mirrors the public-record key manager *exactly*: we enumerate
/// keys via `get_for_voting_round(vote_round, keys_round)` — the same call
/// `AgreementKeyManagerBridge::voting_keys` makes, applying the
/// `effectiveFirst/effectiveLast` window in addition to raw validity — then load
/// each one's secrets by its participation ID. `keys_round` must be the same
/// online-stake lookback round the pseudonode uses (`balance_round(vote_round)`),
/// so the set of accounts/keys here matches the records the pseudonode will sign
/// under. Using `get_for_round` alone (raw `firstValid/lastValid` only) or a
/// different `keys_round` could load a secret for a record the pseudonode won't
/// use — or the wrong one of several — leaving it signing with mismatched secrets.
///
/// Records are sorted by participation ID before the keep-first step below so the
/// collapse is deterministic (the underlying SQL has no `ORDER BY`).
///
/// Keys with no loadable secret (a legacy record with no voting blob) are skipped;
/// a load error for one key is logged and skipped rather than failing the node.
///
/// This is a **startup snapshot** for the imminent round, handed to the agreement
/// service once; it does not refresh as rounds advance, so it does not survive
/// participation-key validity-window boundaries (a key that becomes effective
/// only later, or a mid-run rotation). Per-round secret refresh in the pseudonode
/// is tracked in TASK-272.
fn load_signing_keys_for_round(
    part_store: &ParticipationStore,
    vote_round: Round,
    keys_round: Round,
) -> HashMap<Address, AccountSigningKeys> {
    let mut signing_keys = HashMap::new();
    let mut records = match part_store.get_for_voting_round(vote_round, keys_round) {
        Ok(records) => records,
        Err(e) => {
            warn!(error = %e, "failed to enumerate participation keys; node will not sign consensus messages");
            return signing_keys;
        }
    };
    // Deterministic keep-first when an account has multiple effective keys:
    // `get_for_voting_round`'s SQL has no `ORDER BY`, so sort by participation ID.
    records.sort_by_key(|a| a.participation_id.0);
    for record in &records {
        match part_store.get_for_round(&record.participation_id, vote_round) {
            Ok(Some(part)) => {
                // `part.parent` is the root account the key votes for; the
                // pseudonode looks up signing keys by that address. The map
                // holds one secret per address, so if an account has more than
                // one simultaneously-effective key (e.g. multiple unregistered
                // keys with NULL/0 effective rounds), only one secret can be
                // represented. Keep the first deterministically and warn rather
                // than silently overwriting — disambiguating per public record
                // needs per-record signing in the pseudonode (TASK-272).
                match signing_keys.entry(part.parent) {
                    std::collections::hash_map::Entry::Occupied(_) => {
                        warn!(
                            account = %record.account,
                            participation_id = %record.participation_id,
                            "multiple effective participation keys for this account; keeping the first loaded secret and ignoring this one (TASK-272)",
                        );
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(AccountSigningKeys {
                            vrf: part.vrf,
                            ots: part.voting,
                        });
                    }
                }
            }
            Ok(None) => {
                // Effective record with no loadable voting secret (legacy
                // record / empty blob) — it simply won't contribute signatures.
            }
            Err(e) => {
                warn!(
                    account = %record.account,
                    participation_id = %record.participation_id,
                    error = %e,
                    "failed to load participation secrets; this key will not sign",
                );
            }
        }
    }
    signing_keys
}

/// Resolved on-disk paths for the tracker DB, block DB, and agreement
/// crash-recovery DB, after applying `algo_config::Local`'s per-resource
/// directory overrides (issue #953: `HotDataDir`/`ColdDataDir`/
/// `TrackerDBDir`/`BlockDBDir`/`CrashDBDir`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedResourcePaths {
    tracker_path: PathBuf,
    block_path: PathBuf,
    crash_path: PathBuf,
}

/// Resolve where the tracker DB, block DB, and agreement crash-recovery DB
/// should live, given the `--ledger-path` prefix and the loaded
/// `config.json` (`algo_config::Local`).
///
/// Mirrors go-algorand's `Local.EnsureAndResolveGenesisDirs`
/// (`../go-algorand/config/localTemplate.go:897-985`) fallback chain —
/// `TrackerDBDir` falls back to `HotDataDir`, `BlockDBDir` falls back to
/// `ColdDataDir`, `CrashDBDir` falls back to `HotDataDir`, and `HotDataDir`/
/// `ColdDataDir` each fall back to the ledger prefix's own directory —
/// adapted to algod-rust's `<prefix>.tracker.sqlite` /
/// `<prefix>.block.sqlite` / `crash.sqlite` filename layout
/// (`../go-algorand/ledger/ledger.go:327,336`, `node/node.go:305-323`)
/// instead of go's per-resource genesis-ID subdirectory layout: overriding
/// a resource's directory relocates its file but keeps the ledger prefix's
/// basename for the tracker/block pair, and `crash.sqlite`'s fixed name
/// (go's `config.CrashFilename`) for the crash DB.
///
/// Every directory empty (the default, and today's pre-#953 behavior)
/// resolves every path to exactly what `SqliteLedger::open`/the old
/// `open_crash_db` produced: `<ledger_path>.tracker.sqlite`,
/// `<ledger_path>.block.sqlite`, and `crash.sqlite` next to the ledger.
///
/// Pure function: unlike go's `EnsureAndResolveGenesisDirs`, this does not
/// create directories or move pre-existing DB files between old/new
/// locations on a reconfigure — the caller must `create_dir_all` each
/// resolved parent directory before opening, and an operator who changes
/// these settings on an existing node is responsible for moving any
/// existing files themselves.
fn resolve_resource_paths(ledger_path: &Path, cfg: &algo_config::Local) -> ResolvedResourcePaths {
    let prefix = algo_ledger::sqlite::derive_ledger_prefix(ledger_path);
    let root_dir = prefix
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let basename = prefix.file_name().map(|n| n.to_owned());

    fn dir_or(cfg_val: &str, fallback: &Path) -> PathBuf {
        if cfg_val.is_empty() {
            fallback.to_path_buf()
        } else {
            PathBuf::from(cfg_val)
        }
    }

    let hot_dir = dir_or(&cfg.hot_data_dir, &root_dir);
    let cold_dir = dir_or(&cfg.cold_data_dir, &root_dir);
    let tracker_dir = dir_or(&cfg.tracker_db_dir, &hot_dir);
    let block_dir = dir_or(&cfg.block_db_dir, &cold_dir);
    let crash_dir = dir_or(&cfg.crash_db_dir, &hot_dir);

    let prefix_in = |dir: &Path| -> PathBuf {
        match &basename {
            Some(name) => dir.join(name),
            None => dir.to_path_buf(),
        }
    };

    ResolvedResourcePaths {
        tracker_path: algo_ledger::sqlite::tracker_path_for_prefix(&prefix_in(&tracker_dir)),
        block_path: algo_ledger::sqlite::block_path_for_prefix(&prefix_in(&block_dir)),
        crash_path: crash_dir.join("crash.sqlite"),
    }
}

/// Open (or create) the agreement crash recovery database at an explicit,
/// already-resolved path.
///
/// Mirrors go-algorand v4.6.0-stable `node/node.go:305-323`, which opens
/// `crash.sqlite` (`config.CrashFilename`) inside the resolved
/// `CrashDBDir`/`HotDataDir`/genesis directory and threads the resulting
/// accessor into `agreement.Parameters`. The caller resolves the path via
/// [`resolve_resource_paths`] (issue #953) so `HotDataDir`/`CrashDBDir`
/// overrides apply uniformly across every call site.
///
/// Without this connection, `Parameters.crash_db` is `None`, the agreement
/// service skips persistence entirely, and a node crash mid-round can lead to
/// equivocation (double-vote) on restart. See [[DOC-21]] §3.7.
fn open_crash_db(crash_db_path: &Path) -> anyhow::Result<rusqlite::Connection> {
    if let Some(dir) = crash_db_path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create crash db directory {}: {}",
                dir.display(),
                e
            )
        })?;
    }
    let conn = rusqlite::Connection::open(crash_db_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open agreement crash db at {}: {}",
            crash_db_path.display(),
            e
        )
    })?;
    info!(
        path = %crash_db_path.display(),
        "opened agreement crash recovery database"
    );
    Ok(conn)
}

/// A REST peer to fetch catchpoint files and blocks from for a live
/// `POST /v2/catchup/:catchpoint` request (issue #940).
///
/// go-algorand's `CatchpointCatchupService` fetches over the same gossip
/// network `--peers` already connects to; algod-rust's catchup path
/// (`algo_ledger::sync::SyncOrchestrator`, shared with the standalone
/// `catchpoint_sync`/`sync` subcommand and `node start --follow`'s live
/// catchup wiring — issue #937) fetches over REST instead, so a
/// participating node — which otherwise has no REST peer configured at
/// all — needs one explicitly. `url: None` (the default) leaves
/// `start_catchup`/`abort_catchup` reporting `NotImplemented`, exactly as
/// before this issue.
#[derive(Debug, Default, Clone)]
pub struct CatchupPeerOptions {
    /// `--catchup-peer`.
    pub url: Option<String>,
    /// `--catchup-peer-token`.
    pub token: String,
}

/// CLI overrides for the networking `config.json` fields wired into
/// `algo-network` (issue #748). Each `None` means "not explicitly passed
/// on the CLI" — the loaded `algo_config::Local` value applies instead
/// (itself already `config.json`-overlaid onto go-matching built-in
/// defaults), closing the gap where these knobs previously existed only
/// on `relay`, not `participate`.
#[derive(Debug, Default, Clone)]
pub struct NetworkOptions {
    /// `--max-per-ip`. Go: `MaxConnectionsPerIP`.
    pub max_connections_per_ip: Option<i64>,
    /// `--incoming-limit`. Go: `IncomingConnectionsLimit`.
    pub incoming_connections_limit: Option<i64>,
    /// `--rate-limit`. Go: `ConnectionsRateLimitingCount`.
    pub connections_rate_limiting_count: Option<u64>,
    /// `--rate-limit-window-seconds`. Go: `ConnectionsRateLimitingWindowSeconds`.
    pub connections_rate_limiting_window_seconds: Option<u64>,
    /// `--broadcast-limit`. Go: `BroadcastConnectionsLimit`.
    pub broadcast_connections_limit: Option<i64>,
    /// `--tls-cert`. Go: `TLSCertFile`.
    pub tls_cert_file: Option<String>,
    /// `--tls-key`. Go: `TLSKeyFile`.
    pub tls_key_file: Option<String>,
}

/// Fully-resolved networking configuration, ready to fold into
/// [`WebsocketNetworkConfig`]. `pub(crate)` so `commands::relay` can reuse
/// the exact same CLI-overrides-`config.json` merge [`NetworkOptions`]
/// already implements for `participate` (issue #768 gives `relay` its own
/// `config.json` loading via the same mechanism).
#[derive(Debug, Clone)]
pub(crate) struct ResolvedNetwork {
    pub(crate) max_connections_per_ip: u32,
    pub(crate) incoming_connections_limit: u32,
    pub(crate) connections_rate_limiting_count: u32,
    pub(crate) broadcast_connections_limit: u32,
    pub(crate) tls_cert_file: Option<String>,
    pub(crate) tls_key_file: Option<String>,
}

use crate::commands::network_common::resolve_unsigned_limit;

/// Go's empty-string-means-unset convention (`TLSCertFile`/`TLSKeyFile`
/// both default to `""`) translated to `Option<String>`.
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

impl NetworkOptions {
    /// Merge CLI overrides onto the loaded `config.json` (`Local`), which
    /// itself already carries go-matching built-in defaults for every
    /// field here.
    pub(crate) fn resolve(&self, local: &algo_config::Local) -> ResolvedNetwork {
        ResolvedNetwork {
            max_connections_per_ip: resolve_unsigned_limit(
                self.max_connections_per_ip
                    .unwrap_or(local.max_connections_per_ip),
            ),
            incoming_connections_limit: resolve_unsigned_limit(
                self.incoming_connections_limit
                    .unwrap_or(local.incoming_connections_limit),
            ),
            connections_rate_limiting_count: self
                .connections_rate_limiting_count
                .unwrap_or(local.connections_rate_limiting_count)
                .try_into()
                .unwrap_or(u32::MAX),
            broadcast_connections_limit: resolve_unsigned_limit(
                self.broadcast_connections_limit
                    .unwrap_or(local.broadcast_connections_limit),
            ),
            tls_cert_file: self
                .tls_cert_file
                .clone()
                .or_else(|| non_empty(&local.tls_cert_file)),
            tls_key_file: self
                .tls_key_file
                .clone()
                .or_else(|| non_empty(&local.tls_key_file)),
        }
    }
}

/// CLI + TOML inputs for the REST API server. CLI fields already
/// shadow the TOML fields at parse time; this struct keeps them
/// together so the resolver sees a single consistent bundle.
#[derive(Debug, Default, Clone)]
pub struct RestOptions {
    /// `--rest-listen` flag value. When `None`, the `[rest].listen`
    /// field from the loaded config file is consulted.
    pub listen: Option<String>,
    /// `--data-dir` flag value. Applied as the API server's data
    /// directory (where `algod.token`, `algod.admin.token`, and
    /// `algod.net` are read/written). Defaults to the `[rest].data_dir`
    /// field when unset.
    pub data_dir: Option<PathBuf>,
    /// `--genesis-path` flag value. Used to read `genesis.json`
    /// verbatim for the REST API's `/genesis` endpoint. Defaults to
    /// `[rest].genesis_path`, then `<data_dir>/genesis.json`.
    pub genesis_path: Option<PathBuf>,
    /// The parsed `[rest]` table, if any. Provides defaults for every
    /// CLI flag above; CLI flags always win when both are set.
    pub file_rest: Option<RestConfig>,
    /// `config.json`'s `DisableAPIAuth` (go: `config.Local.DisableAPIAuth`,
    /// issue #748). There is no CLI flag for this (matching go, which has
    /// none either) — `config.json` is the only source.
    pub disable_api_auth: bool,
    /// `config.json`'s `EndpointAddress` (issue #751) — the headline fix:
    /// go always defaults this to `"127.0.0.1:0"` and always starts REST.
    /// Consulted only when neither `--rest-listen` nor `[rest].listen` is
    /// set; an explicit empty string is treated as an algod-rust-only
    /// "disable REST" affordance (see [`ENDPOINT_ADDRESS`](algo_config)'s
    /// doc comment for the full decision record).
    pub endpoint_address: String,
    /// `config.json`'s `EnablePrivateNetworkAccessHeader` (issue #751).
    pub enable_private_network_access_header: bool,
    /// `config.json`'s `RestReadTimeoutSeconds` (issue #751).
    pub rest_read_timeout_seconds: i64,
    /// `config.json`'s `RestWriteTimeoutSeconds` (issue #751).
    pub rest_write_timeout_seconds: i64,
    /// `config.json`'s `RestConnectionsSoftLimit` (issue #751).
    pub rest_connections_soft_limit: u64,
    /// `config.json`'s `RestConnectionsHardLimit` (issue #751).
    pub rest_connections_hard_limit: u64,
}

/// Fully-resolved REST configuration, ready to hand to [`ApiServer`].
#[derive(Debug, Clone)]
struct ResolvedRest {
    listen: SocketAddr,
    data_dir: Option<PathBuf>,
    api_token: Option<String>,
    admin_token: Option<String>,
    genesis_path: Option<PathBuf>,
    async_backlog_size: Option<usize>,
    disable_api_auth: bool,
    enable_private_network_access_header: bool,
    rest_read_timeout_seconds: i64,
    rest_write_timeout_seconds: i64,
    rest_connections_soft_limit: u64,
    rest_connections_hard_limit: u64,
}

impl RestOptions {
    /// Merge CLI flags, `[rest]` TOML fields, and a sensible
    /// `data_dir` default so the caller gets a concrete socket
    /// address + auxiliary paths. Returns `Ok(None)` when REST is
    /// disabled: no `--rest-listen`, no `[rest].listen`, and either no
    /// `config.json` `EndpointAddress` override or an explicit empty one
    /// (issue #751 — go itself always defaults `EndpointAddress` to
    /// `"127.0.0.1:0"` and always starts REST; algod-rust aligns with that
    /// default while keeping an explicit empty string as its own opt-out).
    fn resolve(&self, default_data_dir: Option<&Path>) -> anyhow::Result<Option<ResolvedRest>> {
        let listen_str = self
            .listen
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.listen.clone()))
            .or_else(|| Some(self.endpoint_address.clone()))
            .filter(|s| !s.is_empty());
        let Some(listen_str) = listen_str else {
            return Ok(None);
        };
        let listen: SocketAddr = listen_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --rest-listen address {:?}: {e}", listen_str))?;

        let data_dir = self
            .data_dir
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.data_dir.clone()))
            .or_else(|| default_data_dir.map(Path::to_path_buf));

        // Token overrides come only from the config file — we avoid a
        // CLI flag so operators aren't tempted to paste secrets on the
        // command line (process-listing leak). The API server defaults
        // to reading `algod.token` / `algod.admin.token` from
        // `data_dir`, so CLI-only setups work without any overrides.
        let (api_token, admin_token) = match self.file_rest.as_ref() {
            Some(rest) => (rest.api_token.clone(), rest.admin_token.clone()),
            None => (None, None),
        };

        let genesis_path = self
            .genesis_path
            .clone()
            .or_else(|| self.file_rest.as_ref().and_then(|r| r.genesis_path.clone()));

        let async_backlog_size = self.file_rest.as_ref().and_then(|r| r.async_backlog_size);

        Ok(Some(ResolvedRest {
            listen,
            data_dir,
            api_token,
            admin_token,
            genesis_path,
            async_backlog_size,
            disable_api_auth: self.disable_api_auth,
            enable_private_network_access_header: self.enable_private_network_access_header,
            rest_read_timeout_seconds: self.rest_read_timeout_seconds,
            rest_write_timeout_seconds: self.rest_write_timeout_seconds,
            rest_connections_soft_limit: self.rest_connections_soft_limit,
            rest_connections_hard_limit: self.rest_connections_hard_limit,
        }))
    }
}

/// Best-effort load of `genesis.json`. Tries the explicit
/// `genesis_path` first and, on `NotFound`, falls back to
/// `<data_dir>/genesis.json`. Returns `Ok(None)` only when *both*
/// candidates are absent (or neither candidate was provided); returns
/// `Err` on real I/O errors (permission denied, partial read, etc.)
/// so a missing file never blocks startup while a misconfigured one
/// does.
///
/// The fallback chain matters when an operator passes
/// `--genesis-path` pointing at a stale location: the documented
/// behaviour is "use the explicit path if present, otherwise try the
/// data-dir default". The prior short-circuit on explicit-NotFound
/// silently synthesized a stub, which could make `/genesis` serve
/// incorrect bytes when a real file was available under `data_dir`.
fn load_genesis_json(
    explicit: Option<&Path>,
    data_dir: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    // Walk the candidate list in priority order. Each entry is
    // (path, origin-label); the label appears in log lines so
    // operators can see which candidate served the response.
    let mut candidates: Vec<(std::path::PathBuf, &'static str)> = Vec::new();
    if let Some(p) = explicit {
        candidates.push((p.to_path_buf(), "--genesis-path"));
    }
    if let Some(dir) = data_dir {
        let derived = dir.join("genesis.json");
        // Deduplicate — if `--genesis-path` already pointed at the
        // same file, we don't want a noisy second read attempt.
        if !candidates.iter().any(|(p, _)| p == &derived) {
            candidates.push((derived, "<data_dir>/genesis.json"));
        }
    }

    for (path, origin) in &candidates {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                info!(
                    path = %path.display(),
                    origin = origin,
                    bytes = contents.len(),
                    "loaded genesis.json"
                );
                return Ok(Some(contents));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Try the next candidate. Missing files are soft
                // failures so the synthesized stub remains available
                // as a last resort.
                continue;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to read genesis.json at {} ({}): {e}",
                    path.display(),
                    origin
                ));
            }
        }
    }
    Ok(None)
}

/// Build a stub genesis.json body for the REST `/genesis` endpoint
/// when no real file is available. Matches go-algorand's minimal
/// `bookkeeping.Genesis` JSON shape (network + id + proto + empty
/// alloc) so downstream clients that only read `network` / `id` work.
fn synthesize_genesis_json(genesis_id: &str, network: &str, proto: &str) -> String {
    // Strip the `network-` prefix from genesis_id to get the suffix
    // go-algorand stores in `id` (e.g. "mainnet-v1.0" → "v1.0").
    let id_suffix = genesis_id
        .strip_prefix(&format!("{network}-"))
        .unwrap_or(genesis_id);
    let value = serde_json::json!({
        "network": network,
        "id": id_suffix,
        "proto": proto,
        "alloc": [],
        "fees": "",
        "rwd": "",
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Read a go-algorand `.partkey` file into a [`Participation`].
///
/// SQLite always opens a database read-write, and even a pure `SELECT` wants
/// to be able to create the journal/WAL sidecar next to the file. Partkeys
/// legitimately live on read-only media — in the stress-test compose the whole
/// `goal network create` tree is bind-mounted `:ro` so no container can
/// corrupt another's key material — so copy the bytes to a private temp file
/// and open *that*. This mirrors how
/// `AlgodNodeInterface::install_participation_key` handles the REST upload
/// path, which has the same constraint for a different reason (it starts from
/// bytes, not a path).
fn restore_partkey_file(path: &Path) -> anyhow::Result<algo_ledger::participation::Participation> {
    use std::io::Write as _;

    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading partkey file {}: {}", path.display(), e))?;
    if bytes.is_empty() {
        anyhow::bail!("partkey file {} is empty", path.display());
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut tmp = std::env::temp_dir();
    tmp.push(format!(
        "algod-rust-import-partkey.{}.{nonce}.sqlite",
        std::process::id()
    ));

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        // Private-key material: 0600 where the platform supports it,
        // exclusive creation everywhere (never follow a pre-placed symlink).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("creating temp partkey copy: {e}"))?;
        f.write_all(&bytes)
            .and_then(|()| f.flush())
            .map_err(|e| anyhow::anyhow!("writing temp partkey copy: {e}"))?;
    }

    let result = (|| {
        let db = algo_ledger::erasable_db::ErasableDb::open(&tmp)
            .map_err(|e| anyhow::anyhow!("opening partkey copy of {}: {}", path.display(), e))?;
        restore_participation(&db)
            .map_err(|e| anyhow::anyhow!("restoring partkey {}: {}", path.display(), e))
    })();

    let _ = std::fs::remove_file(&tmp);
    result
}

/// Import go-algorand `.partkey` files (the single-account
/// `ParticipationAccount` schema written by `goal network create` /
/// `algokey part generate`) into the multi-key participation *registry*
/// that [`ParticipationStore`] — and therefore `--partkey-path` — reads.
///
/// The two schemas are not interchangeable: `restore_participation` reads
/// shape (1), `ParticipationStore::insert` writes shape (2). Without this
/// bridge the only way to get a Go-generated key into a Rust participation
/// node is the REST admin `POST /v2/participation` endpoint, which
/// `participate` does not expose (it never calls
/// `.with_participation_store()`).
///
/// Re-importing an already-present key is a no-op rather than an error, so
/// a container that restarts against a persistent volume converges instead
/// of crash-looping on the `UNIQUE(participationID)` constraint.
///
/// Returns the number of keys newly inserted.
fn import_go_partkeys(store: &ParticipationStore, paths: &[PathBuf]) -> anyhow::Result<usize> {
    let mut inserted = 0usize;
    for path in paths {
        let participation = restore_partkey_file(path)?;
        if participation.parent == Address([0u8; 32]) {
            anyhow::bail!(
                "partkey {} has a missing (zero) parent address",
                path.display()
            );
        }
        match store.insert(&participation) {
            Ok(id) => {
                inserted += 1;
                info!(
                    path = %path.display(),
                    account = %participation.parent,
                    participation_id = %id,
                    first_valid = participation.first_valid.0,
                    last_valid = participation.last_valid.0,
                    "imported go-algorand participation key"
                );
            }
            Err(rusqlite::Error::SqliteFailure(ffi, _))
                if ffi.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                info!(
                    path = %path.display(),
                    account = %participation.parent,
                    "participation key already present in registry; skipping"
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "inserting partkey {} into registry: {}",
                    path.display(),
                    e
                ));
            }
        }
    }
    Ok(inserted)
}

/// Rust port of go-algorand's `config.IsPartKeyFilename`
/// (`../go-algorand/config/keyfile.go:86-91` @ v4.6.0-stable).
///
/// Go builds partkey names with `fmt.Sprintf("%s.%d.%d.partkey", account,
/// firstValid, lastValid)` and recognises a name by *round-tripping* it:
/// `extractPartValidInterval` pulls the two numeric components, then the
/// name is accepted only if re-formatting them reproduces the original
/// string. That round-trip is why `Wallet1.01.1500.partkey` and
/// `Wallet1.+0.1500.partkey` are rejected even though both parse — and it
/// is the behaviour this port has to reproduce, because a name Go skips
/// must be skipped here too (otherwise a mixed cluster disagrees about
/// which files are key material).
///
/// It also means the SQLite sidecars `algod` leaves next to a live partkey
/// (`*.partkey-wal`, `*.partkey-shm`) fall out for free: their final
/// dot-component is not `partkey`.
fn is_partkey_filename(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    let np = parts.len();
    // Go requires at least `<name>.<first>.<last>.partkey`.
    if np < 4 || parts[np - 1] != "partkey" {
        return false;
    }
    let (first_str, last_str) = (parts[np - 3], parts[np - 2]);
    let (Ok(first), Ok(last)) = (first_str.parse::<u64>(), last_str.parse::<u64>()) else {
        return false;
    };
    if first > last {
        return false;
    }
    // The `%d` round-trip: rejects leading zeros, `+` signs, and any other
    // spelling that wouldn't have been produced by `PartKeyFilename`.
    first_str == first.to_string() && last_str == last.to_string()
}

/// Discover go-algorand `.partkey` files in `dir`, mirroring
/// `AlgorandFullNode.loadParticipationKeys`
/// (`../go-algorand/node/node.go:1020-1088` @ v4.6.0-stable), which reads
/// the node's genesis directory and considers every entry whose name
/// satisfies `config.IsPartKeyFilename`.
///
/// Parity notes:
/// - An unreadable directory is a hard error, exactly as in Go
///   (`could not read directory %v`). A *missing* directory is the
///   caller's business — `run` only calls this for paths it has already
///   established exist, so a read failure here really is a broken node.
/// - Names that don't match are skipped silently, as in Go.
/// - Results are sorted so import order (and therefore the log
///   transcript) is deterministic; Go inherits `os.ReadDir`'s sort.
fn discover_partkey_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        anyhow::anyhow!(
            "could not read participation key directory {}: {}",
            dir.display(),
            e
        )
    })?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            anyhow::anyhow!(
                "could not read an entry of participation key directory {}: {}",
                dir.display(),
                e
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_partkey_filename(name) {
            continue;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        found.push(path);
    }
    found.sort();
    Ok(found)
}

/// Resolve the full set of `.partkey` files to bridge into the registry at
/// startup: the explicit `--import-partkey` paths, plus everything
/// auto-discovered under `--partkey-dir` and under the Go-style genesis
/// directory `<data_dir>/<genesis_id>`.
///
/// The genesis-directory scan is the parity path: it is where
/// `goal network create` drops each node's key
/// (`netroot/Node1/phase6net-v1/Wallet1.0.1500.partkey`) and where Go's
/// `loadParticipationKeys` looks. Pointing `--data-dir` at a
/// goal-generated node directory therefore needs no conversion step at
/// all, which is the acceptance bar for issue #468.
///
/// Duplicates are collapsed so a path named explicitly *and* found by a
/// scan is only imported once; `import_go_partkeys` tolerates re-imports
/// anyway, but a deduplicated list keeps the startup log honest.
fn resolve_partkey_imports(
    explicit: &[PathBuf],
    partkey_dirs: &[PathBuf],
    data_dir: Option<&Path>,
    genesis_id: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut dirs: Vec<PathBuf> = partkey_dirs.to_vec();
    // Go parity: algod always scans its genesis dir, no flag required.
    if let Some(data_dir) = data_dir {
        let genesis_dir = data_dir.join(genesis_id);
        if genesis_dir.is_dir() && !dirs.iter().any(|d| d == &genesis_dir) {
            info!(
                dir = %genesis_dir.display(),
                "scanning the genesis directory for participation keys (go-algorand parity)"
            );
            dirs.push(genesis_dir);
        }
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let push_unique = |p: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.iter().any(|existing| existing == &p) {
            out.push(p);
        }
    };
    for p in explicit {
        push_unique(p.clone(), &mut out);
    }
    for dir in &dirs {
        for path in discover_partkey_files(dir)? {
            info!(
                path = %path.display(),
                "discovered go-algorand participation key file"
            );
            push_unique(path, &mut out);
        }
    }
    Ok(out)
}

/// Seed `accountbase` + `accounttotals` from a `genesis.json` when the ledger
/// is brand new.
///
/// This is the same bootstrap `relay --genesis-json` performs (see
/// `commands/relay.rs`, PLAN-32 / TASK-95). A participation node needs it for
/// a *stricter* reason than a relay does: without genesis balances the node
/// has no online stake table, so it can neither run sortition for its own
/// keys nor validate anybody else's proposals — it would sit at round 0
/// forever on a fresh private network.
///
/// "Already seeded" is `accounttotals` row presence, not `online_stake > 0`,
/// so a restart against a populated volume is a no-op.
fn seed_ledger_from_genesis(
    ledger: &mut SqliteLedger,
    genesis_path: &Path,
    latest: u64,
) -> anyhow::Result<()> {
    let already_seeded = ledger.has_account_totals().unwrap_or(false);
    if already_seeded {
        info!(
            latest_round = latest,
            "ledger already seeded (accounttotals row present); skipping genesis bootstrap"
        );
        return Ok(());
    }
    if latest > 0 {
        anyhow::bail!(
            "ledger at round {latest} has blocks but no accounttotals row — refusing to \
             re-seed genesis over accumulated history. Delete the ledger DB pair and restart."
        );
    }
    let genesis_str = std::fs::read_to_string(genesis_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read genesis.json at {}: {}",
            genesis_path.display(),
            e
        )
    })?;
    let genesis = parse_genesis_json(&genesis_str)
        .map_err(|e| anyhow::anyhow!("failed to parse genesis.json: {}", e))?;
    ledger
        .begin_block()
        .map_err(|e| anyhow::anyhow!("begin_block during genesis seed: {}", e))?;
    populate_store(ledger, &genesis)
        .map_err(|e| anyhow::anyhow!("populate_store from genesis: {}", e))?;
    seed_account_totals_from_genesis(ledger, &genesis)
        .map_err(|e| anyhow::anyhow!("seed_account_totals_from_genesis: {}", e))?;
    // Store the round-0 genesis block, exactly as `algod-rust node` does.
    //
    // Without it the ledger has account state but no block-0 *header*, and
    // the block header is where the committee seed lives. Agreement's
    // `LedgerReader::seed(0)` (the lookback seed for round 1) then fails
    // with "seed not found in header for round 0", so the node cannot run
    // sortition for its own keys, cannot verify anybody else's round-1
    // votes, and cannot authenticate a fetched round-1 certificate during
    // catchup — it can never leave round 1. Issue #478.
    let genesis_block = make_genesis_block(&genesis)
        .map_err(|e| anyhow::anyhow!("building genesis block: {}", e))?;
    let blk_data = canonical_encode_block(&genesis_block);
    let hdr_data = canonical_encode_block_header_from_block(&genesis_block);
    ledger
        .put_block(0, &genesis_block.current_protocol, &hdr_data, &blk_data)
        .map_err(|e| anyhow::anyhow!("put_block(0) for genesis: {}", e))?;
    // Seed the running txn-counter from the genesis block header (1000 under
    // modern protocols); block 0 is never applied, so nothing else would.
    ledger.set_txn_counter(genesis_block.txn_counter);
    ledger
        .commit_block()
        .map_err(|e| anyhow::anyhow!("commit_block during genesis seed: {}", e))?;
    info!(
        genesis_path = %genesis_path.display(),
        allocations = genesis.alloc.len(),
        online_stake = ledger.online_stake().unwrap_or(0),
        "seeded ledger from genesis (accountbase + accounttotals + block 0)"
    );
    Ok(())
}

/// Run the participate command: start the agreement protocol and participate
/// in consensus using the provided participation keys.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ledger_path: &Path,
    genesis_id: Option<&str>,
    network: &str,
    peers: &[String],
    partkey_path: &Path,
    import_partkeys: &[PathBuf],
    partkey_dirs: &[PathBuf],
    genesis_json_path: Option<&Path>,
    listen_address: Option<&str>,
    relay_messages: bool,
    genesis_hash_hex: Option<&str>,
    rest_opts: RestOptions,
    p2p_opts: P2pOptions,
    network_opts: NetworkOptions,
    node_config: algo_config::Local,
    dns_bootstrap_override: Option<&str>,
    catchup_opts: CatchupPeerOptions,
) -> anyhow::Result<()> {
    // Load `<data_dir>/consensus.json` (if present) and merge it onto the
    // built-in consensus table, exactly like `node.rs`'s `run_node` already
    // does for `node start` (issue #750/#762). Found missing here during
    // issue #814's live mixed-cluster verification: `participate` --
    // the actual entry point a consensus-participating node runs, and the
    // one `ops/mixed-cluster/` uses -- never called this, so a
    // `consensus.json` override dropped into a participating node's data
    // dir was silently ignored while the very same file worked for
    // `node start`. Must happen before the ledger/participation/agreement
    // machinery below ever evaluates a transaction or block, matching
    // `node.rs`'s write-once/thread-safety contract (see
    // `install_consensus_overrides`'s doc comment).
    if let Some(data_dir) = rest_opts.data_dir.as_deref() {
        let consensus_overrides_path =
            data_dir.join(algo_types::consensus::CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);
        let consensus_protocols = algo_types::consensus::preload_configurable_consensus_protocols(
            data_dir,
        )
        .map_err(|e| anyhow::anyhow!("loading {}: {e}", consensus_overrides_path.display()))?;
        algo_types::consensus::install_consensus_overrides(&consensus_protocols);
        if consensus_overrides_path.exists() {
            info!(path = %consensus_overrides_path.display(), "loaded consensus-parameter overrides");
        }
    }

    let resolved_p2p = p2p_opts.resolve();
    let network_mode = resolved_p2p.mode;
    // Resolve genesis ID: use the provided value, or look it up by network name.
    let resolved_genesis_id = match genesis_id {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => genesis_id_for(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network '{}': use --genesis-id to specify the genesis ID",
                    network
                )
            })?
            .to_string(),
    };

    // Parse genesis hash (default to zeros if not provided).
    let genesis_hash = match genesis_hash_hex {
        Some(hex_str) => parse_genesis_hash(hex_str)?,
        None => [0u8; 32],
    };

    info!(
        ledger = %ledger_path.display(),
        genesis_id = %resolved_genesis_id,
        network = network,
        peers = peers.len(),
        partkey = %partkey_path.display(),
        listen = listen_address.unwrap_or("none"),
        "starting consensus participation"
    );

    // -----------------------------------------------------------------------
    // 1. Open the SQLite ledger (shared between agreement and pool bridges).
    // -----------------------------------------------------------------------
    // Resolve per-resource directory overrides (issue #953:
    // `HotDataDir`/`ColdDataDir`/`TrackerDBDir`/`BlockDBDir`/`CrashDBDir`)
    // before opening anything, so the tracker DB, block DB, and crash DB
    // each land in their configured location.
    let resolved_paths = resolve_resource_paths(ledger_path, &node_config);
    for resolved_dir in [
        resolved_paths.tracker_path.parent(),
        resolved_paths.block_path.parent(),
        resolved_paths.crash_path.parent(),
    ]
    .into_iter()
    .flatten()
    {
        std::fs::create_dir_all(resolved_dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create resource directory {}: {}",
                resolved_dir.display(),
                e
            )
        })?;
    }
    let mut sqlite_ledger = SqliteLedger::open_split(
        &resolved_paths.tracker_path,
        &resolved_paths.block_path,
        Some(algo_ledger::sqlite::derive_ledger_prefix(ledger_path)),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to open ledger (tracker={}, block={}): {}",
            resolved_paths.tracker_path.display(),
            resolved_paths.block_path.display(),
            e
        )
    })?;

    // Apply config-driven storage settings (issue #749):
    // `LedgerSynchronousMode` (SQLite `synchronous` pragma on the main
    // ledger connection) and `DisableLedgerLRUCache` (merkle trie page
    // cache eviction). `open` already applied
    // `algo_ledger::sqlite::DEFAULT_LEDGER_SYNCHRONOUS_MODE`, so this is a
    // no-op unless the operator's `config.json` overrides it.
    sqlite_ledger
        .set_synchronous_mode(node_config.ledger_synchronous_mode)
        .map_err(|e| anyhow::anyhow!("set ledger synchronous mode: {e}"))?;
    sqlite_ledger.set_lru_cache_disabled(node_config.disable_ledger_lru_cache);
    // `MaxAcctLookback` (issue #755): applied as a *floor* on top of
    // `algo_ledger::delta_cache::DEFAULT_WINDOW_SIZE` (320 rounds), never
    // below it -- go's own default (4) would be an unsafe ceiling for
    // algod-rust's hard-window `DeltaCache` (see `set_delta_cache_window`'s
    // doc comment), so this is a no-op at go's default and only extends
    // the window when the operator explicitly asks for more than 320.
    sqlite_ledger.set_delta_cache_window(node_config.max_acct_lookback as usize);

    // `OptimizeAccountsDatabaseOnStartup` (issue #749): run SQLite `VACUUM`
    // on the accounts DB once, mirroring go's
    // `Ledger.reloadLedger` -> `accountUpdates.vacuumDatabase`
    // (`../go-algorand/ledger/ledger.go:268-272`). Opt-in and potentially
    // slow on a large accounts DB, matching go's own "not a typical
    // operational use-case" framing.
    if node_config.optimize_accounts_database_on_startup {
        info!("OptimizeAccountsDatabaseOnStartup: vacuuming accounts database");
        sqlite_ledger
            .vacuum_accounts_database()
            .map_err(|e| anyhow::anyhow!("vacuum accounts database: {e}"))?;
    }

    // Issue #770: automatic interval-driven catchpoint generation, wired
    // into the live block-apply loop via `commit_block`. A no-op unless
    // `config.json` resolves `CatchpointTracking`/`CatchpointInterval`/
    // `CatchpointDir` to an enabled state (see
    // `resolve_automatic_catchpoint_config`).
    if let Some(auto_cfg) = resolve_automatic_catchpoint_config(&node_config) {
        info!(
            interval = auto_cfg.interval,
            file_history_length = auto_cfg.file_history_length,
            dir = %auto_cfg.dir.display(),
            "automatic catchpoint generation enabled"
        );
        sqlite_ledger.configure_automatic_catchpoints(Some(auto_cfg));
    }

    // Reject anything but a fully populated block archive before
    // booting agreement. Participating with a missing tail block — or
    // with the catchpoint-only "blockdb empty" shape — would risk
    // producing votes against state that the block archive can't
    // reproduce on the next restart.
    match sqlite_ledger.reconcile_cross_file().map_err(|e| {
        anyhow::anyhow!("reconcile cross-file consistency for participate ledger: {e}")
    })? {
        algo_ledger::CrossFileState::Empty | algo_ledger::CrossFileState::Consistent { .. } => {}
        algo_ledger::CrossFileState::CatchpointOnly { tracker_round } => {
            anyhow::bail!(
                "participate requires blocks on disk; the ledger is catchpoint-only at round \
                 {tracker_round}. Run `algod-rust sync` first to populate the block archive."
            );
        }
        algo_ledger::CrossFileState::BlockBehind {
            tracker_round,
            block_max_round,
        } => {
            anyhow::bail!(
                "ledger inconsistency: tracker at round {tracker_round} but blockdb.blocks max \
                 is {block_max_round}. Recover from a catchpoint or delete the DB."
            );
        }
    }

    let latest = sqlite_ledger.current_round().0;
    info!(path = %ledger_path.display(), latest_round = latest, "opened ledger database");

    // Optional: bootstrap genesis state when the ledger is fresh. Mirrors
    // `relay --genesis-json`; see `seed_ledger_from_genesis` for why a
    // participation node needs it even more than a relay does.
    if let Some(genesis_path) = genesis_json_path {
        seed_ledger_from_genesis(&mut sqlite_ledger, genesis_path, latest)?;
    }

    let ledger = Arc::new(Mutex::new(sqlite_ledger));

    // Open (and immediately close) the agreement crash recovery database
    // alongside the ledger, purely to fail fast at startup if it can't be
    // opened (e.g. a permissions problem) rather than only discovering that
    // once the agreement service actually starts. Without a working crash
    // db, agreement state is never persisted before votes are broadcast, so
    // a crash-restart could cause equivocation. Mirrors Go's
    // `node/node.go:305-323`. See [[DOC-21]] §3.7.
    //
    // The real, long-lived connection used by the agreement service is
    // opened fresh on every `ParticipateAgreementControl::build_cycle` call
    // (issue #940) — a live catchpoint-catchup pause/resume tears the
    // agreement `Service` down and rebuilds it, and `Parameters::crash_db`
    // is consumed by `Service::start`, so each cycle needs its own handle.
    drop(open_crash_db(&resolved_paths.crash_path)?);

    // -----------------------------------------------------------------------
    // 2. Open the participation key store.
    // -----------------------------------------------------------------------
    let part_store = ParticipationStore::open(partkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open participation key store at {}: {}",
            partkey_path.display(),
            e
        )
    })?;

    // Bridge go-algorand `.partkey` files into the registry schema before
    // counting keys, so a node whose only key material comes from a
    // `goal network create` netroot still boots with live keys.
    let to_import = resolve_partkey_imports(
        import_partkeys,
        partkey_dirs,
        rest_opts.data_dir.as_deref(),
        &resolved_genesis_id,
    )?;
    if !to_import.is_empty() {
        let n = import_go_partkeys(&part_store, &to_import)?;
        info!(
            requested = to_import.len(),
            inserted = n,
            "imported go-algorand participation keys into the registry"
        );
    }

    let key_count = part_store.get_all().map(|v| v.len()).unwrap_or(0);
    info!(
        path = %partkey_path.display(),
        keys = key_count,
        "opened participation key store"
    );

    if key_count == 0 {
        warn!("No participation keys found — node will not produce valid proposals or votes");
    } else {
        // Check whether loaded keys have the required VRF/vote secrets.
        // Records missing vote_id or vrf_public_key will be filtered out by
        // the key manager and won't contribute to consensus.
        if let Ok(records) = part_store.get_all() {
            let missing: Vec<_> = records
                .iter()
                .filter(|r| r.vote_id.is_none() || r.vrf_public_key.is_none())
                .collect();
            for rec in &missing {
                warn!(
                    account = %rec.account,
                    participation_id = %rec.participation_id,
                    vote_id_present = rec.vote_id.is_some(),
                    vrf_key_present = rec.vrf_public_key.is_some(),
                    "participation key is missing vote_id or VRF key — it will not produce valid consensus messages"
                );
            }
        }
    }

    // A second connection to the same participation-key database, for the
    // autonomous heartbeat service (issue #820). `part_store` itself is
    // moved into `AgreementKeyManagerBridge` below, so the heartbeat
    // service -- which only ever reads (`get_for_voting_round`,
    // `get_for_round`), never writes -- gets its own handle rather than
    // sharing that one. Opened here (after the go-algorand `.partkey`
    // import above) so it sees the fully-migrated database.
    let heartbeat_part_store = ParticipationStore::open(partkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open a second participation key store handle (for the heartbeat \
             service) at {}: {}",
            partkey_path.display(),
            e
        )
    })?;

    // A third connection to the same participation-key database, for the
    // autonomous state-proof signing/proving service (issue #814), opened
    // unconditionally alongside the heartbeat store's own extra handle --
    // cheap, and keeps this block colocated with its sibling above. The
    // service itself is only spawned when `enable_state_proof_worker`
    // opts in (see near the heartbeat-service spawn point below).
    let stateproof_part_store = ParticipationStore::open(partkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open a third participation key store handle (for the state-proof \
             service) at {}: {}",
            partkey_path.display(),
            e
        )
    })?;

    // -----------------------------------------------------------------------
    // 3. Build the gossip network node.
    //
    // Mode selection (#542): mirrors go-algorand's `node.go` `newNode`
    // (`recreateNetwork`), which constructs exactly one of a WS network,
    // a P2P network, or a hybrid of both, keyed off
    // `cfg.EnableP2P`/`cfg.EnableP2PHybridMode`. `WsOnly` and `Hybrid`
    // both run the existing WS-gossip stack unchanged; `P2pOnly` must
    // open no WS-gossip listener and dial no WS peers at all — this is
    // the "no leak" guarantee the issue requires. `ws_active` below is a
    // direct, mechanical translation of `NetworkMode::ws_listener_active`,
    // whose per-mode semantics (including the "no leak" guarantee) are
    // unit-tested in `p2p_transport.rs`
    // (`ws_only_runs_ws_listener_and_no_p2p`, `p2p_only_runs_no_ws_listener`,
    // `hybrid_runs_both`).
    // -----------------------------------------------------------------------
    let ws_active = network_mode.ws_listener_active();
    let effective_listen_address = if ws_active {
        listen_address.map(|s| s.to_string())
    } else {
        if listen_address.is_some() {
            warn!(
                "P2P-only mode is active (--enable-p2p without --enable-p2p-hybrid-mode); \
                 ignoring --listen-address — no WS-gossip listener will be opened. Use \
                 --p2p-listen-address instead."
            );
        }
        None
    };

    // Resolve networking config.json fields (issue #748): CLI flags win
    // when explicitly passed, otherwise the loaded `config.json` (`Local`,
    // itself already carrying go-matching built-in defaults) applies.
    // This closes the prior `relay`-only gap for these knobs on
    // `participate`.
    let resolved_net = network_opts.resolve(&node_config);
    let rate_limit_window_secs = network_opts
        .connections_rate_limiting_window_seconds
        .unwrap_or(node_config.connections_rate_limiting_window_seconds);

    let phonebook = Arc::new(Phonebook::new(
        resolved_net.connections_rate_limiting_count as usize,
        Duration::from_secs(rate_limit_window_secs),
    ));
    if ws_active && !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    } else if !ws_active && !peers.is_empty() {
        warn!(
            "P2P-only mode is active; ignoring --peers (WS-gossip peer list) — use \
             --p2p-bootstrap-peers instead."
        );
    } else if ws_active && peers.is_empty() {
        // No explicit --peers: fall back to DNS SRV discovery on known
        // networks, mirroring `sync --gossip`/`observe` (issue #748 — this
        // was previously entirely absent from `participate`, which had no
        // way to find peers besides an explicit --peers list).
        if let Some(network_name) = genesis_id_for(network).map(|_| network) {
            let dns_template = dns_bootstrap_override.unwrap_or(&node_config.dns_bootstrap_id);
            match algo_network::Discovery::new(
                phonebook.clone(),
                Box::new(algo_network::HickorySrvResolver::new(None)),
                dns_template,
                network_name,
                dns_bootstrap_override.is_some(),
            ) {
                Ok(discovery) => {
                    discovery.refresh_phonebook_addresses().await;
                    info!("DNS discovery complete");
                }
                Err(e) => {
                    warn!(error = %e, "DNS bootstrap discovery failed; continuing with no peers");
                }
            }
        } else {
            debug!(
                network = network,
                "no --peers and unrecognized network name; skipping DNS discovery"
            );
        }
    }

    // `EnableGossipService` (go: gates the gossip WS listener itself,
    // independent of whether a listen address is configured) — when
    // false, suppress listening entirely even if `--listen-address` was
    // given (issue #748).
    let effective_listen_address = if node_config.enable_gossip_service {
        effective_listen_address
    } else {
        if effective_listen_address.is_some() {
            warn!(
                "EnableGossipService is false in config.json; ignoring --listen-address — \
                 no WS-gossip listener will be opened"
            );
        }
        None
    };

    // Issue #788 (`enrichNetworkingConfig`'s `GossipFanout` bump,
    // `config/config.go:170-179`): once a node has a real listen address
    // (go's `NetAddress != ""` equivalent), its `GossipFanout` gets bumped
    // to go's relay default unless explicitly overridden. Computed before
    // `effective_listen_address` is moved into `net_address` below.
    let is_listen_server = effective_listen_address.is_some();

    let net_config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: effective_listen_address,
        // Default participation nodes to "peer" (non-relay) mode;
        // `--relay-messages`/`ForceRelayMessages` let callers opt this
        // node into forwarding gossip even without a listen address.
        // `WebsocketNetwork` itself now derives the *effective* forwarding
        // decision as `net_address.is_some() || relay_messages` (go's
        // `IsListenServer() || ForceRelayMessages`) — see issue #748's fix
        // to `ws_network.rs`; this field is just go's `ForceRelayMessages`
        // input, OR'd from both the CLI flag and `config.json`. In
        // P2P-only mode `net_address` is forced to `None` above, so this
        // can never open a listener regardless.
        relay_messages: ws_active && (relay_messages || node_config.force_relay_messages),
        // No additional floor is applied on top of `resolve_gossip_fanout`
        // here (unlike the pre-#788 code, which unconditionally floored at
        // `DEFAULT_GOSSIP_FANOUT`): go's `GossipFanout` has no minimum, so
        // an operator who explicitly configures a small value gets exactly
        // that, floored only by `--peers`' own count — `relay.rs` was
        // fixed the same way for consistency between the two commands.
        gossip_fanout: resolve_gossip_fanout(&node_config, is_listen_server, peers.len()),
        max_connections_per_ip: resolved_net.max_connections_per_ip,
        incoming_connections_limit: resolved_net.incoming_connections_limit,
        connections_rate_limiting_count: resolved_net.connections_rate_limiting_count,
        broadcast_connections_limit: resolved_net.broadcast_connections_limit,
        tls_cert_file: resolved_net.tls_cert_file,
        tls_key_file: resolved_net.tls_key_file,
        block_service_mem_cap: node_config.block_service_mem_cap,
        // Message-hash dedup filter sizing + localhost rate-limit
        // exemption (issue #768).
        enable_incoming_message_filter: node_config.enable_incoming_message_filter,
        incoming_message_filter_bucket_count: node_config
            .incoming_message_filter_bucket_count
            .max(0) as usize,
        incoming_message_filter_bucket_size: node_config.incoming_message_filter_bucket_size.max(0)
            as usize,
        enable_outgoing_network_message_filtering: node_config
            .enable_outgoing_network_message_filtering,
        outgoing_message_filter_bucket_count: node_config
            .outgoing_message_filter_bucket_count
            .max(0) as usize,
        outgoing_message_filter_bucket_size: node_config.outgoing_message_filter_bucket_size.max(0)
            as usize,
        disable_localhost_connection_rate_limit: node_config
            .disable_localhost_connection_rate_limit,
        ..Default::default()
    };

    let gossip_node = Arc::new(WebsocketNetwork::new(net_config, phonebook));

    // -------------------------------------------------------------------
    // Construct the transaction pool early and register the inbound TX
    // handler on the multiplexer **before** starting the listener. If
    // we start the gossip node first and register after, inbound TX
    // frames that arrive during the startup window fall through to
    // `Multiplexer::handle`'s Ignore fallback and are silently dropped
    // (PLAN-33 / TASK-69, gap G1 in DOC-23).
    //
    // The `SeenTxCache` is created here so it can be shared with the
    // TxSyncer when TASK-70 lands.
    // -------------------------------------------------------------------
    let pool_ledger_adapter = Arc::new(PoolLedgerAdapter::new(ledger.clone()));
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    // Issue #753: `TxSyncTimeoutSeconds`/`TxSyncIntervalSeconds`/
    // `TxSyncServeResponseSize` are threaded from `node_config` here rather
    // than left at `TxSyncerConfig::default()`. Note this doesn't yet drive
    // a running sync loop: `algo_network::TxSyncer::start` is never invoked
    // anywhere in this binary today — a separate, real gap tracked by
    // issue #774 — only `seen_cache_size` is read below, for an unrelated
    // seen-tx dedup cache.
    let tx_syncer_config = algo_network::TxSyncerConfig {
        sync_timeout: std::time::Duration::from_secs(
            node_config.tx_sync_timeout_seconds.max(0) as u64
        ),
        sync_interval: std::time::Duration::from_secs(
            node_config.tx_sync_interval_seconds.max(0) as u64
        ),
        server_response_size: node_config.tx_sync_serve_response_size.max(0) as usize,
        ..algo_network::TxSyncerConfig::default()
    };
    let tx_seen_cache = Arc::new(algo_network::SeenTxCache::new(
        tx_syncer_config.seen_cache_size,
    ));
    // Application-call excessive-rate-limiter (ARL) (issue #821): protects
    // pool-admission resources from any single application generating
    // excessive gossip-pushed transaction volume or eval failures. Shared
    // (same `Arc`) across every `TxTagHandler` registered below (WS-gossip
    // and, if enabled, the libp2p P2P transport) so a single node-wide
    // limiter sees traffic from both transports, mirroring go-algorand's
    // single `TxHandler.appLimiter`. See
    // `algo_pool::app_rate_limiter`'s module doc and
    // `algo_network::tx_tag_handler`'s module doc for the full design and
    // the go-algorand trace establishing this as the correct wiring point.
    let app_rate_limiter = node_config.enable_tx_backlog_app_rate_limiting.then(|| {
        Arc::new(algo_pool::AppRateLimiter::new(
            node_config.tx_backlog_app_tx_rate_limiter_max_size.max(0) as usize,
            node_config.tx_backlog_app_tx_per_second_rate.max(0) as u64,
            std::time::Duration::from_secs(
                node_config.tx_backlog_service_rate_window_seconds.max(0) as u64,
            ),
        ))
    });
    // Mirrors go's `appLimiterBacklogThreshold = int(float64(TxBacklogSize) *
    // float64(TxBacklogAppRateLimitingCongestionPct) / 100)`, applied here
    // to `PoolConfig::default().pool_size` since algod-rust's `TxTagHandler`
    // checks pool occupancy rather than a separate backlog-queue depth (see
    // that module's doc comment for why).
    let app_rate_limiter_congestion_threshold = ((PoolConfig::default().pool_size as f64)
        * (node_config
            .tx_backlog_app_rate_limiting_congestion_pct
            .max(0) as f64)
        / 100.0) as usize;
    // Serve blocks to peers, both over HTTP (`/v1/{genesisID}/block/{round}`)
    // and over gossip (`UniEnsBlockReq`). Registered before `start_arc()` so
    // the routes exist the moment the listener accepts its first connection.
    // Issue #478: without this a Rust node acting as a relay answered every
    // block request with 404 / timeout, so nothing could catch up from it.
    let block_service = Arc::new(BlockService::new(
        Arc::new(ParticipateBlockService {
            ledger: ledger.clone(),
        }) as Arc<dyn LedgerForBlockService>,
        resolved_genesis_id.clone(),
        0,
    ));
    gossip_node.register_http_handler("/", block_service.http_router());

    // Serve the TxSyncer pull protocol's HTTP endpoint (issue #774). Like
    // `block_service` above, this must be registered before `start_arc()`
    // so the route exists the moment the listener accepts its first
    // connection. `PoolPendingTxAggregate` is also reused below as the
    // `TxSyncer`'s own `PendingTxAggregate` — same pool, same snapshot
    // semantics.
    let tx_sync_pool_aggregate = Arc::new(algo_network::PoolPendingTxAggregate::new(pool.clone()));
    // Peer-fairness servicing gate (issues #821, #860): guards how much of
    // this node's own tx-sync servicing capacity each requesting peer can
    // consume, so one peer polling aggressively cannot starve another
    // peer's pull requests. See `algo_network::TxSyncPeerLimiter`'s doc
    // comment for the full design; this is the pull-based mirror image of
    // go's ElasticRateLimiter/RED inbound-admission gate, which has no
    // reachable equivalent point on algod-rust's pull architecture.
    let tx_sync_peer_limiter = Arc::new(algo_network::TxSyncPeerLimiter::new(
        tx_syncer_config.server_max_concurrent_requests,
        tx_syncer_config.server_capacity_per_peer,
        std::time::Duration::from_secs(10),
    ));
    let tx_sync_service = algo_network::TxSyncService::new(
        tx_sync_pool_aggregate.clone(),
        resolved_genesis_id.clone(),
        tx_syncer_config.server_response_size,
    )
    .with_peer_limiter(tx_sync_peer_limiter);
    gossip_node.register_http_handler("/", tx_sync_service.http_router());

    let mut ws_tx_tag_handler =
        algo_network::TxTagHandler::new(pool.clone(), tx_seen_cache.clone());
    if let Some(limiter) = &app_rate_limiter {
        ws_tx_tag_handler = ws_tx_tag_handler
            .with_app_rate_limiter(limiter.clone(), app_rate_limiter_congestion_threshold);
    }
    let mut gossip_handlers = vec![algo_network::handler::TaggedMessageHandler {
        tag: algo_network::Tag::Transaction,
        handler: Arc::new(ws_tx_tag_handler),
    }];
    // `EnableGossipBlockService` (go default: true, matching algod-rust's
    // prior always-on behavior) — gate the UniEnsBlockReq gossip-tag
    // handler so it can be turned off via config.json (issue #748).
    if node_config.enable_gossip_block_service {
        gossip_handlers.push(algo_network::handler::TaggedMessageHandler {
            tag: algo_network::Tag::UniEnsBlockReq,
            handler: Arc::new(ParticipateBlockRequestHandler {
                block_service: Arc::clone(&block_service),
            }),
        });
    }

    // Autonomous state-proof signing/proving service (issue #814):
    // register the `Tag::StateProofSig` gossip handler unconditionally
    // (harmless when the background loop below isn't spawned -- an
    // unspawned service just never signs anything, so incoming
    // signatures would only ever be inserted into an empty runtime and
    // ignored) but only when the operator has opted in
    // (`EnableStateProofWorker`), since a node with the handler
    // registered but never verified live is exactly the state this
    // service must not silently be in by default. See
    // `crate::commands::stateproof_service`'s module doc comment for the
    // full opt-in rationale.
    let stateproof_sig_conn = if node_config.enable_state_proof_worker {
        Some(Arc::new(std::sync::Mutex::new(
            crate::commands::stateproof_service::open_sig_db(None).map_err(|e| {
                anyhow::anyhow!("failed to open state-proof signature database: {e}")
            })?,
        )))
    } else {
        None
    };
    let stateproof_runtime = stateproof_sig_conn.as_ref().map(|sig_conn| {
        let (handler, runtime) = crate::commands::stateproof_service::build_handler(
            ledger.clone(),
            Arc::clone(sig_conn),
        );
        gossip_handlers.push(handler);
        runtime
    });

    gossip_node.multiplexer().register_handlers(gossip_handlers);

    // -------------------------------------------------------------------
    // Bootstrap the pool's block evaluator from the current ledger tip
    // BEFORE starting the gossip network.
    //
    // Without this, submissions routed through `LocalTxBroadcaster`
    // (either in-process or via the REST `POST /v2/transactions` path)
    // fail with `PoolError::NoPendingBlockEvaluator` until agreement
    // commits its first block. The pool's `recompute_block_evaluator`
    // reads `ledger.latest()` + `block_hdr(latest)` to build the
    // evaluator, so the `Block` passed here is purely a trigger — its
    // fields are ignored. Mirrors go-algorand's `node.go:startNode`,
    // which calls `pool.OnNewBlock` during node initialization to
    // prime the pool.
    //
    // Bootstrapping before `start_arc()` closes the second startup
    // race noted in PLAN-33 / TASK-69 (gap G1 in DOC-23): inbound TX
    // frames that arrive immediately after the listener binds would
    // otherwise call `pool.remember()` on a pool with no evaluator
    // and surface as `NoPendingBlockEvaluator` errors.
    //
    // On a freshly-initialized ledger that lacks a tip block,
    // `recompute_block_evaluator` returns early and leaves the pool
    // without an evaluator, which is the pre-bootstrap behavior —
    // this call is strictly additive.
    // -------------------------------------------------------------------
    pool.on_new_block(&algo_types::Block::default(), &HashSet::new());

    // Start the network (listener + mesh). TX-tag handler is already
    // wired AND the pool has its evaluator, so inbound transactions
    // cannot slip past during the startup window.
    gossip_node
        .start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start gossip network: {}", e))?;

    let (addr, listening) = gossip_node.address();
    if listening {
        info!(address = %addr, "gossip network listening");
    } else {
        info!("gossip network started (no listener)");
    }

    // -----------------------------------------------------------------------
    // 3a-p2p. Bring up the libp2p P2P transport (#542), alongside
    // (`Hybrid`) or instead of (`P2pOnly`) the WS-gossip stack just
    // started above.
    //
    // `P2pTransport` implements `GossipNode` directly (#559), so inbound
    // transactions received over the P2P TX gossipsub topic are fed into
    // the very same `TxTagHandler` pipeline WS-received transactions use
    // (sharing `pool` and `tx_seen_cache`) by registering that handler on
    // `transport.multiplexer()`, exactly as it's registered on
    // `gossip_node.multiplexer()` above. Outbound local-tx broadcast and
    // agreement (proposal/vote/bundle) traffic are routed over whichever
    // transport(s) `network_mode` has active via `p2p_active_gossip_node`
    // below (a `DualGossipNode` fan-out in `Hybrid` mode) — see
    // `crate::commands::dual_gossip_node`'s module doc comment.
    // -----------------------------------------------------------------------
    let p2p_transport: Option<Arc<P2pTransport>> = if network_mode.p2p_active() {
        let listen_multiaddr = resolved_p2p
            .listen_address
            .as_deref()
            .map(|s| {
                s.parse()
                    .map_err(|e| anyhow::anyhow!("invalid --p2p-listen-address {s:?}: {e}"))
            })
            .transpose()?;
        let mut bootstrap_peers = Vec::with_capacity(resolved_p2p.bootstrap_peers.len());
        for addr in &resolved_p2p.bootstrap_peers {
            bootstrap_peers.push(addr.parse().map_err(|e| {
                anyhow::anyhow!("invalid --p2p-bootstrap-peers entry {addr:?}: {e}")
            })?);
        }
        let has_listen_multiaddr = listen_multiaddr.is_some();
        let p2p_data_dir = rest_opts
            .data_dir
            .clone()
            .or_else(|| ledger_path.parent().map(Path::to_path_buf));

        let transport = P2pTransport::start(P2pTransportConfig {
            network_id: network.to_string(),
            listen_multiaddr,
            bootstrap_peers,
            persist_peer_id: resolved_p2p.persist_peer_id,
            data_dir: p2p_data_dir,
            // `config.json`'s `P2PPrivateKeyLocation` (issue #768): a
            // custom path override for the P2P peer-ID private key file,
            // alongside the existing `--p2p-persist-peer-id` flag. Empty
            // (go's default) means "use the data-dir-derived default".
            private_key_path: (!node_config.p2p_private_key_location.is_empty())
                .then(|| PathBuf::from(&node_config.p2p_private_key_location)),
            enable_dht_providers: node_config.enable_dht_providers,
            dht_mode: node_config.dht_mode.clone(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("failed to start P2P transport: {e}"))?;

        // Give the swarm a brief moment to confirm its listen address (if
        // any) before logging, so the "listening" log line is accurate
        // rather than always reporting "not yet confirmed".
        if has_listen_multiaddr {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        info!(
            peer_id = %transport.peer_id(),
            listening = transport.is_listening(),
            listen_addrs = ?transport.listen_addrs(),
            connected_peers = transport.connected_peer_count(),
            algorand_ws_stream_peers = transport.stream_peer_count(),
            "P2P transport started"
        );

        // Inbound TX routing: register the same pool/seen-cache-backed
        // handler WS-gossip uses, before any P2P traffic can be dispatched.
        //
        // Also register the same `UniEnsBlockReq` handler WS-gossip uses
        // (issue #591): without this, a P2P peer that falls behind and
        // tries to catch up from *this* node gets no reply at all — the
        // P2P `/algorand-ws` stream now writes back a handler's `Respond`
        // result (see `p2p_transport.rs`'s `spawn_ws_peer`), but only if a
        // handler is actually registered here to produce one.
        let mut p2p_tx_tag_handler =
            algo_network::TxTagHandler::new(pool.clone(), tx_seen_cache.clone());
        if let Some(limiter) = &app_rate_limiter {
            p2p_tx_tag_handler = p2p_tx_tag_handler
                .with_app_rate_limiter(limiter.clone(), app_rate_limiter_congestion_threshold);
        }
        let mut p2p_handlers = vec![algo_network::handler::TaggedMessageHandler {
            tag: algo_network::Tag::Transaction,
            handler: Arc::new(p2p_tx_tag_handler),
        }];
        // See the matching `enable_gossip_block_service` gate on the
        // WS-gossip registration above (issue #748).
        if node_config.enable_gossip_block_service {
            p2p_handlers.push(algo_network::handler::TaggedMessageHandler {
                tag: algo_network::Tag::UniEnsBlockReq,
                handler: Arc::new(ParticipateBlockRequestHandler {
                    block_service: Arc::clone(&block_service),
                }),
            });
        }
        transport.multiplexer().register_handlers(p2p_handlers);

        Some(Arc::new(transport))
    } else {
        None
    };

    // The `GossipNode` traffic-routing traffic (outbound local tx,
    // agreement proposals/votes/bundles) should flow over: WS-gossip only
    // (`WsOnly`), the P2P transport only (`P2pOnly`), or both
    // (`Hybrid`, via `DualGossipNode`) — matching `network_mode` exactly.
    let p2p_active_gossip_node: Arc<dyn GossipNode> = match (&network_mode, &p2p_transport) {
        (NetworkMode::P2pOnly, Some(p2p)) => p2p.clone() as Arc<dyn GossipNode>,
        (NetworkMode::Hybrid, Some(p2p)) => Arc::new(dual_gossip_node::DualGossipNode::new(
            gossip_node.clone() as Arc<dyn GossipNode>,
            p2p.clone() as Arc<dyn GossipNode>,
        )),
        _ => gossip_node.clone() as Arc<dyn GossipNode>,
    };

    // -----------------------------------------------------------------------
    // 3b. Construct the local tx broadcaster.
    //
    // Shares `tx_seen_cache` with the inbound TX handler so peer echoes
    // of our local submissions are deduplicated before reaching the
    // pool. Needed by the `AlgodNodeInterface::broadcast_signed_tx_group`
    // path (PLAN-74 TASK-77) — cheap to construct even when the REST
    // server is disabled so the adapter's shape stays stable. Broadcasts
    // over whichever transport(s) `network_mode` has active (#559).
    // -----------------------------------------------------------------------
    let broadcaster = Arc::new(LocalTxBroadcaster::new(
        Arc::new(PoolIngestAdapter::new(pool.clone())),
        p2p_active_gossip_node.clone(),
        tx_seen_cache.clone(),
    ));

    // -----------------------------------------------------------------------
    // 3b-2. Start the transaction-sync pull loop (issue #774).
    //
    // go-algorand always runs `rpcs.TxSyncer` alongside gossip broadcast
    // (`node/node.go:342`, unconditional since the initial commit,
    // `v1.0.23-stable`): each tick, sample one peer, ask it (via Bloom
    // filter over HTTP) for transaction groups we're missing. Without
    // this, a node that missed a gossip broadcast — a dropped connection
    // mid-relay, a peer that joined the mesh just after the broadcast —
    // has no fallback recovery path; algod-rust had the full engine
    // (`TxSyncer`, `sync_round`, its three collaborator traits) built
    // (PLAN-33) but `TxSyncer::start` was never called anywhere in this
    // binary.
    //
    // `GossipTxSyncPeerSource` samples `gossip_node`'s (WS-gossip)
    // outgoing-connected peers specifically — see that type's doc
    // comment for why only outgoing connections are dialable HTTP
    // targets — and pulls from each sampled peer's `TxSyncService`
    // endpoint (registered above). This deliberately does not cover the
    // P2P transport: `P2pTransport`'s peers communicate over a libp2p
    // stream, not a dialable HTTP listener, so there is no HTTP peer
    // client to build for them. In `P2pOnly` mode `gossip_node` has no
    // WS peers at all (mirrors the same acknowledged gap noted elsewhere
    // in this file for other WS-specific affordances), so `sample_peer`
    // simply returns `None` and each round is a no-op — safe, not a
    // crash, but a real coverage gap tracked as a follow-up rather than
    // silently absorbed.
    // -----------------------------------------------------------------------
    let tx_syncer = Arc::new(algo_network::TxSyncer::new(
        tx_syncer_config,
        tx_sync_pool_aggregate,
        Arc::new(algo_network::GossipTxSyncPeerSource::new(
            gossip_node.clone() as Arc<dyn GossipNode>,
            resolved_genesis_id.clone(),
            reqwest::Client::new(),
            node_config.tx_sync_serve_response_size.max(0) as usize,
        )),
        Arc::new(algo_network::PoolSolicitedTxHandler::new(
            Arc::new(PoolIngestAdapter::new(pool.clone())),
            tx_seen_cache.clone(),
        )),
    ));
    tx_syncer.start();

    // -----------------------------------------------------------------------
    // 3c. Optional: start the REST API server.
    //
    // REST starts by default (issue #751 — matching go-algorand, which
    // always starts its REST API on `EndpointAddress`, defaulting to an
    // ephemeral `127.0.0.1:0`): `--rest-listen`, `[rest].listen` in
    // `algod-rust.toml`, and `config.json`'s `EndpointAddress` are
    // consulted in that priority order, and only an explicit empty string
    // from one of those sources disables it. When enabled, we build an
    // `AlgodNodeInterface` adapter around the ledger + pool + broadcaster
    // and hand it to `ApiServer::serve`. Shutdown is coordinated through a
    // shared `CancellationToken` that the Ctrl-C handler cancels (see step
    // 7 below).
    // -----------------------------------------------------------------------
    let shutdown_token = CancellationToken::new();

    // Consensus-participation metrics (issue #473). Created here, ahead of
    // both the REST server and the agreement service, because the REST
    // adapter is built first and must share the very same collector the
    // agreement service will later write to (`Service::with_metrics` below).
    let participation_metrics = Arc::new(algo_agreement::ParticipationMetrics::new());

    // -----------------------------------------------------------------------
    // 3d. Build the `ParticipateAgreementControl` (issue #940) — the
    //     pause/resume handle for the live agreement `Service` +
    //     `CatchupService` pair. Built here, before the REST adapter below,
    //     because `with_catchup_manager` (like `with_pool`/`with_broadcaster`
    //     etc.) has to be attached before the adapter is frozen into an
    //     `Arc` and handed to `ApiServer::serve`. The agreement/catchup pair
    //     itself isn't started yet — that happens via `resume()` once the
    //     REST server is up, in the same place `Service::start()` used to
    //     run inline.
    // -----------------------------------------------------------------------
    let rt_handle = tokio::runtime::Handle::current();
    let agreement_network_config = algo_network::AgreementNetworkConfig {
        vote_queue_len: node_config.agreement_incoming_votes_queue_length as usize,
        proposal_queue_len: node_config.agreement_incoming_proposals_queue_length as usize,
        bundle_queue_len: node_config.agreement_incoming_bundles_queue_length as usize,
    };
    // Stable for the node's whole lifetime — shared with the
    // pool-block-follower/heartbeat/state-proof-worker threads spawned
    // once below, which are never restarted by a pause/resume cycle. See
    // `ParticipateAgreementControl`'s doc comment.
    let round_advanced = Arc::new(std::sync::Condvar::new());
    let agreement_control = Arc::new(ParticipateAgreementControl {
        ledger: ledger.clone(),
        ledger_path: ledger_path.to_path_buf(),
        crash_db_path: resolved_paths.crash_path.clone(),
        p2p_active_gossip_node: p2p_active_gossip_node.clone(),
        gossip_node: gossip_node.clone(),
        rt_handle: rt_handle.clone(),
        agreement_network_config,
        partkey_path: partkey_path.to_path_buf(),
        resolved_genesis_id: resolved_genesis_id.clone(),
        genesis_hash,
        pool: pool.clone(),
        round_advanced: round_advanced.clone(),
        participation_metrics: participation_metrics.clone(),
        enable_agreement_reporting: node_config.enable_agreement_reporting,
        enable_agreement_time_metrics: node_config.enable_agreement_time_metrics,
        network_mode,
        p2p_transport: p2p_transport.clone(),
        catchup_parallel_blocks: node_config.catchup_parallel_blocks,
        running: tokio::sync::Mutex::new(None),
    });

    // Live catchpoint-catchup mode (issue #940): only meaningful with a REST
    // peer to fetch the catchpoint/blocks from — see `CatchupPeerOptions`'s
    // doc comment for why `participate` needs this explicitly (unlike
    // `node start --follow`, which already has one). Also skipped on an
    // archival node, mirroring go's own refusal
    // (`AlgorandFullNode.StartCatchup`) and `node.rs`'s `--follow` wiring.
    let catchup_manager = match catchup_opts.url.as_deref() {
        Some(url) if !node_config.archival => {
            let live_catchup_params = crate::live_catchup::LiveCatchupParams {
                algod_url: url.to_string(),
                algod_token: catchup_opts.token.clone(),
                db_path: ledger_path.to_path_buf(),
                genesis_id: resolved_genesis_id.clone(),
                genesis_hash,
                concurrency: 8,
                catchpoint_peer_urls: Vec::new(),
            };
            let runner = Arc::new(crate::live_catchup::OrchestratorCatchupRunner::new(
                live_catchup_params,
            ));
            Some(crate::live_catchup::LiveCatchupManager::new(
                runner,
                agreement_control.clone() as Arc<dyn crate::live_catchup::NormalSyncControl>,
            ))
        }
        _ => None,
    };

    let default_data_dir = ledger_path.parent().map(Path::to_path_buf);
    let rest_cfg = rest_opts.resolve(default_data_dir.as_deref())?;
    let rest_server_handle = if let Some(cfg) = rest_cfg {
        let genesis_json = load_genesis_json(cfg.genesis_path.as_deref(), cfg.data_dir.as_deref())?
            .unwrap_or_else(|| {
                warn!(
                    "no genesis.json found; synthesizing a minimal stub for the /genesis endpoint"
                );
                synthesize_genesis_json(&resolved_genesis_id, network, CONSENSUS_V41)
            });

        let iface_config = NodeInterfaceConfig {
            genesis_id: resolved_genesis_id.clone(),
            genesis_hash: Digest(genesis_hash),
            genesis_json,
            build_version: BuildVersion::from_build_env(),
            default_protocol: CONSENSUS_V41.into(),
        };

        let mut adapter = AlgodNodeInterface::new(ledger.clone(), iface_config)
            .with_pool(pool.clone())
            .with_broadcaster(broadcaster.clone())
            .with_shutdown_token(shutdown_token.clone())
            .with_participation_metrics(participation_metrics.clone())
            // `GET /v2/node/peers` (issue #673): the WS gossip network is
            // always constructed (even in P2P-only mode it just reports no
            // connections — the "no leak" guarantee above), so it's always
            // safe to attach here.
            .with_ws_network(gossip_node.clone() as Arc<dyn algo_network::GossipNode>)
            // `config.json`'s `EnableDeveloperAPI`/`EnableExperimentalAPI`/
            // `MaxAPIResourcesPerAccount`/`MaxAPIBoxPerApplication` (issue
            // #751) — see `AlgodNodeInterface::enable_developer_api`'s doc
            // comment for the `dev_mode`-conflation fix these wire past.
            .with_enable_developer_api(node_config.enable_developer_api)
            .with_enable_experimental_api(node_config.enable_experimental_api)
            .with_max_api_resources_per_account(node_config.max_api_resources_per_account)
            .with_max_api_box_per_application(node_config.max_api_box_per_application)
            // `config.json`'s `EnableRuntimeMetrics`/`EnableNetDevMetrics`
            // (issue #776): process-wide `/metrics` counters, wired
            // independently of the participation-metrics collector above.
            .with_enable_runtime_metrics(node_config.enable_runtime_metrics)
            .with_enable_netdev_metrics(node_config.enable_netdev_metrics);
        if let Some(p2p) = &p2p_transport {
            adapter = adapter.with_p2p_network(p2p.clone() as Arc<dyn algo_network::GossipNode>);
        }
        if let Some(capacity) = cfg.async_backlog_size {
            adapter = adapter.with_async_backlog_capacity(capacity);
        }
        if let Some(mgr) = &catchup_manager {
            adapter = adapter.with_catchup_manager(mgr.clone());
        }
        let node = Arc::new(adapter);

        let api_config = ApiServerConfig {
            listen_addr: cfg.listen,
            data_dir: cfg.data_dir.clone(),
            api_token: cfg.api_token.clone(),
            admin_token: cfg.admin_token.clone(),
            disable_api_auth: cfg.disable_api_auth,
            enable_private_network_access_header: cfg.enable_private_network_access_header,
            rest_read_timeout_seconds: cfg.rest_read_timeout_seconds,
            rest_write_timeout_seconds: cfg.rest_write_timeout_seconds,
            rest_connections_soft_limit: cfg.rest_connections_soft_limit,
            rest_connections_hard_limit: cfg.rest_connections_hard_limit,
        };

        info!(
            listen = %cfg.listen,
            data_dir = ?cfg.data_dir,
            "starting REST API server"
        );

        let shutdown_future = {
            let token = shutdown_token.clone();
            async move { token.cancelled().await }
        };
        let api_server = ApiServer::new(api_config);
        let (bound_addr, join_handle) = api_server
            .serve(node, shutdown_future)
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind REST API listener: {e}"))?;
        info!(address = %bound_addr, "REST API server bound");
        Some(join_handle)
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // 4/5/6. Build and start the agreement `Service` + `CatchupService` pair
    // (issue #940). What used to be built inline exactly once here now
    // lives in `ParticipateAgreementControl::build_cycle` (called by
    // `resume()` below) so a live catchpoint catchup can later pause
    // (`ParticipateAgreementControl::pause`, called from
    // `LiveCatchupManager::start_catchup`) and resume the exact same pair
    // without restarting this whole function.
    // -----------------------------------------------------------------------
    agreement_control.resume().await;

    // -----------------------------------------------------------------------
    // Pool block follower.
    //
    // go-algorand drives `pool.OnNewBlock` from a ledger block listener that
    // fires for *every* committed round (`node.go`'s `blockListener` /
    // `ledger.Wait`). Here it was only ever called once, at startup, to prime
    // the evaluator — so the pool's evaluator stayed pinned at the node's
    // starting round forever. Every user-submitted transaction was then
    // rejected with "transaction round window [N, N+1000] does not cover
    // block round <startup round>", and committed transactions were never
    // dropped from the pool (issue #478).
    //
    // The follower is woken by `agreement_ledger`'s `round_advanced` condvar
    // (the same one `AgreementLedgerBridge::ensure_block` notifies right
    // after committing a block) rather than a fixed sleep — see
    // `run_pool_block_follower`'s doc comment for why the original
    // sleep-then-check polling fell behind under sustained load (issue #492).
    let pool_follower_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Issue #940: this is the same `Arc<Condvar>` every agreement
    // pause/resume cycle's `AgreementLedgerBridge` reuses (see
    // `ParticipateAgreementControl::build_cycle`), so this thread keeps
    // waking correctly across a live catchpoint catchup's pause/resume.
    let pool_follower_round_advanced = round_advanced.clone();
    let pool_follower = {
        let pool = pool.clone();
        let ledger = ledger.clone();
        let stop = Arc::clone(&pool_follower_stop);
        let round_advanced = Arc::clone(&pool_follower_round_advanced);
        // Read the starting round here, in the spawning thread, not inside
        // the closure -- see `run_pool_block_follower`'s doc comment on
        // `initial_round` for why that distinction matters.
        let initial_round = {
            let l = ledger.lock().expect("ledger lock poisoned");
            l.current_round().0
        };
        std::thread::Builder::new()
            .name("pool-block-follower".to_string())
            .spawn(move || {
                run_pool_block_follower(
                    &pool,
                    &ledger,
                    &round_advanced,
                    &stop,
                    Duration::from_millis(200),
                    initial_round,
                );
            })
            .expect("failed to spawn pool-block-follower thread")
    };

    // -----------------------------------------------------------------------
    // 5b. Start the autonomous heartbeat service (issue #820).
    //
    // Mirrors go-algorand's `heartbeat.Service`: watches every locally-held
    // participation key each round and, if the account it participates for
    // is under an active challenge and hasn't been seen since before it,
    // proactively submits a fee-exempt `hb` transaction through the same
    // local-submission path (`broadcaster`) any other locally-originated
    // transaction uses. See `crate::commands::heartbeat_service` for the
    // decision logic and `algo_ledger::heartbeat`/`heartbeat_builder` for
    // the challenge-detection and transaction-construction primitives it's
    // built from.
    //
    // Reuses the same `round_advanced` condvar as the pool-block-follower
    // above (both are woken by `AgreementLedgerBridge::ensure_block`'s
    // `notify_all` after each committed block) and the same `rt_handle`
    // used elsewhere in this function for bridging sync ledger/participation
    // reads to the one async call this service needs
    // (`LocalTxBroadcaster::submit_group`).
    // -----------------------------------------------------------------------
    let (heartbeat_service_stop, heartbeat_service_join) =
        crate::commands::heartbeat_service::spawn(
            ledger.clone(),
            heartbeat_part_store,
            broadcaster.clone(),
            Arc::clone(&pool_follower_round_advanced),
            rt_handle.clone(),
            crate::commands::heartbeat_service::DEFAULT_POLL_INTERVAL,
        );
    info!("heartbeat service started");

    // -----------------------------------------------------------------------
    // 5c. Start the autonomous state-proof signing/proving service (issue
    // #814), only when opted in via `EnableStateProofWorker`. See
    // `crate::commands::stateproof_service`'s module doc comment for the
    // full rationale and scope. Shares the same `round_advanced` condvar
    // and `rt_handle` as the heartbeat service above.
    // -----------------------------------------------------------------------
    let stateproof_service_handle = if let (Some(sig_conn), Some(runtime)) =
        (stateproof_sig_conn.clone(), stateproof_runtime.clone())
    {
        info!("state-proof worker enabled (EnableStateProofWorker) -- starting service");
        Some(crate::commands::stateproof_service::spawn(
            ledger.clone(),
            stateproof_part_store,
            sig_conn,
            runtime,
            Arc::clone(&gossip_node) as Arc<dyn algo_network::GossipNode>,
            broadcaster.clone(),
            genesis_hash,
            Arc::clone(&pool_follower_round_advanced),
            rt_handle.clone(),
            crate::commands::stateproof_service::DEFAULT_POLL_INTERVAL,
        ))
    } else {
        None
    };

    info!(
        genesis_id = %resolved_genesis_id,
        "consensus participation active -- press Ctrl+C to stop"
    );

    // -----------------------------------------------------------------------
    // 7. Wait for shutdown signal (Ctrl+C).
    // -----------------------------------------------------------------------
    tokio::signal::ctrl_c().await?;

    info!("shutting down consensus participation...");

    // Cancel the shared token first so the REST server's graceful
    // shutdown begins unblocking in-flight requests while we tear
    // down agreement + gossip. The server's own draining uses axum's
    // `with_graceful_shutdown`, so connections finish their current
    // request before the listener closes.
    shutdown_token.cancel();

    // Stop the agreement service first, then the catchup service (mirrors
    // Go's shutdown order where the agreement service is stopped before the
    // catchup service, ensuring no new certificates are sent after the
    // catchup service shuts down). `ParticipateAgreementControl::pause`
    // (issue #940) does exactly this ordering internally; a no-op if a live
    // catchpoint catchup has already paused it.
    agreement_control.pause().await;
    pool_follower_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = pool_follower.join();
    heartbeat_service_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = heartbeat_service_join.join();
    if let Some((stateproof_service_stop, stateproof_service_join)) = stateproof_service_handle {
        stateproof_service_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = stateproof_service_join.join();
    }
    // Stop the tx-sync pull loop before tearing down gossip — it samples
    // peers from `gossip_node`, so stopping it first avoids a
    // last-second round starting against a network that's mid-shutdown.
    tx_syncer.stop().await;
    gossip_node.stop().await;

    // Await the REST server last — its graceful shutdown depends on
    // axum finishing any in-flight requests, and by now gossip has
    // stopped serving fresh data so the responses are stable. The
    // adapter's `wait_for_round` honours `shutdown_token` so
    // long-poll `wait-for-block-after` handlers return 408 promptly
    // instead of hanging out their full 60s deadline; a hard-cap
    // timeout is still applied as a defence-in-depth safety net in
    // case a future handler forgets to honour the token.
    if let Some(join_handle) = rest_server_handle {
        match tokio::time::timeout(REST_SHUTDOWN_HARD_CAP, join_handle).await {
            Ok(Ok(())) => info!("REST API server stopped"),
            Ok(Err(e)) => warn!(err = %e, "REST API server task terminated unexpectedly"),
            Err(_) => warn!(
                cap = ?REST_SHUTDOWN_HARD_CAP,
                "REST API server did not drain within the shutdown cap; abandoning the join handle"
            ),
        }
    }

    // Issue #794: don't let the process exit while a background automatic
    // catchpoint export (issue #770) is still writing. `export_catchpoint_file`
    // now writes atomically (temp file + rename), so abandoning the wait
    // can never leave a corrupt file at a previously-published path -- but
    // waiting (briefly, bounded) still lets the newest catchpoint actually
    // land instead of being silently dropped on every restart.
    let wait_result = tokio::task::spawn_blocking({
        let ledger = Arc::clone(&ledger);
        move || {
            ledger
                .lock()
                .unwrap()
                .wait_for_pending_catchpoint_export_timeout(CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT)
        }
    })
    .await;
    match wait_result {
        Ok(true) => {}
        Ok(false) => warn!(
            timeout = ?CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT,
            "shutting down with an automatic catchpoint export still in flight"
        ),
        Err(e) => warn!(error = %e, "catchpoint-export shutdown wait task panicked"),
    }

    info!("consensus participation stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_pool::traits::BlockEvaluator;
    use algo_types::{
        consensus::consensus_params_for_version, Address, ConsensusParams, Round,
        SignedTransaction, Transaction, TxnType,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    // ── Helper: create an in-memory ledger ──────────────────────────
    fn test_ledger() -> Arc<Mutex<SqliteLedger>> {
        Arc::new(Mutex::new(
            SqliteLedger::open_in_memory().expect("in-memory ledger"),
        ))
    }

    // ── start_evaluator advances the header ─────────────────────────

    #[test]
    fn start_evaluator_advances_round_and_branch() {
        use algo_pool::traits::PoolLedger;

        // Empty in-memory ledger: no accounts, no totals seeded. The evaluator
        // must still advance the header off the supplied previous header.
        let adapter = PoolLedgerAdapter::new(test_ledger());

        let prev = BlockHeader {
            round: Round(5),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev.clone(), 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        assert_eq!(
            block.round,
            Round(6),
            "evaluator advances to prev round + 1"
        );
        assert_eq!(
            block.branch,
            algo_codec::compute_block_header_digest(&prev).0,
            "branch = previous header digest (go's prev.Hash())",
        );
        assert_eq!(block.fee_sink, prev.fee_sink, "fee sink carried");
        assert_eq!(
            block.rewards_pool, prev.rewards_pool,
            "rewards pool carried"
        );
        // No reward units seeded (empty ledger) → rewards level carries unchanged.
        assert_eq!(block.rewards_level, prev.rewards_level);
        assert_eq!(
            block.seed, [0u8; 32],
            "seed left for the producer/agreement"
        );
    }

    // ── dev-mode expired-participation-key sweep (issue #526) ───────

    #[test]
    fn dev_block_lists_and_sweeps_expired_online_account() {
        use algo_ledger::apply::apply_block;
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // Seed an online account whose vote key expired before the round
        // about to be built (round 6): VoteLastValid = 3 < 6.
        let expired_addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &expired_addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    vote_id: Some([1u8; 32]),
                    vote_last_valid: 3,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        // The self-produced block must carry the expired account, mirroring
        // go's generateKnockOfflineAccountsList populating
        // block.ParticipationUpdates.ExpiredParticipationAccounts at
        // proposal time -- without this, apply.rs's already-correct
        // reset_expired_online_accounts (the consumer side) never fires for
        // algod-rust's own self-produced blocks.
        assert_eq!(
            block.expired_participation_accounts.as_deref(),
            Some(&[expired_addr][..]),
            "dev-mode block must list the account with the expired participation key"
        );

        // Applying the block sweeps the account to Offline (apply.rs's
        // consumer side, already correct prior to this fix). apply_block_impl
        // expects to apply directly on top of the store's current round, so
        // advance the fresh in-memory ledger's current round to match the
        // (round 5) header the evaluator built on.
        let mut l = ledger.lock().expect("ledger lock");
        l.set_current_round(Round(5));
        apply_block(&mut *l, &block).expect("apply_block");
        let acct = l.get_account(&expired_addr).expect("account exists");
        assert_eq!(
            acct.status,
            AccountStatus::Offline,
            "expired account swept offline after applying the self-produced block"
        );
    }

    #[test]
    fn dev_block_omits_expired_list_when_no_accounts_expired() {
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // Online account whose vote key is still valid at the round being
        // built (round 6): VoteLastValid = 100 >= 6.
        let online_addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &online_addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    vote_id: Some([1u8; 32]),
                    vote_last_valid: 100,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        assert!(
            block.expired_participation_accounts.is_none(),
            "no account has expired -- the list must stay empty/omitted"
        );
    }

    // ── dev-mode absentee-account sweep (issue #845) ─────────────────

    #[test]
    fn dev_block_lists_and_suspends_absent_online_account() {
        use algo_ledger::apply::apply_block;
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // Seed a single online, incentive-eligible account that hasn't
        // proposed or heartbeated since round 1. With only one online
        // account, total_online_voting_stake == this account's own stake,
        // so is_absent's allowable_lag collapses to exactly ABSENT_FACTOR
        // (20): last_seen(1) + 20 = 21 < 101 (the round being built), so
        // this account must be listed absent.
        let absent_addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &absent_addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    incentive_eligible: true,
                    last_heartbeat: 1,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(100),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        // The self-produced block must carry the absent account, mirroring
        // go's generateKnockOfflineAccountsList populating
        // block.ParticipationUpdates.AbsentParticipationAccounts at
        // proposal time -- without this, the apply-side suspend sweep
        // (`algo_ledger::apply::suspend_absent_accounts`, the consumer
        // side, already correct) never fires for algod-rust's own
        // self-produced blocks.
        assert_eq!(
            block.absent_participation_accounts.as_deref(),
            Some(&[absent_addr][..]),
            "dev-mode block must list the genuinely-absent online account"
        );

        // Applying the block suspends the account (apply.rs's consumer
        // side, already correct prior to this fix).
        let mut l = ledger.lock().expect("ledger lock");
        l.set_current_round(Round(100));
        apply_block(&mut *l, &block).expect("apply_block");
        let acct = l.get_account(&absent_addr).expect("account exists");
        assert_eq!(
            acct.status,
            AccountStatus::Offline,
            "absent account suspended (Offline) after applying the self-produced block"
        );
        assert!(
            !acct.incentive_eligible,
            "absent account loses incentive eligibility once suspended"
        );
    }

    #[test]
    fn dev_block_omits_absent_list_when_no_accounts_absent() {
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // Same single-online-account setup as the positive case, but with
        // a recent last_heartbeat: last_seen(100) + allowable_lag(20) =
        // 120, which is NOT < 101, so this account is not absent.
        let online_addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &online_addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    incentive_eligible: true,
                    last_heartbeat: 100,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(100),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        assert!(
            block.absent_participation_accounts.is_none(),
            "no account is absent -- the list must stay empty/omitted"
        );
    }

    #[test]
    fn dev_block_excludes_not_incentive_eligible_account_from_absent_list() {
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // An account that would otherwise trip is_absent (very stale
        // last_heartbeat), but is not IncentiveEligible -- go's
        // generateKnockOfflineAccountsList only considers
        // `Status == Online && IncentiveEligible` candidates for the
        // absentee check at all.
        let addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    incentive_eligible: false,
                    last_heartbeat: 1,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(100),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");

        assert!(
            block.absent_participation_accounts.is_none(),
            "a non-IncentiveEligible account must never be listed absent"
        );
    }

    #[test]
    fn dev_block_excludes_own_participating_account_from_absent_list() {
        use algo_pool::traits::PoolLedger;
        use algo_types::AccountStatus;

        let ledger = test_ledger();

        // Same stale-heartbeat setup that would otherwise trip is_absent,
        // but this address is passed as one of the node's own
        // `voting_accounts` -- go's generateKnockOfflineAccountsList never
        // proposes suspending an address the proposer itself holds keys
        // for ("This function is passed a list of participating addresses
        // so a node will not propose a block that suspends or expires
        // itself").
        let own_addr = Address([9u8; 32]);
        {
            let mut l = ledger.lock().expect("ledger lock");
            l.set_account(
                &own_addr,
                AccountData {
                    micro_algos: 5_000_000,
                    status: AccountStatus::Online,
                    incentive_eligible: true,
                    last_heartbeat: 1,
                    ..AccountData::default()
                },
            );
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let prev = BlockHeader {
            round: Round(100),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            timestamp: 1000,
            ..BlockHeader::default()
        };

        let mut eval = adapter
            .start_evaluator(prev, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[own_addr]).expect("generate_block");

        assert!(
            block.absent_participation_accounts.is_none(),
            "the proposer's own participating address must never be self-suspended"
        );
    }

    // ── pool block follower (issue #492) ────────────────────────────

    /// Commit a block to `ledger` outside of full state application --
    /// mirrors the minimal round-0 commit `seed_ledger_from_genesis` does
    /// for the genesis block, without the accompanying account totals
    /// (unneeded: `start_evaluator_advances_round_and_branch` already shows
    /// the evaluator only needs a header to build off of).
    fn commit_block_for_test(ledger: &Arc<Mutex<SqliteLedger>>, block: &algo_types::Block) {
        let hdr_data = canonical_encode_block_header_from_block(block);
        let blk_data = canonical_encode_block(block);
        let mut l = ledger.lock().expect("ledger lock");
        l.begin_block().expect("begin_block");
        l.put_block(block.round.0, &block.current_protocol, &hdr_data, &blk_data)
            .expect("put_block");
        l.set_current_round(block.round);
        l.commit_block().expect("commit_block");
    }

    /// Evaluate and commit the next block on top of `prev_hdr`, returning
    /// the newly committed header (for chaining into the next call).
    fn commit_next_block_for_test(
        ledger: &Arc<Mutex<SqliteLedger>>,
        prev_hdr: BlockHeader,
    ) -> BlockHeader {
        use algo_pool::traits::PoolLedger;

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        let mut eval = adapter
            .start_evaluator(prev_hdr, 0, 0)
            .expect("start_evaluator");
        let block = eval.generate_block(&[]).expect("generate_block");
        commit_block_for_test(ledger, &block);
        BlockHeader::decode_from_bytes(&canonical_encode_block_header_from_block(&block))
            .expect("decode committed header")
    }

    /// The fixed keypair used by [`window_pinned_txn`]'s probe transactions.
    fn probe_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Genesis hash shared by the test ledger's genesis header and every
    /// probe transaction -- `require_genesis_hash` is on for V41, so probe
    /// txns need a hash matching the block header's, not just a non-zero one.
    const PROBE_GENESIS_HASH: [u8; 32] = [0xAA; 32];

    /// Fund the probe sender directly via `set_account`, bypassing full
    /// genesis population -- this test only needs the sender to be able to
    /// pay its own txn fee, not a fully seeded ledger.
    fn fund_probe_sender(ledger: &Arc<Mutex<SqliteLedger>>) {
        let sender = Address(probe_signing_key().verifying_key().to_bytes());
        let mut l = ledger.lock().expect("ledger lock");
        l.set_account(
            &sender,
            AccountData {
                micro_algos: 1_000_000_000,
                ..AccountData::default()
            },
        );
    }

    /// Build a minimal signed payment transaction whose round window is
    /// exactly `[round, round]`, matching the round-window check in
    /// `validate_group_stateless_inner` (~line 821) that surfaces the
    /// pending-evaluator's round to callers.
    fn window_pinned_txn(round: Round, genesis_id: &str) -> SignedTransaction {
        let signing_key = probe_signing_key();
        let sender = Address(signing_key.verifying_key().to_bytes());
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver: sender,
            fee: 1_000,
            first_valid: round,
            last_valid: round,
            genesis_id: genesis_id.to_string(),
            genesis_hash: PROBE_GENESIS_HASH,
            ..Transaction::default()
        };
        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = signing_key.sign(&msg).to_bytes();
        SignedTransaction {
            txn,
            sig,
            ..SignedTransaction::default()
        }
    }

    /// Repeatedly try `pool.remember_one(txn)` until it succeeds or
    /// `deadline` passes. Returns `true` on success.
    ///
    /// The pending-block evaluator's round check (issue #492's symptom) is
    /// exactly what makes this fail while the evaluator lags: a txn with
    /// `first_valid == last_valid == round` is only accepted once the
    /// evaluator has caught up to that round.
    /// `round_advanced` is re-notified on every retry so the test doesn't
    /// depend on the follower thread having already reached its
    /// `wait_timeout` call by the time the burst below finishes committing.
    /// A plain `Condvar` has no memory of a notify sent while nobody was
    /// waiting, and under parallel `cargo test` CPU contention the follower
    /// thread's actual start can be delayed by an unpredictable amount --
    /// so a single post-burst notify is not reliable. Re-notifying every
    /// 5ms guarantees one lands soon after the follower does start waiting,
    /// without depending on precise timing.
    fn wait_for_acceptance(
        pool: &TransactionPool,
        txn: &SignedTransaction,
        round_advanced: &std::sync::Condvar,
        deadline: Instant,
    ) -> bool {
        loop {
            if pool.remember_one(txn.clone()).is_ok() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            round_advanced.notify_all();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Reproduces issue #492: with a burst of rounds committed back-to-back
    /// (as happens under sustained load) and `round_advanced` notified right
    /// after each commit -- exactly like
    /// `AgreementLedgerBridge::ensure_block` -- the follower must catch the
    /// pending-block evaluator up promptly, not only after `poll_interval`
    /// elapses.
    ///
    /// `poll_interval` is set to a full 5 seconds specifically so this test
    /// cannot pass "by accident" via the fallback poll: the old
    /// sleep-then-check implementation unconditionally blocked for the
    /// *entire* `poll_interval` before ever looking at the ledger, so it
    /// would fail this test deterministically (a >=5s wait against a <2s
    /// deadline). The fixed, condvar-driven implementation wakes on notify
    /// regardless of `poll_interval` and passes in well under a second.
    #[test]
    fn pool_block_follower_catches_up_on_notify_not_poll_interval() {
        let ledger = test_ledger();

        let genesis_hdr = BlockHeader {
            round: Round(0),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            genesis_hash: PROBE_GENESIS_HASH,
            timestamp: 1_000,
            ..BlockHeader::default()
        };
        let genesis_block = algo_types::Block {
            round: genesis_hdr.round,
            current_protocol: genesis_hdr.current_protocol.clone(),
            fee_sink: genesis_hdr.fee_sink,
            rewards_pool: genesis_hdr.rewards_pool,
            genesis_id: genesis_hdr.genesis_id.clone(),
            genesis_hash: genesis_hdr.genesis_hash,
            timestamp: genesis_hdr.timestamp,
            ..algo_types::Block::default()
        };
        commit_block_for_test(&ledger, &genesis_block);
        fund_probe_sender(&ledger);

        let pool_ledger_adapter = Arc::new(PoolLedgerAdapter::new(ledger.clone()));
        let pool = Arc::new(TransactionPool::new(
            PoolConfig::default(),
            pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        pool.ensure_evaluator_primed();

        let round_advanced = Arc::new(std::sync::Condvar::new());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let initial_round = ledger.lock().unwrap().current_round().0;
        let follower = {
            let pool = pool.clone();
            let ledger = ledger.clone();
            let round_advanced = round_advanced.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                run_pool_block_follower(
                    &pool,
                    &ledger,
                    &round_advanced,
                    &stop,
                    Duration::from_secs(5),
                    initial_round,
                );
            })
        };

        // Give the follower a moment to reach its `wait_timeout` call before
        // starting the burst below -- in production it's spawned once at
        // node startup and is already parked waiting long before real load
        // hits, so a notify is never lost; a plain `Condvar` has no memory
        // of notifications sent while nobody was waiting, so without this
        // the test itself (not the fix) could race the burst ahead of the
        // follower's first wait and spuriously fail on the 5s poll fallback.
        std::thread::sleep(Duration::from_millis(50));

        // Commit a burst of rounds back-to-back, notifying after each --
        // mirrors several rounds committing faster than a fixed poll
        // interval under sustained load.
        const ROUNDS: u64 = 5;
        let mut prev_hdr = genesis_hdr.clone();
        for _ in 0..ROUNDS {
            prev_hdr = commit_next_block_for_test(&ledger, prev_hdr);
            round_advanced.notify_all();
        }

        // The evaluator's natural target after `ROUNDS` commits is
        // `ROUNDS + 1` (the next round to build on top of the committed
        // chain) -- pin the probe txn's window there so acceptance proves
        // the evaluator actually reached the tip, not merely "some round".
        let txn = window_pinned_txn(Round(ROUNDS + 1), &genesis_hdr.genesis_id);
        let deadline = Instant::now() + Duration::from_secs(2);
        let accepted = wait_for_acceptance(&pool, &txn, &round_advanced, deadline);

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        round_advanced.notify_all();
        follower.join().expect("follower thread panicked");

        assert!(
            accepted,
            "pending-block evaluator did not catch up to round {ROUNDS} within 2s of \
             notify-driven commits -- it must be woken by round_advanced, not stuck \
             waiting out poll_interval"
        );
    }

    /// A block source that reports a transient read failure for one round
    /// exactly once, then serves it normally. Verifies the follower retries
    /// rather than silently skipping past a round it couldn't read.
    struct FlakyOnceBlockSource {
        inner: Arc<Mutex<SqliteLedger>>,
        fail_round: u64,
        already_failed: std::sync::atomic::AtomicBool,
    }

    impl CommittedBlockSource for FlakyOnceBlockSource {
        fn current_round(&self) -> Option<u64> {
            self.inner.current_round()
        }

        fn get_block(&self, round: u64) -> Option<algo_types::Block> {
            if round == self.fail_round
                && !self
                    .already_failed
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                return None;
            }
            self.inner.get_block(round)
        }
    }

    #[test]
    fn pool_block_follower_retries_round_after_transient_read_failure() {
        let ledger = test_ledger();

        let genesis_hdr = BlockHeader {
            round: Round(0),
            current_protocol: algo_types::CONSENSUS_V41.to_string(),
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            genesis_id: "net-x".to_string(),
            genesis_hash: PROBE_GENESIS_HASH,
            timestamp: 1_000,
            ..BlockHeader::default()
        };
        let genesis_block = algo_types::Block {
            round: genesis_hdr.round,
            current_protocol: genesis_hdr.current_protocol.clone(),
            fee_sink: genesis_hdr.fee_sink,
            rewards_pool: genesis_hdr.rewards_pool,
            genesis_id: genesis_hdr.genesis_id.clone(),
            genesis_hash: genesis_hdr.genesis_hash,
            timestamp: genesis_hdr.timestamp,
            ..algo_types::Block::default()
        };
        commit_block_for_test(&ledger, &genesis_block);
        fund_probe_sender(&ledger);

        let pool_ledger_adapter = Arc::new(PoolLedgerAdapter::new(ledger.clone()));
        let pool = Arc::new(TransactionPool::new(
            PoolConfig::default(),
            pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        pool.ensure_evaluator_primed();

        let round_advanced = Arc::new(std::sync::Condvar::new());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Round 1 fails to read exactly once; a short poll_interval lets
        // the follower's fallback retry it promptly.
        let flaky_source = Arc::new(FlakyOnceBlockSource {
            inner: ledger.clone(),
            fail_round: 1,
            already_failed: std::sync::atomic::AtomicBool::new(false),
        });

        let initial_round = ledger.lock().unwrap().current_round().0;
        let follower = {
            let pool = pool.clone();
            let flaky_source = flaky_source.clone();
            let round_advanced = round_advanced.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                run_pool_block_follower(
                    &pool,
                    &*flaky_source,
                    &round_advanced,
                    &stop,
                    Duration::from_millis(20),
                    initial_round,
                );
            })
        };

        let new_hdr = commit_next_block_for_test(&ledger, genesis_hdr.clone());
        round_advanced.notify_all();

        // The evaluator's target after this one commit is `new_hdr.round + 1`
        // (the next round to build on top of it).
        let txn = window_pinned_txn(new_hdr.round.next(), &genesis_hdr.genesis_id);
        let deadline = Instant::now() + Duration::from_secs(1);
        let accepted = wait_for_acceptance(&pool, &txn, &round_advanced, deadline);

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        round_advanced.notify_all();
        follower.join().expect("follower thread panicked");

        assert!(
            accepted,
            "pool must retry round {} after a transient read failure instead of \
             silently skipping past it",
            new_hdr.round.0
        );
    }

    // ── load_signing_keys_for_round ─────────────────────────────────

    #[test]
    fn load_signing_keys_returns_secrets_for_valid_round() {
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([7u8; 32]);
        // Generate a key valid for rounds [0, 1000]. key_lifetime=0 skips
        // state-proof key generation — irrelevant to VRF/OTS signing.
        let part = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate participation");
        let want_vrf_pk = part.vrf_pubkey().0;
        store.insert(&part).expect("insert participation");

        // A round inside the validity window loads the secrets, keyed by the
        // parent account, with the VRF keypair reconstructed from its seed.
        // (Unregistered key → NULL effective window, so any keys_round passes.)
        let keys = load_signing_keys_for_round(&store, Round(1), Round(1));
        assert_eq!(keys.len(), 1, "exactly one account's secrets loaded");
        let signing = keys.get(&account).expect("secrets for the account");
        assert_eq!(
            signing.vrf.pk.0, want_vrf_pk,
            "loaded VRF keypair must match the inserted key",
        );

        // A round outside the validity window loads nothing.
        let none = load_signing_keys_for_round(&store, Round(2_000), Round(2_000));
        assert!(none.is_empty(), "no secrets outside the validity window");
    }

    #[test]
    fn load_signing_keys_empty_store_returns_empty() {
        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        assert!(load_signing_keys_for_round(&store, Round(1), Round(1)).is_empty());
    }

    #[test]
    fn load_signing_keys_uses_effective_window_not_raw_validity() {
        // Regression: the loader must select keys with the same effective-window
        // semantics the pseudonode's key manager uses (`get_for_voting_round`),
        // not raw firstValid/lastValid (`get_for_round` alone). Otherwise an
        // account holding a deactivated key (still raw-valid) could overwrite the
        // active key's secret in the address-keyed map, leaving the node signing
        // the active public record with the wrong secret.
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([9u8; 32]);

        // Two keys for the same account, both raw-valid over [0, 1000] but with
        // distinct VRF keypairs so we can tell which secret got loaded.
        let key_a = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key A");
        let key_b = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key B");
        let vrf_a = key_a.vrf_pubkey().0;
        let vrf_b = key_b.vrf_pubkey().0;
        assert_ne!(vrf_a, vrf_b, "test keys must differ");
        let id_a = store.insert(&key_a).expect("insert key A");
        let id_b = store.insert(&key_b).expect("insert key B");

        // Activate A at round 1, then B at round 500 — registering B deactivates
        // A (sets A.effectiveLast = 499). At round 600 only B is effective: A's
        // effectiveLast (499) is below the vote round, so the effective-window
        // filter excludes it even though it's still raw-valid over [0, 1000].
        store.register(&id_a, Round(1)).expect("register A");
        store.register(&id_b, Round(500)).expect("register B");

        let keys = load_signing_keys_for_round(&store, Round(600), Round(600));
        let signing = keys.get(&account).expect("the effective key's secrets");
        assert_eq!(
            signing.vrf.pk.0, vrf_b,
            "must load the EFFECTIVE key (B), not the deactivated-but-raw-valid key (A)",
        );
    }

    #[test]
    fn load_signing_keys_collapses_multiple_effective_keys_deterministically() {
        // The signing map holds one secret per address. If an account has two
        // simultaneously-effective keys (both unregistered → NULL/0 effective
        // rounds, so both pass `get_for_voting_round`), the loader must collapse
        // to a single, deterministically-chosen entry (keep-first + warn) rather
        // than panic or produce duplicates. Full per-record disambiguation is
        // tracked in TASK-272.
        use algo_ledger::participation::Participation;

        let store = ParticipationStore::open_in_memory().expect("in-memory part store");
        let account = Address([3u8; 32]);
        let key_a = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key A");
        let key_b = Participation::generate(account, Round(0), Round(1000), 10_000, 0)
            .expect("generate key B");
        let vrf_a = key_a.vrf_pubkey().0;
        let vrf_b = key_b.vrf_pubkey().0;
        store.insert(&key_a).expect("insert key A");
        store.insert(&key_b).expect("insert key B");

        let keys = load_signing_keys_for_round(&store, Round(1), Round(1));
        assert_eq!(keys.len(), 1, "one secret per address — collapsed");
        let loaded = keys
            .get(&account)
            .expect("a secret for the account")
            .vrf
            .pk
            .0;
        assert!(
            loaded == vrf_a || loaded == vrf_b,
            "loaded secret must be one of the inserted keys",
        );
    }

    // ── Helpers: RestOptions / load_genesis_json ────────────────────
    //
    // These tests cover the CLI/TOML merge and genesis-file fallback
    // added in PLAN-74 TASK-79; they don't touch the agreement
    // protocol so no mock ledger / evaluator is needed.

    #[test]
    fn rest_options_disabled_when_no_listen_anywhere() {
        let opts = RestOptions::default();
        let resolved = opts.resolve(None).expect("resolve ok");
        assert!(resolved.is_none());
    }

    /// Issue #751, the headline fix: with no `--rest-listen`/`[rest].listen`
    /// but `config.json`'s real (go-matching) `EndpointAddress` default
    /// present, REST must resolve enabled on that ephemeral address —
    /// aligning with go-algorand's always-on-by-default REST server.
    #[test]
    fn rest_options_endpoint_address_enables_rest_by_default() {
        let opts = RestOptions {
            endpoint_address: "127.0.0.1:0".to_string(),
            ..RestOptions::default()
        };
        let resolved = opts
            .resolve(None)
            .expect("resolve ok")
            .expect("REST must be enabled by EndpointAddress alone");
        assert_eq!(resolved.listen.ip().to_string(), "127.0.0.1");
        assert_eq!(resolved.listen.port(), 0);
    }

    /// `--rest-listen` still wins over `config.json`'s `EndpointAddress`.
    #[test]
    fn rest_options_cli_listen_overrides_endpoint_address() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:9999".to_string()),
            endpoint_address: "127.0.0.1:0".to_string(),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).expect("resolve ok").expect("enabled");
        assert_eq!(resolved.listen.to_string(), "127.0.0.1:9999");
    }

    /// An explicit empty `EndpointAddress` is algod-rust's own "disable
    /// REST" affordance (go itself has no real off switch — its own
    /// empty-string fallback just binds port 80).
    #[test]
    fn rest_options_explicit_empty_endpoint_address_disables_rest() {
        let opts = RestOptions {
            endpoint_address: String::new(),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).expect("resolve ok");
        assert!(resolved.is_none());
    }

    /// `RestReadTimeoutSeconds`/`RestWriteTimeoutSeconds`/
    /// `RestConnectionsSoftLimit`/`RestConnectionsHardLimit`/
    /// `EnablePrivateNetworkAccessHeader` all flow through to
    /// `ResolvedRest` unchanged.
    #[test]
    fn rest_options_new_751_fields_flow_through_resolve() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            enable_private_network_access_header: true,
            rest_read_timeout_seconds: 5,
            rest_write_timeout_seconds: 10,
            rest_connections_soft_limit: 11,
            rest_connections_hard_limit: 22,
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).expect("resolve ok").expect("enabled");
        assert!(resolved.enable_private_network_access_header);
        assert_eq!(resolved.rest_read_timeout_seconds, 5);
        assert_eq!(resolved.rest_write_timeout_seconds, 10);
        assert_eq!(resolved.rest_connections_soft_limit, 11);
        assert_eq!(resolved.rest_connections_hard_limit, 22);
    }

    #[test]
    fn rest_options_cli_listen_overrides_toml_listen() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:9999".to_string()),
            data_dir: None,
            genesis_path: None,
            file_rest: Some(RestConfig {
                listen: Some("127.0.0.1:1111".to_string()),
                ..RestConfig::default()
            }),
            disable_api_auth: false,
            ..RestOptions::default()
        };
        let resolved = opts
            .resolve(None)
            .expect("resolve ok")
            .expect("rest enabled");
        assert_eq!(resolved.listen.to_string(), "127.0.0.1:9999");
    }

    #[test]
    fn rest_options_falls_back_to_toml_listen() {
        let opts = RestOptions {
            file_rest: Some(RestConfig {
                listen: Some("0.0.0.0:8080".into()),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().expect("rest enabled");
        assert_eq!(resolved.listen.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn rest_options_invalid_listen_reports_error() {
        let opts = RestOptions {
            listen: Some("not-a-socket-addr".into()),
            ..RestOptions::default()
        };
        let err = opts.resolve(None).unwrap_err();
        assert!(
            err.to_string().contains("invalid --rest-listen"),
            "expected parse-error message, got {err}"
        );
    }

    #[test]
    fn rest_options_data_dir_defaults_to_ledger_parent() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            data_dir: None,
            genesis_path: None,
            file_rest: None,
            disable_api_auth: false,
            ..RestOptions::default()
        };
        let ledger_parent = std::path::Path::new("/srv/algod");
        let resolved = opts.resolve(Some(ledger_parent)).unwrap().unwrap();
        assert_eq!(
            resolved.data_dir.as_deref(),
            Some(ledger_parent),
            "missing data_dir should default to the ledger's parent directory"
        );
    }

    #[test]
    fn rest_options_cli_data_dir_overrides_default() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            data_dir: Some(PathBuf::from("/var/lib/algod")),
            genesis_path: None,
            file_rest: None,
            disable_api_auth: false,
            ..RestOptions::default()
        };
        let resolved = opts
            .resolve(Some(std::path::Path::new("/srv/algod")))
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved.data_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/algod"))
        );
    }

    #[test]
    fn rest_options_token_overrides_come_only_from_toml() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            file_rest: Some(RestConfig {
                api_token: Some("from-toml-api".into()),
                admin_token: Some("from-toml-admin".into()),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert_eq!(resolved.api_token.as_deref(), Some("from-toml-api"));
        assert_eq!(resolved.admin_token.as_deref(), Some("from-toml-admin"));
    }

    #[test]
    fn rest_options_async_backlog_plumbed_from_toml() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            file_rest: Some(RestConfig {
                async_backlog_size: Some(42),
                ..RestConfig::default()
            }),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert_eq!(resolved.async_backlog_size, Some(42));
    }

    /// Issue #748: `config.json`'s `DisableAPIAuth` must reach
    /// `ResolvedRest` (and from there `ApiServerConfig`/`TokenConfig`) —
    /// there is no CLI flag for it (matching go, which has none either),
    /// so `RestOptions::disable_api_auth` is the only path in.
    #[test]
    fn rest_options_disable_api_auth_plumbed_through_resolve() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            disable_api_auth: true,
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert!(resolved.disable_api_auth);
    }

    // --- NetworkOptions::resolve (issue #768: now shared with `relay`) ----

    #[test]
    fn network_options_resolve_falls_back_to_config_json_when_no_cli_override() {
        let local = algo_config::Local {
            max_connections_per_ip: 4,
            incoming_connections_limit: 100,
            connections_rate_limiting_count: 20,
            broadcast_connections_limit: -1,
            tls_cert_file: "/etc/cert.pem".to_string(),
            tls_key_file: "/etc/key.pem".to_string(),
            ..algo_config::Local::default()
        };

        let opts = NetworkOptions::default();
        let resolved = opts.resolve(&local);

        assert_eq!(resolved.max_connections_per_ip, 4);
        assert_eq!(resolved.incoming_connections_limit, 100);
        assert_eq!(resolved.connections_rate_limiting_count, 20);
        assert_eq!(
            resolved.broadcast_connections_limit,
            algo_network::UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT,
            "-1 (unbounded) must translate to the sentinel, not wrap to a huge u32"
        );
        assert_eq!(resolved.tls_cert_file.as_deref(), Some("/etc/cert.pem"));
        assert_eq!(resolved.tls_key_file.as_deref(), Some("/etc/key.pem"));
    }

    #[test]
    fn network_options_resolve_cli_override_wins_over_config_json() {
        let local = algo_config::Local {
            max_connections_per_ip: 4,
            tls_cert_file: "/etc/cert.pem".to_string(),
            ..algo_config::Local::default()
        };

        let opts = NetworkOptions {
            max_connections_per_ip: Some(99),
            tls_cert_file: Some("/opt/mycert.pem".to_string()),
            ..NetworkOptions::default()
        };
        let resolved = opts.resolve(&local);

        assert_eq!(resolved.max_connections_per_ip, 99);
        assert_eq!(resolved.tls_cert_file.as_deref(), Some("/opt/mycert.pem"));
    }

    #[test]
    fn network_options_resolve_empty_tls_paths_are_none() {
        // Go's own "" == unset convention: an untouched `config.json`
        // (empty TLSCertFile/TLSKeyFile) must resolve to `None`, not
        // `Some("")`.
        let local = algo_config::Local::default();
        let resolved = NetworkOptions::default().resolve(&local);
        assert_eq!(resolved.tls_cert_file, None);
        assert_eq!(resolved.tls_key_file, None);
    }

    #[test]
    fn rest_options_disable_api_auth_defaults_to_false() {
        let opts = RestOptions {
            listen: Some("127.0.0.1:4001".into()),
            ..RestOptions::default()
        };
        let resolved = opts.resolve(None).unwrap().unwrap();
        assert!(!resolved.disable_api_auth);
    }

    #[test]
    fn load_genesis_json_returns_none_when_paths_absent() {
        let got = load_genesis_json(None, None).expect("ok with no paths");
        assert!(got.is_none());
    }

    #[test]
    fn load_genesis_json_prefers_explicit_path_then_data_dir() {
        let tmp = std::env::temp_dir().join(format!(
            "algod-rust-test-genesis-{}.json",
            std::process::id()
        ));
        std::fs::write(&tmp, r#"{"network":"unit-test"}"#).unwrap();
        let got = load_genesis_json(Some(&tmp), None)
            .expect("ok")
            .expect("file present");
        assert_eq!(got, r#"{"network":"unit-test"}"#);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_genesis_json_missing_explicit_falls_back_to_data_dir() {
        // When `--genesis-path` points at a missing file but
        // `<data_dir>/genesis.json` exists, the real file wins — we
        // must not silently synthesize a stub when a real file is
        // available under the data directory.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-dd-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let data_dir_genesis = tmp_dir.join("genesis.json");
        std::fs::write(&data_dir_genesis, r#"{"network":"fallback"}"#).unwrap();

        let got = load_genesis_json(
            Some(std::path::Path::new("/no/such/genesis.json")),
            Some(&tmp_dir),
        )
        .expect("ok — fallback succeeds")
        .expect("data_dir/genesis.json should serve the response");
        assert_eq!(got, r#"{"network":"fallback"}"#);

        let _ = std::fs::remove_file(&data_dir_genesis);
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn load_genesis_json_all_candidates_absent_returns_none() {
        // When both the explicit path and the data_dir default are
        // missing, the function returns `Ok(None)` so startup can
        // synthesize a stub. This is the "no real genesis file
        // anywhere on disk" path, distinct from the fallback test
        // above.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-absent-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        // Intentionally do NOT create `genesis.json` in `tmp_dir`.

        let got = load_genesis_json(
            Some(std::path::Path::new("/no/such/genesis.json")),
            Some(&tmp_dir),
        )
        .expect("ok when both absent");
        assert!(got.is_none());

        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn load_genesis_json_deduplicates_when_explicit_equals_data_dir_derived() {
        // If `--genesis-path` resolves to the same file as
        // `<data_dir>/genesis.json`, the function must not attempt
        // two reads. The test exercises the dedup branch by pointing
        // both candidates at the same path.
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-test-dedup-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let shared = tmp_dir.join("genesis.json");
        std::fs::write(&shared, r#"{"network":"shared"}"#).unwrap();

        let got = load_genesis_json(Some(&shared), Some(&tmp_dir))
            .expect("ok")
            .expect("shared file serves");
        assert_eq!(got, r#"{"network":"shared"}"#);

        let _ = std::fs::remove_file(&shared);
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn synthesize_genesis_json_produces_minimal_valid_body() {
        let json = synthesize_genesis_json("mainnet-v1.0", "mainnet", "https://example.com/v41");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["network"], "mainnet");
        assert_eq!(parsed["id"], "v1.0");
        assert_eq!(parsed["proto"], "https://example.com/v41");
        assert!(parsed["alloc"].is_array());
    }

    #[test]
    fn synthesize_genesis_json_passes_through_when_prefix_missing() {
        let json = synthesize_genesis_json("foo-bar-baz", "mainnet", "proto");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "foo-bar-baz");
    }

    // ── Partkey auto-discovery (issue #468) ─────────────────────────
    //
    // The accept/reject table below is Go's, not ours: every case is
    // what `config.IsPartKeyFilename` returns at v4.6.0-stable. A name
    // Go skips must be skipped here, or a mixed cluster disagrees about
    // what counts as key material.

    #[test]
    fn is_partkey_filename_accepts_goal_network_create_names() {
        // Exactly what `goal network create` writes.
        assert!(is_partkey_filename("Wallet1.0.1500.partkey"));
        assert!(is_partkey_filename("Wallet4.0.30000.partkey"));
        // Account names may themselves contain dots — Go takes the
        // numeric fields from the *end* of the name.
        assert!(is_partkey_filename("my.wallet.name.1.100.partkey"));
        // first == last is a legal single-round window.
        assert!(is_partkey_filename("W.7.7.partkey"));
    }

    #[test]
    fn is_partkey_filename_rejects_non_partkey_names() {
        assert!(!is_partkey_filename("Wallet1.rootkey"));
        assert!(!is_partkey_filename("genesis.json"));
        assert!(!is_partkey_filename("partkey"));
        // Too few components: Go requires >= 4.
        assert!(!is_partkey_filename("0.1500.partkey"));
        // The SQLite sidecars a running node leaves behind. Importing a
        // `-wal` as if it were a database would be a hard error at open
        // time, so this exclusion is load-bearing.
        assert!(!is_partkey_filename("Wallet1.0.1500.partkey-wal"));
        assert!(!is_partkey_filename("Wallet1.0.1500.partkey-shm"));
        // Go renames unsupported-schema keys to `*.old` and must not
        // pick them back up on the next boot.
        assert!(!is_partkey_filename("Wallet1.0.1500.partkey.old"));
    }

    #[test]
    fn is_partkey_filename_rejects_non_roundtripping_numbers() {
        // `%d` never emits leading zeros, so Go's round-trip check
        // rejects these even though they parse fine.
        assert!(!is_partkey_filename("W.01.1500.partkey"));
        assert!(!is_partkey_filename("W.0.01500.partkey"));
        assert!(!is_partkey_filename("W.+0.1500.partkey"));
        assert!(!is_partkey_filename("W.-1.1500.partkey"));
        assert!(!is_partkey_filename("W.a.b.partkey"));
        // first > last is incoherent and rejected by
        // `extractPartValidInterval`.
        assert!(!is_partkey_filename("W.1500.0.partkey"));
    }

    #[test]
    fn discover_partkey_files_finds_only_partkeys_sorted() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "Wallet2.0.1500.partkey",
            "Wallet1.0.1500.partkey",
            "Wallet1.rootkey",
            "genesis.json",
            "Wallet1.0.1500.partkey-wal",
        ] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        // A directory whose *name* looks like a partkey must not be
        // returned — Go opens files, not directories.
        std::fs::create_dir(dir.path().join("Wallet9.0.1.partkey")).unwrap();

        let found = discover_partkey_files(dir.path()).expect("discover");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["Wallet1.0.1500.partkey", "Wallet2.0.1500.partkey"],
            "discovery must return only partkey files, in a deterministic order"
        );
    }

    #[test]
    fn discover_partkey_files_on_empty_dir_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_partkey_files(dir.path())
            .expect("discover")
            .is_empty());
    }

    #[test]
    fn discover_partkey_files_errors_on_unreadable_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let err = discover_partkey_files(&missing).expect_err("missing dir must error");
        assert!(
            err.to_string()
                .contains("could not read participation key directory"),
            "error should name the unreadable directory, got: {err}"
        );
    }

    /// The Go-parity path: `--data-dir <node>` alone must find the key
    /// `goal network create` wrote to `<node>/<genesis-id>/`, with no
    /// `--import-partkey` and no `--partkey-dir`.
    #[test]
    fn resolve_partkey_imports_scans_the_genesis_dir_like_go() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_dir = dir.path().join("phase6net-v1");
        std::fs::create_dir(&genesis_dir).unwrap();
        std::fs::write(genesis_dir.join("Wallet1.0.1500.partkey"), b"x").unwrap();
        std::fs::write(genesis_dir.join("Wallet1.rootkey"), b"x").unwrap();

        let got =
            resolve_partkey_imports(&[], &[], Some(dir.path()), "phase6net-v1").expect("resolve");
        assert_eq!(got, vec![genesis_dir.join("Wallet1.0.1500.partkey")]);
    }

    /// A data dir with no genesis subdirectory (a plain Rust-only node)
    /// must not error — the scan is opportunistic.
    #[test]
    fn resolve_partkey_imports_tolerates_missing_genesis_dir() {
        let dir = tempfile::tempdir().unwrap();
        let got =
            resolve_partkey_imports(&[], &[], Some(dir.path()), "phase6net-v1").expect("resolve");
        assert!(got.is_empty());
    }

    /// Explicit paths come first and survive; a path that is both named
    /// explicitly and found by a scan appears once.
    #[test]
    fn resolve_partkey_imports_dedupes_explicit_and_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_dir = dir.path().join("phase6net-v1");
        std::fs::create_dir(&genesis_dir).unwrap();
        let shared = genesis_dir.join("Wallet1.0.1500.partkey");
        std::fs::write(&shared, b"x").unwrap();

        let scan_dir = dir.path().join("extra");
        std::fs::create_dir(&scan_dir).unwrap();
        let extra = scan_dir.join("Wallet2.0.1500.partkey");
        std::fs::write(&extra, b"x").unwrap();

        let got = resolve_partkey_imports(
            std::slice::from_ref(&shared),
            std::slice::from_ref(&scan_dir),
            Some(dir.path()),
            "phase6net-v1",
        )
        .expect("resolve");
        assert_eq!(
            got,
            vec![shared, extra],
            "explicit paths lead, discovered paths follow, no duplicates"
        );
    }

    /// Without a data dir there is no genesis directory to guess at, so
    /// only what the operator named is imported.
    #[test]
    fn resolve_partkey_imports_without_data_dir_uses_explicit_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Wallet1.0.1500.partkey");
        std::fs::write(&p, b"x").unwrap();
        let got = resolve_partkey_imports(std::slice::from_ref(&p), &[], None, "phase6net-v1")
            .expect("resolve");
        assert_eq!(got, vec![p]);
    }

    /// An explicitly requested `--partkey-dir` that doesn't exist is a
    /// configuration error and must fail loudly, unlike the
    /// opportunistic genesis-dir scan.
    #[test]
    fn resolve_partkey_imports_propagates_partkey_dir_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = resolve_partkey_imports(&[], &[missing], None, "phase6net-v1")
            .expect_err("missing --partkey-dir must error");
        assert!(err
            .to_string()
            .contains("could not read participation key directory"));
    }

    /// End-to-end for issue #468 criterion 3, using the real
    /// `goal network create` artifact committed under
    /// `crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create/`
    /// (capture procedure documented in
    /// `crates/core/algo-ledger/tests/goal_network_create_test.rs`).
    ///
    /// Lay the fixture out the way `goal` does — `<data-dir>/<genesis-id>/`
    /// — and drive the whole startup path: discover, restore, insert into
    /// the registry `--partkey-path` reads. No conversion step, no flags
    /// beyond `--data-dir`.
    #[test]
    fn goal_network_create_key_is_discovered_and_registered() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create")
            .join("Wallet1.0.1500.partkey");
        assert!(
            fixture.exists(),
            "goal-network-create fixture missing at {}",
            fixture.display()
        );

        let dir = tempfile::tempdir().unwrap();
        let genesis_dir = dir.path().join("phase6net-v1");
        std::fs::create_dir(&genesis_dir).unwrap();
        let staged = genesis_dir.join("Wallet1.0.1500.partkey");
        std::fs::copy(&fixture, &staged).unwrap();
        // Sidecars and the root key sit next to it in a real netroot.
        std::fs::write(genesis_dir.join("Wallet1.rootkey"), b"not a partkey").unwrap();

        let to_import = resolve_partkey_imports(&[], &[], Some(dir.path()), "phase6net-v1")
            .expect("resolve imports");
        assert_eq!(to_import, vec![staged]);

        let store = ParticipationStore::open_in_memory().expect("registry");
        let inserted = import_go_partkeys(&store, &to_import).expect("import");
        assert_eq!(inserted, 1);

        let records = store.get_all().expect("get_all");
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(
            rec.account.to_string(),
            "TO2V5UP4UGHPVJPY4BBIAVNDF2SYGHCSL6DH5VNLSVCUBZ42BJFJZFKXCE",
            "registered account must be the Wallet1 address from goal's genesis.json"
        );
        assert_eq!(rec.first_valid.0, 0);
        assert_eq!(rec.last_valid.0, 1500);
        assert_eq!(rec.key_dilution, 10_000);
        assert!(
            rec.vote_id.is_some() && rec.vrf_public_key.is_some(),
            "a key missing vote_id or the VRF key is filtered out of consensus"
        );

        // Restarting against the same registry volume must converge, not
        // crash on the UNIQUE(participationID) constraint.
        let again = import_go_partkeys(&store, &to_import).expect("re-import is a no-op");
        assert_eq!(again, 0);
        assert_eq!(store.get_all().expect("get_all").len(), 1);
    }

    /// Negative path: a truncated/garbage file whose *name* passes the
    /// discovery filter must fail the import with a message naming the
    /// file, not silently register nothing.
    #[test]
    fn import_go_partkeys_rejects_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("Wallet1.0.1500.partkey");
        std::fs::write(&bogus, b"this is not a sqlite database").unwrap();

        let store = ParticipationStore::open_in_memory().expect("registry");
        let err = import_go_partkeys(&store, std::slice::from_ref(&bogus))
            .expect_err("corrupt file must fail");
        assert!(
            err.to_string().contains("Wallet1.0.1500.partkey"),
            "error should name the offending file, got: {err}"
        );
        assert!(store.get_all().expect("get_all").is_empty());
    }

    /// An empty file is a distinct failure mode (an interrupted copy);
    /// SQLite would happily open it as a blank database, so
    /// `restore_partkey_file` short-circuits on zero length.
    #[test]
    fn restore_partkey_file_rejects_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("Wallet1.0.1500.partkey");
        std::fs::write(&empty, b"").unwrap();
        let err = match restore_partkey_file(&empty) {
            Ok(_) => panic!("an empty partkey file must not restore"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("is empty"),
            "error should say the file is empty, got: {err}"
        );
    }

    // ── Helper: V41 consensus params ────────────────────────────────
    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V41).unwrap()
    }

    // ── Helper: build an evaluator with pre-seeded account balances ─
    fn make_evaluator(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        accounts: &[(Address, u64)],
    ) -> SimpleBlockEvaluator {
        make_evaluator_with_accounts(ledger, params, round, accounts, &[])
    }

    /// Build an evaluator with full AccountData entries (for min-balance tests).
    fn make_evaluator_with_accounts(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        simple_accounts: &[(Address, u64)],
        full_accounts: &[(Address, AccountData)],
    ) -> SimpleBlockEvaluator {
        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        // Pre-populate the snapshot cache so tests don't need the ledger
        // to actually contain accounts.
        for (addr, balance) in simple_accounts {
            snapshot.accounts.insert(
                *addr,
                Some(algo_types::AccountData {
                    micro_algos: *balance,
                    ..Default::default()
                }),
            );
        }
        for (addr, acct) in full_accounts {
            snapshot.accounts.insert(*addr, Some(acct.clone()));
        }
        SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(round),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }
    }

    // ── Helper: ed25519 keypair → (Address, SigningKey) ─────────────
    fn test_keypair(seed: u8) -> (Address, SigningKey) {
        let secret = [seed; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let pk = signing_key.verifying_key().to_bytes();
        (Address(pk), signing_key)
    }

    // ── Helper: sign a transaction with ed25519 ─────────────────────
    fn sign_txn(txn: &Transaction, key: &SigningKey) -> [u8; 64] {
        let canonical = algo_codec::canonical_encode_transaction(txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        sig.to_bytes()
    }

    // ── Helper: build a signed payment txn for a given round ────────
    fn make_signed_pay(
        sender_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, sender_key);
        SignedTransaction {
            txn,
            sig,
            ..Default::default()
        }
    }

    // ── PoolLedgerAdapter duplicate detection ───────────────────────

    /// Serialize a TxTailRound holding the given txids for `round`.
    fn adapter_tail_bytes(round: u64, txids: &[[u8; 32]]) -> Vec<u8> {
        let tail = algo_types::TxTailRound {
            txn_ids: txids
                .iter()
                .map(|id| serde_bytes::ByteBuf::from(id.to_vec()))
                .collect(),
            last_valid: txids.iter().map(|_| round + 1000).collect(),
            leases: Vec::new(),
            hdr: BlockHeader {
                round: Round(round),
                ..BlockHeader::default()
            },
        };
        algo_codec::canonical_encode_txtail_round(&tail)
    }

    /// Pins the behavior of `contains_confirmed_txid` across the in-memory
    /// txtail cache: hits within the 1000-round window, misses outside it,
    /// and visibility of rounds committed *after* earlier queries (the
    /// incremental-sync path). Written against the pre-cache SQLite-scan
    /// semantics; the cached implementation must answer identically.
    #[test]
    fn adapter_contains_confirmed_txid_tracks_committed_rounds() {
        use algo_ledger::store_trait::LedgerStore;
        use algo_pool::traits::PoolLedger;

        let ledger = test_ledger();
        let confirmed_r1 = [0x11u8; 32];
        let confirmed_r2 = [0x22u8; 32];
        let never_confirmed = [0x33u8; 32];

        {
            let mut l = ledger.lock().unwrap();
            l.put_txtail(1, &adapter_tail_bytes(1, &[confirmed_r1]))
                .unwrap();
            l.set_current_round(Round(1));
        }

        let adapter = PoolLedgerAdapter::new(ledger.clone());
        assert!(adapter.contains_confirmed_txid(Digest(confirmed_r1)));
        assert!(!adapter.contains_confirmed_txid(Digest(never_confirmed)));
        // Not yet committed — must not be reported as confirmed.
        assert!(!adapter.contains_confirmed_txid(Digest(confirmed_r2)));

        // Commit round 2 through the same shared ledger handle (as the
        // participation loop does) — the adapter must pick it up.
        {
            let mut l = ledger.lock().unwrap();
            l.put_txtail(2, &adapter_tail_bytes(2, &[confirmed_r2]))
                .unwrap();
            l.set_current_round(Round(2));
        }
        assert!(adapter.contains_confirmed_txid(Digest(confirmed_r2)));
        assert!(adapter.contains_confirmed_txid(Digest(confirmed_r1)));

        // Advance beyond the 1000-round lookback window: round 1's txid
        // ages out (its own last_valid would have expired — go's
        // MaxTxnLife bound, ledger/txtail.go).
        {
            let mut l = ledger.lock().unwrap();
            l.set_current_round(Round(1002));
        }
        assert!(
            !adapter.contains_confirmed_txid(Digest(confirmed_r1)),
            "txid confirmed at round 1 must age out at round 1002"
        );
        assert!(
            adapter.contains_confirmed_txid(Digest(confirmed_r2)),
            "round 2 is still inside the window at round 1002"
        );
    }

    // ====================================================================
    // 1. CowOverlay unit tests
    // ====================================================================

    #[test]
    fn cow_overlay_txid_dedup() {
        let mut overlay = CowOverlay::new();
        let txid = [0x42; 32];
        assert!(overlay.check_txid(&txid).is_ok());
        overlay.record_txid(txid);
        let err = overlay.check_txid(&txid).unwrap_err();
        assert!(err.to_string().contains("duplicate transaction ID"));
    }

    #[test]
    fn cow_overlay_lease_dedup() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let lease = [0xBB; 32];
        let round = 100;
        assert!(overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .is_ok());
        overlay.record_lease(&sender, &lease, round + 500);
        let err = overlay
            .check_lease_in_overlay(&sender, &lease, round)
            .unwrap_err();
        assert!(err.to_string().contains("duplicate lease"));
    }

    #[test]
    fn cow_overlay_zero_lease_always_allowed() {
        let mut overlay = CowOverlay::new();
        let sender = Address([1; 32]);
        let zero_lease = [0u8; 32];
        overlay.record_lease(&sender, &zero_lease, 999);
        assert!(overlay
            .check_lease_in_overlay(&sender, &zero_lease, 100)
            .is_ok());
    }

    #[test]
    fn cow_overlay_balance_tracking() {
        let mut overlay = CowOverlay::new();
        let addr = Address([5; 32]);
        assert!(overlay.get_balance(&addr).is_none());
        overlay.set_balance(&addr, 1_000_000);
        assert_eq!(overlay.get_balance(&addr), Some(1_000_000));
    }

    #[test]
    fn cow_checkpoint_and_rollback() {
        let mut overlay = CowOverlay::new();
        let addr = Address([7; 32]);
        overlay.set_balance(&addr, 500_000);
        let txid1 = [0x01; 32];
        overlay.record_txid(txid1);

        // Checkpoint (incremental — records nothing initially)
        let mut cp = overlay.checkpoint();

        // Mutate using tracked variants so changes are recorded in the
        // checkpoint for rollback.
        overlay.set_balance_tracked(&addr, 100, &mut cp);
        let txid2 = [0x02; 32];
        overlay.record_txid_tracked(txid2, &mut cp);
        assert_eq!(overlay.get_balance(&addr), Some(100));
        assert!(overlay.check_txid(&txid2).is_err());

        // Rollback — only the tracked mutations are undone.
        overlay.restore(cp);
        assert_eq!(overlay.get_balance(&addr), Some(500_000));
        // txid2 should no longer be seen
        assert!(overlay.check_txid(&txid2).is_ok());
        // txid1 should still be seen
        assert!(overlay.check_txid(&txid1).is_err());
    }

    // ====================================================================
    // 2. stpf rejection / heartbeat acceptance tests (issue #820, revised
    //    for issue #814: the pool no longer blanket-rejects every `stpf`
    //    transaction -- see `validate_group_stateless_inner`'s "1." comment)
    // ====================================================================

    /// A transaction of type `stpf` from an ordinary (non-state-proof-sender)
    /// account, carrying an ordinary payment shape and an ordinary ed25519
    /// signature, must still be rejected -- not because `stpf` is
    /// categorically banned from the pool anymore (issue #814 removed that
    /// blanket guard), but because it fails `stpf`'s own well-formedness
    /// check (`rules.rs`: sender must be `Address::STATE_PROOF_SENDER`).
    #[test]
    fn reject_stpf_from_wrong_sender() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &Address([2; 32]), 0, 1000, 100);
        stx.txn.txn_type = TxnType::Stpf;
        // Re-sign after mutation
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("state-proof sender"),
            "expected a state-proof-sender well-formedness rejection, got: {err}"
        );
    }

    /// Issue #814 live mixed-cluster verification: a genuine, well-formed,
    /// zero-signature `stpf` transaction from `Address::STATE_PROOF_SENDER`
    /// must now be ADMITTED to the pool -- whether it is the node's own
    /// locally-built state proof (`stateproof_service`'s
    /// `LocalTxBroadcaster::submit_group`) or one gossiped in from a peer
    /// that built it first. Before this fix, `validate_group_stateless_inner`
    /// rejected every `stpf` transaction outright with "cannot be submitted
    /// via the pool" -- discovered live when a real go-algorand relay's own
    /// state-proof-worker output was rejected by the Rust node's pool, and
    /// confirmed that the Rust node's *own* state-proof worker would have
    /// hit the identical rejection trying to submit its own proof.
    #[test]
    fn accept_well_formed_state_proof_txn_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let mut eval = make_evaluator(&ledger, &params, 100, &[]);

        let stx = algo_types::SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Stpf,
                sender: Address::STATE_PROOF_SENDER,
                fee: 0,
                first_valid: Round(1),
                last_valid: Round(1000),
                genesis_hash: [0xAA; 32], // matches make_evaluator's block header
                ..Default::default()
            },
            sig: [0u8; 64],
            ..Default::default()
        };

        eval.transaction_group(&[stx])
            .expect("a well-formed zero-signature stpf transaction must be admitted");
        assert_eq!(eval.pay_set_size(), 1);
    }

    /// Issue #820: a well-formed, fee-exempt heartbeat transaction (as the
    /// autonomous heartbeat service would construct via
    /// `algo_ledger::build_heartbeat_transaction`, signed with the
    /// accepting LogicSig) must be accepted by the block evaluator, NOT
    /// blanket-rejected by transaction type. Before this fix, `hb` was
    /// rejected here unconditionally (mirroring `stpf`'s rejection above),
    /// which meant a node's own heartbeat service could never get its
    /// heartbeat into a block it proposed itself -- see the doc comment on
    /// `validate_group_stateless_inner`'s type-rejection block for why
    /// `hb`, unlike `stpf`, is a genuine pool-eligible transaction in
    /// go-algorand.
    #[test]
    fn accept_heartbeat_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let mut eval = make_evaluator(&ledger, &params, 100, &[]);

        let first_id = algo_consensus_crypto::one_time_id_for_round(0, 10);
        let last_id = algo_consensus_crypto::one_time_id_for_round(2000, 10);
        let num_batches = last_id.batch - first_id.batch + 1;
        let voting =
            algo_consensus_crypto::OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = voting.verifier();

        let stx = algo_ledger::build_heartbeat_transaction(algo_ledger::HeartbeatParams {
            hb_address: Address([7u8; 32]),
            voting: &voting,
            vote_id,
            key_dilution: 10,
            genesis_hash: [0xAA; 32], // matches make_evaluator's block header
            latest_round: Round(90),
            latest_seed: [0x55u8; 32],
            challenge_discount: false, // pre-v42: zero fee alone signals the claim
        });

        eval.transaction_group(&[stx])
            .expect("a well-formed accepting-LogicSig heartbeat must be admitted");
        assert_eq!(eval.pay_set_size(), 1);
    }

    /// A heartbeat whose LogicSig sets `RekeyTo` fails the accepting
    /// program's own check (`txn RekeyTo == global ZeroAddress`) --
    /// confirming that removing the blanket `hb` rejection does not mean
    /// "accept any heartbeat unconditionally"; ordinary signature
    /// verification (LogicSig execution) still gates admission.
    #[test]
    fn reject_heartbeat_with_rekey_from_pool() {
        let ledger = test_ledger();
        let params = v41_params();
        let mut eval = make_evaluator(&ledger, &params, 100, &[]);

        let first_id = algo_consensus_crypto::one_time_id_for_round(0, 10);
        let last_id = algo_consensus_crypto::one_time_id_for_round(2000, 10);
        let num_batches = last_id.batch - first_id.batch + 1;
        let voting =
            algo_consensus_crypto::OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = voting.verifier();

        let mut stx = algo_ledger::build_heartbeat_transaction(algo_ledger::HeartbeatParams {
            hb_address: Address([7u8; 32]),
            voting: &voting,
            vote_id,
            key_dilution: 10,
            genesis_hash: [0xAA; 32],
            latest_round: Round(90),
            latest_seed: [0x55u8; 32],
            challenge_discount: false,
        });
        stx.txn.rekey_to = Some(Address([9u8; 32]));

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            !err.to_string().contains("cannot be submitted via the pool"),
            "must not be rejected by blanket type check anymore, got: {err}"
        );
    }

    // ====================================================================
    // 3. Signature verification tests
    // ====================================================================

    #[test]
    fn valid_single_sig_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(10);
        let (receiver, _) = test_keypair(11);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 10_000_000), (receiver, 100_000)],
        );

        let stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        assert!(eval.transaction_group(&[stx]).is_ok());
    }

    #[test]
    fn invalid_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(20);
        let (receiver, _) = test_keypair(21);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx = make_signed_pay(&key, &sender, &receiver, 1000, 1000, 100);
        // Corrupt signature
        stx.sig[0] ^= 0xFF;

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "expected signature error, got: {err}"
        );
    }

    #[test]
    fn missing_signature_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(30);
        let (receiver, _) = test_keypair(31);
        let eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                sender,
                receiver,
                amount: 1000,
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(1100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                ..Default::default()
            },
            sig: [0u8; 64], // no signature
            ..Default::default()
        };

        let err = eval.test_transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("no signature"),
            "expected no-signature error, got: {err}"
        );
    }

    // ====================================================================
    // 4. Lease uniqueness tests
    // ====================================================================

    #[test]
    fn duplicate_lease_in_block_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(40);
        let (receiver, _) = test_keypair(41);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xCC; 32];

        // First txn with lease (amount=0 to avoid receiver min-balance issues)
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second txn with same lease but different note (so txid differs) — should be rejected
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            lease,
            note: ByteBuf::from(vec![0x01]), // different note -> different txid
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("lease"),
            "expected lease error, got: {err}"
        );
    }

    #[test]
    fn different_leases_accepted() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(42);
        let (receiver, _) = test_keypair(43);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = [0xDD; 32];
        stx1.sig = sign_txn(&stx1.txn, &key);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = [0xEE; 32];
        stx2.sig = sign_txn(&stx2.txn, &key);
        assert!(eval.transaction_group(&[stx2]).is_ok());
    }

    // ====================================================================
    // 5. TxID dedup tests
    // ====================================================================

    #[test]
    fn duplicate_txid_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(50);
        let (receiver, _) = test_keypair(51);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);

        // First submission succeeds
        assert!(eval.transaction_group(std::slice::from_ref(&stx)).is_ok());

        // Same exact transaction again — should be rejected as duplicate txid
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate transaction ID"),
            "expected duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_txid_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(52);
        let (receiver, _) = test_keypair(53);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Build a single transaction and submit it twice in the same group.
        // Both copies are identical so they have the same txid.
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx.clone(), stx]).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate transaction ID within group"),
            "expected intra-group duplicate txid error, got: {err}"
        );
    }

    #[test]
    fn duplicate_lease_within_group_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(54);
        let (receiver, _) = test_keypair(55);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let lease = [0xFF; 32];

        // Two transactions from the same sender with the same lease but
        // different notes (so they have different txids).
        let mut stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx1.txn.lease = lease;
        stx1.txn.note = ByteBuf::from(vec![0x01]);
        stx1.sig = sign_txn(&stx1.txn, &key);

        let mut stx2 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        stx2.txn.lease = lease;
        stx2.txn.note = ByteBuf::from(vec![0x02]);
        stx2.sig = sign_txn(&stx2.txn, &key);

        let err = eval.transaction_group(&[stx1, stx2]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate lease within group"),
            "expected intra-group duplicate lease error, got: {err}"
        );
    }

    // ====================================================================
    // 6. Balance / min-balance tests
    // ====================================================================

    #[test]
    fn insufficient_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(60);
        let (receiver, _) = test_keypair(61);
        // Sender only has 500 microAlgos — not enough for fee(1000) + amount(100)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 500)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance"),
            "expected insufficient balance, got: {err}"
        );
    }

    #[test]
    fn sender_below_min_balance_rejected() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(62);
        let (receiver, _) = test_keypair(63);
        // Sender has exactly min_balance + fee + amount — after deduction they'd
        // have amount=0 left. Let's set them up so they'd have a few uAlgos left
        // but below min_balance.
        // fee=1000, amount=0 -> sender_after = balance - 1000
        // We want: 0 < sender_after < min_balance
        // So balance = 1000 + 50_000 = 51_000, sender_after = 50_000 < 100_000
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 51_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum") || err.to_string().contains("min"),
            "expected min-balance error, got: {err}"
        );
    }

    #[test]
    fn close_remainder_zeros_sender_and_credits_close_addr() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(64);
        let (receiver, _) = test_keypair(65);
        let (close_addr, _) = test_keypair(66);
        // Sender: 1_000_000, fee=1000, amount=200_000
        // After cost: 1_000_000 - 1000 - 200_000 = 799_000
        // Close: sender -> 0, close_addr gets 799_000
        let initial_close_balance = 500_000u64;
        let initial_receiver_balance = 100_000u64;
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, 1_000_000),
                (receiver, initial_receiver_balance),
                (close_addr, initial_close_balance),
            ],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 200_000, 1000, 100);
        stx.txn.close_remainder_to = close_addr;
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(eval.transaction_group(&[stx]).is_ok());

        // Verify sender is zero (closed)
        assert_eq!(eval.effective_balance(&sender), 0);
        // Verify close_addr got the remainder
        // sender_after_cost = 1_000_000 - 1000 - 200_000 = 799_000
        // close_addr = 500_000 + 799_000 = 1_299_000
        assert_eq!(
            eval.effective_balance(&close_addr),
            initial_close_balance + (1_000_000 - 1000 - 200_000)
        );
        // Verify receiver got the amount
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + 200_000
        );
    }

    #[test]
    fn cross_group_receiver_can_spend() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(70);
        let (sender_b, key_b) = test_keypair(71);
        let (receiver, _) = test_keypair(72);
        // sender_a has 1M, sender_b has 0
        // Group 1: A sends 500_000 to B
        // Group 2: B sends 100_000 to receiver (needs balance from group 1)
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 1_000_000),
                (sender_b, 200_000), // needs min balance + fee
            ],
        );

        // Group 1: A -> B for 500_000
        let stx1 = make_signed_pay(&key_a, &sender_a, &sender_b, 500_000, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Group 2: B -> receiver for 100_000 (B should have 200_000 + 500_000 = 700_000 now)
        let stx2 = make_signed_pay(&key_b, &sender_b, &receiver, 100_000, 1000, 100);
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "receiver from group 1 should be able to spend in group 2"
        );

        // B's balance: 700_000 - 100_000 - 1000 = 599_000
        assert_eq!(eval.effective_balance(&sender_b), 599_000);
    }

    // ====================================================================
    // 7. COW rollback test (rejected group doesn't corrupt overlay)
    // ====================================================================

    #[test]
    fn rejected_group_does_not_corrupt_overlay() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(80);
        let (receiver, _) = test_keypair(81);
        // Give sender enough for one group but the second would drop below min balance
        // after the first. The second group should fail min-balance check and
        // the overlay should be rolled back.
        //
        // Balance: 200_000. min_balance = 100_000.
        // Group 1: fee=1000, amount=0 -> sender=199_000 (ok, above min_balance)
        // Group 2 (will fail): fee=1000, amount=99_000 -> sender=99_000 (below min_balance!)
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 200_000)]);

        // Group 1 succeeds
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 199_000);

        // Group 2 should fail (would put sender at 99_000 < 100_000)
        // Use a different note to avoid duplicate txid
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 99_000,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "expected min-balance error, got: {err}"
        );

        // After rollback, sender balance should still be 199_000 (from group 1)
        assert_eq!(
            eval.effective_balance(&sender),
            199_000,
            "overlay should be rolled back after rejected group"
        );

        // And we should be able to do a valid group 3
        let stx3_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x02]),
            ..Default::default()
        };
        let sig3 = sign_txn(&stx3_txn, &key);
        let stx3 = SignedTransaction {
            txn: stx3_txn,
            sig: sig3,
            ..Default::default()
        };
        assert!(eval.transaction_group(&[stx3]).is_ok());
        assert_eq!(eval.effective_balance(&sender), 198_000);
    }

    // ====================================================================
    // 8. Exact byte counting / block size limit tests
    // ====================================================================

    #[test]
    fn block_byte_limit_enforced() {
        let ledger = test_ledger();
        let mut params = v41_params();
        // Set a very small block byte limit to force rejection
        params.max_txn_bytes_per_block = 50;
        let (sender, key) = test_keypair(90);
        let (receiver, _) = test_keypair(91);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // A normal pay txn will be >50 bytes in STIB encoding
        let stx = make_signed_pay(&key, &sender, &receiver, 100, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("block byte limit") || err.to_string().contains("exceed"),
            "expected block byte limit error, got: {err}"
        );
    }

    #[test]
    fn second_group_exceeds_byte_limit() {
        let ledger = test_ledger();
        let mut params = v41_params();
        let (sender, key) = test_keypair(92);
        let (receiver, _) = test_keypair(93);

        // First, figure out how big a single STIB is (amount=0 avoids receiver min-balance)
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        let stib_size = algo_codec::canonical_encode_signed_txn_in_block(&stx).len();

        // Set limit so first txn fits but second doesn't
        params.max_txn_bytes_per_block = (stib_size + 10) as u64;
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // First group fits
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(eval.transaction_group(&[stx1]).is_ok());

        // Second group should exceed
        let stx2_txn = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&stx2_txn, &key);
        let stx2 = SignedTransaction {
            txn: stx2_txn,
            sig: sig2,
            ..Default::default()
        };
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("exceed") || err.to_string().contains("block byte limit"),
            "expected byte limit error, got: {err}"
        );
    }

    // ====================================================================
    // 9. Merkle commitment tests
    // ====================================================================

    #[test]
    fn generate_block_with_payset_computes_txn_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(100);
        let (receiver, _) = test_keypair(101);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // Payset should be non-empty
        assert_eq!(block.payset.len(), 1);

        // txn_commitment should be non-zero (Merkle root of non-empty payset)
        assert_ne!(
            block.txn_commitment, [0u8; 32],
            "txn_commitment should be non-zero for non-empty payset"
        );

        // Verify it matches the independently computed Merkle root
        let expected = algo_validate::merkle::compute_payset_merkle_root(&block);
        assert_eq!(block.txn_commitment, expected);
    }

    #[test]
    fn generate_block_empty_payset_has_zero_commitment() {
        let ledger = test_ledger();
        let params = v41_params();
        let eval = make_evaluator(&ledger, &params, 100, &[]);

        // Cast to mutable for generate_block
        let mut eval = eval;
        let block = eval.generate_block(&[]).unwrap();

        assert!(block.payset.is_empty());
        assert_eq!(
            block.txn_commitment, [0u8; 32],
            "empty payset should have zero txn_commitment"
        );
    }

    #[test]
    fn generate_block_v41_computes_vector_commitments() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(102);
        let (receiver, _) = test_keypair(103);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        // V41 has both txn256 (v34+) and txn512 (v41+)
        assert!(
            algo_validate::rules::has_txn256(CONSENSUS_V41),
            "V41 should support txn256"
        );
        assert!(
            algo_validate::rules::has_txn512(CONSENSUS_V41),
            "V41 should support txn512"
        );

        assert_ne!(
            block.txn256, [0u8; 32],
            "txn256 should be non-zero for V41 with non-empty payset"
        );
        assert_ne!(
            block.txn512, [0u8; 64],
            "txn512 should be non-zero for V41 with non-empty payset"
        );

        // Verify they match independently computed values
        let expected_256 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha256,
        );
        assert_eq!(block.txn256.as_slice(), expected_256.as_slice());

        let expected_512 = algo_validate::merkle::compute_vector_commitment(
            &block,
            algo_validate::merkle::HashAlgo::Sha512,
        );
        assert_eq!(block.txn512.as_slice(), expected_512.as_slice());
    }

    #[test]
    fn generate_block_old_protocol_skips_vector_commitments() {
        let ledger = test_ledger();
        // Use v30 params — no vector commitments
        let v30_proto = algo_types::consensus::CONSENSUS_V30;
        let params = consensus_params_for_version(v30_proto).unwrap();
        let (sender, key) = test_keypair(104);
        let (receiver, _) = test_keypair(105);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: v30_proto.to_string(),
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: {
                    let mut m = HashMap::new();
                    m.insert(
                        sender,
                        Some(algo_types::AccountData {
                            micro_algos: 10_000_000,
                            ..Default::default()
                        }),
                    );
                    m
                },
                lease_table: algo_ledger::LeaseTable::new(),
                round: 100,
                snapshot_round: Round(0),
                read_snapshot: None,
            },
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        assert!(!algo_validate::rules::has_txn256(v30_proto));
        assert!(!algo_validate::rules::has_txn512(v30_proto));
        assert_eq!(block.txn256, [0u8; 32], "v30 should not compute txn256");
        assert_eq!(block.txn512, [0u8; 64], "v30 should not compute txn512");
    }

    // ====================================================================
    // 10. Evaluator round and pay_set_size
    // ====================================================================

    #[test]
    fn evaluator_round_and_pay_set_size() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(110);
        let (receiver, _) = test_keypair(111);
        let mut eval = make_evaluator(&ledger, &params, 42, &[(sender, 10_000_000)]);

        assert_eq!(eval.round(), Round(42));
        assert_eq!(eval.pay_set_size(), 0);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 42);
        eval.transaction_group(&[stx]).unwrap();

        assert_eq!(eval.pay_set_size(), 1);
    }

    // ====================================================================
    // 11. STIB genesis field stripping
    // ====================================================================

    #[test]
    fn transaction_group_strips_genesis_fields() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(120);
        let (receiver, _) = test_keypair(121);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        // Pre-check: the txn has genesis fields set
        assert_eq!(stx.txn.genesis_id, "test-v1");
        assert_eq!(stx.txn.genesis_hash, [0xAA; 32]);

        eval.transaction_group(&[stx]).unwrap();

        // After inclusion, the included_txns should have genesis fields stripped
        // (STIB format). Generate the block to access them.
        let block = eval.generate_block(&[]).unwrap();
        let stib = &block.payset[0];
        assert!(
            stib.txn.genesis_id.is_empty(),
            "STIB should have genesis_id stripped"
        );
        assert_eq!(
            stib.txn.genesis_hash, [0u8; 32],
            "STIB should have genesis_hash zeroed"
        );
        assert!(stib.has_genesis_id, "STIB should set has_genesis_id flag");
    }

    // ====================================================================
    // 12. Multi-transaction group test (T1)
    // ====================================================================

    #[test]
    fn multi_txn_group_accepted_and_included() {
        let ledger = test_ledger();
        let params = v41_params();
        let (sender_a, key_a) = test_keypair(130);
        let (sender_b, key_b) = test_keypair(131);
        let (receiver, _) = test_keypair(132);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender_a, 10_000_000),
                (sender_b, 10_000_000),
                (receiver, 100_000),
            ],
        );

        // Build two transactions that will form a group.
        let mut txn_a = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_a,
            receiver,
            amount: 1_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let mut txn_b = Transaction {
            txn_type: TxnType::Pay,
            sender: sender_b,
            receiver,
            amount: 2_000,
            fee: 1_000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };

        // Compute group ID (compute_group_id zeroes the group field internally).
        let group_id = algo_validate::rules::compute_group_id(&[txn_a.clone(), txn_b.clone()]);
        txn_a.group = *group_id.as_bytes();
        txn_b.group = *group_id.as_bytes();

        // Sign both transactions (with group field set).
        let sig_a = sign_txn(&txn_a, &key_a);
        let sig_b = sign_txn(&txn_b, &key_b);
        let stx_a = SignedTransaction {
            txn: txn_a,
            sig: sig_a,
            ..Default::default()
        };
        let stx_b = SignedTransaction {
            txn: txn_b,
            sig: sig_b,
            ..Default::default()
        };

        // Submit as a single group of 2 transactions.
        assert!(
            eval.transaction_group(&[stx_a, stx_b]).is_ok(),
            "multi-txn group should be accepted"
        );

        // Both should appear in the block payset.
        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(
            block.payset.len(),
            2,
            "block should contain both transactions from the group"
        );
    }

    // ====================================================================
    // 13. Header field propagation test (T3)
    // ====================================================================

    #[test]
    fn generate_block_propagates_all_header_fields() {
        let ledger = test_ledger();
        let params = v41_params();

        // Set distinctive values on the header fields that H2 was dropping.
        let fee_sink = Address([0x11; 32]);
        let rewards_pool = Address([0x22; 32]);
        let proposer = Address([0x33; 32]);

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(500),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                rewards_pool,
                proposer,
                rewards_level: 42,
                rewards_rate: 100,
                rewards_residue: 7,
                rewards_recalculation_round: Round(1000),
                bonus: 99,
                proposer_payout: 6789,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot: LedgerSnapshot {
                accounts: HashMap::new(),
                lease_table: algo_ledger::LeaseTable::new(),
                round: 500,
                snapshot_round: Round(0),
                read_snapshot: None,
            },
            overlay: CowOverlay::new(),
            fees_collected: 12345,
        };

        let block = eval.generate_block(&[]).unwrap();

        // Verify all header fields were propagated to the generated block.
        assert_eq!(block.fee_sink, fee_sink, "fee_sink should be propagated");
        assert_eq!(
            block.rewards_pool, rewards_pool,
            "rewards_pool should be propagated"
        );
        assert_eq!(block.proposer, proposer, "proposer should be propagated");
        assert_eq!(
            block.rewards_level, 42,
            "rewards_level should be propagated"
        );
        assert_eq!(block.rewards_rate, 100, "rewards_rate should be propagated");
        assert_eq!(
            block.rewards_residue, 7,
            "rewards_residue should be propagated"
        );
        assert_eq!(
            block.rewards_recalculation_round,
            Round(1000),
            "rewards_recalculation_round should be propagated"
        );
        assert_eq!(block.bonus, 99, "bonus should be propagated");
        assert_eq!(
            block.fees_collected, 12345,
            "fees_collected should be propagated"
        );
        assert_eq!(
            block.proposer_payout, 6789,
            "proposer_payout should be propagated"
        );
    }

    // ====================================================================
    // 14. Effective min-balance tests
    // ====================================================================

    #[test]
    fn effective_min_balance_base_account() {
        let params = v41_params();
        let acct = AccountData::default();
        // Base account with no assets/apps should have just the base min_balance.
        assert_eq!(effective_min_balance(&acct, &params), params.min_balance);
    }

    #[test]
    fn effective_min_balance_with_assets() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };
        // base + 3 * min_balance for assets
        let expected = params.min_balance + 3 * params.min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn effective_min_balance_with_apps_and_schema() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 10_000_000,
            total_created_apps: 2,
            total_apps_opted_in: 1,
            total_extra_app_pages: 3,
            total_app_schema: algo_types::StateSchema {
                num_uint: 4,
                num_byte_slice: 2,
            },
            ..Default::default()
        };
        // base
        let mut expected = params.min_balance;
        // created apps: 2 * app_flat_params_min_balance
        expected += 2 * params.app_flat_params_min_balance;
        // opted-in apps: 1 * app_flat_opt_in_min_balance
        expected += params.app_flat_opt_in_min_balance;
        // schema entries: (4+2) * schema_min_balance_per_entry
        expected += 6 * params.schema_min_balance_per_entry;
        // schema uints: 4 * schema_uint_min_balance
        expected += 4 * params.schema_uint_min_balance;
        // schema bytes: 2 * schema_bytes_min_balance
        expected += 2 * params.schema_bytes_min_balance;
        // extra pages: 3 * app_flat_params_min_balance
        expected += 3 * params.app_flat_params_min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn effective_min_balance_with_boxes() {
        let params = v41_params();
        let acct = AccountData {
            micro_algos: 10_000_000,
            total_boxes: 5,
            total_box_bytes: 1000,
            ..Default::default()
        };
        let expected = params.min_balance
            + 5 * params.box_flat_min_balance
            + 1000 * params.box_byte_min_balance;
        assert_eq!(effective_min_balance(&acct, &params), expected);
    }

    #[test]
    fn min_balance_check_uses_effective_min_balance() {
        // An account with 3 asset opt-ins has an effective min balance of
        // 100_000 + 3 * 100_000 = 400_000. A transaction that would leave
        // the account with 300_000 should be rejected even though 300_000
        // exceeds the base min_balance of 100_000.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(140);
        let (receiver, _) = test_keypair(141);

        let sender_acct = AccountData {
            micro_algos: 500_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };

        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // fee=1000, amount=199_000 -> sender after = 500_000 - 200_000 = 300_000
        // effective min balance = 100_000 + 3*100_000 = 400_000
        // 300_000 < 400_000 -> should be rejected
        let stx = make_signed_pay(&key, &sender, &receiver, 199_000, 1000, 100);
        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "expected min-balance error for account with assets, got: {err}"
        );
    }

    #[test]
    fn account_with_assets_above_effective_min_accepted() {
        // Same as above but leaving enough balance above effective min.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(142);
        let (receiver, _) = test_keypair(143);

        let sender_acct = AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 3,
            ..Default::default()
        };

        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // fee=1000, amount=0 -> sender after = 999_000
        // effective min balance = 100_000 + 3*100_000 = 400_000
        // 999_000 >= 400_000 -> should be accepted
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "account with assets above effective min balance should be accepted"
        );
    }

    // ====================================================================
    // 15. FeeSink balance tracking tests
    // ====================================================================

    #[test]
    fn fee_sink_credited_after_transaction() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(150);
        let (receiver, _) = test_keypair(151);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        // FeeSink starts with 1_000_000
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Submit a transaction with fee=2000
        let stx = make_signed_pay(&key, &sender, &receiver, 0, 2000, 100);
        eval.transaction_group(&[stx]).unwrap();

        // FeeSink should have been credited: 1_000_000 + 2000 = 1_002_000
        assert_eq!(
            eval.effective_balance(&fee_sink),
            1_002_000,
            "FeeSink should be credited with the transaction fee"
        );
        assert_eq!(
            eval.fees_collected, 2000,
            "fees_collected should track the running total"
        );
    }

    #[test]
    fn fee_sink_accumulates_across_groups() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(152);
        let (receiver, _) = test_keypair(153);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Group 1: fee=1000
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();

        // Group 2: fee=3000 (different note to get different txid)
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 3000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        eval.transaction_group(&[stx2]).unwrap();

        // FeeSink should have accumulated: 0 + 1000 + 3000 = 4000
        assert_eq!(
            eval.effective_balance(&fee_sink),
            4000,
            "FeeSink should accumulate fees across groups"
        );
        assert_eq!(
            eval.fees_collected, 4000,
            "fees_collected should accumulate across groups"
        );
    }

    #[test]
    fn fees_collected_in_generated_block() {
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(154);
        let (receiver, _) = test_keypair(155);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        let stx = make_signed_pay(&key, &sender, &receiver, 0, 5000, 100);
        eval.transaction_group(&[stx]).unwrap();

        let block = eval.generate_block(&[]).unwrap();
        assert_eq!(
            block.fees_collected, 5000,
            "generated block should contain accumulated fees_collected"
        );
    }

    #[test]
    fn fee_sink_rollback_on_min_balance_violation() {
        // When a group is rejected due to min-balance violation,
        // the fees_collected should be rolled back too.
        let ledger = test_ledger();
        let params = v41_params();
        let fee_sink = Address([0xFE; 32]);
        let (sender, key) = test_keypair(156);
        let (receiver, _) = test_keypair(157);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        // Sender has 200_000, min_balance = 100_000
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 200_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            fee_sink,
            Some(AccountData {
                micro_algos: 0,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // First: a valid group with fee=1000
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();
        assert_eq!(eval.fees_collected, 1000);

        // Second: a group that will fail min-balance (would leave 99_000 < 100_000)
        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 99_000,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        assert!(eval.transaction_group(&[stx2]).is_err());

        // fees_collected should be rolled back to 1000 (from the first group only)
        assert_eq!(
            eval.fees_collected, 1000,
            "fees_collected should be rolled back on rejection"
        );
        // FeeSink balance should also be rolled back
        assert_eq!(
            eval.effective_balance(&fee_sink),
            1000,
            "FeeSink balance should be rolled back on rejection"
        );
    }

    // ====================================================================
    // F6. sender == close_remainder_to test
    // ====================================================================

    #[test]
    fn close_remainder_to_self_is_rejected() {
        // `PaymentTxnFields.wellFormed` (go-algorand
        // data/transactions/payment.go) rejects a payment whose
        // close_remainder_to equals its own sender ("transaction cannot
        // close account to its sender"); algod-rust enforces the same rule
        // in `validate_transaction_wellformed` (crates/core/algo-validate/
        // src/rules.rs, added in #837 — see also that crate's
        // `test_payment_close_to_self_rejected`). Such a transaction can
        // therefore never reach the balance-apply layer this test targets.
        //
        // This replaces the former `close_remainder_to_self_zeros_sender`
        // test, which predates #837 and expected the (now provably
        // unreachable) self-close to succeed and zero the sender's
        // balance. The apply-layer close-to-a-third-party path is already
        // covered by `close_remainder_zeros_sender_and_credits_close_addr`.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(200);
        let (receiver, _) = test_keypair(201);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (receiver, 100_000)],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 100_000, 1000, 100);
        stx.txn.close_remainder_to = sender; // close to self: rejected
        stx.sig = sign_txn(&stx.txn, &key);

        let err = eval
            .transaction_group(&[stx])
            .expect_err("close_remainder_to == sender must be rejected");
        assert!(
            err.to_string()
                .contains("cannot close account to its sender"),
            "unexpected error: {err}"
        );
    }

    // ====================================================================
    // F7. sender == fee_sink: fees_collected NOT incremented
    // ====================================================================

    #[test]
    fn sender_is_fee_sink_no_fees_collected_increment() {
        let ledger = test_ledger();
        let params = v41_params();
        // Use a deterministic address as FeeSink. We need the sender to
        // BE the fee_sink address.
        let (fee_sink_addr, fee_sink_key) = test_keypair(210);
        let (receiver, _) = test_keypair(211);

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            fee_sink_addr,
            Some(algo_types::AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );
        snapshot.accounts.insert(
            receiver,
            Some(algo_types::AccountData {
                micro_algos: 100_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                fee_sink: fee_sink_addr, // FeeSink IS the sender
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Send a transaction FROM the FeeSink address
        let stx = make_signed_pay(&fee_sink_key, &fee_sink_addr, &receiver, 1000, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "transaction from FeeSink should succeed"
        );

        // fees_collected should NOT be incremented when sender == FeeSink
        assert_eq!(
            eval.fees_collected, 0,
            "fees_collected should not be incremented when sender is the FeeSink"
        );

        // The fee_sink balance should reflect only the amount debit (1000),
        // NOT the fee debit, because the fee is a self-transfer (no-op).
        // Original: 10_000_000, amount sent: 1000 => expected: 9_999_000
        assert_eq!(
            eval.effective_balance(&fee_sink_addr),
            10_000_000 - 1000, // amount only, fee is self-transfer
            "fee_sink balance should only be debited by the payment amount, not the fee"
        );
    }

    // ====================================================================
    // 16. Rekey / auth-addr validation tests
    // ====================================================================

    /// Helper: build a signed payment txn with a custom auth_addr field.
    /// The transaction is signed by `signer_key` and the `auth_addr` on
    /// the SignedTransaction is set to `auth_addr_opt`.
    fn make_signed_pay_with_auth(
        signer_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
        auth_addr_opt: Option<Address>,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, signer_key);
        SignedTransaction {
            txn,
            sig,
            auth_addr: auth_addr_opt,
            ..Default::default()
        }
    }

    /// Helper: build a signed payment txn with rekey_to set.
    #[allow(clippy::too_many_arguments)]
    fn make_signed_pay_with_rekey(
        signer_key: &SigningKey,
        sender: &Address,
        receiver: &Address,
        amount: u64,
        fee: u64,
        round: u64,
        auth_addr_opt: Option<Address>,
        rekey_to: Address,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type: TxnType::Pay,
            sender: *sender,
            receiver: *receiver,
            amount,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            rekey_to: Some(rekey_to),
            ..Default::default()
        };
        let sig = sign_txn(&txn, signer_key);
        SignedTransaction {
            txn,
            sig,
            auth_addr: auth_addr_opt,
            ..Default::default()
        }
    }

    #[test]
    fn rekey_correct_auth_addr_passes() {
        // Account has been rekeyed in the ledger. Transaction with the
        // correct auth_addr should pass validation.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _sender_key) = test_keypair(160);
        let (receiver, _) = test_keypair(161);
        let (auth, auth_key) = test_keypair(162);

        // Set up the sender's account with auth_addr pointing to the
        // auth key (simulating a prior rekey).
        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Transaction is signed by auth_key, auth_addr=Some(auth).
        let stx =
            make_signed_pay_with_auth(&auth_key, &sender, &receiver, 0, 1000, 100, Some(auth));

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "rekeyed account with correct auth_addr should be accepted"
        );
    }

    #[test]
    fn rekey_wrong_auth_addr_rejected() {
        // Account has been rekeyed in the ledger. Transaction with the
        // wrong auth_addr (signed by original sender key) should fail.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(163);
        let (receiver, _) = test_keypair(164);
        let (auth, _auth_key) = test_keypair(165);

        // Sender has auth_addr = auth (rekeyed).
        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Transaction is signed by sender_key (wrong!) with no auth_addr.
        // The authorizer is sender, but the ledger expects auth.
        let stx = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn rekey_missing_auth_addr_rejected() {
        // Account has been rekeyed but the transaction doesn't set
        // auth_addr at all (authorizer = sender, expected = auth).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(166);
        let (receiver, _) = test_keypair(167);
        let (auth, _) = test_keypair(168);

        let sender_acct = AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // No auth_addr on the transaction — authorizer defaults to sender.
        let stx = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn non_rekeyed_account_with_auth_addr_rejected() {
        // Account has NOT been rekeyed (auth_addr is None/zero in ledger).
        // Transaction sets auth_addr to some other address — this should fail
        // because the expected authorizer is the sender itself.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _sender_key) = test_keypair(169);
        let (receiver, _) = test_keypair(170);
        let (other, other_key) = test_keypair(171);

        // Sender has no auth_addr — not rekeyed.
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Transaction claims auth_addr = other (wrong!).
        let stx =
            make_signed_pay_with_auth(&other_key, &sender, &receiver, 0, 1000, 100, Some(other));

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "expected auth-addr mismatch error, got: {err}"
        );
    }

    #[test]
    fn rekey_to_within_block_affects_subsequent_txn() {
        // Transaction 1: sender rekeys to auth via rekey_to.
        // Transaction 2: sender must now use auth as authorizer.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(172);
        let (receiver, _) = test_keypair(173);
        let (auth, auth_key) = test_keypair(174);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: sender sends a payment and rekeys to auth.
        // Signed by sender_key (no auth_addr set), rekey_to = auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey transaction should succeed"
        );

        // Txn 2: sender sends another payment, now signed by auth_key
        // with auth_addr = auth. This should succeed because the overlay
        // tracks the rekey from txn 1.
        let stx2 =
            make_signed_pay_with_auth(&auth_key, &sender, &receiver, 0, 1000, 100, Some(auth));
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "post-rekey transaction with correct auth should succeed"
        );
    }

    #[test]
    fn rekey_to_within_block_old_key_rejected() {
        // Transaction 1: sender rekeys to auth.
        // Transaction 2: sender tries to use the old key — should fail.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(175);
        let (receiver, _) = test_keypair(176);
        let (auth, _auth_key) = test_keypair(177);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: rekey to auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey transaction should succeed"
        );

        // Txn 2: try to use sender_key (old key, no auth_addr).
        let stx2 = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);
        let err = eval.transaction_group(&[stx2]).unwrap_err();
        assert!(
            err.to_string().contains("should have been authorized by"),
            "old key after rekey should be rejected, got: {err}"
        );
    }

    #[test]
    fn rekey_back_to_self_restores_original_key() {
        // Transaction 1: sender rekeys to auth.
        // Transaction 2: sender (signed by auth) rekeys back to self.
        // Transaction 3: sender uses original key — should succeed.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, sender_key) = test_keypair(178);
        let (receiver, _) = test_keypair(179);
        let (auth, auth_key) = test_keypair(180);

        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 10_000_000)]);

        // Txn 1: rekey sender -> auth.
        let stx1 =
            make_signed_pay_with_rekey(&sender_key, &sender, &receiver, 0, 1000, 100, None, auth);
        assert!(
            eval.transaction_group(&[stx1]).is_ok(),
            "rekey to auth should succeed"
        );

        // Txn 2: rekey sender -> sender (rekey back to self), signed by auth.
        let stx2 = make_signed_pay_with_rekey(
            &auth_key,
            &sender,
            &receiver,
            0,
            1000,
            100,
            Some(auth),
            sender,
        );
        assert!(
            eval.transaction_group(&[stx2]).is_ok(),
            "rekey back to self should succeed"
        );

        // Txn 3: sender uses original key (no auth_addr).
        let stx3 = make_signed_pay_with_auth(&sender_key, &sender, &receiver, 0, 1000, 100, None);
        assert!(
            eval.transaction_group(&[stx3]).is_ok(),
            "after rekeying back to self, original key should work"
        );
    }

    // ====================================================================
    // Reward-adjusted balance tests
    // ====================================================================

    /// Helper: build an evaluator with a non-zero rewards_level in the block
    /// header, allowing tests to exercise reward-adjusted balance logic.
    fn make_evaluator_with_rewards(
        ledger: &Arc<Mutex<SqliteLedger>>,
        params: &ConsensusParams,
        round: u64,
        rewards_level: u64,
        full_accounts: &[(Address, AccountData)],
    ) -> SimpleBlockEvaluator {
        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        for (addr, acct) in full_accounts {
            snapshot.accounts.insert(*addr, Some(acct.clone()));
        }
        SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(round),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                rewards_level,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        }
    }

    #[test]
    fn reward_adjusted_effective_balance() {
        // An account with 2_000_000 microAlgos (2 reward units) and
        // rewards_base=10, with block rewards_level=20, should have
        // pending rewards = (20-10) * (2_000_000 / 1_000_000) = 20.
        // Effective balance = 2_000_000 + 20 = 2_000_020.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 2_000_000,
            rewards_base: 10,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 20, &[(sender, acct)]);

        assert_eq!(eval.effective_balance(&sender), 2_000_020);
    }

    #[test]
    fn reward_adjusted_balance_allows_transfer_above_raw() {
        // Sender has 1_000_000 raw microAlgos + pending rewards of 500_000.
        // This means the sender can afford a transfer of up to ~1_500_000.
        // Without reward adjustment, a 1_200_000 (amount + fee) transfer
        // would be rejected because raw balance is only 1_000_000.
        //
        // Setup: 1_000_000 microAlgos, rewards_base=0, rewards_level=500_000.
        // reward_units = 1_000_000 / 1_000_000 = 1
        // pending = (500_000 - 0) * 1 = 500_000
        // effective = 1_000_000 + 500_000 = 1_500_000
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(1);
        let (receiver, _) = test_keypair(2);
        let fee_sink = Address([0xFE; 32]);
        let acct = AccountData {
            micro_algos: 1_000_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        // Also seed the fee_sink so it exists.
        let fee_sink_acct = AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(
            &ledger,
            &params,
            100,
            500_000,
            &[(sender, acct), (fee_sink, fee_sink_acct)],
        );
        eval.hdr.fee_sink = fee_sink;

        // Send 1_199_000 + 1_000 fee = 1_200_000 total cost.
        // Raw balance = 1_000_000 would fail, but reward-adjusted = 1_500_000 passes.
        let stx = make_signed_pay(&key, &sender, &receiver, 1_199_000, 1_000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "transfer should succeed with reward-adjusted balance"
        );
    }

    #[test]
    fn not_participating_gets_no_reward_adjustment() {
        // NotParticipating accounts do not receive rewards, so the
        // effective balance should equal the raw micro_algos.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 5_000_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::NotParticipating,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 100, &[(sender, acct)]);

        // Without reward adjustment, would be 5_000_000.
        // With reward adjustment for Online, would be 5_000_000 + (100 * 5) = 5_000_500.
        // But NotParticipating → no rewards → 5_000_000.
        assert_eq!(eval.effective_balance(&sender), 5_000_000);
    }

    #[test]
    fn reward_adjusted_balance_raw_below_threshold_but_adjusted_above() {
        // Sender's raw balance is below the amount needed, but after
        // reward adjustment the effective balance is sufficient.
        // raw = 900_000, reward units = 0 (below 1 Algo), so no adjustment.
        // This verifies sub-unit balances correctly get no reward boost.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 900_000,
            rewards_base: 0,
            status: algo_types::AccountStatus::Online,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 1_000, &[(sender, acct)]);

        // reward_units = 900_000 / 1_000_000 = 0 (integer division)
        // pending = 1000 * 0 = 0
        // effective = 900_000
        assert_eq!(eval.effective_balance(&sender), 900_000);
    }

    #[test]
    fn reward_adjusted_balance_offline_still_gets_rewards() {
        // Offline accounts (not NotParticipating) still receive rewards,
        // matching Go's behavior where only NotParticipating is excluded.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, _key) = test_keypair(1);
        let acct = AccountData {
            micro_algos: 3_000_000,
            rewards_base: 5,
            status: algo_types::AccountStatus::Offline,
            ..Default::default()
        };
        let mut eval = make_evaluator_with_rewards(&ledger, &params, 100, 15, &[(sender, acct)]);

        // reward_units = 3_000_000 / 1_000_000 = 3
        // pending = (15 - 5) * 3 = 30
        // effective = 3_000_000 + 30 = 3_000_030
        assert_eq!(eval.effective_balance(&sender), 3_000_030);
    }

    // ====================================================================
    // 16. Non-payment transaction type balance handling tests
    // ====================================================================

    /// Helper: build a signed non-payment transaction (only fee deducted).
    fn make_signed_txn(
        sender_key: &SigningKey,
        sender: &Address,
        txn_type: TxnType,
        fee: u64,
        round: u64,
    ) -> SignedTransaction {
        let txn = Transaction {
            txn_type,
            sender: *sender,
            fee,
            first_valid: Round(round),
            last_valid: Round(round + 1000),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        let sig = sign_txn(&txn, sender_key);
        SignedTransaction {
            txn,
            sig,
            ..Default::default()
        }
    }

    #[test]
    fn keyreg_only_deducts_fee() {
        // Key registration transactions should only deduct the fee from the
        // sender's Algo balance — no amount or close-remainder-to handling.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(110);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg transaction should be accepted"
        );
        // Only fee deducted: 1_000_000 - 1000 = 999_000
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn acfg_only_deducts_fee() {
        // Asset config transactions should only deduct the fee.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(111);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Acfg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "acfg transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn afrz_only_deducts_fee() {
        // Asset freeze transactions should only deduct the fee.
        //
        // `AssetFreezeTxnFields.wellFormed` (go-algorand
        // data/transactions/asset.go) requires FreezeAsset != 0 and
        // FreezeAccount non-empty; algod-rust enforces the same in
        // `validate_transaction_wellformed` (crates/core/algo-validate/src/
        // rules.rs, added in #837). A bare-default afrz txn (freeze_asset=0,
        // freeze_account=None) is therefore correctly rejected, so this
        // fixture must set both fields to reach the balance-apply logic
        // under test.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(112);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let mut stx = make_signed_txn(&key, &sender, TxnType::Afrz, 1000, 100);
        stx.txn.freeze_asset = 1;
        stx.txn.freeze_account = Some(sender);
        stx.sig = sign_txn(&stx.txn, &key);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "afrz transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn appl_only_deducts_fee() {
        // Application call transactions should only deduct the fee from Algo
        // balance (inner transactions are handled separately).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(113);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        // ApplicationID == 0 means this is a creation call, which (per
        // issue #701's `wellFormed` program-presence/version check) now
        // requires non-empty Approval/ClearState programs.
        let mut txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            ..Default::default()
        };
        txn.approval_program = Some(serde_bytes::ByteBuf::from(vec![6]));
        txn.clear_state_program = Some(serde_bytes::ByteBuf::from(vec![6]));
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl transaction should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn axfer_does_not_deduct_algo_amount() {
        // Asset transfer transactions move asset units (not Algos).
        // The `amount` field on Transaction is the payment-specific `amt`
        // field. For axfer, the asset amount is in `asset_amount` (`aamt`).
        // Only the fee should be deducted from the sender's Algo balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(114);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Axfer, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer transaction should be accepted"
        );
        // Only fee deducted, asset_amount does not affect Algo balance.
        assert_eq!(eval.effective_balance(&sender), 999_000);
    }

    #[test]
    fn axfer_with_receiver_does_not_credit_algo_balance() {
        // Even when an axfer has receiver and amount fields set (which they
        // could be due to the flat Transaction struct), the Algo balance of
        // the receiver should NOT be credited. Only payment transactions
        // move Algos via the receiver/amount fields.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(115);
        let (receiver, _) = test_keypair(116);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (receiver, 500_000)],
        );

        // Build an axfer that happens to have payment fields set (should be
        // ignored for balance purposes).
        let txn = Transaction {
            txn_type: TxnType::Axfer,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            // These are payment fields — should be ignored for axfer:
            receiver,
            amount: 100_000,
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer should be accepted even with payment fields set"
        );
        // Sender: only fee deducted (amount is payment-specific, ignored for axfer)
        assert_eq!(eval.effective_balance(&sender), 999_000);
        // Receiver: unchanged (amount is not credited for non-payment txns)
        assert_eq!(eval.effective_balance(&receiver), 500_000);
    }

    #[test]
    fn non_payment_close_remainder_to_ignored() {
        // The close_remainder_to field is a payment-specific field. If a
        // non-payment transaction somehow has it set, it should NOT cause
        // the sender's balance to be closed out.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(117);
        let (close_addr, _) = test_keypair(118);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[(sender, 1_000_000), (close_addr, 500_000)],
        );

        // Build a keyreg with close_remainder_to set (should be ignored).
        let txn = Transaction {
            txn_type: TxnType::Keyreg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            close_remainder_to: close_addr,
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg with close_remainder_to should be accepted (field ignored)"
        );
        // Sender: only fee deducted, NOT closed out
        assert_eq!(eval.effective_balance(&sender), 999_000);
        // Close address: unchanged
        assert_eq!(eval.effective_balance(&close_addr), 500_000);
    }

    #[test]
    fn non_payment_precheck_only_requires_fee() {
        // The balance precheck should only require fee (not fee+amount) for
        // non-payment transactions. A sender with just enough for the fee
        // plus min-balance should pass.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(119);
        // Sender has min_balance (100_000) + fee (1000) = 101_000.
        // For a payment with amount=50_000, this would fail the precheck.
        // For a keyreg (fee-only), this should succeed.
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 101_000)]);

        let stx = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "keyreg with exact fee + min_balance should be accepted"
        );
        assert_eq!(eval.effective_balance(&sender), 100_000);
    }

    #[test]
    fn multiple_non_payment_txn_types_in_sequence() {
        // Multiple non-payment transactions from the same sender should
        // each only deduct their fee, not any amount field.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(120);
        let mut eval = make_evaluator(&ledger, &params, 100, &[(sender, 1_000_000)]);

        // Three different non-payment transaction types in sequence.
        // All use round=100 (the block round) but different fees/types
        // to produce unique txids.
        let stx1 = make_signed_txn(&key, &sender, TxnType::Keyreg, 1000, 100);
        let stx2 = make_signed_txn(&key, &sender, TxnType::Acfg, 2000, 100);
        // afrz well-formedness requires freeze_asset != 0 and a non-empty
        // freeze_account (go-algorand AssetFreezeTxnFields.wellFormed,
        // enforced since #837) — see afrz_only_deducts_fee above.
        let mut stx3 = make_signed_txn(&key, &sender, TxnType::Afrz, 1500, 100);
        stx3.txn.freeze_asset = 1;
        stx3.txn.freeze_account = Some(sender);
        stx3.sig = sign_txn(&stx3.txn, &key);

        eval.transaction_group(&[stx1])
            .expect("stx1 keyreg should succeed");
        eval.transaction_group(&[stx2])
            .expect("stx2 acfg should succeed");
        eval.transaction_group(&[stx3])
            .expect("stx3 afrz should succeed");

        // Total fees: 1000 + 2000 + 1500 = 4500
        assert_eq!(eval.effective_balance(&sender), 1_000_000 - 4500);
    }

    #[test]
    fn payment_still_deducts_amount_and_handles_close() {
        // Regression test: ensure payment transactions still correctly
        // deduct amount, credit receiver, and handle close_remainder_to
        // after the transaction-type gating was added.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(121);
        let (receiver, _) = test_keypair(122);
        let (close_addr, _) = test_keypair(123);
        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, 2_000_000),
                (receiver, 100_000),
                (close_addr, 300_000),
            ],
        );

        let mut stx = make_signed_pay(&key, &sender, &receiver, 500_000, 1000, 100);
        stx.txn.close_remainder_to = close_addr;
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "payment with close_remainder_to should be accepted"
        );
        // Sender: closed to 0
        assert_eq!(eval.effective_balance(&sender), 0);
        // Receiver: 100_000 + 500_000 = 600_000
        assert_eq!(eval.effective_balance(&receiver), 600_000);
        // Close addr: 300_000 + remainder (2_000_000 - 1000 - 500_000 = 1_499_000)
        assert_eq!(eval.effective_balance(&close_addr), 300_000 + 1_499_000);
    }

    // ====================================================================
    // Resource count delta tracking tests
    // ====================================================================

    #[test]
    fn acfg_create_raises_sender_min_balance() {
        // Creating an asset (acfg with config_asset=0) should raise the
        // sender's effective min-balance by 2 * min_balance: one for the
        // created asset (total_created_assets) counted via
        // total_assets_opted_in, plus a second for the auto-holding.
        // Go reference: asset.go:87-88 sets TotalAssets += 1 and
        // TotalAssetParams += 1. Our effective_min_balance uses
        // total_assets_opted_in (asset holdings) which maps to TotalAssets.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(200);

        // Sender has exactly enough for fee + base min_balance. After the
        // acfg create, the overlay should reflect +1 total_created_assets
        // and +1 total_assets_opted_in, raising effective min to:
        //   base (100_000) + 1*min_balance (assets) = 200_000
        // But we also need the created-asset cost. Total effective min:
        //   100_000 + 1*100_000 (opted-in asset) + 0 (created assets not
        //   counted separately by effective_min_balance) ... wait, let me
        //   check: effective_min_balance counts total_assets_opted_in and
        //   total_created_apps, not total_created_assets directly.
        //
        // Actually, checking the Go code: `MinBalance` uses `TotalAssets`
        // (which includes both holdings and created) for asset cost.
        // Our effective_min_balance uses `total_assets_opted_in` for asset
        // cost. On asset create, Go increments TotalAssets by 1 (for the
        // auto-holding). We do the same with delta_total_assets_opted_in.
        //
        // So effective min after create: base + 1*min_balance = 200_000.
        // Give sender 201_000 (fee=1000, so after fee = 200_000 = min_bal).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        // Build acfg create transaction (config_asset=0 means create).
        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        // After create: balance = 200_000, effective min = 200_000.
        // This should just barely pass.
        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "acfg create with exact min balance should be accepted"
        );

        // Verify resource deltas were applied.
        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 1,
            "total_assets_opted_in should be 1 after asset create"
        );
        assert_eq!(
            acct_data.total_created_assets, 1,
            "total_created_assets should be 1 after asset create"
        );
    }

    #[test]
    fn acfg_create_rejected_when_min_balance_too_low() {
        // Creating an asset raises min-balance. If the sender doesn't have
        // enough balance to cover the new min-balance, the txn is rejected.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(201);

        // Sender has 150_000. After fee (1000): 149_000.
        // After acfg create: effective min = 100_000 + 1*100_000 = 200_000.
        // 149_000 < 200_000 -> should be rejected.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "acfg create should be rejected when balance < new min: {err}"
        );
    }

    #[test]
    fn appl_optin_raises_sender_min_balance() {
        // Opting into an app (on_completion=1 with existing app_id) should
        // raise the sender's effective min-balance by app_flat_opt_in_min_balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(202);

        // After opt-in: effective min = base + 1*app_flat_opt_in_min_balance
        // = 100_000 + 100_000 = 200_000.
        // Give sender 201_000 (fee=1000, after fee=200_000).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 42, // existing app
            on_completion: 1,   // OptIn
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl opt-in with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_apps_opted_in, 1,
            "total_apps_opted_in should be 1 after app opt-in"
        );
    }

    #[test]
    fn appl_optin_rejected_when_min_balance_too_low() {
        // Opting into an app raises min-balance. If the sender doesn't have
        // enough to cover it, the txn is rejected.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(203);

        // After fee (1000): 149_000. Effective min after opt-in: 200_000.
        // 149_000 < 200_000 -> rejected.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 42,
            on_completion: 1, // OptIn
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        let err = eval.transaction_group(&[stx]).unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "appl opt-in should be rejected when balance < new min: {err}"
        );
    }

    #[test]
    fn resource_deltas_rolled_back_on_min_balance_violation() {
        // When a min-balance check fails, the resource count deltas
        // should be rolled back along with balance changes.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(204);

        // Sender has 150_000. After fee: 149_000.
        // acfg create raises min to 200_000 -> violation -> rollback.
        let sender_acct = AccountData {
            micro_algos: 150_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Acfg,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            config_asset: 0,
            asset_params: Some(algo_types::AssetParams::default()),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(eval.transaction_group(&[stx]).is_err());

        // After rollback, resource deltas should be empty and
        // account data should show no changes.
        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 0,
            "total_assets_opted_in should be 0 after rollback"
        );
        assert_eq!(
            acct_data.total_created_assets, 0,
            "total_created_assets should be 0 after rollback"
        );
        // Balance should also be unchanged (rollback).
        assert_eq!(
            eval.effective_balance(&sender),
            150_000,
            "balance should be restored after rollback"
        );
    }

    #[test]
    fn axfer_optin_raises_sender_min_balance() {
        // Asset opt-in via axfer (sender == asset_receiver, amount == 0)
        // should raise the sender's effective min-balance.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(205);

        // After opt-in: effective min = base + 1*min_balance = 200_000.
        // Give sender 201_000 (fee=1000, after fee=200_000).
        let sender_acct = AccountData {
            micro_algos: 201_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Axfer,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            xaid: 99,                     // existing asset
            asset_amount: 0,              // opt-in amount
            asset_receiver: Some(sender), // self-transfer = opt-in
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "axfer opt-in with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 1,
            "total_assets_opted_in should be 1 after axfer opt-in"
        );
    }

    #[test]
    fn appl_create_raises_sender_min_balance() {
        // Creating an app (application_id=0) should raise the sender's
        // effective min-balance by app_flat_params_min_balance plus
        // schema costs and extra page costs.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(206);

        // App create with global schema: 2 uints, 1 byte-slice, 1 extra page.
        // Effective min after create:
        //   base: 100_000
        //   + 1 * app_flat_params_min_balance (created app): 100_000
        //   + 1 * app_flat_params_min_balance (extra page): 100_000
        //   + 3 * schema_min_balance_per_entry (2 uint + 1 byte): 75_000
        //   + 2 * schema_uint_min_balance: 7_000
        //   + 1 * schema_bytes_min_balance: 25_000
        //   = 407_000
        // Give sender 408_000 (fee=1000, after fee=407_000).
        let sender_acct = AccountData {
            micro_algos: 408_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        let txn = Transaction {
            txn_type: TxnType::Appl,
            sender,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            application_id: 0, // create
            on_completion: 0,  // NoOp
            global_state_schema: Some(algo_types::StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            }),
            extra_program_pages: 1,
            approval_program: Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01])),
            clear_state_program: Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01])),
            ..Default::default()
        };
        let sig = sign_txn(&txn, &key);
        let stx = SignedTransaction {
            txn,
            sig,
            ..Default::default()
        };

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "appl create with exact min balance should be accepted"
        );

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_created_apps, 1,
            "total_created_apps should be 1 after app create"
        );
        assert_eq!(
            acct_data.total_extra_app_pages, 1,
            "total_extra_app_pages should be 1 after app create"
        );
        assert_eq!(
            acct_data.total_app_schema.num_uint, 2,
            "schema num_uint should be 2 after app create"
        );
        assert_eq!(
            acct_data.total_app_schema.num_byte_slice, 1,
            "schema num_byte_slice should be 1 after app create"
        );
    }

    #[test]
    fn multiple_acfg_creates_accumulate_resource_deltas() {
        // Two asset creates in sequence should accumulate resource deltas.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(207);

        // After 2 creates: effective min = base + 2*min_balance = 300_000.
        // Give sender enough for 2 fees + 300_000.
        let sender_acct = AccountData {
            micro_algos: 302_000,
            ..Default::default()
        };
        let mut eval =
            make_evaluator_with_accounts(&ledger, &params, 100, &[], &[(sender, sender_acct)]);

        for i in 0..2u64 {
            let txn = Transaction {
                txn_type: TxnType::Acfg,
                sender,
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(1100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                config_asset: 0,
                asset_params: Some(algo_types::AssetParams::default()),
                // Use note field to make txids unique.
                note: serde_bytes::ByteBuf::from(vec![i as u8]),
                ..Default::default()
            };
            let sig = sign_txn(&txn, &key);
            let stx = SignedTransaction {
                txn,
                sig,
                ..Default::default()
            };
            eval.transaction_group(&[stx])
                .unwrap_or_else(|e| panic!("acfg create {i} should succeed: {e}"));
        }

        let acct_data = eval.get_account_data(&sender).unwrap();
        assert_eq!(
            acct_data.total_assets_opted_in, 2,
            "total_assets_opted_in should be 2 after two asset creates"
        );
        assert_eq!(
            acct_data.total_created_assets, 2,
            "total_created_assets should be 2 after two asset creates"
        );
    }

    // ====================================================================
    // F9. receiver == close_remainder_to: credits accumulate
    // ====================================================================

    #[test]
    fn receiver_equals_close_remainder_to_accumulates_credits() {
        // When receiver and close_remainder_to are the SAME address, the
        // receiver should get both the payment amount AND the remaining
        // close-out balance. The sender should end at 0 (closed).
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(220);
        let (receiver, _) = test_keypair(221);

        let initial_receiver_balance = 100_000u64;
        let sender_balance = 1_000_000u64;
        let amount = 200_000u64;
        let fee = 1_000u64;

        let mut eval = make_evaluator(
            &ledger,
            &params,
            100,
            &[
                (sender, sender_balance),
                (receiver, initial_receiver_balance),
            ],
        );

        // Build payment where receiver == close_remainder_to
        let mut stx = make_signed_pay(&key, &sender, &receiver, amount, fee, 100);
        stx.txn.close_remainder_to = receiver; // same as receiver
        stx.sig = sign_txn(&stx.txn, &key);

        assert!(
            eval.transaction_group(&[stx]).is_ok(),
            "payment with receiver == close_remainder_to should be accepted"
        );

        // Sender should be zero (closed out)
        assert_eq!(
            eval.effective_balance(&sender),
            0,
            "sender should be zero after close"
        );

        // Receiver gets: amount + remainder
        // remainder = sender_balance - fee - amount = 1_000_000 - 1_000 - 200_000 = 799_000
        // total credit to receiver = amount + remainder = 200_000 + 799_000 = 999_000
        let remainder = sender_balance - fee - amount;
        assert_eq!(
            eval.effective_balance(&receiver),
            initial_receiver_balance + amount + remainder,
            "receiver should get both payment amount and close remainder"
        );
    }

    // ====================================================================
    // F10. Empty group rejection
    // ====================================================================

    #[test]
    fn empty_group_rejected() {
        // Calling transaction_group with an empty slice should return an
        // error mentioning the empty group.
        let ledger = test_ledger();
        let params = v41_params();
        let mut eval = make_evaluator(&ledger, &params, 100, &[]);

        let err = eval
            .transaction_group(&[])
            .expect_err("empty group should be rejected");
        assert!(
            err.to_string().contains("empty"),
            "expected error mentioning 'empty', got: {err}"
        );
    }

    // ====================================================================
    // F11. generate_block txn_counter increment
    // ====================================================================

    #[test]
    fn generate_block_txn_counter_incremented() {
        // After processing N transactions, generate_block() should produce
        // a block header whose txn_counter equals the original txn_counter + N.
        let ledger = test_ledger();
        let params = v41_params();
        let (sender, key) = test_keypair(230);
        let (receiver, _) = test_keypair(231);

        let starting_txn_counter = 42_000u64;

        let mut snapshot = LedgerSnapshot {
            accounts: HashMap::new(),
            lease_table: algo_ledger::LeaseTable::new(),
            round: 100,
            snapshot_round: Round(0),
            read_snapshot: None,
        };
        snapshot.accounts.insert(
            sender,
            Some(AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            }),
        );

        let mut eval = SimpleBlockEvaluator {
            hdr: BlockHeader {
                round: Round(100),
                genesis_id: "test-v1".to_string(),
                genesis_hash: [0xAA; 32],
                current_protocol: CONSENSUS_V41.to_string(),
                txn_counter: starting_txn_counter,
                ..Default::default()
            },
            consensus_params: params.clone(),
            included_txns: Vec::new(),
            txn_bytes: 0,
            max_txn_bytes: params.max_txn_bytes_per_block as usize,
            ledger: ledger.clone(),
            snapshot,
            overlay: CowOverlay::new(),
            fees_collected: 0,
        };

        // Submit 3 individual transaction groups (1 txn each)
        let stx1 = make_signed_pay(&key, &sender, &receiver, 0, 1000, 100);
        eval.transaction_group(&[stx1]).unwrap();

        let txn2 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x01]),
            ..Default::default()
        };
        let sig2 = sign_txn(&txn2, &key);
        let stx2 = SignedTransaction {
            txn: txn2,
            sig: sig2,
            ..Default::default()
        };
        eval.transaction_group(&[stx2]).unwrap();

        let txn3 = Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver,
            amount: 0,
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(1100),
            genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            note: ByteBuf::from(vec![0x02]),
            ..Default::default()
        };
        let sig3 = sign_txn(&txn3, &key);
        let stx3 = SignedTransaction {
            txn: txn3,
            sig: sig3,
            ..Default::default()
        };
        eval.transaction_group(&[stx3]).unwrap();

        let block = eval.generate_block(&[]).unwrap();

        assert_eq!(
            block.txn_counter,
            starting_txn_counter + 3,
            "txn_counter should equal starting value + number of transactions"
        );
    }

    /// `open_crash_db` must create `crash.sqlite` next to the ledger and the
    /// resulting connection must round-trip persisted state through close +
    /// reopen — exercising the same restore path the agreement service uses
    /// on restart. Covers TASK-61 / [[DOC-21]] §3.7.
    #[test]
    fn test_open_crash_db_roundtrip() {
        use algo_agreement::persistence::{persist, restore};
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Use a unique tmp dir so parallel test runs don't collide.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-crashdb-test-{}-{}",
            std::process::id(),
            nonce,
        ));
        fs::create_dir_all(&tmp_dir).expect("create tmp dir");
        let crash_db_path = tmp_dir.join("crash.sqlite");

        let payload: Vec<u8> = b"persisted-agreement-state".to_vec();

        // Open the crash db, write a payload, then drop the connection to
        // simulate a node shutdown / crash.
        {
            let conn = super::open_crash_db(&crash_db_path).expect("open crash db");
            persist(&conn, &payload).expect("persist payload");
        }

        // The file must exist next to the ledger using the Go-compatible name.
        assert!(
            crash_db_path.exists(),
            "crash.sqlite was not created at {}",
            crash_db_path.display(),
        );

        // Reopen and restore — must return the exact bytes we wrote.
        let conn = super::open_crash_db(&crash_db_path).expect("reopen crash db");
        let restored = restore(&conn)
            .expect("restore must succeed")
            .expect("restored payload must be present");
        assert_eq!(
            restored, payload,
            "restored bytes do not match persisted bytes",
        );

        // Cleanup. Drop conn first so SQLite releases its file handles.
        drop(conn);
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    // ── resolve_resource_paths (issue #953) ───────────────────────────

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestDefaultResourcePaths` (`node/node_test.go`): with no
    /// `HotDataDir`/`ColdDataDir`/`TrackerDBDir`/`BlockDBDir`/`CrashDBDir`
    /// configured, every resource resolves next to the ledger path —
    /// exactly the pre-#953 behavior, so existing deployments see no
    /// change.
    #[test]
    fn resolve_resource_paths_defaults_to_ledger_directory() {
        let cfg = algo_config::Local::default();
        let ledger_path = Path::new("/data/ledger");
        let resolved = super::resolve_resource_paths(ledger_path, &cfg);
        assert_eq!(
            resolved.tracker_path,
            PathBuf::from("/data/ledger.tracker.sqlite")
        );
        assert_eq!(
            resolved.block_path,
            PathBuf::from("/data/ledger.block.sqlite")
        );
        assert_eq!(resolved.crash_path, PathBuf::from("/data/crash.sqlite"));
    }

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestConfiguredDataDirs`: with `HotDataDir`/`ColdDataDir` set but
    /// `TrackerDBDir`/`BlockDBDir`/`CrashDBDir` left empty, the tracker DB
    /// and crash DB fall back to `HotDataDir` and the block DB falls back
    /// to `ColdDataDir`.
    #[test]
    fn resolve_resource_paths_honors_hot_and_cold_data_dirs() {
        let cfg = algo_config::Local {
            hot_data_dir: "/data/hot".to_string(),
            cold_data_dir: "/data/cold".to_string(),
            ..Default::default()
        };
        let ledger_path = Path::new("/data/ledger");
        let resolved = super::resolve_resource_paths(ledger_path, &cfg);
        assert_eq!(
            resolved.tracker_path,
            PathBuf::from("/data/hot/ledger.tracker.sqlite"),
            "tracker DB must fall back to HotDataDir"
        );
        assert_eq!(
            resolved.block_path,
            PathBuf::from("/data/cold/ledger.block.sqlite"),
            "block DB must fall back to ColdDataDir"
        );
        assert_eq!(
            resolved.crash_path,
            PathBuf::from("/data/hot/crash.sqlite"),
            "crash DB must fall back to HotDataDir"
        );
    }

    /// TDD anchor for issue #953, mirroring go-algorand's
    /// `TestConfiguredResourcePaths`: explicit `TrackerDBDir`/`BlockDBDir`/
    /// `CrashDBDir` take precedence over `HotDataDir`/`ColdDataDir`, even
    /// when both are configured to different directories.
    #[test]
    fn resolve_resource_paths_honors_explicit_per_resource_overrides() {
        let cfg = algo_config::Local {
            hot_data_dir: "/data/hot".to_string(),
            cold_data_dir: "/data/cold".to_string(),
            tracker_db_dir: "/data/custom_tracker".to_string(),
            block_db_dir: "/data/custom_block".to_string(),
            crash_db_dir: "/data/custom_crash".to_string(),
            ..Default::default()
        };
        let ledger_path = Path::new("/data/ledger");
        let resolved = super::resolve_resource_paths(ledger_path, &cfg);
        assert_eq!(
            resolved.tracker_path,
            PathBuf::from("/data/custom_tracker/ledger.tracker.sqlite")
        );
        assert_eq!(
            resolved.block_path,
            PathBuf::from("/data/custom_block/ledger.block.sqlite")
        );
        assert_eq!(
            resolved.crash_path,
            PathBuf::from("/data/custom_crash/crash.sqlite")
        );
    }

    /// Confirms `resolve_resource_paths`'s output actually round-trips
    /// through `SqliteLedger::open_split`: opening the ledger at the
    /// resolved tracker/block paths must create real files at the
    /// configured `TrackerDBDir`/`BlockDBDir`, not the default ledger
    /// directory — closing the gap between the pure path-resolution logic
    /// above and go's `TestConfiguredResourcePaths`, which asserts against
    /// real files on disk.
    #[test]
    fn resolve_resource_paths_wires_into_a_real_open_split() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-resource-paths-test-{}-{}",
            std::process::id(),
            nonce,
        ));
        let tracker_dir = tmp_dir.join("tracker_dir");
        let block_dir = tmp_dir.join("block_dir");
        std::fs::create_dir_all(&tracker_dir).expect("create tracker dir");
        std::fs::create_dir_all(&block_dir).expect("create block dir");

        let cfg = algo_config::Local {
            tracker_db_dir: tracker_dir.to_string_lossy().into_owned(),
            block_db_dir: block_dir.to_string_lossy().into_owned(),
            ..Default::default()
        };

        let ledger_path = tmp_dir.join("ledger");
        let resolved = super::resolve_resource_paths(&ledger_path, &cfg);

        let ledger =
            SqliteLedger::open_split(&resolved.tracker_path, &resolved.block_path, None)
                .expect("open ledger at resolved per-resource paths");
        drop(ledger);

        assert!(
            resolved.tracker_path.exists(),
            "tracker db must exist at the configured TrackerDBDir"
        );
        assert!(
            resolved.block_path.exists(),
            "block db must exist at the configured BlockDBDir"
        );
        // Not at the default (unconfigured) ledger directory.
        assert!(!tmp_dir.join("ledger.tracker.sqlite").exists());
        assert!(!tmp_dir.join("ledger.block.sqlite").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ── ParticipateAgreementControl (issue #940) ─────────────────────

    /// Builds a `ParticipateAgreementControl` wired against a real
    /// in-memory ledger, a real (never-started, so no network I/O)
    /// `WebsocketNetwork`, a real `TransactionPool`, and a fresh temp-file
    /// `ParticipationStore`/crash-db directory — everything
    /// `build_cycle`/`pause`/`resume` touch is real, matching production
    /// wiring, except the network stays offline (no listener bound, no
    /// peers dialed) since these tests only exercise the agreement
    /// `Service`'s own start/stop lifecycle, not wire traffic.
    fn test_agreement_control() -> (ParticipateAgreementControl, PathBuf) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let tmp_dir = std::env::temp_dir().join(format!(
            "algod-rust-agreement-control-test-{}-{}",
            std::process::id(),
            nonce,
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
        let ledger_path = tmp_dir.join("ledger");
        let partkey_path = tmp_dir.join("partkeys.sqlite");

        let ledger = test_ledger();
        let pool = Arc::new(TransactionPool::new(
            PoolConfig::default(),
            Arc::new(PoolLedgerAdapter::new(ledger.clone()))
                as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        let phonebook = Arc::new(Phonebook::new(0, Duration::from_secs(60)));
        let gossip_node = Arc::new(WebsocketNetwork::new(
            WebsocketNetworkConfig::default(),
            phonebook,
        ));
        let part_store = ParticipationStore::open(&partkey_path).expect("open partkey store");
        drop(part_store);

        let control = ParticipateAgreementControl {
            ledger,
            ledger_path: ledger_path.clone(),
            crash_db_path: tmp_dir.join("crash.sqlite"),
            p2p_active_gossip_node: gossip_node.clone() as Arc<dyn GossipNode>,
            gossip_node,
            rt_handle: tokio::runtime::Handle::current(),
            agreement_network_config: algo_network::AgreementNetworkConfig::default(),
            partkey_path,
            resolved_genesis_id: "test-v1".to_string(),
            genesis_hash: [0xAA; 32],
            pool,
            round_advanced: Arc::new(std::sync::Condvar::new()),
            participation_metrics: Arc::new(algo_agreement::ParticipationMetrics::new()),
            enable_agreement_reporting: false,
            enable_agreement_time_metrics: false,
            network_mode: NetworkMode::WsOnly,
            p2p_transport: None,
            catchup_parallel_blocks: 4,
            running: tokio::sync::Mutex::new(None),
        };
        (control, tmp_dir)
    }

    /// TDD anchor for issue #940: `resume()` must actually start a live
    /// agreement `Service` + `CatchupService` pair (not silently do
    /// nothing), and `pause()` must cleanly stop it, leaving the control
    /// idle again — mirroring `LiveCatchupManager::start_catchup`/the
    /// `drive` cleanup path pausing/resuming a `NormalSyncControl`
    /// (`live_catchup.rs`).
    #[tokio::test]
    async fn resume_starts_a_cycle_and_pause_cleanly_stops_it() {
        let (control, tmp_dir) = test_agreement_control();

        assert!(control.running.lock().await.is_none(), "must start idle");

        control.resume().await;
        assert!(
            control.running.lock().await.is_some(),
            "resume() must start a running agreement cycle"
        );

        control.pause().await;
        assert!(
            control.running.lock().await.is_none(),
            "pause() must fully stop the cycle and clear the running state"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// `resume()` must be a no-op when a cycle is already running — mirrors
    /// `NormalSyncControl::resume`'s doc contract ("A no-op if it's already
    /// running") that `LiveCatchupManager` and `node.rs`'s
    /// `FollowLoopControl` both already rely on.
    #[tokio::test]
    async fn resume_is_a_no_op_when_already_running() {
        let (control, tmp_dir) = test_agreement_control();

        control.resume().await;
        assert!(control.running.lock().await.is_some());

        // A second resume() must not replace (or duplicate) the running
        // cycle.
        control.resume().await;
        assert!(control.running.lock().await.is_some());

        control.pause().await;
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// `pause()` must be a no-op (not panic) when nothing is running —
    /// mirrors `NormalSyncControl::pause`'s implicit contract and the
    /// shutdown path in `run()` calling `agreement_control.pause().await`
    /// unconditionally even when a live catchpoint catchup already paused
    /// it.
    #[tokio::test]
    async fn pause_is_a_no_op_when_nothing_is_running() {
        let (control, tmp_dir) = test_agreement_control();
        control.pause().await;
        assert!(control.running.lock().await.is_none());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    /// The full pause -> resume cycle must be safely repeatable multiple
    /// times in a row against the *same* control instance and the *same*
    /// underlying ledger — the exact shape a live catchpoint catchup drives
    /// it through repeatedly across a node's lifetime (`start_catchup`
    /// pauses, the catchup finishes or is aborted, `drive`'s cleanup
    /// resumes; a later `start_catchup` repeats this). Each `build_cycle`
    /// call constructs entirely fresh bridge/service instances (see
    /// `ParticipateAgreementControl`'s doc comment), so this is the
    /// regression guard that repeating that construct/destroy cycle never
    /// panics, hangs, or leaves the control wedged.
    #[tokio::test]
    async fn pause_resume_cycle_repeats_safely_multiple_times() {
        let (control, tmp_dir) = test_agreement_control();

        for _ in 0..3 {
            control.resume().await;
            assert!(control.running.lock().await.is_some());
            control.pause().await;
            assert!(control.running.lock().await.is_none());
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
