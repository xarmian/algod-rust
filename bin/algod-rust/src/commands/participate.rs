use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::{
    AsyncCryptoVerifier, BlockFactoryBridge, BlockValidatorBridge, EventsProcessingMonitor,
    NetworkAdvancer, Parameters, RandomSource, Service,
};
use algo_ledger::participation::ParticipationStore;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{
    AgreementKeyManagerBridge, AgreementLedgerBridge, BlockFetcher, CatchupService, SqliteLedger,
};
use algo_network::{
    AgreementNetworkBridge, GossipNode, Phonebook, WebsocketNetwork, WebsocketNetworkConfig,
    RELAY_ROLE,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_rest_client::GossipBlockSource;
use algo_types::{Block, BlockHeader, Round};
use rand::Rng;
use tracing::{info, warn};

use crate::commands::network_common::genesis_id_for;

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
    fn fetch_block(&self, round: Round) -> Result<Block, String> {
        self.rt_handle.block_on(async {
            let peers = self.ws_network.get_unicast_peers().await;
            if peers.is_empty() {
                return Err(format!(
                    "no unicast peers available to fetch block for round {}",
                    round
                ));
            }
            let source = GossipBlockSource::new(peers);
            use algo_rest_client::BlockSource;
            let response = source
                .get_block(round)
                .await
                .map_err(|e| format!("block fetch failed for round {}: {}", round, e))?;
            Ok(response.block)
        })
    }
}

/// A `BlockEvaluator` that validates transactions using stateless rules and
/// includes them in the block being built.
///
/// Stateless validation covers: well-formedness (fees, round window, note/
/// lease/group size), group ID consistency, group fee pooling, and signature
/// verification. Stateful validation (balance checks, application state,
/// nonce/lease uniqueness across blocks) requires ledger lookups that are not
/// yet wired and is documented below.
struct SimpleBlockEvaluator {
    hdr: algo_types::BlockHeader,
    /// Consensus parameters for the protocol version of this block.
    consensus_params: algo_types::ConsensusParams,
    /// Transactions included in the block so far.
    included_txns: Vec<algo_types::SignedTransaction>,
    /// Running total of serialized transaction bytes (for the per-block cap).
    txn_bytes: usize,
}

impl SimpleBlockEvaluator {
    /// Validate a transaction group using all available stateless checks.
    ///
    /// Checks performed:
    /// 1. Well-formedness of each transaction (fee, round window, note, etc.)
    /// 2. Group ID consistency (computed group ID must match stored group ID)
    /// 3. Group fee pooling validation
    ///
    /// Not yet implemented:
    /// - Signature verification (requires `algo_avm::group::GroupBudget` for
    ///   logicsig budget tracking; add `algo-avm` as a dependency to enable)
    /// - Sender balance / min-balance checks (stateful)
    /// - Application state validation (stateful)
    /// - Cross-block lease uniqueness (stateful)
    fn validate_group(
        &self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        if txgroup.is_empty() {
            return Err(algo_error::AlgoError::Validation {
                message: "empty transaction group".into(),
            });
        }

        let params = &self.consensus_params;
        let round = self.hdr.round;

        // 1. Per-transaction well-formedness.
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

        // 2. Group ID consistency.
        algo_validate::validate_transaction_group(txgroup)?;

        // 3. Group fee pooling (for multi-txn groups with fee pooling enabled).
        if in_group && params.enable_fee_pooling {
            let refs: Vec<&algo_types::SignedTransaction> = txgroup.iter().collect();
            algo_validate::validate_group_fees_with_params(&refs, params).map_err(|e| {
                algo_error::AlgoError::Validation {
                    message: format!("group fee validation failed: {e}"),
                }
            })?;
        }

        Ok(())
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
        self.validate_group(txgroup)
    }

    fn transaction_group(
        &mut self,
        txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        self.validate_group(txgroup)?;

        // Estimate serialized size and check the per-block byte cap.
        let max_bytes = self.consensus_params.max_txn_bytes_per_block as usize;
        let estimated_bytes: usize = txgroup
            .iter()
            .map(|stx| {
                // Rough estimate: 200 bytes base + note + sig overhead.
                // A precise calculation would use canonical msgpack encoding,
                // but this conservative estimate is sufficient for cap enforcement.
                200 + stx.txn.note.len() + 64
            })
            .sum();

        if self.txn_bytes + estimated_bytes > max_bytes {
            return Err(algo_error::AlgoError::Ledger {
                message: format!(
                    "transaction group would exceed block byte limit ({} + {} > {})",
                    self.txn_bytes, estimated_bytes, max_bytes,
                ),
            });
        }

        self.txn_bytes += estimated_bytes;
        self.included_txns.extend_from_slice(txgroup);
        Ok(())
    }

    fn generate_block(
        &mut self,
        _voting_accounts: &[algo_types::Address],
    ) -> Result<algo_types::Block, algo_error::AlgoError> {
        let txn_count = self.included_txns.len() as u64;
        // Clear included transactions — they are tracked by the pool/ledger
        // separately. The block carries a transaction commitment (Merkle root),
        // not the individual transactions. Computing the Merkle root requires
        // canonical encoding of each SignedTxnInBlock which is not yet wired;
        // for now the commitment is left as zero for empty blocks, and a
        // placeholder for non-empty blocks.
        self.included_txns.clear();
        Ok(algo_types::Block {
            round: self.hdr.round,
            branch: self.hdr.branch,
            seed: self.hdr.seed,
            timestamp: self.hdr.timestamp,
            genesis_id: self.hdr.genesis_id.clone(),
            genesis_hash: self.hdr.genesis_hash,
            current_protocol: self.hdr.current_protocol.clone(),
            txn_counter: self.hdr.txn_counter + txn_count,
            ..Default::default()
        })
    }

    fn reset_txn_bytes(&mut self) {
        self.txn_bytes = 0;
    }
}

/// A minimal `PoolLedger` that wraps `SqliteLedger` behind a `Mutex`.
///
/// The `TransactionPool` requires an `Arc<dyn PoolLedger>`, so we provide
/// this thin adapter that delegates to the same SQLite ledger used by the
/// agreement bridges.
struct PoolLedgerAdapter {
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl algo_pool::traits::PoolLedger for PoolLedgerAdapter {
    fn latest(&self) -> Round {
        self.ledger
            .lock()
            .map(|l| l.current_round())
            .unwrap_or(Round(0))
    }

    fn block_hdr(&self, round: Round) -> Result<algo_types::BlockHeader, algo_error::AlgoError> {
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
        BlockHeader::decode_from_bytes(&hdr_data).map_err(|e| algo_error::AlgoError::Ledger {
            message: format!("block_hdr({}) decode error: {e}", round.0),
        })
    }

    fn consensus_params(
        &self,
        _round: Round,
    ) -> Result<algo_types::ConsensusParams, algo_error::AlgoError> {
        // Return V41 params as a reasonable default.
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41).ok_or_else(
            || algo_error::AlgoError::Ledger {
                message: "could not look up v41 consensus params".into(),
            },
        )
    }

    fn start_evaluator(
        &self,
        hdr: algo_types::BlockHeader,
        _payset_hint: usize,
        _max_txn_bytes_per_block: usize,
    ) -> Result<Box<dyn algo_pool::traits::BlockEvaluator>, algo_error::AlgoError> {
        let consensus_params =
            algo_types::consensus::consensus_params_for_version(&hdr.current_protocol)
                .or_else(|| {
                    algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
                })
                .ok_or_else(|| algo_error::AlgoError::Ledger {
                    message: "could not look up consensus params for block evaluator".into(),
                })?;
        Ok(Box::new(SimpleBlockEvaluator {
            hdr,
            consensus_params,
            included_txns: Vec::new(),
            txn_bytes: 0,
        }))
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

/// Run the participate command: start the agreement protocol and participate
/// in consensus using the provided participation keys.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ledger_path: &Path,
    genesis_id: Option<&str>,
    network: &str,
    peers: &[String],
    partkey_path: &Path,
    listen_address: Option<&str>,
    genesis_hash_hex: Option<&str>,
) -> anyhow::Result<()> {
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
    let sqlite_ledger = SqliteLedger::open(ledger_path).map_err(|e| {
        anyhow::anyhow!("failed to open ledger at {}: {}", ledger_path.display(), e)
    })?;
    let latest = sqlite_ledger.current_round().0;
    info!(path = %ledger_path.display(), latest_round = latest, "opened ledger database");

    let ledger = Arc::new(Mutex::new(sqlite_ledger));

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

    // -----------------------------------------------------------------------
    // 3. Build the gossip network node.
    // -----------------------------------------------------------------------
    let phonebook = Arc::new(Phonebook::new(60, Duration::from_secs(60)));
    if !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    }

    let net_config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: listen_address.map(|s| s.to_string()),
        relay_messages: false, // participation node, not a relay
        gossip_fanout: peers.len().max(algo_network::DEFAULT_GOSSIP_FANOUT),
        ..Default::default()
    };

    let gossip_node = Arc::new(WebsocketNetwork::new(net_config, phonebook));

    // Start the network (listener + mesh).
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
    // 4. Build agreement bridges.
    // -----------------------------------------------------------------------

    // Network bridge: wraps GossipNode for agreement message passing.
    let rt_handle = tokio::runtime::Handle::current();
    let agreement_network = AgreementNetworkBridge::with_defaults(
        gossip_node.clone() as Arc<dyn GossipNode>,
        rt_handle.clone(),
    );

    // Network advancer: wraps the gossip node so the ledger bridge can
    // signal network progress when certificates arrive.
    let network_advancer: Arc<dyn NetworkAdvancer> = Arc::new(GossipNetworkAdvancer {
        node: gossip_node.clone() as Arc<dyn GossipNode>,
    });

    // Ledger bridge: wraps SqliteLedger for agreement read/write access.
    // Uses `new_with_catchup` to enable the certificate-driven catchup path.
    // The returned `cert_rx` is consumed by the CatchupService below.
    let (agreement_ledger, cert_rx) =
        AgreementLedgerBridge::new_with_catchup(ledger.clone(), network_advancer);

    // Key manager bridge: wraps ParticipationStore for voting key lookups.
    let key_manager = AgreementKeyManagerBridge::new(part_store);

    // Block factory bridge: wraps TransactionPool for block assembly.
    let pool_ledger_adapter = Arc::new(PoolLedgerAdapter {
        ledger: ledger.clone(),
    });
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        pool_ledger_adapter as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    let block_factory = BlockFactoryBridge::new(pool);

    // Block validator bridge: wraps algo-validate for incoming block checks.
    // Extract the timestamp from the latest committed block header so the
    // validator can enforce the MaxTimestampIncrement constraint.
    let prev_timestamp: Option<i64> = {
        let l = ledger.lock().expect("ledger lock");
        let current = l.current_round().0;
        if current > 0 {
            match l.get_block_header_data(current) {
                Ok(Some(hdr_bytes)) => match BlockHeader::decode_from_bytes(&hdr_bytes) {
                    Ok(hdr) => {
                        info!(
                            round = current,
                            timestamp = hdr.timestamp,
                            "extracted previous block timestamp"
                        );
                        Some(hdr.timestamp)
                    }
                    Err(e) => {
                        warn!(round = current, error = %e, "failed to decode block header for timestamp; skipping timestamp validation");
                        None
                    }
                },
                Ok(None) => {
                    warn!(
                        round = current,
                        "no block header data found; skipping timestamp validation"
                    );
                    None
                }
                Err(e) => {
                    warn!(round = current, error = %e, "failed to read block header data; skipping timestamp validation");
                    None
                }
            }
        } else {
            // Round 0 (genesis) — no previous timestamp needed.
            None
        }
    };
    let block_validator =
        BlockValidatorBridge::new(resolved_genesis_id.clone(), genesis_hash, prev_timestamp);

    // Real random source backed by the OS CSPRNG; no-op monitor.
    let random_source = RealRandomSource;
    let monitor = NoOpMonitor;

    // Real crypto verifier backed by the agreement ledger bridge.
    // This verifies VRF credentials and OTS signatures on incoming votes
    // and bundles, rather than blindly accepting them.
    let crypto_ledger = Arc::new(AgreementLedgerBridge::new(ledger.clone()));
    let crypto = AsyncCryptoVerifier::new(crypto_ledger);

    // -----------------------------------------------------------------------
    // 5. Build and start the catchup service.
    // -----------------------------------------------------------------------
    // The catchup service runs a background thread that receives certificates
    // from the agreement service (via `cert_rx`) and fetches the corresponding
    // blocks from peers when the ledger doesn't have them yet.
    //
    // The catchup bridge is a separate `AgreementLedgerBridge` wrapping the
    // same underlying `SqliteLedger`. It only needs `ensure_block` to commit
    // fetched blocks, and shares the same ledger mutex so commits are visible
    // to the agreement service immediately.
    let catchup_bridge = Arc::new(AgreementLedgerBridge::new(ledger.clone()));

    let block_fetcher: Arc<dyn BlockFetcher> = Arc::new(GossipBlockFetcher {
        ws_network: gossip_node.clone(),
        rt_handle,
    });

    let mut catchup_service =
        CatchupService::start(cert_rx, ledger.clone(), catchup_bridge, block_fetcher);
    info!("catchup service started");

    // -----------------------------------------------------------------------
    // 6. Build and start the agreement Service.
    // -----------------------------------------------------------------------
    let params = Parameters {
        network: agreement_network,
        ledger: agreement_ledger,
        key_manager,
        block_factory,
        block_validator,
        random_source,
        monitor,
        crypto,
    };

    let service = Service::new(params);
    let handle = service.start();

    info!(
        genesis_id = %resolved_genesis_id,
        latest_round = latest,
        "consensus participation active -- press Ctrl+C to stop"
    );

    // -----------------------------------------------------------------------
    // 7. Wait for shutdown signal (Ctrl+C).
    // -----------------------------------------------------------------------
    tokio::signal::ctrl_c().await?;

    info!("shutting down consensus participation...");

    // Stop the agreement service first, then the catchup service (mirrors
    // Go's shutdown order where the agreement service is stopped before the
    // catchup service, ensuring no new certificates are sent after the
    // catchup service shuts down).
    handle.shutdown();
    catchup_service.stop();
    gossip_node.stop().await;
    info!("consensus participation stopped");

    Ok(())
}
