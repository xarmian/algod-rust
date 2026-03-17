use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::{
    BlockFactoryBridge, BlockValidatorBridge, Parameters, RandomSource, Service,
    StubEventsProcessingMonitor,
};
use algo_ledger::participation::ParticipationStore;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{AgreementKeyManagerBridge, AgreementLedgerBridge, SqliteLedger};
use algo_network::{
    AgreementNetworkBridge, GossipNode, Phonebook, WebsocketNetwork, WebsocketNetworkConfig,
    RELAY_ROLE,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_types::{BlockHeader, Round};
use rand::Rng;
use tracing::{info, warn};

use crate::commands::network_common::genesis_id_for;

/// A `RandomSource` backed by the OS/thread-local CSPRNG.
///
/// Replaces `StubRandomSource::constant(42)` for production use.
struct RealRandomSource;

impl RandomSource for RealRandomSource {
    fn uint64(&self) -> u64 {
        rand::thread_rng().gen()
    }
}

/// A minimal `BlockEvaluator` that builds empty blocks from a header template.
///
/// A full implementation would validate and include transactions from the
/// pool. For now this produces valid-but-empty blocks, which is sufficient
/// for participating in consensus without proposing transactions.
struct SimpleBlockEvaluator {
    hdr: algo_types::BlockHeader,
}

impl algo_pool::traits::BlockEvaluator for SimpleBlockEvaluator {
    fn round(&self) -> Round {
        self.hdr.round
    }

    fn pay_set_size(&self) -> usize {
        0
    }

    fn test_transaction_group(
        &self,
        _txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // TODO: implement real transaction validation
        Err(algo_error::AlgoError::Ledger {
            message: "SimpleBlockEvaluator does not support transaction validation yet".into(),
        })
    }

    fn transaction_group(
        &mut self,
        _txgroup: &[algo_types::SignedTransaction],
    ) -> Result<(), algo_error::AlgoError> {
        // TODO: implement real transaction inclusion
        Err(algo_error::AlgoError::Ledger {
            message: "SimpleBlockEvaluator does not support transaction inclusion yet".into(),
        })
    }

    fn generate_block(
        &mut self,
        _voting_accounts: &[algo_types::Address],
    ) -> Result<algo_types::Block, algo_error::AlgoError> {
        // Return an empty block based on the header template.
        Ok(algo_types::Block {
            round: self.hdr.round,
            branch: self.hdr.branch,
            seed: self.hdr.seed,
            timestamp: self.hdr.timestamp,
            genesis_id: self.hdr.genesis_id.clone(),
            genesis_hash: self.hdr.genesis_hash,
            current_protocol: self.hdr.current_protocol.clone(),
            ..Default::default()
        })
    }

    fn reset_txn_bytes(&mut self) {}
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
        Ok(Box::new(SimpleBlockEvaluator { hdr }))
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
        rt_handle,
    );

    // Ledger bridge: wraps SqliteLedger for agreement read/write access.
    let agreement_ledger = AgreementLedgerBridge::new(ledger.clone());

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
    let prev_timestamp: Option<i64> = {
        let _l = ledger.lock().expect("ledger lock");
        // TODO: Extract timestamp from the latest block header msgpack.
        // For now, skip timestamp validation by returning None.
        None
    };
    let block_validator =
        BlockValidatorBridge::new(resolved_genesis_id.clone(), genesis_hash, prev_timestamp);

    // Real random source backed by the OS CSPRNG; stub monitor.
    let random_source = RealRandomSource;
    let monitor = StubEventsProcessingMonitor::new();

    // -----------------------------------------------------------------------
    // 5. Build and start the agreement Service.
    // -----------------------------------------------------------------------
    let params = Parameters {
        network: agreement_network,
        ledger: agreement_ledger,
        key_manager,
        block_factory,
        block_validator,
        random_source,
        monitor,
    };

    let service = Service::new(params);
    let handle = service.start();

    info!(
        genesis_id = %resolved_genesis_id,
        latest_round = latest,
        "consensus participation active -- press Ctrl+C to stop"
    );

    // -----------------------------------------------------------------------
    // 6. Wait for shutdown signal (Ctrl+C).
    // -----------------------------------------------------------------------
    tokio::signal::ctrl_c().await?;

    info!("shutting down consensus participation...");
    handle.shutdown();
    gossip_node.stop().await;
    info!("consensus participation stopped");

    Ok(())
}
