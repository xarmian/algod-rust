//! `algod-rust node start` — run a node: serve the algod v2 REST API backed by
//! a genesis-initialized local ledger (TASK-263 / PLAN-262).
//!
//! This is the localnet / dev entry point. Unlike `participate`, it requires no
//! participation keys or peers — it boots a ledger from `genesis.json` (or
//! initializes a fresh one) and serves the REST API, following the data-dir
//! layout Go uses so `goal -d <datadir> …` works unchanged.
//!
//! By default this is a **read-serving** node: status, blocks, account, and
//! genesis endpoints. With `--dev` (or a `"devmode": true` genesis), it also
//! attaches a transaction pool and produces one block per submitted group
//! (single-node, no agreement) — giving instant submit→confirm (TASK-264).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use algo_codec::{canonical_encode_block_header_from_block, encode_block};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::{
    make_genesis_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis,
    SqliteLedger,
};
use algo_pool::{PoolConfig, TransactionPool};
use algo_rest_api::node::BuildVersion;
use algo_rest_api::server::{ApiServer, ApiServerConfig};
use algo_types::Digest;
use anyhow::Context;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cli::NodeCommands;
use crate::commands::participate::PoolLedgerAdapter;
use crate::node_interface_impl::{AlgodNodeInterface, NodeInterfaceConfig};

/// Default REST bind address when `--listen` is not provided. Matches
/// go-algorand's default algod endpoint port.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

pub async fn run(cmd: NodeCommands) -> anyhow::Result<()> {
    match cmd {
        NodeCommands::Start {
            data_dir,
            listen,
            genesis,
            dev,
        } => run_start(&data_dir, listen.as_deref(), genesis.as_deref(), dev).await,
    }
}

async fn run_start(
    data_dir: &Path,
    listen: Option<&str>,
    genesis_path_arg: Option<&Path>,
    dev_flag: bool,
) -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // 1. Resolve + parse genesis.json.
    // -----------------------------------------------------------------------
    let genesis_path = genesis_path_arg
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join("genesis.json"));
    let genesis_str = std::fs::read_to_string(&genesis_path)
        .with_context(|| format!("reading genesis.json at {}", genesis_path.display()))?;
    let genesis = parse_genesis_json(&genesis_str)
        .map_err(|e| anyhow::anyhow!("parsing genesis.json: {e}"))?;
    // Go's `Genesis.ID()` = "<network>-<schemaID>" (the `id` field is the
    // schema id). Used as the per-genesis ledger subdirectory + reported by
    // `/v2/status` and `/genesis`.
    let genesis_id = format!("{}-{}", genesis.network, genesis.id);
    let gh = algo_ledger::genesis::genesis_hash(&genesis);

    // -----------------------------------------------------------------------
    // 2. Open the ledger (Go layout: <datadir>/<genesisID>/ledger.*), seeding
    //    genesis state on first boot.
    // -----------------------------------------------------------------------
    let ledger_dir = data_dir.join(&genesis_id);
    std::fs::create_dir_all(&ledger_dir)
        .with_context(|| format!("creating ledger directory {}", ledger_dir.display()))?;
    let ledger_prefix = ledger_dir.join("ledger");
    let mut sqlite_ledger = SqliteLedger::open(&ledger_prefix)
        .map_err(|e| anyhow::anyhow!("opening ledger at {}: {e}", ledger_prefix.display()))?;

    let latest = sqlite_ledger.current_round().0;
    // "Already seeded" is the presence of the accounttotals row, not nonzero
    // online stake (a network with every allocation offline legitimately has
    // online=0 after seeding). Mirrors the relay command's check.
    let already_seeded = sqlite_ledger.has_account_totals().unwrap_or(false);
    if already_seeded {
        info!(round = latest, genesis_id = %genesis_id, "opened existing ledger");
    } else {
        if latest > 0 {
            anyhow::bail!(
                "ledger at {} has block history (round {latest}) but no account totals — \
                 refusing to re-seed genesis over existing history. Purge the data dir and \
                 restart to rebuild cleanly.",
                ledger_prefix.display()
            );
        }
        info!(genesis_id = %genesis_id, "initializing a fresh ledger from genesis");
        sqlite_ledger
            .begin_block()
            .map_err(|e| anyhow::anyhow!("begin_block during genesis seed: {e}"))?;
        populate_store(&mut sqlite_ledger, &genesis)
            .map_err(|e| anyhow::anyhow!("populate_store from genesis: {e}"))?;
        seed_account_totals_from_genesis(&mut sqlite_ledger, &genesis)
            .map_err(|e| anyhow::anyhow!("seed_account_totals_from_genesis: {e}"))?;
        // Store the round-0 genesis block so the ledger has a tip header for the
        // pool evaluator to chain block 1 from, and so /v2/blocks/0 serves. No
        // apply — genesis state is already seeded above (mirrors relay's
        // round-0 handling).
        let genesis_block = make_genesis_block(&genesis)
            .map_err(|e| anyhow::anyhow!("building genesis block: {e}"))?;
        let blk_data = encode_block(&genesis_block)
            .map_err(|e| anyhow::anyhow!("encoding genesis block: {e}"))?;
        let hdr_data = canonical_encode_block_header_from_block(&genesis_block);
        sqlite_ledger
            .put_block(0, &genesis_block.current_protocol, &hdr_data, &blk_data)
            .map_err(|e| anyhow::anyhow!("put_block(0) for genesis: {e}"))?;
        // No certificate for the genesis block — it isn't agreed upon. Leaving
        // certdata NULL makes `get_block_cert(0)` return None, so the
        // `/v2/blocks/0` envelope is a valid `{block}` map (an empty-bytes cert
        // would emit a `cert` key with no value → invalid msgpack).
        sqlite_ledger
            .commit_block()
            .map_err(|e| anyhow::anyhow!("commit_block during genesis seed: {e}"))?;
    }

    // Dev mode is enabled by the `--dev` flag or a `"devmode": true` genesis.
    let dev_mode = dev_flag || genesis.devmode;

    // Dev-mode block production restores the genesis hash stripped from committed
    // transactions by treating a zero hash as "stripped" (see
    // `dev_producer::restore_block_genesis_fields`). That is only unambiguous
    // under protocols that require a genesis hash, so refuse dev mode on legacy
    // optional-genesis-hash protocols rather than risk mis-derived txids.
    if dev_mode {
        let params = algo_types::consensus::consensus_params_for_version(&genesis.proto)
            .ok_or_else(|| {
                anyhow::anyhow!("dev mode: unknown genesis protocol '{}'", genesis.proto)
            })?;
        if !params.require_genesis_hash {
            anyhow::bail!(
                "dev mode requires a protocol that mandates a genesis hash (modern protocols); \
                 genesis protocol '{}' does not — refusing to start in dev mode",
                genesis.proto
            );
        }
    }

    let ledger = Arc::new(Mutex::new(sqlite_ledger));

    // Cancellation token shared with the adapter and the server: cancelling it
    // on Ctrl-C also unblocks in-flight `wait-for-block-after` handlers promptly
    // instead of letting them poll to their 60s timeout (mirrors participate).
    let shutdown_token = CancellationToken::new();

    // -----------------------------------------------------------------------
    // 3. Build the node interface adapter. In dev mode it also gets a
    //    transaction pool and produces a block on each submitted group
    //    (single-node, no agreement); otherwise it stays read-serving.
    // -----------------------------------------------------------------------
    let node_config = NodeInterfaceConfig {
        genesis_id: genesis_id.clone(),
        genesis_hash: Digest(gh),
        genesis_json: genesis_str,
        build_version: BuildVersion::from_build_env(),
        default_protocol: genesis.proto.clone(),
    };
    let mut node_interface = AlgodNodeInterface::new(ledger.clone(), node_config)
        .with_shutdown_token(shutdown_token.clone());
    if dev_mode {
        let pool = Arc::new(TransactionPool::new(
            PoolConfig::default(),
            Arc::new(PoolLedgerAdapter::new(ledger.clone()))
                as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        node_interface = node_interface.with_pool(pool).with_dev_mode();
        info!("dev mode enabled — each submitted transaction group produces a block");
    }
    let node = Arc::new(node_interface);

    // -----------------------------------------------------------------------
    // 4. Serve the REST API. `ApiServer::serve` writes algod.net /
    //    algod.token / algod.admin.token into the data dir for `goal` to read.
    // -----------------------------------------------------------------------
    let listen_addr: SocketAddr = listen.unwrap_or(DEFAULT_LISTEN).parse().with_context(|| {
        format!(
            "parsing --listen address {:?}",
            listen.unwrap_or(DEFAULT_LISTEN)
        )
    })?;
    let api_config = ApiServerConfig {
        listen_addr,
        data_dir: Some(data_dir.to_path_buf()),
        api_token: None,
        admin_token: None,
    };
    let shutdown_future = {
        let token = shutdown_token.clone();
        async move { token.cancelled().await }
    };
    let (bound_addr, join_handle) = ApiServer::new(api_config)
        .serve(node, shutdown_future)
        .await
        .map_err(|e| anyhow::anyhow!("binding REST API listener: {e}"))?;
    info!(
        address = %bound_addr,
        data_dir = %data_dir.display(),
        "algod-rust node serving REST API — press Ctrl-C to stop"
    );

    // -----------------------------------------------------------------------
    // 5. Run until Ctrl-C, then shut the server down gracefully.
    // -----------------------------------------------------------------------
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("failed to listen for Ctrl-C ({e}); shutting down");
    }
    info!("shutdown requested");
    shutdown_token.cancel();
    let _ = join_handle.await;
    Ok(())
}
