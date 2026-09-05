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

use algo_codec::{canonical_encode_block, canonical_encode_block_header_from_block};
use algo_ledger::participation::ParticipationStore;
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
use crate::live_catchup::{
    LiveCatchupManager, LiveCatchupParams, NormalSyncControl, OrchestratorCatchupRunner,
};
use crate::node_interface_impl::{AlgodNodeInterface, FollowerSyncRoundState, NodeInterfaceConfig};

/// Default REST bind address when `--listen` is not provided. Matches
/// go-algorand's default algod endpoint port.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// Resolve `node start`'s REST listen address: an explicit `--listen`/`-l`
/// CLI flag always wins (issue #757, mirroring `participate`'s
/// `RestOptions::resolve` CLI-flag-overrides-config.json precedence,
/// `commands/participate.rs`); otherwise fall back to config.json's
/// `EndpointAddress` when non-empty; otherwise [`DEFAULT_LISTEN`].
///
/// Unlike `participate` (where REST is optional and an explicit empty
/// `EndpointAddress` opts out of serving it at all), `node start`'s entire
/// purpose is to serve the REST API, so an empty/unset config value falls
/// through to `DEFAULT_LISTEN` rather than disabling the server.
fn resolve_listen_addr(cli_listen: Option<&str>, config_endpoint_address: &str) -> String {
    cli_listen
        .map(str::to_string)
        .or_else(|| Some(config_endpoint_address.to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| DEFAULT_LISTEN.to_string())
}

/// Whether `config.json`'s `DNSBootstrapID` is set to a value `node start`
/// cannot act on. Returns `true` (a warning is owed) whenever the field is
/// non-empty — `node start` is REST-only by design (issue #779) and has no
/// gossip/relay networking layer that could ever resolve a DNS-SRV bootstrap
/// peer, unlike `participate`/`relay`. Pulled out as its own function so the
/// decision is independently testable rather than only reachable by running
/// the full `run_start` startup sequence.
fn dns_bootstrap_unconsumed(dns_bootstrap_id: &str) -> bool {
    !dns_bootstrap_id.is_empty()
}

/// Whether the follower-node dev-mode-genesis warning (issue #951) is owed
/// at startup — go's `MakeFollower` (`node/follower_node.go`) logs "Follower
/// running on a devMode network. Must submit txns to a different node."
/// whenever a real follower node's own genesis has `DevMode: true`,
/// unconditionally (it does not depend on what the followed peer's genesis
/// says — go's `AlgorandFollowerNode` reads only its *own* `genesis.DevMode`
/// field). Pulled out as its own pure function, mirroring
/// [`dns_bootstrap_unconsumed`], so the decision is independently testable.
fn follower_devmode_warning_needed(follower_mode: bool, genesis_devmode: bool) -> bool {
    follower_mode && genesis_devmode
}

pub async fn run(cmd: NodeCommands) -> anyhow::Result<()> {
    match cmd {
        NodeCommands::Start {
            data_dir,
            listen,
            genesis,
            dev,
            follow,
            follow_token,
        } => {
            run_start(
                &data_dir,
                listen.as_deref(),
                genesis.as_deref(),
                dev,
                follow.as_deref(),
                &follow_token,
            )
            .await
        }
    }
}

async fn run_start(
    data_dir: &Path,
    listen: Option<&str>,
    genesis_path_arg: Option<&Path>,
    dev_flag: bool,
    follow_url: Option<&str>,
    follow_token: &str,
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
    // `--dev` (self-produced blocks) and `--follow` (syncing someone else's
    // blocks) are mutually exclusive block-production sources.
    if dev_flag && follow_url.is_some() {
        anyhow::bail!("--dev and --follow are mutually exclusive");
    }
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
        let blk_data = canonical_encode_block(&genesis_block);
        let hdr_data = canonical_encode_block_header_from_block(&genesis_block);
        sqlite_ledger
            .put_block(0, &genesis_block.current_protocol, &hdr_data, &blk_data)
            .map_err(|e| anyhow::anyhow!("put_block(0) for genesis: {e}"))?;
        // Seed the running txn-counter state from the genesis block (1000 under
        // modern protocols). The block-0 header carries it, but only block
        // *apply* advances the counter and we don't apply block 0 — so without
        // this the first produced block's id generation would start from 0
        // (first created asset/app id 1 instead of 1001), diverging from go and
        // from the block header's own txn_counter. TASK-279.
        sqlite_ledger.set_txn_counter(genesis_block.txn_counter);
        // No certificate for the genesis block — it isn't agreed upon. Leaving
        // certdata NULL makes `get_block_cert(0)` return None, so the
        // `/v2/blocks/0` envelope is a valid `{block}` map (an empty-bytes cert
        // would emit a `cert` key with no value → invalid msgpack).
        sqlite_ledger
            .commit_block()
            .map_err(|e| anyhow::anyhow!("commit_block during genesis seed: {e}"))?;
    }

    // Dev mode is enabled by the `--dev` flag or a `"devmode": true` genesis
    // -- unless `--follow` was explicitly requested, in which case follow
    // mode wins over the genesis field: a genesis shared with a dev-mode
    // peer (e.g. the `validate-api` harness's go-algorand node, which
    // itself needs `devmode: true` to self-confirm submitted transactions)
    // would otherwise silently force this node into producing its own
    // blocks instead of syncing the peer's, defeating `--follow`'s purpose.
    let dev_mode = dev_flag || (genesis.devmode && follow_url.is_none());
    if genesis.devmode && follow_url.is_some() {
        info!("genesis sets \"devmode\": true but --follow was given — following the peer instead of self-producing blocks");
    }
    // Follower-node dev-mode-genesis warning (issue #951), matching go's
    // `MakeFollower` (`node/follower_node.go`) exactly — logged whenever a
    // real follower node's own genesis is dev-mode, since a follower can't
    // submit transactions to itself either way (no pool/broadcaster in
    // follower mode) and a dev-mode chain isn't produced by consensus
    // agreement other peers could also follow.
    if follower_devmode_warning_needed(follow_url.is_some(), genesis.devmode) {
        warn!("Follower running on a devMode network. Must submit txns to a different node.");
    }

    // Load `<data_dir>/consensus.json` (if present) and merge it onto the
    // built-in consensus table (issue #750; Go:
    // `PreloadConfigurableConsensusProtocols`, `config/config.go`). A missing
    // file falls back to the built-in table unchanged; a malformed file is a
    // real startup error rather than being silently ignored.
    //
    // Installing the merge result via `install_consensus_overrides` (issue
    // #762) makes `consensus_params_for_version` itself override-aware, so
    // every one of its ~57 call sites throughout ledger apply, AVM
    // evaluation, agreement/committee logic, REST API handlers, and
    // simulation transparently observes these overrides from this point
    // onward -- mirroring go-algorand's single mutable package-level
    // `config.Consensus` map, which every `config.Consensus[version]` caller
    // sees update the instant `LoadConfigurableConsensusProtocols` runs. This
    // call happens once, here, on the node's single startup thread, strictly
    // before the ledger/participation/agreement machinery constructed below
    // ever evaluates a transaction or block -- see
    // `install_consensus_overrides`'s doc comment for the write-once /
    // thread-safety contract this relies on.
    let consensus_overrides_path =
        data_dir.join(algo_types::consensus::CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);
    let consensus_protocols =
        algo_types::consensus::preload_configurable_consensus_protocols(data_dir)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", consensus_overrides_path.display()))?;
    algo_types::consensus::install_consensus_overrides(&consensus_protocols);
    if consensus_overrides_path.exists() {
        info!(path = %consensus_overrides_path.display(), "loaded consensus-parameter overrides");
    }

    // Dev-mode block production restores the genesis hash stripped from committed
    // transactions by treating a zero hash as "stripped" (see
    // `dev_producer::restore_block_genesis_fields`). That is only unambiguous
    // under protocols that require a genesis hash, so refuse dev mode on legacy
    // optional-genesis-hash protocols rather than risk mis-derived txids.
    if dev_mode {
        let params = consensus_protocols
            .get(&genesis.proto)
            .cloned()
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

    // -----------------------------------------------------------------------
    // 2b. Load `<data_dir>/config.json` (go-algorand `config.Local`
    //     equivalent, issue #754) — `node start` previously never read this
    //     file at all, leaving `docker/localnet-rust/data/config.json`
    //     decorative dead weight (issue #757). A missing file falls back to
    //     `Local::default()` (go-matching defaults, same as `participate`'s
    //     handling in `main.rs`); a malformed one is logged and defaults are
    //     used rather than refusing to start — `node start` is the
    //     localnet/dev entry point and a bad hand-edited config.json
    //     shouldn't brick it.
    let file_config = match algo_config::Local::load_from_data_dir(data_dir) {
        Ok(cfg) => {
            info!(
                version = cfg.version,
                endpoint_address = %cfg.endpoint_address,
                dns_bootstrap_id = %cfg.dns_bootstrap_id,
                enable_developer_api = cfg.enable_developer_api,
                "loaded config.json"
            );
            cfg
        }
        Err(e) => {
            warn!(error = %e, "failed to load config.json; continuing with defaults");
            algo_config::Local::default()
        }
    };
    // `DNSBootstrapID` (config.json) has a real, exercised consumer on
    // `algod-rust participate`/`relay` (issue #748's `Discovery`/`Phonebook`
    // DNS-SRV peer bootstrap over the gossip WS protocol), but `node start`
    // has no gossip/relay networking layer at all — its only peer-syncing
    // affordance is `--follow <url>`, an explicit REST peer URL.
    //
    // Issue #779 investigated giving `node start` a DNS-bootstrap-driven
    // auto-follow path (resolving a peer via `Discovery`/`HickorySrvResolver`
    // and feeding it into `--follow`) and concluded that is not just
    // out-of-scope-for-now but architecturally incoherent: go-algorand's SRV
    // records (`DNSBootstrapID`) resolve *gossip*-protocol relay addresses
    // (the WS port `participate`/`relay` dial), not REST API addresses —
    // there is no protocol-level relationship between a discovered gossip
    // peer and a `--follow`-able REST endpoint. Auto-deriving one from the
    // other would be pure guesswork (same host, unrelated port), not a real
    // discovery mechanism. Consuming `DNSBootstrapID` for real would require
    // giving `node start` an actual gossip/relay networking layer first —
    // which would turn it into a second `participate`/`relay`, duplicating
    // machinery those commands already own — so this is formally
    // out-of-scope by design, not a follow-up to build. `node start` stays
    // REST-only: self-produced blocks (`--dev`) or one explicit REST peer
    // (`--follow`).
    if dns_bootstrap_unconsumed(&file_config.dns_bootstrap_id) {
        info!(
            dns_bootstrap_id = %file_config.dns_bootstrap_id,
            "config.json sets DNSBootstrapID, but `node start` is REST-only and has no \
             gossip-protocol networking layer to resolve DNS-SRV bootstrap peers for — \
             ignoring (see issue #779; use `algod-rust participate`/`relay` for \
             DNS-bootstrap-driven peer discovery, or `node start --follow <url>` for an \
             explicit REST peer)"
        );
    }

    // Participation-key registry. Lives at <genesisDir>/partregistry.sqlite,
    // matching go's `config.ParticipationRegistryFilename`
    // (../go-algorand/node/node.go:868). Backs the admin-only
    // /v2/participation* endpoints so `goal account addpartkey/listpartkeys/
    // deletepartkey` round-trip against the node.
    let part_registry_path = ledger_dir.join("partregistry.sqlite");
    let part_store = ParticipationStore::open(&part_registry_path).map_err(|e| {
        anyhow::anyhow!(
            "opening participation registry at {}: {e}",
            part_registry_path.display()
        )
    })?;
    let part_store = Arc::new(Mutex::new(part_store));

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
    // -----------------------------------------------------------------------
    // 3a. `--follow <peer>`: construct the pausable/resumable block-sync
    //     loop up front (rather than spawning it directly, as before), so
    //     it can double as the [`NormalSyncControl`] a
    //     [`LiveCatchupManager`] (issue #937) pauses while a live
    //     catchpoint catchup owns the ledger, and resumes afterward. The
    //     loop itself is unchanged — still `run_follow_loop`, still
    //     applying via `apply_block_caching_delta` — only its start/stop
    //     is now indirected through `FollowLoopControl`.
    // -----------------------------------------------------------------------
    let follow_control = follow_url.map(|url| {
        FollowLoopControl::new(
            ledger.clone(),
            Arc::new(algo_rest_client::AlgodClient::new(url, follow_token))
                as Arc<dyn algo_rest_client::BlockSource>,
        )
    });
    if let Some(control) = &follow_control {
        info!(
            peer = follow_url.unwrap(),
            "follow mode enabled — syncing blocks from peer"
        );
        control.resume().await;
    }

    // -----------------------------------------------------------------------
    // 3a-bis. Real, ledger-owning follower-node state (issue #951): only
    //     `--follow <peer>` makes this a follower node in go-algorand's
    //     sense (`AlgorandFollowerNode` vs `AlgorandFullNode`) — plain
    //     read-serving/`--dev` `node start` stays a full node. Constructed
    //     up front (before the catchup manager below) so both the
    //     `NodeInterface` adapter and the live catchpoint-catchup toggle
    //     share the exact same sync-round state, matching go's single
    //     `AlgorandFollowerNode` owning both.
    // -----------------------------------------------------------------------
    let follower_sync_round = follow_url
        .map(|_| FollowerSyncRoundState::new(ledger.clone(), file_config.max_acct_lookback));

    // Live catchpoint-catchup mode (issue #937): only meaningful when
    // there's a known peer (`--follow`'s URL) to fetch the catchpoint and
    // blocks from, and a running sync loop against that same peer to pause
    // while the catchup owns the ledger. Without `--follow` (plain
    // read-serving or `--dev`), `start_catchup`/`abort_catchup` stay
    // `NotImplemented` — there's no peer to catch up *from*. Also skipped
    // on an archival node (`config.json`'s `Archival`), mirroring go's own
    // refusal — `AlgorandFullNode.StartCatchup`, "catching up using a
    // catchpoint is not supported on archive nodes" (`node/node.go`).
    let catchup_manager = match (&follow_control, follow_url) {
        (Some(control), Some(url)) if !file_config.archival => {
            let params = LiveCatchupParams {
                algod_url: url.to_string(),
                algod_token: follow_token.to_string(),
                db_path: ledger_prefix.clone(),
                genesis_id: genesis_id.clone(),
                genesis_hash: gh,
                concurrency: 8,
                catchpoint_peer_urls: Vec::new(),
            };
            let runner = Arc::new(OrchestratorCatchupRunner::new(params));
            let manager =
                LiveCatchupManager::new(runner, control.clone() as Arc<dyn NormalSyncControl>);
            // Issue #951: a completed live catchup must reset the follower
            // node's sync round before resuming normal sync, mirroring
            // go's `SetCatchpointCatchupMode(false)` — see
            // `TestFastCatchupResume` (`node/follower_node_test.go`).
            if let Some(state) = &follower_sync_round {
                manager.set_sync_round_reset_hook(
                    state.clone() as Arc<dyn crate::live_catchup::SyncRoundResetHook>
                );
            }
            Some(manager)
        }
        _ => None,
    };

    let mut node_interface = AlgodNodeInterface::new(ledger.clone(), node_config)
        .with_shutdown_token(shutdown_token.clone())
        .with_participation_store(part_store)
        // config.json's `EnableDeveloperAPI` (issue #751/#757) — mirrors
        // `participate`'s wiring. `enable_developer_api()` itself already
        // ORs this with dev-mode (see
        // `AlgodNodeInterface::enable_developer_api`), so `--dev` keeps
        // working unchanged whether or not this is set.
        .with_enable_developer_api(file_config.enable_developer_api)
        // `config.json`'s `EnableRuntimeMetrics`/`EnableNetDevMetrics`
        // (issue #776): process-wide `/metrics` counters, independent of
        // consensus participation, so `node start` wires them the same way
        // `participate` does.
        .with_enable_runtime_metrics(file_config.enable_runtime_metrics)
        .with_enable_netdev_metrics(file_config.enable_netdev_metrics);
    if dev_mode {
        let pool = Arc::new(TransactionPool::new(
            PoolConfig::default(),
            Arc::new(PoolLedgerAdapter::new(ledger.clone()))
                as Arc<dyn algo_pool::traits::PoolLedger>,
        ));
        node_interface = node_interface.with_pool(pool).with_dev_mode();
        info!("dev mode enabled — each submitted transaction group produces a block");
    }
    if let Some(mgr) = &catchup_manager {
        node_interface = node_interface.with_catchup_manager(mgr.clone());
    }
    if let Some(state) = &follower_sync_round {
        node_interface = node_interface.with_follower_mode(state.clone());
    }
    let node = Arc::new(node_interface);

    // -----------------------------------------------------------------------
    // 4. Serve the REST API. `ApiServer::serve` writes algod.net /
    //    algod.token / algod.admin.token into the data dir for `goal` to read.
    // -----------------------------------------------------------------------
    let listen_str = resolve_listen_addr(listen, &file_config.endpoint_address);
    let listen_addr: SocketAddr = listen_str
        .parse()
        .with_context(|| format!("parsing listen address {listen_str:?}"))?;
    let api_config = ApiServerConfig {
        listen_addr,
        data_dir: Some(data_dir.to_path_buf()),
        api_token: None,
        admin_token: None,
        disable_api_auth: false,
        enable_private_network_access_header: false,
        rest_read_timeout_seconds: file_config.rest_read_timeout_seconds,
        rest_write_timeout_seconds: file_config.rest_write_timeout_seconds,
        rest_connections_soft_limit: file_config.rest_connections_soft_limit,
        rest_connections_hard_limit: file_config.rest_connections_hard_limit,
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
    // 5. Run until Ctrl-C, then shut the server down gracefully. The
    //    `--follow` block-sync loop (started in step 3a, via
    //    `FollowLoopControl::resume`) is stopped through the same
    //    pause/resume interface a live catchpoint catchup uses (issue
    //    #937), rather than a directly-held `JoinHandle` — `pause()`
    //    cancels and joins it exactly like the old direct-join code did.
    // -----------------------------------------------------------------------
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("failed to listen for Ctrl-C ({e}); shutting down");
    }
    info!("shutdown requested");
    shutdown_token.cancel();
    let _ = join_handle.await;
    if let Some(control) = &follow_control {
        control.pause().await;
    }
    Ok(())
}

/// Poll interval between `--follow` peer status checks / block fetches when
/// caught up to (or briefly behind on) the peer's tip.
const FOLLOW_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Continuously fetch new blocks from `client` (a REST peer, in real usage
/// `AlgodClient`) one round at a time, starting from `ledger`'s own current
/// round + 1, and apply each through `apply_block_caching_delta` — the same
/// real sync-path call `algod-rust sync` makes for non-comparison runs (see
/// `commands/sync.rs`) — so the delta cache backing `GET /v2/deltas/{round}`
/// is populated exactly as it would be for a node syncing from a genuine
/// peer, not a `--dev` self-produced block.
///
/// Runs until `cancel` fires. Fetch/apply errors are logged and retried
/// after [`FOLLOW_POLL_INTERVAL`] rather than aborting the loop, mirroring
/// `commands/catchpoint_sync.rs`'s gossip-handoff follow loop.
async fn run_follow_loop(
    ledger: Arc<Mutex<SqliteLedger>>,
    client: Arc<dyn algo_rest_client::BlockSource>,
    cancel: CancellationToken,
) {
    use algo_ledger::LedgerStore;

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let current = {
            let l = ledger.lock().expect("ledger mutex poisoned");
            l.current_round().0
        };

        let status = match client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "follow: failed to fetch peer status, retrying");
                tokio::time::sleep(FOLLOW_POLL_INTERVAL).await;
                continue;
            }
        };

        if current >= status.last_round {
            tokio::time::sleep(FOLLOW_POLL_INTERVAL).await;
            continue;
        }

        let next_round = current + 1;
        let block_resp = match client.get_block(algo_types::Round(next_round)).await {
            Ok(b) => b,
            Err(e) => {
                warn!(round = next_round, error = %e, "follow: block fetch failed, retrying");
                tokio::time::sleep(FOLLOW_POLL_INTERVAL).await;
                continue;
            }
        };

        // Kept in its own synchronous helper (no `.await` inside) so the
        // `std::sync::MutexGuard` never needs to be held across a suspend
        // point -- a `MutexGuard` is `!Send`, which would otherwise make
        // this whole loop's future not `Send` and reject it from
        // `tokio::spawn`.
        apply_one_block(&ledger, next_round, &block_resp.block);
    }
}

/// Synchronously locks `ledger`, applies `block` via the real sync-path
/// call (`apply_block_caching_delta`), and commits (or rolls back on
/// failure), logging either outcome. See [`run_follow_loop`] for why this
/// is split out as a plain (non-`async`) function.
fn apply_one_block(ledger: &Mutex<SqliteLedger>, round: u64, block: &algo_types::Block) {
    let mut l = ledger.lock().expect("ledger mutex poisoned");
    if let Err(e) = l.begin_block() {
        warn!(round, error = %e, "follow: begin_block failed");
        return;
    }
    match l.apply_block_caching_delta(block) {
        Ok(()) => match l.commit_block() {
            Ok(()) => {
                info!(round, "follow: applied block");
            }
            Err(e) => {
                warn!(round, error = %e, "follow: commit_block failed");
            }
        },
        Err(e) => {
            warn!(round, error = %e, "follow: apply_block failed");
            let _ = l.rollback_block();
        }
    }
}

/// [`NormalSyncControl`] that pauses/resumes `--follow`'s background block-
/// sync loop (issue #937's live catchpoint-catchup toggle).
///
/// Each `resume()` spawns a *fresh* [`run_follow_loop`] task with its own
/// [`CancellationToken`], deliberately independent of `run_start`'s
/// process-wide `shutdown_token` — pausing for a live catchpoint catchup
/// must not look like (or race with) a full node shutdown, and the loop
/// needs to be resumable afterward. `run_start`'s own shutdown sequence
/// calls [`Self::pause`] directly instead of awaiting a stored
/// `JoinHandle`, so the two cancellation sources never overlap.
struct FollowLoopControl {
    ledger: Arc<Mutex<SqliteLedger>>,
    client: Arc<dyn algo_rest_client::BlockSource>,
    running: tokio::sync::Mutex<Option<(CancellationToken, tokio::task::JoinHandle<()>)>>,
}

impl FollowLoopControl {
    fn new(
        ledger: Arc<Mutex<SqliteLedger>>,
        client: Arc<dyn algo_rest_client::BlockSource>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            client,
            running: tokio::sync::Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl NormalSyncControl for FollowLoopControl {
    async fn pause(&self) {
        let mut guard = self.running.lock().await;
        if let Some((cancel, handle)) = guard.take() {
            cancel.cancel();
            let _ = handle.await;
        }
    }

    async fn resume(&self) {
        let mut guard = self.running.lock().await;
        if guard.is_none() {
            let cancel = CancellationToken::new();
            let ledger = self.ledger.clone();
            let client = self.client.clone();
            let cancel_task = cancel.clone();
            let handle =
                tokio::spawn(async move { run_follow_loop(ledger, client, cancel_task).await });
            *guard = Some((cancel, handle));
        }
    }
}

#[cfg(test)]
mod follow_loop_tests {
    use super::*;
    use algo_rest_client::NodeStatus;
    use algo_types::BlockResponse;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;

    /// A minimal in-memory `BlockSource` mock: serves pre-built blocks by
    /// round and reports the highest round it holds as the peer's tip, so
    /// `run_follow_loop` can be pinned without any live process or network.
    struct MockPeer {
        blocks: RwLock<std::collections::BTreeMap<u64, algo_types::Block>>,
        fetch_count: AtomicU64,
    }

    #[async_trait]
    impl algo_rest_client::BlockSource for MockPeer {
        async fn get_block_raw(&self, round: algo_types::Round) -> algo_error::Result<Vec<u8>> {
            let resp = self.get_block(round).await?;
            // Wrap like the real `GET /v2/blocks/{round}?format=msgpack`
            // response envelope (`BlockResponse { block, cert }`), not a
            // bare `canonical_encode_block` -- `decode_block_response`
            // (what `AlgodClient::get_block` and this mock's own
            // `get_block` below call) expects the wrapped shape.
            rmp_serde::to_vec_named(&resp).map_err(|e| algo_error::AlgoError::Ledger {
                message: format!("encoding block response {}: {e}", round.0),
            })
        }

        async fn get_block(&self, round: algo_types::Round) -> algo_error::Result<BlockResponse> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let blocks = self.blocks.read().unwrap();
            let block =
                blocks
                    .get(&round.0)
                    .cloned()
                    .ok_or_else(|| algo_error::AlgoError::Ledger {
                        message: format!("no block at round {}", round.0),
                    })?;
            Ok(BlockResponse { block, cert: None })
        }

        async fn get_status(&self) -> algo_error::Result<NodeStatus> {
            let blocks = self.blocks.read().unwrap();
            let last_round = blocks.keys().next_back().copied().unwrap_or(0);
            Ok(NodeStatus {
                last_round,
                ..Default::default()
            })
        }

        async fn wait_for_round(
            &self,
            _round: algo_types::Round,
        ) -> algo_error::Result<NodeStatus> {
            self.get_status().await
        }
    }

    /// Pins the target `run_follow_loop` behavior: starting from a fresh
    /// (round-0) ledger, it must fetch and apply every block the mock peer
    /// holds — through `apply_block_caching_delta`, so the delta cache is
    /// populated exactly as the real sync path populates it — and then stop
    /// issuing new fetches once caught up (idle-polling instead).
    #[tokio::test(flavor = "multi_thread")]
    async fn follow_loop_applies_peer_blocks_via_sync_path_and_populates_delta_cache() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
        let fee_sink = algo_types::Address([3u8; 32]);

        // Two trivial, empty-payset blocks (round 1, round 2) the mock peer
        // will serve — enough to prove the loop advances more than one
        // round and then idles. Mirrors
        // `sqlite.rs`'s `apply_block_caching_delta_caches_full_delta_for_appl_with_inner_acfg`,
        // which applies a hand-built `Block` directly to a fresh ledger with
        // no genesis chain (block *application* here doesn't validate
        // header linkage — that's `algo-validate`'s job, orthogonal to what
        // this loop exercises).
        let mut blocks = std::collections::BTreeMap::new();
        for round in 1..=2u64 {
            let block = algo_types::Block {
                round: algo_types::Round(round),
                fee_sink,
                current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
                ..algo_types::Block::default()
            };
            blocks.insert(round, block);
        }

        let store = SqliteLedger::open_in_memory().unwrap();
        let peer = Arc::new(MockPeer {
            blocks: RwLock::new(blocks),
            fetch_count: AtomicU64::new(0),
        });
        let ledger = Arc::new(Mutex::new(store));
        let cancel = CancellationToken::new();

        let loop_handle = {
            let ledger = ledger.clone();
            let peer: Arc<dyn algo_rest_client::BlockSource> = peer.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move { run_follow_loop(ledger, peer, cancel).await })
        };

        // Wait until both blocks are applied (bounded poll, not a fixed sleep).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let round = {
                use algo_ledger::LedgerStore;
                ledger.lock().unwrap().current_round().0
            };
            if round >= 2 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "follow loop did not reach round 2 in time (stuck at {round})"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // The real sync-path call (`apply_block_caching_delta`) must have
        // populated the delta cache for both applied rounds — this is the
        // assertion that actually distinguishes the sync path from a
        // `cache_state_delta`-direct dev-mode apply.
        {
            let l = ledger.lock().unwrap();
            assert!(
                l.get_cached_state_delta(1).is_some(),
                "round 1 delta must be cached via apply_block_caching_delta"
            );
            assert!(
                l.get_cached_state_delta(2).is_some(),
                "round 2 delta must be cached via apply_block_caching_delta"
            );
        }
        assert_eq!(
            peer.fetch_count.load(Ordering::SeqCst),
            2,
            "loop must fetch exactly the two available rounds, not re-fetch once caught up"
        );

        cancel.cancel();
        let _ = loop_handle.await;
    }
}

#[cfg(test)]
mod config_json_wiring_tests {
    use super::*;

    // -------------------------------------------------------------------
    // `resolve_listen_addr` — issue #757's CLI-flag-overrides-config.json
    // precedence for `node start`'s REST listen address.
    // -------------------------------------------------------------------

    #[test]
    fn cli_listen_flag_wins_over_config_endpoint_address() {
        assert_eq!(
            resolve_listen_addr(Some("127.0.0.1:9999"), "0.0.0.0:8080"),
            "127.0.0.1:9999",
            "an explicit --listen must override config.json's EndpointAddress"
        );
    }

    #[test]
    fn config_endpoint_address_used_when_no_cli_flag() {
        assert_eq!(
            resolve_listen_addr(None, "0.0.0.0:8080"),
            "0.0.0.0:8080",
            "with no --listen, config.json's EndpointAddress must be honored \
             (this is the fix for issue #757 — previously `node start` never \
             consulted config.json at all and always fell back to \
             DEFAULT_LISTEN here)"
        );
    }

    #[test]
    fn default_listen_used_when_neither_cli_nor_config_set() {
        assert_eq!(
            resolve_listen_addr(None, ""),
            DEFAULT_LISTEN,
            "an empty config.json EndpointAddress must not disable REST for \
             `node start` (unlike `participate`, which treats that as an \
             opt-out) — it falls through to DEFAULT_LISTEN"
        );
    }

    // -------------------------------------------------------------------
    // The real `docker/localnet-rust/data/config.json` fixture must parse
    // cleanly via the same `Local::load_from_data_dir` mechanism `node
    // start` now calls, and its fields must be exactly what
    // docker/Dockerfile's `localnet` CMD / this test's expectations agree
    // on -- proving the file is a genuine input, not decoration.
    // -------------------------------------------------------------------

    #[test]
    fn docker_localnet_rust_config_json_loads_and_matches_expected_fields() {
        // CARGO_MANIFEST_DIR is `bin/algod-rust`; the fixture lives at the
        // repo root's `docker/localnet-rust/data/`.
        let data_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/localnet-rust/data");
        let cfg = algo_config::Local::load_from_data_dir(&data_dir)
            .expect("docker/localnet-rust/data/config.json must parse as a valid Local config");
        assert_eq!(cfg.endpoint_address, "0.0.0.0:8080");
        assert_eq!(cfg.dns_bootstrap_id, "");
        assert!(cfg.enable_developer_api);
    }

    // -------------------------------------------------------------------
    // `dns_bootstrap_unconsumed` — issue #779's disposition: `node start`
    // is REST-only by design and must warn (not silently ignore, and not
    // pretend to act on) a non-empty `DNSBootstrapID`, since it has no
    // gossip-protocol networking layer to resolve DNS-SRV bootstrap peers
    // for (unlike `participate`/`relay`, whose `Discovery`/`Phonebook`
    // machinery is the real consumer — issue #748).
    // -------------------------------------------------------------------

    #[test]
    fn dns_bootstrap_unconsumed_true_when_set() {
        assert!(
            dns_bootstrap_unconsumed("<network>.algorand.network"),
            "a non-empty DNSBootstrapID must be flagged as unconsumed — node start has \
             no networking layer to act on it"
        );
    }

    #[test]
    fn dns_bootstrap_unconsumed_false_when_unset() {
        assert!(
            !dns_bootstrap_unconsumed(""),
            "an empty (unset) DNSBootstrapID — the stock docker/localnet-rust/data/config.json \
             default — must not trigger a warning; there is nothing to ignore"
        );
    }

    #[test]
    fn resolve_listen_addr_matches_docker_config_when_no_cli_override() {
        // Pins that, absent a --listen flag, `node start` would resolve to
        // exactly the address docker/Dockerfile's `localnet` CMD passes
        // explicitly via `-l 0.0.0.0:8080` — i.e. the CLI flag and the
        // config.json file agree, so keeping both (rather than dropping
        // one) is a no-op precedence-wise, just an explicit-override
        // safety net matching go-algorand's own CLI-overrides-config.json
        // precedent.
        let data_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/localnet-rust/data");
        let cfg = algo_config::Local::load_from_data_dir(&data_dir).expect("loads");
        assert_eq!(
            resolve_listen_addr(None, &cfg.endpoint_address),
            "0.0.0.0:8080"
        );
        assert_eq!(
            resolve_listen_addr(Some("0.0.0.0:8080"), &cfg.endpoint_address),
            "0.0.0.0:8080"
        );
    }

    // -------------------------------------------------------------------
    // `follower_devmode_warning_needed` — issue #951's `TestDevModeWarning`
    // (`node/follower_node_test.go#L125`) equivalent: go's `MakeFollower`
    // logs "Follower running on a devMode network. Must submit txns to a
    // different node." whenever a real follower node's own genesis is
    // dev-mode, regardless of anything about the peer it follows.
    // -------------------------------------------------------------------

    #[test]
    fn follower_devmode_warning_needed_when_following_devmode_genesis() {
        assert!(
            follower_devmode_warning_needed(true, true),
            "a follower node running against its own dev-mode genesis must warn, \
             matching go's MakeFollower"
        );
    }

    #[test]
    fn follower_devmode_warning_not_needed_when_not_following() {
        assert!(
            !follower_devmode_warning_needed(false, true),
            "plain `node start` (not `--follow`) is never a real follower node in \
             go's sense, so this warning does not apply to it even with a dev-mode genesis"
        );
    }

    #[test]
    fn follower_devmode_warning_not_needed_for_non_devmode_genesis() {
        assert!(
            !follower_devmode_warning_needed(true, false),
            "a follower node against a non-dev-mode genesis must not warn"
        );
    }
}
