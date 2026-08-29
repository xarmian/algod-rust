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

    // Load `<data_dir>/consensus.json` (if present) and merge it onto the
    // built-in consensus table (issue #750; Go:
    // `PreloadConfigurableConsensusProtocols`, `config/config.go`). A missing
    // file falls back to the built-in table unchanged; a malformed file is a
    // real startup error rather than being silently ignored. This is the
    // node's "active protocol version" consensus-parameter resolution point
    // (the genesis protocol) -- the other ~57 call sites of
    // `consensus_params_for_version` throughout ledger/AVM/agreement remain
    // on the compile-time built-in table only; threading operator overrides
    // through every one of them is a materially larger architectural change
    // (go's own design keeps a single mutable package-level `Consensus` map
    // read everywhere) tracked separately rather than folded into this
    // startup wiring.
    let consensus_overrides_path =
        data_dir.join(algo_types::consensus::CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);
    let consensus_protocols =
        algo_types::consensus::preload_configurable_consensus_protocols(data_dir)
            .map_err(|e| anyhow::anyhow!("loading {}: {e}", consensus_overrides_path.display()))?;
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
    let mut node_interface = AlgodNodeInterface::new(ledger.clone(), node_config)
        .with_shutdown_token(shutdown_token.clone())
        .with_participation_store(part_store);
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
    // 4b. `--follow`: spawn a background task that syncs new blocks from a
    //     remote REST peer through the real sync path
    //     (`apply_block_caching_delta`, the same call `algod-rust sync`
    //     makes — see `commands/sync.rs`), while this process keeps serving
    //     its own REST API. This is what lets `GET /v2/deltas/{round}`
    //     be queried against a genuinely synced block, as opposed to
    //     `--dev` mode's self-produced-block path (which calls
    //     `cache_state_delta` directly and never exercises
    //     `apply_block_caching_delta` at all). Issue #612.
    // -----------------------------------------------------------------------
    let follow_handle = follow_url.map(|url| {
        let client: Arc<dyn algo_rest_client::BlockSource> =
            Arc::new(algo_rest_client::AlgodClient::new(url, follow_token));
        info!(peer = url, "follow mode enabled — syncing blocks from peer");
        let ledger = ledger.clone();
        let cancel = shutdown_token.clone();
        tokio::spawn(async move { run_follow_loop(ledger, client, cancel).await })
    });

    // -----------------------------------------------------------------------
    // 5. Run until Ctrl-C, then shut the server down gracefully.
    // -----------------------------------------------------------------------
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("failed to listen for Ctrl-C ({e}); shutting down");
    }
    info!("shutdown requested");
    shutdown_token.cancel();
    let _ = join_handle.await;
    if let Some(h) = follow_handle {
        let _ = h.await;
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
