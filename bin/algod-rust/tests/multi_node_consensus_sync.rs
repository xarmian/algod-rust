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

//! Two-binary, real-agreement, multi-node catchup harness (issue #827 theme
//! 4).
//!
//! `../go-algorand/node/node_test.go`'s `TestInitialSync` /
//! `TestSyncingFullNode` spin up several **in-process** `AlgorandFullNode`
//! objects (real agreement, real gossip, real block sync, all inside one Go
//! test binary) and assert that a node starting from genesis catches up to
//! the same block hashes as a node that has been producing blocks. That
//! exact shape doesn't transfer to algod-rust: there's no in-process
//! "full node" object analogous to Go's `AlgorandFullNode` -- `participate`
//! wires an owned `tokio` runtime, OS-level sockets, and a dedicated OS
//! thread for the agreement `Service`, so "several nodes in one test
//! process" would mean several of all of that colliding in one address
//! space.
//!
//! This test proves the same property -- a node that starts from genesis
//! with no chain history catches up to another node's real, agreement
//! produced block hashes over the classic WebSocket gossip transport -- by
//! spawning two real `algod-rust participate` **child processes** on
//! loopback, the same pattern `tx_propagation_two_binary.rs` already
//! established for tx-gossip. What's new here relative to that file is
//! that both nodes run **real agreement**, not just the tx-pool/gossip
//! layer:
//!
//! - Node A holds 100% of genesis online stake plus a freshly generated,
//!   real VRF + one-time-signature participation key (built directly via
//!   [`algo_ledger::participation`] -- no `goal`/go-algorand involved) and
//!   is started first as a relay. Because it holds all online stake, real
//!   Algorand sortition selects it into essentially every committee, so it
//!   can reach the soft/cert-vote supermajority alone and produce a chain
//!   of real, certified blocks by itself -- exactly the "single funded
//!   account" shape `goal network create` uses for a one-node private
//!   network, just assembled without `goal`.
//! - Node B starts from the *same* genesis.json (so its round-0 state
//!   matches node A's) but with an empty participation-key registry and is
//!   peered only at node A's gossip address. It never proposes or votes;
//!   its only way to advance is the catchup/`BlockService` fetch path.
//!
//! The test waits for node A to produce a few real rounds, waits for node B
//! to catch up to the same round, and then compares `GET
//! /v2/blocks/:round/hash` between the two nodes -- the algod-rust
//! equivalent of Go's `e0.Hash() == ei.Hash()` assertion.
//!
//! ## What this intentionally does not cover
//!
//! - P2P/libp2p transport, hybrid topology, or catchpoint-catchup mode --
//!   `TestNodeP2PRelays`, `TestNodeHybridTopology`, and
//!   `TestNodeSetCatchpointCatchupMode`'s scenarios are out of scope for
//!   this harness; see the issue #827 progress note for why those remain
//!   open.
//! - Multi-way partition/reconnect timing (`TestSyncingFullNode`'s
//!   mid-run `DisconnectPeers` / `RequestConnectOutgoing` dance) -- the
//!   2-node shape here proves the underlying catchup mechanism; a partition
//!   variant can be layered on top of this same harness later without a
//!   redesign.
//!
//! ## Running
//!
//! ```text
//! cargo test --package algod-rust --test multi_node_consensus_sync \
//!   -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` because it spawns two real child processes and waits for
//! several rounds of genuine BFT agreement (VRF sortition + soft/cert
//! voting) end to end -- tens of seconds of wall clock, not appropriate for
//! the default `cargo test --workspace` path.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_ledger::participation::{Participation, ParticipationStore};
use algo_types::{Address, Round};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GENESIS_ID: &str = "v1";
const NETWORK_NAME: &str = "algod-rust-sync-test";
/// Same fee-sink / rewards-pool addresses `docker/localnet-rust/data/genesis.json`
/// uses -- arbitrary fixed accounts, reused here purely so the literal
/// strings are already known-good rather than freshly derived.
const FEE_SINK_ADDR: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";
const REWARDS_POOL_ADDR: &str = "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM";
/// Genesis balance for the single online staking account. Large enough
/// that min-balance / fee bookkeeping never gets close to a floor.
const STAKE_ACCOUNT_ALGOS: u64 = 10_000_000_000_000;
const REWARDS_POOL_ALGOS: u64 = 100_000_000_000;

// ---------------------------------------------------------------------------
// Genesis + participation-key construction (pure Rust, no go-algorand)
// ---------------------------------------------------------------------------

/// A freshly generated online participation key plus the address it
/// belongs to, and the genesis.json text both nodes boot from.
struct OnlineGenesis {
    genesis_json: String,
    stake_address: Address,
    participation: Participation,
}

/// Build a genesis.json with one ONLINE staking account (real VRF +
/// one-time-signature public keys embedded in its `alloc[].state`, mirroring
/// what `goal network create` writes) plus the fee sink and rewards pool.
/// `devmode` is deliberately omitted (false) -- this must go through real
/// agreement, not the single-node dev-mode fast path.
fn build_online_genesis() -> OnlineGenesis {
    build_online_genesis_with_proto(algo_types::consensus::CONSENSUS_V41)
}

/// Same as [`build_online_genesis`], but with an explicit `proto` string --
/// used by the consensus-upgrade test below to boot from a custom,
/// `consensus.json`-defined protocol version instead of the real
/// [`algo_types::consensus::CONSENSUS_V41`].
fn build_online_genesis_with_proto(proto: &str) -> OnlineGenesis {
    // A fresh ed25519 keypair *is* the account's spending key; for a
    // pure genesis-stake account (never spends) only the address (public
    // key) bytes matter.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let stake_address = Address(sk.verifying_key().to_bytes());

    // Real VRF + one-time-signature participation key, generated the
    // same way `algokey part generate` / `FillDBWithParticipationKeys`
    // does. `key_lifetime = 0` skips state-proof (Falcon) key
    // generation entirely -- state proofs aren't needed for ordinary
    // agreement participation and skipping them keeps setup fast.
    let first_valid = Round(0);
    let last_valid = Round(10_000);
    let participation = Participation::generate(
        stake_address,
        first_valid,
        last_valid,
        /* key_dilution */ 0,
        /* key_lifetime */ 0,
    )
    .expect("generate online participation key");

    let vrf_pk_b64 = BASE64_STANDARD.encode(participation.vrf_pubkey().0);
    let vote_id_b64 = BASE64_STANDARD.encode(participation.voting.verifier());

    let genesis_json = format!(
        r#"{{
  "network": "{network}",
  "id": "{id}",
  "proto": "{proto}",
  "fees": "{fee_sink}",
  "rwd": "{rewards_pool}",
  "alloc": [
    {{
      "addr": "{stake_addr}",
      "comment": "stake",
      "state": {{
        "algo": {stake_algos},
        "onl": 1,
        "sel": "{sel}",
        "vote": "{vote}",
        "voteKD": {vote_kd},
        "voteFst": {vote_fst},
        "voteLst": {vote_lst}
      }}
    }},
    {{
      "addr": "{fee_sink}",
      "comment": "FeeSink",
      "state": {{ "algo": 0, "onl": 0 }}
    }},
    {{
      "addr": "{rewards_pool}",
      "comment": "RewardsPool",
      "state": {{ "algo": {rewards_algos}, "onl": 0 }}
    }}
  ]
}}"#,
        network = NETWORK_NAME,
        id = GENESIS_ID,
        proto = proto,
        fee_sink = FEE_SINK_ADDR,
        rewards_pool = REWARDS_POOL_ADDR,
        stake_addr = stake_address,
        stake_algos = STAKE_ACCOUNT_ALGOS,
        sel = vrf_pk_b64,
        vote = vote_id_b64,
        vote_kd = participation.key_dilution,
        vote_fst = first_valid.0,
        vote_lst = last_valid.0,
        rewards_algos = REWARDS_POOL_ALGOS,
    );

    OnlineGenesis {
        genesis_json,
        stake_address,
        participation,
    }
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Bind a loopback socket on port 0, capture the OS-assigned port, and
/// release it. Small race window where another process could take it,
/// acceptable for an ignored integration test.
fn alloc_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind on loopback");
    listener.local_addr().expect("local_addr").port()
}

// ---------------------------------------------------------------------------
// Child process lifecycle
// ---------------------------------------------------------------------------

struct NodeProcess {
    child: Child,
    _data_dir: TempDir,
    rest_addr: String,
    gossip_addr: String,
    data_dir_path: PathBuf,
}

impl NodeProcess {
    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spawn one `algod-rust participate` child process with a fresh ledger
/// that bootstraps from `genesis_json`.
///
/// When `online_participation` is `Some`, the node's partkey registry is
/// pre-populated with that key (via [`ParticipationStore::insert`] --
/// the same bridge `participate --import-partkey` uses for go-algorand
/// `.partkey` files, just skipping the file round-trip since the key
/// already exists as a Rust value) and the node is started with
/// `--relay-messages` so peers can dial it. Otherwise the node starts
/// with an empty registry (never proposes/votes) and no `--peers`
/// unless `peer_gossip_addr` is given.
fn spawn_participate_node(
    gossip_port: u16,
    rest_port: u16,
    genesis_json: &str,
    online_participation: Option<&Participation>,
    peer_gossip_addr: Option<&str>,
) -> NodeProcess {
    spawn_participate_node_with_consensus_override(
        gossip_port,
        rest_port,
        genesis_json,
        online_participation,
        peer_gossip_addr,
        None,
    )
}

/// Same as [`spawn_participate_node`], but additionally writes
/// `consensus_override_json` (when given) to `<data_dir>/consensus.json`
/// before spawning -- `participate` loads and merges that file onto the
/// built-in consensus table at startup (issue #814/PR #933), which is what
/// lets a private network like this one run a custom, non-`CONSENSUS_V41`
/// protocol (e.g. the `TestSimpleUpgrade`-equivalent test below).
fn spawn_participate_node_with_consensus_override(
    gossip_port: u16,
    rest_port: u16,
    genesis_json: &str,
    online_participation: Option<&Participation>,
    peer_gossip_addr: Option<&str>,
    consensus_override_json: Option<&str>,
) -> NodeProcess {
    spawn_participate_node_full(
        gossip_port,
        rest_port,
        genesis_json,
        online_participation,
        peer_gossip_addr,
        consensus_override_json,
        None,
        None,
    )
}

/// Full-generality node spawn used by every helper above plus the live
/// catchpoint-catchup test below: additionally writes `config_json` (when
/// given) to `<data_dir>/config.json` -- e.g. to enable automatic
/// interval-driven catchpoint export/serving (issue #770/#955) -- and, when
/// `catchup_peer` is given (`(rest_url, token)`), passes `--catchup-peer`/
/// `--catchup-peer-token` so this node's `NodeInterface::start_catchup`
/// (issue #940) can fetch a live catchpoint-catchup from that peer instead
/// of `NotImplemented`.
#[allow(clippy::too_many_arguments)]
fn spawn_participate_node_full(
    gossip_port: u16,
    rest_port: u16,
    genesis_json: &str,
    online_participation: Option<&Participation>,
    peer_gossip_addr: Option<&str>,
    consensus_override_json: Option<&str>,
    config_json: Option<&str>,
    catchup_peer: Option<(&str, &str)>,
) -> NodeProcess {
    let data_dir = tempfile::Builder::new()
        .prefix("algod-rust-multinode-")
        .tempdir()
        .expect("tempdir");
    let data_dir_path = data_dir.path().to_path_buf();

    let genesis_path = data_dir_path.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis.json");

    if let Some(overrides) = consensus_override_json {
        std::fs::write(data_dir_path.join("consensus.json"), overrides)
            .expect("write consensus.json");
    }
    if let Some(config) = config_json {
        std::fs::write(data_dir_path.join("config.json"), config).expect("write config.json");
    }

    let ledger_path = data_dir_path.join("ledger.sqlite");
    let partkey_path = data_dir_path.join("partkey.sqlite");

    if let Some(participation) = online_participation {
        let store = ParticipationStore::open(&partkey_path).expect("open partkey store");
        store
            .insert(participation)
            .expect("insert online participation key");
    } else {
        // Touch so the path exists; ParticipationStore::open (inside the
        // child) creates the schema on an empty file too, but creating
        // it here keeps the two code paths symmetric.
        std::fs::File::create(&partkey_path).expect("create empty partkey file");
    }

    let gossip_addr = format!("127.0.0.1:{gossip_port}");
    let rest_addr = format!("127.0.0.1:{rest_port}");

    let bin = env!("CARGO_BIN_EXE_algod-rust");
    let mut cmd = Command::new(bin);
    cmd.arg("participate")
        .arg("--ledger-path")
        .arg(&ledger_path)
        .arg("--partkey-path")
        .arg(&partkey_path)
        .arg("--genesis-id")
        .arg(GENESIS_ID)
        .arg("--network")
        .arg("custom")
        .arg("--genesis-json")
        .arg(&genesis_path)
        .arg("--genesis-path")
        .arg(&genesis_path)
        .arg("--listen-address")
        .arg(&gossip_addr)
        .arg("--rest-listen")
        .arg(&rest_addr)
        .arg("--data-dir")
        .arg(&data_dir_path)
        .env(
            "RUST_LOG",
            std::env::var("MULTINODE_RUST_LOG").unwrap_or_else(|_| "warn".to_string()),
        );
    if online_participation.is_some() {
        cmd.arg("--relay-messages");
    }
    if let Some(peer) = peer_gossip_addr {
        cmd.arg("--peers").arg(peer);
    }
    if let Some((url, token)) = catchup_peer {
        cmd.arg("--catchup-peer")
            .arg(url)
            .arg("--catchup-peer-token")
            .arg(token);
    }

    let log_path = data_dir_path.join("algod.stderr.log");
    let log_file = std::fs::File::create(&log_path).expect("create log file");
    let log_file_dup = log_file.try_clone().expect("clone log fd");
    cmd.stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_dup));

    let child = cmd.spawn().expect("spawn algod-rust participate");

    NodeProcess {
        child,
        _data_dir: data_dir,
        rest_addr,
        gossip_addr,
        data_dir_path,
    }
}

// ---------------------------------------------------------------------------
// REST client helpers
// ---------------------------------------------------------------------------

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
}

async fn wait_for_rest_ready(client: &reqwest::Client, rest_addr: &str, deadline: Instant) {
    let url = format!("http://{rest_addr}/health");
    let mut last_err: Option<String> = None;
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) => last_err = Some(format!("HTTP {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!(
        "REST API at {rest_addr} did not become ready before deadline; last error: {last_err:?}"
    );
}

async fn read_api_token(data_dir: &Path, deadline: Instant) -> String {
    read_token_file(data_dir, "algod.token", deadline).await
}

/// Same as [`read_api_token`], but for `algod.admin.token` -- the
/// `POST`/`DELETE /v2/catchup/:catchpoint` routes are registered in the
/// admin-only tier (`crates/node/algo-rest-api/src/router.rs`), so a live
/// catchpoint-catchup request must authenticate with this token, not the
/// ordinary API one.
async fn read_admin_token(data_dir: &Path, deadline: Instant) -> String {
    read_token_file(data_dir, "algod.admin.token", deadline).await
}

async fn read_token_file(data_dir: &Path, filename: &str, deadline: Instant) -> String {
    let path = data_dir.join(filename);
    loop {
        if let Ok(buf) = tokio::fs::read_to_string(&path).await {
            let trimmed = buf.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        if Instant::now() >= deadline {
            panic!("failed to read {} before deadline", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Poll `GET /v2/status` until `last-round >= min_round`, or panic at
/// `deadline`. Returns the observed round.
async fn wait_for_round(
    client: &reqwest::Client,
    rest_addr: &str,
    token: &str,
    min_round: u64,
    deadline: Instant,
    label: &str,
) -> u64 {
    let url = format!("http://{rest_addr}/v2/status");
    let mut last_round = None;
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(&url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(r) = body.get("last-round").and_then(|v| v.as_u64()) {
                        last_round = Some(r);
                        if r >= min_round {
                            return r;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "{label}: last-round did not reach {min_round} before deadline (last observed: {last_round:?})"
    );
}

/// Read the current consensus protocol version this node's *latest applied
/// block* is on, via `GET /v2/status`'s `last-version` field (populated from
/// the latest block header's `current_protocol` --
/// `bin/algod-rust/src/node_interface_impl.rs`'s `status()`).
async fn get_last_version(client: &reqwest::Client, rest_addr: &str, token: &str) -> String {
    let url = format!("http://{rest_addr}/v2/status");
    let resp = client
        .get(&url)
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("GET {url} returned {status} with non-JSON body: {e}"));
    assert!(status.is_success(), "GET {url} returned {status}: {body}");
    body.get("last-version")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("GET {url} response missing last-version: {body}"))
        .to_string()
}

/// Read `block.proto` (the `CurrentProtocol` this specific round was
/// produced under) via `GET /v2/blocks/:round?format=json`. Unlike
/// [`get_last_version`] (which only ever reflects the *latest* round), this
/// lets the test inspect the protocol a specific already-applied round --
/// e.g. genesis (round 0) -- ran under, even after later rounds have moved
/// on to a newer protocol.
async fn get_block_protocol(
    client: &reqwest::Client,
    rest_addr: &str,
    token: &str,
    round: u64,
) -> String {
    let url = format!("http://{rest_addr}/v2/blocks/{round}?format=json");
    let resp = client
        .get(&url)
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("GET {url} returned {status} with non-JSON body: {e}"));
    assert!(status.is_success(), "GET {url} returned {status}: {body}");
    body.get("block")
        .and_then(|b| b.get("proto"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("GET {url} response missing block.proto: {body}"))
        .to_string()
}

/// Build a `<data_dir>/consensus.json` override defining two custom protocol
/// versions, `test0` and `test1`, mirroring go-algorand's `TestSimpleUpgrade`
/// (`node/node_test.go`): `test0` is a full copy of the real `future`
/// consensus params (`docker/config/vfuture-consensus.json`) with a fast,
/// low-threshold upgrade path (`ApprovedUpgrades: {"test1": 0}`,
/// `UpgradeVoteRounds: 2`, `UpgradeThreshold: 1`, `DefaultUpgradeWaitRounds:
/// 2`) that proposes and approves switching to `test1` in its very first
/// block; `test1` is the same base params with a slower vote/threshold of
/// its own (unused here -- it has no further `ApprovedUpgrades`) so a node
/// that reaches it stops proposing.
///
/// Reusing the real `future` params as the base (rather than hand-rolling a
/// minimal one) keeps every non-upgrade-related field -- committee sizes,
/// agreement timeouts, fees -- at real, already-proven-to-work values (the
/// same base this repo's `participate_consensus_override_test.rs` uses for
/// its own consensus.json override).
fn build_simple_upgrade_consensus_override() -> String {
    const FIXTURE: &str = include_str!("../../../docker/config/vfuture-consensus.json");
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE)
        .expect("docker/config/vfuture-consensus.json must be valid JSON");
    let template = fixture
        .get("future")
        .expect("vfuture-consensus.json must define \"future\"")
        .clone();

    let mut test0 = template.clone();
    test0["UpgradeVoteRounds"] = serde_json::json!(2);
    test0["UpgradeThreshold"] = serde_json::json!(1);
    test0["DefaultUpgradeWaitRounds"] = serde_json::json!(2);
    test0["MinUpgradeWaitRounds"] = serde_json::json!(0);
    test0["MaxVersionStringLen"] = serde_json::json!(64);
    test0["MaxTxnBytesPerBlock"] = serde_json::json!(1_000_000u64);
    test0["DefaultKeyDilution"] = serde_json::json!(10_000);
    test0["SupportGenesisHash"] = serde_json::json!(false);
    test0["ApprovedUpgrades"] = serde_json::json!({ "test1": 0 });

    let mut test1 = template;
    test1["UpgradeVoteRounds"] = serde_json::json!(10);
    test1["UpgradeThreshold"] = serde_json::json!(8);
    test1["DefaultUpgradeWaitRounds"] = serde_json::json!(10);
    test1["MinUpgradeWaitRounds"] = serde_json::json!(0);
    test1["MaxVersionStringLen"] = serde_json::json!(64);
    test1["MaxTxnBytesPerBlock"] = serde_json::json!(1_000_000u64);
    test1["DefaultKeyDilution"] = serde_json::json!(10_000);
    test1["SupportGenesisHash"] = serde_json::json!(false);
    test1["ApprovedUpgrades"] = serde_json::json!({});

    let overrides = serde_json::json!({ "test0": test0, "test1": test1 });
    serde_json::to_string_pretty(&overrides).expect("encode consensus.json override")
}

async fn get_block_hash(
    client: &reqwest::Client,
    rest_addr: &str,
    token: &str,
    round: u64,
) -> String {
    let url = format!("http://{rest_addr}/v2/blocks/{round}/hash");
    let resp = client
        .get(&url)
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("GET {url} returned {status} with non-JSON body: {e}"));
    assert!(status.is_success(), "GET {url} returned {status}: {body}");
    body.get("blockHash")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("GET {url} response missing blockHash: {body}"))
        .to_string()
}

/// Poll `GET /v2/status` until `last-catchpoint` is non-empty (a real
/// automatic catchpoint export has completed and been persisted to the
/// ledger's `catchpointstate` table -- issue #824 theme 6), or panic at
/// `deadline`. Returns the observed label (`"<round>#<hash>"`).
///
/// The label lags the round it was generated for: `SqliteLedger`'s
/// automatic-export worker thread is only joined (persisting the label)
/// either at the *next* interval boundary or at graceful shutdown (see
/// `configure_automatic_catchpoints`'s doc comment) -- so this must be
/// polled well past the target export round, not right at it.
async fn wait_for_last_catchpoint(
    client: &reqwest::Client,
    rest_addr: &str,
    token: &str,
    deadline: Instant,
    label: &str,
) -> String {
    let url = format!("http://{rest_addr}/v2/status");
    loop {
        if let Ok(resp) = client
            .get(&url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(lc) = body.get("last-catchpoint").and_then(|v| v.as_str()) {
                        if !lc.is_empty() {
                            return lc.to_string();
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("{label}: last-catchpoint did not become non-empty before deadline");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// `POST /v2/catchup/:catchpoint` against `rest_addr`, mirroring go's
/// `Handlers.StartCatchup` -- the admin-tier route
/// (`crates/node/algo-rest-api/src/router.rs`), so `admin_token` (not the
/// ordinary API token) is required. The `#` in `catchpoint` must be
/// percent-encoded (`%23`) since it's otherwise a URL-fragment delimiter.
async fn start_catchup(
    client: &reqwest::Client,
    rest_addr: &str,
    admin_token: &str,
    catchpoint: &str,
) {
    let encoded = catchpoint.replace('#', "%23");
    let url = format!("http://{rest_addr}/v2/catchup/{encoded}");
    let resp = client
        .post(&url)
        .header("X-Algo-API-Token", admin_token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {url} failed: {e}"));
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "POST {url} returned {status}: {body}");
}

/// Poll `GET /v2/status` until the in-flight `catchpoint` field goes back
/// to empty (the live catchup finished, successfully or not), or panic at
/// `deadline`.
async fn wait_for_catchup_to_finish(
    client: &reqwest::Client,
    rest_addr: &str,
    token: &str,
    deadline: Instant,
) {
    let url = format!("http://{rest_addr}/v2/status");
    loop {
        if let Ok(resp) = client
            .get(&url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let in_progress = body
                        .get("catchpoint")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    if !in_progress {
                        return;
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("live catchpoint catchup did not finish before deadline");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn dump_node_logs(node: &NodeProcess, label: &str) {
    let log_path = node.data_dir_path.join("algod.stderr.log");
    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(80);
    eprintln!(
        "=== node {label} log tail ({} lines @ {}) ===\n{}",
        lines.len() - start,
        log_path.display(),
        lines[start..].join("\n"),
    );
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Node A produces real, agreement-certified blocks by itself (100% online
/// stake); node B starts from genesis with no chain history and syncs to
/// node A's blocks purely via the classic WebSocket gossip/catchup path.
/// Asserts node B's synced block hash matches node A's, the algod-rust
/// equivalent of go-algorand's `TestInitialSync`.
#[tokio::test]
#[ignore = "spawns child algod-rust processes and runs real BFT agreement; run with --ignored"]
async fn follower_node_initial_sync_matches_leader_block_hashes() {
    let online = build_online_genesis();

    let gossip_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let gossip_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let mut node_a = spawn_participate_node(
        gossip_a,
        rest_a,
        &online.genesis_json,
        Some(&online.participation),
        None,
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(150);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;

    // Let node A, running real agreement alone with 100% of online stake,
    // produce a handful of real certified rounds before node B joins.
    const TARGET_ROUND: u64 = 3;
    let round_a = wait_for_round(
        &client,
        &node_a.rest_addr,
        &token_a,
        TARGET_ROUND,
        overall_deadline,
        "node A",
    )
    .await;

    // Now bring up node B from the identical genesis, peered only at node
    // A, with no participation keys of its own -- it can only advance via
    // catchup/gossip block-fetch.
    let mut node_b = spawn_participate_node(
        gossip_b,
        rest_b,
        &online.genesis_json,
        None,
        Some(&node_a.gossip_addr),
    );

    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;

    let round_b = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        round_a,
        overall_deadline,
        "node B",
    )
    .await;

    // Compare a round both nodes definitely have (the lower of the two
    // observed rounds is always safe on both sides).
    let compare_round = round_a.min(round_b);
    let hash_a = get_block_hash(&client, &node_a.rest_addr, &token_a, compare_round).await;
    let hash_b = get_block_hash(&client, &node_b.rest_addr, &token_b, compare_round).await;

    if hash_a != hash_b {
        dump_node_logs(&node_a, "A");
        dump_node_logs(&node_b, "B");
    }
    node_b.shutdown();
    node_a.shutdown();

    assert_eq!(
        hash_a, hash_b,
        "node B's synced block at round {compare_round} does not match node A's \
         (stake account {})",
        online.stake_address
    );
}

/// The algod-rust equivalent of go-algorand's `TestSyncingFullNode`'s
/// steady-state shape (minus the mid-run `DisconnectPeers` drill): once a
/// follower node has done its initial catch-up, it keeps pace with the
/// leader as *further* rounds are produced -- not merely a one-shot replay
/// of history it already had queued up when it joined.
///
/// Joins node B to node A immediately (rather than after node A has a
/// head start, as in the initial-sync test above) and asserts B keeps
/// advancing in lockstep and matching block hashes across several
/// subsequent rounds, each verified independently.
#[tokio::test]
#[ignore = "spawns child algod-rust processes and runs real BFT agreement; run with --ignored"]
async fn follower_node_keeps_pace_with_leader_across_multiple_rounds() {
    let online = build_online_genesis();

    let gossip_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let gossip_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let mut node_a = spawn_participate_node(
        gossip_a,
        rest_a,
        &online.genesis_json,
        Some(&online.participation),
        None,
    );
    let mut node_b = spawn_participate_node(
        gossip_b,
        rest_b,
        &online.genesis_json,
        None,
        Some(&format!("127.0.0.1:{gossip_a}")),
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(180);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;

    // Check three successive checkpoints, each requiring node B to have
    // both advanced past the previous one *and* to agree with node A's
    // hash at that round -- proves ongoing lockstep, not just a single
    // successful catch-up.
    for checkpoint in [2u64, 4, 6] {
        let round_a = wait_for_round(
            &client,
            &node_a.rest_addr,
            &token_a,
            checkpoint,
            overall_deadline,
            "node A",
        )
        .await;
        let round_b = wait_for_round(
            &client,
            &node_b.rest_addr,
            &token_b,
            checkpoint,
            overall_deadline,
            "node B",
        )
        .await;

        let compare_round = round_a.min(round_b);
        let hash_a = get_block_hash(&client, &node_a.rest_addr, &token_a, compare_round).await;
        let hash_b = get_block_hash(&client, &node_b.rest_addr, &token_b, compare_round).await;

        if hash_a != hash_b {
            dump_node_logs(&node_a, "A");
            dump_node_logs(&node_b, "B");
            node_b.shutdown();
            node_a.shutdown();
            panic!(
                "node B diverged from node A at round {compare_round} (checkpoint {checkpoint})"
            );
        }
    }

    node_b.shutdown();
    node_a.shutdown();
}

/// The algod-rust equivalent of go-algorand's `TestSimpleUpgrade`
/// (`node/node_test.go`): a consensus-protocol-version upgrade happening
/// mid-chain, verifying that a leader (which proposes/certifies blocks) and
/// a follower (which only syncs them) both transition through it staying in
/// lockstep -- same block hashes at every round both have, genesis still on
/// the old protocol, later rounds on the new one.
///
/// Go's version spins up several in-process `AlgorandFullNode`s all voting
/// and certifying; this test reuses the same two-real-child-process shape as
/// the tests above (one node holding 100% of online stake self-certifies,
/// the other only catches up via gossip/`BlockService`), which is the
/// *upgrade-vote-counting* shape that actually matters here: with
/// `UpgradeThreshold: 1` (below), a single online, voting account is already
/// enough for `test0`'s automatic upgrade-proposal/approval machinery
/// (`crates/core/algo-ledger/src/block_header.rs`'s `process_upgrade_params`/
/// `apply_upgrade_vote`, ported from go's `ProcessUpgradeParams`) to reach
/// consensus on switching to `test1` -- go's own multi-wallet setup exists to
/// exercise `UpgradeThreshold` counting across several *independent* voters,
/// which this repo's committee/certificate-signing path already has
/// dedicated coverage for elsewhere (`block_header.rs`'s own upgrade-vote
/// unit tests). What this test adds on top, that a unit test cannot, is
/// proving the upgrade actually propagates end-to-end over the real gossip
/// wire to a second, non-voting process and that both processes' blocks
/// stay hash-identical across it.
#[tokio::test]
#[ignore = "spawns child algod-rust processes and runs real BFT agreement; run with --ignored"]
async fn two_nodes_stay_in_sync_through_consensus_protocol_upgrade() {
    const OLD_PROTOCOL: &str = "test0";
    const NEW_PROTOCOL: &str = "test1";

    let online = build_online_genesis_with_proto(OLD_PROTOCOL);
    let consensus_override = build_simple_upgrade_consensus_override();

    let gossip_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let gossip_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let mut node_a = spawn_participate_node_with_consensus_override(
        gossip_a,
        rest_a,
        &online.genesis_json,
        Some(&online.participation),
        None,
        Some(&consensus_override),
    );
    let mut node_b = spawn_participate_node_with_consensus_override(
        gossip_b,
        rest_b,
        &online.genesis_json,
        None,
        Some(&format!("127.0.0.1:{gossip_a}")),
        Some(&consensus_override),
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(300);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;

    // Genesis (round 0) must still be on the old protocol on both nodes --
    // matches go's `tests == 0` check that no upgrade has happened yet.
    let genesis_protocol_a = get_block_protocol(&client, &node_a.rest_addr, &token_a, 0).await;
    let genesis_protocol_b = get_block_protocol(&client, &node_b.rest_addr, &token_b, 0).await;
    assert_eq!(
        genesis_protocol_a, OLD_PROTOCOL,
        "node A's genesis block must be on the pre-upgrade protocol"
    );
    assert_eq!(
        genesis_protocol_b, OLD_PROTOCOL,
        "node B's genesis block must be on the pre-upgrade protocol"
    );

    // With `test0`'s UpgradeVoteRounds: 2 / UpgradeThreshold: 1 /
    // DefaultUpgradeWaitRounds: 2, the single online-stake account proposes
    // and approves the switch to `test1` in round 1's header, and the
    // switch takes effect at round 1 + 2 + 2 = 5
    // (`next_protocol_switch_on`). Round 12 leaves a wide margin past that.
    const TARGET_ROUND: u64 = 12;
    let round_a = wait_for_round(
        &client,
        &node_a.rest_addr,
        &token_a,
        TARGET_ROUND,
        overall_deadline,
        "node A",
    )
    .await;
    let round_b = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        TARGET_ROUND,
        overall_deadline,
        "node B",
    )
    .await;

    // Both nodes must have completed the same upgrade -- matches go's
    // `tests == maxRounds-1` check that every node ended up on the new
    // protocol.
    let last_version_a = get_last_version(&client, &node_a.rest_addr, &token_a).await;
    let last_version_b = get_last_version(&client, &node_b.rest_addr, &token_b).await;

    // Both nodes must agree on the block contents throughout the
    // transition, not just the protocol label -- matches go's per-round
    // `blocks[i].Hash()` comparison across every node.
    let compare_round = round_a.min(round_b);
    let hash_a = get_block_hash(&client, &node_a.rest_addr, &token_a, compare_round).await;
    let hash_b = get_block_hash(&client, &node_b.rest_addr, &token_b, compare_round).await;

    if hash_a != hash_b || last_version_a != NEW_PROTOCOL || last_version_b != NEW_PROTOCOL {
        dump_node_logs(&node_a, "A");
        dump_node_logs(&node_b, "B");
    }
    node_b.shutdown();
    node_a.shutdown();

    assert_eq!(
        last_version_a, NEW_PROTOCOL,
        "node A must have completed the upgrade to the new protocol by round {round_a}"
    );
    assert_eq!(
        last_version_b, NEW_PROTOCOL,
        "node B must have completed the upgrade to the new protocol by round {round_b}"
    );
    assert_eq!(
        hash_a, hash_b,
        "node B's synced block at round {compare_round} does not match node A's through the \
         protocol upgrade"
    );
}

/// The algod-rust equivalent of go-algorand's `TestNodeSetCatchpointCatchupMode`
/// (`node/node_test.go`) happy path: a real live catchpoint-catchup, end to
/// end, against a real self-generated catchpoint file -- closing the one
/// gap `docs/phase17/parity_daemon_node.md` flagged as "not verified" after
/// issues #937/#940 (issue #827 theme 4).
///
/// Node A runs with `CatchpointTracking: Stored`/a short `CatchpointInterval`
/// (issue #770's automatic export) and `EnableLedgerService` (issue #955's
/// catchpoint-tarball-serving endpoint), so it both generates and serves a
/// real catchpoint file entirely on its own, the same way `wsRelay`/
/// `hybridRelay` profile nodes do in production. Node B starts from the
/// *same* genesis with no chain history and, critically, is **not** peered
/// via gossip at all (no `--peers`) -- its only way to advance is the
/// explicit `POST /v2/catchup/:catchpoint` request this test issues against
/// it (`LiveCatchupManager::start_catchup`, issue #940's
/// `ParticipateAgreementControl` wiring), which fetches the catchpoint
/// tarball and replay blocks from node A over REST via
/// `--catchup-peer`/`--catchup-peer-token`.
///
/// Writing this test surfaced two real bugs, both fixed alongside it:
///
/// - `CatchpointService`'s HTTP router (`GET/HEAD /v1/{genesis_id}/ledger/{round}`)
///   was previously only ever mounted on the gossip network's own HTTP
///   listener (`gossip_node.register_http_handler`) -- a *different* port
///   from `--rest-listen`. Since `--catchup-peer` is documented as, and
///   `CatchpointDownloader` always fetches from, a REST URL, a live
///   catchpoint-catchup request against a real `--catchup-peer` 404'd
///   unconditionally, even against a peer that genuinely had the labeled
///   catchpoint file. Fixed by giving `ApiServer` a
///   `with_extra_router` builder (`crates/node/algo-rest-api/src/server.rs`)
///   that `participate` uses to merge `CatchpointService`'s router onto the
///   REST server too.
/// - `BlockHeader::round`'s `#[serde(rename = "rnd")]` field had no
///   `default`, so a genuine genesis (round 0) header -- whose `rnd` key is
///   correctly omitted by the canonical/omitempty encoder, since 0 is its
///   zero value like every other field on the struct -- failed to decode
///   generically ("missing field `rnd`"). This broke
///   `reconstruct_lease_table`'s post-catchpoint-import lookback-block
///   replay (`crates/core/algo-ledger/src/catchpoint/verify.rs`) whenever
///   the lookback window reached back to round 0, silently leaving the
///   catchup in a `Failed` state even though the catchpoint itself had
///   already been imported correctly. Fixed by adding `default` to that
///   field (`crates/core/algo-types/src/header.rs`), matching every other
///   zero-valued field's existing `default`/`skip_serializing_if` pairing.
#[tokio::test]
#[ignore = "spawns child algod-rust processes and runs real BFT agreement; run with --ignored"]
async fn follower_catches_up_via_live_catchpoint_catchup_from_a_real_catchpoint() {
    let online = build_online_genesis();

    let gossip_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let gossip_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    // Owned independently of either node's own `--data-dir` (itself a
    // throwaway `TempDir` created inside `spawn_participate_node_full`) --
    // any absolute directory node A can write to and node B's peer fetch
    // never needs to see directly (it always goes through node A's REST
    // `CatchpointService`, never the filesystem).
    let catchpoint_dir = tempfile::Builder::new()
        .prefix("algod-rust-catchpoint-dir-")
        .tempdir()
        .expect("tempdir for catchpoint export");
    std::fs::create_dir_all(catchpoint_dir.path()).expect("ensure catchpoint dir exists");

    // A short interval so a handful of real agreement rounds already
    // produces several catchpoints; `Stored` (2) forces `stores_catchpoints()`
    // to `true` unconditionally (go: `config.Local.StoresCatchpoints`),
    // independent of `Archival`.
    let config_a = serde_json::json!({
        "EnableLedgerService": true,
        "CatchpointDir": catchpoint_dir.path().to_string_lossy(),
        "CatchpointInterval": 2,
        "CatchpointTracking": 2,
    })
    .to_string();

    let mut node_a = spawn_participate_node_full(
        gossip_a,
        rest_a,
        &online.genesis_json,
        Some(&online.participation),
        None,
        None,
        Some(&config_a),
        None,
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(180);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;

    // Reach round 4 -- past the interval-2 boundary a second time, which is
    // what actually joins round 2's export thread and persists its label
    // (see `wait_for_last_catchpoint`'s doc comment). Comfortable margin
    // past the minimum needed.
    wait_for_round(
        &client,
        &node_a.rest_addr,
        &token_a,
        4,
        overall_deadline,
        "node A",
    )
    .await;
    let label = wait_for_last_catchpoint(
        &client,
        &node_a.rest_addr,
        &token_a,
        overall_deadline,
        "node A",
    )
    .await;
    let catchpoint_round: u64 = label
        .split('#')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("could not parse round out of catchpoint label {label:?}"));
    assert!(
        catchpoint_round > 0,
        "catchpoint label {label:?} must not be for genesis"
    );

    // Node B: same genesis, empty partkey registry, deliberately **not**
    // peered via gossip (`peer_gossip_addr: None`) -- if it advances at
    // all, it can only be via the explicit `start_catchup` call below, not
    // an incidental ordinary catchup path.
    let node_a_rest_url = format!("http://{}", node_a.rest_addr);
    let mut node_b = spawn_participate_node_full(
        gossip_b,
        rest_b,
        &online.genesis_json,
        None,
        None,
        None,
        None,
        Some((&node_a_rest_url, &token_a)),
    );

    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;
    let admin_token_b = read_admin_token(&node_b.data_dir_path, overall_deadline).await;

    // Confirm node B genuinely starts from genesis (round 0) -- the
    // catchup below is the *only* thing that can move it.
    let round_b_before = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        0,
        overall_deadline,
        "node B (pre-catchup)",
    )
    .await;
    assert_eq!(
        round_b_before, 0,
        "node B must start at round 0 -- it has no gossip peers to have caught up any other way"
    );

    start_catchup(&client, &node_b.rest_addr, &admin_token_b, &label).await;
    wait_for_catchup_to_finish(&client, &node_b.rest_addr, &token_b, overall_deadline).await;

    let round_b_after = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        catchpoint_round,
        overall_deadline,
        "node B (post-catchup)",
    )
    .await;

    let hash_a = get_block_hash(&client, &node_a.rest_addr, &token_a, catchpoint_round).await;
    let hash_b = get_block_hash(&client, &node_b.rest_addr, &token_b, catchpoint_round).await;

    if hash_a != hash_b {
        dump_node_logs(&node_a, "A");
        dump_node_logs(&node_b, "B");
    }
    node_b.shutdown();
    node_a.shutdown();

    assert_eq!(
        hash_a, hash_b,
        "node B's block at the catchpoint round {catchpoint_round} (reached at round \
         {round_b_after} via live catchpoint catchup) does not match node A's"
    );
}
