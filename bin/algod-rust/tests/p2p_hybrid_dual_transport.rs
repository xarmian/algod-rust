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

//! Three-real-process proof that `--enable-p2p --enable-p2p-hybrid-mode`
//! (go: `EnableP2PHybridMode`) actually runs the classic WS-gossip stack and
//! the libp2p P2P stack *simultaneously* for one `algod-rust participate`
//! process, and that both transports carry real, live traffic for it — the
//! last remaining gap this session's `docs/phase17/parity_daemon_node.md`
//! row for go-algorand's `TestNodeHybridTopology`
//! (`../go-algorand/node/node_test.go:919`) called out:
//! "the additional `EnableP2PHybridMode` dual-transport wiring on top of
//! [the DHT-auto-dial mesh-discovery piece landed by issue #1073] (the
//! hybrid half of this specific test's topology) remains unexercised".
//!
//! ## Topology
//!
//! One hybrid leader `h`, two single-transport followers:
//!
//! ```text
//!         WS-gossip              libp2p P2P
//!   o_ws <----------- h -----------------> o_p2p
//! ```
//!
//! - `h` holds 100% of genesis online stake plus a real, freshly generated
//!   VRF + one-time-signature participation key and runs
//!   `--enable-p2p --enable-p2p-hybrid-mode` with both a WS listen address
//!   (`--listen-address`) and a P2P listen address (`--p2p-listen-address`)
//!   open at once — `NetworkMode::Hybrid` per `p2p_transport.rs`'s
//!   `hybrid_runs_both` unit test, exercised here for the first time across
//!   real child processes. Because it holds all online stake, real Algorand
//!   sortition selects it into essentially every committee, so it proposes,
//!   votes, and certifies real blocks by itself.
//! - `o_ws` is a plain WS-gossip-only follower (`NetworkMode::WsOnly`, no
//!   `--enable-p2p` at all), peered at `h`'s WS gossip address
//!   (`--peers`). It has no participation key, so its only way to advance
//!   is `participate.rs`'s `GossipBlockFetcher` catchup path over the WS
//!   transport.
//! - `o_p2p` is a plain P2P-only follower (`--enable-p2p`, no hybrid mode,
//!   `NetworkMode::P2pOnly`), dialing `h`'s P2P multiaddr directly
//!   (`--p2p-bootstrap-peers`). It has no participation key either, so its
//!   only way to advance is `P2pBlockFetcher`'s catchup path over the
//!   libp2p transport.
//!
//! ## What this proves
//!
//! `h`'s single `participate` process serves real, independently-verified
//! catchup traffic to `o_ws` purely over WS gossip and to `o_p2p` purely
//! over the libp2p P2P transport, at the same time, from the same running
//! node — the concrete, testable meaning of "hybrid mode's dual-transport
//! wiring exercised end-to-end in a real multi-process scenario". The test
//! asserts all three nodes agree on the same round's block hash.
//!
//! ## What this intentionally does not cover
//!
//! This is deliberately *not* a literal reproduction of go's
//! `TestNodeHybridTopology` `N -- R -- A` topology, which additionally
//! requires: a relay `R` with block-serving disabled so `N` is forced to
//! *discover* `A` purely via the DHT (rather than being told `A`'s address
//! directly, as `o_ws`/`o_p2p` are told `h`'s addresses here), and all three
//! nodes running hybrid mode rather than one hybrid node plus two
//! single-transport observers. Composing DHT-driven discovery (issue #1073,
//! proven in `p2p_dht_mesh_discovery.rs`) with a *second* hybrid node behind
//! a relay is a materially larger harness (four-plus processes, a
//! block-service-disabled relay, and DHT propagation timing on top of
//! hybrid dual-transport startup) and was not attempted in this pass. What
//! this file closes is the specific, narrower gap the parity doc's own note
//! named as still unexercised: hybrid mode's dual-transport wiring itself,
//! proven with real traffic on both sides.
//!
//! ## Running
//!
//! ```text
//! cargo test --package algod-rust --test p2p_hybrid_dual_transport \
//!   -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` for the same reason every other file in this family is: real
//! child processes, real BFT agreement, tens of seconds of wall clock.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_ledger::participation::{Participation, ParticipationStore};
use algo_p2p::{get_or_create_keypair, IdentityConfig};
use algo_types::{Address, Round};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GENESIS_ID: &str = "v1";
const NETWORK_NAME: &str = "algod-rust-hybrid-dual-transport-test";
/// Same fixed fee-sink / rewards-pool addresses the sibling harnesses use.
const FEE_SINK_ADDR: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";
const REWARDS_POOL_ADDR: &str = "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM";
const STAKE_ACCOUNT_ALGOS: u64 = 10_000_000_000_000;
const REWARDS_POOL_ALGOS: u64 = 100_000_000_000;

// ---------------------------------------------------------------------------
// Genesis + participation-key construction (pure Rust, no go-algorand)
// ---------------------------------------------------------------------------

struct OnlineGenesis {
    genesis_json: String,
    stake_address: Address,
    participation: Participation,
}

fn build_online_genesis() -> OnlineGenesis {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let stake_address = Address(sk.verifying_key().to_bytes());

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

    let genesis = serde_json::json!({
        "network": NETWORK_NAME,
        "id": GENESIS_ID,
        "proto": algo_types::consensus::CONSENSUS_V41,
        "fees": FEE_SINK_ADDR,
        "rwd": REWARDS_POOL_ADDR,
        "alloc": [
            {
                "addr": stake_address.to_string(),
                "comment": "stake",
                "state": {
                    "algo": STAKE_ACCOUNT_ALGOS,
                    "onl": 1,
                    "sel": vrf_pk_b64,
                    "vote": vote_id_b64,
                    "voteKD": participation.key_dilution,
                    "voteFst": first_valid.0,
                    "voteLst": last_valid.0,
                }
            },
            {
                "addr": FEE_SINK_ADDR,
                "comment": "FeeSink",
                "state": { "algo": 0, "onl": 0 }
            },
            {
                "addr": REWARDS_POOL_ADDR,
                "comment": "RewardsPool",
                "state": { "algo": REWARDS_POOL_ALGOS, "onl": 0 }
            },
        ],
    });

    OnlineGenesis {
        genesis_json: serde_json::to_string_pretty(&genesis).expect("encode genesis.json"),
        stake_address,
        participation,
    }
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Bind a loopback socket on port 0, capture the OS-assigned port, and
/// release it. Small race window where another process could take it,
/// acceptable for an ignored integration test — same approach every sibling
/// harness in this directory uses.
fn alloc_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind on loopback");
    listener.local_addr().expect("local_addr").port()
}

// ---------------------------------------------------------------------------
// P2P identity pre-generation
// ---------------------------------------------------------------------------

/// Pre-generate a libp2p identity and persist it to `<data_dir>/
/// peerIDPrivKey.key` so this test knows `h`'s `PeerId` before it ever
/// starts — needed to build `o_p2p`'s `--p2p-bootstrap-peers` multiaddr.
fn pregenerate_p2p_identity(data_dir: &Path) -> PeerId {
    let cfg = IdentityConfig {
        private_key_path: None,
        data_dir: Some(data_dir.to_path_buf()),
        persist_peer_id: true,
    };
    let keypair = get_or_create_keypair(&cfg).expect("generate + persist P2P identity");
    keypair.public().to_peer_id()
}

fn p2p_multiaddr(port: u16, peer_id: PeerId) -> Multiaddr {
    let mut addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}")
        .parse()
        .expect("valid multiaddr");
    addr.push(Protocol::P2p(peer_id));
    addr
}

// ---------------------------------------------------------------------------
// Child process lifecycle
// ---------------------------------------------------------------------------

struct NodeProcess {
    child: Child,
    _data_dir: Option<TempDir>,
    rest_addr: String,
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

/// What kind of node to spawn — which transport it runs and how it
/// reaches `h`, the hybrid leader. `h` itself is spawned by
/// [`spawn_hybrid_leader_with_identity`] instead, since its P2P identity
/// must be pre-generated and reused (see that function's doc comment).
enum Role {
    /// `o_ws`: WS-gossip only, dials `h` at `peer_ws_addr`.
    WsOnlyFollower { peer_ws_addr: String },
    /// `o_p2p`: libp2p P2P only, dials `h` at `peer_multiaddr`.
    P2pOnlyFollower { peer_multiaddr: Multiaddr },
}

/// Spawn one `algod-rust participate` child process per [`Role`]. See this
/// file's module doc comment for the overall topology.
fn spawn_node(rest_port: u16, genesis_json: &str, role: Role) -> NodeProcess {
    let data_dir = tempfile::Builder::new()
        .prefix("algod-rust-hybrid-node-")
        .tempdir()
        .expect("tempdir");
    let data_dir_path = data_dir.path().to_path_buf();

    let genesis_path = data_dir_path.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis.json");

    let ledger_path = data_dir_path.join("ledger.sqlite");
    let partkey_path = data_dir_path.join("partkey.sqlite");

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
        .arg("--rest-listen")
        .arg(&rest_addr)
        .arg("--data-dir")
        .arg(&data_dir_path);

    match role {
        Role::WsOnlyFollower { peer_ws_addr } => {
            std::fs::File::create(&partkey_path).expect("create empty partkey file");
            cmd.arg("--peers").arg(peer_ws_addr);
        }
        Role::P2pOnlyFollower { peer_multiaddr } => {
            std::fs::File::create(&partkey_path).expect("create empty partkey file");
            cmd.arg("--enable-p2p")
                .arg("--p2p-persist-peer-id")
                .arg("--p2p-bootstrap-peers")
                .arg(peer_multiaddr.to_string());
        }
    }

    cmd.env(
        "RUST_LOG",
        std::env::var("MULTINODE_RUST_LOG").unwrap_or_else(|_| "warn".to_string()),
    );

    let log_path = data_dir_path.join("algod.stderr.log");
    let log_file = std::fs::File::create(&log_path).expect("create log file");
    let log_file_dup = log_file.try_clone().expect("clone log fd");
    cmd.stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_dup));

    let child = cmd.spawn().expect("spawn algod-rust participate");

    let keep_dirs = std::env::var("P2P_TEST_KEEP_DIRS").is_ok();
    let owned_dir = if keep_dirs {
        let _ = data_dir.keep();
        None
    } else {
        Some(data_dir)
    };

    NodeProcess {
        child,
        _data_dir: owned_dir,
        rest_addr,
        data_dir_path,
    }
}

// ---------------------------------------------------------------------------
// REST client helpers (same shape as the sibling harnesses)
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
    let path = data_dir.join("algod.token");
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

fn dump_node_logs(node: &NodeProcess, label: &str) {
    let log_path = node.data_dir_path.join("algod.stderr.log");
    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(150);
    eprintln!(
        "=== hybrid-topology node {label} log tail ({} lines @ {}) ===\n{}",
        lines.len() - start,
        log_path.display(),
        lines[start..].join("\n"),
    );
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Node `h` runs `--enable-p2p --enable-p2p-hybrid-mode` with 100% of
/// genesis online stake, producing real, agreement-certified blocks over
/// both transports at once. `o_ws` (WS-gossip only) and `o_p2p` (libp2p P2P
/// only) each dial `h` directly on their own transport and catch up with no
/// chain history of their own. All three must agree on the same round's
/// block hash — proving `h`'s hybrid dual-transport wiring
/// (`bin/algod-rust/src/commands/dual_gossip_node.rs`,
/// `bin/algod-rust/src/commands/participate.rs`'s `FallbackBlockFetcher`/
/// `NetworkMode::Hybrid` construction) carries real traffic on both sides at
/// once, closing the last gap left open by this session's `TestNodeP2PRelays`
/// work (issue #1073).
#[tokio::test]
#[ignore = "spawns three real algod-rust processes (one in hybrid WS+P2P mode) and runs \
            real BFT agreement; run with --ignored"]
async fn hybrid_leader_serves_both_a_ws_only_and_a_p2p_only_follower() {
    let online = build_online_genesis();

    let ws_port_h = alloc_loopback_port();
    let p2p_port_h = alloc_loopback_port();
    let rest_h = alloc_loopback_port();
    let rest_ws = alloc_loopback_port();
    let rest_p2p = alloc_loopback_port();

    // `h`'s P2P identity must be known before it starts, since `o_p2p`
    // dials it directly by multiaddr (no DHT discovery in this harness).
    // Pre-generate the identity directly into the directory that becomes
    // `h`'s own data dir (`spawn_hybrid_leader_with_identity` below reuses
    // it verbatim), so the child process's `--p2p-persist-peer-id` startup
    // loads this exact key instead of generating a fresh one.
    let identity_dir = tempfile::Builder::new()
        .prefix("algod-rust-hybrid-h-identity-")
        .tempdir()
        .expect("tempdir for h's pre-generated identity");
    let peer_id_h = pregenerate_p2p_identity(identity_dir.path());
    let multiaddr_h = p2p_multiaddr(p2p_port_h, peer_id_h);

    let mut h = spawn_hybrid_leader_with_identity(
        rest_h,
        &online.genesis_json,
        &online.participation,
        ws_port_h,
        p2p_port_h,
        identity_dir,
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(150);

    wait_for_rest_ready(&client, &h.rest_addr, overall_deadline).await;
    let token_h = read_api_token(&h.data_dir_path, overall_deadline).await;

    // Let `h`, running real agreement alone with 100% of online stake over
    // both transports, produce a handful of real certified rounds before
    // either follower joins.
    const TARGET_ROUND: u64 = 3;
    let round_h = wait_for_round(
        &client,
        &h.rest_addr,
        &token_h,
        TARGET_ROUND,
        overall_deadline,
        "h",
    )
    .await;

    let mut o_ws = spawn_node(
        rest_ws,
        &online.genesis_json,
        Role::WsOnlyFollower {
            peer_ws_addr: format!("127.0.0.1:{ws_port_h}"),
        },
    );
    let mut o_p2p = spawn_node(
        rest_p2p,
        &online.genesis_json,
        Role::P2pOnlyFollower {
            peer_multiaddr: multiaddr_h,
        },
    );

    wait_for_rest_ready(&client, &o_ws.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &o_p2p.rest_addr, overall_deadline).await;
    let token_ws = read_api_token(&o_ws.data_dir_path, overall_deadline).await;
    let token_p2p = read_api_token(&o_p2p.data_dir_path, overall_deadline).await;

    let round_ws = wait_for_round(
        &client,
        &o_ws.rest_addr,
        &token_ws,
        round_h,
        overall_deadline,
        "o_ws",
    )
    .await;
    let round_p2p = wait_for_round(
        &client,
        &o_p2p.rest_addr,
        &token_p2p,
        round_h,
        overall_deadline,
        "o_p2p",
    )
    .await;

    let compare_round = round_h.min(round_ws).min(round_p2p);
    let hash_h = get_block_hash(&client, &h.rest_addr, &token_h, compare_round).await;
    let hash_ws = get_block_hash(&client, &o_ws.rest_addr, &token_ws, compare_round).await;
    let hash_p2p = get_block_hash(&client, &o_p2p.rest_addr, &token_p2p, compare_round).await;

    if hash_h != hash_ws || hash_h != hash_p2p {
        dump_node_logs(&h, "h (hybrid leader)");
        dump_node_logs(&o_ws, "o_ws (WS-only follower)");
        dump_node_logs(&o_p2p, "o_p2p (P2P-only follower)");
    }
    o_p2p.shutdown();
    o_ws.shutdown();
    h.shutdown();

    assert_eq!(
        hash_h, hash_ws,
        "WS-only follower's synced block at round {compare_round} does not match hybrid leader's \
         (stake account {}) -- WS side of hybrid mode did not carry real traffic",
        online.stake_address
    );
    assert_eq!(
        hash_h, hash_p2p,
        "P2P-only follower's synced block at round {compare_round} does not match hybrid leader's \
         (stake account {}) -- P2P side of hybrid mode did not carry real traffic",
        online.stake_address
    );
}

/// Spawns `h` (the hybrid leader) reusing a data dir that already has a
/// pre-generated `peerIDPrivKey.key` in it, so this test's own
/// `pregenerate_p2p_identity` call and the child process end up agreeing on
/// the same `PeerId` (needed so `o_p2p`'s bootstrap multiaddr is valid
/// *before* `h` ever starts).
fn spawn_hybrid_leader_with_identity(
    rest_port: u16,
    genesis_json: &str,
    online_participation: &Participation,
    ws_listen_port: u16,
    p2p_listen_port: u16,
    identity_dir: TempDir,
) -> NodeProcess {
    let data_dir_path = identity_dir.path().to_path_buf();

    let genesis_path = data_dir_path.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis.json");

    // `EnableP2PHybridMode` requires a non-empty `PublicAddress`
    // (`algo_config::validate_p2p_hybrid_config`, go:
    // `ValidateP2PHybridConfig`) -- there is no CLI flag for it, only
    // `config.json`. Mirrors go's own `TestNodeHybridTopology`
    // `cfg.PublicAddress = ni.wsNetAddr()`.
    let config_path = data_dir_path.join("config.json");
    std::fs::write(
        &config_path,
        format!(r#"{{"PublicAddress": "127.0.0.1:{ws_listen_port}"}}"#),
    )
    .expect("write config.json with PublicAddress");

    let ledger_path = data_dir_path.join("ledger.sqlite");
    let partkey_path = data_dir_path.join("partkey.sqlite");
    let store = ParticipationStore::open(&partkey_path).expect("open partkey store");
    store
        .insert(online_participation)
        .expect("insert online participation key");

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
        .arg("--rest-listen")
        .arg(&rest_addr)
        .arg("--data-dir")
        .arg(&data_dir_path)
        .arg("--listen-address")
        .arg(format!("127.0.0.1:{ws_listen_port}"))
        .arg("--relay-messages")
        .arg("--enable-p2p")
        .arg("--enable-p2p-hybrid-mode")
        .arg("--p2p-persist-peer-id")
        .arg("--p2p-listen-address")
        .arg(format!("/ip4/127.0.0.1/tcp/{p2p_listen_port}"));

    cmd.env(
        "RUST_LOG",
        std::env::var("MULTINODE_RUST_LOG").unwrap_or_else(|_| "warn".to_string()),
    );

    let log_path = data_dir_path.join("algod.stderr.log");
    let log_file = std::fs::File::create(&log_path).expect("create log file");
    let log_file_dup = log_file.try_clone().expect("clone log fd");
    cmd.stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_dup));

    let child = cmd.spawn().expect("spawn algod-rust participate");

    let keep_dirs = std::env::var("P2P_TEST_KEEP_DIRS").is_ok();
    let owned_dir = if keep_dirs {
        let _ = identity_dir.keep();
        None
    } else {
        Some(identity_dir)
    };

    NodeProcess {
        child,
        _data_dir: owned_dir,
        rest_addr,
        data_dir_path,
    }
}
