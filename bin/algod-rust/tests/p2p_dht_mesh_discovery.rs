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

//! Three-real-process reproduction of go-algorand's `TestNodeP2PRelays`
//! topology (`../go-algorand/node/node_test.go`), proving issue #1073's
//! periodic DHT-driven mesh-discovery wiring
//! (`bin/algod-rust/src/commands/p2p_transport.rs`'s `P2pTransport::start`)
//! actually connects two real `algod-rust` processes that were never given
//! each other's multiaddr.
//!
//! ## Topology
//!
//! `R1 (DHT) -> R2 (phonebook) <- N`:
//!
//! - `r2` is the only bootstrap peer either `r1` or `n` is ever configured
//!   with (`--p2p-bootstrap-peers`). Neither `r1` nor `n` is ever given the
//!   other's multiaddr, or even `PeerId`, directly.
//! - `r1` is a P2P listen server (`--p2p-listen-address`), so
//!   `P2pTransport::start` advertises its `Gossip` capability on the DHT at
//!   startup (mirroring go's `node.Capabilities()`/`AdvertiseCapabilities`).
//! - `n` is the plain client: `P2pTransport::start`'s periodic
//!   mesh-discovery task (`DHT_MESH_REFRESH_INTERVAL`, ticking immediately
//!   on startup) looks up `Gossip`-capability peers via the DHT — routed
//!   through `r2`, the only peer `n` knows — discovers `r1`'s `PeerId`, and
//!   dials it automatically.
//!
//! ## What this proves
//!
//! `n`'s own outbound-peer list (`GET /v2/node/peers`, admin-token-gated)
//! ends up containing `r1`'s `PeerId`, even though `n` was never configured
//! with `r1`'s address. This is a direct, unambiguous connectivity check —
//! deliberately not inferred indirectly from block/gossip propagation (which
//! `r2` could relay for `n` regardless of whether `n` ever directly connects
//! to `r1`, and would prove nothing about this issue's specific auto-dial
//! wiring).
//!
//! No participation keys or online stake are used: this test only exercises
//! P2P connectivity, not agreement, so all three nodes run with empty
//! partkey registries against a minimal, no-online-stake genesis.
//!
//! ## Running
//!
//! ```text
//! cargo test --package algod-rust --test p2p_dht_mesh_discovery \
//!   -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` for the same reason `p2p_multi_node_consensus.rs` is: real
//! child processes and tens of seconds of wall clock (this test's own
//! deadline must comfortably exceed `DHT_MESH_REFRESH_INTERVAL`'s first
//! immediate tick plus real DHT provider-record propagation + closest-peers
//! address resolution across three real, independently-scheduled processes).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_p2p::{get_or_create_keypair, IdentityConfig};
use algo_types::Address;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GENESIS_ID: &str = "v1";
const NETWORK_NAME: &str = "algod-rust-p2p-dht-mesh-test";

// ---------------------------------------------------------------------------
// Minimal, no-online-stake genesis (connectivity-only test — no agreement)
// ---------------------------------------------------------------------------

fn build_genesis_json() -> String {
    // Arbitrary but valid fee-sink/rewards-pool addresses, matching the
    // pattern `node_serve_test.rs`'s `write_genesis` uses for a
    // non-agreement harness: no online accounts at all, since this test
    // only exercises P2P connectivity.
    let fees = Address([0xFE; 32]).to_algorand_string();
    let rwd = Address([0xFD; 32]).to_algorand_string();
    let genesis = serde_json::json!({
        "network": NETWORK_NAME,
        "id": GENESIS_ID,
        "proto": algo_types::consensus::CONSENSUS_V41,
        "fees": fees,
        "rwd": rwd,
        "alloc": [
            { "addr": fees, "comment": "FeeSink", "state": { "algo": 0, "onl": 0 } },
            { "addr": rwd, "comment": "RewardsPool", "state": { "algo": 100_000_000_000u64, "onl": 0 } },
        ],
    });
    serde_json::to_string_pretty(&genesis).expect("encode genesis.json")
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Bind a loopback socket on port 0, capture the OS-assigned port, and
/// release it. Small race window where another process could take it,
/// acceptable for an ignored integration test — same approach
/// `p2p_multi_node_consensus.rs` uses.
fn alloc_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind on loopback");
    listener.local_addr().expect("local_addr").port()
}

// ---------------------------------------------------------------------------
// P2P identity pre-generation
// ---------------------------------------------------------------------------

/// Pre-generate a libp2p identity and persist it to `<data_dir>/
/// peerIDPrivKey.key` so this test knows a child process's `PeerId` before
/// that process ever starts — needed for `r2`'s multiaddr (both `r1` and
/// `n` are configured with it directly), and for `r1`'s `PeerId` (needed
/// only so this test can recognize it in `n`'s peer list — `r1`'s multiaddr
/// itself is deliberately never given to `n`).
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

/// Spawn one `algod-rust participate` child process wired for the libp2p P2P
/// transport only, with `EnableDHTProviders` turned on via `config.json`
/// (there is no CLI flag for it — see `algo_config::Local::enable_dht_providers`'s
/// doc comment, wired from `config.json`'s `EnableDHTProviders` field only).
///
/// `bootstrap_peer`, when set, is the *only* peer this node is ever told
/// about — used to build the `R1 (DHT) -> R2 (phonebook) <- N` topology
/// where neither `r1` nor `n` is ever configured with the other's address.
fn spawn_dht_p2p_node(
    data_dir: TempDir,
    p2p_port: u16,
    rest_port: u16,
    genesis_json: &str,
    bootstrap_peer: Option<&Multiaddr>,
) -> NodeProcess {
    let data_dir_path = data_dir.path().to_path_buf();

    let genesis_path = data_dir_path.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis.json");

    // `EnableDHTProviders` (issue #768) has no CLI flag — only `config.json`
    // wires it (`algo_config::Local::enable_dht_providers`). `DHTMode` is
    // deliberately left unset (`""`): `resolve_dht_mode`'s empty-string
    // semantics already default to Kademlia server mode whenever this node
    // also has a listen address, matching go's own default, so this test
    // does not need to set it explicitly for `r1`/`r2` (`n` has no listen
    // address, so it stays client mode either way).
    let config_path = data_dir_path.join("config.json");
    std::fs::write(&config_path, r#"{"EnableDHTProviders": true}"#)
        .expect("write config.json enabling DHT providers");

    let ledger_path = data_dir_path.join("ledger.sqlite");
    let partkey_path = data_dir_path.join("partkey.sqlite");
    std::fs::File::create(&partkey_path).expect("create empty partkey file");

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
        .arg("--enable-p2p")
        .arg("--p2p-persist-peer-id")
        .arg("--p2p-listen-address")
        .arg(format!("/ip4/127.0.0.1/tcp/{p2p_port}"));
    if let Some(peer) = bootstrap_peer {
        cmd.arg("--p2p-bootstrap-peers").arg(peer.to_string());
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

async fn read_admin_token(data_dir: &Path, deadline: Instant) -> String {
    let path = data_dir.join("algod.admin.token");
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

/// Poll `n`'s `GET /v2/node/peers` (admin-token-gated — go-algorand PR #6674
/// tags `GetPeers` `private`-only, mirrored here, see
/// `crates/node/algo-rest-api/src/router.rs`) until `target_peer_id`'s
/// string form appears among the reported peer addresses (a P2P peer's
/// `network-address` is its `PeerId` string — see
/// `bin/algod-rust/src/node_interface_impl.rs`'s `get_peers`), or panics at
/// `deadline`.
async fn wait_for_peer_connection(
    client: &reqwest::Client,
    rest_addr: &str,
    admin_token: &str,
    target_peer_id: PeerId,
    deadline: Instant,
    label: &str,
) {
    let url = format!("http://{rest_addr}/v2/node/peers");
    let target = target_peer_id.to_string();
    let mut last_seen: Vec<String> = Vec::new();
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(&url)
            .header("X-Algo-API-Token", admin_token)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(peers) = body.get("Peers").and_then(|v| v.as_array()) {
                        last_seen = peers
                            .iter()
                            .filter_map(|p| {
                                p.get("network-address")
                                    .and_then(|a| a.as_str())
                                    .map(str::to_string)
                            })
                            .collect();
                        if last_seen.iter().any(|addr| addr == &target) {
                            return;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "{label}: never observed a connection to {target} before deadline \
         (last observed peer list: {last_seen:?})"
    );
}

fn dump_node_logs(node: &NodeProcess, label: &str) {
    let log_path = node.data_dir_path.join("algod.stderr.log");
    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(150);
    eprintln!(
        "=== P2P node {label} log tail ({} lines @ {}) ===\n{}",
        lines.len() - start,
        log_path.display(),
        lines[start..].join("\n"),
    );
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Reproduces go's `TestNodeP2PRelays` topology across three real
/// `algod-rust participate` processes: `n` discovers and dials `r1` purely
/// via DHT `Gossip`-capability lookup (routed through `r2`, the only peer
/// `n` is ever configured with) — see this file's module doc comment.
#[tokio::test]
#[ignore = "spawns three real algod-rust processes over the libp2p P2P transport and \
            drives real DHT provider-record propagation; run with --ignored"]
async fn n_discovers_and_dials_r1_purely_via_dht_gossip_capability_lookup() {
    let genesis_json = build_genesis_json();

    let p2p_port_r2 = alloc_loopback_port();
    let rest_r2 = alloc_loopback_port();
    let p2p_port_r1 = alloc_loopback_port();
    let rest_r1 = alloc_loopback_port();
    let p2p_port_n = alloc_loopback_port();
    let rest_n = alloc_loopback_port();

    let data_dir_r2 = tempfile::Builder::new()
        .prefix("algod-rust-p2p-dht-r2-")
        .tempdir()
        .expect("tempdir for r2");
    let data_dir_r1 = tempfile::Builder::new()
        .prefix("algod-rust-p2p-dht-r1-")
        .tempdir()
        .expect("tempdir for r1");
    let data_dir_n = tempfile::Builder::new()
        .prefix("algod-rust-p2p-dht-n-")
        .tempdir()
        .expect("tempdir for n");

    // `r2`'s identity must be known before any process starts, since both
    // `r1` and `n` dial it directly by multiaddr. `r1`'s identity is
    // pre-generated too — not to dial it (nothing ever does directly), but
    // so this test knows which `PeerId` to look for in `n`'s peer list.
    let peer_id_r2 = pregenerate_p2p_identity(data_dir_r2.path());
    let multiaddr_r2 = p2p_multiaddr(p2p_port_r2, peer_id_r2);
    let peer_id_r1 = pregenerate_p2p_identity(data_dir_r1.path());

    // `r2` first: the only node neither `r1` nor `n` needs an address for,
    // and the one both of them dial.
    let mut r2 = spawn_dht_p2p_node(data_dir_r2, p2p_port_r2, rest_r2, &genesis_json, None);

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(150);
    wait_for_rest_ready(&client, &r2.rest_addr, overall_deadline).await;

    // `r1`: a P2P listen server (so `P2pTransport::start` advertises its
    // `Gossip` capability, issue #1073's live wiring), dialing only `r2`.
    let mut r1 = spawn_dht_p2p_node(
        data_dir_r1,
        p2p_port_r1,
        rest_r1,
        &genesis_json,
        Some(&multiaddr_r2),
    );
    wait_for_rest_ready(&client, &r1.rest_addr, overall_deadline).await;

    // `n`: dials only `r2` — it is never given `r1`'s multiaddr, or even
    // `r1`'s `PeerId`, by any out-of-band means. The only way `n` can end up
    // connected to `r1` is by discovering it via `r2`'s DHT knowledge
    // (`r2` learns `r1`'s address once `r1` connects to it) and
    // auto-dialing it — exactly issue #1073's periodic mesh-discovery task.
    let mut n = spawn_dht_p2p_node(
        data_dir_n,
        p2p_port_n,
        rest_n,
        &genesis_json,
        Some(&multiaddr_r2),
    );
    wait_for_rest_ready(&client, &n.rest_addr, overall_deadline).await;

    let admin_token_n = read_admin_token(&n.data_dir_path, overall_deadline).await;

    // The actual regression guard: `n`'s own reported peer list must
    // eventually include `r1`'s `PeerId` — proving `n` discovered and
    // dialed `r1` purely via the DHT, not any configured bootstrap address
    // (`n`'s only configured bootstrap peer is `r2`).
    let result = tokio::time::timeout(
        overall_deadline.saturating_duration_since(Instant::now()),
        async {
            wait_for_peer_connection(
                &client,
                &n.rest_addr,
                &admin_token_n,
                peer_id_r1,
                overall_deadline,
                "n",
            )
            .await;
        },
    )
    .await;

    if result.is_err() {
        dump_node_logs(&r2, "R2");
        dump_node_logs(&r1, "R1");
        dump_node_logs(&n, "N");
    }
    n.shutdown();
    r1.shutdown();
    r2.shutdown();

    result.expect(
        "n never discovered and dialed r1 via DHT Gossip-capability lookup before the overall deadline",
    );
}
