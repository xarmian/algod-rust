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

//! Two-binary, real-agreement, **libp2p P2P transport** multi-node harness
//! (issue #827's last remaining theme-4 gap).
//!
//! `multi_node_consensus_sync.rs` (issue #827's earlier pass) built this same
//! two-real-child-process shape for the classic WebSocket-gossip transport
//! and closed `TestInitialSync`/`TestSyncingFullNode`/`TestSimpleUpgrade`.
//! This file is the P2P-transport counterpart: `crates/node/algo-p2p` had no
//! integration-test harness capable of spawning real multi-node P2P
//! connections at all before this file (`crates/node/algo-p2p/tests/` still
//! doesn't exist -- `algo-p2p` deliberately has no `algod-rust` binary to
//! drive from inside its own crate, so this harness lives here instead,
//! exactly where the classic-transport one does).
//!
//! ## What this proves
//!
//! Node A holds 100% of genesis online stake plus a real, freshly generated
//! VRF + one-time-signature participation key and is started `--enable-p2p`
//! with a P2P listen address (`NetworkMode::P2pOnly` -- no WS-gossip listener
//! at all). Because it holds all online stake, real Algorand sortition
//! selects it into essentially every committee, so it proposes, votes, and
//! certifies real blocks by itself entirely over the libp2p transport
//! (`bin/algod-rust/src/commands/p2p_transport.rs`'s gossipsub + the raw
//! `/algorand-ws/2.2.0` stream it opens per peer). Node B starts from the
//! same genesis with an empty participation-key registry, also `--enable-p2p`,
//! dialing node A directly by multiaddr (`--p2p-bootstrap-peers`); it never
//! proposes or votes, and can only advance via the P2P catch-up/block-fetch
//! path. The test waits for node A to produce a few real rounds, waits for
//! node B to catch up to the same round entirely over P2P, and asserts their
//! block hashes match -- the algod-rust equivalent of go-algorand's
//! `TestInitialSync`/`TestSyncingFullNode` shape, ported to the P2P
//! transport instead of the classic WS-gossip one, and the same underlying
//! machinery `../go-algorand/node/node_test.go`'s `TestNodeP2P_NetProtoVersions`
//! depends on: two real, independent `algod-rust` processes reaching genuine
//! BFT agreement and propagating blocks entirely over libp2p.
//!
//! ## What this intentionally does not cover
//!
//! - **Two independently-staked P2P voters jointly reaching quorum**, the
//!   literal shape of go's `TestNodeP2P_NetProtoVersions` (each of two nodes
//!   holding half of online stake, both proposing/voting), used to be an
//!   open gap here: attempting it directly surfaced a real,
//!   **transport-independent** stall (round 1 never certified even after
//!   several minutes, despite both nodes' votes being observably received
//!   and accepted by each side's `algo_agreement::service`), root-caused to
//!   a `participate`-CLI-vs-ledger genesis id/hash mismatch rejecting every
//!   peer-authored proposal (`algo_validate::block::validate_block`'s
//!   genesis-consistency check) and filed as issue #1066. Now that that fix
//!   (`resolve_effective_genesis_expectations`) has landed,
//!   `p2p_two_independently_staked_voters_reach_quorum` below proves this
//!   shape does work over the P2P transport too (issue #1070). Go's
//!   specific differing-`EnableVoteCompression`-version negotiation --
//!   `P2pTransport` had no config knob to disable vote-compression
//!   negotiation per node at the time this note was written -- is now
//!   covered too: `algo_config::Local::enable_vote_compression` (issue
//!   #1239) wires into `P2pTransportConfig::enable_vote_compression`, and
//!   `p2p_two_voters_with_differing_vote_compression_settings_reach_quorum`
//!   below proves two nodes with differing settings still certify a round
//!   together.
//! - **`TestNodeP2PRelays`** -- a 3-node `R1 (DHT) -> R2 (phonebook) <- N`
//!   topology where a non-relay participant must *discover* a second relay
//!   purely via the Kademlia DHT (no direct multiaddr for it at all).
//!   `algo_p2p::dht`'s DHT-provider/bootstrap machinery exists and is
//!   unit-tested in-crate, but proving live DHT-based discovery end-to-end
//!   across three real child processes (accurate `PeersPhonebookRelays`-style
//!   phonebook-refresh timing, `RequestConnectOutgoing` retriggering) is a
//!   materially larger harness than this direct-dial 2-node shape and was not
//!   attempted in this pass -- left `missing-test`.
//! - **`TestNodeHybridTopology`** -- a 3-node `N -- R -- A` topology mixing
//!   `EnableP2PHybridMode` (dual WS+P2P transport) with DHT discovery and a
//!   selectively-disabled block service on the middle relay. Depends on the
//!   same DHT-discovery machinery as `TestNodeP2PRelays` above, plus hybrid
//!   dual-transport wiring (`crate::commands::dual_gossip_node`) on top --
//!   left `missing-test` for the same reason.
//!
//! Peer discovery here is direct dial-by-multiaddr (node B's
//! `--p2p-bootstrap-peers` names node A's `/ip4/127.0.0.1/tcp/<port>/p2p/
//! <peer-id>` directly), not DHT-based, so node A's libp2p peer identity must
//! be known *before* either process starts. This test pre-generates it
//! directly in Rust via [`algo_p2p::get_or_create_keypair`] (the exact same
//! function `participate`'s own P2P startup path calls) and writes it to
//! `<data_dir>/peerIDPrivKey.key` -- the default path `algo_p2p::identity`'s
//! load precedence checks before generating a fresh key -- so the child
//! process loads the identity this test already knows the `PeerId` for.
//! Only node B dials: both sides dialing each other at once (each configured
//! with the other as a bootstrap peer) reliably produced a noise-handshake
//! failure on both sides' simultaneous outbound dial
//! (`libp2p_core::upgrade::apply: Failed to upgrade outbound stream
//! upgrade=/noise` / `InvalidData`, at effectively the same instant) -- a
//! real, previously-unexercised gap, since every existing in-process
//! `p2p_transport.rs` unit test only ever dials in one direction
//! (`connected_pair()`'s listener never dials the dialer back). One-directional
//! dial sidesteps that gap entirely and is sufficient to prove this test's
//! target property; a standalone `algo-p2p`-level regression test for the
//! mutual-dial race is filed separately as issue #1067.
//!
//! ## Running
//!
//! ```text
//! cargo test --package algod-rust --test p2p_multi_node_consensus \
//!   -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` for the same reason `multi_node_consensus_sync.rs` is: real
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
const NETWORK_NAME: &str = "algod-rust-p2p-sync-test";
/// Same fixed fee-sink / rewards-pool addresses `multi_node_consensus_sync.rs`
/// uses -- arbitrary, but already known-good rather than freshly derived.
const FEE_SINK_ADDR: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";
const REWARDS_POOL_ADDR: &str = "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM";
const STAKE_ACCOUNT_ALGOS: u64 = 10_000_000_000_000;
const REWARDS_POOL_ALGOS: u64 = 100_000_000_000;

// ---------------------------------------------------------------------------
// Genesis + participation-key construction (pure Rust, no go-algorand)
// ---------------------------------------------------------------------------

/// A freshly generated online participation key plus the address it
/// belongs to, and the genesis.json text both nodes boot from. Same
/// single-100%-stake-account shape as `multi_node_consensus_sync.rs`'s
/// `OnlineGenesis` -- see this file's module doc comment for why a 50/50
/// two-voter split is not used here.
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

/// Two independently-staked online accounts, each holding half of genesis
/// online stake, plus the shared genesis.json both nodes boot from. The P2P
/// counterpart of `multi_node_consensus_sync.rs`'s `TwoVoterGenesis`/
/// `build_two_voter_genesis` (issue #1066), needed here for issue #1070's
/// P2P-transport two-voter quorum test -- go's `TestNodeP2P_NetProtoVersions`
/// literal shape of two nodes each holding half of online stake.
///
/// Not extracted into a shared helper module with `multi_node_consensus_sync.rs`:
/// each `tests/*.rs` file here compiles as its own independent test binary
/// crate (Rust integration-test items are not visible across files), the two
/// files already build their genesis JSON with different idioms (raw
/// `format!` templates there vs. `serde_json::json!` here, matching each
/// file's own existing style), and use different `NETWORK_NAME`/stake
/// constants -- so sharing would mean introducing a new `tests/common/`
/// module purely to save ~50 lines of straightforward, test-only JSON
/// construction, at the cost of coupling two otherwise-independent
/// integration-test binaries together. Duplicating (adapted to this file's
/// own `serde_json::json!` style) is the better trade here.
struct TwoVoterGenesis {
    genesis_json: String,
    participation_a: Participation,
    participation_b: Participation,
}

fn build_two_voter_genesis() -> TwoVoterGenesis {
    fn make_account(first_valid: Round, last_valid: Round) -> (Address, Participation) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let address = Address(sk.verifying_key().to_bytes());
        let participation = Participation::generate(
            address,
            first_valid,
            last_valid,
            /* key_dilution */ 0,
            /* key_lifetime */ 0,
        )
        .expect("generate online participation key");
        (address, participation)
    }

    let first_valid = Round(0);
    let last_valid = Round(10_000);
    let (addr_a, participation_a) = make_account(first_valid, last_valid);
    let (addr_b, participation_b) = make_account(first_valid, last_valid);

    let alloc_state = |addr: &Address, p: &Participation| {
        serde_json::json!({
            "addr": addr.to_string(),
            "comment": "stake",
            "state": {
                "algo": STAKE_ACCOUNT_ALGOS / 2,
                "onl": 1,
                "sel": BASE64_STANDARD.encode(p.vrf_pubkey().0),
                "vote": BASE64_STANDARD.encode(p.voting.verifier()),
                "voteKD": p.key_dilution,
                "voteFst": first_valid.0,
                "voteLst": last_valid.0,
            }
        })
    };

    let genesis = serde_json::json!({
        "network": NETWORK_NAME,
        "id": GENESIS_ID,
        "proto": algo_types::consensus::CONSENSUS_V41,
        "fees": FEE_SINK_ADDR,
        "rwd": REWARDS_POOL_ADDR,
        "alloc": [
            alloc_state(&addr_a, &participation_a),
            alloc_state(&addr_b, &participation_b),
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

    TwoVoterGenesis {
        genesis_json: serde_json::to_string_pretty(&genesis).expect("encode genesis.json"),
        participation_a,
        participation_b,
    }
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Bind a loopback socket on port 0, capture the OS-assigned port, and
/// release it. Small race window where another process could take it,
/// acceptable for an ignored integration test -- same approach
/// `multi_node_consensus_sync.rs` uses.
fn alloc_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind on loopback");
    listener.local_addr().expect("local_addr").port()
}

// ---------------------------------------------------------------------------
// P2P identity pre-generation
// ---------------------------------------------------------------------------

/// Pre-generate a libp2p identity and persist it to `<data_dir>/
/// peerIDPrivKey.key` (the same default path `algo_p2p::identity`'s load
/// precedence checks before generating a fresh key) so this test knows the
/// child process's `PeerId` -- needed to build node B's
/// `--p2p-bootstrap-peers` multiaddr -- before that process ever starts.
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
/// transport only (`--enable-p2p`, no `--listen-address`/`--peers` at all --
/// `NetworkMode::P2pOnly` never opens a WS-gossip listener or dials a WS
/// peer).
///
/// When `online_participation` is `Some`, the node's partkey registry is
/// pre-populated with that key and it is the dial-in-only leader (no
/// `bootstrap_peer`). Otherwise the node starts with an empty registry
/// (never proposes/votes) and dials `bootstrap_peer` (the leader's
/// multiaddr) to catch up purely via the P2P block-fetch path. `data_dir`
/// must already have its `peerIDPrivKey.key` written for the leader (see
/// [`pregenerate_p2p_identity`]) so the child loads the identity this test
/// already computed the multiaddr for, rather than generating a new one.
#[allow(clippy::too_many_arguments)]
fn spawn_p2p_participate_node(
    data_dir: TempDir,
    p2p_port: u16,
    rest_port: u16,
    genesis_json: &str,
    online_participation: Option<&Participation>,
    bootstrap_peer: Option<&Multiaddr>,
) -> NodeProcess {
    spawn_p2p_participate_node_with_config(
        data_dir,
        p2p_port,
        rest_port,
        genesis_json,
        online_participation,
        bootstrap_peer,
        None,
    )
}

/// Full-generality variant of [`spawn_p2p_participate_node`] that additionally
/// writes `config_json` (when given) to `<data_dir>/config.json` before
/// spawning -- e.g. to override `algo_config::Local` fields like
/// `EnableVoteCompression` per node (issue #1239), the same
/// `config.json`-in-data-dir mechanism `multi_node_consensus_sync.rs` uses
/// for the classic WS-gossip transport's equivalent tests.
#[allow(clippy::too_many_arguments)]
fn spawn_p2p_participate_node_with_config(
    data_dir: TempDir,
    p2p_port: u16,
    rest_port: u16,
    genesis_json: &str,
    online_participation: Option<&Participation>,
    bootstrap_peer: Option<&Multiaddr>,
    config_json: Option<&str>,
) -> NodeProcess {
    let data_dir_path = data_dir.path().to_path_buf();

    let genesis_path = data_dir_path.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).expect("write genesis.json");

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
        std::fs::File::create(&partkey_path).expect("create empty partkey file");
    }

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
// REST client helpers (same shape as multi_node_consensus_sync.rs)
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
    let start = lines.len().saturating_sub(120);
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

/// Node A produces real, agreement-certified blocks by itself (100% online
/// stake) entirely over the libp2p P2P transport; node B starts from
/// genesis with no chain history and syncs to node A's blocks purely via
/// the P2P catchup/block-fetch path (no WS-gossip involved on either side).
/// Asserts node B's synced block hash matches node A's -- the P2P-transport
/// counterpart of `multi_node_consensus_sync.rs`'s
/// `follower_node_initial_sync_matches_leader_block_hashes`, and the same
/// underlying "real agreement + block propagation over libp2p" property
/// go-algorand's `TestNodeP2P_NetProtoVersions` depends on (see this file's
/// module doc comment for the two-independent-voters shape that property
/// exercises but which is blocked on a separately filed, transport-
/// independent multi-voter aggregation bug).
#[tokio::test]
#[ignore = "spawns two real algod-rust processes over the libp2p P2P transport and runs \
            real BFT agreement; run with --ignored"]
async fn p2p_follower_syncs_to_leader_via_real_agreement() {
    let online = build_online_genesis();

    let p2p_port_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let p2p_port_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let data_dir_a = tempfile::Builder::new()
        .prefix("algod-rust-p2p-node-a-")
        .tempdir()
        .expect("tempdir for node A");
    let data_dir_b = tempfile::Builder::new()
        .prefix("algod-rust-p2p-node-b-")
        .tempdir()
        .expect("tempdir for node B");

    // Node A's identity must be known *before* either process starts, since
    // node B's `--p2p-bootstrap-peers` dials it directly by multiaddr (no
    // DHT discovery involved in this harness -- see the module doc
    // comment). Only node B dials -- node A is dial-in-only.
    let peer_id_a = pregenerate_p2p_identity(data_dir_a.path());
    let multiaddr_a = p2p_multiaddr(p2p_port_a, peer_id_a);

    let mut node_a = spawn_p2p_participate_node(
        data_dir_a,
        p2p_port_a,
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

    // Now bring up node B from the identical genesis, peered only at node A
    // over P2P, with no participation keys of its own -- it can only advance
    // via the P2P catchup/block-fetch path.
    let mut node_b = spawn_p2p_participate_node(
        data_dir_b,
        p2p_port_b,
        rest_b,
        &online.genesis_json,
        None,
        Some(&multiaddr_a),
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
        "node B's synced block at round {compare_round} does not match node A's over the P2P \
         transport (stake account {})",
        online.stake_address
    );
}

/// The P2P-transport counterpart of `multi_node_consensus_sync.rs`'s
/// `two_independently_staked_voters_reach_quorum` (issue #1066): two
/// independently-staked, independently-signing `algod-rust participate`
/// processes, each holding 50% of genesis online stake plus its own real
/// VRF + one-time-signature participation key, both proposing/voting --
/// this time entirely over the libp2p P2P transport instead of the classic
/// WS-gossip one. Round 1 must certify and both nodes must agree on its
/// block hash. This is the literal shape go-algorand's
/// `TestNodeP2P_NetProtoVersions` (`node/node_test.go`) depends on, closing
/// the one gap `p2p_follower_syncs_to_leader_via_real_agreement`'s module
/// doc comment above left open.
///
/// This test was blocked on two now-fixed bugs (issue #1070):
///
/// - Issue #1066: `participate::run` resolved `BlockValidatorBridge`'s
///   "expected" genesis id/hash from the raw `--genesis-id`/
///   `--genesis-hash` CLI values instead of the genesis actually seeded
///   into the ledger, so every peer's proposal (the only proposal a node
///   did not author itself) was rejected on a genesis-id/hash mismatch,
///   and round 1 never certified. Transport-independent -- lives in the
///   shared `algo_validate::block::validate_block` path -- so this fix
///   (`resolve_effective_genesis_expectations`) unblocks the P2P shape
///   exactly as it did the classic-transport one.
/// - Issue #1067: a separate, P2P-transport-specific bug where two
///   `P2pHost`s dialing each other at close to the same instant corrupted
///   the Noise handshake on both sides (`PortUse::Reuse` colliding both
///   sides' outbound sockets onto their own listen port). Sidestepped here
///   the same way `p2p_follower_syncs_to_leader_via_real_agreement` does:
///   only node B dials node A (`--p2p-bootstrap-peers` on B only, none on
///   A) -- a single bidirectional connection established from one side is
///   sufficient for gossipsub to carry both nodes' votes/proposals in both
///   directions once connected, so the mutual-simultaneous-dial race this
///   test does not need to exercise never triggers. Issue #1067's own fix
///   (`P2pHost::dial` now uses `DialOpts::allocate_new_port()`) has its own
///   dedicated regression test in `crates/node/algo-p2p/src/host.rs`.
#[tokio::test]
#[ignore = "spawns two real algod-rust processes over the libp2p P2P transport and runs \
            real BFT agreement; run with --ignored"]
async fn p2p_two_independently_staked_voters_reach_quorum() {
    let genesis = build_two_voter_genesis();

    let p2p_port_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let p2p_port_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let data_dir_a = tempfile::Builder::new()
        .prefix("algod-rust-p2p-voter-a-")
        .tempdir()
        .expect("tempdir for node A");
    let data_dir_b = tempfile::Builder::new()
        .prefix("algod-rust-p2p-voter-b-")
        .tempdir()
        .expect("tempdir for node B");

    // Node A's identity must be known before either process starts, since
    // node B dials it directly by multiaddr. Only node B dials -- node A
    // never dials out -- to avoid the mutual-simultaneous-dial race fixed
    // by, but not needed to be re-exercised by, issue #1067.
    let peer_id_a = pregenerate_p2p_identity(data_dir_a.path());
    let multiaddr_a = p2p_multiaddr(p2p_port_a, peer_id_a);

    let mut node_a = spawn_p2p_participate_node(
        data_dir_a,
        p2p_port_a,
        rest_a,
        &genesis.genesis_json,
        Some(&genesis.participation_a),
        None,
    );
    let mut node_b = spawn_p2p_participate_node(
        data_dir_b,
        p2p_port_b,
        rest_b,
        &genesis.genesis_json,
        Some(&genesis.participation_b),
        Some(&multiaddr_a),
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(120);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;

    let round_a = wait_for_round(
        &client,
        &node_a.rest_addr,
        &token_a,
        1,
        overall_deadline,
        "node A",
    )
    .await;
    let round_b = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        1,
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
    }
    node_b.shutdown();
    node_a.shutdown();

    assert_eq!(
        hash_a, hash_b,
        "node A and node B (each 50% of genesis online stake, independently signing, over the \
         P2P transport) disagree on round {compare_round}'s block hash"
    );
}

/// The literal shape of go-algorand's `TestNodeP2P_NetProtoVersions`
/// (`node/node_test.go`): two nodes with *differing* `EnableVoteCompression`
/// settings (node A: `false`, node B: go's real default `true`) still reach
/// consensus together, closing the one gap
/// `p2p_two_independently_staked_voters_reach_quorum`'s module doc comment
/// above left open -- issue #1239 gave `algo_config::Local` a real
/// `EnableVoteCompression` field and wired it into
/// `P2pTransportConfig::enable_vote_compression`, so this scenario can
/// finally be reproduced: node A negotiates every handshake with vote
/// compression advertised off (`advertise_vote_compression(false, ..)`
/// only sets `COMPRESSED_PROPOSAL`, no `COMPRESSED_VOTE_VPACK*` bits), node
/// B still advertises the full default set, and the intersection each side
/// computes (`remote_features.intersection(config.our_features)`) collapses
/// to "no vote compression" on both -- proving the transport falls back to
/// the uncompressed `AgreementVote` wire format cleanly rather than
/// stalling or misdecoding votes, exactly as go's differing-version-
/// negotiation test asserts.
///
/// Same two-independently-staked-voters shape as
/// `p2p_two_independently_staked_voters_reach_quorum` (each holds 50% of
/// genesis online stake, both propose/vote) -- the only difference is node
/// A's `<data_dir>/config.json` override, written via
/// [`spawn_p2p_participate_node_with_config`]. `"Version": 38` (
/// `algo_config::LATEST_VERSION`) is required in that override: an
/// explicit field value given at an earlier version is indistinguishable
/// from "unset" and gets silently carried forward to the latest version's
/// own default during `Local::migrate()` (see `algo-config`'s
/// `migrate_field` and this exact pattern in its own
/// `enable_vote_compression_present_and_defaults_true` unit test).
#[tokio::test]
#[ignore = "spawns two real algod-rust processes over the libp2p P2P transport and runs \
            real BFT agreement; run with --ignored"]
async fn p2p_two_voters_with_differing_vote_compression_settings_reach_quorum() {
    let genesis = build_two_voter_genesis();

    let p2p_port_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let p2p_port_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    let data_dir_a = tempfile::Builder::new()
        .prefix("algod-rust-p2p-votecompress-a-")
        .tempdir()
        .expect("tempdir for node A");
    let data_dir_b = tempfile::Builder::new()
        .prefix("algod-rust-p2p-votecompress-b-")
        .tempdir()
        .expect("tempdir for node B");

    // Node A's identity must be known before either process starts, since
    // node B dials it directly by multiaddr. Only node B dials -- node A
    // never dials out -- to avoid the mutual-simultaneous-dial race fixed
    // by, but not needed to be re-exercised by, issue #1067.
    let peer_id_a = pregenerate_p2p_identity(data_dir_a.path());
    let multiaddr_a = p2p_multiaddr(p2p_port_a, peer_id_a);

    // Node A: vote compression explicitly disabled.
    let mut node_a = spawn_p2p_participate_node_with_config(
        data_dir_a,
        p2p_port_a,
        rest_a,
        &genesis.genesis_json,
        Some(&genesis.participation_a),
        None,
        Some(r#"{"Version": 38, "EnableVoteCompression": false}"#),
    );
    // Node B: default config -- vote compression enabled (go's real
    // default), the differing side of the negotiation.
    let mut node_b = spawn_p2p_participate_node_with_config(
        data_dir_b,
        p2p_port_b,
        rest_b,
        &genesis.genesis_json,
        Some(&genesis.participation_b),
        Some(&multiaddr_a),
        None,
    );

    let client = http_client();
    let overall_deadline = Instant::now() + Duration::from_secs(120);

    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir_path, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir_path, overall_deadline).await;

    let round_a = wait_for_round(
        &client,
        &node_a.rest_addr,
        &token_a,
        1,
        overall_deadline,
        "node A",
    )
    .await;
    let round_b = wait_for_round(
        &client,
        &node_b.rest_addr,
        &token_b,
        1,
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
    }
    node_b.shutdown();
    node_a.shutdown();

    assert_eq!(
        hash_a, hash_b,
        "node A (EnableVoteCompression=false) and node B (EnableVoteCompression=true, default) \
         disagree on round {compare_round}'s block hash -- differing vote-compression settings \
         should not prevent reaching consensus together"
    );
}
