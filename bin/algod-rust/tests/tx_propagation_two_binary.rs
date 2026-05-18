//! Two-binary tx-propagation integration test (PLAN-74 / TASK-80).
//!
//! Completes the deferred *binary* variant of TASK-73's in-process
//! tx-propagation test. The in-process variant
//! (`crates/node/algo-network/tests/tx_propagation_inproc.rs`) proves
//! the gossip layer by wiring two `WebsocketNetwork` instances in the
//! same process. This test proves the *REST-driven* variant
//! end-to-end: it spawns two real `algod-rust participate
//! --rest-listen` child processes on loopback, submits a signed
//! transaction via `POST /v2/transactions` on node A, and polls `GET
//! /v2/transactions/pending/:txid` on node B until the same txid
//! appears — exercising the full production chain wired by PLAN-74:
//!
//! ```text
//! REST handler → AlgodNodeInterface::broadcast_signed_tx_group
//!   → LocalTxBroadcaster → pool + gossip
//!   → peer's TxTagHandler → peer's pool
//!   → peer's REST `pending` endpoint
//! ```
//!
//! The test is `#[ignore]` by default because it:
//!
//!   - binds four random 127.0.0.1 ports (pre-bind + release, so two
//!     concurrent runs of the same test could race for ports),
//!   - spawns two `algod-rust` child processes,
//!   - takes roughly 5-10 seconds wall-clock when nothing goes wrong.
//!
//! Run with:
//!
//! ```text
//! cargo test --package algod-rust --test tx_propagation_two_binary \
//!   -- --ignored --nocapture
//! ```
//!
//! # What the test intentionally does NOT cover
//!
//! - Real consensus progress. Both nodes start with empty
//!   participation stores, so they never produce or commit blocks.
//!   The point here is tx-propagation via the pool + gossip layer,
//!   not end-to-end consensus (covered by other tests / the
//!   mixed-cluster harness).
//! - Signature verification. `LocalTxBroadcaster::submit_group` and
//!   `TxTagHandler::handle` do not verify signatures today; this is
//!   consistent with the in-process test and mirrors go-algorand's
//!   trusted local-submission ingestion path.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_codec::{canonical_encode_block_header, canonical_encode_transaction, compute_txn_id};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::SqliteLedger;
use algo_types::consensus::CONSENSUS_V41;
use algo_types::{AccountData, BlockHeader, Digest, Round, SignedTransaction, TxnType};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GENESIS_ID: &str = "twobin-test-v1.0";
const GENESIS_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
/// Deterministic note byte fed to [`signing_key_for`] — the bootstrap
/// pre-funds the corresponding sender account, and the test signs a
/// payment txn from that same account.
const TEST_NOTE: u8 = 0x42;

/// Minimal genesis.json body for the `/genesis` endpoint + ledger
/// metadata table. `proto` matches `CONSENSUS_V41` so the pool's
/// consensus-params lookup succeeds during evaluator bootstrap.
fn genesis_json_body() -> String {
    format!(
        r#"{{
  "network": "twobin-test",
  "id": "v1.0",
  "proto": "{proto}",
  "fees": "4C3M7EIFNOS3F5WZUAFQM3WRNWV6UYGGVP7HSAGIAIBBXBNZYEMLXVW4ZE",
  "rwd": "737777777777777777777777777777777777777777777777777UFEJ2CI",
  "alloc": [
    {{
      "addr": "4C3M7EIFNOS3F5WZUAFQM3WRNWV6UYGGVP7HSAGIAIBBXBNZYEMLXVW4ZE",
      "comment": "fee sink",
      "state": {{ "algo": 0, "onl": 0 }}
    }},
    {{
      "addr": "737777777777777777777777777777777777777777777777777UFEJ2CI",
      "comment": "rewards pool",
      "state": {{ "algo": 0, "onl": 0 }}
    }}
  ]
}}"#,
        proto = CONSENSUS_V41
    )
}

fn parse_hex_32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("genesis hash hex must be ASCII");
        out[i] = u8::from_str_radix(s, 16).expect("genesis hash hex must parse");
    }
    out
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Bind a loopback socket on port 0, capture the OS-assigned port,
/// and release it. The caller uses the port immediately; there is a
/// small race window where another process could take it, acceptable
/// for an ignored integration test.
fn alloc_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind on loopback");
    listener.local_addr().expect("local_addr").port()
}

// ---------------------------------------------------------------------------
// Per-node bootstrap
// ---------------------------------------------------------------------------

struct NodeLayout {
    data_dir: TempDir,
}

impl NodeLayout {
    fn ledger_path(&self) -> PathBuf {
        self.data_dir.path().join("ledger.sqlite")
    }

    fn partkey_path(&self) -> PathBuf {
        self.data_dir.path().join("partkey.sqlite")
    }

    fn genesis_path(&self) -> PathBuf {
        self.data_dir.path().join("genesis.json")
    }
}

/// Create a fresh data directory with:
/// - `genesis.json` (for the `/genesis` endpoint),
/// - `ledger.sqlite` containing a synthesized round-0 block whose
///   header uses `CONSENSUS_V41`, so the pool's startup evaluator
///   bootstrap (see `bin/algod-rust/src/commands/participate.rs`)
///   can succeed,
/// - `partkey.sqlite` as an empty file — `ParticipationStore::open`
///   creates the tables on first use, and an empty store keeps
///   `participate` from producing consensus messages.
fn bootstrap_node_layout() -> NodeLayout {
    let dir = tempfile::Builder::new()
        .prefix("algod-rust-twobin-")
        .tempdir()
        .expect("tempdir");
    let layout = NodeLayout { data_dir: dir };

    std::fs::write(layout.genesis_path(), genesis_json_body()).expect("write genesis.json");

    let mut ledger = SqliteLedger::open(&layout.ledger_path()).expect("open ledger");
    let genesis_hash = parse_hex_32(GENESIS_HASH_HEX);

    // Bootstrap at round 1 rather than round 0 because
    // `canonical_encode_block_header` omits `rnd` when it's 0 (Go's
    // omitempty semantics), and `BlockHeader::decode_from_reader`
    // requires the field — so a round-0 header round-trips into a
    // decode failure inside `AlgodNodeInterface::status`.
    // Using round 1 sidesteps that wrinkle without needing a
    // hand-rolled msgpack writer, and the pool's evaluator bootstrap
    // simply creates an evaluator for round 2 against this header.
    let bootstrap_round = Round(1);
    let hdr = BlockHeader {
        round: bootstrap_round,
        current_protocol: CONSENSUS_V41.to_string(),
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash,
        timestamp: 1,
        ..Default::default()
    };
    let hdr_bytes = canonical_encode_block_header(&hdr);
    // `put_block` writes the `blocks` row directly; the committed
    // tracker round is only flushed to `acctrounds.acctbase` (Go's
    // `accountsRound`, the post-G6-part-3 home for what
    // `algod_rust_meta.current_round` used to hold) when
    // `commit_block` runs. Without the begin/commit pair the child
    // process would open the ledger with `current_round = None`,
    // which makes `AlgodNodeInterface::status` return "failed
    // retrieving node status" to the REST handler.
    ledger
        .put_block(bootstrap_round.0, CONSENSUS_V41, &hdr_bytes, &hdr_bytes)
        .expect("put_block");
    ledger.set_protocol(CONSENSUS_V41.to_string());
    ledger.set_genesis_hash(genesis_hash);
    ledger.set_genesis_id(GENESIS_ID.to_string());
    ledger.set_current_round(bootstrap_round);

    // Pre-fund the test sender so the pool's fee + min-balance
    // checks pass on both nodes. `set_account` writes to the
    // `accountbase` table directly; persistence rolls up into the
    // chain-state flush performed by `commit_block` below.
    let sender = sender_address_for(TEST_NOTE);
    ledger.set_account(
        &sender,
        AccountData {
            micro_algos: 1_000_000_000,
            ..Default::default()
        },
    );

    ledger.begin_block().expect("begin bootstrap block");
    ledger.commit_block().expect("commit bootstrap block");
    drop(ledger);

    // Partkey SQLite file — empty (no keys). Touch so the path exists;
    // `ParticipationStore::open` in the child creates the schema.
    std::fs::File::create(layout.partkey_path()).expect("create partkey file");

    layout
}

// ---------------------------------------------------------------------------
// Child process lifecycle
// ---------------------------------------------------------------------------

struct NodeProcess {
    child: Child,
    /// Retained so the temp dir lives as long as the process.
    _layout: NodeLayout,
    gossip_addr: String,
    rest_addr: String,
    data_dir: PathBuf,
}

impl NodeProcess {
    /// Kill the child process and reap it. Idempotent; also called
    /// from `Drop`.
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

fn spawn_node(
    gossip_port: u16,
    rest_port: u16,
    peer_gossip_addr: Option<&str>,
    relay: bool,
) -> NodeProcess {
    let layout = bootstrap_node_layout();
    let data_dir = layout.data_dir.path().to_path_buf();
    let gossip_addr = format!("127.0.0.1:{gossip_port}");
    let rest_addr = format!("127.0.0.1:{rest_port}");

    let bin = env!("CARGO_BIN_EXE_algod-rust");
    let mut cmd = Command::new(bin);
    cmd.arg("participate")
        .arg("--ledger-path")
        .arg(layout.ledger_path())
        .arg("--partkey-path")
        .arg(layout.partkey_path())
        .arg("--genesis-id")
        .arg(GENESIS_ID)
        .arg("--genesis-hash")
        .arg(GENESIS_HASH_HEX)
        .arg("--listen-address")
        .arg(&gossip_addr)
        .arg("--rest-listen")
        .arg(&rest_addr)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--genesis-path")
        .arg(layout.genesis_path())
        .env(
            "RUST_LOG",
            std::env::var("TWOBIN_RUST_LOG").unwrap_or_else(|_| "warn".to_string()),
        );
    if relay {
        cmd.arg("--relay-messages");
    }
    if let Some(peer) = peer_gossip_addr {
        cmd.arg("--peers").arg(peer);
    }
    // Route child stdout + stderr to a file in the data dir so the
    // test harness can surface logs on failure without libtest's
    // capture eating them. The binary's `tracing_subscriber::fmt()`
    // writes to stdout by default, not stderr, so both must be
    // captured.
    let log_path = data_dir.join("algod.stderr.log");
    let log_file = std::fs::File::create(&log_path).expect("create log file");
    let log_file_dup = log_file.try_clone().expect("clone log fd");
    cmd.stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_dup));

    let child = cmd.spawn().expect("spawn algod-rust participate");

    NodeProcess {
        child,
        _layout: layout,
        gossip_addr,
        rest_addr,
        data_dir,
    }
}

// ---------------------------------------------------------------------------
// REST client helpers (async reqwest; already a workspace dependency)
// ---------------------------------------------------------------------------

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client")
}

/// Poll `http://<rest_addr>/health` until it returns success or the
/// deadline passes, then panic with the last observed error.
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
        "REST API at {rest_addr} did not become ready before deadline; last error: {:?}",
        last_err
    );
}

/// Read `algod.token` from a node's data directory, retrying briefly
/// to handle the window between process spawn and
/// `ApiServer::serve` writing the token file.
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

// ---------------------------------------------------------------------------
// Txn construction
// ---------------------------------------------------------------------------

/// Derive the deterministic signing key used by [`make_signed_tx`]
/// for a given note byte. Used by the ledger bootstrap to pre-fund
/// the sender account so the pool's min-balance / fee checks pass.
fn signing_key_for(note: u8) -> ed25519_dalek::SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = note.wrapping_add(1); // avoid the all-zero seed
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn sender_address_for(note: u8) -> algo_types::Address {
    algo_types::Address(signing_key_for(note).verifying_key().to_bytes())
}

/// Build a valid, ed25519-signed payment transaction.
///
/// Pool-level ingestion (`validate_transaction_wellformed` +
/// `verify_transaction_signature`) runs on the submitting node, so a
/// dummy signature is not enough — the signature must verify against
/// the sender's public key. We generate a throwaway ed25519 keypair
/// and set `sender = pk`, matching Algorand's single-sig model where
/// the address IS the public key.
fn make_signed_tx(note: u8, genesis_hash: [u8; 32]) -> SignedTransaction {
    use ed25519_dalek::Signer;

    let sk = signing_key_for(note);
    let vk = sk.verifying_key();

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = TxnType::Pay;
    stx.txn.fee = 1_000_000;
    stx.txn.first_valid = Round(1);
    stx.txn.last_valid = Round(1_000);
    stx.txn.sender = algo_types::Address(vk.to_bytes());
    // Payment receiver can be any non-zero address — reuse sender.
    stx.txn.receiver = stx.txn.sender;
    stx.txn.amount = 0;
    stx.txn.genesis_hash = genesis_hash;
    stx.txn.genesis_id = GENESIS_ID.to_string();
    stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);

    // Sign `"TX" || canonical_encode_transaction(txn)`, matching
    // `algo_validate::signature::verify_single_sig`.
    let mut msg = Vec::with_capacity(2 + 256);
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical_encode_transaction(&stx.txn));
    stx.sig = sk.sign(&msg).to_bytes();
    stx
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// End-to-end: REST submit on node A → gossip → REST pending-by-txid
/// on node B returns 200.
#[tokio::test]
#[ignore = "spawns child algod-rust processes; run with --ignored"]
async fn txn_propagates_from_a_to_b_via_rest() {
    // 1. Allocate four loopback ports up-front.
    let gossip_a = alloc_loopback_port();
    let rest_a = alloc_loopback_port();
    let gossip_b = alloc_loopback_port();
    let rest_b = alloc_loopback_port();

    // 2. Spawn node A first, then node B pointed at A's gossip port.
    // Node A acts as a relay so node B can dial it and exchange
    // gossip messages (mirrors the in-process test's setup).
    let mut node_a = spawn_node(gossip_a, rest_a, None, /* relay */ true);
    let mut node_b = spawn_node(gossip_b, rest_b, Some(&node_a.gossip_addr), false);

    let overall_deadline = Instant::now() + Duration::from_secs(20);
    let client = http_client();

    // 3. Wait for both REST servers to be ready and read their tokens.
    wait_for_rest_ready(&client, &node_a.rest_addr, overall_deadline).await;
    wait_for_rest_ready(&client, &node_b.rest_addr, overall_deadline).await;
    let token_a = read_api_token(&node_a.data_dir, overall_deadline).await;
    let token_b = read_api_token(&node_b.data_dir, overall_deadline).await;

    // 4. Build a valid-shape txn (unsigned — local submission skips
    //    signature verification, matching the in-process test).
    let genesis_hash = parse_hex_32(GENESIS_HASH_HEX);
    let tx = make_signed_tx(TEST_NOTE, genesis_hash);
    let txid: Digest = compute_txn_id(&tx.txn);
    let txid_str = txid.to_string();
    // The REST handler decodes concatenated `SignedTxn` msgpack
    // entries via `SignedTransaction::decode_from_reader`, which
    // accepts the `rmp_serde::to_vec_named` wire format used
    // everywhere else in the codebase (e.g.,
    // `algo_network::local_tx_broadcast::encode_tx_group`).
    let body = rmp_serde::to_vec_named(&tx).expect("encode signed txn");

    // 5. POST to node A.
    let post_resp = client
        .post(format!("http://{}/v2/transactions", node_a.rest_addr))
        .header("X-Algo-API-Token", &token_a)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .expect("POST /v2/transactions");
    let post_status = post_resp.status();
    let post_body = post_resp.text().await.unwrap_or_default();
    if !post_status.is_success() {
        node_b.shutdown();
        node_a.shutdown();
        dump_node_logs(&node_a, "A");
        panic!("POST /v2/transactions on node A returned {post_status}: {post_body}");
    }

    // 6. Poll node B for the txid.
    let pending_url = format!(
        "http://{}/v2/transactions/pending/{}",
        node_b.rest_addr, txid_str
    );
    let poll_deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_it = false;
    let mut last_status: Option<reqwest::StatusCode> = None;
    while Instant::now() < poll_deadline {
        if let Ok(resp) = client
            .get(&pending_url)
            .header("X-Algo-API-Token", &token_b)
            .send()
            .await
        {
            last_status = Some(resp.status());
            if resp.status().is_success() {
                saw_it = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Explicit teardown (Drop also handles this, but be deterministic
    // on the happy-path log output).
    node_b.shutdown();
    node_a.shutdown();

    if !saw_it {
        dump_node_logs(&node_a, "A");
        dump_node_logs(&node_b, "B");
    }
    assert!(
        saw_it,
        "node B did not observe txid {txid_str} within 10 s (last status: {last_status:?})",
    );
}

/// Tail the last 50 lines of a node's stdout/stderr log. Used on
/// assertion failure to surface startup diagnostics in the test
/// output, since libtest otherwise swallows child process output.
fn dump_node_logs(node: &NodeProcess, label: &str) {
    let log_path = node.data_dir.join("algod.stderr.log");
    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(50);
    eprintln!(
        "=== node {label} log tail ({} lines @ {}) ===\n{}",
        lines.len() - start,
        log_path.display(),
        lines[start..].join("\n"),
    );
}
