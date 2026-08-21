//! Live dual-node long-poll timing conformance suite (issue #450).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) to `GET /v2/status/wait-for-block-after/{round}`'s
//! *timing* behavior specifically -- the immediate-return, notification, and
//! timeout paths, none of which the JSON-shape-focused suites cover.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_longpoll_parity \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```
//!
//! # Serialization requirement
//!
//! Three of these tests call `produce_one_block`, which submits a
//! transaction to advance a node's round -- shared mutable state on the
//! live nodes, exactly as in `live_txn_cross_verification.rs`. Running them
//! concurrently (this file's original default) lets one test's block
//! production interleave with another's wait, so a poll can observe a round
//! advanced by a *different* test than the one it's asserting about. Run
//! with `--test-threads=1`.
//!
//! # The timeout test's cost
//!
//! go's `WaitForBlockTimeout` is a real, fixed 60-second constant
//! (`daemon/algod/api/server/v2/handlers.go`), and algod-rust's
//! `WAIT_FOR_BLOCK_TIMEOUT` already matches it exactly
//! (`crates/node/algo-rest-api/src/handlers.rs`). Neither can be shortened
//! for the test without either patching the real go binary (defeating the
//! point of a live comparison) or diverging from what's actually being
//! verified. `wait_for_block_timeout_matches_go` accepts this cost but
//! keeps it bounded: it issues both nodes' requests *concurrently*
//! (`tokio::join!`), so the wall-clock cost is one ~60s wait, not two
//! sequential ones -- an acceptable, bounded addition to `make
//! validate-api`'s existing multi-minute budget, and it is the only test in
//! this file that takes anywhere near that long.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use algo_codec::canonical_encode_transaction;
use algo_types::{Round, SignedTransaction, TxnType};
use ed25519_dalek::Signer;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

fn go_url() -> String {
    std::env::var("ALGOD_GO_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".to_string())
}

fn rust_url() -> String {
    std::env::var("ALGOD_RUST_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".to_string())
}

fn client() -> reqwest::Client {
    // No blanket timeout -- the timeout test deliberately waits ~60s for a
    // real HTTP response; a client-side timeout would race the assertion
    // it's trying to make.
    reqwest::Client::builder()
        .build()
        .expect("build reqwest client")
}

fn dev_signing_key() -> ed25519_dalek::SigningKey {
    let seed = algo_consensus_crypto::passphrase::mnemonic_to_key(DEV_MNEMONIC)
        .expect("dev mnemonic must decode to a valid key");
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn dev_address() -> algo_types::Address {
    algo_types::Address(dev_signing_key().verifying_key().to_bytes())
}

fn unique_note(tag: &str) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_longpoll_parity:{tag}:{nanos}").into_bytes()
}

/// Submit a self-payment on `base` to force a new dev-mode block, advancing
/// that node's round by exactly one. Reuses the same signing pattern as
/// `live_txn_cross_verification.rs` (kept duplicated rather than shared,
/// since integration-test binaries can't import from one another).
async fn produce_one_block(client: &reqwest::Client, base: &str) {
    let params: serde_json::Value = client
        .get(format!("{base}/v2/transactions/params"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let genesis_hash_bytes = base64_decode(params["genesis-hash"].as_str().unwrap());
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis_hash_bytes);
    let last_round = params["last-round"].as_u64().unwrap();

    let mut txn = algo_types::Transaction {
        txn_type: TxnType::Pay,
        sender: dev_address(),
        receiver: dev_address(),
        fee: params["min-fee"].as_u64().unwrap().max(1000),
        // go rejects a validity window wider than MaxTxnLife (1000 rounds,
        // "transaction window size excessive") -- anchor first_valid to the
        // current round rather than a fixed 1, since this file's later
        // tests call produce_one_block after earlier ones have already
        // advanced the round well past 1.
        first_valid: Round(last_round.max(1)),
        last_valid: Round(last_round + 1000),
        genesis_id: params["genesis-id"].as_str().unwrap().to_string(),
        genesis_hash,
        note: unique_note("produce-block").into(),
        ..Default::default()
    };
    let sk = dev_signing_key();
    let mut msg = Vec::with_capacity(2 + 256);
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical_encode_transaction(&txn));
    let sig = sk.sign(&msg).to_bytes();
    let stx = SignedTransaction {
        txn: std::mem::take(&mut txn),
        sig,
        ..Default::default()
    };
    let bytes = rmp_serde::to_vec_named(&stx).expect("encode signed txn");

    let resp = client
        .post(format!("{base}/v2/transactions"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/x-binary")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "produce_one_block: submission rejected: {}",
        resp.text().await.unwrap_or_default()
    );
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(s).expect("valid base64")
}

async fn current_round(client: &reqwest::Client, base: &str) -> u64 {
    let status: serde_json::Value = client
        .get(format!("{base}/v2/status"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    status["last-round"].as_u64().unwrap()
}

// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn wait_for_block_immediate_when_round_already_committed() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // Force at least one committed block past genesis, so "round
        // already past" is exercisable (round 0's wait-for-block-after
        // target is round 1, which is never "already past" at genesis).
        produce_one_block(&c, &base).await;
        let round = current_round(&c, &base).await;
        assert!(round >= 1, "{label}: expected round to have advanced");

        let start = Instant::now();
        let resp = c
            .get(format!(
                "{base}/v2/status/wait-for-block-after/{}",
                round - 1
            ))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(resp.status(), 200, "{label}: unexpected status");
        assert!(
            elapsed < Duration::from_secs(5),
            "{label}: wait-for-block-after(round-1) must return immediately when round is already committed, took {elapsed:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn wait_for_block_notification_releases_promptly() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let round = current_round(&c, &base).await;

        // Start the long-poll concurrently with producing the next block --
        // the poll must observe the new block and release well before any
        // timeout, not just eventually after one.
        let poll = c
            .get(format!("{base}/v2/status/wait-for-block-after/{round}"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send();
        let produce = produce_one_block(&c, &base);

        let start = Instant::now();
        let (poll_result, ()) = tokio::join!(poll, produce);
        let elapsed = start.elapsed();

        let resp = poll_result.unwrap();
        assert_eq!(resp.status(), 200, "{label}: unexpected status");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["last-round"].as_u64(),
            Some(round + 1),
            "{label}: released status must reflect the newly-produced round"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "{label}: wait-for-block-after must release promptly on notification, took {elapsed:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs; ~60s wall-clock"]
async fn wait_for_block_timeout_matches_go() {
    // A round far enough in the future that neither node will ever reach it
    // within the test, so this exercises go's real WaitForBlockTimeout (1
    // minute, `daemon/algod/api/server/v2/handlers.go`) and algod-rust's
    // matching WAIT_FOR_BLOCK_TIMEOUT constant
    // (`crates/node/algo-rest-api/src/handlers.rs`). Both requests run
    // concurrently so the total wall-clock cost is ~60s, not ~120s.
    let c = client();
    let go_round = current_round(&c, &go_url()).await + 1_000_000;
    let rust_round = current_round(&c, &rust_url()).await + 1_000_000;

    let go_req = c
        .get(format!(
            "{}/v2/status/wait-for-block-after/{go_round}",
            go_url()
        ))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send();
    let rust_req = c
        .get(format!(
            "{}/v2/status/wait-for-block-after/{rust_round}",
            rust_url()
        ))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send();

    let start = Instant::now();
    let (go_resp, rust_resp) = tokio::join!(go_req, rust_req);
    let elapsed = start.elapsed();

    assert_eq!(go_resp.unwrap().status(), 200, "go: unexpected status");
    assert_eq!(rust_resp.unwrap().status(), 200, "rust: unexpected status");

    // go's WaitForBlockTimeout is exactly 60s; assert a tolerance band
    // around it rather than exact equality (network/scheduling jitter),
    // and a floor comfortably below 60s to catch a timeout that's wired up
    // but firing far too early.
    assert!(
        elapsed >= Duration::from_secs(55) && elapsed <= Duration::from_secs(75),
        "expected both nodes to release via the ~60s timeout, took {elapsed:?}"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn wait_for_block_invalid_round_error_envelope_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // Non-numeric round: rejected by path-parameter extraction before
        // the handler runs on both sides -- must still produce go's JSON
        // error envelope (issue #446's json_envelope_layer work), not a
        // raw framework error body.
        let resp = c
            .get(format!("{base}/v2/status/wait-for-block-after/not-a-round"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            400,
            "{label}: non-numeric round must be rejected with 400"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["message"].as_str().is_some(),
            "{label}: error body must carry go's JSON envelope shape ({{\"message\": ...}}), got {body}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn wait_for_block_round_overflow_matches() {
    // u64::MAX: parses as a valid round, and go computes `round+1` with
    // plain unsigned wraparound (no overflow check at all) -- confirmed
    // live: go returns 200 immediately, since the wrapped target (round 0)
    // is always already committed. algod-rust previously had an explicit
    // "round overflow" 400 guard here that didn't match go at all; fixed
    // (`handlers::wait_for_block`) to wrap the same way.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let start = Instant::now();
        let resp = c
            .get(format!(
                "{base}/v2/status/wait-for-block-after/{}",
                u64::MAX
            ))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            resp.status(),
            200,
            "{label}: round=u64::MAX must wrap and return 200 immediately, matching go"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "{label}: must return immediately (wrapped target round 0 is always committed), took {elapsed:?}"
        );
    }
}
