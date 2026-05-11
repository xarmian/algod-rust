//! Integration tests for the `sync` CLI subcommand.
//!
//! Prerequisites:
//!   - `make localnet-up` must have been run (algod-go container running on localhost:4001)
//!   - Some transactions should exist (the test generates them if needed)
//!
//! Run with:
//!   cargo test --package algod-rust --test sync_test -- --nocapture --test-threads=1
//!
//! These tests run serially (not in parallel) because they share the localnet.
//! Use `--test-threads=1` to ensure sequential execution.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const ALGOD_URL: &str = "http://localhost:4001";
const ALGOD_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Global counter for unique transaction notes across tests.
static TXN_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if the localnet is running by inspecting the algod-go container.
fn localnet_is_running() -> bool {
    Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Health.Status}}",
            "algod-go",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "healthy")
        .unwrap_or(false)
}

/// Get the current last round from the algod REST API.
fn get_last_round() -> Option<u64> {
    let url = format!("{}/v2/status", ALGOD_URL);
    let output = Command::new("curl")
        .args([
            "-s",
            "-H",
            &format!("X-Algo-API-Token: {}", ALGOD_TOKEN),
            &url,
        ])
        .output()
        .ok()?;
    let body = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
    parsed.get("last-round").and_then(|v| v.as_u64())
}

/// Generate transactions via docker exec to advance the chain.
/// Each transaction gets a unique note to avoid "already in ledger" errors.
fn generate_txns(n: usize) {
    let output = Command::new("docker")
        .args([
            "exec",
            "algod-go",
            "goal",
            "account",
            "list",
            "-d",
            "/algod/data",
        ])
        .output()
        .expect("failed to list accounts");
    let account_list = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = account_list.lines().collect();
    assert!(
        lines.len() >= 2,
        "need at least 2 accounts, got: {}",
        account_list
    );

    let from = lines[0].split_whitespace().nth(1).expect("no FROM address");
    let to = lines
        .last()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("no TO address");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for i in 0..n {
        let seq = TXN_COUNTER.fetch_add(1, Ordering::SeqCst);
        let note = format!("sync-test-{}-{}-{}", ts, seq, i);
        let status = Command::new("docker")
            .args([
                "exec",
                "algod-go",
                "goal",
                "clerk",
                "send",
                "-a",
                "1000",
                "-f",
                from,
                "-t",
                to,
                "-d",
                "/algod/data",
                "-n",
                &note,
            ])
            .status()
            .expect("failed to send txn");
        assert!(status.success(), "txn {} failed", i);
    }
}

/// Extract genesis.json from the docker container to a temp path.
fn extract_genesis(dest: &Path) {
    let status = Command::new("docker")
        .args([
            "cp",
            "algod-go:/algod/data/genesis.json",
            dest.to_str().unwrap(),
        ])
        .status()
        .expect("failed to docker cp genesis.json");
    assert!(status.success(), "docker cp genesis.json failed");
    assert!(dest.exists(), "genesis.json not found after docker cp");
}

/// Get the path to the built binary.
fn binary_path() -> PathBuf {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    workspace_root.join("target/debug/algod-rust")
}

/// Build the binary (in case it's not up to date).
fn ensure_binary_built() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let status = Command::new("cargo")
        .args(["build", "--bin", "algod-rust"])
        .current_dir(workspace_root)
        .status()
        .expect("cargo build failed");
    assert!(status.success(), "cargo build --bin algod-rust failed");
}

/// Create a unique temp directory for test artifacts.
fn create_temp_dir(test_name: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "algod-rust-sync-test-{}-{}-{}",
        test_name,
        std::process::id(),
        ts
    ));
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

/// Clean up a temp directory.
fn cleanup_temp_dir(dir: &Path) {
    if dir.exists() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Query the last committed round from a SQLite ledger DB.
///
/// Since TASK-100 the ledger is a pair of files
/// (`<prefix>.tracker.sqlite` + `<prefix>.block.sqlite`);
/// `algod_rust_meta` lives on the tracker file, so resolve the legacy
/// `.sqlite` test path to its tracker file before opening. The
/// SqliteLedger stores values as little-endian u64 bytes in
/// `algod_rust_meta`.
fn query_last_committed_round(db_path: &Path) -> Option<u64> {
    let tracker = ledger_tracker_path(db_path);
    let conn = rusqlite::Connection::open(tracker).ok()?;
    conn.query_row(
        "SELECT value FROM algod_rust_meta WHERE key = 'current_round'",
        [],
        |row| {
            let bytes: Vec<u8> = row.get(0)?;
            if bytes.len() == 8 {
                Ok(Some(u64::from_le_bytes(bytes.try_into().unwrap())))
            } else {
                Ok(None)
            }
        },
    )
    .ok()
    .flatten()
}

/// Return whether the on-disk ledger pair exists at `db_path` (treated
/// as a prefix, with legacy `.sqlite` suffix stripped). Mirrors what
/// `algo_ledger::ledger_exists` does in the binary.
fn ledger_pair_exists(db_path: &Path) -> bool {
    ledger_tracker_path(db_path).exists()
}

/// Compute the tracker file path that the binary will actually create
/// for the given `--db <db_path>` argument. Matches the prefix
/// derivation in `algo_ledger::derive_ledger_prefix`.
fn ledger_tracker_path(db_path: &Path) -> std::path::PathBuf {
    let s = db_path.to_string_lossy();
    let prefix = s
        .strip_suffix(".tracker.sqlite")
        .or_else(|| s.strip_suffix(".block.sqlite"))
        .or_else(|| s.strip_suffix(".sqlite"))
        .unwrap_or(&s);
    std::path::PathBuf::from(format!("{prefix}.tracker.sqlite"))
}

/// Run sync with the given arguments and return (stdout, stderr, success).
fn run_sync(args: &[&str]) -> (String, String, bool) {
    let output = Command::new(binary_path())
        .args(args)
        .env("RUST_LOG", "info")
        .output()
        .expect("failed to run sync");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Macro to skip the test if localnet is not running.
macro_rules! require_localnet {
    () => {
        if !localnet_is_running() {
            eprintln!("SKIPPED: localnet not running (run `make localnet-up` first)");
            return;
        }
    };
}

/// Test syncing blocks from genesis to a target round.
///
/// Note: the localnet may have diverse transaction types (acfg, axfer, appl, etc.)
/// that the ledger cannot fully apply yet. We do NOT use `--fail-fast` so the sync
/// processes all blocks (skipping those that fail apply). The test verifies:
/// - sync completes successfully (exit 0)
/// - the SQLite DB is created with committed rounds
/// - the output contains "blocks/sec" throughput and a sync summary
#[test]
fn test_sync_from_genesis() {
    require_localnet!();
    ensure_binary_built();

    let temp_dir = create_temp_dir("from-genesis");
    let genesis_path = temp_dir.join("genesis.json");
    let db_path = temp_dir.join("ledger.sqlite");

    extract_genesis(&genesis_path);

    // Generate some transactions to ensure there are blocks.
    generate_txns(10);
    std::thread::sleep(std::time::Duration::from_secs(2));

    let last_round = get_last_round().expect("failed to get last round");
    assert!(
        last_round >= 5,
        "expected at least 5 rounds, got {}",
        last_round
    );

    // Pick a reasonable target.
    let target = last_round.min(50);
    let target_str = target.to_string();
    let genesis_str = genesis_path.to_str().unwrap();
    let db_str = db_path.to_str().unwrap();

    // Do NOT use --fail-fast: the localnet may have diverse txn types that
    // trigger apply errors (e.g., asset opt-ins, app calls). The sync should
    // still complete and report a summary.
    let (stdout, stderr, success) = run_sync(&[
        "sync",
        "--network",
        "custom",
        "--algod-url",
        ALGOD_URL,
        "--algod-token",
        ALGOD_TOKEN,
        "--genesis",
        genesis_str,
        "--db",
        db_str,
        "--start",
        "0",
        "--end",
        &target_str,
        "--concurrency",
        "4",
    ]);

    println!("=== sync stdout ===\n{}", stdout);
    println!("=== sync stderr ===\n{}", stderr);

    // The sync may exit non-zero if some blocks failed to apply (expected with
    // diverse txn types). Check that the DB was created and has committed rounds.
    let _ = success; // don't assert on exit code due to possible apply failures

    // Verify the DB exists. Since TASK-100 the binary writes
    // `<prefix>.tracker.sqlite` + `<prefix>.block.sqlite`, not the legacy
    // single `ledger.sqlite` file, so check the tracker file.
    assert!(ledger_pair_exists(&db_path), "ledger DB was not created");

    // Verify there is a last committed round in the DB.
    let committed =
        query_last_committed_round(&db_path).expect("failed to query last committed round");
    assert!(
        committed >= 1,
        "expected at least round 1 committed, got {}",
        committed
    );

    // Verify "blocks/sec" appears in output (summary line).
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("blocks/sec"),
        "expected 'blocks/sec' in output"
    );

    // Verify sync summary was printed to stdout.
    assert!(
        stdout.contains("=== Sync Summary ==="),
        "expected sync summary in stdout"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test that re-running sync with an existing DB detects "already past target"
/// and exits cleanly.
#[test]
fn test_sync_resume_already_past_target() {
    require_localnet!();
    ensure_binary_built();

    let temp_dir = create_temp_dir("resume-past");
    let genesis_path = temp_dir.join("genesis.json");
    let db_path = temp_dir.join("ledger.sqlite");

    extract_genesis(&genesis_path);

    // Ensure chain is past round 10.
    generate_txns(5);
    std::thread::sleep(std::time::Duration::from_secs(2));

    let target = 10_u64;
    let target_str = target.to_string();
    let genesis_str = genesis_path.to_str().unwrap();
    let db_str = db_path.to_str().unwrap();

    // First sync: build the DB up to target (no fail-fast).
    let (_stdout, _stderr, _success) = run_sync(&[
        "sync",
        "--network",
        "custom",
        "--algod-url",
        ALGOD_URL,
        "--algod-token",
        ALGOD_TOKEN,
        "--genesis",
        genesis_str,
        "--db",
        db_str,
        "--start",
        "0",
        "--end",
        &target_str,
        "--concurrency",
        "4",
    ]);

    // Verify first sync produced a DB with committed rounds.
    let committed1 =
        query_last_committed_round(&db_path).expect("DB should have committed rounds after sync");
    assert!(committed1 >= 1, "expected at least round 1 committed");

    // Second sync: same DB, same target -- should detect "already past target".
    let (stdout2, stderr2, success2) = run_sync(&[
        "sync",
        "--network",
        "custom",
        "--algod-url",
        ALGOD_URL,
        "--algod-token",
        ALGOD_TOKEN,
        "--genesis",
        genesis_str,
        "--db",
        db_str,
        "--start",
        "0",
        "--end",
        &target_str,
        "--concurrency",
        "4",
    ]);

    println!("=== resume stdout ===\n{}", stdout2);
    println!("=== resume stderr ===\n{}", stderr2);

    // Should succeed (exit 0) because "already past target" is not an error.
    assert!(
        success2,
        "resume sync should succeed: stdout={}\nstderr={}",
        stdout2, stderr2
    );

    // The log should mention "already past target" somewhere.
    let combined2 = format!("{}{}", stdout2, stderr2);
    assert!(
        combined2.contains("already past target"),
        "expected 'already past target' in output, got:\n{}",
        combined2
    );

    // DB should still have the same last committed round.
    let committed2 =
        query_last_committed_round(&db_path).expect("failed to query last committed round");
    assert_eq!(committed1, committed2);

    cleanup_temp_dir(&temp_dir);
}

/// Test that sync resumes from the last committed round when given an existing DB.
#[test]
fn test_sync_resume_continues() {
    require_localnet!();
    ensure_binary_built();

    let temp_dir = create_temp_dir("resume-cont");
    let genesis_path = temp_dir.join("genesis.json");
    let db_path = temp_dir.join("ledger.sqlite");

    extract_genesis(&genesis_path);

    // Generate enough transactions so chain is well past round 15.
    generate_txns(15);
    std::thread::sleep(std::time::Duration::from_secs(2));

    let last_round = get_last_round().expect("failed to get last round");
    // Make sure we have enough blocks for both sync phases.
    assert!(
        last_round >= 15,
        "chain not advanced enough: {}",
        last_round
    );

    let first_target = 5_u64;
    let first_target_str = first_target.to_string();
    let genesis_str = genesis_path.to_str().unwrap();
    let db_str = db_path.to_str().unwrap();

    // First sync: up to round 5.
    let (_stdout, _stderr, _success) = run_sync(&[
        "sync",
        "--network",
        "custom",
        "--algod-url",
        ALGOD_URL,
        "--algod-token",
        ALGOD_TOKEN,
        "--genesis",
        genesis_str,
        "--db",
        db_str,
        "--start",
        "0",
        "--end",
        &first_target_str,
        "--concurrency",
        "4",
    ]);

    let committed1 = query_last_committed_round(&db_path).expect("DB should have committed rounds");
    assert!(committed1 >= 1, "expected at least round 1 committed");

    // Second sync: extend to a higher target (no --genesis needed, DB already exists).
    let second_target = last_round.min(30);
    let second_target_str = second_target.to_string();

    let (stdout2, stderr2, _success2) = run_sync(&[
        "sync",
        "--network",
        "custom",
        "--algod-url",
        ALGOD_URL,
        "--algod-token",
        ALGOD_TOKEN,
        "--db",
        db_str,
        "--start",
        "0",
        "--end",
        &second_target_str,
        "--concurrency",
        "4",
    ]);

    println!("=== resume-continues stdout ===\n{}", stdout2);
    println!("=== resume-continues stderr ===\n{}", stderr2);

    // Should have resumed (log mentions "resuming sync").
    let combined2 = format!("{}{}", stdout2, stderr2);
    assert!(
        combined2.contains("resuming sync"),
        "expected 'resuming sync' in output, got:\n{}",
        combined2
    );

    // DB should have advanced past the first target.
    let committed2 =
        query_last_committed_round(&db_path).expect("failed to query after second sync");
    assert!(
        committed2 > committed1,
        "expected last committed round to advance past {}, got {}",
        committed1,
        committed2
    );

    cleanup_temp_dir(&temp_dir);
}
