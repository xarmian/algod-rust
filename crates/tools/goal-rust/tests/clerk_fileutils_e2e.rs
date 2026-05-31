//! Offline `clerk` txn-file utilities — `inspect` / `split` / `group`
//! (TASK-289, PLAN-288). These are local file transforms with no network, so
//! they're exercised by building a transaction file on disk and driving the
//! `goal-rust` binary against it.
//!
//! When `../go-algorand` is present and builds, the same inputs are run through
//! Go's `goal` and the outputs are compared for parity — gated like
//! `localnet_node_e2e`'s Go section so the default run still asserts the
//! goal-rust behavior on its own.
//!
//! ```bash
//! cargo test -p goal-rust --test clerk_fileutils_e2e
//! # With Go parity (builds ../go-algorand/cmd/goal):
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test clerk_fileutils_e2e
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use algo_codec::{canonical_encode_signed_transaction, decode_signed_txn_stream};
use algo_types::{Address, SignedTransaction, Transaction, TxnType};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Build Go's `goal` from `../go-algorand`, returning `None` (with a logged
/// reason) when the checkout is absent or the build fails.
fn try_ensure_go_goal() -> Option<PathBuf> {
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("goal");
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd/goal").exists() {
        eprintln!("Go-parity SKIPPED: ../go-algorand/cmd/goal not found");
        return None;
    }
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./cmd/goal")
        .current_dir(&goalg)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        Ok(s) => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/goal` exited {s:?}");
            None
        }
        Err(e) => {
            eprintln!("Go-parity SKIPPED: failed to invoke `go build`: {e}");
            None
        }
    }
}

fn unsigned_payment(amount: u64, sender: [u8; 32], receiver: [u8; 32]) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            sender: Address(sender),
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1001.into(),
            genesis_hash: [9u8; 32],
            amount,
            receiver: Address(receiver),
            ..Transaction::default()
        },
        ..SignedTransaction::default()
    }
}

/// Write two concatenated unsigned txns to `<dir>/txns.tx` and return the path.
fn write_two_txn_file(dir: &Path) -> (PathBuf, Vec<SignedTransaction>) {
    let a = unsigned_payment(1_000, [1u8; 32], [2u8; 32]);
    let b = unsigned_payment(2_000, [3u8; 32], [4u8; 32]);
    let mut buf = Vec::new();
    buf.extend_from_slice(&canonical_encode_signed_transaction(&a));
    buf.extend_from_slice(&canonical_encode_signed_transaction(&b));
    let path = dir.join("txns.tx");
    std::fs::write(&path, &buf).expect("write txn file");
    (path, vec![a, b])
}

fn goal_rust(args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn assert_ok(out: &std::process::Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: exit={:?}\n  stdout={}\n  stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn inspect_prints_decoded_txns() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (path, txns) = write_two_txn_file(tmp.path());

    let out = assert_ok(
        &goal_rust(&["clerk", "inspect", path.to_str().unwrap()]),
        "clerk inspect",
    );
    // Two transactions are indexed [0] and [1] with the filename prefix.
    let p = path.display().to_string();
    assert!(
        out.contains(&format!("{p}[0]")),
        "missing [0] header:\n{out}"
    );
    assert!(
        out.contains(&format!("{p}[1]")),
        "missing [1] header:\n{out}"
    );
    // Sender addresses render in base32, amounts as decimal.
    assert!(
        out.contains(&Address([1u8; 32]).to_algorand_string()),
        "missing sender base32 address:\n{out}"
    );
    assert!(out.contains("\"amt\": 1000"), "missing amt 1000:\n{out}");
    assert!(out.contains("\"amt\": 2000"), "missing amt 2000:\n{out}");
    assert!(
        out.contains("\"type\": \"pay\""),
        "missing type pay:\n{out}"
    );

    // With --txid, each header carries the transaction id (base32).
    let out_txid = assert_ok(
        &goal_rust(&["clerk", "inspect", "--txid", path.to_str().unwrap()]),
        "clerk inspect --txid",
    );
    let txid0 = algo_codec::compute_txn_id(&txns[0].txn).to_string();
    assert!(
        out_txid.contains(&format!("{p}[0] - {txid0}")),
        "missing txid header:\n{out_txid}"
    );
}

#[test]
fn split_writes_one_file_per_txn() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (path, txns) = write_two_txn_file(tmp.path());
    let out_base = tmp.path().join("out.tx");

    let stdout = assert_ok(
        &goal_rust(&[
            "clerk",
            "split",
            "-i",
            path.to_str().unwrap(),
            "-o",
            out_base.to_str().unwrap(),
        ]),
        "clerk split",
    );
    let f0 = tmp.path().join("out-0.tx");
    let f1 = tmp.path().join("out-1.tx");
    assert!(
        stdout.contains(&format!("Wrote transaction 0 to {}", f0.display())),
        "missing split line 0:\n{stdout}"
    );
    assert!(f0.exists() && f1.exists(), "split output files missing");

    // Each output file decodes to exactly the matching original transaction.
    let d0 = decode_signed_txn_stream(&std::fs::read(&f0).unwrap()).unwrap();
    assert_eq!(d0.len(), 1);
    assert_eq!(d0[0].txn.amount, txns[0].txn.amount);
}

#[test]
fn group_assigns_group_id_to_each_txn() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (path, _txns) = write_two_txn_file(tmp.path());
    let out = tmp.path().join("grouped.tx");

    assert_ok(
        &goal_rust(&[
            "clerk",
            "group",
            "-i",
            path.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ]),
        "clerk group",
    );
    let grouped = decode_signed_txn_stream(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(grouped.len(), 2);
    assert_ne!(grouped[0].txn.group, [0u8; 32], "group id not assigned");
    assert_eq!(
        grouped[0].txn.group, grouped[1].txn.group,
        "both txns must share the group id"
    );
    // The assigned group id must match the codec computation for the pair.
    let expected = algo_codec::compute_group_id(&[grouped[0].txn.clone(), grouped[1].txn.clone()]);
    assert_eq!(grouped[0].txn.group, expected.0);
}

#[test]
fn group_rejects_already_grouped_input() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (path, _txns) = write_two_txn_file(tmp.path());
    let out = tmp.path().join("grouped.tx");
    // First grouping succeeds.
    assert_ok(
        &goal_rust(&[
            "clerk",
            "group",
            "-i",
            path.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ]),
        "clerk group (first)",
    );
    // Re-grouping the already-grouped file must fail.
    let out2 = tmp.path().join("grouped2.tx");
    let rerun = goal_rust(&[
        "clerk",
        "group",
        "-i",
        out.to_str().unwrap(),
        "-o",
        out2.to_str().unwrap(),
    ]);
    assert!(!rerun.status.success(), "re-grouping should fail");
    let stderr = String::from_utf8_lossy(&rerun.stderr);
    assert!(
        stderr.contains("already part of a group"),
        "missing already-grouped error:\n{stderr}"
    );
}

/// Go-parity: when `../go-algorand` builds, the `group` output bytes and the
/// `inspect` JSON must match Go's `goal` exactly for the same input file.
#[test]
fn go_parity_group_and_inspect() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: go_parity_group_and_inspect requires MIXED_CLUSTER=1 (builds ../go-algorand)."
        );
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        eprintln!("go_parity_group_and_inspect: SKIPPED (no buildable ../go-algorand).");
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let (path, _txns) = write_two_txn_file(tmp.path());

    // --- group parity: identical output bytes. ---
    let rust_out = tmp.path().join("grouped_rust.tx");
    let go_out = tmp.path().join("grouped_go.tx");
    assert_ok(
        &goal_rust(&[
            "clerk",
            "group",
            "-i",
            path.to_str().unwrap(),
            "-o",
            rust_out.to_str().unwrap(),
        ]),
        "clerk group (rust)",
    );
    let go_status = Command::new(&go_goal)
        .args(["clerk", "group", "-i"])
        .arg(&path)
        .arg("-o")
        .arg(&go_out)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run go goal group");
    assert!(
        go_status.status.success(),
        "go goal group failed: {}",
        String::from_utf8_lossy(&go_status.stderr)
    );
    assert_eq!(
        std::fs::read(&rust_out).unwrap(),
        std::fs::read(&go_out).unwrap(),
        "grouped output bytes must match Go byte-for-byte"
    );

    // --- inspect parity: identical pretty JSON. ---
    let rust_inspect = assert_ok(
        &goal_rust(&["clerk", "inspect", path.to_str().unwrap()]),
        "clerk inspect (rust)",
    );
    let go_inspect = Command::new(&go_goal)
        .args(["clerk", "inspect"])
        .arg(&path)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run go goal inspect");
    assert!(
        go_inspect.status.success(),
        "go goal inspect failed: {}",
        String::from_utf8_lossy(&go_inspect.stderr)
    );
    assert_eq!(
        rust_inspect,
        String::from_utf8_lossy(&go_inspect.stdout),
        "inspect output must match Go exactly"
    );
}
