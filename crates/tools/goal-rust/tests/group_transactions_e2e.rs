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

//! Live-node `goal-rust clerk group` / `clerk sign` / `clerk rawsend`
//! end-to-end — parity with go-algorand's
//! `test/e2e-go/features/transactions/group_test.go`
//! (`TestGroupTransactions` / `TestGroupTransactionsSubmission`, Phase 17
//! issue #1457 batch 7).
//!
//! Unlike `crates/core/algo-validate/src/rules.rs`'s
//! `validate_transaction_group_strict` unit tests and
//! `bin/algod-rust/src/commands/participate.rs`'s
//! `escaped_single_member_of_real_group_rejected_on_submission` (which drive
//! `SimpleBlockEvaluator::transaction_group` directly), this spawns a real
//! `algod-rust node start --dev` daemon and drives the *entire* CLI pipeline
//! against it over the wire: build two unsigned payments with `clerk send
//! -o`, atomically group them with `clerk group`, sign each with `clerk
//! sign` (through a real `kmd-rust`), then broadcast with `clerk rawsend`
//! against `POST /v2/transactions` — proving the group-submission behavior
//! holds through the actual REST admission path, not just the evaluator
//! call it wraps.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only (mirrors `localnet_node_e2e.rs`).
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test group_transactions_e2e
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_codec::decode_signed_txn_stream;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// The dev account funded by the localnet-rust genesis, and its 25-word
/// mnemonic (published in `docs/DEV_WORKFLOW.md` — local-development only).
const DEV_ADDR: &str = "E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";
/// The FeeSink address from the same genesis — a convenient payment recipient.
const FEE_SINK: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn ensure_rust_bin(pkg: &str) -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", pkg])
        .current_dir(&root)
        .status()
        .unwrap_or_else(|e| panic!("cargo build -p {pkg}: {e}"));
    assert!(status.success(), "cargo build -p {pkg} failed");
    for c in ["debug", "release"] {
        let p = root.join("target").join(c).join(pkg);
        if p.exists() {
            return p;
        }
    }
    panic!("{pkg} binary not found after build");
}

fn stage_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let genesis_src = workspace_root().join("docker/localnet-rust/data/genesis.json");
    std::fs::copy(&genesis_src, tmp.path().join("genesis.json"))
        .unwrap_or_else(|e| panic!("copy dev genesis from {}: {e}", genesis_src.display()));
    tmp
}

fn write_kmd_config(dir: &Path) {
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {"scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1}, "allow_unsafe_scrypt": true},
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct DaemonGuard {
    child: Child,
    name: &'static str,
    log_path: PathBuf,
}

impl DaemonGuard {
    fn log_tail(&self) -> String {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_else(|e| format!("(could not read {} log: {e})", self.name))
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        sigterm(self.child.id());
        let _ = self.child.wait();
    }
}

fn spawn_daemon(
    bin: &Path,
    args: &[&str],
    cwd_dir: &Path,
    ready_dir: &Path,
    name: &'static str,
    stem: &str,
) -> DaemonGuard {
    let log_path = cwd_dir.join(format!("{name}.log"));
    let log = std::fs::File::create(&log_path)
        .unwrap_or_else(|e| panic!("create {} log at {}: {e}", name, log_path.display()));
    let log_err = log.try_clone().expect("clone log handle");
    let child = Command::new(bin)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    let mut guard = DaemonGuard {
        child,
        name,
        log_path,
    };

    let net = ready_dir.join(format!("{stem}.net"));
    let tok = ready_dir.join(format!("{stem}.token"));
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            panic!(
                "{name} exited before readiness (status {status:?}); log:\n{}",
                guard.log_tail()
            );
        }
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return guard;
            }
        }
        if start.elapsed() > Duration::from_secs(60) {
            panic!(
                "{name} did not write {stem}.net/{stem}.token within 60s at {}; log:\n{}",
                ready_dir.display(),
                guard.log_tail()
            );
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn goal_rust(dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn assert_cli_ok(out: &std::process::Output, what: &str, node: &DaemonGuard) -> String {
    assert!(
        out.status.success(),
        "{what} failed: exit={:?}\n  stdout={}\n  stderr={}\n  --- node log ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        node.log_tail(),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Spawn a Rust dev node + kmd-rust, and set up wallet "w" (password "pw")
/// with the funded dev account imported. Returns the guards (kept alive for
/// the duration of the test) and the staged data-dir tempdir.
fn setup_live_node() -> (tempfile::TempDir, DaemonGuard, DaemonGuard) {
    let algod_rust = ensure_rust_bin("algod-rust");
    let kmd_rust = ensure_rust_bin("kmd-rust");

    let data_dir = stage_data_dir();
    let dd = data_dir.path().to_path_buf();

    let node = spawn_daemon(
        &algod_rust,
        &[
            "node",
            "start",
            "-d",
            dd.to_str().unwrap(),
            "-l",
            "127.0.0.1:0",
            "--dev",
        ],
        &dd,
        &dd,
        "node",
        "algod",
    );

    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let kmd = spawn_daemon(
        &kmd_rust,
        &["serve", "--data-dir", kmd_dir.to_str().unwrap()],
        &dd,
        &kmd_dir,
        "kmd",
        "kmd",
    );

    assert_cli_ok(
        &goal_rust(
            &dd,
            &["wallet", "new", "w", "-w", "pw", "--no-display-seed"],
        ),
        "wallet new",
        &node,
    );
    let imported = assert_cli_ok(
        &goal_rust(
            &dd,
            &[
                "account",
                "import",
                "-w",
                "w",
                "--password",
                "pw",
                "--mnemonic",
                DEV_MNEMONIC,
            ],
        ),
        "account import",
        &node,
    );
    assert!(
        imported.contains(DEV_ADDR),
        "import should report the dev address {DEV_ADDR}; got:\n{imported}"
    );

    (data_dir, node, kmd)
}

/// Build two unsigned self-funded payments from `DEV_ADDR`, concatenate them
/// into one file, and atomically group them via `clerk group`. Returns the
/// path to the grouped (unsigned) file.
fn build_grouped_payments(dd: &Path, node: &DaemonGuard, amt_a: u64, amt_b: u64) -> PathBuf {
    let a = dd.join("pay_a.tx");
    let b = dd.join("pay_b.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "send",
                "-a",
                &amt_a.to_string(),
                "-f",
                DEV_ADDR,
                "-t",
                FEE_SINK,
                "-o",
                a.to_str().unwrap(),
            ],
        ),
        "clerk send -o (txn a, unsigned)",
        node,
    );
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "send",
                "-a",
                &amt_b.to_string(),
                "-f",
                DEV_ADDR,
                "-t",
                FEE_SINK,
                "-o",
                b.to_str().unwrap(),
            ],
        ),
        "clerk send -o (txn b, unsigned)",
        node,
    );

    // Concatenate the two unsigned txn files (mirrors `cat a.tx b.tx >
    // pair.tx`, as go's TestGroupTransactions does via `catFiles`).
    let pair = dd.join("pair.tx");
    let mut buf = std::fs::read(&a).expect("read txn a");
    buf.extend(std::fs::read(&b).expect("read txn b"));
    std::fs::write(&pair, &buf).expect("write pair.tx");

    let grouped = dd.join("grouped.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "group",
                "-i",
                pair.to_str().unwrap(),
                "-o",
                grouped.to_str().unwrap(),
            ],
        ),
        "clerk group",
        node,
    );
    grouped
}

/// Balance parsing helper shared with `localnet_node_e2e.rs`'s convention.
fn parse_balance(out: &str) -> Option<u64> {
    out.split_whitespace().next().and_then(|t| t.parse().ok())
}

#[test]
fn group_transactions_submit_and_confirm_together() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: group_transactions_submit_and_confirm_together requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test group_transactions_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_live_node();
    let dd = data_dir.path();

    let before = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (before)",
        &node,
    ))
    .expect("recipient balance is an integer");

    let amt_a: u64 = 1_500_000;
    let amt_b: u64 = 2_500_000;
    let grouped = build_grouped_payments(dd, &node, amt_a, amt_b);

    // Sanity: the two txns in the grouped file share a nonzero, matching
    // group id (mirrors `group_assigns_group_id_to_each_txn` in
    // `clerk_fileutils_e2e.rs`, now against a live-node-priced pair).
    let grouped_bytes = std::fs::read(&grouped).expect("read grouped.tx");
    let grouped_txns = decode_signed_txn_stream(&grouped_bytes).expect("decode grouped.tx");
    assert_eq!(grouped_txns.len(), 2, "expected a 2-member group");
    assert_ne!(
        grouped_txns[0].txn.group, [0u8; 32],
        "group id must be assigned"
    );
    assert_eq!(
        grouped_txns[0].txn.group, grouped_txns[1].txn.group,
        "both members must share the group id"
    );

    // Sign each member (both are sent by DEV_ADDR, the only wallet key).
    let signed = dd.join("signed.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "sign",
                "-i",
                grouped.to_str().unwrap(),
                "-o",
                signed.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "clerk sign",
        &node,
    );

    // Broadcast the whole signed group with `clerk rawsend` and wait for
    // both to confirm.
    let rawsend_out = assert_cli_ok(
        &goal_rust(dd, &["clerk", "rawsend", "-f", signed.to_str().unwrap()]),
        "clerk rawsend (grouped)",
        &node,
    );
    let committed_rounds: Vec<&str> = rawsend_out
        .lines()
        .filter(|l| l.contains("committed in round"))
        .collect();
    assert_eq!(
        committed_rounds.len(),
        2,
        "both group members should confirm; got:\n{rawsend_out}"
    );
    // Dev mode produces one block per accepted group, so both members land
    // in the very same round (the defining atomicity property this test —
    // parity with go's TestGroupTransactions — is proving).
    fn round_of(line: &str) -> &str {
        line.rsplit("committed in round ")
            .next()
            .expect("round suffix")
            .trim()
    }
    assert_eq!(
        round_of(committed_rounds[0]),
        round_of(committed_rounds[1]),
        "grouped members must commit in the same round; got:\n{rawsend_out}"
    );

    let after = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (after)",
        &node,
    ))
    .expect("recipient balance is an integer");
    assert!(
        after >= before + amt_a + amt_b,
        "recipient balance should grow by >= {} (before={before}, after={after})",
        amt_a + amt_b
    );
}

/// Parity with go-algorand's `TestGroupTransactionsSubmission`: signing and
/// broadcasting only ONE member of a genuine multi-member atomic group must
/// be rejected — the group ID stamped on the escaped transaction was
/// computed over both members, so the hash recomputed over the lone
/// submission does not match. This exercises the exact wire path
/// `POST /v2/transactions` -> pool admission uses (dev mode inlines block
/// production on submit), complementing the direct-evaluator coverage in
/// `bin/algod-rust/src/commands/participate.rs`'s
/// `escaped_single_member_of_real_group_rejected_on_submission`.
#[test]
fn group_transactions_escaped_single_member_rejected_live() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: group_transactions_escaped_single_member_rejected_live requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test group_transactions_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_live_node();
    let dd = data_dir.path();

    let amt_a: u64 = 750_000;
    let amt_b: u64 = 900_000;
    let grouped = build_grouped_payments(dd, &node, amt_a, amt_b);

    // Split the grouped (still unsigned) file back into two single-txn
    // files, each still carrying the shared group id.
    let split_base = dd.join("split.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "split",
                "-i",
                grouped.to_str().unwrap(),
                "-o",
                split_base.to_str().unwrap(),
            ],
        ),
        "clerk split",
        &node,
    );
    let member_a = dd.join("split-0.tx");
    assert!(member_a.exists(), "split-0.tx missing");

    // Sign just that one escaped member.
    let signed_a = dd.join("signed_a.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "sign",
                "-i",
                member_a.to_str().unwrap(),
                "-o",
                signed_a.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "clerk sign (escaped member a)",
        &node,
    );

    // Balance before the (expected-to-be-rejected) submission, to confirm no
    // funds moved.
    let before = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (before escaped submit)",
        &node,
    ))
    .expect("recipient balance is an integer");

    // `clerk rawsend` on the lone escaped member must fail: the node's
    // pool-admission path rejects it (group ID mismatch), matching go's
    // TestGroupTransactionsSubmission expectation that a real atomic group
    // cannot be partially submitted.
    let out = goal_rust(dd, &["clerk", "rawsend", "-f", signed_a.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "submitting one member of a real group alone must be rejected; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("group") || combined.contains("Group"),
        "rejection should reference the group-ID mismatch; got:\n{combined}"
    );

    let after = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (after escaped submit)",
        &node,
    ))
    .expect("recipient balance is an integer");
    assert_eq!(
        after, before,
        "recipient balance must not change when the escaped member is rejected"
    );
}
