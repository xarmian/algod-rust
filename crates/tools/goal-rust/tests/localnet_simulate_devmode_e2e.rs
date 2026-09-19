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

//! `TestSimulateTxnTracerDevMode` (go-algorand
//! `test/e2e-go/restAPI/simulate/simulateRestAPI_test.go:46`): a dev-mode
//! node (single-node, rounds only advance on real txn submission) simulates
//! a payment via `goal-rust clerk simulate` and the test asserts the dry-run
//! did NOT change the current round or either balance involved -- part of
//! #1457, batch 10, `docs/phase17/parity_e2e.md`.
//!
//! Also `TestSimulateScratchSlotChange` (go-algorand
//! `test/e2e-go/restAPI/simulate/simulateRestAPI_test.go:1700`): a dev-mode
//! node runs `goal-rust clerk simulate --trace --scratch` against a real app
//! call whose approval program writes the same value to the same scratch
//! slot twice (`store 1` then `load 1; dup; stores`), and the live REST
//! response's `exec-trace.approval-program-trace` must report **two**
//! separate scratch-change entries for slot 1 (both value 1) rather than
//! deduping the second, same-value write away -- part of #1457, batch 11,
//! `docs/phase17/parity_e2e.md`. This exercises the full CLI -> REST ->
//! `Simulator`/`SimulationTracer` round trip; prior coverage
//! (`crates/core/algo-ledger/tests/simulation_trace_test.rs`) only drove
//! `SimulationTracer` through direct Rust calls, not a live simulate
//! request.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only, mirroring
//! `localnet_node_e2e.rs`/`localnet_app_lifecycle_e2e.rs`.
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_simulate_devmode_e2e
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const DEV_ADDR: &str = "E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";
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

fn parse_balance(out: &str) -> Option<u64> {
    out.split_whitespace().next().and_then(|t| t.parse().ok())
}

fn get_json(dd: &Path, path: &str) -> serde_json::Value {
    let algod_net = std::fs::read_to_string(dd.join("algod.net"))
        .expect("algod.net written by spawn_daemon readiness poll")
        .trim()
        .to_string();
    let algod_token = std::fs::read_to_string(dd.join("algod.token"))
        .expect("algod.token written by spawn_daemon readiness poll")
        .trim()
        .to_string();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let url = format!("http://{algod_net}{path}");
        let resp = reqwest::Client::new()
            .get(&url)
            .header("X-Algo-API-Token", &algod_token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url}: {e}"));
        assert!(
            resp.status().is_success(),
            "GET {url} returned {}",
            resp.status()
        );
        resp.json().await.expect("response is valid JSON")
    })
}

/// go's `TestSimulateTxnTracerDevMode`: simulating a payment against a
/// dev-mode node does not advance the round and does not move either
/// balance -- a pure dry run.
#[test]
fn localnet_dev_node_simulate_is_dry_run() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_simulate_devmode_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_simulate_devmode_e2e",
        );
        return;
    }

    let algod_rust = ensure_rust_bin("algod-rust");
    let kmd_rust = ensure_rust_bin("kmd-rust");

    let data_dir = stage_data_dir();
    let dd = data_dir.path();

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
        dd,
        dd,
        "node",
        "algod",
    );

    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let _kmd = spawn_daemon(
        &kmd_rust,
        &["serve", "--data-dir", kmd_dir.to_str().unwrap()],
        dd,
        &kmd_dir,
        "kmd",
        "kmd",
    );

    assert_cli_ok(
        &goal_rust(dd, &["wallet", "new", "w", "-w", "pw", "--no-display-seed"]),
        "wallet new",
        &node,
    );
    assert_cli_ok(
        &goal_rust(
            dd,
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

    let round_before = get_json(dd, "/v2/status")["last-round"]
        .as_u64()
        .expect("status has last-round");
    let sender_before = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", DEV_ADDR]),
        "sender balance (before simulate)",
        &node,
    ))
    .expect("sender balance is an integer");
    let recipient_before = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (before simulate)",
        &node,
    ))
    .expect("recipient balance is an integer");

    let sim_amt: u64 = 500_000;
    let unsigned = dd.join("simulate-unsigned.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "send",
                "-a",
                &sim_amt.to_string(),
                "-f",
                DEV_ADDR,
                "-t",
                FEE_SINK,
                "-o",
                unsigned.to_str().unwrap(),
            ],
        ),
        "clerk send -o (for simulate)",
        &node,
    );
    let sim_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "simulate",
                "-t",
                unsigned.to_str().unwrap(),
                "--allow-empty-signatures",
            ],
        ),
        "clerk simulate",
        &node,
    );
    let sim_json: serde_json::Value =
        serde_json::from_str(&sim_out).expect("simulate output is JSON");

    // Mirrors go's `a.Equal(result.LastRound, currentRoundBeforeSimulate)`
    // and the post-simulate re-check: dev-mode rounds only advance on real
    // submission, so a dry-run simulate must report (and leave) the same
    // round.
    assert_eq!(
        sim_json["last-round"].as_u64(),
        Some(round_before),
        "simulate should report the pre-simulate round unchanged; got:\n{sim_out}"
    );
    let round_after = get_json(dd, "/v2/status")["last-round"]
        .as_u64()
        .expect("status has last-round");
    assert_eq!(
        round_after, round_before,
        "the node's round should not advance from a simulate-only request"
    );

    let group0 = &sim_json["txn-groups"][0];
    assert!(
        group0.get("failure-message").is_none(),
        "simulate of a valid payment should not report a failure-message; got:\n{sim_out}"
    );

    // Mirrors go's post-simulate balance checks: the simulated payment must
    // NOT actually have been applied to the ledger.
    let sender_after = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", DEV_ADDR]),
        "sender balance (after simulate)",
        &node,
    ))
    .expect("sender balance is an integer");
    let recipient_after = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (after simulate)",
        &node,
    ))
    .expect("recipient balance is an integer");
    assert_eq!(
        sender_after, sender_before,
        "simulate must not deduct the payment+fee from the sender's real balance"
    );
    assert_eq!(
        recipient_after, recipient_before,
        "simulate must not credit the payment to the recipient's real balance"
    );

    // A real payment submitted right after the simulate must still succeed
    // (proves simulate leaves the ledger in a clean, reusable state -- not
    // wedged by a dangling snapshot transaction).
    let real_send = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "send",
                "-a",
                &sim_amt.to_string(),
                "-f",
                DEV_ADDR,
                "-t",
                FEE_SINK,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "clerk send (real, after simulate)",
        &node,
    );
    assert!(
        real_send.contains("committed in round"),
        "a real payment submitted after simulate should still confirm; got:\n{real_send}"
    );
}

/// Pull the app index out of `app create`'s "Created app with app index N"
/// line (`crates/tools/goal-rust/src/cmd/app.rs`).
fn parse_app_index(out: &str) -> u64 {
    out.lines()
        .find_map(|l| l.strip_prefix("Created app with app index "))
        .unwrap_or_else(|| panic!("no 'Created app with app index' line in:\n{out}"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("app index not an integer in {out:?}: {e}"))
}

/// go's `TestSimulateScratchSlotChange`: a live simulate request with
/// `ExecTraceConfig{Enable: true, Scratch: true}` against an app call whose
/// approval program writes the same value to the same scratch slot twice
/// (`store 1`, then `load 1; dup; stores`) must report both writes as
/// separate `scratch-changes` entries -- go's tracer records a slot write
/// unconditionally, even when the new value equals the value already there.
#[test]
fn localnet_dev_node_simulate_scratch_slot_change() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_simulate_devmode_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_simulate_devmode_e2e",
        );
        return;
    }

    let algod_rust = ensure_rust_bin("algod-rust");
    let kmd_rust = ensure_rust_bin("kmd-rust");

    let data_dir = stage_data_dir();
    let dd = data_dir.path();

    // `--dev` already turns on `EnableDeveloperAPI` (required for exec-trace
    // requests), so no config.json toggling is needed here -- unlike go's
    // test, which starts with it off to also assert the disabled-API error.
    // That negative path (and the "basic trace must be enabled ..." /
    // "EnableDeveloperAPI turned off ..." error text) is already pinned at
    // the crate level in
    // `crates/core/algo-ledger/tests/simulation_trace_test.rs`, so this live
    // test focuses on the part that unit tests cannot reach: an actual
    // REST/CLI round trip producing correct scratch-change output.
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
        dd,
        dd,
        "node",
        "algod",
    );

    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let _kmd = spawn_daemon(
        &kmd_rust,
        &["serve", "--data-dir", kmd_dir.to_str().unwrap()],
        dd,
        &kmd_dir,
        "kmd",
        "kmd",
    );

    assert_cli_ok(
        &goal_rust(dd, &["wallet", "new", "w", "-w", "pw", "--no-display-seed"]),
        "wallet new",
        &node,
    );
    assert_cli_ok(
        &goal_rust(
            dd,
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

    // Same approval program as go's test (simulateRestAPI_test.go:1729):
    // on create (`CurrentApplicationID == 0`) it just approves; on a later
    // NoOp call it writes 1 to scratch slot 1 twice, via `store` and then
    // `stores` (same value both times).
    let approval_teal = dd.join("scratch_change_approval.teal");
    std::fs::write(
        &approval_teal,
        "#pragma version 8\n\
         global CurrentApplicationID\n\
         bz end\n\
         int 1\n\
         store 1\n\
         load 1\n\
         dup\n\
         stores\n\
         end:\n\
         int 1\n",
    )
    .unwrap();
    let clear_teal = dd.join("scratch_change_clear.teal");
    std::fs::write(&clear_teal, "#pragma version 8\nint 1\n").unwrap();

    let create_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "create",
                "--creator",
                DEV_ADDR,
                "--approval-prog",
                approval_teal.to_str().unwrap(),
                "--clear-prog",
                clear_teal.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app create (scratch-change)",
        &node,
    );
    assert!(
        create_out.contains("committed in round"),
        "app create should confirm in a dev-mode round; got:\n{create_out}"
    );
    let app_id = parse_app_index(&create_out);
    assert!(app_id > 0, "app id should be nonzero; got:\n{create_out}");
    let app_id_s = app_id.to_string();

    // Build the (unsigned) NoOp app-call transaction to a file, matching
    // go's construct-then-simulate flow -- this is the call whose approval
    // program actually executes the store/stores scratch writes.
    let call_unsigned = dd.join("scratch-call-unsigned.tx");
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "call",
                "-f",
                DEV_ADDR,
                "--app-id",
                &app_id_s,
                "-o",
                call_unsigned.to_str().unwrap(),
            ],
        ),
        "app call -o (for simulate)",
        &node,
    );

    // Negative check, mirroring go's first assertion: `--scratch` without
    // `--trace` (basic trace) must fail validation, independent of
    // `EnableDeveloperAPI` (which is already on via `--dev` here).
    let bad_sim = goal_rust(
        dd,
        &[
            "clerk",
            "simulate",
            "-t",
            call_unsigned.to_str().unwrap(),
            "--allow-empty-signatures",
            "--scratch",
        ],
    );
    assert!(
        !bad_sim.status.success(),
        "simulate with --scratch but no --trace should fail; got:\n stdout={}\n stderr={}",
        String::from_utf8_lossy(&bad_sim.stdout),
        String::from_utf8_lossy(&bad_sim.stderr)
    );
    let bad_sim_stderr = String::from_utf8_lossy(&bad_sim.stderr);
    assert!(
        bad_sim_stderr
            .contains("basic trace must be enabled when enabling scratch slot change tracing"),
        "expected the scratch-without-trace validation error; got stderr:\n{bad_sim_stderr}"
    );

    // Real simulate: `--trace --scratch` enables both basic and scratch
    // execution tracing.
    let sim_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "simulate",
                "-t",
                call_unsigned.to_str().unwrap(),
                "--allow-empty-signatures",
                "--trace",
                "--scratch",
            ],
        ),
        "clerk simulate --trace --scratch",
        &node,
    );
    let sim_json: serde_json::Value =
        serde_json::from_str(&sim_out).expect("simulate output is JSON");

    assert!(
        sim_json["txn-groups"][0].get("failure-message").is_none(),
        "simulate of the scratch-change app call should not fail; got:\n{sim_out}"
    );

    let approval_trace = sim_json["txn-groups"][0]["txn-results"][0]["exec-trace"]
        ["approval-program-trace"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("expected exec-trace.approval-program-trace array in:\n{sim_out}")
        });

    // Collect every opcode-trace unit that reports a scratch-changes entry.
    let scratch_units: Vec<&serde_json::Value> = approval_trace
        .iter()
        .filter(|u| u.get("scratch-changes").is_some())
        .collect();

    // go's expected trace has exactly two scratch-changes-bearing units
    // (pc 10 for `store 1`, pc 15 for `stores`), both writing slot 1 = 1.
    // The unconditional-write bug (issue #1225) would have collapsed this
    // to a single, or zero, entries since the second write doesn't change
    // the slot's value.
    assert_eq!(
        scratch_units.len(),
        2,
        "expected exactly 2 scratch-change opcode units (store + stores, both writing slot 1 \
         with the same value); got {} in trace:\n{}",
        scratch_units.len(),
        serde_json::to_string_pretty(approval_trace).unwrap()
    );
    for unit in &scratch_units {
        let changes = unit["scratch-changes"]
            .as_array()
            .expect("scratch-changes is an array");
        assert_eq!(changes.len(), 1, "expected one change per unit: {unit}");
        let change = &changes[0];
        assert_eq!(change["slot"].as_u64(), Some(1), "wrong slot in {change}");
        let new_value = &change["new-value"];
        assert_eq!(
            new_value["type"].as_u64(),
            Some(2),
            "expected uint type in {new_value}"
        );
        assert_eq!(
            new_value["uint"].as_u64(),
            Some(1),
            "expected value 1 in {new_value}"
        );
    }
}
