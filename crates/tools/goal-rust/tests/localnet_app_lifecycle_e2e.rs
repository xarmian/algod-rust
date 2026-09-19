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

//! Localnet application-lifecycle e2e (MIXED_CLUSTER): drives `goal-rust app
//! ...` against `algod-rust node start --dev`, closing the app-lifecycle e2e
//! test-parity gap (part of #1457, batch 10, docs/phase17/parity_e2e.md).
//!
//! Mirrors three go-algorand `test/e2e-go/features/transactions` tests, all
//! against the same running Rust dev node (per-test daemon, matching
//! `localnet_node_e2e.rs`'s structure):
//!
//! - `TestApplication` (`application_test.go`): create an app whose approval
//!   program logs 32 values in a loop, and confirm the logs recorded for the
//!   create txn (read back through `GET /v2/transactions/pending/{txid}`)
//!   match Go's expected sequence exactly.
//! - `TestAccountInformationV2` (`accountv2_test.go`): create an app with a
//!   global+local "counter" program (`OptIn` on-completion so the creator
//!   opts in immediately), then have a second funded account opt in and call
//!   the app, checking the global/local counter state via `app read
//!   --global`/`--local` after each step.
//! - `TestExtraProgramPages` (`app_pages_test.go`): create/update/delete two
//!   apps with extra program pages and confirm the creator's
//!   `apps-total-extra-pages` account field tracks the sum correctly through
//!   create, update, and delete.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only (spawns external binaries), like
//! `localnet_node_e2e.rs`.
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_app_lifecycle_e2e
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// The dev account funded by the localnet-rust genesis, and its 25-word
/// mnemonic (published in `docs/DEV_WORKFLOW.md` -- local-development only).
const DEV_ADDR: &str = "E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

/// Workspace root -- `<this crate>/../../..`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Build an in-tree binary (`algod-rust` / `kmd-rust`) and return its path.
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

/// Stage a fresh node data dir with the localnet-rust dev genesis copied in.
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

/// Pull the app index out of `app create`'s "Created app with app index N"
/// line (`crates/tools/goal-rust/src/cmd/app.rs:715`).
fn parse_app_index(out: &str) -> u64 {
    out.lines()
        .find_map(|l| l.strip_prefix("Created app with app index "))
        .unwrap_or_else(|| panic!("no 'Created app with app index' line in:\n{out}"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("app index not an integer in {out:?}: {e}"))
}

/// Pull the txid out of the "Issued transaction from account ..., txid <id>
/// (fee ...)" line every `app` submit leaf prints
/// (`crates/tools/goal-rust/src/cmd/app.rs:901-906`).
fn parse_issued_txid(out: &str) -> String {
    out.split(", txid ")
        .nth(1)
        .and_then(|rest| rest.split(" (fee").next())
        .unwrap_or_else(|| panic!("no ', txid <id> (fee' segment in:\n{out}"))
        .trim()
        .to_string()
}

/// `app read --global`/`--local` writes go's `protocol.EncodeJSON` byte
/// shape (no trailing newline) -- parse it as JSON.
fn parse_state_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or_else(|e| panic!("app read output not JSON: {e}\n{out}"))
}

/// The `ui` (uint) field of a TealValue JSON entry for `key`, or `None` if
/// the key/field is absent (Go's zero-uint omitempty).
fn state_uint(state: &serde_json::Value, key: &str) -> Option<u64> {
    state.get(key).and_then(|v| v.get("ui")).and_then(|v| v.as_u64())
}

/// GET a raw `/v2/...` endpoint against the node under test, returning the
/// parsed JSON body. Mirrors `localnet_node_e2e.rs`'s raw-REST pattern (used
/// where the `algo-rest-client` wrapper doesn't expose a needed field).
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

fn setup_node_and_dev_wallet() -> (tempfile::TempDir, DaemonGuard, DaemonGuard) {
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
    let kmd = spawn_daemon(
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
    let imported = assert_cli_ok(
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
    assert!(
        imported.contains(DEV_ADDR),
        "import should report the dev address {DEV_ADDR}; got:\n{imported}"
    );

    (data_dir, node, kmd)
}

/// `TestApplication` (go-algorand
/// `test/e2e-go/features/transactions/application_test.go:36`): create an
/// application whose approval program is a v5 loop that logs "a" 30 times
/// then "b", "c" (32 logs total), and confirm the create txn's recorded logs
/// (read back through the raw REST pending-txn-info payload) match exactly.
#[test]
fn localnet_app_create_logs_confirmed_txn() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_app_lifecycle_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_app_lifecycle_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_node_and_dev_wallet();
    let dd = data_dir.path();

    let approval_teal = dd.join("counter_logs_approval.teal");
    std::fs::write(
        &approval_teal,
        "#pragma version 5\n\
         int 1\n\
         loop:\n\
         byte \"a\"\n\
         log\n\
         int 1\n\
         +\n\
         dup\n\
         int 30\n\
         <=\n\
         bnz loop\n\
         byte \"b\"\n\
         log\n\
         byte \"c\"\n\
         log\n",
    )
    .unwrap();
    let clear_teal = dd.join("counter_logs_clear.teal");
    std::fs::write(&clear_teal, "#pragma version 5\nint 1\n").unwrap();

    let create_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "create",
                "--creator",
                DEV_ADDR,
                "--on-completion",
                "optin",
                "--global-ints",
                "1",
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
        "app create (logging counter)",
        &node,
    );
    assert!(
        create_out.contains("committed in round"),
        "app create should confirm in a dev-mode round; got:\n{create_out}"
    );
    let app_id = parse_app_index(&create_out);
    assert!(app_id > 0, "app id should be nonzero; got:\n{create_out}");
    let txid = parse_issued_txid(&create_out);

    let body = get_json(dd, &format!("/v2/transactions/pending/{txid}"));
    assert!(
        body["confirmed-round"].as_u64().is_some(),
        "pending txn info should report a confirmed-round; got:\n{body}"
    );
    let logs = body["logs"]
        .as_array()
        .unwrap_or_else(|| panic!("txn.logs missing/not an array in:\n{body}"));
    let mut expected: Vec<String> = vec!["a".to_string(); 30];
    expected.push("b".to_string());
    expected.push("c".to_string());
    assert_eq!(
        logs.len(),
        expected.len(),
        "expected {} logs (30x 'a' + 'b' + 'c'); got {} in:\n{body}",
        expected.len(),
        logs.len()
    );
    // Each log entry is JSON-encoded as a plain array of byte values (same
    // shape as `txn.txn.note` in the note-roundtrip test), not a base64
    // string.
    let decoded: Vec<String> = logs
        .iter()
        .map(|v| {
            let arr = v
                .as_array()
                .unwrap_or_else(|| panic!("log entry not an array in:\n{body}"));
            let bytes: Vec<u8> = arr
                .iter()
                .map(|b| {
                    b.as_u64()
                        .unwrap_or_else(|| panic!("non-numeric log byte in:\n{body}")) as u8
                })
                .collect();
            String::from_utf8(bytes).unwrap_or_else(|e| panic!("log entry not UTF-8: {e}"))
        })
        .collect();
    assert_eq!(
        decoded, expected,
        "go's TestApplication expects exactly 30x 'a' then 'b' then 'c'"
    );
}

/// `TestAccountInformationV2` (go-algorand
/// `test/e2e-go/features/transactions/accountv2_test.go:79`): create an app
/// with a global+local "counter" program (`OnCompletion=OptIn` so the
/// creator opts in on create), have a second funded account opt in (which
/// also calls the program, bumping the counters), then call the app again
/// with a plain NoOp -- asserting the global counter and each account's
/// local counter after every step via `app read --global`/`--local`.
#[test]
fn localnet_app_lifecycle_global_local_counter_state() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_app_lifecycle_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_app_lifecycle_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_node_and_dev_wallet();
    let dd = data_dir.path();

    // A second, freshly-generated wallet account, funded from the dev
    // account -- mirrors go's `client.GenerateAddress` + funding payment.
    let user_new = assert_cli_ok(
        &goal_rust(dd, &["account", "new", "user", "--password", "pw"]),
        "account new (user)",
        &node,
    );
    let user_addr = user_new
        .strip_prefix("Created new account with address ")
        .and_then(|s| s.lines().next())
        .unwrap_or_else(|| panic!("account new prints an address; got:\n{user_new}"))
        .trim()
        .to_string();
    let fund_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "clerk",
                "send",
                "-a",
                "10000000000",
                "-f",
                DEV_ADDR,
                "-t",
                &user_addr,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "fund user account",
        &node,
    );
    assert!(
        fund_out.contains("committed in round"),
        "funding the user account should confirm; got:\n{fund_out}"
    );

    // Go's counter program (accountv2_test.go:129-152): "counter" b64 key is
    // `Y291bnRlcg==` -- spelled out here as `byte "counter"` (equivalent
    // assembly, avoids a base64-decode round-trip in the test source).
    let approval_teal = dd.join("counter_state_approval.teal");
    std::fs::write(
        &approval_teal,
        "#pragma version 2\n\
         byte \"counter\"\n\
         dup\n\
         app_global_get\n\
         int 1\n\
         +\n\
         app_global_put\n\
         int 0\n\
         int 0\n\
         app_opted_in\n\
         bnz opted_in\n\
         err\n\
         opted_in:\n\
         int 0\n\
         byte \"counter\"\n\
         int 0\n\
         byte \"counter\"\n\
         app_local_get\n\
         int 1\n\
         +\n\
         app_local_put\n\
         int 1\n",
    )
    .unwrap();
    let clear_teal = dd.join("counter_state_clear.teal");
    std::fs::write(&clear_teal, "#pragma version 2\nint 1\n").unwrap();

    // Create with OptIn on-completion: the creator opts in immediately
    // (global counter -> 1, creator's local counter -> 1).
    let create_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "create",
                "--creator",
                DEV_ADDR,
                "--on-completion",
                "optin",
                "--global-ints",
                "1",
                "--local-ints",
                "1",
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
        "app create (counter, OptIn)",
        &node,
    );
    assert!(
        create_out.contains("committed in round"),
        "app create should confirm; got:\n{create_out}"
    );
    let app_id = parse_app_index(&create_out);
    let app_id_s = app_id.to_string();

    let global_after_create = parse_state_json(&assert_cli_ok(
        &goal_rust(dd, &["app", "read", "--app-id", &app_id_s, "--global"]),
        "app read --global (after create)",
        &node,
    ));
    assert_eq!(
        state_uint(&global_after_create, "counter"),
        Some(1),
        "global counter should be 1 after create+optin; got:\n{global_after_create}"
    );
    let creator_local_after_create = parse_state_json(&assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "read", "--app-id", &app_id_s, "--local", "-f", DEV_ADDR],
        ),
        "app read --local (creator, after create)",
        &node,
    ));
    assert_eq!(
        state_uint(&creator_local_after_create, "counter"),
        Some(1),
        "creator's local counter should be 1 after create+optin; got:\n{creator_local_after_create}"
    );

    // User opts in: global counter -> 2, user's local counter -> 1.
    let optin_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "optin",
                "-f",
                &user_addr,
                "--app-id",
                &app_id_s,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app optin (user)",
        &node,
    );
    assert!(
        optin_out.contains("committed in round"),
        "app optin should confirm; got:\n{optin_out}"
    );

    let global_after_optin = parse_state_json(&assert_cli_ok(
        &goal_rust(dd, &["app", "read", "--app-id", &app_id_s, "--global"]),
        "app read --global (after user optin)",
        &node,
    ));
    assert_eq!(
        state_uint(&global_after_optin, "counter"),
        Some(2),
        "global counter should be 2 after user optin; got:\n{global_after_optin}"
    );
    let user_local_after_optin = parse_state_json(&assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "read", "--app-id", &app_id_s, "--local", "-f", &user_addr],
        ),
        "app read --local (user, after optin)",
        &node,
    ));
    assert_eq!(
        state_uint(&user_local_after_optin, "counter"),
        Some(1),
        "user's local counter should be 1 after optin; got:\n{user_local_after_optin}"
    );

    // Account info (raw REST, like go's `AccountData`): creator has exactly
    // one created app, one opted-in app.
    let creator_info = get_json(dd, &format!("/v2/accounts/{DEV_ADDR}"));
    assert_eq!(
        creator_info["total-created-apps"].as_u64(),
        Some(1),
        "creator should have exactly 1 created app; got:\n{creator_info}"
    );
    assert_eq!(
        creator_info["total-apps-opted-in"].as_u64(),
        Some(1),
        "creator should be opted in to exactly 1 app; got:\n{creator_info}"
    );

    // User calls the app with a plain NoOp: global counter -> 3, user's
    // local counter -> 2 (creator's local counter stays at 1).
    let call_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "call",
                "-f",
                &user_addr,
                "--app-id",
                &app_id_s,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app call (noop, user)",
        &node,
    );
    assert!(
        call_out.contains("committed in round"),
        "app call should confirm; got:\n{call_out}"
    );

    let global_after_call = parse_state_json(&assert_cli_ok(
        &goal_rust(dd, &["app", "read", "--app-id", &app_id_s, "--global"]),
        "app read --global (after noop call)",
        &node,
    ));
    assert_eq!(
        state_uint(&global_after_call, "counter"),
        Some(3),
        "global counter should be 3 after the noop call; got:\n{global_after_call}"
    );
    let user_local_after_call = parse_state_json(&assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "read", "--app-id", &app_id_s, "--local", "-f", &user_addr],
        ),
        "app read --local (user, after noop call)",
        &node,
    ));
    assert_eq!(
        state_uint(&user_local_after_call, "counter"),
        Some(2),
        "user's local counter should be 2 after the noop call; got:\n{user_local_after_call}"
    );
    let creator_local_after_call = parse_state_json(&assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "read", "--app-id", &app_id_s, "--local", "-f", DEV_ADDR],
        ),
        "app read --local (creator, after noop call)",
        &node,
    ));
    assert_eq!(
        state_uint(&creator_local_after_call, "counter"),
        Some(1),
        "creator's local counter should still be 1 (only user called the app); got:\n{creator_local_after_call}"
    );
}

/// `TestExtraProgramPages` (go-algorand
/// `test/e2e-go/features/transactions/app_pages_test.go:35`): create app 1
/// with 1 extra page, update it (program still fits, extra-pages field
/// unchanged), create app 2 with 2 extra pages, then delete both -- checking
/// the creator's `apps-total-extra-pages` account field after each step.
#[test]
fn localnet_app_extra_program_pages_accounting() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_app_lifecycle_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_app_lifecycle_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_node_and_dev_wallet();
    let dd = data_dir.path();

    fn apps_total_extra_pages(dd: &Path) -> u64 {
        let info = get_json(dd, &format!("/v2/accounts/{DEV_ADDR}"));
        info["apps-total-extra-pages"].as_u64().unwrap_or(0)
    }

    // Small program (fits in one page) and a big program (>2048 bytes of
    // inconsequential payload, needs extra pages) -- mirrors go's
    // `srcSmallProgram`/`srcBigProgram`.
    let small_teal = dd.join("small.teal");
    std::fs::write(&small_teal, "#pragma version 4\nint 1\nreturn\n").unwrap();
    let big_bytes_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(vec![0u8; 2048])
    };
    let big_teal = dd.join("big.teal");
    std::fs::write(
        &big_teal,
        format!(
            "#pragma version 4\nbyte base64({big_bytes_b64})\npop\nint 1\nreturn\n"
        ),
    )
    .unwrap();

    assert_eq!(
        apps_total_extra_pages(dd),
        0,
        "apps-total-extra-pages should start at 0 (or absent)"
    );

    // create app 1 with 1 extra page.
    let create1 = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "create",
                "--creator",
                DEV_ADDR,
                "--on-completion",
                "noop",
                "--global-byteslices",
                "1",
                "--local-byteslices",
                "1",
                "--extra-pages",
                "1",
                "--approval-prog",
                small_teal.to_str().unwrap(),
                "--clear-prog",
                small_teal.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app create (app1, 1 extra page)",
        &node,
    );
    assert!(
        create1.contains("committed in round"),
        "app1 create should confirm; got:\n{create1}"
    );
    let app1_id = parse_app_index(&create1).to_string();
    assert_eq!(
        apps_total_extra_pages(dd),
        1,
        "apps-total-extra-pages should be 1 after creating app1"
    );

    // update app1 to the big program (still only 1 extra page allotted to
    // it -- go's test asserts the total is unchanged after the update).
    let update1 = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "update",
                "--app-id",
                &app1_id,
                "-f",
                DEV_ADDR,
                "--approval-prog",
                big_teal.to_str().unwrap(),
                "--clear-prog",
                small_teal.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app update (app1, big program)",
        &node,
    );
    assert!(
        update1.contains("committed in round"),
        "app1 update should confirm; got:\n{update1}"
    );
    assert_eq!(
        apps_total_extra_pages(dd),
        1,
        "apps-total-extra-pages should still be 1 after updating app1's program"
    );

    // create app 2 with 2 extra pages, using the big program.
    let create2 = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "app",
                "create",
                "--creator",
                DEV_ADDR,
                "--on-completion",
                "noop",
                "--global-byteslices",
                "1",
                "--local-byteslices",
                "1",
                "--extra-pages",
                "2",
                "--approval-prog",
                big_teal.to_str().unwrap(),
                "--clear-prog",
                small_teal.to_str().unwrap(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "app create (app2, 2 extra pages)",
        &node,
    );
    assert!(
        create2.contains("committed in round"),
        "app2 create should confirm; got:\n{create2}"
    );
    let app2_id = parse_app_index(&create2).to_string();
    assert_eq!(
        apps_total_extra_pages(dd),
        3,
        "apps-total-extra-pages should be 1+2=3 after creating app2"
    );

    // delete app 1 -> total drops to 2.
    let delete1 = assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "delete", "-f", DEV_ADDR, "--app-id", &app1_id, "-w", "w", "--password", "pw"],
        ),
        "app delete (app1)",
        &node,
    );
    assert!(
        delete1.contains("committed in round"),
        "app1 delete should confirm; got:\n{delete1}"
    );
    assert_eq!(
        apps_total_extra_pages(dd),
        2,
        "apps-total-extra-pages should be 2 after deleting app1"
    );

    // delete app 2 -> total drops to 0.
    let delete2 = assert_cli_ok(
        &goal_rust(
            dd,
            &["app", "delete", "-f", DEV_ADDR, "--app-id", &app2_id, "-w", "w", "--password", "pw"],
        ),
        "app delete (app2)",
        &node,
    );
    assert!(
        delete2.contains("committed in round"),
        "app2 delete should confirm; got:\n{delete2}"
    );
    assert_eq!(
        apps_total_extra_pages(dd),
        0,
        "apps-total-extra-pages should be back to 0 after deleting both apps"
    );
}
