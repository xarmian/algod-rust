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

//! Localnet asset-lifecycle e2e (MIXED_CLUSTER): drives `goal-rust asset
//! ...` against `algod-rust node start --dev`, closing the goal-rust `asset`
//! subcommand-group gap (issue #1466) that blocked the last 4 e2e
//! test-parity rows in `docs/phase17/parity_e2e.md` (`TestAssetSend`,
//! `TestAssetGroupCreateSendDestroy`, `TestAssetCreateWaitRestartDelete`,
//! `TestAssetCreateWaitBalLookbackDelete`, tracked under #1457).
//!
//! Exercises the full `asset create` -> `asset optin` -> `asset send` ->
//! `asset send` (close-out) -> `asset destroy` lifecycle end to end, plus
//! `asset info`, against a running Rust dev node -- mirroring the
//! `TestAssetGroupCreateSendDestroy`/`TestAssetSend` scenarios (asset
//! creation, transfer to an opted-in account, and destruction once the
//! creator again holds the full supply) that go's
//! `test/e2e-go/features/transactions/asset_test.go` exercises via
//! `libgoal.Client` directly. Structure (daemon spawn, wallet setup, CLI
//! invocation helpers) mirrors `localnet_app_lifecycle_e2e.rs`.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only (spawns external binaries), like
//! `localnet_app_lifecycle_e2e.rs`/`localnet_node_e2e.rs`.
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_asset_lifecycle_e2e
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

/// Pull the asset index out of `asset create`'s "Created asset with asset
/// index N" line (`crates/tools/goal-rust/src/cmd/asset.rs`).
fn parse_asset_index(out: &str) -> u64 {
    out.lines()
        .find_map(|l| l.strip_prefix("Created asset with asset index "))
        .unwrap_or_else(|| panic!("no 'Created asset with asset index' line in:\n{out}"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("asset index not an integer in {out:?}: {e}"))
}

/// GET a raw `/v2/...` endpoint against the node under test, returning
/// `(status, parsed JSON body)`. Mirrors `localnet_app_lifecycle_e2e.rs`'s
/// raw-REST pattern, but also returns the status so callers can assert a
/// 404 (e.g. an asset that has been destroyed).
fn get_json_status(dd: &Path, path: &str) -> (u16, serde_json::Value) {
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
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        (status, body)
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

/// `TestAssetGroupCreateSendDestroy`/`TestAssetSend`-shaped lifecycle
/// (`test/e2e-go/features/transactions/asset_test.go`): create an asset,
/// opt a second account in, transfer part of the supply to it, close that
/// holding back out, and destroy the asset once the creator again holds
/// the full supply -- all driven through `goal-rust asset ...` against a
/// live node, matching the create/send/destroy lifecycle go's tests
/// exercise directly through `libgoal.Client`.
#[test]
fn localnet_asset_create_send_destroy_lifecycle() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_asset_lifecycle_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_asset_lifecycle_e2e",
        );
        return;
    }

    let (data_dir, node, _kmd) = setup_node_and_dev_wallet();
    let dd = data_dir.path();

    // A second, freshly-generated wallet account, funded from the dev
    // account -- mirrors `localnet_app_lifecycle_e2e.rs`'s user-account
    // setup.
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

    // asset create --creator DEV_ADDR --total 1000 --unitname tst --name
    // "Test Asset" --decimals 0 -w w --password pw
    let create_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "asset",
                "create",
                "--creator",
                DEV_ADDR,
                "--total",
                "1000",
                "--unitname",
                "tst",
                "--name",
                "TestAsset",
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "asset create",
        &node,
    );
    assert!(
        create_out.contains("committed in round"),
        "asset create should confirm in a dev-mode round; got:\n{create_out}"
    );
    let asset_id = parse_asset_index(&create_out);
    assert!(
        asset_id > 0,
        "asset id should be nonzero; got:\n{create_out}"
    );

    // asset info before any transfer: total==1000, issued==1000 (reserve ==
    // creator by default, so "issued" nets to total - reserve's holding,
    // which is the full total since nothing has moved yet).
    let info_out = assert_cli_ok(
        &goal_rust(dd, &["asset", "info", "--assetid", &asset_id.to_string()]),
        "asset info (pre-transfer)",
        &node,
    );
    assert!(
        info_out.contains(&format!("Asset ID:         {asset_id}")),
        "asset info should report the asset id; got:\n{info_out}"
    );
    assert!(
        info_out.contains("Creator:          ") && info_out.contains(DEV_ADDR),
        "asset info should report the creator; got:\n{info_out}"
    );
    assert!(
        info_out.contains("Unit name:        tst"),
        "asset info should report the unit name; got:\n{info_out}"
    );

    // asset optin --assetid <id> -a <user_addr> -w w --password pw
    let optin_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "asset",
                "optin",
                "--assetid",
                &asset_id.to_string(),
                "-a",
                &user_addr,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "asset optin",
        &node,
    );
    assert!(
        optin_out.contains("committed in round"),
        "asset optin should confirm; got:\n{optin_out}"
    );

    // asset send --assetid <id> -f DEV_ADDR -t <user_addr> -a 400 -w w
    // --password pw
    let send_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "asset",
                "send",
                "--assetid",
                &asset_id.to_string(),
                "-f",
                DEV_ADDR,
                "-t",
                &user_addr,
                "-a",
                "400",
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "asset send (to user)",
        &node,
    );
    assert!(
        send_out.contains("committed in round"),
        "asset send should confirm; got:\n{send_out}"
    );

    // Verify the user's holding via GET /v2/accounts/{addr}/assets/{id}.
    let (status, body) =
        get_json_status(dd, &format!("/v2/accounts/{user_addr}/assets/{asset_id}"));
    assert_eq!(
        status, 200,
        "account asset lookup should succeed; got:\n{body}"
    );
    assert_eq!(
        body["asset-holding"]["amount"].as_u64(),
        Some(400),
        "user should hold 400 units after the send; got:\n{body}"
    );

    // asset send --assetid <id> -f <user_addr> -t DEV_ADDR -a 400 -c
    // DEV_ADDR -w w --password pw -- send the full balance back to the
    // creator and close the holding out, so the creator again holds the
    // full 1000-unit supply (required for `asset destroy` to succeed).
    let send_back_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "asset",
                "send",
                "--assetid",
                &asset_id.to_string(),
                "-f",
                &user_addr,
                "-t",
                DEV_ADDR,
                "-a",
                "400",
                "-c",
                DEV_ADDR,
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "asset send (close back to creator)",
        &node,
    );
    assert!(
        send_back_out.contains("committed in round"),
        "asset send (close) should confirm; got:\n{send_back_out}"
    );

    // The user's holding should now be gone (closed out).
    let (status, _body) =
        get_json_status(dd, &format!("/v2/accounts/{user_addr}/assets/{asset_id}"));
    assert_eq!(
        status, 404,
        "user's asset holding should be closed out (404) after the close-to send"
    );

    // asset destroy --creator DEV_ADDR --assetid <id> -w w --password pw
    let destroy_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "asset",
                "destroy",
                "--creator",
                DEV_ADDR,
                "--assetid",
                &asset_id.to_string(),
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "asset destroy",
        &node,
    );
    assert!(
        destroy_out.contains("committed in round"),
        "asset destroy should confirm; got:\n{destroy_out}"
    );

    // The asset should no longer be resolvable via GET /v2/assets/{id}.
    let (status, _body) = get_json_status(dd, &format!("/v2/assets/{asset_id}"));
    assert_eq!(status, 404, "destroyed asset should no longer be found");
}
