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

//! Acceptance test for `algod-rust node start` (TASK-263 / PLAN-262).
//!
//! Spawns the real binary against a fresh data dir with an inline genesis,
//! then verifies the read-serving REST API: it writes the discovery files,
//! seeds genesis state, serves `/v2/status` / `/genesis` / `/v2/accounts`, and
//! authorizes with EITHER the public or the admin token (the go-algorand rule
//! that lets `goal` — which prefers the admin token — drive the node).

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use algo_types::Address;

const FUNDED_AMOUNT: u64 = 5_000_000;

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct NodeGuard(Child);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

/// A self-contained genesis: one funded account + valid fee-sink / rewards-pool
/// addresses, `proto: "future"` (a recognized consensus version).
fn write_genesis(dir: &Path, funded: &str) {
    let fees = Address([0xFE; 32]).to_algorand_string();
    let rwd = Address([0xFD; 32]).to_algorand_string();
    let genesis = format!(
        r#"{{"id":"v1","network":"localnet","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{funded}","comment":"Wallet1","state":{{"algo":{FUNDED_AMOUNT},"onl":0}}}}]}}"#
    );
    std::fs::write(dir.join("genesis.json"), genesis).unwrap();
}

fn spawn_node(dir: &Path) -> NodeGuard {
    let bin = env!("CARGO_BIN_EXE_algod-rust");
    let child = Command::new(bin)
        .args(["node", "start", "-d"])
        .arg(dir)
        .args(["--listen", "127.0.0.1:0"])
        .spawn()
        .expect("spawn algod-rust node start");
    NodeGuard(child)
}

/// Poll for the server-written `algod.net`; return (base_url, api_token, admin_token).
fn wait_ready(dir: &Path) -> (String, String, String) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if let Ok(net) = std::fs::read_to_string(dir.join("algod.net")) {
            let net = net.trim();
            if !net.is_empty() {
                let api = std::fs::read_to_string(dir.join("algod.token")).unwrap_or_default();
                let admin =
                    std::fs::read_to_string(dir.join("algod.admin.token")).unwrap_or_default();
                if !api.trim().is_empty() && !admin.trim().is_empty() {
                    return (
                        format!("http://{net}"),
                        api.trim().to_string(),
                        admin.trim().to_string(),
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("node did not write algod.net/algod.token within 30s");
}

async fn get(client: &reqwest::Client, url: &str, token: &str) -> reqwest::Response {
    client
        .get(url)
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .expect("request")
}

#[tokio::test]
async fn node_start_serves_reads_and_accepts_both_tokens() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let funded = Address([0x11; 32]).to_algorand_string();
    write_genesis(dir, &funded);

    let _node = spawn_node(dir);
    let (base, api_token, admin_token) = wait_ready(dir);
    let client = reqwest::Client::new();

    // /v2/status authorizes with the PUBLIC token...
    let r = get(&client, &format!("{base}/v2/status"), &api_token).await;
    assert_eq!(r.status(), 200, "status with api token");
    let status: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status["last-round"], 0, "fresh genesis is at round 0");

    // ...and ALSO with the ADMIN token (the go rule that lets `goal` drive it).
    let r = get(&client, &format!("{base}/v2/status"), &admin_token).await;
    assert_eq!(r.status(), 200, "status with admin token must be accepted");

    // ...and a wrong token is rejected.
    let r = get(&client, &format!("{base}/v2/status"), "deadbeef").await;
    assert_eq!(r.status(), 401, "bogus token must be 401");

    // /genesis is public (no token) and carries the funded address.
    let r = client
        .get(format!("{base}/genesis"))
        .send()
        .await
        .expect("genesis request");
    assert_eq!(r.status(), 200);
    assert!(
        r.text().await.unwrap().contains(&funded),
        "/genesis must echo the configured allocation"
    );

    // /v2/blocks/0 serves the genesis block (TASK-270) — previously 500'd
    // because no round-0 block existed.
    let r = get(
        &client,
        &format!("{base}/v2/blocks/0?format=json"),
        &api_token,
    )
    .await;
    assert_eq!(r.status(), 200, "genesis block must serve");
    let blk: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        blk["block"]["gen"], "localnet-v1",
        "genesis block carries the genesis id"
    );

    // /v2/accounts/{addr} returns the genesis-funded balance.
    let r = get(
        &client,
        &format!("{base}/v2/accounts/{funded}"),
        &admin_token,
    )
    .await;
    assert_eq!(r.status(), 200, "account lookup");
    let acct: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        acct["amount"], FUNDED_AMOUNT,
        "account amount must match the genesis allocation"
    );
}

#[tokio::test]
async fn node_start_reopens_existing_ledger_without_reseeding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let funded = Address([0x22; 32]).to_algorand_string();
    write_genesis(dir, &funded);

    // First boot seeds genesis; drop it, then boot again on the same data dir.
    {
        let _node = spawn_node(dir);
        let (base, api_token, _admin) = wait_ready(dir);
        let client = reqwest::Client::new();
        let r = get(&client, &format!("{base}/v2/accounts/{funded}"), &api_token).await;
        assert_eq!(r.status(), 200);
    }
    // Clear the first boot's discovery file so `wait_ready` blocks on the
    // second node's fresh (OS-picked) port rather than racing on the stale one.
    std::fs::remove_file(dir.join("algod.net")).ok();

    // Second boot must reopen (not re-seed / not error) and still serve.
    let _node = spawn_node(dir);
    let (base, api_token, _admin) = wait_ready(dir);
    let client = reqwest::Client::new();
    let r = get(&client, &format!("{base}/v2/accounts/{funded}"), &api_token).await;
    assert_eq!(
        r.status(),
        200,
        "second boot must reopen the existing ledger"
    );
    let acct: serde_json::Value = r.json().await.unwrap();
    assert_eq!(acct["amount"], FUNDED_AMOUNT);
}
