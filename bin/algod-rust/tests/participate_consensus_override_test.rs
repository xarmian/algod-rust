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

//! Issue #814 live-verification finding: `algod-rust node start`
//! (`bin/algod-rust/src/commands/node.rs`, proven by
//! `consensus_override_wire_test.rs`) loads `<data_dir>/consensus.json`, but
//! `algod-rust participate` (`bin/algod-rust/src/commands/participate.rs`) --
//! the actual entry point a consensus-participating node runs, and the one
//! `ops/mixed-cluster/` uses -- silently never did. Discovered while
//! deploying a shortened `StateProofInterval` consensus.json to a live
//! mixed-cluster soak: the 3 go-algorand relays honored the override but the
//! Rust participant kept running the built-in default, a genuine
//! validation-parameter mismatch between peers.
//!
//! This test spawns a real `algod-rust participate` process (no peers, so it
//! never actually reaches agreement) against a data dir carrying a
//! `consensus.json` that raises `MinTxnFee`, and asserts the live
//! `/v2/transactions/params` REST response reflects the override --
//! mirroring `consensus_override_wire_test.rs`'s proof for `node start`.

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use algo_types::consensus::{built_in_consensus_protocols, CONSENSUS_FUTURE};
use algo_types::Address;

const OVERRIDE_MULTIPLIER: u64 = 5;

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

fn write_genesis(dir: &Path, funded: &str) {
    let fees = Address([0xFE; 32]).to_algorand_string();
    let rwd = Address([0xFD; 32]).to_algorand_string();
    let genesis = format!(
        r#"{{"id":"v1","network":"localnet","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{funded}","comment":"Wallet1","state":{{"algo":10000000,"onl":0}}}}]}}"#
    );
    std::fs::write(dir.join("genesis.json"), genesis).unwrap();
}

/// Same real, go-algorand-authored fixture `consensus_override_wire_test.rs`
/// uses, with only `MinTxnFee` overwritten.
fn write_consensus_override(dir: &Path, overridden_min_fee: u64) {
    const FIXTURE: &str = include_str!("../../../docker/config/vfuture-consensus.json");
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE)
        .expect("docker/config/vfuture-consensus.json must be valid JSON");
    value["future"]["MinTxnFee"] = serde_json::Value::from(overridden_min_fee);
    let encoded = serde_json::to_vec_pretty(&value).expect("re-encode consensus.json");
    std::fs::write(dir.join("consensus.json"), encoded).expect("write consensus.json");
}

fn spawn_participate(dir: &Path, ledger_path: &Path, partkey_path: &Path, port: u16) -> NodeGuard {
    let bin = env!("CARGO_BIN_EXE_algod-rust");
    let child = Command::new(bin)
        .arg("participate")
        .arg("--ledger-path")
        .arg(ledger_path)
        .arg("--partkey-path")
        .arg(partkey_path)
        .args(["--genesis-id", "v1"])
        .arg("--genesis-json")
        .arg(dir.join("genesis.json"))
        .args(["--network", "localnet"])
        .args(["--peers", ""])
        .args(["--rest-listen", &format!("127.0.0.1:{port}")])
        .arg("--data-dir")
        .arg(dir)
        .spawn()
        .expect("spawn algod-rust participate");
    NodeGuard(child)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
}

async fn wait_for_params(
    c: &reqwest::Client,
    base: &str,
    token: &str,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = c
            .get(format!("{base}/v2/transactions/params"))
            .header("X-Algo-API-Token", token)
            .send()
            .await
        {
            if resp.status().as_u16() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    return body;
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("participate node's /v2/transactions/params never became reachable on {base}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn live_participate_node_loads_consensus_json_override() {
    let pristine_min_fee = built_in_consensus_protocols()
        .get(CONSENSUS_FUTURE)
        .expect("\"future\" must be a known built-in protocol version")
        .min_txn_fee;
    let overridden_min_fee = pristine_min_fee.saturating_mul(OVERRIDE_MULTIPLIER);
    assert!(
        overridden_min_fee > pristine_min_fee,
        "the override must actually raise the fee floor for this test to be meaningful"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    write_genesis(dir, &Address([0x01; 32]).to_algorand_string());
    write_consensus_override(dir, overridden_min_fee);

    let ledger_path = dir.join("ledger");
    let partkey_path = dir.join("partkeys.sqlite");
    // Fixed-ish port derived from the tempdir's own address entropy would be
    // nicer, but 0 (`--rest-listen 127.0.0.1:0`) isn't supported by
    // `participate`'s `algod.net` write-back path used by `node start`'s
    // test, so pick a high, likely-free port instead.
    let port = 21500u16 + (std::process::id() as u16 % 2000);
    let _node = spawn_participate(dir, &ledger_path, &partkey_path, port);

    let base = format!("http://127.0.0.1:{port}");
    let token_path = dir.join("algod.token");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !token_path.exists() {
        if Instant::now() >= deadline {
            panic!("participate node never wrote algod.token under {dir:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let token = std::fs::read_to_string(&token_path).unwrap();
    let token = token.trim();

    let c = client();
    let params = wait_for_params(&c, &base, token).await;
    assert_eq!(
        params["min-fee"].as_u64(),
        Some(overridden_min_fee),
        "a live `algod-rust participate` process must load <data_dir>/consensus.json exactly like \
         `node start` does -- got params: {params}"
    );
}
