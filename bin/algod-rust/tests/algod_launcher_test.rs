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

//! Live test of the go-compatible `algod -d <datadir>` launcher (issue #1990):
//! the real binary is started on a go-layout data directory, must publish
//! `algod.net`/`algod.token`/`algod.pid`, refuse a second instance on the same
//! directory with go's message, and remove `algod.pid` when it is stopped with
//! SIGTERM (which is how `goal node stop` ends it).

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_types::Address;

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SAFETY: plain libc `kill(2)` on a pid we spawned.
    unsafe {
        kill(pid as i32, 15);
    }
}

struct NodeGuard(Child);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            sigterm(self.0.id());
            let _ = self.0.wait();
        }
    }
}

fn write_data_dir(dir: &Path) {
    let funded = Address([0x11; 32]).to_algorand_string();
    let fees = Address([0xFE; 32]).to_algorand_string();
    let rwd = Address([0xFD; 32]).to_algorand_string();
    let genesis = format!(
        r#"{{"id":"v1","network":"launcher","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{rwd}","comment":"RewardsPool","state":{{"algo":100000,"onl":2}}}},{{"addr":"{funded}","comment":"Wallet1","state":{{"algo":10000000,"onl":0}}}}]}}"#
    );
    std::fs::write(dir.join("genesis.json"), genesis).unwrap();
    // go's EndpointAddress: an ephemeral local port
    std::fs::write(
        dir.join("config.json"),
        r#"{"EndpointAddress": "127.0.0.1:0"}"#,
    )
    .unwrap();
}

fn algod(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_algod-rust"));
    cmd.arg("algod").arg("-d").arg(dir);
    cmd
}

fn wait_for(path: &Path, what: &str) -> String {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if let Ok(text) = std::fs::read_to_string(path) {
            if !text.trim().is_empty() {
                return text.trim().to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} ({}) did not appear within 60s", path.display());
}

#[test]
fn algod_dash_d_starts_a_node_with_go_files_and_single_instance_guard() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    write_data_dir(dir);

    let node = NodeGuard(
        algod(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn algod-rust algod"),
    );
    let pid = node.0.id();

    // go's discovery files, written by the running daemon
    let net = wait_for(&dir.join("algod.net"), "algod.net");
    assert!(net.contains(':'), "algod.net must hold host:port, got {net:?}");
    assert!(!wait_for(&dir.join("algod.token"), "algod.token").is_empty());
    assert_eq!(
        wait_for(&dir.join("algod.pid"), "algod.pid"),
        pid.to_string(),
        "algod.pid must hold the daemon's pid so `goal node stop` can find it"
    );
    // the ledger lives in go's per-genesis directory
    assert!(
        dir.join("launcher-v1").is_dir(),
        "ledger directory <datadir>/<genesisID> missing"
    );

    // a second instance on the same data dir is refused with go's message
    let second = algod(dir).output().expect("second algod");
    assert!(!second.status.success(), "second instance must fail");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("failed to lock algod.lock; is an instance of algod already running in this data directory?"),
        "unexpected stderr: {stderr}"
    );

    // SIGTERM (what `goal node stop` sends) ends it and removes algod.pid
    sigterm(pid);
    let mut node = node;
    let start = Instant::now();
    loop {
        if node.0.try_wait().expect("wait").is_some() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "algod did not exit within 60s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !dir.join("algod.pid").exists(),
        "algod.pid must be removed on a SIGTERM shutdown"
    );
}

#[test]
fn algod_dash_g_prints_the_genesis_id_like_go() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_data_dir(tmp.path());
    let out = algod(tmp.path()).arg("-G").output().expect("algod -G");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "launcher-v1");
}

#[test]
fn algod_without_a_data_dir_fails_with_gos_message() {
    let out = Command::new(env!("CARGO_BIN_EXE_algod-rust"))
        .arg("algod")
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("algod");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(
        "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment."
    ));
}

/// A `"devmode": true` genesis (what `goal network create --devMode` writes,
/// and the Docker image's `DEV_MODE=1`) has no agreement; `algod -d` must run
/// it as the instant-block dev node, still with go's files and SIGTERM stop.
#[test]
fn algod_dash_d_runs_a_devmode_genesis_as_the_dev_node() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    write_data_dir(dir);
    let genesis = std::fs::read_to_string(dir.join("genesis.json")).unwrap();
    std::fs::write(
        dir.join("genesis.json"),
        genesis.replacen('{', "{\"devmode\":true,", 1),
    )
    .unwrap();

    let node = NodeGuard(
        algod(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn algod-rust algod"),
    );
    let pid = node.0.id();
    let net = wait_for(&dir.join("algod.net"), "algod.net");
    assert!(net.contains(':'), "{net:?}");
    assert_eq!(wait_for(&dir.join("algod.pid"), "algod.pid"), pid.to_string());
    assert!(dir.join("launcher-v1").is_dir());

    sigterm(pid);
    let mut node = node;
    let start = Instant::now();
    while node.0.try_wait().expect("wait").is_none() {
        assert!(start.elapsed() < Duration::from_secs(60), "no exit within 60s of SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!dir.join("algod.pid").exists());
}
