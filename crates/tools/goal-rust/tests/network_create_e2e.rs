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

//! `goal-rust network create | pregen` end to end (issue #1993): go's messages,
//! exit codes and on-disk layout, with the real binary.

use std::path::Path;
use std::process::{Command, Output};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// One online and one offline wallet, short key validity so generation is quick.
const TEMPLATE: &str = r#"{
  "Genesis": {
    "NetworkName": "e2enet",
    "RewardsPoolBalance": 0,
    "FirstPartKeyRound": 0,
    "LastPartKeyRound": 40,
    "Wallets": [
      {"Name": "Wallet1", "Stake": 70, "Online": true},
      {"Name": "Wallet2", "Stake": 30, "Online": false}
    ]
  },
  "Nodes": [
    {"Name": "Primary", "Wallets": [{"Name": "Wallet1"}, {"Name": "Wallet2"}]}
  ]
}"#;

/// Runs goal with `network create` skipping the kmd key import (`-K`), so
/// these tests need no kmd binary; the import has its own test below.
fn goal(args: &[&str]) -> Output {
    let mut args = args.to_vec();
    if args.starts_with(&["network", "create"]) && !args.contains(&"-K") {
        args.push("-K");
    }
    goal_raw(&args)
}

fn goal_raw(args: &[&str]) -> Output {
    Command::new(GOAL_RUST_BIN)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn write_template(dir: &Path, text: &str) -> String {
    let p = dir.join("template.json");
    std::fs::write(&p, text).unwrap();
    p.display().to_string()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn create_builds_the_network_and_says_so_like_go() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &template]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("Network e2enet created under {}", root.display())),
        "{}",
        stdout(&out)
    );
    assert!(root.join("genesis.json").is_file());
    assert!(root.join("network.json").is_file());
    let gdir = root.join("Primary").join("e2enet-v1");
    assert!(gdir.join("Wallet1.rootkey").is_file());
    assert!(gdir.join("Wallet1.0.40.partkey").is_file());
    assert!(gdir.join("Wallet2.rootkey").is_file());
    assert!(!gdir.join("Wallet2.0.40.partkey").exists(), "offline wallet has no partkey");
    assert!(root.join("Primary/config.json").is_file());
}

#[test]
fn the_network_flag_names_the_network() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &template, "-n", "named"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("Network named created under "));
    assert!(root.join("Primary/named-v1").is_dir());
}

#[test]
fn dev_mode_flag_marks_the_genesis() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &template, "--devMode"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let genesis = std::fs::read_to_string(root.join("genesis.json")).unwrap();
    assert!(genesis.contains("\"devmode\": true"), "{genesis}");
}

#[test]
fn rootdir_is_required() {
    let out = goal(&["network", "create"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("required flag(s) \"rootdir\" not set"), "{}", stderr(&out));
}

#[test]
fn a_non_empty_root_is_refused_and_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("keep"), "x").unwrap();
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &template]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains(&format!("Network Root Directory '{}' already exists and is not empty", root.display())),
        "{}",
        stderr(&out)
    );
    assert!(root.join("keep").is_file());
}

#[test]
fn an_invalid_template_fails_and_cleans_up_unless_noclean() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = TEMPLATE.replace("\"Stake\": 30", "\"Stake\": 5");
    let template = write_template(tmp.path(), &bad);
    let root = tmp.path().join("net");
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &template]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("Error creating private network: invalid template: Genesis account allocations must total 100"),
        "{}",
        stderr(&out)
    );
    assert!(!root.exists(), "the partial network directory is removed");

    let root2 = tmp.path().join("net2");
    let out = goal(&["network", "create", "-r", &root2.display().to_string(), "-t", &template, "--noclean"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains(&format!(" ** failed ** - Preserving network rootdir '{}'", root2.display())));
}

#[test]
fn a_missing_template_file_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("net");
    let out = goal(&["network", "create", "-r", &root.display().to_string(), "-t", &tmp.path().join("nope.json").display().to_string()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Error creating private network: "), "{}", stderr(&out));
}

#[test]
fn pregen_then_create_reuses_the_pregenerated_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let pregen = tmp.path().join("pregen");
    let out = goal(&["network", "pregen", "-t", &template, "-p", &pregen.display().to_string()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(pregen.join("genesis.json").is_file());
    assert!(pregen.join("Wallet1.rootkey").is_file());
    assert!(pregen.join("Wallet1.0.40.partkey").is_file());
    let before = std::fs::read(pregen.join("Wallet1.rootkey")).unwrap();

    let root = tmp.path().join("net");
    let out = goal(&[
        "network", "create", "-r", &root.display().to_string(), "-t", &template,
        "-p", &pregen.display().to_string(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("Reusing existing wallet"), "{}", stdout(&out));
    let after = std::fs::read(root.join("Primary/e2enet-v1/Wallet1.rootkey")).unwrap();
    assert_eq!(before, after, "the pregenerated root key is the one in the node");
}

#[test]
fn pregen_refuses_a_rootdir_and_a_non_empty_target() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let out = goal(&["network", "pregen", "-t", &template, "-p", &tmp.path().join("p").display().to_string(), "-r", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("This command does not take a network directory as an argument. Use --pregendir flag instead."));

    let p = tmp.path().join("p2");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("f"), "x").unwrap();
    let out = goal(&["network", "pregen", "-t", &template, "-p", &p.display().to_string()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("already exists and is not empty"));
}

#[cfg(unix)]
/// Put a built `kmd-rust` next to the `goal-rust` under test, where goal's
/// kmd lookup (go: next to the goal executable) finds it.
fn ensure_kmd_next_to_goal() -> std::path::PathBuf {
    let exe = std::path::Path::new(GOAL_RUST_BIN);
    let dir = exe.parent().unwrap().to_path_buf();
    let name = format!("kmd-rust{}", std::env::consts::EXE_SUFFIX);
    if !dir.join(&name).is_file() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let st = Command::new(cargo)
            .args(["build", "-p", "kmd-rust"])
            .status()
            .expect("cargo build -p kmd-rust");
        assert!(st.success());
    }
    assert!(dir.join(&name).is_file(), "kmd-rust missing in {}", dir.display());
    dir
}

// unix only: goal cannot stop a daemon on Windows (same as `goal node stop`)
#[cfg(unix)]
#[test]
fn create_imports_the_root_keys_into_the_unencrypted_default_wallet() {
    let exe_dir = ensure_kmd_next_to_goal();
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let out = goal_raw(&["network", "create", "-r", &root.display().to_string(), "-t", &template]);
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));
    let o = stdout(&out);
    assert!(o.contains("Imported 2 keys"), "{o}");
    let kmd_dir = root.join("Primary").join("kmd-v0.5");
    assert!(kmd_dir.is_dir(), "kmd data dir created");
    // kmd was stopped again
    assert!(!kmd_dir.join("kmd.pid").exists(), "kmd still running: {}", exe_dir.display());

    // -K skips the import
    let root2 = tmp.path().join("net2");
    let out = goal(&["network", "create", "-r", &root2.display().to_string(), "-t", &template, "-K"]);
    assert!(out.status.success());
    assert!(!stdout(&out).contains("Imported"));
    assert!(!root2.join("Primary").join("kmd-v0.5").exists());
}

// unix only, see above
#[cfg(unix)]
#[test]
fn create_with_a_relative_rootdir_still_imports_the_keys() {
    ensure_kmd_next_to_goal();
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let out = Command::new(GOAL_RUST_BIN)
        .current_dir(tmp.path())
        .args(["network", "create", "-r", "relnet", "-t", &template])
        .env_remove("ALGORAND_DATA")
        .output()
        .unwrap();
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("Imported 2 keys"), "{}", stdout(&out));
}

// ---- lifecycle: start / stop / status / restart / delete (issue #1993) ----

#[cfg(unix)]
const RELAY_TEMPLATE: &str = r#"{
  "Genesis": {"NetworkName": "relaynet", "FirstPartKeyRound": 0, "LastPartKeyRound": 20,
    "Wallets": [{"Name": "W1", "Stake": 100, "Online": true}]},
  "Nodes": [{"Name": "Relay", "IsRelay": true, "Wallets": []},
            {"Name": "N1", "Wallets": [{"Name": "W1"}]}]
}"#;

#[test]
fn lifecycle_commands_need_a_deployed_network() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("nothing").display().to_string();
    for cmd in ["start", "stop", "status", "restart", "delete"] {
        let out = goal(&["network", cmd, "-r", &root]);
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        assert!(stderr(&out).contains("Error loading deployed network: "), "{cmd}: {}", stderr(&out));
    }
    let out = goal(&["network", "stop"]);
    assert!(stderr(&out).contains("required flag(s) \"rootdir\" not set"), "{}", stderr(&out));
}

// unix only: starts real daemons (algod-rust must sit next to goal-rust)
#[cfg(unix)]
#[test]
fn a_relay_and_a_node_start_wired_together() {
    let dir = ensure_kmd_next_to_goal();
    let algod = format!("algod-rust{}", std::env::consts::EXE_SUFFIX);
    if !dir.join(&algod).is_file() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        assert!(Command::new(cargo).args(["build", "-p", "algod-rust"]).status().unwrap().success());
    }
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), RELAY_TEMPLATE);
    let root = tmp.path().join("net");
    let r = root.display().to_string();
    assert!(goal(&["network", "create", "-r", &r, "-t", &template]).status.success());

    let out = goal(&["network", "start", "-r", &r]);
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains(&format!("Network Started under {r}")), "{}", stdout(&out));
    // the relay published its gossip address, like go's algod-listen.net
    let listen = std::fs::read_to_string(root.join("Relay/algod-listen.net")).unwrap();
    assert!(listen.trim().contains(':'), "{listen:?}");

    let out = goal(&["network", "status", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("[Relay]") && stdout(&out).contains("[N1]"), "{}", stdout(&out));

    let out = goal(&["network", "stop", "-r", &r]);
    assert!(out.status.success());
    assert!(!root.join("Relay/algod-listen.net").exists(), "removed on shutdown");
    let out = goal(&["network", "delete", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn stop_and_delete_report_like_go_and_delete_removes_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let r = root.display().to_string();
    assert!(goal(&["network", "create", "-r", &r, "-t", &template]).status.success());
    let out = goal(&["network", "stop", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(&format!("Network Stopped under {r}")), "{}", stdout(&out));
    let out = goal(&["network", "delete", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(&format!("Network Deleted under {r}")), "{}", stdout(&out));
    assert!(!root.exists());
}

// unix only: starting and stopping real daemons
#[cfg(unix)]
#[test]
fn a_devmode_network_starts_reports_status_restarts_and_deletes() {
    let dir = ensure_kmd_next_to_goal();
    let algod = format!("algod-rust{}", std::env::consts::EXE_SUFFIX);
    if !dir.join(&algod).is_file() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let st = Command::new(cargo).args(["build", "-p", "algod-rust"]).status().unwrap();
        assert!(st.success());
    }
    let tmp = tempfile::tempdir().unwrap();
    let template = write_template(tmp.path(), TEMPLATE);
    let root = tmp.path().join("net");
    let r = root.display().to_string();
    let out = goal(&["network", "create", "-r", &r, "-t", &template, "--devMode"]);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = goal(&["network", "start", "-r", &r]);
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains(&format!("Network Started under {r}")));

    let out = goal(&["network", "status", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("[Primary]"), "{}", stdout(&out));
    assert!(stdout(&out).contains("Last committed block:"), "{}", stdout(&out));

    let out = goal(&["network", "restart", "-r", &r]);
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));

    let out = goal(&["network", "delete", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!root.exists());

    // create --start does both
    let out = goal(&["network", "create", "-r", &r, "-t", &template, "--devMode", "--start"]);
    assert!(out.status.success(), "{} {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains(&format!("Network Started under {r}")), "{}", stdout(&out));
    let out = goal(&["network", "delete", "-r", &r]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!root.exists());
}
