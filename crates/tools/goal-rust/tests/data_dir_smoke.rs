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

//! Smoke tests for the binary that touch the data-dir resolver via
//! environment + argv combinations.
//!
//! Phase A acceptance (TASK-221): `--help` must NEVER trigger data-dir
//! resolution (it has to work in CI with no `$ALGORAND_DATA` set), and
//! the env var must NOT leak into help rendering. Subcommand bodies
//! that depend on a data dir come in A4..A11; the module itself is
//! covered by unit tests in `src/data_dir.rs`.

use std::process::Command;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

#[test]
fn root_help_works_with_no_datadir_env_or_flag() {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("--help")
        .env_remove("ALGORAND_DATA")
        .env_remove("ALGORAND_KMD")
        .output()
        .expect("run goal-rust --help");
    assert!(out.status.success(), "exit={:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Usage: goal-rust"),
        "no Usage line: {stdout:?}"
    );
}

#[test]
fn group_help_works_with_algorand_data_set_to_garbage() {
    // `--help` must not validate the env value — it just renders text.
    let out = Command::new(GOAL_RUST_BIN)
        .args(["node", "--help"])
        .env("ALGORAND_DATA", "/no/such/dir/should/not/be/checked")
        .output()
        .expect("run goal-rust node --help");
    assert!(out.status.success(), "exit={:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // clap renders the subcommand's usage line from the running
    // executable's file name, which is `goal-rust.exe` on Windows vs
    // `goal-rust` elsewhere — check for the binary name as a prefix
    // rather than an exact literal so this passes on both.
    let has_usage_line = stdout
        .lines()
        .any(|l| l.starts_with("Usage: goal-rust") && l.contains(" node "));
    assert!(has_usage_line, "no Usage line: {stdout:?}");
}

#[test]
fn group_help_works_with_no_env_at_all() {
    let out = Command::new(GOAL_RUST_BIN)
        .args(["wallet", "--help"])
        .env_remove("ALGORAND_DATA")
        .env_remove("ALGORAND_KMD")
        .output()
        .expect("run goal-rust wallet --help");
    assert!(out.status.success(), "exit={:?}", out.status.code());
}
