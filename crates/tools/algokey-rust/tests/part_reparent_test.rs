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

//! Integration test for `algokey-rust part reparent`.

use std::path::PathBuf;
use std::process::Command;

use algo_types::Address;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn tmp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algokey-rust-part-rep-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Build a checksummed base32 address string from a deterministic seed —
/// avoids hard-coding a magic mainnet address in tests.
fn deterministic_address(seed: u8) -> String {
    // Sha512_256 wrapping is overkill; just need a stable 32-byte pubkey-
    // shaped value with the Algorand checksum.
    let mut bytes = [seed; 32];
    bytes[0] ^= 0xA5;
    let addr = Address(bytes);
    // Display impl emits the canonical base32+checksum encoding.
    format!("{addr}")
}

#[test]
fn reparent_updates_parent_and_preserves_every_other_field() {
    let path = tmp_db_path("happy");
    let original_parent = deterministic_address(0x11);
    let new_parent = deterministic_address(0x77);

    // 1. Generate a small partkey with original parent.
    let gen = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            &original_parent,
        ])
        .output()
        .expect("spawn generate");
    assert!(
        gen.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    // 2. Capture pre-reparent info output so we can diff every line
    // except `Parent address:`.
    let pre_info = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("info");
    assert!(pre_info.status.success());
    let pre = String::from_utf8(pre_info.stdout).unwrap();
    assert!(pre.contains(&format!("Parent address:    {original_parent}\n")));

    // 3. Reparent.
    let rep = algokey_bin()
        .args(["part", "reparent", "--keyfile"])
        .arg(&path)
        .args(["--parent", &new_parent])
        .output()
        .expect("spawn reparent");
    assert!(
        rep.status.success(),
        "reparent failed: stderr {}",
        String::from_utf8_lossy(&rep.stderr)
    );
    let rep_stdout = String::from_utf8(rep.stdout).unwrap();
    // Reparent prints the partkey with the NEW parent.
    assert!(
        rep_stdout.contains(&format!("Parent address:    {new_parent}\n")),
        "reparent stdout missing new parent line: {rep_stdout}"
    );

    // 4. Re-read via info; the new parent must be present and every
    // other line must match the pre-reparent capture.
    let post_info = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("info");
    assert!(post_info.status.success());
    let post = String::from_utf8(post_info.stdout).unwrap();
    assert!(post.contains(&format!("Parent address:    {new_parent}\n")));
    assert!(!post.contains(&format!("Parent address:    {original_parent}\n")));

    // Strict per-line equality on every non-parent line.
    let strip_parent = |s: &str| -> String {
        s.lines()
            .filter(|l| !l.starts_with("Parent address:"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        strip_parent(&pre),
        strip_parent(&post),
        "non-parent fields must round-trip unchanged"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn reparent_rejects_bad_parent_with_go_wording() {
    let path = tmp_db_path("badparent");
    // Need a valid partkey so we get past open / restore.
    let parent = deterministic_address(0x22);
    let gen = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            &parent,
        ])
        .output()
        .expect("gen");
    assert!(gen.status.success());

    let rep = algokey_bin()
        .args(["part", "reparent", "--keyfile"])
        .arg(&path)
        .args(["--parent", "not-an-address"])
        .output()
        .expect("rep");
    assert!(!rep.status.success(), "must exit non-zero");
    let stderr = String::from_utf8_lossy(&rep.stderr);
    assert!(
        stderr.contains("Cannot parse parent address not-an-address"),
        "actual stderr: {stderr}"
    );

    let _ = std::fs::remove_file(&path);
}
