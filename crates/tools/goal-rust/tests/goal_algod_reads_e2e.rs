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

//! go's `goal` commands that read from algod, run against a mock algod that
//! serves canned responses (issue #2460):
//! - `goal ledger block` (`cmd/goal/ledger.go` `blockCmd`): the block's
//!   msgpack transcoded to JSON (`protocol/transcode`), `--b32`, `--strict`,
//!   `-r`, `-o`, and its errors;
//! - `goal version` (`cmd/goal/commands.go` `versionCmd`), with and without
//!   `-v`, one or two data dirs, and a failing `/versions`;
//! - `goal account list` (`cmd/goal/account.go` `listCmd`): the accounts of
//!   the one wallet `ensureWalletHandle` picks, with their status, balance,
//!   multisig threshold, created assets/apps and opted-in apps, and `--info`;
//! - go's `errorRequestFail` (`Error processing command: %s`) for a failing
//!   `/v2/accounts` request (`account balance` / `rewards` / `info`);
//! - go's request errors (`restClient.submitForm`, issue #2466) for every
//!   command above plus `node status` and `ledger supply`: a refused
//!   connection (`Get "<url>": dial tcp <addr>: connect: connection
//!   refused`, `algod.net` naming a closed port), an answer-less close
//!   (`Get "<url>": EOF`), a 401 (`Unauthorized request to ...`), and
//!   go-codec's decode of malformed JSON answers (`json decode error [pos
//!   N]: ...`, or what go-codec accepts that JSON does not);
//! - issue #2476: the same for `account assetdetails`, `account info`'s held
//!   assets, `asset info`, `app info`, `account listpartkeys` /
//!   `partkeyinfo` and the POST / DELETE of `node catchup`; and what go's
//!   `net/http` client makes of answers that are not well-formed HTTP, of the
//!   server's own reason phrase (`resp.Status`, raw bytes), of redirects and
//!   of hosts that do not resolve (`dial tcp: lookup <host> on <DNS>: no
//!   such host`, the host's DNS server masked).
//!
//! `fixtures/goal_algod_reads.jsonl` holds what go v5.0.5-stable's `goal`
//! printed (exit code, stdout, stderr, the data dir masked; a stdout longer
//! than 8 KiB as its SHA-256, an output that is not valid UTF-8 as
//! `base64:<bytes>`) and the files it left in the data dir. Each row
//! runs in a fresh data dir with its own mock algod; the account rows first
//! create two unencrypted wallets and import keys with the same `goal` (and
//! the `kmd` next to it, go's for go's goal, `kmd-rust` for goal-rust).
//!
//! goal-rust must produce the same rows (a default test, no go needed); a
//! `MIXED_CLUSTER=1` run re-checks the file against a real go `goal` and
//! `kmd` (`GOAL_GO` / `KMD_GO` name prebuilt ones), and
//! `REGEN_GOAL_ALGOD_READS_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_GOAL_ALGOD_READS_FIXTURE=1 cargo test -p goal-rust \
//!   --test goal_algod_reads_e2e goal_algod_reads_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

mod common;
use common::pty::{run_env, Stdin};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/goal_algod_reads.jsonl";

const GENESIS: &str = r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#;

/// The files the data dir holds before the command runs.
const INPUTS: [&str; 3] = ["genesis.json", "algod.net", "algod.token"];

/// Directories listed but not walked: kmd's own files are compared by
/// `goal_client_e2e`, and the cached wallet handles are named after random
/// wallet IDs.
const NOT_WALKED: [&str; 2] = ["kmd-v0.5", "goal.cache"];

/// A stdout longer than this is compared by its SHA-256.
const MAX_INLINE: usize = 8192;

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// `<env>` names a prebuilt Go binary; otherwise build
/// `../go-algorand/cmd/<name>`.
fn try_ensure_go_binary(env: &str, name: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env) {
        return Some(PathBuf::from(p));
    }
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join(name);
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd").join(name).exists() {
        eprintln!("Go-parity SKIPPED: ../go-algorand/cmd/{name} not found");
        return None;
    }
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(format!("./cmd/{name}"))
        .current_dir(&goalg)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        _ => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/{name}` failed");
            None
        }
    }
}

fn kmd_rust_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", "kmd-rust"])
        .current_dir(&root)
        .status()
        .expect("cargo build kmd-rust");
    assert!(status.success());
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"))
            .join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found");
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---- the accounts -----------------------------------------------------------

/// `(mnemonic, address)` of the key whose seed is 32 bytes of `b`.
fn key(b: u8) -> (String, String) {
    let seed = [b; 32];
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    (
        algo_consensus_crypto::key_to_mnemonic(&seed).expect("mnemonic"),
        algo_types::Address(pk).to_string(),
    )
}

/// What the mock algod answers for `GET /v2/accounts/<addr>`, by address.
fn account_json(addr: &str) -> Option<(u16, String)> {
    let (a1, a2, a3) = (key(1).1, key(2).1, key(3).1);
    if addr == a1 {
        Some((
            200,
            serde_json::json!({
                "address": a1,
                "amount": 1_000_000u64,
                "amount-without-pending-rewards": 1_000_000u64,
                "min-balance": 100_000u64,
                "pending-rewards": 0,
                "rewards": 7,
                "round": 5,
                "status": "Online",
                "total-apps-opted-in": 1,
                "total-assets-opted-in": 0,
                "total-created-apps": 2,
                "total-created-assets": 2,
                "created-assets": [
                    {"index": 12, "params": {"creator": a1, "decimals": 2, "total": 12345, "unit-name": "T<K>", "name": "Tok", "url": "https://x"}},
                    {"index": 11, "params": {"creator": a1, "decimals": 0, "total": 5}}
                ],
                "created-apps": [
                    {"id": 7, "params": {"creator": a1, "approval-program": "", "clear-state-program": "", "global-state-schema": {"num-uint": 2, "num-byte-slice": 1}, "extra-program-pages": 1}},
                    {"id": 5, "params": {"creator": a1, "approval-program": "", "clear-state-program": ""}}
                ],
                "apps-local-state": [
                    {"id": 9, "schema": {"num-uint": 1, "num-byte-slice": 0}}
                ]
            })
            .to_string(),
        ))
    } else if addr == a2 {
        Some((
            200,
            serde_json::json!({
                "address": a2, "amount": 0, "amount-without-pending-rewards": 0,
                "min-balance": 100_000u64, "pending-rewards": 0, "rewards": 0, "round": 5,
                "status": "Offline", "total-apps-opted-in": 0, "total-assets-opted-in": 0,
                "total-created-apps": 0, "total-created-assets": 0
            })
            .to_string(),
        ))
    } else if addr == a3 {
        Some((
            200,
            serde_json::json!({
                "address": a3, "amount": 42, "amount-without-pending-rewards": 42,
                "min-balance": 100_000u64, "pending-rewards": 0, "rewards": 3, "round": 5,
                "status": "Not Participating", "total-apps-opted-in": 0,
                "total-assets-opted-in": 0, "total-created-apps": 0, "total-created-assets": 0,
                "participation": {"selection-participation-key": "BAUG",
                    "vote-participation-key": "AQID", "vote-first-valid": 1,
                    "vote-last-valid": 3000000, "vote-key-dilution": 10000}
            })
            .to_string(),
        ))
    } else if addr == key(4).1 {
        Some((500, "boom <b>\n".to_string()))
    } else if addr == key(6).1 {
        // held assets: found, found through `name-b64`, unknown, failing
        Some((
            200,
            serde_json::json!({
                "address": key(6).1, "amount": 1, "min-balance": 100_000u64, "round": 5,
                "status": "Offline",
                "assets": [
                    {"asset-id": 13, "amount": 1},
                    {"asset-id": 99, "amount": 2},
                    {"asset-id": 9, "amount": 15},
                    {"asset-id": 12, "amount": 1234, "is-frozen": true}
                ],
                "created-assets": [{"index": 12, "params": asset_params(12)}]
            })
            .to_string(),
        ))
    } else {
        None
    }
}

/// A msgpack unsigned integer in its shortest form.
fn mp_u(n: u64) -> Vec<u8> {
    match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0xcc, n as u8],
        0x100..=0xffff => [vec![0xcd], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![0xce], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![0xcf], n.to_be_bytes().to_vec()].concat(),
    }
}

fn mp_map_head(n: usize) -> Vec<u8> {
    if n < 16 {
        vec![0x80 | n as u8]
    } else {
        [vec![0xde], (n as u16).to_be_bytes().to_vec()].concat()
    }
}

/// A canonical msgpack map with string keys, sorted like go's msgp.
fn mp_obj(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(&str, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut v = mp_map_head(entries.len());
    for (k, e) in sorted {
        v.extend_from_slice(&s(k));
        v.extend_from_slice(e);
    }
    v
}

/// A msgpack map with integer keys.
fn mp_imap(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut v = mp_map_head(entries.len());
    for (k, e) in entries {
        v.extend_from_slice(&mp_u(*k));
        v.extend_from_slice(e);
    }
    v
}

fn addr_bytes(i: u8) -> Vec<u8> {
    algo_types::Address::from_algorand_string(&key(i).1)
        .expect("address")
        .0
        .to_vec()
}

/// The all-zero address.
const ZERO_ADDRESS: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// What the mock algod answers for `GET /v2/accounts/<addr>?format=msgpack`:
/// go's `basics.AccountData`, as algod encodes it (`protocol.CodecHandle`).
fn account_msgpack(addr: &str) -> Option<(u16, Vec<u8>)> {
    if addr == key(1).1 {
        let tv_bytes = |b: &[u8]| mp_obj(&[("tb", mp_str(b)), ("tt", mp_u(1))]);
        let tv_uint = |u: u64| mp_obj(&[("tt", mp_u(2)), ("ui", mp_u(u))]);
        Some((
            200,
            mp_obj(&[
                ("onl", mp_u(1)),
                ("algo", mp_u(1_000_000)),
                ("ebase", mp_u(3)),
                ("ern", mp_u(7)),
                ("vote", mp_bin(&[0x11; 32])),
                ("sel", mp_bin(&[0x22; 32])),
                ("stprf", mp_bin(&[0x33; 64])),
                ("voteFst", mp_u(1)),
                ("voteLst", mp_u(3_000_000)),
                ("voteKD", mp_u(10_000)),
                ("lpr", mp_u(4)),
                ("lhb", mp_u(5)),
                (
                    "apar",
                    mp_imap(&[
                        (
                            12,
                            mp_obj(&[
                                ("am", mp_bin(&[0x44; 32])),
                                ("an", s("Tok<&>")),
                                ("au", s("https://x")),
                                ("c", mp_bin(&addr_bytes(2))),
                                ("dc", mp_u(2)),
                                ("df", vec![0xc3]),
                                ("f", mp_bin(&addr_bytes(2))),
                                ("m", mp_bin(&addr_bytes(1))),
                                ("r", mp_bin(&addr_bytes(1))),
                                ("t", mp_u(12345)),
                                ("un", s("T\u{2028}K")),
                            ]),
                        ),
                        (9, mp_obj(&[("t", mp_u(5))])),
                    ]),
                ),
                (
                    "asset",
                    mp_imap(&[
                        (10, mp_obj(&[("a", mp_u(1))])),
                        (12, mp_obj(&[("a", mp_u(100)), ("f", vec![0xc3])])),
                        (9, mp_obj(&[])),
                    ]),
                ),
                ("spend", mp_bin(&addr_bytes(3))),
                ("ie", vec![0xc3]),
                (
                    "appl",
                    mp_imap(&[(
                        9,
                        mp_obj(&[
                            ("hsch", mp_obj(&[("nbs", mp_u(1)), ("nui", mp_u(1))])),
                            (
                                "tkv",
                                mp_obj(&[("k<", tv_bytes(b"v&\xff\n")), ("n", tv_uint(5))]),
                            ),
                        ]),
                    )]),
                ),
                (
                    "appp",
                    mp_imap(&[
                        (
                            7,
                            mp_obj(&[
                                ("approv", mp_bin(&[6, 0x81, 1])),
                                ("clearp", mp_bin(&[6, 0x81, 1])),
                                ("epp", mp_u(1)),
                                ("fba", vec![0xc3]),
                                ("fbr", vec![0xc3]),
                                ("gs", mp_obj(&[("g", tv_uint(1)), ("", tv_bytes(b""))])),
                                ("gsch", mp_obj(&[("nbs", mp_u(1)), ("nui", mp_u(2))])),
                                ("lsch", mp_obj(&[("nui", mp_u(1))])),
                                ("ss", mp_bin(&addr_bytes(2))),
                                ("v", mp_u(3)),
                            ]),
                        ),
                        (
                            5,
                            mp_obj(&[("approv", mp_bin(&[2])), ("clearp", mp_bin(&[2]))]),
                        ),
                    ]),
                ),
                ("tsch", mp_obj(&[("nbs", mp_u(2)), ("nui", mp_u(3))])),
                ("teap", mp_u(1)),
                ("tbx", mp_u(2)),
                ("tbxb", mp_u(64)),
            ]),
        ))
    } else if addr == key(2).1 {
        Some((200, mp_obj(&[])))
    } else if addr == ZERO_ADDRESS {
        Some((200, mp_obj(&[("algo", mp_u(5))])))
    } else if addr == key(3).1 {
        Some((200, mp_obj(&[("algo", mp_u(42)), ("onl", mp_u(2))])))
    } else if addr == key(4).1 {
        Some((500, b"boom <b>\n".to_vec()))
    } else {
        None
    }
}

// ---- the blocks -------------------------------------------------------------

fn mp_str(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    match s.len() {
        n if n < 32 => v.push(0xa0 | n as u8),
        n if n < 256 => v.extend_from_slice(&[0xd9, n as u8]),
        n => {
            v.push(0xda);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    v.extend_from_slice(s);
    v
}

fn mp_bin(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0xc4, b.len() as u8];
    v.extend_from_slice(b);
    v
}

fn mp_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![0xde];
    v.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (k, e) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(e);
    }
    v
}

fn mp_arr(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0xdc];
    v.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for i in items {
        v.extend_from_slice(i);
    }
    v
}

fn s(x: &str) -> Vec<u8> {
    mp_str(x.as_bytes())
}

/// A msgpack value with each kind `transcode` handles: int keys, binary
/// values under string keys (`:b64`), arrays of binary values, a mixed
/// array, empty containers, nil, booleans, negative and large integers,
/// floats, and strings that need JSON escaping.
fn crafted() -> Vec<u8> {
    let mut f64v = vec![0xcb];
    f64v.extend_from_slice(&0.1f64.to_be_bytes());
    let mut f32v = vec![0xca];
    f32v.extend_from_slice(&1.5f32.to_be_bytes());
    let mut big = vec![0xcb];
    big.extend_from_slice(&1e21f64.to_be_bytes());
    let mut negz = vec![0xcb];
    negz.extend_from_slice(&(-0.0f64).to_be_bytes());
    let mut umax = vec![0xcf];
    umax.extend_from_slice(&u64::MAX.to_be_bytes());
    let mut imin = vec![0xd3];
    imin.extend_from_slice(&i64::MIN.to_be_bytes());
    let f = |x: f64| [vec![0xcb], x.to_be_bytes().to_vec()].concat();
    mp_map(&[
        (s("fsmall"), f(1.5e-7)),
        (s("fint"), f(5.0)),
        (s("fone"), f(1.0)),
        (s("fneg"), f(-2.5)),
        (s("fhuge"), f(-1e300)),
        (s("f20"), f(3e20)),
        (s("nan"), f(f64::NAN)),
        (s("inf"), f(f64::INFINITY)),
        (s("ebins"), mp_arr(&[mp_bin(&[]), mp_bin(&[1])])),
        (mp_bin(b"bk"), mp_bin(&[5])),
        (s("int8"), vec![0xd0, 0x05]),
        (s("int8neg"), vec![0xd0, 0x85]),
        (s("dup"), vec![0x01]),
        (s("dup"), vec![0x02]),
        (s("esc2"), s("\u{8}\u{c}\r\u{2029}\u{10ffff}")),
        (vec![0x01], s("one")),
        (vec![0x7f], s("int key")),
        (vec![0xcd, 0x01, 0x00], s("256")),
        (vec![0xff], s("neg key")),
        (s("bin"), mp_bin(&[1, 2, 3, 0xff])),
        (s("bins"), mp_arr(&[mp_bin(&[1]), mp_bin(&[2, 3])])),
        (s("mixed"), mp_arr(&[mp_bin(&[1]), s("x")])),
        (s("earr"), mp_arr(&[])),
        (s("emap"), mp_map(&[])),
        (s("ebin"), mp_bin(&[])),
        (s("nil"), vec![0xc0]),
        (s("t"), vec![0xc3]),
        (s("f"), vec![0xc2]),
        (s("neg"), vec![0xfb]),
        (s("umax"), umax),
        (s("imin"), imin),
        (s("f64"), f64v),
        (s("f32"), f32v),
        (s("big"), big),
        (s("negz"), negz),
        (
            s("esc"),
            s("<a&b> \"q\" \\ / \u{e9} \u{2028} \t\n\u{1}\u{7f}"),
        ),
        (s("bad utf8"), mp_str(&[b'a', 0xff, b'b'])),
        (
            s("nested"),
            mp_map(&[
                (
                    s("z"),
                    mp_arr(&[vec![0x01], mp_map(&[(s("k"), mp_bin(&[9]))])]),
                ),
                (s("a"), mp_map(&[(vec![0x02], mp_bin(&[7]))])),
            ]),
        ),
        (s("B"), vec![0x00]),
        (s("a"), vec![0x00]),
        (s("aa"), vec![0x00]),
        (s(""), vec![0x00]),
    ])
}

/// The body the mock algod answers for `GET /v2/blocks/<round>`.
fn block(round: u64) -> Option<Vec<u8>> {
    let root = workspace_root();
    let file = |p: &str| std::fs::read(root.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
    Some(match round {
        1 => file("benchmarks/fixtures/micro/block-small.msgpack"),
        2 => file("crates/core/algo-codec/tests/fixtures/aramidmain/block_23132701.msgpack"),
        3 => file("crates/core/algo-ledger/tests/fixtures/stateproof/block_661_stpf.bin"),
        4 => file("benchmarks/fixtures/micro/block-large.msgpack"),
        10 => crafted(),
        // a binary value, an array of them, two values, nothing
        11 => mp_bin(&[1, 2, 3]),
        12 => mp_arr(&[mp_bin(&[1]), mp_bin(&[2])]),
        13 => [
            mp_map(&[(s("a"), vec![0x01])]),
            mp_map(&[(s("b"), vec![0x02])]),
        ]
        .concat(),
        14 => Vec::new(),
        // a truncated map, a byte no value starts with, an empty binary
        // value, an extension value, a value then a truncated one
        15 => vec![0x82, 0xa1, b'a'],
        16 => vec![0xc1],
        17 => mp_bin(&[]),
        18 => mp_map(&[(s("x"), vec![0xd4, 0x05, 0x00])]),
        19 => [mp_map(&[(s("a"), vec![0x01])]), vec![0x92, 0x01]].concat(),
        _ => return None,
    })
}

// ---- the mock algod -----------------------------------------------------------

#[derive(Clone, Copy)]
enum Versions {
    Full,
    NoBuild,
    Fail,
}

fn versions_body(v: Versions) -> (u16, String) {
    let mut doc = serde_json::json!({
        "versions": ["v1", "v2"],
        "genesis_id": "mock-v1",
        "genesis_hash_b64": "SGVsbG8gV29ybGQAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "build": {"major": 5, "minor": 0, "build_number": 5, "commit_hash": "c0ffee",
                  "branch": "rel/stable", "channel": "stable"}
    });
    match v {
        Versions::Full => (200, doc.to_string()),
        Versions::NoBuild => {
            doc["build"] = serde_json::json!({"major": 0, "minor": 0, "build_number": 0,
                "commit_hash": "", "branch": "", "channel": ""});
            doc["versions"] = serde_json::json!([]);
            (200, doc.to_string())
        }
        Versions::Fail => (500, r#"{"message":"versions are down"}"#.to_string()),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// A canned answer replacing `route`'s for the request paths starting with
/// `prefix` (`""`: every path).
#[derive(Clone)]
struct Answer {
    prefix: &'static str,
    status: u16,
    body: Vec<u8>,
}

/// The mock algod of a row.
#[derive(Clone)]
struct Mock {
    versions: Versions,
    answers: Vec<Answer>,
}

const STATUS_JSON: &str = r#"{"catchup-time":0,"last-round":5,"last-version":"future","next-version":"future","next-version-round":6,"next-version-supported":true,"stopped-at-unsupported-round":false,"time-since-last-round":1500000000}"#;

const SUPPLY_JSON: &str = r#"{"current_round":5,"online-money":1000000,"total-money":3000042}"#;

/// The asset params of the asset rows (`model.AssetParams`).
fn asset_params(id: u64) -> Option<serde_json::Value> {
    let (a1, a2) = (key(1).1, key(2).1);
    match id {
        12 => Some(serde_json::json!({
            "creator": a2, "decimals": 2, "total": 12345, "unit-name": "T<K>",
            "name": "Tok\u{1}x", "url": "https://x\u{7f}", "default-frozen": true,
            "manager": a1, "reserve": a1, "freeze": a2, "clawback": a2
        })),
        9 => Some(serde_json::json!({
            "creator": a1, "decimals": 1, "total": 100, "name": "ignored",
            "name-b64": "Tv9t", "unit-name": "u", "url-b64": ""
        })),
        _ => None,
    }
}

/// What the mock algod answers for the asset, application, participation
/// and catchup paths (issue #2476).
fn route_2476(method: &str, path: &str, query: &str) -> Option<(u16, String)> {
    let (a1, a2, a3) = (key(1).1, key(2).1, key(3).1);
    let not_found = || (404, r#"{"message":"not found"}"#.to_string());
    if let Some(rest) = path.strip_prefix("/v2/assets/") {
        return Some(match (rest.parse::<u64>().ok(), rest) {
            (Some(13), _) => (500, r#"{"message":"asset store is down"}"#.to_string()),
            (Some(id), _) => match asset_params(id) {
                Some(p) => (
                    200,
                    serde_json::json!({"index": id, "params": p}).to_string(),
                ),
                None => not_found(),
            },
            _ => not_found(),
        });
    }
    if let Some(rest) = path.strip_prefix("/v2/accounts/") {
        let (addr, tail) = rest.split_once('/')?;
        if tail == "assets" {
            let page2 = query.split('&').any(|kv| kv == "next=tok2");
            return Some(if addr == a1 && page2 {
                (
                    200,
                    serde_json::json!({"round": 5, "asset-holdings": [
                        {"asset-holding": {"amount": 1, "asset-id": 9},
                         "asset-params": {"total": 5}}
                    ]})
                    .to_string(),
                )
            } else if addr == a1 {
                (
                    200,
                    serde_json::json!({"round": 5, "next-token": "tok2", "asset-holdings": [
                        {"asset-holding": {"amount": 12345, "asset-id": 12, "is-frozen": true},
                         "asset-params": asset_params(12)},
                        {"asset-holding": {"amount": 7, "asset-id": 10}}
                    ]})
                    .to_string(),
                )
            } else if addr == a2 {
                (200, r#"{"round":5,"asset-holdings":[]}"#.to_string())
            } else {
                not_found()
            });
        }
        if let Some(id) = tail.strip_prefix("assets/") {
            return Some(if addr == a1 && id == "12" {
                (
                    200,
                    r#"{"round":5,"asset-holding":{"amount":345,"asset-id":12}}"#.to_string(),
                )
            } else {
                not_found()
            });
        }
        return None;
    }
    if let Some(id) = path.strip_prefix("/v2/applications/") {
        return Some(match id {
            "7" => (
                200,
                serde_json::json!({"id": 7, "params": {
                    "approval-program": "BoEB", "clear-state-program": "BoEB",
                    "creator": a1, "extra-program-pages": 1, "family-box-access": true,
                    "foreign-box-reads": true, "global-state-schema": {"num-byte-slice": 1, "num-uint": 2},
                    "local-state-schema": {"num-uint": 3}, "size-sponsor": a2, "version": 12
                }})
                .to_string(),
            ),
            "5" => (
                200,
                r#"{"id":5,"params":{"approval-program":"","clear-state-program":"Ag=="}}"#
                    .to_string(),
            ),
            _ => not_found(),
        });
    }
    if path == "/v2/participation" {
        let part = |addr: &str, id: &str, sel: &str, extra: serde_json::Value| {
            let mut p = serde_json::json!({
                "address": addr, "id": id,
                "key": {"selection-participation-key": sel, "vote-participation-key": "AQID",
                        "vote-first-valid": 1, "vote-last-valid": 3000000, "vote-key-dilution": 10000}
            });
            p.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            p
        };
        return Some((
            200,
            serde_json::json!([
                part(
                    &a3,
                    "PARTKEYIDTHREE",
                    "BAUG",
                    serde_json::json!({
                        "effective-first-valid": 2, "effective-last-valid": 3000000,
                        "last-vote": 9, "last-block-proposal": 11, "last-state-proof": 10
                    })
                ),
                part(&a2, "PARTKEYIDTWO", "BwgJ", serde_json::json!({})),
                part(&key(5).1, "PARTKEYIDFIVE", "", serde_json::json!({})),
            ])
            .to_string(),
        ));
    }
    if let Some(label) = path.strip_prefix("/v2/catchup/") {
        let label = label.replace("%23", "#");
        let message = match (method, query) {
            ("DELETE", _) => "aborted".to_string(),
            (_, "") => label,
            _ => format!("catching up to {label}\u{7}"),
        };
        return Some((
            200,
            serde_json::json!({"catchup-message": message}).to_string(),
        ));
    }
    None
}

/// `(status, content type, body)` for a request path (status 1: `body` is
/// the whole raw reply).
fn route(method: &str, path: &str, mock: &Mock) -> (u16, &'static str, Vec<u8>) {
    let msgpack = path
        .split_once('?')
        .is_some_and(|(_, q)| q.split('&').any(|kv| kv == "format=msgpack"));
    let query = path.split_once('?').map_or("", |(_, q)| q);
    let path = path.split('?').next().unwrap_or("");
    let json = "application/json";
    if let Some(a) = mock.answers.iter().find(|a| path.starts_with(a.prefix)) {
        return (a.status, json, a.body.clone());
    }
    // where the redirect rows send go
    let path = path.strip_prefix("/moved").unwrap_or(path);
    if let Some((code, body)) = route_2476(method, path, query) {
        return (code, json, body.into_bytes());
    }
    let versions = mock.versions;
    if path == "/v2/status" {
        return (200, json, STATUS_JSON.as_bytes().to_vec());
    }
    if path == "/v2/ledger/supply" {
        return (200, json, SUPPLY_JSON.as_bytes().to_vec());
    }
    if path == "/versions" {
        let (code, body) = versions_body(versions);
        return (code, json, body.into_bytes());
    }
    if let Some(r) = path.strip_prefix("/v2/blocks/") {
        return match r.parse::<u64>().ok().and_then(block) {
            Some(b) => (200, "application/msgpack", b),
            None => (
                404,
                json,
                br#"{"message":"failed to retrieve information from the ledger"}"#.to_vec(),
            ),
        };
    }
    if let Some(a) = path.strip_prefix("/v2/accounts/").filter(|_| msgpack) {
        return match account_msgpack(a) {
            Some((200, body)) => (200, "application/msgpack", body),
            Some((code, body)) => (code, json, body),
            None => (404, json, br#"{"message":"no such account"}"#.to_vec()),
        };
    }
    if let Some(a) = path.strip_prefix("/v2/accounts/") {
        return match account_json(a) {
            Some((code, body)) => (code, json, body.into_bytes()),
            None => (404, json, br#"{"message":"no such account"}"#.to_vec()),
        };
    }
    (404, json, br#"{"message":"unknown route"}"#.to_vec())
}

/// Serve `route` on a fresh port until the test process exits.
fn spawn_mock(mock: Mock) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let mock = Arc::new(mock);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mock = mock.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    return;
                }
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                let _ = reader.read_exact(&mut body);
                let method = first.split_whitespace().next().unwrap_or("GET");
                let path = first.split_whitespace().nth(1).unwrap_or("/");
                let (code, ctype, body) = route(method, path, &mock);
                if code == 0 {
                    // close the connection without an answer
                    return;
                }
                if code == 1 {
                    let _ = stream.write_all(&body);
                    return;
                }
                let head = format!(
                    "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reason(code),
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });
    port
}

// ---- the rows -----------------------------------------------------------------

struct Case {
    name: String,
    args: Vec<String>,
    versions: Versions,
    accounts: bool,
    answers: Vec<Answer>,
    /// `algod.net` names a closed port instead of the mock.
    refused: bool,
    /// The data dir holds no `genesis.json`.
    no_genesis: bool,
    /// The data dir holds a `consensus.json`.
    consensus_json: bool,
    /// `algod.net` holds this instead of the mock's address.
    net: Option<&'static str>,
}

fn case(name: &str, args: &[&str]) -> Case {
    Case {
        name: name.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        versions: Versions::Full,
        accounts: false,
        answers: Vec::new(),
        refused: false,
        no_genesis: false,
        consensus_json: false,
        net: None,
    }
}

/// The address `algod.net` names in the `refused` rows: nothing listens on
/// port 1, so go's dial fails with `connection refused`.
const CLOSED_ALGOD: &str = "127.0.0.1:1";

/// The commands of go's `goal` that read from algod, each as
/// `(name, args, the account rows' setup)`.
fn algod_readers() -> Vec<(&'static str, Vec<&'static str>, bool)> {
    vec![
        ("version", vec!["version"], false),
        ("version -v", vec!["version", "-v"], false),
        ("node status", vec!["node", "status"], false),
        ("ledger block", vec!["ledger", "block", "1"], false),
        ("ledger supply", vec!["ledger", "supply"], false),
        (
            "account balance",
            vec!["account", "balance", "-a", "<A1>"],
            false,
        ),
        (
            "account rewards",
            vec!["account", "rewards", "-a", "<A1>"],
            false,
        ),
        ("account info", vec!["account", "info", "-a", "<A1>"], false),
        (
            "account list --info",
            vec!["account", "list", "--info"],
            true,
        ),
    ]
}

/// What a malformed algod answer does to go's go-codec JSON decode
/// (`protocol.NewJSONDecoder`, `restClient.submitForm`): `(row name, path
/// prefix, body, args)`.
fn malformed() -> Vec<(
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
)> {
    const BAL: &[&str] = &["account", "balance", "-a", "<A1>"];
    const INFO: &[&str] = &["account", "info", "-a", "<A1>"];
    const VER: &[&str] = &["version", "-v"];
    const STATUS: &[&str] = &["node", "status"];
    const SUPPLY: &[&str] = &["ledger", "supply"];
    let acct = "/v2/accounts/";
    vec![
        ("unknown field", acct, r#"{"amount":5,"foo":1}"#, BAL),
        (
            "unknown nested field",
            acct,
            r#"{"amount":5,"created-assets":[{"index":1,"params":{"total":1,"bar":2}}]}"#,
            INFO,
        ),
        ("string for a number", acct, r#"{"amount":"abc"}"#, BAL),
        ("quoted number", acct, r#"{"amount":"42"}"#, BAL),
        ("negative number", acct, r#"{"amount":-1}"#, BAL),
        ("fraction", acct, r#"{"amount":1.5}"#, BAL),
        ("float integer", acct, r#"{"amount":1e3}"#, BAL),
        ("overflow", acct, r#"{"amount":18446744073709551616}"#, BAL),
        ("bad exponent", acct, r#"{"amount":1e}"#, BAL),
        ("word for a number", acct, r#"{"amount":abc}"#, BAL),
        ("truncated", acct, r#"{"amount":5"#, BAL),
        ("truncated after colon", acct, r#"{"amount":"#, BAL),
        ("truncated string", acct, r#"{"address":"abc"#, BAL),
        ("missing comma", acct, r#"{"amount":5 "rewards":1}"#, BAL),
        ("missing colon", acct, r#"{"amount" 5}"#, BAL),
        ("empty body", acct, "", BAL),
        ("not json", acct, "<html>", BAL),
        ("array", acct, "[]", BAL),
        ("array of values", acct, "[1,2]", BAL),
        ("null", acct, "null", BAL),
        ("bad literal", acct, r#"{"amount":nul}"#, BAL),
        ("bad true", acct, r#"{"incentive-eligible":tru}"#, BAL),
        (
            "bool for a string",
            acct,
            r#"{"address":true,"amount":3}"#,
            BAL,
        ),
        ("object for a string", acct, r#"{"status":{}}"#, BAL),
        (
            "string for a bool",
            acct,
            r#"{"incentive-eligible":"x"}"#,
            BAL,
        ),
        ("bad escape", acct, r#"{"address":"\x"}"#, BAL),
        ("short unicode escape", acct, r#"{"address":"\u12"}"#, BAL),
        ("number key", acct, r#"{1:2}"#, BAL),
        ("trailing garbage", acct, r#"{"amount":7}xyz"#, BAL),
        (
            "nested null",
            acct,
            r#"{"amount":8,"created-assets":null,"participation":null}"#,
            BAL,
        ),
        (
            "string for an array",
            acct,
            r#"{"created-assets":"x"}"#,
            BAL,
        ),
        ("number for a struct", acct, r#"{"participation":5}"#, BAL),
        (
            "bad base64",
            acct,
            r#"{"created-apps":[{"id":1,"params":{"approval-program":"!!"}}]}"#,
            INFO,
        ),
        (
            "map for an array",
            acct,
            r#"{"created-assets":{"a":1}}"#,
            BAL,
        ),
        (
            "bad array separator",
            acct,
            r#"{"created-assets":[{"index":1};{}]}"#,
            BAL,
        ),
        ("unclosed object", acct, r#"{"amount":2,"#, BAL),
        ("bad versions", "/versions", r#"{"versions":"v1"}"#, VER),
        (
            "bad genesis hash",
            "/versions",
            r#"{"genesis_hash_b64":"???"}"#,
            VER,
        ),
        (
            "unknown versions field",
            "/versions",
            r#"{"versions":[],"x":1}"#,
            VER,
        ),
        ("bad build", "/versions", r#"{"build":{"major":"x"}}"#, VER),
        ("bad status", "/v2/status", r#"{"last-round":"x"}"#, STATUS),
        (
            "negative catchup time",
            "/v2/status",
            r#"{"last-round":3,"catchup-time":-5}"#,
            STATUS,
        ),
        (
            "fractional time",
            "/v2/status",
            r#"{"time-since-last-round":1.5}"#,
            STATUS,
        ),
        (
            "unknown status field",
            "/v2/status",
            r#"{"last-round":3,"y":true}"#,
            STATUS,
        ),
        (
            "bad supply",
            "/v2/ledger/supply",
            r#"{"total-money":true}"#,
            SUPPLY,
        ),
        (
            "unknown supply field",
            "/v2/ledger/supply",
            r#"{"current_round":1,"z":0}"#,
            SUPPLY,
        ),
    ]
}

/// The rows of go's request errors (issue #2466): a refused connection and
/// a 401 for each reader, then the malformed answers.
fn request_error_cases() -> Vec<Case> {
    let mut v = Vec::new();
    for (name, args, accounts) in algod_readers() {
        let mut c = case(name, &args);
        c.name = format!("{name} refused");
        c.accounts = accounts;
        c.refused = true;
        v.push(c);
        let mut c = case(name, &args);
        c.name = format!("{name} 401");
        c.accounts = accounts;
        c.answers = vec![Answer {
            prefix: "",
            status: 401,
            body: br#"{"message":"Invalid API Token"}"#.to_vec(),
        }];
        v.push(c);
    }
    for (name, args) in [
        (
            "account balance closed",
            &["account", "balance", "-a", "<A1>"][..],
        ),
        ("version closed", &["version"]),
        ("node status closed", &["node", "status"]),
    ] {
        let mut c = case(name, args);
        c.answers = vec![Answer {
            prefix: "",
            status: 0,
            body: Vec::new(),
        }];
        v.push(c);
    }
    let mut c = case(
        "account balance 401 raw body",
        &["account", "balance", "-a", "<A1>"],
    );
    c.answers = vec![Answer {
        prefix: "",
        status: 401,
        body: b"no\ttoken\n".to_vec(),
    }];
    v.push(c);
    for (name, args) in [
        ("node status", &["node", "status"][..]),
        ("ledger supply", &["ledger", "supply"]),
    ] {
        v.push(case(name, args));
    }
    for (name, prefix, body, args) in malformed() {
        let mut c = case(name, args);
        c.name = format!("malformed: {name}");
        c.answers = vec![Answer {
            prefix,
            status: 200,
            body: body.as_bytes().to_vec(),
        }];
        v.push(c);
    }
    // `account list --info` keeps what go decoded before the error
    for (name, body) in [
        (
            "malformed: list --info unknown field",
            r#"{"amount":5,"foo":1}"#,
        ),
        (
            "malformed: list --info truncated",
            r#"{"amount":6,"status":"Online""#,
        ),
    ] {
        let mut c = case(name, &["account", "list", "--info", "-w", "b"]);
        c.accounts = true;
        c.answers = vec![Answer {
            prefix: "/v2/accounts/",
            status: 200,
            body: body.as_bytes().to_vec(),
        }];
        v.push(c);
    }
    v
}

fn cases() -> Vec<Case> {
    let mut v = vec![
        // ledger.go blockCmd
        case("ledger block small", &["ledger", "block", "1"]),
        case("ledger block aramid", &["ledger", "block", "2"]),
        case("ledger block stateproof", &["ledger", "block", "3"]),
        case("ledger block large", &["ledger", "block", "4"]),
        case("ledger block crafted", &["ledger", "block", "10"]),
        case(
            "ledger block crafted --b32",
            &["ledger", "block", "10", "--b32"],
        ),
        case(
            "ledger block crafted --strict",
            &["ledger", "block", "10", "--strict"],
        ),
        case(
            "ledger block stateproof --strict --b32",
            &["ledger", "block", "3", "--strict", "--b32"],
        ),
        case("ledger block bin", &["ledger", "block", "11"]),
        case("ledger block bins", &["ledger", "block", "12"]),
        case("ledger block two values", &["ledger", "block", "13"]),
        case("ledger block empty", &["ledger", "block", "14"]),
        case("ledger block truncated", &["ledger", "block", "15"]),
        case("ledger block bad byte", &["ledger", "block", "16"]),
        case("ledger block empty bin", &["ledger", "block", "17"]),
        case("ledger block ext", &["ledger", "block", "18"]),
        case(
            "ledger block value then truncated",
            &["ledger", "block", "19"],
        ),
        case(
            "ledger block truncated -r",
            &["ledger", "block", "15", "-r"],
        ),
        case("ledger block -r", &["ledger", "block", "1", "-r"]),
        case(
            "ledger block --raw -o",
            &["ledger", "block", "1", "--raw", "-o", "out.mp"],
        ),
        case(
            "ledger block -o",
            &["ledger", "block", "2", "-o", "out.json"],
        ),
        case("ledger block -o -", &["ledger", "block", "11", "-o", "-"]),
        case(
            "ledger block -r --b32",
            &["ledger", "block", "1", "-r", "--b32"],
        ),
        case(
            "ledger block -r --strict",
            &["ledger", "block", "1", "-r", "--strict"],
        ),
        case(
            "ledger block -o missing dir",
            &["ledger", "block", "1", "-o", "nodir/x"],
        ),
        case("ledger block not found", &["ledger", "block", "99"]),
        case("ledger block not a number", &["ledger", "block", "x"]),
        case("ledger block +1", &["ledger", "block", "+1"]),
        case(
            "ledger block out of range",
            &["ledger", "block", "18446744073709551616"],
        ),
        case(
            "ledger block max",
            &["ledger", "block", "18446744073709551615"],
        ),
        // commands.go versionCmd
        case("version", &["version"]),
        case("version -v", &["version", "-v"]),
        case("version --verbose", &["version", "--verbose"]),
        case("version two data dirs", &["version", "-d", "<DD>"]),
        // account.go: errorRequestFail
        case("account balance", &["account", "balance", "-a", "<A1>"]),
        case("account rewards", &["account", "rewards", "-a", "<A3>"]),
        case(
            "account balance not found",
            &["account", "balance", "-a", "<A5>"],
        ),
        case(
            "account rewards not found",
            &["account", "rewards", "-a", "<A5>"],
        ),
        case("account info not found", &["account", "info", "-a", "<A5>"]),
        case("account balance 500", &["account", "balance", "-a", "<A4>"]),
        case("account info 500", &["account", "info", "-a", "<A4>"]),
    ];
    for (name, versions) in [
        ("version -v without build", Versions::NoBuild),
        ("version failing", Versions::Fail),
    ] {
        let mut c = case(name, &["version", "-v"]);
        c.versions = versions;
        v.push(c);
    }
    let mut c = case("version failing two data dirs", &["version", "-d", "<DD>"]);
    c.versions = Versions::Fail;
    v.push(c);
    // account.go listCmd, after the account setup below
    for (name, args) in [
        ("account list", &["account", "list"][..]),
        ("account list -w b", &["account", "list", "-w", "b"]),
        ("account list -w a", &["account", "list", "-w", "a"]),
        ("account list -w empty", &["account", "list", "-w", "empty"]),
        (
            "account list -w nosuch",
            &["account", "list", "-w", "nosuch"],
        ),
        ("account list --info", &["account", "list", "--info"]),
        (
            "account list --info -w b",
            &["account", "list", "--info", "-w", "b"],
        ),
    ] {
        let mut c = case(name, args);
        c.accounts = true;
        v.push(c);
    }
    v.extend(request_error_cases());
    v.extend(info_cases());
    v.extend(followup_cases());
    v.extend(remaining_reader_cases());
    v.extend(transport_cases());
    v
}

/// Issue #2476: the remaining commands that read from algod, through go's
/// REST client: `account assetdetails`, `account info`'s held assets,
/// `asset info`, `app info`, `account listpartkeys` / `partkeyinfo` and the
/// POST / DELETE of `node catchup`.
fn remaining_reader_cases() -> Vec<Case> {
    const LABEL: &str = "5#AB";
    let readers: Vec<(&str, Vec<&str>, bool)> = vec![
        (
            "account assetdetails",
            vec!["account", "assetdetails", "-a", "<A1>"],
            false,
        ),
        (
            "asset info",
            vec!["asset", "info", "--assetid", "12"],
            false,
        ),
        ("app info", vec!["app", "info", "--app-id", "7"], false),
        (
            "account listpartkeys",
            vec!["account", "listpartkeys"],
            false,
        ),
        ("account partkeyinfo", vec!["account", "partkeyinfo"], false),
        ("node catchup", vec!["node", "catchup", LABEL], false),
    ];
    let mut v = Vec::new();
    for (name, args, accounts) in &readers {
        v.push(case(name, args));
        let mut c = case(&format!("{name} refused"), args);
        c.accounts = *accounts;
        c.refused = true;
        v.push(c);
        let mut c = case(&format!("{name} 401"), args);
        c.answers = vec![Answer {
            prefix: "",
            status: 401,
            body: br#"{"message":"Invalid API Token"}"#.to_vec(),
        }];
        v.push(c);
    }
    for (name, args) in [
        (
            "account assetdetails -l",
            &["account", "assetdetails", "-a", "<A1>", "-l", "2"][..],
        ),
        (
            "account assetdetails -n",
            &["account", "assetdetails", "-a", "<A1>", "-n", "tok2"],
        ),
        (
            "account assetdetails empty",
            &["account", "assetdetails", "-a", "<A2>"],
        ),
        (
            "account assetdetails not found",
            &["account", "assetdetails", "-a", "<A5>"],
        ),
        (
            "account info held assets",
            &["account", "info", "-a", "<A6>"],
        ),
        (
            "account info held assets ids",
            &["account", "info", "-a", "<A6>", "--onlyShowAssetIDs"],
        ),
        ("asset info b64 name", &["asset", "info", "--assetid", "9"]),
        (
            "asset info not found",
            &["asset", "info", "--assetid", "99"],
        ),
        ("asset info 500", &["asset", "info", "--assetid", "13"]),
        (
            "asset info by unit name",
            &["asset", "info", "--unitname", "T<K>", "--creator", "<A1>"],
        ),
        (
            "asset info by empty unit name",
            &["asset", "info", "--unitname", "", "--creator", "<A1>"],
        ),
        (
            "asset info unit name of unknown creator",
            &["asset", "info", "--unitname", "x", "--creator", "<A5>"],
        ),
        ("app info minimal", &["app", "info", "--app-id", "5"]),
        ("app info not found", &["app", "info", "--app-id", "8"]),
        (
            "node catchup --min",
            &["node", "catchup", LABEL, "--min", "7"],
        ),
        (
            "node catchup two data dirs",
            &["node", "catchup", LABEL, "-d", "<DD>"],
        ),
        ("node catchup --abort idle", &["node", "catchup", "--abort"]),
    ] {
        v.push(case(name, args));
    }
    // `node catchup --abort` while a catchup runs: the DELETE
    let catching_up = br#"{"catchpoint":"5#AB","last-round":3}"#;
    let mut c = case("node catchup --abort", &["node", "catchup", "--abort"]);
    c.answers = vec![Answer {
        prefix: "/v2/status",
        status: 200,
        body: catching_up.to_vec(),
    }];
    v.push(c);
    let mut c = case(
        "node catchup --abort failing",
        &["node", "catchup", "--abort"],
    );
    c.answers = vec![
        Answer {
            prefix: "/v2/status",
            status: 200,
            body: catching_up.to_vec(),
        },
        Answer {
            prefix: "/v2/catchup/",
            status: 400,
            body: br#"{"message":"no catchup in progress"}"#.to_vec(),
        },
    ];
    v.push(c);
    // malformed answers, decoded by go-codec
    for (name, prefix, body, args) in [
        (
            "account assetdetails unknown field",
            "/v2/accounts/",
            &br#"{"round":1,"x":2}"#[..],
            &["account", "assetdetails", "-a", "<A1>"][..],
        ),
        (
            "account assetdetails bad holding",
            "/v2/accounts/",
            br#"{"asset-holdings":[{"asset-holding":{"amount":"x"}}]}"#,
            &["account", "assetdetails", "-a", "<A1>"],
        ),
        (
            "asset info truncated",
            "/v2/assets/",
            br#"{"index":12,"params":{"total":5"#,
            &["asset", "info", "--assetid", "12"],
        ),
        (
            "app info bad program",
            "/v2/applications/",
            br#"{"id":7,"params":{"approval-program":"!!"}}"#,
            &["app", "info", "--app-id", "7"],
        ),
        (
            "account partkeyinfo not an array",
            "/v2/participation",
            br#"{"address":"x"}"#,
            &["account", "partkeyinfo"],
        ),
        (
            "account partkeyinfo null",
            "/v2/participation",
            b"null",
            &["account", "partkeyinfo"],
        ),
        (
            "account listpartkeys bad key",
            "/v2/participation",
            br#"[{"key":{"vote-first-valid":true}}]"#,
            &["account", "listpartkeys"],
        ),
        (
            "node catchup unknown field",
            "/v2/catchup/",
            br#"{"catchup-message":"5#AB","more":1}"#,
            &["node", "catchup", LABEL],
        ),
        (
            "node catchup message number",
            "/v2/catchup/",
            br#"{"catchup-message":42}"#,
            &["node", "catchup", LABEL],
        ),
    ] {
        let mut c = case(&format!("malformed: {name}"), args);
        c.answers = vec![Answer {
            prefix,
            status: 200,
            body: body.to_vec(),
        }];
        v.push(c);
    }
    // `account dump`'s JSON of strings that are not UTF-8
    let mut c = case(
        "account dump invalid utf-8 name",
        &["account", "dump", "-a", "<A1>"],
    );
    c.answers = vec![Answer {
        prefix: "/v2/accounts/",
        status: 200,
        body: mp_obj(&[(
            "apar",
            mp_imap(&[(
                1,
                mp_obj(&[("an", mp_str(b"a\xffb")), ("un", mp_str(b"\xe2\x82"))]),
            )]),
        )]),
    }];
    v.push(c);
    v
}

/// Issue #2476: what go's `net/http` client makes of answers that are not
/// well-formed HTTP, of a reason phrase of the server's own, of redirects
/// and of hosts that do not resolve; for `version` (go prints the error
/// unfiltered to stdout), `account balance` (`reportErrorf`) and `ledger
/// block` (a raw answer).
fn transport_cases() -> Vec<Case> {
    let version = &["version"][..];
    let balance = &["account", "balance", "-a", "<A1>"][..];
    let block = &["ledger", "block", "1"][..];
    let raw: Vec<(&str, &[u8], &[&str])> = vec![
        ("garbage", b"garbage\r\n\r\n", version),
        ("tls answer", b"\x15\x03\x01\x00\x02\x02P", version),
        ("short status code", b"HTTP/1.1 20 OK\r\n\r\n", version),
        ("bad status code", b"HTTP/1.1 2x0 OK\r\n\r\n", balance),
        ("bad version", b"HTTX/1.1 200 OK\r\n\r\n", version),
        (
            "header without colon",
            b"HTTP/1.1 200 OK\r\nbad header\r\n\r\n",
            version,
        ),
        (
            "header starting with a space",
            b"HTTP/1.1 200 OK\r\n X: 1\r\n\r\n",
            version,
        ),
        (
            "bad content length",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            version,
        ),
        (
            "two content lengths",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            version,
        ),
        (
            "unsupported transfer encoding",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            version,
        ),
        (
            "headers cut",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n",
            version,
        ),
        ("status line cut", b"HTTP/1.1 200 OK", version),
        (
            "own reason phrase",
            b"HTTP/1.1 500 Boom Town\r\nContent-Length: 2\r\n\r\n{}",
            version,
        ),
        (
            "own reason phrase reportErrorf",
            b"HTTP/1.1 503 Boom Town\r\nContent-Length: 0\r\n\r\n",
            balance,
        ),
        (
            "no reason phrase",
            b"HTTP/1.1 599\r\nContent-Length: 0\r\n\r\n",
            version,
        ),
        (
            "reason phrase not utf-8",
            b"HTTP/1.1 500 B\xffad\r\nContent-Length: 0\r\n\r\n",
            version,
        ),
        (
            "reason phrase not utf-8 reportErrorf",
            b"HTTP/1.1 500 B\xffad\x01\r\nContent-Length: 0\r\n\r\n",
            balance,
        ),
        (
            "chunked answer",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ve\r\nf\r\nrsions\":[\"v9\"]}\r\n0\r\n\r\n",
            version,
        ),
        (
            "100 continue first",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"versions\":[\"7\"]}",
            version,
        ),
        (
            "body cut json",
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"versions\":[\"v1\"",
            version,
        ),
        (
            "body cut after json",
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"versions\":[\"v1\"]}",
            version,
        ),
        (
            "body cut raw",
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n\x81\xa3rnd\x05",
            block,
        ),
        (
            "body until close",
            b"HTTP/1.1 200 OK\r\n\r\n{\"versions\":[\"v3\"]}",
            version,
        ),
        (
            "redirect",
            b"HTTP/1.1 302 Found\r\nLocation: /moved/versions\r\nContent-Length: 0\r\n\r\n",
            version,
        ),
        (
            "redirect loop",
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /versions\r\nContent-Length: 0\r\n\r\n",
            version,
        ),
        (
            "redirect without location",
            b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n",
            version,
        ),
    ];
    let mut v = Vec::new();
    for (name, reply, args) in raw {
        let mut c = case(&format!("transport: {name}"), args);
        c.answers = vec![Answer {
            prefix: if args == block {
                "/v2/blocks/"
            } else if args == version {
                // `/moved/versions` answers as `/versions` does
                "/versions"
            } else {
                ""
            },
            status: 1,
            body: reply.to_vec(),
        }];
        v.push(c);
    }
    // a 401 after a redirect names the URL go was sent to
    let mut c = case("transport: 401 after redirect", version);
    c.answers = vec![
        Answer {
            prefix: "/moved/",
            status: 401,
            body: br#"{"message":"Invalid API Token"}"#.to_vec(),
        },
        Answer {
            prefix: "/versions",
            status: 1,
            body: b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /moved/versions\r\nContent-Length: 0\r\n\r\n".to_vec(),
        },
    ];
    v.push(c);
    for (name, net, args) in [
        ("unknown host", "algod.invalid:8080", version),
        ("unknown host reportErrorf", "algod.invalid:8080", balance),
        ("not a domain name", "256.1.1.1:80", version),
        ("localhost refused", "localhost:1", version),
        ("bad port", "127.0.0.1:99999", version),
    ] {
        let mut c = case(&format!("transport: {name}"), args);
        c.net = Some(net);
        v.push(c);
    }
    v
}

/// Issue #2485: `node status` stops at the first failing data dir (go's
/// `getStatus` → `reportErrorf`), and msgp's `Unknown field` names a key
/// that is not valid UTF-8 as go prints it.
fn followup_cases() -> Vec<Case> {
    let mut v = vec![case(
        "node status two data dirs",
        &["node", "status", "-d", "<DD>"],
    )];
    for (name, prefix) in [
        ("node status failing two data dirs", "/v2/status"),
        ("node status failing versions two data dirs", "/versions"),
    ] {
        let mut c = case(name, &["node", "status", "-d", "<DD>"]);
        c.answers = vec![Answer {
            prefix,
            status: 500,
            body: br#"{"message":"status is down"}"#.to_vec(),
        }];
        v.push(c);
    }
    let mut c = case(
        "node status refused two data dirs",
        &["node", "status", "-d", "<DD>"],
    );
    c.refused = true;
    v.push(c);
    for (name, body) in [
        // a truncated 4-byte sequence: go's `range` reads 3 runes of it
        (
            "account dump unknown field truncated utf-8",
            vec![0x81, 0xa3, 0xf0, 0x9f, 0x98, 0x01],
        ),
        (
            "account dump unknown field invalid utf-8 bin key",
            vec![0x81, 0xc4, 0x04, b'a', 0xe2, 0x82, b'b', 0x01],
        ),
        (
            "account dump unknown field invalid utf-8 byte",
            vec![0x81, 0xa2, 0xff, b'z', 0x01],
        ),
    ] {
        let mut c = case(name, &["account", "dump", "-a", "<A1>"]);
        c.answers = vec![Answer {
            prefix: "/v2/accounts/",
            status: 200,
            body,
        }];
        v.push(c);
    }
    v
}

/// `goal -v`, `license`, `protocols`, `report` (`cmd/goal/commands.go`) and
/// `account dump` (`cmd/goal/account.go` `dumpCmd`), issue #2467.
fn info_cases() -> Vec<Case> {
    let mut v = vec![
        case("-v", &["-v"]),
        case("--version", &["--version"]),
        case("license", &["license"]),
        case("protocols", &["protocols"]),
        case("report", &["report"]),
        case("report two data dirs", &["report", "-d", "<DD>"]),
        case("account dump", &["account", "dump", "-a", "<A1>"]),
        case("account dump empty", &["account", "dump", "-a", "<A2>"]),
        case(
            "account dump offline",
            &["account", "dump", "--address", "<A3>"],
        ),
        case(
            "account dump -o",
            &["account", "dump", "-a", "<A1>", "-o", "out.mp"],
        ),
        case(
            "account dump -o empty",
            &["account", "dump", "-a", "<A2>", "-o", "out.mp"],
        ),
        case(
            "account dump -o missing dir",
            &["account", "dump", "-a", "<A1>", "-o", "nodir/x"],
        ),
        case("account dump 500", &["account", "dump", "-a", "<A4>"]),
        case("account dump not found", &["account", "dump", "-a", "<A5>"]),
        case(
            "account dump bad address",
            &["account", "dump", "-a", "XYZ"],
        ),
        case("account dump no address", &["account", "dump"]),
    ];
    v.push(case(
        "account dump zero address",
        &["account", "dump", "-a", ZERO_ADDRESS],
    ));
    let mut c = case("protocols with consensus.json", &["protocols"]);
    c.consensus_json = true;
    v.push(c);
    let mut c = case("report failing", &["report"]);
    c.versions = Versions::Fail;
    v.push(c);
    let mut c = case("report refused", &["report"]);
    c.refused = true;
    v.push(c);
    let mut c = case("report without genesis", &["report"]);
    c.no_genesis = true;
    v.push(c);
    for (name, args) in [
        (
            "account dump refused",
            &["account", "dump", "-a", "<A1>"][..],
        ),
        ("report 401", &["report"]),
    ] {
        let mut c = case(name, args);
        if name.ends_with("refused") {
            c.refused = true;
        } else {
            c.answers = vec![Answer {
                prefix: "",
                status: 401,
                body: br#"{"message":"Invalid API Token"}"#.to_vec(),
            }];
        }
        v.push(c);
    }
    let mut c = case("account dump 401", &["account", "dump", "-a", "<A1>"]);
    c.answers = vec![Answer {
        prefix: "",
        status: 401,
        body: br#"{"message":"Invalid API Token"}"#.to_vec(),
    }];
    v.push(c);
    let mut answers: Vec<(&str, Vec<u8>)> = vec![
        ("account dump json answer", br#"{"amount":5}"#.to_vec()),
        (
            "account dump unknown field",
            vec![0x81, 0xa3, b'f', b'o', b'o', 0x01],
        ),
        (
            "account dump truncated",
            vec![0x82, 0xa3, b'o', b'n', b'l', 0x01],
        ),
        ("account dump empty answer", Vec::new()),
    ];
    answers.extend(malformed_account_data());
    for (name, body) in answers {
        let mut c = case(name, &["account", "dump", "-a", "<A1>"]);
        c.answers = vec![Answer {
            prefix: "/v2/accounts/",
            status: 200,
            body,
        }];
        v.push(c);
    }
    v
}

/// msgpack `basics.AccountData` answers go's msgp decoder accepts or fails
/// in its own ways: the array form of a struct, nil, short and long fixed
/// byte arrays, bin keys, type errors at each nesting, unknown fields in a
/// struct decoded inline or by its own method, bounds.
fn malformed_account_data() -> Vec<(&'static str, Vec<u8>)> {
    let one = |k: &str, v: Vec<u8>| mp_obj(&[(k, v)]);
    let imap1 = |v: Vec<u8>| mp_imap(&[(1, v)]);
    let arr = |items: &[Vec<u8>]| {
        let mut v = vec![0xdc];
        v.extend_from_slice(&(items.len() as u16).to_be_bytes());
        for i in items {
            v.extend_from_slice(i);
        }
        v
    };
    let nils = |n: usize| arr(&vec![vec![0xc0]; n]);
    let mut nested = vec![vec![0xc0]; 13];
    // the 14th field, `Assets`: asset 3 holding `[7, true]`
    nested.push(mp_imap(&[(3, vec![0x92, 0x07, 0xc3])]));
    vec![
        ("account dump string status", one("onl", s("x"))),
        ("account dump array form", vec![0x92, 0x01, 0x05]),
        ("account dump too many array fields", nils(23)),
        ("account dump array form nested", arr(&nested)),
        ("account dump nil", vec![0xc0]),
        (
            "account dump trailing bytes",
            [one("algo", mp_u(9)), vec![0xc1, 0xc1]].concat(),
        ),
        ("account dump negative", one("algo", vec![0xff])),
        (
            "account dump negative int16",
            one("ebase", vec![0xd1, 0xff, 0x00]),
        ),
        ("account dump status overflow", one("onl", mp_u(300))),
        ("account dump invalid prefix", one("onl", vec![0xc1])),
        ("account dump short vote", one("vote", mp_bin(&[1, 2, 3]))),
        ("account dump long vote", one("vote", mp_bin(&[9; 40]))),
        (
            "account dump vote as array",
            one("vote", vec![0x92, 0x01, 0x02]),
        ),
        ("account dump vote as string", one("vote", s("abc"))),
        ("account dump vote as int", one("vote", mp_u(5))),
        (
            "account dump bin key",
            [vec![0x81], mp_bin(b"algo"), mp_u(7)].concat(),
        ),
        ("account dump int key", vec![0x81, 0x01, 0x02]),
        (
            "account dump nested unknown field",
            one("apar", imap1(one("zz", mp_u(1)))),
        ),
        (
            "account dump inline unknown field",
            one("asset", imap1(one("zz", mp_u(1)))),
        ),
        (
            "account dump schema unknown field",
            one("appp", imap1(one("lsch", one("zz", mp_u(1))))),
        ),
        (
            "account dump total schema unknown field",
            one("tsch", one("zz", mp_u(1))),
        ),
        (
            "account dump teal value unknown field",
            one("appl", imap1(one("tkv", one("k", one("zz", mp_u(1)))))),
        ),
        (
            "account dump teal key not a string",
            one("appl", imap1(one("tkv", mp_imap(&[(5, mp_obj(&[]))])))),
        ),
        (
            "account dump teal type",
            one("appp", imap1(one("gs", one("k", one("tt", s("x")))))),
        ),
        (
            "account dump asset key",
            one("apar", mp_obj(&[("x", mp_obj(&[]))])),
        ),
        ("account dump asset map", one("apar", mp_u(1))),
        ("account dump bool", one("ie", mp_u(1))),
        (
            "account dump decimals overflow",
            one("apar", imap1(one("dc", mp_u(1 << 33)))),
        ),
        (
            "account dump long unit name",
            one("apar", imap1(one("un", s("123456789")))),
        ),
        (
            "account dump unit name int",
            one("apar", imap1(one("un", mp_u(5)))),
        ),
        (
            "account dump unit name bin",
            one("apar", imap1(one("un", mp_bin(b"U<")))),
        ),
        (
            "account dump manager short",
            one("apar", imap1(one("m", vec![0xc4, 0x05, 0x01]))),
        ),
        (
            "account dump program as array",
            one("appp", imap1(one("approv", vec![0x92, 0x06, 0x81]))),
        ),
        (
            "account dump program bad byte",
            one("appp", imap1(one("approv", vec![0x91, 0xcd, 0x01, 0x00]))),
        ),
        (
            "account dump holding array form",
            one("asset", imap1(vec![0x92, 0x05, 0xc3])),
        ),
        (
            "account dump holding too many fields",
            one("asset", imap1(vec![0x93, 0x05, 0xc3, 0xc0])),
        ),
        (
            "account dump holding array bad",
            one("asset", imap1(vec![0x92, 0x05, 0x05])),
        ),
        (
            "account dump app array form",
            one(
                "appp",
                imap1(arr(&[
                    mp_bin(&[1]),
                    vec![0xc0],
                    one("g", mp_obj(&[("ui", mp_u(4))])),
                ])),
            ),
        ),
        (
            "account dump nil fields",
            mp_obj(&[
                ("algo", vec![0xc0]),
                ("apar", vec![0xc0]),
                ("ie", vec![0xc0]),
                ("vote", vec![0xc0]),
            ]),
        ),
        (
            "account dump duplicate fields",
            [
                vec![0x84],
                s("tsch"),
                one("nui", mp_u(1)),
                s("tsch"),
                one("nbs", mp_u(2)),
                s("vote"),
                mp_bin(&[5; 32]),
                s("vote"),
                mp_bin(&[6; 2]),
            ]
            .concat(),
        ),
        (
            "account dump truncated nested",
            one("apar", vec![0x81, 0x01, 0x81, 0xa1, b't']),
        ),
        (
            "account dump map32",
            [vec![0xdf, 0, 0, 0, 1], s("algo"), mp_u(3)].concat(),
        ),
        ("account dump short map16", vec![0xde, 0x00]),
    ]
}

/// What `uname -a` prints on this host: `goal report` prints it.
fn uname() -> String {
    Command::new("uname")
        .arg("-a")
        .output()
        .map(|o| text(&o.stdout))
        .unwrap_or_default()
}

/// Replace the `<DD>` / `<An>` placeholders of an argument.
fn expand(arg: &str, dd: &Path) -> String {
    let mut a = arg.replace("<DD>", dd.to_str().unwrap());
    for i in 1..=6u8 {
        a = a.replace(&format!("<A{i}>"), &key(i).1);
    }
    a
}

/// The wallets and keys of the account rows: wallets `a` (the default: the
/// first one), `b` and `empty`; keys 1 and 2 and a 1-of-2 multisig of them
/// in `a`, key 3 in `b`; key 2 the default account.
fn setup_accounts(goal: &Path, dd: &Path) {
    let (m1, a1) = key(1);
    let (m2, a2) = key(2);
    let (m3, _) = key(3);
    // Cheap scrypt parameters, so a debug kmd-rust creates wallets quickly;
    // the kmd dir must be private for goal to start kmd in it.
    use std::os::unix::fs::PermissionsExt;
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir(&kmd_dir).unwrap();
    std::fs::set_permissions(&kmd_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {"scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1},
                       "allow_unsafe_scrypt": true},
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(kmd_dir.join("kmd_config.json"), cfg.to_string()).unwrap();
    let steps: Vec<Vec<&str>> = vec![
        vec!["wallet", "new", "a", "--unencrypted", "--no-display-seed"],
        vec!["wallet", "new", "b", "--unencrypted", "--no-display-seed"],
        vec![
            "wallet",
            "new",
            "empty",
            "--unencrypted",
            "--no-display-seed",
        ],
        vec!["account", "import", "-w", "a", "--mnemonic", &m1],
        vec!["account", "import", "-w", "a", "--mnemonic", &m2],
        vec!["account", "import", "-w", "b", "--mnemonic", &m3],
        vec!["account", "multisig", "new", &a1, &a2, "-T", "1", "-w", "a"],
        vec!["account", "-f", "Unnamed-1"],
    ];
    for step in steps {
        let ran = run_env(goal, dd, &step, Stdin::Null, &[("PATH", "/usr/bin:/bin")]);
        assert_eq!(
            ran.code,
            Some(0),
            "setup {step:?} failed: stdout={} stderr={}",
            text(&ran.stdout),
            text(&ran.stderr)
        );
    }
}

/// The sorted list of every file and directory under `dd` but the inputs, as
/// `<path> <mode> <d|f>`, a file named `out*` with its SHA-256.
fn files(dd: &Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).expect("read_dir").flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if INPUTS.contains(&rel.as_str()) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&p).expect("metadata");
            let mode = meta.permissions().mode() & 0o777;
            if meta.is_dir() {
                out.push(format!("{rel} {mode:o} d"));
                if !NOT_WALKED.contains(&rel.as_str()) {
                    walk(root, &p, out);
                }
            } else if rel.starts_with("out") {
                let sum = hex::encode(Sha256::digest(std::fs::read(&p).unwrap()));
                out.push(format!("{rel} {mode:o} f {sum}"));
            } else {
                out.push(format!("{rel} {mode:o} f"));
            }
        }
    }
    let mut out = Vec::new();
    walk(dd, dd, &mut out);
    out.sort();
    out
}

/// Stop the kmd a command started (its pid in `kmd-v0.5/kmd.pid`).
fn stop_kmd(dd: &Path) {
    let Ok(pid) = std::fs::read_to_string(dd.join("kmd-v0.5/kmd.pid")) else {
        return;
    };
    let pid = pid.trim();
    let _ = Command::new("kill").args(["-TERM", pid]).status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let alive = Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = Command::new("kill").args(["-KILL", pid]).status();
}

/// `lookup <host> on <server>: ...` with the server as `<DNS>`.
fn mask_dns_server(t: &str) -> String {
    let mut out = String::new();
    let mut rest = t;
    while let Some(i) = rest.find("lookup ") {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let line_end = tail.find('\n').unwrap_or(tail.len());
        let line = &tail[..line_end];
        match (line.find(" on "), line.rfind(": ")) {
            (Some(on), Some(colon)) if on < colon => {
                out.push_str(&line[..on + 4]);
                out.push_str("<DNS>");
                out.push_str(&line[colon..]);
            }
            _ => out.push_str(line),
        }
        rest = &tail[line_end..];
    }
    out.push_str(rest);
    out
}

fn row(goal: &Path, c: &Case) -> serde_json::Value {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    let port = spawn_mock(Mock {
        versions: c.versions,
        answers: c.answers.clone(),
    });
    if !c.no_genesis {
        std::fs::write(dd.join("genesis.json"), GENESIS).unwrap();
    }
    if c.consensus_json {
        let doc = serde_json::json!({"v7": {"MinBalance": 123}, "extra": {"MinBalance": 5}});
        std::fs::write(dd.join("consensus.json"), doc.to_string()).unwrap();
    }
    let net = if let Some(n) = c.net {
        n.to_string()
    } else if c.refused {
        CLOSED_ALGOD.to_string()
    } else {
        format!("127.0.0.1:{port}")
    };
    std::fs::write(dd.join("algod.net"), format!("{net}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "a".repeat(64)).unwrap();
    // The genesis directory algod creates, where goal keeps its accounts list.
    std::fs::create_dir(dd.join("testnet-v1")).unwrap();
    if c.accounts {
        setup_accounts(goal, &dd);
    }
    let args: Vec<String> = c.args.iter().map(|a| expand(a, &dd)).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = run_env(goal, &dd, &args, Stdin::Null, &[("PATH", "/usr/bin:/bin")]);
    let files = files(&dd);
    stop_kmd(&dd);
    let uname = uname();
    // An output that is not valid UTF-8 is kept byte for byte: masked through
    // the lossless `raw_text` form, then written as `base64:<bytes>`.
    let mask = |b: &[u8]| {
        let mut t = match std::str::from_utf8(b) {
            Ok(s) => s.to_string(),
            Err(_) => algo_types::raw_text::encode(b).into_owned(),
        };
        if !uname.is_empty() {
            t = t.replace(
                &uname, "<UNAME>
",
            );
        }
        let mut t = t.replace(dd.to_str().unwrap(), "<DD>");
        for i in 1..=6u8 {
            t = t.replace(&key(i).1, &format!("<A{i}>"));
        }
        let t = t.replace(&format!("127.0.0.1:{port}"), "<ALGOD>");
        // the host's DNS server, which go's resolver names
        let t = mask_dns_server(&t);
        if std::str::from_utf8(b).is_ok() {
            t
        } else {
            let bytes = algo_types::raw_text::decode(&t);
            format!("base64:{}", data_encoding::BASE64.encode(&bytes))
        }
    };
    let stdout = if ran.stdout.len() > MAX_INLINE {
        format!(
            "sha256:{} ({} bytes)",
            hex::encode(Sha256::digest(&ran.stdout)),
            ran.stdout.len()
        )
    } else {
        mask(&ran.stdout)
    };
    serde_json::json!({
        "name": c.name,
        "code": ran.code,
        "stdout": stdout,
        "stderr": mask(&ran.stderr),
        "files": files,
    })
}

/// Every row, the binary run from a copy in a fresh directory with a `PATH`
/// that holds no kmd; `kmd` is `(the kmd binary, its name next to goal)`.
fn sequence(goal: &Path, kmd: (&Path, &str)) -> Vec<serde_json::Value> {
    let bin_tmp = tempfile::tempdir().expect("tempdir");
    let bin_dir = bin_tmp.path().canonicalize().unwrap();
    std::fs::copy(goal, bin_dir.join("goal")).expect("copy the goal binary");
    std::fs::copy(kmd.0, bin_dir.join(kmd.1)).expect("copy the kmd binary");
    cases()
        .iter()
        .map(|c| row(&bin_dir.join("goal"), c))
        .collect()
}

fn read_fixture() -> Vec<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

#[test]
fn goal_algod_reads_fixture_matches_goal_rust() {
    let want = read_fixture();
    let kmd = kmd_rust_binary();
    let got = sequence(Path::new(GOAL_RUST_BIN), (&kmd, "kmd-rust"));
    assert_eq!(got.len(), want.len(), "{FIXTURE} is out of date");
    let mismatches: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w != g)
        .map(|(w, g)| format!("{}:\n  go:   {w}\n  rust: {g}", w["name"]))
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ from go:\n{}",
        mismatches.len(),
        want.len(),
        mismatches.join("\n")
    );
}

#[test]
fn goal_algod_reads_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_binary("GOAL_GO", "goal") else {
        return;
    };
    let Some(go_kmd) = try_ensure_go_binary("KMD_GO", "kmd") else {
        return;
    };
    let text: String = sequence(&go_goal, (&go_kmd, "kmd"))
        .iter()
        .map(|r| format!("{r}\n"))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("REGEN_GOAL_ALGOD_READS_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    let stale: Vec<String> = committed
        .lines()
        .zip(text.lines())
        .filter(|(c, g)| c != g)
        .map(|(c, g)| format!("  fixture: {c}\n  go:      {g}"))
        .collect();
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output ({} vs {} rows): regenerate it with \
         REGEN_GOAL_ALGOD_READS_FIXTURE=1\n{}",
        committed.lines().count(),
        text.lines().count(),
        stale.join("\n")
    );
}
