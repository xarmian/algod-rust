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

//! The password prompts of go's `goal` outside `clerk` (issue #2407):
//! `wallet new` (`infoChoosePasswordPrompt` and `infoPasswordConfirmation`,
//! each read by `ensurePassword`), `wallet rename` (`infoPasswordPrompt` +
//! `ensurePassword` for an encrypted wallet only) and the account commands that
//! go through `getWalletHandleMaybePassword` (`account import`, `export`,
//! `delete`, `new`), plus the line reads of `wallet new` (`--recover`'s
//! mnemonic and the backup-phrase question) and cobra's `unknown flag` for the
//! password/extra flags go's `goal` does not define.
//!
//! The rows after those (issue #2474) run against a mock algod: every other
//! command that reads a wallet password (`ensureWalletHandleMaybePassword(..,
//! true)` / `createSignedTransaction`: `account changeonlinestatus`,
//! `marknonparticipating`, `multisig delete`, `clerk send` / `sign` /
//! `multisig sign` / `multisig signprogram`, the `app` and `asset` commands
//! that sign) from a pipe, `/dev/null` and a pty, and go's
//! `account renewpartkey` (`generateAndRegisterPartKey`: the key generated
//! into `$TMPDIR`, installed, then registered with `-w`'s wallet) and
//! `renewallpartkeys` (`renewPartKeysInDir`), then (issue #2488) go's
//! `account addpartkey` (the key generated locally into `--outdir`, or into
//! `$TMPDIR` and installed) and `changeonlinestatus` failing to choose a
//! participation key before any password is read, then (issue #2497) go's
//! `changeonlinestatus` flags (`--txfile`, `--partkeyfile`, `--signer`,
//! `--lease`, `--validrounds`, `--rekey-to`) and its failure to fetch the
//! suggested parameters. The last row holds the SHA-256
//! of every transaction the commands broadcast or wrote. Masked as
//! nondeterministic: the IDs of the new participation keys (`<PART_ID>`) and
//! go's spinning cursor (`/-\|` + backspace, one per 100 ms).
//!
//! go reads a password with `terminal.ReadPassword(stdin)` only: a pipe or
//! `/dev/null` fails with `Couldn't read password: inappropriate ioctl for
//! device`; a terminal is the one way to type it. `fixtures/wallet_password.jsonl`
//! holds what go v5.0.5-stable's `goal` printed (stdout, stderr, exit code) for
//! one fixed sequence of calls against a kmd-rust, every path (pipe,
//! `/dev/null`, a real pty) of each command. goal-rust must produce the same
//! rows (a default test, no go needed); a `MIXED_CLUSTER=1` run re-checks the
//! file against a real go `goal` (`GOAL_GO` names a prebuilt one), and
//! `REGEN_WALLET_PASSWORD_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_WALLET_PASSWORD_FIXTURE=1 cargo test -p goal-rust \
//!   --test wallet_password_e2e wallet_password_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod common;
use common::pty::{run, run_env, Ran, Stdin};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/wallet_password.jsonl";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

/// The all-zero seed's address.
const ZERO_ADDR: &str = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI";

const CONFIRM: &str = "Please confirm the password: ";
const BACKUP: &str = "Would you like to see it now? (Y/n): ";
const RECOVERY: &str = "hit return when you are done: ";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// `GOAL_GO` names a prebuilt Go `goal`; otherwise build `../go-algorand/cmd/goal`.
fn try_ensure_go_goal() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GOAL_GO") {
        return Some(PathBuf::from(p));
    }
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("goal");
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd/goal").exists() {
        eprintln!("Go-parity SKIPPED: ../go-algorand/cmd/goal not found");
        return None;
    }
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./cmd/goal")
        .current_dir(&goalg)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        _ => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/goal` failed");
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

fn write_kmd_config(dir: &Path) {
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {"scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1}, "allow_unsafe_scrypt": true},
        },
        "session_lifetime_secs": 600,
    });
    std::fs::write(
        dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_ready(dir: &Path) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (
            std::fs::read_to_string(dir.join("kmd.net")),
            std::fs::read_to_string(dir.join("kmd.token")),
        ) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("kmd-rust never ready".into())
}

struct KmdGuard(Child);
impl Drop for KmdGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ---- the mock algod ---------------------------------------------------------

/// The round the mock algod reports.
const LAST_ROUND: u64 = 5;

/// The txid the mock algod answers a broadcast with.
const MOCK_TXID: &str = "TXIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// What the mock algod serves; the sequence changes it between rows.
#[derive(Default)]
struct Algod {
    /// `GET /v2/participation`.
    parts: Vec<serde_json::Value>,
    /// What a `POST /v2/participation` installs: `(address, first, last)`.
    install: Option<(String, u64, u64)>,
    /// `(method, path prefix, status, body)` answers replacing the routes.
    fail: Vec<(&'static str, &'static str, u16, &'static str)>,
    /// The SHA-256 of each `POST /v2/transactions` body.
    broadcast: Vec<String>,
}

type AlgodState = Arc<Mutex<Algod>>;

fn b64(b: &[u8]) -> String {
    data_encoding::BASE64.encode(b)
}

/// A `/v2/participation` entry of `address` valid for `first..=last`, its
/// keys fixed.
fn part_entry(address: &str, first: u64, last: u64) -> serde_json::Value {
    part_entry_voting(address, first, last, 0x11)
}

/// [`part_entry`] with a vote key of 32 bytes of `vote`.
fn part_entry_voting(address: &str, first: u64, last: u64, vote: u8) -> serde_json::Value {
    serde_json::json!({
        "id": "PARTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "address": address,
        "key": {
            "selection-participation-key": b64(&[0x22; 32]),
            "vote-participation-key": b64(&[vote; 32]),
            "state-proof-key": b64(&[0x33; 64]),
            "vote-first-valid": first,
            "vote-last-valid": last,
            "vote-key-dilution": 100,
        },
    })
}

fn algod_route(method: &str, path: &str, st: &mut Algod) -> (u16, String) {
    let path = path.split('?').next().unwrap_or("");
    if let Some(f) = st
        .fail
        .iter()
        .find(|f| f.0 == method && path.starts_with(f.1))
    {
        return (f.2, f.3.to_string());
    }
    let creator = key(1).1;
    let json = match (method, path) {
        ("GET", "/v2/status") => serde_json::json!({
            "catchup-time": 0, "last-round": LAST_ROUND, "last-version": "future",
            "next-version": "future", "next-version-round": LAST_ROUND + 1,
            "next-version-supported": true, "stopped-at-unsupported-round": false,
            "time-since-last-round": 0,
        }),
        ("GET", p) if p.starts_with("/v2/status/wait-for-block-after/") => serde_json::json!({
            "catchup-time": 0, "last-round": LAST_ROUND + 1, "last-version": "future",
            "next-version": "future", "next-version-round": LAST_ROUND + 2,
            "next-version-supported": true, "stopped-at-unsupported-round": false,
            "time-since-last-round": 0,
        }),
        ("GET", "/v2/transactions/params") => serde_json::json!({
            "consensus-version": "future", "fee": 0, "genesis-hash": b64(&[7; 32]),
            "genesis-id": "v1", "last-round": LAST_ROUND, "min-fee": 1000,
        }),
        ("GET", "/v2/participation") => serde_json::Value::Array(st.parts.clone()),
        ("POST", "/v2/participation") => {
            if let Some((a, f, l)) = st.install.clone() {
                st.parts.push(part_entry(&a, f, l));
            }
            serde_json::json!({"partId": "PARTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
        }
        ("POST", "/v2/transactions") => serde_json::json!({"txId": MOCK_TXID}),
        ("GET", p) if p.starts_with("/v2/transactions/pending/") => serde_json::json!({
            "confirmed-round": LAST_ROUND + 1, "pool-error": "",
            "txn": {"txn": {"type": "pay", "snd": b64(&[0; 32])}},
        }),
        ("GET", p) if p.starts_with("/v2/assets/") => serde_json::json!({
            "index": 7,
            "params": {
                "creator": creator, "manager": creator, "reserve": creator,
                "freeze": creator, "clawback": creator, "decimals": 0, "total": 100,
                "unit-name": "u",
            },
        }),
        ("GET", p) if p.starts_with("/v2/applications/") => serde_json::json!({
            "id": 9,
            "params": {
                "creator": creator,
                "approval-program": b64(&[2, 0x20, 1, 1, 0x22]),
                "clear-state-program": b64(&[2, 0x20, 1, 1, 0x22]),
            },
        }),
        ("GET", p) if p.starts_with("/v2/accounts/") => {
            let addr = p.trim_start_matches("/v2/accounts/");
            let addr = addr.split('/').next().unwrap_or("");
            serde_json::json!({
                "address": addr, "amount": 10_000_000, "amount-without-pending-rewards": 10_000_000,
                "min-balance": 100_000, "pending-rewards": 0, "rewards": 0, "round": LAST_ROUND,
                "status": "Offline", "total-apps-opted-in": 0, "total-assets-opted-in": 0,
                "total-created-apps": 0, "total-created-assets": 0,
            })
        }
        _ => return (404, r#"{"message":"unknown route"}"#.to_string()),
    };
    (200, json.to_string())
}

/// Serve the mock algod on a fresh port until the test process exits.
fn spawn_algod(state: AlgodState) -> u16 {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let state = state.clone();
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
                let mut words = first.split_whitespace();
                let method = words.next().unwrap_or("GET").to_string();
                let path = words.next().unwrap_or("/").to_string();
                let mut st = state.lock().unwrap();
                if method == "POST" && path == "/v2/transactions" {
                    use sha2::Digest;
                    st.broadcast.push(hex::encode(sha2::Sha256::digest(&body)));
                }
                let (code, body) = algod_route(&method, &path, &mut st);
                drop(st);
                let reason = match code {
                    200 => "OK",
                    400 => "Bad Request",
                    404 => "Not Found",
                    _ => "Internal Server Error",
                };
                let head = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            });
        }
    });
    port
}

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

/// The address of the 1-of-2 multisig of keys 1 and 2 (go's
/// `crypto.MultisigAddrGen`).
fn msig_addr() -> String {
    use sha2::{Digest, Sha512_256};
    let mut h = Sha512_256::new();
    h.update(b"MultisigAddr");
    h.update([1u8, 1u8]);
    for b in [1u8, 2] {
        let pk = ed25519_dalek::SigningKey::from_bytes(&[b; 32])
            .verifying_key()
            .to_bytes();
        h.update(pk);
    }
    algo_types::Address(h.finalize().into()).to_string()
}

/// A data dir with a kmd-rust, no wallet and a mock algod.
fn setup() -> (tempfile::TempDir, KmdGuard, AlgodState) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    let algod = AlgodState::default();
    let port = spawn_algod(algod.clone());
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "a".repeat(64)).unwrap();
    std::fs::create_dir_all(dd.join("tmp")).unwrap();
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    // The genesis directory go's accounts list (accountList.json) is kept in.
    std::fs::create_dir_all(dd.join("testnet-v1")).unwrap();
    write_kmd_config(&kmd_dir);
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    )
    .unwrap();
    let child = Command::new(kmd_rust_binary())
        .args(["serve", "--data-dir"])
        .arg(&kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    poll_ready(&kmd_dir).expect("ready");
    (tmp, guard, algod)
}

/// `s` with every run of exactly `len` characters of `class` replaced by `tag`.
fn mask_runs(s: &str, len: usize, class: impl Fn(char) -> bool, tag: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if class(chars[i]) {
            let start = i;
            while i < chars.len() && class(chars[i]) {
                i += 1;
            }
            if i - start == len {
                out.push_str(tag);
            } else {
                out.extend(&chars[start..i]);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// go's `util.RunFuncWithSpinningCursor` draws one of `/-\|` and a backspace
/// every 100 ms while it waits: how many depends on the host's speed.
fn strip_spinner(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '/' | '-' | '\\' | '|') && chars.peek() == Some(&'\u{8}') {
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

/// `s` with the ID after each `Participation ID: ` replaced by `<PART_ID>`.
fn mask_part_ids(s: &str) -> String {
    const AT: &str = "Participation ID: ";
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(AT) {
        out.push_str(&rest[..i + AT.len()]);
        rest = &rest[i + AT.len()..];
        let n = rest
            .find(|c: char| !(c.is_ascii_uppercase() || ('2'..='7').contains(&c)))
            .unwrap_or(rest.len());
        out.push_str("<PART_ID>");
        rest = &rest[n..];
    }
    out.push_str(rest);
    out
}

/// One row: the run's exit code, stdout and stderr; the data dir, the wallet
/// IDs, the addresses of new accounts and the IDs of new participation keys
/// (which differ per run) masked, the known keys named, go's spinner dropped.
fn row(name: &str, dd: &Path, ran: &Ran) -> serde_json::Value {
    let mask = |b: &[u8]| {
        let s = String::from_utf8_lossy(b).replace(dd.to_str().unwrap(), "<DD>");
        let s = strip_spinner(&s);
        let s = mask_runs(
            &s,
            32,
            |c| c.is_ascii_digit() || ('a'..='f').contains(&c),
            "<WALLET_ID>",
        );
        let s = s
            .replace(ZERO_ADDR, "<ZERO_ADDR>")
            .replace(&key(1).1, "<A1>")
            .replace(&key(2).1, "<A2>")
            .replace(&msig_addr(), "<MSIG>")
            .replace(MOCK_TXID, "<TXID>");
        let s = mask_runs(
            &s,
            58,
            |c| c.is_ascii_uppercase() || ('2'..='7').contains(&c),
            "<ADDR>",
        );
        mask_part_ids(&s)
    };
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.into());
    row.insert("code".into(), ran.code.into());
    row.insert("stdout".into(), mask(&ran.stdout).into());
    row.insert("stderr".into(), mask(&ran.stderr).into());
    serde_json::Value::Object(row)
}

fn choose(wallet: &str) -> String {
    format!("Please choose a password for wallet '{wallet}': ")
}

fn enter(wallet: &str) -> String {
    format!("Please enter the password for wallet '{wallet}': ")
}

/// The fixed sequence of calls through `bin`.
fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let (tmp, _kmd, algod) = setup();
    let dd = tmp.path().canonicalize().unwrap();
    let rows = std::cell::RefCell::new(Vec::new());
    let step_ran = |name: &str, ran: &Ran| rows.borrow_mut().push(row(name, &dd, ran));
    let step = |name: &str, args: &[&str], stdin: Stdin<'_>| {
        step_ran(name, &run(bin, &dd, args, stdin));
    };
    let (c_w1, c_r1, e_w1, e_r1) = (choose("w1"), choose("r1"), enter("w1"), enter("r1"));

    // `wallet new`: both passwords from the terminal only.
    let new_w1 = ["wallet", "new", "w1"];
    step(
        "wallet new stdin is a pipe",
        &new_w1,
        Stdin::Pipe("pw\npw\nn\n"),
    );
    step("wallet new stdin is /dev/null", &new_w1, Stdin::Null);
    step(
        "wallet new confirmation differs",
        &new_w1,
        Stdin::PtyAnswers(&[(&c_w1, "pw"), (CONFIRM, "other")]),
    );
    step(
        "wallet new pty, backup phrase declined",
        &new_w1,
        Stdin::PtyAnswers(&[(&c_w1, "pw"), (CONFIRM, "pw"), (BACKUP, "n")]),
    );
    step(
        "wallet new unencrypted, backup answer on a pipe",
        &["wallet", "new", "u1", "--unencrypted"],
        Stdin::Pipe("n\n"),
    );
    step(
        "wallet new unencrypted, backup answer on /dev/null",
        &["wallet", "new", "u2", "--unencrypted"],
        Stdin::Null,
    );
    step(
        "wallet new unencrypted --no-display-seed /dev/null",
        &["wallet", "new", "u3", "--unencrypted", "--no-display-seed"],
        Stdin::Null,
    );
    let new_r1 = ["wallet", "new", "r1", "--recover"];
    step(
        "wallet new --recover mnemonic on /dev/null",
        &new_r1,
        Stdin::Null,
    );
    step(
        "wallet new --recover mnemonic without a newline",
        &new_r1,
        Stdin::Pipe(ZERO_MNEMONIC),
    );
    let piped = format!("{ZERO_MNEMONIC}\npw\npw\n");
    step(
        "wallet new --recover stdin is a pipe",
        &new_r1,
        Stdin::Pipe(&piped),
    );
    step(
        "wallet new --recover pty",
        &new_r1,
        Stdin::PtyAnswers(&[(RECOVERY, ZERO_MNEMONIC), (&c_r1, "pw"), (CONFIRM, "pw")]),
    );

    // `wallet rename`: the password of an encrypted wallet from the terminal.
    let rename_w1 = ["wallet", "rename", "w1", "w1b"];
    step(
        "wallet rename stdin is a pipe",
        &rename_w1,
        Stdin::Pipe("pw\n"),
    );
    step("wallet rename stdin is /dev/null", &rename_w1, Stdin::Null);
    step(
        "wallet rename wrong password",
        &rename_w1,
        Stdin::Pty {
            prompt: &e_w1,
            line: "bad",
        },
    );
    step(
        "wallet rename pty",
        &rename_w1,
        Stdin::Pty {
            prompt: &e_w1,
            line: "pw",
        },
    );
    step(
        "wallet rename unencrypted /dev/null",
        &["wallet", "rename", "u1", "u1b"],
        Stdin::Null,
    );

    // The account commands: getWalletHandleMaybePassword, cold cache first.
    let _ = std::fs::remove_dir_all(dd.join("goal.cache"));
    let import = ["account", "import", "imp", "-m", ZERO_MNEMONIC, "-w", "r1"];
    step(
        "account import cold stdin is a pipe",
        &import,
        Stdin::Pipe("pw\n"),
    );
    step(
        "account import cold stdin is /dev/null",
        &import,
        Stdin::Null,
    );
    step(
        "account import cold wrong password",
        &import,
        Stdin::Pty {
            prompt: &e_r1,
            line: "bad",
        },
    );
    step(
        "account import cold pty",
        &import,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    let export = ["account", "export", "-a", ZERO_ADDR, "-w", "r1"];
    step(
        "account export cached stdin is a pipe",
        &export,
        Stdin::Pipe("pw\n"),
    );
    step(
        "account export cached stdin is /dev/null",
        &export,
        Stdin::Null,
    );
    step(
        "account export cached wrong password",
        &export,
        Stdin::Pty {
            prompt: &e_r1,
            line: "bad",
        },
    );
    step(
        "account export cached pty",
        &export,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    step(
        "account new cached encrypted wallet /dev/null",
        &["account", "new", "-w", "r1"],
        Stdin::Null,
    );
    step(
        "account new unencrypted wallet /dev/null",
        &["account", "new", "-w", "u1b"],
        Stdin::Null,
    );
    let delete = ["account", "delete", "-a", ZERO_ADDR, "-w", "r1"];
    step(
        "account delete cached stdin is /dev/null",
        &delete,
        Stdin::Null,
    );
    step(
        "account delete cached pty",
        &delete,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    // kmd lists the wallets in the order of their (random) IDs: the blocks
    // sorted by name.
    let mut listed = run(bin, &dd, &["wallet", "list"], Stdin::Null);
    let sep = format!("{}\n", "#".repeat(50));
    let text = String::from_utf8_lossy(&listed.stdout).into_owned();
    let mut blocks: Vec<&str> = text.split(&sep).filter(|b| !b.is_empty()).collect();
    blocks.sort_unstable();
    listed.stdout = blocks
        .iter()
        .map(|b| format!("{sep}{b}"))
        .chain([sep.clone()])
        .collect::<String>()
        .into_bytes();
    step_ran("wallet list, blocks sorted", &listed);

    // Flags goal does not define.
    for args in [
        &["wallet", "new", "x", "-w", "pw"][..],
        &["wallet", "new", "x", "--password", "pw"],
        &["wallet", "new", "x", "--driver", "sqlite"],
        &["wallet", "rename", "a", "b", "-w", "pw"],
        &["wallet", "rename", "a", "b", "--password", "pw"],
        &["account", "new", "--password", "pw"],
        &["account", "list", "--password", "pw"],
        &["account", "export", "-a", ZERO_ADDR, "--password", "pw"],
        &["account", "import", "-m", "m", "--password", "pw"],
        &[
            "account",
            "changeonlinestatus",
            "-a",
            ZERO_ADDR,
            "--offline",
        ],
        &[
            "account",
            "renewpartkey",
            "-a",
            ZERO_ADDR,
            "--roundLastValid",
            "5",
            "--register",
        ],
        &[
            "account",
            "renewallpartkeys",
            "--roundLastValid",
            "5",
            "--register",
        ],
    ] {
        step(&args.join(" "), args, Stdin::Null);
    }

    // The commands that sign through the mock algod (issue #2474), against an
    // encrypted wallet `sig` holding keys 1 and 2 and their 1-of-2 multisig.
    // go's participation keys are written to `$TMPDIR`.
    let tmpdir = dd.join("tmp");
    let envs = [("TMPDIR", tmpdir.to_str().unwrap())];
    let step_env = |name: &str, args: &[&str], stdin: Stdin<'_>| {
        step_ran(name, &run_env(bin, &dd, args, stdin, &envs));
    };
    let (c_sig, e_sig) = (choose("sig"), enter("sig"));
    let (m1, a1) = key(1);
    let (m2, a2) = key(2);
    let msig = msig_addr();
    step_env(
        "wallet new sig pty",
        &["wallet", "new", "sig", "--no-display-seed"],
        Stdin::PtyAnswers(&[(&c_sig, "spw"), (CONFIRM, "spw")]),
    );
    for (n, m) in [("1", &m1), ("2", &m2)] {
        step_env(
            &format!("account import key {n} into sig pty"),
            &["account", "import", "-w", "sig", "-m", m],
            Stdin::Pty {
                prompt: &e_sig,
                line: "spw",
            },
        );
    }
    step_env(
        "account multisig new into sig",
        &[
            "account", "multisig", "new", &a1, &a2, "-T", "1", "-w", "sig",
        ],
        Stdin::Pty {
            prompt: &e_sig,
            line: "spw",
        },
    );
    let prog = "#pragma version 2\nint 1\n";
    std::fs::write(dd.join("a.teal"), prog).unwrap();
    std::fs::write(dd.join("c.teal"), prog).unwrap();
    for (from, out) in [(&a1, "pay.tx"), (&msig, "msig.tx")] {
        step_env(
            &format!("clerk send unsigned to {out} pty"),
            &[
                "clerk", "send", "--from", from, "--to", &a2, "--amount", "1", "--note", "n", "-o",
                out, "-w", "sig",
            ],
            Stdin::Pty {
                prompt: &e_sig,
                line: "spw",
            },
        );
    }

    // A command that reads the password of `sig`: from a pipe, from
    // /dev/null and from a terminal.
    let three = |name: &str, args: &[&str], before: &dyn Fn()| {
        for (how, stdin) in [
            ("stdin is a pipe", Stdin::Pipe("spw\n")),
            ("stdin is /dev/null", Stdin::Null),
            (
                "pty",
                Stdin::Pty {
                    prompt: &e_sig,
                    line: "spw",
                },
            ),
        ] {
            before();
            step_env(&format!("{name} {how}"), args, stdin);
        }
    };
    let nothing = || {};
    let fresh_renew = |last: u64| {
        let mut st = algod.lock().unwrap();
        st.parts.clear();
        st.fail.clear();
        st.install = Some((key(1).1, LAST_ROUND, last));
    };

    // `account renewpartkey`: go generates the key into $TMPDIR, installs it
    // and registers it with `-w`'s wallet (`generateAndRegisterPartKey`).
    let renew = [
        "account",
        "renewpartkey",
        "-a",
        &a1,
        "--roundLastValid",
        "1100",
        "-w",
        "sig",
    ];
    let renew_n: Vec<&str> = renew.iter().copied().chain(["-N"]).collect();
    three("account renewpartkey -w sig -N", &renew_n, &|| {
        fresh_renew(1100)
    });
    fresh_renew(1100);
    step_env(
        "account renewpartkey -w sig waits for the commit pty",
        &renew,
        Stdin::Pty {
            prompt: &e_sig,
            line: "spw",
        },
    );
    fresh_renew(1100);
    step_env(
        "account renewpartkey default wallet cannot sign pty",
        &renew[..6],
        Stdin::Pty {
            prompt: &enter("w1b"),
            line: "pw",
        },
    );
    fresh_renew(1100);
    step_env(
        "account renewpartkey roundLastValid too early",
        &[
            "account",
            "renewpartkey",
            "-a",
            &a1,
            "--roundLastValid",
            "1005",
        ],
        Stdin::Null,
    );
    fresh_renew(1100);
    algod.lock().unwrap().parts = vec![part_entry(&a1, 1, 2000)];
    step_env(
        "account renewpartkey existing key valid long enough",
        &renew,
        Stdin::Null,
    );
    fresh_renew(1100);
    step_env(
        "account renewpartkey unparsable address",
        &[
            "account",
            "renewpartkey",
            "-a",
            "NOTANADDRESS",
            "--roundLastValid",
            "1100",
        ],
        Stdin::Null,
    );
    fresh_renew(1100);
    algod.lock().unwrap().fail = vec![(
        "POST",
        "/v2/participation",
        400,
        r#"{"message":"install failed"}"#,
    )];
    step_env("account renewpartkey install fails", &renew, Stdin::Null);
    fresh_renew(1100);
    algod.lock().unwrap().fail =
        vec![("POST", "/v2/transactions", 400, r#"{"message":"rejected"}"#)];
    step_env(
        "account renewpartkey broadcast fails pty",
        &renew,
        Stdin::Pty {
            prompt: &e_sig,
            line: "spw",
        },
    );
    fresh_renew(1100);
    algod.lock().unwrap().fail = vec![("GET", "/v2/participation", 500, r#"{"message":"boom"}"#)];
    step_env("account renewpartkey listing fails", &renew, Stdin::Null);

    // `account renewallpartkeys`: every account with a key, per data dir.
    let renew_all = [
        "account",
        "renewallpartkeys",
        "--roundLastValid",
        "1100",
        "-w",
        "sig",
    ];
    for (name, parts) in [
        ("no keys", vec![]),
        ("key valid beyond", vec![part_entry(&a1, 1, 2000)]),
        ("key expiring earlier", vec![part_entry(&a1, 1, 900)]),
        (
            "two keys of one account",
            vec![part_entry(&a1, 1, 900), part_entry(&a1, 901, 1500)],
        ),
    ] {
        fresh_renew(1100);
        algod.lock().unwrap().parts = parts;
        step_env(
            &format!("account renewallpartkeys {name}"),
            &renew_all,
            Stdin::Pty {
                prompt: &e_sig,
                line: "spw",
            },
        );
    }
    fresh_renew(1100);
    step_env(
        "account renewallpartkeys roundLastValid too early",
        &["account", "renewallpartkeys", "--roundLastValid", "1000"],
        Stdin::Null,
    );
    fresh_renew(1100);
    algod.lock().unwrap().fail = vec![("GET", "/v2/participation", 500, r#"{"message":"boom"}"#)];
    step_env(
        "account renewallpartkeys listing fails",
        &renew_all,
        Stdin::Null,
    );
    fresh_renew(1100);
    let dd_s = dd.to_str().unwrap().to_string();
    step_env(
        "account renewallpartkeys two data dirs",
        &[
            "-d",
            &dd_s,
            "account",
            "renewallpartkeys",
            "--roundLastValid",
            "1100",
        ],
        Stdin::Null,
    );

    // `account addpartkey` (issue #2488): go generates the key locally, into
    // `--outdir` or into $TMPDIR and installed (`GenParticipationKeysTo`).
    // Each `--outdir` row is followed by what the generation left behind:
    // the files in $TMPDIR and `--outdir`, and how many keys were installed.
    let left_behind = |name: &str| {
        let names = |dir: &Path| {
            let mut v: Vec<String> = std::fs::read_dir(dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            v.sort_unstable();
            v.join(" ")
        };
        let text = format!(
            "tmp: {}\npartkeys: {}\ninstalled: {}\n",
            names(&tmpdir),
            names(&dd.join("partkeys")),
            algod.lock().unwrap().parts.len()
        );
        step_ran(
            &format!("{name}: files left behind"),
            &Ran {
                code: Some(0),
                stdout: text.into_bytes(),
                stderr: Vec::new(),
            },
        );
    };
    std::fs::create_dir_all(dd.join("partkeys")).unwrap();
    let add = [
        "account",
        "addpartkey",
        "-a",
        &a1,
        "--roundFirstValid",
        "5",
        "--roundLastValid",
        "1100",
    ];
    let add_o: Vec<&str> = add.iter().copied().chain(["-o", "partkeys"]).collect();
    fresh_renew(1100);
    step_env("account addpartkey installed", &add, Stdin::Null);
    left_behind("account addpartkey installed");
    fresh_renew(1100);
    step_env("account addpartkey --outdir", &add_o, Stdin::Null);
    left_behind("account addpartkey --outdir");
    step_env(
        "account addpartkey --outdir key file exists",
        &add_o,
        Stdin::Null,
    );
    let add_missing: Vec<&str> = add.iter().copied().chain(["--outdir", "nosuch"]).collect();
    step_env(
        "account addpartkey --outdir does not exist",
        &add_missing,
        Stdin::Null,
    );
    fresh_renew(1100);
    algod.lock().unwrap().fail = vec![(
        "POST",
        "/v2/participation",
        400,
        r#"{"message":"install failed"}"#,
    )];
    step_env("account addpartkey install fails", &add, Stdin::Null);
    left_behind("account addpartkey install fails");
    fresh_renew(1100);
    for (name, a, first, last) in [
        ("unparsable address", "NOTANADDRESS", "5", "1100"),
        (
            "roundFirstValid after roundLastValid",
            a1.as_str(),
            "1100",
            "5",
        ),
        ("validity period too large", a1.as_str(), "5", "20000000"),
    ] {
        step_env(
            &format!("account addpartkey {name}"),
            &[
                "account",
                "addpartkey",
                "-a",
                a,
                "--roundFirstValid",
                first,
                "--roundLastValid",
                last,
            ],
            Stdin::Null,
        );
    }
    left_behind("account addpartkey failures");

    // `account changeonlinestatus` builds the keyreg (`MakeUnsignedGoOnlineTx`
    // → `chooseParticipation`) before it reads the password.
    let online = [
        "account",
        "changeonlinestatus",
        "-a",
        &a1,
        "-w",
        "sig",
        "-N",
    ];
    for (name, parts) in [
        ("no participation key", vec![]),
        ("key not valid yet", vec![part_entry(&a1, 900, 2000)]),
        ("key expired", vec![part_entry(&a1, 1, 3)]),
        ("key of another account", vec![part_entry(&a2, 1, 2000)]),
    ] {
        fresh_renew(1100);
        algod.lock().unwrap().parts = parts;
        step_env(
            &format!("account changeonlinestatus {name}"),
            &online,
            Stdin::Null,
        );
    }
    fresh_renew(1100);
    algod.lock().unwrap().fail = vec![("GET", "/v2/participation", 500, r#"{"message":"boom"}"#)];
    step_env(
        "account changeonlinestatus listing fails",
        &online,
        Stdin::Null,
    );
    // Of two keys expiring together go registers the first one listed: the
    // broadcast's SHA-256 in the last row tells which.
    fresh_renew(1100);
    algod.lock().unwrap().parts = vec![
        part_entry_voting(&a1, 1, 2000, 0x44),
        part_entry_voting(&a1, 1, 1500, 0x55),
        part_entry_voting(&a1, 1, 2000, 0x66),
    ];
    step_env(
        "account changeonlinestatus two keys expire together pty",
        &online,
        Stdin::Pty {
            prompt: &e_sig,
            line: "spw",
        },
    );

    // The other commands that sign with a wallet.
    fresh_renew(1100);
    algod.lock().unwrap().parts = vec![part_entry(&a1, 1, 2000)];
    let w = ["-w", "sig"];
    let with_w = |args: &[&str]| -> Vec<String> {
        args.iter().chain(w.iter()).map(|s| s.to_string()).collect()
    };
    let commands: Vec<(&str, Vec<String>)> = vec![
        (
            "account changeonlinestatus online",
            with_w(&["account", "changeonlinestatus", "-a", &a1, "-N"]),
        ),
        (
            "account changeonlinestatus offline",
            with_w(&["account", "changeonlinestatus", "-a", &a1, "-o=false", "-N"]),
        ),
        (
            "account marknonparticipating",
            with_w(&["account", "marknonparticipating", "-a", &a1, "-N"]),
        ),
        (
            "clerk send",
            with_w(&[
                "clerk", "send", "--from", &a1, "--to", &a2, "--amount", "1", "--note", "n", "-N",
            ]),
        ),
        (
            "clerk send -o --sign",
            with_w(&[
                "clerk",
                "send",
                "--from",
                &a1,
                "--to",
                &a2,
                "--amount",
                "1",
                "--note",
                "n",
                "-o",
                "signed-send.tx",
                "-s",
            ]),
        ),
        (
            "clerk sign",
            with_w(&["clerk", "sign", "-i", "pay.tx", "-o", "pay.stx"]),
        ),
        (
            "clerk multisig sign",
            with_w(&["clerk", "multisig", "sign", "-t", "msig.tx", "-a", &a1]),
        ),
        (
            "clerk multisig signprogram",
            with_w(&[
                "clerk",
                "multisig",
                "signprogram",
                "-p",
                "a.teal",
                "-a",
                &a1,
                "-A",
                &msig,
                "-o",
                "prog.lsig",
            ]),
        ),
        (
            "app create",
            with_w(&[
                "app",
                "create",
                "--creator",
                &a1,
                "--approval-prog",
                "a.teal",
                "--clear-prog",
                "c.teal",
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "app update",
            with_w(&[
                "app",
                "update",
                "--app-id",
                "9",
                "--from",
                &a1,
                "--approval-prog",
                "a.teal",
                "--clear-prog",
                "c.teal",
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "app optin",
            with_w(&[
                "app", "optin", "--app-id", "9", "--from", &a1, "--note", "n", "-N",
            ]),
        ),
        (
            "app call",
            with_w(&[
                "app", "call", "--app-id", "9", "--from", &a1, "--note", "n", "-N",
            ]),
        ),
        (
            "app closeout",
            with_w(&[
                "app", "closeout", "--app-id", "9", "--from", &a1, "--note", "n", "-N",
            ]),
        ),
        (
            "app clear",
            with_w(&[
                "app", "clear", "--app-id", "9", "--from", &a1, "--note", "n", "-N",
            ]),
        ),
        (
            "app delete",
            with_w(&[
                "app", "delete", "--app-id", "9", "--from", &a1, "--note", "n", "-N",
            ]),
        ),
        (
            "app method",
            with_w(&[
                "app", "method", "--app-id", "9", "--from", &a1, "--method", "f()void", "--note",
                "n", "-N",
            ]),
        ),
        (
            "asset create",
            with_w(&[
                "asset",
                "create",
                "--creator",
                &a1,
                "--total",
                "100",
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "asset destroy",
            with_w(&[
                "asset",
                "destroy",
                "--assetid",
                "7",
                "--creator",
                &a1,
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "asset config",
            with_w(&[
                "asset",
                "config",
                "--assetid",
                "7",
                "--manager",
                &a1,
                "--new-manager",
                &a2,
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "asset send",
            with_w(&[
                "asset",
                "send",
                "--assetid",
                "7",
                "--from",
                &a1,
                "--to",
                &a2,
                "--amount",
                "1",
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "asset freeze",
            with_w(&[
                "asset",
                "freeze",
                "--assetid",
                "7",
                "--freezer",
                &a1,
                "--account",
                &a2,
                "--freeze=true",
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "asset optin",
            with_w(&[
                "asset",
                "optin",
                "--assetid",
                "7",
                "--account",
                &a1,
                "--note",
                "n",
                "-N",
            ]),
        ),
        (
            "account multisig delete",
            with_w(&["account", "multisig", "delete", "-a", &msig]),
        ),
    ];
    for (name, args) in &commands {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        three(name, &args, &nothing);
    }

    // `account changeonlinestatus` flags (issue #2497): go's `changeOnlineCmd`
    // checks the flags, reads `--partkeyfile`'s parent address, computes the
    // validity window, then `changeAccountOnlineStatus` builds the keyreg with
    // `--lease` and `--rekey-to` and either writes it unsigned to `--txfile`
    // (`writeTxnToFile`, which only checks `--signer`) or signs it with
    // `--signer`'s key and broadcasts it.
    fresh_renew(1100);
    algod.lock().unwrap().parts = vec![part_entry(&a1, 1, 2000)];
    let partkey = format!("partkeys/{a1}.5.1100.partkey");
    let lease = b64(&[0x5a; 32]);
    let short_lease = b64(&[1; 8]);
    let cos = |extra: &[&str]| -> Vec<String> {
        ["account", "changeonlinestatus"]
            .iter()
            .chain(extra)
            .map(|s| s.to_string())
            .collect()
    };
    let flag_rows: Vec<(&str, Vec<String>)> = vec![
        (
            "--txfile online",
            cos(&["-a", &a1, "-w", "sig", "--txfile", "cos-online.tx"]),
        ),
        (
            "--txfile offline",
            cos(&["-a", &a1, "-o=false", "-w", "sig", "-t", "cos-offline.tx"]),
        ),
        (
            "--partkeyfile --txfile",
            cos(&[
                "--partkeyfile",
                &partkey,
                "-w",
                "sig",
                "-t",
                "cos-partkey.tx",
            ]),
        ),
        (
            "--partkeyfile offline",
            cos(&["--partkeyfile", &partkey, "-o=false", "-t", "x.tx"]),
        ),
        (
            "--partkeyfile missing",
            cos(&["--partkeyfile", "partkeys/missing.partkey", "-t", "x.tx"]),
        ),
        (
            "--partkeyfile not a database",
            cos(&["--partkeyfile", "a.teal", "-t", "x.tx"]),
        ),
        ("no address nor partkeyfile", cos(&["-t", "x.tx"])),
        (
            "--lease --validrounds --rekey-to --txfile",
            cos(&[
                "-a",
                &a1,
                "-w",
                "sig",
                "-x",
                &lease,
                "-v",
                "10",
                "--rekey-to",
                &a2,
                "-t",
                "cos-flags.tx",
            ]),
        ),
        (
            "--lease not base64",
            cos(&["-a", &a1, "-x", "!!", "-t", "x.tx"]),
        ),
        (
            "--lease too short",
            cos(&["-a", &a1, "-x", &short_lease, "-t", "x.tx"]),
        ),
        (
            "--validrounds zero",
            cos(&["-a", &a1, "-v", "0", "-t", "x.tx"]),
        ),
        (
            "--validrounds and --lastvalid",
            cos(&["-a", &a1, "-v", "10", "--lastvalid", "100", "-t", "x.tx"]),
        ),
        (
            "--validrounds too large",
            cos(&["-a", &a1, "-v", "100000000", "-t", "x.tx"]),
        ),
        (
            "--rekey-to unparsable",
            cos(&["-a", &a1, "--rekey-to", "NOTANADDRESS", "-t", "x.tx"]),
        ),
        (
            "--signer --txfile",
            cos(&["-a", &a1, "-w", "sig", "-S", &a2, "-t", "cos-signer.tx"]),
        ),
        (
            "--signer unparsable --txfile",
            cos(&["-a", &a1, "-S", "NOTANADDRESS", "-t", "x.tx"]),
        ),
        (
            "--signer is the sender --txfile",
            cos(&["-a", &a1, "-S", &a1, "-t", "x.tx"]),
        ),
        (
            "--signer broadcast",
            cos(&["-a", &a1, "-w", "sig", "-S", &a2, "-N"]),
        ),
        (
            "--signer unparsable broadcast",
            cos(&["-a", &a1, "-w", "sig", "-S", "NOTANADDRESS", "-N"]),
        ),
        (
            "unparsable address",
            cos(&["-a", "NOTANADDRESS", "-t", "x.tx"]),
        ),
    ];
    for (name, args) in &flag_rows {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        step_env(
            &format!("account changeonlinestatus {name} pty"),
            &args,
            Stdin::Pty {
                prompt: &e_sig,
                line: "spw",
            },
        );
    }
    // go's error when the suggested parameters cannot be fetched
    // (`ComputeValidityRounds` → `cachedSuggestedParams`), online and offline.
    for (name, online) in [("online", "-o=true"), ("offline", "-o=false")] {
        algod.lock().unwrap().fail = vec![(
            "GET",
            "/v2/transactions/params",
            500,
            r#"{"message":"no params"}"#,
        )];
        step_env(
            &format!("account changeonlinestatus suggested params fail {name}"),
            &["account", "changeonlinestatus", "-a", &a1, online, "-N"],
            Stdin::Null,
        );
    }
    algod.lock().unwrap().fail.clear();
    // What the signing commands broadcast and wrote, as `<file> <SHA-256>`
    // lines (kmd-rust signs for either goal, so the bytes must be equal).
    let mut written = String::new();
    for f in [
        "pay.tx",
        "msig.tx",
        "signed-send.tx",
        "pay.stx",
        "prog.lsig",
        "cos-online.tx",
        "cos-offline.tx",
        "cos-partkey.tx",
        "cos-flags.tx",
        "cos-signer.tx",
        "x.tx",
    ] {
        let sum = match std::fs::read(dd.join(f)) {
            Ok(b) => {
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(b))
            }
            Err(_) => "missing".to_string(),
        };
        written.push_str(&format!("{f} {sum}\n"));
    }
    for (i, sum) in algod.lock().unwrap().broadcast.iter().enumerate() {
        written.push_str(&format!("broadcast {i} {sum}\n"));
    }
    step_ran(
        "files the signing commands wrote",
        &Ran {
            code: Some(0),
            stdout: written.into_bytes(),
            stderr: Vec::new(),
        },
    );
    rows.into_inner()
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
fn wallet_password_fixture_matches_goal_rust() {
    let want = read_fixture();
    let got = sequence(Path::new(GOAL_RUST_BIN));
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
fn wallet_password_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let text: String = sequence(&go_goal)
        .iter()
        .map(|r| format!("{r}\n"))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("REGEN_WALLET_PASSWORD_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_WALLET_PASSWORD_FIXTURE=1"
    );
}
