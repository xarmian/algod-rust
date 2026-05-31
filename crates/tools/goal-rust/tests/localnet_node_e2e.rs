//! Localnet end-to-end (MIXED_CLUSTER): proves the in-tree Rust node
//! (`algod-rust node start --dev`) is usable like go-algorand — drive both
//! `goal-rust` AND the Go `goal` against the *same* running Rust daemon
//! (TASK-269 / Phase D2, PLAN-262).
//!
//! This is the inverse of `algod_account_interop_test.rs` (Go CLI ↔ Go daemon /
//! Go CLI ↔ Rust daemon): here the **daemon under test is the Rust node**, and
//! we point two different `goal` front-ends (ours and Go's) at it to show the
//! localnet REST/submit surface is wire-compatible for the dev-account
//! lifecycle.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only. The default `cargo test` run skips
//! this cleanly (it spawns external binaries and — for the Go-goal section —
//! builds Go from `../go-algorand`).
//!
//! ```bash
//! # Default run: gated, skips with a friendly note.
//! cargo test -p goal-rust --test localnet_node_e2e
//!
//! # Full localnet e2e against the Rust node:
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_node_e2e
//! ```
//!
//! ## What this covers (against `algod-rust node start --dev` + `kmd-rust`)
//!
//! The dev genesis (`docker/localnet-rust/data/genesis.json`, also baked into
//! the Docker localnet — Phase D1) funds a single dev account whose mnemonic is
//! published in `docs/DEV_WORKFLOW.md`, so unlike the bare-`algod -d <genesis>`
//! interop test we *have* a funded, signable account.
//!
//! - **goal-rust direction** (always exercised under the gate):
//!   1. `wallet new` + `account import -m <dev mnemonic>` → funded address.
//!   2. `account list` → the imported account renders as `[online]` (the dev
//!      genesis allocates it online) with its funded balance.
//!   3. `account info` → assets/apps sections + a nonzero Minimum Balance
//!      (Phase C2 read path).
//!   4. `account balance` → the genesis-funded amount.
//!   5. `account changeonlinestatus --offline` → keyreg submit, dev-mode block,
//!      confirmed; `account list` flips to `[offline]` (Phase C1, needs a
//!      funded signer).
//!   6. `account addpartkey` then `changeonlinestatus --online` → status flips
//!      back to `[online]`.
//!
//! - **Go-goal direction** (only when `../go-algorand` is present + builds):
//!   1. Go `goal account info` / `account balance` → read paths.
//!   2. Go `goal clerk send` → a real payment, signed via `kmd-rust`, submitted
//!      to the Rust dev node and confirmed within one dev-mode round; the
//!      recipient balance increases by the sent amount.
//!
//! `goal-rust clerk send` is still a stub (the whole `clerk` group is
//! unimplemented in `goal-rust`), so the payment submit/confirm path is covered
//! via **Go** `goal` here. If `../go-algorand` is absent or `go build` fails,
//! the Go-goal section is skipped with a note rather than failing — the
//! goal-rust lifecycle above still runs and asserts.
//!
//! ## The A11 lesson
//!
//! Daemon readiness polling watches the child process so an early exit surfaces
//! its captured stdout/stderr, and on any failure we dump the node + kmd logs
//! (`node.log` / `kmd.log`) so a flake is debuggable instead of a bare timeout.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// The dev account funded by the localnet-rust genesis, and its 25-word
/// mnemonic (published in `docs/DEV_WORKFLOW.md` — local-development only).
const DEV_ADDR: &str = "E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";
/// The FeeSink address from the same genesis — a convenient payment recipient.
const FEE_SINK: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

/// Workspace root — `<this crate>/../../..`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Build an in-tree binary (`algod-rust` / `kmd-rust`) and return its path.
/// Mirrors `account_changeonlinestatus_e2e.rs`'s `kmd_rust_binary`.
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

/// Build the Go `goal` from `../go-algorand`, caching under
/// `target/algod-interop/`. Returns `None` (with a logged reason) when the
/// checkout is absent or the build fails, so the Go-goal section can skip
/// rather than fail the whole test. Mirrors `algod_account_interop_test`'s
/// `ensure_go_cmd`, but non-fatal.
fn try_ensure_go_goal() -> Option<PathBuf> {
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("goal");
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd/goal").exists() {
        eprintln!(
            "Go-goal section SKIPPED: ../go-algorand/cmd/goal not found at {}",
            goalg.display()
        );
        return None;
    }
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./cmd/goal")
        .current_dir(&goalg)
        .status();
    match status {
        Ok(s) if s.success() => Some(bin),
        Ok(s) => {
            eprintln!("Go-goal section SKIPPED: `go build ./cmd/goal` exited {s:?}");
            None
        }
        Err(e) => {
            eprintln!("Go-goal section SKIPPED: failed to invoke `go build`: {e}");
            None
        }
    }
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
    // Insecure scrypt so the test isn't dominated by KDF cost (matches the other
    // kmd integration tests).
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

/// Reaps the child on drop (SIGTERM) and keeps the log path for surfacing on
/// failure (the A11 lesson — a timeout-only path hides startup failures).
struct DaemonGuard {
    child: Child,
    name: &'static str,
    log_path: PathBuf,
}

impl DaemonGuard {
    /// Read the daemon's captured log (its stdout+stderr are redirected here).
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

/// Spawn a daemon with stdout+stderr redirected to `<dir>/<name>.log`, then
/// poll for `<dir>/<stem>.net` + `<stem>.token`. If the child exits early or
/// readiness times out, the captured log is included in the panic message.
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

/// Run `goal-rust -d <dd> <args...>` with `ALGORAND_DATA` scrubbed.
fn goal_rust(dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

/// Run the Go `goal -d <dd> <args...>` with `ALGORAND_DATA` scrubbed.
fn go_goal(bin: &Path, dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run Go goal")
}

/// Assert a CLI invocation succeeded, dumping both streams + the daemon logs on
/// failure so a node-side error is debuggable (A11).
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

/// Parse the microAlgo count from a `goal` line like
/// `Minimum Balance:\t100000 microAlgos` — the first integer token after
/// `label`.
fn parse_labeled_microalgos(out: &str, label: &str) -> Option<u64> {
    out.lines()
        .find_map(|line| line.split_once(label).map(|(_, rest)| rest))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|t| t.parse().ok())
}

/// Leading integer of a `goal account balance` line (`<n> microAlgos`).
fn parse_balance(out: &str) -> Option<u64> {
    out.split_whitespace().next().and_then(|t| t.parse().ok())
}

/// The status tag on the `account list` row for `addr` — `online` / `offline`
/// from the leading `[online]` / `[offline]` marker.
fn account_list_status(list_out: &str, addr: &str) -> Option<String> {
    list_out
        .lines()
        .find(|l| l.contains(addr))
        .and_then(|l| l.trim_start().strip_prefix('['))
        .and_then(|rest| rest.split(']').next())
        .map(str::to_string)
}

#[test]
fn localnet_dev_node_drives_goal_rust_and_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_node_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_node_e2e",
        );
        return;
    }

    let algod_rust = ensure_rust_bin("algod-rust");
    let kmd_rust = ensure_rust_bin("kmd-rust");

    let data_dir = stage_data_dir();
    let dd = data_dir.path();

    // --- Spawn the Rust dev node. It writes algod.net/algod.token into <dd>. ---
    // Bind 127.0.0.1:0 so the OS picks a free port (avoids the fixed 8080
    // default clashing across parallel test runs).
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

    // --- Spawn kmd-rust under <dd>/kmd-v0.5 (goal's default resolution). ---
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let _kmd = spawn_daemon(
        &kmd_rust,
        &["serve", "--data-dir", kmd_dir.to_str().unwrap()],
        dd,
        &kmd_dir,
        "kmd",
        "kmd",
    );

    // =====================================================================
    // goal-rust direction
    // =====================================================================

    // 1. Encrypted wallet + import the funded dev account.
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

    // 2. account list → the imported account is online (genesis allocates it
    //    `onl: 1`) with its funded balance.
    let list_out = assert_cli_ok(
        &goal_rust(dd, &["account", "list", "--password", "pw"]),
        "account list",
        &node,
    );
    assert_eq!(
        account_list_status(&list_out, DEV_ADDR).as_deref(),
        Some("online"),
        "dev account should start online; got:\n{list_out}"
    );

    // 3. account info → assets/apps sections + a nonzero Minimum Balance (C2).
    let info_out = assert_cli_ok(
        &goal_rust(dd, &["account", "info", "-a", DEV_ADDR]),
        "account info",
        &node,
    );
    let min_balance = parse_labeled_microalgos(&info_out, "Minimum Balance:")
        .unwrap_or_else(|| panic!("account info missing a Minimum Balance line; got:\n{info_out}"));
    assert!(
        min_balance > 0,
        "Minimum Balance parsed as 0 — likely `/v2/accounts/{{addr}}` wire drift; got:\n{info_out}"
    );

    // 4. account balance → the genesis-funded amount (4e15 microAlgos), less any
    //    fees already paid. Assert it's a large nonzero value.
    let bal_out = assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", DEV_ADDR]),
        "account balance",
        &node,
    );
    let balance = parse_balance(&bal_out)
        .unwrap_or_else(|| panic!("account balance not a leading integer; got {bal_out:?}"));
    assert!(
        balance > 1_000_000_000,
        "dev account balance {balance} unexpectedly small; got:\n{bal_out}"
    );

    // 5. changeonlinestatus --offline → keyreg submit + dev-mode block; status
    //    flips to offline (C1: needs the funded signer we just imported).
    let offline_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "changeonlinestatus",
                "-a",
                DEV_ADDR,
                "--offline",
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "changeonlinestatus --offline",
        &node,
    );
    assert!(
        offline_out.contains("committed in round"),
        "offline keyreg should confirm in a dev-mode round; got:\n{offline_out}"
    );
    let list_off = assert_cli_ok(
        &goal_rust(dd, &["account", "list", "--password", "pw"]),
        "account list (after offline)",
        &node,
    );
    assert_eq!(
        account_list_status(&list_off, DEV_ADDR).as_deref(),
        Some("offline"),
        "status should flip to offline; got:\n{list_off}"
    );

    // 6. addpartkey, then changeonlinestatus --online → status flips back. Going
    //    online needs a participation key registered for the account.
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "addpartkey",
                "-a",
                DEV_ADDR,
                "--roundFirstValid",
                "1",
                "--roundLastValid",
                "2000",
            ],
        ),
        "account addpartkey",
        &node,
    );
    // Generation registers the key; poll listpartkeys until it shows up.
    let start = Instant::now();
    loop {
        let lpk = goal_rust(dd, &["account", "listpartkeys"]);
        if lpk.status.success() && String::from_utf8_lossy(&lpk.stdout).contains("E4A7") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "partkey for {DEV_ADDR} not registered within 30s of addpartkey; node log:\n{}",
            node.log_tail()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let online_out = assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "changeonlinestatus",
                "-a",
                DEV_ADDR,
                "--online",
                "-w",
                "w",
                "--password",
                "pw",
            ],
        ),
        "changeonlinestatus --online",
        &node,
    );
    assert!(
        online_out.contains("committed in round"),
        "online keyreg should confirm in a dev-mode round; got:\n{online_out}"
    );
    let list_on = assert_cli_ok(
        &goal_rust(dd, &["account", "list", "--password", "pw"]),
        "account list (after online)",
        &node,
    );
    assert_eq!(
        account_list_status(&list_on, DEV_ADDR).as_deref(),
        Some("online"),
        "status should flip back to online; got:\n{list_on}"
    );

    // =====================================================================
    // Go-goal direction (skips cleanly if ../go-algorand absent / build fails)
    // =====================================================================
    let Some(go_goal_bin) = try_ensure_go_goal() else {
        eprintln!(
            "localnet_node_e2e: goal-rust lifecycle PASSED; Go-goal section skipped (no buildable ../go-algorand)."
        );
        return;
    };

    // Read paths: Go goal hits the Rust node's /v2/accounts read endpoints.
    let go_info = go_goal(&go_goal_bin, dd, &["account", "info", "-a", DEV_ADDR]);
    assert!(
        go_info.status.success(),
        "Go goal account info failed: {}\n  node log:\n{}",
        String::from_utf8_lossy(&go_info.stderr),
        node.log_tail(),
    );
    assert!(
        String::from_utf8_lossy(&go_info.stdout).contains("Minimum Balance:"),
        "Go goal account info missing Minimum Balance; got:\n{}",
        String::from_utf8_lossy(&go_info.stdout)
    );

    // Payment submit/confirm via Go goal (goal-rust's clerk send is a stub).
    // Go goal only skips the password prompt for an *unencrypted* wallet, so
    // create one and re-import the dev account there.
    assert_cli_ok(
        &goal_rust(dd, &["wallet", "new", "wu", "-w", "", "--no-display-seed"]),
        "wallet new (unencrypted)",
        &node,
    );
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "import",
                "-w",
                "wu",
                "--password",
                "",
                "--mnemonic",
                DEV_MNEMONIC,
            ],
        ),
        "account import (unencrypted wallet)",
        &node,
    );

    let before = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (before)",
        &node,
    ))
    .expect("recipient balance is an integer");

    let pay_amt: u64 = 1_000_000;
    let send = go_goal(
        &go_goal_bin,
        dd,
        &[
            "clerk",
            "send",
            "-a",
            &pay_amt.to_string(),
            "-f",
            DEV_ADDR,
            "-t",
            FEE_SINK,
            "-w",
            "wu",
        ],
    );
    let send_out = String::from_utf8_lossy(&send.stdout);
    assert!(
        send.status.success(),
        "Go goal clerk send failed: exit={:?}\n  stdout={send_out}\n  stderr={}\n  node log:\n{}",
        send.status.code(),
        String::from_utf8_lossy(&send.stderr),
        node.log_tail(),
    );
    assert!(
        send_out.contains("committed in round"),
        "Go goal payment should confirm in a dev-mode round; got:\n{send_out}"
    );

    let after = parse_balance(&assert_cli_ok(
        &goal_rust(dd, &["account", "balance", "-a", FEE_SINK]),
        "recipient balance (after)",
        &node,
    ))
    .expect("recipient balance is an integer");
    assert!(
        after >= before + pay_amt,
        "recipient balance should grow by >= {pay_amt} (before={before}, after={after})"
    );
}
