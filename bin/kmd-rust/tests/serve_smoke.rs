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

//! `kmd-rust serve` smoke test: spawn the binary, hit /versions,
//! send SIGTERM, assert clean shutdown.
//!
//! This is the acceptance test for TASK-217 (B9): end-to-end through
//! the same binary `goal kmd` would talk to.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
fn signal_term(pid: u32) {
    // SIGTERM = 15.  We send it via libc::kill; spawning `kill`
    // would be a heavier dep for the same effect.
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

#[cfg(unix)]
fn poll_for_net_file(data_dir: &Path) -> std::io::Result<String> {
    let net_path = data_dir.join("kmd.net");
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if net_path.exists() {
            let s = std::fs::read_to_string(&net_path)?;
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("kmd.net never appeared at {}", net_path.display()),
    ))
}

#[cfg(unix)]
fn write_minimal_config(data_dir: &Path) {
    // Use insecure scrypt params so the serve smoke test isn't
    // dominated by KDF cost.
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {
                "scrypt": {
                    "scrypt_n": 2,
                    "scrypt_r": 1,
                    "scrypt_p": 1,
                },
                "allow_unsafe_scrypt": true,
            },
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        data_dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

/// End-to-end: spawn the binary, fetch /versions through the
/// bound port, then SIGTERM and confirm clean shutdown + cleanup.
#[cfg(unix)]
#[tokio::test]
async fn serve_starts_serves_versions_and_shuts_down_cleanly() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path();
    write_minimal_config(data_dir);

    // Find the binary the cargo test harness just built.
    let bin = env!("CARGO_BIN_EXE_kmd-rust");
    let child = Command::new(bin)
        .args([
            "serve",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--address",
            "127.0.0.1:0", // OS-assigned, avoids 7833 conflicts
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kmd-rust");

    // Run the rest of the test, but always reap the child on the way out.
    let test_outcome: Result<(), String> = async {
        // 1. Wait for kmd.net.
        let addr = tokio::task::spawn_blocking({
            let data_dir = data_dir.to_path_buf();
            move || poll_for_net_file(&data_dir)
        })
        .await
        .unwrap()
        .map_err(|e| format!("net file: {e}"))?;

        // 2. Read kmd.token.
        let token = std::fs::read_to_string(data_dir.join("kmd.token"))
            .map_err(|e| format!("kmd.token: {e}"))?
            .trim()
            .to_string();
        if token.len() < 64 {
            return Err(format!("kmd.token too short: {} chars", token.len()));
        }

        // 3. GET /versions (no auth — non-versioned route).
        let url = format!("http://{addr}/versions");
        let resp = reqwest::get(&url).await.map_err(|e| format!("GET: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("/versions status: {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
        if body != serde_json::json!({"versions": ["v1"]}) {
            return Err(format!("unexpected /versions body: {body}"));
        }

        // 4. Auth probe — without the token, /v1/wallets is 401.
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/v1/wallets"))
            .send()
            .await
            .map_err(|e| format!("GET v1: {e}"))?;
        if resp.status() != 401 {
            return Err(format!("unauthenticated /v1 status: {}", resp.status()));
        }

        // 5. With the token, /v1/wallets returns 200 and an empty
        //    (or omitted) wallets list — fresh data dir.
        let resp = client
            .get(format!("http://{addr}/v1/wallets"))
            .header("X-KMD-API-Token", &token)
            .send()
            .await
            .map_err(|e| format!("auth GET: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("authenticated /v1 status: {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.unwrap();
        // Empty list: either omitted or [].
        match body.get("wallets") {
            None => {}
            Some(v) if v.as_array().is_some_and(|a| a.is_empty()) => {}
            other => {
                return Err(format!(
                    "expected empty wallets list, got {:?}",
                    other.unwrap_or(&body)
                ));
            }
        }

        Ok(())
    }
    .await;

    // 6. SIGTERM and reap.
    signal_term(child.id());
    let status = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .expect("wait kmd-rust");
    if let Err(msg) = test_outcome {
        eprintln!("test failure: {msg}");
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&status.stdout));
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&status.stderr));
        panic!("smoke test failed: {msg}");
    }
    assert!(
        status.status.success(),
        "kmd-rust exited non-zero: {:?}\nstderr:\n{}",
        status.status,
        String::from_utf8_lossy(&status.stderr),
    );

    // 7. Lifecycle files cleaned up.
    assert!(!data_dir.join("kmd.net").exists(), "kmd.net not removed");
    assert!(!data_dir.join("kmd.pid").exists(), "kmd.pid not removed");
}

#[cfg(unix)]
#[test]
fn check_config_succeeds_on_well_formed_config() {
    let tmp = tempfile::TempDir::new().unwrap();
    write_minimal_config(tmp.path());
    let bin = env!("CARGO_BIN_EXE_kmd-rust");
    let status = Command::new(bin)
        .args(["check-config", "--data-dir", tmp.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "check-config: {status:?}");
}

// (Intentionally no "missing config" test: load_kmd_config falls back
// to defaults when kmd_config.json is absent, matching Go's behavior
// at `daemon/kmd/config/config.go:loadConfig`.  Misconfiguration
// detection is exercised by the algo-kmd unit tests instead.)

/// Regression for Codex PR #360 round 1: kmd_config.json's
/// `address` / `allowed_origins` / `allow_header_pna` fields were
/// being ignored — only CLI flags reached the server.  This test
/// writes those fields into the config (no CLI overrides), spawns
/// `kmd-rust serve`, and checks the server bound the configured
/// address.
#[cfg(unix)]
#[tokio::test]
async fn serve_uses_address_from_kmd_config_json_when_cli_absent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path();

    // Pick a deterministic port via TcpListener on :0, then close
    // the listener so the kmd-rust child can take it.  Tiny race
    // window (another process could grab the port between drop and
    // bind) — acceptable for a local smoke test.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_addr = probe.local_addr().unwrap();
    drop(probe);

    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {
                "scrypt": {"scrypt_n": 2, "scrypt_r": 1, "scrypt_p": 1},
                "allow_unsafe_scrypt": true,
            },
        },
        "session_lifetime_secs": 60,
        "address": configured_addr.to_string(),
        "allowed_origins": ["http://example.com"],
        "allow_header_pna": true,
    });
    std::fs::write(
        data_dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_kmd-rust");
    // NB: no --address / --allow-origin / --allow-header-pna flags —
    // we want to prove the config-only path works.
    let child = Command::new(bin)
        .args(["serve", "--data-dir", data_dir.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kmd-rust");

    let outcome: Result<(), String> = async {
        let addr = tokio::task::spawn_blocking({
            let data_dir = data_dir.to_path_buf();
            move || poll_for_net_file(&data_dir)
        })
        .await
        .unwrap()
        .map_err(|e| format!("net file: {e}"))?;

        if addr != configured_addr.to_string() {
            return Err(format!(
                "bound address {addr} != configured {configured_addr}"
            ));
        }

        // Sanity: the bound port is reachable and PNA preflight from
        // the configured origin echoes the right header back.
        let client = reqwest::Client::new();
        let resp = client
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/versions"))
            .header("Origin", "http://example.com")
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Private-Network", "true")
            .send()
            .await
            .map_err(|e| format!("OPTIONS: {e}"))?;
        let pna = resp
            .headers()
            .get("access-control-allow-private-network")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if pna.as_deref() != Some("true") {
            return Err(format!(
                "PNA preflight not echoed back; header = {pna:?} — config-driven allow_header_pna ignored"
            ));
        }
        Ok(())
    }
    .await;

    signal_term(child.id());
    let exit = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .expect("wait kmd-rust");

    if let Err(msg) = outcome {
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&exit.stdout));
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&exit.stderr));
        panic!("{msg}");
    }
    assert!(
        exit.status.success(),
        "kmd-rust exit: {:?}\nstderr:\n{}",
        exit.status,
        String::from_utf8_lossy(&exit.stderr),
    );
}
